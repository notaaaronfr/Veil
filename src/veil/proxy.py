"""Veil proxy: an OpenAI / Azure OpenAI compatible endpoint that pseudonymises every
request before it leaves the branch and restores the reply.

Apps point their OpenAI or Azure OpenAI SDK at Veil instead of the provider; nothing else
changes. Stateless: each request gets a fresh session (fresh keys), the whole message
history is protected in one pass so tags are consistent across messages, and the vault is
wiped when the response ends. Logs and metrics carry counts and types, never values.

Multi-tenant: every caller authenticates (API key or Entra ID token) as a client of one
tenant; the tenant's own key, dictionary, protection policy, approved upstreams (provider,
region, deployments), tier ceiling and ledger apply. Every decision is written to the
tenant's tamper-evident ledger.

Supported (everything else is refused, never forwarded unprotected):
  POST /openai/deployments/{deployment}/chat/completions   (Azure)
  POST /openai/deployments/{deployment}/embeddings
  POST /v1/chat/completions, /openai/v1/chat/completions, /v1/embeddings
  GET  /livez, /readyz, /healthz, /metrics
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import random
import re
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import __version__
from .auth import AuthError, Authenticator, Principal
from .config import Settings
from .ledger import Ledgers
from .ner import QUASI_TYPES
from .policy import classify
from .resilience import CircuitBreaker, RateLimiter
from .restore import restore
from .session import Session, Veil
from .streaming import StreamRestorer
from .tenancy import Config, Tenant, Upstream

log = logging.getLogger("veil.proxy")
audit = logging.getLogger("veil.audit")


BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60)


def _labels(labels: dict) -> str:
    return "{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}" if labels else ""


class Metrics:
    """Prometheus text-format counters and histograms. Labels carry types/tenants, never values."""

    def __init__(self):
        self.c: Counter = Counter()
        self.h: dict = {}

    def inc(self, name: str, n: int = 1, **labels):
        self.c[name + _labels(labels)] += n

    def observe(self, name: str, value: float, **labels):
        key = (name, tuple(sorted(labels.items())))
        counts, total = self.h.get(key, ([0] * len(BUCKETS), [0.0, 0]))
        for i, b in enumerate(BUCKETS):
            if value <= b:
                counts[i] += 1
        total[0] += value
        total[1] += 1
        self.h[key] = (counts, total)

    def render(self) -> str:
        out = [f"veil_{k} {v}\n" for k, v in sorted(self.c.items())]
        for (name, labels), (counts, (s, n)) in sorted(self.h.items()):
            lab = dict(labels)
            for b, c in zip(BUCKETS, counts):
                out.append(f"veil_{name}_bucket{_labels(lab | {'le': b})} {c}\n")
            out.append(f"veil_{name}_bucket{_labels(lab | {'le': '+Inf'})} {n}\n")
            out.append(f"veil_{name}_sum{_labels(lab)} {s}\n")
            out.append(f"veil_{name}_count{_labels(lab)} {n}\n")
        return "".join(out)


def _error(status: int, message: str, code: str = "veil_error") -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": code, "code": code}}, status_code=status)


# ---------------------------------------------------------------- request protection

class RequestProtector:
    """Protects every text-bearing field of one request with one session."""

    def __init__(self, session: Session, metrics: Metrics, images: str = "drop"):
        self.s = session
        self.m = metrics
        self.images = images
        self.dropped_images = 0
        self.detected: Counter = Counter()
        self.scrubbed = self.redacted = 0
        self.degraded: set[str] = set()
        self.unprotected_images = 0

    def text(self, value: str, task: str | None = None) -> str:
        if not value:
            return value
        p = self.s.protect(value, task=task)
        self.detected.update(p.detected)
        self.scrubbed += p.scrubbed
        self.redacted += p.redacted
        self.degraded.update(p.degraded)
        return p.outbound

    def content(self, content, task: str | None):
        if isinstance(content, str):
            return self.text(content, task)
        if isinstance(content, list):
            out = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    part = {**part, "text": self.text(part.get("text", ""), task)}
                elif isinstance(part, dict) and part.get("type") in ("image_url", "input_image", "image"):
                    # images cannot be inspected for personal data
                    if self.images == "drop":
                        self.dropped_images += 1
                        part = {"type": "text", "text": "[image removed by Veil: images are not sent outside the branch]"}
                    else:
                        self.unprotected_images += 1
                out.append(part)
            return out
        return content

    def messages(self, messages: list[dict]) -> list[dict]:
        task = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user" and isinstance(m.get("content"), str)),
            None,
        )
        out = []
        for m in messages:
            m = dict(m)
            if "content" in m and m["content"] is not None:
                m["content"] = self.content(m["content"], task)
            if m.get("tool_calls"):
                m["tool_calls"] = [self._tool_call(tc) for tc in m["tool_calls"]]
            if m.get("function_call", {}).get("arguments"):
                m["function_call"] = {**m["function_call"], "arguments": self.text(m["function_call"]["arguments"])}
            out.append(m)
        return out

    def _tool_call(self, tc: dict) -> dict:
        fn = tc.get("function") or {}
        if fn.get("arguments"):
            tc = {**tc, "function": {**fn, "arguments": self.text(fn["arguments"])}}
        return tc

    def summary(self) -> dict:
        return {
            "detected": dict(self.detected),
            "scrubbed": self.scrubbed,
            "redacted": self.redacted,
            "degraded": sorted(self.degraded),
            "unprotected_images": self.unprotected_images,
            "dropped_images": self.dropped_images,
        }


# ---------------------------------------------------------------- response restoration

def restore_completion(body: dict, session: Session) -> tuple[dict, int, int]:
    restored = hallucinated = 0

    def r(text):
        nonlocal restored, hallucinated
        if not isinstance(text, str) or not text:
            return text
        out, rep = restore(text, session.vault)
        restored += rep.restored
        hallucinated += len(rep.hallucinated)
        return out

    for ch in body.get("choices", []):
        msg = ch.get("message") or {}
        for key in ("content", "refusal"):
            if key in msg:
                msg[key] = r(msg[key])
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            if "arguments" in fn:
                fn["arguments"] = r(fn["arguments"])
    return body, restored, hallucinated



# ---------------------------------------------------------------- runtime settings

@dataclass
class Runtime:
    """Process-wide knobs (per-tenant policy lives in the Config)."""

    ner: bool = True
    device: str = "cpu"
    context: bool = False
    context_budget: float = 8.0
    upstream_timeout: float = 120.0
    max_body_bytes: int = 4 * 1024 * 1024
    retries: int = 2
    breaker_threshold: int = 5
    breaker_cooldown: float = 30.0

    @classmethod
    def from_env(cls) -> "Runtime":
        e = os.environ.get
        return cls(
            ner=e("VEIL_NER", "1") not in ("0", "false", "no", "off"),
            device=e("VEIL_DEVICE", "cpu"),
            context=e("VEIL_CONTEXT", "0") in ("1", "true", "yes", "on"),
            context_budget=float(e("VEIL_CONTEXT_BUDGET", "8")),
            upstream_timeout=float(e("VEIL_UPSTREAM_TIMEOUT", "120")),
            max_body_bytes=int(e("VEIL_MAX_BODY_BYTES", str(4 * 1024 * 1024))),
            retries=int(e("VEIL_UPSTREAM_RETRIES", "2")),
        )

    @classmethod
    def from_settings(cls, s: Settings) -> "Runtime":
        return cls(s.ner, s.device, s.context, s.context_budget, s.upstream_timeout, s.max_body_bytes)


class _TenantNER:
    """The NER model is shared across tenants; each tenant only gets the quasi-identifier
    types it enabled (direct identifiers are always on)."""

    def __init__(self, ner, enabled: frozenset):
        self.ner, self.drop = ner, set(QUASI_TYPES) - set(enabled) - {"ORG"}

    def detect(self, text):
        return [s for s in self.ner.detect(text) if s.type not in self.drop]

    def quasi_signals(self, text):
        return self.ner.quasi_signals(text)


_RID = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
RETRY_STATUS = {429, 502, 503, 504}


def _upstream_headers(u: Upstream) -> dict:
    h = {"content-type": "application/json"}
    if u.auth == "bearer":
        h["authorization"] = f"Bearer {u.key}"
    elif u.auth == "api-key":
        h["api-key"] = u.key
    return h


def _retry_after(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        try:
            return min(10.0, float(resp.headers.get("retry-after", "")))
        except ValueError:
            pass
    return min(10.0, 0.5 * (3**attempt)) * (0.5 + random.random())


# ---------------------------------------------------------------- app

def create_app(
    config: Config | Settings,
    transport: httpx.AsyncBaseTransport | None = None,
    ner=None,
    context=None,
    hardening=None,
    runtime: Runtime | None = None,
) -> FastAPI:
    if isinstance(config, Settings):  # legacy single-tenant mode
        runtime = runtime or Runtime.from_settings(config)
        config = Config.from_settings(config)
    runtime = runtime or Runtime.from_env()
    metrics = Metrics()
    state: dict = {"ner": "disabled", "context": "disabled", "hardening": hardening or {}, "ledger_errors": 0}

    if runtime.ner and ner is None:
        try:
            from .ner import NERDetector

            union = frozenset().union(*(t.quasi for t in config.tenants.values()))
            ner = NERDetector(device=runtime.device, quasi=set(union))
            ner._load()  # load at startup, not on the first request
            state["ner"] = "ready"
        except Exception:
            log.exception("NER unavailable; running deterministic layers only")
            ner, state["ner"] = None, "failed"
    elif ner is not None:
        state["ner"] = "ready"
    if runtime.context and context is None:
        try:
            from .context import ContextGuard

            context = ContextGuard()
            state["context"] = "ready"
        except Exception:
            log.exception("context guard unavailable")
            context, state["context"] = None, "failed"
    elif context is not None:
        state["context"] = "ready"

    veils = {
        tid: Veil(t.branch_key, t.dictionary, ner=_TenantNER(ner, t.quasi) if ner else None, context=context,
                  context_budget=runtime.context_budget, quasi=t.quasi)
        for tid, t in config.tenants.items()
    }
    authn = Authenticator(config)
    ledgers = None
    if config.ledger:
        os.makedirs(config.ledger.dir, exist_ok=True)  # readiness probes it before the first write
        ledgers = Ledgers(config.ledger.dir, config.ledger.hmac_key, config.ledger.fsync)
    limiter = RateLimiter()
    breakers: dict[str, CircuitBreaker] = {}

    def breaker(tenant: Tenant, u: Upstream) -> CircuitBreaker:
        key = f"{tenant.id}/{u.id}"
        if key not in breakers:
            breakers[key] = CircuitBreaker(runtime.breaker_threshold, runtime.breaker_cooldown)
        return breakers[key]

    @asynccontextmanager
    async def lifespan(app):
        app.state.client = httpx.AsyncClient(timeout=runtime.upstream_timeout, transport=transport)
        yield
        await app.state.client.aclose()

    app = FastAPI(title="Veil", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    # ------------------------------------------------------------------ ledger

    async def record(tenant: Tenant, base: dict, **overrides) -> None:
        fields = {**base, **overrides}
        line = {"tenant": tenant.id, **fields}
        audit.info(json.dumps(line, default=str))
        if ledgers is None:
            return
        try:
            await run_in_threadpool(lambda: ledgers[tenant.id].append(veil_version=__version__, **fields))
        except Exception:
            state["ledger_errors"] += 1
            metrics.inc("ledger_errors_total", tenant=tenant.id)
            log.exception("ledger write failed for tenant %s; /readyz now reports not ready", tenant.id)

    # ------------------------------------------------------------------ health

    @app.get("/livez")
    async def livez():
        return {"status": "alive"}

    @app.get("/readyz")
    async def readyz():
        problems = []
        if state["ledger_errors"]:
            problems.append("ledger writes failing")
        if ledgers is not None:
            try:
                probe = os.path.join(config.ledger.dir, ".ready-probe")
                with open(probe, "w") as f:
                    f.write("ok")
                os.unlink(probe)
            except OSError as e:
                problems.append(f"ledger directory not writable: {e}")
        degraded = state["ner"] == "failed" or state["context"] == "failed"
        body = {"status": "ready" if not problems else "not_ready", "problems": problems, "degraded": degraded}
        return JSONResponse(body, status_code=200 if not problems else 503)

    @app.get("/healthz")
    async def healthz():
        return {
            "status": "ok", "version": __version__, "ner": state["ner"], "context": state["context"],
            "hardening": state["hardening"], "ledger": "enabled" if ledgers else "disabled",
            "tenants": {tid: {"quasi": sorted(t.quasi), "images": t.images, "ceiling": t.ceiling,
                              "upstreams": {u.id: {"provider": u.provider, "region": u.region, "in_branch": u.in_branch}
                                            for u in t.upstreams.values()},
                              "dictionary_entities": len(t.dictionary.entities) if t.dictionary else 0}
                        for tid, t in config.tenants.items()},
            "breakers": {k: b.state for k, b in breakers.items()},
        }

    @app.get("/metrics")
    async def metrics_endpoint():
        return PlainTextResponse(metrics.render())

    # ------------------------------------------------------------------ shared request steps

    async def admit(request: Request, scope: str, rid: str):
        """Authenticate, check scope and rate limit. Returns (principal, error response)."""
        try:
            principal: Principal = await run_in_threadpool(authn.authenticate, request.headers)
        except AuthError as e:
            metrics.inc("requests_total", route=scope, outcome=str(e.status))
            return None, _error(e.status, str(e), "unauthorized" if e.status == 401 else "forbidden")
        if not principal.can(scope):
            metrics.inc("requests_total", route=scope, outcome="403", tenant=principal.tenant.id)
            return None, _error(403, f"client {principal.client_id} lacks the '{scope}' scope", "forbidden")
        rpm = principal.client.rate_limit_rpm if principal.client else 0
        wait = limiter.check(principal.client_id, rpm)
        if wait:
            metrics.inc("rate_limited_total", tenant=principal.tenant.id)
            resp = _error(429, "rate limit exceeded", "rate_limited")
            resp.headers["retry-after"] = str(int(wait) + 1)
            return None, resp
        return principal, None

    async def read_json(request: Request):
        raw = await request.body()
        if len(raw) > runtime.max_body_bytes:
            return None, _error(413, "request body too large")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return None, _error(400, "request body is not valid JSON")
        if not isinstance(body, dict):
            return None, _error(400, "request body must be a JSON object")
        return body, None

    async def send(request: Request, tenant: Tenant, u: Upstream, url: str, body: dict, stream: bool):
        """POST to the upstream through its circuit breaker, retrying transient failures."""
        br = breaker(tenant, u)
        client: httpx.AsyncClient = request.app.state.client
        resp = None
        for attempt in range(runtime.retries + 1):
            if not br.allow():
                raise _BreakerOpen()
            try:
                req = client.build_request("POST", u.url + url, json=body, headers=_upstream_headers(u))
                resp = await client.send(req, stream=stream)
            except httpx.TransportError as e:
                br.failure()
                metrics.inc("upstream_errors_total", kind=type(e).__name__, upstream=u.id)
                if attempt == runtime.retries:
                    raise
                await asyncio.sleep(_retry_after(None, attempt))
                continue
            if resp.status_code >= 500:
                br.failure()
            else:
                br.success()
            if resp.status_code in RETRY_STATUS and attempt < runtime.retries:
                metrics.inc("upstream_retries_total", status=str(resp.status_code), upstream=u.id)
                delay = _retry_after(resp, attempt)
                await resp.aclose()
                await asyncio.sleep(delay)
                continue
            return resp
        return resp

    async def handoff(tenant: Tenant, principal: Principal, rid: str, decision, base: dict) -> JSONResponse:
        hid = "ho_" + uuid.uuid4().hex[:16]
        await record(tenant, base, decision="handoff", handoff_id=hid, reason=decision.reason)
        metrics.inc("handoffs_total", tenant=tenant.id)
        if tenant.handoff_webhook:
            payload = {"handoff_id": hid, "tenant": tenant.id, "client": principal.client_id, "request_id": rid,
                       "tier": decision.effective, "reason": decision.reason}  # never content

            async def notify():
                try:
                    async with httpx.AsyncClient(timeout=5, transport=transport) as c:
                        await c.post(tenant.handoff_webhook, json=payload)
                except Exception:
                    log.exception("handoff webhook failed for %s", hid)

            asyncio.get_running_loop().create_task(notify())
        resp = _error(403, "Red-tier request: it may not leave the branch and has been handed off to a person",
                      "red_tier_handoff")
        body = json.loads(resp.body)
        body["error"]["handoff_id"] = hid
        return JSONResponse(body, status_code=403, headers={"x-request-id": rid, "x-veil-tier": decision.effective})

    # ------------------------------------------------------------------ chat

    async def chat(request: Request, path: str, deployment: str | None):
        rid = request.headers.get("x-request-id", "")
        rid = rid if _RID.match(rid) else uuid.uuid4().hex[:16]
        principal, err = await admit(request, "chat", rid)
        if err:
            err.headers["x-request-id"] = rid
            return err
        tenant = principal.tenant
        body, err = await read_json(request)
        if err:
            return err
        deployment = deployment or body.get("model")
        base = {"request_id": rid, "client": principal.client_id, "auth": principal.method, "route": "chat",
                "deployment": deployment}
        upstream = config.route(tenant, principal.client, deployment, request.headers.get("x-veil-upstream"))
        if upstream is None:
            await record(tenant, base, decision="refused", reason="deployment not approved for tenant")
            metrics.inc("requests_total", route="chat", outcome="403", tenant=tenant.id)
            return _error(403, f"deployment {deployment!r} is not approved for tenant {tenant.id}", "deployment_not_approved")

        original = copy.deepcopy(body)
        session = veils[tenant.id].session()
        t0 = time.perf_counter()
        prot = RequestProtector(session, metrics, tenant.images)
        try:
            body["messages"] = await run_in_threadpool(prot.messages, body.get("messages") or [])
        except Exception:
            session.close()
            log.exception("[%s] protection failed; request not forwarded", rid)
            metrics.inc("requests_total", route="chat", outcome="protect_error", tenant=tenant.id)
            await record(tenant, base, decision="refused", reason="protection error")
            return _error(500, "Veil could not protect this request; nothing was sent upstream")
        protect_ms = round((time.perf_counter() - t0) * 1000)
        _count(metrics, prot, tenant.id)
        decision = classify(tenant, request.headers.get("x-veil-classification"), dict(prot.detected))
        base |= {"protect_ms": protect_ms, "tier_label": decision.label, "tier_effective": decision.effective,
                 **{k: v for k, v in prot.summary().items()}, "generalised": session._tx.generalised}

        if decision.action == "handoff":
            session.close()
            return await handoff(tenant, principal, rid, decision, base)
        if decision.action == "red_local":
            upstream, body = tenant.upstreams[tenant.red_upstream], original  # never leaves the branch
            session.close()
            session = None
        base |= {"upstream": upstream.id, "provider": upstream.provider, "region": upstream.region,
                 "decision": "red_local" if session is None else "forwarded"}
        url = path + (f"?{request.url.query}" if request.url.query else "")
        hdrs = {"x-request-id": rid, "x-veil-tier": decision.effective}

        if body.get("stream"):
            return await _stream(request, tenant, upstream, url, body, session, base, hdrs)

        t1 = time.perf_counter()
        try:
            resp = await send(request, tenant, upstream, url, body, stream=False)
        except _BreakerOpen:
            if session:
                session.close()
            await record(tenant, base, decision="upstream_unavailable", reason="circuit open")
            return _error(503, f"upstream {upstream.id} is unavailable (circuit open)", "upstream_unavailable")
        except httpx.HTTPError as e:
            if session:
                session.close()
            await record(tenant, base, decision="upstream_error", reason=type(e).__name__)
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        base["upstream_ms"] = round((time.perf_counter() - t1) * 1000)
        base["upstream_status"] = resp.status_code
        try:
            out = resp.json()
        except ValueError:
            if session:
                session.close()
            await record(tenant, base, reason="non-JSON upstream response")
            return _error(502, "upstream returned a non-JSON response", "upstream_error")
        if resp.status_code == 200 and session is not None:
            out, base["restored"], base["hallucinated_tags"] = restore_completion(out, session)
            metrics.inc("restored_total", base["restored"], tenant=tenant.id)
            metrics.inc("hallucinated_tags_total", base["hallucinated_tags"], tenant=tenant.id)
        if session:
            session.close()
        metrics.inc("requests_total", route="chat", outcome=str(resp.status_code), tenant=tenant.id)
        metrics.observe("upstream_seconds", base["upstream_ms"] / 1000, tenant=tenant.id)
        metrics.observe("protect_seconds", protect_ms / 1000, tenant=tenant.id)
        await record(tenant, base)
        return JSONResponse(out, status_code=resp.status_code, headers=hdrs)

    async def _stream(request, tenant, upstream, url, body, session, base, hdrs):
        try:
            resp = await send(request, tenant, upstream, url, body, stream=True)
        except _BreakerOpen:
            if session:
                session.close()
            await record(tenant, base, decision="upstream_unavailable", reason="circuit open")
            return _error(503, f"upstream {upstream.id} is unavailable (circuit open)", "upstream_unavailable")
        except httpx.HTTPError as e:
            if session:
                session.close()
            await record(tenant, base, decision="upstream_error", reason=type(e).__name__)
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        base["upstream_status"] = resp.status_code
        if resp.status_code != 200:
            content = await resp.aread()
            await resp.aclose()
            if session:
                session.close()
            await record(tenant, base, stream=True)
            try:
                return JSONResponse(json.loads(content or b"{}"), status_code=resp.status_code, headers=hdrs)
            except ValueError:
                return _error(resp.status_code, "upstream error", "upstream_error")

        restorers: dict[tuple, StreamRestorer] = {}

        def restorer(*key) -> StreamRestorer:
            if key not in restorers:
                restorers[key] = StreamRestorer(session.vault)
            return restorers[key]

        def flush_choice(chunk: dict, idx: int) -> list[str]:
            events = []
            for key, rs in restorers.items():
                if key[0] != idx:
                    continue
                rest = rs.flush()
                if not rest:
                    continue
                delta = {"content": rest} if key[1] == "content" else {
                    "tool_calls": [{"index": key[2], "function": {"arguments": rest}}]}
                events.append(json.dumps({**chunk, "choices": [{"index": idx, "delta": delta, "finish_reason": None}]}))
            return events

        async def gen():
            try:
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        yield (line + "\n") if line else "\n"
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]" or session is None:  # red_local: nothing to restore
                        yield line + "\n\n"
                        continue
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        yield line + "\n\n"
                        continue
                    pre: list[str] = []
                    for ch in chunk.get("choices", []):
                        idx = ch.get("index", 0)
                        delta = ch.get("delta") or {}
                        if isinstance(delta.get("content"), str):
                            delta["content"] = restorer(idx, "content").feed(delta["content"])
                        for tc in delta.get("tool_calls") or []:
                            fn = tc.get("function") or {}
                            if isinstance(fn.get("arguments"), str):
                                fn["arguments"] = restorer(idx, "tool", tc.get("index", 0)).feed(fn["arguments"])
                        if ch.get("finish_reason"):
                            pre += flush_choice(chunk, idx)
                    for ev in pre:
                        yield f"data: {ev}\n\n"
                    yield f"data: {json.dumps(chunk)}\n\n"
                for key, rs in restorers.items():
                    rest = rs.flush()
                    if rest:
                        yield f"data: {json.dumps({'choices': [{'index': key[0], 'delta': {'content': rest}}]})}\n\n"
            finally:
                await resp.aclose()
                base["restored"] = sum(r.report.restored for r in restorers.values())
                base["hallucinated_tags"] = sum(len(r.report.hallucinated) for r in restorers.values())
                metrics.inc("restored_total", base["restored"], tenant=tenant.id)
                metrics.inc("requests_total", route="chat_stream", outcome="200", tenant=tenant.id)
                if session:
                    session.close()
                await record(tenant, base, stream=True)

        return StreamingResponse(gen(), media_type="text/event-stream", headers=hdrs)

    # ------------------------------------------------------------------ embeddings

    async def embeddings(request: Request, path: str, deployment: str | None):
        rid = request.headers.get("x-request-id", "")
        rid = rid if _RID.match(rid) else uuid.uuid4().hex[:16]
        principal, err = await admit(request, "embeddings", rid)
        if err:
            return err
        tenant = principal.tenant
        body, err = await read_json(request)
        if err:
            return err
        deployment = deployment or body.get("model")
        base = {"request_id": rid, "client": principal.client_id, "auth": principal.method, "route": "embeddings",
                "deployment": deployment}
        upstream = config.route(tenant, principal.client, deployment, request.headers.get("x-veil-upstream"))
        if upstream is None:
            await record(tenant, base, decision="refused", reason="deployment not approved for tenant")
            return _error(403, f"deployment {deployment!r} is not approved for tenant {tenant.id}", "deployment_not_approved")
        inp = body.get("input")
        if inp is not None and not (isinstance(inp, str) or (isinstance(inp, list) and all(isinstance(x, str) for x in inp))):
            return _error(400, "Veil supports string or list-of-strings embedding input only")
        original = copy.deepcopy(body)
        session = veils[tenant.id].session()
        prot = RequestProtector(session, metrics, tenant.images)
        try:
            if isinstance(inp, str):
                body["input"] = await run_in_threadpool(prot.text, inp)
            elif isinstance(inp, list):
                body["input"] = await run_in_threadpool(lambda: [prot.text(x) for x in inp])
        finally:
            session.close()  # embeddings are never restored
        _count(metrics, prot, tenant.id)
        decision = classify(tenant, request.headers.get("x-veil-classification"), dict(prot.detected))
        base |= {"tier_label": decision.label, "tier_effective": decision.effective, **prot.summary()}
        if decision.action == "handoff":
            return await handoff(tenant, principal, rid, decision, base)
        if decision.action == "red_local":
            upstream, body = tenant.upstreams[tenant.red_upstream], original
        base |= {"upstream": upstream.id, "provider": upstream.provider, "region": upstream.region,
                 "decision": "red_local" if decision.action == "red_local" else "forwarded"}
        url = path + (f"?{request.url.query}" if request.url.query else "")
        try:
            resp = await send(request, tenant, upstream, url, body, stream=False)
        except _BreakerOpen:
            await record(tenant, base, decision="upstream_unavailable", reason="circuit open")
            return _error(503, f"upstream {upstream.id} is unavailable (circuit open)", "upstream_unavailable")
        except httpx.HTTPError as e:
            await record(tenant, base, decision="upstream_error", reason=type(e).__name__)
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        base["upstream_status"] = resp.status_code
        metrics.inc("requests_total", route="embeddings", outcome=str(resp.status_code), tenant=tenant.id)
        await record(tenant, base)
        return JSONResponse(resp.json(), status_code=resp.status_code, headers={"x-request-id": rid})

    # ------------------------------------------------------------------ routes

    @app.post("/openai/deployments/{deployment}/chat/completions")
    async def azure_chat(deployment: str, request: Request):
        return await chat(request, f"/openai/deployments/{deployment}/chat/completions", deployment)

    @app.post("/v1/chat/completions")
    async def v1_chat(request: Request):
        return await chat(request, "/v1/chat/completions", None)

    @app.post("/openai/v1/chat/completions")
    async def azure_v1_chat(request: Request):
        return await chat(request, "/openai/v1/chat/completions", None)

    @app.post("/openai/deployments/{deployment}/embeddings")
    async def azure_embeddings(deployment: str, request: Request):
        return await embeddings(request, f"/openai/deployments/{deployment}/embeddings", deployment)

    @app.post("/v1/embeddings")
    async def v1_embeddings(request: Request):
        return await embeddings(request, "/v1/embeddings", None)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def unsupported(path: str):
        metrics.inc("requests_total", route="unsupported", outcome="404")
        return _error(404, f"/{path} is not supported by Veil and was not forwarded", "unsupported_endpoint")

    return app


class _BreakerOpen(Exception):
    pass


def _count(metrics: Metrics, prot: RequestProtector, tenant: str) -> None:
    for t, n in prot.detected.items():
        metrics.inc("entities_detected_total", n, type=t, tenant=tenant)
    metrics.inc("scrubbed_total", prot.scrubbed, tenant=tenant)
    metrics.inc("redacted_total", prot.redacted, tenant=tenant)
    metrics.inc("unprotected_images_total", prot.unprotected_images, tenant=tenant)
    metrics.inc("dropped_images_total", prot.dropped_images, tenant=tenant)
    for layer in prot.degraded:
        metrics.inc("degraded_total", layer=layer, tenant=tenant)


class _JSONFormatter(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        out = {"ts": self.formatTime(r, "%Y-%m-%dT%H:%M:%S%z"), "level": r.levelname, "logger": r.name, "msg": r.getMessage()}
        if r.exc_info:
            out["exc"] = self.formatException(r.exc_info)
        return json.dumps(out)


def _logging() -> None:
    h = logging.StreamHandler()
    h.setFormatter(_JSONFormatter() if os.environ.get("VEIL_LOG_FORMAT", "json") == "json" else
                   logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(os.environ.get("VEIL_LOG_LEVEL", "INFO"))


def app_from_env() -> FastAPI:
    """Factory for gunicorn: gunicorn -c python:veil.gunicorn_conf "veil.proxy:app_from_env()".
    Multi-tenant when VEIL_CONFIG points at a config file, else legacy single-tenant env vars."""
    from .hardening import harden

    _logging()
    from .tenancy import active_config

    return create_app(active_config(), hardening=harden(), runtime=Runtime.from_env())


def main():  # veil-proxy: single process, for development; the image runs gunicorn
    import uvicorn

    uvicorn.run(
        app_from_env(),
        host=os.environ.get("VEIL_HOST", "0.0.0.0"),
        port=int(os.environ.get("VEIL_PORT", "8080")),
        access_log=False,  # the audit log replaces it; access logs could carry query strings
    )


if __name__ == "__main__":
    main()
