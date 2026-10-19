"""Veil proxy: an OpenAI / Azure OpenAI compatible endpoint that pseudonymises every
request before it leaves the branch and restores the reply.

Apps point their OpenAI or Azure OpenAI SDK at Veil instead of the provider; nothing else
changes. Stateless: each request gets a fresh session (fresh keys), the whole message
history is protected in one pass so tags are consistent across messages, and the vault is
wiped when the response ends. Logs and metrics carry counts and types, never values.

Supported (everything else is refused, never forwarded unprotected):
  POST /openai/deployments/{deployment}/chat/completions   (Azure)
  POST /openai/deployments/{deployment}/embeddings
  POST /v1/chat/completions, POST /v1/embeddings            (OpenAI-style / Azure v1)
  GET  /healthz, GET /metrics
"""

from __future__ import annotations

import hmac
import json
import logging
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from .config import Settings
from .restore import restore
from .session import Session, Veil
from .streaming import StreamRestorer

log = logging.getLogger("veil.proxy")
audit = logging.getLogger("veil.audit")


class Metrics:
    def __init__(self):
        self.c: Counter = Counter()

    def inc(self, name: str, n: int = 1, **labels):
        key = name + ("{" + ",".join(f'{k}="{v}"' for k, v in sorted(labels.items())) + "}" if labels else "")
        self.c[key] += n

    def render(self) -> str:
        return "".join(f"veil_{k} {v}\n" for k, v in sorted(self.c.items()))


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


# ---------------------------------------------------------------- app

def create_app(
    settings: Settings, transport: httpx.AsyncBaseTransport | None = None, ner=None, context=None, hardening=None
) -> FastAPI:
    metrics = Metrics()
    state: dict = {"ner": "disabled", "context": "disabled", "hardening": hardening or {}}

    if settings.ner and ner is None:
        try:
            from .ner import NERDetector

            ner = NERDetector(device=settings.device, quasi=set(settings.quasi))
            ner._load()  # load at startup, not on the first request
            state["ner"] = "ready"
        except Exception:
            log.exception("NER unavailable; running deterministic layers only")
            ner, state["ner"] = None, "failed"
    elif ner is not None:
        state["ner"] = "ready"
    if settings.context and context is None:
        try:
            from .context import ContextGuard

            context = ContextGuard()
            state["context"] = "ready"
        except Exception:
            log.exception("context guard unavailable")
            context, state["context"] = None, "failed"
    elif context is not None:
        state["context"] = "ready"

    veil = Veil(settings.branch_key, settings.dictionary, ner=ner, context=context,
                context_budget=settings.context_budget, quasi=settings.quasi)

    @asynccontextmanager
    async def lifespan(app):
        app.state.client = httpx.AsyncClient(
            base_url=settings.upstream_url, timeout=settings.upstream_timeout, transport=transport
        )
        yield
        await app.state.client.aclose()

    app = FastAPI(title="Veil", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authorised(request: Request) -> bool:
        if settings.allow_unauthenticated:
            return True
        token = request.headers.get("api-key") or ""
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        return any(hmac.compare_digest(token, k) for k in settings.client_keys)

    def upstream_headers() -> dict:
        h = {"content-type": "application/json"}
        if settings.upstream_auth == "bearer":
            h["authorization"] = f"Bearer {settings.upstream_key}"
        else:
            h["api-key"] = settings.upstream_key
        return h

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "ner": state["ner"], "context": state["context"],
                "quasi": sorted(settings.quasi), "images": settings.images,
                "hardening": state.get("hardening", {}),
                "dictionary_entities": len(settings.dictionary.entities) if settings.dictionary else 0}

    @app.get("/metrics")
    async def metrics_endpoint():
        return PlainTextResponse(metrics.render())

    async def read_json(request: Request):
        raw = await request.body()
        if len(raw) > settings.max_body_bytes:
            return None, _error(413, "request body too large")
        try:
            return json.loads(raw), None
        except json.JSONDecodeError:
            return None, _error(400, "request body is not valid JSON")

    async def chat(request: Request, upstream_path: str):
        rid = uuid.uuid4().hex[:12]
        if not authorised(request):
            metrics.inc("requests_total", route="chat", outcome="unauthorised")
            return _error(401, "missing or invalid Veil client key", "unauthorized")
        body, err = await read_json(request)
        if err:
            return err
        session = veil.session()
        t0 = time.perf_counter()
        prot = RequestProtector(session, metrics, settings.images)
        try:
            body["messages"] = await run_in_threadpool(prot.messages, body.get("messages") or [])
        except Exception:
            session.close()
            log.exception("[%s] protection failed; request not forwarded", rid)
            metrics.inc("requests_total", route="chat", outcome="protect_error")
            return _error(500, "Veil could not protect this request; nothing was sent upstream")
        protect_ms = round((time.perf_counter() - t0) * 1000)
        _count(metrics, prot)
        url = upstream_path + (f"?{request.url.query}" if request.url.query else "")
        record = {"rid": rid, "route": "chat", "path": request.url.path, "protect_ms": protect_ms, **prot.summary()}

        if body.get("stream"):
            return await _stream(request.app.state.client, url, body, session, record, metrics)

        t1 = time.perf_counter()
        try:
            resp = await request.app.state.client.post(url, json=body, headers=upstream_headers())
        except httpx.HTTPError as e:
            session.close()
            metrics.inc("upstream_errors_total", kind=type(e).__name__)
            audit.info(json.dumps({**record, "upstream_error": type(e).__name__}))
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        record["upstream_ms"] = round((time.perf_counter() - t1) * 1000)
        record["upstream_status"] = resp.status_code
        try:
            out = resp.json()
        except ValueError:
            session.close()
            return _error(502, "upstream returned a non-JSON response", "upstream_error")
        if resp.status_code == 200:
            out, record["restored"], record["hallucinated_tags"] = restore_completion(out, session)
            metrics.inc("restored_total", record["restored"])
            metrics.inc("hallucinated_tags_total", record["hallucinated_tags"])
        session.close()
        metrics.inc("requests_total", route="chat", outcome=str(resp.status_code))
        audit.info(json.dumps(record))
        return JSONResponse(out, status_code=resp.status_code)

    async def _stream(client, url, body, session, record, metrics):
        req = client.build_request("POST", url, json=body, headers=upstream_headers())
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            session.close()
            metrics.inc("upstream_errors_total", kind=type(e).__name__)
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        if resp.status_code != 200:
            content = await resp.aread()
            await resp.aclose()
            session.close()
            metrics.inc("requests_total", route="chat_stream", outcome=str(resp.status_code))
            return JSONResponse(json.loads(content or b"{}"), status_code=resp.status_code)

        restorers: dict[tuple, StreamRestorer] = {}

        def restorer(*key) -> StreamRestorer:
            if key not in restorers:
                restorers[key] = StreamRestorer(session.vault)
            return restorers[key]

        def flush_choice(chunk: dict, idx: int) -> list[str]:
            """Emit any held-back text for choice `idx` before its finish event."""
            events = []
            for key, rs in restorers.items():
                if key[0] != idx:
                    continue
                rest = rs.flush()
                if not rest:
                    continue
                if key[1] == "content":
                    delta = {"content": rest}
                else:
                    delta = {"tool_calls": [{"index": key[2], "function": {"arguments": rest}}]}
                events.append(json.dumps({**chunk, "choices": [{"index": idx, "delta": delta, "finish_reason": None}]}))
            return events

        async def gen():
            try:
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        if line:
                            yield line + "\n"
                        else:
                            yield "\n"
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        yield "data: [DONE]\n\n"
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
                # stream ended without finish events: flush whatever is left
                for key, rs in restorers.items():
                    rest = rs.flush()
                    if rest:
                        yield f"data: {json.dumps({'choices': [{'index': key[0], 'delta': {'content': rest}}]})}\n\n"
            finally:
                await resp.aclose()
                record["restored"] = sum(r.report.restored for r in restorers.values())
                record["hallucinated_tags"] = sum(len(r.report.hallucinated) for r in restorers.values())
                record["stream"] = True
                metrics.inc("restored_total", record["restored"])
                metrics.inc("requests_total", route="chat_stream", outcome="200")
                audit.info(json.dumps(record))
                session.close()

        return StreamingResponse(gen(), media_type="text/event-stream")

    async def embeddings(request: Request, upstream_path: str):
        if not authorised(request):
            metrics.inc("requests_total", route="embeddings", outcome="unauthorised")
            return _error(401, "missing or invalid Veil client key", "unauthorized")
        body, err = await read_json(request)
        if err:
            return err
        session = veil.session()
        prot = RequestProtector(session, metrics, settings.images)
        try:
            inp = body.get("input")
            if isinstance(inp, str):
                body["input"] = await run_in_threadpool(prot.text, inp)
            elif isinstance(inp, list) and all(isinstance(x, str) for x in inp):
                body["input"] = await run_in_threadpool(lambda: [prot.text(x) for x in inp])
            elif inp is not None:
                return _error(400, "Veil supports string or list-of-strings embedding input only")
        finally:
            session.close()  # embeddings are never restored
        _count(metrics, prot)
        url = upstream_path + (f"?{request.url.query}" if request.url.query else "")
        try:
            resp = await request.app.state.client.post(url, json=body, headers=upstream_headers())
        except httpx.HTTPError as e:
            metrics.inc("upstream_errors_total", kind=type(e).__name__)
            return _error(502, f"upstream unreachable ({type(e).__name__})", "upstream_error")
        audit.info(json.dumps({"route": "embeddings", "upstream_status": resp.status_code, **prot.summary()}))
        metrics.inc("requests_total", route="embeddings", outcome=str(resp.status_code))
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.post("/openai/deployments/{deployment}/chat/completions")
    async def azure_chat(deployment: str, request: Request):
        return await chat(request, f"/openai/deployments/{deployment}/chat/completions")

    @app.post("/v1/chat/completions")
    async def v1_chat(request: Request):
        return await chat(request, "/v1/chat/completions")

    @app.post("/openai/v1/chat/completions")
    async def azure_v1_chat(request: Request):
        return await chat(request, "/openai/v1/chat/completions")

    @app.post("/openai/deployments/{deployment}/embeddings")
    async def azure_embeddings(deployment: str, request: Request):
        return await embeddings(request, f"/openai/deployments/{deployment}/embeddings")

    @app.post("/v1/embeddings")
    async def v1_embeddings(request: Request):
        return await embeddings(request, "/v1/embeddings")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def unsupported(path: str):
        metrics.inc("requests_total", route="unsupported", outcome="404")
        return _error(404, f"/{path} is not supported by Veil and was not forwarded", "unsupported_endpoint")

    return app


def _count(metrics: Metrics, prot: RequestProtector) -> None:
    for t, n in prot.detected.items():
        metrics.inc("entities_detected_total", n, type=t)
    metrics.inc("scrubbed_total", prot.scrubbed)
    metrics.inc("redacted_total", prot.redacted)
    metrics.inc("unprotected_images_total", prot.unprotected_images)
    metrics.inc("dropped_images_total", prot.dropped_images)
    for layer in prot.degraded:
        metrics.inc("degraded_total", layer=layer)


def app_from_env() -> FastAPI:
    """Factory for gunicorn: gunicorn -c python:veil.gunicorn_conf "veil.proxy:app_from_env()"."""
    import os

    from .hardening import harden

    logging.basicConfig(level=os.environ.get("VEIL_LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
    return create_app(Settings.from_env(), hardening=harden())


def main():  # veil-proxy: single process, for development; the image runs gunicorn
    import os

    import uvicorn

    uvicorn.run(
        app_from_env(),
        host=os.environ.get("VEIL_HOST", "0.0.0.0"),
        port=int(os.environ.get("VEIL_PORT", "8080")),
        access_log=False,  # the audit log replaces it; access logs could carry query strings
    )


if __name__ == "__main__":
    main()
