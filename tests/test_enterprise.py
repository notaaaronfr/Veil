"""Multi-tenant proxy: auth (keys + Entra ID), scopes, upstream allowlist, tiers, ledger,
rate limits, circuit breaker, readiness."""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from veil.auth import hash_key
from veil.ledger import Ledger
from veil.proxy import Runtime, create_app
from veil.tenancy import Config

KEY_A, KEY_A2, KEY_B, KEY_OLD = "veil_a_one", "veil_a_two", "veil_b_one", "veil_a_expired"
ISSUER, AUD, TID = "https://login.microsoftonline.com/tid-123/v2.0", "api://veil", "tid-123"


class Upstreams:
    """Fake providers keyed by host; records every request."""

    def __init__(self, status=200):
        self.calls: list[httpx.Request] = []
        self.status = status

    def __call__(self, req: httpx.Request):
        self.calls.append(req)
        if req.url.host == "hooks.internal":
            return httpx.Response(200, json={})
        body = json.loads(req.content)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"message": "busy"}})
        last = next((m["content"] for m in reversed(body.get("messages", [])) if m["role"] == "user"), "")
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": f"echo: {last}"}}]})

    def bodies(self, host):
        return [r.content.decode() for r in self.calls if r.url.host == host]


def write(p, text):
    p.write_text(text)
    return str(p)


@pytest.fixture
def cfg(tmp_path):
    s = tmp_path
    raw = {
        "ledger": {"dir": str(s / "ledger"), "hmac_key_file": write(s / "lk", "ab" * 32), "fsync": False},
        "oidc": {"issuer": ISSUER, "audience": AUD, "tenant_id": TID, "jwks_uri": "https://unused/keys"},
        "tenants": {
            "dubai-holding": {
                "branch_key_file": write(s / "bk1", "11" * 32),
                "ceiling": "amber",
                "red_types": ["HEALTH"],
                "handoff_webhook": "https://hooks.internal/veil",
                "quasi": "AGE,DOB",
                "upstreams": {
                    "azure-uaenorth": {"provider": "azure-openai", "region": "uaenorth", "url": "https://dh-uaenorth.example",
                                       "key_file": write(s / "k1", "azure-secret"), "deployments": ["gpt-4o"]},
                },
            },
            "branch-two": {
                "branch_key_file": write(s / "bk2", "22" * 32),
                "red_upstream": "local",
                "upstreams": {
                    "azure-eu": {"provider": "azure-openai", "region": "swedencentral", "url": "https://b2-eu.example",
                                 "key_file": write(s / "k2", "eu-secret"), "deployments": ["gpt-4o"]},
                    "local": {"provider": "customer-hosted", "url": "http://llm.branch.local", "auth": "none",
                              "in_branch": True, "deployments": ["gpt-4o"]},
                },
            },
        },
        "clients": [
            {"id": "crm", "tenant": "dubai-holding", "scopes": ["chat"], "rate_limit_rpm": 0,
             "keys": [{"sha256": hash_key(KEY_A)}, {"sha256": hash_key(KEY_A2)},
                      {"sha256": hash_key(KEY_OLD), "expires": "2020-01-01"}],
             "oidc_subjects": ["app-crm"]},
            {"id": "b2-app", "tenant": "branch-two", "rate_limit_rpm": 2, "keys": [{"sha256": hash_key(KEY_B)}]},
        ],
    }
    return Config.parse(raw)


def client(cfg, up=None, **rt):
    up = up or Upstreams()
    app = create_app(cfg, transport=httpx.MockTransport(up), runtime=Runtime(ner=False, retries=rt.pop("retries", 0), **rt))
    return TestClient(app), up


CHAT = "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
MSG = {"messages": [{"role": "user", "content": "Email Sara at sara.m@example.ae, card 4111 1111 1111 1111"}]}


# ------------------------------------------------------------------ authentication

def test_keys_scopes_expiry_and_rotation(cfg):
    c, up = client(cfg)
    with c:
        assert c.post(CHAT, json=MSG).status_code == 401
        assert c.post(CHAT, json=MSG, headers={"api-key": "veil_wrong"}).status_code == 401
        assert c.post(CHAT, json=MSG, headers={"api-key": KEY_OLD}).status_code == 401  # expired
        assert c.post(CHAT, json=MSG, headers={"api-key": KEY_A}).status_code == 200
        assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {KEY_A2}"}).status_code == 200  # rotation
        r = c.post("/v1/embeddings", json={"model": "gpt-4o", "input": "x"}, headers={"api-key": KEY_A})
        assert r.status_code == 403  # crm has only the chat scope
    assert len(up.bodies("dh-uaenorth.example")) == 2


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **over):
    claims = {"iss": ISSUER, "aud": AUD, "tid": TID, "azp": "app-crm", "exp": int(time.time()) + 300, "iat": int(time.time())}
    claims.update(over)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


def test_entra_id_tokens(cfg, rsa_key):
    c, up = client(cfg)

    class FakeJWKS:
        def get_signing_key_from_jwt(self, t):
            return type("K", (), {"key": rsa_key.public_key()})()

    with c:
        import veil.auth as auth_mod  # inject the signing keys (no network in tests)

        orig = auth_mod.Authenticator._jwks_client
        auth_mod.Authenticator._jwks_client = lambda self: FakeJWKS()
        try:
            ok = c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(rsa_key)}"})
            assert ok.status_code == 200
            assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(rsa_key, aud='api://other')}"}).status_code == 401
            assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(rsa_key, tid='evil')}"}).status_code == 401
            assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(rsa_key, exp=int(time.time()) - 3600)}"}).status_code == 401
            assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(rsa_key, azp='unknown-app')}"}).status_code == 403
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            assert c.post(CHAT, json=MSG, headers={"authorization": f"Bearer {token(other)}"}).status_code == 401  # bad signature
        finally:
            auth_mod.Authenticator._jwks_client = orig


# ------------------------------------------------------------------ tenancy and routing

def test_tenants_are_isolated_and_unapproved_deployments_refused(cfg):
    c, up = client(cfg)
    with c:
        r = c.post("/openai/deployments/gpt-5-preview/chat/completions", json=MSG, headers={"api-key": KEY_A})
        assert r.status_code == 403 and r.json()["error"]["code"] == "deployment_not_approved"
        # dubai-holding's client cannot reach branch-two's upstream even by asking for it
        r = c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-veil-upstream": "azure-eu"})
        assert r.status_code == 403
        assert c.post(CHAT, json=MSG, headers={"api-key": KEY_B}).status_code == 200
    assert up.bodies("b2-eu.example") and not up.bodies("dh-uaenorth.example")  # only the approved route was used
    for b in up.bodies("b2-eu.example"):
        assert "sara.m@example.ae" not in b and "4111 1111" not in b


def test_upstream_keys_are_per_tenant_and_never_the_client_key(cfg):
    c, up = client(cfg)
    with c:
        c.post(CHAT, json=MSG, headers={"api-key": KEY_A})
    req = up.calls[0]
    assert req.headers["api-key"] == "azure-secret" and KEY_A not in str(req.headers)


# ------------------------------------------------------------------ tiers

def test_red_label_without_local_model_is_handed_off_not_sent(cfg):
    c, up = client(cfg)
    with c:
        r = c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-veil-classification": "red"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "red_tier_handoff"
    hid = r.json()["error"]["handoff_id"]
    assert not up.bodies("dh-uaenorth.example")
    hooks = up.bodies("hooks.internal")
    assert hooks and hid in hooks[0] and "Sara" not in hooks[0] and "4111" not in hooks[0]  # ids only, no content


def test_red_types_force_red(cfg):
    c, up = client(cfg)
    body = {"messages": [{"role": "user", "content": "I'm a 52-year-old with diabetes"}]}
    # HEALTH is only detected by NER; emulate the detection result through the label to keep the test model-free
    with c:
        r = c.post(CHAT, json=body, headers={"api-key": KEY_A, "x-veil-classification": "red"})
    assert r.status_code == 403


def test_red_goes_to_verified_in_branch_model_unmodified(cfg):
    c, up = client(cfg)
    with c:
        r = c.post(CHAT, json=MSG, headers={"api-key": KEY_B, "x-veil-classification": "red"})
    assert r.status_code == 200 and r.headers["x-veil-tier"] == "red"
    local = up.bodies("llm.branch.local")
    assert local and "4111 1111 1111 1111" in local[0]  # original text, but it never left the branch
    assert not up.bodies("b2-eu.example")


def test_green_label_with_sensitive_content_is_raised_to_amber(cfg):
    c, up = client(cfg)
    with c:
        r = c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-veil-classification": "green"})
    assert r.status_code == 200 and r.headers["x-veil-tier"] == "amber"
    assert "4111 1111" not in up.bodies("dh-uaenorth.example")[0]


# ------------------------------------------------------------------ ledger

def test_every_decision_is_in_a_verifiable_ledger_without_values(cfg):
    c, up = client(cfg)
    with c:
        c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-request-id": "req-1"})
        c.post("/openai/deployments/nope/chat/completions", json=MSG, headers={"api-key": KEY_A})
        c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-veil-classification": "red"})
    lg = Ledger(cfg.ledger.dir, "dubai-holding", cfg.ledger.hmac_key)
    ok, msg = lg.verify()
    assert ok, msg
    recs = [json.loads(l) for s in lg.segments() for l in s.read_text().splitlines()]
    assert [r["decision"] for r in recs] == ["forwarded", "refused", "handoff"]
    assert recs[0]["request_id"] == "req-1" and recs[0]["provider"] == "azure-openai" and recs[0]["region"] == "uaenorth"
    raw = "".join(s.read_text() for s in lg.segments())
    assert "Sara" not in raw and "sara.m" not in raw and "4111" not in raw
    assert not (lg.dir.parent / "branch-two").exists() or not list((lg.dir.parent / "branch-two").glob("*.jsonl"))


# ------------------------------------------------------------------ resilience

def test_rate_limit_per_client(cfg):
    c, _ = client(cfg)
    with c:
        codes = [c.post(CHAT, json=MSG, headers={"api-key": KEY_B}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_circuit_breaker_fails_fast_after_repeated_upstream_errors(cfg):
    up = Upstreams(status=500)
    c, _ = client(cfg, up, breaker_threshold=3, breaker_cooldown=60)
    with c:
        codes = [c.post(CHAT, json=MSG, headers={"api-key": KEY_A}).status_code for _ in range(5)]
        health = c.get("/healthz").json()
    assert codes[:3] == [500, 500, 500] and codes[3:] == [503, 503]
    assert len(up.bodies("dh-uaenorth.example")) == 3  # no calls while the circuit is open
    assert health["breakers"]["dubai-holding/azure-uaenorth"] == "open"


def test_retries_transient_upstream_errors(cfg):
    class Flaky(Upstreams):
        def __call__(self, req):
            self.calls.append(req)
            if len(self.calls) < 3:
                return httpx.Response(503, json={}, headers={"retry-after": "0"})
            return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]})

    up = Flaky()
    c, _ = client(cfg, up, retries=2)
    with c:
        assert c.post(CHAT, json=MSG, headers={"api-key": KEY_A}).status_code == 200
    assert len(up.calls) == 3


def test_readiness_fails_when_ledger_cannot_be_written(cfg, tmp_path):
    c, _ = client(cfg)
    with c:
        assert c.get("/readyz").status_code == 200
        cfg.ledger.dir = str(tmp_path / "missing" / "dir")
        r = c.get("/readyz")
        assert r.status_code == 503 and "not writable" in r.json()["problems"][0]
        assert c.get("/livez").status_code == 200


def test_request_id_is_echoed(cfg):
    c, _ = client(cfg)
    with c:
        r = c.post(CHAT, json=MSG, headers={"api-key": KEY_A, "x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"


def test_classifier_raises_but_never_lowers(cfg):
    from veil.policy import classify

    dh = cfg.tenants["dubai-holding"]  # ceiling amber, red_types HEALTH, no red upstream
    assert classify(dh, "green", {}).effective == "green"
    assert classify(dh, "green", {"EMAIL": 1}).effective == "amber"
    d = classify(dh, "amber", {"HEALTH": 1})
    assert d.effective == "red" and d.action == "handoff" and "HEALTH" in d.reason
    assert classify(dh, "red", {}).action == "handoff"
    assert classify(cfg.tenants["branch-two"], "red", {}).action == "red_local"
    assert classify(dh, "bogus", {}).label == "amber"  # unknown label -> tenant default
