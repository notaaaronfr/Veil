import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from veil import BranchDictionary, Entity
from veil.config import Settings
from veil.proxy import create_app

SECRETS = ["Sara", "Mansoori", "sara.m@example.ae", "4111", "123 4567", "784-1985-1234567-4"]
CLIENT_KEY = "client-key-1"
UPSTREAM_KEY = "upstream-secret"


class FakeUpstream:
    """Records every request and answers by echoing the last user message."""

    def __init__(self, stream_chunks=None, status=200, fail=False):
        self.requests: list[httpx.Request] = []
        self.stream_chunks = stream_chunks
        self.status = status
        self.fail = fail

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            raise httpx.ConnectError("down")
        body = json.loads(request.content)
        if request.url.path.endswith("/embeddings"):
            return httpx.Response(200, json={"data": [{"embedding": [0.1]}]})
        if self.stream_chunks is not None:
            sse = "".join(
                f"data: {json.dumps({'choices': [{'index': 0, 'delta': {'content': c}, 'finish_reason': None}]})}\n\n"
                for c in self.stream_chunks
            )
            sse += f"data: {json.dumps({'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
            sse += "data: [DONE]\n\n"
            return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
        last = next(m["content"] for m in reversed(body["messages"]) if m["role"] == "user")
        msg = {"role": "assistant", "content": f"You said: {last}"}
        if body.get("tools"):
            msg["tool_calls"] = [{"id": "t1", "type": "function",
                                  "function": {"name": "send_email", "arguments": json.dumps({"to": last.split()[-1]})}}]
        return httpx.Response(self.status, json={"choices": [{"index": 0, "message": msg, "finish_reason": "stop"}]})

    def sent(self) -> str:
        return " ".join(r.content.decode() for r in self.requests)


def make(upstream: FakeUpstream, **kw) -> TestClient:
    settings = Settings(
        upstream_url="https://example-uaenorth.openai.azure.com",
        upstream_key=UPSTREAM_KEY,
        branch_key=b"k" * 32,
        client_keys={CLIENT_KEY},
        dictionary=BranchDictionary([Entity("c1", "PERSON", ["Sara Al Mansoori"])]),
        ner=False,
        **kw,
    )
    return TestClient(create_app(settings, transport=httpx.MockTransport(upstream)))


AZURE = "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
H = {"api-key": CLIENT_KEY}


def assert_clean(text: str):
    for s in SECRETS:
        assert s not in text, f"{s!r} left the branch"


def test_requires_client_key_and_forwards_nothing_without_it():
    up = FakeUpstream()
    with make(up) as c:
        r = c.post(AZURE, json={"messages": [{"role": "user", "content": "hi Sara Al Mansoori"}]})
    assert r.status_code == 401 and up.requests == []


def test_chat_round_trip_protects_whole_history_and_restores():
    up = FakeUpstream()
    msgs = [
        {"role": "system", "content": "You help Sara Al Mansoori (sara.m@example.ae)."},
        {"role": "user", "content": "My card is 4111 1111 1111 1111"},
        {"role": "assistant", "content": "Noted, Sara."},
        {"role": "user", "content": "Call me on +971 50 123 4567 about ID 784-1985-1234567-4"},
    ]
    with make(up) as c:
        r = c.post(AZURE, json={"messages": msgs}, headers=H)
    assert r.status_code == 200
    assert_clean(up.sent())
    req = up.requests[0]
    assert req.url.path == "/openai/deployments/gpt-4o/chat/completions"
    assert req.url.params["api-version"] == "2024-10-21"
    assert req.headers["api-key"] == UPSTREAM_KEY and CLIENT_KEY not in str(req.headers)
    sent = json.loads(req.content)["messages"]
    assert "[PERSON_1]" in sent[0]["content"] and "[PERSON_1_FIRST]" in sent[2]["content"]  # one identity
    assert r.json()["choices"][0]["message"]["content"] == (
        "You said: Call me on +971 50 123 4567 about ID 784-1985-1234567-4"
    )


def test_tool_call_arguments_are_restored_for_the_app():
    up = FakeUpstream()
    with make(up) as c:
        r = c.post(AZURE, headers=H, json={
            "messages": [{"role": "user", "content": "Email sara.m@example.ae"}],
            "tools": [{"type": "function", "function": {"name": "send_email", "parameters": {}}}],
        })
    assert_clean(up.sent())
    args = json.loads(r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
    assert args == {"to": "sara.m@example.ae"}


def test_streaming_restores_surrogates_split_across_chunks():
    # the surrogate for Sara Al Mansoori is [PERSON_1]; split it across chunks
    up = FakeUpstream(stream_chunks=["Dear [PERS", "ON_1], your ", "request is ", "done."])
    with make(up) as c:
        r = c.post(AZURE, headers=H, json={"stream": True, "messages": [{"role": "user", "content": "Sara Al Mansoori here"}]})
        text = "".join(
            json.loads(line[5:])["choices"][0]["delta"].get("content", "")
            for line in r.text.splitlines()
            if line.startswith("data:") and line.strip() != "data: [DONE]"
        )
    assert_clean(up.sent())
    assert text == "Dear Sara Al Mansoori, your request is done."
    assert r.text.rstrip().endswith("data: [DONE]")


def test_embeddings_input_is_protected():
    up = FakeUpstream()
    with make(up) as c:
        r = c.post("/v1/embeddings", headers=H, json={"input": ["Sara Al Mansoori, card 4111 1111 1111 1111"]})
    assert r.status_code == 200
    assert_clean(up.sent())


def test_unsupported_endpoint_is_refused_not_forwarded():
    up = FakeUpstream()
    with make(up) as c:
        r = c.post("/v1/responses", headers=H, json={"input": "Sara Al Mansoori"})
    assert r.status_code == 404 and up.requests == []


def test_upstream_down_returns_502():
    with make(FakeUpstream(fail=True)) as c:
        r = c.post(AZURE, headers=H, json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 502


def test_logs_and_metrics_carry_no_values(caplog):
    up = FakeUpstream()
    with caplog.at_level(logging.INFO, logger="veil"), make(up) as c:
        c.post(AZURE, headers=H, json={"messages": [{"role": "user", "content": "Sara Al Mansoori, 4111 1111 1111 1111"}]})
        metrics = c.get("/metrics").text
        health = c.get("/healthz").json()
    assert "veil_entities_detected_total" in metrics
    assert_clean(metrics)
    assert_clean(caplog.text)
    assert health["status"] == "ok"


def test_images_dropped_by_default_and_passed_when_configured():
    img = {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
    msg = [{"role": "user", "content": [{"type": "text", "text": "what is this?"}, img]}]
    up = FakeUpstream()
    with make(up) as c:
        c.post(AZURE, headers=H, json={"messages": msg})
    assert "base64,AAAA" not in up.sent() and "image removed by Veil" in up.sent()
    up2 = FakeUpstream()
    with make(up2, images="pass") as c:
        c.post(AZURE, headers=H, json={"messages": msg})
        assert 'veil_unprotected_images_total{tenant="default"} 1' in c.get("/metrics").text
    assert "base64,AAAA" in up2.sent()


def test_quasi_identifiers_generalised_before_leaving():
    up = FakeUpstream()
    with make(up, quasi=frozenset({"AGE", "DOB"})) as c:
        r = c.post(AZURE, headers=H, json={"messages": [
            {"role": "user", "content": "I'm a 52-year-old, born on 26 November 1973."}]})
    sent = json.loads(up.requests[0].content)["messages"][0]["content"]
    assert sent == "I'm a 50-something-year-old, born on a date in the 1970s."
    assert r.status_code == 200
