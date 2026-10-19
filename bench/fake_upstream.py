"""Stand-in for Azure OpenAI in end-to-end tests. Echoes the last user message (streamed
or not) and appends every request body it receives to received.jsonl, so a test can prove
what would have left the branch.

    uv run python bench/fake_upstream.py  # listens on :19099
"""

import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

LOG = Path(__file__).parent / "out" / "received.jsonl"
app = FastAPI()


@app.post("/openai/deployments/{dep}/chat/completions")
async def chat(dep: str, request: Request):
    body = await request.json()
    LOG.parent.mkdir(exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps({"headers": {k: v for k, v in request.headers.items() if k in ("api-key", "authorization")},
                            "body": body}) + "\n")
    last = next(m["content"] for m in reversed(body["messages"]) if m["role"] == "user")
    reply = f"Here is what I received: {last}"
    if body.get("stream"):
        async def gen():
            for i in range(0, len(reply), 7):  # 7-char chunks split tags and numbers
                chunk = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": dep,
                         "choices": [{"index": 0, "delta": {"content": reply[i:i + 7]}, "finish_reason": None}]}
                yield f"data: {json.dumps(chunk)}\n\n"
            end = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": dep,
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            yield f"data: {json.dumps(end)}\n\ndata: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")
    return JSONResponse({"id": "x", "object": "chat.completion", "created": 0, "model": dep,
                         "choices": [{"index": 0, "finish_reason": "stop",
                                      "message": {"role": "assistant", "content": reply}}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=19099, log_level="warning")
