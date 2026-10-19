"""End-to-end check through a running Veil, using the official OpenAI SDK as an app would.

    uv run python bench/e2e_client.py http://localhost:8080 <client-key>
"""

import json
import sys
from pathlib import Path

from openai import AzureOpenAI

URL, KEY = sys.argv[1], sys.argv[2]
RECEIVED = Path(__file__).parent / "out" / "received.jsonl"
SECRETS = ["Priya", "Raghunathan", "Sara", "Mansoori", "سارة", "priya.r@example.ae", "4111", "123 4567",
           "1234567", "0331234567890123456", "Acme Trading"]

PROMPT = ("Draft a reply to Priya Raghunathan (priya.r@example.ae, +971 50 123 4567) at Acme Trading LLC. "
          "Her card 4111 1111 1111 1111 was charged twice; refund to IBAN AE070331234567890123456. "
          "Also cc سارة المنصوري, Emirates ID 784-1985-1234567-4.")

RECEIVED.unlink(missing_ok=True)
client = AzureOpenAI(azure_endpoint=URL, api_key=KEY, api_version="2024-10-21")
msgs = [{"role": "user", "content": PROMPT}]

r = client.chat.completions.create(model="gpt-4o", messages=msgs)
plain = r.choices[0].message.content
stream = client.chat.completions.create(model="gpt-4o", messages=msgs, stream=True)
streamed = "".join(c.choices[0].delta.content or "" for c in stream if c.choices)

sent = RECEIVED.read_text()
leaks = [s for s in SECRETS if s in sent]
expected = "Here is what I received: " + PROMPT
print("upstream received   :", json.loads(sent.splitlines()[0])["body"]["messages"][0]["content"])
print("upstream auth header:", json.loads(sent.splitlines()[0])["headers"])
print("leaks to upstream   :", leaks or "none")
print("non-stream restored :", plain == expected)
print("stream restored     :", streamed == expected)
if leaks or plain != expected or streamed != expected:
    print("\nnon-stream:", plain, "\nstream    :", streamed)
    sys.exit(1)
