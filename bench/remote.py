"""OpenAI-compatible remote model for EVALUATION ONLY (frontier attacker).

Reads ELCHAI_MODEL_BASE_URL / ELCHAI_MODEL_API_KEY from .env. Only benchmark data
(synthetic RAT-Bench texts and our outputs on them) is ever sent. The product itself
never calls this.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from pathlib import Path


def load_env(path: Path = Path(__file__).resolve().parent.parent / ".env") -> None:
    if path.exists():
        for line in path.read_text().splitlines():
            m = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$", line)
            if m:
                os.environ.setdefault(m[1], m[2].strip().strip("'\""))


class RemoteLLM:
    def __init__(self, model: str):
        load_env()
        self.model_id = model
        self.base = os.environ["ELCHAI_MODEL_BASE_URL"].rstrip("/")
        self.key = os.environ["ELCHAI_MODEL_API_KEY"]

    def chat(self, system: str, user: str, max_tokens: int = 800) -> str:
        body = json.dumps(
            {
                "model": self.model_id,
                "temperature": 0,
                "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.base}/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
        )
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return json.load(r)["choices"][0]["message"]["content"] or ""
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(2**attempt)
        return ""

    def json(self, system: str, user: str, max_tokens: int = 800) -> dict:
        m = re.search(r"\{.*\}", self.chat(system, user, max_tokens), re.S)
        try:
            return json.loads(m.group()) if m else {}
        except json.JSONDecodeError:
            return {}
