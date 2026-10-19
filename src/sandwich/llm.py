"""Local LLM runner (MLX on Apple Silicon). Nothing leaves the machine.

Runtime hygiene per "The Illusion of Local Privacy" (2026): in-process, no server, no
slot-save files, no prompt logging.
"""

from __future__ import annotations

import json
import re

DEFAULT_MODEL = "mlx-community/Qwen3-4B-Instruct-2507-4bit"


class LocalLLM:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model_id = model
        self._m = self._t = None

    def _load(self):
        if self._m is None:
            from mlx_lm import load

            self._m, self._t = load(self.model_id)

    def chat(self, system: str, user: str, max_tokens: int = 800) -> str:
        self._load()
        from mlx_lm import generate

        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        prompt = self._t.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
        return generate(self._m, self._t, prompt=prompt, max_tokens=max_tokens)

    def json(self, system: str, user: str, max_tokens: int = 800) -> dict:
        """Best-effort JSON: the first {...} block of the reply, or {} if unparseable."""
        raw = self.chat(system, user, max_tokens)
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return {}
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            # truncated output: keep complete items only
            cut = m.group()[: m.group().rfind("}") + 1]
            for suffix in ("]}", "}"):
                try:
                    return json.loads(cut + suffix)
                except json.JSONDecodeError:
                    continue
            return {}
