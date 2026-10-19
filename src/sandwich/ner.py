"""Step 1c: NER for names the branch dictionary doesn't know.

- GLiNER multi-PII (urchade/gliner_multi_pii-v1): English and Arabic, zero-shot labels.
- CAMeLBERT-MSA NER for Arabic-script text (second opinion; Arabic is where English-first
  tools fail — RAT-Bench: Presidio 86–88% re-identified outside English).

Models load lazily and run locally; nothing leaves the branch.
"""

from __future__ import annotations

import re

from .detect import Span

_GLINER_LABELS = {
    "person": "PERSON",
    "organization": "ORG",
    "street address": "ADDRESS",
    "email address": "EMAIL",
    "phone number": "PHONE",
    "social security number": "SSN",
    "credit card number": "CARD",
}
_CAMEL_LABELS = {"PERS": "PERSON", "ORG": "ORG"}
_QUASI_LABELS = [
    "age", "date of birth", "occupation", "employer", "nationality", "ethnicity", "religion",
    "marital status", "medical condition", "education", "city", "country", "family member",
]
_ARABIC = re.compile(r"[؀-ۿ]")
_EMAIL_LIKE = re.compile(r"@|\bat\b|\bdot\b|\.(com|net|org|ae)\b", re.I)


def _chunks(text: str, size: int = 1200):
    """Split on sentence/line ends into ~size-char chunks, yielding (offset, chunk)."""
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = max(text.rfind(c, start + size // 2, end) for c in ".\n!?؟")
            end = cut + 1 if cut > start else end
        yield start, text[start:end]
        start = end


class NERDetector:
    def __init__(self, threshold: float = 0.5, device: str = "cpu", arabic: bool = True):
        self.threshold = threshold
        self.device = device
        self.arabic = arabic
        self._gliner = None
        self._camel = None

    def _load(self):
        if self._gliner is None:
            from gliner import GLiNER

            self._gliner = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1").to(self.device)
        if self.arabic and self._camel is None:
            from transformers import pipeline

            self._camel = pipeline(
                "ner",
                model="CAMeL-Lab/bert-base-arabic-camelbert-msa-ner",
                aggregation_strategy="simple",
                device=self.device,
            )

    def detect(self, text: str) -> list[Span]:
        self._load()
        spans: list[Span] = []
        for off, chunk in _chunks(text):
            for e in self._gliner.predict_entities(chunk, list(_GLINER_LABELS), threshold=self.threshold):
                s, t = off + e["start"], off + e["end"]
                kind, value = _GLINER_LABELS[e["label"]], text[s:t]
                if kind == "EMAIL" and not _EMAIL_LIKE.search(value):
                    continue  # GLiNER also tags the bare word "email"
                if kind in ("PHONE", "SSN", "CARD") and not re.search(r"\d|zero|one|two|three|four|five|six|seven|eight|nine", value, re.I):
                    continue  # "my phone number" is not a phone number
                spans.append(Span(s, t, kind, value))
            if self.arabic and _ARABIC.search(chunk):
                spans.extend(self._camel_spans(text, off, chunk))
        return spans

    def quasi_signals(self, text: str, threshold: float = 0.5) -> list[str]:
        """Cheap trigger for the (slow) context guard: which personal attributes GLiNER
        sees, without running the local LLM. Empty list = nothing to generalise."""
        self._load()
        found = []
        for _, chunk in _chunks(text):
            for e in self._gliner.predict_entities(chunk, _QUASI_LABELS, threshold=threshold):
                found.append(e["label"])
        return sorted(set(found))

    def _camel_spans(self, text: str, off: int, chunk: str) -> list[Span]:
        # CAMeLBERT returns word pieces (أد + ##نوك); merge adjacent pieces of one group,
        # then widen to whole words so clitics (بـ, و) are covered too.
        merged: list[list] = []
        for e in self._camel(chunk):
            label = _CAMEL_LABELS.get(e["entity_group"])
            if not label or e["score"] < self.threshold:
                continue
            if merged and merged[-1][2] == label and e["start"] - merged[-1][1] <= 1:
                merged[-1][1] = e["end"]
            else:
                merged.append([e["start"], e["end"], label])
        out = []
        for s, t, label in merged:
            s, t = off + s, off + t
            while s > 0 and text[s - 1].isalnum():
                s -= 1
            while t < len(text) and text[t].isalnum():
                t += 1
            out.append(Span(s, t, label, text[s:t]))
        return out
