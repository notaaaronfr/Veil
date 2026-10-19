"""The verified sandwich, phase 1 (deterministic core).

    session = Sandwich(branch_key, dictionary).session()
    p = session.protect(user_text)
    if p.blocked: route to human / local model
    reply = call_llm(session.llm_history)        # pseudonymised context only
    shown = session.receive(reply)               # restored for display only

Dual history (BodhiPromptShield: late restoration 1.6% exposure vs 51% early): the LLM
context never contains restored values.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field

from .canonical import canonicalise
from .detect import BranchDictionary, Detector, Entity, PatternDetector, Span, resolve_overlaps
from .gate import Hit, find_leaks
from .restore import RestoreReport, restore
from .transform import Transformer
from .vault import SessionVault


@dataclass
class Protected:
    outbound: str
    blocked: bool
    detected: Counter = field(default_factory=Counter)  # type -> count, no values
    scrubbed: int = 0  # leaks the hard line caught and fixed
    residual: list[str] = field(default_factory=list)  # types still leaking -> blocked
    context: object | None = None  # ContextReport when the context guard ran


class Session:
    def __init__(
        self,
        branch_key: bytes,
        detectors: list[Detector],
        dictionary: BranchDictionary | None,
        ner: Detector | None = None,
        context=None,
    ):
        self.id = uuid.uuid4().hex
        self._context = context
        self.vault = SessionVault(branch_key, self.id)
        self._tx = Transformer(self.vault)
        self._detectors = detectors
        self._dictionary = dictionary
        self._ner = ner
        self._session_dict = BranchDictionary()
        self._seen: set[str] = set()
        self.llm_history: list[dict] = []
        self.display_history: list[dict] = []

    def _scrub(self, text: str, hits: list[Hit]) -> str:
        chosen = resolve_overlaps(
            [h.span or _HitSpan(h) for h in hits]  # type: ignore[arg-type]
        )
        for s in sorted(chosen, key=lambda s: s.start, reverse=True):
            sur = s.hit.surrogate if isinstance(s, _HitSpan) else self._tx.surrogate_for(s)
            text = text[: s.start] + sur + text[s.end :]
        return text

    def _promote(self, canon: str, known: list[Span]) -> list[Span]:
        """NER names become session dictionary entities, so every later mention — full,
        first or last name, Arabic spelling, any turn — gets the same tag and the egress
        check knows to look for them."""
        direct = []
        for s in self._ner.detect(canon):
            if s.type in ("PERSON", "ORG"):
                name = " ".join(s.value.split()).strip(" .,:;\"'")
                if not _looks_proper(name):
                    continue
                if any(k.start < s.end and s.start < k.end for k in known):
                    continue  # already a branch-dictionary entity
                eid = f"ner:{s.type}:{name.casefold()}"
                known_forms = self._session_dict.forms() | (self._dictionary.forms() if self._dictionary else set())
                if eid not in self._seen and " ".join(name.casefold().split()) not in known_forms:
                    self._seen.add(eid)
                    self._session_dict.add(Entity(eid, s.type, [name], case_sensitive=True))
            else:
                direct.append(s)
        return direct + self._session_dict.detect(canon)

    def _needs_context(self, canon: str) -> bool:
        """Run the slow local-LLM guard only when there is something for it to do: when NER
        is available and sees no personal attributes, skip it (fails open to running)."""
        signals = getattr(self._ner, "quasi_signals", None)
        if signals is None:
            return True
        self.last_signals = signals(canon)
        return bool(self.last_signals)

    def protect(self, text: str, task: str | None = None, max_scrubs: int = 2) -> Protected:
        canon = canonicalise(text)
        spans = [s for d in self._detectors for s in d.detect(canon)]
        if self._ner:
            spans += self._promote(canon, [s for s in spans if s.entity_id])
        spans = resolve_overlaps(spans)
        out = self._tx.apply(canon, spans)
        result = Protected(out, False, Counter(s.type for s in spans))
        if self._context and self._needs_context(canon):
            out, result.context = self._context.protect(out, self._tx, task)

        dictionaries = [d for d in (self._dictionary, self._session_dict) if d]
        for _ in range(max_scrubs + 1):
            hits = find_leaks(out, self.vault, dictionaries)
            if not hits:
                break
            if _ == max_scrubs:
                result.blocked = True
                result.residual = sorted({h.type for h in hits})
                break
            result.scrubbed += len(hits)
            out = self._scrub(out, hits)

        result.outbound = out
        if not result.blocked:
            self.llm_history.append({"role": "user", "content": out})
            self.display_history.append({"role": "user", "content": text})
        return result

    def receive(self, llm_reply: str) -> tuple[str, RestoreReport]:
        self.llm_history.append({"role": "assistant", "content": llm_reply})
        shown, rep = restore(llm_reply, self.vault)
        self.display_history.append({"role": "assistant", "content": shown})
        return shown, rep

    def close(self) -> None:
        self.vault.close()
        self.display_history.clear()


@dataclass(frozen=True)
class _HitSpan:
    hit: Hit

    @property
    def start(self):
        return self.hit.start

    @property
    def end(self):
        return self.hit.end

    @property
    def type(self):
        return self.hit.type

    component = None


_ROLE_WORDS = {
    "patient", "doctor", "dr", "chatbot", "assistant", "user", "person", "target", "other",
    "sir", "madam", "customer", "client", "agent", "ai", "mr", "mrs", "ms",
}


_CONNECTORS = {"al", "el", "bin", "bint", "ibn", "abu", "de", "van", "von", "da", "di", "of", "and", "the", "&"}
_PRONOUNS = {"i", "you", "he", "she", "we", "they", "me", "him", "her", "us", "them", "my", "your"}


def _looks_proper(name: str) -> bool:
    """GLiNER also tags 'my mom', 'bakery', 'you'. Keep spans that read as proper nouns:
    Arabic script, or every word capitalised apart from name particles/connectors."""
    if re.search(r"[؀-ۿ]", name):
        return True
    toks = re.findall(r"[^\W\d_]+", name)
    if not toks or len(name) < 2 or name.casefold() in _ROLE_WORDS:
        return False
    if all(t.casefold() in _PRONOUNS | _ROLE_WORDS for t in toks):
        return False
    return any(t[0].isupper() for t in toks) and all(
        t[0].isupper() or t.casefold() in _CONNECTORS for t in toks
    )


class Sandwich:
    def __init__(
        self,
        branch_key: bytes | None = None,
        dictionary: BranchDictionary | None = None,
        ner: Detector | None = None,
        context=None,
    ):
        self.branch_key = branch_key or os.urandom(32)
        self.dictionary = dictionary
        self.ner = ner
        self.context = context  # sandwich.context.ContextGuard (local LLM), optional
        self.detectors: list[Detector] = [PatternDetector()]
        if dictionary:
            self.detectors.append(dictionary)

    def session(self) -> Session:
        return Session(self.branch_key, self.detectors, self.dictionary, self.ner, self.context)
