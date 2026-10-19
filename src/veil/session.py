"""Veil session: the verified sandwich (detect -> transform -> context -> egress check -> restore).

    session = Veil(branch_key, dictionary).session()
    p = session.protect(user_text)
    reply = call_llm(session.llm_history)        # pseudonymised context only
    shown = session.receive(reply)               # restored for display only

Never-fail policy: a request is never refused. If a model-based layer (NER, context
guard) errors or runs out of time, protection degrades to the deterministic layers and
`Protected.degraded` says which ones were skipped. Anything the egress check finds and
cannot scrub to a surrogate is replaced with [REDACTED]. What is never relaxed: a value
known to be sensitive is never sent, and nothing is sent without the deterministic layers
(a failure there raises instead of sending raw text).

Dual history (BodhiPromptShield: late restoration 1.6% exposure vs 51% early): the LLM
context never contains restored values.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field

from .canonical import canonicalise
from .detect import BranchDictionary, Detector, Entity, PatternDetector, Span, resolve_overlaps
from .gate import Hit, find_leaks
from .restore import RestoreReport, restore
from .transform import Transformer
from .vault import SessionVault


REDACTED = "[REDACTED]"
log = logging.getLogger("veil")
_context_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="veil-context")


@dataclass
class Protected:
    outbound: str
    blocked: bool = False  # kept for API compatibility; the never-fail policy never blocks
    detected: Counter = field(default_factory=Counter)  # type -> count, no values
    scrubbed: int = 0  # leaks the hard line caught and replaced with surrogates
    redacted: int = 0  # leaks it could only remove ([REDACTED], not restorable)
    residual: list[str] = field(default_factory=list)  # types that needed redaction
    degraded: list[str] = field(default_factory=list)  # layers skipped: "ner", "context", "context-timeout"
    context: object | None = None  # ContextReport when the context guard ran


class Session:
    def __init__(
        self,
        branch_key: bytes,
        detectors: list[Detector],
        dictionary: BranchDictionary | None,
        ner: Detector | None = None,
        context=None,
        context_budget: float | None = None,
    ):
        self.id = uuid.uuid4().hex
        self._context = context
        self._context_budget = context_budget
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
        degraded: list[str] = []
        canon = canonicalise(text)
        # deterministic layers: no try/except -- if these fail we must not send anything
        spans = [s for d in self._detectors for s in d.detect(canon)]
        if self._ner:
            try:
                spans += self._promote(canon, [s for s in spans if s.entity_id])
            except Exception:
                log.exception("NER failed; continuing with deterministic layers only")
                degraded.append("ner")
        spans = resolve_overlaps(spans)
        out = self._tx.apply(canon, spans)
        result = Protected(out, detected=Counter(s.type for s in spans), degraded=degraded)
        if self._context:
            out = self._run_context(out, canon, task, result)

        dictionaries = [d for d in (self._dictionary, self._session_dict) if d]
        for _ in range(max_scrubs):
            hits = find_leaks(out, self.vault, dictionaries)
            if not hits:
                break
            result.scrubbed += len(hits)
            out = self._scrub(out, hits)
        else:
            # Still leaking after the scrub rounds: remove the text outright rather than
            # refuse the request. Not restorable, but the value never leaves.
            hits = find_leaks(out, self.vault, dictionaries)
            if hits:
                result.residual = sorted({h.type for h in hits})
                result.redacted = len(hits)
                for h in sorted(resolve_overlaps([_HitSpan(h) for h in hits]), key=lambda s: s.start, reverse=True):
                    out = out[: h.start] + REDACTED + out[h.end :]

        result.outbound = out
        self.llm_history.append({"role": "user", "content": out})
        self.display_history.append({"role": "user", "content": text})
        return result

    def _run_context(self, out: str, canon: str, task: str | None, result: Protected) -> str:
        """Phase 3 is best effort: on error or when over budget, send the phase-2 output."""
        try:
            if not self._needs_context(canon):
                return out
            fut = _context_pool.submit(self._context.protect, out, self._tx, task)
            out2, result.context = fut.result(timeout=self._context_budget)
            return out2
        except FutureTimeout:
            log.warning("context guard over budget (%.1fs); sending phase-2 output", self._context_budget)
            result.degraded.append("context-timeout")
        except Exception:
            log.exception("context guard failed; sending phase-2 output")
            result.degraded.append("context")
        return out

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
# Acronyms GLiNER sometimes tags as organisations; replacing them hides what a number IS.
_ACRONYMS = {
    "iban", "swift", "bic", "pin", "otp", "atm", "vat", "trn", "tin", "ssn", "id", "eid", "llc",
    "ceo", "cfo", "coo", "cto", "hr", "it", "ai", "api", "pdf", "kyc", "aml", "uae", "gcc", "aed", "usd",
}


def _looks_proper(name: str) -> bool:
    """GLiNER also tags 'my mom', 'bakery', 'you'. Keep spans that read as proper nouns:
    Arabic script, or every word capitalised apart from name particles/connectors."""
    if re.search(r"[؀-ۿ]", name):
        return True
    toks = re.findall(r"[^\W\d_]+", name)
    if not toks or len(name) < 2 or name.casefold() in _ROLE_WORDS:
        return False
    if all(t.casefold() in _PRONOUNS | _ROLE_WORDS | _ACRONYMS for t in toks):
        return False
    return any(t[0].isupper() for t in toks) and all(
        t[0].isupper() or t.casefold() in _CONNECTORS for t in toks
    )


class Veil:
    def __init__(
        self,
        branch_key: bytes | None = None,
        dictionary: BranchDictionary | None = None,
        ner: Detector | None = None,
        context=None,
        context_budget: float | None = None,
        quasi: set[str] | frozenset = frozenset(),
    ):
        """`quasi`: quasi-identifier types to protect deterministically (AGE, DOB); the NER
        detector carries its own set for the model-detected types."""
        self.branch_key = branch_key or os.urandom(32)
        self.dictionary = dictionary
        self.ner = ner
        self.context = context  # veil.context.ContextGuard (local LLM), optional
        self.context_budget = context_budget  # seconds; None = wait for it
        self.detectors: list[Detector] = [PatternDetector(quasi)]
        if dictionary:
            self.detectors.append(dictionary)

    def session(self) -> Session:
        return Session(
            self.branch_key, self.detectors, self.dictionary, self.ner, self.context, self.context_budget
        )


# Backwards-compatible name used by the benchmark scripts.
Sandwich = Veil
