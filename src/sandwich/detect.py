"""Step 1: detection.

a. Patterns with checksums (Emirates ID, IBAN, card, phone, email, IPv4). Digit runs are
   found with separators allowed between every digit, then classified, so spaced or
   hyphen-split numbers are caught.
b. Branch dictionary: the branch's known clients/staff/orgs in Arabic and Latin script,
   matched at every occurrence and by name component (first / last), which gives
   coreference-consistent tags by construction.
c. NER plugs in through the `Detector` protocol (phase 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from .canonical import tolerant_pattern
from .fpe import iban_valid, luhn_valid


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    value: str
    entity_id: str | None = None  # dictionary entity, for component tags
    component: str | None = None  # "FIRST" / "LAST"


class Detector(Protocol):
    def detect(self, text: str) -> list[Span]: ...


_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Za-z0-9])")
_DIGIT_RUN = re.compile(r"(?<![\w])(?:\+|00)?\d(?:[ \-.()/]{0,2}\d){5,}(?!\w)")


_ACCOUNT_CUE = re.compile(
    r"(account|acct|a/c|iban|policy|contract|customer|member|ref|no\.|number|#|id|ssn|social|رقم|حساب|هوية)\W*$",
    re.I,
)


def _classify_digits(raw: str, before: str = "") -> str | None:
    digits = re.sub(r"\D", "", raw)
    plus = raw.lstrip().startswith("+")
    n = len(digits)
    if n == 15 and digits.startswith("784"):
        return "EMIRATES_ID"
    if digits.startswith("00971") or (plus and digits.startswith("971")):
        return "PHONE" if 11 <= n <= 14 else None
    if n == 12 and digits.startswith("9715"):  # +971 5x mobile with the plus lost
        return "PHONE"
    if re.fullmatch(r"\d{3}-\d{2}-\d{4}", raw):
        return "SSN"
    if re.fullmatch(r"\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}", raw):  # Belgian national register no.
        return "NATIONAL_ID"
    if digits[0] == "0" and 9 <= n <= 11 and re.search(r"[ \-./]", raw):  # national-format phone
        return "PHONE"
    if n == 10 and re.fullmatch(r"\d{3}\)?[ \-.]{1,2}\d{3}[ \-.]\d{4}", raw):  # (831) 625-7933
        return "PHONE"
    if n == 11 and plus is False and digits[0] == "1" and re.search(r"[ \-.]", raw):
        return "PHONE"
    if 13 <= n <= 19 and luhn_valid(digits):
        return "CARD"
    if n == 10 and digits.startswith("05"):
        return "PHONE"
    if n == 9 and digits[0] == "0" and digits[1] in "234679":
        return "PHONE"
    if plus and 8 <= n <= 15:
        return "PHONE"
    # Unclassified long numbers are treated as account/reference numbers (format-preserved,
    # so the task still works). 9–11 digits only with a cue word, to spare plain amounts.
    if n >= 12 or (n >= 9 and _ACCOUNT_CUE.search(before[-25:])):
        return "ACCOUNT"
    return None


class PatternDetector:
    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in _EMAIL.finditer(text):
            spans.append(Span(m.start(), m.end(), "EMAIL", m.group()))
        for m in _IBAN.finditer(text):
            if iban_valid(m.group()):
                spans.append(Span(m.start(), m.end(), "IBAN", m.group()))
        for m in _IPV4.finditer(text):
            spans.append(Span(m.start(), m.end(), "IP", m.group()))
        for m in _DIGIT_RUN.finditer(text):
            raw = m.group().rstrip(" -.(")
            kind = _classify_digits(raw, text[max(0, m.start() - 25) : m.start()])
            if kind:
                spans.append(Span(m.start(), m.start() + len(raw), kind, raw))
        return spans


_PARTICLES = {"al", "el", "bin", "bint", "ibn", "abu", "umm", "bu", "de", "van", "von", "da", "di"}


@dataclass
class Entity:
    id: str
    type: str  # PERSON, ORG, LOC, ...
    names: list[str]  # all spellings, e.g. Latin and Arabic
    components: dict[str, list[str]] = field(default_factory=dict)
    # NER-found names match as written (+ ALL CAPS), so "Target" the shop doesn't swallow
    # every "target". Branch-dictionary entities match case-insensitively.
    case_sensitive: bool = False


def _person_components(name: str) -> dict[str, list[str]]:
    toks = name.split()
    if len(toks) < 2:
        return {}
    first = toks[0]
    rest = toks[1:]
    last_full = " ".join(rest)
    lasts = [last_full]
    core = [t for t in rest if t.lower() not in _PARTICLES]
    if core and " ".join(core) != last_full:
        lasts.append(" ".join(core))
    # Arabic definite article fused to the surname: المنصوري → منصوري
    if len(rest) == 1 and rest[0].startswith("ال") and len(rest[0]) > 4:
        lasts.append(rest[0][2:])
    return {"FIRST": [first] if len(first) >= 3 else [], "LAST": [x for x in lasts if len(x) >= 3]}


class BranchDictionary:
    """Known entities of one branch. Matching is tolerant; replacement covers every occurrence."""

    def __init__(self, entities: Iterable[Entity] = ()):
        self.entities: list[Entity] = []
        for e in entities:
            self.add(e)

    def add(self, entity: Entity) -> None:
        if entity.type == "PERSON" and not entity.components:
            comps: dict[str, list[str]] = {}
            for n in entity.names:
                for k, v in _person_components(n).items():
                    comps.setdefault(k, []).extend(v)
            entity.components = comps
        self.entities.append(entity)

    def _index(self):
        """{folded value: (regex, [(entity, component)])} — one regex per distinct spelling."""
        if getattr(self, "_idx_n", -1) == len(self.entities):
            return self._idx
        idx: dict[str, tuple[re.Pattern, list]] = {}
        for e in self.entities:
            forms = [(n, None) for n in e.names] + [
                (v, comp) for comp, vals in e.components.items() for v in vals
            ]
            for value, comp in forms:
                key = " ".join(value.casefold().split())
                if key not in idx:
                    if e.case_sensitive:
                        rx = re.compile(f"{tolerant_pattern(value)}|{tolerant_pattern(value.upper())}")
                    else:
                        rx = re.compile(tolerant_pattern(value), re.I)
                    idx[key] = (rx, [])
                idx[key][1].append((e, comp))
        self._idx, self._idx_n = idx, len(self.entities)
        return idx

    def forms(self) -> set[str]:
        """Every known spelling and name component, folded."""
        return set(self._index())

    def detect(self, text: str) -> list[Span]:
        full, partial = [], []
        for key, (rx, owners) in self._index().items():
            for m in rx.finditer(text):
                (partial if owners[0][1] else full).append((m, key, owners))
        spans = []
        present = set()
        for m, _, owners in full:
            e = owners[0][0]
            present.add(e.id)
            spans.append(Span(m.start(), m.end(), e.type, m.group(), e.id, None))
        # A first/last name shared by several known people binds to whoever is named in
        # full in this text; otherwise it becomes its own pseudo-entity, never a stranger.
        for m, key, owners in partial:
            here = [(e, c) for e, c in owners if e.id in present]
            if here:
                e, comp = here[0]
                spans.append(Span(m.start(), m.end(), e.type, m.group(), e.id, comp))
            elif len({e.id for e, _ in owners}) == 1:
                e, comp = owners[0]
                spans.append(Span(m.start(), m.end(), e.type, m.group(), e.id, comp))
            else:
                e, comp = owners[0]
                spans.append(Span(m.start(), m.end(), e.type, m.group(), f"name:{comp}:{key}", comp))
        return spans


_PRIORITY = {"EMAIL": 0, "IBAN": 1, "EMIRATES_ID": 2, "CARD": 3, "PHONE": 4, "IP": 5, "ACCOUNT": 6}


def resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Keep longest span; on ties prefer full names over components, then pattern priority."""
    ranked = sorted(
        spans,
        key=lambda s: (-(s.end - s.start), s.component is not None, _PRIORITY.get(s.type, 9), s.start),
    )
    taken: list[Span] = []
    for s in ranked:
        if all(s.end <= t.start or s.start >= t.end for t in taken):
            taken.append(s)
    return sorted(taken, key=lambda s: s.start)
