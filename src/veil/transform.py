"""Step 3: replace detected spans with surrogates.

- Dictionary entities and free-text types -> indexed typed tags, with component tags
  [PERSON_1_FIRST] / [PERSON_1_LAST] so every way of referring to a person maps to the
  same index (Deußer 2026, Pasch & Cha 2025: indexed tags >= surrogates on utility).
- Structured identifiers -> FF1 surrogates that keep layout and valid checksums
  (Pr∈∈mpt, NDSS 2026). Falls back to a tag if the domain is below the NIST minimum.
"""

from __future__ import annotations

import re

from .detect import Span
from .fpe import FF1, iban_check_digits, luhn_check_digit
from .vault import SessionVault

FPE_TYPES = {"EMIRATES_ID", "CARD", "PHONE", "IBAN", "ACCOUNT", "SSN", "NATIONAL_ID"}
# Generalised, not tagged: the coarse value keeps the task working (DR-SL 2026: generalising
# keeps ~2x the utility of placeholders at equal leakage). Not restored.
GENERALISE_TYPES = {"AGE", "DOB"}

_WORD_NUM = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
    "sixteen seventeen eighteen nineteen".split())}
_WORD_NUM |= {w: 10 * i for i, w in enumerate("_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()) if w != "_"}


def _parse_number(text: str) -> int | None:
    m = re.search(r"\d{1,3}", text)
    if m:
        return int(m.group())
    words = re.findall(r"[a-z]+", text.lower())
    nums = [_WORD_NUM[w] for w in words if w in _WORD_NUM]
    return sum(nums) if nums else None


def generalise(type_: str, value: str) -> str:
    if type_ == "AGE":
        n = _parse_number(value)
        if n is None or not 0 < n < 120:
            return "an adult"
        band = "under 10" if n < 10 else "teenage" if n < 20 else f"{n // 10 * 10}-something"
        # keep the surrounding words: "52-year-old" -> "50-something-year-old", "aged 52" -> "aged 50-something"
        units = "one|two|three|four|five|six|seven|eight|nine"
        m = re.search(rf"\d{{1,3}}|(?:{'|'.join(sorted(_WORD_NUM, key=len, reverse=True))})(?:[- ](?:{units}))?", value, re.I)
        return value[: m.start()] + band + value[m.end():] if m and n >= 20 else band
    if type_ == "DOB":
        y = re.search(r"(19|20)\d{2}", value)
        if not y:
            return "a date"
        decade = int(y.group()) // 10 * 10
        return f"the {decade}s" if value.strip() == y.group() else f"a date in the {decade}s"
    return value


def norm_key(span: Span) -> str:
    if span.entity_id:
        return f"{span.entity_id}:{span.component or ''}"
    if span.type in FPE_TYPES:
        return re.sub(r"[^0-9A-Za-z]", "", span.value).upper()
    return " ".join(span.value.casefold().split())


def _render(surface: str, new_alnum: str) -> str:
    it = iter(new_alnum)
    return "".join(next(it) if c.isalnum() else c for c in surface)


class Transformer:
    def __init__(self, vault: SessionVault):
        self.vault = vault
        self._ff10 = FF1(vault.fpe_key, 10)
        self._ff36 = FF1(vault.fpe_key, 36)
        self._counters: dict[str, int] = {}
        self._entity_index: dict[tuple[str, str], int] = {}
        self._originals: set[str] = set()
        self.generalised = 0

    def _next(self, type_: str) -> int:
        self._counters[type_] = self._counters.get(type_, 0) + 1
        return self._counters[type_]

    def _tag(self, span: Span) -> str:
        if span.entity_id:
            key = (span.type, span.entity_id)
            if key not in self._entity_index:
                self._entity_index[key] = self._next(span.type)
            n = self._entity_index[key]
            return f"[{span.type}_{n}_{span.component}]" if span.component else f"[{span.type}_{n}]"
        return f"[{span.type}_{self._next(span.type)}]"

    def _fpe(self, span: Span) -> str | None:
        raw = re.sub(r"[^0-9A-Za-z]", "", span.value).upper()
        tweak = span.type.encode()
        try:
            if span.type == "EMIRATES_ID":
                body = "784" + self._ff10.encrypt(raw[3:14], tweak)
                new = body + luhn_check_digit(body)
            elif span.type == "CARD":
                body = raw[0] + self._ff10.encrypt(raw[1:-1], tweak)
                new = body + luhn_check_digit(body)
            elif span.type == "PHONE":
                # keep country + operator/area code so a mobile stays a mobile
                if raw.startswith("00971"):
                    keep = 7 if raw[5] == "5" else 6
                elif raw.startswith("971"):
                    keep = 5 if raw[3] == "5" else 4
                elif raw.startswith("0"):
                    keep = 3 if raw[1] == "5" else 2
                else:
                    keep = 2
                new = raw[:keep] + self._ff10.encrypt(raw[keep:], tweak)
            elif span.type in ("ACCOUNT", "SSN", "NATIONAL_ID"):
                new = self._ff10.encrypt(raw, tweak)
            elif span.type == "IBAN":
                cc, bban = raw[:2], raw[4:]
                f = self._ff10 if bban.isdigit() else self._ff36
                nb = f.encrypt(bban.lower(), tweak).upper()
                new = cc + iban_check_digits(cc, nb) + nb
            else:
                return None
        except ValueError:  # domain below NIST minimum
            return None
        if new == raw or new in self._originals:
            return None
        return _render(span.value, new)

    def surrogate_for(self, span: Span) -> str:
        if span.type in GENERALISE_TYPES:
            self.generalised += 1
            return generalise(span.type, span.value)
        key = norm_key(span)
        existing = self.vault.lookup_surrogate(span.type, key)
        if existing:
            if self.vault.entries[existing].kind == "tag":
                self.vault.add_surface(existing, span.value)
            return existing
        self._originals.add(re.sub(r"[^0-9A-Za-z]", "", span.value).upper())
        sur = self._fpe(span) if span.type in FPE_TYPES else None
        kind = "fpe" if sur else "tag"
        sur = sur or self._tag(span)
        self.vault.put(sur, span.type, kind, span.value, key)
        return sur

    def apply(self, text: str, spans: list[Span]) -> str:
        # register every original first so FPE output can't collide with a value in the text
        for s in spans:
            if s.type in FPE_TYPES:
                self._originals.add(re.sub(r"[^0-9A-Za-z]", "", s.value).upper())
        # assign left to right so numbering and default spelling follow reading order
        subs = [(s, self.surrogate_for(s)) for s in sorted(spans, key=lambda s: s.start)]
        out = text
        for s, sur in reversed(subs):
            out = out[: s.start] + sur + out[s.end :]
        return out
