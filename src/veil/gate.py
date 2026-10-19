"""Step 6: egress hard line.

DR-SL (2026) found 159/160 "protected" outputs still carried literal values because
span replacement missed repeat mentions. This check runs on the FINAL outbound payload
and searches for every original value in the session, normalised, at every occurrence.
Reports carry types and surrogates only, never values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import tolerant_pattern
from .detect import BranchDictionary, Span
from .vault import SessionVault


def separated_pattern(key: str) -> str:
    """Match `key` with up to two separator chars between any two of its characters."""
    return r"[ \-.()/]{0,2}".join(map(re.escape, key))


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    type: str
    surrogate: str | None  # known vault entry, or None for a dictionary hit
    span: Span | None = None


def _squash(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", s).upper()


_TAG = re.compile(r"\[[A-Z]+(?:_[A-Z]+)*_\d+(?:_(?:FIRST|LAST))?\]|\[REDACTED\]")


def find_leaks(text: str, vault: SessionVault, dictionaries: list[BranchDictionary] = ()) -> list[Hit]:
    # Our own tags are not leaks: blank them out (same length, offsets preserved) so an
    # original like "email" can't match inside "[EMAIL_1]" and loop the scrubber.
    text = _TAG.sub(lambda m: " " * len(m.group()), text)
    hits: list[Hit] = []
    for entry, original in vault.items():
        if entry.type in ("EMIRATES_ID", "CARD", "PHONE", "IBAN", "ACCOUNT", "SSN", "NATIONAL_ID") and sum(
            c.isalnum() for c in original
        ) >= 6 and any(c.isdigit() for c in original):
            key = _squash(original)
            if entry.type == "PHONE":
                key = key[-9:]  # subscriber part, whatever prefix the text uses
            for m in re.finditer(separated_pattern(key), text, re.I):
                hits.append(Hit(m.start(), m.end(), entry.type, entry.surrogate))
        elif entry.type == "EMAIL":
            local = original.split("@")[0]
            for needle in {original, local} if len(local) >= 4 else {original}:
                for m in re.finditer(re.escape(needle), text, re.I):
                    hits.append(Hit(m.start(), m.end(), entry.type, entry.surrogate))
        else:
            for m in re.finditer(tolerant_pattern(original), text, re.I):
                hits.append(Hit(m.start(), m.end(), entry.type, entry.surrogate))
    for d in dictionaries:
        for s in d.detect(text):
            hits.append(Hit(s.start, s.end, s.type, None, s))
    return hits
