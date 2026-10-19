"""Step 7: restore from the allowlist of issued surrogates only.

Model-based restoration hallucinates (HaS; Pr∈∈mpt's NER desanitiser missed exotic fake
names). We only ever substitute surrogates this session issued. Tags the model invented
are flagged, never guessed. Models mangle tags (Deußer 2026), so accepted forms include
[PERSON_1], <PERSON 1>, {person-1}, PERSON_1 and possessives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .gate import separated_pattern
from .vault import SessionVault


@dataclass
class RestoreReport:
    restored: int = 0
    hallucinated: list[str] = field(default_factory=list)
    suspected_mangled: list[str] = field(default_factory=list)


def _squash(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", s).upper()


_ARABIC = re.compile(r"[؀-ۿ]")
_LATIN = re.compile(r"[A-Za-z]")


def _pick_surface(surfaces: list[str], m: re.Match) -> str:
    """Choose the spelling whose script matches the surrounding text."""
    if len(surfaces) == 1:
        return surfaces[0]
    # nearest letter wins: left context first (the sentence the tag sits in), then right
    tag = r"[\[<{(][^\]>})]*[\]>})]|[A-Z]+_\d+(?:_[A-Z]+)?"
    left = re.sub(tag, " ", m.string[max(0, m.start() - 60) : m.start()])
    right = re.sub(tag, " ", m.string[m.end() : m.end() + 60])
    letters = [c for c in reversed(left) if _ARABIC.match(c) or _LATIN.match(c)]
    letters += [c for c in right if _ARABIC.match(c) or _LATIN.match(c)]
    if not letters:
        return surfaces[0]
    want_ar = bool(_ARABIC.match(letters[0]))
    for s in surfaces:
        if bool(_ARABIC.search(s)) == want_ar:
            return s
    return surfaces[0]


def restore(text: str, vault: SessionVault) -> tuple[str, RestoreReport]:
    rep = RestoreReport()
    tag_entries = {s: e for s, e in vault.entries.items() if e.kind == "tag"}
    types = sorted({e.type for e in tag_entries.values()}, key=len, reverse=True)

    if types:
        t = "|".join(map(re.escape, types))
        bracketed = re.compile(
            rf"[\[<{{]\s*({t})[ _\-]?(\d+)(?:[ _\-](FIRST|LAST))?\s*[\]>}}]", re.I
        )
        bare = re.compile(rf"(?<![\w\[<{{])({t})_(\d+)(?:_(FIRST|LAST))?(?![\w\]>}}])")

        def sub(m: re.Match) -> str:
            canon = f"[{m.group(1).upper()}_{m.group(2)}" + (
                f"_{m.group(3).upper()}]" if m.group(3) else "]"
            )
            if canon in tag_entries:
                rep.restored += 1
                return _pick_surface(vault.reveal_all(canon), m)
            rep.hallucinated.append(m.group(0))
            return m.group(0)

        text = bracketed.sub(sub, text)
        text = bare.sub(sub, text)
        prose = re.compile(rf"(?<![\w\[<{{(])({t})\s+(\d+)(?![\w\]>}})])", re.I)
        rep.suspected_mangled = [m.group(0) for m in prose.finditer(text)]

    for sur, e in vault.entries.items():
        if e.kind != "fpe":
            continue
        original = vault.reveal(sur)
        rx = re.compile(
            r"(?<![0-9A-Za-z+])\+?" + separated_pattern(_squash(sur)) + r"(?![0-9A-Za-z])", re.I
        )
        text, n = rx.subn(lambda _m, o=original: o, text)
        rep.restored += n
    return text, rep
