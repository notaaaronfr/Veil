"""Restore surrogates in a streamed reply without splitting them.

A surrogate can arrive across chunks ("[PERS" + "ON_1]", "+971 50 7" + "63 0505"). We
release everything except a tail that could still be the start of one, restore the
released part, and flush the rest at the end of the stream. The extra latency is at most
one word or one number.
"""

from __future__ import annotations

import re

from .gate import separated_pattern
from .restore import RestoreReport, restore
from .vault import SessionVault

_OPEN_TAG = re.compile(r"[\[<{][^\]>}]{0,48}$")  # unclosed bracket near the end
_TRAILING_WORD = re.compile(r"[A-Za-z0-9_]{1,40}$")  # could be a bare tag such as PERSON_1_FI...
# could be a format-preserved number, including an IBAN's country prefix ("AE50 7368 ...")
# a lone trailing "+" too: releasing it early would double it when "+971..." is restored
_TRAILING_NUMBER = re.compile(r"(?:\b[A-Z]{1,2}\d{0,2}[ A-Z0-9]{0,36}|\+(?:\d[\d \-().]{0,40})?|\d[\d \-().]{0,40})$")


_TAG = re.compile(r"[\[<{]?[A-Za-z]+(?:_[A-Za-z]+)*[ _\-]?\d+(?:[ _\-](?:FIRST|LAST))?[\]>}]?", re.I)


class StreamRestorer:
    def __init__(self, vault: SessionVault):
        self.vault = vault
        self.buffer = ""
        self.report = RestoreReport()
        # the exact surrogates this session issued, as separator-tolerant patterns
        self._issued = [
            re.compile(r"\+?" + separated_pattern(re.sub(r"[^0-9A-Za-z]", "", s)), re.I)
            for s, e in vault.entries.items()
            if e.kind == "fpe"
        ]

    def _safe_cut(self) -> int:
        # 1. tails that could still become a surrogate
        cut = len(self.buffer)
        for rx in (_OPEN_TAG, _TRAILING_WORD, _TRAILING_NUMBER):
            m = rx.search(self.buffer)
            if m:
                cut = min(cut, m.start())
        # 2. never cut through a surrogate that has fully arrived (e.g. "AE13...595. " where
        #    the number rule alone would cut between "AE" and the digits)
        moved = True
        while moved:
            moved = False
            for rx in self._issued + [_TAG]:
                for m in rx.finditer(self.buffer):
                    if m.start() < cut < m.end():
                        cut, moved = m.start(), True
        return cut

    def _restore(self, text: str) -> str:
        out, rep = restore(text, self.vault)
        self.report.restored += rep.restored
        self.report.hallucinated += rep.hallucinated
        self.report.suspected_mangled += rep.suspected_mangled
        return out

    def feed(self, text: str) -> str:
        self.buffer += text
        cut = self._safe_cut()
        ready, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return self._restore(ready) if ready else ""

    def flush(self) -> str:
        ready, self.buffer = self.buffer, ""
        return self._restore(ready) if ready else ""
