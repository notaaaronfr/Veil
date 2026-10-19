"""Per-session mapping vault.

Session keys come from HKDF-SHA256(branch_key, salt=session_id), so sessions are
unlinkable and a leaked session key exposes one session only (BodhiPromptShield blast-
radius analysis). Original values are held AES-256-GCM encrypted in memory and only
decrypted on lookup.

Limit: CPython cannot guarantee immutable `str` copies are zeroed. The production vault
should be Rust/C with mlock + zeroize ("The Illusion of Local Privacy", 2026).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class Entry:
    surrogate: str
    type: str
    kind: str  # "tag" or "fpe"


class SessionVault:
    def __init__(self, branch_key: bytes, session_id: str):
        okm = HKDF(
            algorithm=hashes.SHA256(), length=64, salt=session_id.encode(), info=b"sandwich/v1"
        ).derive(branch_key)
        self._keys = bytearray(okm)
        self._aead = AESGCM(bytes(self._keys[:32]))
        self._sealed: dict[str, list[tuple[bytes, bytes]]] = {}
        self._by_value: dict[tuple[str, str], str] = {}  # (type, normalised value) -> surrogate
        self.entries: dict[str, Entry] = {}
        self.closed = False

    @property
    def fpe_key(self) -> bytes:
        self._check()
        return bytes(self._keys[32:])

    def _check(self):
        if self.closed:
            raise RuntimeError("vault closed")

    def lookup_surrogate(self, type_: str, norm_value: str) -> str | None:
        return self._by_value.get((type_, norm_value))

    def _seal(self, surrogate: str, type_: str, value: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, self._aead.encrypt(nonce, value.encode(), f"{type_}|{surrogate}".encode())

    def put(self, surrogate: str, type_: str, kind: str, original: str, norm_value: str) -> None:
        self._check()
        self._sealed[surrogate] = [self._seal(surrogate, type_, original)]
        self.entries[surrogate] = Entry(surrogate, type_, kind)
        self._by_value[(type_, norm_value)] = surrogate

    def add_surface(self, surrogate: str, surface: str) -> None:
        """Another spelling of the same value (e.g. Arabic script). First spelling is the default."""
        self._check()
        if surface not in self.reveal_all(surrogate):
            self._sealed[surrogate].append(self._seal(surrogate, self.entries[surrogate].type, surface))

    def reveal_all(self, surrogate: str) -> list[str]:
        self._check()
        e = self.entries.get(surrogate)
        if e is None:
            return []
        aad = f"{e.type}|{surrogate}".encode()
        return [self._aead.decrypt(n, c, aad).decode() for n, c in self._sealed[surrogate]]

    def reveal(self, surrogate: str) -> str | None:
        vals = self.reveal_all(surrogate)
        return vals[0] if vals else None

    def items(self):
        """Every (entry, original spelling) pair — the egress check must see all spellings."""
        for s, e in self.entries.items():
            for v in self.reveal_all(s):
                yield e, v

    def close(self) -> None:
        for i in range(len(self._keys)):
            self._keys[i] = 0
        self._sealed.clear()
        self._by_value.clear()
        self.entries.clear()
        self._aead = None
        self.closed = True
