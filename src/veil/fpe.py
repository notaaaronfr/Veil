"""FF1 format-preserving encryption (NIST SP 800-38G).

FF1 rather than FF3/FF3-1: the second public draft of SP 800-38G Rev.1 withdraws FF3.
Pr∈∈mpt (NDSS 2026) showed format-preserving surrogates keep lookup-task accuracy at
100% where opaque tokens drop to ~71%.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALPHABET36 = "0123456789abcdefghijklmnopqrstuvwxyz"
MIN_DOMAIN = 1_000_000  # SP 800-38G Rev.1: radix**minlen >= 10**6


class FF1:
    def __init__(self, key: bytes, radix: int = 10):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        if not 2 <= radix <= 36:
            raise ValueError("radix must be in 2..36")
        self._ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        self.radix = radix
        self.alphabet = ALPHABET36[:radix]

    def _ciph(self, block: bytes) -> bytes:
        return self._ecb.update(block)

    def _prf(self, data: bytes) -> bytes:
        y = bytes(16)
        for i in range(0, len(data), 16):
            y = self._ciph(bytes(a ^ b for a, b in zip(y, data[i : i + 16])))
        return y

    def _num(self, digits: list[int]) -> int:
        x = 0
        for d in digits:
            x = x * self.radix + d
        return x

    def _str(self, x: int, m: int) -> list[int]:
        out = [0] * m
        for i in range(m - 1, -1, -1):
            x, out[i] = divmod(x, self.radix)
        return out

    def _round_y(self, P: bytes, T: bytes, i: int, num_b: int, b: int, d: int) -> int:
        Q = T + bytes((-len(T) - b - 1) % 16) + bytes([i]) + num_b.to_bytes(b, "big")
        R = self._prf(P + Q)
        S = R
        j = 1
        while len(S) < d:
            S += self._ciph(bytes(a ^ c for a, c in zip(R, j.to_bytes(16, "big"))))
            j += 1
        return int.from_bytes(S[:d], "big")

    def _setup(self, n: int, T: bytes):
        if self.radix**n < MIN_DOMAIN:
            raise ValueError(f"domain radix^{n} below {MIN_DOMAIN}")
        u, v = n // 2, n - n // 2
        b = -(-((self.radix**v - 1).bit_length()) // 8)
        d = 4 * (-(-b // 4)) + 4
        P = (
            bytes([1, 2, 1])
            + self.radix.to_bytes(3, "big")
            + bytes([10, u % 256])
            + n.to_bytes(4, "big")
            + len(T).to_bytes(4, "big")
        )
        return u, v, b, d, P

    def _parse(self, x: str) -> list[int]:
        try:
            return [self.alphabet.index(c) for c in x.lower()]
        except ValueError:
            raise ValueError(f"symbol outside radix-{self.radix} alphabet") from None

    def encrypt(self, x: str, tweak: bytes = b"") -> str:
        X = self._parse(x)
        n = len(X)
        u, v, b, d, P = self._setup(n, tweak)
        A, B = X[:u], X[u:]
        for i in range(10):
            m = u if i % 2 == 0 else v
            y = self._round_y(P, tweak, i, self._num(B), b, d)
            C = self._str((self._num(A) + y) % self.radix**m, m)
            A, B = B, C
        return "".join(self.alphabet[c] for c in A + B)

    def decrypt(self, x: str, tweak: bytes = b"") -> str:
        X = self._parse(x)
        n = len(X)
        u, v, b, d, P = self._setup(n, tweak)
        A, B = X[:u], X[u:]
        for i in range(9, -1, -1):
            m = u if i % 2 == 0 else v
            y = self._round_y(P, tweak, i, self._num(A), b, d)
            C = self._str((self._num(B) - y) % self.radix**m, m)
            A, B = C, A
        return "".join(self.alphabet[c] for c in A + B)


def luhn_check_digit(payload: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(payload)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    return len(number) > 1 and luhn_check_digit(number[:-1]) == number[-1]


def iban_check_digits(country: str, bban: str) -> str:
    rearranged = (bban + country + "00").upper()
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return f"{98 - int(numeric) % 97:02d}"


def iban_valid(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    return iban_check_digits(s[:2], s[4:]) == s[2:4]
