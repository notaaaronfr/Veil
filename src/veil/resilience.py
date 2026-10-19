"""Rate limiting and upstream circuit breaking.

Both are per worker process: with N gunicorn workers the effective client rate limit is
up to N x the configured value. Size limits accordingly (OPERATIONS.md).
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, per_minute: int):
        self.rate = per_minute / 60.0
        self.capacity = max(1.0, float(per_minute))
        self.tokens = self.capacity
        self.t = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> float:
        """0 if allowed, else seconds until a token is available."""
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            return (1 - self.tokens) / self.rate


class RateLimiter:
    def __init__(self):
        self.buckets: dict[str, TokenBucket] = {}

    def check(self, key: str, per_minute: int) -> float:
        if per_minute <= 0:
            return 0.0
        b = self.buckets.get(key)
        if b is None or b.capacity != per_minute:
            b = self.buckets[key] = TokenBucket(per_minute)
        return b.take()


class CircuitBreaker:
    """Opens after `threshold` consecutive failures; while open, requests fail fast for
    `cooldown` seconds, then one trial request is let through (half-open)."""

    def __init__(self, threshold: int = 5, cooldown: float = 30.0):
        self.threshold, self.cooldown = threshold, cooldown
        self.failures = 0
        self.opened_at: float | None = None
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            if self.opened_at is None:
                return True
            if time.monotonic() - self.opened_at >= self.cooldown:
                self.opened_at = time.monotonic()  # half-open: one trial, re-armed on failure
                return True
            return False

    def success(self) -> None:
        with self.lock:
            self.failures, self.opened_at = 0, None

    def failure(self) -> None:
        with self.lock:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_at = time.monotonic()

    @property
    def state(self) -> str:
        if self.opened_at is None:
            return "closed"
        return "open" if time.monotonic() - self.opened_at < self.cooldown else "half-open"
