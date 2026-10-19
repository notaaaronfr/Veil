"""Append-only, hash-chained, HMAC-certified decision ledger (one chain per tenant).

Every request produces one record of APPROVED FIELDS ONLY (allow-list below): who called,
which upstream/provider/region, tier decision, counts by entity type, timings, status.
Never prompt text, never values.

    record.prev = hash of the previous record
    record.hash = sha256(prev || canonical-json(record without hash/mac))
    record.mac  = HMAC-SHA256(ledger key, hash)       -> "certified": editing the files is
                                                         not enough to forge a valid chain

Layout:  <dir>/<tenant>/YYYY-MM-DD.jsonl  (day segments), head.json (last seq/hash),
         anchor.json (chain start after retention pruning), hold.json (legal hold), .lock
Appends from several gunicorn workers are serialised with flock and fsynced.

Retention: segments older than the tenant's retention_days are deleted unless a legal
hold is active; the prune itself is recorded in the chain and the anchor keeps the chain
verifiable from the first retained record.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

GENESIS = "0" * 64

# The only fields a record may carry. Anything else is dropped before writing.
APPROVED_FIELDS = {
    "event", "request_id", "tenant", "client", "auth", "route", "deployment", "upstream", "provider",
    "region", "tier_label", "tier_effective", "decision", "reason", "detected", "generalised", "scrubbed",
    "redacted", "degraded", "dropped_images", "unprotected_images", "upstream_status", "protect_ms",
    "upstream_ms", "restored", "hallucinated_tags", "stream", "handoff_id", "veil_version",
    "pruned_through_seq", "pruned_segments", "hold_reason", "actor",
}


def _canonical(rec: dict) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _approved(fields: dict) -> dict:
    out = {}
    for k, v in fields.items():
        if k not in APPROVED_FIELDS or v is None:
            continue
        if k == "detected":  # type -> count only
            v = {str(t): int(n) for t, n in dict(v).items()}
        out[k] = v
    return out


class Ledger:
    def __init__(self, root: str, tenant: str, key: bytes, fsync: bool = True):
        self.dir = Path(root) / tenant
        self.dir.mkdir(parents=True, exist_ok=True)
        self.tenant = tenant
        self.key = key
        self.fsync = fsync

    # ------------------------------------------------------------------ locking / state

    @contextmanager
    def _locked(self):
        with open(self.dir / ".lock", "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def _read_json(self, name: str, default):
        p = self.dir / name
        return json.loads(p.read_text()) if p.exists() else default

    def _write_json(self, name: str, obj) -> None:
        tmp = self.dir / f".{name}.tmp"
        tmp.write_text(json.dumps(obj))
        if self.fsync:
            with open(tmp, "rb+") as f:
                os.fsync(f.fileno())
        os.replace(tmp, self.dir / name)

    def head(self) -> dict:
        return self._read_json("head.json", self._read_json("anchor.json", {"seq": 0, "hash": GENESIS}))

    # ------------------------------------------------------------------ append

    def append(self, **fields) -> dict:
        rec = _approved(fields)
        rec.setdefault("event", "request")
        with self._locked():
            head = self.head()
            rec["seq"] = head["seq"] + 1
            rec["ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            rec["tenant"] = self.tenant
            rec["prev"] = head["hash"]
            digest = hashlib.sha256(rec["prev"].encode() + _canonical(rec)).hexdigest()
            rec["hash"] = digest
            rec["mac"] = hmac.new(self.key, digest.encode(), hashlib.sha256).hexdigest()
            seg = self.dir / f"{rec['ts'][:10]}.jsonl"
            with open(seg, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                if self.fsync:
                    os.fsync(f.fileno())
            self._write_json("head.json", {"seq": rec["seq"], "hash": digest})
        return rec

    # ------------------------------------------------------------------ verify

    def segments(self) -> list[Path]:
        return sorted(p for p in self.dir.glob("????-??-??.jsonl"))

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain from the anchor. Returns (ok, message)."""
        anchor = self._read_json("anchor.json", {"seq": 0, "hash": GENESIS})
        prev, seq, n = anchor["hash"], anchor["seq"], 0
        for seg in self.segments():
            for lineno, line in enumerate(seg.read_text(encoding="utf-8").splitlines(), 1):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"{seg.name}:{lineno}: not valid JSON"
                body = {k: v for k, v in rec.items() if k not in ("hash", "mac")}
                if rec.get("seq") != seq + 1:
                    return False, f"{seg.name}:{lineno}: sequence gap (expected {seq + 1}, found {rec.get('seq')})"
                if rec.get("prev") != prev:
                    return False, f"{seg.name}:{lineno}: seq {rec['seq']} does not link to the previous record"
                digest = hashlib.sha256(prev.encode() + _canonical(body)).hexdigest()
                if digest != rec.get("hash"):
                    return False, f"{seg.name}:{lineno}: seq {rec['seq']} content was altered"
                mac = hmac.new(self.key, digest.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(mac, rec.get("mac", "")):
                    return False, f"{seg.name}:{lineno}: seq {rec['seq']} certificate (HMAC) invalid"
                prev, seq, n = digest, rec["seq"], n + 1
        head = self.head()
        if (head["seq"], head["hash"]) != (seq, prev):
            return False, f"head.json says seq {head['seq']} but the chain ends at seq {seq} (records deleted?)"
        return True, f"ok: {n} records verified (seq {anchor['seq'] + 1}..{seq})"

    # ------------------------------------------------------------------ legal hold / retention

    def hold(self) -> dict:
        return self._read_json("hold.json", {"active": False})

    def set_hold(self, active: bool, reason: str = "", actor: str = "") -> None:
        with self._locked():
            self._write_json("hold.json", {"active": active, "reason": reason, "actor": actor,
                                           "since": datetime.now(timezone.utc).isoformat()})
        self.append(event="legal_hold_set" if active else "legal_hold_released", hold_reason=reason, actor=actor)

    def prune(self, retention_days: int, today: date | None = None, actor: str = "retention") -> dict:
        """Delete whole day segments older than retention_days, unless a legal hold is active."""
        if self.hold().get("active"):
            return {"pruned": 0, "skipped": "legal hold active"}
        today = today or datetime.now(timezone.utc).date()
        cutoff = today - timedelta(days=retention_days)
        old = [s for s in self.segments() if date.fromisoformat(s.stem) < cutoff]
        if not old:
            return {"pruned": 0}
        with self._locked():
            if self.hold().get("active"):  # re-check under the lock
                return {"pruned": 0, "skipped": "legal hold active"}
            last = json.loads(old[-1].read_text(encoding="utf-8").splitlines()[-1])
            self._write_json("anchor.json", {"seq": last["seq"], "hash": last["hash"], "set": time.time()})
            for s in old:
                s.unlink()
        self.append(event="retention_prune", pruned_through_seq=last["seq"], pruned_segments=len(old), actor=actor)
        return {"pruned": len(old), "through_seq": last["seq"]}


class Ledgers:
    """One Ledger per tenant, created on first use."""

    def __init__(self, root: str, key: bytes, fsync: bool = True):
        self.root, self.key, self.fsync = root, key, fsync
        self._by_tenant: dict[str, Ledger] = {}

    def __getitem__(self, tenant: str) -> Ledger:
        if tenant not in self._by_tenant:
            self._by_tenant[tenant] = Ledger(self.root, tenant, self.key, self.fsync)
        return self._by_tenant[tenant]
