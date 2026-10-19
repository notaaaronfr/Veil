"""veil-admin: operator CLI.

    veil-admin key new                                  new client key + config line (hash only)
    veil-admin config check  -c veil.yaml               validate a config before deploying
    veil-admin ledger verify -c veil.yaml [-t TENANT]   verify hash chain + HMAC certificates
    veil-admin ledger prune  -c veil.yaml [-t TENANT]   apply retention (skips tenants on hold)
    veil-admin hold set|release|status -c veil.yaml -t TENANT [--reason R] [--actor A]
"""

from __future__ import annotations

import argparse
import sys

from .auth import new_key
from .ledger import Ledger
from .tenancy import Config, ConfigError


def _config(path: str) -> Config:
    try:
        return Config.load(path)
    except (ConfigError, OSError, ValueError) as e:
        sys.exit(f"config error: {e}")


def _ledger(cfg: Config, tenant: str) -> Ledger:
    if cfg.ledger is None:
        sys.exit("config has no ledger section")
    if tenant not in cfg.tenants:
        sys.exit(f"unknown tenant {tenant!r}")
    return Ledger(cfg.ledger.dir, tenant, cfg.ledger.hmac_key, cfg.ledger.fsync)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="veil-admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("key").add_subparsers(dest="action", required=True)
    kn = k.add_parser("new")
    kn.add_argument("--expires", help="YYYY-MM-DD")
    for name in ("config", "ledger"):
        p = sub.add_parser(name).add_subparsers(dest="action", required=True)
        for action in (("check",) if name == "config" else ("verify", "prune")):
            a = p.add_parser(action)
            a.add_argument("-c", "--config", required=True)
            if name == "ledger":
                a.add_argument("-t", "--tenant")
    h = sub.add_parser("hold")
    h.add_argument("action", choices=["set", "release", "status"])
    h.add_argument("-c", "--config", required=True)
    h.add_argument("-t", "--tenant", required=True)
    h.add_argument("--reason", default="")
    h.add_argument("--actor", default="")
    a = ap.parse_args(argv)

    if a.cmd == "key":
        key, digest = new_key()
        print(f"key (give to the app once; it is not stored): {key}")
        print("config line:")
        print(f"      - sha256: {digest}" + (f"\n        expires: {a.expires}" if a.expires else ""))
        return 0

    cfg = _config(a.config)
    if a.cmd == "config":
        for tid, t in cfg.tenants.items():
            ups = ", ".join(f"{u.id} ({u.provider}/{u.region or '-'}{', in-branch' if u.in_branch else ''})" for u in t.upstreams.values())
            print(f"tenant {tid}: ceiling={t.ceiling} quasi={len(t.quasi)} types images={t.images} "
                  f"retention={t.retention_days}d red={'local:' + t.red_upstream if t.red_upstream else 'handoff'} upstreams: {ups}")
        for c in cfg.clients.values():
            print(f"client {c.id}: tenant={c.tenant} scopes={','.join(c.scopes)} keys={len(c.keys)} "
                  f"oidc={len(c.oidc_subjects)} rpm={c.rate_limit_rpm or 'unlimited'}")
        print(f"oidc: {'enabled' if cfg.oidc else 'disabled'}   ledger: {cfg.ledger.dir if cfg.ledger else 'DISABLED'}")
        if cfg.ledger is None:
            print("warning: no ledger configured; decisions will not be recorded", file=sys.stderr)
        return 0

    if a.cmd == "ledger":
        tenants = [a.tenant] if a.tenant else list(cfg.tenants)
        failed = False
        for tid in tenants:
            lg = _ledger(cfg, tid)
            if a.action == "verify":
                ok, msg = lg.verify()
                failed |= not ok
                print(f"{tid}: {'OK' if ok else 'FAILED'} {msg}")
            else:
                print(f"{tid}: {lg.prune(cfg.tenants[tid].retention_days)}")
        return 1 if failed else 0

    lg = _ledger(cfg, a.tenant)
    if a.action == "status":
        print(lg.hold())
    else:
        lg.set_hold(a.action == "set", a.reason, a.actor)
        print(f"{a.tenant}: legal hold {'set' if a.action == 'set' else 'released'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
