"""Multi-tenant configuration.

One Veil deployment serves several tenants (branches / clients). Each tenant has its own
branch key, dictionary, protection policy, approved upstreams (provider + region +
deployments), tier ceiling, ledger chain and retention. Clients (calling apps) belong to
one tenant and carry their own scopes, upstream subset and rate limit.

The file is YAML (or JSON); see deploy/veil.example.yaml. Without VEIL_CONFIG the legacy
single-tenant environment variables (VEIL_UPSTREAM_URL, ...) become tenant "default".
Secrets are always referenced by *_file paths, never inlined.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .config import Settings, load_dictionary, parse_quasi
from .detect import BranchDictionary

TIERS = ("green", "amber", "red")

# Last valid configuration, set by the gunicorn master (gunicorn_conf) at start and on each
# SIGHUP. Workers are forked from the master and inherit it, so a broken or half-written
# config file on reload is logged and ignored instead of taking the service down.
_ACTIVE: "Config | None" = None


def active_config() -> "Config":
    return _ACTIVE if _ACTIVE is not None else Config.from_env()


def load_active() -> "Config":
    """(Re)load from the environment; on success it becomes the active config."""
    global _ACTIVE
    _ACTIVE = Config.from_env()
    return _ACTIVE
SCOPES = ("chat", "embeddings")


class ConfigError(ValueError):
    pass


def _read_secret(path: str | None, what: str) -> str:
    if not path:
        raise ConfigError(f"{what}: missing *_file path")
    try:
        return Path(path).read_text().strip()
    except OSError as e:
        raise ConfigError(f"{what}: cannot read {path}: {e}") from None


@dataclass
class Upstream:
    id: str
    provider: str  # azure-openai | openai | customer-hosted
    url: str
    key: str
    auth: str = "api-key"  # api-key | bearer | none
    region: str = ""
    deployments: tuple[str, ...] = ()
    in_branch: bool = False  # verified to run inside the branch: may receive Red-tier traffic


@dataclass
class ClientKey:
    sha256: str
    expires: date | None = None


@dataclass
class Client:
    id: str
    tenant: str
    keys: list[ClientKey] = field(default_factory=list)
    scopes: tuple[str, ...] = SCOPES
    upstreams: tuple[str, ...] = ()  # empty = all of the tenant's upstreams
    rate_limit_rpm: int = 0  # 0 = unlimited
    oidc_subjects: tuple[str, ...] = ()  # Entra application (client) IDs mapped to this client


@dataclass
class Tenant:
    id: str
    branch_key: bytes
    upstreams: dict[str, Upstream]
    dictionary: BranchDictionary | None = None
    quasi: frozenset = frozenset()
    images: str = "drop"
    default_label: str = "amber"  # classification when the app sends none
    ceiling: str = "amber"  # highest tier allowed to leave the branch
    red_types: frozenset = frozenset()  # detected types that force Red (e.g. HEALTH)
    red_upstream: str | None = None  # in-branch upstream for Red; None = hand off to a person
    handoff_webhook: str | None = None
    retention_days: int = 365


@dataclass
class OIDC:
    issuer: str
    audience: str
    jwks_uri: str = ""
    tenant_id: str = ""  # Entra directory ID; checked against the "tid" claim when set


@dataclass
class LedgerConfig:
    dir: str
    hmac_key: bytes
    fsync: bool = True


@dataclass
class Config:
    tenants: dict[str, Tenant]
    clients: dict[str, Client]
    oidc: OIDC | None = None
    ledger: LedgerConfig | None = None
    allow_unauthenticated: bool = False  # development only: unauthenticated callers act as tenant "default"
    legacy_client_keys: set[str] = field(default_factory=set)  # plain keys from VEIL_CLIENT_KEYS (single tenant)

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_env(cls) -> "Config":
        path = os.environ.get("VEIL_CONFIG")
        if path:
            return cls.load(path)
        return cls.from_settings(Settings.from_env())

    @classmethod
    def from_settings(cls, s: Settings) -> "Config":
        """Legacy single-tenant mode: the VEIL_* environment variables become tenant "default"."""
        up = Upstream("default", "azure-openai", s.upstream_url, s.upstream_key, s.upstream_auth)
        tenant = Tenant("default", s.branch_key, {"default": up}, s.dictionary, s.quasi, s.images)
        return cls({"default": tenant}, {}, allow_unauthenticated=s.allow_unauthenticated,
                   legacy_client_keys=set(s.client_keys))

    @classmethod
    def load(cls, path: str) -> "Config":
        text = Path(path).read_text()
        if path.endswith(".json"):
            raw = json.loads(text)
        else:
            import yaml

            raw = yaml.safe_load(text)
        return cls.parse(raw or {})

    @classmethod
    def parse(cls, raw: dict) -> "Config":
        tenants = {tid: _tenant(tid, t or {}) for tid, t in (raw.get("tenants") or {}).items()}
        if not tenants:
            raise ConfigError("config defines no tenants")
        clients = {}
        for c in raw.get("clients") or []:
            cl = _client(c, tenants)
            if cl.id in clients:
                raise ConfigError(f"duplicate client id {cl.id!r}")
            clients[cl.id] = cl
        oidc = None
        if raw.get("oidc"):
            o = raw["oidc"]
            if not o.get("issuer") or not o.get("audience"):
                raise ConfigError("oidc: issuer and audience are required")
            oidc = OIDC(o["issuer"].rstrip("/"), o["audience"], o.get("jwks_uri", ""), o.get("tenant_id", ""))
        ledger = None
        if raw.get("ledger"):
            lg = raw["ledger"]
            key = bytes.fromhex(_read_secret(lg.get("hmac_key_file"), "ledger.hmac_key_file"))
            if len(key) < 32:
                raise ConfigError("ledger HMAC key must be at least 32 bytes (64 hex chars)")
            ledger = LedgerConfig(lg.get("dir", "/var/lib/veil/ledger"), key, bool(lg.get("fsync", True)))
        return cls(tenants, clients, oidc, ledger, bool(raw.get("allow_unauthenticated", False)))

    # ------------------------------------------------------------------ routing

    def route(self, tenant: Tenant, client: Client | None, deployment: str | None, prefer: str | None = None) -> Upstream | None:
        """The approved upstream for this deployment, or None (= refuse, never forward)."""
        allowed = [u for uid, u in tenant.upstreams.items() if client is None or not client.upstreams or uid in client.upstreams]
        if prefer:
            allowed = [u for u in allowed if u.id == prefer]
        for u in allowed:
            if not u.deployments or (deployment and deployment in u.deployments):
                if not u.in_branch or tenant.red_upstream != u.id:  # Red-only upstream is not a normal route
                    return u
        return None


def _tier(value: str, what: str) -> str:
    v = (value or "").lower()
    if v not in TIERS:
        raise ConfigError(f"{what} must be one of {TIERS}, got {value!r}")
    return v


def _tenant(tid: str, t: dict) -> Tenant:
    key_hex = _read_secret(t.get("branch_key_file"), f"tenant {tid}: branch_key_file")
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise ConfigError(f"tenant {tid}: branch key must be 32 bytes (64 hex chars)")
    ups = {}
    for uid, u in (t.get("upstreams") or {}).items():
        auth = u.get("auth", "api-key")
        ups[uid] = Upstream(
            id=uid,
            provider=u.get("provider", "azure-openai"),
            url=u["url"].rstrip("/"),
            key="" if auth == "none" else _read_secret(u.get("key_file"), f"tenant {tid} upstream {uid}: key_file"),
            auth=auth,
            region=u.get("region", ""),
            deployments=tuple(u.get("deployments") or ()),
            in_branch=bool(u.get("in_branch", False)),
        )
    if not ups:
        raise ConfigError(f"tenant {tid}: no upstreams approved")
    red = t.get("red_upstream")
    if red and (red not in ups or not ups[red].in_branch):
        raise ConfigError(f"tenant {tid}: red_upstream {red!r} must be an upstream with in_branch: true")
    images = (t.get("images") or "drop").lower()
    if images not in ("drop", "pass"):
        raise ConfigError(f"tenant {tid}: images must be drop or pass")
    return Tenant(
        id=tid,
        branch_key=key,
        upstreams=ups,
        dictionary=load_dictionary(t.get("dictionary_file")),
        quasi=parse_quasi(str(t.get("quasi", "all"))),
        images=images,
        default_label=_tier(t.get("default_label", "amber"), f"tenant {tid}: default_label"),
        ceiling=_tier(t.get("ceiling", "amber"), f"tenant {tid}: ceiling"),
        red_types=frozenset(x.upper() for x in t.get("red_types") or ()),
        red_upstream=red,
        handoff_webhook=t.get("handoff_webhook"),
        retention_days=int(t.get("retention_days", 365)),
    )


def _client(c: dict, tenants: dict[str, Tenant]) -> Client:
    cid = c.get("id")
    if not cid:
        raise ConfigError("client without id")
    tenant = c.get("tenant")
    if tenant not in tenants:
        raise ConfigError(f"client {cid}: unknown tenant {tenant!r}")
    scopes = tuple(c.get("scopes") or SCOPES)
    bad = set(scopes) - set(SCOPES)
    if bad:
        raise ConfigError(f"client {cid}: unknown scopes {sorted(bad)}")
    ups = tuple(c.get("upstreams") or ())
    unknown = set(ups) - set(tenants[tenant].upstreams)
    if unknown:
        raise ConfigError(f"client {cid}: upstreams {sorted(unknown)} not approved for tenant {tenant}")
    keys = []
    for k in c.get("keys") or []:
        h = k.get("sha256", "")
        if len(h) != 64:
            raise ConfigError(f"client {cid}: key sha256 must be 64 hex chars")
        exp = k.get("expires")
        keys.append(ClientKey(h.lower(), date.fromisoformat(str(exp)) if exp else None))
    return Client(cid, tenant, keys, scopes, ups, int(c.get("rate_limit_rpm", 0)), tuple(c.get("oidc_subjects") or ()))
