"""Client authentication: per-app API keys and Microsoft Entra ID (OIDC) tokens.

API keys: Veil stores only SHA-256 hashes (`veil-admin key new` prints one). A client may
hold several keys at once (rotation) and each key may expire. Keys are sent as `api-key`
or `Authorization: Bearer veil_...`.

Entra ID: `Authorization: Bearer <JWT>`; signature checked against the issuer's JWKS,
plus issuer, audience, expiry and (optionally) the Entra tenant id. The token's
application id (`azp` v2 / `appid` v1) selects the configured client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .tenancy import SCOPES, Client, Config, Tenant


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Principal:
    tenant: Tenant
    client: Client | None  # None = legacy shared key / unauthenticated dev mode
    method: str  # api-key | oidc | legacy-key | unauthenticated

    @property
    def client_id(self) -> str:
        return self.client.id if self.client else self.method

    def can(self, scope: str) -> bool:
        return self.client is None or scope in self.client.scopes


def new_key() -> tuple[str, str]:
    """(key to give the app, sha256 to put in the config)."""
    key = "veil_" + secrets.token_urlsafe(32)
    return key, hash_key(key)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class Authenticator:
    def __init__(self, config: Config):
        self.config = config
        self._by_hash = {k.sha256: (c, k) for c in config.clients.values() for k in c.keys}
        self._by_subject = {s: c for c in config.clients.values() for s in c.oidc_subjects}
        self._jwks = None

    def authenticate(self, headers) -> Principal:
        token = headers.get("api-key") or ""
        auth = headers.get("authorization") or ""
        if not token and auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not token:
            if self.config.allow_unauthenticated and "default" in self.config.tenants:
                return Principal(self.config.tenants["default"], None, "unauthenticated")
            raise AuthError("missing credentials: send a Veil key (api-key header) or an Entra ID bearer token")
        if token.count(".") == 2 and not token.startswith("veil_"):
            return self._oidc(token)
        return self._api_key(token)

    # ------------------------------------------------------------------ API keys

    def _api_key(self, token: str) -> Principal:
        found = self._by_hash.get(hash_key(token))
        if found:
            client, key = found
            if key.expires and key.expires < datetime.now(timezone.utc).date():
                raise AuthError("Veil key expired")
            return Principal(self.config.tenants[client.tenant], client, "api-key")
        if any(hmac.compare_digest(token, k) for k in self.config.legacy_client_keys):
            return Principal(self.config.tenants["default"], None, "legacy-key")
        raise AuthError("invalid Veil key")

    # ------------------------------------------------------------------ Entra ID

    def _jwks_client(self):
        if self._jwks is None:
            import jwt

            o = self.config.oidc
            uri = o.jwks_uri or self._discover_jwks(o.issuer)
            self._jwks = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600)
        return self._jwks

    @staticmethod
    def _discover_jwks(issuer: str) -> str:
        with urllib.request.urlopen(f"{issuer}/.well-known/openid-configuration", timeout=10) as r:
            return json.load(r)["jwks_uri"]

    def _oidc(self, token: str) -> Principal:
        o = self.config.oidc
        if o is None:
            raise AuthError("bearer tokens are not enabled (no oidc section in the Veil config)")
        import jwt

        try:
            key = self._jwks_client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token, key.key, algorithms=["RS256"], audience=o.audience, issuer=o.issuer,
                options={"require": ["exp", "iss", "aud"]}, leeway=60,
            )
        except jwt.PyJWTError as e:
            raise AuthError(f"invalid token: {e}") from None
        if o.tenant_id and claims.get("tid") != o.tenant_id:
            raise AuthError("token issued for a different Entra tenant")
        subject = claims.get("azp") or claims.get("appid")
        client = self._by_subject.get(subject)
        if client is None:
            raise AuthError(f"application {subject!r} is not registered as a Veil client", 403)
        return Principal(self.config.tenants[client.tenant], client, "oidc")


__all__ = ["AuthError", "Authenticator", "Principal", "SCOPES", "hash_key", "new_key"]
