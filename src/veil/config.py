"""Proxy configuration, from environment variables only (12-factor; secrets from files).

Required in production:
  VEIL_UPSTREAM_URL         e.g. https://<resource>.openai.azure.com  (Azure OpenAI, UAE North)
  VEIL_UPSTREAM_KEY_FILE    file holding the upstream API key (or VEIL_UPSTREAM_KEY)
  VEIL_BRANCH_KEY_FILE      file holding the 32-byte branch key, hex (or VEIL_BRANCH_KEY)
  VEIL_CLIENT_KEYS_FILE     one client key per line (or VEIL_CLIENT_KEYS, comma-separated)
Optional:
  VEIL_UPSTREAM_AUTH        "api-key" (Azure, default) | "bearer"
  VEIL_DICTIONARY_FILE      JSON list of {"id", "type", "names": [...]} known entities
  VEIL_NER                  1 (default) | 0
  VEIL_DEVICE               cpu (default) | cuda | mps
  VEIL_QUASI                quasi-identifiers to protect: "all" (default), "none", or a comma
                            list of AGE,DOB,LOCATION,OCCUPATION,ORG,NATIONALITY,ETHNICITY,RELIGION,
                            MARITAL,HEALTH,EDUCATION,CITIZENSHIP,EMPLOYMENT
  VEIL_IMAGES               drop (default: image parts replaced by a text note) | pass
  VEIL_CONTEXT              0 (default) | 1   local-LLM context guard (phase 3)
  VEIL_CONTEXT_BUDGET       seconds, default 8; over budget -> phase-2 output is sent
  VEIL_UPSTREAM_TIMEOUT     seconds, default 120
  VEIL_MAX_BODY_BYTES       default 4 MiB
  VEIL_ALLOW_UNAUTHENTICATED  1 only for local development
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .detect import BranchDictionary, Entity


def _secret(name: str, required: bool = True) -> str | None:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text().strip()
    value = os.environ.get(name)
    if value is None and required:
        raise RuntimeError(f"missing {name} or {name}_FILE")
    return value


def _flag(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    upstream_url: str
    upstream_key: str
    branch_key: bytes
    client_keys: set[str] = field(default_factory=set)
    upstream_auth: str = "api-key"
    dictionary: BranchDictionary | None = None
    ner: bool = True
    device: str = "cpu"
    context: bool = False
    context_budget: float = 8.0
    upstream_timeout: float = 120.0
    max_body_bytes: int = 4 * 1024 * 1024
    allow_unauthenticated: bool = False
    quasi: frozenset = frozenset()
    images: str = "drop"

    @classmethod
    def from_env(cls) -> "Settings":
        allow_unauth = _flag("VEIL_ALLOW_UNAUTHENTICATED", False)
        keys_raw = _secret("VEIL_CLIENT_KEYS", required=not allow_unauth) or ""
        client_keys = {k.strip() for k in keys_raw.replace(",", "\n").splitlines() if k.strip()}
        branch_key = bytes.fromhex(_secret("VEIL_BRANCH_KEY"))
        if len(branch_key) != 32:
            raise RuntimeError("VEIL_BRANCH_KEY must be 32 bytes (64 hex characters)")
        return cls(
            upstream_url=os.environ["VEIL_UPSTREAM_URL"].rstrip("/"),
            upstream_key=_secret("VEIL_UPSTREAM_KEY"),
            branch_key=branch_key,
            client_keys=client_keys,
            upstream_auth=os.environ.get("VEIL_UPSTREAM_AUTH", "api-key"),
            dictionary=load_dictionary(os.environ.get("VEIL_DICTIONARY_FILE")),
            ner=_flag("VEIL_NER", True),
            device=os.environ.get("VEIL_DEVICE", "cpu"),
            context=_flag("VEIL_CONTEXT", False),
            context_budget=float(os.environ.get("VEIL_CONTEXT_BUDGET", "8")),
            upstream_timeout=float(os.environ.get("VEIL_UPSTREAM_TIMEOUT", "120")),
            max_body_bytes=int(os.environ.get("VEIL_MAX_BODY_BYTES", str(4 * 1024 * 1024))),
            allow_unauthenticated=allow_unauth,
            quasi=parse_quasi(os.environ.get("VEIL_QUASI", "all")),
            images=_choice("VEIL_IMAGES", ("drop", "pass"), "drop"),
        )


def _choice(name: str, allowed: tuple, default: str) -> str:
    v = os.environ.get(name, default).strip().lower()
    if v not in allowed:
        raise RuntimeError(f"{name} must be one of {allowed}")
    return v


def parse_quasi(value: str) -> frozenset:
    from .ner import QUASI_TYPES

    v = value.strip().upper()
    if v in ("", "NONE", "0", "OFF"):
        return frozenset()
    if v in ("ALL", "1", "ON"):
        return frozenset(QUASI_TYPES)
    types = {t.strip() for t in v.split(",") if t.strip()}
    unknown = types - set(QUASI_TYPES)
    if unknown:
        raise RuntimeError(f"VEIL_QUASI: unknown types {sorted(unknown)}; choose from {QUASI_TYPES}")
    return frozenset(types)


def load_dictionary(path: str | None) -> BranchDictionary | None:
    if not path:
        return None
    rows = json.loads(Path(path).read_text())
    return BranchDictionary(Entity(r["id"], r.get("type", "PERSON"), list(r["names"])) for r in rows)
