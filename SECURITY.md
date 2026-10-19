# Security model

## What Veil is for

Veil reduces the personal data that reaches an external LLM provider. It also proves, request by request, where data went and why. Veil is **risk reduction, not a guarantee**: detection has measured miss rates (see RESULTS.md), and some information can only be inferred from context.

## Trust boundaries

```
 app ──TLS──► Caddy ──► Veil ──TLS──► approved upstream (e.g. Azure OpenAI, UAE North)
  │                      │
  │                      ├─► in-branch model (Red tier, never leaves the branch)
  │                      └─► ledger volume (tamper-evident decision records)
  └──── branch network ───────────────┘
```

| Boundary | Trusted |
|---|---|
| Branch VM, Veil process, ledger volume | Yes. The operator controls them |
| Calling apps | Authenticated: per-app keys or Entra ID tokens, scoped to one tenant |
| Upstream provider | **Not trusted with personal data.** It sees surrogates and generalised values only, and only within the tenant's approved provider, region and deployments |
| Handoff webhook | Receives IDs and reasons, never content |

## Threats and controls

| Threat | Control |
|---|---|
| Personal data reaches the provider | Detection layers: patterns with checksums, dictionary, NER, quasi-identifiers. Then the **egress hard line**: every known value is searched for at every occurrence in the final payload and redacted if it can't be swapped. Images are dropped by default |
| Evasion (zero-width characters, homoglyphs, spelled digits, Arabic-Indic or fullwidth digits) | Canonicalisation before detection; the 9 evasion families are tested |
| Linking a person across requests | A fresh HKDF-derived key per request, so surrogates differ every time |
| Re-identification from context | Quasi-identifier generalisation and tagging. **This is only partially mitigated**; the measured residual risk is in RESULTS.md §1 |
| Data sent to an unapproved provider or region | Per-tenant upstream allowlist enforced by Veil, plus an egress firewall (`deploy/nftables.conf`) underneath it |
| Red-tier data leaves the branch | Tier gate: in-branch model or a person, never the external upstream |
| Wrong tenant's data or keys used | Clients are bound to one tenant; tenants have separate branch keys, dictionaries, upstream keys and ledgers |
| Stolen client key | Keys are stored as SHA-256 hashes only, can expire, rotate without downtime, and are per app (blast radius of one app). Entra ID tokens are short-lived |
| Forged or expired tokens | Signature (JWKS), issuer, audience, expiry and directory ID are checked |
| Request flooding | Per-client rate limits, body-size limits (Caddy and Veil), circuit breakers towards upstreams |
| Tampering with the audit trail | Hash chain with HMAC-SHA256 certificates using a key kept outside the ledger; `veil-admin ledger verify` detects edits, deletions, reordering and re-forged chains |
| Audit trail lost or unwritable | Records are written with fsync. `/readyz` turns 503 when the ledger can't be written, so the load balancer stops sending traffic |
| Audit trail deleted early | Retention prunes only whole day files past `retention_days`, never under legal hold. Prunes and holds are themselves chained |
| Prompt residue in memory | Workers are non-dumpable (no `/proc/<pid>/mem` or ptrace from other processes), no core dumps, no swap, optional `mlockall`, workers recycled every N requests |
| Values in logs or metrics | Ledger fields come from an allow-list. Logs and metrics carry types and counts only. Access logs drop URIs and headers. Tests enforce all of this |
| Container breakout or privilege | Non-root (uid 10001), read-only root filesystem, all capabilities dropped, `no-new-privileges`, internal-only network between Caddy and Veil |
| Supply chain | Dependencies locked with hashes (`uv.lock`); base images pinned by digest; models baked in at build time, no runtime downloads; pip-audit and Trivy scans and an SBOM in CI; Dependabot |
| Broken configuration takes the service down | The master validates on reload and keeps the last valid config |

## Key management

| Key | Where | Rotation |
|---|---|---|
| Branch key (per tenant) | `/etc/veil/secrets/<tenant>.branch.key` | Any time. Only per-request keys are derived from it, and nothing is persisted under it |
| Ledger HMAC key | `/etc/veil/secrets/ledger.key`, with a copy in the secret store | Rotating it starts a new chain: archive and verify the old one with the old key first |
| Upstream API keys | `/etc/veil/secrets/…` | Per provider policy; reload Veil after changing |
| Client keys | Hashes only, in `veil.yaml` | Overlapping keys; see OPERATIONS.md §3 |

## Out of scope / known limits

- **A compromised branch VM or Veil host.** It sees plaintext by design.
- **Inference from context that isn't a detectable value**, on CPU-only deployments.
- **Images**, if a tenant sets `images: pass`.
- **CPython memory hygiene.** Residue is made unreadable, not guaranteed erased.
- **The upstream's own retention and abuse monitoring.** Choose providers and settings accordingly; the provider matrix is a separate deliverable.

## Reporting a vulnerability

Report privately to the Veil maintainers. Do not open a public issue.
