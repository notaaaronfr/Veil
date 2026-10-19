# Changelog

## 0.4.0: enterprise (19 Oct 2026)

### Added

- **Multi-tenant configuration** (`VEIL_CONFIG`, YAML). Each tenant has its own:
  - branch key and dictionary;
  - `quasi` and `images` policy;
  - tier labels;
  - approved upstreams (provider, region, deployments);
  - ledger and retention.

  The legacy single-tenant environment variables still work; they define a tenant called `default`.
- **Authentication:**
  - per-app API keys, stored as hashes, with scopes, expiry and overlapping keys for rotation;
  - Microsoft Entra ID tokens (JWKS, issuer, audience, expiry and directory checks).
- **Upstream allowlist.** Unapproved deployments are refused and recorded, never forwarded.
- **Green/Amber/Red tier gate:**
  - the app label is raised by what Veil detects;
  - Red goes to a verified in-branch model, or to a person (`403 red_tier_handoff` and a webhook carrying IDs only).
- **Tamper-evident ledger:**
  - per-tenant hash chain with HMAC certificates and approved fields only;
  - safe with several worker processes and fsynced;
  - retention pruning with legal hold;
  - verification with `veil-admin ledger verify`.
- **`veil-admin` CLI:** `key new`, `config check`, `ledger verify` and `ledger prune`, `hold set`, `hold release` and `hold status`.
- **Resilience:**
  - per-client rate limits and per-upstream circuit breakers;
  - retries with `Retry-After`;
  - `/livez` and `/readyz`, with readiness failing when the ledger can't be written;
  - request IDs, JSON logs, latency histograms.
- **Configuration reload.** The gunicorn master validates config changes on SIGHUP and keeps serving the last valid config if the new one is broken.
- **Shared models.** The master loads the models once and workers share them copy-on-write: 2.3 GB for 2 workers instead of 4.6 GB, and a reload no longer doubles memory.
- **Deployment bundle** in `deploy/`:
  - Compose with Caddy for TLS and optional mutual TLS;
  - a daily maintenance job;
  - a systemd unit, an nftables egress allowlist, Prometheus alerts and an example config.
- **Supply chain:**
  - an image built from `uv.lock` (CPU torch locked for Linux) with a digest-pinned base image;
  - pip-audit, a Trivy scan and an SBOM in CI;
  - Dependabot.
- **Documentation:** OPERATIONS.md (rewritten), SECURITY.md (threat model), RUNBOOK.md.

### Fixed

- The gunicorn control socket on a read-only filesystem.
- Workers killed for running out of memory during a reload.
- Readiness reporting not ready before the first ledger write.

## 0.3.0

- CPU quasi-identifier protection (`VEIL_QUASI`), the image policy (`VEIL_IMAGES`), process hardening, gunicorn worker recycling.

## 0.2.0

- OpenAI and Azure compatible proxy, streaming restore, never-fail policy, CPU Docker image.
