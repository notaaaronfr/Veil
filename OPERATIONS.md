# Operating Veil

Veil is an OpenAI / Azure OpenAI compatible proxy. Each request is processed inside the branch:

1. Personal data is pseudonymised before the request leaves.
2. The request goes only to the tenant's approved upstreams.
3. Every decision is recorded in a tamper-evident ledger.
4. The reply is restored.

One deployment serves several **tenants** (branches or clients). The deployment target is **Docker on VMs**. See also:
- [SECURITY.md](SECURITY.md): the threat model;
- [RUNBOOK.md](RUNBOOK.md): incidents;
- [RESULTS.md](RESULTS.md): measured protection.

## 1. Install

```bash
# on the VM (Docker Engine + compose plugin installed)
sudo mkdir -p /etc/veil/secrets /etc/veil/tls /opt/veil
sudo cp -r deploy /opt/veil/                          # docker-compose.yml, Caddyfile, unit, firewall
docker load < veil-0.4.0.tar                          # or pull from your registry
sudo cp /opt/veil/deploy/veil.example.yaml /etc/veil/veil.yaml   # then edit (section 2)
```

**Secrets.** Each secret is one file in `/etc/veil/secrets/`, mode `0400`, owned by uid `10001`. Generate the keys with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

You need:
- `ledger.key`: certifies the ledger. Keep a copy in your secret store; you need it to verify the ledger later.
- `<tenant>.branch.key`: one per tenant.
- `<tenant>.<upstream>.key`: the upstream API keys, for example Azure OpenAI.

**TLS.** Issue a server certificate from your internal CA: `/etc/veil/tls/veil.crt` and `veil.key`. Optionally add `clients-ca.crt` for mutual TLS (see the `Caddyfile`).

**Validate, then start.**

```bash
cd /opt/veil/deploy
docker compose run --rm veil veil-admin config check -c /etc/veil/veil.yaml
sudo install -m 0644 veil.service /etc/systemd/system/ && sudo systemctl enable --now veil
```

**Lock down egress.** Load `deploy/nftables.conf` with your approved upstream addresses. Veil refuses unapproved deployments itself; the firewall enforces the same rule at the network level.

The stack runs three services:

| Service | Role |
|---|---|
| `caddy` | TLS 1.2/1.3 on :443, optional mutual TLS, 4 MB body limit, no query strings in access logs |
| `veil` | gunicorn: the master loads the models once and workers share them. Read-only filesystem, no capabilities, non-root, non-dumpable, no core dumps, no swap |
| `maintenance` | Daily ledger verification and retention pruning (legal holds respected) |

## 2. Configuration (`/etc/veil/veil.yaml`)

The annotated template is `deploy/veil.example.yaml`.

| Section | Purpose |
|---|---|
| `tenants.<id>` | Per tenant: branch key, dictionary, `quasi` and `images` policy, tier labels (`default_label`, `ceiling`, `red_types`, `red_upstream`), handoff webhook, `retention_days`, and **approved `upstreams`** (provider, region, URL, key file, deployments). |
| `clients[]` | Calling apps: tenant, `scopes` (`chat`, `embeddings`), optional `upstreams` subset, `rate_limit_rpm`, API key **hashes** with expiry, and Entra `oidc_subjects`. |
| `oidc` | Microsoft Entra ID token validation: `issuer`, `audience`, `tenant_id`. |
| `ledger` | Directory, HMAC key file, `fsync`. |

**Apply changes** with `systemctl reload veil` (SIGHUP). The master validates the new file first:
- **if it is invalid** (including half-written), the reload is **rejected** and the previous config keeps serving; look for `config reload REJECTED` in the logs;
- **if it is valid**, workers restart with it gracefully, without reloading the models.

Process-wide settings are environment variables in `docker-compose.yml`:

| Variable | Default | Meaning |
|---|---|---|
| `VEIL_WORKERS` | 2 | gunicorn workers. Models are shared, so extra workers cost little memory |
| `VEIL_MAX_REQUESTS` | 2000 | Recycle a worker after N requests (with jitter); bounds memory residue |
| `VEIL_TORCH_THREADS` | cores ÷ workers | CPU threads per worker |
| `VEIL_MEMORY` | 8g | Container memory limit; swap is disabled for the container |
| `VEIL_UPSTREAM_TIMEOUT` | 120 | Seconds |
| `VEIL_UPSTREAM_RETRIES` | 2 | Retries on connection errors, 429 and 502–504 (honours `Retry-After`) |
| `VEIL_MLOCK` | 0 | `1` locks memory; needs `IPC_LOCK` and a memlock ulimit |
| `VEIL_LOG_FORMAT` | json | `json` or `text` |

Without `VEIL_CONFIG`, the older single-tenant variables (`VEIL_UPSTREAM_URL`, `VEIL_BRANCH_KEY_FILE` and the rest) still work. They define one tenant called `default`.

## 3. Clients and authentication

**API key.** Run `docker compose run --rm veil veil-admin key new [--expires 2027-06-30]`. It prints the key once, together with the config line, which contains only the key's hash. Add that line under the client's `keys`, then reload. The app sends the key as an `api-key` header or as `Authorization: Bearer veil_…`.

**Rotation.** A client can have several valid keys at once:
1. Add the new key and reload.
2. Move the app to the new key.
3. Remove the old key and reload.

Expired keys are refused automatically.

**Entra ID:**
1. Register a "Veil" application with an Application ID URI (the `audience`).
2. Grant each calling app an app role on it.
3. Put each app's client ID in that client's `oidc_subjects`.

Apps send `Authorization: Bearer <token>`. Veil checks:
- the signature, against Entra's published keys;
- issuer, audience and expiry;
- the directory ID, if `tenant_id` is set.

The VM needs egress to `login.microsoftonline.com` for the signing keys.

**Connecting an app:**

```python
from openai import AzureOpenAI
client = AzureOpenAI(azure_endpoint="https://veil.branch.internal", api_key="<Veil key>", api_version="2024-10-21")
client.chat.completions.create(model="gpt-4o", messages=[...], extra_headers={"x-veil-classification": "amber"})
```

**Request headers Veil understands:**

| Header | Purpose |
|---|---|
| `x-veil-classification` | `green`, `amber` or `red`: the app's Pulse label |
| `x-request-id` | Correlation ID, echoed back in the response |
| `x-veil-upstream` | Pick one of several approved upstreams |

**Response headers:** `x-request-id`, and `x-veil-tier` (the effective tier).

## 4. Tiers (pre-flight policy gate)

The effective tier is the app's label, **raised** (never lowered) by what Veil detects:
- any sensitive value makes it at least Amber;
- any of the tenant's `red_types` makes it Red.

| Effective tier | What happens |
|---|---|
| Up to the tenant's `ceiling` | Pseudonymised and forwarded to the approved upstream |
| Above the ceiling, with a `red_upstream` set (an upstream marked `in_branch: true`) | The **original** request goes to that in-branch model. It never leaves the branch |
| Above the ceiling, with no in-branch model | **Handed off to a person.** The app gets `403 red_tier_handoff` with a `handoff_id`. The webhook receives the IDs and reason, never content. The ledger records it |

Classification is risk reduction, not a guarantee. It depends on detection, which has measured miss rates.

## 5. Ledger, retention and legal hold

Each tenant has its own hash-chained ledger at `/var/lib/veil/ledger/<tenant>/`, with one file per day. Every record is certified with HMAC-SHA256 using `ledger.key`.

A record holds **approved fields only**:
- request ID, client, authentication method;
- route, deployment, upstream, provider, region;
- tier label and effective tier, decision, reason;
- counts by entity type, scrubbed and redacted counts, degraded layers, image counts;
- upstream status, timings.

It never holds prompt text or values.

```bash
docker compose exec veil veil-admin ledger verify -c /etc/veil/veil.yaml          # all tenants
docker compose exec veil veil-admin hold set -c /etc/veil/veil.yaml -t <tenant> --reason "<case>" --actor "<who>"
docker compose exec veil veil-admin hold status -c /etc/veil/veil.yaml -t <tenant>
docker compose exec veil veil-admin hold release -c /etc/veil/veil.yaml -t <tenant> --actor "<who>"
```

**Retention.** The `maintenance` service prunes whole day files older than `retention_days`. **A tenant under legal hold is never pruned.** Pruning and holds are themselves recorded in the chain, and an anchor keeps the chain verifiable after pruning.

**What Veil stores.** Veil stores no prompts, drafts or replies. Retention of intermediate drafts belongs to the calling application.

**Backups.** Back up the `veil-ledger` volume like any audit store. Verify restored copies with `ledger verify`, using the same `ledger.key`.

## 6. What is protected

| Layer | What it covers |
|---|---|
| Canonicalisation | Zero-width characters, Arabic-Indic and fullwidth digits, homoglyphs, spelled-out digits |
| Patterns with checksums | Emirates ID, IBAN, card, phone, email, SSN, national IDs, account numbers; deterministic age and date-of-birth patterns |
| Branch dictionary | Known people and organisations, in Arabic and Latin script |
| NER (GLiNER + CAMeLBERT) | Unknown names, organisations and addresses; quasi-identifiers per tenant `quasi` setting. Age and birth date are generalised; place, occupation, employer, nationality, ethnicity, religion, marital status, health, education, citizenship and employment are tagged |
| Egress hard line | Every known value, at every occurrence, in the final payload. Anything that can't be swapped for a surrogate is replaced with `[REDACTED]`, and the request is never refused |
| Allowlist | Only the tenant's approved upstreams and deployments |

**Never refused for privacy reasons.** If NER fails, Veil continues on its deterministic layers; `/readyz` stays ready but reports `degraded`. If the deterministic layers themselves fail, the request returns `500` and nothing is sent.

**Not protected:**
- Images when `images: pass` (counted and logged).
- The `name` field on messages.
- Clues that are not values, such as sex conveyed by pronouns or "since the divorce". On CPU-only servers these are handled only by the local-LLM layer, which is disabled. See RESULTS.md.

## 7. Monitoring

| Endpoint | Meaning |
|---|---|
| `/livez` | Process is up |
| `/readyz` | Ready to serve. Returns 503 if the ledger cannot be written, so traffic stops rather than going unrecorded |
| `/healthz` | Tenants, upstreams, model state, hardening applied, circuit-breaker states |
| `/metrics` | Prometheus format (internal network only; Caddy hides it) |

Metrics include:
- requests by tenant and outcome;
- entities detected by type;
- scrubbed, redacted, degraded and handoff counts;
- rate-limited requests;
- upstream errors and retries;
- ledger errors;
- protect and upstream latency histograms.

Alert rules are in `deploy/prometheus-alerts.yml`. Each alert links to a section of RUNBOOK.md.

**Logs** are JSON on stdout, rotated by Docker. The `veil.audit` logger mirrors each ledger record. Neither logs nor metrics contain values; tests enforce this.

## 8. Capacity

Measured on a 4-vCPU container with production defaults, 12 concurrent requests, over TLS:
- **Throughput:** about 4.3 requests/s.
- **Latency:** p50 2.7 s, p95 3.1 s.
- **Memory:** 2.4 GB for 2 workers, because the models are shared.

On a single request, protection takes 0.1–0.8 s, depending on length.

Throughput scales with cores. For more capacity, run several VMs behind a load balancer; Veil is stateless apart from the ledger.

> **Rate limits are per worker process.** With N workers, a client can get up to N × `rate_limit_rpm`.

## 9. Limits of this release

- **Memory residue.** CPython cannot guarantee that every copy of a value is wiped from memory. Veil makes residue unreadable rather than promising erasure:
  - non-dumpable workers;
  - no core dumps;
  - no swap;
  - worker recycling.
- **Cross-script names.** The same unknown person written in Arabic and in Latin script gets two tags. Branch-dictionary entries are linked across scripts.
- **Context guard.** The local-LLM layer runs on Apple Silicon only. A Linux GPU runtime is not yet integrated.
