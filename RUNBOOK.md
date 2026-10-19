# Veil runbook

All commands run in `/opt/veil/deploy` on the Veil VM. `dc` means `docker compose`.

## Veil down

**Symptoms:** `VeilDown` alert; apps get connection errors or 502 from Caddy.

1. Check the services: `dc ps`.
2. Read the logs: `dc logs --tail 200 veil`.
3. If the container is restarting with `HaltServer` or a config error at **startup**, the config is invalid:
   - run `dc run --rm veil veil-admin config check -c /etc/veil/veil.yaml`;
   - fix the file, then run `systemctl restart veil`.
4. If you see `Worker was sent SIGKILL ... out of memory`, raise `VEIL_MEMORY` or lower `VEIL_WORKERS`. The models are shared, so the memory needed is about 2.3 GB plus about 0.1 GB per worker.
5. Out-of-memory at the host level: check `dmesg`. Other workloads on the VM may be competing for memory.

## Ledger write errors

**Symptoms:** `VeilLedgerWriteErrors` alert. `/readyz` returns 503, so traffic is stopped by design.

1. Check disk space and permissions on the `veil-ledger` volume: `docker system df -v`, `df -h`.
2. Free space or grow the volume, then confirm `/readyz` returns 200.
3. Run `dc exec veil veil-admin ledger verify -c /etc/veil/veil.yaml`.
4. If verification fails, treat it as a possible tampering incident (next section).

## Ledger verification failed

**Symptoms:** the `maintenance` logs or a manual verify print `FAILED`.

1. **Do not prune or edit anything.** Set a legal hold on the affected tenant:
   `dc exec veil veil-admin hold set -c /etc/veil/veil.yaml -t <tenant> --reason "integrity investigation" --actor "<you>"`
2. Copy the tenant's ledger directory off the host for forensics. The message names the first bad file, line and sequence number.
3. Message types:
   - **"certificate (HMAC) invalid"**: records were rewritten by someone without the key.
   - **"content was altered"**: a record was edited.
   - **"sequence gap" or "head.json says…"**: records were deleted.
4. Rotate the ledger key, and the host credentials if needed (SECURITY.md, key management). Escalate to security.

## Upstream failing

**Symptoms:** `VeilUpstreamCircuitOpen` alert; apps get 503 `upstream_unavailable` or 502.

1. `/healthz` shows `breakers`. An "open" breaker means Veil is failing fast for 30 s at a time.
2. Check the provider's status page and your quota. 429s are retried automatically, honouring `Retry-After`.
3. Check egress: run `dc exec veil python -c "import urllib.request;urllib.request.urlopen('https://<upstream>')"`, then check `nftables` and DNS.
4. Recovery is automatic: after the cooldown, one trial request is let through and closes the breaker if it succeeds.

## Degraded protection

**Symptoms:** `VeilDegradedProtection` alert; `/readyz` reports `"degraded": true`.

The NER layer failed and Veil is running on its deterministic layers. Patterns, checksums, dictionary and the egress check still apply; unknown names and quasi-identifiers are not detected.

1. Read `dc logs veil | grep -i "NER"`.
2. Restart with `systemctl restart veil`. The models are baked into the image, so a reload doesn't need network access.
3. If the failure persists, redeploy the image. Until then, consider tightening tenants (for example `ceiling: green`) if policy requires it.

## Redaction spike

**Symptoms:** `VeilRedactionSpike` alert.

Values were found in the final payload that couldn't be swapped for surrogates, and were redacted instead. Nothing leaked, but answers for those requests lose information.

1. Use the ledger to find which client and route: `"redacted": N` per request ID.
2. Common causes:
   - a client sends a new data format;
   - a dictionary entry matches common words.
3. Fix the dictionary, or report the format so it can be handled.

## Red-tier handoffs

**Symptoms:** `VeilHandoffs` alert (info).

1. The app received `403 red_tier_handoff` with a `handoff_id`, and the tenant's webhook received the same ID. Route it through the service desk.
2. The ledger record (`decision: handoff`) gives the reason, for example "red types detected: HEALTH".

## Slow responses

**Symptoms:** `VeilHighLatency` alert.

1. Check the protect latency against the upstream latency: `veil_protect_seconds` and `veil_upstream_seconds`.
2. If protection is slow, the CPU is saturated. Add cores or VMs, or check `VEIL_TORCH_THREADS` (it should be cores ÷ workers).
3. Very long conversations cost more, because the whole history is protected on every request.

## Compromised client key

1. Remove the key's `sha256` line from the client in `veil.yaml`, then run `systemctl reload veil`. The key stops working immediately.
2. Issue a replacement with `veil-admin key new`.
3. Review the ledger for that client's requests in the suspect window: `"client": "<id>"`.

## Config change

1. Edit `/etc/veil/veil.yaml`.
2. Validate: `dc run --rm veil veil-admin config check -c /etc/veil/veil.yaml`.
3. Apply: `systemctl reload veil`.
4. Confirm with `dc logs --tail 20 veil | grep -E "reloaded|REJECTED"`. On `REJECTED` the old config is still serving; fix the file and reload again.

## Legal hold

| Action | Command |
|---|---|
| Set | `dc exec veil veil-admin hold set -c /etc/veil/veil.yaml -t <tenant> --reason "<case>" --actor "<who>"` |
| Check | `dc exec veil veil-admin hold status -c /etc/veil/veil.yaml -t <tenant>` |
| Release (only on legal's instruction) | `dc exec veil veil-admin hold release -c /etc/veil/veil.yaml -t <tenant> --actor "<who>"` |

Setting and releasing are recorded in the tenant's ledger.
