#!/usr/bin/env bash
# End-to-end test of the deploy/ bundle on this machine: Caddy (TLS) -> Veil (gunicorn,
# multi-tenant, ledger) -> fake upstream on the host (bench/fake_upstream.py on :19099).
#   bash bench/compose_e2e.sh            (needs the image veil:0.4.0 and the fake upstream running)
set -euo pipefail
cd "$(dirname "$0")/.."
E=bench/out/compose-e2e
rm -rf "$E" && mkdir -p "$E/etc/secrets" "$E/etc/tls"

hex() { python3 -c "import secrets;print(secrets.token_hex(32))"; }
hex > "$E/etc/secrets/ledger.key"; hex > "$E/etc/secrets/a.branch.key"; hex > "$E/etc/secrets/b.branch.key"
echo upstream-a-key > "$E/etc/secrets/a.up.key"; echo upstream-b-key > "$E/etc/secrets/b.up.key"
KEY_A=$(uv run veil-admin key new | head -1 | sed 's/.*: //'); SHA_A=$(python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$KEY_A")
KEY_B=$(uv run veil-admin key new | head -1 | sed 's/.*: //'); SHA_B=$(python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$KEY_B")
printf '[{"id":"c1","type":"PERSON","names":["Sara Al Mansoori","سارة المنصوري"]}]' > "$E/etc/a.dictionary.json"

cat > "$E/etc/veil.yaml" <<YAML
ledger: {dir: /var/lib/veil/ledger, hmac_key_file: /etc/veil/secrets/ledger.key}
tenants:
  tenant-a:
    branch_key_file: /etc/veil/secrets/a.branch.key
    dictionary_file: /etc/veil/a.dictionary.json
    upstreams:
      azure-uaenorth: {provider: azure-openai, region: uaenorth, url: "http://host.docker.internal:19099",
                       key_file: /etc/veil/secrets/a.up.key, deployments: [gpt-4o]}
  tenant-b:
    branch_key_file: /etc/veil/secrets/b.branch.key
    upstreams:
      azure-eu: {provider: azure-openai, region: swedencentral, url: "http://host.docker.internal:19099",
                 key_file: /etc/veil/secrets/b.up.key, deployments: [gpt-4o-mini]}
clients:
  - {id: app-a, tenant: tenant-a, keys: [{sha256: $SHA_A}]}
  - {id: app-b, tenant: tenant-b, keys: [{sha256: $SHA_B}]}
YAML

# test CA + server certificate for "localhost"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=veil-test-ca" -keyout "$E/ca.key" -out "$E/etc/tls/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$E/etc/tls/veil.key" -out "$E/veil.csr" 2>/dev/null
printf "subjectAltName=DNS:localhost" > "$E/san.ext"
openssl x509 -req -in "$E/veil.csr" -CA "$E/etc/tls/ca.crt" -CAkey "$E/ca.key" -CAcreateserial -days 2 -extfile "$E/san.ext" -out "$E/etc/tls/veil.crt" 2>/dev/null
chmod 644 "$E"/etc/secrets/* "$E"/etc/tls/*

uv run veil-admin config check -c "$E/etc/veil.yaml" 2>/dev/null | sed "s#$E/etc#/etc/veil#g" || true

cat > "$E/override.yml" <<YAML
services:
  veil:
    volumes: ["$PWD/$E/etc:/etc/veil:ro", "veil-ledger:/var/lib/veil/ledger"]
  maintenance:
    volumes: ["$PWD/$E/etc:/etc/veil:ro", "veil-ledger:/var/lib/veil/ledger"]
  caddy:
    ports: !override ["18443:443"]
    volumes: !override ["$PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro", "$PWD/$E/etc/tls:/etc/caddy/tls:ro"]
YAML

DC="docker compose -p veil-e2e -f deploy/docker-compose.yml -f $E/override.yml"
$DC down -v >/dev/null 2>&1 || true
VEIL_IMAGE=veil:0.4.0 $DC up -d --wait
echo "--- stack up"; $DC ps --format '{{.Service}} {{.Status}}'

uv run python - "$KEY_A" "$KEY_B" "$PWD/$E/etc/tls/ca.crt" <<'PY'
import sys, httpx, json
from openai import AzureOpenAI, PermissionDeniedError
key_a, key_b, ca = sys.argv[1:]
http = httpx.Client(verify=ca)
a = AzureOpenAI(azure_endpoint="https://localhost:18443", api_key=key_a, api_version="2024-10-21", http_client=http)
b = AzureOpenAI(azure_endpoint="https://localhost:18443", api_key=key_b, api_version="2024-10-21", http_client=http)
p = "Email Sara Al Mansoori (sara.m@example.ae, +971 50 123 4567), she is a 52-year-old born on 26 November 1973."
# names / email / phone are tagged and come back exactly; age and birth date are
# generalised on purpose and come back generalised
expected = p.replace("52-year-old", "50-something-year-old").replace("26 November 1973", "a date in the 1970s")
r = a.chat.completions.with_raw_response.create(model="gpt-4o", messages=[{"role": "user", "content": p}])
print("tenant-a over TLS   :", r.http_response.status_code, "tier", r.headers.get("x-veil-tier"), "restored:", r.parse().choices[0].message.content.endswith(expected))
s = "".join(c.choices[0].delta.content or "" for c in a.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": p}], stream=True) if c.choices)
print("tenant-a stream     :", s.endswith(expected))
try:
    b.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])  # tenant-b may only use gpt-4o-mini
except PermissionDeniedError as e:
    print("tenant-b gpt-4o     : refused", e.status_code)
print("tenant-b gpt-4o-mini:", b.chat.completions.with_raw_response.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}]).http_response.status_code)
try:
    httpx.get("https://localhost:18443/healthz", timeout=5)  # system CA store: must fail
    print("untrusted client    : CONNECTED (bad)")
except httpx.ConnectError:
    print("untrusted client    : rejected (TLS verify)")
sent = open("bench/out/received.jsonl").read()
leaks = [x for x in ("Sara", "Mansoori", "sara.m@", "123 4567", "1973", "52-year") if x in sent]
print("leaks to upstream   :", leaks or "none")
PY
echo "--- ledger verification (inside the stack)"
$DC exec -T veil veil-admin ledger verify -c /etc/veil/veil.yaml
$DC exec -T veil python -c "import json,glob; recs=[json.loads(l) for f in sorted(glob.glob('/var/lib/veil/ledger/tenant-a/*.jsonl')) for l in open(f)]; print('tenant-a decisions:', [(r['decision'], r.get('tier_effective'), r.get('detected')) for r in recs][:3])"
