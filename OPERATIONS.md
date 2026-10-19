# Running Veil in a branch

Veil is an OpenAI / Azure OpenAI compatible proxy. Apps send requests to Veil exactly as they would to Azure OpenAI. Veil pseudonymises each request inside the branch, forwards it to the upstream deployment (Azure OpenAI, UAE North), restores the reply, and wipes the request's keys and mapping.

## 1. Build or pull the image

```bash
docker build -t veil:0.2.0 .                           # native
docker build --platform linux/amd64 -t veil:0.2.0 .    # for an x86 branch server
```

The image is CPU-only. The NER models are baked in, so the container needs **no internet access** at runtime. Egress should be allowed only to the upstream endpoint.

## 2. Secrets and configuration

Generate a branch key once per branch and keep it in your secret store, not in the image:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > branch.key
```

| Variable | Required | Meaning |
|---|---|---|
| `VEIL_UPSTREAM_URL` | yes | e.g. `https://<resource>.openai.azure.com` |
| `VEIL_UPSTREAM_KEY_FILE` | yes | file containing the Azure OpenAI key |
| `VEIL_BRANCH_KEY_FILE` | yes | file containing the 64-hex-character branch key |
| `VEIL_CLIENT_KEYS_FILE` | yes | one client key per line; apps send one of these as `api-key` or `Authorization: Bearer` |
| `VEIL_UPSTREAM_AUTH` | no | `api-key` (Azure, the default) or `bearer` |
| `VEIL_DICTIONARY_FILE` | no | known clients and staff (see below) |
| `VEIL_NER` | no | `1` (default). If the models fail to load, Veil runs on its deterministic layers and `/healthz` reports `ner: failed` |
| `VEIL_QUASI` | no | Quasi-identifiers to protect: `all` (default), `none`, or a list chosen from `AGE,DOB,LOCATION,OCCUPATION,ORG,NATIONALITY,ETHNICITY,RELIGION,MARITAL,HEALTH,EDUCATION,CITIZENSHIP,EMPLOYMENT`. Age and birth date are generalised ("50-something", "a date in the 1970s"); the rest become reversible tags |
| `VEIL_IMAGES` | no | `drop` (default): each image is replaced by a text note, because Veil cannot inspect images. `pass`: images are forwarded, counted and logged |
| `VEIL_WORKERS` | no | gunicorn workers, default 2. Each loads its own models, at about 2.3 GB RSS |
| `VEIL_MAX_REQUESTS` | no | requests before a worker is recycled, default 2000, with jitter. Bounds how long any prompt residue lives in memory |
| `VEIL_TORCH_THREADS` | no | CPU threads per worker, default cores ÷ workers |
| `VEIL_MLOCK` | no | `1` keeps the process out of swap (`mlockall`). Needs `--cap-add IPC_LOCK` and `--ulimit memlock=-1` |
| `VEIL_CONTEXT` | no | `0` (default). The local-LLM context guard is not supported on CPU-only servers in this release |
| `VEIL_CONTEXT_BUDGET` | no | seconds before the context guard is abandoned. The phase-2 output is sent instead |
| `VEIL_UPSTREAM_TIMEOUT` | no | seconds, default 120 |
| `VEIL_MAX_BODY_BYTES` | no | default 4 MiB |
| `VEIL_PORT` | no | default 8080 |
| `VEIL_LOG_LEVEL` | no | default `INFO` |

Every variable that takes a `_FILE` path also accepts the value directly in the variable without the suffix. Use files in production.

**Dictionary file** (`VEIL_DICTIONARY_FILE`). These are the branch's known people and organisations. They are matched in Arabic and Latin script, at every mention, and by first or last name:

```json
[
  {"id": "c-1042", "type": "PERSON", "names": ["Sara Al Mansoori", "سارة المنصوري"]},
  {"id": "o-17",   "type": "ORG",    "names": ["Emirates Falcon Holdings"]}
]
```

## 3. Run

```bash
docker run -d --name veil -p 8080:8080 \
  -v /etc/veil:/run/secrets:ro \
  -e VEIL_UPSTREAM_URL=https://<resource>.openai.azure.com \
  -e VEIL_UPSTREAM_KEY_FILE=/run/secrets/upstream.key \
  -e VEIL_BRANCH_KEY_FILE=/run/secrets/branch.key \
  -e VEIL_CLIENT_KEYS_FILE=/run/secrets/client.keys \
  -e VEIL_DICTIONARY_FILE=/run/secrets/dictionary.json \
  --read-only --tmpfs /tmp --memory 6g \
  veil:0.2.0
```

The image runs gunicorn with `VEIL_WORKERS` workers. Workers are recycled every `VEIL_MAX_REQUESTS` requests without downtime. Each worker process is hardened at start: it is marked non-dumpable, so other processes cannot read its memory through `/proc/<pid>/mem` or ptrace, and core dumps are disabled. `/healthz` reports what was applied.

Add the following settings, which keep request data off disk and out of the host:

| Setting | Why |
|---|---|
| `--read-only` | Nothing is written to the container filesystem |
| `--tmpfs /tmp` | Scratch space lives in memory only |
| No swap for the container | Pseudonymisation mappings never reach disk |
| Core dumps disabled | A crash doesn't write process memory to disk |
| TLS in front of port 8080 (reverse proxy or service mesh) | Traffic between apps and Veil is encrypted |

## 4. Point apps at Veil

```python
from openai import AzureOpenAI

client = AzureOpenAI(
    azure_endpoint="https://veil.branch.internal",   # was https://<resource>.openai.azure.com
    api_key="<a Veil client key>",                    # not the Azure key
    api_version="2024-10-21",
)
client.chat.completions.create(model="gpt-4o", messages=[...], stream=True)
```

Veil supports the following endpoints:

| Endpoint | What Veil does |
|---|---|
| `…/chat/completions` (Azure deployment path, `/v1`, `/openai/v1`) | Protects the request, restores the reply. Streaming works |
| `…/embeddings` | Protects the input. Nothing to restore |

Everything else returns **404 and is never forwarded**, because Veil cannot protect what it does not understand.

## 5. What is protected

Veil processes every text field it forwards:
- system, user, assistant and tool messages;
- multi-part text;
- tool-call and function-call arguments;
- embedding input.

**Within one request**, each person gets one tag, consistent across all messages. **Across requests**, nothing is linkable, because each request uses fresh keys.

| Layer | Default | What it covers |
|---|---|---|
| Canonicalisation | on | Zero-width characters, Arabic-Indic and fullwidth digits, homoglyphs, spelled-out digits |
| Patterns with checksums | on | Emirates ID, IBAN, cards, phone numbers, email, SSN, national IDs, account numbers |
| Branch dictionary | if configured | Known people and organisations |
| NER | on | Unknown names and organisations (English, multilingual and Arabic), addresses |
| Egress hard line | always | Every known value, at every occurrence, in the final payload |
| Quasi-identifiers (NER + patterns) | on (`VEIL_QUASI=all`) | Age and birth date (generalised); city or state, occupation, employer, nationality, ethnicity, religion, marital status, health, education, citizenship and employment (tagged) |
| Context guard (local LLM) | off on CPU | Deeper rewriting of context clues. Apple Silicon only in this release |

The **never-fail policy** works as follows:
- A request is never refused for privacy reasons.
- If NER fails, Veil continues with its deterministic layers.
- If the egress check finds a value it cannot turn into a surrogate, that value is replaced by `[REDACTED]`.
- A known value is never sent.
- If the deterministic layers themselves fail, the request returns `500` and nothing is sent.

**Not protected:**
- **Images, when `VEIL_IMAGES=pass`.** They are forwarded, counted in `veil_unprotected_images_total` and logged. With the default `drop` they never leave.
- **The `name` field on messages.**
- **Clues that are not entities.** Sex conveyed by pronouns, and attributes implied only by context ("since the divorce" is caught; "my ex" may not be). See RESULTS.md for measured residual risk.

## 6. Observability

| Endpoint or logger | What it gives you |
|---|---|
| `GET /healthz` | Status, and whether NER and the context guard are `ready`, `failed` or `disabled` |
| `GET /metrics` | Prometheus text format: requests by outcome, entities detected by type, scrubbed, redacted, degraded layers, restored, hallucinated tags, unprotected images |
| Audit log (`veil.audit`) | One JSON line per request: request ID, path, protection timing, detected counts by type, scrubbed, redacted, degraded, upstream status and timing, restored count |

**Logs and metrics never contain values.** Tests enforce this.

## 7. Performance (CPU, 4 threads, `bench/latency.py`)

Single request, NER without quasi-identifiers:

| Message size | Protect time, p50 | Protect time, p95 |
|---|---|---|
| 93 chars | 69 ms | 118 ms |
| 930 chars | 137 ms | 310 ms |
| 2,800 chars | 589 ms | 798 ms |

These were measured on an Apple M5 CPU; re-measure on the branch server. Quasi-identifier detection adds GLiNER labels and costs roughly 20–25% throughput. Memory is about 2.3 GB per worker, so allow 6 GB for the default 2 workers.

Under load (`bench/load.py`: container with 4 vCPUs, 12 concurrent requests, production defaults):

| Workers | Throughput | p50 | p95 |
|---|---|---|---|
| 1 | 4.5 req/s | 2.6 s | 2.9 s |
| 2 (default) | 3.9 req/s | 2.9 s | 3.8 s |

The default is 2 workers even though 1 is slightly faster. With a single worker, each recycle pauses service for about 20 s while the models reload. To scale, add cores or replicas: Veil is stateless, so any load balancer works. Without NER the protect step takes under 1 ms. The whole conversation is protected on every request, so long chats pay for their full history each turn.

## 8. Known limits in this release

- **Memory residue.** CPython cannot guarantee that every copy of a value is wiped. Veil makes residue unreadable rather than promising erasure:
  - non-dumpable workers;
  - no core dumps;
  - optional `mlockall`;
  - worker recycling.

  Disable swap on the host, or use `VEIL_MLOCK=1`.
- **The same unknown person in Arabic and Latin script gets two different tags.** Dictionary entries are linked across scripts.
- **The context guard needs Apple MLX.** A Linux CPU or GPU runtime (llama.cpp) is not yet integrated.
