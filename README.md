# Veil: verified pseudonymisation for LLM calls

Veil is a drop-in proxy for Azure OpenAI and OpenAI. Each request is processed inside the branch before it leaves:

1. Names, IDs, cards, IBANs, phone numbers, emails and addresses are detected in Arabic and English.
2. They are replaced with tags or with format-preserving surrogates.
3. The outbound payload is checked again before it is sent.
4. The reply is restored, including when it streams.

Apps change only their endpoint and key.

```python
from openai import AzureOpenAI

client = AzureOpenAI(azure_endpoint="https://veil.branch.internal", api_key="<Veil client key>", api_version="2024-10-21")
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "Email Sara Al Mansoori, ID 784-1985-1234567-4"}])
# upstream sees:  "Email [PERSON_1], ID 784-0326-8154733-2"   (FF1 surrogate, valid checksum)
# app receives the reply with the real values restored
```

| Document | Contents |
|---|---|
| [OPERATIONS.md](OPERATIONS.md) | Deploy, configure, operate |
| [DESIGN.md](DESIGN.md) | Architecture and the research behind each layer |
| [RESULTS.md](RESULTS.md) | Benchmarks, including the official RAT-Bench run, with honest limits |

## Develop

```bash
uv sync --all-extras                 # proxy + NER (+ MLX context guard on Apple Silicon)
uv run pytest                        # unit, proxy, streaming and never-fail tests
docker build -t veil .               # CPU image, models baked in, runs offline
```

The library can also be used directly:

```python
from veil import Veil, BranchDictionary, Entity

clients = BranchDictionary([Entity("c1", "PERSON", ["Sara Al Mansoori", "سارة المنصوري"])])
session = Veil(branch_key, clients).session()
p = session.protect("Email Sara Al Mansoori, ID 784-1985-1234567-4")
shown, report = session.receive(llm_reply)
session.close()
```

## Benchmarks

```bash
uv run python bench/run.py                 # UAE synthetic + evasion families
uv run python bench/ratbench.py            # RAT-Bench proxy leak vs Presidio / GLiNER
uv run python bench/latency.py             # CPU protect latency
uv run python bench/fake_upstream.py &     # then, against a running Veil:
uv run python bench/e2e_client.py http://localhost:8080 <client-key>
uv run python bench/load.py http://localhost:8080 <client-key>
```
