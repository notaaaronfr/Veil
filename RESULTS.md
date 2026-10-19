# Results (17 Oct 2026)

All data is synthetic or public. Reproduce with `bench/run.py` and `bench/ratbench.py`. Outputs are saved under `bench/out/`.

## RAT-Bench: direct identifiers

Share of records in which any direct identifier (name, ID, card, phone, address, email) is still recoverable from the outbound text. Lower is better. Brackets are Wilson 95% intervals; n = 100 per cell.

| System | EN easy | EN hard | Dutch | Serbian |
|---|---|---|---|---|
| No protection | 100% | 79% | 100% | 100% |
| Presidio (default) | 18% [12–27] | 50% [40–60] | 46% [37–56] | 26% [18–35] |
| GLiNER multi-PII alone | 34% [26–44] | 51% [41–61] | 41% [32–51] | 39% [30–49] |
| Ours, phase 1 (patterns + dictionary) | 40% | 73% | — | — |
| **Ours, phase 2 (+ NER)** | **8% [4–15]** | **20% [13–29]** | **11% [6–19]** | **7% [3–14]** |

Utility, measured as BLEU of the outbound text against the original (higher is better):

| System | EN easy | EN hard | EN implicit | Dutch | Serbian |
|---|---|---|---|---|---|
| Presidio | 89 | 91 | 92 | 59 | 35 |
| GLiNER alone | 87 | 86 | 88 | 85 | 89 |
| **Ours, phase 2** | 87 | 80 | 96 | 71 | 87 |

**What still leaks (phase 2):**
- Paraphrased addresses, such as "been at 195 for ages" or "off East Morgan Avenue".
- Card numbers split across sentences.
- Spelled-out emails.

These are the cases phase 3 (local LLM) targets.

**Caveats, read before quoting:**
- **The leak metric is a proxy.** An independent checker looks for gold values in the output; it does not run RAT-Bench's official GPT-4.1 attacker. The official score also covers *indirect* identifiers, which this table does not. `bench/ratbench_official.py` is ready to run once an API key is available.
- **The Hugging Face "spanish" config contains the English records** (100/100 identical). Spanish was therefore not tested. Dutch and Serbian are genuine.
- **Some formats were added after seeing the data.** The patterns for Belgian RRN, Serbian JMBG and Serbian phone formats were added after inspecting those configs. They are real national formats, but this favours us slightly on Dutch and Serbian.
- **Azure AI Language PII** (the strongest commercial tool in the RAT-Bench paper) is not yet compared. `bench/ratbench.py --systems azure` runs once credentials are set.

## Phase 3: context guard (local Qwen3-4B)

Measured on RAT-Bench English: the first 40 *hard* and first 40 *implicit* records (80 total).

**Direct identifiers (proxy leak).** Share of hard records still leaking:

| System | Hard records leaking | BLEU (hard) | BLEU (implicit) |
|---|---|---|---|
| No protection | 75% [60–86] | 100 | 100 |
| Presidio | 45% [31–60] | 91 | 92 |
| GLiNER alone | 55% [40–69] | 86 | 88 |
| Ours, phase 2 | 15% [7–29] | 78 | 97 |
| **Ours, phase 3** | **5% [1–17]** | 70 | 83 |

**Indirect identifiers.** The attack is a Staab-style guessing game run by a local Llama-3.1-8B attacker, a different model family from the guard. Scores are top-3 guesses checked against RAT-Bench gold attributes, 351 attributes in total.

| System | Inferred | Occupation | State | Marital | Education | Sex | Birth year |
|---|---|---|---|---|---|---|---|
| No protection | 57.5% [52–63] | 31/42 | 36/37 | 42/50 | 22/40 | 37/42 | 17/51 |
| Presidio | 50.7% [46–56] | 31/42 | 26/37 | 42/50 | 20/40 | 38/42 | 11/51 |
| Ours, phase 2 | 51.9% [47–57] | 28/42 | 33/37 | 38/50 | 19/40 | 34/42 | 15/51 |
| **Ours, phase 3** | **44.7% [40–50]** | **20/42** | 25/37 | 35/50 | 16/40 | 34/42 | 15/51 |

Paired exact McNemar tests on the same attributes:
- Phase 3 vs Presidio: p = 0.015
- Phase 3 vs phase 2: p < 0.001

**Frontier attacker: GPT-4.1, the attacker used in the RAT-Bench paper.** Run via OpenRouter on synthetic data only, same 80 records and 351 attributes:

| System | Inferred | Occupation | State | Marital | Education | Sex | Birth year |
|---|---|---|---|---|---|---|---|
| No protection | 76.9% [72–81] | 40/42 | 37/37 | 50/50 | 23/40 | 42/42 | 37/51 |
| Presidio | 73.2% [68–78] | 40/42 | 33/37 | 50/50 | 25/40 | 42/42 | 29/51 |
| Ours, phase 2 | 67.8% [63–73] | 38/42 | 34/37 | 41/50 | 19/40 | 35/42 | 33/51 |
| **Ours, phase 3** | **64.4% [59–69]** | 35/42 | 31/37 | 41/50 | 22/40 | 36/42 | 29/51 |

Paired exact McNemar tests under GPT-4.1:
- Phase 3 vs Presidio: p = 0.0002
- Phase 2 vs Presidio: p = 0.016
- Phase 3 vs phase 2: p = 0.036

Presidio barely improves on no protection (73% vs 77%). A frontier model infers almost everything that Presidio leaves in the context.

GPT-6.1-sol was also tried and discarded as an attacker. It refused 10–19 records per system and answered "unknown" far more often, which matches the GPT-5-class refusals reported in the RAT-Bench paper. Its numbers are therefore not a valid upper bound. The cached guesses are in `bench/out/`.

**Reading this honestly:**
- **Phase 3 is the only system that significantly reduces inference, but the effect is moderate.**
- **Sex is barely affected.** Pronouns and relationship words still give it away.
- **Marital status and state still leak heavily.** This matches the literature: no published method solves combination leakage.
- **The utility cost is about 20 BLEU points on hard records.**
- **Latency is about 35 s per message** on an M5 laptop with a 4B model, measured interactively. The batch timing was distorted by the machine sleeping.
- **Absolute leakage is high for every system.** Under GPT-4.1, phase 3 still lets 64% of attributes be inferred. The gains over Presidio are significant but leave most of the inference problem unsolved.
- **n = 80 records.** Rerun on the full set before quoting.

## UAE synthetic benchmark (`bench/run.py`)

The test set has 900 samples across 9 evasion families: zero-width characters, Arabic-Indic digits, fullwidth digits, spaced digits, dotted digits, homoglyphs, upper case, spelled-out digits, and none. It mixes Arabic and English, using clients the branch knows and names it does not.

| System | Leaking samples |
|---|---|
| Presidio | 44–100%, depending on evasion family |
| **Ours, phase 2** | **0 / 900** (upper bound ≤ 4.6% per family; ≤ 26% per small unknown-name bucket) |

Restoration under 4 manglings of the model output: 900/900 each.

This is our own test set, so it plays to our strengths. Treat RAT-Bench as the fairer comparison.

## Known limits

- **Cross-script names are not linked.** The same unknown person written in Arabic and Latin script gets two different tags. Branch-dictionary clients are linked.
- **Indirect identifiers are not handled yet.** Age, job, city and family are phase 3.
- **The vault is written in Python.** Memory cannot be guaranteed wiped; this moves to Rust in phase 4.
