# Results (19 Oct 2026)

All data is synthetic or public. Outputs are reproducible with `bench/`; they are git-ignored under `bench/out/`.

> **Correction (19 Oct).** Earlier versions of this file were affected by a bug. The egress check blocked about 10% of phase 2 outputs (29/300 English records), because the bare word "email" matched inside our own `[EMAIL_n]` tags. Blocked records counted as "no leak" and as BLEU ≈ 0. The bug is fixed, all affected outputs were regenerated with 0 blocked, and the numbers below are the corrected ones. Rows not yet re-run are marked *pre-fix*.

## 1. Official RAT-Bench score (headline)

This uses the official pipeline from `github.com/imperial-aisp/rat-bench`:
- the authors' Staab-style attack prompt and parser;
- CorrectMatch re-identification risk on the authors' weighted US census sample;
- a record counts as re-identified if any direct identifier is guessed or the correctness is ≥ 0.2.

The attacker is **Claude Sonnet 5.5**. The paper used GPT-4.1, so absolute numbers are not directly comparable with the paper's table. The sample is the first 40 *hard* and first 40 *implicit* English records, and every system is attacked on the same records. All 330 attacker calls completed with no refusals, at a cost of $10.87.

| Re-identification rate ↓ | Hard (n=40) | Implicit (n=40) | Pooled (n=80) |
|---|---|---|---|
| No protection | 100% | 32.5% [20–47] | 53/80 |
| Presidio (the authors' configuration) | 80% [68–93] | 27.5% [15–42] | 43/80 |
| Ours, phase 2 (patterns + dictionary + NER) | 90% [80–97] | 27.5% [15–42] | 47/80 |
| Ours, phase 2 + CPU quasi-identifiers (`VEIL_QUASI=all`, the production default) | 75% | 27.5% | 41/80 |
| **Ours, phase 3 (+ local context guard)** | **65% [50–80]** | **12.5% [3–25]** | **31/80** |

Paired exact McNemar tests on the same records:
- Phase 3 vs Presidio: p = 0.023
- Phase 3 vs phase 2: p < 0.001
- Phase 2 vs Presidio: p = 0.42, no significant difference
- Phase 2 + CPU quasi vs Presidio: p = 0.65, no significant difference (41 vs 44 of 80)
- Phase 3 vs phase 2 + CPU quasi: p = 0.031

The second attack run on the same saved guesses gave Presidio 82.5% instead of 80% on the hard level. CorrectMatch refits its model each run, so the score varies slightly between runs.

**How to read this:**
- **Phase 2 leaks fewer direct identifiers than Presidio** (hard: 17 vs 25 records with a correctly guessed direct identifier). Presidio blanks every date and location, and the risk score counts birth date and state. Phase 2 keeps those for utility, so it does not beat Presidio on this score. Closing that gap is phase 3's job.
- **CPU quasi-identifier protection** (shipped in the proxy) closes the gap to Presidio and edges past it on hard records (75% vs 82.5%), at equal utility. It does nothing for *implicit* records, whose clues are not taggable values ("since the divorce", "up north"). Only the LLM rewrite catches those.
- **Phase 3 is the only system that significantly beats Presidio.** It has 6 direct-identifier hits on hard records, and implicit-level risk falls from 27.5% to 12.5%.
- **The pipeline reproduces the paper.** On these subsets, our reproduction gives no protection 100% / 32.5% and Presidio 80–82.5% / 27.5%. The paper reports 98% / 32% and 77% / 30%.
- **The paper's other numbers are a rough reference only, since its attacker differs:**
  - Azure AI Language PII: 33% hard, 21% implicit.
  - Best LLM anonymiser (iterative GPT-4.1): 18% / 18%.
- **Limits:** n = 40 per level, a single attacker run, and English only.

**Local patches to the RAT-Bench clone** (run outside this repo):
- the census-file path;
- credentials read from environment variables;
- a usage and stop-reason log in the Claude attacker;
- a slim runner that skips anonymisers that don't install on macOS;
- a CorrectMatch encoding fix. The current CorrectMatch.jl treats raw census codes as already encoded 1..K. Values are re-encoded to 1..K the same way CorrectMatch's categorical path does, and this was checked equal to the original path wherever that path works.

## 2. Direct identifiers, RAT-Bench (proxy leak, all systems)

This is a quick, attacker-free proxy. An independent checker looks for gold direct identifiers in the outbound text. Lower leak is better; higher BLEU means more of the text is preserved.

| System | EN easy | EN hard | BLEU easy / hard / implicit |
|---|---|---|---|
| No protection | 100% | 79% | 100 / 100 / 100 |
| Presidio (default) | 18% | 50% | 89 / 91 / 92 |
| GLiNER alone | 34% | 51% | 87 / 86 / 88 |
| **Ours, phase 2** | **8%** | **28%** | **96 / 97 / 99** |

On the 40-record hard subset:

| System | Leak | BLEU |
|---|---|---|
| Presidio | 45% | 91 |
| Ours, phase 2 | 25% | 97 |
| **Ours, phase 3** | **5%** | 88 |

**Dutch and Serbian, phase 2** (*pre-fix*, with 2 Dutch records blocked):

| System | Dutch | Serbian | BLEU (Dutch / Serbian) |
|---|---|---|---|
| Presidio | 46% | 26% | 59 / 35 |
| Ours, phase 2 | 11% | 7% | 71 / 87 |

The patterns for Belgian RRN, Serbian JMBG and Serbian phone numbers were added after inspecting those configs. The Hugging Face "spanish" config is a copy of the English records, so Spanish was not tested.

## 3. Earlier attacker studies (*pre-fix*, superseded by §1)

These were run on outputs from before the blocking fix, on the same 80 records:

| Study | No protection | Presidio | Phase 2 | Phase 3 | Phase 3 vs Presidio |
|---|---|---|---|---|---|
| Local Llama-3.1-8B attacker, attributes inferred | 57.5% | 50.7% | 51.9% | 44.7% | p = 0.015 |
| GPT-4.1 attacker via OpenRouter | 76.9% | 73.2% | 67.8% | 64.4% | p = 0.0002 |

GPT-6.1-sol was discarded as an attacker because it refused too often.

## 4. UAE synthetic benchmark (`bench/run.py`)

The test set has 900 samples across 9 evasion families, mixing Arabic and English, with clients the branch knows and names it does not. Results:
- Presidio leaks 44–100%, depending on the evasion family.
- **Ours, phase 2 leaks 0/900.**
- Restoration is 100% under 4 model-output manglings.

This is our own test set, so it plays to our strengths.

## Known limits

- **Indirect identifiers.** Even phase 3 leaves 65% of hard records re-identifiable under a frontier attacker. No published method solves combination leakage.
- **Phase 3 latency.** It takes roughly 35 s per message on an M5 laptop with a 4B model. A NER trigger (≤ 0.1 s) skips it for messages that contain no personal attributes.
- **Cross-script links.** The same unknown person in Arabic and Latin script gets two tags. Branch-dictionary clients are linked.
- **Vault.** It is written in Python, so wiping memory cannot be guaranteed. It moves to Rust in phase 4.
- **Azure PII.** A head-to-head with Azure AI Language PII on the same attacker still needs Azure credentials.
