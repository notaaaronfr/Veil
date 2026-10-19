# Verified Sandwich: design

A pseudonymisation layer for LLM calls made from inside a Tuego branch. Every component traces to a published result. "Best in market" is a claim we must prove on public benchmarks, not assert.

## Why the plain sandwich is not enough

| Gap in the plain sandwich / market tools | Evidence |
|---|---|
| Span-only replacement misses repeat mentions | DR-SL: 159/160 "protected" outputs still held literal values |
| Detectors are evaded by zero-width, homoglyph, fullwidth, spelled-out digits | BodhiPromptShield: up to 99.7% attack success |
| Presidio fails hard formats and non-English | RAT-Bench: 77% re-identified (hard), 86–88% (ES/ZH) |
| Quasi-identifiers leak even with perfect entity removal | RAT-Bench: 19–37% implicit re-id for *every* tool; Staab: 44–64% attribute accuracy after Azure PII |
| Opaque tokens break tasks that need the format of an ID | Pr∈∈mpt: FPE 100% vs AES blob 70.97% on lookup tasks |
| Early restoration leaks into history/memory/tools | Bodhi: 51% exposure (early) vs 1.6% (late) |
| Model-based restoration hallucinates | HaS, Pr∈∈mpt NER-desanitisation misses |

## Architecture

```
TOP SLICE (in branch)
  0  Canonicalise        NFKC, strip zero-width, Arabic-Indic → ASCII digits,
                         fold mixed-script homoglyphs
  1  Detect              a. patterns + checksums (Emirates ID, IBAN, card, phone, email, IP)
                         b. branch dictionary of known entities (clients, staff), Arabic+Latin,
                            every occurrence and every name component
                         c. NER: Wojood/AraBERT (AR) + GLiNER-PII (EN)            [phase 2]
  2  Classify need       local 3–8B: essential vs non-essential vs quasi-identifier [phase 3]
  3  Transform           per-type strategy (below)
  4  Rewrite context     generalise non-essential quasi-identifiers               [phase 3]
  5  Attack locally      Staab-style attribute adversary + enumeration probe;
                         ≤3 rounds (SEAL); fail → answer locally / human          [phase 3]
  6  Egress hard line    every original value, normalised, every occurrence,
                         searched in the FINAL payload → block on any hit
FILLING                  external model (Azure OpenAI UAE North) sees only step-6-cleared text
BOTTOM SLICE (in branch)
  7  Restore             allowlist of issued surrogates only; exact → tolerant tag →
                         digit-normalised; unknown tags flagged, never guessed
  8  Dual history        LLM context stays pseudonymised; real values only for display
                         or an authorised tool call (late restoration)
```

## Per-type strategy

| Type | Strategy | Source |
|---|---|---|
| Person names | Indexed typed tags `[PERSON_1]` with component tags `[PERSON_1_FIRST]` / `[PERSON_1_LAST]` (coreference by construction) | Deußer 2026; Pasch & Cha 2025 (tags ≥ surrogates on utility); gap: no paper measures variant coreference |
| Orgs, locations | Indexed tags; leave public subject-of-query entities alone | LOPSIDED; Deußer over-detection |
| Emirates ID, IBAN, card, phone | **FF1** format-preserving encryption, per-session key, tweak = type, checksums recomputed (Luhn, mod-97) | Pr∈∈mpt (FF3 there; FF3 is deprecated by NIST, so FF1) |
| Email | Indexed tag | — |
| Amounts, ages | Phase 3: mDP noise with dependency graph, or keep when essential | Pr∈∈mpt Alg. 3 |
| Quasi-identifiers | Phase 3: generalise (age 52 → 50–59) rather than delete | DR-SL: generalisation 0.431 utility vs placeholders 0.228 at equal leakage |

Explicitly rejected: word/char-level DP text noise (reversed by LLMs: Pang RAID'25, Meisenbacher WPES'25), ConfusionPrompt decoys (real prompt still sent, ≥15× cost), PrivacyRestore and TEE/MPC/FHE (need provider cooperation).

## Key handling

- The session key is derived via HKDF-SHA256 from the branch key with salt = session id. Sessions cannot be linked, and a leaked session key exposes only that session.
- The mapping is held AES-256-GCM-encrypted in memory and wiped when the session closes.
- Python cannot guarantee that immutable strings are zeroed. The production vault should be Rust or C with `mlock` and `zeroize`. See "Illusion of Local Privacy" (2026) for the residue failure modes.
- Local model server rules: no slot-save, no sensitive logging, no telemetry, and a restart between tenants.

## Evaluation (the proof)

| Metric | How | Bar to claim "best" |
|---|---|---|
| Re-identification | RAT-Bench (easy/hard/implicit, EN/ES/ZH) | Beat Azure PII (22/33/21) |
| Quality vs leak | PUPA (901 real prompts), swap-consistent judge | Beat P2Skill 15.6% leak / 0.69 quality |
| Leak of what left the branch | Gold values normalised-searched in outbound payload | 0 literal leaks, Wilson 95% UB reported |
| Restoration | Issued → restored exactly; mangled/hallucinated tags counted | ≥ 99.5% |
| Evasion | 8 families (zero-width, homoglyph, fullwidth, spacing, case, leet, separator, spelled digits) | Report ASR per family |
| Arabic / UAE | Own synthetic UAE persona set (released openly; no public Arabic PII benchmark exists) | First public numbers |
| Attacks | Placeholder inversion, cross-request linkage, directory linkage, injection via restore | Report each |

Baselines on identical splits: Presidio, Azure AI Language PII, GLiNER-PII, and no protection.

## Phases

1. **Deterministic core.** Canonicalisation, pattern detection with checksums, branch dictionary, FF1, encrypted vault, egress hard line, allowlist restore, synthetic UAE harness. No models needed.
2. **NER.** Wojood/AraBERT and GLiNER-PII, Presidio and Azure baselines, RAT-Bench adapter.
3. **Context.** Need-classifier, generalisation, local adversary loop (SEAL-style), route-to-local fallback, PUPA run.
4. **Hardening.** Rust vault, canary sweep of local model server, streaming restore.
