"""RAT-Bench head-to-head on DIRECT identifiers (name, SSN, card, phone, address, email).

Systems: none | presidio (default, en_core_web_lg, <TYPE> replacement — RAT-Bench's setup)
         | gliner (GLiNER multi-PII alone, <TYPE>) | ours-p1 (no NER) | ours-p2 (with NER)

Leak metric is a PROXY, computed by an independent checker from RAT-Bench's gold values:
  numbers  leaked if >=5 consecutive gold digits survive (spelled digits folded first)
  name     leaked if any name token (>=3 chars) survives as a word
  email    leaked if the local part survives (spoken "dot", spaces, hyphens folded away)
  address  leaked if the house number or the street's core word survives
The official RAT-Bench risk score needs their GPT-4.1 attacker (API key) and also covers
indirect identifiers; this proxy covers direct identifiers only.

    uv run python bench/ratbench.py --lang english spanish
"""

from __future__ import annotations

import argparse
import json
import re
import time
import unicodedata
from collections import defaultdict
from pathlib import Path

from datasets import load_dataset
from sacrebleu.metrics import BLEU

from run import fmt  # Wilson-CI formatter

OUT = Path(__file__).parent / "out"
WORDS = {w: str(i) for i, w in enumerate("zero one two three four five six seven eight nine".split())}
WORDS |= {w: str(i) for i, w in enumerate("cero uno dos tres cuatro cinco seis siete ocho nueve".split())}
DIRECTIONS = {"n", "s", "e", "w", "north", "south", "east", "west", "ne", "nw", "se", "sw"}


def fold(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).casefold()
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")
    return re.sub(r"\b(" + "|".join(WORDS) + r")\b", lambda m: WORDS[m[1]], s)


def has_word(tok: str, text: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(tok)}s?(?!\w)", text) is not None


def leaked(kind: str, gold: str, out: str) -> bool:
    o = fold(out)
    g = fold(gold)
    if kind in ("SSN", "credit card number", "phone number", "RRN", "JMBG"):
        gd = re.sub(r"\D", "", g)
        od = re.sub(r"(?<=\d)[\s\-.(),/]{1,3}(?=\d)", "", o)
        return any(gd[i : i + 5] in run for run in re.findall(r"\d{5,}", od) for i in range(len(gd) - 4))
    if kind == "name":
        return any(has_word(t, o) for t in re.findall(r"\w{3,}", g))
    if kind == "email":
        # "lisa dot redbird eight three at gee mail" -> lisaredbird83atgeemail
        compact = lambda s: re.sub(r"[\s\-_.]|\bdot\b|\bpunto\b", "", s)
        return compact(g.split("@")[0]) in compact(o)
    if kind == "address":
        m = re.match(r"\s*(\d+)\s+(.*)", g)
        if not m:  # European order: "Nieuwstraat 144, 8000 Brugge"
            m2 = re.match(r"\s*([^\d,]+?)\s+(\d+)", g)
            if not m2:
                return any(has_word(t, o) for t in re.findall(r"[a-z]{4,}", g))
            street, number = m2.groups()
            core = next((t for t in re.findall(r"\w{4,}", street)), None)
            return bool(re.search(rf"(?<!\d){number}(?!\d)", o)) or (core is not None and has_word(core, o))
        number, rest = m.groups()
        core = next((t for t in re.findall(r"[a-z]+", rest) if t not in DIRECTIONS and len(t) >= 4), None)
        return bool(re.search(rf"(?<!\d){number}(?!\d)", o)) or (core is not None and has_word(core, o))
    raise ValueError(kind)


# ---------------- systems ----------------

def sys_none():
    return lambda t: t


def sys_presidio():
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine

    an, anon = AnalyzerEngine(), AnonymizerEngine()
    return lambda t: anon.anonymize(text=t, analyzer_results=an.analyze(text=t, language="en")).text


def sys_azure():
    """Azure AI Language PII (RAT-Bench's best NER tool). Needs AZURE_LANGUAGE_ENDPOINT/KEY
    and `uv add azure-ai-textanalytics`. Sends text to Azure — synthetic data only."""
    import os

    from azure.ai.textanalytics import TextAnalyticsClient
    from azure.core.credentials import AzureKeyCredential

    client = TextAnalyticsClient(
        os.environ["AZURE_LANGUAGE_ENDPOINT"], AzureKeyCredential(os.environ["AZURE_LANGUAGE_KEY"])
    )

    def run(t):
        chunks = [t[i : i + 5000] for i in range(0, len(t), 5000)]
        return "".join(d.redacted_text for d in client.recognize_pii_entities(chunks))

    return run


def sys_gliner(ner):
    def run(t):
        spans = sorted(ner.detect(t), key=lambda s: (s.start, -(s.end - s.start)))
        out, last = [], 0
        for s in spans:
            if s.start >= last:
                out.append(t[last : s.start] + f"<{s.type}>")
                last = s.end
        return "".join(out) + t[last:]

    return run


TASK = "summarise this conversation and answer questions about what was discussed"


def sys_ours(ner=None, context=None):
    from sandwich import Sandwich

    sw = Sandwich(ner=ner, context=context)

    def run(t):
        s = sw.session()
        p = s.protect(t, task=TASK)
        s.close()
        return "<BLOCKED>" if p.blocked else p.outbound

    return run


def _context():
    from sandwich.context import ContextGuard

    return ContextGuard()


def load_outputs(lang: str, name: str, tag: str, full, subset) -> dict:
    """Saved outputs keyed by (difficulty, id) — RAT-Bench ids restart at 0 per difficulty.
    Files are written in dataset order, so each line is matched to its record by position
    (against the full dataset or the subset, whichever it was run on), and the id checked."""
    path = OUT / f"ratbench_{lang}_{name}{tag}.jsonl"
    if not path.exists():
        path = OUT / f"ratbench_{lang}_{name}.jsonl"
    lines = [json.loads(line) for line in path.open()]
    ref = full if len(lines) == len(full) else subset
    if len(lines) != len(ref):
        raise ValueError(f"{path.name}: {len(lines)} lines matches neither the full set nor the subset")
    out = {}
    for r, j in zip(ref, lines):
        assert j["id"] == r["id"], f"{path.name}: order mismatch at id {r['id']}"
        out[(r["difficulty"], r["id"])] = j["out"]
    return out


def select(data, per_diff: int, difficulties: list[int] | None):
    """First `per_diff` records of each difficulty (0 = all)."""
    keep, seen = [], defaultdict(int)
    for i, r in enumerate(data):
        d = r["difficulty"]
        if difficulties and d not in difficulties:
            continue
        if per_diff and seen[d] >= per_diff:
            continue
        seen[d] += 1
        keep.append(i)
    return data.select(keep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", nargs="+", default=["english"])
    ap.add_argument("--systems", nargs="+", default=["none", "presidio", "gliner", "ours-p1", "ours-p2"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--rescore", action="store_true", help="score saved outputs, don't re-run systems")
    ap.add_argument("--per-diff", type=int, default=0, help="first N records of each difficulty")
    ap.add_argument("--difficulty", type=int, nargs="*", help="1=easy 2=hard 3=implicit")
    ap.add_argument("--tag", default="", help="suffix for output files (subset runs)")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    from sandwich.ner import NERDetector

    ner = NERDetector(device=args.device)  # loads lazily, so --rescore stays fast
    factories = {
        "none": sys_none,
        "presidio": sys_presidio,
        "azure": sys_azure,
        "gliner": lambda: sys_gliner(ner),
        "ours-p1": lambda: sys_ours(None),
        "ours-p2": lambda: sys_ours(ner),
        "ours-p3": lambda: sys_ours(ner, _context()),
    }
    bleu = BLEU(effective_order=True)

    for lang in args.lang:
        data = full = load_dataset("imperial-cpg/rat-bench", lang)["train"]
        if args.limit:
            data = data.select(range(args.limit))
        if args.per_diff or args.difficulty:
            data = select(data, args.per_diff, args.difficulty)
        print(f"\n=== RAT-Bench {lang}: {len(data)} records (direct identifiers, proxy leak) ===")
        print(f"{'system':<10}{'difficulty':<12}{'records leaking (95% CI)':<34}{'BLEU':>6}   per-type leaks")
        for name in args.systems:
            path = OUT / f"ratbench_{lang}_{name}{args.tag}.jsonl"
            t0 = time.time()
            if args.rescore:
                saved = load_outputs(lang, name, args.tag, full, data)
                rows = [(r, saved[(r["difficulty"], r["id"])]) for r in data]
            else:
                fn = factories[name]()
                rows = []
                with path.open("w") as f:
                    for r in data:
                        out = fn(r["text"])
                        rows.append((r, out))
                        f.write(json.dumps({"id": r["id"], "out": out}, ensure_ascii=False) + "\n")
            secs = (time.time() - t0) / len(data)
            by = defaultdict(lambda: defaultdict(int))
            for r, out in rows:
                d = by[r["difficulty"]]
                d["n"] += 1
                d["bleu"] += bleu.sentence_score(out, [r["text"]]).score
                kinds = [k for k, v in r["direct_identifiers"].items() if leaked(k, v, out)]
                d["leak"] += bool(kinds)
                for k in kinds:
                    d[k] += 1
            for diff in sorted(by):
                d = by[diff]
                types = ", ".join(f"{k}={v}" for k, v in d.items() if k not in ("n", "leak", "bleu"))
                label = {1: "easy", 2: "hard", 3: "implicit"}.get(diff, diff)
                print(f"{name:<10}{label:<12}{fmt(d['leak'], d['n']):<34}{d['bleu'] / d['n']:6.1f}   {types}")
            print(f"{'':<10}{secs:.2f}s/record")


if __name__ == "__main__":
    main()
