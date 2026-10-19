"""Build official RAT-Bench input files with our outputs injected.

Run with the RAT-Bench venv, from the rat-bench repo root:
    cd ~/rat-bench-official && .venv/bin/python ~/pseudonamise/bench/official_prep.py

Writes:
  benchmark_full/level_{1,2,3}.jsonl  100 records each: pre_anon, presidio (their config, run
                                     fresh here), sandwich_p2 (our saved outputs)
  benchmark_sub/level_{2,3}.jsonl     first 40 hard / implicit: + sandwich_p3
"""

import json
import sys
from pathlib import Path

from datasets import load_dataset

sys.path.insert(0, ".")
from pii_benchmark.anonymizers.presidio import PresidioAnonymizer  # noqa: E402

OURS = Path.home() / "pseudonamise/bench/out"


def saved(name: str) -> list[str]:
    return [json.loads(line)["out"] for line in (OURS / name).open()]


def _merge(path: Path, fresh: list[dict], ours: dict[str, list[str]]) -> None:
    """Write `fresh` records, but keep everything an earlier run already added to the file
    (baseline guesses cost API calls). Our fields are replaced and their stale
    guesses/correctness dropped, so only our methods get re-attacked."""
    old = [json.loads(line) for line in path.open()] if path.exists() else fresh
    assert [r["id"] for r in old] == [r["id"] for r in fresh]
    with path.open("w") as f:
        for i, rec in enumerate(old):
            for method, texts in ours.items():
                rec = {k: v for k, v in rec.items() if not (method in k and k != f"text_anon_{method}")}
                rec[f"text_anon_{method}"] = texts[i]
            f.write(json.dumps(rec) + "\n")


def main():
    data = list(load_dataset("imperial-cpg/rat-bench", "english")["train"])
    p2 = saved("ratbench_english_ours-p2.jsonl")
    assert len(p2) == len(data) == 300
    presidio = PresidioAnonymizer()

    by_level: dict[int, list[dict]] = {1: [], 2: [], 3: []}
    p2_level: dict[int, list[str]] = {1: [], 2: [], 3: []}
    for r, ours in zip(data, p2):
        rec = dict(r)
        rec["text_anon_presidio"] = presidio.anonymize(r["text"])
        by_level[r["difficulty"]].append(rec)
        p2_level[r["difficulty"]].append(ours)

    full = Path("benchmark_full")
    full.mkdir(exist_ok=True)
    for lvl, recs in by_level.items():
        _merge(full / f"level_{lvl}.jsonl", recs, {"sandwich_p2": p2_level[lvl]})

    # phase-3 subset: saved in subset order = first 40 hard, then first 40 implicit
    p3 = saved("ratbench_english_ours-p3_sub.jsonl")
    assert len(p3) == 80
    sub = Path("benchmark_sub")
    sub.mkdir(exist_ok=True)
    for j, lvl in enumerate((2, 3)):
        _merge(
            sub / f"level_{lvl}.jsonl",
            by_level[lvl][:40],
            {"sandwich_p2": p2_level[lvl][:40], "sandwich_p3": p3[40 * j : 40 * (j + 1)]},
        )
    blocked = sum(t == "<BLOCKED>" for t in p2) + sum(t == "<BLOCKED>" for t in p3)
    print("written:", {lvl: len(v) for lvl, v in by_level.items()}, "+ subset 40/40; blocked outputs:", blocked)


if __name__ == "__main__":
    main()
