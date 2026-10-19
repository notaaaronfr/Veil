"""CPU latency of Veil's protect step (what each request pays before going upstream).

    uv run python bench/latency.py [--threads 4] [--n 30]
"""

import argparse
import statistics
import time

import torch

from veil import Veil
from veil.ner import NERDetector

SHORT = "Please draft a reply to Priya Raghunathan about invoice 4471; her number is +971 50 123 4567."
MEDIUM = (SHORT + " She works at Acme Trading LLC in Dubai and asked to move the meeting with Johan Lindqvist. "
          "Her card 4111 1111 1111 1111 was charged twice. ") * 4
LONG = MEDIUM * 3


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--n", type=int, default=30)
    a = ap.parse_args()
    torch.set_num_threads(a.threads)
    for name, ner in [("patterns+dictionary", None), ("+ NER (CPU)", NERDetector(device="cpu"))]:
        veil = Veil(ner=ner)
        veil.session().protect(SHORT)  # warm-up / model load
        for label, text in [("short", SHORT), ("medium", MEDIUM), ("long", LONG)]:
            ms = []
            for _ in range(a.n):
                s = veil.session()
                t = time.perf_counter()
                s.protect(text)
                ms.append((time.perf_counter() - t) * 1000)
                s.close()
            print(f"{name:<22}{label:<8}{len(text):>6} chars   p50 {statistics.median(ms):7.1f} ms   p95 {pct(ms, 95):7.1f} ms")


if __name__ == "__main__":
    main()
