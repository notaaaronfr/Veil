"""Plug-in for the official RAT-Bench pipeline (github.com/imperial-aisp/rat-bench).

The official score covers direct AND indirect identifiers. It uses a GPT-4.1 attacker,
so it needs an OpenAI key in their credentials.py. To run it:

    git clone https://github.com/imperial-aisp/rat-bench && cd rat-bench && uv sync
    python install_correctmatch.py
    cp /path/to/pseudonamise/bench/ratbench_official.py pii_benchmark/anonymizers/sandwich_anonymizer.py
    uv pip install -e /path/to/pseudonamise
    # register SandwichAnonymizer in pii_benchmark/anonymizers/get_anonymizers.py
    # then run scripts/*.sh: generate -> anonymize -> attack -> utility

Only the outbound text is scored. Restoration happens after the attacker would see it,
so it does not affect the score.
"""

from sandwich import Sandwich
from sandwich.ner import NERDetector

try:  # base class location per the RAT-Bench README
    from pii_benchmark.anonymizers.anonymizer import Anonymizer
except ImportError:  # allow import outside the RAT-Bench tree
    Anonymizer = object


class SandwichAnonymizer(Anonymizer):
    name = "sandwich"

    def __init__(self, *args, device: str = "cpu", **kwargs):
        self._sw = Sandwich(ner=NERDetector(device=device))

    def anonymize(self, text: str) -> str:
        s = self._sw.session()
        try:
            p = s.protect(text)
            return "" if p.blocked else p.outbound
        finally:
            s.close()
