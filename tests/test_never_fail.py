import time

from veil import BranchDictionary, Entity, Veil
from veil.context import ContextGuard

DICT = BranchDictionary([Entity("c1", "PERSON", ["Sara Al Mansoori"])])
TEXT = "Email Sara Al Mansoori about card 4111 1111 1111 1111"


class BrokenNER:
    def detect(self, text):
        raise RuntimeError("model file corrupt")


class SlowLLM:
    def json(self, system, user, max_tokens=0):
        time.sleep(2)
        return {}


def test_ner_failure_degrades_to_deterministic_layers():
    s = Veil(b"k" * 32, DICT, ner=BrokenNER()).session()
    p = s.protect(TEXT)
    assert p.degraded == ["ner"]
    assert "Sara" not in p.outbound and "4111 1111" not in p.outbound


def test_context_guard_over_budget_sends_phase2_output():
    s = Veil(b"k" * 32, DICT, context=ContextGuard(SlowLLM()), context_budget=0.2).session()
    t0 = time.time()
    p = s.protect(TEXT)
    assert time.time() - t0 < 1.5
    assert "context-timeout" in p.degraded
    assert p.outbound.startswith("Email [PERSON_1] about card ")


def test_unscrubbable_leak_is_redacted_not_blocked(monkeypatch):
    s = Veil(b"k" * 32, DICT).session()
    monkeypatch.setattr(s, "_scrub", lambda text, hits: text)  # scrubber can't fix anything
    # force a leak: the transform "misses" the second mention
    real_apply = s._tx.apply
    monkeypatch.setattr(s._tx, "apply", lambda text, spans: real_apply(text, spans[:1]) )
    p = s.protect("Sara Al Mansoori called. Sara Al Mansoori again.")
    assert not p.blocked
    assert p.redacted >= 1 and "PERSON" in p.residual
    assert "Sara" not in p.outbound and "[REDACTED]" in p.outbound
