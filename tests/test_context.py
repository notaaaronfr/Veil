from sandwich import Sandwich
from sandwich.context import ContextGuard, _recovers


class ScriptedLLM:
    """Returns canned JSON per call: first extraction, then adversary guesses, then edits."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = 0

    def json(self, system, user, max_tokens=0):
        self.calls += 1
        return self.replies.pop(0) if self.replies else {}


TEXT = "I'm a 52-year-old cardiologist from Chennai, at 195 Palm St. Refund AED 1,200 please."


def guard(*replies):
    return Sandwich(b"k" * 32, context=ContextGuard(ScriptedLLM(*replies))).session()


def test_edits_apply_only_to_real_substrings_and_keep_essentials():
    s = guard(
        {
            "items": [
                {"text": "52-year-old", "kind": "quasi", "attribute": "age", "general": "middle-aged"},
                {"text": "cardiologist", "kind": "quasi", "attribute": "occupation", "essential": True},
                {"text": "195 Palm St", "kind": "direct", "attribute": "street address"},
                {"text": "invented phrase", "kind": "quasi", "attribute": "x", "general": "y"},
                {"text": "AED 1,200", "kind": "direct", "attribute": "refund amount"},
            ]
        },
        {"guesses": []},
    )
    p = s.protect(TEXT, task="request a refund")
    assert p.outbound == "I'm a middle-aged cardiologist from Chennai, at [ADDRESS_1]. Refund AED 1,200 please."
    assert p.context.kept_essential == 1 and p.context.tagged == 1 and p.context.generalised == 1
    out, _ = s.receive("Your address [ADDRESS_1] is on file.")
    assert out == "Your address 195 Palm St is on file."


def test_adversary_loop_generalises_evidence_that_recovers_originals():
    s = guard(
        {"items": [{"text": "Chennai", "kind": "quasi", "attribute": "birthplace", "general": "a large city"}]},
        # adversary still recovers Chennai with certainty 5 from "Marina Beach"
        {"guesses": [{"attribute": "birthplace", "guess": "Chennai", "certainty": 5, "evidence": ["Marina Beach"]}]},
        {"items": [{"text": "Marina Beach", "kind": "quasi", "attribute": "landmark", "general": "the beach"}]},
        {"guesses": []},
    )
    p = s.protect("Born in Chennai, I grew up near Marina Beach.")
    assert p.outbound == "Born in a large city, I grew up near the beach."
    assert p.context.rounds == 2


def test_vague_guesses_are_not_hits():
    assert not _recovers("in their 50s", {"52-year-old"})
    assert _recovers("52", {"52-year-old"})
    assert _recovers("pediatric cardiologist", {"cardiologist"})
    assert not _recovers("a doctor", {"cardiologist"})
