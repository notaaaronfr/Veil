"""Steps 2, 4 and 5: need-to-know classification, generalisation, local adversary loop.

Design choices from the literature:
- The local model returns an EDIT LIST (exact substring -> replacement), never a free
  rewrite. Need to Know (2026) found ~7% of free rewrites inject new sensitive facts;
  edits on verified substrings cannot.
- Enumeration-style prompting ("list every value"), not "who is this?": DR-SL (2026)
  found the adversarial-question format produced mostly false passes (enumeration 0.992
  recall of residual values).
- Generalise, don't delete, quasi-identifiers the task doesn't need (DR-SL: semantic
  utility 0.431 vs 0.228 for placeholders at equal leakage). Keep what the task needs
  (Need to Know / PUFT contextual integrity).
- Direct-identifier fragments the NER missed (split card digits, spoken emails,
  paraphrased addresses) become reversible tags, so they restore like everything else.
- Adversary loop (Staab 2025, SEAL 2025): a local attacker guesses attributes and cites
  its evidence; confident guesses get their evidence generalised. ≤ 2 rounds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detect import Span
from .llm import LocalLLM

EXTRACT_SYSTEM = """You are a privacy filter. The text below will be sent to an external AI service.
Some values are already replaced by tags like [PERSON_1] or [ADDRESS_2]; never report tags.

List EVERY remaining piece of text that identifies the person or reveals personal attributes:
- kind "direct": anything pinning down one person or account, including PARTIAL, SPLIT or SPELLED-OUT forms: names, nicknames, street names, house numbers, postcodes, digits of phone/ID/card/account numbers, email handles, usernames, plates.
- kind "quasi": personal attributes: exact age, birth date or year, birthplace, city/region/state, nationality, ethnicity or race, religion, occupation, employer or workplace, school or degree, marital status, family details, health conditions, income, citizenship or immigration status, employment status.

Do NOT list money amounts, prices, product names or transaction details; they are not personal attributes.
Keep each "text" short: only the identifying words, never a whole sentence, never punctuation at the ends.

The user's task is: {task}
Set "essential" true ONLY if the task cannot be done without that exact detail.
For quasi items give "general": a vaguer phrase that fits grammatically in place of "text", keeps the useful meaning, but no longer narrows down the person (e.g. "52-year-old" -> "middle-aged", "pediatric cardiologist" -> "doctor", "Chennai" -> "abroad"). Omit "general" for direct items.

Return JSON only:
{{"items":[{{"text":"<exact substring>","kind":"direct|quasi","attribute":"<short name>","essential":false,"general":"<vaguer phrase>"}}]}}"""

ADVERSARY_SYSTEM = """You are a privacy auditor playing a guessing game. Read the text and infer, about the main person, as many of these as you can: sex, age, birth year, location (city/state/country), nationality or birthplace, marital status, occupation, employer, education, ethnicity.
For each attribute give your best guess, your certainty from 1 (wild guess) to 5 (stated or near-certain), and the exact phrases from the text that gave it away.
Return JSON only:
{"guesses":[{"attribute":"...","guess":"...","certainty":1,"evidence":["<exact phrase from the text>"]}]}"""

_DIRECT_TYPES = [
    (re.compile(r"address|street|house|postcode|zip|road", re.I), "ADDRESS"),
    (re.compile(r"email|handle|username", re.I), "EMAIL"),
    (re.compile(r"phone|mobile|tel", re.I), "PHONE"),
    (re.compile(r"card", re.I), "CARD"),
    (re.compile(r"name|nickname", re.I), "PERSON"),
]
_TAG = re.compile(r"\[[A-Z_]+_\d+(?:_[A-Z]+)?\]")


def _direct_type(attribute: str) -> str:
    for rx, t in _DIRECT_TYPES:
        if rx.search(attribute):
            return t
    return "ID"


def _chunks(text: str, size: int = 2000):
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = max(text.rfind(c, start + size // 2, end) for c in ".\n!?؟")
            end = cut + 1 if cut > start else end
        yield text[start:end]
        start = end


@dataclass
class ContextReport:
    tagged: int = 0  # direct fragments turned into reversible tags
    generalised: int = 0  # quasi-identifiers made vaguer (not restored)
    kept_essential: int = 0
    adversary_hits: list[str] = field(default_factory=list)  # attributes still guessed with certainty >= 4
    rounds: int = 0


class ContextGuard:
    def __init__(self, llm: LocalLLM | None = None, rounds: int = 2, certainty: int = 4):
        self.llm = llm or LocalLLM()
        self.rounds = rounds
        self.certainty = certainty

    # -- edits --------------------------------------------------------------------------

    def _extract(self, text: str, task: str) -> list[dict]:
        items = []
        for chunk in _chunks(text):
            out = self.llm.json(EXTRACT_SYSTEM.format(task=task), chunk, max_tokens=1200)
            items += [i for i in out.get("items", []) if isinstance(i, dict)]
        return items

    @staticmethod
    def _valid(item_text: str, text: str) -> bool:
        t = item_text.strip()
        return 2 <= len(t) <= 80 and not _TAG.fullmatch(t) and t in text

    def _apply(
        self, text: str, items: list[dict], tx, rep: ContextReport, essential: set[str], truth: dict | None = None
    ) -> str:
        edits: list[tuple[int, int, str]] = []
        for it in sorted(items, key=lambda i: -len(str(i.get("text", "")))):
            t = str(it.get("text", "")).strip(" .,;:!?\"'")
            if not self._valid(t, text) or _NOT_PERSONAL.search(str(it.get("attribute", ""))):
                continue
            if truth is not None and it.get("kind") == "quasi":
                truth.setdefault(str(it.get("attribute", "")).casefold(), set()).add(t)
            if it.get("kind") == "quasi" and it.get("essential"):
                essential.add(t)
                rep.kept_essential += 1
                continue
            if t in essential:
                continue
            for m in re.finditer(re.escape(t), text):
                s, e = m.span()
                if any(s < b and a < e for a, b, _ in edits) or _inside_tag(text, s, e):
                    continue
                if it.get("kind") == "direct":
                    sur = tx.surrogate_for(Span(s, e, _direct_type(str(it.get("attribute", ""))), t))
                    edits.append((s, e, sur))
                    rep.tagged += 1
                else:
                    general = str(it.get("general", "")).strip()
                    if not general or t.casefold() in general.casefold():
                        continue
                    edits.append((s, e, general))
                    rep.generalised += 1
        for s, e, r in sorted(edits, reverse=True):
            text = text[:s] + r + text[e:]
        return text

    # -- adversary loop -----------------------------------------------------------------

    def _adversary(self, text: str) -> list[dict]:
        out = self.llm.json(ADVERSARY_SYSTEM, text[:6000], max_tokens=500)
        return [g for g in out.get("guesses", []) if isinstance(g, dict)]

    def protect(self, text: str, tx, task: str | None = None) -> tuple[str, ContextReport]:
        rep = ContextReport()
        task = task or "answer the user's request in the text"
        essential: set[str] = set()
        truth: dict[str, set[str]] = {}  # original quasi values, known only inside the branch
        text = self._apply(text, self._extract(text, task), tx, rep, essential, truth)
        originals = {v for vals in truth.values() for v in vals} - essential
        for _ in range(self.rounds):
            if not originals:
                break
            rep.rounds += 1
            # a hit = confident guess that recovers an ORIGINAL value, not the generalised one
            confident = [
                g
                for g in self._adversary(text)
                if _num(g.get("certainty")) >= self.certainty and _recovers(str(g.get("guess", "")), originals)
            ]
            evidence = [
                {"text": p, "kind": "quasi", "attribute": g.get("attribute", ""), "general": ""}
                for g in confident
                for p in g.get("evidence", []) or []
                if isinstance(p, str) and self._valid(p.strip(), text) and p.strip() not in essential
            ]
            rep.adversary_hits = sorted({str(g.get("attribute")) for g in confident})
            if not evidence:
                break
            # ask for vaguer forms of exactly the phrases that gave the person away
            phrases = "\n".join(f"- {e['text']}" for e in evidence)
            out = self.llm.json(
                EXTRACT_SYSTEM.format(task=task),
                f"Only consider these phrases, which still reveal the person; make each vaguer:\n{phrases}\n\nFull text for context:\n{text[:4000]}",
                max_tokens=800,
            )
            items = [i for i in out.get("items", []) if isinstance(i, dict)]
            before = text
            text = self._apply(text, items, tx, rep, essential)
            if text == before:
                break
        return text, rep


_NOT_PERSONAL = re.compile(r"amount|money|price|charge|cost|fee|payment|product|transaction", re.I)
_STOP = {"the", "and", "with", "from", "for", "year", "years", "old", "who", "has", "was", "his", "her"}


def _recovers(guess: str, originals: set[str]) -> bool:
    """Does the guess name an original value? Numbers must match exactly (52 vs 'in their 50s');
    words must share a content word of 4+ letters (cardiologist, Chennai)."""
    g = guess.casefold()
    g_nums = set(re.findall(r"\d+", g))
    g_words = {w for w in re.findall(r"[^\W\d_]{4,}", g)} - _STOP
    for o in originals:
        o = o.casefold()
        if g_nums & set(re.findall(r"\d+", o)):
            return True
        if g_words & ({w for w in re.findall(r"[^\W\d_]{4,}", o)} - _STOP):
            return True
    return False


def _inside_tag(text: str, s: int, e: int) -> bool:
    for m in _TAG.finditer(text, max(0, s - 40), min(len(text), e + 40)):
        if m.start() < e and s < m.end():
            return True
    return False


def _num(x) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0
