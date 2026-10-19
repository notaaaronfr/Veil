"""Step 0: canonicalise text before detection.

Closes the evasion families BodhiPromptShield measured (zero-width up to 99.7% ASR,
homoglyph, fullwidth, spelled-out digits) and RAT-Bench "hard" formats.
"""

from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎‎‏"))

_DIGITS = {**{0x0660 + i: str(i) for i in range(10)}, **{0x06F0 + i: str(i) for i in range(10)}}

# Cyrillic/Greek letters that render like Latin. Only folded inside mixed-script tokens,
# so genuine Russian or Greek text is left alone.
_CONFUSABLES = str.maketrans(
    "аеорсхуіјѕԁһӏАВЕКМНОРСТХУІЈЅαοκνρτυχΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aeopcxyijsdhlABEKMHOPCTXYIJSaokvptyxABEZHIKMNOPTYX",
)
_LATIN = re.compile(r"[A-Za-z]")
_NONLATIN_CONFUSABLE = re.compile(r"[Ͱ-ϿЀ-ӿ]")

_EN_DIGIT_WORDS = "zero one two three four five six seven eight nine".split()
_AR_DIGIT_WORDS = ["صفر", "واحد", "اثنان", "ثلاثة", "أربعة", "خمسة", "ستة", "سبعة", "ثمانية", "تسعة"]
_WORD_TO_DIGIT = {w: str(i) for i, w in enumerate(_EN_DIGIT_WORDS)} | {
    w: str(i) for i, w in enumerate(_AR_DIGIT_WORDS)
}
_DIGIT_WORD = "|".join(map(re.escape, sorted(_WORD_TO_DIGIT, key=len, reverse=True)))
# Six or more digit words in a row is an identifier, not prose.
_SPELLED_RUN = re.compile(rf"(?<!\w)(?:{_DIGIT_WORD})(?:[\s,\-]+(?:{_DIGIT_WORD})){{5,}}(?!\w)", re.I)


def _fold_mixed_script(text: str) -> str:
    def fold(m: re.Match) -> str:
        tok = m.group(0)
        if _LATIN.search(tok) and _NONLATIN_CONFUSABLE.search(tok):
            return tok.translate(_CONFUSABLES)
        return tok

    return re.sub(r"\w+", fold, text)


def _spelled_digits(text: str) -> str:
    def conv(m: re.Match) -> str:
        words = re.findall(_DIGIT_WORD, m.group(0), re.I)
        return "".join(_WORD_TO_DIGIT[w.lower()] for w in words)

    return _SPELLED_RUN.sub(conv, text)


def canonicalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(ZERO_WIDTH).translate(_DIGITS)
    text = _fold_mixed_script(text)
    return _spelled_digits(text)


# --- matching helpers (used for detection and the egress check, never to rewrite text) ---

_AR_CLASS = {
    "ا": "[اأإآٱ]", "أ": "[اأإآٱ]", "إ": "[اأإآٱ]", "آ": "[اأإآٱ]",
    "ي": "[يى]", "ى": "[يى]", "ة": "[ةه]", "ه": "[ةه]",
}
_AR_MARKS = "[ً-ٰٟـ]*"  # harakat + tatweel


def tolerant_pattern(value: str) -> str:
    """Regex for `value` tolerant of case, spacing/hyphens, Arabic letter variants and diacritics."""
    parts = []
    for tok in re.split(r"[\s\-]+", value.strip()):
        chars = []
        for ch in tok:
            if ch in _AR_CLASS:
                chars.append(_AR_CLASS[ch])
            else:
                chars.append(re.escape(ch))
            if "؀" <= ch <= "ۿ":
                chars.append(_AR_MARKS)
        parts.append("".join(chars))
    return r"(?<!\w)" + r"[\s\-]+".join(parts) + r"(?!\w)"
