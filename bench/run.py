"""Phase-1 benchmark on synthetic UAE data.

Measures, per evasion family:
  leak     — share of samples where ANY gold value is in the outbound payload, judged by an
             independent checker (not the gate we are testing)
  blocked  — share the hard line refused to send
  restore  — share where the restored reply equals the original after a simulated LLM echo,
             under several tag/number manglings models are known to produce
Names come in two kinds: known to the branch dictionary (detectable now) and unknown
(needs NER, phase 2) — reported separately so the NER gap is visible, not hidden.

    uv run python bench/run.py [--n 300] [--seed 7]
"""

from __future__ import annotations

import argparse
import math
import random
import re
import unicodedata
from collections import defaultdict

from veil import BranchDictionary, Entity, Sandwich
from veil.canonical import canonicalise
from veil.fpe import iban_check_digits, luhn_check_digit

FIRST = [("Sara", "سارة"), ("Mohammed", "محمد"), ("Fatima", "فاطمة"), ("Khalid", "خالد"),
         ("Aisha", "عائشة"), ("Omar", "عمر"), ("Mariam", "مريم"), ("Rashid", "راشد"),
         ("Noura", "نورة"), ("Hamdan", "حمدان"), ("Layla", "ليلى"), ("Saeed", "سعيد")]
LAST = [("Al Mansoori", "المنصوري"), ("Al Nahyan", "النهيان"), ("Al Shamsi", "الشامسي"),
        ("Al Mazrouei", "المزروعي"), ("Al Suwaidi", "السويدي"), ("Al Ketbi", "الكتبي"),
        ("Al Falasi", "الفلاسي"), ("Al Hashemi", "الهاشمي"), ("Al Dhaheri", "الظاهري")]
UNKNOWN = [("Priya Raghunathan", "بريا راغوناثان"), ("Johan Lindqvist", "يوهان ليندكفيست"),
           ("Tariq Bashir", "طارق بشير"), ("Elena Petrova", "إيلينا بتروفا"),
           ("Yousef Haddad", "يوسف حداد"), ("Ananya Iyer", "أنانيا آير")]

TEMPLATES_EN = [
    "Please draft a letter to {name} confirming account {iban}. Emirates ID {eid}, mobile {phone}, email {email}. Ask {first} to bring card {card}.",
    "Summarise the complaint from {name} ({email}). Reach {first} on {phone}. Refund to {iban}; ID on file {eid}; card ending in full {card}.",
]
TEMPLATES_AR = [
    "اكتب رسالة إلى {name_ar} بخصوص الحساب {iban}. رقم الهوية {eid}، الهاتف {phone}، البريد {email}.",
]

EVASIONS = ["none", "zero_width", "arabic_digits", "fullwidth", "spaced", "dotted",
            "homoglyph", "upper", "spelled_eid"]
MANGLES = ["echo", "angle_space", "bare", "strip_number_separators"]


def eid(r):
    body = "784" + str(r.randint(1950, 2005)) + f"{r.randrange(10**7):07d}"
    d = body + luhn_check_digit(body)
    return f"{d[:3]}-{d[3:7]}-{d[7:14]}-{d[14]}"


def iban(r):
    bban = f"{r.randrange(1000):03d}{r.randrange(10**16):016d}"
    return f"AE{iban_check_digits('AE', bban)}{bban}"


def card(r):
    body = "4" + f"{r.randrange(10**14):014d}"
    d = body + luhn_check_digit(body)
    return " ".join(d[i : i + 4] for i in range(0, 16, 4))


def phone(r):
    return f"+971 5{r.choice('024568')} {r.randrange(1000):03d} {r.randrange(10000):04d}"


ZW = "​"
AR_DIG = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")
CYR = str.maketrans("aeo", "аео")
WORDS = "zero one two three four five six seven eight nine".split()


def evade(kind, value, is_digits):
    if kind == "zero_width":
        return ZW.join(value)
    if kind == "arabic_digits" and is_digits:
        return value.translate(AR_DIG)
    if kind == "fullwidth" and is_digits:
        return "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else c for c in value)
    if kind == "spaced" and is_digits:
        return " ".join(c for c in value if c.isdigit())
    if kind == "dotted" and is_digits:
        return ".".join(re.findall(r"\d{1,3}", re.sub(r"\D", "", value)))
    if kind == "homoglyph" and not is_digits:
        return value.translate(CYR)
    if kind == "upper" and not is_digits:
        return value.upper()
    return value


# ---------- independent leak checker (deliberately shares no code with the gate) ----------

def _fold(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).replace(ZW, "")
    s = s.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    s = s.translate(str.maketrans("аеорсх", "aeopcx"))
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    for i, w in enumerate(WORDS):
        s = re.sub(rf"\b{w}\b", str(i), s, flags=re.I)
    return s.casefold()


def leaked(outbound: str, gold: dict) -> list[str]:
    o = _fold(outbound)
    o_digits = re.sub(r"(?<=\d)[^0-9a-z؀-ۿ]{1,3}(?=\d)", "", o)
    found = []
    for k, v in gold.items():
        if k in ("eid", "iban", "card", "phone"):
            core = re.sub(r"[^0-9]", "", v)[-9:] if k == "phone" else re.sub(r"[^0-9]", "", v)[-12:]
            if core in o_digits:
                found.append(k)
        elif k == "email":
            if v.split("@")[0].casefold() in o:
                found.append(k)
        else:  # names: any meaningful token
            toks = [t for t in re.split(r"[\s\-]+", _fold(v)) if len(t) >= 4 and t not in ("al",)]
            if any(re.search(rf"(?<!\w){re.escape(t)}(?!\w)", o) for t in toks):
                found.append(k)
    return found


def mangle(kind, text):
    if kind == "angle_space":
        return re.sub(r"\[([A-Z]+)_(\d+)((?:_[A-Z]+)?)\]", lambda m: f"<{m[1]} {m[2]}{m[3]}>", text)
    if kind == "bare":
        return re.sub(r"\[([A-Z]+_\d+(?:_[A-Z]+)?)\]", r"\1", text)
    if kind == "strip_number_separators":
        return re.sub(r"(?<=\d)[ \-](?=\d)", "", text)
    return text


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - a) / d), min(1.0, (c + a) / d))


def fmt(k, n):
    lo, hi = wilson(k, n)
    return f"{k:>4}/{n:<4} {100*k/n:5.1f}%  [{100*lo:4.1f}–{100*hi:4.1f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--system", default="ours-p1", choices=["ours-p1", "ours-p2", "presidio"])
    ap.add_argument("--device", default="cpu")
    args = ap.parse_args()
    r = random.Random(args.seed)

    people = [(f, l) for f in FIRST for l in LAST]
    dictionary = BranchDictionary(
        Entity(f"p{i}", "PERSON", [f"{f[0]} {l[0]}", f"{f[1]} {l[1]}"]) for i, (f, l) in enumerate(people)
    )
    presidio = None
    if args.system == "presidio":  # leak only; Presidio has no restore
        from ratbench import sys_presidio

        presidio = sys_presidio()
    ner = None
    if args.system == "ours-p2":
        from veil.ner import NERDetector

        ner = NERDetector(device=args.device)
    sw = Sandwich(dictionary=dictionary, ner=ner)

    stats = defaultdict(lambda: defaultdict(int))
    for i in range(args.n):
        for ev in EVASIONS:
            known = r.random() < 0.85
            if known:
                f, l = r.choice(people)
                name, name_ar, first = f"{f[0]} {l[0]}", f"{f[1]} {l[1]}", f[0]
            else:
                name, name_ar = r.choice(UNKNOWN)
                first = name.split()[0]
            g = {"eid": eid(r), "iban": iban(r), "card": card(r), "phone": phone(r),
                 "email": f"{first.lower()}.{r.randrange(100, 999)}@example.ae"}
            ar = r.random() < 0.3
            tpl = r.choice(TEMPLATES_AR if ar else TEMPLATES_EN)
            shown = dict(g)
            for k in ("eid", "iban", "card", "phone"):
                shown[k] = evade(ev, g[k], True)
            if ev == "spelled_eid":
                shown["eid"] = " ".join(WORDS[int(c)] for c in g["eid"] if c.isdigit())
            nm, fm = evade(ev, name, False), evade(ev, first, False)
            text = tpl.format(name=nm, name_ar=name_ar, first=fm, **{k: shown[k] for k in g})
            gold = {**g, "name": name if not ar else name_ar}
            if not ar:
                gold["first"] = first

            bucket = ev + ("" if known else " (unknown name)")
            st = stats[bucket]
            st["n"] += 1
            if presidio:
                lk = leaked(presidio(text), gold)
                st["leak"] += bool(lk)
                for k in lk:
                    st[f"leak:{k}"] += 1
                continue
            s = sw.session()
            p = s.protect(text)
            if p.blocked:
                st["blocked"] += 1
            else:
                lk = leaked(p.outbound, gold)
                if lk:
                    st["leak"] += 1
                    for k in lk:
                        st[f"leak:{k}"] += 1
                for mg in MANGLES:
                    out, _ = s.receive(mangle(mg, p.outbound))
                    st[f"rt_n:{mg}"] += 1
                    if out == canonicalise(text):
                        st[f"rt_ok:{mg}"] += 1
            s.close()

    print(f"\nUAE synthetic benchmark  system={args.system}  n={args.n} per evasion family, seed={args.seed}\n")
    print(f"{'family':<34}{'any value leaked (95% CI)':<34}{'blocked':<10}leaked fields")
    for b in sorted(stats, key=lambda b: ("unknown" in b, b)):
        st = stats[b]
        fields = ", ".join(f"{k[5:]}={v}" for k, v in st.items() if k.startswith("leak:"))
        print(f"{b:<34}{fmt(st['leak'], st['n'] - st['blocked']):<34}{st['blocked']:<10}{fields}")

    print(f"\n{'restore exactness under mangling':<34}")
    tot = defaultdict(lambda: [0, 0])
    for b, st in stats.items():
        for mg in MANGLES:
            tot[mg][0] += st[f"rt_ok:{mg}"]
            tot[mg][1] += st[f"rt_n:{mg}"]
    for mg, (k, n) in tot.items():
        if n:
            print(f"  {mg:<32}{fmt(k, n)}")


if __name__ == "__main__":
    main()
