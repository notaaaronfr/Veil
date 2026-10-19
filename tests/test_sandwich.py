from sandwich import BranchDictionary, Entity, Sandwich
from sandwich.canonical import canonicalise
from sandwich.fpe import iban_valid, luhn_valid

DICT = BranchDictionary(
    [
        Entity("c1", "PERSON", ["Sara Al Mansoori", "سارة المنصوري"]),
        Entity("o1", "ORG", ["Emirates Falcon Holdings"]),
    ]
)
EID = "784-1985-1234567-4"  # Luhn-valid
IBAN = "AE070331234567890123456"


def make():
    return Sandwich(b"k" * 32, DICT).session()


def test_round_trip_and_nothing_leaks():
    s = make()
    text = (
        f"Email Sara Al Mansoori (sara.m@example.ae, +971 50 123 4567) at Emirates Falcon Holdings. "
        f"Her ID is {EID}, IBAN {IBAN}, card 4111 1111 1111 1111. Thank Sara for her help."
    )
    p = s.protect(text)
    assert not p.blocked
    for secret in ["Sara", "Mansoori", "sara.m", "1234567", "0331234567890123456", "4111", "Falcon"]:
        assert secret not in p.outbound, secret
    assert "[PERSON_1]" in p.outbound and "[PERSON_1_FIRST]" in p.outbound
    restored, rep = s.receive(p.outbound)
    assert restored == canonicalise(text)
    assert not rep.hallucinated


def test_fpe_surrogates_keep_format_and_checksums():
    s = make()
    p = s.protect(f"ID {EID} IBAN {IBAN} card 4111111111111111")
    words = p.outbound.split()
    eid, iban, card = words[1], words[3], words[5]
    assert eid.startswith("784-") and len(eid) == len(EID) and eid != EID
    assert luhn_valid(eid.replace("-", ""))
    assert iban.startswith("AE") and iban_valid(iban) and iban != IBAN
    assert luhn_valid(card) and card != "4111111111111111"


def test_evasions_are_caught():
    s = make()
    evasive = [
        "784​-1985-1234567-4",  # zero-width
        "٧٨٤-١٩٨٥-١٢٣٤٥٦٧-٤",  # Arabic-Indic digits
        "７８４-１９８５-１２３４５６７-４",  # fullwidth
        "7 8 4 1 9 8 5 1 2 3 4 5 6 7 4",  # spaced
        "Sаra Al Mansoori",  # Cyrillic а
        "سارَة المنصوري",  # diacritic
        "SARA AL-MANSOORI",  # case + hyphen
        "seven eight four one nine eight five one two three four five six seven four",
    ]
    for e in evasive:
        p = s.protect(f"Customer: {e}")
        assert not p.blocked, e
        assert "1234567" not in p.outbound.replace(" ", "") and "Mansoori" not in p.outbound, (e, p.outbound)


def test_restore_handles_mangled_and_hallucinated_tags():
    s = make()
    s.protect("Call Sara Al Mansoori about Emirates Falcon Holdings")
    out, rep = s.receive("Dear <PERSON 1>, re: ORG_1 and [person_1]'s note. Also [PERSON_9].")
    assert out.startswith("Dear Sara Al Mansoori, re: Emirates Falcon Holdings and Sara Al Mansoori's")
    assert rep.hallucinated == ["[PERSON_9]"]


def test_reformatted_fpe_value_is_restored():
    s = make()
    p = s.protect(f"ID {EID}")
    sur = p.outbound.split()[1]
    out, _ = s.receive(f"The ID {sur.replace('-', '')} is valid")
    assert EID in out


def test_sessions_are_unlinkable():
    a, b = make(), make()
    assert a.protect(f"ID {EID}").outbound != b.protect(f"ID {EID}").outbound


def test_llm_history_never_holds_real_values():
    s = make()
    p = s.protect("Sara Al Mansoori asked about her card 4111111111111111")
    s.receive(p.outbound)
    blob = str(s.llm_history)
    assert "Sara" not in blob and "4111111111111111" not in blob


def test_bilingual_restore_picks_matching_script():
    s = make()
    p = s.protect("أرسل إلى سارة المنصوري. Then email Sara Al Mansoori.")
    out, _ = s.receive(p.outbound)
    assert out == "أرسل إلى سارة المنصوري. Then email Sara Al Mansoori."


def test_mobile_surrogate_stays_mobile():
    s = make()
    p = s.protect("call +971 50 123 4567 or 050 765 4321")
    assert "+971 50 " in p.outbound and " 050 " in p.outbound
    assert "123 4567" not in p.outbound and "765 4321" not in p.outbound


def test_shared_first_name_binds_to_person_in_text():
    d = BranchDictionary(
        [
            Entity("a", "PERSON", ["Mohammed Al Shamsi"]),
            Entity("b", "PERSON", ["Mohammed Al Ketbi"]),
        ]
    )
    s = Sandwich(b"k" * 32, d).session()
    p = s.protect("Write to Mohammed Al Ketbi. Tell Mohammed the card is ready.")
    assert p.outbound == "Write to [PERSON_1]. Tell [PERSON_1_FIRST] the card is ready."
    p2 = Sandwich(b"k" * 32, d).session().protect("Tell Mohammed hello")
    assert "Mohammed" not in p2.outbound


def test_parentheses_survive_restore():
    s = make()
    p = s.protect("From Sara Al Mansoori (sara.m@example.ae).")
    out, _ = s.receive(p.outbound.replace("[EMAIL_1]", "EMAIL_1"))
    assert out == "From Sara Al Mansoori (sara.m@example.ae)."


class FakeNER:
    """Stands in for GLiNER: tags capitalised two-word names and lone 'Priya'."""

    def detect(self, text):
        import re

        from sandwich.detect import Span

        return [
            Span(m.start(), m.end(), "PERSON", m.group())
            for m in re.finditer(r"Priya Raghunathan|Johan Lindqvist|\bPriya\b", text)
        ]


def test_ner_names_keep_one_identity_across_turns():
    s = Sandwich(b"k" * 32, ner=FakeNER()).session()
    assert s.protect("Reply to Priya Raghunathan today.").outbound == "Reply to [PERSON_1] today."
    assert s.protect("Also cc Priya and Johan Lindqvist.").outbound == "Also cc [PERSON_1_FIRST] and [PERSON_2]."
    out, _ = s.receive("Dear [PERSON_1_FIRST], cc [PERSON_2].")
    assert out == "Dear Priya, cc Johan Lindqvist."


def test_word_matching_a_tag_name_does_not_block():
    class WordNER:  # mimics GLiNER tagging the bare word "email"
        def detect(self, text):
            from sandwich.detect import Span

            i = text.index("email")
            return [Span(i, i + 5, "EMAIL", "email")]

    s = Sandwich(b"k" * 32, ner=WordNER()).session()
    p = s.protect("Send it by email to sara.m@example.ae")
    assert not p.blocked
    assert "sara.m" not in p.outbound


def test_vault_wiped_on_close():
    s = make()
    s.protect("Sara Al Mansoori")
    s.close()
    assert s.vault.closed and not s.vault.entries
