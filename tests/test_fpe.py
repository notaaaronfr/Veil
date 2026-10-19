import pytest

from sandwich.fpe import FF1, iban_check_digits, iban_valid, luhn_valid

KEY = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")


@pytest.mark.parametrize(
    "radix,tweak,pt,ct",
    [
        (10, "", "0123456789", "2433477484"),
        (10, "39383736353433323130", "0123456789", "6124200773"),
        (36, "3737373770717273373737", "0123456789abcdefghi", "a9tv40mll9kdu509eum"),
    ],
)
def test_nist_vectors(radix, tweak, pt, ct):
    f = FF1(KEY, radix)
    t = bytes.fromhex(tweak)
    assert f.encrypt(pt, t) == ct
    assert f.decrypt(ct, t) == pt


def test_small_domain_rejected():
    with pytest.raises(ValueError):
        FF1(KEY).encrypt("12345")


def test_checksums():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert iban_valid("AE070331234567890123456")
    assert iban_check_digits("AE", "0331234567890123456") == "07"
