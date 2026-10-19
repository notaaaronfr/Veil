import pytest

from veil.config import parse_quasi
from veil.hardening import harden
from veil.ner import QUASI_TYPES


def test_parse_quasi():
    assert parse_quasi("all") == frozenset(QUASI_TYPES)
    assert parse_quasi("none") == frozenset()
    assert parse_quasi("age, dob") == {"AGE", "DOB"}
    with pytest.raises(RuntimeError):
        parse_quasi("AGE,SHOE_SIZE")


def test_harden_reports_what_it_applied():
    applied = harden()
    assert applied["core_dumps"] == "disabled"
    assert "dumpable" in applied
