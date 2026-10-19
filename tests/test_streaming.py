import random

from veil import Veil
from veil.streaming import StreamRestorer


def split_randomly(text: str, rng: random.Random) -> list[str]:
    cuts = sorted(rng.sample(range(1, len(text)), k=min(8, len(text) - 1)))
    return [text[a:b] for a, b in zip([0] + cuts, cuts + [len(text)])]


def test_every_chunk_alignment_with_words_around_surrogates():
    """Regression: 'IBAN AE..595. ' made the number rule cut between 'AE' and the digits."""
    original = "Her card 4111 1111 1111 1111 was charged twice; refund to IBAN AE070331234567890123456. Also cc +971 50 123 4567."
    for size in (3, 5, 7, 11):
        for pad in range(size):
            s = Veil(b"k" * 32).session()
            p = s.protect(original)
            reply = "x" * pad + p.outbound
            rs = StreamRestorer(s.vault)
            out = "".join(rs.feed(reply[i : i + size]) for i in range(0, len(reply), size)) + rs.flush()
            assert out == "x" * pad + original, (size, pad, out)


def test_any_split_of_any_surrogate_restores_exactly():
    original = "Call +971 50 123 4567, IBAN AE070331234567890123456, card 4111 1111 1111 1111, ok?"
    rng = random.Random(0)
    for _ in range(200):
        s = Veil(b"k" * 32).session()
        p = s.protect(original)
        rs = StreamRestorer(s.vault)
        out = "".join(rs.feed(chunk) for chunk in split_randomly(p.outbound, rng)) + rs.flush()
        assert out == original, (p.outbound, out)
