import json
import multiprocessing as mp
from datetime import date, timedelta

from veil.ledger import Ledger

KEY = b"k" * 32


def test_chain_verifies_and_never_stores_unapproved_fields(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    lg.append(request_id="r1", detected={"PERSON": 2}, prompt="Sara Al Mansoori", value="4111")
    lg.append(request_id="r2", decision="forwarded")
    ok, msg = lg.verify()
    assert ok, msg
    text = "".join(p.read_text() for p in lg.segments())
    assert "Sara" not in text and "4111" not in text and "prompt" not in text


def test_tampering_is_detected(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    for i in range(3):
        lg.append(request_id=f"r{i}", decision="forwarded")
    seg = lg.segments()[0]
    lines = seg.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "handoff"
    lines[1] = json.dumps(rec)
    seg.write_text("\n".join(lines) + "\n")
    ok, msg = lg.verify()
    assert not ok and "altered" in msg


def test_forged_chain_without_key_fails_certificate(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    lg.append(request_id="r1")
    forger = Ledger(str(tmp_path / "x"), "t1", b"z" * 32)  # attacker recomputes hashes with their own key
    forger.append(request_id="r1")
    (lg.segments()[0]).write_text(forger.segments()[0].read_text())
    (lg.dir / "head.json").write_text((forger.dir / "head.json").read_text())
    ok, msg = lg.verify()
    assert not ok and "HMAC" in msg


def test_deleting_records_is_detected(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    for i in range(3):
        lg.append(request_id=f"r{i}")
    seg = lg.segments()[0]
    seg.write_text("\n".join(seg.read_text().splitlines()[:2]) + "\n")  # drop the last record
    ok, msg = lg.verify()
    assert not ok


def _writer(root, n):
    lg = Ledger(root, "t1", KEY)
    for i in range(n):
        lg.append(request_id=f"{i}")


def test_concurrent_writers_keep_one_valid_chain(tmp_path):
    procs = [mp.get_context("fork").Process(target=_writer, args=(str(tmp_path), 25)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    lg = Ledger(str(tmp_path), "t1", KEY)
    ok, msg = lg.verify()
    assert ok, msg
    assert lg.head()["seq"] == 100


def test_retention_prunes_old_segments_and_chain_stays_verifiable(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    for i in range(3):
        lg.append(request_id=f"r{i}")
    old = lg.segments()[0]
    old.rename(lg.dir / "2020-01-01.jsonl")  # pretend these records are old
    res = lg.prune(retention_days=30, today=date.today())
    assert res["pruned"] == 1
    lg.append(request_id="after")
    ok, msg = lg.verify()
    assert ok, msg
    events = [json.loads(l)["event"] for s in lg.segments() for l in s.read_text().splitlines()]
    assert "retention_prune" in events


def test_legal_hold_blocks_pruning(tmp_path):
    lg = Ledger(str(tmp_path), "t1", KEY)
    lg.append(request_id="r0")
    lg.segments()[0].rename(lg.dir / "2020-01-01.jsonl")
    lg.set_hold(True, reason="case 42", actor="legal")
    assert lg.prune(retention_days=30)["skipped"] == "legal hold active"
    assert (lg.dir / "2020-01-01.jsonl").exists()
    lg.set_hold(False, actor="legal")
    assert lg.prune(retention_days=30, today=date.today() + timedelta(days=1))["pruned"] >= 1
    ok, msg = lg.verify()
    assert ok, msg
