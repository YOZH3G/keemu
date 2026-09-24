"""Validate the frozen MVP 1A ledger without treating partial evidence as PASS."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/evidence/m1a17-acceptance.json"
IDS = {*(f"A{n:02}" for n in range(1, 10)), *(f"A{n:02}" for n in range(18, 22))}


def test_frozen_ledger_is_complete_and_truthful() -> None:
    data = json.loads(LEDGER.read_text())
    assert data["subtask_id"] == "m1a-17"
    assert data["subtask_digest"] == (
        "912e38d2c86706657d67ab27fe36716b1143d564707c6a2233614f5da756b119"
    )
    assert set(data["acceptance"]) == IDS
    assert data["mvp1a_gate"] == "BLOCKED"
    assert "NOT clean Ubuntu VM" in data["runner"]["kind"]
    assert data["test_runs"]["live"]["counts"] == {"PASS": 22, "FAIL": 0, "SKIP": 0}
    assert data["test_runs"]["portable"]["counts"] == {
        "PASS": 130,
        "FAIL": 0,
        "SKIP": 19,
    }
    live = data["test_runs"]["live"]["tests"]
    for result in data["acceptance"].values():
        assert result["status"] == "BLOCKED"
        assert result["aarch64_slice"] == "PASS"
        assert result["blocker"]
        assert result["live_tests"]
        assert all(live[test] == "PASS" for test in result["live_tests"])
    defects = data["negative_package_observations"]
    assert len(defects) == 2
    assert all(item["observed"] == item["expected"] == "FAIL" for item in defects)
    assert all(item["harness_result"] == "PASS" for item in defects)
    assert len(data["phase_skips"]) == 2
    assert all(item["status"] == "SKIP" for item in data["phase_skips"])


def test_retained_local_evidence_hashes_when_available() -> None:
    data = json.loads(LEDGER.read_text())
    evidence = [data["test_runs"][key] for key in ("live", "portable")]
    for item in data["artifacts"].values():
        evidence.extend(item if isinstance(item, list) else [item])
    for entry in evidence:
        path = ROOT / entry["path"]
        if path.is_file():
            assert path.resolve().is_relative_to(ROOT)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
