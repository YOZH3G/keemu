"""Independent portable checks for the m1b-22 frozen, bounded observation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.freeze_m1b22 import (
    DEST,
    IDS,
    ROOT,
    TARGETS,
    inspect_capabilities,
    inspect_matrix,
    publish,
    suite,
)

LEDGER = DEST / "m1b22-acceptance.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_evidence_is_present_hash_bound_and_no_false_pass() -> None:
    ledger = json.loads(LEDGER.read_text())
    assert ledger["subtask"] == "m1b-22"
    assert ledger["required_ids"] == list(IDS)
    assert ledger["mvp1b_gate"] == "BLOCKED"
    assert set(ledger["targets"]) == {
        "generic-aarch64",
        "generic-mipsel",
        "generic-mips",
    }
    assert {row["target"] for row in ledger["targets"].values()} == set(TARGETS)
    for row in ledger["targets"].values():
        assert row["A01"] == "PASS"
        assert all(row[id] == "BLOCKED" for id in IDS if id != "A01")
    for previous in ledger["previous_evidence"].values():
        assert sha(ROOT / previous["path"]) == previous["sha256"]
    for name in ("live", "portable"):
        record = ledger["test_runs"][name]
        assert sha(ROOT / record["artifact"]["path"]) == record["artifact"]["sha256"]
        assert sha(DEST / f"m1b22-{name}-junit.xml") == record["artifact"]["sha256"]
    assert ledger["test_runs"]["live"]["counts"] == {"PASS": 28, "FAIL": 0, "SKIP": 0}
    assert ledger["test_runs"]["portable"]["counts"] == {
        "PASS": 187,
        "FAIL": 0,
        "SKIP": 22,
    }
    matrix = ledger["matrix"]
    for key in ("parent", "child"):
        artifact = matrix[key]
        assert sha(ROOT / artifact["path"]) == artifact["sha256"]
        assert sha(DEST / f"m1b22-matrix-{key}.json") == artifact["sha256"]
    assert inspect_matrix(ROOT / matrix["parent"]["path"])[0] == matrix
    capabilities = ledger["capabilities"]
    assert (
        sha(ROOT / capabilities["artifact"]["path"])
        == capabilities["artifact"]["sha256"]
    )
    assert sha(DEST / "m1b22-capabilities.json") == capabilities["artifact"]["sha256"]
    assert (
        inspect_capabilities(ROOT / capabilities["artifact"]["path"])[0] == capabilities
    )
    for name, record in ledger["doctor"].items():
        data = json.loads((DEST / f"m1b22-doctor-{name}.json").read_text())
        assert data["exit_code"] == record["exit_code"] == 4
        assert data["report"]["profile"]["id"] == name
        assert data["report"]["overall"] == record["overall"] == "BLOCKED"
        assert {c["id"]: c["status"] for c in data["report"]["checks"]} == record[
            "checks"
        ]
    assert ledger["owned_resources_after"] == {"container": [], "network": []}
    assert (
        ledger["negative_package_observation"]["package_reports"] == "FAIL at inspect"
    )


def test_evidence_freezer_refuses_overwrite_and_modified_inputs(tmp_path: Path) -> None:
    prior = LEDGER.read_bytes()
    with pytest.raises(FileExistsError):
        publish(LEDGER, b"replacement")
    assert LEDGER.read_bytes() == prior

    bad_suite = tmp_path / "live.xml"
    bad_suite.write_bytes(
        (DEST / "m1b22-live-junit.xml")
        .read_bytes()
        .replace(b'tests="28"', b'tests="27"', 1)
    )
    with pytest.raises(ValueError, match="count mismatch"):
        suite(bad_suite, {"PASS": 28, "FAIL": 0, "SKIP": 0}, ())

    bad_capabilities = tmp_path / "capabilities.json"
    data = json.loads((DEST / "m1b22-capabilities.json").read_text())
    data["results"][1]["socket_status"] = "PASS"
    bad_capabilities.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unexpected capability result"):
        inspect_capabilities(bad_capabilities)
