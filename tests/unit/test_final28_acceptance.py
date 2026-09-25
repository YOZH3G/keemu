"""Final ledger must preserve previous evidence and fail closed on promotion."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.validate_final28 import LEDGER, ROOT, validate


def test_final_ledger_reconciles_hashes_tests_and_contradictions() -> None:
    ledger = validate()
    assert len(ledger["acceptance"]) == 21
    assert ledger["acceptance"]["A01"]["status"] == "PASS"
    assert ledger["acceptance"]["A14"]["status"] == "BLOCKED"
    assert ledger["acceptance"]["A17"]["status"] == "BLOCKED"
    assert ledger["gates"]["Completion"].startswith("BLOCKED")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: data["acceptance"].pop("A21"), "exact A01-A21 coverage"),
        (lambda data: data["acceptance"]["A14"].update(status="PASS"), "promoted"),
        (
            lambda data: data["sources"]["m1b22"].update(sha256="0" * 64),
            "evidence hash mismatch",
        ),
        (
            lambda data: data["acceptance"]["A11"].update(tests=["tests/missing.py"]),
            "missing test",
        ),
        (
            lambda data: data["historical_tests"]["m1b22_live"].update(PASS=29),
            "JUnit mismatch",
        ),
    ],
)
def test_final_ledger_rejects_tamper(change, message: str, tmp_path: Path) -> None:
    original = LEDGER.read_bytes()
    data = copy.deepcopy(json.loads(original))
    change(data)
    altered = tmp_path / "ledger.json"
    altered.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=message):
        validate(ROOT, altered)
    assert LEDGER.read_bytes() == original
