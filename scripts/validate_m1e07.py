"""Read-only validator for the frozen MVP 1E reconciliation; never audits release."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/evidence/mvp1e-m1e07-reconciliation.json"


def digest(path: str) -> str:
    candidate = ROOT / path
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(ROOT):
        raise ValueError(f"unsafe path: {path}")
    return hashlib.sha256(candidate.read_bytes()).hexdigest()


def require_text(path: str, text: str) -> None:
    content = (ROOT / path).read_text(encoding="utf-8")
    if text not in content:
        raise ValueError(f"missing documentation marker: {path}: {text}")


def check() -> dict[str, object]:
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    if record["subtask"] != "m1e-07":
        raise ValueError("wrong reconciliation subtask")
    if record["subtask_digest"] != (
        "004bcbb4e25dc16465e96d14f8ebf408a211ff1e9adce8c238739f2e19dfd5ba"
    ):
        raise ValueError("wrong frozen reconciliation digest")
    if record["reconciliation_status"] != "PASS":
        raise ValueError("reconciliation is not PASS")
    if record["milestone_status"] != "PENDING_INDEPENDENT_FINAL_AUDIT":
        raise ValueError("worked ahead on final audit")
    expected = {
        "E01": "PASS",
        "E02": "PASS",
        "E03": "PASS",
        "E04": "PASS",
        "E05": "PASS",
        "E06": "BLOCKED",
        "E07": "SCOPED_PASS",
        "E08": "RECONCILIATION_PASS_FINAL_AUDIT_PENDING",
    }
    actual = {key: value["status"] for key, value in record["acceptance_matrix"].items()}
    if actual != expected:
        raise ValueError("acceptance matrix changed")
    for group in ("evidence_sha256", "predecessor_sha256"):
        for path, expected_hash in record[group].items():
            if digest(path) != expected_hash:
                raise ValueError(f"hash mismatch: {path}")
    e06 = json.loads(
        (ROOT / "docs/evidence/mvp1e-m1e05r-independent-review.json").read_text()
    )
    if e06["E06"] != "BLOCKED" or e06["c3_telemetry"]["learning_accepted"]:
        raise ValueError("E06 or C3 learning was promoted")
    e07 = json.loads((ROOT / "docs/evidence/mvp1e-m1e06-adversarial.json").read_text())
    if (
        e07["status"] != "SCOPED_PASS"
        or e07["E06"] != "BLOCKED"
        or e07["MVP1D"] != {"D02": "BLOCKED", "D07": "BLOCKED"}
        or e07["E08"] != "NOT_EVALUATED"
    ):
        raise ValueError("E07 or predecessor truth changed")
    samples = record["c3_telemetry"]["samples"]
    if set(samples) != {"m1e-00", "m1e-05", "m1e-07"}:
        raise ValueError("incomplete C3 telemetry")
    if record["c3_telemetry"]["mode"] != "shadow" or record["c3_telemetry"]["automatic_promotion"]:
        raise ValueError("C3 telemetry promoted policy")
    if samples["m1e-05"]["learning_accepted"]:
        raise ValueError("blocked C3 sample accepted for learning")
    if samples["m1e-07"]["runtime_attestation"] != "PENDING_SUPERVISOR_BOUNDARY":
        raise ValueError("planned lock promoted to attestation")
    for path, marker in {
        "README.md": "MVP 1E MIPS/MIPSEL lifecycle reconciliation",
        "README_RU.md": "MVP 1E: сверка MIPS/MIPSEL lifecycle",
        "docs/architecture.md": "MVP 1E MIPS/MIPSEL lifecycle",
        "docs/limitations.md": "MVP 1E MIPS/MIPSEL lifecycle",
        "docs/progress.md": "MVP 1E m1e-07 reconciliation",
        "docs/traceability.md": "MVP 1E E01–E08 reconciliation",
        "docs/decisions/0020-mvp1e-reconciliation-boundary.md": "MVP 1E reconciliation preserves scoped evidence",
    }.items():
        require_text(path, marker)
    return {
        "subtask": record["subtask"],
        "reconciliation": record["reconciliation_status"],
        "milestone": record["milestone_status"],
        "E06": actual["E06"],
        "E07": actual["E07"],
        "E08": actual["E08"],
        "evidence_hashes": len(record["evidence_sha256"]),
        "predecessor_hashes": len(record["predecessor_sha256"]),
    }


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
