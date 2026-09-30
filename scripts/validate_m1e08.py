"""Replay the independent MVP 1E audit without product or runtime mutation."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from keemu.models import RunReport
from scripts.validate_m1e06 import check as check_e07
from scripts.validate_m1e06 import junit
from scripts.validate_m1e07 import check as check_reconciliation

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/evidence/mvp1e-m1e08-final-audit.json"
EXPECTED = {
    "E01": "PASS",
    "E02": "PASS",
    "E03": "PASS",
    "E04": "PASS",
    "E05": "PASS",
    "E06": "BLOCKED",
    "E07": "PASS",
    "E08": "PASS",
}
PROFILES = {"generic-aarch64", "generic-mips", "generic-mipsel"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def bound(path: str, expected: str | None = None) -> bytes:
    candidate = ROOT / path
    require(not Path(path).is_absolute(), f"absolute evidence path: {path}")
    require(candidate.resolve().is_relative_to(ROOT), f"escaped path: {path}")
    require(
        not any(p.is_symlink() for p in (candidate, *candidate.parents)),
        f"linked evidence path: {path}",
    )
    raw = candidate.read_bytes()
    if expected is not None:
        require(
            hashlib.sha256(raw).hexdigest() == expected,
            f"evidence hash mismatch: {path}",
        )
    return raw


def load(path: str) -> dict:
    return json.loads(bound(path))


def counts(raw: bytes) -> dict[str, int]:
    cases = junit(raw)
    return {
        status: list(cases.values()).count(status)
        for status in ("PASS", "FAIL", "ERROR", "SKIP")
    }


def check(record: dict | None = None) -> dict:
    if record is None:
        record = json.loads(RECORD.read_bytes())
    if not isinstance(record, dict):
        raise ValueError("audit record is not an object")
    require(record["subtask"] == "m1e-08", "wrong frozen subtask")
    require(
        record["subtask_digest"]
        == "29349c92ec0deee393e5c03aa48f863e4e0ab02e5fcc47267a07cc8d6ffbc97e",
        "wrong frozen subtask digest",
    )
    require(record["audit_status"] == "PASS", "audit not complete")
    require(
        record["milestone_status"] == record["release_status"] == "BLOCKED",
        "blocked milestone or release promoted",
    )
    require(record["release_checks_status"] == "FAIL", "failed checks hidden")
    actual = {gate["id"]: gate["status"] for gate in record["gates"]}
    require(len(record["gates"]) == 8 and actual == EXPECTED, "gate verdict changed")
    require(record["gates"][5]["blockers"] == ["R1", "R2", "R3"], "E06 gap hidden")
    require(record["gates"][6]["historical_status"] == "SCOPED_PASS", "E07 promoted")
    require(
        record["predecessor_status"]
        == {
            "D02": "BLOCKED",
            "D07": "BLOCKED",
            "MVP1D_release": "BLOCKED",
            "MVP1_release": "BLOCKED",
        },
        "predecessor status changed",
    )
    for group in ("bound_sources", "predecessor_sha256", "documentation_sha256"):
        for path, expected in record[group].items():
            bound(path, expected)
    artifacts = record["artifacts"]
    for path, expected in artifacts.items():
        bound(path, expected)
    require(len(artifacts) == record["artifact_count"], "artifact count mismatch")
    require(check_reconciliation()["E06"] == "BLOCKED", "reconciliation changed")
    e07 = check_e07()
    require(e07["adversarial_unique_PASS"] == 19, "adversarial count changed")
    require(e07["typed_reports"] == 47, "typed report count changed")
    require(e07["retained_artifacts"] == 142, "retained E07 count changed")
    require(e07["E08"] == "NOT_EVALUATED", "E07 historical E08 changed")
    supplement = load("docs/evidence/mvp1e-m1e06-verification.json")
    for item in supplement["supplemental_artifacts"].values():
        raw = bound(item["retained"], item["sha256"])
        if item["retained"].endswith(".xml"):
            require(counts(raw) == supplement["final_portable"], "supplement count")
    publication = load("docs/evidence/mvp1e-m1e06-publication.json")
    rule = publication["publication_ignore_rule"]
    bound(rule["path"], rule["sha256"])
    prefix = "docs/evidence/raw/mvp1e-m1e08/"
    independent = load(prefix + "independent-checks.json")
    for source in independent["source_bindings"]:
        commit, path = source["publication_commit"], source["path"]
        require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid commit")
        raw = subprocess.run(  # noqa: S603 -- fixed git read; validated commit
            ["git", "show", f"{commit}:{path}"],  # noqa: S607 -- project Git tool
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
        require(
            hashlib.sha256(raw).hexdigest() == source["expected_sha256"],
            f"historical source mismatch: {path}",
        )
        bound(path, source["current_sha256"])
    for item in independent["profile_and_lock_bindings"]:
        bound(item["path"], item["sha256"])
    for item in record["historical_junit"]:
        raw = bound(item["retained"], item["sha256"])
        require(counts(raw) == item["counts"], f"JUnit count: {item['original']}")
    for item in record["e04_typed_reports"]:
        report = RunReport.model_validate_json(bound(item["retained"], item["sha256"]))
        require(report.overall == item["overall"], "E04 report status changed")
        require(
            next(x.status for x in report.checks if x.id == "cleanup")
            == item["cleanup"],
            "E04 cleanup changed",
        )
        operation = report.partial_failure.operation if report.partial_failure else None
        require(operation == item["failure_operation"], "E04 primary failure changed")
    portable = counts(bound(prefix + "portable.xml"))
    require(portable == record["verification"]["fresh_portable"], "portable count")
    require(
        portable == {"PASS": 353, "FAIL": 0, "ERROR": 0, "SKIP": 84},
        "portable status changed",
    )
    stale = independent["stale_m1e05_registry"]
    require(len(stale) == 6, "stale registry limitation hidden")
    require(
        all(x["state"] == "running" and x["container_absent"] for x in stale),
        "stale registry promoted to cleanup",
    )
    caches = independent["current_caches"]
    require({x["profile"] for x in caches} == PROFILES, "cache matrix incomplete")
    require(all(x["verification"] == "PASS" for x in caches), "cache proof missing")
    before = load(prefix + "baseline.json")
    after = load(prefix + "postflight.json")
    require(before["docker"] == after["docker"], "Docker parity lost")
    require(before["registry"] == after["registry"], "registry changed")
    require(before["protected"] == after["protected"], "product changed")
    require(not after["docker"]["owner_containers"], "owned container remains")
    require(not after["docker"]["owner_networks"], "owned network remains")
    history = load(prefix + "history-baseline.json")
    for mapping in (before["protected"], history):
        for path, expected in mapping.items():
            bound(path, expected)
    runtime = load(prefix + "runtime.json")
    require(
        runtime["provider"] == "openai-codex"
        and runtime["model"] == "gpt-6.1-sol"
        and runtime["reasoning_config"] == {"enabled": True, "effort": "high"},
        "actual runtime mismatches lock",
    )
    boundaries = load(prefix + "prior-boundaries.json")
    require(len(boundaries) == 9, "prior boundary count")
    require(
        all(
            x["outcome"]["attestation_status"] == "ATTESTED"
            and x["outcome"]["session_deleted"]
            for x in boundaries
        ),
        "prior terminal boundary missing",
    )
    require(not record["c3_telemetry"]["automatic_promotion"], "C3 promotion")
    require(record["c3_telemetry"]["mode"] == "shadow", "C3 not shadow")
    require(
        record["supervisor_boundary"] == "PENDING; supervisor-owned",
        "worker invented terminal attestation or publication",
    )
    quality = record["verification"]
    require(
        quality["repository_lint"]["status"] == "FAIL"
        and quality["repository_lint"]["errors"] == 3,
        "lint failure hidden",
    )
    require(
        quality["repository_format"]["status"] == "FAIL"
        and len(quality["repository_format"]["files"]) == 8,
        "format hidden",
    )
    require(
        quality["stale_architecture_regression"]
        == {"PASS": 0, "FAIL": 2, "ERROR": 0, "SKIP": 0},
        "R3 FAIL hidden",
    )
    return {
        "subtask": "m1e-08",
        "audit": "PASS",
        "gates": actual,
        "milestone": "BLOCKED",
        "release": "BLOCKED",
        "release_checks": "FAIL",
        "fresh_portable": portable,
        "adversarial_unique_PASS": 19,
        "typed_E07_reports": 47,
        "retained_E07_artifacts": 142,
        "audit_artifacts": len(artifacts),
        "stale_registry_records": len(stale),
    }


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
