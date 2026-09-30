"""Freeze retained E07 artifacts once; no runtime mutation or E08 verdict."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from scripts.validate_m1e06 import junit
from tests.integration.m1e06_support import EVIDENCE, ROOT, TARGETS, digest, publish

DEST = ROOT / "docs/evidence/raw/mvp1e-m1e06"
MANIFEST = ROOT / "docs/evidence/mvp1e-m1e06-adversarial.json"


def freeze() -> dict:
    if MANIFEST.exists() or DEST.exists():
        raise FileExistsError("E07 evidence is write-once")
    selected: set[Path] = set()
    matrix = {}
    for profile, target, _ in TARGETS:
        row = {"target": target, "observations": {}}
        for kind in (
            "stage",
            "lifecycle",
            "one-shot-kill",
            "persistent-create-kill",
            "persistent-script",
            "one-shot-outcomes",
        ):
            candidates = [
                p / "observation.json"
                for p in EVIDENCE.glob(kind + "-" + profile + "-*")
                if (p / "observation.json").is_file()
            ]
            if not candidates:
                raise ValueError(f"missing live observation: {kind} {profile}")
            path = max(candidates, key=lambda p: p.stat().st_mtime_ns)
            selected.add(path)
            row["observations"][kind] = str(path.relative_to(ROOT))
        matrix[profile] = row
    concurrent = max(
        EVIDENCE.glob("concurrent-three-target-*/observation.json"),
        key=lambda p: p.stat().st_mtime_ns,
    )
    selected.add(concurrent)
    selected.update(
        p
        for p in EVIDENCE.iterdir()
        if p.is_file() and p.suffix in {".json", ".xml", ".log"}
    )
    references = []

    def referenced(value):
        if isinstance(value, dict):
            if "sha256" in value and "path" in value:
                path = Path(value["path"])
                path = path if path.is_absolute() else ROOT / path
                if path.name == "report.json":
                    if not path.resolve().is_relative_to(ROOT):
                        raise ValueError("report reference outside project")
                    if digest(path.read_bytes()) != value["sha256"]:
                        raise ValueError("live report reference hash mismatch")
                    references.append(path)
            for nested in value.values():
                referenced(nested)
        elif isinstance(value, list):
            for nested in value:
                referenced(nested)

    for path in list(selected):
        if path.suffix == ".json":
            referenced(json.loads(path.read_text()))
    selected.update(references)
    for path in references:
        selected.add(path.parent / "operation-log.jsonl")
    # Preserve the exact reports that establish the legacy regression FAIL.
    stale = Path("/opt/data/cache/scratch/m1e06-stale-regression")
    stale_copies = []
    for path in sorted(stale.rglob("report.json")):
        destination = EVIDENCE / "stale-runtime-reports" / path.parent.name
        destination.mkdir(parents=True)
        for name in ("report.json", "operation-log.jsonl"):
            shutil.copyfile(path.parent / name, destination / name)
            selected.add(destination / name)
        stale_copies.append(str((destination / "report.json").relative_to(ROOT)))
    if len(stale_copies) != 2:
        raise ValueError("not exactly two retained legacy runtime reports")
    restoration = json.loads((EVIDENCE / "historical-raw-restoration.json").read_text())
    for path, item in restoration["restorations"].items():
        if digest((ROOT / path).read_bytes()) != item["original_sha256"]:
            raise ValueError("historical raw restoration no longer matches")
        selected.add(ROOT / path)
        selected.update(ROOT / p for p in item["source_reports"])
    artifacts = {}
    typed = {}
    DEST.mkdir(parents=True)
    for path in sorted(selected):
        original = str(path.relative_to(ROOT))
        destination = DEST / original
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        raw = path.read_bytes()
        expected = digest(raw)
        if digest(destination.read_bytes()) != expected:
            raise ValueError("retained artifact differs from original bytes")
        artifacts[original] = {
            "retained": str(destination.relative_to(ROOT)),
            "sha256": expected,
            "bytes": len(raw),
        }
        if path.name == "report.json":
            typed[original] = json.loads(raw)["overall"]
    roles = {
        "adversarial-boundaries.xml": "adversarial_acceptance",
        "adversarial-remainder.xml": "adversarial_acceptance",
        "one-shot-outcomes.xml": "adversarial_acceptance",
        "portable.xml": "portable",
        "init-regression.xml": "real_regression",
        "lifecycle-regression.xml": "real_regression",
        "script-regression.xml": "real_regression",
        "stale-architecture-regression.xml": "known_stale_regression_FAIL",
        "adversarial-initial.xml": "corrected_harness_failure",
        "adversarial-final.xml": "corrected_harness_failure",
    }
    tests = {}
    for filename, role in roles.items():
        path = EVIDENCE / filename
        cases = junit(path.read_bytes())
        tests[str(path.relative_to(ROOT))] = {
            "role": role,
            "counts": {
                key: list(cases.values()).count(key)
                for key in ("PASS", "FAIL", "ERROR", "SKIP")
            },
        }
    source_paths = (
        "tests/integration/m1e06_support.py",
        "tests/integration/test_m1e06_adversarial.py",
        "scripts/validate_m1e06.py",
        "scripts/freeze_m1e06.py",
    )
    record = {
        "schema_version": 1,
        "subtask": "m1e-06",
        "acceptance_ref": "E07",
        "subtask_digest": (
            "1bd33eb6b7da79a9a2848c43efc11290dcd8548870be20cddd43c6ed9f317eff"
        ),
        "recorded_at": datetime.now(UTC).isoformat(),
        "status": "SCOPED_PASS",
        "scope": (
            "completed bounded three-target adversarial verification, "
            "not product hardening, E06 acceptance or milestone audit"
        ),
        "E06": "BLOCKED",
        "MVP1D": {"D02": "BLOCKED", "D07": "BLOCKED"},
        "E08": "NOT_EVALUATED",
        "milestone_release": "NOT_EVALUATED",
        "source_sha256": {
            path: digest((ROOT / path).read_bytes()) for path in source_paths
        },
        "matrix": matrix,
        "concurrent_observation": str(concurrent.relative_to(ROOT)),
        "junit": tests,
        "artifacts": artifacts,
        "typed_reports": typed,
        "baseline": str((EVIDENCE / "baseline.json").relative_to(ROOT)),
        "postflight": str((EVIDENCE / "postflight.json").relative_to(ROOT)),
        "runtime_metadata": str(
            (EVIDENCE / "runtime-canonical.json").relative_to(ROOT)
        ),
        "quota_admission": str((EVIDENCE / "quota-admission.json").relative_to(ROOT)),
        "stale_runtime_reports": stale_copies,
        "limitations": [
            "Hostile concurrent same-UID stat-to-unlink race is not atomically "
            "proved safe; D02/D07 remain BLOCKED.",
            "Persistent host-worker SIGKILL leaves an artifact and no interrupted "
            "report; healthy recover refuses adoption. Whole test-owned "
            "environment down/destroy is teardown, not automatic artifact recovery.",
            "One-shot host-worker SIGKILL has no report; full-ID/run/name/label "
            "checked removal is explicit test-owned recovery, not a production "
            "crash-report/recovery feature.",
            "E06 R1/R2/R3 and missing historical C3 RED/GREEN remain unchanged. "
            "New raw results prove current bounded behavior, not historical TDD.",
            "The unchanged legacy architecture regression actually FAILed twice "
            "because enabled MIPS execution PASS contradicts its removed BLOCKED "
            "gate. No test correction was made.",
            "An unchanged legacy AArch64 persistent script regression directly "
            "removes its container but leaves a running registry record. Public "
            "recover refuses that state; only the exact newly issued test record "
            "received explicit test-owner flock/compare running-to-failed teardown "
            "before production recover. This is NOT production stale-running "
            "recovery and no prior stale record was changed.",
            "Two new-harness failures and two foreground tool interruptions are "
            "retained separately, never counted as adversarial acceptance PASS. "
            "The exact remaining test-owned IDs were removed and absence verified.",
            "The unchanged old m1e03 test overwrote two fixed ignored observation "
            "paths. Fresh bytes were retained separately; exact original bytes "
            "were recovered exclusively from preserved original reports and "
            "matched the frozen SHA-256 before restoration.",
            "No whole firewall/socket census, hard disk quota, fresh-Ubuntu "
            "runner or target HTTPS claim; Docker-managed firewall changes "
            "were not enumerated.",
            "No product, existing test, lock/profile/schema, binfmt handler, "
            "module, host namespace, credentials, routing policy or historical "
            "ledger mutation. Approved host-handler observers use only the "
            "pre-existing read-only bounded helper contract.",
        ],
    }
    publish(MANIFEST, record)
    return {
        "retained_artifacts": len(artifacts),
        "typed_reports": len(typed),
        "matrix_profiles": sorted(matrix),
        "junit": tests,
    }


if __name__ == "__main__":
    print(json.dumps(freeze(), sort_keys=True))
