"""Freeze m1b-22 observations; never promote bounded slices to full acceptance.

Run after an opt-in live suite and the portable suite. Evidence is published
no-replace. Raw JUnit, matrix parent/child and capability data are tracked.
"""

# ruff: noqa: E501, S607 -- evidence descriptions and fixed local tools
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from keemu.models import RunReport

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs/evidence"
PROFILES = ("generic-aarch64", "generic-mipsel", "generic-mips")
TARGETS = ("aarch64-3.10", "mipsel-3.4", "mips-3.4")
IDS = ("A01", "A02", "A03", "A04", "A05", "A06", "A10", "A11")
REQUIRED_LIVE = (
    "test_target_opkg_inventory_and_network_with_owned_cleanup",
    "test_real_ipk_success_and_failed_postinst",
    "test_static_defect_reports_fail_before_docker[options0-architecture]",
    "test_static_defect_reports_fail_before_docker[options1-shebang]",
    "test_persistent_service_readiness_after_same_container_restart",
    "test_cleanup_failure_preserves_primary_failure",
    "test_matrix_real_child_and_unsupported_targets",
    "test_locked_target_image_and_offline_inventory[mipsel-3.4]",
    "test_locked_target_image_and_offline_inventory[mips-3.4]",
)
REQUIRED_PORTABLE = (
    "test_mismatch_is_fail_and_overrides_unsupported_target",
    "test_unknown_is_not_success_and_required_check_blocks",
    "test_exact_process_and_persistent_state",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path: Path) -> dict[str, str]:
    if not path.is_file() or not path.resolve().is_relative_to(ROOT):
        raise ValueError(f"missing or external artifact: {path}")
    return {"path": str(path.resolve().relative_to(ROOT)), "sha256": sha(path)}


def suite(path: Path, expected: dict[str, int], nodes: tuple[str, ...]) -> dict:
    raw = path.read_bytes()
    if (
        len(raw) > 2_000_000
        or b"<!DOCTYPE" in raw.upper()
        or b"<!ENTITY" in raw.upper()
    ):
        raise ValueError("unsafe JUnit XML")
    tree = ET.fromstring(raw)  # noqa: S314 -- bounded local JUnit with DTD refused
    block = tree.find("testsuite")
    if block is None:
        raise ValueError("missing JUnit testsuite")
    cases = {}
    for case in block.findall("testcase"):
        name = case.get("name")
        if not name or name in cases:
            raise ValueError("missing or duplicate JUnit node")
        cases[name] = (
            "FAIL"
            if case.find("failure") is not None or case.find("error") is not None
            else "SKIP"
            if case.find("skipped") is not None
            else "PASS"
        )
    counts = {
        status: list(cases.values()).count(status)
        for status in ("PASS", "FAIL", "SKIP")
    }
    if (
        counts != expected
        or len(cases) != int(block.get("tests", "-1"))
        or counts["FAIL"]
        != int(block.get("failures", "-1")) + int(block.get("errors", "-1"))
        or counts["SKIP"] != int(block.get("skipped", "-1"))
    ):
        raise ValueError(f"JUnit count mismatch: {counts} != {expected}")
    if any(cases.get(name) != "PASS" for name in nodes):
        raise ValueError("required JUnit node missing or not PASS")
    return {
        "artifact": artifact(path),
        "counts": counts,
        "required_nodes": {name: cases[name] for name in nodes},
    }


def docker_owned(kind: str) -> list[str]:
    argv = (
        ["docker", "container" if kind == "container" else "network", "ls", "-q", "-a"]
        if kind == "container"
        else ["docker", "network", "ls", "-q"]
    )
    result = subprocess.run(  # noqa: S603, S607 -- fixed read-only Docker owner query
        [*argv, "--filter", "label=org.keemu.owner=keemu"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.split()


def doctor(profile: str) -> tuple[dict, bytes]:
    qemu_dir = ROOT / ".runtime/p0/qemu-user-root/usr/bin"
    env = {**os.environ, "PATH": str(qemu_dir) + ":" + os.environ.get("PATH", "")}
    result = subprocess.run(  # noqa: S603 -- exact project executable, read-only doctor
        [str(ROOT / ".venv/bin/keemu"), "doctor", "--profile", profile],
        cwd=ROOT,
        env=env,
        capture_output=True,
        timeout=30,
    )
    if result.returncode not in (0, 4) or result.stderr or not result.stdout:
        raise ValueError(f"doctor {profile} did not return a valid report")
    report = RunReport.model_validate_json(result.stdout)
    if report.profile.id != profile or report.overall not in ("PASS", "BLOCKED"):
        raise ValueError("doctor profile/status mismatch")
    raw = (
        json.dumps(
            {"exit_code": result.returncode, "report": report.model_dump(mode="json")},
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    return {
        "exit_code": result.returncode,
        "overall": report.overall,
        "checks": {check.id: check.status for check in report.checks},
        "note": "doctor sees worker /proc only; binfmt BLOCKED is visibility, not a Docker target-exec failure",
    }, raw


def inspect_matrix(path: Path) -> tuple[dict, Path]:
    report = RunReport.model_validate_json(path.read_bytes())
    statuses = {check.id: check.status for check in report.checks}
    if (
        report.overall != "BLOCKED"
        or report.operation != "matrix"
        or statuses
        != {
            "completeness": "PASS",
            "generic-aarch64": "PASS",
            "generic-mipsel": "BLOCKED",
            "generic-mips": "BLOCKED",
        }
    ):
        raise ValueError(f"unexpected real matrix result: {statuses}")
    evidence = next(c.evidence[0] for c in report.checks if c.id == "generic-aarch64")
    marker = "child_report="
    if marker not in evidence or "; sha256=" not in evidence:
        raise ValueError("matrix child hash missing")
    child_text, digest = evidence.split(marker, 1)[1].split("; sha256=", 1)
    child = Path(child_text)
    if (
        not child.resolve().is_relative_to(ROOT)
        or sha(child) != digest.split(";", 1)[0]
        or RunReport.model_validate_json(child.read_bytes()).overall != "PASS"
    ):
        raise ValueError("matrix child binding invalid")
    return {
        "status": report.overall,
        "checks": statuses,
        "parent": artifact(path),
        "child": artifact(child),
    }, child


def inspect_capabilities(path: Path) -> tuple[dict, dict]:
    data = json.loads(path.read_text())
    if (
        data["schema_version"] != 1
        or data["subtask"] != "m1b-22"
        or data["modules_before"] != data["modules_after"]
        or [r["target"] for r in data["results"]] != list(TARGETS)
    ):
        raise ValueError("capability probe coverage or module preservation failed")
    for row in data["results"]:
        if (
            row["cleanup"] != "PASS"
            or row["native_control_status"] != "PASS"
            or row["queue_bind"] != "NOT RUN"
            or row["packet_verdict"] != "BLOCKED"
            or row["target_socket"]["exit"] != 1
            or "Protocol not supported" not in row["target_socket"]["stderr"]
            or row["socket_status"] != "BLOCKED"
        ):
            raise ValueError(f"unexpected capability result: {row['target']}")
    return {
        "artifact": artifact(path),
        "per_target": {
            row["target"]: {
                "target_socket": row["socket_status"],
                "target_exit": row["target_socket"]["exit"],
                "target_error": row["target_socket"]["stderr"].strip(),
                "native_socket": row["native_control_status"],
                "queue_bind": row["queue_bind"],
                "packet_verdict": row["packet_verdict"],
                "iptables_backend": row["iptables_backend"],
                "ipset_create": row["ipset_create"],
                "conntrack": row["conntrack"],
                "forwarding": row["forwarding"],
                "cleanup": row["cleanup"],
            }
            for row in data["results"]
        },
    }, data


def publish(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def freeze(live: Path, portable: Path, matrix: Path, capabilities: Path) -> dict:
    # Validate every source before first publication. Prior frozen observations
    # are read-only and remain unchanged, including historical BLOCKED results.
    previous = artifact(ROOT / "docs/evidence/m1a17-acceptance.json")
    mips = artifact(ROOT / "docs/evidence/m1b18-targets-pass.json")
    history = json.loads((ROOT / mips["path"]).read_text())
    if history["a01_target_exec_three_generic"].split()[0] != "PASS":
        raise ValueError("A01 target execution source not PASS")
    live_suite = suite(live, {"PASS": 28, "FAIL": 0, "SKIP": 0}, REQUIRED_LIVE)
    portable_suite = suite(
        portable, {"PASS": 187, "FAIL": 0, "SKIP": 22}, REQUIRED_PORTABLE
    )
    observed_matrix, child = inspect_matrix(matrix)
    observed_caps, _ = inspect_capabilities(capabilities)
    doctors = {name: doctor(name) for name in PROFILES}
    owned = {kind: docker_owned(kind) for kind in ("container", "network")}
    if any(owned.values()):
        raise ValueError(f"project-owned Docker resources remain: {owned}")
    if set(IDS) != {"A01", "A02", "A03", "A04", "A05", "A06", "A10", "A11"}:
        raise ValueError("acceptance IDs incomplete")
    targets = {}
    for profile, target in zip(PROFILES, TARGETS, strict=True):
        targets[profile] = {
            "target": target,
            "A01": "PASS",  # prior approved target exec plus current AArch64 live test
            "A02": "BLOCKED",
            "A03": "BLOCKED",
            "A04": "BLOCKED",
            "A05": "BLOCKED",
            "A06": "BLOCKED",
            "A10": "BLOCKED",
            "A11": "BLOCKED",
            "reason": (
                "Real AArch64 one-shot/persistent bounded tests PASS, but full file/"
                "process/socket/negative-case and report facets remain unproved."
                if profile == "generic-aarch64"
                else "Rootfs/opkg/target fixture smoke PASS; general keemu init/test lifecycle "
                "and required negative/failure cases are unsupported."
            ),
        }
    ledger = {
        "schema_version": 1,
        "subtask": "m1b-22",
        "created_at": datetime.now(UTC).isoformat(),
        "git_commit": subprocess.run(  # noqa: S603 -- fixed local read-only Git
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip(),
        "mvp1b_gate": "BLOCKED",
        "required_ids": list(IDS),
        "targets": targets,
        "interpretation": "A01 is PASS for target ELF/shell/nested exec on three generic targets only. "
        "A02-A06/A10/A11 remain BLOCKED across three targets. "
        "Negative fixture FAIL is correct when the harness expects FAIL; "
        "synthetic NDM process PASS does not satisfy target/device A11.",
        "gaps": {
            "A02": "Installed-file byte equality and independent postinst exit unproved; MIPS lifecycles unsupported",
            "A03": "Full process/socket census and cross-target stop/remove unproved",
            "A04": "Wrong ELF/loader/dependency end-to-end cases absent on all three",
            "A05": "Permission/broken-link end-to-end cases absent on all three",
            "A06": "Persistent failure report and one-shot crash recovery absent; cross-target errors unrun",
            "A10": "MIPS/MIPSEL static BLOCKED; no installed-package child report for either",
            "A11": "Synthetic host shim only; no observed physical bytes, target ndmc or package invocation",
        },
        "previous_evidence": {"aarch64": previous, "mips": mips},
        "test_runs": {"live": live_suite, "portable": portable_suite},
        "matrix": observed_matrix,
        "capabilities": observed_caps,
        "doctor": {name: value[0] for name, value in doctors.items()},
        "doctor_visibility": "Worker /proc lacks host binfmt registration; each Docker target execution is independently proven. Doctor result is not promoted to PASS.",
        "owned_resources_after": owned,
        "negative_package_observation": {
            "scope": "AArch64 wrong architecture and bad shebang",
            "package_reports": "FAIL at inspect",
            "harness_tests": [REQUIRED_LIVE[2], REQUIRED_LIVE[3]],
            "harness_status": "PASS",
        },
        "unrun": {
            "mips_lifecycle": "BLOCKED unsupported implementation",
            "target_ndm": "BLOCKED no target installation/observed response",
            "queue_bind_verdict": "BLOCKED host module approval and target socket failure",
            "fresh_ubuntu": "SKIP shared Docker host",
        },
    }
    raw: dict[str, Path | bytes] = {
        "live-junit.xml": live,
        "portable-junit.xml": portable,
        "capabilities.json": capabilities,
        "matrix-parent.json": matrix,
        "matrix-child.json": child,
    }
    for profile, (_, doctor_bytes) in doctors.items():
        raw[f"doctor-{profile}.json"] = doctor_bytes
    for name in (*raw, "acceptance.json"):
        dest = DEST / ("m1b22-" + name)
        if dest.exists() or dest.is_symlink():
            raise FileExistsError(dest)
    for name, source in raw.items():
        content = source if isinstance(source, bytes) else source.read_bytes()
        publish(DEST / ("m1b22-" + name), content)
    publish(
        DEST / "m1b22-acceptance.json",
        json.dumps(ledger, indent=2, sort_keys=True).encode() + b"\n",
    )
    return ledger


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for field in ("live", "portable", "matrix", "capabilities"):
        parser.add_argument("--" + field, required=True, type=Path)
    args = parser.parse_args()
    outcome = freeze(args.live, args.portable, args.matrix, args.capabilities)
    print(
        "docs/evidence/m1b22-acceptance.json",
        sha(DEST / "m1b22-acceptance.json"),
        outcome["mvp1b_gate"],
    )
