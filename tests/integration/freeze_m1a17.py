"""Freeze the bounded MVP 1A AArch64 acceptance observation, not a release PASS.

Run after the opt-in live and default portable suites, with their JUnit XML under
.runtime/m1a17-*. This script refuses to overwrite an existing frozen ledger.
"""

# ruff: noqa: E501 -- evidence descriptions and frozen test names are literal

from __future__ import annotations

import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs/evidence/m1a17-acceptance.json"
IDS = [*(f"A{n:02}" for n in range(1, 10)), *(f"A{n:02}" for n in range(18, 22))]
LIVE = ROOT / ".runtime/m1a17-live-junit.xml"
PORTABLE = ROOT / ".runtime/m1a17-portable-junit.xml"
SUBTASK_DIGEST = "912e38d2c86706657d67ab27fe36716b1143d564707c6a2233614f5da756b119"

# Full-ID blockers are requirements not yet proved. A passing bounded slice
# never changes the acceptance ID to PASS.
GAPS = {
    "A01": "MIPS/MIPSEL required by spec, deferred to MVP 1B; no cross-target result",
    "A02": "installed-file byte equality, independent postinst exit and MIPS/MIPSEL absent",
    "A03": "full process/socket census, generic host publish and cross-target runs absent",
    "A04": "wrong-ELF/loader/dependency end-to-end cases and other targets absent",
    "A05": "permission/broken-link end-to-end cases and other targets absent",
    "A06": "persistent failure report bundle, one-shot SIGKILL recovery and other targets absent",
    "A07": "fixture-only host HTTP/HTTPS; generic test/up publishing absent",
    "A08": "fixture-only host UDP; generic scenario UDP probe absent",
    "A09": "fixture-only persisted state; generic published persistent lifecycle absent",
    "A18": "explicit persistent recovery only; one-shot and network interruption coverage absent",
    "A19": "offline prepared local AArch64 repeat only; clean air-gapped install and general/cross-target repeats absent",
    "A20": "no hard continuous disk quota or complete socket/process/security-profile audit",
    "A21": "persistent failures have no schema-version-2 report; full provenance/coverage absent",
}

# These node names are real collection IDs, not approximate feature labels.
NODES = {
    "A01": ["test_target_opkg_inventory_and_network_with_owned_cleanup"],
    "A02": [
        "test_aarch64_hello_offline_locked_repeat",
        "test_real_ipk_success_and_failed_postinst",
    ],
    "A03": [
        "test_real_ipk_success_and_failed_postinst",
        "test_persistent_service_readiness_after_same_container_restart",
    ],
    "A04": ["test_static_defect_reports_fail_before_docker[options0-architecture]"],
    "A05": ["test_static_defect_reports_fail_before_docker[options1-shebang]"],
    "A06": [
        "test_real_ipk_success_and_failed_postinst",
        "test_cleanup_failure_preserves_primary_failure",
    ],
    "A07": ["test_https_aarch64_with_local_ca"],
    "A08": ["test_https_aarch64_with_local_ca"],
    "A09": [
        "test_https_aarch64_with_local_ca",
        "test_persistent_service_readiness_after_same_container_restart",
    ],
    "A18": ["test_sigkill_recovery_isolation_and_foreign_preservation"],
    "A19": [
        "test_aarch64_hello_offline_locked_repeat",
        "test_live_image_and_offline_repeat_never_fetches",
    ],
    "A20": [
        "test_owned_runtime_boundary",
        "test_sigkill_recovery_isolation_and_foreign_preservation",
    ],
    "A21": [
        "test_real_ipk_success_and_failed_postinst",
        "test_cleanup_failure_preserves_primary_failure",
    ],
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*args: str) -> str:
    return subprocess.run(  # noqa: S603 -- fixed local git/docker calls only
        args, check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def suite(path: Path) -> tuple[dict, dict[str, str]]:
    raw = path.read_bytes()
    if (
        len(raw) > 2_000_000
        or b"<!DOCTYPE" in raw.upper()
        or b"<!ENTITY" in raw.upper()
    ):
        raise ValueError("oversized or DTD-bearing JUnit XML")
    xml = ET.fromstring(raw)  # noqa: S314 -- bounded local JUnit without DTD
    block = xml.find("testsuite")
    if block is None:
        raise ValueError(f"missing testsuite in {path}")
    cases = {}
    for case in block.findall("testcase"):
        name = case.get("name")
        if name is None or name in cases:
            raise ValueError("missing or duplicate JUnit test name")
        cases[name] = (
            "FAIL"
            if case.find("failure") is not None or case.find("error") is not None
            else "SKIP"
            if case.find("skipped") is not None
            else "PASS"
        )
    total = int(block.get("tests", "-1"))
    if total != len(cases):
        raise ValueError("JUnit case count mismatch")
    counts = {
        status: sum(s == status for s in cases.values())
        for status in ("PASS", "FAIL", "SKIP")
    }
    if counts["FAIL"] != int(block.get("failures", "-1")) + int(
        block.get("errors", "-1")
    ):
        raise ValueError("JUnit failure count mismatch")
    if counts["SKIP"] != int(block.get("skipped", "-1")):
        raise ValueError("JUnit skip count mismatch")
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha(path),
        "counts": counts,
        "tests": cases,
    }, cases


def artifact(path: Path) -> dict:
    if not path.is_file() or not path.resolve().is_relative_to(ROOT):
        raise ValueError(f"missing or external artifact: {path}")
    return {"path": str(path.relative_to(ROOT)), "sha256": sha(path)}


def latest(pattern: str) -> Path:
    candidates = sorted(
        ROOT.glob(pattern), key=lambda p: p.stat().st_mtime_ns, reverse=True
    )
    if not candidates:
        raise ValueError(f"missing runtime evidence: {pattern}")
    return candidates[0]


def freeze() -> dict:
    if OUTPUT.exists() or OUTPUT.is_symlink():
        raise FileExistsError(OUTPUT)
    live, cases = suite(LIVE)
    portable, _ = suite(PORTABLE)
    if live["counts"] != {"PASS": 22, "FAIL": 0, "SKIP": 0}:
        raise ValueError("unexpected live suite outcome")
    if portable["counts"] != {"PASS": 130, "FAIL": 0, "SKIP": 19}:
        raise ValueError("unexpected portable suite outcome")
    if set(GAPS) != set(NODES) or set(GAPS) != set(IDS):
        raise ValueError("acceptance IDs incomplete")
    for names in NODES.values():
        if any(cases.get(name) != "PASS" for name in names):
            raise ValueError(f"required live test missing or not PASS: {names}")

    tls = latest(".runtime/m1a15/live-*/evidence.json")
    observed = json.loads(tls.read_text())
    if observed["cleanup"] != {"private_keys_absent": True, "target_absent": True}:
        raise ValueError("TLS cleanup unverified")
    if any(
        not port.startswith("127.0.0.1:") for port in observed["published"].values()
    ):
        raise ValueError("unexpected publish")
    if set(observed["observations"]) != {
        "initial",
        "service_restart",
        "container_restart",
    }:
        raise ValueError("missing HTTP/HTTPS/UDP observation")
    for entry in observed["observations"].values():
        if (
            entry["trusted_tls"],
            entry["http"],
            entry["udp"],
            entry["https_state"],
            entry["untrusted_ca"],
            entry["wrong_hostname"],
        ) != ("PASS", "PASS", "PASS", "secure", "REJECTED", "REJECTED"):
            raise ValueError("TLS/HTTP/UDP observation inconsistent")
    recovery = latest(".runtime/m1a16/m1a16-*.json")
    recovered = json.loads(recovery.read_text())
    if recovered["foreign_before"] != recovered["foreign_after"] or {
        c["point"] for c in recovered["cases"]
    } != {"creating", "installing"}:
        raise ValueError("recovery/foreign-resource evidence incomplete")
    reports = {
        "hello": sorted(
            ROOT.glob("reports/m1a15-hello-*/report.json"),
            key=lambda p: p.stat().st_mtime_ns,
            reverse=True,
        )[:2],
        "service": [latest("reports/m1a13-service-*/report.json")],
        "startup": [latest("reports/m1a13-startup-*/report.json")],
        "timeout": [latest("reports/m1a13-timeout-*/report.json")],
        "cleanup_error": [latest("reports/m1a13-cleanup-*/report.json")],
        "defect": sorted(
            ROOT.glob("reports/m1a13-static-*/report.json"),
            key=lambda p: p.stat().st_mtime_ns,
            reverse=True,
        )[:2],
    }
    if len(reports["hello"]) != 2 or len(reports["defect"]) != 2:
        raise ValueError("missing repeat or defect report")
    expected = {
        "hello": "PASS",
        "service": "PASS",
        "startup": "FAIL",
        "timeout": "ERROR",
        "cleanup_error": "ERROR",
        "defect": "FAIL",
    }
    for kind, paths in reports.items():
        for path in paths:
            data = json.loads(path.read_text())
            if (
                data["overall"] != expected[kind]
                or data["checks"][-1]["id"] != "cleanup"
            ):
                raise ValueError(f"unexpected report result: {path}")
    defects = [
        json.loads(path.read_text())["partial_failure"]["message"]
        for path in reports["defect"]
    ]
    if not any("architecture" in msg for msg in defects) or not any(
        "shebang" in msg for msg in defects
    ):
        raise ValueError("negative cases do not cover architecture and shebang")
    two = [json.loads(p.read_text()) for p in reports["hello"]]
    for field in ("scenario", "artifact"):
        if two[0][field]["sha256"] != two[1][field]["sha256"]:
            raise ValueError(f"offline repeat input mismatch: {field}")

    owned_containers = command(
        "docker", "container", "ls", "-aq", "--filter", "label=org.keemu.owner=keemu"
    )
    owned_networks = command(
        "docker", "network", "ls", "-q", "--filter", "label=org.keemu.owner=keemu"
    )
    if owned_containers or owned_networks:
        raise ValueError("KEEMU-owned Docker resources remain")
    image_id = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())[
        "oci_digest"
    ]
    if (
        command("docker", "image", "inspect", image_id, "--format", "{{.Id}}")
        != image_id
    ):
        raise ValueError("locked base missing on runner")
    results = {
        id: {
            "status": "BLOCKED",
            "aarch64_slice": "PASS",
            "live_tests": NODES[id],
            "blocker": GAPS[id],
        }
        for id in IDS
    }
    result = {
        "schema_version": 1,
        "subtask_id": "m1a-17",
        "subtask_digest": SUBTASK_DIGEST,
        "created_at": datetime.now(UTC).isoformat(),
        "git_commit": command("git", "rev-parse", "HEAD"),
        "runner": {
            "kind": "project-clean shared Docker host, NOT clean Ubuntu VM",
            "docker_server": command(
                "docker", "version", "--format", "{{.Server.Version}}"
            ),
            "host_kernel": command("docker", "info", "--format", "{{.KernelVersion}}"),
            "locked_base_image": image_id,
            "binfmt_proof": "AArch64 target shell/opkg/nested ELF executed in live tests; host proc entry not visible in worker namespace",
            "foreign_resources": "preserved before/after recovery probe; see recovery artifact",
            "owned_containers_after": [],
            "owned_networks_after": [],
        },
        "test_runs": {"live": live, "portable": portable},
        "artifacts": {
            "tls": artifact(tls),
            "recovery": artifact(recovery),
            **{
                kind: [artifact(path) for path in paths]
                for kind, paths in reports.items()
            },
        },
        "negative_package_observations": [
            {
                "report": artifact(path),
                "observed": "FAIL",
                "expected": "FAIL",
                "stage": "inspect",
                "harness_result": "PASS",
            }
            for path in reports["defect"]
        ],
        "phase_skips": [
            {
                "status": "SKIP",
                "scope": "MIPS/MIPSEL target acceptance",
                "reason": "deferred to MVP 1B; required for whole A01-A06",
            },
            {
                "status": "SKIP",
                "scope": "fresh-Ubuntu instruction",
                "reason": "shared Docker host is project-clean, not a fresh Ubuntu VM",
            },
        ],
        "acceptance": results,
        "mvp1a_gate": "BLOCKED",
        "interpretation": "Live PASS is a bounded AArch64 slice only; negative package FAIL is expected. No full acceptance ID is PASS. SKIP is not PASS. This is not release or clean-host acceptance.",
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


if __name__ == "__main__":
    ledger = freeze()
    print(OUTPUT, sha(OUTPUT), ledger["mvp1a_gate"])
