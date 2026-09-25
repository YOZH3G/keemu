"""Offline, read-only validation of the final-29 release observation.

This validates retained results, not a fresh Docker/network execution or release PASS.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/evidence/final29-release.json"


def bound_bytes(path: str, expected: str) -> bytes:
    candidate = ROOT / path
    if not candidate.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError(f"path escapes repository: {path}")
    raw = candidate.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"hash mismatch: {path}")
    return raw


def check() -> dict[str, object]:
    record = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if record["schema_version"] != 1 or record["subtask"] != "final-29":
        raise ValueError("wrong release observation")
    if record["release_gate"] != "BLOCKED" or record["full_sweep"]["result"] != "FAIL":
        raise ValueError("failed sweep promoted to release PASS")
    for name, digest in record["raw_logs_sha256"].items():
        bound_bytes(name, digest)
    full = record["full_sweep"]
    cases = ElementTree.fromstring(  # noqa: S314 -- local SHA-256-bound JUnit
        bound_bytes(full["source"], full["source_sha256"])
    )
    observed: dict[str, str] = {}
    for case in cases.findall(".//testcase"):
        name = f"{case.attrib['classname']}.{case.attrib['name']}"
        observed[name] = (
            "FAIL"
            if case.find("failure") is not None or case.find("error") is not None
            else "SKIP"
            if case.find("skipped") is not None
            else "PASS"
        )
    counts = {
        status: list(observed.values()).count(status)
        for status in ("PASS", "FAIL", "SKIP")
    }
    if counts != full["counts"] or len(observed) != sum(counts.values()):
        raise ValueError("JUnit counts disagree with release ledger")
    for status, rows in (("FAIL", full["failed"]), ("SKIP", full["skipped"])):
        expected = {
            row["test"].replace("/", ".").replace(".py::", ".").replace("::", ".")
            for row in rows
        }
        actual = {name for name, value in observed.items() if value == status}
        if expected != actual:
            raise ValueError(f"incorrect {status} list: {actual ^ expected}")
    portable = record["portable"]
    if portable["result"] != "PASS" or portable["counts"] != {
        "PASS": 208,
        "SKIP": 30,
        "FAIL": 0,
    }:
        raise ValueError("portable result mismatch")
    portable_log = bound_bytes(portable["log"], portable["log_sha256"])
    if "208 passed, 30 skipped" not in portable_log.decode():
        raise ValueError("portable log mismatch")
    target = record["three_target"]
    rows = json.loads(bound_bytes(target["raw"], target["raw_sha256"]))["results"]
    if {item["target"] for item in rows} != {"mips-3.4", "mipsel-3.4"}:
        raise ValueError("MIPS target coverage mismatch")
    if any(
        item["direct_status"] != "PASS" or item["docker_status"] != "PASS"
        for item in rows
    ):
        raise ValueError("MIPS target execution not PASS")
    capability = json.loads(
        bound_bytes(target["capability_raw"], target["capability_sha256"])
    )
    if capability["modules_before"] != capability["modules_after"]:
        raise ValueError("module state changed during capability probe")
    if {item["target"] for item in capability["results"]} != {
        "aarch64-3.10",
        "mips-3.4",
        "mipsel-3.4",
    }:
        raise ValueError("socket target coverage mismatch")
    if any(
        item["socket_status"] != "BLOCKED" or item["native_control_status"] != "PASS"
        for item in capability["results"]
    ):
        raise ValueError("socket differential disagrees")
    network = record["applicable_network"]
    interruption = json.loads(
        bound_bytes(
            network["fresh_interruption_raw"],
            network["fresh_interruption_sha256"],
        )
    )
    if any(
        interruption["baseline"][kind] != interruption["postflight"][kind]
        for kind in ("container", "network")
    ):
        raise ValueError("foreign Docker state changed during interruption test")
    if interruption["interrupted_report"] != network["interrupted_A21_report"]:
        raise ValueError("interrupted report limit differs")
    host = record["clean_host"]
    snapshot = json.loads(bound_bytes(host["source"], host["source_sha256"]))
    if snapshot["owner_containers"] or snapshot["owner_networks"]:
        raise ValueError("owned resources remained in clean-host snapshot")
    if (
        snapshot["module_state"] != host["modules"]
        or snapshot["kernel_taint"] != host["kernel_taint"]
    ):
        raise ValueError("module/taint snapshot differs")
    if any(item["present"] for item in snapshot["image_prerequisites"].values()):
        raise ValueError("missing-image diagnosis conflicts with snapshot")
    return {
        "subtask": "final-29",
        "cases": counts,
        "target_probes": len(rows),
        "socket_probes": len(capability["results"]),
        "release_gate": "BLOCKED",
    }


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
