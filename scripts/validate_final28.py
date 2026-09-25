"""Validate the final-28 reconciliation without running privileged integration tests."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/evidence/final28-acceptance.json"
IDS = {f"A{number:02}" for number in range(1, 22)}
THREE_TARGET = {"A01", "A02", "A03", "A04", "A05", "A06", "A10", "A11"}
TARGETS = {"generic-aarch64", "generic-mipsel", "generic-mips"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_bytes(root: Path, entry: dict[str, str]) -> bytes:
    name = entry["path"]
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), f"unsafe source: {name}")
    content = path.read_bytes()
    require(
        re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None
        and hashlib.sha256(content).hexdigest() == entry["sha256"],
        f"evidence hash mismatch: {name}",
    )
    return content


def junit_counts(content: bytes) -> dict[str, int]:
    suites = ElementTree.fromstring(content)  # noqa: S314 - SHA-256-bound local JUnit
    cases = suites.findall(".//testcase")
    return {
        "PASS": sum(not list(case) for case in cases),
        "FAIL": sum(
            bool(case.findall("failure") or case.findall("error")) for case in cases
        ),
        "SKIP": sum(bool(case.findall("skipped")) for case in cases),
    }


def validate(root: Path = ROOT, ledger_path: Path = LEDGER) -> dict:
    ledger = json.loads(ledger_path.read_text())
    require(
        ledger["schema_version"] == 1 and ledger["subtask"] == "final-28",
        "ledger identity",
    )
    require(set(ledger["targets"]) == TARGETS, "target coverage")
    require(set(ledger["acceptance"]) == IDS, "exact A01-A21 coverage")
    require(ledger["acceptance"]["A01"]["status"] == "PASS", "A01 target execution")
    require(
        all(
            ledger["acceptance"][name]["status"] == "BLOCKED" for name in IDS - {"A01"}
        ),
        "unproved whole ID promoted to PASS",
    )
    require(
        set(ledger["sources"])
        == {key for row in ledger["acceptance"].values() for key in row["evidence"]}
        | {"m1b18_initial"},
        "unbound or unused evidence",
    )
    for ident, row in ledger["acceptance"].items():
        require(
            row["observed"] and row["gap"] and row["evidence"] and row["tests"],
            f"incomplete {ident}",
        )
        require(
            all(key in ledger["sources"] for key in row["evidence"]),
            f"unknown evidence: {ident}",
        )
        for name in row["tests"]:
            path = root / name
            require(
                name.startswith("tests/") and path.is_file(),
                f"missing test: {ident} {name}",
            )
    sources = {
        key: json.loads(source_bytes(root, entry))
        for key, entry in ledger["sources"].items()
        if entry["path"].endswith(".json")
    }
    for entry in ledger["sources"].values():
        if not entry["path"].endswith(".json"):
            source_bytes(root, entry)
    old = sources["m1a17"]
    mips = sources["m1b18_pass"]
    first = sources["m1b18_initial"]
    cross = sources["m1b22"]
    require(
        all(row["status"] == "BLOCKED" for row in old["acceptance"].values()),
        "historical AArch64 status",
    )
    require(
        all(row["status"] == "SKIP" for row in old["phase_skips"]), "historical skips"
    )
    require(
        first["slice_status"] == "BLOCKED" and mips["slice_status"] == "PASS",
        "MIPS chronological status",
    )
    require(
        mips["historical_blocked_ledger_sha256"]
        == ledger["sources"]["m1b18_initial"]["sha256"],
        "MIPS historical binding",
    )
    require(
        mips["aarch64_ledger_sha256"] == ledger["sources"]["m1a17"]["sha256"],
        "AArch64 historical binding",
    )
    require(
        {row["profile"] for row in mips["targets"]} == TARGETS - {"generic-aarch64"},
        "MIPS targets",
    )
    require(
        all(row["docker_binfmt"] == "PASS" for row in mips["targets"]),
        "MIPS Docker target execution",
    )
    require(
        set(cross["required_ids"]) == THREE_TARGET and cross["mvp1b_gate"] == "BLOCKED",
        "cross-target gate",
    )
    for profile in TARGETS:
        row = cross["targets"][profile]
        require(
            row["A01"] == "PASS"
            and all(row[id] == "BLOCKED" for id in THREE_TARGET - {"A01"}),
            f"cross-target status {profile}",
        )
        require(
            cross["doctor"][profile]["overall"] == "BLOCKED",
            f"doctor visibility {profile}",
        )
    require(
        cross["matrix"]["status"] == "BLOCKED"
        and cross["matrix"]["checks"]["generic-aarch64"] == "PASS",
        "matrix precedence",
    )
    require(
        all(
            cross["matrix"]["checks"][profile] == "BLOCKED"
            for profile in TARGETS - {"generic-aarch64"}
        ),
        "matrix unsupported targets",
    )
    for profile in TARGETS:
        probe = cross["capabilities"]["per_target"][cross["targets"][profile]["target"]]
        require(
            probe["target_socket"] == "BLOCKED" and probe["native_socket"] == "PASS",
            f"socket differential {profile}",
        )
    require(
        all(
            item["observed"] == item["expected"] == "FAIL"
            and item["harness_result"] == "PASS"
            for item in old["negative_package_observations"]
        ),
        "negative package semantics",
    )
    for entries in old["artifacts"].values():
        for entry in entries if isinstance(entries, list) else [entries]:
            source_bytes(root, entry)
    old_raw = root / first["raw_probe"]
    require(
        not old_raw.exists()
        or hashlib.sha256(old_raw.read_bytes()).hexdigest()
        != first["raw_probe_sha256"],
        "historical MIPS raw unexpectedly recovered; reconcile its status",
    )
    for label, record, kind in (
        ("m1a17_live", old["test_runs"]["live"], "direct"),
        ("m1a17_portable", old["test_runs"]["portable"], "direct"),
        ("m1b22_live", cross["test_runs"]["live"], "nested"),
        ("m1b22_portable", cross["test_runs"]["portable"], "nested"),
    ):
        entry = record if kind == "direct" else record["artifact"]
        require(
            junit_counts(source_bytes(root, entry))
            == ledger["historical_tests"][label]
            == record["counts"],
            f"JUnit mismatch {label}",
        )
    for entry in cross["previous_evidence"].values():
        source_bytes(root, entry)
    for key in ("parent", "child"):
        source_bytes(root, cross["matrix"][key])
    source_bytes(root, cross["capabilities"]["artifact"])
    for key in ("m1c26_initial_blocker", "m1c26_module_recheck"):
        prior = sources[key]
        require(
            prior["result"].startswith("BLOCKED")
            and prior["target_socket"]["exit_code"] == 1
            and "Protocol not supported" in prior["target_socket"]["stderr"],
            f"direct target queue blocker {key}",
        )
    packet = sources["m1c26"]
    corr = packet["correlation"]
    require(
        corr
        == {
            "adapter_verdicts": 17,
            "kernel_sequence": 17,
            "pcap_records": 17,
            "rule_packets": 17,
            "target_accepted": 10,
            "target_dropped": 7,
        },
        "packet correlation",
    )
    require(
        packet["pcap"]["sha256"] == ledger["sources"]["m1c26_pcap"]["sha256"]
        and packet["pcap"]["bytes"]
        == len(source_bytes(root, ledger["sources"]["m1c26_pcap"])),
        "pcap binding",
    )
    require(
        packet["no_listener_queue"] == ""
        and packet["no_listener_state"]["accepted"] == 10,
        "no-listener fail closed",
    )
    require(
        sources["m1c26_rollback"]["rollback"]["unload_order"]
        == ["xt_NFQUEUE", "iptable_filter"],
        "module rollback",
    )
    api = sources["m1c25_api"]
    persistence = sources["m1c25_persistence"]
    require(
        api["whole_id"] == persistence["whole_id"] == "PARTIAL"
        and api["mode"] == persistence["mode"] == "api-only",
        "API-only status",
    )
    require(
        "br0 routing not reconfigured" in persistence["scope"],
        "restart routing limitation",
    )
    network = sources["m1c27"]
    require(
        network["baseline"] == network["postflight"] and len(network["cases"]) == 3,
        "foreign Docker parity",
    )
    require(
        all(
            case["foreign_policy_rules_after_kill"]
            == case["foreign_policy_rules_after_recovery"]
            == network["foreign_rules"]
            for case in network["cases"]
        ),
        "foreign policy rule parity",
    )
    require(
        network["interrupted_report"].startswith("NOT IMPLEMENTED")
        and network["host_firewall_rules"].startswith("NOT RUN"),
        "interruption gaps",
    )
    require(
        len(ledger["contradictions"]) >= 7
        and all(
            ledger["gates"][key] == "BLOCKED"
            for key in ("MVP 1A", "MVP 1B", "MVP 1C", "MVP 1")
        ),
        "unresolved contradictions or gate promotion",
    )
    return ledger


if __name__ == "__main__":
    result = validate()
    print(
        f"validated {len(result['acceptance'])} IDs, "
        f"{len(result['sources'])} hash-bound sources; release BLOCKED"
    )
