"""Read-only validation of retained E07 evidence, never a milestone release audit."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree

from keemu.models import RunReport

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/evidence/mvp1e-m1e06-adversarial.json"
PROFILES = {"generic-aarch64", "generic-mips", "generic-mipsel"}


def bound(path: str, expected: str) -> bytes:
    candidate = ROOT / path
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(ROOT):
        raise ValueError(f"unsafe evidence path: {path}")
    raw = candidate.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"evidence hash mismatch: {path}")
    return raw


def junit(raw: bytes) -> dict[str, str]:
    tree = ElementTree.fromstring(raw)  # noqa: S314 -- hash-bound local JUnit
    observed = {}
    for item in tree.findall(".//testcase"):
        name = item.attrib["classname"] + "." + item.attrib["name"]
        if name in observed:
            raise ValueError(f"duplicate JUnit case: {name}")
        observed[name] = (
            "ERROR"
            if item.find("error") is not None
            else "FAIL"
            if item.find("failure") is not None
            else "SKIP"
            if item.find("skipped") is not None
            else "PASS"
        )
    totals = {
        key: sum(value == key for value in observed.values())
        for key in ("PASS", "FAIL", "ERROR", "SKIP")
    }
    suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
    declared = {
        key: sum(int(s.attrib.get(attr, "0")) for s in suites)
        for key, attr in (
            ("FAIL", "failures"),
            ("ERROR", "errors"),
            ("SKIP", "skipped"),
        )
    }
    if any(totals[key] != value for key, value in declared.items()):
        raise ValueError("declared JUnit status totals disagree")
    if sum(int(s.attrib["tests"]) for s in suites) != len(observed):
        raise ValueError("declared JUnit testcase count disagrees")
    return observed


def check() -> dict:
    record = json.loads(MANIFEST.read_text())
    if record["subtask"] != "m1e-06" or record["acceptance_ref"] != "E07":
        raise ValueError("wrong frozen subtask")
    if record["subtask_digest"] != (
        "1bd33eb6b7da79a9a2848c43efc11290dcd8548870be20cddd43c6ed9f317eff"
    ):
        raise ValueError("wrong frozen digest")
    if record["status"] != "SCOPED_PASS" or record["E06"] != "BLOCKED":
        raise ValueError("verification or engineering verdict changed")
    if record["MVP1D"] != {"D02": "BLOCKED", "D07": "BLOCKED"}:
        raise ValueError("predecessor blocker promoted")
    if record["E08"] != "NOT_EVALUATED":
        raise ValueError("worked ahead on the final audit")
    for path, expected in record["source_sha256"].items():
        bound(path, expected)
    artifacts = record["artifacts"]
    payloads = {
        path: bound(item["retained"], item["sha256"])
        for path, item in artifacts.items()
    }
    for name in record["typed_reports"]:
        report = RunReport.model_validate_json(payloads[name])
        if report.overall != record["typed_reports"][name]:
            raise ValueError("typed report status changed")
    testcases = {}
    counts = {}
    for name, expected in record["junit"].items():
        observed = junit(payloads[name])
        totals = {
            key: list(observed.values()).count(key)
            for key in ("PASS", "FAIL", "ERROR", "SKIP")
        }
        if totals != expected["counts"]:
            raise ValueError(f"wrong JUnit counts: {name}")
        counts[name] = totals
        if expected["role"] == "adversarial_acceptance":
            if any(status != "PASS" for status in observed.values()):
                raise ValueError("adversarial acceptance did not PASS")
            if testcases.keys() & observed.keys():
                raise ValueError("adversarial cases double-counted")
            testcases.update(observed)
    if len(testcases) != 19:
        raise ValueError("not exactly 19 unique adversarial cases")
    matrix = record["matrix"]
    if set(matrix) != PROFILES:
        raise ValueError("incomplete three-target matrix")
    for profile, row in matrix.items():
        if set(row["observations"]) != {
            "stage",
            "lifecycle",
            "one-shot-kill",
            "persistent-create-kill",
            "persistent-script",
            "one-shot-outcomes",
        }:
            raise ValueError(f"incomplete dimensions: {profile}")
        observations = {
            kind: json.loads(payloads[path])
            for kind, path in row["observations"].items()
        }
        if any(value["profile"] != profile for value in observations.values()):
            raise ValueError("observation profile mismatch")
        stage = observations["stage"]
        if stage["source_inode_swap"] != "BLOCKED":
            raise ValueError("source swap adopted")
        if stage["collision"] != "preserved_no_overwrite":
            raise ValueError("staged collision overwritten")
        if not stage["container_teardown"]["removed_and_absent"]:
            raise ValueError("stage container not exact-cleaned")
        kills = observations["one-shot-kill"]["phases"]
        if {x["phase"] for x in kills} != {"after-create", "after-stage", "active"}:
            raise ValueError("one-shot interruption boundary missing")
        for event in kills:
            if event["worker_returncode"] != -9:
                raise ValueError("worker not actually SIGKILLed")
            if event["interrupted_report"] != "absent_no_PASS":
                raise ValueError("interrupted report falsely PASS")
            if not event["explicit_test_recovery"]["removed_and_absent"]:
                raise ValueError("interrupted container remains")
        creates = observations["persistent-create-kill"]["phases"]
        if {x["phase"] for x in creates} != {"creating", "installing"}:
            raise ValueError("persistent interruption boundary missing")
        for event in creates:
            if (
                event["worker_returncode"] != -9
                or not event["idempotent"]
                or not event["tombstone_consistent"]
            ):
                raise ValueError("persistent explicit recovery not verified")
            if event["production_recovery"]["removed"] != [event["container"]]:
                raise ValueError("recovery removed non-exact IDs")
        persistent = observations["persistent-script"]
        if persistent["automatic_artifact_recovery"] != "BLOCKED_not_implemented":
            raise ValueError("persistent artifact limitation promoted")
        if (
            persistent["production_down_destroy_tombstone"]["state"] != "destroyed"
            or not persistent["service_and_postinst_preserved"]
            or persistent["same_name_concurrency"] != "busy"
        ):
            raise ValueError("persistent cleanup/service/lock proof missing")
        if [x["status"] for x in persistent["reports"]] != ["PASS", "FAIL"]:
            raise ValueError("persistent timeout status reinterpreted")
        if [x["status"] for x in observations["one-shot-outcomes"]["reports"]] != [
            "PASS",
            "FAIL",
            "PASS",
            "FAIL",
        ]:
            raise ValueError("one-shot outcomes reinterpreted")
    concurrent = json.loads(payloads[record["concurrent_observation"]])
    if (
        not concurrent["simultaneous_stage_barrier"]
        or not concurrent["exact_cleanup"]
        or len({x["container"] for x in concurrent["stages"]}) != 3
        or len({x["path"] for x in concurrent["stages"]}) != 3
        or {x["profile"] for x in concurrent["reports"]} != PROFILES
    ):
        raise ValueError("three-target concurrent isolation proof missing")
    baseline = json.loads(payloads[record["baseline"]])
    postflight = json.loads(payloads[record["postflight"]])
    if baseline["docker"] != postflight["docker"]:
        raise ValueError("unrelated Docker resources changed")
    if baseline["protected"] != postflight["protected"]:
        raise ValueError("frozen source/evidence changed")
    if baseline["registry"] != postflight["prior_registry"]:
        raise ValueError("prior registry records changed")
    for path, expected in baseline["protected"].items():
        bound(path, expected)
    if any(
        x["state"] != "destroyed" or not x["consistent"]
        for x in postflight["new_registry"].values()
    ):
        raise ValueError("new test registry record not a consistent tombstone")
    runtime = json.loads(payloads[record["runtime_metadata"]])
    if (
        runtime["model"] != "gpt-6.1-sol"
        or runtime["billing_provider"] != "openai-codex"
        or runtime["reasoning_config"] != {"enabled": True, "effort": "xhigh"}
    ):
        raise ValueError("actual canonical runtime disagrees with frozen route")
    return {
        "subtask": "m1e-06",
        "E07": "SCOPED_PASS",
        "adversarial_unique_PASS": len(testcases),
        "junit": counts,
        "typed_reports": len(record["typed_reports"]),
        "retained_artifacts": len(artifacts),
        "E06": "BLOCKED",
        "D02_D07": "BLOCKED",
        "E08": "NOT_EVALUATED",
    }


if __name__ == "__main__":
    print(json.dumps(check(), sort_keys=True))
