from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from keemu.models import CheckResult, ProfileMetadata, RunReport, RuntimeMetadata
from keemu.reports import build_report, write_report_bundle
from keemu.script_results import (
    ScriptAssertionResult,
    ScriptCleanupResult,
    ScriptExecutionResult,
    ScriptExecutionSpec,
    ScriptReportMetadata,
    ScriptResult,
    ScriptStatus,
)

DIGEST = "a" * 64
CONTAINER = "b" * 64
IMAGE = "sha256:" + "c" * 64
TARGET = f"/opt/tmp/keemu-script-{DIGEST}-{'d' * 24}/script.sh"


def _spec(**changes: object) -> ScriptExecutionSpec:
    values: dict[str, object] = dict(
        source="fixtures/scripts/test.sh",
        sha256=DIGEST,
        target_path=TARGET,
        profile_id="generic-aarch64",
        profile_revision=1,
        architecture="aarch64-3.10",
        image_id=IMAGE,
        container_id=CONTAINER,
        mode="one-shot",
        argv=("--token=SECRET_ARGUMENT", "two words"),
        cwd="/opt/etc",
        timeout_seconds=60,
    )
    values.update(changes)
    return ScriptExecutionSpec(**values)


def _outcome(**changes: object) -> ScriptExecutionResult:
    values: dict[str, object] = dict(
        state="executed",
        exit_code=0,
        timed_out=False,
        process_tree_clean=True,
        duration_seconds=0.25,
        stdout=b"SECRET_STDOUT\n",
        stderr=b"SECRET_STDERR\x00",
        truncated_stdout=False,
        truncated_stderr=True,
    )
    values.update(changes)
    return ScriptExecutionResult(**values)


def _assert(status: ScriptStatus = "PASS", expected: int = 0) -> ScriptAssertionResult:
    return ScriptAssertionResult(
        id="exit-code",
        kind="exit-code",
        status=status,
        reason_code="exit-code-check",
        expected_exit_code=expected,
    )


def _clean(kind: str = "target-script", verified: bool = True) -> ScriptCleanupResult:
    return ScriptCleanupResult(
        kind=kind,
        attempted=True,
        verified=verified,
        reason_code=None if verified else "identity-changed",
    )


def _result(**changes: object) -> ScriptResult:
    fields: dict[str, object] = dict(
        spec=_spec(),
        outcome=_outcome(),
        assertions=(_assert(),),
        cleanup=(_clean(), _clean("container")),
    )
    fields.update(changes)
    return ScriptResult(**fields)


def _blocked() -> ScriptExecutionResult:
    return _outcome(
        state="blocked",
        exit_code=None,
        process_tree_clean=False,
        stdout=b"",
        stderr=b"",
        truncated_stderr=False,
    )


def test_pass_is_derived_only_from_execution_assertions_and_verified_cleanup() -> None:
    result = _result()
    metadata = result.report_metadata()
    assert result.status == metadata.status == "PASS"
    assert metadata.execution.interpreter == "/bin/sh"
    assert metadata.execution.target_path == TARGET
    assert metadata.execution.timeout_seconds == 60
    assert metadata.outcome.stdout.byte_count == len(result.outcome.stdout)
    assert (
        metadata.outcome.stdout.sha256
        == hashlib.sha256(result.outcome.stdout).hexdigest()
    )
    assert metadata.outcome.stderr.truncated is True
    assert (
        metadata.execution.argv[0].sha256
        == hashlib.sha256(result.spec.argv[0].encode()).hexdigest()
    )
    assert "SECRET" not in json.dumps(metadata.model_dump(mode="json"))
    assert "SECRET" not in str(result.outcome.model_dump(mode="json"))
    assert "SECRET" not in str(result.spec.model_dump(mode="json"))
    assert (
        ScriptReportMetadata.model_validate(metadata.model_dump(mode="json"))
        == metadata
    )


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_result(assertions=(_assert("FAIL"),)), "FAIL"),
        (_result(outcome=_outcome(exit_code=7), assertions=(_assert("FAIL"),)), "FAIL"),
        (_result(outcome=_outcome(exit_code=7)), "FAIL"),
        (
            _result(outcome=_outcome(exit_code=7), assertions=(_assert(expected=7),)),
            "PASS",
        ),
        (_result(outcome=_outcome(timed_out=True, exit_code=None)), "FAIL"),
        (
            _result(
                outcome=_outcome(
                    timed_out=True, exit_code=None, process_tree_clean=False
                )
            ),
            "ERROR",
        ),
        (
            _result(
                outcome=_outcome(
                    state="error",
                    exit_code=None,
                    process_tree_clean=False,
                    stdout=b"",
                    stderr=b"",
                    truncated_stderr=False,
                )
            ),
            "ERROR",
        ),
        (
            _result(
                spec=_spec(target_path=None, container_id=None),
                outcome=_blocked(),
                assertions=(),
                cleanup=(),
            ),
            "BLOCKED",
        ),
        (_result(assertions=(_assert("BLOCKED"),)), "BLOCKED"),
        (_result(assertions=(_assert("ERROR"),)), "ERROR"),
        (_result(cleanup=(_clean(verified=False),)), "ERROR"),
        (_result(cleanup=(_clean(), _clean("container", False))), "ERROR"),
        (_result(cleanup=()), "ERROR"),
        (_result(assertions=()), "ERROR"),
        (_result(cleanup=(_clean(), _clean())), "ERROR"),
        (_result(assertions=(_assert(), _assert())), "ERROR"),
        (_result(spec=_spec(mode="persistent"), cleanup=(_clean(),)), "PASS"),
        (_result(spec=_spec(mode="persistent")), "ERROR"),
    ],
)
def test_status_mapping(result: ScriptResult, expected: str) -> None:
    assert result.status == expected
    assert result.report_metadata().status == expected


def test_blocked_input_with_failed_cleanup_is_error() -> None:
    result = _result(
        spec=_spec(target_path=None, container_id=None),
        outcome=_blocked(),
        assertions=(),
        cleanup=(_clean(verified=False),),
    )
    assert result.status == "ERROR"


def test_blocked_after_container_allocation_requires_exact_cleanup() -> None:
    spec = _spec(target_path=None)
    blocked = _blocked()
    assert (
        _result(
            spec=spec, outcome=blocked, assertions=(), cleanup=(_clean("container"),)
        )
        .report_metadata()
        .status
        == "BLOCKED"
    )
    assert (
        _result(spec=spec, outcome=blocked, assertions=(), cleanup=()).status == "ERROR"
    )
    assert (
        _result(
            outcome=blocked,
            assertions=(),
            cleanup=(_clean(), _clean("container")),
        )
        .report_metadata()
        .status
        == "BLOCKED"
    )
    assert _result(outcome=blocked, assertions=(), cleanup=()).status == "ERROR"


@pytest.mark.parametrize(
    "changes",
    [
        {"target_path": "/opt/tmp/foreign/script.sh"},
        {"target_path": TARGET.replace(DIGEST, "e" * 64)},
        {"container_id": None},
        {"cwd": "/opt/../etc"},
        {"cwd": "/var"},
        {"source": "../outside.sh"},
        {"source": "fixture/\nsecret.sh"},
        {"timeout_seconds": 601},
        {"timeout_seconds": 0},
        {"argv": ("bad\x00arg",)},
        {"argv": ("x" * 4097,)},
        {"argv": tuple("x" for _ in range(127))},
    ],
)
def test_spec_rejects_unsafe_or_unbounded_contract(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _spec(**changes)


def test_results_and_cleanup_reject_contradictory_claims() -> None:
    for changes in (
        {"state": "blocked", "exit_code": 0},
        {"state": "executed", "exit_code": None},
        {"stdout": b"x" * (1024 * 1024 + 1)},
        {"duration_seconds": float("nan")},
    ):
        with pytest.raises(ValidationError):
            _outcome(**changes)
    with pytest.raises(ValidationError):
        ScriptCleanupResult(kind="target-script", attempted=False, verified=True)
    with pytest.raises(ValidationError):
        ScriptCleanupResult(kind="target-script", attempted=True, verified=False)
    metadata = _result().report_metadata().model_dump(mode="json")
    metadata["status"] = "BLOCKED"
    with pytest.raises(ValidationError, match="script status does not match"):
        ScriptReportMetadata.model_validate(metadata)


def test_report_round_trip_schema_parity_and_no_secret_publication(
    tmp_path: Path,
) -> None:
    result = _result()
    script = result.report_metadata()
    report = build_report(
        run_id="run-script-123",
        created_at="2026-09-27T00:00:00Z",
        operation="script",
        script=script,
        profile=ProfileMetadata(
            id="generic-aarch64", revision=1, kind="generic", sha256=DIGEST
        ),
        runtime=RuntimeMetadata(
            keemu_version="0.1",
            git_commit=None,
            git_dirty=None,
            oci_digest=IMAGE,
            qemu_version=None,
            binfmt_configuration=(),
            host_kernel="test",
            entware_target="aarch64-3.10",
            feed_lock_sha256=None,
            versions=(),
            network_fidelity=None,
            native_tools=(),
        ),
        checks=[
            CheckResult(
                id="script",
                status=result.status,
                cause_class="package",
                evidence=("exit-code assertion verified",),
                mode="real",
                required=True,
                duration_seconds=0.25,
                limitations=(),
            )
        ],
    )
    paths = write_report_bundle(report, tmp_path / report.run_id)
    payload = paths.json.read_text()
    markdown = paths.markdown.read_text()
    assert "SECRET" not in payload + markdown
    assert "truncated `true`" in markdown
    assert json.loads(payload)["script"] == script.model_dump(mode="json")
    assert RunReport.model_validate_json(payload) == report
    for change in (
        {"profile": report.profile.model_copy(update={"revision": 2})},
        {"runtime": report.runtime.model_copy(update={"entware_target": "mips-3.4"})},
        {"checks": (report.checks[0].model_copy(update={"id": "not-script"}),)},
    ):
        with pytest.raises(ValidationError, match="script report metadata disagrees"):
            RunReport.model_validate(replace_report(report, **change))
    root = Path(__file__).resolve().parents[2]
    assert (
        json.loads((root / "schemas/run-report.schema.json").read_text())
        == RunReport.model_json_schema()
    )
    assert (
        json.loads((root / "schemas/script-report.schema.json").read_text())
        == ScriptReportMetadata.model_json_schema()
    )


def replace_report(report: RunReport, **changes: object) -> dict[str, object]:
    return report.model_copy(update=changes).model_dump(mode="python")
