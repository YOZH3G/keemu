from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import keemu.reports as reports_module
from keemu.models import (
    ArtifactMetadata,
    CapabilityResult,
    OperationLogEntry,
    PartialFailureMetadata,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
    RuntimeVersion,
    ScenarioMetadata,
    SubstitutionMetadata,
)
from keemu.profiles import GenericProfile
from keemu.reports import (
    CheckResult,
    build_report,
    exit_code_for_status,
    write_report_bundle,
)

PROFILE = ProfileMetadata(
    id="generic-aarch64",
    revision=1,
    kind="generic",
    sha256="1" * 64,
)
RUNTIME = RuntimeMetadata(
    keemu_version="0.1.0",
    git_commit="a" * 40,
    git_dirty=False,
    oci_digest="sha256:" + "b" * 64,
    qemu_version="10.0.13",
    binfmt_configuration=["enabled", "flags: F"],
    host_kernel="6.8.0-test",
    entware_target="aarch64-3.10",
    feed_lock_sha256="c" * 64,
    versions=[
        RuntimeVersion(name="docker", version="26.1.5"),
        RuntimeVersion(name="python", version="3.12.13"),
    ],
    network_fidelity=None,
    native_tools=["tini"],
)


def _passing_report(run_id: str) -> RunReport:
    return build_report(
        run_id=run_id,
        created_at="2026-09-22T19:40:00Z",
        operation="test",
        profile=PROFILE,
        runtime=RUNTIME,
        checks=[
            CheckResult(
                id="bundle",
                status="PASS",
                cause_class="harness",
                evidence=("bundle assembled",),
                mode="real",
                required=True,
                duration_seconds=0.1,
                limitations=(),
            )
        ],
    )


def test_required_skip_aggregates_to_blocked_with_coverage() -> None:
    report = build_report(
        run_id="run-123",
        created_at="2026-09-22T08:00:00Z",
        operation="doctor",
        profile=PROFILE,
        runtime=RUNTIME,
        checks=[
            CheckResult(
                id="host",
                status="PASS",
                cause_class="environment",
                evidence=["Linux x86_64"],
                mode="real",
                required=True,
                duration_seconds=0.1,
                limitations=[],
            ),
            CheckResult(
                id="binfmt",
                status="SKIP",
                cause_class="environment",
                evidence=["registration absent"],
                mode="real",
                required=True,
                duration_seconds=0.0,
                limitations=[],
            ),
        ],
    )

    assert report.schema_version == 2
    assert report.overall == "BLOCKED"
    assert report.coverage.model_dump() == {
        "required": 2,
        "passed": 1,
        "failed": 0,
        "blocked": 1,
        "skipped": 1,
        "warned": 0,
        "errors": 0,
    }


def test_json_and_markdown_are_written_from_same_report_object(
    tmp_path: Path,
) -> None:
    report = build_report(
        run_id="run-456",
        created_at="2026-09-22T13:00:00Z",
        operation="doctor",
        profile=PROFILE,
        runtime=RUNTIME,
        checks=[
            CheckResult(
                id="host",
                status="PASS",
                cause_class="environment",
                evidence=["Linux x86_64"],
                mode="real",
                required=True,
                duration_seconds=0.1,
                limitations=[],
            )
        ],
    )

    paths = write_report_bundle(report, tmp_path / report.run_id)

    payload = json.loads(paths.json.read_text(encoding="utf-8"))
    markdown = paths.markdown.read_text(encoding="utf-8")
    assert payload == report.model_dump(mode="json")
    assert "Run: `run-456`" in markdown
    assert "Overall: **PASS**" in markdown
    assert "| host | PASS | real | required | Linux x86_64 |" in markdown


def test_committed_json_schemas_match_current_models() -> None:
    root = Path(__file__).resolve().parents[2]

    assert json.loads((root / "schemas/run-report.schema.json").read_text()) == (
        RunReport.model_json_schema()
    )
    assert json.loads((root / "schemas/generic-profile.schema.json").read_text()) == (
        GenericProfile.model_json_schema()
    )


def test_exit_code_for_aggregate_status() -> None:
    assert exit_code_for_status("PASS") == 0
    assert exit_code_for_status("WARN") == 0
    assert exit_code_for_status("FAIL") == 1
    assert exit_code_for_status("ERROR") == 3
    assert exit_code_for_status("BLOCKED") == 4


def test_report_captures_a21_metadata_and_is_frozen() -> None:
    report = build_report(
        run_id="run-metadata",
        created_at="2026-09-22T19:10:00Z",
        operation="test",
        artifact=ArtifactMetadata(
            id="web-demo",
            kind="ipk",
            version="1.0.0",
            source="fixtures/packages/web-demo.ipk",
            sha256="d" * 64,
            architecture="aarch64-3.10",
        ),
        scenario=ScenarioMetadata(
            id="web-demo",
            schema_version=1,
            source="fixtures/scenarios/web-demo.yaml",
            sha256="e" * 64,
        ),
        profile=PROFILE,
        runtime=RUNTIME,
        capabilities=[
            CapabilityResult(
                id="nfqueue",
                status="BLOCKED",
                mode="real",
                evidence=["Docker daemon unavailable"],
                limitations=["active probe not run"],
            )
        ],
        substitutions=[
            SubstitutionMetadata(
                id="native-firewall-control",
                replaces="target iptables",
                reason="P0 control experiment",
                evidence=["planned control path"],
            )
        ],
        operation_log=[
            OperationLogEntry(
                sequence=1,
                operation="install",
                started_at="2026-09-22T19:10:00Z",
                completed_at="2026-09-22T19:10:02Z",
                status="FAIL",
                argv=["opkg", "install", "web-demo.ipk"],
                cwd="/opt",
                exit_code=1,
                duration_seconds=2.0,
                stdout_path="stdout/install.log",
                stderr_path="stderr/install.log",
                timed_out=False,
                truncated=False,
            )
        ],
        partial_failure=PartialFailureMetadata(
            status="FAIL",
            operation_sequence=1,
            operation="install",
            cause_class="package",
            message="postinst exited 1",
            interrupted=False,
            cleanup_attempted=True,
            cleanup_status="PASS",
            preserved_artifacts=[
                "report.json",
                "report.md",
                "operation-log.jsonl",
                "stderr/install.log",
            ],
        ),
        checks=[
            CheckResult(
                id="postinst",
                status="FAIL",
                cause_class="package",
                evidence=["exit_code=1"],
                mode="real",
                required=True,
                duration_seconds=2.0,
                limitations=[],
            )
        ],
        limitations=["Docker integration not run"],
    )

    payload = report.model_dump(mode="json")
    assert report.overall == "FAIL"
    assert payload["artifact"]["sha256"] == "d" * 64
    assert payload["scenario"]["sha256"] == "e" * 64
    assert payload["profile"]["revision"] == 1
    assert payload["runtime"]["git_dirty"] is False
    assert payload["capabilities"][0]["status"] == "BLOCKED"
    assert payload["substitutions"][0]["replaces"] == "target iptables"
    assert payload["operation_log"][0]["exit_code"] == 1
    assert payload["partial_failure"]["cleanup_status"] == "PASS"
    with pytest.raises(ValidationError):
        report.overall = "PASS"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        report.checks.append(report.checks[0])

    payload["overall"] = "PASS"
    with pytest.raises(ValidationError, match="aggregate status"):
        RunReport.model_validate(payload)

    payload = report.model_dump(mode="json")
    payload["coverage"]["required"] = 2
    with pytest.raises(ValidationError, match="coverage does not match"):
        RunReport.model_validate(payload)

    payload = report.model_dump(mode="json")
    payload["operation_log"][0]["sequence"] = 2
    with pytest.raises(ValidationError, match="contiguous"):
        RunReport.model_validate(payload)


def test_failed_report_bundle_is_complete_and_cannot_be_overwritten(
    tmp_path: Path,
) -> None:
    operation = OperationLogEntry(
        sequence=1,
        operation="readiness",
        started_at="2026-09-22T19:20:00Z",
        completed_at="2026-09-22T19:20:30Z",
        status="ERROR",
        argv=["curl", "http://127.0.0.1:18080/health"],
        cwd=None,
        exit_code=None,
        duration_seconds=30.0,
        stdout_path="stdout/readiness.log",
        stderr_path="stderr/readiness.log",
        timed_out=True,
        truncated=False,
    )
    report = build_report(
        run_id="run-failed",
        created_at="2026-09-22T19:20:00Z",
        operation="test",
        profile=PROFILE,
        runtime=RUNTIME,
        operation_log=[operation],
        partial_failure=PartialFailureMetadata(
            status="ERROR",
            operation_sequence=1,
            operation="readiness",
            cause_class="harness",
            message="readiness timed out",
            interrupted=False,
            cleanup_attempted=True,
            cleanup_status="WARN",
            preserved_artifacts=[
                "report.json",
                "report.md",
                "operation-log.jsonl",
            ],
        ),
        checks=[],
    )

    paths = write_report_bundle(report, tmp_path / report.run_id)

    assert report.overall == "ERROR"
    assert paths.operation_log.name == "operation-log.jsonl"
    log_lines = paths.operation_log.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in log_lines] == [
        operation.model_dump(mode="json")
    ]
    markdown = paths.markdown.read_text(encoding="utf-8")
    assert "## Partial failure" in markdown
    assert "- Operation sequence: `1`" in markdown
    with pytest.raises(FileExistsError):
        write_report_bundle(report, tmp_path / report.run_id)


def test_existing_empty_report_directory_is_not_replaced(tmp_path: Path) -> None:
    destination = tmp_path / "run-existing-empty"
    destination.mkdir()
    original = destination.stat()

    with pytest.raises(FileExistsError):
        write_report_bundle(_passing_report(destination.name), destination)

    current = destination.stat()
    assert (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
    assert list(destination.iterdir()) == []


def test_dangling_destination_symlink_is_not_replaced(tmp_path: Path) -> None:
    missing_target = tmp_path / "missing-target"
    destination = tmp_path / "run-dangling-symlink"
    destination.symlink_to(missing_target, target_is_directory=True)
    original = destination.lstat()

    with pytest.raises(FileExistsError):
        write_report_bundle(_passing_report(destination.name), destination)

    current = destination.lstat()
    assert (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
    assert destination.is_symlink()
    assert destination.readlink() == missing_target
    assert not missing_target.exists()


def test_report_directory_created_during_publication_is_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "run-race"
    original_publish = reports_module._publish_directory_noreplace
    raced_directory_stat = None

    def create_destination_at_publication(
        temporary: Path, requested_destination: Path
    ) -> None:
        nonlocal raced_directory_stat
        destination.mkdir()
        raced_directory_stat = destination.stat()
        original_publish(temporary, requested_destination)

    monkeypatch.setattr(
        reports_module,
        "_publish_directory_noreplace",
        create_destination_at_publication,
    )

    with pytest.raises(FileExistsError):
        write_report_bundle(_passing_report(destination.name), destination)

    assert raced_directory_stat is not None
    current = destination.stat()
    assert (current.st_dev, current.st_ino) == (
        raced_directory_stat.st_dev,
        raced_directory_stat.st_ino,
    )
    assert list(destination.iterdir()) == []
    assert list(tmp_path.glob(f".{destination.name}.*")) == []


def test_report_publication_fails_closed_without_renameat2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "run-no-renameat2"
    monkeypatch.setattr(reports_module, "_RENAMEAT2", None, raising=False)

    with pytest.raises(OSError) as raised:
        write_report_bundle(_passing_report(destination.name), destination)

    assert raised.value.errno == errno.ENOSYS
    assert not destination.exists()
    assert list(tmp_path.glob(f".{destination.name}.*")) == []


def _partial_failure_payload(
    operation_log: list[OperationLogEntry],
) -> dict[str, object]:
    report = build_report(
        run_id="run-partial-failure-validation",
        created_at="2026-09-22T19:30:00Z",
        operation="test",
        profile=PROFILE,
        runtime=RUNTIME,
        operation_log=operation_log,
        checks=[],
    )
    payload = report.model_dump(mode="json")
    payload["overall"] = "FAIL"
    payload["partial_failure"] = {
        "status": "FAIL",
        "operation_sequence": 1,
        "operation": "install",
        "cause_class": "package",
        "message": "install failed",
        "interrupted": False,
        "cleanup_attempted": False,
        "cleanup_status": None,
        "preserved_artifacts": [],
    }
    return payload


def _operation(
    sequence: int, operation: str, status: str = "FAIL"
) -> OperationLogEntry:
    return OperationLogEntry(
        sequence=sequence,
        operation=operation,
        started_at="2026-09-22T19:30:00Z",
        completed_at="2026-09-22T19:30:01Z",
        status=status,  # type: ignore[arg-type]
        argv=[operation],
        cwd=None,
        exit_code=1,
        duration_seconds=1.0,
        stdout_path=None,
        stderr_path=None,
        timed_out=False,
        truncated=False,
    )


def test_partial_failure_rejects_contradictory_operation_status() -> None:
    payload = _partial_failure_payload([_operation(1, "install", "ERROR")])

    with pytest.raises(ValidationError, match="partial failure status does not match"):
        RunReport.model_validate(payload)


def test_partial_failure_rejects_missing_operation_sequence() -> None:
    payload = _partial_failure_payload([_operation(1, "install")])
    payload["partial_failure"]["operation_sequence"] = 2  # type: ignore[index]

    with pytest.raises(
        ValidationError, match="partial failure operation sequence is absent"
    ):
        RunReport.model_validate(payload)


def test_partial_failure_rejects_wrong_operation_sequence() -> None:
    payload = _partial_failure_payload(
        [_operation(1, "install"), _operation(2, "cleanup")]
    )
    payload["partial_failure"]["operation_sequence"] = 2  # type: ignore[index]

    with pytest.raises(
        ValidationError, match="partial failure operation does not match"
    ):
        RunReport.model_validate(payload)
