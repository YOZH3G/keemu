from __future__ import annotations

import ctypes
import errno
import json
import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from keemu.models import (
    ArtifactMetadata,
    CapabilityResult,
    CheckResult,
    Coverage,
    OperationLogEntry,
    PartialFailureMetadata,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
    ScenarioMetadata,
    Status,
    SubstitutionMetadata,
    aggregate_status,
    coverage_for,
)

_AT_FDCWD = -100
_RENAME_NOREPLACE = 1
_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int

__all__ = [
    "CheckResult",
    "Coverage",
    "ReportPaths",
    "RunReport",
    "build_report",
    "render_markdown",
    "write_report_bundle",
]


@dataclass(frozen=True, slots=True)
class ReportPaths:
    json: Path
    markdown: Path
    operation_log: Path


def exit_code_for_status(status: Status) -> int:
    """Map a completed report status to the documented process exit code."""
    return {"FAIL": 1, "ERROR": 3, "BLOCKED": 4}.get(status, 0)


def build_report(
    *,
    run_id: str,
    created_at: str,
    operation: str,
    profile: ProfileMetadata,
    runtime: RuntimeMetadata,
    checks: Sequence[CheckResult],
    artifact: ArtifactMetadata | None = None,
    scenario: ScenarioMetadata | None = None,
    capabilities: Sequence[CapabilityResult] = (),
    substitutions: Sequence[SubstitutionMetadata] = (),
    operation_log: Sequence[OperationLogEntry] = (),
    partial_failure: PartialFailureMetadata | None = None,
    limitations: Sequence[str] = (),
) -> RunReport:
    materialized = list(checks)
    return RunReport(
        schema_version=2,
        run_id=run_id,
        created_at=created_at,
        operation=operation,
        artifact=artifact,
        scenario=scenario,
        profile=profile,
        runtime=runtime,
        capabilities=tuple(capabilities),
        substitutions=tuple(substitutions),
        overall=aggregate_status(materialized, partial_failure),
        coverage=coverage_for(materialized),
        operation_log=tuple(operation_log),
        partial_failure=partial_failure,
        checks=tuple(materialized),
        limitations=tuple(limitations),
    )


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def render_markdown(report: RunReport) -> str:
    lines = [
        f"# KEEMU {report.operation} report",
        "",
        f"Run: `{report.run_id}`",
        f"Created: `{report.created_at}`",
        f"Profile: `{report.profile.id}` revision {report.profile.revision}",
        f"Overall: **{report.overall}**",
        "",
        "## Coverage",
        "",
        "| Required | Passed | Failed | Blocked | Skipped | Warned | Errors |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {report.coverage.required} | {report.coverage.passed} | "
            f"{report.coverage.failed} | {report.coverage.blocked} | "
            f"{report.coverage.skipped} | {report.coverage.warned} | "
            f"{report.coverage.errors} |"
        ),
        "",
        "## Checks",
        "",
        "| ID | Status | Mode | Requirement | Evidence |",
        "|---|---|---|---|---|",
    ]
    for check in report.checks:
        evidence = _markdown_cell("; ".join(check.evidence))
        requirement = "required" if check.required else "optional"
        lines.append(
            f"| {_markdown_cell(check.id)} | {check.status} | {check.mode} | "
            f"{requirement} | {evidence} |"
        )
    if report.partial_failure is not None:
        failure = report.partial_failure
        lines.extend(
            (
                "",
                "## Partial failure",
                "",
                f"- Status: **{failure.status}**",
                f"- Operation sequence: `{failure.operation_sequence}`",
                f"- Operation: `{failure.operation}`",
                f"- Cause: `{failure.cause_class}`",
                f"- Message: {_markdown_cell(failure.message)}",
                f"- Cleanup attempted: `{str(failure.cleanup_attempted).lower()}`",
                f"- Cleanup status: `{failure.cleanup_status or 'not-run'}`",
            )
        )
    if report.limitations:
        lines.extend(("", "## Limitations", ""))
        lines.extend(f"- {limitation}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        stream.write(content)
        temporary = Path(stream.name)
    temporary.replace(path)


def _publish_directory_noreplace(temporary: Path, directory: Path) -> None:
    if _RENAMEAT2 is None:
        raise OSError(
            errno.ENOSYS,
            "atomic no-replace directory publication is unavailable",
            directory,
        )

    ctypes.set_errno(0)
    result = _RENAMEAT2(
        _AT_FDCWD,
        os.fsencode(temporary),
        _AT_FDCWD,
        os.fsencode(directory),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return

    error = ctypes.get_errno() or errno.EIO
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), directory)
    raise OSError(error, os.strerror(error), directory)


def write_report_bundle(report: RunReport, directory: Path) -> ReportPaths:
    directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{directory.name}.", dir=directory.parent)
    )
    payload = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True
    ) + "\n"
    operation_log = "".join(
        json.dumps(entry.model_dump(mode="json"), sort_keys=True) + "\n"
        for entry in report.operation_log
    )
    try:
        _atomic_write_text(temporary / "report.json", payload)
        _atomic_write_text(temporary / "report.md", render_markdown(report))
        _atomic_write_text(temporary / "operation-log.jsonl", operation_log)
        _publish_directory_noreplace(temporary, directory)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return ReportPaths(
        json=directory / "report.json",
        markdown=directory / "report.md",
        operation_log=directory / "operation-log.jsonl",
    )
