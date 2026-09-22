from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from keemu.models import CheckResult, Coverage, RunReport, Status

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


def exit_code_for_status(status: Status) -> int:
    """Map a completed report status to the documented process exit code."""
    return {"FAIL": 1, "ERROR": 3, "BLOCKED": 4}.get(status, 0)


def _coverage(checks: Sequence[CheckResult]) -> Coverage:
    required_checks = [check for check in checks if check.required]
    return Coverage(
        required=len(required_checks),
        passed=sum(check.status == "PASS" for check in required_checks),
        failed=sum(check.status == "FAIL" for check in required_checks),
        blocked=sum(
            check.status in {"BLOCKED", "SKIP"} for check in required_checks
        ),
        skipped=sum(check.status == "SKIP" for check in required_checks),
        warned=sum(check.status == "WARN" for check in required_checks),
        errors=sum(check.status == "ERROR" for check in required_checks),
    )


def _overall(checks: Sequence[CheckResult]) -> Status:
    required = [check for check in checks if check.required]
    if not required:
        return "BLOCKED"
    effective = [
        "BLOCKED" if check.status == "SKIP" else check.status
        for check in required
    ]
    for status in ("ERROR", "FAIL", "BLOCKED", "WARN"):
        if status in effective:
            return status  # type: ignore[return-value]
    if not any(status == "PASS" for status in effective):
        return "BLOCKED"
    return "PASS"


def build_report(
    *,
    run_id: str,
    created_at: str,
    operation: str,
    profile_id: str,
    checks: Sequence[CheckResult],
    limitations: Sequence[str] = (),
) -> RunReport:
    materialized = list(checks)
    return RunReport(
        schema_version=1,
        run_id=run_id,
        created_at=created_at,
        operation=operation,
        profile_id=profile_id,
        overall=_overall(materialized),
        coverage=_coverage(materialized),
        checks=materialized,
        limitations=list(limitations),
    )


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def render_markdown(report: RunReport) -> str:
    lines = [
        f"# KEEMU {report.operation} report",
        "",
        f"Run: `{report.run_id}`",
        f"Created: `{report.created_at}`",
        f"Profile: `{report.profile_id}`",
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


def write_report_bundle(report: RunReport, directory: Path) -> ReportPaths:
    json_path = directory / "report.json"
    markdown_path = directory / "report.md"
    payload = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True
    ) + "\n"
    _atomic_write_text(json_path, payload)
    _atomic_write_text(markdown_path, render_markdown(report))
    return ReportPaths(json=json_path, markdown=markdown_path)
