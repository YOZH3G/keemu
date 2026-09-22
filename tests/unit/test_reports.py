from __future__ import annotations

import json
from pathlib import Path

from keemu.models import RunReport
from keemu.profiles import GenericProfile
from keemu.reports import (
    CheckResult,
    build_report,
    exit_code_for_status,
    write_report_bundle,
)


def test_required_skip_aggregates_to_blocked_with_coverage() -> None:
    report = build_report(
        run_id="run-123",
        created_at="2026-09-22T08:00:00Z",
        operation="doctor",
        profile_id="generic-aarch64",
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
        profile_id="generic-aarch64",
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

    paths = write_report_bundle(report, tmp_path)

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
