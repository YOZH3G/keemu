"""Unsupported general targets use the common script contract, not a target probe."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.docker_runtime import DockerRuntime
from keemu.models import RunReport
from keemu.script_lifecycle import run_one_shot_script

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "fixtures/scripts/mvp1d/success.sh"


@pytest.mark.parametrize(
    ("profile", "target"),
    (("generic-mips", "mips-3.4"), ("generic-mipsel", "mipsel-3.4")),
)
def test_unsupported_general_target_reports_blocked_without_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, target: str
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("unsupported target attempted Docker lifecycle or script execution")

    monkeypatch.setattr(DockerRuntime, "create", forbidden)
    monkeypatch.setattr(DockerRuntime, "exec", forbidden)
    result = run_one_shot_script(
        SCRIPT,
        project_root=ROOT,
        profile_id=profile,
        argv=("literal;$(false)",),
        report_root=tmp_path,
    )
    report = result.report
    assert report == RunReport.model_validate_json(result.paths.json.read_text())
    assert report.overall == result.script.status == "BLOCKED"
    assert report.partial_failure is not None
    assert report.script is not None
    assert report.partial_failure.operation == "capability"
    assert report.partial_failure.message == "ScriptCapabilityUnavailable"
    assert report.script.execution.architecture == target
    assert report.script.execution.profile_id == profile
    assert report.script.execution.container_id is None
    assert report.script.execution.target_path is None
    assert report.script.outcome.state == "blocked"
    assert report.script.outcome.exit_code is None
    assert report.script.cleanup == ()
    assert "literal;$(false)" not in result.paths.json.read_text()

    response = CliRunner().invoke(
        cli,
        ["script", SCRIPT, "--profile", profile, "--repo", str(ROOT)],
    )
    assert response.exit_code == 4, response.output
    payload = json.loads(response.output)
    assert payload["overall"] == "BLOCKED"
    assert payload["script"]["execution"]["architecture"] == target
    assert payload["script"]["outcome"]["state"] == "blocked"


def test_unknown_profile_still_rejects_invalid_input(tmp_path: Path) -> None:
    response = CliRunner().invoke(
        cli,
        ["script", SCRIPT, "--profile", "generic-unknown", "--repo", str(ROOT)],
    )
    assert response.exit_code == 2
    assert "unsupported script profile" in response.output
    assert not list(tmp_path.iterdir())
