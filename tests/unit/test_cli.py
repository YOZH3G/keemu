from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.models import RunReport


def test_p0_verify_lock_reports_verified_artifacts(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    payload = b"locked package"
    (cache / "fixture.ipk").write_bytes(payload)
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "entware-rootfs-lock",
                "target": "aarch64-3.10",
                "packages": [
                    {
                        "filename": "fixture.ipk",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["p0", "verify-lock", "--lock", str(lock), "--cache", str(cache)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "artifact_count": 1,
        "status": "verified",
        "target": "aarch64-3.10",
    }


def test_p0_verify_fixture_lock_reports_locked_sources() -> None:
    repo = Path(__file__).resolve().parents[2]
    result = CliRunner().invoke(
        cli,
        [
            "p0",
            "verify-fixture-lock",
            "--lock",
            str(repo / "locks" / "p0-fixtures-aarch64.json"),
            "--root",
            str(repo),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "fixture_count": 3,
        "fixtures": ["hello", "web-demo", "nfqueue-consumer"],
        "status": "verified",
    }


def test_doctor_returns_blocked_exit_code_and_json(tmp_path: Path) -> None:
    empty_path = tmp_path / "bin"
    empty_path.mkdir()
    binfmt = tmp_path / "binfmt_misc"
    binfmt.mkdir()
    profiles = Path(__file__).resolve().parents[2] / "profiles" / "generic"

    result = CliRunner().invoke(
        cli,
        [
            "doctor",
            "--profile",
            "generic-aarch64",
            "--profiles-dir",
            str(profiles),
            "--docker-socket",
            str(tmp_path / "docker.sock"),
            "--binfmt-root",
            str(binfmt),
            "--search-path",
            str(empty_path),
        ],
    )

    assert result.exit_code == 4, result.output
    payload = json.loads(result.output)
    report = RunReport.model_validate(payload)
    assert payload["schema_version"] == 2
    assert payload["overall"] == "BLOCKED"
    assert payload["profile"]["id"] == "generic-aarch64"
    assert report.coverage.blocked >= 4
    docker_daemon = next(
        check for check in report.checks if check.id == "docker-daemon"
    )
    assert docker_daemon.status == "BLOCKED"
    assert docker_daemon.mode == "real"
    assert str(tmp_path / "docker.sock") in docker_daemon.evidence[0]


def test_doctor_rejects_invalid_profile_id_with_input_exit_code() -> None:
    result = CliRunner().invoke(cli, ["doctor", "--profile", "invalid!"])

    assert result.exit_code == 2
    assert "invalid profile ID" in result.output


@pytest.mark.parametrize(
    ("status", "exit_code"),
    (("PASS", 0), ("FAIL", 1), ("BLOCKED", 4), ("ERROR", 3)),
)
def test_script_forwards_contract_and_maps_report_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, exit_code: int
) -> None:
    captured: dict[str, object] = {}

    def fake_run(script: Path, **kwargs: object) -> SimpleNamespace:
        captured["script"] = script
        captured.update(kwargs)
        return SimpleNamespace(
            report=SimpleNamespace(
                overall=status,
                model_dump=lambda **_: {"overall": status, "schema_version": 2},
            )
        )

    monkeypatch.setattr("keemu.cli.run_one_shot_script", fake_run)
    result = CliRunner().invoke(
        cli,
        [
            "script",
            "fixtures/scripts/mvp1d/argv.sh",
            "--profile",
            "generic-aarch64",
            "--timeout",
            "120",
            "--cwd",
            "/opt/etc",
            "--expect-exit-code",
            "7",
            "--repo",
            str(tmp_path),
            "--",
            "literal;$(false)",
            "two words",
        ],
    )

    assert result.exit_code == exit_code, result.output
    assert json.loads(result.output) == {"overall": status, "schema_version": 2}
    assert captured == {
        "script": Path("fixtures/scripts/mvp1d/argv.sh"),
        "project_root": tmp_path,
        "profile_id": "generic-aarch64",
        "argv": ("literal;$(false)", "two words"),
        "cwd": "/opt/etc",
        "timeout_seconds": 120,
        "expected_exit_code": 7,
    }


def test_script_uses_frozen_defaults_and_rejects_invalid_cli_numbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(script: Path, **kwargs: object) -> SimpleNamespace:
        captured["script"] = script
        captured.update(kwargs)
        return SimpleNamespace(
            report=SimpleNamespace(
                overall="PASS",
                model_dump=lambda **_: {"overall": "PASS", "schema_version": 2},
            )
        )

    monkeypatch.setattr("keemu.cli.run_one_shot_script", fake_run)
    base = [
        "script",
        "fixtures/scripts/mvp1d/success.sh",
        "--profile",
        "generic-aarch64",
        "--repo",
        str(tmp_path),
    ]
    result = CliRunner().invoke(cli, base)

    assert result.exit_code == 0, result.output
    assert captured["argv"] == ()
    assert captured["cwd"] == "/opt"
    assert captured["timeout_seconds"] == 60
    assert captured["expected_exit_code"] == 0

    for option, value in (("--timeout", "0"), ("--expect-exit-code", "256")):
        invalid = CliRunner().invoke(cli, [*base, option, value])
        assert invalid.exit_code == 2
        assert "Invalid value" in invalid.output


def test_script_maps_common_input_contract_failure_to_exit_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise ValueError("invalid script arguments")

    monkeypatch.setattr("keemu.cli.run_one_shot_script", reject)
    result = CliRunner().invoke(
        cli,
        [
            "script",
            "fixtures/scripts/mvp1d/success.sh",
            "--profile",
            "generic-aarch64",
            "--repo",
            str(tmp_path),
            "--",
            "arg",
        ],
    )

    assert result.exit_code == 2
    assert "invalid script arguments" in result.output
