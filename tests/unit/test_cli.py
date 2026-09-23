from __future__ import annotations

import hashlib
import json
from pathlib import Path

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
