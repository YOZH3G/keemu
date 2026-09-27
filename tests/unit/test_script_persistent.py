"""Persistent script CLI and registry refusal without Docker mutations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.input_locks import PersistentEnvironment, ResourceIdentity
from keemu.registry import Registry, RegistryError
from keemu.script_persistent import run_persistent_script


def _record(name: str) -> PersistentEnvironment:
    return PersistentEnvironment(
        schema_version=1,
        kind="persistent-environment",
        name=name,
        run_id="env-persistent-test",
        state="creating",
        scenario_id="fixture",
        scenario_sha256=hashlib.sha256(b"scenario").hexdigest(),
        profile_id="generic-aarch64",
        profile_sha256="a" * 64,
        lock_sha256="b" * 64,
        oci_digest="sha256:" + "c" * 64,
        resource=None,
    )


@pytest.mark.parametrize(
    ("status", "code"),
    (("PASS", 0), ("FAIL", 1), ("BLOCKED", 4), ("ERROR", 3)),
)
def test_exec_script_cli_forwards_literal_argv_and_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, code: int
) -> None:
    seen: dict[str, object] = {}

    def run(name: str, script: Path, **kwargs: object) -> SimpleNamespace:
        seen.update(name=name, script=script, **kwargs)
        return SimpleNamespace(
            report=SimpleNamespace(
                overall=status,
                model_dump=lambda **_: {"overall": status},
            )
        )

    monkeypatch.setattr("keemu.cli.run_persistent_script", run)
    result = CliRunner().invoke(
        cli,
        [
            "exec",
            "fixture",
            "--script",
            "fixtures/scripts/mvp1d/argv.sh",
            "--repo",
            str(tmp_path),
            "--timeout",
            "3",
            "--cwd",
            "/opt/etc",
            "--expect-exit-code",
            "7",
            "--",
            "a;$(false)",
            "two words",
        ],
    )
    assert result.exit_code == code, result.output
    assert json.loads(result.output) == {"overall": status}
    assert seen == {
        "name": "fixture",
        "script": Path("fixtures/scripts/mvp1d/argv.sh"),
        "project_root": tmp_path,
        "argv": ("a;$(false)", "two words"),
        "cwd": "/opt/etc",
        "timeout_seconds": 3,
        "expected_exit_code": 7,
    }


def test_exec_original_argv_and_script_only_options(
    tmp_path: Path, monkeypatch
) -> None:
    seen = []

    def operate(root, name, action, *, argv):
        seen.append((root, name, action, argv))
        return {"exit_code": 0}

    monkeypatch.setattr("keemu.cli.operate", operate)
    legacy = CliRunner().invoke(
        cli, ["exec", "fixture", "--repo", str(tmp_path), "--", "/bin/true"]
    )
    assert legacy.exit_code == 0
    assert seen == [(tmp_path, "fixture", "exec", ("/bin/true",))]
    invalid = CliRunner().invoke(
        cli, ["exec", "fixture", "--timeout", "1", "--", "/bin/true"]
    )
    assert invalid.exit_code == 2
    assert len(seen) == 1


def test_running_gate_and_registry_inode_replace_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "input.sh"
    script.write_bytes(b"exit 0\n")
    registry = Registry(tmp_path / ".runtime/registry")
    with registry.locked("fixture") as entry:
        first = _record("fixture")
        entry.create(first, b"scenario")

    def no_docker(*_args, **_kwargs):
        pytest.fail("Docker accessed before running registry gate")

    monkeypatch.setattr("keemu.script_persistent._runtime", no_docker)
    with pytest.raises(RegistryError, match="running environment"):
        run_persistent_script("fixture", script, project_root=tmp_path)
    with registry.locked("fixture") as entry:
        current = entry.read()
        path = entry.directory / "environment.json"
        replacement = entry.directory / "replacement"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)
        with pytest.raises(RegistryError, match="replaced or modified"):
            entry.verify_unchanged(current)


def test_foreign_resource_refused_without_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "input.sh"
    script.write_bytes(b"exit 0\n")
    registry = Registry(tmp_path / ".runtime/registry")
    with registry.locked("fixture") as entry:
        first = _record("fixture")
        entry.create(first, b"scenario")
        installing = first.model_copy(
            update={
                "state": "installing",
                "resource": ResourceIdentity(
                    container_id="d" * 64,
                    owner_label="keemu",
                    run_id_label=first.run_id,
                ),
            }
        )
        entry.update(first, installing)
        stopped = installing.model_copy(update={"state": "stopped"})
        entry.update(installing, stopped)
        starting = stopped.model_copy(update={"state": "starting"})
        entry.update(stopped, starting)
        entry.update(starting, starting.model_copy(update={"state": "running"}))

    def foreign(_record):
        raise RegistryError("foreign container identity")

    monkeypatch.setattr("keemu.script_persistent._runtime", foreign)
    with pytest.raises(RegistryError, match="foreign"):
        run_persistent_script("fixture", script, project_root=tmp_path)
    with registry.locked("fixture") as entry:
        assert entry.read().state == "running"


def test_invalid_argv_and_cwd_are_redacted_before_docker(tmp_path: Path) -> None:
    script = tmp_path / "input.sh"
    script.write_bytes(b"exit 0\n")
    secret = "sensitive-argument" * 300
    result = CliRunner().invoke(
        cli,
        [
            "exec",
            "fixture",
            "--script",
            "input.sh",
            "--repo",
            str(tmp_path),
            "--",
            secret,
        ],
    )
    assert result.exit_code == 2
    assert "invalid script arguments" in result.output
    assert secret not in result.output
    with pytest.raises(ValueError, match="invalid target working directory"):
        run_persistent_script(
            "fixture", script, project_root=tmp_path, cwd="/opt/../etc"
        )
