"""Atomic registry, concurrency, and replacement refusal without Docker."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu import persistent
from keemu.cli import cli
from keemu.docker_runtime import DockerBoundaryError
from keemu.input_locks import PersistentEnvironment, ResourceIdentity
from keemu.persistent import operate
from keemu.registry import Registry, RegistryError


def record(name: str, state: str = "creating") -> PersistentEnvironment:
    return PersistentEnvironment(
        schema_version=1,
        kind="persistent-environment",
        name=name,
        run_id="env-valid-run",
        state=state,
        scenario_id="fixture",
        scenario_sha256=hashlib.sha256(b"scenario").hexdigest(),
        profile_id="generic-aarch64",
        profile_sha256="a" * 64,
        lock_sha256="b" * 64,
        oci_digest="sha256:" + "c" * 64,
        resource=None,
    )


def test_atomic_state_transitions_and_tombstone(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry")
    with registry.locked("fixture") as entry:
        first = record("fixture")
        entry.create(first, b"scenario")
        assert entry.read() == first
        assert entry.scenario(first.scenario_sha256) == b"scenario"
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
        assert entry.read() == installing
        with pytest.raises(RegistryError, match="replaced or modified"):
            entry.update(first, installing)
        with pytest.raises(RegistryError, match="identity replacement"):
            entry.update(
                installing,
                installing.model_copy(update={"oci_digest": "sha256:" + "e" * 64}),
            )
        with pytest.raises(RegistryError, match="state transition"):
            entry.update(installing, installing.model_copy(update={"state": "running"}))
        with pytest.raises(RegistryError, match="identity replacement"):
            entry.update(
                installing, installing.model_copy(update={"scenario_id": "other"})
            )
        with pytest.raises(RegistryError, match="already exists"):
            entry.create(first, b"scenario")


def test_name_lock_serializes_only_same_name(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry")
    with registry.locked("first"):
        with pytest.raises(RegistryError, match="busy"):
            with registry.locked("first"):
                pytest.fail("concurrent same-name lock admitted")
        with registry.locked("second") as other:
            other.create(record("second"), b"scenario")
    with registry.locked("first") as entry:
        entry.create(record("first"), b"scenario")


def test_lock_contends_across_processes_but_not_names(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry")
    probe = (
        "import sys; from pathlib import Path; "
        "from keemu.registry import Registry, RegistryError; "
        "r=Registry(Path(sys.argv[1])); "
        "\ntry:\n with r.locked(sys.argv[2]): print('acquired')"
        "\nexcept RegistryError: print('busy')"
    )
    with registry.locked("first"):
        for name, expected in (("first", "busy"), ("second", "acquired")):
            result = subprocess.run(  # noqa: S603 -- fixed Python probe
                [sys.executable, "-c", probe, str(registry.root), name],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            assert result.stdout.strip() == expected


def test_symlink_lock_and_replaced_state_are_rejected(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry")
    with registry.locked("safe") as entry:
        entry.create(record("safe"), b"scenario")
        state = entry.directory / "environment.json"
        state.unlink()
        state.symlink_to(tmp_path / "victim")
        with pytest.raises(OSError):
            entry.read()
    (tmp_path / "registry/locks/evil.lock").symlink_to(tmp_path / "victim")
    with pytest.raises(OSError):
        with registry.locked("evil"):
            pytest.fail("symlink lock admitted")
    assert not (tmp_path / "victim").exists()


def test_modified_snapshot_and_partial_directory_fail_closed(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry")
    with registry.locked("safe") as entry:
        first = record("safe")
        entry.create(first, b"scenario")
        (entry.directory / "scenario.yaml").write_bytes(b"changed")
        with pytest.raises(RegistryError, match="replaced or modified"):
            entry.scenario(first.scenario_sha256)
        state = entry.directory / "environment.json"
        replacement = entry.directory / "replacement"
        replacement.write_bytes(state.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(state)
        with pytest.raises(RegistryError, match="replaced or modified"):
            entry.update(first, first.model_copy(update={"state": "failed"}))
        state.write_text(json.dumps(first.model_dump(mode="json")))
        with pytest.raises(RegistryError, match="replaced or modified"):
            entry.update(first, first.model_copy(update={"state": "failed"}))
    (tmp_path / "registry/incomplete").mkdir(mode=0o700)
    with registry.locked("incomplete") as entry:
        with pytest.raises(RegistryError, match="already exists"):
            entry.create(record("incomplete"), b"scenario")


def test_foreign_docker_identity_refuses_lifecycle_and_cli_error(tmp_path, monkeypatch):
    registry = Registry(tmp_path / ".runtime/registry")
    with registry.locked("fixture") as entry:
        initial = record("fixture")
        entry.create(initial, b"scenario")
        installing = initial.model_copy(
            update={
                "state": "installing",
                "resource": ResourceIdentity(
                    container_id="d" * 64,
                    owner_label="keemu",
                    run_id_label=initial.run_id,
                ),
            }
        )
        entry.update(initial, installing)
        entry.update(installing, installing.model_copy(update={"state": "stopped"}))

    class ForeignDocker:
        def __init__(self, *_args, **_kwargs):
            pass

        def inspect(self, *_args):
            raise DockerBoundaryError("container ownership labels mismatch")

        def start(self, *_args):
            pytest.fail("foreign container started")

        def remove_container(self, *_args):
            pytest.fail("foreign container removed")

    monkeypatch.setattr("keemu.persistent.DockerRuntime", ForeignDocker)
    with pytest.raises(DockerBoundaryError, match="ownership"):
        operate(tmp_path, "fixture", "up")
    result = CliRunner().invoke(
        cli, ["up", "--name", "fixture", "--repo", str(tmp_path)]
    )
    assert result.exit_code == 3
    assert "ownership labels mismatch" in result.output
    with registry.locked("fixture") as entry:
        assert entry.read().state == "stopped"


def test_cli_requires_identity_and_lock_pair(tmp_path):
    for args in (
        ["status", "../foreign", "--repo", str(tmp_path)],
        ["up", "--name", "fixture", "--scenario", "x", "--repo", str(tmp_path)],
    ):
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 2


def test_prepare_uses_secure_scenario_snapshot_after_path_replacement(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path
    scenario_path = root / "scenario.yaml"
    lock_path = root / "scenario.lock.json"
    package_path = root / "package.ipk"
    profile_path = root / "profiles/generic/generic-aarch64.yaml"
    feed_path = root / "locks/p0-aarch64.json"
    base_path = root / persistent.BASE_LOCK
    profile_path.parent.mkdir(parents=True)
    feed_path.parent.mkdir(parents=True)
    base_path.parent.mkdir(parents=True, exist_ok=True)
    (root / ".runtime").mkdir()

    scenario = {
        "schema_version": 1,
        "id": "fixture",
        "profile": "generic-aarch64",
        "install": {
            "kind": "ipk",
            "path": "package.ipk",
            "package_name": "fixture",
        },
        "service": None,
        "runtime": {"env": {}, "cwd": "/opt", "settle_seconds": 0, "publish": []},
        "requirements": {"capabilities": [], "ndm_fixtures": []},
        "checks": [
            {
                "id": "installed",
                "kind": "file",
                "path": "/opt/bin/fixture",
                "exists": True,
            }
        ],
        "persistence": {"paths": []},
        "cleanup": {"allowed_residual_paths": []},
    }
    malicious = dict(scenario)
    malicious["service"] = {
        "start": ["/bin/sh", "-c", "echo malicious"],
        "stop": ["/bin/sh", "-c", "true"],
        "readiness": {
            "kind": "http",
            "vantage": "target_loopback",
            "url": "http://127.0.0.1:8080/health",
            "expected_status": [200],
            "body_contains": "ok",
            "timeout_seconds": 5,
        },
    }
    secure_scenario = (json.dumps(scenario) + "\n").encode()
    scenario_path.write_text(json.dumps(malicious), encoding="utf-8")

    profile = {
        "schema_version": 1,
        "id": "generic-aarch64",
        "revision": 1,
        "kind": "generic",
        "entware_target": "aarch64-3.10",
        "cpu": {
            "arch": "aarch64",
            "endian": "little",
            "elf_class": 64,
            "qemu": "qemu-aarch64",
        },
        "kernel": {"execution": "host", "reported_release": None},
        "filesystem": {"entware_root": "/opt"},
        "ndm": {"mode": "strict", "fixtures": []},
        "network": {"logical_to_linux": {}},
    }
    profile_blob = (json.dumps(profile) + "\n").encode()
    profile_path.write_bytes(profile_blob)
    package_path.write_bytes(b"fixture-package")
    feed_path.write_text("{}\n", encoding="utf-8")
    feed_hash = hashlib.sha256(feed_path.read_bytes()).hexdigest()
    image_id = "sha256:" + "c" * 64
    base_path.write_text(
        json.dumps(
            {
                "oci_digest": image_id,
                "input_lock_sha256": feed_hash,
                "target": "aarch64-3.10",
                "cache_key": "fixture",
            }
        ),
        encoding="utf-8",
    )
    lock_data = {
        "schema_version": 1,
        "kind": "scenario-lock",
        "scenario_id": "fixture",
        "scenario_sha256": hashlib.sha256(secure_scenario).hexdigest(),
        "profile_id": "generic-aarch64",
        "profile_revision": 1,
        "profile_sha256": hashlib.sha256(profile_blob).hexdigest(),
        "entware_target": "aarch64-3.10",
        "oci_digest": image_id,
        "qemu_version": "fixture",
        "feed_lock_sha256": feed_hash,
        "sources": [
            {
                "id": "fixture",
                "kind": "ipk",
                "path": "package.ipk",
                "sha256": hashlib.sha256(package_path.read_bytes()).hexdigest(),
                "origin": "fixture",
                "release": "1.0",
                "architecture": "aarch64",
            }
        ],
    }
    lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

    real_lock_loader = persistent.load_scenario_lock

    def replace_before_lock(*args, **kwargs):
        scenario_path.write_bytes(secure_scenario)
        return real_lock_loader(*args, **kwargs)

    monkeypatch.setattr(persistent, "load_scenario_lock", replace_before_lock)
    monkeypatch.setattr(
        persistent,
        "inspect_ipk",
        lambda *_args, **_kwargs: type(
            "Inspection",
            (),
            {"metadata": {"Package": "fixture", "Version": "1.0"}, "status": "PASS"},
        )(),
    )
    monkeypatch.setattr(
        persistent,
        "init_locked",
        lambda *_args, **_kwargs: {"oci_digest": image_id},
    )
    monkeypatch.setattr(persistent.DockerRuntime, "image", lambda _self: {})

    with pytest.raises(
        persistent.PersistentError, match="scenario/profile/lock changed"
    ):
        persistent._prepare(root, scenario_path, lock_path)


def test_status_marks_transitional_registry_state_inconsistent(
    tmp_path: Path, monkeypatch
) -> None:
    registry = Registry(tmp_path / ".runtime/registry")
    with registry.locked("fixture") as entry:
        creating = record("fixture")
        entry.create(creating, b"scenario")
        installing = creating.model_copy(
            update={
                "state": "installing",
                "resource": ResourceIdentity(
                    container_id="d" * 64,
                    owner_label="keemu",
                    run_id_label=creating.run_id,
                ),
            }
        )
        entry.update(creating, installing)
        stopped = installing.model_copy(update={"state": "stopped"})
        entry.update(installing, stopped)
        starting = stopped.model_copy(update={"state": "starting"})
        entry.update(stopped, starting)

    class Runtime:
        def inspect(self, *_args):
            return {"State": {"Running": False}}

    monkeypatch.setattr(persistent, "_runtime", lambda _record: (Runtime(), "d" * 64))

    assert operate(tmp_path, "fixture", "status")["consistent"] is False


def test_status_reports_creating_without_container_as_inconsistent(
    tmp_path: Path, monkeypatch
) -> None:
    registry = Registry(tmp_path / ".runtime/registry")
    with registry.locked("fixture") as entry:
        entry.create(record("fixture"), b"scenario")

    reconciliation = {
        "container_owned": [],
        "container_missing": [],
        "container_unexpected": [],
        "network_owned": [],
        "network_unexpected": [],
    }

    class Runtime:
        def __init__(self, *_args, **_kwargs):
            pass

        def reconcile(self):
            return reconciliation

    monkeypatch.setattr(persistent, "DockerRuntime", Runtime)

    status = operate(tmp_path, "fixture", "status")

    assert status["docker_running"] is None
    assert status["consistent"] is False
    assert status["reconciliation"] == reconciliation


def test_registry_rejects_symlinked_runtime_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".runtime").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        with Registry(tmp_path / ".runtime/registry").locked("fixture"):
            pytest.fail("symlinked registry ancestor admitted")

    assert not (outside / "registry").exists()


@pytest.mark.parametrize("cache_key", ["../outside", "/absolute", "not-a-digest"])
def test_locked_rootfs_rejects_untrusted_cache_key(
    tmp_path: Path, cache_key: str
) -> None:
    with pytest.raises(persistent.PersistentError, match="cache key"):
        persistent._locked_rootfs(tmp_path, {"cache_key": cache_key})
