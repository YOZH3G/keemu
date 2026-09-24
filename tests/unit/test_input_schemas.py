from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from keemu.input_locks import (
    LockError,
    PersistentEnvironment,
    ScenarioLock,
    load_persistent_environment,
    load_scenario_lock,
)
from keemu.input_paths import UnsafePath, resolve_input_path
from keemu.profiles import ProfileError, load_profile, load_yaml_unique
from keemu.scenarios import Scenario, load_scenario

SCENARIO = """schema_version: 1
id: web-demo
profile: generic-aarch64
install:
  kind: ipk
  path: ../packages/web-demo.ipk
  package_name: web-demo
service:
  start: [/opt/etc/init.d/S80web-demo, start]
  stop: [/opt/etc/init.d/S80web-demo, stop]
  readiness:
    kind: http
    vantage: target_loopback
    url: http://127.0.0.1:8080/health
    expected_status: [200]
    body_contains: healthy
runtime:
  env: {}
  cwd: /opt
  settle_seconds: 2
  publish:
    - host_port: 18080
      target_port: 8080
      protocol: tcp
requirements:
  capabilities: []
  ndm_fixtures: []
checks:
  - id: health
    kind: http
    vantage: host_publish
    url: http://127.0.0.1:18080/health
    expected_status: [200]
    body_contains: healthy
persistence:
  paths: [/opt/etc/web-demo/config.json]
cleanup:
  allowed_residual_paths: [/opt/etc/web-demo/config.json]
"""
DIGEST = "a" * 64


def scenario_files(tmp_path: Path) -> Path:
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "packages").mkdir()
    (tmp_path / "packages/web-demo.ipk").write_bytes(b"fixture")
    source = tmp_path / "scenarios/web-demo.yaml"
    source.write_text(SCENARIO, encoding="utf-8")
    return source


def test_scenario_sample_and_strict_contract(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    scenario = load_scenario(path, project_root=tmp_path)
    assert scenario.runtime.publish[0].host_ip == "127.0.0.1"
    assert scenario.install.path == "../packages/web-demo.ipk"
    assert scenario.service is not None
    with pytest.raises(ValidationError):
        scenario.id = "changed"
    assert Scenario.model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize(
    "old,new",
    [
        ("schema_version: 1", "schema_version: true"),
        ("schema_version: 1", "schema_version: 2"),
        ("schema_version: 1", 'schema_version: "1"'),
        ("package_name: web-demo", "package_name: web-demo\n  unknown: true"),
        (
            "  publish:\n",
            (
                "  publish:\n"
                "    - host_port: 18080\n"
                "      target_port: 8080\n"
                "      protocol: tcp\n"
            ),
        ),
        ("      protocol: tcp", "      protocol: foo"),
        ("      target_port: 8080", "      target_port: 65536"),
        ("    - host_port: 18080", "    - host_port: 18081"),
        ("  capabilities: []", "  capabilities: [SYS_MODULE]"),
        ("  capabilities: []", "  capabilities: [NET_ADMIN, NET_ADMIN]"),
        ("    - host_port: 18080", "    - host_ip: 0.0.0.0\n      host_port: 18080"),
        ("    vantage: host_publish", "    vantage: client"),
        ("  paths: [/opt/etc/web-demo/config.json]", "  paths: [/etc/passwd]"),
        ("  paths: [/opt/etc/web-demo/config.json]", "  paths: [/opt/../etc/passwd]"),
        ("    expected_status: [200]", "    expected_status: [true]"),
        ("    body_contains: healthy", "    body_contains: ''"),
        ("  env: {}", "  env: {API_KEY: literal-secret}"),
    ],
)
def test_scenario_rejects_invalid_inputs(tmp_path: Path, old: str, new: str) -> None:
    path = scenario_files(tmp_path)
    path.write_text(SCENARIO.replace(old, new), encoding="utf-8")
    with pytest.raises((ValidationError, UnsafePath)):
        load_scenario(path, project_root=tmp_path)


def test_rejects_yaml_duplicate_and_alias(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    path.write_text(SCENARIO + "id: other\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="duplicate"):
        load_scenario(path, project_root=tmp_path)
    path.write_text(
        SCENARIO.replace("id: web-demo", "id: &alias web-demo").replace(
            "package_name: web-demo", "package_name: *alias"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="aliases"):
        load_scenario(path, project_root=tmp_path)


@pytest.mark.parametrize("loader", [load_yaml_unique, load_profile])
def test_yaml_path_loader_bounds_read_before_allocation(
    tmp_path: Path, monkeypatch, loader
) -> None:
    path = tmp_path / "oversized.yaml"
    path.write_bytes(b"x" * (1024 * 1024 + 1))

    def unbounded_read_forbidden(_path):
        raise AssertionError("Path.read_bytes performs an unbounded allocation")

    monkeypatch.setattr(Path, "read_bytes", unbounded_read_forbidden)
    with pytest.raises(ProfileError, match="exceeds 1 MiB"):
        loader(path)


def test_resolve_input_rejects_escape_symlink_and_missing(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    with pytest.raises(UnsafePath, match="escapes"):
        resolve_input_path(
            "../../outside.ipk", scenario_dir=path.parent, project_root=tmp_path
        )
    (tmp_path / "packages/web-demo.ipk").unlink()
    (tmp_path / "packages/web-demo.ipk").symlink_to("/etc/passwd")
    with pytest.raises(UnsafePath, match="symlink"):
        load_scenario(path, project_root=tmp_path)
    (tmp_path / "packages/web-demo.ipk").unlink()
    with pytest.raises(UnsafePath, match="missing"):
        load_scenario(path, project_root=tmp_path)
    path.rename(path.with_suffix(".old"))
    path.symlink_to(path.with_suffix(".old"))
    with pytest.raises(UnsafePath, match="symlink"):
        load_scenario(path, project_root=tmp_path)


def test_shell_is_explicit_and_argv_only(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    path.write_text(
        SCENARIO.replace(
            "start: [/opt/etc/init.d/S80web-demo, start]",
            "start: [sh, -c, 'echo not-reviewed']",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="explicit /bin/sh -c"):
        load_scenario(path, project_root=tmp_path)
    path.write_text(
        SCENARIO.replace(
            "start: [/opt/etc/init.d/S80web-demo, start]",
            "start: [/bin/sh, -c, 'echo reviewed']",
        ),
        encoding="utf-8",
    )
    assert load_scenario(path, project_root=tmp_path).service is not None


def test_https_requires_trust_file_even_in_readiness(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    path.write_text(
        SCENARIO.replace(
            "    kind: http\n    vantage: target_loopback",
            "    kind: https\n    ca_cert: ../packages/ca.pem\n"
            "    vantage: target_loopback",
        ).replace(
            "url: http://127.0.0.1:8080/health", "url: https://127.0.0.1:8080/health"
        ),
        encoding="utf-8",
    )
    with pytest.raises(UnsafePath, match="missing"):
        load_scenario(path, project_root=tmp_path)
    (tmp_path / "packages/ca.pem").write_text("test-only", encoding="utf-8")
    assert load_scenario(path, project_root=tmp_path).service is not None


def test_bounded_scenario_and_lock_inputs(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    path.write_text(SCENARIO + "#" * (1024 * 1024), encoding="utf-8")
    with pytest.raises(ProfileError, match="exceeds"):
        load_scenario(path, project_root=tmp_path)
    lock = path.with_name("lock.json")
    lock.write_text(json.dumps(lock_data()) + " " * (2 * 1024 * 1024), encoding="utf-8")
    with pytest.raises(LockError, match="exceeds"):
        load_scenario_lock(lock, project_root=tmp_path)


def test_pinned_installer_requires_explicit_contract(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    text = SCENARIO.replace(
        "  kind: ipk\n  path: ../packages/web-demo.ipk\n  package_name: web-demo",
        """  kind: pinned-installer
  path: ../packages/web-demo.ipk
  source_lock: bundle-a
  entrypoint: [/bin/sh, -c, 'exec /opt/install.sh']
  working_directory: /opt/install
  timeout_seconds: 300
  verify_install: {argv: [/opt/install/verify]}
  uninstall: {argv: [/opt/install/uninstall]}""",
    )
    path.write_text(text, encoding="utf-8")
    assert load_scenario(path, project_root=tmp_path).install.kind == "pinned-installer"
    path.write_text(
        text.replace("  uninstall: {argv: [/opt/install/uninstall]}\n", ""),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="uninstall"):
        load_scenario(path, project_root=tmp_path)


def lock_data() -> dict:
    return {
        "schema_version": 1,
        "kind": "scenario-lock",
        "scenario_id": "web-demo",
        "scenario_sha256": hashlib.sha256(SCENARIO.encode()).hexdigest(),
        "profile_id": "generic-aarch64",
        "profile_revision": 1,
        "profile_sha256": DIGEST,
        "entware_target": "aarch64-3.10",
        "oci_digest": "sha256:" + DIGEST,
        "qemu_version": "test-only",
        "feed_lock_sha256": DIGEST,
        "sources": [
            {
                "id": "web-demo",
                "kind": "ipk",
                "path": "../packages/web-demo.ipk",
                "sha256": hashlib.sha256(b"fixture").hexdigest(),
                "origin": "test-fixture",
                "release": "test-only",
                "architecture": "aarch64",
            }
        ],
    }


def test_pinned_lock_binds_exact_source_reference(tmp_path: Path) -> None:
    scenario_path = scenario_files(tmp_path)
    pinned = SCENARIO.replace(
        "  kind: ipk\n  path: ../packages/web-demo.ipk\n  package_name: web-demo",
        "  kind: pinned-installer\n  path: ../packages/web-demo.ipk\n"
        "  source_lock: bundle-a\n  entrypoint: [/opt/install.sh]\n"
        "  working_directory: /opt\n  timeout_seconds: 300\n"
        "  verify_install: {argv: [/opt/verify]}\n"
        "  uninstall: {argv: [/opt/uninstall]}",
    )
    scenario_path.write_text(pinned, encoding="utf-8")
    scenario = load_scenario(scenario_path, project_root=tmp_path)
    data = lock_data()
    data["scenario_sha256"] = hashlib.sha256(pinned.encode()).hexdigest()
    data["sources"][0].update(id="bundle-a", kind="pinned-bundle")
    path = scenario_path.with_name("lock.json")
    path.write_text(json.dumps(data), encoding="utf-8")
    assert (
        load_scenario_lock(
            path, project_root=tmp_path, scenario=scenario, scenario_path=scenario_path
        )
        .sources[0]
        .id
        == "bundle-a"
    )
    data["sources"][0]["id"] = "wrong"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(LockError, match="source reference mismatch"):
        load_scenario_lock(
            path, project_root=tmp_path, scenario=scenario, scenario_path=scenario_path
        )


def test_lock_strictness_identity_and_duplicate_keys(tmp_path: Path) -> None:
    scenario_path = scenario_files(tmp_path)
    scenario = load_scenario(scenario_path, project_root=tmp_path)
    path = tmp_path / "scenarios/lock.json"
    path.write_text(json.dumps(lock_data()), encoding="utf-8")
    assert (
        load_scenario_lock(
            path, project_root=tmp_path, scenario=scenario, scenario_path=scenario_path
        )
        .sources[0]
        .kind
        == "ipk"
    )
    for key, value in (
        ("schema_version", 2),
        ("profile_id", "other"),
        ("oci_digest", "latest"),
    ):
        data = lock_data()
        data[key] = value
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises((ValidationError, LockError)):
            load_scenario_lock(
                path,
                project_root=tmp_path,
                scenario=scenario,
                scenario_path=scenario_path,
            )
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(LockError, match="duplicate"):
        load_scenario_lock(path, project_root=tmp_path)
    path.write_text(
        json.dumps(lock_data()).replace(
            '"schema_version": 1', '"schema_version": true'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_scenario_lock(path, project_root=tmp_path)
    assert ScenarioLock.model_json_schema()["additionalProperties"] is False
    for field, value in (("release", "latest"), ("architecture", "mips")):
        bad = lock_data()
        bad["sources"][0][field] = value
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValidationError):
            load_scenario_lock(path, project_root=tmp_path)
    path.write_text(json.dumps(lock_data()), encoding="utf-8")
    (tmp_path / "packages/web-demo.ipk").write_bytes(b"changed")
    with pytest.raises(LockError, match="source hash mismatch"):
        load_scenario_lock(path, project_root=tmp_path)
    (tmp_path / "packages/web-demo.ipk").write_bytes(b"fixture")
    scenario_path.write_text(SCENARIO + "\n", encoding="utf-8")
    with pytest.raises(LockError, match="scenario hash mismatch"):
        load_scenario_lock(
            path, project_root=tmp_path, scenario=scenario, scenario_path=scenario_path
        )


def test_lock_rejects_missing_and_symlinked_artifacts(tmp_path: Path) -> None:
    path = scenario_files(tmp_path)
    lock = path.with_name("lock.json")
    lock.write_text(json.dumps(lock_data()), encoding="utf-8")
    (tmp_path / "packages/web-demo.ipk").unlink()
    with pytest.raises(UnsafePath):
        load_scenario_lock(lock, project_root=tmp_path)
    (tmp_path / "packages/web-demo.ipk").symlink_to("/etc/passwd")
    with pytest.raises(UnsafePath):
        load_scenario_lock(lock, project_root=tmp_path)


def test_committed_input_schemas_match_models() -> None:
    root = Path(__file__).resolve().parents[2] / "schemas"
    for filename, model in (
        ("scenario.schema.json", Scenario),
        ("scenario-lock.schema.json", ScenarioLock),
        ("persistent-environment.schema.json", PersistentEnvironment),
    ):
        assert json.loads((root / filename).read_text(encoding="utf-8")) == (
            model.model_json_schema()
        )


def environment_data() -> dict:
    return {
        "schema_version": 1,
        "kind": "persistent-environment",
        "name": "demo",
        "run_id": "run-01",
        "state": "running",
        "scenario_id": "web-demo",
        "scenario_sha256": DIGEST,
        "profile_id": "generic-aarch64",
        "profile_sha256": DIGEST,
        "lock_sha256": DIGEST,
        "oci_digest": "sha256:" + DIGEST,
        "resource": {
            "container_id": DIGEST,
            "owner_label": "keemu",
            "run_id_label": "run-01",
        },
    }


def test_environment_strict_state_and_ownership(tmp_path: Path) -> None:
    path = tmp_path / "environment.json"
    path.write_text(json.dumps(environment_data()), encoding="utf-8")
    assert load_persistent_environment(path, state_root=tmp_path).state == "running"
    for field, value in (
        ("state", "unknown"),
        ("schema_version", 2),
        ("name", "../foreign"),
        ("resource", None),
    ):
        data = copy.deepcopy(environment_data())
        data[field] = value
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValidationError):
            load_persistent_environment(path, state_root=tmp_path)
    data = environment_data()
    data["resource"]["run_id_label"] = "run-02"
    with pytest.raises(ValidationError, match="run ID"):
        PersistentEnvironment.model_validate(data)
