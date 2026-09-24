"""Bounded persistent AArch64 lifecycle; registry is not Docker authority."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from keemu.docker_runtime import DockerRuntime, Output
from keemu.init_cache import init_locked
from keemu.input_locks import (
    PersistentEnvironment,
    ResourceIdentity,
    _reject_constant,
    _unique_object,
    load_scenario_lock,
)
from keemu.input_paths import resolve_input_path, safe_name
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.lifecycle import BASE_LOCK, StageFailure, _probe, _retry_probe, _secure_bytes
from keemu.profiles import load_profile_bytes
from keemu.registry import Entry, Registry, RegistryError
from keemu.scenarios import IPKInstall, Scenario, load_scenario_bytes


class PersistentError(RuntimeError):
    """Persistent operation refused or target operation failed."""


CACHE_KEY = re.compile(r"[0-9a-f]{64}\Z")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _locked_rootfs(root: Path, base: dict) -> Path:
    key = base.get("cache_key")
    if not isinstance(key, str) or not CACHE_KEY.fullmatch(key):
        raise PersistentError("invalid locked cache key")
    project = root.resolve()
    cache_root = (root / ".runtime/init-cache").resolve(strict=False)
    rootfs = (cache_root / key / "rootfs").resolve(strict=False)
    if not cache_root.is_relative_to(project) or not rootfs.is_relative_to(cache_root):
        raise PersistentError("locked cache key escapes project cache")
    return rootfs


@dataclass(frozen=True)
class Prepared:
    scenario: Scenario
    scenario_blob: bytes
    lock_blob: bytes
    profile_blob: bytes
    package: bytes
    package_hash: str
    package_version: str
    image_id: str


def _prepare(root: Path, scenario_path: Path, lock_path: Path) -> Prepared:
    scenario_blob = _secure_bytes(scenario_path, root, 1024 * 1024)
    lock_blob = _secure_bytes(lock_path, root, 2 * 1024 * 1024)
    scenario = load_scenario_bytes(
        scenario_blob, scenario_dir=scenario_path.parent, project_root=root
    )
    lock = load_scenario_lock(
        lock_path, project_root=root, scenario=scenario, scenario_path=scenario_path
    )
    profile_path = root / "profiles/generic" / f"{scenario.profile}.yaml"
    profile_blob = _secure_bytes(profile_path, root, 1024 * 1024)
    profile = load_profile_bytes(profile_blob)
    if (
        _hash(scenario_blob) != lock.scenario_sha256
        or json.loads(
            lock_blob, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        != lock.model_dump(mode="json")
        or _hash(profile_blob) != lock.profile_sha256
        or profile.id != lock.profile_id
        or profile.revision != lock.profile_revision
        or profile.entware_target != lock.entware_target
    ):
        raise PersistentError("scenario/profile/lock changed or disagrees")
    if (
        profile.entware_target != "aarch64-3.10"
        or scenario.requirements.capabilities
        or scenario.requirements.ndm_fixtures
        or scenario.runtime.env
        or scenario.runtime.publish
        or not isinstance(scenario.install, IPKInstall)
    ):
        raise PersistentError("unsupported target, capability, installer or publish")
    if scenario.service is not None and (
        scenario.service.readiness.vantage != "target_loopback"
        or scenario.service.readiness.kind != "http"
    ):
        raise PersistentError("service readiness vantage unsupported")
    base = json.loads(_secure_bytes(root / BASE_LOCK, root, 2 * 1024 * 1024))
    if (
        base.get("oci_digest") != lock.oci_digest
        or base.get("input_lock_sha256") != lock.feed_lock_sha256
        or base.get("target") != lock.entware_target
        or _hash(_secure_bytes(root / "locks/p0-aarch64.json", root, 2 * 1024 * 1024))
        != lock.feed_lock_sha256
    ):
        raise PersistentError("base/feed lock mismatch")
    source = resolve_input_path(
        scenario.install.path, scenario_dir=scenario_path.parent, project_root=root
    )
    package = _secure_bytes(source, root, 64 * 1024 * 1024)
    package_hash = _hash(package)
    if not any(
        item.kind == "ipk"
        and resolve_input_path(
            item.path, scenario_dir=lock_path.parent, project_root=root
        )
        == source
        and item.sha256 == package_hash
        for item in lock.sources
    ):
        raise PersistentError("IPK source missing or changed")
    with tempfile.TemporaryDirectory(dir=root / ".runtime") as folder:
        copied = Path(folder) / "input.ipk"
        copied.write_bytes(package)
        try:
            inspection = inspect_ipk(
                copied,
                profile=profile,
                rootfs=_locked_rootfs(root, base),
            )
        except IPKError as exc:
            raise PersistentError(f"invalid IPK: {exc}") from exc
    if inspection.metadata["Package"] != scenario.install.package_name or (
        inspection.status in {"FAIL", "BLOCKED"}
        and not (
            inspection.status == "BLOCKED"
            and "postinst" in inspection.control_scripts
            and all(
                f.code
                in {"missing-interpreter", "missing-dependency", "unresolved-link"}
                for f in inspection.findings
                if f.status == "BLOCKED"
            )
        )
    ):
        raise PersistentError(
            "IPK static inspection failed or package identity mismatch"
        )
    if init_locked(root, offline=True).get("oci_digest") != lock.oci_digest:
        raise PersistentError("prepared image mismatch")
    DockerRuntime("preflight-" + uuid4().hex, lock.oci_digest).image()
    return Prepared(
        scenario,
        scenario_blob,
        lock_blob,
        profile_blob,
        package,
        package_hash,
        inspection.metadata["Version"],
        lock.oci_digest,
    )


def _runtime(record: PersistentEnvironment) -> tuple[DockerRuntime, str]:
    runtime = DockerRuntime(record.run_id, record.oci_digest)
    if record.resource is None:
        raise RegistryError("environment has no recorded container identity")
    identifier = record.resource.container_id
    runtime.inspect("container", identifier)
    state = runtime.reconcile({identifier})
    if (
        state["container_missing"]
        or state["container_unexpected"]
        or (state["network_owned"] or state["network_unexpected"])
    ):
        raise RegistryError(
            "Docker labels/registry resources disagree; refuse mutation"
        )
    return runtime, identifier


def _transition(
    entry: Entry,
    record: PersistentEnvironment,
    state: str,
    *,
    resource: ResourceIdentity | None = None,
) -> PersistentEnvironment:
    updated = record.model_copy(
        update={
            "state": state,
            "resource": resource if resource is not None else record.resource,
        }
    )
    entry.update(record, updated)
    return updated


def _scenario(entry: Entry, record: PersistentEnvironment) -> Scenario:
    data = entry.scenario(record.scenario_sha256)
    return Scenario.model_validate(load_yaml_unique_text(data))


def load_yaml_unique_text(data: bytes) -> object:
    # Use the same duplicate-key/alias-rejecting loader as file inputs, without
    # trusting the original mutable path on a later invocation.

    from keemu.profiles import _UniqueKeyLoader

    loader = _UniqueKeyLoader(data.decode("utf-8"))
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _service_start(runtime: DockerRuntime, identifier: str, scenario: Scenario) -> None:
    if scenario.service is None:
        return
    probe = scenario.service.readiness
    if probe.vantage != "target_loopback" or probe.kind != "http":
        raise PersistentError("service readiness vantage unsupported")
    try:
        _probe(runtime, identifier, probe)
    except StageFailure as exc:
        if exc.status != "FAIL" or not str(exc).startswith("HTTP connection refused:"):
            raise PersistentError(f"service readiness failed: {exc}") from exc
        output = runtime.exec(
            identifier, list(scenario.service.start), allow_failure=True
        )
        if output.exit_code:
            raise PersistentError(
                f"service start failed: exit={output.exit_code}"
            ) from exc
    try:
        _retry_probe(lambda: _probe(runtime, identifier, probe), probe.timeout_seconds)
    except StageFailure as exc:
        raise PersistentError(f"service readiness failed: {exc}") from exc


def _service_stop(runtime: DockerRuntime, identifier: str, scenario: Scenario) -> None:
    if scenario.service is not None:
        output = runtime.exec(
            identifier, list(scenario.service.stop), allow_failure=True
        )
        if output.exit_code:
            raise PersistentError(f"service stop failed: exit={output.exit_code}")


def _install(
    runtime: DockerRuntime, identifier: str, prepared: Prepared, root: Path
) -> None:
    scenario = prepared.scenario
    if not isinstance(scenario.install, IPKInstall):
        raise PersistentError("unsupported installer")
    gzip = runtime.exec(identifier, ["/opt/bin/busybox", "--list"]).stdout.splitlines()
    if b"gzip" not in gzip:
        raise PersistentError("target gzip unavailable")
    absent = runtime.exec(
        identifier,
        ["/bin/sh", "-c", 'test ! -e "$1" && test ! -L "$1"', "sh", "/opt/bin/gzip"],
        allow_failure=True,
    )
    if absent.exit_code:
        raise PersistentError("target gzip link already exists")
    runtime.exec(
        identifier,
        ["/opt/bin/busybox", "ln", "-s", "/opt/bin/busybox", "/opt/bin/gzip"],
    )
    with tempfile.TemporaryDirectory(dir=root / ".runtime") as folder:
        staged = Path(folder) / "input.ipk"
        staged.write_bytes(prepared.package)
        staged.chmod(0o644)
        target = (
            f"/opt/tmp/{scenario.install.package_name}_"
            f"{prepared.package_version}_aarch64-3.10.ipk"
        )
        if (
            _hash(_secure_bytes(staged, root, 64 * 1024 * 1024))
            != prepared.package_hash
        ):
            raise PersistentError("staged IPK replaced")
        runtime.copy_file(identifier, str(staged), target)
        readback = Path(folder) / "readback.ipk"
        runtime.read_staged_file(identifier, target, str(readback))
        if (
            _hash(_secure_bytes(readback, root, 64 * 1024 * 1024))
            != prepared.package_hash
        ):
            raise PersistentError("target IPK differs from locked source")
        inventory = runtime.exec(identifier, ["/opt/bin/opkg", "list-installed"])
        names = {
            line.split(" - ", 1)[0] for line in inventory.stdout.decode().splitlines()
        }
        with tempfile.TemporaryDirectory(dir=root / ".runtime") as inspect_dir:
            copied = Path(inspect_dir) / "input.ipk"
            copied.write_bytes(prepared.package)
            inspection = inspect_ipk(copied)
        for alternatives in inspection.dependencies:
            if not any(alt.split(" ", 1)[0] in names for alt in alternatives):
                raise PersistentError("dependency absent from locked base")
        installed = runtime.exec(
            identifier,
            ["/opt/bin/opkg", "install", target],
            timeout=300,
            allow_failure=True,
        )
        if installed.exit_code:
            raise PersistentError(f"opkg install failed: exit={installed.exit_code}")
        listed = runtime.exec(
            identifier,
            ["/opt/bin/opkg", "list-installed", scenario.install.package_name],
            allow_failure=True,
        )
        if (
            listed.exit_code
            or f"{scenario.install.package_name} - {prepared.package_version}"
            not in listed.stdout.decode().splitlines()
        ):
            raise PersistentError("installed package/version not in target inventory")
        files = runtime.exec(
            identifier,
            ["/opt/bin/opkg", "files", scenario.install.package_name],
            allow_failure=True,
        )
        if files.exit_code:
            raise PersistentError("installed file inventory unavailable")
        recorded = set(files.stdout.decode("utf-8", "replace").splitlines())
        for item in inspection.entries:
            path = "/" + item.path
            if item.kind != "dir" and path not in recorded:
                raise PersistentError(f"installed file absent from inventory: {path}")
            exists = runtime.exec(
                identifier,
                ["/bin/sh", "-c", 'test -e "$1" || test -L "$1"', "sh", path],
                allow_failure=True,
            )
            if exists.exit_code:
                raise PersistentError(f"installed file absent: {path}")
            if (
                item.kind == "symlink"
                and runtime.exec(
                    identifier,
                    ["/bin/sh", "-c", 'test -e "$1"', "sh", path],
                    allow_failure=True,
                ).exit_code
            ):
                raise PersistentError(f"installed symlink broken: {path}")


def create(
    root: Path, name: str, scenario_path: Path, lock_path: Path
) -> PersistentEnvironment:
    safe_name(name)
    root = root.resolve()
    with Registry(root / ".runtime/registry").locked(name) as entry:
        if entry.directory.exists() or entry.directory.is_symlink():
            raise RegistryError(f"environment already exists: {name}")
        prepared = _prepare(root, scenario_path, lock_path)
        scenario = prepared.scenario
        record = PersistentEnvironment(
            schema_version=1,
            kind="persistent-environment",
            name=name,
            run_id="env-" + uuid4().hex,
            state="creating",
            scenario_id=scenario.id,
            scenario_sha256=_hash(prepared.scenario_blob),
            profile_id=scenario.profile,
            profile_sha256=_hash(prepared.profile_blob),
            lock_sha256=_hash(prepared.lock_blob),
            oci_digest=prepared.image_id,
            resource=None,
        )
        runtime = DockerRuntime(record.run_id, record.oci_digest)
        initial = runtime.reconcile()
        if initial["container_owned"] or initial["network_owned"]:
            raise RegistryError("run ID already owns Docker resources")
        entry.create(record, prepared.scenario_blob)
        identifier = None
        try:
            identifier = runtime.create("keemu-" + record.run_id)
            record = _transition(
                entry,
                record,
                "installing",
                resource=ResourceIdentity(
                    container_id=identifier,
                    owner_label="keemu",
                    run_id_label=record.run_id,
                ),
            )
            runtime.start(identifier)
            _install(runtime, identifier, prepared, root)
            record = _transition(entry, record, "stopped")
            # Container stays running when service/start readiness is evaluated.
            record = _transition(entry, record, "starting")
            _service_start(runtime, identifier, scenario)
            record = _transition(entry, record, "running")
            return record
        except Exception as exc:
            cleanup_error = None
            try:
                # Only IDs from this run, and only after an empty initial reconcile.
                for owned in runtime.reconcile()["container_owned"]:
                    runtime.remove_container(owned)
                for owned in runtime.reconcile()["network_owned"]:
                    runtime.remove_network(owned)
                state = runtime.reconcile()
                if state["container_owned"] or state["network_owned"]:
                    raise RegistryError("owned resources remain after failed create")
            except Exception as cleanup_exc:
                cleanup_error = cleanup_exc
            try:
                _transition(entry, record, "failed")
            except Exception as state_exc:
                raise PersistentError(
                    f"create failed: {exc}; cleanup: {cleanup_error}; "
                    f"registry: {state_exc}"
                ) from exc
            raise PersistentError(
                f"create failed: {exc}; cleanup: {cleanup_error or 'verified absent'}"
            ) from exc


def operate(root: Path, name: str, action: str, *, argv: tuple[str, ...] = ()) -> dict:
    safe_name(name)
    if action not in {
        "up",
        "down",
        "restart",
        "destroy",
        "status",
        "logs",
        "ports",
        "exec",
    }:
        raise PersistentError("unsupported lifecycle action")
    with Registry(root.resolve() / ".runtime/registry").locked(name) as entry:
        record = entry.read()
        if action == "status" and record.state == "destroyed":
            runtime = DockerRuntime(record.run_id, record.oci_digest)
            owned = runtime.reconcile()
            return {
                "environment": record.model_dump(mode="json"),
                "docker_running": None,
                "consistent": not owned["container_owned"]
                and not owned["network_owned"],
                "reconciliation": owned,
            }
        if action == "status" and record.state == "failed":
            runtime = DockerRuntime(record.run_id, record.oci_digest)
            owned = runtime.reconcile()
            return {
                "environment": record.model_dump(mode="json"),
                "docker_running": None,
                "consistent": False,
                "reconciliation": owned,
            }
        if action == "status" and record.state == "creating":
            runtime = DockerRuntime(record.run_id, record.oci_digest)
            owned = runtime.reconcile()
            return {
                "environment": record.model_dump(mode="json"),
                "docker_running": None,
                "consistent": False,
                "reconciliation": owned,
            }
        runtime, identifier = _runtime(record)
        observed = runtime.inspect("container", identifier)
        running = bool(observed.get("State", {}).get("Running"))
        if action == "status":
            return {
                "environment": record.model_dump(mode="json"),
                "docker_running": running,
                "consistent": record.state in {"running", "stopped"}
                and running == (record.state == "running"),
            }
        if record.state in {
            "creating",
            "installing",
            "starting",
            "stopping",
            "failed",
            "destroyed",
        }:
            raise RegistryError(f"environment in {record.state}; recovery required")
        if running != (record.state == "running"):
            raise RegistryError(
                "Docker state disagrees with registry; recovery required"
            )
        if action == "ports":
            return {
                "name": name,
                "ports": observed.get("NetworkSettings", {}).get("Ports") or {},
            }
        if action == "logs":
            output = runtime.logs(identifier)
            return {
                "name": name,
                "stdout": output.stdout.decode("utf-8", "replace"),
                "stderr": output.stderr.decode("utf-8", "replace"),
                "truncated_stdout": output.truncated_stdout,
                "truncated_stderr": output.truncated_stderr,
            }
        if action == "exec":
            if (
                not running
                or not argv
                or any(len(arg) > 4096 or "\0" in arg for arg in argv)
            ):
                raise PersistentError("exec needs running environment and bounded argv")
            output: Output = runtime.exec(identifier, list(argv), allow_failure=True)
            return {
                "name": name,
                "exit_code": output.exit_code,
                "stdout": output.stdout.decode("utf-8", "replace"),
                "stderr": output.stderr.decode("utf-8", "replace"),
            }
        scenario = _scenario(entry, record)
        if action == "restart":
            if record.state != "running":
                raise RegistryError("restart needs running environment")
            record = _stop(entry, record, runtime, identifier, scenario)
            return {
                "environment": _start(
                    entry, record, runtime, identifier, scenario
                ).model_dump(mode="json")
            }
        if action == "up":
            if record.state != "stopped":
                raise RegistryError("up needs stopped environment")
            return {
                "environment": _start(
                    entry, record, runtime, identifier, scenario
                ).model_dump(mode="json")
            }
        if action == "down":
            if record.state != "running":
                raise RegistryError("down needs running environment")
            return {
                "environment": _stop(
                    entry, record, runtime, identifier, scenario
                ).model_dump(mode="json")
            }
        if running:
            raise RegistryError("destroy needs stopped environment; use down first")
        runtime.remove_container(identifier)
        # Retain immutable tombstone; no same-name replacement even after destruction.
        record = _transition(entry, record, "destroyed")
        return {"environment": record.model_dump(mode="json"), "removed": identifier}


def _start(
    entry: Entry,
    record: PersistentEnvironment,
    runtime: DockerRuntime,
    identifier: str,
    scenario: Scenario,
) -> PersistentEnvironment:
    record = _transition(entry, record, "starting")
    try:
        runtime.start(identifier)
        _service_start(runtime, identifier, scenario)
        return _transition(entry, record, "running")
    except Exception:
        _transition(entry, record, "failed")
        raise


def _stop(
    entry: Entry,
    record: PersistentEnvironment,
    runtime: DockerRuntime,
    identifier: str,
    scenario: Scenario,
) -> PersistentEnvironment:
    record = _transition(entry, record, "stopping")
    try:
        _service_stop(runtime, identifier, scenario)
        runtime.stop(identifier)
        return _transition(entry, record, "stopped")
    except Exception:
        _transition(entry, record, "failed")
        raise
