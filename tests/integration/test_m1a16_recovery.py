"""Opt-in SIGKILL recovery and isolation proof on disposable Docker resources."""

# ruff: noqa: E501, S607 -- fixed Docker executable and bounded test evidence
from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.input_locks import PersistentEnvironment, ResourceIdentity
from keemu.persistent import operate, recover
from keemu.registry import Registry, RegistryError
from tests.integration.test_lifecycle import inputs

ROOT = Path(__file__).resolve().parents[2]
IMAGE = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())["oci_digest"]

# The child uses the actual persistent create path. The first barrier is
# immediately after Docker create but before ID publication; the second is
# after ID publication and container start, before target installation.
CHILD = """
import sys, time
from pathlib import Path
from keemu import persistent
from keemu.docker_runtime import DockerRuntime
root, name, scenario, lock, point = sys.argv[1:]
if point == 'creating':
    original = DockerRuntime.create
    def stall(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        print('READY', flush=True)
        time.sleep(120)
        return result
    DockerRuntime.create = stall
else:
    def stall(*args):
        print('READY', flush=True)
        time.sleep(120)
    persistent._install = stall
persistent.create(Path(root), name, Path(scenario), Path(lock))
"""


def barrier(proc: subprocess.Popen) -> None:
    selector = selectors.DefaultSelector()
    try:
        assert proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        if not selector.select(240):
            raise AssertionError("child failed to reach interruption barrier")
        if proc.stdout.readline().strip() != "READY":
            assert proc.stderr is not None
            raise AssertionError("child failed before barrier: " + proc.stderr.read(4096))
    finally:
        selector.close()


def foreign_snapshot() -> dict:
    """Read-only baseline of non-KEEMU Docker resource identity and state."""
    result = subprocess.run(  # noqa: S603 -- fixed Docker read-only query
        ["docker", "container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    containers = {}
    for identifier in result.stdout.splitlines():
        item = json.loads(subprocess.run(  # noqa: S603 -- fixed Docker inspect
            ["docker", "container", "inspect", identifier],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout)[0]
        if (item["Config"].get("Labels") or {}).get("org.keemu.owner") != "keemu":
            containers[identifier] = {
                "running": item["State"]["Running"], "image": item["Image"],
                "name": item["Name"],
            }
    result = subprocess.run(  # noqa: S603 -- fixed Docker read-only query
        ["docker", "network", "ls", "--no-trunc", "--format", "{{.ID}}"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    networks = {}
    for identifier in result.stdout.splitlines():
        item = json.loads(subprocess.run(  # noqa: S603 -- fixed Docker inspect
            ["docker", "network", "inspect", identifier],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout)[0]
        if (item.get("Labels") or {}).get("org.keemu.owner") != "keemu":
            networks[identifier] = {"name": item["Name"], "driver": item["Driver"]}
    return {"containers": containers, "networks": networks}


@pytest.mark.docker
def test_sigkill_recovery_isolation_and_foreign_preservation(monkeypatch):
    if os.getenv("KEEMU_TEST_RECOVERY") != "1":
        pytest.skip("opt in to SIGKILL/disposable Docker recovery test")
    (ROOT / ".runtime").mkdir(exist_ok=True)
    foreign_before = foreign_snapshot()
    run = "m1a16-" + uuid.uuid4().hex[:12]
    other = DockerRuntime(run + "-other", IMAGE)
    foreign_network = foreign_container = None
    stale_name = None
    evidence = {"run": run, "cases": [], "foreign_before": foreign_before}
    try:
        foreign_network = other.create_network("keemu-" + run + "-other")
        foreign_container = other.create(
            "keemu-" + run + "-other", network_id=foreign_network
        )
        other.start(foreign_container)
        foreign_owned_before = {
            "container": other.inspect("container", foreign_container)["State"]["Running"],
            "network": other.inspect("network", foreign_network)["Name"],
        }
        stale_name = "stale-" + uuid.uuid4().hex[:12]
        with Registry(ROOT / ".runtime/registry").locked(stale_name) as entry:
            initial = PersistentEnvironment(
                schema_version=1, kind="persistent-environment", name=stale_name,
                run_id=run + "-stale", state="creating", scenario_id="keemu-hello",
                scenario_sha256=hashlib.sha256(b"stale").hexdigest(),
                profile_id="generic-aarch64", profile_sha256="a" * 64,
                lock_sha256="b" * 64, oci_digest=IMAGE, resource=None,
            )
            entry.create(initial, b"stale")
            entry.update(initial, initial.model_copy(update={
                "state": "installing",
                "resource": ResourceIdentity(
                    container_id=foreign_container, owner_label="keemu",
                    run_id_label=initial.run_id,
                ),
            }))
        with pytest.raises(RegistryError, match="without matching ownership"):
            recover(ROOT, stale_name)
        with Registry(ROOT / ".runtime/registry").locked(stale_name) as entry:
            assert entry.read().state == "installing"
        assert other.inspect("container", foreign_container)["State"]["Running"]
        evidence["stale_registry"] = "foreign run ID refused; registry unchanged"
        with pytest.raises(DockerBoundaryError, match="Docker container failed"):
            DockerRuntime(run + "-collision", IMAGE).create(
                "keemu-" + run + "-other"
            )
        assert other.inspect("container", foreign_container)["State"]["Running"]
        evidence["collision"] = "existing Docker name retained"
        for point in ("creating", "installing"):
            name = "recover-" + uuid.uuid4().hex[:12]
            with tempfile.TemporaryDirectory(dir=ROOT / ".runtime", prefix="m1a16-") as folder:
                scenario, lock = inputs(Path(folder))
                proc = subprocess.Popen(  # noqa: S603 -- fixed Python test child
                    [sys.executable, "-u", "-c", CHILD, str(ROOT), name,
                     str(scenario), str(lock), point],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                record = None
                try:
                    barrier(proc)
                    with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                        # The live creator holds this lock until killed.
                        pytest.fail("creator lock unexpectedly released")
                except RegistryError as exc:
                    assert "busy" in str(exc)
                finally:
                    proc.kill()
                    proc.wait(timeout=20)
                try:
                    with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                        record = entry.read()
                    assert record.state == point
                    runtime = DockerRuntime(record.run_id, record.oci_digest)
                    owned = runtime.reconcile()["container_owned"]
                    assert len(owned) == 1
                    identifier = owned[0]
                    observed = runtime.inspect("container", identifier)
                    assert observed["Name"] == "/keemu-" + record.run_id
                    assert observed["HostConfig"]["NetworkMode"] == "none"
                    assert observed["HostConfig"]["Privileged"] is False
                    assert not observed["HostConfig"]["Binds"]
                    assert not observed["HostConfig"].get("Mounts")
                    assert not observed["HostConfig"]["CapAdd"]
                    assert "ALL" in observed["HostConfig"]["CapDrop"]
                    assert "no-new-privileges" in observed["HostConfig"]["SecurityOpt"]
                    assert observed["HostConfig"]["Memory"] == 1073741824
                    assert observed["HostConfig"]["MemorySwap"] == 1073741824
                    assert observed["HostConfig"]["NanoCpus"] == 2000000000
                    assert observed["HostConfig"]["PidsLimit"] == 256
                    assert observed["HostConfig"]["LogConfig"] == {
                        "Type": "json-file", "Config": {"max-file": "1", "max-size": "20m"},
                    }
                    assert not observed["HostConfig"]["PortBindings"]
                    if point == "installing":
                        assert record.resource is not None
                        assert record.resource.container_id == identifier
                        assert observed["State"]["Running"]
                        status = runtime.exec(identifier, ["/bin/sh", "-c",
                            "test ! -e /var/run/docker.sock && "
                            "/opt/bin/busybox cat /proc/1/status /proc/net/tcp /proc/net/udp"])
                        lines = status.stdout.decode().splitlines()
                        assert "CapEff:\t0000000000000000" in lines
                        assert "  sl  local_address" in status.stdout.decode()
                        sockets = runtime.exec(identifier, [
                            "/opt/bin/busybox", "cat", "/proc/net/tcp", "/proc/net/udp",
                        ]).stdout.decode().splitlines()
                        assert len(sockets) == 2  # empty TCP/UDP endpoint tables
                        assert all("local_address" in line for line in sockets)
                        evidence["sockets"] = {"tcp_udp_endpoints": 0}
                    assert operate(ROOT, name, "status")["consistent"] is False
                    with pytest.raises(RegistryError, match="already exists"):
                        with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                            first = record.model_copy(
                                update={"state": "creating", "resource": None}
                            )
                            entry.create(first, entry.scenario(record.scenario_sha256))
                    with pytest.raises(DockerBoundaryError, match="ownership"):
                        runtime.remove_container(foreign_container)
                    with pytest.raises(DockerBoundaryError, match="ownership"):
                        runtime.remove_network(foreign_network)
                    if point == "installing":
                        original_remove = DockerRuntime.remove_container
                        attempts = 0
                        def fail_once(self, identifier, original_remove=original_remove):
                            nonlocal attempts
                            attempts += 1
                            if attempts == 1:
                                raise DockerBoundaryError("injected removal timeout")
                            return original_remove(self, identifier)
                        monkeypatch.setattr(DockerRuntime, "remove_container", fail_once)
                        with pytest.raises(DockerBoundaryError, match="injected removal timeout"):
                            recover(ROOT, name)
                        assert runtime.reconcile()["container_owned"] == [identifier]
                        monkeypatch.setattr(DockerRuntime, "remove_container", original_remove)
                    result = recover(ROOT, name)
                    assert result["removed"] == [identifier]
                    assert recover(ROOT, name)["retry"] is True
                    assert runtime.reconcile()["container_owned"] == []
                    assert identifier not in DockerRuntime.listed_ids("container")
                    with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                        assert entry.read().state == "destroyed"
                    assert other.inspect("container", foreign_container)["State"]["Running"]
                    assert other.inspect("network", foreign_network)["Name"] == foreign_owned_before["network"]
                    evidence["cases"].append({"point": point, "run_id": record.run_id,
                                              "removed": identifier, "retry": point == "installing"})
                finally:
                    if record is not None:
                        # Emergency cleanup on assertion failure, only this exact run.
                        local = DockerRuntime(record.run_id, record.oci_digest)
                        for identifier in local.reconcile()["container_owned"]:
                            local.remove_container(identifier)
    finally:
        if foreign_container:
            other.remove_container(foreign_container)
        if foreign_network:
            other.remove_network(foreign_network)
        if stale_name:
            # The intentionally inconsistent record becomes safely recoverable
            # only once its foreign ID really is absent.
            assert recover(ROOT, stale_name)["state"] == "destroyed"
    assert foreign_snapshot() == foreign_before
    evidence["foreign_after"] = foreign_snapshot()
    path = ROOT / ".runtime/m1a16" / (run + ".json")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"evidence": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}))
