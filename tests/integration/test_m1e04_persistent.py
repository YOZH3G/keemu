"""Opt-in real registry-backed MIPS/MIPSEL lifecycle and crash recovery."""
from __future__ import annotations

import os
import selectors
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from keemu.docker_runtime import DockerRuntime
from keemu.persistent import PersistentError, create, operate, recover
from keemu.registry import Registry, RegistryError
from tests.integration.test_lifecycle import ROOT, bind_scenario
from tests.integration.test_m1e03_lifecycle import TARGETS, target_inputs

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


def _barrier(proc):
    selector = selectors.DefaultSelector()
    try:
        assert proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        assert selector.select(180), "creator did not reach barrier"
        assert proc.stdout.readline().strip() == "READY"
    finally:
        selector.close()


@pytest.mark.docker
@pytest.mark.parametrize(("profile", "target"), TARGETS)
def test_persistent_mips_lifecycle_and_recovery(profile, target):
    if os.getenv("KEEMU_TEST_M1E04") != "1":
        pytest.skip("opt in to MIPS/MIPSEL persistent lifecycle")
    (ROOT / ".runtime").mkdir(exist_ok=True)
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime", prefix="m1e04-") as folder:
        directory = Path(folder)
        scenario, lock = target_inputs(directory, profile, target)
        name = "m1e04-" + uuid4().hex[:18]
        record = create(ROOT, name, scenario, lock)
        assert record.state == "running" and record.resource
        identifier = record.resource.container_id
        runtime = DockerRuntime(record.run_id, record.oci_digest, target=target)
        try:
            assert operate(ROOT, name, "status")["consistent"]
            assert operate(ROOT, name, "ports")["ports"] == {}
            assert "stdout" in operate(ROOT, name, "logs")
            assert "KEEMU-HELLO" in operate(
                ROOT, name, "exec", argv=("/opt/bin/keemu-hello",)
            )["stdout"]
            restarted = operate(ROOT, name, "restart")
            assert restarted["environment"]["resource"]["container_id"] == identifier
            assert operate(ROOT, name, "down")["environment"]["state"] == "stopped"
            assert operate(ROOT, name, "up")["environment"]["state"] == "running"
            count = operate(
                ROOT,
                name,
                "exec",
                argv=(
                    "/bin/sh", "-c", 'read n < /opt/etc/keemu-count; test "$n" = 1'
                ),
            )
            assert count["exit_code"] == 0
            with pytest.raises(RegistryError, match="already exists"):
                create(ROOT, name, scenario, lock)
            with pytest.raises(RegistryError, match="healthy"):
                recover(ROOT, name)
            assert operate(ROOT, name, "down")["environment"]["state"] == "stopped"
            assert operate(ROOT, name, "destroy")["environment"]["state"] == "destroyed"
            assert recover(ROOT, name)["retry"] is True
            assert operate(ROOT, name, "status")["consistent"]
            with pytest.raises(RegistryError, match="already exists"):
                create(ROOT, name, scenario, lock)
        finally:
            for owned in runtime.reconcile()["container_owned"]:
                if owned == identifier:
                    runtime.remove_container(owned)
        assert not runtime.reconcile()["container_owned"]
        # A real target-loopback service must survive a same-ID restart and
        # down/up without rerunning postinst.
        scenario, lock = target_inputs(directory, profile, target)
        scenario.write_text(
            scenario.read_text().replace(
                "service: null",
                "service:\n"
                "  start: [/opt/bin/busybox, httpd, -p, '18765', -h, /opt/etc]\n"
                "  stop: [/opt/bin/busybox, killall, httpd]\n"
                "  readiness: {kind: http, vantage: target_loopback, "
                "url: 'http://127.0.0.1:18765/keemu-count', "
                "expected_status: [200], body_contains: '1', timeout_seconds: 5}",
            )
        )
        bind_scenario(lock, scenario)
        service_name = "m1e04-service-" + uuid4().hex[:16]
        service = create(ROOT, service_name, scenario, lock)
        assert service.resource
        service_id = service.resource.container_id
        service_runtime = DockerRuntime(
            service.run_id, service.oci_digest, target=target
        )
        try:
            assert operate(ROOT, service_name, "restart")["environment"][
                "resource"
            ]["container_id"] == service_id
            assert operate(ROOT, service_name, "down")["environment"][
                "state"
            ] == "stopped"
            assert operate(ROOT, service_name, "up")["environment"][
                "state"
            ] == "running"
            assert operate(
                ROOT,
                service_name,
                "exec",
                argv=("/bin/sh", "-c", 'read n < /opt/etc/keemu-count; echo "$n"'),
            )["stdout"].strip() == "1"
            assert operate(ROOT, service_name, "down")["environment"][
                "state"
            ] == "stopped"
            assert operate(ROOT, service_name, "destroy")["environment"][
                "state"
            ] == "destroyed"
        finally:
            if service_id in service_runtime.reconcile()["container_owned"]:
                service_runtime.remove_container(service_id)
        scenario, lock = target_inputs(directory, profile, target)
        foreign_run = "m1e04-foreign-" + uuid4().hex[:16]
        foreign = DockerRuntime(foreign_run, service.oci_digest, target=target)
        foreign_id = foreign.create("keemu-" + foreign_run)
        try:
            name = "m1e04-fail-" + uuid4().hex[:16]
            scenario, lock = target_inputs(
                directory, profile, target, failed_postinst=True
            )
            with pytest.raises(PersistentError, match="opkg install failed"):
                create(ROOT, name, scenario, lock)
            with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                failed = entry.read()
            assert failed.state == "failed" and failed.resource
            assert not DockerRuntime(
                failed.run_id, failed.oci_digest, target=target
            ).reconcile()["container_owned"]
            assert recover(ROOT, name)["state"] == "destroyed"
            assert foreign.inspect("container", foreign_id)["Id"] == foreign_id
        finally:
            foreign.remove_container(foreign_id)
        scenario, lock = target_inputs(directory, profile, target)
        for point in ("creating", "installing"):
            name = "m1e04-crash-" + uuid4().hex[:16]
            proc = subprocess.Popen(  # noqa: S603 -- fixed Python test worker
                [
                    sys.executable, "-u", "-c", CHILD, str(ROOT), name,
                    str(scenario), str(lock), point,
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                _barrier(proc)
            finally:
                proc.kill()
                proc.wait(timeout=20)
            with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                interrupted = entry.read()
            assert interrupted.state == point
            stranded = DockerRuntime(
                interrupted.run_id, interrupted.oci_digest, target=target
            )
            owned = stranded.reconcile()["container_owned"]
            assert len(owned) == 1
            assert not operate(ROOT, name, "status")["consistent"]
            assert recover(ROOT, name)["removed"] == owned
            assert recover(ROOT, name)["retry"] is True
            assert not stranded.reconcile()["container_owned"]
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
