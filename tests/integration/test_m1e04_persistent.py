"""Opt-in real registry-backed MIPS/MIPSEL lifecycle and crash recovery."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.input_locks import PersistentEnvironment, ResourceIdentity
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
def test_persistent_mips_lifecycle_and_recovery(profile, target, monkeypatch):
    if os.getenv("KEEMU_TEST_M1E04") != "1":
        pytest.skip("opt in to MIPS/MIPSEL persistent lifecycle")
    (ROOT / ".runtime").mkdir(exist_ok=True)
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime", prefix="m1e04-") as folder:
        directory = Path(folder)
        wrong, wrong_lock = target_inputs(
            directory, profile, target, architecture="aarch64-3.10"
        )
        wrong_name = "m1e04-wrong-" + uuid4().hex[:16]
        with pytest.raises(PersistentError, match="static inspection"):
            create(ROOT, wrong_name, wrong, wrong_lock)
        assert not (ROOT / ".runtime/registry" / wrong_name).exists()
        changed, changed_lock = target_inputs(directory, profile, target)
        (directory / "hello.ipk").write_bytes(b"changed after lock")
        changed_name = "m1e04-changed-" + uuid4().hex[:16]
        with pytest.raises((ValueError, RuntimeError), match="hash|changed"):
            create(ROOT, changed_name, changed, changed_lock)
        assert not (ROOT / ".runtime/registry" / changed_name).exists()
        scenario, lock = target_inputs(directory, profile, target)
        name = "m1e04-" + uuid4().hex[:18]
        record = create(ROOT, name, scenario, lock)
        assert record.state == "running" and record.resource
        identifier = record.resource.container_id
        runtime = DockerRuntime(record.run_id, record.oci_digest, target=target)
        try:
            assert operate(ROOT, name, "status")["consistent"]
            runner = CliRunner()
            cli_status = runner.invoke(cli, ["status", name, "--repo", str(ROOT)])
            assert cli_status.exit_code == 0, cli_status.output
            assert json.loads(cli_status.output)["environment"]["profile_id"] == profile
            cli_exec = runner.invoke(
                cli,
                ["exec", name, "--repo", str(ROOT), "--", "/opt/bin/keemu-hello"],
            )
            assert cli_exec.exit_code == 0, cli_exec.output
            assert "KEEMU-HELLO" in json.loads(cli_exec.output)["stdout"]
            assert operate(ROOT, name, "ports")["ports"] == {}
            assert "stdout" in operate(ROOT, name, "logs")
            assert (
                "KEEMU-HELLO"
                in operate(ROOT, name, "exec", argv=("/opt/bin/keemu-hello",))["stdout"]
            )
            restarted = operate(ROOT, name, "restart")
            assert restarted["environment"]["resource"]["container_id"] == identifier
            assert operate(ROOT, name, "down")["environment"]["state"] == "stopped"
            assert operate(ROOT, name, "up")["environment"]["state"] == "running"
            count = operate(
                ROOT,
                name,
                "exec",
                argv=("/bin/sh", "-c", 'read n < /opt/etc/keemu-count; test "$n" = 1'),
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
        fixture_lock = json.loads(
            (ROOT / "locks" / f"m1b18-fixtures-{target}.json").read_text()
        )
        fixture = fixture_lock["fixtures"]["web-demo"]
        web_binary = (ROOT / fixture["path"]).read_bytes()
        assert hashlib.sha256(web_binary).hexdigest() == fixture["sha256"]
        scenario, lock = target_inputs(
            directory, profile, target, web_binary=web_binary
        )
        scenario.write_text(
            scenario.read_text().replace(
                "service: null",
                "service:\n"
                "  start: [/bin/sh, -c, "
                "'/opt/bin/web-demo 18765 "
                ">/dev/null 2>&1 & echo $! > /opt/tmp/web-demo.pid']\n"
                "  stop: [/bin/sh, -c, "
                '\'read pid < /opt/tmp/web-demo.pid; kill -TERM "$pid"; '
                "/opt/bin/busybox rm -f /opt/tmp/web-demo.pid']\n"
                "  readiness: {kind: http, vantage: target_loopback, "
                "url: 'http://127.0.0.1:18765/health', "
                "expected_status: [200], body_contains: keemu-web-demo, "
                "timeout_seconds: 5}",
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
            restarted = operate(ROOT, service_name, "restart")
            assert restarted["environment"]["resource"]["container_id"] == service_id
            stopped = operate(ROOT, service_name, "down")
            assert stopped["environment"]["state"] == "stopped"
            started = operate(ROOT, service_name, "up")
            assert started["environment"]["state"] == "running"
            output = operate(
                ROOT,
                service_name,
                "exec",
                argv=("/bin/sh", "-c", 'read n < /opt/etc/keemu-count; echo "$n"'),
            )
            assert output["stdout"].strip() == "1"
            stopped = operate(ROOT, service_name, "down")
            assert stopped["environment"]["state"] == "stopped"
            destroyed = operate(ROOT, service_name, "destroy")
            assert destroyed["environment"]["state"] == "destroyed"
        finally:
            if service_id in service_runtime.reconcile()["container_owned"]:
                service_runtime.remove_container(service_id)
        scenario, lock = target_inputs(directory, profile, target)
        foreign_run = "m1e04-foreign-" + uuid4().hex[:16]
        foreign = DockerRuntime(foreign_run, service.oci_digest, target=target)
        foreign_id = foreign.create("keemu-" + foreign_run)
        try:
            stale_name = "m1e04-stale-" + uuid4().hex[:16]
            stale_run = "env-" + uuid4().hex
            with Registry(ROOT / ".runtime/registry").locked(stale_name) as entry:
                first = PersistentEnvironment(
                    schema_version=1,
                    kind="persistent-environment",
                    name=stale_name,
                    run_id=stale_run,
                    state="creating",
                    scenario_id="keemu-hello",
                    scenario_sha256=hashlib.sha256(scenario.read_bytes()).hexdigest(),
                    profile_id=profile,
                    profile_sha256=hashlib.sha256(
                        (ROOT / "profiles/generic" / f"{profile}.yaml").read_bytes()
                    ).hexdigest(),
                    lock_sha256=hashlib.sha256(lock.read_bytes()).hexdigest(),
                    oci_digest=service.oci_digest,
                    resource=None,
                )
                entry.create(first, scenario.read_bytes())
                entry.update(
                    first,
                    first.model_copy(
                        update={
                            "state": "installing",
                            "resource": ResourceIdentity(
                                container_id=foreign_id,
                                owner_label="keemu",
                                run_id_label=stale_run,
                            ),
                        }
                    ),
                )
            with pytest.raises(RegistryError, match="without matching ownership"):
                recover(ROOT, stale_name)
            assert foreign.inspect("container", foreign_id)["Id"] == foreign_id
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
        assert recover(ROOT, stale_name)["state"] == "destroyed"
        scenario, lock = target_inputs(directory, profile, target)
        for point in ("creating", "installing"):
            name = "m1e04-crash-" + uuid4().hex[:16]
            proc = subprocess.Popen(  # noqa: S603 -- fixed Python test worker
                [
                    sys.executable,
                    "-u",
                    "-c",
                    CHILD,
                    str(ROOT),
                    name,
                    str(scenario),
                    str(lock),
                    point,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _barrier(proc)
                with pytest.raises(RegistryError, match="busy"):
                    with Registry(ROOT / ".runtime/registry").locked(name):
                        pytest.fail("live creator released its per-name lock")
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
            extra = stranded.create("keemu-" + interrupted.run_id + "-extra")
            try:
                with pytest.raises(RegistryError, match="extra owned|ambiguous"):
                    recover(ROOT, name)
                assert stranded.inspect("container", owned[0])["Id"] == owned[0]
            finally:
                stranded.remove_container(extra)
            other_target = "mipsel-3.4" if target == "mips-3.4" else "mips-3.4"
            other_base = (
                "m1e-init-mipsel.json" if target == "mips-3.4" else "m1e-init-mips.json"
            )
            other_image = json.loads((ROOT / "locks" / other_base).read_text())[
                "oci_digest"
            ]
            mismatched = DockerRuntime(
                interrupted.run_id, other_image, target=other_target
            )
            wrong = mismatched.create("keemu-" + interrupted.run_id + "-wrong")
            try:
                with pytest.raises(DockerBoundaryError, match="ownership labels"):
                    recover(ROOT, name)
                assert stranded.inspect("container", owned[0])["Id"] == owned[0]
            finally:
                mismatched.remove_container(wrong)
            if point == "installing":
                with monkeypatch.context() as scoped:

                    def refuse_remove(_runtime, _identifier):
                        raise DockerBoundaryError("injected removal refusal")

                    scoped.setattr(DockerRuntime, "remove_container", refuse_remove)
                    with pytest.raises(
                        DockerBoundaryError, match="injected removal refusal"
                    ):
                        recover(ROOT, name)
                assert stranded.inspect("container", owned[0])["Id"] == owned[0]
                with Registry(ROOT / ".runtime/registry").locked(name) as entry:
                    assert entry.read().state == "installing"
            recovered = CliRunner().invoke(
                cli, ["recover", name, "--yes", "--repo", str(ROOT)]
            )
            assert recovered.exit_code == 0, recovered.output
            assert json.loads(recovered.output)["removed"] == owned
            assert recover(ROOT, name)["retry"] is True
            assert not stranded.reconcile()["container_owned"]
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
