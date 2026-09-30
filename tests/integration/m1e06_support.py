"""Bounded evidence helpers for the frozen E07 verification; no product changes."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

from keemu.docker_runtime import DockerRuntime, _exec, _json
from keemu.persistent import operate
from tests.integration.test_lifecycle import ROOT, bind_scenario, inputs
from tests.integration.test_m1e03_lifecycle import target_inputs

TARGETS = (
    ("generic-aarch64", "aarch64-3.10", "m1a-init-aarch64.json"),
    ("generic-mips", "mips-3.4", "m1e-init-mips.json"),
    ("generic-mipsel", "mipsel-3.4", "m1e-init-mipsel.json"),
)
EVIDENCE = ROOT / os.environ.get("KEEMU_M1E06_EVIDENCE", "reports/m1e06")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def publish(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def case_dir(label: str) -> Path:
    path = EVIDENCE / (label + "-" + uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def snapshot() -> dict:
    containers = {}
    networks = {}
    for identifier in sorted(DockerRuntime.listed_ids("container")):
        items = _json(["docker", "container", "inspect", identifier])
        assert isinstance(items, list)
        item = items[0]
        containers[identifier] = {
            "Id": item["Id"],
            "Name": item["Name"],
            "Image": item["Image"],
            "State": item["State"],
            "Labels": item["Config"].get("Labels"),
        }
    for identifier in sorted(DockerRuntime.listed_ids("network")):
        items = _json(["docker", "network", "inspect", identifier])
        assert isinstance(items, list)
        item = items[0]
        networks[identifier] = {
            key: item.get(key)
            for key in (
                "Id",
                "Name",
                "Driver",
                "Internal",
                "IPAM",
                "Containers",
                "Labels",
            )
        }
    volumes = sorted(
        _exec(["docker", "volume", "ls", "-q"]).stdout.decode().splitlines()
    )
    return {"containers": containers, "networks": networks, "volumes": volumes}


def preserve(old: dict) -> None:
    current = snapshot()
    for identifier, item in old["containers"].items():
        assert current["containers"][identifier] == item, identifier
    for identifier, item in old["networks"].items():
        observed = dict(current["networks"][identifier])
        endpoints = observed.pop("Containers") or {}
        expected = dict(item)
        prior = expected.pop("Containers") or {}
        assert observed == expected, identifier
        assert {key: endpoints[key] for key in prior} == prior, identifier
        # Docker lists even network-none containers as endpoints on "none".
        # Temporary endpoints are permitted only for new exact project-owned
        # containers; final teardown still requires whole-snapshot equality.
        for added in endpoints.keys() - prior.keys():
            assert added not in old["containers"]
            assert current["containers"][added]["Labels"]["org.keemu.owner"] == "keemu"
    assert current["volumes"] == old["volumes"]


def pin(profile: str) -> dict:
    filename = next(name for p, _, name in TARGETS if p == profile)
    return json.loads((ROOT / "locks" / filename).read_text())


def scenario(directory: Path, profile: str, target: str, *, service=False):
    options = {}
    if service:
        if target == "aarch64-3.10":
            options["web_demo"] = True
        else:
            locked = json.loads(
                (ROOT / "locks" / f"m1b18-fixtures-{target}.json").read_text()
            )["fixtures"]["web-demo"]
            binary = (ROOT / locked["path"]).read_bytes()
            assert digest(binary) == locked["sha256"]
            options["web_binary"] = binary
    directory.mkdir(parents=True, exist_ok=True)
    paths = (
        inputs(directory, **options)
        if target == "aarch64-3.10"
        else target_inputs(directory, profile, target, **options)
    )
    source, lock = paths
    if service:
        arguments = (
            "18765 18766 /opt/etc/keemu-count" if target == "aarch64-3.10" else "18765"
        )
        body = "state=1" if target == "aarch64-3.10" else "keemu-web-demo"
        source.write_text(
            source.read_text().replace(
                "service: null",
                "service:\n"
                f"  start: [/bin/sh, -c, '/opt/bin/web-demo {arguments} "
                ">/dev/null 2>&1 & echo $! > /opt/tmp/web-demo.pid']\n"
                "  stop: [/bin/sh, -c, 'read pid < /opt/tmp/web-demo.pid; "
                'kill -TERM "$pid"; /opt/bin/busybox rm -f /opt/tmp/web-demo.pid\']\n'
                "  readiness: {kind: http, vantage: target_loopback, "
                "url: 'http://127.0.0.1:18765/health', expected_status: [200], "
                f"body_contains: {body}, timeout_seconds: 5}}",
            )
        )
        bind_scenario(lock, source)
    return paths


def destroy(name: str, runtime: DockerRuntime, identifier: str) -> dict:
    stopped = operate(ROOT, name, "down")
    assert stopped["environment"]["state"] == "stopped"
    result = operate(ROOT, name, "destroy")
    assert result["environment"]["state"] == "destroyed"
    assert operate(ROOT, name, "status")["consistent"]
    assert runtime.reconcile()["container_owned"] == []
    assert identifier not in DockerRuntime.listed_ids("container")
    return result["environment"]


def recover_one_shot(runtime: DockerRuntime, identifier: str) -> dict:
    observed = runtime.reconcile(expected_containers={identifier})
    assert observed["container_owned"] == [identifier]
    assert not observed["network_owned"] and not observed["container_unexpected"]
    item = runtime.inspect("container", identifier)
    assert item["Name"] == "/keemu-" + runtime.run_id
    runtime.remove_container(identifier)
    assert runtime.reconcile()["container_owned"] == []
    assert identifier not in DockerRuntime.listed_ids("container")
    return {
        "id": identifier,
        "name": item["Name"],
        "labels": item["Config"]["Labels"],
        "removed_and_absent": True,
        "scope": "explicit_test_owned_not_production",
    }


CHILD = """import json, sys, time
from pathlib import Path
from keemu.docker_runtime import DockerRuntime
from keemu import persistent
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_persistent import run_persistent_script
from keemu.script_stage import ScriptStager
from keemu.script_process import ScriptProcessRunner
mode, root, profile, name, source, lock, phase, marker, reports = sys.argv[1:]
def gate(value):
    Path(marker).write_text(json.dumps(value))
    time.sleep(120)
if mode == 'create':
    if phase == 'creating':
        original = DockerRuntime.create
        def stalled(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            gate({'container': result})
            return result
        DockerRuntime.create = stalled
    else:
        def stalled(*args):
            gate({'point': 'installing'})
        persistent._install = stalled
    persistent.create(Path(root), name, Path(source), Path(lock))
else:
    if phase == 'after-create':
        original = ScriptStager.stage
        def stalled(self, script, container):
            gate({'container': container})
            return original(self, script, container)
        ScriptStager.stage = stalled
    elif phase == 'after-stage':
        original = ScriptProcessRunner.run
        def stalled(self, staged, **kwargs):
            gate({'container': staged.container_id, 'path': staged.path})
            return original(self, staged, **kwargs)
        ScriptProcessRunner.run = stalled
    if mode == 'persistent':
        run_persistent_script(name, source, project_root=Path(root),
            timeout_seconds=3, report_root=Path(reports))
    else:
        run_one_shot_script(source, project_root=Path(root), profile_id=profile,
            run_id=name, timeout_seconds=3, report_root=Path(reports))
"""


def worker(mode, profile, name, source, lock, phase, directory):
    marker = directory / (phase + "-barrier.json")
    reports = directory / (phase + "-reports")
    proc = subprocess.Popen(  # noqa: S603 -- fixed Python API, no host shell
        [
            sys.executable,
            "-u",
            "-c",
            CHILD,
            mode,
            str(ROOT),
            profile,
            name,
            str(source),
            str(lock),
            phase,
            str(marker),
            str(reports),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc, marker, reports


def wait_barrier(proc, marker: Path) -> dict:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if marker.exists():
            return json.loads(marker.read_text())
        assert proc.poll() is None, ("worker exited before barrier", proc.returncode)
        time.sleep(0.1)
    raise AssertionError("90-second barrier deadline expired")


def kill(proc) -> None:
    if proc.poll() is None:
        os.kill(proc.pid, signal.SIGKILL)
    assert proc.wait(timeout=10) == -signal.SIGKILL


def no_report(reports: Path) -> None:
    assert not reports.exists() or not list(reports.rglob("report.json"))
