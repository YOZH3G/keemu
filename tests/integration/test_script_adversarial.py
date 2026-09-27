"""Opt-in bounded, real Docker/binfmt script race and interruption evidence.

SIGKILL targets only test-owned host workers; explicit recovery removes only
full-ID/run/label/name-verified one-shot containers. No host script shell.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_stage import ScriptStager

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"
OBSERVATIONS = ROOT / "reports/m1d11-observations.json"


def _enabled() -> None:
    if os.getenv("KEEMU_TEST_SCRIPT_ADVERSARIAL") != "1":
        pytest.skip("opt in to owned AArch64 script adversarial Docker/binfmt probe")


def _snapshot() -> dict[str, list[str]]:
    return {
        kind: sorted(DockerRuntime.listed_ids(kind))
        for kind in ("container", "network")
    }


def _record(key: str, value: dict) -> None:
    # Each independent case publishes only bounded non-secret observations.
    OBSERVATIONS.parent.mkdir(exist_ok=True)
    observed = json.loads(OBSERVATIONS.read_text()) if OBSERVATIONS.exists() else {}
    observed[key] = value
    OBSERVATIONS.write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n")


def _recover_one_shot(runtime: DockerRuntime, identifier: str) -> None:
    owned = runtime.reconcile(expected_containers={identifier})
    assert owned["container_owned"] == [identifier]
    assert not owned["network_owned"] and not owned["container_unexpected"]
    item = runtime.inspect("container", identifier)
    assert item["Name"] == "/keemu-" + runtime.run_id
    runtime.remove_container(identifier)
    assert not runtime.reconcile()["container_owned"]
    assert not runtime.reconcile()["network_owned"]


@pytest.mark.docker
def test_real_stage_race_collision_retry_and_foreign_preservation(monkeypatch):
    _enabled()
    before = _snapshot()
    foreign_run = "m1d11-foreign-" + uuid.uuid4().hex[:12]
    own_run = "m1d11-stage-" + uuid.uuid4().hex[:12]
    foreign = DockerRuntime(foreign_run, IMAGE)
    runtime = DockerRuntime(own_run, IMAGE)
    foreign_id = foreign.create("keemu-" + foreign_run)
    container = None
    try:
        foreign.start(foreign_id)
        foreign_state = foreign.inspect("container", foreign_id)["State"]
        container = runtime.create("keemu-" + own_run)
        runtime.start(container)
        host = runtime.inspect("container", container)["HostConfig"]
        assert not host["Privileged"] and host["NetworkMode"] == "none"
        assert not host["PidMode"] and not host.get("Binds")
        assert not host.get("Mounts") and not host.get("CapAdd")
        assert "ALL" in host["CapDrop"] and not host.get("PortBindings")
        monkeypatch.setenv("KEEMU_HOST_SECRET_SENTINEL", "host-only-value")
        assert (
            runtime.exec(
                container,
                [
                    "/bin/sh",
                    "-c",
                    'test -z "${KEEMU_HOST_SECRET_SENTINEL+x}" && '
                    "test ! -e /var/run/docker.sock && test ! -e /opt/data/workspace/keemu",
                ],
            ).exit_code
            == 0
        )
        (ROOT / ".runtime").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".runtime", prefix="m1d11-"
        ) as folder:
            path = Path(folder) / "input.sh"
            original = b"#!/bin/sh\nprintf 'original\\n'\n"
            path.write_bytes(original)
            source = ScriptInput.validate(path.relative_to(ROOT), project_root=ROOT)
            # Same-byte inode replacement between validation and stage fails closed.
            replacement = Path(folder) / "next.sh"
            replacement.write_bytes(original)
            os.replace(replacement, path)
            with pytest.raises(ScriptInputChanged):
                source.recheck_for_staging()
            source = ScriptInput.validate(path.relative_to(ROOT), project_root=ROOT)
            stager = ScriptStager(runtime)
            monkeypatch.setattr(
                "keemu.script_stage.secrets.token_hex", lambda _: "b" * 24
            )
            original_identity = stager._identity
            mutated = False

            def change_after_recheck(container_id, target, *, directory):
                nonlocal mutated
                if target == "/opt/tmp" and not mutated:
                    mutated = True
                    path.write_bytes(b"#!/bin/sh\nexit 99\n")
                return original_identity(container_id, target, directory=directory)

            with monkeypatch.context() as patch:
                patch.setattr(stager, "_identity", change_after_recheck)
                staged = stager.stage(source, container)
            assert mutated
            assert staged.sha256 == hashlib.sha256(original).hexdigest()
            stager.verify(staged)
            with pytest.raises(ScriptInputChanged):
                source.recheck_for_staging()
            # Deterministic nonce collision may neither overwrite nor acquire cleanup.
            path.write_bytes(original)
            with pytest.raises(DockerBoundaryError):
                stager.stage(
                    ScriptInput.validate(path.relative_to(ROOT), project_root=ROOT),
                    container,
                )
            stager.verify(staged)
            original_exec = stager._exec
            refused = False

            def refuse_once(container_id, command, *args, **kwargs):
                nonlocal refused
                if not refused and 'rm -- "$file"' in command:
                    refused = True
                    raise DockerBoundaryError("injected cleanup refusal")
                return original_exec(container_id, command, *args, **kwargs)

            with monkeypatch.context() as patch:
                patch.setattr(stager, "_exec", refuse_once)
                assert not stager.cleanup(staged).success
            assert refused
            stager.verify(staged)
            assert stager.cleanup(staged).success
            # Another stage: replace issued target inode with foreign test-owned bytes.
            source = ScriptInput.validate(path.relative_to(ROOT), project_root=ROOT)
            monkeypatch.setattr(
                "keemu.script_stage.secrets.token_hex", lambda _: "c" * 24
            )
            swapped = stager.stage(source, container)
            directory = swapped.path.rsplit("/", 1)[0]
            runtime.exec(
                container,
                [
                    "/bin/sh",
                    "-c",
                    'printf foreign > "$1" && /opt/bin/busybox mv -- "$1" "$2"',
                    "m1d11-test",
                    directory + "/replacement",
                    swapped.path,
                ],
            )
            assert not stager.cleanup(swapped).success
            assert (
                runtime.exec(
                    container, ["/opt/bin/busybox", "cat", swapped.path]
                ).stdout
                == b"foreign"
            )
            # Test teardown, not production adoption: remove only exact test-owned path.
            runtime.exec(container, ["/opt/bin/busybox", "rm", swapped.path])
            runtime.exec(container, ["/opt/bin/busybox", "rmdir", directory])
            _record(
                "stage",
                {
                    "same_byte_inode_swap": "BLOCKED",
                    "post_recheck_source_mutation": "frozen_target_digest_verified",
                    "collision": "existing_target_preserved",
                    "injected_cleanup": "refused_then_exact_retry_passed",
                    "target_inode_replacement": "cleanup_refused_foreign_bytes_preserved",
                    "host_isolation": "network_none_cap_drop_no_mount_socket_or_host_env",
                },
            )
        assert foreign.inspect("container", foreign_id)["State"] == foreign_state
    finally:
        if container is not None:
            _recover_one_shot(runtime, container)
        foreign.remove_container(foreign_id)
    assert _snapshot() == before


@pytest.mark.docker
def test_sigkill_at_allocation_stage_and_active_timeout_preserves_foreign():
    _enabled()
    before = _snapshot()
    foreign_run = "m1d11-foreign-" + uuid.uuid4().hex[:12]
    foreign = DockerRuntime(foreign_run, IMAGE)
    foreign_id = foreign.create("keemu-" + foreign_run)
    observations = {}
    try:
        foreign.start(foreign_id)
        foreign_state = foreign.inspect("container", foreign_id)["State"]
        (ROOT / ".runtime").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=ROOT / ".runtime", prefix="m1d11-kill-"
        ) as folder:
            directory = Path(folder)
            active_source = directory / "long.sh"
            active_source.write_bytes(
                b"#!/bin/sh\nprintf '%s\\n' \"$$\" > /opt/tmp/m1d11-active-"
                + foreign_run.encode()
                + b"\n"
                b"/opt/bin/busybox sleep 120\n"
            )
            for phase in ("after-create", "after-stage", "active"):
                run_id = "m1d11-kill-" + uuid.uuid4().hex[:12]
                runtime = DockerRuntime(run_id, IMAGE)
                marker = directory / (phase + ".json")
                report_root = directory / "run-reports"
                # Child uses Python's API, never host-shell execution of input.
                child_code = """import json, time
from pathlib import Path
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_stage import ScriptStager
from keemu.script_process import ScriptProcessRunner
root, source, run_id, phase, marker, reports = __import__('sys').argv[1:]
if phase == 'after-create':
    original = ScriptStager.stage
    def gate(self, script, container):
        Path(marker).write_text(json.dumps({'container':container}))
        time.sleep(30)
        return original(self, script, container)
    ScriptStager.stage = gate
if phase == 'after-stage':
    original = ScriptProcessRunner.run
    def gate(self, staged, **kwargs):
        Path(marker).write_text(json.dumps({'container':staged.container_id, 'path':staged.path}))
        time.sleep(30)
        return original(self, staged, **kwargs)
    ScriptProcessRunner.run = gate
run_one_shot_script(source, project_root=Path(root), run_id=run_id,
                    report_root=Path(reports), timeout_seconds=3)
"""
                source = (
                    active_source.relative_to(ROOT)
                    if phase == "active"
                    else Path("fixtures/scripts/mvp1d/success.sh")
                )
                worker = subprocess.Popen(  # noqa: S603 -- fixed Python argv, no shell
                    [
                        sys.executable,
                        "-c",
                        child_code,
                        str(ROOT),
                        str(source),
                        run_id,
                        phase,
                        str(marker),
                        str(report_root),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                identifier = None
                try:
                    deadline = time.monotonic() + 35
                    while time.monotonic() < deadline:
                        owned = runtime.reconcile()["container_owned"]
                        if len(owned) == 1:
                            identifier = owned[0]
                        if phase != "active" and marker.exists():
                            break
                        if phase == "active" and identifier:
                            result = runtime.exec(
                                identifier,
                                [
                                    "/bin/sh",
                                    "-c",
                                    'test -s "$1" && /opt/bin/busybox cat -- "$1"',
                                    "m1d11-test",
                                    "/opt/tmp/m1d11-active-" + foreign_run,
                                ],
                                allow_failure=True,
                            )
                            if result.exit_code == 0:
                                marker.write_text(
                                    json.dumps(
                                        {
                                            "container": identifier,
                                            "shell_pid": int(result.stdout),
                                        }
                                    )
                                )
                                break
                        if worker.poll() is not None:
                            pytest.fail(
                                f"worker exited before {phase} barrier: {worker.returncode}"
                            )
                        time.sleep(0.1)
                    assert marker.exists() and identifier is not None, phase
                    evidence = json.loads(marker.read_text())
                    assert evidence["container"] == identifier
                    if phase == "after-stage":
                        assert evidence["path"].startswith("/opt/tmp/keemu-script-")
                        assert (
                            runtime.exec(
                                identifier,
                                ["/opt/bin/busybox", "test", "-f", evidence["path"]],
                            ).exit_code
                            == 0
                        )
                    assert worker.poll() is None, phase
                    os.kill(worker.pid, signal.SIGKILL)
                    assert worker.wait(timeout=5) == -signal.SIGKILL
                    assert not (report_root / run_id).exists()
                    if phase == "active":
                        # Host worker death supplies no helper response. Wait for the
                        # independently observed target PID to die, never infer PASS.
                        pid = evidence["shell_pid"]
                        deadline = time.monotonic() + 12
                        live = None
                        while time.monotonic() < deadline:
                            live = runtime.exec(
                                identifier,
                                ["/opt/bin/busybox", "kill", "-0", str(pid)],
                                allow_failure=True,
                            )
                            if live.exit_code != 0:
                                break
                            time.sleep(0.25)
                        assert live is not None and live.exit_code != 0, (
                            "script survived its target helper timeout"
                        )
                        evidence = {"script_descendant_absent_after_bounded_wait": True}
                    else:
                        evidence = {
                            "owned_container_found": True,
                            "target_copy_present": phase == "after-stage",
                        }
                    observations[phase] = evidence
                    assert (
                        foreign.inspect("container", foreign_id)["State"]
                        == foreign_state
                    )
                finally:
                    if worker.poll() is None:
                        os.kill(worker.pid, signal.SIGKILL)
                        worker.wait(timeout=5)
                    if identifier is not None:
                        _recover_one_shot(runtime, identifier)
            _record(
                "interruption",
                {
                    **observations,
                    "reports": "none_after_SIGKILL_no_false_PASS",
                    "recovery": "explicit_exact_owner_full_ID_container_removal",
                    "foreign": "same_ID_and_state_through_all_phases",
                },
            )
    finally:
        foreign.remove_container(foreign_id)
    assert _snapshot() == before
