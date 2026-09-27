"""Opt-in real target process-tree timeout and foreign-process preservation."""

import os
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerRuntime
from keemu.script_input import ScriptInput
from keemu.script_process import ScriptProcessRunner
from keemu.script_stage import ScriptStager

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"


@pytest.mark.docker
def test_target_timeout_reaps_descendants_preserves_foreign():
    if os.getenv("KEEMU_TEST_SCRIPT_PROCESS") != "1":
        pytest.skip("opt in to owned AArch64 Docker/binfmt script process probe")
    run_id = "m1d04-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run_id, IMAGE)
    root = Path(__file__).resolve().parents[2]
    stager = ScriptStager(runtime)
    runner = ScriptProcessRunner(stager)
    container = runtime.create("keemu-" + run_id)
    staged = None
    foreign = None
    try:
        runtime.start(container)
        foreign = int(
            runtime.exec(
                container,
                [
                    "/bin/sh",
                    "-c",
                    "/opt/bin/busybox sleep 120 </dev/null >/dev/null 2>&1 & "
                    'printf "%s" "$!"',
                ],
            ).stdout
        )
        live = ["/opt/bin/busybox", "kill", "-0", str(foreign)]
        assert runtime.exec(container, live, allow_failure=True).exit_code == 0
        script = ScriptInput.validate(
            "fixtures/scripts/mvp1d/timeout-process.sh", project_root=root
        )
        staged = stager.stage(script, container)
        result = runner.run(staged, timeout_seconds=1)
        assert result.timed_out and result.process_tree_clean, (
            result.exit_code,
            result.duration_seconds,
        )
        assert result.duration_seconds < 8
        assert result.stdout.startswith(b"child=")
        child = int(result.stdout.partition(b"\n")[0].split(b"=")[1])
        assert child != foreign
        assert (
            runtime.exec(
                container,
                ["/opt/bin/busybox", "kill", "-0", str(child)],
                allow_failure=True,
            ).exit_code
            != 0
        )
        assert runtime.exec(container, live, allow_failure=True).exit_code == 0
        assert stager.cleanup(staged).success
        staged = None
    finally:
        if staged is not None:
            assert stager.cleanup(staged).success
        if foreign is not None:
            runtime.exec(
                container,
                ["/opt/bin/busybox", "kill", str(foreign)],
                allow_failure=True,
            )
        runtime.remove_container(container)
        assert runtime.reconcile()["container_owned"] == []


@pytest.mark.docker
def test_target_exit_argv_streams_and_term_resistant_tree(tmp_path, monkeypatch):
    if os.getenv("KEEMU_TEST_SCRIPT_PROCESS") != "1":
        pytest.skip("opt in to owned AArch64 Docker/binfmt script process probe")
    run_id = "m1d04-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run_id, IMAGE)
    stager = ScriptStager(runtime)
    runner = ScriptProcessRunner(stager)
    container = runtime.create("keemu-" + run_id)
    staged = None
    try:
        runtime.start(container)
        monkeypatch.setenv("KEEMU_HOST_SECRET_SENTINEL", "not-in-target")
        (tmp_path / "args.sh").write_bytes(
            b'test -z "${KEEMU_HOST_SECRET_SENTINEL+x}" || exit 99\n'
            b'printf "arg=%s\\n" "$1"; printf "error\\n" >&2; exit 7\n'
        )
        staged = stager.stage(
            ScriptInput.validate("args.sh", project_root=tmp_path), container
        )
        value = "literal;$(false)"
        result = runner.run(staged, timeout_seconds=3, argv=(value,))
        assert not result.timed_out and result.process_tree_clean
        assert result.exit_code == 7
        assert result.stdout == f"arg={value}\n".encode()
        assert result.stderr == b"error\n"
        assert not result.truncated_stdout and not result.truncated_stderr
        assert stager.cleanup(staged).success
        staged = None

        (tmp_path / "output.sh").write_bytes(
            b'/opt/bin/busybox head -c 1048600 /dev/zero\nprintf "err" >&2\n'
        )
        staged = stager.stage(
            ScriptInput.validate("output.sh", project_root=tmp_path), container
        )
        result = runner.run(staged, timeout_seconds=5)
        assert result.exit_code == 0 and result.process_tree_clean
        assert len(result.stdout) == 1024 * 1024 and result.truncated_stdout
        assert result.stderr == b"err" and not result.truncated_stderr
        assert stager.cleanup(staged).success
        staged = None

        (tmp_path / "resistant.sh").write_bytes(
            b"/bin/sh -c "
            b"'trap \"\" TERM; while :; do /opt/bin/busybox sleep 2; done' "
            b'</dev/null &\nwait "$!"\n'
        )
        staged = stager.stage(
            ScriptInput.validate("resistant.sh", project_root=tmp_path), container
        )
        result = runner.run(staged, timeout_seconds=1)
        assert result.timed_out and result.process_tree_clean, (
            result.exit_code,
            result.duration_seconds,
        )
        assert 2 <= result.duration_seconds < 8  # TERM then KILL after grace
        assert stager.cleanup(staged).success
        staged = None

        (tmp_path / "orphan.sh").write_bytes(
            b"/opt/bin/busybox sleep 120 </dev/null >/dev/null 2>&1 & "
            b'printf "orphan=%s\n" "$!"\n'
        )
        staged = stager.stage(
            ScriptInput.validate("orphan.sh", project_root=tmp_path), container
        )
        result = runner.run(staged, timeout_seconds=1)
        assert result.timed_out and result.process_tree_clean
        orphan = int(result.stdout.split(b"=", 1)[1])
        assert (
            runtime.exec(
                container,
                ["/opt/bin/busybox", "kill", "-0", str(orphan)],
                allow_failure=True,
            ).exit_code
            != 0
        )
        assert stager.cleanup(staged).success
        staged = None
    finally:
        if staged is not None:
            assert stager.cleanup(staged).success
        runtime.remove_container(container)
        assert runtime.reconcile()["container_owned"] == []
