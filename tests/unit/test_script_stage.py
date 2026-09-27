"""D02 staging contract: all script bytes stay opaque to the host shell."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from keemu import docker_runtime as dr
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_stage import ScriptStageError, ScriptStager

CID = "b" * 64
IMAGE = "sha256:" + "a" * 64


class FakeRuntime:
    run_id = "owned-run"
    image_id = IMAGE
    target = "aarch64-3.10"

    def __init__(self):
        self.running = True
        self.foreign = False
        self.tmp = (1, 2, 0o40755, 3, 0, 0)
        self.dir_id = (1, 3, 0o40700, 2, 0, 0)
        self.file_id = (1, 4, 0o100600, 1, 0, 0)
        self.directory = None
        self.file = None
        self.file_bytes = None
        self.corrupt = False
        self.fail_remove = False
        self.fail_upload = False
        self.file_collision = False
        self.relabel_after_mkdir = False
        self.inspections = 0
        self.calls = []

    def inspect(self, kind, identifier):
        assert kind == "container" and identifier == CID
        self.inspections += 1
        if self.foreign:
            raise dr.DockerBoundaryError("container ownership labels mismatch")
        return {"State": {"Running": self.running}}

    @staticmethod
    def _stat(path, data):
        return (
            f"{path} {data[4]} 0 {data[2]:x} {data[5]} {data[5]} "
            f"{data[0]:x} {data[1]} {data[3]} 0 0 0 0 0 4096\n"
        ).encode()

    def exec(self, identifier, argv, *, input_data=None, timeout=30):
        self.inspect("container", identifier)
        assert argv[:4] == ["/bin/sh", "-c", argv[2], "keemu-stage"]
        command, args = argv[2], argv[4:]
        assert "echo" not in command and "eval" not in command
        self.calls.append((command, args, input_data))
        if command.startswith("test ! -L") and "stat -t" in command and len(args) == 1:
            path = args[0]
            if path == "/opt/tmp":
                value = self.tmp
            elif path == self.directory and self.directory is not None:
                value = self.dir_id
            elif path == self.file and self.file is not None:
                value = (*self.file_id[:4], len(self.file_bytes), self.file_id[5])
            else:
                raise dr.DockerBoundaryError("target object missing")
            return dr.Output(self._stat(path, value), b"")
        if "mkdir -m 700" in command:
            if self.directory is not None:
                raise dr.DockerBoundaryError("target directory collision")
            self.directory = args[0]
            if self.relabel_after_mkdir:
                self.foreign = True
            return dr.Output(b"", b"")
        if "set -C && /opt/bin/busybox cat >" in command:
            assert input_data is not None and timeout == 90
            if self.fail_upload:
                self.file = args[1]
                self.file_bytes = input_data[:2]
                raise dr.DockerBoundaryError("transfer interrupted")
            if self.file_collision and self.file is None:
                self.file = args[1]
                self.file_bytes = b"foreign"
            if self.file is not None or self.directory != args[0]:
                raise dr.DockerBoundaryError("no-clobber refused")
            self.file = args[1]
            self.file_bytes = input_data
            return dr.Output(b"", b"")
        if command == '/opt/bin/busybox cat -- "$1"':
            assert self.file == args[0]
            data = self.file_bytes
            if self.corrupt:
                data = b"X" + data[1:]
            return dr.Output(data, b"")
        if "rm --" in command:
            if self.fail_remove:
                raise dr.DockerBoundaryError("target rm failed")
            assert self.directory == args[0] and self.file == args[1]
            expected = (
                f"{len(self.file_bytes)}:{self.file_id[2]:x}:"
                f"{self.file_id[5]}:{self.file_id[0]:x}:"
                f"{self.file_id[1]}:{self.file_id[3]}"
            )
            if args[2] != expected:
                raise dr.DockerBoundaryError("target inode replaced")
            self.file = self.file_bytes = self.directory = None
            return dr.Output(b"", b"")
        if command.startswith("/opt/bin/busybox rmdir --"):
            if self.file is not None:
                raise dr.DockerBoundaryError("directory not empty")
            self.directory = None
            return dr.Output(b"", b"")
        if "test ! -e" in command:
            if self.directory or self.file:
                raise dr.DockerBoundaryError("target still exists")
            return dr.Output(b"", b"")
        pytest.fail(f"unexpected target command: {command}")


def _script(tmp_path: Path, content: bytes = b"#!/bin/sh\nprintf safe\n"):
    (tmp_path / "input.sh").write_bytes(content)
    return ScriptInput.validate("input.sh", project_root=tmp_path)


def test_stage_digest_path_no_clobber_readback_and_exact_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "keemu.script_stage.secrets.token_hex", lambda count: "a" * (2 * count)
    )
    script = _script(tmp_path, b"\0' ; $(bad) \xff")
    runtime = FakeRuntime()
    stager = ScriptStager(runtime)
    staged = stager.stage(script, CID)
    assert staged.path == f"/opt/tmp/keemu-script-{script.sha256}-{'a' * 24}/script.sh"
    assert staged.sha256 == hashlib.sha256(runtime.file_bytes).hexdigest()
    assert runtime.file_bytes == script.recheck_for_staging()
    assert runtime.file == staged.path
    assert sum(call[2] is not None for call in runtime.calls) == 1
    assert all(
        script.recheck_for_staging().decode("latin-1") not in command
        for command, _, _ in runtime.calls
    )
    with pytest.raises(ScriptStageError, match="reservation failed") as exc:
        ScriptStager(runtime).stage(script, CID)
    assert exc.value.cleanup is None  # mkdir collision is never cleanup authority
    assert runtime.file_bytes == script.recheck_for_staging()
    assert stager.cleanup(staged).success
    assert runtime.file is runtime.directory is None
    assert stager.cleanup(staged).success is False  # stale authority never reused


def test_file_collision_refuses_overwrite_and_foreign_relabel(tmp_path):
    script = _script(tmp_path)
    collision = FakeRuntime()
    collision.file_collision = True
    with pytest.raises(ScriptStageError) as exc:
        ScriptStager(collision).stage(script, CID)
    assert not exc.value.cleanup.success
    assert collision.file_bytes == b"foreign"
    assert all("rm --" not in command for command, _, _ in collision.calls)

    relabelled = FakeRuntime()
    relabelled.relabel_after_mkdir = True
    with pytest.raises(ScriptStageError, match="reservation failed"):
        ScriptStager(relabelled).stage(script, CID)
    assert relabelled.directory is not None and relabelled.file is None
    assert relabelled.inspections >= 3


def test_changed_source_and_foreign_container_never_mutate(tmp_path):
    script = _script(tmp_path)
    runtime = FakeRuntime()
    (tmp_path / "input.sh").write_bytes(b"replacement")
    with pytest.raises(ScriptInputChanged):
        ScriptStager(runtime).stage(script, CID)
    assert runtime.calls == []
    script = ScriptInput.validate("input.sh", project_root=tmp_path)
    runtime.foreign = True
    with pytest.raises(dr.DockerBoundaryError, match="ownership"):
        ScriptStager(runtime).stage(script, CID)
    assert runtime.calls == []


def test_corrupt_readback_rolls_back_exact_inode(tmp_path):
    runtime = FakeRuntime()
    runtime.corrupt = True
    with pytest.raises(ScriptStageError, match="staging failed") as exc:
        ScriptStager(runtime).stage(_script(tmp_path), CID)
    assert exc.value.cleanup.success
    assert runtime.file is runtime.directory is None


def test_partial_transfer_retained_when_inode_not_proven(tmp_path):
    runtime = FakeRuntime()
    runtime.fail_upload = True
    with pytest.raises(ScriptStageError, match="staging failed") as exc:
        ScriptStager(runtime).stage(_script(tmp_path), CID)
    assert not exc.value.cleanup.success
    assert runtime.file_bytes == b"#!"
    assert runtime.directory is not None
    assert all("rm --" not in call[0] for call in runtime.calls)


def test_replacement_parent_and_cleanup_error_fail_closed(tmp_path):
    runtime = FakeRuntime()
    stager = ScriptStager(runtime)
    staged = stager.stage(_script(tmp_path), CID)
    runtime.file_id = (1, 55, 0o100600, 1, 0, 0)
    assert not stager.cleanup(staged).success
    assert runtime.file == staged.path
    runtime.file_id = (1, 4, 0o100600, 1, 0, 0)
    runtime.tmp = (1, 99, 0o40755, 3, 0, 0)
    assert not stager.cleanup(staged).success
    runtime.tmp = (1, 2, 0o40755, 3, 0, 0)
    runtime.fail_remove = True
    result = stager.cleanup(staged)
    assert not result.success and "target rm failed" in result.error
    assert runtime.file == staged.path
    runtime.fail_remove = False
    assert stager.cleanup(staged).success


def test_no_running_container_or_shared_directory(tmp_path):
    runtime = FakeRuntime()
    runtime.running = False
    with pytest.raises(ScriptStageError, match="running"):
        ScriptStager(runtime).stage(_script(tmp_path), CID)
    runtime.running = True
    runtime.dir_id = (1, 3, 0o40777, 2, 0, 0)
    with pytest.raises(ScriptStageError) as exc:
        ScriptStager(runtime).stage(_script(tmp_path), CID)
    assert not exc.value.cleanup.success


@pytest.mark.parametrize(
    "content", [b"", b"z" * (1024 * 1024)], ids=["empty", "maximum"]
)
def test_bounded_binary_stdin_transfer_without_shell_reparse(monkeypatch, content):
    original = subprocess.Popen

    def substitute(_argv, **kwargs):
        return original(
            [
                sys.executable,
                "-c",
                "import hashlib,sys; "
                "sys.stdout.write(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
            ],
            **kwargs,
        )

    monkeypatch.setattr(dr.subprocess, "Popen", substitute)
    output = dr._exec(
        ["docker", "container", "exec", "-i", CID, "/bin/sh"],
        input_data=content,
        timeout=10,
    )
    assert output.stdout.decode() == hashlib.sha256(content).hexdigest()
    with pytest.raises(dr.DockerBoundaryError, match="stdin"):
        dr._exec(
            ["docker", "container", "exec", "-i", CID],
            input_data=b"x" * (1024 * 1024 + 1),
        )
    with pytest.raises(dr.DockerBoundaryError, match="stdin"):
        dr._exec(["docker", "container", "cp", CID], input_data=b"x")
