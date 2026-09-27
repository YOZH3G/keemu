"""Opt-in real Docker/binfmt staging probe; never execute script content."""

import os
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.script_input import ScriptInput
from keemu.script_stage import ScriptStageError, ScriptStager

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"


@pytest.mark.docker
def test_target_script_stage_integrity_collision_and_exact_cleanup(monkeypatch):
    if os.getenv("KEEMU_TEST_SCRIPT_STAGE") != "1":
        pytest.skip("opt in to owned AArch64 Docker/binfmt script staging")
    run_id = "m1d02-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run_id, IMAGE)
    try:
        runtime.image()
    except DockerBoundaryError as exc:
        pytest.skip(f"locked AArch64 image unavailable: {exc}")
    root = Path(__file__).resolve().parents[2]
    script = ScriptInput.validate(
        "fixtures/scripts/mvp1d/success.sh", project_root=root
    )
    stager = ScriptStager(runtime)
    container = runtime.create("keemu-" + run_id)
    staged = None
    try:
        runtime.start(container)
        monkeypatch.setattr(
            "keemu.script_stage.secrets.token_hex", lambda size: "c" * (size * 2)
        )
        staged = stager.stage(script, container)
        stager.verify(staged)
        assert staged.sha256 == script.sha256
        with pytest.raises(ScriptStageError, match="reservation failed"):
            stager.stage(script, container)
        stager.verify(staged)  # collision neither overwrote nor claimed cleanup
        monkeypatch.setattr(
            "keemu.script_stage.secrets.token_hex", lambda size: "d" * (size * 2)
        )
        # A repeat input with a new nonce gets an independent object.
        other = stager.stage(script, container)
        try:
            assert other.path != staged.path
            stager.verify(staged)
        finally:
            assert stager.cleanup(other).success
        monkeypatch.setattr(
            "keemu.script_stage.secrets.token_hex", lambda size: "e" * (size * 2)
        )
        original_exec = stager._exec
        injected = None

        def collide_at_file(container_id, command, *args, **kwargs):
            nonlocal injected
            if "set -C && /opt/bin/busybox cat >" in command:
                injected = args[1]
                runtime.exec(
                    container_id,
                    [
                        "/bin/sh",
                        "-c",
                        'set -C; /opt/bin/busybox printf collision > "$1"',
                        "keemu-test",
                        injected,
                    ],
                )
            return original_exec(container_id, command, *args, **kwargs)

        monkeypatch.setattr(stager, "_exec", collide_at_file)
        try:
            with pytest.raises(ScriptStageError) as collision:
                stager.stage(script, container)
            assert collision.value.cleanup is not None
            assert not collision.value.cleanup.success
            assert injected is not None
            assert (
                runtime.exec(
                    container,
                    ["/opt/bin/busybox", "cat", "--", injected],
                ).stdout
                == b"collision"
            )
        finally:
            if injected is not None:
                runtime.exec(
                    container,
                    [
                        "/bin/sh",
                        "-c",
                        'test ! -L "$1" && test -f "$1" && '
                        '/opt/bin/busybox rm -- "$1" && '
                        '/opt/bin/busybox rmdir -- "$2"',
                        "keemu-test",
                        injected,
                        injected.rsplit("/", 1)[0],
                    ],
                )
            monkeypatch.setattr(stager, "_exec", original_exec)
        assert stager.cleanup(staged).success
        staged = None
    finally:
        if staged is not None:
            result = stager.cleanup(staged)
            assert result.success, result.error
        runtime.remove_container(container)
        assert not runtime.reconcile()["container_owned"]
