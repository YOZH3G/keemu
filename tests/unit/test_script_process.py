"""Supervisor response, input bounds and ownership failure contracts."""

import hashlib

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.script_process import ScriptProcessError, ScriptProcessRunner, _decode
from keemu.script_stage import StagedScript, TargetIdentity

CID = "b" * 64
IMAGE = "sha256:" + "a" * 64


def _frame(code=0, timed=0, clean=1, stdout=b"a", stderr=b"b"):
    return (
        f"KEEMU1 {code} {timed} {clean} 100 {len(stdout)} {len(stderr)} 0 0\n".encode()
        + stdout
        + stderr
    )


def test_framed_streams_exit_and_timeout():
    result = _decode(_frame(code=7, stdout=b"\x00raw", stderr=b"err"))
    assert (result.exit_code, result.stdout, result.stderr) == (7, b"\x00raw", b"err")
    assert result.process_tree_clean and not result.timed_out
    result = _decode(_frame(code=-1, timed=1, clean=0))
    assert result.timed_out and not result.process_tree_clean
    assert result.exit_code is None
    assert hashlib.sha256(result.stdout).hexdigest() == hashlib.sha256(b"a").hexdigest()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"KEEMU1 0 0 1 1 1 0 0 0\n",
        _frame() + b"junk",
        b"KEEMU1 0 0 1 1 1048577 0 0 0\n",
        _frame(code=-1),
        _frame(code=256),
        _frame(clean=2),
        b"KEEMU1 0 0 1 1 1 1 0 0\na",
    ],
)
def test_corrupt_frame_fails_closed(data):
    with pytest.raises(ScriptProcessError):
        _decode(data)


class ForeignRuntime(DockerRuntime):
    def __init__(self):
        super().__init__("owned-run", IMAGE)
        self.calls = 0

    def inspect(self, kind, identifier):
        self.calls += 1
        raise DockerBoundaryError("container ownership labels mismatch")


def _staged(runtime):
    identity = TargetIdentity(1, 2, 0o100600, 1, 1, 0)
    return StagedScript(
        CID,
        runtime.run_id,
        IMAGE,
        runtime.target,
        "/opt/tmp/keemu-script-" + "a" * 64 + "-" + "b" * 24 + "/script.sh",
        "a" * 64,
        1,
        identity,
        identity,
        identity,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 601},
        {"timeout_seconds": True},
        {"cwd": "/other"},
        {"cwd": "/opt/../tmp"},
        {"argv": ("x\x00y",)},
        {"argv": ("x",) * 127},
    ],
)
def test_refuse_invalid_intent_before_any_mutation(kwargs):
    from keemu.script_stage import ScriptStager

    runtime = ForeignRuntime()
    runner = ScriptProcessRunner(ScriptStager(runtime))
    with pytest.raises(ScriptProcessError):
        runner.run(_staged(runtime), **kwargs)
    assert runtime.calls == 0


def test_foreign_container_refused_before_build_or_target_mutation(monkeypatch):
    from keemu.script_stage import ScriptStager

    runtime = ForeignRuntime()
    stager = ScriptStager(runtime)
    staged = _staged(runtime)
    stager._issued[staged.path] = staged
    runner = ScriptProcessRunner(stager)
    monkeypatch.setattr(
        "keemu.script_process._helper_bytes", lambda: pytest.fail("built")
    )
    with pytest.raises(DockerBoundaryError, match="ownership"):
        runner.run(staged)
    assert runtime.calls == 1
