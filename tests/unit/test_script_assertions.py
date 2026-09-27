"""Shared assertion contract: exact status, redaction, and fail-closed probes."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.docker_runtime import DockerBoundaryError, Output
from keemu.script_assertions import ScriptExpectations, check_script_assertions
from keemu.script_results import (
    ScriptCleanupResult,
    ScriptExecutionResult,
    script_status,
)


class Stage:
    def __init__(self, code: int = 0):
        self.code = code
        self.runtime = self
        self.calls = []

    def _check(self, staged):
        self.calls.append("check")

    def exec(self, container, command, **kwargs):
        assert container == "owner-id"
        assert command[:2] == ["/bin/sh", "-c"]
        assert command[-2] == "keemu-assert"
        assert kwargs == {"allow_failure": True, "timeout": 30}
        self.calls.append(command[-1])
        return Output(b"", b"", exit_code=self.code)


def outcome(**changes):
    values = dict(
        state="executed",
        exit_code=0,
        timed_out=False,
        process_tree_clean=True,
        duration_seconds=0.1,
        stdout=b"public-token\n",
        stderr=b"warning\n",
        truncated_stdout=False,
        truncated_stderr=False,
    )
    values.update(changes)
    return ScriptExecutionResult(**values)


def statuses(result, expectations=None, *, expected_exit_code=0, code=0):
    stage = Stage(code)
    assertions = check_script_assertions(
        result,
        expected_exit_code,
        expectations or ScriptExpectations(),
        stager=stage,
        staged=SimpleNamespace(container_id="owner-id"),
    )
    status = script_status(
        result,
        assertions,
        (ScriptCleanupResult(kind="target-script", attempted=True, verified=True),),
        "persistent",
        target_allocated=True,
        container_allocated=True,
    )
    return assertions, status, stage.calls


def test_exact_pass_fail_blocked_error_mapping_and_redaction():
    expected = ScriptExpectations(
        ("public-token",),
        ("fatal SECRET_NEEDLE",),
        ("/opt/etc/present",),
        ("/opt/etc/absent",),
    )
    assertions, status, calls = statuses(outcome(), expected, code=0)
    assert [item.status for item in assertions] == [
        "PASS",
        "PASS",
        "PASS",
        "PASS",
        "FAIL",
    ]
    assert status == "FAIL"
    assert calls == [
        "check",
        "/opt/etc/present",
        "check",
        "check",
        "/opt/etc/absent",
        "check",
    ]
    assert "SECRET_NEEDLE" not in json.dumps([item.model_dump() for item in assertions])
    assert (
        assertions[2].expected_sha256
        == hashlib.sha256(b"fatal SECRET_NEEDLE").hexdigest()
    )
    assert (
        statuses(outcome(), ScriptExpectations(("public-token",), ("fatal",)))[1]
        == "PASS"
    )
    assert statuses(outcome(exit_code=7))[1] == "FAIL"
    assert statuses(outcome(exit_code=7), expected_exit_code=7)[1] == "PASS"
    assert statuses(outcome(stdout=b""), ScriptExpectations(("missing",)))[1] == "FAIL"
    assert (
        statuses(
            outcome(stderr=b"fatal"), ScriptExpectations(stderr_not_contains=("fatal",))
        )[1]
        == "FAIL"
    )
    assert (
        statuses(
            outcome(stdout=b"", truncated_stdout=True),
            ScriptExpectations(stdout_contains=("missing",)),
        )[1]
        == "BLOCKED"
    )
    assert (
        statuses(
            outcome(stderr=b"", truncated_stderr=True),
            ScriptExpectations(stderr_not_contains=("fatal",)),
        )[1]
        == "BLOCKED"
    )
    assert (
        statuses(
            outcome(stdout=b"public-token", truncated_stdout=True),
            ScriptExpectations(stdout_contains=("public-token",)),
        )[1]
        == "PASS"
    )
    assert statuses(outcome(timed_out=True, exit_code=None), expected)[1] == "FAIL"
    assert (
        statuses(outcome(timed_out=True, exit_code=None, process_tree_clean=False))[1]
        == "ERROR"
    )


def test_filesystem_probe_absence_symlink_and_io_error():
    assert (
        statuses(
            outcome(), ScriptExpectations(files_absent=("/opt/etc/missing",)), code=1
        )[1]
        == "PASS"
    )
    assert (
        statuses(
            outcome(), ScriptExpectations(files_exist=("/opt/etc/missing",)), code=1
        )[1]
        == "FAIL"
    )
    for code in (2, 127):
        with pytest.raises(DockerBoundaryError, match="unverified"):
            statuses(
                outcome(), ScriptExpectations(files_exist=("/opt/etc/link",)), code=code
            )


@pytest.mark.parametrize(
    "values",
    [
        {"files_exist": ("/opt/../etc",)},
        {"files_exist": ("/etc/passwd",)},
        {"files_exist": ("/opt/etc/\nsecret",)},
        {"files_exist": ("/opt//etc",)},
        {"files_exist": ("/opt/etc/link",), "files_absent": ("/opt/etc/link",)},
        {"stdout_contains": ("x" * 257,)},
        {"stderr_not_contains": ("bad\0needle",)},
        {"files_absent": tuple(f"/opt/{i}" for i in range(17))},
    ],
)
def test_invalid_expectations_fail_before_target_mutation(values):
    with pytest.raises(ValueError, match="assertion"):
        ScriptExpectations(**values)


@pytest.mark.parametrize("persistent", [False, True])
def test_cli_forwards_exact_assertions_and_rejects_invalid_paths(
    monkeypatch, persistent
):
    seen = {}

    def fake(*args, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(
            report=SimpleNamespace(
                overall="PASS",
                model_dump=lambda **_: {"overall": "PASS"},
            )
        )

    monkeypatch.setattr(
        "keemu.cli.run_persistent_script"
        if persistent
        else "keemu.cli.run_one_shot_script",
        fake,
    )
    base = (
        ["exec", "fixture", "--script", "input.sh"]
        if persistent
        else ["script", "input.sh", "--profile", "generic-aarch64"]
    )
    options = [
        "--stdout-contains",
        "SECRET_NEEDLE",
        "--stderr-not-contains",
        "fatal",
        "--expect-file",
        "/opt/etc/result",
        "--expect-file-absent",
        "/opt/etc/other",
    ]
    valid = CliRunner().invoke(cli, [*base, *options])
    assert valid.exit_code == 0, valid.output
    assert seen["expectations"] == ScriptExpectations(
        ("SECRET_NEEDLE",), ("fatal",), ("/opt/etc/result",), ("/opt/etc/other",)
    )
    assert "SECRET_NEEDLE" not in valid.output
    seen.clear()
    invalid = CliRunner().invoke(cli, [*base, "--expect-file", "/opt/../etc/passwd"])
    assert invalid.exit_code == 2
    assert not seen
    assert "/etc/passwd" not in invalid.output
    if persistent:
        legacy = CliRunner().invoke(
            cli, ["exec", "fixture", "--expect-file", "/opt/etc/result"]
        )
        assert legacy.exit_code == 2
