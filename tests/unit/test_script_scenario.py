"""Scenario dispatch preserves source snapshot, typed status and redaction."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from keemu.scenarios import ScriptCheck
from keemu.script_input import ScriptInput
from keemu.script_results import ScriptExecutionResult
from keemu.script_scenario import ScenarioScriptError, run_script_check


def test_scenario_shared_dispatch_and_immutable_input(tmp_path, monkeypatch):
    script = tmp_path / "probe.sh"
    script.write_bytes(b"#!/bin/sh\necho private-output\nexit 7\n")
    source = ScriptInput.validate(script, project_root=tmp_path)
    check = ScriptCheck(
        id="probe",
        kind="script",
        path="probe.sh",
        expected_exit_code=7,
        argv=("literal;$(id)",),
        stdout_contains=("private-output",),
    )
    state = {"clean": True, "exit": 7, "calls": []}

    class Stager:
        def __init__(self, runtime):
            self.runtime = runtime

        def stage(self, source_input, container):
            assert source_input.recheck_for_staging() == source._bytes
            assert container == "owned"
            state["calls"].append("stage")
            return SimpleNamespace(container_id=container)

        def cleanup(self, staged):
            state["calls"].append("cleanup")
            return SimpleNamespace(success=state["clean"])

    class Runner:
        def __init__(self, stager):
            pass

        def run(self, staged, **kwargs):
            assert kwargs == {
                "timeout_seconds": 60,
                "cwd": "/opt",
                "argv": ("literal;$(id)",),
            }
            state["calls"].append("run")
            return ScriptExecutionResult(
                state="executed",
                exit_code=state["exit"],
                timed_out=False,
                process_tree_clean=True,
                duration_seconds=0.01,
                stdout=b"private-output\n",
                stderr=b"",
                truncated_stdout=False,
                truncated_stderr=False,
            )

    monkeypatch.setattr("keemu.script_scenario.ScriptStager", Stager)
    monkeypatch.setattr("keemu.script_scenario.ScriptProcessRunner", Runner)
    result = run_script_check(check, source, object(), "owned")
    assert result.status == "PASS"
    assert "private-output" not in result.evidence
    assert "literal;$(id)" not in result.evidence
    assert source.sha256 in result.evidence
    assert state["calls"] == ["stage", "run", "cleanup"]
    state["exit"] = 0
    assert run_script_check(check, source, object(), "owned").status == "FAIL"
    state["clean"] = False
    with pytest.raises(ScenarioScriptError, match="script-cleanup-unverified"):
        run_script_check(check, source, object(), "owned")
    state["clean"] = True
    state["calls"].clear()
    script.write_bytes(b"#!/bin/sh\necho changed\n")
    with pytest.raises(ScenarioScriptError) as caught:
        run_script_check(check, source, object(), "owned")
    assert caught.value.status == "BLOCKED"
    assert state["calls"] == []
