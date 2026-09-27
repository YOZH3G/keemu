"""Dispatch a locked scenario script through the shared target staging and runner.

Only redacted identities leave this boundary; output and argv stay in memory.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from keemu.docker_runtime import DockerRuntime
from keemu.scenarios import ScriptCheck
from keemu.script_assertions import ScriptExpectations, check_script_assertions
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_process import ScriptProcessRunner
from keemu.script_results import ScriptCleanupResult, script_status
from keemu.script_stage import ScriptStager


@dataclass(frozen=True)
class ScenarioScriptOutcome:
    status: Literal["PASS", "FAIL", "BLOCKED", "ERROR"]
    evidence: str


class ScenarioScriptError(Exception):
    status: Literal["BLOCKED", "ERROR"]

    def __init__(self, status: Literal["BLOCKED", "ERROR"], reason: str):
        super().__init__(reason)
        self.status = status


def run_script_check(
    check: ScriptCheck, source: ScriptInput, runtime: DockerRuntime, container: str
) -> ScenarioScriptOutcome:
    """Stage checked bytes, run target /bin/sh, assert, then remove exact object."""
    stager = ScriptStager(runtime)
    staged = None
    outcome = None
    assertions = ()
    failure: ScenarioScriptError | None = None
    cleaned = False
    try:
        staged = stager.stage(source, container)  # rechecks immutable host snapshot
        outcome = ScriptProcessRunner(stager).run(
            staged,
            timeout_seconds=check.timeout_seconds,
            cwd=check.cwd,
            argv=check.argv,
        )
        assertions = check_script_assertions(
            outcome,
            check.expected_exit_code,
            ScriptExpectations(
                check.stdout_contains,
                check.stderr_not_contains,
                check.files_exist,
                check.files_absent,
            ),
            stager=stager,
            staged=staged,
        )
    except ScriptInputChanged:
        failure = ScenarioScriptError("BLOCKED", "script-input-changed")
    except Exception:
        failure = ScenarioScriptError("ERROR", "script-execution-unverified")
    finally:
        if staged is not None:
            try:
                cleaned = stager.cleanup(staged).success
            except Exception:
                cleaned = False
    if staged is not None and not cleaned:
        raise ScenarioScriptError("ERROR", "script-cleanup-unverified")
    if failure is not None:
        raise failure
    if outcome is None or staged is None:
        raise ScenarioScriptError("ERROR", "script-execution-unverified")
    status = script_status(
        outcome,
        assertions,
        (ScriptCleanupResult(kind="target-script", attempted=True, verified=True),),
        "persistent",
        target_allocated=True,
        container_allocated=True,
    )
    evidence = (
        f"source_sha256={source.sha256} target_sha256={source.sha256} "
        f"exit={outcome.exit_code} timed_out={outcome.timed_out} "
        f"process_tree_clean={outcome.process_tree_clean} "
        f"stdout_sha256={hashlib.sha256(outcome.stdout).hexdigest()} "
        f"stderr_sha256={hashlib.sha256(outcome.stderr).hexdigest()} "
        f"stdout_bytes={len(outcome.stdout)} stderr_bytes={len(outcome.stderr)} "
        f"truncated_stdout={outcome.truncated_stdout} "
        f"truncated_stderr={outcome.truncated_stderr} "
        f"assertions={','.join(item.kind + ':' + item.status for item in assertions)} "
        "target_cleanup=verified"
    )
    return ScenarioScriptOutcome(status, evidence)
