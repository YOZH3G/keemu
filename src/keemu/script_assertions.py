"""Bounded in-memory script assertions against checked target execution.

Untrusted needles and target paths never enter the published report. Target
filesystem reads are owner-verified and confined to canonical /opt descendants.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from keemu.docker_runtime import DockerBoundaryError
from keemu.script_results import ScriptAssertionResult, ScriptExecutionResult
from keemu.script_stage import ScriptStager, StagedScript


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _target_path(path: str) -> bool:
    return (
        isinstance(path, str)
        and len(path.encode("utf-8")) <= 4096
        and path.startswith("/opt/")
        and all(part not in {"", ".", ".."} for part in path[5:].split("/"))
        and not any(ord(char) < 32 or ord(char) == 127 for char in path)
    )


@dataclass(frozen=True, slots=True)
class ScriptExpectations:
    stdout_contains: tuple[str, ...] = ()
    stderr_not_contains: tuple[str, ...] = ()
    files_exist: tuple[str, ...] = ()
    files_absent: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        groups = (
            self.stdout_contains,
            self.stderr_not_contains,
            self.files_exist,
            self.files_absent,
        )
        if any(not isinstance(group, tuple) or len(group) > 16 for group in groups):
            raise ValueError("invalid bounded script assertions")
        for group in groups[:2]:
            if any(
                not isinstance(item, str)
                or not item
                or "\0" in item
                or len(item.encode("utf-8")) > 256
                for item in group
            ):
                raise ValueError("invalid bounded script assertions")
        if any(not _target_path(item) for group in groups[2:] for item in group):
            raise ValueError("invalid target assertion path")
        if sum(len(item.encode("utf-8")) for group in groups for item in group) > 8192:
            raise ValueError("script assertions exceed byte cap")
        if set(self.files_exist) & set(self.files_absent):
            raise ValueError("contradictory filesystem assertions")


def _exists(stager: ScriptStager, staged: StagedScript, path: str) -> bool:
    """Distinguish absence from unsafe symlinks/failed probes; never follow links."""
    stager._check(staged)
    # Literal constant shell program; path is a separate argv parameter, never code.
    output = stager.runtime.exec(
        staged.container_id,
        [
            "/bin/sh",
            "-c",
            'p=/opt; if [ -L "$p" ] || [ ! -d "$p" ] || '
            '[ ! -x "$p" ]; then exit 2; fi; '
            "rest=${1#/opt/}; "
            'while [ -n "$rest" ]; do '
            "part=${rest%%/*}; "
            'if [ "$part" = "$rest" ]; then rest=; else rest=${rest#*/}; fi; '
            "p=$p/$part; "
            'if [ -L "$p" ]; then exit 2; fi; '
            'if [ -n "$rest" ] && '
            '{ [ ! -d "$p" ] || [ ! -x "$p" ]; }; then exit 2; fi; '
            "done; "
            'if [ -e "$p" ]; then exit 0; else exit 1; fi',
            "keemu-assert",
            path,
        ],
        allow_failure=True,
        timeout=30,
    )
    stager._check(staged)
    if (
        output.truncated_stdout
        or output.truncated_stderr
        or output.stdout
        or output.stderr
        or output.exit_code not in (0, 1)
    ):
        raise DockerBoundaryError("target filesystem assertion probe unverified")
    return output.exit_code == 0


def check_script_assertions(
    outcome: ScriptExecutionResult,
    expected_exit_code: int,
    expectations: ScriptExpectations,
    *,
    stager: ScriptStager,
    staged: StagedScript,
) -> tuple[ScriptAssertionResult, ...]:
    """Evaluate captured bytes before redaction and filesystem before cleanup."""
    results = [
        ScriptAssertionResult(
            id="exit-code",
            kind="exit-code",
            status="PASS"
            if not outcome.timed_out and outcome.exit_code == expected_exit_code
            else "FAIL",
            reason_code="exit-code-check" if not outcome.timed_out else "timed-out",
            expected_exit_code=expected_exit_code,
        )
    ]
    if outcome.timed_out or not outcome.process_tree_clean:
        # No subsequent observation can certify partial execution or survivors.
        return tuple(results)
    for index, needle in enumerate(expectations.stdout_contains):
        found = needle.encode("utf-8") in outcome.stdout
        results.append(
            ScriptAssertionResult(
                id=f"stdout-contains-{index}",
                kind="stdout-contains",
                status="PASS"
                if found
                else ("BLOCKED" if outcome.truncated_stdout else "FAIL"),
                reason_code="stdout-match"
                if found
                else (
                    "stdout-truncated"
                    if outcome.truncated_stdout
                    else "stdout-mismatch"
                ),
                expected_sha256=_digest(needle),
            )
        )
    for index, needle in enumerate(expectations.stderr_not_contains):
        found = needle.encode("utf-8") in outcome.stderr
        results.append(
            ScriptAssertionResult(
                id=f"stderr-not-contains-{index}",
                kind="stderr-not-contains",
                status="FAIL"
                if found
                else ("BLOCKED" if outcome.truncated_stderr else "PASS"),
                reason_code="stderr-mismatch"
                if found
                else (
                    "stderr-truncated" if outcome.truncated_stderr else "stderr-match"
                ),
                expected_sha256=_digest(needle),
            )
        )
    for kind, paths, expected in (
        ("file-exists", expectations.files_exist, True),
        ("file-absent", expectations.files_absent, False),
    ):
        for index, path in enumerate(paths):
            exists = _exists(stager, staged, path)
            results.append(
                ScriptAssertionResult(
                    id=f"{kind}-{index}",
                    kind=kind,
                    status="PASS" if exists == expected else "FAIL",
                    reason_code="file-check" if exists == expected else "file-mismatch",
                    expected_sha256=_digest(path),
                )
            )
    return tuple(results)
