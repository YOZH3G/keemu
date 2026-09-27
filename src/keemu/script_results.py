"""Typed script outcomes; no target execution or report publication in this module.

Raw argv and captured streams stay in memory. Published metadata contains only
per-argument and per-stream byte counts and SHA-256 identities, never raw
untrusted output or potentially secret-bearing arguments.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from keemu.docker_runtime import COMMAND_LIMIT

CHECK_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
OCI_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


ScriptStatus = Literal["PASS", "FAIL", "BLOCKED", "ERROR"]
ScriptState = Literal["executed", "blocked", "error"]
_SCRIPT_TARGET = re.compile(
    r"/opt/tmp/keemu-script-([0-9a-f]{64})-[0-9a-f]{24}/script\.sh\Z"
)


class ScriptExecutionSpec(StrictModel):
    """Pinned intent; argv is never serialized into a report by Pydantic."""

    source: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=SHA256_PATTERN)
    target_path: str | None
    profile_id: str = Field(pattern=IDENTIFIER_PATTERN)
    profile_revision: int = Field(ge=1)
    architecture: Literal["aarch64-3.10", "mips-3.4", "mipsel-3.4"]
    image_id: str = Field(pattern=OCI_DIGEST_PATTERN)
    container_id: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    mode: Literal["one-shot", "persistent"]
    interpreter: Literal["/bin/sh"] = "/bin/sh"
    argv: tuple[str, ...] = Field(default=(), strict=False, exclude=True, repr=False)
    cwd: str = "/opt"
    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        if (
            self.source.startswith("/")
            or "\\" in self.source
            or any(part in {"", ".", ".."} for part in self.source.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in self.source)
        ):
            raise ValueError("script source must be a project-relative path")
        if self.target_path is not None and self.container_id is None:
            raise ValueError("target path needs container identity")
        if self.target_path is not None:
            match = _SCRIPT_TARGET.fullmatch(self.target_path)
            if match is None or match.group(1) != self.sha256:
                raise ValueError("script target path does not match digest")
        if self.cwd != "/opt" and (
            not self.cwd.startswith("/opt/")
            or any(part in {"", ".", ".."} for part in self.cwd[5:].split("/"))
        ):
            raise ValueError("invalid target working directory")
        if len(self.argv) > 126 or any(
            not arg or len(arg) > 4096 or "\0" in arg for arg in self.argv
        ):
            raise ValueError("invalid bounded script arguments")
        if sum(len(arg.encode("utf-8")) for arg in self.argv) > 65536:
            raise ValueError("script argument bytes exceeded cap")
        return self


class ScriptExecutionResult(StrictModel):
    state: ScriptState
    exit_code: int | None
    timed_out: bool
    process_tree_clean: bool
    duration_seconds: float = Field(ge=0, le=660, allow_inf_nan=False)
    stdout: bytes = Field(max_length=COMMAND_LIMIT, exclude=True, repr=False)
    stderr: bytes = Field(max_length=COMMAND_LIMIT, exclude=True, repr=False)
    truncated_stdout: bool
    truncated_stderr: bool

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.state != "executed" and (
            self.exit_code is not None
            or self.timed_out
            or self.process_tree_clean
            or self.stdout
            or self.stderr
            or self.truncated_stdout
            or self.truncated_stderr
        ):
            raise ValueError("nonexecuted script has execution evidence")
        if self.state == "executed" and not self.timed_out and self.exit_code is None:
            raise ValueError("completed script requires exit code")
        return self


class ScriptAssertionResult(StrictModel):
    id: str = Field(pattern=CHECK_ID_PATTERN)
    kind: Literal["exit-code", "stdout-contains", "stderr-not-contains", "file-exists"]
    status: ScriptStatus
    reason_code: str = Field(pattern=CHECK_ID_PATTERN)
    expected_exit_code: int | None = None

    @model_validator(mode="after")
    def validate_expectation(self) -> Self:
        if (self.kind == "exit-code") != (self.expected_exit_code is not None):
            raise ValueError("exit-code assertion needs an explicit expected code")
        return self


class ScriptCleanupResult(StrictModel):
    kind: Literal["target-script", "container"]
    attempted: bool
    verified: bool
    reason_code: str | None = Field(default=None, pattern=CHECK_ID_PATTERN)

    @model_validator(mode="after")
    def validate_cleanup(self) -> Self:
        if self.verified and (not self.attempted or self.reason_code is not None):
            raise ValueError("verified cleanup needs an attempted clean result")
        if not self.verified and self.attempted and self.reason_code is None:
            raise ValueError("failed cleanup needs a reason code")
        return self


class ScriptArgumentMetadata(StrictModel):
    byte_count: int = Field(ge=1, le=16384)
    sha256: str = Field(pattern=SHA256_PATTERN)


class ScriptStreamMetadata(StrictModel):
    byte_count: int = Field(ge=0, le=COMMAND_LIMIT)
    sha256: str = Field(pattern=SHA256_PATTERN)
    truncated: bool


class ScriptExecutionMetadata(StrictModel):
    source: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=SHA256_PATTERN)
    target_path: str | None
    profile_id: str = Field(pattern=IDENTIFIER_PATTERN)
    profile_revision: int = Field(ge=1)
    architecture: Literal["aarch64-3.10", "mips-3.4", "mipsel-3.4"]
    image_id: str = Field(pattern=OCI_DIGEST_PATTERN)
    container_id: str | None
    mode: Literal["one-shot", "persistent"]
    interpreter: Literal["/bin/sh"]
    argv: tuple[ScriptArgumentMetadata, ...] = Field(strict=False, max_length=126)
    cwd: str
    timeout_seconds: int = Field(ge=1, le=600)

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            self.source.startswith("/")
            or "\\" in self.source
            or any(part in {"", ".", ".."} for part in self.source.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in self.source)
        ):
            raise ValueError("script report source must be project-relative")
        if self.cwd != "/opt" and (
            not self.cwd.startswith("/opt/")
            or any(part in {"", ".", ".."} for part in self.cwd[5:].split("/"))
        ):
            raise ValueError("invalid script report working directory")
        if self.target_path is not None and self.container_id is None:
            raise ValueError("script report target identity is incomplete")
        if self.container_id is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.container_id
        ):
            raise ValueError("script report container identity is invalid")
        if self.target_path is not None:
            match = _SCRIPT_TARGET.fullmatch(self.target_path)
            if match is None or match.group(1) != self.sha256:
                raise ValueError("script report target identity differs from source")
        return self


class ScriptOutcomeMetadata(StrictModel):
    state: ScriptState
    exit_code: int | None
    timed_out: bool
    process_tree_clean: bool
    duration_seconds: float = Field(ge=0, le=660, allow_inf_nan=False)
    stdout: ScriptStreamMetadata
    stderr: ScriptStreamMetadata

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        empty = hashlib.sha256(b"").hexdigest()
        if self.state != "executed" and (
            self.exit_code is not None
            or self.timed_out
            or self.process_tree_clean
            or self.stdout.byte_count
            or self.stderr.byte_count
            or self.stdout.sha256 != empty
            or self.stderr.sha256 != empty
            or self.stdout.truncated
            or self.stderr.truncated
        ):
            raise ValueError("nonexecuted report has execution evidence")
        if self.state == "executed" and not self.timed_out and self.exit_code is None:
            raise ValueError("completed report needs exit code")
        return self


class ScriptReportMetadata(StrictModel):
    execution: ScriptExecutionMetadata
    outcome: ScriptOutcomeMetadata
    assertions: tuple[ScriptAssertionResult, ...] = Field(strict=False)
    cleanup: tuple[ScriptCleanupResult, ...] = Field(strict=False)
    status: ScriptStatus

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status != script_status(
            self.outcome,
            self.assertions,
            self.cleanup,
            self.execution.mode,
            target_allocated=self.execution.target_path is not None,
            container_allocated=self.execution.container_id is not None,
        ):
            raise ValueError("script status does not match execution and cleanup")
        if self.outcome.state == "executed" and (
            self.execution.target_path is None or self.execution.container_id is None
        ):
            raise ValueError("executed script needs a staged target identity")
        return self


def script_status(
    outcome: ScriptExecutionResult | ScriptOutcomeMetadata,
    assertions: tuple[ScriptAssertionResult, ...],
    cleanup: tuple[ScriptCleanupResult, ...],
    mode: Literal["one-shot", "persistent"],
    *,
    target_allocated: bool,
    container_allocated: bool,
) -> ScriptStatus:
    """ERROR > FAIL > BLOCKED > PASS; missing proof cannot become PASS."""
    kinds = [item.kind for item in cleanup]
    if len({item.id for item in assertions}) != len(assertions):
        return "ERROR"
    if len(kinds) != len(set(kinds)) or (mode == "persistent" and "container" in kinds):
        return "ERROR"
    if any(item.attempted and not item.verified for item in cleanup):
        return "ERROR"
    if (
        (target_allocated and "target-script" not in kinds)
        or (container_allocated and mode == "one-shot" and "container" not in kinds)
        or (outcome.state == "executed" and not target_allocated)
        or any(not item.verified for item in cleanup)
    ):
        return "ERROR"
    if outcome.state == "error" or any(item.status == "ERROR" for item in assertions):
        return "ERROR"
    if outcome.state == "executed" and not outcome.process_tree_clean:
        return "ERROR"

    if outcome.timed_out or any(item.status == "FAIL" for item in assertions):
        return "FAIL"
    if outcome.state == "executed" and any(
        item.kind == "exit-code" and outcome.exit_code != item.expected_exit_code
        for item in assertions
    ):
        return "FAIL"
    if outcome.state == "blocked" or any(
        item.status == "BLOCKED" for item in assertions
    ):
        return "BLOCKED"
    if (
        outcome.state != "executed"
        or not assertions
        or not any(
            item.kind == "exit-code" and item.status == "PASS" for item in assertions
        )
    ):
        return "ERROR"
    return "PASS"


def _stream(data: bytes, truncated: bool) -> ScriptStreamMetadata:
    return ScriptStreamMetadata(
        byte_count=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        truncated=truncated,
    )


@dataclass(frozen=True, slots=True)
class ScriptResult:
    spec: ScriptExecutionSpec
    outcome: ScriptExecutionResult
    assertions: tuple[ScriptAssertionResult, ...]
    cleanup: tuple[ScriptCleanupResult, ...]

    @property
    def status(self) -> ScriptStatus:
        return script_status(
            self.outcome,
            self.assertions,
            self.cleanup,
            self.spec.mode,
            target_allocated=self.spec.target_path is not None,
            container_allocated=self.spec.container_id is not None,
        )

    def report_metadata(self) -> ScriptReportMetadata:
        """Build only digest/length output identities; never persist raw bytes/argv."""
        spec = self.spec
        outcome = self.outcome
        return ScriptReportMetadata(
            execution=ScriptExecutionMetadata(
                source=spec.source,
                sha256=spec.sha256,
                target_path=spec.target_path,
                profile_id=spec.profile_id,
                profile_revision=spec.profile_revision,
                architecture=spec.architecture,
                image_id=spec.image_id,
                container_id=spec.container_id,
                mode=spec.mode,
                interpreter=spec.interpreter,
                argv=tuple(
                    ScriptArgumentMetadata(
                        byte_count=len(raw), sha256=hashlib.sha256(raw).hexdigest()
                    )
                    for raw in (arg.encode("utf-8") for arg in spec.argv)
                ),
                cwd=spec.cwd,
                timeout_seconds=spec.timeout_seconds,
            ),
            outcome=ScriptOutcomeMetadata(
                state=outcome.state,
                exit_code=outcome.exit_code,
                timed_out=outcome.timed_out,
                process_tree_clean=outcome.process_tree_clean,
                duration_seconds=outcome.duration_seconds,
                stdout=_stream(outcome.stdout, outcome.truncated_stdout),
                stderr=_stream(outcome.stderr, outcome.truncated_stderr),
            ),
            assertions=self.assertions,
            cleanup=self.cleanup,
            status=self.status,
        )
