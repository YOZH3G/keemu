from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Status = Literal["PASS", "WARN", "FAIL", "SKIP", "BLOCKED", "ERROR"]
CauseClass = Literal["package", "environment", "harness", "unknown"]
EvidenceMode = Literal["real", "shim", "static"]
FailureStatus = Literal["FAIL", "BLOCKED", "ERROR"]
NetworkFidelity = Literal["S0", "S1", "S2"]

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
CHECK_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
OCI_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CheckResult(StrictModel):
    id: str = Field(pattern=CHECK_ID_PATTERN)
    status: Status
    cause_class: CauseClass
    evidence: tuple[str, ...] = Field(strict=False)
    mode: EvidenceMode
    required: bool
    duration_seconds: float = Field(ge=0)
    limitations: tuple[str, ...] = Field(strict=False)


class Coverage(StrictModel):
    required: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    blocked: int = Field(ge=0)
    skipped: int = Field(ge=0)
    warned: int = Field(ge=0)
    errors: int = Field(ge=0)


class ArtifactMetadata(StrictModel):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    kind: str = Field(min_length=1, max_length=64)
    version: str | None
    source: str
    sha256: str = Field(pattern=SHA256_PATTERN)
    architecture: str | None


class ScenarioMetadata(StrictModel):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    schema_version: int = Field(ge=1)
    source: str
    sha256: str = Field(pattern=SHA256_PATTERN)


class ProfileMetadata(StrictModel):
    id: str = Field(pattern=IDENTIFIER_PATTERN)
    revision: int = Field(ge=1)
    kind: Literal["generic", "device"]
    sha256: str | None = Field(pattern=SHA256_PATTERN)


class RuntimeVersion(StrictModel):
    name: str = Field(pattern=CHECK_ID_PATTERN)
    version: str


class RuntimeMetadata(StrictModel):
    keemu_version: str
    git_commit: str | None = Field(pattern=GIT_COMMIT_PATTERN)
    git_dirty: bool | None
    oci_digest: str | None = Field(pattern=OCI_DIGEST_PATTERN)
    qemu_version: str | None
    binfmt_configuration: tuple[str, ...] = Field(strict=False)
    host_kernel: str
    entware_target: str
    feed_lock_sha256: str | None = Field(pattern=SHA256_PATTERN)
    versions: tuple[RuntimeVersion, ...] = Field(strict=False)
    network_fidelity: NetworkFidelity | None
    native_tools: tuple[str, ...] = Field(strict=False)


class CapabilityResult(StrictModel):
    id: str = Field(pattern=CHECK_ID_PATTERN)
    status: Status
    mode: EvidenceMode
    evidence: tuple[str, ...] = Field(strict=False)
    limitations: tuple[str, ...] = Field(strict=False)


class SubstitutionMetadata(StrictModel):
    id: str = Field(pattern=CHECK_ID_PATTERN)
    replaces: str
    reason: str
    evidence: tuple[str, ...] = Field(strict=False)


class OperationLogEntry(StrictModel):
    sequence: int = Field(ge=1)
    operation: str = Field(pattern=CHECK_ID_PATTERN)
    started_at: str
    completed_at: str | None
    status: Status
    argv: tuple[str, ...] = Field(strict=False)
    cwd: str | None
    exit_code: int | None
    duration_seconds: float = Field(ge=0)
    stdout_path: str | None
    stderr_path: str | None
    timed_out: bool
    truncated: bool


class PartialFailureMetadata(StrictModel):
    status: FailureStatus
    operation_sequence: int = Field(ge=1)
    operation: str = Field(pattern=CHECK_ID_PATTERN)
    cause_class: CauseClass
    message: str
    interrupted: bool
    cleanup_attempted: bool
    cleanup_status: Status | None
    preserved_artifacts: tuple[str, ...] = Field(strict=False)


def coverage_for(checks: Sequence[CheckResult]) -> Coverage:
    required_checks = [check for check in checks if check.required]
    return Coverage(
        required=len(required_checks),
        passed=sum(check.status == "PASS" for check in required_checks),
        failed=sum(check.status == "FAIL" for check in required_checks),
        blocked=sum(
            check.status in {"BLOCKED", "SKIP"} for check in required_checks
        ),
        skipped=sum(check.status == "SKIP" for check in required_checks),
        warned=sum(check.status == "WARN" for check in required_checks),
        errors=sum(check.status == "ERROR" for check in required_checks),
    )


def aggregate_status(
    checks: Sequence[CheckResult], partial_failure: PartialFailureMetadata | None
) -> Status:
    effective: list[Status] = [
        "BLOCKED" if check.status == "SKIP" else check.status
        for check in checks
        if check.required
    ]
    if partial_failure is not None:
        effective.append(partial_failure.status)
    if not effective:
        return "BLOCKED"
    priorities: tuple[Status, ...] = ("ERROR", "FAIL", "BLOCKED", "WARN")
    for status in priorities:
        if status in effective:
            return status
    if "PASS" not in effective:
        return "BLOCKED"
    return "PASS"


class RunReport(StrictModel):
    schema_version: Literal[2]
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    created_at: str
    operation: str
    artifact: ArtifactMetadata | None
    scenario: ScenarioMetadata | None
    profile: ProfileMetadata
    runtime: RuntimeMetadata
    capabilities: tuple[CapabilityResult, ...] = Field(strict=False)
    substitutions: tuple[SubstitutionMetadata, ...] = Field(strict=False)
    overall: Status
    coverage: Coverage
    operation_log: tuple[OperationLogEntry, ...] = Field(strict=False)
    partial_failure: PartialFailureMetadata | None
    checks: tuple[CheckResult, ...] = Field(strict=False)
    limitations: tuple[str, ...] = Field(strict=False)

    @model_validator(mode="after")
    def validate_derived_metadata(self) -> Self:
        expected_coverage = coverage_for(self.checks)
        if self.coverage != expected_coverage:
            raise ValueError("coverage does not match required checks")
        expected_status = aggregate_status(self.checks, self.partial_failure)
        if self.overall != expected_status:
            raise ValueError("aggregate status does not match report results")
        sequences = [entry.sequence for entry in self.operation_log]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("operation log sequence must be contiguous from 1")
        if self.partial_failure is not None:
            operation = next(
                (
                    entry
                    for entry in self.operation_log
                    if entry.sequence == self.partial_failure.operation_sequence
                ),
                None,
            )
            if operation is None:
                raise ValueError("partial failure operation sequence is absent")
            if operation.operation != self.partial_failure.operation:
                raise ValueError(
                    "partial failure operation does not match operation log"
                )
            if operation.status != self.partial_failure.status:
                raise ValueError("partial failure status does not match operation log")
        return self
