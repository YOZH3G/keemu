from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["PASS", "WARN", "FAIL", "SKIP", "BLOCKED", "ERROR"]
CauseClass = Literal["package", "environment", "harness", "unknown"]
EvidenceMode = Literal["real", "shim", "static"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CheckResult(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    status: Status
    cause_class: CauseClass
    evidence: list[str]
    mode: EvidenceMode
    required: bool
    duration_seconds: float = Field(ge=0)
    limitations: list[str]


class Coverage(StrictModel):
    required: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    blocked: int = Field(ge=0)
    skipped: int = Field(ge=0)
    warned: int = Field(ge=0)
    errors: int = Field(ge=0)


class RunReport(StrictModel):
    schema_version: Literal[1]
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    created_at: str
    operation: str
    profile_id: str
    overall: Status
    coverage: Coverage
    checks: list[CheckResult]
    limitations: list[str]
