"""Strict three-target matrix and sequential one-shot execution.

A matrix binds one locked scenario/IPK per target. Static applicability is not a
substitute for target execution; unsupported lifecycle targets remain BLOCKED.
"""

from __future__ import annotations

import hashlib
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self
from uuid import uuid4

from pydantic import Field, model_validator

from keemu import __version__
from keemu.input_locks import load_scenario_lock
from keemu.input_paths import HostInputPath, SafeName, resolve_input_path
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.lifecycle import LifecycleResult, _now, _secure_bytes, run_scenario
from keemu.models import (
    CauseClass,
    CheckResult,
    OperationLogEntry,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
    ScenarioMetadata,
    Status,
)
from keemu.profiles import load_profile, load_yaml_unique_bytes
from keemu.reports import ReportPaths, build_report, write_report_bundle
from keemu.scenarios import InputModel, IPKInstall, load_scenario

TARGETS = ("generic-aarch64", "generic-mipsel", "generic-mips")


class MatrixCase(InputModel):
    profile: SafeName
    scenario: HostInputPath
    lock: HostInputPath


class Matrix(InputModel):
    schema_version: Literal[1]
    id: SafeName
    cases: tuple[MatrixCase, ...] = Field(min_length=1, max_length=32, strict=False)

    @model_validator(mode="after")
    def unique_cases(self) -> Self:
        profiles = [case.profile for case in self.cases]
        if len(profiles) != len(set(profiles)):
            raise ValueError("duplicate matrix profile")
        return self


@dataclass(frozen=True)
class MatrixResult:
    report: RunReport
    paths: ReportPaths


def _check(
    name: str,
    status: Status,
    detail: str,
    *,
    mode: Literal["real", "static"] = "static",
    cause: CauseClass = "environment",
) -> CheckResult:
    return CheckResult(
        id=name,
        status=status,
        cause_class=cause,
        mode=mode,
        required=True,
        duration_seconds=0,
        evidence=(detail[:1024],),
        limitations=(detail[:1024],) if status in {"SKIP", "WARN", "BLOCKED"} else (),
    )


def run_matrix(
    matrix_path: Path,
    *,
    project_root: Path,
    report_root: Path | None = None,
    run_id: str | None = None,
) -> MatrixResult:
    """Validate every input before any child run, then visit cases in file order.

    Malformed matrix/input is an input error; missing target runtime is BLOCKED;
    a verified wrong-architecture IPK is FAIL. Child reports remain immutable.
    """
    root = project_root.resolve()
    path = resolve_input_path(
        matrix_path.name, scenario_dir=matrix_path.parent, project_root=root
    )
    data = _secure_bytes(path, root, 1024 * 1024)
    matrix = Matrix.model_validate(load_yaml_unique_bytes(data))
    if run_id is None:
        run_id = "matrix-" + uuid4().hex
    # Build-report run ID validation must precede all child side effects.
    if (
        not run_id
        or len(run_id) < 3
        or len(run_id) > 128
        or not all(c.isascii() and (c.isalnum() or c in "._-") for c in run_id)
        or not run_id[0].isalnum()
    ):
        raise ValueError("invalid matrix run ID")
    reports = report_root or root / "reports"
    # Refuse a pre-existing parent destination before any child starts. The
    # atomic writer checks again at publication; it never overwrites it.
    if (reports / run_id).exists() or (reports / run_id).is_symlink():
        raise FileExistsError("matrix report destination exists")

    prepared: list[tuple[MatrixCase, Path, Path, Status | None, str]] = []
    logical_package: str | None = None
    for case in matrix.cases:
        scenario_path = resolve_input_path(
            case.scenario, scenario_dir=path.parent, project_root=root
        )
        lock_path = resolve_input_path(
            case.lock, scenario_dir=path.parent, project_root=root
        )
        scenario = load_scenario(scenario_path, project_root=root)
        if scenario.profile != case.profile:
            raise ValueError(f"case {case.profile}: scenario profile mismatch")
        if not isinstance(scenario.install, IPKInstall):
            raise ValueError(f"case {case.profile}: matrix requires locked IPK")
        if logical_package is None:
            logical_package = scenario.install.package_name
        elif logical_package != scenario.install.package_name:
            raise ValueError("matrix scenarios must name one logical package")
        lock = load_scenario_lock(
            lock_path, project_root=root, scenario=scenario, scenario_path=scenario_path
        )
        if case.profile not in TARGETS:
            prepared.append(
                (
                    case,
                    scenario_path,
                    lock_path,
                    "BLOCKED",
                    "unsupported target profile",
                )
            )
            continue
        profile_path = root / "profiles/generic" / f"{case.profile}.yaml"
        profile = load_profile(profile_path)
        profile_data = _secure_bytes(profile_path, root, 1024 * 1024)
        if (
            profile.id != case.profile
            or lock.profile_id != case.profile
            or profile.revision != lock.profile_revision
            or hashlib.sha256(profile_data).hexdigest() != lock.profile_sha256
            or profile.entware_target != lock.entware_target
        ):
            raise ValueError(f"case {case.profile}: profile/lock mismatch")
        source = resolve_input_path(
            scenario.install.path, scenario_dir=scenario_path.parent, project_root=root
        )
        # Source hashes were validated by load_scenario_lock; secure use-time
        # read closes symlink swaps before static inspection. The child repeats
        # all checks before Docker and copies exactly its privately read bytes.
        artifact = _secure_bytes(source, root, 64 * 1024 * 1024)
        source_lock = next(
            item
            for item in lock.sources
            if resolve_input_path(
                item.path, scenario_dir=lock_path.parent, project_root=root
            )
            == source
        )
        if hashlib.sha256(artifact).hexdigest() != source_lock.sha256:
            raise ValueError(f"case {case.profile}: source changed during validation")
        try:
            inspection = inspect_ipk(source, profile=profile)
        except IPKError as exc:
            raise ValueError(f"case {case.profile}: invalid IPK: {exc}") from exc
        mismatch = [
            finding
            for finding in inspection.findings
            if finding.status == "FAIL"
            and finding.code
            in {"architecture", "elf-architecture", "elf-abi", "architecture-all-elf"}
        ]
        if mismatch:
            detail = "architecture-mismatch: " + "; ".join(
                f"{finding.code}: {finding.detail}" for finding in mismatch
            )
            prepared.append((case, scenario_path, lock_path, "FAIL", detail))
        elif profile.entware_target != "aarch64-3.10":
            prepared.append(
                (
                    case,
                    scenario_path,
                    lock_path,
                    "BLOCKED",
                    "target lifecycle unsupported: locked MIPS/MIPSEL rootfs probes "
                    "do not implement keemu test",
                )
            )
        else:
            prepared.append((case, scenario_path, lock_path, None, ""))

    checks: list[CheckResult] = []
    operations: list[OperationLogEntry] = []
    missing = [
        target
        for target in TARGETS
        if target not in {case.profile for case in matrix.cases}
    ]
    if missing:
        checks.append(
            _check(
                "completeness",
                "BLOCKED",
                "missing required targets: " + ", ".join(missing),
            )
        )
    else:
        checks.append(
            _check(
                "completeness",
                "PASS",
                "all three generic targets mapped to distinct locked scenarios",
            )
        )
    for index, (case, scenario_path, lock_path, preflight_status, detail) in enumerate(
        prepared
    ):
        started = _now()
        child: LifecycleResult | None = None
        status: Status
        cause: CauseClass = "environment"
        mode: Literal["real", "static"] = "static"
        if preflight_status is not None:
            status = preflight_status
            if status == "FAIL":
                cause = "package"
        else:
            try:
                child = run_scenario(
                    scenario_path,
                    lock_path,
                    project_root=root,
                    report_root=reports,
                    run_id=f"{run_id}-case-{index + 1}",
                )
                status = child.report.overall
                cause = (
                    child.report.partial_failure.cause_class
                    if child.report.partial_failure is not None
                    else "unknown"
                )
                mode = (
                    "real"
                    if any(
                        check.id == "fresh-environment" and check.status == "PASS"
                        for check in child.report.checks
                    )
                    else "static"
                )
                detail = (
                    f"child_report={child.paths.json}; "
                    "sha256="
                    f"{hashlib.sha256(child.paths.json.read_bytes()).hexdigest()}; "
                    f"mode=real; overall={status}"
                )
            except Exception as exc:
                status = "ERROR"
                cause = "harness"
                detail = (
                    f"child execution/publication error: {type(exc).__name__}: "
                    f"{str(exc)[:512]}"
                )
        if preflight_status is not None:
            detail = f"profile={case.profile}; scenario={scenario_path}; {detail}"
        checks.append(
            _check(
                case.profile,
                status,
                detail,
                mode=mode,
                cause=cause,
            )
        )
        operations.append(
            OperationLogEntry(
                sequence=index + 1,
                operation="case-" + case.profile,
                started_at=started,
                completed_at=_now(),
                status=status,
                argv=(),
                cwd=None,
                exit_code=None,
                duration_seconds=0,
                stdout_path=None,
                stderr_path=None,
                timed_out=False,
                truncated=False,
            )
        )

    report = build_report(
        run_id=run_id,
        created_at=_now(),
        operation="matrix",
        profile=ProfileMetadata(id="matrix", revision=1, kind="generic", sha256=None),
        runtime=RuntimeMetadata(
            keemu_version=__version__,
            git_commit=None,
            git_dirty=None,
            oci_digest=None,
            qemu_version=None,
            binfmt_configuration=(),
            host_kernel=platform.release(),
            entware_target="matrix",
            feed_lock_sha256=None,
            versions=(),
            network_fidelity=None,
            native_tools=(),
        ),
        scenario=ScenarioMetadata(
            id=matrix.id,
            schema_version=1,
            source=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
        ),
        checks=checks,
        operation_log=operations,
        limitations=(
            "MIPS/MIPSEL target probes are not a general IPK lifecycle; "
            "required cases remain BLOCKED until supported",
            "Each child report has its own cleanup and evidence; "
            "static mismatch is not target execution",
        ),
    )
    paths = write_report_bundle(
        report, reports / run_id, evidence={"resolved-scenario.yaml": data}
    )
    return MatrixResult(report, paths)
