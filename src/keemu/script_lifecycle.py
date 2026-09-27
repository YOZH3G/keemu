"""Disposable script lifecycle on the existing locked AArch64 Docker/binfmt base.

No CLI, persistent registry, scenario checks or host-side script execution here.
Only exact run-owned containers are eligible for cleanup; raw argv and output
remain in memory and never enter the report bundle.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from keemu import __version__
from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.init_cache import init_locked
from keemu.lifecycle import _secure_bytes
from keemu.models import (
    CheckResult,
    OperationLogEntry,
    PartialFailureMetadata,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
)
from keemu.profiles import load_profile_bytes
from keemu.reports import ReportPaths, build_report, write_report_bundle
from keemu.script_assertions import ScriptExpectations, check_script_assertions
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_process import ScriptProcessRunner
from keemu.script_results import (
    ScriptCleanupResult,
    ScriptExecutionResult,
    ScriptExecutionSpec,
    ScriptResult,
)
from keemu.script_stage import ScriptStager, StagedScript

BASE_LOCK = "locks/m1a-init-aarch64.json"


@dataclass(frozen=True)
class OneShotScriptResult:
    script: ScriptResult
    report: RunReport
    paths: ReportPaths


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _empty(state: str) -> ScriptExecutionResult:
    return ScriptExecutionResult(
        state=state,
        exit_code=None,
        timed_out=False,
        process_tree_clean=False,
        duration_seconds=0,
        stdout=b"",
        stderr=b"",
        truncated_stdout=False,
        truncated_stderr=False,
    )


def run_one_shot_script(
    script_path: str | Path,
    *,
    project_root: Path,
    profile_id: str = "generic-aarch64",
    argv: tuple[str, ...] = (),
    cwd: str = "/opt",
    timeout_seconds: int = 60,
    expected_exit_code: int = 0,
    expectations: ScriptExpectations | None = None,
    run_id: str | None = None,
    report_root: Path | None = None,
) -> OneShotScriptResult:
    """Run one validated script, publish a redacted immutable report, remove only ours.

    Invalid caller input raises ValueError before Docker allocation. An unavailable
    locked image/input is BLOCKED; an uncertain process or cleanup is ERROR.
    """
    root = project_root.resolve()
    run_id = run_id or "script-" + uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", run_id):
        raise ValueError("invalid run ID")
    if profile_id != "generic-aarch64":
        raise ValueError("one-shot script lifecycle requires generic-aarch64")
    if type(expected_exit_code) is not int or not 0 <= expected_exit_code <= 255:
        raise ValueError("invalid expected exit code")
    if expectations is not None and not isinstance(expectations, ScriptExpectations):
        raise ValueError("invalid script assertions")
    expectations = expectations or ScriptExpectations()
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
        raise ValueError("invalid script timeout")
    if cwd != "/opt" and (
        not cwd.startswith("/opt/")
        or any(part in {"", ".", ".."} for part in cwd[5:].split("/"))
    ):
        raise ValueError("invalid target working directory")
    if (
        len(argv) > 126
        or any(
            not isinstance(arg, str) or not arg or "\0" in arg or len(arg) > 4096
            for arg in argv
        )
        or sum(len(arg.encode("utf-8")) for arg in argv) > 65536
    ):
        raise ValueError("invalid script arguments")
    source = ScriptInput.validate(script_path, project_root=root)
    relative = source.source_path.relative_to(root).as_posix()
    # Validate the report intent before provisioning a resource.
    base = json.loads(_secure_bytes(root / BASE_LOCK, root, 2 * 1024 * 1024))
    image_id = base["oci_digest"]
    profile_path = root / "profiles/generic/generic-aarch64.yaml"
    profile_bytes = _secure_bytes(profile_path, root, 1024 * 1024)
    profile = load_profile_bytes(profile_bytes)
    if profile.id != profile_id or profile.entware_target != base["target"]:
        raise ValueError("profile and locked target disagree")
    profile_hash = hashlib.sha256(profile_bytes).hexdigest()
    runtime = DockerRuntime(run_id, image_id, target=profile.entware_target)
    ScriptExecutionSpec(
        source=relative,
        sha256=source.sha256,
        target_path=None,
        profile_id=profile.id,
        profile_revision=profile.revision,
        architecture=profile.entware_target,
        image_id=image_id,
        container_id=None,
        mode="one-shot",
        argv=argv,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )
    reports = report_root or root / "reports"
    stager = ScriptStager(runtime)
    runner = ScriptProcessRunner(stager)
    container: str | None = None
    staged: StagedScript | None = None
    allocation_attempted = False
    cleanup: list[ScriptCleanupResult] = []
    operations: list[OperationLogEntry] = []
    failure: tuple[int, str, str, str] | None = None
    outcome = _empty("error")
    assertions = ()
    error_status: str | None = None
    target_path: str | None = None

    def operation(name: str, action, *, failed_status: str):
        nonlocal failure
        started = _now()
        tick = time.monotonic()
        status = "PASS"
        try:
            return action()
        except Exception as exc:
            status = "BLOCKED" if isinstance(exc, ScriptInputChanged) else failed_status
            if failure is None:
                # Do not serialize exception text: target output/argv could be secret.
                failure = (len(operations) + 1, name, status, type(exc).__name__)
            raise
        finally:
            operations.append(
                OperationLogEntry(
                    sequence=len(operations) + 1,
                    operation=name,
                    started_at=started,
                    completed_at=_now(),
                    status=status,
                    argv=(),
                    cwd=None,
                    exit_code=None,
                    duration_seconds=time.monotonic() - tick,
                    stdout_path=None,
                    stderr_path=None,
                    timed_out=False,
                    truncated=False,
                )
            )

    try:

        def capability() -> None:
            cache = init_locked(root, offline=True)
            if cache.get("oci_digest") != image_id:
                raise DockerBoundaryError("locked AArch64 image mismatch")
            if (
                hashlib.sha256(
                    _secure_bytes(profile_path, root, 1024 * 1024)
                ).hexdigest()
                != profile_hash
            ):
                raise DockerBoundaryError("profile input changed")
            runtime.image()
            existing = runtime.reconcile()
            if existing["container_owned"] or existing["network_owned"]:
                raise DockerBoundaryError("run ID already owns Docker resources")

        operation("capability", capability, failed_status="BLOCKED")

        def create() -> str:
            nonlocal allocation_attempted, container
            allocation_attempted = True
            container = runtime.create("keemu-" + run_id)
            runtime.start(container)
            if (
                runtime.inspect("container", container).get("State", {}).get("Running")
                is not True
            ):
                raise DockerBoundaryError("owned container did not start")
            return container

        operation("create", create, failed_status="ERROR")
        if container is None:
            raise DockerBoundaryError("container identity unavailable")

        def stage() -> StagedScript:
            nonlocal staged, target_path
            staged = stager.stage(source, container)
            target_path = staged.path
            return staged

        operation("stage", stage, failed_status="ERROR")
        if staged is None:
            raise DockerBoundaryError("script staging identity unavailable")
        outcome = operation(
            "execute",
            lambda: runner.run(
                staged, timeout_seconds=timeout_seconds, cwd=cwd, argv=argv
            ),
            failed_status="ERROR",
        )
        assertions = operation(
            "assert",
            lambda: check_script_assertions(
                outcome, expected_exit_code, expectations, stager=stager, staged=staged
            ),
            failed_status="ERROR",
        )
    except ScriptInputChanged:
        outcome = _empty("blocked")
        error_status = "BLOCKED"
    except Exception:
        outcome = _empty("blocked" if failure and failure[2] == "BLOCKED" else "error")
        error_status = outcome.state.upper()
    finally:
        if staged is not None:
            try:
                stage_removed = stager.cleanup(staged).success
            except Exception:
                stage_removed = False
            cleanup.append(
                ScriptCleanupResult(
                    kind="target-script",
                    attempted=True,
                    verified=stage_removed,
                    reason_code=None if stage_removed else "target-cleanup-failed",
                )
            )
            operations.append(
                OperationLogEntry(
                    sequence=len(operations) + 1,
                    operation="cleanup-target",
                    started_at=_now(),
                    completed_at=_now(),
                    status="PASS" if stage_removed else "ERROR",
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
        if allocation_attempted:
            # A create can allocate an ID before returning. Reconcile only this
            # unique run, require exact intended name and at most one owned ID.
            removed = False
            try:
                owned = runtime.reconcile()
                if owned["network_owned"] or len(owned["container_owned"]) > 1:
                    raise DockerBoundaryError("ambiguous run-owned resources")
                ids = owned["container_owned"]
                if container is not None and ids != [container]:
                    raise DockerBoundaryError("created container identity changed")
                if ids:
                    item = runtime.inspect("container", ids[0])
                    if item.get("Name") != "/keemu-" + run_id:
                        raise DockerBoundaryError("owned container name changed")
                    runtime.remove_container(ids[0])
                    container = ids[0]
                after = runtime.reconcile()
                if after["container_owned"] or after["network_owned"]:
                    raise DockerBoundaryError("run-owned resources remain")
                removed = True
            except Exception:
                # Never infer cleanup from a failed inspect/removal/readback.
                removed = False
            cleanup.append(
                ScriptCleanupResult(
                    kind="container",
                    attempted=True,
                    verified=removed,
                    reason_code=None if removed else "container-cleanup-unverified",
                )
            )
            operations.append(
                OperationLogEntry(
                    sequence=len(operations) + 1,
                    operation="cleanup-container",
                    started_at=_now(),
                    completed_at=_now(),
                    status="PASS" if removed else "ERROR",
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

    # An uncertain helper cleanup cannot be promoted by later container removal.
    if error_status == "ERROR":
        outcome = _empty("error")
    spec = ScriptExecutionSpec(
        source=relative,
        sha256=source.sha256,
        target_path=target_path,
        profile_id=profile.id,
        profile_revision=profile.revision,
        architecture=profile.entware_target,
        image_id=image_id,
        container_id=container,
        mode="one-shot",
        argv=argv,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )
    result = ScriptResult(spec, outcome, assertions, tuple(cleanup))
    script_metadata = result.report_metadata()
    check = CheckResult(
        id="script",
        status=result.status,
        cause_class="harness"
        if result.status == "ERROR"
        else ("environment" if result.status == "BLOCKED" else "package"),
        evidence=(
            "target execution and owned cleanup classified; raw streams withheld",
        ),
        mode="real",
        required=True,
        duration_seconds=outcome.duration_seconds,
        limitations=(),
    )
    if failure is not None:
        sequence, name, status, reason = failure
        partial = PartialFailureMetadata(
            status=status,
            operation_sequence=sequence,
            operation=name,
            cause_class="environment" if status == "BLOCKED" else "harness",
            message=reason,
            interrupted=False,
            cleanup_attempted=bool(cleanup),
            cleanup_status="ERROR"
            if any(not item.verified for item in cleanup)
            else "PASS",
            preserved_artifacts=(str(reports / run_id / "report.json"),),
        )
    else:
        first_bad = next((op for op in operations if op.status == "ERROR"), None)
        partial = (
            None
            if first_bad is None
            else PartialFailureMetadata(
                status="ERROR",
                operation_sequence=first_bad.sequence,
                operation=first_bad.operation,
                cause_class="harness",
                message="owned cleanup unverified",
                interrupted=False,
                cleanup_attempted=True,
                cleanup_status="ERROR",
                preserved_artifacts=(str(reports / run_id / "report.json"),),
            )
        )
    report = build_report(
        run_id=run_id,
        created_at=_now(),
        operation="script",
        profile=ProfileMetadata(
            id=profile.id,
            revision=profile.revision,
            kind="generic",
            sha256=profile_hash,
        ),
        runtime=RuntimeMetadata(
            keemu_version=__version__,
            git_commit=None,
            git_dirty=None,
            oci_digest=image_id,
            qemu_version=None,
            binfmt_configuration=(),
            host_kernel=platform.release(),
            entware_target=profile.entware_target,
            feed_lock_sha256=base.get("input_lock_sha256"),
            versions=(),
            network_fidelity=None,
            native_tools=(),
        ),
        checks=(check,),
        script=script_metadata,
        operation_log=operations,
        partial_failure=partial,
        limitations=(
            "Userspace execution does not establish physical Keenetic compatibility",
        ),
    )
    paths = write_report_bundle(report, reports / run_id)
    return OneShotScriptResult(result, report, paths)
