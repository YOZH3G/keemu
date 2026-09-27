"""Persistent script execution in one registry-locked, owner-verified environment.

Never stops/removes the environment or touches its service. Only the issued
private target script/runner directory is eligible for cleanup.
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from keemu import __version__
from keemu.docker_runtime import DockerBoundaryError
from keemu.init_cache import init_locked
from keemu.input_paths import safe_name
from keemu.lifecycle import _secure_bytes
from keemu.models import (
    CheckResult,
    OperationLogEntry,
    PartialFailureMetadata,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
)
from keemu.persistent import _runtime
from keemu.profiles import load_profile_bytes
from keemu.registry import Registry, RegistryError
from keemu.reports import ReportPaths, build_report, write_report_bundle
from keemu.script_assertions import ScriptExpectations, check_script_assertions
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_lifecycle import BASE_LOCK, _empty, _now
from keemu.script_process import ScriptProcessRunner
from keemu.script_results import (
    ScriptCleanupResult,
    ScriptExecutionSpec,
    ScriptResult,
)
from keemu.script_stage import ScriptStager, StagedScript


@dataclass(frozen=True)
class PersistentScriptResult:
    script: ScriptResult
    report: RunReport
    paths: ReportPaths


def run_persistent_script(
    name: str,
    script_path: str | Path,
    *,
    project_root: Path,
    argv: tuple[str, ...] = (),
    cwd: str = "/opt",
    timeout_seconds: int = 60,
    expected_exit_code: int = 0,
    expectations: ScriptExpectations | None = None,
    report_root: Path | None = None,
) -> PersistentScriptResult:
    """Use the shared input/stager/process/result contract, not container cleanup."""
    safe_name(name)
    root = project_root.resolve()
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
    reports = report_root or root / "reports"
    run_id = "script-exec-" + uuid4().hex
    with Registry(root / ".runtime/registry").locked(name) as entry:
        record = entry.read()
        if record.state != "running" or record.resource is None:
            raise RegistryError("script exec requires a running environment")
        if record.profile_id != "generic-aarch64":
            raise RegistryError("persistent script lifecycle unavailable for target")
        runtime, container = _runtime(record)
        observed = runtime.inspect("container", container)
        if (
            observed.get("Name") != "/keemu-" + record.run_id
            or observed.get("State", {}).get("Running") is not True
        ):
            raise RegistryError(
                "container name or running state disagrees with registry"
            )
        entry.verify_unchanged(record)
        entry.scenario(record.scenario_sha256)
        profile_path = root / "profiles/generic" / f"{record.profile_id}.yaml"
        profile_bytes = _secure_bytes(profile_path, root, 1024 * 1024)
        profile = load_profile_bytes(profile_bytes)
        profile_hash = hashlib.sha256(profile_bytes).hexdigest()
        if (
            profile_hash != record.profile_sha256
            or profile.id != record.profile_id
            or profile.entware_target != runtime.target
        ):
            raise RegistryError("locked persistent profile changed")
        # This validates cwd, argv count/bytes and intent before target mutation.
        intent = ScriptExecutionSpec(
            source=relative,
            sha256=source.sha256,
            target_path=None,
            profile_id=profile.id,
            profile_revision=profile.revision,
            architecture=profile.entware_target,
            image_id=record.oci_digest,
            container_id=container,
            mode="persistent",
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )

        stager = ScriptStager(runtime)
        runner = ScriptProcessRunner(stager)
        staged: StagedScript | None = None
        target_path: str | None = None
        outcome = _empty("error")
        assertions = ()
        cleanup: list[ScriptCleanupResult] = []
        operations: list[OperationLogEntry] = []
        failure: tuple[int, str, str, str] | None = None

        def operation(name: str, action, *, failed_status: str):
            nonlocal failure
            started = _now()
            tick = time.monotonic()
            status = "PASS"
            try:
                return action()
            except Exception as exc:
                status = (
                    "BLOCKED" if isinstance(exc, ScriptInputChanged) else failed_status
                )
                if failure is None:
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
                base = _secure_bytes(root / BASE_LOCK, root, 2 * 1024 * 1024)
                locked = json.loads(base)
                if (
                    locked.get("oci_digest") != record.oci_digest
                    or locked.get("target") != profile.entware_target
                    or init_locked(root, offline=True).get("oci_digest")
                    != record.oci_digest
                ):
                    raise DockerBoundaryError("locked persistent image changed")
                runtime.image()
                entry.verify_unchanged(record)

            operation("capability", capability, failed_status="BLOCKED")

            def stage() -> StagedScript:
                nonlocal staged, target_path
                entry.verify_unchanged(record)
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
                    outcome,
                    expected_exit_code,
                    expectations,
                    stager=stager,
                    staged=staged,
                ),
                failed_status="ERROR",
            )
        except ScriptInputChanged:
            outcome = _empty("blocked")
        except Exception:
            outcome = _empty(
                "blocked" if failure and failure[2] == "BLOCKED" else "error"
            )
        finally:
            if staged is not None:
                try:
                    removed = stager.cleanup(staged).success
                except Exception:
                    removed = False
                cleanup.append(
                    ScriptCleanupResult(
                        kind="target-script",
                        attempted=True,
                        verified=removed,
                        reason_code=None if removed else "target-cleanup-failed",
                    )
                )
                operations.append(
                    OperationLogEntry(
                        sequence=len(operations) + 1,
                        operation="cleanup-target",
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
            try:
                entry.verify_unchanged(record)
                entry.scenario(record.scenario_sha256)
                post_runtime, post_id = _runtime(record)
                post = post_runtime.inspect("container", post_id)
                if (
                    post_id != container
                    or post.get("Name") != "/keemu-" + record.run_id
                    or post.get("State", {}).get("Running") is not True
                ):
                    raise RegistryError("persistent container changed during script")
            except Exception as exc:
                if failure is None:
                    failure = (
                        len(operations) + 1,
                        "verify-environment",
                        "ERROR",
                        type(exc).__name__,
                    )
                outcome = _empty("error")
                operations.append(
                    OperationLogEntry(
                        sequence=len(operations) + 1,
                        operation="verify-environment",
                        started_at=_now(),
                        completed_at=_now(),
                        status="ERROR",
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

        spec = intent.model_copy(update={"target_path": target_path})
        result = ScriptResult(spec, outcome, assertions, tuple(cleanup))
        if failure is not None:
            sequence, failed_name, status, reason = failure
            partial = PartialFailureMetadata(
                status=status,
                operation_sequence=sequence,
                operation=failed_name,
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
            failed_cleanup = next(
                (op for op in operations if op.status == "ERROR"), None
            )
            partial = (
                None
                if failed_cleanup is None
                else PartialFailureMetadata(
                    status="ERROR",
                    operation_sequence=failed_cleanup.sequence,
                    operation=failed_cleanup.operation,
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
                oci_digest=record.oci_digest,
                qemu_version=None,
                binfmt_configuration=(),
                host_kernel=platform.release(),
                entware_target=profile.entware_target,
                feed_lock_sha256=None,
                versions=(),
                network_fidelity=None,
                native_tools=(),
            ),
            checks=(
                CheckResult(
                    id="script",
                    status=result.status,
                    cause_class="harness"
                    if result.status == "ERROR"
                    else ("environment" if result.status == "BLOCKED" else "package"),
                    evidence=(
                        "target execution and exact cleanup classified; "
                        "raw streams withheld",
                    ),
                    mode="real",
                    required=True,
                    duration_seconds=outcome.duration_seconds,
                    limitations=(),
                ),
            ),
            script=result.report_metadata(),
            operation_log=operations,
            partial_failure=partial,
            limitations=(
                "Userspace execution does not establish physical "
                "Keenetic compatibility",
            ),
        )
        paths = write_report_bundle(report, reports / run_id)
        return PersistentScriptResult(result, report, paths)
