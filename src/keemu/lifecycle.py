"""One-shot, locked IPK lifecycle; registry and matrix are separate.

A report is attempted for every invocation, including validation failures. No failed
step is converted to PASS; cleanup never overwrites the primary failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from yaml import YAMLError

from keemu import __version__
from keemu.docker_runtime import DockerRuntime, Output
from keemu.init_cache import init_locked
from keemu.input_locks import load_scenario_lock
from keemu.input_paths import resolve_input_path
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.models import (
    ArtifactMetadata,
    CheckResult,
    OperationLogEntry,
    PartialFailureMetadata,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
    ScenarioMetadata,
    Status,
    SubstitutionMetadata,
)
from keemu.profiles import load_profile
from keemu.reports import ReportPaths, build_report, write_report_bundle
from keemu.scenarios import (
    CommandCheck,
    FileCheck,
    HTTPCheck,
    IPKInstall,
    Scenario,
    UDPCheck,
    load_scenario,
)

BASE_LOCK = "locks/m1a-init-aarch64.json"


@dataclass(frozen=True)
class LifecycleResult:
    report: RunReport
    paths: ReportPaths


class StageFailure(Exception):
    def __init__(
        self, status: Status, cause: str, message: str, output: Output | None = None
    ):
        super().__init__(message)
        self.status = status
        self.cause = cause
        self.output = output


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _secure_bytes(path: Path, root: Path, limit: int) -> bytes:
    """Read through no-follow directory FDs; reject replacement and large input."""
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    if not absolute.is_relative_to(root) or absolute == root:
        raise ValueError("input outside project")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in absolute.relative_to(root).parts[:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        file_fd = os.open(
            absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
        )
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("unsafe or oversized input")
            with os.fdopen(file_fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            after = os.fstat(file_fd)
            if (
                len(data) > limit
                or len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size)
                != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)
            ):
                raise ValueError("input changed during read")
            return data
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _item(
    status: Status,
    name: str,
    detail: str,
    *,
    mode: str = "real",
    cause: str = "package",
) -> CheckResult:
    return CheckResult(
        id=name,
        status=status,
        cause_class=cause,
        mode=mode,
        evidence=(detail[:1024],),
        required=True,
        duration_seconds=0,
        limitations=(detail[:1024],) if status in {"BLOCKED", "SKIP", "WARN"} else (),
    )


def _output_evidence(output: Output) -> str:
    return (
        f"exit={output.exit_code} stdout_sha256={_hash(output.stdout)} "
        f"stderr_sha256={_hash(output.stderr)} stdout_bytes={len(output.stdout)} "
        f"stderr_bytes={len(output.stderr)}"
    )


def _residual(
    diff: tuple[str, ...],
    baseline: tuple[str, ...],
    allowed: tuple[str, ...],
    baseline_dirs: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    """Report added/changed/deleted /opt entries not in the explicit allowance.

    opkg status bookkeeping is necessarily changed by an install/remove; no other
    package files are silently whitelisted. Directories are not ignored.
    """
    # opkg's pinned config uses /opt/tmp as a second destination; its empty
    # administrative tree is recreated during install, even for -d root.
    # Whitelist exact bookkeeping entries, not the whole scratch subtree.
    exempt = {
        "C /opt/lib/opkg/status",
        "A /opt/tmp/opt",
        "A /opt/tmp/opt/lib",
        "A /opt/tmp/opt/lib/opkg",
        "A /opt/tmp/opt/lib/opkg/info",
        "A /opt/tmp/opt/lib/opkg/status",
    }
    return tuple(
        line
        for line in diff
        if line not in baseline
        and line not in exempt
        and not (line.startswith("C ") and line[2:] in baseline_dirs)
        and not any(line[2:] == p or line[2:].startswith(p + "/") for p in allowed)
    )


def run_scenario(
    scenario_path: Path,
    lock_path: Path,
    *,
    project_root: Path,
    report_root: Path | None = None,
    run_id: str | None = None,
) -> LifecycleResult:
    """Execute a disposable one-shot scenario; always publish truthful report.

    Does not create/modify persistent environment registry. Failed resource cleanup
    is recorded with exact owned IDs; reconciliation is read-only, never a sweep.
    """
    root = project_root.resolve()
    reports = report_root or root / "reports"
    if run_id is None:
        run_id = f"test-{uuid4().hex}"
    # Validate before any Docker call, even when provided by a programmatic caller.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", run_id):
        raise ValueError("invalid run ID")
    checks: list[CheckResult] = []
    operations: list[OperationLogEntry] = []
    failure: tuple[int, str, StageFailure] | None = None
    profile_meta = ProfileMetadata(
        id="unknown", revision=1, kind="generic", sha256=None
    )
    scenario_blob: bytes | None = None
    lock_blob: bytes | None = None
    evidence: dict[str, bytes] = {}
    artifact: ArtifactMetadata | None = None
    scenario_meta: ScenarioMetadata | None = None
    base: dict = {}
    runtime: DockerRuntime | None = None
    container: str | None = None
    network: str | None = None
    staged: str | None = None
    package_name = ""
    installed = False
    service_started = False
    baseline: tuple[str, ...] = ()
    final_diff: tuple[str, ...] | None = None
    baseline_dirs: frozenset[str] = frozenset()
    scenario: Scenario | None = None
    cleanup_errors: list[str] = []
    substitutions: list[SubstitutionMetadata] = []
    cleanup_authorized = False

    def step(
        name: str,
        action,
        *,
        argv: tuple[str, ...] = (),
        cause: str = "package",
        status: Status = "FAIL",
    ):
        nonlocal failure
        start = _now()
        tick = time.monotonic()
        code = None
        truncated = False
        timed_out = False
        output: Output | None = None
        outcome: Status = "PASS"
        try:
            value = action()
            if isinstance(value, Output):
                output = value
                code = value.exit_code
                truncated = value.truncated_stdout or value.truncated_stderr
            return value
        except StageFailure as exc:
            outcome = exc.status
            if exc.output is not None:
                output = exc.output
                code = exc.output.exit_code
                truncated = exc.output.truncated_stdout or exc.output.truncated_stderr
            if failure is None:
                failure = (len(operations) + 1, name, exc)
            raise
        except Exception as exc:
            outcome = status
            timed_out = "timed out" in str(exc).lower()
            mapped = StageFailure(
                status, cause, f"{type(exc).__name__}: {str(exc)[:512]}"
            )
            if failure is None:
                failure = (len(operations) + 1, name, mapped)
            raise mapped from exc
        finally:
            sequence = len(operations) + 1
            stdout_path = stderr_path = None
            if output is not None:
                stdout_path = f"stdout/{sequence:03d}-{name}.bin"
                stderr_path = f"stderr/{sequence:03d}-{name}.bin"
                evidence[stdout_path] = output.stdout
                evidence[stderr_path] = output.stderr
            operations.append(
                OperationLogEntry(
                    sequence=sequence,
                    operation=name,
                    started_at=start,
                    completed_at=_now(),
                    status=outcome,
                    argv=argv,
                    cwd=None,
                    exit_code=code,
                    duration_seconds=time.monotonic() - tick,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timed_out=timed_out,
                    truncated=truncated,
                )
            )

    def command(
        name: str, args: tuple[str, ...], *, timeout: int = 60, expected: int = 0
    ) -> Output:
        if runtime is None or container is None or scenario is None:
            raise StageFailure("ERROR", "harness", "target runtime not ready")

        def execute() -> Output:
            output = runtime.exec(
                container,
                list(args),
                timeout=min(timeout, 600),
                allow_failure=True,
                cwd=scenario.runtime.cwd,
            )
            if output.exit_code != expected:
                raise StageFailure(
                    "FAIL",
                    "package",
                    f"{name}: exit={output.exit_code}, expected={expected}; "
                    + _output_evidence(output),
                    output=output,
                )
            return output

        return step(name, execute, argv=args, cause="unknown", status="ERROR")

    try:

        def validate():
            nonlocal \
                scenario, \
                profile_meta, \
                scenario_meta, \
                artifact, \
                base, \
                runtime, \
                package_name, \
                scenario_blob, \
                lock_blob
            try:
                scenario = load_scenario(scenario_path, project_root=root)
            except (OSError, ValueError, YAMLError) as exc:
                raise StageFailure(
                    "ERROR", "harness", f"invalid scenario input: {exc}"
                ) from exc
            profile_path = root / "profiles/generic" / f"{scenario.profile}.yaml"
            try:
                profile = load_profile(profile_path)
                lock = load_scenario_lock(
                    lock_path,
                    project_root=root,
                    scenario=scenario,
                    scenario_path=scenario_path,
                )
            except (OSError, ValueError, YAMLError) as exc:
                if "hash mismatch" in str(exc):
                    raise StageFailure(
                        "BLOCKED", "environment", f"locked input changed: {exc}"
                    ) from exc
                raise StageFailure(
                    "ERROR", "harness", f"invalid scenario/lock input: {exc}"
                ) from exc
            scenario_blob = _secure_bytes(scenario_path, root, 1024 * 1024)
            lock_blob = _secure_bytes(lock_path, root, 2 * 1024 * 1024)
            if json.loads(lock_blob) != lock.model_dump(mode="json"):
                raise StageFailure(
                    "BLOCKED", "environment", "lock changed during validation"
                )
            profile_blob = _secure_bytes(profile_path, root, 1024 * 1024)
            if (
                _hash(scenario_blob) != lock.scenario_sha256
                or _hash(profile_blob) != lock.profile_sha256
                or profile.id != lock.profile_id
                or profile.revision != lock.profile_revision
                or profile.entware_target != lock.entware_target
            ):
                raise StageFailure(
                    "BLOCKED", "environment", "scenario/profile lock mismatch"
                )
            scenario_meta = ScenarioMetadata(
                id=scenario.id,
                schema_version=1,
                source=str(scenario_path),
                sha256=lock.scenario_sha256,
            )
            profile_meta = ProfileMetadata(
                id=profile.id,
                revision=profile.revision,
                kind=profile.kind,
                sha256=lock.profile_sha256,
            )
            if (
                profile.entware_target != "aarch64-3.10"
                or scenario.requirements.capabilities
                or scenario.requirements.ndm_fixtures
                or scenario.runtime.env
                or scenario.runtime.publish
            ):
                raise StageFailure(
                    "BLOCKED",
                    "environment",
                    "target, capability, NDM or secret environment unsupported "
                    "in this slice; host publishing is a later slice",
                )
            if not isinstance(scenario.install, IPKInstall):
                raise StageFailure(
                    "BLOCKED", "environment", "pinned-installer adapter not implemented"
                )
            source = resolve_input_path(
                scenario.install.path,
                scenario_dir=scenario_path.parent,
                project_root=root,
            )
            entry = next(
                (
                    s
                    for s in lock.sources
                    if s.kind == "ipk"
                    and resolve_input_path(
                        s.path, scenario_dir=lock_path.parent, project_root=root
                    )
                    == source
                ),
                None,
            )
            if entry is None:
                raise StageFailure(
                    "BLOCKED", "environment", "IPK source absent from lock"
                )
            blob = _secure_bytes(source, root, 64 * 1024 * 1024)
            if _hash(blob) != entry.sha256:
                raise StageFailure(
                    "BLOCKED", "environment", "IPK changed after validation"
                )
            package_name = scenario.install.package_name
            artifact = ArtifactMetadata(
                id=package_name,
                kind="ipk",
                version=entry.release,
                source=entry.origin,
                sha256=entry.sha256,
                architecture=entry.architecture,
            )
            base_path = root / BASE_LOCK
            base = json.loads(_secure_bytes(base_path, root, 2 * 1024 * 1024))
            if (
                base.get("oci_digest") != lock.oci_digest
                or base.get("input_lock_sha256") != lock.feed_lock_sha256
                or base.get("target") != lock.entware_target
            ):
                raise StageFailure(
                    "BLOCKED", "environment", "base image/feed lock mismatch"
                )
            if (
                not (root / "locks/p0-aarch64.json").is_file()
                or _hash(
                    _secure_bytes(root / "locks/p0-aarch64.json", root, 2 * 1024 * 1024)
                )
                != lock.feed_lock_sha256
            ):
                raise StageFailure("BLOCKED", "environment", "feed input lock changed")
            runtime = DockerRuntime(
                run_id, lock.oci_digest, target=profile.entware_target
            )
            return profile, lock, source, blob, scenario_blob, lock_blob

        profile, lock, source, blob, scenario_blob, lock_blob = step(
            "validate", validate, cause="environment", status="BLOCKED"
        )
        checks.append(
            _item(
                "PASS",
                "input-lock",
                "scenario, profile, IPK and base hashes matched",
                mode="static",
            )
        )
        if runtime is None or scenario is None:
            raise StageFailure("ERROR", "harness", "target runtime not ready")

        # Private copy binds static analysis to exactly the bytes copied to target.
        def stage_local():
            nonlocal staged
            stage_root = root / ".runtime/lifecycle-stage"
            stage_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if stage_root.is_symlink() or stage_root.stat().st_uid != os.getuid():
                raise StageFailure("ERROR", "harness", "untrusted staging directory")
            os.chmod(stage_root, 0o700)
            with tempfile.NamedTemporaryFile(
                dir=stage_root, prefix="ipk-", suffix=".ipk", delete=False
            ) as stream:
                stream.write(blob)
                staged = stream.name
            # Docker cp retains mode. opkg's target helper needs the copy readable;
            # the host staging directory remains 0700 for privacy.
            os.chmod(staged, 0o644)

        step("stage-local", stage_local, cause="harness", status="ERROR")

        def static_inspect():
            if staged is None:
                raise StageFailure("ERROR", "harness", "private IPK not staged")
            try:
                inspection = inspect_ipk(
                    Path(staged),
                    profile=profile,
                    rootfs=root / ".runtime/init-cache" / base["cache_key"] / "rootfs",
                )
            except IPKError as exc:
                raise StageFailure(
                    "ERROR", "harness", f"invalid package input: {exc}"
                ) from exc
            if inspection.metadata["Package"] != package_name:
                raise StageFailure(
                    "FAIL", "package", "IPK package name disagrees with scenario"
                )
            if inspection.status == "FAIL":
                raise StageFailure(
                    "FAIL",
                    "package",
                    "static inspection failed: "
                    + "; ".join(
                        f.code for f in inspection.findings if f.status == "FAIL"
                    ),
                )
            if inspection.status == "BLOCKED" and any(
                f.code
                not in {"missing-interpreter", "missing-dependency", "unresolved-link"}
                or "postinst" not in inspection.control_scripts
                for f in inspection.findings
                if f.status == "BLOCKED"
            ):
                raise StageFailure(
                    "BLOCKED",
                    "environment",
                    "static inspection needs unresolved inputs",
                )
            return inspection

        inspection = step("inspect", static_inspect)
        checks.append(
            _item(
                "WARN" if inspection.status in {"WARN", "BLOCKED"} else "PASS",
                "static-inspection",
                f"status={inspection.status}; "
                f"findings={','.join(f.code for f in inspection.findings)}",
                mode="static",
            )
        )

        def capability():
            result = init_locked(root, offline=True)
            if result.get("oci_digest") != lock.oci_digest:
                raise StageFailure("BLOCKED", "environment", "prepared image mismatch")
            return runtime.image()

        step("capability", capability, cause="environment", status="BLOCKED")
        checks.append(
            _item("PASS", "base-capability", "offline cache and Docker image verified")
        )

        # No network or host publish in this one-shot slice.
        def create():
            nonlocal network, container, baseline_dirs, cleanup_authorized
            if runtime is None or scenario is None:
                raise StageFailure("ERROR", "harness", "target runtime not ready")
            state = runtime.reconcile()
            if state["container_owned"] or state["network_owned"]:
                raise StageFailure(
                    "BLOCKED", "environment", "run ID already owns Docker resources"
                )
            cleanup_authorized = True
            container = runtime.create("keemu-" + run_id)
            runtime.start(container)
            # The pinned base contains target BusyBox's gzip applet but not a
            # gzip command link. opkg's archive reader launches gzip by name:
            # without this link even an unchanged locked IPK is "Malformed".
            gzip_link = "/opt/bin/gzip"
            available = runtime.exec(
                container, ["/opt/bin/busybox", "--list"], timeout=30
            ).stdout.splitlines()
            if b"gzip" not in available:
                raise StageFailure("BLOCKED", "environment", "target gzip unavailable")
            absent = runtime.exec(
                container,
                ["/bin/sh", "-c", 'test ! -e "$1" && test ! -L "$1"', "sh", gzip_link],
                allow_failure=True,
            )
            if absent.exit_code != 0:
                raise StageFailure("BLOCKED", "environment", "gzip link already exists")
            runtime.exec(
                container,
                ["/opt/bin/busybox", "ln", "-s", "/opt/bin/busybox", gzip_link],
            )
            substitutions.append(
                SubstitutionMetadata(
                    id="opkg-gzip",
                    replaces="missing /opt/bin/gzip command in pinned base",
                    reason="target opkg invokes gzip to read local IPK archives",
                    evidence=(
                        "Target BusyBox gzip applet checked before linking in "
                        "disposable container; no host tool substituted",
                    ),
                )
            )
            directories = (
                runtime.exec(
                    container,
                    ["/opt/bin/find", "/opt", "-xdev", "-type", "d"],
                    timeout=60,
                )
                .stdout.decode("utf-8")
                .splitlines()
            )
            baseline_dirs = frozenset(directories)
            return runtime.diff(container)

        baseline = step("create", create, cause="environment", status="ERROR")
        checks.append(
            _item(
                "PASS",
                "fresh-environment",
                "owned container started; baseline Docker diff captured",
            )
        )
        destination = (
            f"/opt/tmp/{package_name}_{inspection.metadata['Version']}_"
            f"{inspection.metadata['Architecture']}.ipk"
        )

        def copy_and_verify():
            if container is None or staged is None or artifact is None:
                raise StageFailure("ERROR", "harness", "target staging not ready")
            if (
                _hash(_secure_bytes(Path(staged), root, 64 * 1024 * 1024))
                != artifact.sha256
            ):
                raise StageFailure("BLOCKED", "environment", "private IPK changed")
            runtime.copy_file(container, staged, destination)
            readback = str(Path(staged).with_name("readback-" + uuid4().hex + ".ipk"))
            try:
                runtime.read_staged_file(container, destination, readback)
                if (
                    _hash(_secure_bytes(Path(readback), root, 64 * 1024 * 1024))
                    != artifact.sha256
                ):
                    raise StageFailure(
                        "BLOCKED", "environment", "staged target IPK hash mismatch"
                    )
            finally:
                if os.path.lexists(readback):
                    os.unlink(readback)

        step("stage-ipk", copy_and_verify, cause="environment", status="BLOCKED")
        checks.append(_item("PASS", "staged-ipk", "target hash matches source lock"))

        # Preflight dependencies from installed inventory; never fetch from a feed.
        def check_dependencies():
            if container is None:
                raise StageFailure("ERROR", "harness", "target container not ready")
            inv = runtime.exec(
                container, ["/opt/bin/opkg", "list-installed"], allow_failure=True
            )
            if inv.exit_code:
                raise StageFailure(
                    "ERROR", "environment", "cannot read target package inventory"
                )
            names = {
                line.split(" - ", 1)[0] for line in inv.stdout.decode().splitlines()
            }
            missing = [
                " | ".join(alternatives)
                for alternatives in inspection.dependencies
                if not any(alt.split(" ", 1)[0] in names for alt in alternatives)
            ]
            if missing:
                raise StageFailure(
                    "BLOCKED",
                    "environment",
                    "dependencies not in locked base: " + ",".join(missing),
                )

        step("dependencies", check_dependencies, cause="environment", status="BLOCKED")
        output = command(
            "install", ("/opt/bin/opkg", "install", destination), timeout=300
        )
        installed = True
        checks.append(
            _item(
                "PASS",
                "install-exit",
                "opkg install "
                + _output_evidence(output)
                + "; postinst invoked by opkg only; separate exit unknown",
            )
        )

        def verify_install():
            if container is None:
                raise StageFailure("ERROR", "harness", "target container not ready")
            listing = runtime.exec(
                container,
                ["/opt/bin/opkg", "list-installed", package_name],
                allow_failure=True,
            )
            if listing.exit_code != 0 or not any(
                line == f"{package_name} - {inspection.metadata['Version']}"
                for line in listing.stdout.decode().splitlines()
            ):
                raise StageFailure(
                    "FAIL",
                    "package",
                    "opkg package inventory missing after install",
                    listing,
                )
            files = runtime.exec(
                container, ["/opt/bin/opkg", "files", package_name], allow_failure=True
            )
            if files.exit_code != 0:
                raise StageFailure(
                    "FAIL", "package", "opkg files inventory unavailable", files
                )
            recorded = set(files.stdout.decode("utf-8", "replace").splitlines())
            for entry in inspection.entries:
                path = "/" + entry.path
                if entry.kind != "dir" and path not in recorded:
                    raise StageFailure(
                        "FAIL",
                        "package",
                        f"installed file absent from opkg inventory: {path}",
                    )
                presence = runtime.exec(
                    container,
                    ["/bin/sh", "-c", 'test -e "$1" || test -L "$1"', "sh", path],
                    allow_failure=True,
                )
                if presence.exit_code != 0:
                    raise StageFailure(
                        "FAIL", "package", f"installed file absent: {path}"
                    )
                if entry.kind == "symlink":
                    linked = runtime.exec(
                        container,
                        ["/bin/sh", "-c", 'test -e "$1"', "sh", path],
                        allow_failure=True,
                    )
                    if linked.exit_code != 0:
                        raise StageFailure(
                            "FAIL", "package", f"broken installed symlink: {path}"
                        )
            return files

        files = step("verify-install", verify_install, cause="unknown", status="ERROR")
        checks.append(
            _item(
                "PASS",
                "installed-state",
                f"opkg package and file inventory verified; {_output_evidence(files)}",
            )
        )
        if scenario.service is not None:
            # A postinst may already have started the service. Probe first;
            # never duplicate start/boot just because a start argv is present.
            def detect_service():
                try:
                    return _probe(runtime, container, scenario.service.readiness)
                except StageFailure as exc:
                    if exc.status == "FAIL" and str(exc).startswith(
                        "HTTP connection refused:"
                    ):
                        return None
                    raise

            already_ready = step(
                "detect-service", detect_service, cause="unknown", status="ERROR"
            )
            if already_ready is None:
                output = command("service-start", scenario.service.start)
                checks.append(_item("PASS", "service-start", _output_evidence(output)))
            else:
                checks.append(_item("PASS", "installer-started", already_ready))
            service_started = True
            # Readiness must be an actual endpoint assertion, not process presence.
            ready = step(
                "readiness",
                lambda: _retry_probe(
                    lambda: _probe(runtime, container, scenario.service.readiness),
                    scenario.service.readiness.timeout_seconds,
                ),
                cause="environment",
                status="BLOCKED",
            )
            checks.append(_item("PASS", "readiness", ready))
        for check in scenario.checks:

            def verify(check=check):
                if container is None:
                    raise StageFailure("ERROR", "harness", "target container not ready")
                if isinstance(check, CommandCheck):
                    output = runtime.exec(
                        container,
                        list(check.command.argv),
                        timeout=min(check.command.timeout_seconds, 600),
                        allow_failure=True,
                        cwd=scenario.runtime.cwd,
                    )
                    if output.exit_code != check.expected_exit_code:
                        raise StageFailure(
                            "FAIL",
                            "package",
                            f"expected exit={check.expected_exit_code}; "
                            + _output_evidence(output),
                            output,
                        )
                    return _output_evidence(output)
                if isinstance(check, FileCheck):
                    output = runtime.exec(
                        container,
                        ["/bin/sh", "-c", 'test -e "$1"', "sh", check.path],
                        allow_failure=True,
                    )
                    if (output.exit_code == 0) != check.exists:
                        raise StageFailure(
                            "FAIL",
                            "package",
                            f"file expectation not met: {check.path}",
                            output,
                        )
                    return f"file={check.path} exists={check.exists}"
                return _probe(runtime, container, check)

            detail = step("check-" + check.id, verify, cause="unknown", status="ERROR")
            checks.append(_item("PASS", "check-" + check.id, detail))
        if scenario.service is not None:
            output = command("service-stop", scenario.service.stop)
            service_started = False
            checks.append(_item("PASS", "service-stop", _output_evidence(output)))

            # A wrong HTTP body/status is still a live socket, not a closed one.
            checks.append(
                _item(
                    "PASS",
                    "service-closed",
                    step(
                        "verify-stop",
                        lambda: _retry_probe(
                            lambda: _probe_stopped(
                                runtime, container, scenario.service.readiness
                            ),
                            scenario.service.readiness.timeout_seconds,
                        ),
                        cause="unknown",
                        status="ERROR",
                    ),
                )
            )
        output = command(
            "remove", ("/opt/bin/opkg", "remove", package_name), timeout=300
        )
        installed = False
        checks.append(_item("PASS", "remove-exit", _output_evidence(output)))

        def residual():
            nonlocal final_diff
            if container is None:
                raise StageFailure("ERROR", "harness", "target container not ready")
            inv = runtime.exec(
                container,
                ["/opt/bin/opkg", "list-installed", package_name],
                allow_failure=True,
            )
            if inv.exit_code or any(
                line.startswith(package_name + " - ")
                for line in inv.stdout.decode().splitlines()
            ):
                raise StageFailure(
                    "FAIL", "package", "package remains in opkg inventory"
                )
            runtime.exec(container, ["/opt/bin/busybox", "rm", "-f", destination])
            diff = runtime.diff(container)
            final_diff = diff
            differences = _residual(
                diff, baseline, scenario.cleanup.allowed_residual_paths, baseline_dirs
            )
            if differences:
                raise StageFailure(
                    "FAIL",
                    "package",
                    "unexpected residuals: " + "; ".join(differences[:20]),
                )
            return "opkg absent; residual diff matches baseline and explicit allowance"

        checks.append(
            _item(
                "PASS",
                "residual",
                step("residual", residual, cause="unknown", status="ERROR"),
            )
        )
    except StageFailure as exc:
        if failure:
            checks.append(_item(exc.status, failure[1], str(exc), cause=exc.cause))
    finally:
        # Cleanup is unconditional, including partial create and failed postinst.
        if staged:
            try:
                os.unlink(staged)
            except OSError as exc:
                cleanup_errors.append(f"local stage: {exc}")
        if runtime is not None:
            if cleanup_authorized and container:
                if (
                    service_started
                    and scenario is not None
                    and scenario.service is not None
                ):
                    try:
                        stopped = runtime.exec(
                            container, list(scenario.service.stop), allow_failure=True
                        )
                        if stopped.exit_code:
                            cleanup_errors.append(
                                "best-effort service stop: " + _output_evidence(stopped)
                            )
                    except Exception as exc:
                        cleanup_errors.append(f"best-effort service stop: {exc}")
                if installed or failure is not None:
                    try:
                        if package_name:
                            removed = runtime.exec(
                                container,
                                ["/opt/bin/opkg", "remove", package_name],
                                timeout=300,
                                allow_failure=True,
                            )
                            if removed.exit_code:
                                cleanup_errors.append(
                                    "best-effort package removal: "
                                    + _output_evidence(removed)
                                )
                    except Exception as exc:
                        cleanup_errors.append(f"best-effort package removal: {exc}")
                try:
                    runtime.remove_container(container)
                except Exception as exc:
                    cleanup_errors.append(f"owned container {container}: {exc}")
            if cleanup_authorized and network:
                try:
                    runtime.remove_network(network)
                except Exception as exc:
                    cleanup_errors.append(f"owned network {network}: {exc}")
            if cleanup_authorized:
                try:
                    state = runtime.reconcile()
                    # A create can allocate an ID before the boundary returns it.
                    # Only exact run-owned IDs may be removed.
                    for identifier in state["container_owned"]:
                        runtime.remove_container(identifier)
                    for identifier in state["network_owned"]:
                        runtime.remove_network(identifier)
                    state = runtime.reconcile()
                    if state["container_owned"] or state["network_owned"]:
                        cleanup_errors.append("owned resources remain: " + str(state))
                except Exception as exc:
                    cleanup_errors.append(f"cleanup reconciliation unavailable: {exc}")
        if cleanup_errors:
            checks.append(
                _item("ERROR", "cleanup", "; ".join(cleanup_errors), cause="harness")
            )
        else:
            checks.append(
                _item(
                    "PASS",
                    "cleanup",
                    "owned resources removed and absence reconciled"
                    if cleanup_authorized
                    else "no Docker resources allocated by this run",
                )
            )
        # A cleanup failure has its own operation; never hide the original cause.
        operations.append(
            OperationLogEntry(
                sequence=len(operations) + 1,
                operation="cleanup",
                started_at=_now(),
                completed_at=_now(),
                status="ERROR" if cleanup_errors else "PASS",
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
    if failure is not None:
        sequence, name, issue = failure
        partial = PartialFailureMetadata(
            status=issue.status,
            operation_sequence=sequence,
            operation=name,
            cause_class=issue.cause,
            message=str(issue),
            interrupted=False,
            cleanup_attempted=True,
            cleanup_status="ERROR" if cleanup_errors else "PASS",
            preserved_artifacts=(str(reports / run_id / "report.json"),),
        )
    elif cleanup_errors:
        partial = PartialFailureMetadata(
            status="ERROR",
            operation_sequence=len(operations),
            operation="cleanup",
            cause_class="harness",
            message="; ".join(cleanup_errors),
            interrupted=False,
            cleanup_attempted=True,
            cleanup_status="ERROR",
            preserved_artifacts=(str(reports / run_id / "report.json"),),
        )
    else:
        partial = None
    metadata = RuntimeMetadata(
        keemu_version=__version__,
        git_commit=None,
        git_dirty=None,
        oci_digest=base.get("oci_digest"),
        qemu_version=None,
        binfmt_configuration=(),
        host_kernel=platform.release(),
        entware_target=base.get("target", "unknown"),
        feed_lock_sha256=base.get("input_lock_sha256"),
        versions=(),
        network_fidelity=None,
        native_tools=(),
    )
    if scenario_blob is not None and lock_blob is not None:
        evidence["resolved-scenario.yaml"] = scenario_blob
        evidence["lock.json"] = lock_blob
    if final_diff is not None:
        evidence["filesystem.diff.json"] = (
            json.dumps(
                {
                    "kind": "docker-diff-metadata",
                    "baseline": baseline,
                    "after": final_diff,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
    report = build_report(
        run_id=run_id,
        created_at=_now(),
        operation="test",
        profile=profile_meta,
        runtime=metadata,
        checks=checks,
        artifact=artifact,
        scenario=scenario_meta,
        operation_log=operations,
        partial_failure=partial,
        substitutions=substitutions,
        limitations=(
            "No persistent registry; Docker-host/client vantage, target HTTPS "
            "and UDP not implemented in this slice",
            "Postinst is run only by opkg; independent postinst exit/count not claimed",
            "Docker diff is metadata-only; byte-identical residuals and "
            "socket closure are not proven by it",
            "Only opkg's exact observed scratch bookkeeping entries are "
            "exempt from residual comparison",
        ),
    )
    paths = write_report_bundle(report, reports / run_id, evidence=evidence)
    return LifecycleResult(report=report, paths=paths)


def _probe(runtime: DockerRuntime, container: str, probe) -> str:
    if not isinstance(probe, (HTTPCheck, UDPCheck)):
        # Service readiness is HTTPProbe, not HTTPCheck; test by kind.
        if getattr(probe, "kind", None) not in {"http", "https", "udp"}:
            raise StageFailure("BLOCKED", "environment", "unknown probe kind")
    if probe.vantage != "target_loopback" or probe.kind != "http":
        raise StageFailure(
            "BLOCKED",
            "environment",
            f"{probe.kind}/{probe.vantage} requires a separate proven vantage/tool",
        )
    import urllib.parse

    parsed = urllib.parse.urlsplit(probe.url)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise StageFailure(
            "BLOCKED", "environment", "target HTTP endpoint must use loopback"
        )
    output = runtime.exec(
        container,
        ["/opt/bin/busybox", "wget", "-S", "-O", "-", probe.url],
        timeout=min(probe.timeout_seconds, 600),
        allow_failure=True,
    )
    if output.exit_code != 0:
        stderr = output.stderr.decode("utf-8", "replace")
        if "Connection refused" in stderr:
            raise StageFailure(
                "FAIL",
                "package",
                "HTTP connection refused: " + _output_evidence(output),
                output,
            )
        raise StageFailure(
            "FAIL",
            "package",
            "HTTP request failed: " + _output_evidence(output),
            output,
        )
    headers = output.stderr.decode("utf-8", "replace")
    codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", headers)
    if not codes:
        raise StageFailure("BLOCKED", "environment", "wget did not expose HTTP status")
    if (
        int(codes[-1]) not in probe.expected_status
        or probe.body_contains.encode() not in output.stdout
    ):
        raise StageFailure(
            "FAIL",
            "package",
            "HTTP status/body mismatch: " + _output_evidence(output),
            output,
        )
    return f"HTTP status={codes[-1]} body marker matched; " + _output_evidence(output)


def _probe_stopped(runtime: DockerRuntime, container: str, probe) -> str:
    """Only a refused target-loopback connection proves HTTP is not listening."""
    if probe.kind != "http" or probe.vantage != "target_loopback":
        raise StageFailure("BLOCKED", "environment", "socket closure probe unsupported")
    output = runtime.exec(
        container,
        ["/opt/bin/busybox", "wget", "-S", "-O", "-", probe.url],
        timeout=min(probe.timeout_seconds, 600),
        allow_failure=True,
    )
    stderr = output.stderr.decode("utf-8", "replace")
    if re.search(r"HTTP/\d(?:\.\d)?\s+\d{3}", stderr) or output.exit_code == 0:
        raise StageFailure(
            "FAIL", "package", "HTTP endpoint still reachable after stop", output
        )
    if "Connection refused" not in stderr:
        raise StageFailure(
            "BLOCKED",
            "environment",
            "socket closure inconclusive: " + _output_evidence(output),
            output,
        )
    return "target-loopback HTTP connection refused; " + _output_evidence(output)


def _retry_probe(action, timeout_seconds: int) -> str:
    deadline = time.monotonic() + min(timeout_seconds, 600)
    while True:
        try:
            return action()
        except StageFailure as exc:
            if exc.status != "FAIL" or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
