from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from keemu import __version__
from keemu.models import (
    CapabilityResult,
    CheckResult,
    ProfileMetadata,
    RunReport,
    RuntimeMetadata,
    RuntimeVersion,
    Status,
)
from keemu.profiles import GenericProfile
from keemu.reports import build_report


def _check(
    identifier: str,
    status: Status,
    evidence: str,
    *,
    required: bool = True,
) -> CheckResult:
    return CheckResult(
        id=identifier,
        status=status,
        required=required,
        mode="real",
        cause_class="environment",
        evidence=(evidence,),
        duration_seconds=0.0,
        limitations=(evidence,) if status in {"WARN", "BLOCKED"} else (),
    )


def collect_doctor(
    profile: GenericProfile,
    *,
    search_path: str | None = None,
    docker_socket: Path = Path("/var/run/docker.sock"),
    binfmt_root: Path = Path("/proc/sys/fs/binfmt_misc"),
    disk_path: Path = Path("."),
    minimum_free_bytes: int = 5 * 1024 * 1024 * 1024,
) -> RunReport:
    """Collect read-only host capability evidence for one generic profile."""
    checks: list[CheckResult] = []
    binfmt_configuration: list[str] = []
    system = platform.system()
    machine = platform.machine()
    host_ok = system == "Linux" and machine in {"x86_64", "amd64"}
    checks.append(
        _check(
            "host-platform",
            "PASS" if host_ok else "BLOCKED",
            f"system={system} machine={machine}",
        )
    )

    docker = shutil.which("docker", path=search_path)
    checks.append(
        _check(
            "docker-cli",
            "PASS" if docker else "BLOCKED",
            docker or "docker executable not found",
        )
    )
    if not docker_socket.is_socket():
        checks.append(
            _check(
                "docker-daemon",
                "BLOCKED",
                f"Docker socket unavailable: {docker_socket}",
            )
        )
    elif docker is None:
        checks.append(
            _check("docker-daemon", "BLOCKED", "Docker CLI unavailable for probe")
        )
    else:
        try:
            probe = subprocess.run(  # noqa: S603 -- resolved argv; shell is disabled.
                [docker, "info", "--format", "{{.ServerVersion}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env={**os.environ, "DOCKER_HOST": f"unix://{docker_socket}"},
            )
        except subprocess.TimeoutExpired:
            checks.append(
                _check(
                    "docker-daemon",
                    "ERROR",
                    "docker info timed out after 10 seconds",
                )
            )
        else:
            if probe.returncode == 0:
                checks.append(
                    _check("docker-daemon", "PASS", f"server={probe.stdout.strip()}")
                )
            else:
                detail = (probe.stderr or probe.stdout).strip().splitlines()
                checks.append(
                    _check(
                        "docker-daemon",
                        "BLOCKED",
                        detail[-1]
                        if detail
                        else f"docker info exited {probe.returncode}",
                    )
                )

    qemu = shutil.which(profile.cpu.qemu, path=search_path) or shutil.which(
        f"{profile.cpu.qemu}-static", path=search_path
    )
    checks.append(
        _check(
            "qemu",
            "PASS" if qemu else "BLOCKED",
            qemu or f"{profile.cpu.qemu} executable not found",
        )
    )

    registration_names = (profile.cpu.qemu, f"{profile.cpu.qemu}-static")
    registration = next(
        (
            binfmt_root / name
            for name in registration_names
            if (binfmt_root / name).is_file()
        ),
        None,
    )
    if registration is None:
        checks.append(
            _check(
                "binfmt",
                "BLOCKED",
                f"no registration for {profile.cpu.arch} under {binfmt_root}",
            )
        )
    else:
        content = registration.read_text(encoding="utf-8", errors="replace")
        binfmt_configuration = content.splitlines()
        status: Status = (
            "PASS" if content.splitlines()[:1] == ["enabled"] else "BLOCKED"
        )
        checks.append(_check("binfmt", status, f"registration={registration}"))

    usage = shutil.disk_usage(disk_path)
    disk_ok = usage.free >= minimum_free_bytes
    checks.append(
        _check(
            "disk-space",
            "PASS" if disk_ok else "BLOCKED",
            f"free_bytes={usage.free} minimum_bytes={minimum_free_bytes}",
        )
    )
    limitations = [
        limitation
        for check in checks
        for limitation in check.limitations
    ]
    profile_payload = json.dumps(
        profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    return build_report(
        run_id=f"doctor-{uuid4().hex}",
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        operation="doctor",
        profile=ProfileMetadata(
            id=profile.id,
            revision=profile.revision,
            kind=profile.kind,
            sha256=hashlib.sha256(profile_payload).hexdigest(),
        ),
        runtime=RuntimeMetadata(
            keemu_version=__version__,
            git_commit=None,
            git_dirty=None,
            oci_digest=None,
            qemu_version=None,
            binfmt_configuration=tuple(binfmt_configuration),
            host_kernel=platform.release(),
            entware_target=profile.entware_target,
            feed_lock_sha256=None,
            versions=(
                RuntimeVersion(name="python", version=platform.python_version()),
            ),
            network_fidelity=None,
            native_tools=(),
        ),
        capabilities=tuple(
            CapabilityResult(
                id=check.id,
                status=check.status,
                mode=check.mode,
                evidence=check.evidence,
                limitations=check.limitations,
            )
            for check in checks
        ),
        checks=checks,
        limitations=limitations,
    )
