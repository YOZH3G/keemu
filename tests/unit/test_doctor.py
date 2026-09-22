from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from keemu.doctor import collect_doctor
from keemu.models import RunReport
from keemu.profiles import GenericProfile

PROFILE = GenericProfile.model_validate(
    {
        "schema_version": 1,
        "id": "generic-aarch64",
        "revision": 1,
        "kind": "generic",
        "entware_target": "aarch64-3.10",
        "cpu": {
            "arch": "aarch64",
            "endian": "little",
            "elf_class": 64,
            "qemu": "qemu-aarch64",
        },
        "kernel": {"execution": "host", "reported_release": None},
        "filesystem": {"entware_root": "/opt"},
        "ndm": {"mode": "strict", "fixtures": []},
        "network": {"logical_to_linux": {"ISP": "wan0", "Bridge0": "br0"}},
    }
)


def test_doctor_reports_missing_runtime_capabilities_as_blocked(
    tmp_path: Path,
) -> None:
    empty_path = tmp_path / "bin"
    empty_path.mkdir()
    binfmt = tmp_path / "binfmt_misc"
    binfmt.mkdir()

    report = collect_doctor(
        PROFILE,
        search_path=str(empty_path),
        docker_socket=tmp_path / "docker.sock",
        binfmt_root=binfmt,
        disk_path=tmp_path,
    )

    statuses = {check.id: check.status for check in report.checks}
    assert isinstance(report, RunReport)
    assert report.overall == "BLOCKED"
    assert statuses["docker-cli"] == "BLOCKED"
    assert statuses["docker-daemon"] == "BLOCKED"
    assert statuses["qemu"] == "BLOCKED"
    assert statuses["binfmt"] == "BLOCKED"
    assert statuses["disk-space"] == "PASS"
    assert report.coverage.required == len(report.checks)
    assert report.coverage.blocked == 4


def test_doctor_reports_docker_probe_timeout_as_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    docker_socket = tmp_path / "docker.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(docker_socket))
    monkeypatch.setattr(
        "keemu.doctor.shutil.which",
        lambda executable, path=None: f"/mock/{executable}",
    )
    monkeypatch.setattr(
        "keemu.doctor.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd=args[0], timeout=10)
        ),
    )
    try:
        report = collect_doctor(
            PROFILE,
            docker_socket=docker_socket,
            binfmt_root=tmp_path / "binfmt_misc",
            disk_path=tmp_path,
        )
    finally:
        listener.close()

    docker_daemon = next(
        check for check in report.checks if check.id == "docker-daemon"
    )
    assert docker_daemon.status == "ERROR"
    assert report.overall == "ERROR"
