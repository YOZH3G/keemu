from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from keemu.entware import verify_artifact_cache


@dataclass(frozen=True, slots=True)
class DiagnosticRootfsResult:
    package_count: int
    installed_packages: str


@dataclass(frozen=True, slots=True)
class DiagnosticSmokeResult:
    stdout: str
    stderr: str


def _run(
    argv: list[str], *, timeout: int, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- argv only; shell execution is disabled.
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def build_diagnostic_rootfs(
    *,
    lock_path: Path,
    package_cache: Path,
    destination: Path,
    qemu: Path,
    bootstrap_opkg: Path,
    timeout: int = 300,
) -> DiagnosticRootfsResult:
    """Build a locked rootfs with real target opkg via direct QEMU user-mode.

    This is a diagnostic P0 path, not the required Docker runtime proof.
    """
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    verified = verify_artifact_cache(lock, package_cache)
    if destination.exists():
        raise FileExistsError(f"destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        for relative in (
            "bin",
            "sbin",
            "etc",
            "lib",
            "usr",
            "tmp",
            "run",
            "var",
            "root",
            "opt/etc",
            "opt/tmp",
            "opt/var/lock",
            "opt/var/opkg-lists",
        ):
            (temporary / relative).mkdir(parents=True, exist_ok=True)
        opkg_config = temporary / ".keemu-opkg.conf"
        opkg_config.write_text(
            "\n".join(
                (
                    "dest root /",
                    "arch all 100",
                    f"arch {lock['target']} 160",
                    "",
                )
            ),
            encoding="utf-8",
        )
        packages = [str((package_cache / filename).resolve()) for filename in verified]
        base = [
            str(qemu.resolve()),
            str(bootstrap_opkg.resolve()),
            "-f",
            str(opkg_config.resolve()),
            "-o",
            str(temporary.resolve()),
            "-t",
            str((temporary / "opt/tmp").resolve()),
        ]
        _run(base + ["--nodeps", "install", *packages], timeout=timeout)
        installed = _run(base + ["list-installed"], timeout=60).stdout
        (temporary / "bin/sh").symlink_to("/opt/bin/busybox")
        loaders = {
            "aarch64-3.10": "ld-linux-aarch64.so.1",
            "mipsel-3.4": "ld.so.1",
            "mips-3.4": "ld.so.1",
        }
        loader = loaders[lock["target"]]
        (temporary / "lib" / loader).symlink_to("/opt/lib/" + loader)
        opkg_config.unlink()
        temporary.replace(destination)
        return DiagnosticRootfsResult(
            package_count=len(verified), installed_packages=installed
        )
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def run_proot_smoke(
    *,
    rootfs: Path,
    qemu: Path,
    proot: Path,
    proot_library_path: Path,
    timeout: int = 60,
) -> DiagnosticSmokeResult:
    """Run nested target ELF and shebang checks in unprivileged PRoot."""
    script = rootfs / "opt/tmp/keemu-nested-smoke.sh"
    script.write_text(
        "#!/bin/sh\necho shebang-child-ok\n/opt/bin/busybox uname -m\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    env = {
        "HOME": "/root",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(proot_library_path.resolve()),
    }
    command = [
        str(proot.resolve()),
        "-R",
        str(rootfs.resolve()),
        "-q",
        str(qemu.resolve()),
        "-w",
        "/opt",
        "/bin/sh",
        "-c",
        "echo target-shell-ok; "
        "/opt/bin/opkg --version; "
        "/opt/bin/busybox true; "
        "echo nested-elf-ok; "
        "/opt/tmp/keemu-nested-smoke.sh",
    ]
    completed = _run(command, timeout=timeout, env=env)
    return DiagnosticSmokeResult(stdout=completed.stdout, stderr=completed.stderr)
