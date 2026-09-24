"""Offline, isolated target-GCC build of MIPS fixtures against Entware libc."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from keemu.entware import verify_artifact_cache

REPO = Path(__file__).resolve().parents[1]
SOURCES = {
    "hello": "fixtures/sources/hello/hello.c",
    "web-demo": "fixtures/sources/web-demo/web_demo.c",
    "nfqueue-consumer": "fixtures/sources/nfqueue/nfqueue_consumer.c",
}
CFLAGS = [
    "-std=c17",
    "-O2",
    "-g0",
    "-fno-ident",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-mabi=32",
    "-march=mips32r2",
    "-msoft-float",
    "-Wl,--build-id=none",
]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    argv: list[str], *, timeout: int = 600, env: dict[str, str] | None = None
) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed project tool argv, no shell.
        argv, text=True, capture_output=True, timeout=timeout, env=env
    )
    if result.returncode:
        raise RuntimeError(
            f"{argv[:4]} exited {result.returncode}: {result.stderr[-1600:]}"
        )
    return result.stdout.strip()


def build(target: str) -> dict:
    arch = target.removesuffix("-3.4")
    workspace = REPO / ".runtime/m1b18" / target
    sdk_lock = json.loads((REPO / "locks" / f"m1b18-sdk-{target}.json").read_text())
    verify_artifact_cache(sdk_lock, workspace / "packages")
    root = workspace / "sdk-rootfs"
    if not root.exists():
        shutil.copytree(workspace / "rootfs", root, symlinks=True)
        config = root / "opt/etc/opkg.conf"
        config.write_text(f"dest root /\narch all 100\narch {target} 160\n")
        bootstrap = [
            str(
                (REPO / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{arch}").resolve()
            ),
            str((workspace / "opkg").resolve()),
            "-f",
            str(config),
            "-o",
            str(root),
            "-t",
            str(root / "opt/tmp"),
        ]
        packages = [
            str((workspace / "packages" / item["filename"]).resolve())
            for item in sdk_lock["packages"]
        ]
        run(bootstrap + ["--nodeps", "install", *packages])
    sources = root / "opt/tmp/keemu-build"
    sources.mkdir(parents=True, exist_ok=True)
    for name, path in SOURCES.items():
        shutil.copyfile(REPO / path, sources / f"{name}.c")
    qemu = REPO / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{arch}"
    proot = REPO / ".runtime/p0/proot-root/usr/bin/proot"
    lib = REPO / ".runtime/p0/proot-root/usr/lib/x86_64-linux-gnu"
    env = {
        "HOME": "/root",
        "PATH": "/opt/bin:/opt/sbin:/usr/bin:/bin",
        "LANG": "C",
        "LD_LIBRARY_PATH": str(lib.resolve()),
    }
    outputs = {}
    for name, source in SOURCES.items():
        argv = [
            str(proot),
            "-R",
            str(root),
            "-q",
            str(qemu),
            "-w",
            "/opt",
            "/opt/bin/gcc",
            *CFLAGS,
            "-o",
            f"/opt/tmp/keemu-build/{name}",
            f"/opt/tmp/keemu-build/{name}.c",
        ]
        completed = subprocess.run(  # noqa: S603 -- pinned target GCC argv.
            argv, capture_output=True, text=True, env=env, timeout=600
        )
        if completed.returncode:
            if name == "nfqueue-consumer":
                outputs[name] = {"status": "BLOCKED", "reason": completed.stderr[-800:]}
                continue
            raise RuntimeError(f"{target} {name} build: {completed.stderr[-1200:]}")
        binary = sources / name
        output = workspace / "fixtures" / name
        output.parent.mkdir(exist_ok=True)
        shutil.copyfile(binary, output)
        output.chmod(0o755)
        outputs[name] = {
            "status": "PASS",
            "source": source,
            "source_sha256": sha(REPO / source),
            "path": str(output.relative_to(REPO)),
            "sha256": sha(output),
        }
        print(target, name, outputs[name]["sha256"], flush=True)
    return {
        "target": target,
        "sdk_lock_sha256": sha(REPO / "locks" / f"m1b18-sdk-{target}.json"),
        "qemu_sha256": sha(qemu),
        "compiler": run(
            [str(proot), "-R", str(root), "-q", str(qemu), "/opt/bin/gcc", "--version"],
            env=env,
        ).splitlines()[0],
        "flags": CFLAGS,
        "fixtures": outputs,
    }


if __name__ == "__main__":
    for target in ("mipsel-3.4", "mips-3.4"):
        result = build(target)
        destination = REPO / "locks" / f"m1b18-fixtures-{target}.json"
        prior = json.loads(destination.read_text()) if destination.exists() else None
        if prior is not None:
            # Historical first capture predates the QEMU binding.
            prior.setdefault("qemu_sha256", result["qemu_sha256"])
        if prior is not None and prior != result:
            raise ValueError(f"fixture output differs from frozen lock: {target}")
        if prior is None or "qemu_sha256" not in json.loads(destination.read_text()):
            destination.write_text(json.dumps(result, indent=2) + "\n")
