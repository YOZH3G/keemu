"""Prepare each MIPS base rootfs from the SHA-256-captured Entware closure."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from keemu.entware import verify_artifact_cache
from keemu.init_cache import _inventory
from keemu.p0 import build_diagnostic_rootfs

REPO = Path(__file__).resolve().parents[1]


def prepare(target: str) -> dict:
    if target not in ("mipsel-3.4", "mips-3.4"):
        raise ValueError("unsupported target")
    work = REPO / ".runtime/m1b18" / target
    lock_path = REPO / "locks" / f"m1b18-{target}.json"
    lock = json.loads(lock_path.read_text())
    if lock["target"] != target:
        raise ValueError("target lock mismatch")
    verify_artifact_cache(lock, work / "packages")
    for artifact in lock["bootstrap_artifacts"]:
        if (
            hashlib.sha256((work / artifact["filename"]).read_bytes()).hexdigest()
            != artifact["sha256"]
        ):
            raise ValueError("bootstrap artifact mismatch")
    root = work / "rootfs"
    if root.exists() or root.is_symlink():
        raise FileExistsError(f"refusing to replace existing rootfs: {root}")
    result = build_diagnostic_rootfs(
        lock_path=lock_path,
        package_cache=work / "packages",
        destination=root,
        qemu=REPO / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{target[:-4]}",
        bootstrap_opkg=work / "opkg",
        timeout=600,
    )
    inventory = _inventory(result.installed_packages, lock)
    if result.package_count != len(inventory):
        raise ValueError("target opkg inventory count mismatch")
    return {
        "target": target,
        "package_count": len(inventory),
        "rootfs": str(root.relative_to(REPO)),
    }


if __name__ == "__main__":
    for target in ("mipsel-3.4", "mips-3.4"):
        print(json.dumps(prepare(target), sort_keys=True))
