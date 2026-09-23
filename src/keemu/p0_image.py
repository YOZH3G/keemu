"""P0-only locked mixed-architecture OCI image builder and offline architecture audit.

No container is created or run here; Docker-backed target execution belongs to p0-05.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import tarfile
from pathlib import Path

from keemu.entware import _sha256_file, verify_artifact_cache
from keemu.p0 import build_diagnostic_rootfs

TARGET = "aarch64-3.10"
PLATFORM = "linux/amd64"
IMAGE = "keemu/p0-aarch64:mixed-v1"
LABELS = {
    "org.keemu.owner": "keemu",
    "org.keemu.phase": "p0-04",
    "org.keemu.target": TARGET,
    "org.keemu.native": "linux/amd64",
    "org.keemu.runtime": "mixed-native-init-target-rootfs",
}
# These are container-creation settings, not properties of an OCI image.
CONTAINER_LIMITS = (
    "--memory=256m",
    "--memory-swap=256m",
    "--cpus=1",
    "--pids-limit=128",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--network=none",
    "--read-only",
    "--tmpfs=/tmp:rw,nosuid,nodev,size=16m",
    "--tmpfs=/run:rw,nosuid,nodev,size=4m",
    "--tmpfs=/opt/var:rw,nosuid,nodev,size=32m",
)


def container_create_argv(name: str, image_id: str, run_id: str) -> list[str]:
    """Future runtime boundary: never create a container in p0-04."""
    if (
        not name.startswith("keemu-")
        or not run_id
        or not image_id.startswith("sha256:")
    ):
        raise ValueError("invalid owned container parameters")
    return [
        "docker",
        "create",
        "--name",
        name,
        "--platform",
        PLATFORM,
        *(
            part
            for key, value in LABELS.items()
            for part in ("--label", f"{key}={value}")
        ),
        "--label",
        f"org.keemu.run-id={run_id}",
        *CONTAINER_LIMITS,
        image_id,
    ]


def _run(args: list[str], timeout: int = 600) -> str:
    return subprocess.run(  # noqa: S603 -- fixed executable, argv only, no shell.
        args, check=True, capture_output=True, text=True, timeout=timeout
    ).stdout


def audit_tree(root: Path) -> dict[str, object]:
    """Hash regular files and symlinks; reject non-target ELF outside /__keemu."""
    digest = hashlib.sha256()
    machines: dict[str, list[str]] = {"aarch64": [], "amd64": []}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if target.startswith("/proc/") or target.startswith("/sys/"):
                raise ValueError(f"unsafe rootfs link: {relative}")
            record = f"L {relative} {stat.S_IMODE(mode):o} {target}\n"
        elif stat.S_ISREG(mode):
            sha = _sha256_file(path)
            record = f"F {relative} {stat.S_IMODE(mode):o} {sha}\n"
            with path.open("rb") as stream:
                header = stream.read(20)
            if header.startswith(b"\x7fELF"):
                if header[4] != 2 or header[5] != 1:
                    raise ValueError(f"wrong ELF class/endianness: {relative}")
                machine = struct.unpack("<H", header[18:20])[0]
                expected = 62 if relative.startswith("__keemu/") else 183
                if machine != expected:
                    raise ValueError(f"wrong ELF architecture: {relative} ({machine})")
                machines["amd64" if machine == 62 else "aarch64"].append(relative)
        else:
            raise ValueError(f"unsupported rootfs node: {relative}")
        digest.update(record.encode())
    for required in ("bin/sh", "opt/bin/opkg", "opt/bin/busybox", "__keemu/init"):
        if not ((root / required).exists() or (root / required).is_symlink()):
            raise ValueError(f"required target path absent: {required}")
    if os.readlink(root / "bin/sh") != "/opt/bin/busybox":
        raise ValueError("target /bin/sh is not Entware BusyBox")
    for required in ("opt/bin/opkg", "opt/bin/busybox", "__keemu/init"):
        if not (root / required).is_file() or (root / required).is_symlink():
            raise ValueError(f"required ELF is not a regular file: {required}")
    if not machines["aarch64"] or machines["amd64"] != ["__keemu/init"]:
        raise ValueError("native/target ELF inventory is incomplete")
    return {"tree_sha256": digest.hexdigest(), "elf": machines}


def build_image(repo: Path) -> dict[str, object]:
    repo = repo.resolve()
    runtime = repo / ".runtime/p0"
    context = runtime / "mixed-image-build"
    if context.exists():
        raise FileExistsError(context)
    lock_path = repo / "locks/p0-aarch64.json"
    native_source = repo / "fixtures/recipes/aarch64/keemu-init.c"
    lock = json.loads(lock_path.read_text())
    if lock["target"] != TARGET:
        raise ValueError("unexpected Entware target")
    cache = runtime / "aarch64-k3.10/packages"
    verified = verify_artifact_cache(lock, cache)
    context.mkdir(parents=True)
    root = context / "rootfs"
    try:
        result = build_diagnostic_rootfs(
            lock_path=lock_path,
            package_cache=cache,
            destination=root,
            qemu=runtime / "qemu-user-root/usr/bin/qemu-aarch64",
            bootstrap_opkg=runtime / "aarch64-k3.10/opkg",
            timeout=600,
        )
        if result.package_count != len(verified):
            raise ValueError("installed package count differs from lock")
        (root / "tmp").chmod(0o1777)
        (root / "run").chmod(0o755)
        etc = root / "etc"
        (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="ascii")
        (etc / "group").write_text("root:x:0:\n", encoding="ascii")
        (etc / "hosts").write_text(
            "127.0.0.1 localhost\n::1 localhost\n", encoding="ascii"
        )
        (root / "__keemu").mkdir()
        _run(
            [
                "gcc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-static",
                "-o",
                str(root / "__keemu/init"),
                str(native_source),
            ],
            timeout=60,
        )
        audit = audit_tree(root)
        labels = {
            **LABELS,
            "org.keemu.rootfs-sha256": audit["tree_sha256"],
            "org.keemu.package-lock-sha256": _sha256_file(lock_path),
            "org.keemu.init-source-sha256": _sha256_file(native_source),
        }
        dockerfile = (
            "FROM scratch\n"
            + "".join(f'LABEL {key}="{value}"\n' for key, value in labels.items())
            + (
                "COPY rootfs/ /\n"
                'ENV PATH="/opt/bin:/opt/sbin:/bin:/sbin" HOME="/root"\n'
                'ENTRYPOINT ["/__keemu/init"]\n'
                "STOPSIGNAL SIGTERM\n"
            )
        )
        (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        _run(
            [
                "docker",
                "build",
                "--platform",
                PLATFORM,
                "--network",
                "none",
                "--iidfile",
                str(context / "iid"),
                "-t",
                IMAGE,
                str(context),
            ],
            timeout=600,
        )
        image_id = (context / "iid").read_text().strip()
        inspected = json.loads(_run(["docker", "image", "inspect", image_id]))[0]
        if (
            inspected["Id"] != image_id
            or inspected["Architecture"] != "amd64"
            or inspected["Os"] != "linux"
            or inspected["Config"]["Labels"] != labels
            or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
        ):
            raise ValueError("built image inspect differs from audited input")
        evidence = {
            "schema_version": 1,
            "kind": "p0-mixed-image-lock",
            "image_id": image_id,
            "image_reference": IMAGE,
            "platform": PLATFORM,
            "labels": labels,
            "entrypoint": inspected["Config"]["Entrypoint"],
            "tree_sha256": audit["tree_sha256"],
            "architecture_audit": audit["elf"],
            "package_count": result.package_count,
            "native_compiler": _run(["gcc", "-dumpfullversion"]).strip(),
            "docker_server": _run(
                ["docker", "version", "--format", "{{.Server.Version}}"]
            ).strip(),
            "container_create_template": container_create_argv(
                "keemu-example", image_id, "example"
            ),
            "scope": (
                "image build/inspect only; no container run, binfmt, "
                "port or namespace proof"
            ),
        }
        return evidence
    finally:
        shutil.rmtree(context)


def verify_image_lock(lock_path: Path, saved_image: Path) -> dict[str, int]:
    """Independently compare live Docker inspect and the saved image layer."""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    repo = lock_path.resolve().parent.parent
    for label, source in (
        ("org.keemu.package-lock-sha256", repo / "locks/p0-aarch64.json"),
        (
            "org.keemu.init-source-sha256",
            repo / "fixtures/recipes/aarch64/keemu-init.c",
        ),
    ):
        if _sha256_file(source) != lock["labels"][label]:
            raise ValueError(f"locked source changed: {source}")
    inspected = json.loads(_run(["docker", "image", "inspect", lock["image_id"]]))[0]
    if (
        inspected["Id"] != lock["image_id"]
        or inspected["Architecture"] != "amd64"
        or inspected["Os"] != "linux"
        or inspected["Config"]["Labels"] != lock["labels"]
        or inspected["Config"]["Entrypoint"] != lock["entrypoint"]
    ):
        raise ValueError("live image differs from lock")
    counts = {"aarch64": 0, "amd64": 0}
    with tarfile.open(saved_image) as image:
        manifest_file = image.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("saved image lacks manifest")
        manifest = json.load(manifest_file)[0]
        if lock["image_reference"] not in manifest["RepoTags"]:
            raise ValueError("saved image tag differs from lock")
        config_file = image.extractfile(manifest["Config"])
        if config_file is None:
            raise ValueError("saved image lacks config")
        config = config_file.read()
        if hashlib.sha256(config).hexdigest() != lock["saved_config_sha256"]:
            raise ValueError("saved image config hash mismatch")
        saved_config = json.loads(config)
        if saved_config["config"]["Labels"] != lock["labels"]:
            raise ValueError("saved image labels differ from lock")
        if len(manifest["Layers"]) != 1:
            raise ValueError("expected a single scratch-image layer")
        layer_file = image.extractfile(manifest["Layers"][0])
        if layer_file is None:
            raise ValueError("saved image lacks layer")
        layer = layer_file.read()
        if hashlib.sha256(layer).hexdigest() != lock["saved_layer_sha256"]:
            raise ValueError("saved image layer hash mismatch")

    required = {"__keemu/init", "opt/bin/busybox", "opt/bin/opkg"}
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(layer)) as layer_tar:
        for member in layer_tar:
            if member.name == "bin/sh":
                if not member.issym() or member.linkname != "/opt/bin/busybox":
                    raise ValueError("image shell is not target BusyBox")
                seen.add(member.name)
            if not member.isfile():
                continue
            if member.name in required:
                seen.add(member.name)
            stream = layer_tar.extractfile(member)
            if stream is None:
                raise ValueError(f"saved image unreadable: {member.name}")
            with stream:
                header = stream.read(20)
            if not header.startswith(b"\x7fELF"):
                continue
            machine = struct.unpack("<H", header[18:20])[0]
            expected = 62 if member.name.startswith("__keemu/") else 183
            if header[4:6] != b"\x02\x01" or machine != expected:
                raise ValueError(f"wrong ELF in saved layer: {member.name}")
            counts["amd64" if machine == 62 else "aarch64"] += 1
    if seen != required | {"bin/sh"} or counts != lock["architecture_audit"]:
        raise ValueError("saved layer inventory differs from lock")
    return counts
