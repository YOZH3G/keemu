"""Build and verify the two locked mixed native-init / MIPS target images.

No host binfmt registration or target privilege is changed. Image IDs are
Docker-local config digests; the feed URLs are mutable, cached bytes are not.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import struct
import subprocess
import tarfile
from pathlib import Path

from keemu.entware import verify_artifact_cache
from keemu.init_cache import _inventory
from keemu.p0_image import _run as docker_run

REPO = Path(__file__).resolve().parents[1]
QEMU = REPO / ".runtime/p0/qemu-user-root/usr/bin"
NATIVE = (
    REPO
    / ".runtime/init-cache"
    / json.loads((REPO / "locks/m1a-init-aarch64.json").read_text())["cache_key"]
    / "rootfs/__keemu/init"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_elf(path: Path, target: str) -> dict:
    data = path.read_bytes()
    endian = {"mipsel-3.4": "little", "mips-3.4": "big"}[target]
    if (
        data[:4] != b"\x7fELF"
        or data[4] != 1
        or data[5] != (1 if endian == "little" else 2)
    ):
        raise ValueError(f"ELF class/endianness mismatch: {path}")
    if int.from_bytes(data[18:20], endian) != 8:
        raise ValueError(f"ELF machine mismatch: {path}")
    flags = int.from_bytes(data[36:40], endian)
    if flags & 0x0000F000 != 0x1000 or flags & 0xF0000000 != 0x70000000:
        raise ValueError(
            f"ELF ABI/ISA flags differ from o32/MIPS32r2: {path} ({flags:#x})"
        )
    attributes = subprocess.run(  # noqa: S603 -- argv only, read-only ELF parser.
        ["/usr/bin/readelf", "-A", str(path)],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    ).stdout
    if "ISA: MIPS32r2" not in attributes or "FP ABI: Soft float" not in attributes:
        raise ValueError(f"ELF ISA/FPU attributes missing or incompatible: {path}")
    return {
        "class": 32,
        "endian": endian,
        "machine": 8,
        "abi": "o32",
        "isa": "MIPS32r2",
        "fpu": "soft-float",
        "flags": f"{flags:#x}",
        "sha256": digest(path),
    }


def tree_audit(root: Path, target: str) -> dict:
    records = []
    elves = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            link = str(path.readlink())
            if link.startswith(("/proc/", "/sys/")):
                raise ValueError(f"unsafe link: {relative}")
            records.append(f"L {relative} {stat.S_IMODE(mode):o} {link}\n")
        elif stat.S_ISREG(mode):
            records.append(f"F {relative} {stat.S_IMODE(mode):o} {digest(path)}\n")
            with path.open("rb") as stream:
                magic = stream.read(4)
            if magic == b"\x7fELF":
                if relative == "__keemu/init":
                    if (
                        path.read_bytes()[4:6] != b"\x02\x01"
                        or struct.unpack("<H", path.read_bytes()[18:20])[0] != 62
                    ):
                        raise ValueError("native init is not amd64 ELF64")
                else:
                    elves[relative] = checked_elf(path, target)
        else:
            raise ValueError(f"unsupported rootfs node: {relative}")
    if not elves or any(
        name not in elves
        for name in (
            "opt/bin/busybox",
            "opt/bin/opkg",
            "opt/keemu/fixtures/hello",
            "opt/keemu/fixtures/web-demo",
            "opt/keemu/fixtures/nfqueue-consumer",
        )
    ):
        raise ValueError("target ELF inventory incomplete")
    if (root / "bin/sh").readlink() != Path("/opt/bin/busybox"):
        raise ValueError("shell is not target BusyBox")
    return {
        "tree_sha256": hashlib.sha256("".join(records).encode()).hexdigest(),
        "target_elf_count": len(elves),
        "elf": elves,
        "native_init_sha256": digest(root / "__keemu/init"),
    }


def prepare(target: str) -> dict:
    work = REPO / ".runtime/m1b18" / target
    lock_path = REPO / "locks" / f"m1b18-{target}.json"
    lock = json.loads(lock_path.read_text())
    fixture_path = REPO / "locks" / f"m1b18-fixtures-{target}.json"
    fixtures = json.loads(fixture_path.read_text())
    if lock["target"] != target or fixtures["target"] != target:
        raise ValueError("rootfs/fixture target mismatch")
    verify_artifact_cache(lock, work / "packages")
    if digest(work / "Packages.gz") != lock["source"]["index_compressed_sha256"]:
        raise ValueError("index gzip digest mismatch")
    for item in lock["bootstrap_artifacts"]:
        if digest(work / item["filename"]) != item["sha256"]:
            raise ValueError("bootstrap mismatch")
    native_digest = json.loads((REPO / "locks/m1a-init-aarch64.json").read_text())[
        "labels"
    ]["org.keemu.init-binary-sha256"]
    if digest(NATIVE) != native_digest:
        raise ValueError("native init mismatch")
    qemu = QEMU / f"qemu-{target.removesuffix('-3.4')}"
    if not qemu.is_file():
        raise ValueError("locked QEMU absent")
    root = work / "image-rootfs"
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(work / "rootfs", root, symlinks=True)
    # The diagnostic rootfs only installs packages. Query its real target
    # status with the separately prepared, hash-verified SDK configuration.
    inventory = subprocess.run(  # noqa: S603 -- pinned QEMU/opkg, argv only.
        [
            str(qemu),
            str(work / "opkg"),
            "-f",
            str(work / "sdk-rootfs/opt/etc/opkg.conf"),
            "-o",
            str(work / "rootfs"),
            "-t",
            str(work / "rootfs/opt/tmp"),
            "list-installed",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    installed = _inventory(inventory, lock)
    status = root / "opt/lib/opkg/status"
    normalized, count = re.subn(
        r"^Installed-Time: [0-9]+$",
        "Installed-Time: 0",
        status.read_text(),
        flags=re.MULTILINE,
    )
    if count != len(installed):
        raise ValueError("unexpected installed-time inventory")
    status.write_text(normalized)
    (root / "opt/etc/opkg.conf").write_text(
        f"src/gz entware {lock['source']['base_url']}\n"
        f"dest root /\ndest ram /opt/tmp\nlists_dir ext /opt/var/opkg-lists\n"
        f"option tmp_dir /opt/tmp\narch all 100\narch {target} 160\n"
    )
    (root / "__keemu").mkdir()
    shutil.copyfile(NATIVE, root / "__keemu/init")
    (root / "__keemu/init").chmod(0o755)
    (root / "opt/keemu/fixtures").mkdir(parents=True)
    for name, item in fixtures["fixtures"].items():
        if item["status"] != "PASS":
            raise ValueError(f"required fixture missing: {name}")
        source = REPO / item["path"]
        if (
            digest(source) != item["sha256"]
            or digest(REPO / item["source"]) != item["source_sha256"]
        ):
            raise ValueError(f"fixture hash mismatch: {name}")
        dest = root / "opt/keemu/fixtures" / name
        shutil.copyfile(source, dest)
        dest.chmod(0o755)
    audit = tree_audit(root, target)
    labels = {
        "org.keemu.owner": "keemu",
        "org.keemu.phase": "m1b-18",
        "org.keemu.target": target,
        "org.keemu.native": "linux/amd64",
        "org.keemu.rootfs-sha256": audit["tree_sha256"],
        "org.keemu.package-lock-sha256": digest(lock_path),
        "org.keemu.fixture-lock-sha256": digest(fixture_path),
        "org.keemu.init-binary-sha256": native_digest,
    }
    context = work / "image-build"
    context.mkdir(exist_ok=True)
    destination = context / "rootfs"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(root, destination, symlinks=True)
    dockerfile = (
        "FROM scratch\n"
        + "".join(f'LABEL {key}="{value}"\n' for key, value in labels.items())
        + (
            'COPY rootfs/ /\nENV PATH="/opt/bin:/opt/sbin:/bin:/sbin" HOME="/root"\n'
            'ENTRYPOINT ["/__keemu/init"]\nSTOPSIGNAL SIGTERM\n'
        )
    )
    (context / "Dockerfile").write_text(dockerfile)
    iid = context / "iid"
    if iid.exists():
        iid.unlink()
    docker_run(
        [
            "docker",
            "build",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--iidfile",
            str(iid),
            str(context),
        ],
        timeout=600,
    )
    image_id = iid.read_text().strip()
    live = json.loads(docker_run(["docker", "image", "inspect", image_id]))[0]
    if (
        live["Id"] != image_id
        or live["Architecture"] != "amd64"
        or live["Config"]["Labels"] != labels
        or live["Config"]["Entrypoint"] != ["/__keemu/init"]
    ):
        raise ValueError("Docker image inspect mismatch")
    archive = work / "image.tar"
    docker_run(["docker", "save", "-o", str(archive), image_id], timeout=300)
    with tarfile.open(archive) as image:
        manifest_file = image.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("saved image manifest missing")
        manifest = json.load(manifest_file)
        if len(manifest) != 1 or len(manifest[0]["Layers"]) != 1:
            raise ValueError("expected one scratch image layer")
        config_file = image.extractfile(manifest[0]["Config"])
        layer_file = image.extractfile(manifest[0]["Layers"][0])
        if config_file is None or layer_file is None:
            raise ValueError("saved image config/layer missing")
        config = config_file.read()
        layer = layer_file.read()
        saved = json.loads(config)
        if (
            saved["config"]["Labels"] != labels
            or saved["config"]["Entrypoint"] != ["/__keemu/init"]
            or saved["architecture"] != "amd64"
        ):
            raise ValueError("saved image config mismatch")
    return {
        "schema_version": 1,
        "kind": "m1b18-locked-target-image",
        "target": target,
        "platform": "linux/amd64",
        "image_id": image_id,
        "labels": labels,
        "package_count": len(installed),
        "inventory": installed,
        "audit": audit,
        "archive_sha256": digest(archive),
        "saved_config_sha256": hashlib.sha256(config).hexdigest(),
        "saved_layer_sha256": hashlib.sha256(layer).hexdigest(),
        "opkg_config_sha256": digest(root / "opt/etc/opkg.conf"),
    }


if __name__ == "__main__":
    for target in ("mipsel-3.4", "mips-3.4"):
        result = prepare(target)
        destination = REPO / "locks" / f"m1b18-image-{target}.json"
        prior = json.loads(destination.read_text()) if destination.exists() else None
        if prior is not None and prior != result:
            raise ValueError(f"image rebuild differs from frozen lock: {target}")
        if prior is None:
            destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(target, result["image_id"], result["audit"]["target_elf_count"])
