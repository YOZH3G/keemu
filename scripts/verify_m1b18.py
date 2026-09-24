"""Read-only offline MIPS/MIPSEL artifact, rootfs, and image verification."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path

from keemu.entware import build_entware_lock, verify_artifact_cache
from keemu.init_cache import _inventory, _run
from scripts.build_m1b18_images import checked_elf, digest, tree_audit

REPO = Path(__file__).resolve().parents[1]


def saved_image(archive: Path, image_lock: dict, root: Path) -> None:
    if digest(archive) != image_lock["archive_sha256"]:
        raise ValueError("saved image archive hash mismatch")
    with tarfile.open(archive) as image:
        manifest_file = image.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("saved image manifest missing")
        manifest = json.load(manifest_file)
        if len(manifest) != 1 or len(manifest[0]["Layers"]) != 1:
            raise ValueError("saved image must be one scratch layer")
        config_file = image.extractfile(manifest[0]["Config"])
        layer_file = image.extractfile(manifest[0]["Layers"][0])
        if config_file is None or layer_file is None:
            raise ValueError("saved image config/layer missing")
        config = config_file.read()
        layer = layer_file.read()
    if (
        hashlib.sha256(config).hexdigest() != image_lock["saved_config_sha256"]
        or hashlib.sha256(layer).hexdigest() != image_lock["saved_layer_sha256"]
    ):
        raise ValueError("saved image config/layer hash mismatch")
    saved = json.loads(config)
    if (
        saved["config"]["Labels"] != image_lock["labels"]
        or saved["config"]["Entrypoint"] != ["/__keemu/init"]
        or saved["architecture"] != "amd64"
        or saved["os"] != "linux"
    ):
        raise ValueError("saved image config identity mismatch")
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(layer)) as tar:
        for member in tar:
            if member.isdir():
                continue
            if (
                member.name in entries
                or member.name.startswith("/")
                or ".." in Path(member.name).parts
            ):
                raise ValueError("unsafe/duplicate image entry")
            if member.isfile():
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("saved image entry unreadable")
                entries[member.name] = (
                    "F",
                    member.mode,
                    hashlib.sha256(stream.read()).hexdigest(),
                )
            elif member.issym():
                entries[member.name] = ("L", member.mode, member.linkname)
            else:
                raise ValueError("unsupported saved image entry")
    stripped = []
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        name = path.relative_to(root).as_posix()
        actual = entries.pop(name, None)
        if stat.S_ISLNK(mode):
            expected = ("L", stat.S_IMODE(mode), str(path.readlink()))
        elif stat.S_ISREG(mode):
            expected = ("F", stat.S_IMODE(mode), digest(path))
            if actual != expected and actual == (
                "F",
                stat.S_IMODE(mode) & ~0o6000,
                digest(path),
            ):
                stripped.append(name)
                expected = actual
        else:
            raise ValueError("unsupported rootfs entry")
        if actual != expected:
            raise ValueError(f"saved image differs from rootfs: {name}")
    if entries or stripped not in ([], ["opt/bin/busybox"]):
        raise ValueError(
            f"saved image extra/attenuated entries: {list(entries)[:4]}, {stripped}"
        )


def verify(target: str, *, repo: Path = REPO) -> dict:
    if target not in {"mipsel-3.4", "mips-3.4"}:
        raise ValueError("unsupported target")
    lock_path = repo / "locks" / f"m1b18-{target}.json"
    sdk_path = repo / "locks" / f"m1b18-sdk-{target}.json"
    fixtures_path = repo / "locks" / f"m1b18-fixtures-{target}.json"
    image_path = repo / "locks" / f"m1b18-image-{target}.json"
    root_lock = json.loads(lock_path.read_text())
    sdk_lock = json.loads(sdk_path.read_text())
    fixtures = json.loads(fixtures_path.read_text())
    image_lock = json.loads(image_path.read_text())
    if (
        root_lock["target"] != sdk_lock["target"] != target
        or fixtures["target"] != image_lock["target"]
        or fixtures["target"] != target
    ):
        raise ValueError("lock target mismatch")
    work = repo / ".runtime/m1b18" / target
    index_gzip = (work / "Packages.gz").read_bytes()
    index = gzip.decompress(index_gzip)
    source = root_lock["source"]
    if (
        hashlib.sha256(index_gzip).hexdigest() != source["index_compressed_sha256"]
        or hashlib.sha256(index).hexdigest() != source["index_sha256"]
        or sdk_lock["source"]["index_sha256"] != source["index_sha256"]
    ):
        raise ValueError("feed index hash mismatch")
    for lock in (root_lock, sdk_lock):
        candidate = build_entware_lock(
            index,
            target=target,
            roots=lock["root_packages"],
            index_url=source["index_url"],
            base_url=source["base_url"],
            captured_at=lock["captured_at"],
        )
        if candidate["packages"] != lock["packages"] or len(lock["packages"]) == 0:
            raise ValueError("package closure differs from captured index")
        verify_artifact_cache(lock, work / "packages")
    for item in root_lock["bootstrap_artifacts"]:
        if digest(work / item["filename"]) != item["sha256"]:
            raise ValueError("bootstrap artifact hash mismatch")
    qemu = repo / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{target[:-4]}"
    if (
        digest(qemu) != fixtures["qemu_sha256"]
        or digest(sdk_path) != fixtures["sdk_lock_sha256"]
    ):
        raise ValueError("SDK/QEMU lock mismatch")
    for name, item in fixtures["fixtures"].items():
        if (
            item["status"] != "PASS"
            or digest(repo / item["source"]) != item["source_sha256"]
            or digest(repo / item["path"]) != item["sha256"]
        ):
            raise ValueError(f"fixture/source hash mismatch: {name}")
        checked_elf(repo / item["path"], target)
    root = work / "image-rootfs"
    audit = tree_audit(root, target)
    if audit != image_lock["audit"] or image_lock["package_count"] != len(
        root_lock["packages"]
    ):
        raise ValueError("rootfs architecture/tree mismatch")
    if (
        image_lock["labels"]["org.keemu.rootfs-sha256"] != audit["tree_sha256"]
        or image_lock["labels"]["org.keemu.package-lock-sha256"] != digest(lock_path)
        or image_lock["labels"]["org.keemu.fixture-lock-sha256"]
        != digest(fixtures_path)
        or image_lock["labels"]["org.keemu.target"] != target
    ):
        raise ValueError("image label bindings mismatch")
    if digest(root / "opt/etc/opkg.conf") != image_lock["opkg_config_sha256"]:
        raise ValueError("opkg config hash mismatch")
    status = (root / "opt/lib/opkg/status").read_text()
    if status.count("Installed-Time: 0\n") != image_lock["package_count"]:
        raise ValueError("installed-time canonicalization mismatch")
    # Inventory was obtained by the target opkg in build; reread independently.
    current = _run(
        [
            str(qemu),
            str(work / "opkg"),
            "-f",
            str(root / "opt/etc/opkg.conf"),
            "-o",
            str(root),
            "-t",
            str(root / "opt/tmp"),
            "list-installed",
        ],
        timeout=90,
    )
    if _inventory(current, root_lock) != image_lock["inventory"]:
        raise ValueError("target opkg inventory mismatch")
    saved_image(work / "image.tar", image_lock, root)
    inspected = json.loads(
        _run(["docker", "image", "inspect", image_lock["image_id"]])
    )[0]
    if (
        inspected["Id"] != image_lock["image_id"]
        or inspected["Architecture"] != "amd64"
        or inspected["Os"] != "linux"
        or inspected["Config"]["Labels"] != image_lock["labels"]
        or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
    ):
        raise ValueError("live Docker image mismatch")
    return {
        "target": target,
        "package_count": len(root_lock["packages"]),
        "target_elf_count": audit["target_elf_count"],
        "image_id": image_lock["image_id"],
        "status": (
            "PASS (offline artifact/image integrity, not Docker target execution)"
        ),
    }


if __name__ == "__main__":
    for target in ("mipsel-3.4", "mips-3.4"):
        print(json.dumps(verify(target), sort_keys=True))
