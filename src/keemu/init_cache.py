"""Offline-locked AArch64 base preparation; no scenario or persistent lifecycle.

A cache is ready only after verified inputs, target opkg inventory, an audited
mixed image, and an owned Docker/binfmt smoke. The metadata is published last.
"""

from __future__ import annotations

import fcntl
import gzip
import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path

from keemu.entware import _sha256_file
from keemu.p0 import build_diagnostic_rootfs
from keemu.p0_image import audit_tree
from keemu.p0_runtime_image import verify as verify_native_image
from keemu.reports import _publish_directory_noreplace

SCHEMA_VERSION = 4
TARGET = "aarch64-3.10"
HEX = re.compile(r"[0-9a-f]{64}\Z")


class InitError(ValueError):
    """A locked input, cache, image, or runtime smoke failed closed."""


def _run(argv: list[str], *, timeout: int = 300) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed executables, argv only.
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise InitError(
            f"command failed ({result.returncode}): {argv[:3]!r}: "
            f"{result.stderr[-1200:]}"
        )
    return result.stdout.strip()


def _regular_hash(path: Path, expected: str) -> None:
    if not HEX.fullmatch(expected):
        raise InitError(f"invalid locked hash for {path.name}")
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
        raise InitError(f"missing, linked or mismatched locked input: {path.name}")


def _inputs(repo: Path) -> tuple[dict, dict, str]:
    lock_path = repo / "locks/p0-aarch64.json"
    native_path = repo / "locks/p0-mixed-image-aarch64-p005.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    native = json.loads(native_path.read_text(encoding="utf-8"))
    if (lock.get("schema_version"), lock.get("kind"), lock.get("target")) != (
        1,
        "entware-rootfs-lock",
        TARGET,
    ):
        raise InitError("wrong rootfs lock schema or target")
    if (
        native.get("kind") != "p0-derived-runtime-image-lock"
        or native.get("platform") != "linux/amd64"
    ):
        raise InitError("wrong native init lock")
    if native.get("labels", {}).get("org.keemu.package-lock-sha256") != _sha256_file(
        lock_path
    ):
        raise InitError("native init base does not bind this package lock")
    _regular_hash(repo / native["source_path"], native["source_sha256"])
    base = repo / ".runtime/p0/aarch64-k3.10"
    bootstrap = next(
        (a for a in lock["bootstrap_artifacts"] if a["filename"] == "opkg"), None
    )
    if bootstrap is None:
        raise InitError("bootstrap opkg absent from lock")
    _regular_hash(base / "opkg", bootstrap["sha256"])
    qemu_deb = next(
        (
            a
            for a in lock["diagnostic_tooling"]
            if a["filename"].startswith("qemu-user_")
        ),
        None,
    )
    if qemu_deb is None:
        raise InitError("locked QEMU package missing")
    _regular_hash(repo / ".runtime/p0" / qemu_deb["filename"], qemu_deb["sha256"])
    qemu = repo / ".runtime/p0/qemu-user-root/usr/bin/qemu-aarch64"
    image_lock = json.loads(
        (repo / "locks/m1a-init-aarch64.json").read_text(encoding="utf-8")
    )
    _regular_hash(qemu, image_lock["qemu_binary_sha256"])
    index = base / "Packages.gz"
    _regular_hash(index, lock["source"]["index_compressed_sha256"])
    with gzip.open(index, "rb") as stream:
        if hashlib.sha256(stream.read()).hexdigest() != lock["source"]["index_sha256"]:
            raise InitError("feed index content hash mismatch")
    names: set[str] = set()
    for item in lock["packages"]:
        name = item["filename"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.+%~-]+\.ipk", name)
            or name in names
            or item["architecture"] not in (TARGET, "all")
        ):
            raise InitError("unsafe or duplicate locked package")
        names.add(name)
        _regular_hash(base / "packages" / name, item["sha256"])
    if not names:
        raise InitError("empty package lock")
    return lock, native, _sha256_file(lock_path)


def _inventory(text: str, lock: dict) -> list[dict[str, str]]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([^\s]+) - ([^\s]+)(?: - .*)?", line)
        if not match or match[1] in found:
            raise InitError("malformed or duplicate target opkg inventory")
        found[match[1]] = match[2]
    expected = {a["name"]: a["version"] for a in lock["packages"]}
    if found != expected or len(expected) != len(lock["packages"]):
        missing = sorted(expected.keys() - found.keys())
        extra = sorted(found.keys() - expected.keys())
        versions = sorted(
            n for n in expected.keys() & found.keys() if expected[n] != found[n]
        )
        raise InitError(
            "target opkg inventory differs from lock: "
            f"missing={missing}, extra={extra}, versions={versions}"
        )
    return [{"name": name, "version": found[name]} for name in sorted(found)]


def _image_archive(archive: Path, expected_labels: dict) -> dict:
    """Compare every saved image file with its staged rootfs, not just labels."""
    with tarfile.open(archive) as image:
        manifest_file = image.extractfile("manifest.json")
        if manifest_file is None:
            raise InitError("image archive missing manifest")
        entries = json.load(manifest_file)
        if len(entries) != 1 or len(entries[0]["Layers"]) != 1:
            raise InitError("image archive is not a single scratch layer")
        entry = entries[0]
        config_stream = image.extractfile(entry["Config"])
        layer_stream = image.extractfile(entry["Layers"][0])
        if config_stream is None or layer_stream is None:
            raise InitError("image archive missing config or layer")
        config = config_stream.read()
        saved_config = json.loads(config)
        if (
            saved_config.get("config", {}).get("Labels") != expected_labels
            or saved_config.get("config", {}).get("Entrypoint") != ["/__keemu/init"]
            or saved_config.get("os") != "linux"
            or saved_config.get("architecture") != "amd64"
            or entry.get("RepoTags") not in (None, [])
        ):
            raise InitError("saved image config differs from locked mixed image")
        layer_bytes = layer_stream.read()
    records: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as layer:
        for member in layer:
            if member.isdir():
                continue
            if (
                member.name in records
                or member.name.startswith("/")
                or ".." in Path(member.name).parts
            ):
                raise InitError("unsafe or duplicate image member")
            if member.isfile():
                content = layer.extractfile(member)
                if content is None:
                    raise InitError("unreadable image member")
                digest = hashlib.sha256(content.read()).hexdigest()
                records[member.name] = f"F {member.name} {member.mode:o} {digest}\n"
            elif member.issym():
                records[member.name] = (
                    f"L {member.name} {member.mode:o} {member.linkname}\n"
                )
            else:
                raise InitError("unsupported image member")
    image_tree = hashlib.sha256(
        "".join(records[name] for name in sorted(records)).encode()
    ).hexdigest()
    return {
        "saved_config_sha256": hashlib.sha256(config).hexdigest(),
        "saved_layer_sha256": hashlib.sha256(layer_bytes).hexdigest(),
        "image_tree_sha256": image_tree,
        "image_records": records,
    }


def _verify_image_files(root: Path, saved: dict) -> None:
    """Docker clears setuid on COPY; no other mode or byte change is accepted."""
    records = dict(saved["image_records"])
    stripped: list[str] = []
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        name = path.relative_to(root).as_posix()
        image_record = records.pop(name, None)
        if stat.S_ISLNK(mode):
            expected = f"L {name} {stat.S_IMODE(mode):o} {path.readlink()}\n"
        elif stat.S_ISREG(mode):
            expected = f"F {name} {stat.S_IMODE(mode):o} {_sha256_file(path)}\n"
            if image_record != expected and stat.S_IMODE(mode) & 0o6000:
                safe_mode = stat.S_IMODE(mode) & ~0o6000
                attenuated = f"F {name} {safe_mode:o} {_sha256_file(path)}\n"
                if image_record == attenuated:
                    stripped.append(name)
                    expected = attenuated
        else:
            raise InitError("unsupported rootfs member")
        if image_record != expected:
            raise InitError(f"saved image differs from rootfs: {name}")
    if records:
        raise InitError("saved image has extra files")
    if stripped != ["opt/bin/busybox"]:
        raise InitError(f"unexpected image mode attenuation: {stripped}")


def _verify_frozen_metadata(
    metadata: dict, cache: Path, lock: dict, native: dict, lock_sha: str, repo: Path
) -> None:
    if (
        metadata.get("schema_version") != SCHEMA_VERSION
        or metadata.get("target") != TARGET
        or metadata.get("lock_sha256") != lock_sha
        or metadata.get("native_image_id") != native["image_id"]
    ):
        raise InitError("cache identity mismatch")
    image_lock = json.loads(
        (repo / "locks/m1a-init-aarch64.json").read_text(encoding="utf-8")
    )
    bindings = {
        "schema_version": (image_lock.get("cache_schema_version"), SCHEMA_VERSION),
        "cache_key": (image_lock.get("cache_key"), cache.name),
        "input_lock_sha256": (image_lock.get("input_lock_sha256"), lock_sha),
        "native_image_id": (image_lock.get("native_image_id"), native["image_id"]),
        "rootfs_tree_sha256": (
            image_lock.get("rootfs_tree_sha256"),
            metadata.get("tree_sha256"),
        ),
        "image_tree_sha256": (
            image_lock.get("image_tree_sha256"),
            metadata.get("image_tree_sha256"),
        ),
        "oci_digest": (image_lock.get("oci_digest"), metadata.get("oci_digest")),
        "saved_archive_sha256": (
            image_lock.get("saved_archive_sha256"),
            metadata.get("saved_archive_sha256"),
        ),
        "saved_config_sha256": (
            image_lock.get("saved_config_sha256"),
            metadata.get("saved_config_sha256"),
        ),
        "saved_layer_sha256": (
            image_lock.get("saved_layer_sha256"),
            metadata.get("saved_layer_sha256"),
        ),
        "package_count": (
            image_lock.get("package_count"),
            metadata.get("package_count"),
        ),
        "installed_inventory_sha256": (
            image_lock.get("installed_inventory_sha256"),
            metadata.get("inventory_sha256"),
        ),
        "feed_config_sha256": (
            image_lock.get("feed_config_sha256"),
            metadata.get("feed_config_sha256"),
        ),
        "feed_index_sha256": (
            image_lock.get("feed_index_sha256"),
            metadata.get("feed_index_sha256"),
        ),
        "labels": (image_lock.get("labels"), metadata.get("labels")),
        "smoke": (image_lock.get("smoke"), metadata.get("smoke")),
    }
    if (
        metadata.get("package_count") != len(lock["packages"])
        or metadata.get("feed_index_sha256")
        != lock["source"]["index_compressed_sha256"]
        or image_lock.get("kind") != "mvp1a-locked-base-image"
    ):
        raise InitError("committed image lock differs from cache manifest")
    if any(expected != actual for expected, actual in bindings.values()):
        raise InitError("committed image lock differs from cache manifest")


def _verify_cache(
    cache: Path, lock: dict, native: dict, lock_sha: str, repo: Path
) -> dict:
    if cache.is_symlink():
        raise InitError("cache path is a symlink")
    metadata_path = cache / "manifest.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise InitError("incomplete cache (manifest missing)")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    _verify_frozen_metadata(metadata, cache, lock, native, lock_sha, repo)
    root = cache / "rootfs"
    if root.is_symlink():
        raise InitError("cached rootfs is a symlink")
    audit = audit_tree(root)
    if audit["tree_sha256"] != metadata.get("tree_sha256"):
        raise InitError("cached rootfs hash mismatch")
    if _sha256_file(root / "__keemu/init") != native["binary_sha256"]:
        raise InitError("cached native init differs from lock")
    feed = root / "opt/etc/opkg.conf"
    if feed.is_symlink() or _sha256_file(feed) != metadata.get("feed_config_sha256"):
        raise InitError("cached feed configuration mismatch")
    inventory = root / "__keemu/installed-packages.json"
    if inventory.is_symlink() or _sha256_file(inventory) != metadata.get(
        "inventory_sha256"
    ):
        raise InitError("cached inventory hash mismatch")
    data = json.loads(inventory.read_text(encoding="utf-8"))
    if data != _inventory(
        "".join(f"{x['name']} - {x['version']}\n" for x in data), lock
    ):
        raise InitError("cached inventory differs from lock")
    archive = cache / "image.tar"
    _regular_hash(archive, metadata["saved_archive_sha256"])
    saved = _image_archive(archive, metadata["labels"])
    _verify_image_files(root, saved)
    for field in ("saved_config_sha256", "saved_layer_sha256", "image_tree_sha256"):
        if saved[field] != metadata[field]:
            raise InitError(f"cached image {field} mismatch")
    inspected = json.loads(
        _run(["docker", "image", "inspect", metadata["oci_digest"]])
    )[0]
    labels = inspected["Config"]["Labels"]
    if (
        inspected["Id"] != metadata["oci_digest"]
        or inspected["Architecture"] != "amd64"
        or inspected["Os"] != "linux"
        or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
        or labels != metadata["labels"]
        or labels.get("org.keemu.rootfs-sha256") != audit["tree_sha256"]
    ):
        raise InitError("cached OCI image mismatch")
    return metadata


def _smoke(image_id: str, lock: dict) -> dict[str, str]:
    name = "keemu-init-" + uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex
    labels = [
        "--label",
        "org.keemu.owner=keemu",
        "--label",
        f"org.keemu.run-id={run_id}",
    ]
    cid = None
    try:
        cid = _run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--platform",
                "linux/amd64",
                *labels,
                "--network=bridge",
                "--memory=256m",
                "--memory-swap=256m",
                "--cpus=1",
                "--pids-limit=128",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--read-only",
                "--tmpfs=/tmp:rw,nosuid,nodev,size=16m",
                "--tmpfs=/opt/tmp:rw,nosuid,nodev,size=16m",
                image_id,
            ]
        )
        _run(["docker", "start", cid])
        target = _run(
            [
                "docker",
                "exec",
                cid,
                "/bin/sh",
                "-c",
                "set -e; /opt/bin/opkg --version; "
                "/opt/bin/busybox uname -m; /opt/bin/busybox true; echo nested-ok",
            ]
        )
        if "nested-ok" not in target or "aarch64" not in target:
            raise InitError("target shell/opkg/nested smoke mismatch")
        installed = _run(
            [
                "docker",
                "exec",
                cid,
                "/opt/bin/opkg",
                "list-installed",
            ]
        )
        _inventory(installed, lock)
        network = _run(
            [
                "docker",
                "exec",
                cid,
                "/bin/sh",
                "-c",
                "set -e; /opt/bin/busybox nslookup bin.entware.net; echo dns-ok",
            ],
            timeout=60,
        )
        if "dns-ok" not in network:
            raise InitError("target DNS smoke mismatch")
        # Entware's locked BusyBox wget has no TLS support; do not claim a
        # target-namespace TLS proof from a different vantage.
        import urllib.request

        with urllib.request.urlopen(
            "https://bin.entware.net/aarch64-k3.10/Packages.gz", timeout=30
        ) as response:
            if response.status != 200 or not response.read(1):
                raise InitError("host-vantage HTTPS smoke mismatch")
        return {
            "target": "PASS",
            "dns": "PASS (target Docker bridge)",
            "https": "PASS (Hermes host namespace, default CA/hostname verification)",
            "limitation": (
                "HTTPS was not executed in target namespace: "
                "locked BusyBox wget lacks TLS"
            ),
        }
    finally:
        if cid:
            inspected = json.loads(_run(["docker", "inspect", cid]))[0]
            if (
                inspected["Id"] != cid
                or inspected["Config"]["Labels"].get("org.keemu.owner") != "keemu"
                or inspected["Config"]["Labels"].get("org.keemu.run-id") != run_id
            ):
                raise InitError("container ownership mismatch; refused cleanup")
            _run(["docker", "stop", "-t", "5", cid], timeout=30)
            _run(["docker", "rm", cid], timeout=30)
            if _run(["docker", "ps", "-aq", "--filter", f"id={cid}"]):
                raise InitError("owned smoke container persists after cleanup")


def init_locked(
    repo: Path, *, cache_root: Path | None = None, offline: bool = False
) -> dict:
    """Prepare once; offline repeat validates inputs and cache without network."""
    repo = repo.resolve()
    lock, native, lock_sha = _inputs(repo)
    key = hashlib.sha256(
        f"{SCHEMA_VERSION}:{TARGET}:{lock_sha}:{native['image_id']}".encode()
    ).hexdigest()
    cache_root = cache_root or repo / ".runtime/init-cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    cache = cache_root / key
    with (cache_root / f".{key}.lock").open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        if cache.exists() or cache.is_symlink():
            metadata = _verify_cache(cache, lock, native, lock_sha, repo)
            return {**metadata, "cache_state": "verified", "offline_repeat": offline}
        if offline:
            raise InitError("locked offline cache not prepared")
        verify_native_image(repo)
        temporary = Path(tempfile.mkdtemp(prefix=f".{key}.", dir=cache_root))
        try:
            root = temporary / "rootfs"
            result = build_diagnostic_rootfs(
                lock_path=repo / "locks/p0-aarch64.json",
                package_cache=repo / ".runtime/p0/aarch64-k3.10/packages",
                destination=root,
                qemu=repo / ".runtime/p0/qemu-user-root/usr/bin/qemu-aarch64",
                bootstrap_opkg=repo / ".runtime/p0/aarch64-k3.10/opkg",
            )
            inventory = _inventory(result.installed_packages, lock)
            # opkg writes wall-clock Installed-Time on each run. Freeze only
            # that bookkeeping field after target opkg has installed all IPKs.
            status = root / "opt/lib/opkg/status"
            contents = status.read_text(encoding="utf-8")
            canonical, changed = re.subn(
                r"^Installed-Time: [0-9]+$",
                "Installed-Time: 0",
                contents,
                flags=re.MULTILINE,
            )
            if changed != len(inventory):
                raise InitError("unexpected installed-time fields in opkg status")
            status.write_text(canonical, encoding="utf-8")
            # opkg's default target config is needed for later local-IPK use.
            # The HTTPS feed URL records origin, but init never runs update.
            feed = root / "opt/etc/opkg.conf"
            feed.write_text(
                f"src/gz entware {lock['source']['base_url']}\n"
                "dest root /\n"
                "dest ram /opt/tmp\n"
                "lists_dir ext /opt/var/opkg-lists\n"
                "option tmp_dir /opt/tmp\n"
                "arch all 100\n"
                f"arch {TARGET} 160\n",
                encoding="utf-8",
            )
            native_binary = root / "__keemu/init"
            native_binary.parent.mkdir()
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
                    str(native_binary),
                    str(repo / native["source_path"]),
                ],
                timeout=90,
            )
            _regular_hash(native_binary, native["binary_sha256"])
            inv_path = root / "__keemu/installed-packages.json"
            inv_path.write_text(
                json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
            )
            audit = audit_tree(root)
            labels = {
                "org.keemu.owner": "keemu",
                "org.keemu.phase": "m1a-11",
                "org.keemu.target": TARGET,
                "org.keemu.native": "linux/amd64",
                "org.keemu.rootfs-sha256": audit["tree_sha256"],
                "org.keemu.package-lock-sha256": lock_sha,
                "org.keemu.init-binary-sha256": native["binary_sha256"],
            }
            dockerfile = (
                "FROM scratch\n"
                + "".join(f'LABEL {k}="{v}"\n' for k, v in labels.items())
                + (
                    "COPY rootfs/ /\n"
                    'ENV PATH="/opt/bin:/opt/sbin:/bin:/sbin" HOME="/root"\n'
                    'ENTRYPOINT ["/__keemu/init"]\nSTOPSIGNAL SIGTERM\n'
                )
            )
            (temporary / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            iid = temporary / "iid"
            _run(
                [
                    "docker",
                    "build",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "none",
                    "--iidfile",
                    str(iid),
                    str(temporary),
                ],
                timeout=600,
            )
            image_id = iid.read_text(encoding="ascii").strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise InitError("Docker returned invalid image digest")
            inspected = json.loads(_run(["docker", "image", "inspect", image_id]))[0]
            if (
                inspected["Id"] != image_id
                or inspected["Config"]["Labels"] != labels
                or inspected["Architecture"] != "amd64"
                or inspected["Os"] != "linux"
                or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
            ):
                raise InitError("built image does not match audited rootfs")
            smoke = _smoke(image_id, lock)
            archive = temporary / "image.tar"
            _run(["docker", "save", "-o", str(archive), image_id], timeout=300)
            saved = _image_archive(archive, labels)
            _verify_image_files(root, saved)
            metadata = {
                "schema_version": SCHEMA_VERSION,
                "target": TARGET,
                "lock_sha256": lock_sha,
                "native_image_id": native["image_id"],
                "oci_digest": image_id,
                "tree_sha256": audit["tree_sha256"],
                "labels": labels,
                "package_count": len(inventory),
                "feed_config_sha256": _sha256_file(feed),
                "feed_index_sha256": lock["source"]["index_compressed_sha256"],
                "inventory_sha256": _sha256_file(inv_path),
                "saved_archive_sha256": _sha256_file(archive),
                "saved_config_sha256": saved["saved_config_sha256"],
                "saved_layer_sha256": saved["saved_layer_sha256"],
                "image_tree_sha256": saved["image_tree_sha256"],
                "smoke": smoke,
            }
            _verify_frozen_metadata(metadata, cache, lock, native, lock_sha, repo)
            (temporary / "manifest.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n"
            )
            iid.unlink()
            (temporary / "Dockerfile").unlink()
            _publish_directory_noreplace(temporary, cache)
            _verify_cache(cache, lock, native, lock_sha, repo)
            return {**metadata, "cache_state": "built", "offline_repeat": False}
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
