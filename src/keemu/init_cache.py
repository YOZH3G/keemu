"""Offline-locked generic base preparation; no scenario or persistent lifecycle.

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
MIPS_SCHEMA_VERSION = 5
TARGET = "aarch64-3.10"
MIPS = "mips-3.4"
HEX = re.compile(r"[0-9a-f]{64}\Z")
BINFORMAT_OBSERVER_IMAGE = (
    "sha256:7956ad1f365ad2ce4454673cb3f3ab31798703b2a3ea1d1329c509250f974bee"
)
BINFORMAT_SOURCE = "/proc/sys/fs/binfmt_misc"
BINFORMAT_DESTINATION = "/__keemu_binfmt"


def _cache_schema(target: str) -> int:
    return MIPS_SCHEMA_VERSION if target == MIPS else SCHEMA_VERSION


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


def _image_lock_path(repo: Path, target: str) -> Path:
    if target == TARGET:
        return repo / "locks/m1a-init-aarch64.json"
    if target == MIPS:
        return repo / "locks/m1e-init-mips.json"
    raise InitError("unsupported locked init target")


def _paths(repo: Path, target: str) -> tuple[Path, Path, Path, Path]:
    if target == TARGET:
        return (
            repo / "locks/p0-aarch64.json",
            repo / ".runtime/p0/aarch64-k3.10",
            repo / ".runtime/p0/qemu-user-root/usr/bin/qemu-aarch64",
            repo / "profiles/generic/generic-aarch64.yaml",
        )
    if target == MIPS:
        return (
            repo / "locks/m1b18-mips-3.4.json",
            repo / ".runtime/m1b18/mips-3.4",
            repo / ".runtime/p0/qemu-user-root/usr/bin/qemu-mips",
            repo / "profiles/generic/generic-mips.yaml",
        )
    raise InitError("unsupported locked init target")


def _observe_host_mips_binfmt(*, name: str | None = None) -> tuple[str, str]:
    """Read only daemon-host binfmt via an exact owned, disposable Docker helper."""
    run_id = uuid.uuid4().hex
    name = name or f"keemu-binfmt-{run_id[:12]}"
    if not re.fullmatch(r"keemu-binfmt-[a-z0-9-]+", name):
        raise InitError("invalid binfmt observer name")
    image = json.loads(_run(["docker", "image", "inspect", BINFORMAT_OBSERVER_IMAGE]))
    if (
        len(image) != 1
        or image[0].get("Id") != BINFORMAT_OBSERVER_IMAGE
        or image[0].get("Architecture") != "amd64"
        or image[0].get("Config", {}).get("Volumes") != {"/opt/data": {}}
    ):
        raise InitError("unverified binfmt observer image")
    cid: str | None = None
    volume: str | None = None

    def inspected() -> dict:
        if cid is None:
            raise InitError("binfmt observer has no issued container ID")
        result = json.loads(_run(["docker", "inspect", cid]))
        if len(result) != 1:
            raise InitError("ambiguous binfmt observer inspect")
        item = result[0]
        labels = item.get("Config", {}).get("Labels") or {}
        if (
            item.get("Id") != cid
            or item.get("Name") != "/" + name
            or item.get("Image") != BINFORMAT_OBSERVER_IMAGE
            or labels.get("org.keemu.owner") != "keemu"
            or labels.get("org.keemu.run-id") != run_id
        ):
            raise InitError("binfmt observer ownership mismatch; refused cleanup")
        return item

    try:
        create_argv = [
            "docker",
            "create",
            "--name",
            name,
            "--network=none",
            "--memory=128m",
            "--memory-swap=128m",
            "--cpus=0.5",
            "--pids-limit=32",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--mount",
            (f"type=bind,src={BINFORMAT_SOURCE},dst={BINFORMAT_DESTINATION},readonly"),
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--entrypoint",
            "/bin/cat",
            BINFORMAT_OBSERVER_IMAGE,
            f"{BINFORMAT_DESTINATION}/status",
            f"{BINFORMAT_DESTINATION}/qemu-mips",
        ]

        def recover_issued_id() -> None:
            nonlocal cid
            matches = _run(
                ["docker", "ps", "-aq", "--no-trunc", "--filter", f"name=^/{name}$"]
            ).splitlines()
            if len(matches) == 1 and re.fullmatch(r"[0-9a-f]{64}", matches[0]):
                cid = matches[0]

        try:
            cid = _run(create_argv)
        except InitError:
            # A lost Docker CLI response can follow a successful allocation.
            # The full-ID/image/label check in inspected() gates cleanup.
            recover_issued_id()
            raise
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            recover_issued_id()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise InitError("invalid binfmt observer container ID")
        item = inspected()
        host = item.get("HostConfig", {})
        if (
            host.get("NetworkMode") != "none"
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("CapDrop") != ["ALL"]
            or "no-new-privileges" not in (host.get("SecurityOpt") or [])
        ):
            raise InitError("binfmt observer isolation mismatch")
        mounts = item.get("Mounts", [])
        bind = [m for m in mounts if m.get("Type") == "bind"]
        volumes = [m for m in mounts if m.get("Type") == "volume"]
        if len(volumes) == 1 and volumes[0].get("Destination") == "/opt/data":
            volume = volumes[0].get("Name")
        if (
            len(mounts) != 2
            or len(bind) != 1
            or bind[0].get("Source") != BINFORMAT_SOURCE
            or bind[0].get("Destination") != BINFORMAT_DESTINATION
            or bind[0].get("RW") is not False
            or len(volumes) != 1
            or volumes[0].get("Destination") != "/opt/data"
        ):
            raise InitError("binfmt observer mount mismatch")
        volume = volumes[0].get("Name")
        if not isinstance(volume, str) or not re.fullmatch(r"[0-9a-f]{64}", volume):
            raise InitError("ambiguous binfmt observer anonymous volume")
        volume_info = json.loads(_run(["docker", "volume", "inspect", volume]))
        if len(volume_info) != 1 or volume_info[0].get("Name") != volume:
            raise InitError("binfmt observer volume identity mismatch")
        if _run(
            ["docker", "ps", "-aq", "--no-trunc", "--filter", f"volume={volume}"]
        ).splitlines() != [cid]:
            raise InitError("binfmt observer volume has ambiguous attachments")
        output = _run(["docker", "start", "-a", cid], timeout=40)
        if inspected().get("State", {}).get("ExitCode") != 0:
            raise InitError("binfmt observer exited unsuccessfully")
        status, separator, entry = output.partition("\n")
        if not separator or not entry:
            raise InitError("incomplete host binfmt readback")
        return status + "\n", entry + "\n"
    finally:
        if cid and re.fullmatch(r"[0-9a-f]{64}", cid):
            item = inspected()
            if volume is None:
                candidates = [
                    m.get("Name")
                    for m in item.get("Mounts", [])
                    if m.get("Type") == "volume" and m.get("Destination") == "/opt/data"
                ]
                if len(candidates) == 1:
                    volume = candidates[0]
            if not isinstance(volume, str) or not re.fullmatch(r"[0-9a-f]{64}", volume):
                raise InitError("binfmt observer volume ambiguous; refused cleanup")
            _run(["docker", "rm", "-f", cid], timeout=40)
            if _run(["docker", "ps", "-aq", "--no-trunc", "--filter", f"id={cid}"]):
                raise InitError("binfmt observer container persists after cleanup")
            if volume:
                if _run(
                    [
                        "docker",
                        "ps",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        f"volume={volume}",
                    ]
                ):
                    raise InitError("binfmt observer volume still attached")
                _run(["docker", "volume", "rm", volume], timeout=40)
                if volume in _run(["docker", "volume", "ls", "-q"]).splitlines():
                    raise InitError("binfmt observer volume persists after cleanup")


def _preflight_mips_binfmt(repo: Path, *, proc: Path | None = None) -> None:
    """Require current exact readback, not historical registration evidence."""
    expected = json.loads(_image_lock_path(repo, MIPS).read_text())["binfmt"]
    if proc is None:
        status, entry = _observe_host_mips_binfmt()
    else:
        try:
            status = (proc / "status").read_text(encoding="ascii")
            entry = (proc / "qemu-mips").read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise InitError(
                "current host qemu-mips binfmt readback unavailable"
            ) from error
    lines = entry.splitlines()
    actual = {
        line.split(" ", 1)[0]: line.split(" ", 1)[1]
        for line in lines[1:]
        if " " in line
    }
    if (
        status.strip() != "enabled"
        or not lines
        or lines[0] != "enabled"
        or actual.get("interpreter") != expected["interpreter"]
        or actual.get("flags:") != expected["flags"]
        or actual.get("offset") != "0"
        or actual.get("magic") != expected["magic"]
        or actual.get("mask") != expected["mask"]
        or len(lines) != 6
        or len(actual) != 5
    ):
        raise InitError("current host qemu-mips binfmt differs from locked handler")


def _inputs(repo: Path, *, target: str = TARGET) -> tuple[dict, dict, str]:
    lock_path, base, qemu, profile = _paths(repo, target)
    native_path = repo / "locks/p0-mixed-image-aarch64-p005.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    native = json.loads(native_path.read_text(encoding="utf-8"))
    if (lock.get("schema_version"), lock.get("kind"), lock.get("target")) != (
        1,
        "entware-rootfs-lock",
        target,
    ):
        raise InitError("wrong rootfs lock schema or target")
    if (
        native.get("kind") != "p0-derived-runtime-image-lock"
        or native.get("platform") != "linux/amd64"
    ):
        raise InitError("wrong native init lock")
    if target == TARGET and native.get("labels", {}).get(
        "org.keemu.package-lock-sha256"
    ) != _sha256_file(lock_path):
        raise InitError("native init base does not bind this package lock")
    _regular_hash(repo / native["source_path"], native["source_sha256"])
    if profile.is_symlink() or not profile.is_file():
        raise InitError("missing or linked profile")
    bootstrap = next(
        (a for a in lock["bootstrap_artifacts"] if a["filename"] == "opkg"), None
    )
    if bootstrap is None:
        raise InitError("bootstrap opkg absent from lock")
    _regular_hash(base / "opkg", bootstrap["sha256"])
    image_lock = json.loads(_image_lock_path(repo, target).read_text(encoding="utf-8"))
    if target == TARGET:
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
    else:
        fixtures_path = repo / "locks/m1b18-fixtures-mips-3.4.json"
        fixtures = json.loads(fixtures_path.read_text(encoding="utf-8"))
        prior = json.loads(
            (repo / "locks/m1b18-image-mips-3.4.json").read_text(encoding="utf-8")
        )
        if (
            fixtures.get("target") != target
            or prior.get("target") != target
            or prior.get("labels", {}).get("org.keemu.init-binary-sha256")
            != native["binary_sha256"]
            or image_lock.get("fixture_lock_sha256") != _sha256_file(fixtures_path)
            or image_lock.get("profile_sha256") != _sha256_file(profile)
            or fixtures.get("qemu_sha256") != image_lock.get("qemu_binary_sha256")
        ):
            raise InitError("MIPS prerequisite lock binding mismatch")
        sdk = repo / "locks/m1b18-sdk-mips-3.4.json"
        _regular_hash(sdk, fixtures["sdk_lock_sha256"])
        for artifact in lock["bootstrap_artifacts"]:
            _regular_hash(base / artifact["filename"], artifact["sha256"])
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
            or item["architecture"] not in (target, "all")
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


def _audit_rootfs(root: Path, target: str) -> dict:
    if target == TARGET:
        return audit_tree(root)
    if target != MIPS:
        raise InitError("unsupported locked init target")
    digest = hashlib.sha256()
    target_elfs = 0
    native_elfs = 0
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            link = str(path.readlink())
            if link.startswith(("/proc/", "/sys/")):
                raise InitError("unsafe rootfs link")
            record = f"L {name} {stat.S_IMODE(mode):o} {link}\n"
        elif stat.S_ISREG(mode):
            record = f"F {name} {stat.S_IMODE(mode):o} {_sha256_file(path)}\n"
            with path.open("rb") as stream:
                header = stream.read(40)
            if header.startswith(b"\x7fELF"):
                if name == "__keemu/init":
                    if (
                        header[4:6] != b"\x02\x01"
                        or int.from_bytes(header[18:20], "little") != 62
                    ):
                        raise InitError("native init ELF mismatch")
                    native_elfs += 1
                else:
                    flags = int.from_bytes(header[36:40], "big")
                    if (
                        header[4:6] != b"\x01\x02"
                        or int.from_bytes(header[18:20], "big") != 8
                        or flags & 0x0000F000 != 0x1000
                        or flags & 0xF0000000 != 0x70000000
                    ):
                        raise InitError(f"MIPS ELF class/endian/ABI mismatch: {name}")
                    target_elfs += 1
        else:
            raise InitError("unsupported rootfs member")
        digest.update(record.encode())
    for required in ("bin/sh", "opt/bin/opkg", "opt/bin/busybox", "__keemu/init"):
        if not ((root / required).is_file() or (root / required).is_symlink()):
            raise InitError(f"required target path absent: {required}")
    if (
        (root / "bin/sh").readlink() != Path("/opt/bin/busybox")
        or not target_elfs
        or native_elfs != 1
    ):
        raise InitError("native/target ELF inventory incomplete")
    return {"tree_sha256": digest.hexdigest(), "elf_count": target_elfs}


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


def _canonical_mips_archive(source: Path, destination: Path) -> str:
    """Freeze legacy Docker's COPY mtimes and config history before loading.

    Only the MIPS v5 archive uses this serializer; existing AArch64 v4 bytes
    and its Docker build path remain untouched. OCI digests are recomputed from
    the normalized uncompressed layer, compressed layer, config and manifest.
    """
    if source == destination or source.is_symlink() or not source.is_file():
        raise InitError("invalid MIPS image archive source")

    def encoded(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    with tarfile.open(source) as archive:

        def member_bytes(name: str) -> bytes:
            stream = archive.extractfile(name)
            if stream is None:
                raise InitError(f"missing MIPS image archive member: {name}")
            return stream.read()

        entries = json.loads(member_bytes("manifest.json"))
        index = json.loads(member_bytes("index.json"))
        if (
            len(entries) != 1
            or len(entries[0].get("Layers", [])) != 1
            or entries[0].get("RepoTags") not in (None, [])
            or len(index.get("manifests", [])) != 1
            or json.loads(member_bytes("oci-layout")) != {"imageLayoutVersion": "1.0.0"}
        ):
            raise InitError("unexpected MIPS OCI image archive layout")
        entry = entries[0]
        config_path, layer_path = entry["Config"], entry["Layers"][0]
        descriptor = index["manifests"][0]
        manifest_path = "blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")
        manifest_bytes = member_bytes(manifest_path)
        manifest = json.loads(manifest_bytes)
        config_bytes = member_bytes(config_path)
        layer_bytes = member_bytes(layer_path)
        if (
            descriptor["digest"] != "sha256:" + digest(manifest_bytes)
            or descriptor["size"] != len(manifest_bytes)
            or manifest["schemaVersion"] != 2
            or len(manifest["layers"]) != 1
            or manifest["config"]["digest"] != "sha256:" + digest(config_bytes)
            or manifest["config"]["size"] != len(config_bytes)
            or manifest["layers"][0]["digest"] != "sha256:" + digest(layer_bytes)
            or manifest["layers"][0]["size"] != len(layer_bytes)
            or config_path != "blobs/sha256/" + digest(config_bytes)
            or layer_path != "blobs/sha256/" + digest(layer_bytes)
        ):
            raise InitError("MIPS OCI image archive digest mismatch")
        config = json.loads(config_bytes)
        if (
            config.get("os") != "linux"
            or config.get("architecture") != "amd64"
            or config.get("config", {}).get("Entrypoint") != ["/__keemu/init"]
            or config.get("rootfs", {}).get("type") != "layers"
            or config["rootfs"]["diff_ids"]
            != ["sha256:" + digest(gzip.decompress(layer_bytes))]
            or not config.get("history")
        ):
            raise InitError("MIPS OCI image config mismatch")

        raw = io.BytesIO()
        with (
            tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:gz") as old,
            tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as new,
        ):
            members = old.getmembers()
            names = [member.name for member in members]
            if len(set(names)) != len(names):
                raise InitError("duplicate MIPS OCI layer path")
            for member in sorted(members, key=lambda item: item.name):
                if (
                    member.name.startswith("/")
                    or ".." in Path(member.name).parts
                    or not (member.isfile() or member.isdir() or member.issym())
                    or member.pax_headers
                ):
                    raise InitError("unsafe MIPS OCI layer member")
                member.mtime = 0
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                new.addfile(
                    member, old.extractfile(member) if member.isfile() else None
                )
        uncompressed = raw.getvalue()
        compressed = io.BytesIO()
        with gzip.GzipFile(
            fileobj=compressed, mode="wb", filename="", mtime=0
        ) as zipfile:
            zipfile.write(uncompressed)
        canonical_layer = compressed.getvalue()
        config["created"] = "1970-01-01T00:00:00Z"
        for history in config["history"]:
            history["created"] = config["created"]
        config["rootfs"]["diff_ids"] = ["sha256:" + digest(uncompressed)]
        canonical_config = encoded(config)
        manifest["config"]["digest"] = "sha256:" + digest(canonical_config)
        manifest["config"]["size"] = len(canonical_config)
        manifest["layers"][0]["digest"] = "sha256:" + digest(canonical_layer)
        manifest["layers"][0]["size"] = len(canonical_layer)
        canonical_manifest = encoded(manifest)
        descriptor["digest"] = "sha256:" + digest(canonical_manifest)
        descriptor["size"] = len(canonical_manifest)
        contents = {
            "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
            "index.json": encoded(index),
            "manifest.json": encoded(
                [
                    {
                        "Config": "blobs/sha256/" + digest(canonical_config),
                        "RepoTags": None,
                        "Layers": ["blobs/sha256/" + digest(canonical_layer)],
                    }
                ]
            ),
            "blobs/sha256/" + digest(canonical_manifest): canonical_manifest,
            "blobs/sha256/" + digest(canonical_config): canonical_config,
            "blobs/sha256/" + digest(canonical_layer): canonical_layer,
        }
    with tarfile.open(destination, mode="w", format=tarfile.PAX_FORMAT) as result:
        for directory in ("blobs", "blobs/sha256"):
            header = tarfile.TarInfo(directory)
            header.type = tarfile.DIRTYPE
            header.mode = 0o755
            result.addfile(header)
        for name, data in sorted(contents.items()):
            header = tarfile.TarInfo(name)
            header.mode = 0o644
            header.size = len(data)
            result.addfile(header, io.BytesIO(data))
    return "sha256:" + digest(canonical_manifest)


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
    target = lock["target"]
    if (
        metadata.get("schema_version") != _cache_schema(target)
        or metadata.get("target") != target
        or metadata.get("lock_sha256") != lock_sha
        or metadata.get("native_image_id") != native["image_id"]
    ):
        raise InitError("cache identity mismatch")
    image_lock = json.loads(_image_lock_path(repo, target).read_text(encoding="utf-8"))
    bindings = {
        "schema_version": (
            image_lock.get("cache_schema_version"),
            _cache_schema(target),
        ),
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
        "target": (image_lock.get("target"), target),
    }
    expected_kind = (
        "mvp1a-locked-base-image" if target == TARGET else "mvp1e-locked-base-image"
    )
    if (
        metadata.get("package_count") != len(lock["packages"])
        or metadata.get("feed_index_sha256")
        != lock["source"]["index_compressed_sha256"]
        or image_lock.get("kind") != expected_kind
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
    audit = _audit_rootfs(root, lock["target"])
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


def _smoke(image_id: str, lock: dict, *, repo: Path | None = None) -> dict[str, str]:
    if lock["target"] == MIPS:
        _preflight_mips_binfmt(repo or Path(__file__).resolve().parents[2])
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
        architecture = "aarch64" if lock["target"] == TARGET else "mips"
        if "nested-ok" not in target or architecture not in target:
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

        index_url = lock["source"]["index_url"]
        if not index_url.startswith("https://bin.entware.net/"):
            raise InitError("locked HTTPS smoke URL is not the Entware feed")
        with urllib.request.urlopen(index_url, timeout=30) as response:  # noqa: S310
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
    repo: Path,
    *,
    cache_root: Path | None = None,
    offline: bool = False,
    target: str = TARGET,
) -> dict:
    """Prepare once; offline repeat validates inputs and cache without network."""
    repo = repo.resolve()
    lock, native, lock_sha = _inputs(repo, target=target)
    schema = _cache_schema(target)
    key = hashlib.sha256(
        f"{schema}:{target}:{lock_sha}:{native['image_id']}".encode()
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
        if target == TARGET:
            verify_native_image(repo)
        else:
            _preflight_mips_binfmt(repo)
        lock_path, base, qemu, _ = _paths(repo, target)
        temporary = Path(tempfile.mkdtemp(prefix=f".{key}.", dir=cache_root))
        try:
            root = temporary / "rootfs"
            result = build_diagnostic_rootfs(
                lock_path=lock_path,
                package_cache=base / "packages",
                destination=root,
                qemu=qemu,
                bootstrap_opkg=base / "opkg",
                timeout=600 if target == MIPS else 300,
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
                f"arch {target} 160\n",
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
            audit = _audit_rootfs(root, target)
            labels = {
                "org.keemu.owner": "keemu",
                "org.keemu.phase": "m1a-11" if target == TARGET else "m1e-01",
                "org.keemu.target": target,
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
            archive = temporary / "image.tar"
            if target == MIPS:
                raw_archive = temporary / "built.tar"
                _run(
                    ["docker", "save", "-o", str(raw_archive), image_id],
                    timeout=300,
                )
                image_id = _canonical_mips_archive(raw_archive, archive)
                raw_archive.unlink()
                _run(["docker", "load", "-i", str(archive)], timeout=300)
                inspected = json.loads(_run(["docker", "image", "inspect", image_id]))[
                    0
                ]
                if (
                    inspected["Id"] != image_id
                    or inspected["Config"]["Labels"] != labels
                    or inspected["Architecture"] != "amd64"
                    or inspected["Os"] != "linux"
                    or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
                ):
                    raise InitError("canonical MIPS image differs from audited rootfs")
            smoke = _smoke(image_id, lock, repo=repo)
            if target == TARGET:
                _run(["docker", "save", "-o", str(archive), image_id], timeout=300)
            saved = _image_archive(archive, labels)
            _verify_image_files(root, saved)
            metadata = {
                "schema_version": schema,
                "target": target,
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
