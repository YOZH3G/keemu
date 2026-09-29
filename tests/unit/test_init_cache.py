from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.init_cache import (
    BINFORMAT_OBSERVER_IMAGE,
    InitError,
    _audit_rootfs,
    _canonical_mips_archive,
    _inputs,
    _inventory,
    _observe_host_mips_binfmt,
    _preflight_mips_binfmt,
    _verify_frozen_metadata,
    _verify_image_files,
)

ROOT = Path(__file__).resolve().parents[2]


def test_inventory_exact_versions_names_and_duplicates() -> None:
    lock = {
        "packages": [
            {"name": "busybox", "version": "1.37.0-6"},
            {"name": "opkg", "version": "2025.11.05~80503d94-1"},
        ]
    }
    inventory = _inventory("busybox - 1.37.0-6\nopkg - 2025.11.05~80503d94-1\n", lock)
    assert inventory == [
        {"name": "busybox", "version": "1.37.0-6"},
        {"name": "opkg", "version": "2025.11.05~80503d94-1"},
    ]
    for value in (
        "busybox - 1.37.0-6\n",
        "busybox - 1.37.0-7\nopkg - 2025.11.05~80503d94-1\n",
        "busybox - 1.37.0-6\nopkg - 2025.11.05~80503d94-1\nextra - 1\n",
        "busybox - 1.37.0-6\nbusybox - 1.37.0-6\n",
    ):
        with pytest.raises(InitError):
            _inventory(value, lock)


def test_committed_digest_and_archive_bind_manifest_before_publication() -> None:
    pin = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())
    lock = json.loads((ROOT / pin["input_lock"]).read_text())
    native = json.loads((ROOT / pin["native_lock"]).read_text())
    metadata = {
        "schema_version": pin["cache_schema_version"],
        "target": pin["target"],
        "lock_sha256": pin["input_lock_sha256"],
        "native_image_id": pin["native_image_id"],
        "tree_sha256": pin["rootfs_tree_sha256"],
        "image_tree_sha256": pin["image_tree_sha256"],
        "oci_digest": pin["oci_digest"],
        "saved_archive_sha256": pin["saved_archive_sha256"],
        "saved_config_sha256": pin["saved_config_sha256"],
        "saved_layer_sha256": pin["saved_layer_sha256"],
        "inventory_sha256": pin["installed_inventory_sha256"],
        "feed_config_sha256": pin["feed_config_sha256"],
        "feed_index_sha256": pin["feed_index_sha256"],
        "package_count": pin["package_count"],
        "labels": pin["labels"],
        "smoke": pin["smoke"],
    }
    path = Path(pin["cache_key"])
    _verify_frozen_metadata(
        metadata, path, lock, native, pin["input_lock_sha256"], ROOT
    )
    for key, replacement in (
        ("oci_digest", "sha256:" + "0" * 64),
        ("saved_archive_sha256", "0" * 64),
        ("inventory_sha256", "0" * 64),
        ("image_tree_sha256", "0" * 64),
        ("feed_index_sha256", "0" * 64),
        ("package_count", 19),
        ("smoke", {}),
    ):
        changed = copy.deepcopy(metadata)
        changed[key] = replacement
        with pytest.raises(InitError, match="committed image lock"):
            _verify_frozen_metadata(
                changed, path, lock, native, pin["input_lock_sha256"], ROOT
            )
    with pytest.raises(InitError, match="committed image lock"):
        _verify_frozen_metadata(
            metadata,
            Path("wrong-cache-key"),
            lock,
            native,
            pin["input_lock_sha256"],
            ROOT,
        )


def test_image_audit_rejects_mutated_content_and_extras(tmp_path: Path) -> None:
    root = tmp_path / "root"
    file = root / "opt/bin/busybox"
    file.parent.mkdir(parents=True)
    file.write_bytes(b"actual")
    file.chmod(0o4755)
    import hashlib

    record = "F opt/bin/busybox 755 " + hashlib.sha256(b"actual").hexdigest() + "\n"
    _verify_image_files(root, {"image_records": {"opt/bin/busybox": record}})
    with pytest.raises(InitError, match="differs"):
        _verify_image_files(
            root, {"image_records": {"opt/bin/busybox": record.replace("755", "777")}}
        )
    with pytest.raises(InitError, match="extra"):
        _verify_image_files(
            root, {"image_records": {"opt/bin/busybox": record, "foreign": "x"}}
        )


def test_init_rejects_unsupported_profile_and_requires_locked_flag() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--profile", "generic-aarch64"]).exit_code == 2
    with patch(
        "keemu.cli.init_locked", return_value={"cache_state": "verified"}
    ) as init:
        result = runner.invoke(
            cli, ["init", "--profile", "generic-mips", "--locked", "--offline"]
        )
    assert result.exit_code == 0
    assert json.loads(result.output) == {"cache_state": "verified"}
    assert init.call_args.kwargs == {"offline": True, "target": "mips-3.4"}
    with patch(
        "keemu.cli.init_locked", return_value={"cache_state": "verified"}
    ) as init:
        result = runner.invoke(
            cli, ["init", "--profile", "generic-mipsel", "--locked", "--offline"]
        )
    assert result.exit_code == 0
    assert init.call_args.kwargs == {"offline": True, "target": "mipsel-3.4"}


def test_mips_inputs_bind_target_closure() -> None:
    lock, native, digest = _inputs(ROOT, target="mips-3.4")
    assert lock["target"] == "mips-3.4"
    assert native["binary_sha256"]
    assert digest
    assert len(lock["packages"]) == 20


def test_mipsel_inputs_bind_independent_target_closure() -> None:
    lock, native, digest = _inputs(ROOT, target="mipsel-3.4")
    assert lock["target"] == "mipsel-3.4"
    assert native["binary_sha256"]
    assert digest
    assert len(lock["packages"]) == 20
    assert digest != _inputs(ROOT, target="mips-3.4")[2]


def test_mipsel_binfmt_requires_its_own_exact_handler(tmp_path: Path) -> None:
    pin = json.loads((ROOT / "locks/m1e-init-mipsel.json").read_text())
    handler = pin["binfmt"]
    root = tmp_path / "binfmt_misc"
    root.mkdir()
    (root / "status").write_text("enabled\n")
    entry = root / "qemu-mipsel"
    entry.write_text(
        "enabled\n"
        f"interpreter {handler['interpreter']}\n"
        f"flags: {handler['flags']}\n"
        "offset 0\n"
        f"magic {handler['magic']}\n"
        f"mask {handler['mask']}\n"
    )
    _preflight_mips_binfmt(ROOT, target="mipsel-3.4", proc=root)
    entry.write_text(entry.read_text().replace("flags: POF", "flags: P"))
    with pytest.raises(InitError, match="binfmt"):
        _preflight_mips_binfmt(ROOT, target="mipsel-3.4", proc=root)


def test_mipsel_elf_endian_is_checked_not_bypassed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    elf = root / "opt/bin/opkg"
    elf.parent.mkdir(parents=True)
    data = bytearray(40)
    data[:6] = b"\x7fELF\x01\x02"
    data[18:20] = (8).to_bytes(2, "big")
    data[36:40] = (0x70001005).to_bytes(4, "big")
    elf.write_bytes(data)
    with pytest.raises(InitError, match="endian"):
        _audit_rootfs(root, "mipsel-3.4")


def test_mips_binfmt_requires_exact_current_handler(tmp_path: Path) -> None:
    pin = json.loads((ROOT / "locks/m1e-init-mips.json").read_text())
    handler = pin["binfmt"]
    root = tmp_path / "binfmt_misc"
    root.mkdir()
    (root / "status").write_text("enabled\n")
    entry = root / "qemu-mips"
    entry.write_text(
        "enabled\n"
        f"interpreter {handler['interpreter']}\n"
        f"flags: {handler['flags']}\n"
        "offset 0\n"
        f"magic {handler['magic']}\n"
        f"mask {handler['mask']}\n"
    )
    _preflight_mips_binfmt(ROOT, proc=root)
    entry.write_text(entry.read_text().replace("flags: POF", "flags: P"))
    with pytest.raises(InitError, match="binfmt"):
        _preflight_mips_binfmt(ROOT, proc=root)
    entry.unlink()
    with pytest.raises(InitError, match="binfmt"):
        _preflight_mips_binfmt(ROOT, proc=root)


@pytest.mark.parametrize(
    ("owner", "create_error"),
    [("keemu", False), ("foreign", False), ("keemu", True)],
)
@pytest.mark.parametrize("target", ["mips-3.4", "mipsel-3.4"])
def test_mips_observer_is_owner_checked_and_cleans_anonymous_volume(
    owner: str,
    create_error: bool,
    target: str,
) -> None:
    cid = "a" * 64
    volume = "b" * 64
    suffix = "mips" if target == "mips-3.4" else "mipsel"
    handler = json.loads((ROOT / f"locks/m1e-init-{suffix}.json").read_text())["binfmt"]
    output = (
        "enabled\nenabled\n"
        f"interpreter {handler['interpreter']}\n"
        f"flags: {handler['flags']}\n"
        "offset 0\n"
        f"magic {handler['magic']}\n"
        f"mask {handler['mask']}\n"
    )
    calls: list[list[str]] = []
    attached = True
    status = entry = ""

    def fake_run(argv: list[str], *, timeout: int = 300) -> str:
        nonlocal attached
        calls.append(argv)
        match argv[1:3]:
            case ["image", "inspect"]:
                return json.dumps(
                    [
                        {
                            "Id": BINFORMAT_OBSERVER_IMAGE,
                            "Architecture": "amd64",
                            "Config": {"Volumes": {"/opt/data": {}}},
                        }
                    ]
                )
            case ["create", *_]:
                assert "--network=none" in argv
                assert "--cap-drop=ALL" in argv
                assert "--read-only" in argv
                assert any(
                    "/proc/sys/fs/binfmt_misc" in arg and "readonly" in arg
                    for arg in argv
                )
                assert argv[-1] == f"/__keemu_binfmt/qemu-{suffix}"
                if create_error:
                    raise InitError("create failed after allocation")
                return cid
            case ["inspect", _]:
                return json.dumps(
                    [
                        {
                            "Id": cid,
                            "Name": "/keemu-binfmt-test",
                            "Image": BINFORMAT_OBSERVER_IMAGE,
                            "Config": {
                                "Labels": {
                                    "org.keemu.owner": owner,
                                    "org.keemu.run-id": "c" * 32,
                                }
                            },
                            "HostConfig": {
                                "NetworkMode": "none",
                                "Privileged": False,
                                "ReadonlyRootfs": True,
                                "CapDrop": ["ALL"],
                                "SecurityOpt": ["no-new-privileges"],
                            },
                            "Mounts": [
                                {
                                    "Type": "bind",
                                    "Source": "/proc/sys/fs/binfmt_misc",
                                    "Destination": "/__keemu_binfmt",
                                    "RW": False,
                                },
                                {
                                    "Type": "volume",
                                    "Name": volume,
                                    "Destination": "/opt/data",
                                    "RW": True,
                                },
                            ],
                            "State": {"ExitCode": 0},
                        }
                    ]
                )
            case ["start", _]:
                return output.strip()
            case ["ps", *_]:
                assert "--no-trunc" in argv
                if argv[-1] == "name=^/keemu-binfmt-test$":
                    return cid
                return cid if attached and argv[-1] == f"volume={volume}" else ""
            case ["volume", "ls"]:
                return ""
            case ["volume", "inspect"]:
                return json.dumps([{"Name": volume}])
            case ["rm", *_]:
                attached = False
                return cid
            case ["volume", "rm"]:
                return volume
        raise AssertionError(argv)

    with (
        patch("keemu.init_cache._run", side_effect=fake_run),
        patch(
            "keemu.init_cache.uuid.uuid4",
            return_value=type("U", (), {"hex": "c" * 32})(),
        ),
    ):
        if owner == "foreign":
            with pytest.raises(InitError, match="ownership mismatch"):
                _observe_host_mips_binfmt(target=target, name="keemu-binfmt-test")
        elif create_error:
            with pytest.raises(InitError, match="create failed after allocation"):
                _observe_host_mips_binfmt(target=target, name="keemu-binfmt-test")
        else:
            status, entry = _observe_host_mips_binfmt(
                target=target, name="keemu-binfmt-test"
            )
    if owner == "foreign":
        assert not any(c[1] in ("start", "rm") for c in calls)
        return
    if create_error:
        assert not any(c[1] == "start" for c in calls)
        assert [c[1:3] for c in calls].count(["volume", "rm"]) == 1
        return
    assert status == "enabled\n"
    assert entry.startswith("enabled\ninterpreter")
    assert [c[1:3] for c in calls].count(["volume", "rm"]) == 1
    assert [c[1] for c in calls].index("rm") < [c[1:3] for c in calls].index(
        ["volume", "rm"]
    )


def test_mips_archive_canonicalization_freezes_config_and_layer(tmp_path: Path) -> None:
    def timestamped_source(path: Path, timestamp: int) -> None:
        def encoded(value: object) -> bytes:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

        def digest(value: bytes) -> str:
            return hashlib.sha256(value).hexdigest()

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as layer:
            header = tarfile.TarInfo("fixture")
            header.size = 3
            header.mtime = timestamp
            layer.addfile(header, io.BytesIO(b"abc"))
        layer_bytes = gzip.compress(raw.getvalue(), mtime=timestamp)
        config_bytes = encoded(
            {
                "os": "linux",
                "architecture": "amd64",
                "config": {"Entrypoint": ["/__keemu/init"]},
                "rootfs": {
                    "type": "layers",
                    "diff_ids": ["sha256:" + digest(raw.getvalue())],
                },
                "created": f"2026-01-01T00:00:{timestamp:02}Z",
                "history": [{"created": f"2026-01-01T00:00:{timestamp:02}Z"}],
            }
        )
        manifest_bytes = encoded(
            {
                "schemaVersion": 2,
                "config": {
                    "digest": "sha256:" + digest(config_bytes),
                    "size": len(config_bytes),
                },
                "layers": [
                    {
                        "digest": "sha256:" + digest(layer_bytes),
                        "size": len(layer_bytes),
                    }
                ],
            }
        )
        members = {
            "oci-layout": encoded({"imageLayoutVersion": "1.0.0"}),
            "index.json": encoded(
                {
                    "manifests": [
                        {
                            "digest": "sha256:" + digest(manifest_bytes),
                            "size": len(manifest_bytes),
                        }
                    ]
                }
            ),
            "manifest.json": encoded(
                [
                    {
                        "Config": "blobs/sha256/" + digest(config_bytes),
                        "RepoTags": None,
                        "Layers": ["blobs/sha256/" + digest(layer_bytes)],
                    }
                ]
            ),
            "blobs/sha256/" + digest(manifest_bytes): manifest_bytes,
            "blobs/sha256/" + digest(config_bytes): config_bytes,
            "blobs/sha256/" + digest(layer_bytes): layer_bytes,
        }
        with tarfile.open(path, mode="w") as archive:
            for name, content in members.items():
                header = tarfile.TarInfo(name)
                header.size = len(content)
                archive.addfile(header, io.BytesIO(content))

    sources = [tmp_path / "source-one.tar", tmp_path / "source-two.tar"]
    for timestamp, source in enumerate(sources, start=1):
        timestamped_source(source, timestamp)
    first, second = tmp_path / "one.tar", tmp_path / "two.tar"
    ids = [
        _canonical_mips_archive(source, dest)
        for source, dest in zip(sources, (first, second), strict=True)
    ]
    assert ids[0] == ids[1]
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first) as archive:
        manifest = json.load(archive.extractfile("manifest.json"))[0]
        config = json.load(archive.extractfile(manifest["Config"]))
        assert config["created"] == "1970-01-01T00:00:00Z"
        assert all(
            entry["created"] == "1970-01-01T00:00:00Z" for entry in config["history"]
        )
        with tarfile.open(fileobj=archive.extractfile(manifest["Layers"][0])) as layer:
            assert all(member.mtime == 0 for member in layer)


def test_mips_committed_metadata_refuses_divergent_image() -> None:
    pin = json.loads((ROOT / "locks/m1e-init-mips.json").read_text())
    lock = json.loads((ROOT / pin["input_lock"]).read_text())
    native = json.loads((ROOT / pin["native_lock"]).read_text())
    metadata = {
        "schema_version": pin["cache_schema_version"],
        "target": pin["target"],
        "lock_sha256": pin["input_lock_sha256"],
        "native_image_id": pin["native_image_id"],
        "tree_sha256": pin["rootfs_tree_sha256"],
        "image_tree_sha256": pin["image_tree_sha256"],
        "oci_digest": pin["oci_digest"],
        "saved_archive_sha256": pin["saved_archive_sha256"],
        "saved_config_sha256": pin["saved_config_sha256"],
        "saved_layer_sha256": pin["saved_layer_sha256"],
        "inventory_sha256": pin["installed_inventory_sha256"],
        "feed_config_sha256": pin["feed_config_sha256"],
        "feed_index_sha256": pin["feed_index_sha256"],
        "package_count": pin["package_count"],
        "labels": pin["labels"],
        "smoke": pin["smoke"],
    }
    _verify_frozen_metadata(
        metadata, Path(pin["cache_key"]), lock, native, pin["input_lock_sha256"], ROOT
    )
    for key in ("oci_digest", "tree_sha256", "inventory_sha256", "smoke"):
        changed = copy.deepcopy(metadata)
        changed[key] = {} if key == "smoke" else "0" * 64
        with pytest.raises(InitError):
            _verify_frozen_metadata(
                changed,
                Path(pin["cache_key"]),
                lock,
                native,
                pin["input_lock_sha256"],
                ROOT,
            )


def test_mipsel_committed_metadata_rejects_cross_target_and_tampering() -> None:
    pin = json.loads((ROOT / "locks/m1e-init-mipsel.json").read_text())
    lock = json.loads((ROOT / pin["input_lock"]).read_text())
    native = json.loads((ROOT / pin["native_lock"]).read_text())
    fields = {
        "schema_version": "cache_schema_version",
        "target": "target",
        "lock_sha256": "input_lock_sha256",
        "native_image_id": "native_image_id",
        "tree_sha256": "rootfs_tree_sha256",
        "image_tree_sha256": "image_tree_sha256",
        "oci_digest": "oci_digest",
        "saved_archive_sha256": "saved_archive_sha256",
        "saved_config_sha256": "saved_config_sha256",
        "saved_layer_sha256": "saved_layer_sha256",
        "inventory_sha256": "installed_inventory_sha256",
        "feed_config_sha256": "feed_config_sha256",
        "feed_index_sha256": "feed_index_sha256",
        "package_count": "package_count",
        "labels": "labels",
        "smoke": "smoke",
    }
    metadata = {key: pin[value] for key, value in fields.items()}
    args = (Path(pin["cache_key"]), lock, native, pin["input_lock_sha256"], ROOT)
    _verify_frozen_metadata(metadata, *args)
    for field in ("target", "oci_digest", "tree_sha256", "labels", "smoke"):
        altered = copy.deepcopy(metadata)
        altered[field] = "mips-3.4" if field == "target" else None
        with pytest.raises(InitError):
            _verify_frozen_metadata(altered, *args)
    with pytest.raises(InitError, match="committed image lock"):
        _verify_frozen_metadata(metadata, Path("foreign"), *args[1:])
