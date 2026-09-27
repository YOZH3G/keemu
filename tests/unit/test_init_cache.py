from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.init_cache import (
    InitError,
    _inputs,
    _inventory,
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
    assert (
        runner.invoke(
            cli, ["init", "--profile", "generic-mipsel", "--locked"]
        ).exit_code
        == 2
    )


def test_mips_inputs_bind_target_closure() -> None:
    lock, native, digest = _inputs(ROOT, target="mips-3.4")
    assert lock["target"] == "mips-3.4"
    assert native["binary_sha256"]
    assert digest
    assert len(lock["packages"]) == 20


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
