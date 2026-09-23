from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.init_cache import (
    InitError,
    _inventory,
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
    result = runner.invoke(cli, ["init", "--profile", "generic-mips", "--locked"])
    assert result.exit_code == 2
    assert "only the verified generic-aarch64" in result.output
