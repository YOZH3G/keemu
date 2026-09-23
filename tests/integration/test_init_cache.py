"""Opt-in real Docker/binfmt and copied-cache corruption checks for m1a-11."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from keemu.init_cache import InitError, _inputs, _smoke, _verify_cache, init_locked

REPO = Path(__file__).resolve().parents[2]
PIN = json.loads((REPO / "locks/m1a-init-aarch64.json").read_text())
pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("KEEMU_RUN_INIT_CACHE") != "1",
        reason="set KEEMU_RUN_INIT_CACHE=1 with pinned cache and Docker/binfmt",
    ),
]


def test_live_image_and_offline_repeat_never_fetches() -> None:
    with patch("urllib.request.urlopen", side_effect=AssertionError("offline fetched")):
        result = init_locked(REPO, offline=True)
    assert result["cache_state"] == "verified"
    assert result["oci_digest"] == PIN["oci_digest"]
    assert result["tree_sha256"] == PIN["rootfs_tree_sha256"]
    assert result["package_count"] == PIN["package_count"]


def test_target_opkg_inventory_and_network_with_owned_cleanup() -> None:
    lock, _, _ = _inputs(REPO)
    result = _smoke(PIN["oci_digest"], lock)
    assert result["target"] == "PASS"
    assert result["dns"] == "PASS (target Docker bridge)"
    assert "not executed in target namespace" in result["limitation"]


@pytest.mark.parametrize(
    "corruption",
    ["missing-manifest", "rootfs-byte", "archive-byte", "inventory-byte", "feed-byte"],
)
def test_copied_corrupt_cache_fails_closed(tmp_path: Path, corruption: str) -> None:
    lock, native, lock_sha = _inputs(REPO)
    source = REPO / ".runtime/init-cache" / PIN["cache_key"]
    candidate = tmp_path / PIN["cache_key"]
    shutil.copytree(source, candidate, symlinks=True)
    _verify_cache(candidate, lock, native, lock_sha, REPO)
    file = {
        "missing-manifest": candidate / "manifest.json",
        "rootfs-byte": candidate / "rootfs/opt/lib/opkg/status",
        "archive-byte": candidate / "image.tar",
        "inventory-byte": candidate / "rootfs/__keemu/installed-packages.json",
        "feed-byte": candidate / "rootfs/opt/etc/opkg.conf",
    }[corruption]
    if corruption == "missing-manifest":
        file.unlink()
    else:
        with file.open("ab") as stream:
            stream.write(b"tamper")
    with pytest.raises((InitError, OSError, ValueError)):
        _verify_cache(candidate, lock, native, lock_sha, REPO)
