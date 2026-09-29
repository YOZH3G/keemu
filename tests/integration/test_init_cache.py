"""Opt-in real Docker/binfmt and copied-cache corruption checks for m1a-11."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from keemu.init_cache import (
    InitError,
    _inputs,
    _preflight_mips_binfmt,
    _smoke,
    _verify_cache,
    init_locked,
)

REPO = Path(__file__).resolve().parents[2]
PIN = json.loads((REPO / "locks/m1a-init-aarch64.json").read_text())
MIPS_PIN = json.loads((REPO / "locks/m1e-init-mips.json").read_text())
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


def test_mips_offline_repeat_never_fetches() -> None:
    with patch("urllib.request.urlopen", side_effect=AssertionError("offline fetched")):
        cached = init_locked(REPO, target="mips-3.4", offline=True)
    assert cached["oci_digest"] == MIPS_PIN["oci_digest"]
    assert cached["tree_sha256"] == MIPS_PIN["rootfs_tree_sha256"]
    assert cached["package_count"] == MIPS_PIN["package_count"]


def test_mips_locked_build_repeat_and_target_smoke(tmp_path: Path) -> None:
    try:
        _preflight_mips_binfmt(REPO)
    except InitError:
        pytest.skip("exact host qemu-mips binfmt readback unavailable")
    cached = init_locked(REPO, target="mips-3.4", offline=True)
    lock, native, digest = _inputs(REPO, target="mips-3.4")
    assert _smoke(cached["oci_digest"], lock) == MIPS_PIN["smoke"]
    isolated = tmp_path / "independent"
    rebuilt = init_locked(REPO, target="mips-3.4", cache_root=isolated)
    assert rebuilt["cache_state"] == "built"
    assert rebuilt["oci_digest"] == cached["oci_digest"]
    assert rebuilt["saved_archive_sha256"] == cached["saved_archive_sha256"]
    with patch("urllib.request.urlopen", side_effect=AssertionError("offline fetched")):
        repeated = init_locked(
            REPO, target="mips-3.4", cache_root=isolated, offline=True
        )
    assert repeated["cache_state"] == "verified"
    assert _verify_cache(isolated / MIPS_PIN["cache_key"], lock, native, digest, REPO)


def test_mips_unreadable_handler_refuses_build_before_docker(tmp_path: Path) -> None:
    with (
        patch(
            "keemu.init_cache._observe_host_mips_binfmt",
            side_effect=InitError("current host qemu-mips binfmt readback unavailable"),
        ),
        patch("keemu.init_cache._run", side_effect=AssertionError("Docker called")),
    ):
        with pytest.raises(InitError, match="binfmt readback unavailable"):
            init_locked(REPO, target="mips-3.4", cache_root=tmp_path)
    assert not (tmp_path / MIPS_PIN["cache_key"]).exists()


def test_mips_existing_cache_is_never_overwritten(tmp_path: Path) -> None:
    cache = tmp_path / MIPS_PIN["cache_key"]
    cache.mkdir()
    marker = cache / "foreign"
    marker.write_bytes(b"preserve")
    with pytest.raises(InitError, match="incomplete cache"):
        init_locked(REPO, target="mips-3.4", cache_root=tmp_path)
    assert marker.read_bytes() == b"preserve"


@pytest.mark.parametrize("corruption", ["rootfs", "archive", "inventory", "feed"])
def test_mips_copied_corruption_refused(tmp_path: Path, corruption: str) -> None:
    lock, native, digest = _inputs(REPO, target="mips-3.4")
    source = REPO / ".runtime/init-cache" / MIPS_PIN["cache_key"]
    cache = tmp_path / MIPS_PIN["cache_key"]
    shutil.copytree(source, cache, symlinks=True)
    file = {
        "rootfs": cache / "rootfs/opt/lib/opkg/status",
        "archive": cache / "image.tar",
        "inventory": cache / "rootfs/__keemu/installed-packages.json",
        "feed": cache / "rootfs/opt/etc/opkg.conf",
    }[corruption]
    with file.open("ab") as stream:
        stream.write(b"corrupt")
    with pytest.raises((InitError, OSError, ValueError)):
        _verify_cache(cache, lock, native, digest, REPO)
