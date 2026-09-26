"""D01 host-only secure script input tests; never execute fixture scripts."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from keemu.script_input import (
    MAX_SCRIPT_BYTES,
    ScriptInput,
    ScriptInputChanged,
    ScriptInputError,
)


def test_valid_script_pins_exact_bytes_and_source(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "test.sh"
    source.parent.mkdir()
    content = b"#!/bin/sh\necho pinned\n"
    source.write_bytes(content)
    script = ScriptInput.validate("./scripts/test.sh", project_root=tmp_path)
    assert script.source_path == source
    assert script.sha256 == hashlib.sha256(content).hexdigest()
    assert script.size == len(content)
    assert script.identity.inode == source.stat().st_ino
    assert script.recheck_for_staging() == content
    assert content.decode() not in repr(script)
    assert ScriptInput.validate(source, project_root=tmp_path).sha256 == script.sha256


def test_inner_dotdot_requires_real_no_follow_component(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "test.sh").write_bytes(b"ok")
    assert (
        ScriptInput.validate(
            "real/../test.sh", project_root=tmp_path
        ).recheck_for_staging()
        == b"ok"
    )
    (tmp_path / "link").symlink_to("real", target_is_directory=True)
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("link/../test.sh", project_root=tmp_path)


@pytest.mark.parametrize(
    "path",
    [
        "../outside.sh",
        "a/../../outside.sh",
        "./../outside.sh",
        "/etc/passwd",
        "file.txt",
        "sub//test.sh",
        "test.sh/",
        "test.sh\x00",
        "test.sh\n",
        "test.sh\\bad",
    ],
)
def test_rejects_traversal_and_invalid_path(tmp_path: Path, path: str) -> None:
    with pytest.raises(ScriptInputError):
        ScriptInput.validate(path, project_root=tmp_path)


def test_rejects_symlink_final_parent_root_and_dangling(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "test.sh").write_bytes(b"ok")
    (tmp_path / "alias.sh").symlink_to("real/test.sh")
    (tmp_path / "dangling.sh").symlink_to("missing.sh")
    (tmp_path / "alias").symlink_to("real", target_is_directory=True)
    for path in ("alias.sh", "dangling.sh", "alias/test.sh"):
        with pytest.raises(ScriptInputError):
            ScriptInput.validate(path, project_root=tmp_path)
    linked_root = tmp_path.parent / (tmp_path.name + "-root-link")
    linked_root.symlink_to(tmp_path, target_is_directory=True)
    try:
        with pytest.raises(ScriptInputError):
            ScriptInput.validate("real/test.sh", project_root=linked_root)
    finally:
        linked_root.unlink()


def test_rejects_fifo_directory_hardlink_and_device(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.sh")
    (tmp_path / "directory.sh").mkdir()
    (tmp_path / "real.sh").write_bytes(b"regular")
    os.link(tmp_path / "real.sh", tmp_path / "hard.sh")
    for path in ("pipe.sh", "directory.sh", "hard.sh", "real.sh"):
        with pytest.raises(ScriptInputError):
            ScriptInput.validate(path, project_root=tmp_path)
    # mknod may be denied in unprivileged test environments.
    try:
        os.mknod(tmp_path / "device.sh", 0o600 | 0o20000, os.makedev(1, 3))
    except PermissionError:
        pass
    else:
        with pytest.raises(ScriptInputError):
            ScriptInput.validate("device.sh", project_root=tmp_path)


def test_size_bound_and_unbounded_override_refused(tmp_path: Path) -> None:
    (tmp_path / "limit.sh").write_bytes(b"a" * 8)
    script = ScriptInput.validate("limit.sh", project_root=tmp_path, max_bytes=8)
    assert script.size == 8
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("limit.sh", project_root=tmp_path, max_bytes=7)
    with pytest.raises(ScriptInputError):
        ScriptInput.validate(
            "limit.sh", project_root=tmp_path, max_bytes=MAX_SCRIPT_BYTES + 1
        )
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("limit.sh", project_root=tmp_path, max_bytes=True)
    (tmp_path / "oversized.sh").write_bytes(b"x" * (MAX_SCRIPT_BYTES + 1))
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("oversized.sh", project_root=tmp_path)


@pytest.mark.parametrize("mutation", ["bytes", "inode", "mode", "metadata", "link"])
def test_recheck_detects_replacement_and_metadata(
    tmp_path: Path, mutation: str
) -> None:
    source = tmp_path / "input.sh"
    original = b"echo initial\n"
    source.write_bytes(original)
    script = ScriptInput.validate("input.sh", project_root=tmp_path)
    if mutation == "bytes":
        source.write_bytes(b"echo updated\n")
    elif mutation == "inode":
        (tmp_path / "replacement.sh").write_bytes(original)
        os.replace(tmp_path / "replacement.sh", source)
    elif mutation == "mode":
        source.chmod(0o600)
    elif mutation == "metadata":
        timestamps = (source.stat().st_atime_ns, source.stat().st_mtime_ns + 1)
        os.utime(source, ns=timestamps)
    else:
        os.link(source, tmp_path / "hard.sh")
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()


def test_recheck_detects_path_and_parent_swap(tmp_path: Path) -> None:
    parent = tmp_path / "dir"
    parent.mkdir()
    source = parent / "input.sh"
    source.write_bytes(b"original")
    script = ScriptInput.validate("dir/input.sh", project_root=tmp_path)
    parent.rename(tmp_path / "moved")
    (tmp_path / "dir").symlink_to("moved", target_is_directory=True)
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()
    (tmp_path / "dir").unlink()
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir/input.sh").write_bytes(b"original")
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()


def test_mutation_during_read_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.sh"
    source.write_bytes(b"a" * 200)
    real_read = os.read
    called = False

    def changing_read(fd: int, size: int) -> bytes:
        nonlocal called
        data = real_read(fd, size)
        if not called:
            called = True
            source.write_bytes(b"b" * 200)
        return data

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("input.sh", project_root=tmp_path)
    assert called


def test_mutation_between_two_path_reads_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keemu.script_input as module

    source = tmp_path / "input.sh"
    source.write_bytes(b"initial")
    real_read_once = module._read_once
    called = False

    def replacing_read(*args):
        nonlocal called
        result = real_read_once(*args)
        if not called:
            called = True
            replacement = tmp_path / "other.sh"
            replacement.write_bytes(b"initial")
            os.replace(replacement, source)
        return result

    monkeypatch.setattr(module, "_read_once", replacing_read)
    with pytest.raises(ScriptInputError):
        ScriptInput.validate("input.sh", project_root=tmp_path)
    assert called


def test_staging_returns_frozen_bytes_not_live_path(tmp_path: Path) -> None:
    source = tmp_path / "input.sh"
    source.write_bytes(b"original")
    script = ScriptInput.validate("input.sh", project_root=tmp_path)
    payload = script.recheck_for_staging()
    source.write_bytes(b"changed!")
    assert payload == b"original"
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()


def test_stage_detects_mutation_during_its_own_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import keemu.script_input as module

    source = tmp_path / "input.sh"
    source.write_bytes(b"original")
    script = ScriptInput.validate("input.sh", project_root=tmp_path)
    real_read_once = module._read_once
    called = False

    def replacing_read(*args):
        nonlocal called
        result = real_read_once(*args)
        if not called:
            called = True
            source.write_bytes(b"different")
        return result

    monkeypatch.setattr(module, "_read_once", replacing_read)
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()
    assert called


def test_parent_metadata_change_is_refused(tmp_path: Path) -> None:
    parent = tmp_path / "dir"
    parent.mkdir()
    (parent / "input.sh").write_bytes(b"original")
    script = ScriptInput.validate("dir/input.sh", project_root=tmp_path)
    parent.chmod(0o700)
    with pytest.raises(ScriptInputChanged):
        script.recheck_for_staging()


@pytest.mark.parametrize(
    ("name", "digest"),
    [
        (
            "success.sh",
            "65d5b25df7afed318a7e6e45f3c44999567308d0e80199782c0e54d8ff8b09aa",
        ),
        (
            "exit-7.sh",
            "f51458d097634e46983303c0117d810bc57666cad739424da9357f1d1f99e133",
        ),
        (
            "argv.sh",
            "71cbbf6d031f751390b3cba488a148dc0d1f4ccd2834195b22046c33232b8009",
        ),
        (
            "filesystem.sh",
            "91c56ac2e28a44ee4c6d4ebc61beec149df2efad6bfed510dd4a106733c09174",
        ),
        (
            "streams.sh",
            "227e3ad22a8477b5d7040d6d183dbc1caff062fc545157affd775a7468e7e752",
        ),
        (
            "timeout-child.sh",
            "e188c137e2d4a1730ca6cf7bbaf2bf00076fc767adb1630687521515108d1309",
        ),
    ],
)
def test_frozen_fixture_identity_without_host_execution(name: str, digest: str) -> None:
    root = Path(__file__).resolve().parents[2]
    source = f"fixtures/scripts/mvp1d/{name}"
    script = ScriptInput.validate(source, project_root=root)
    assert script.sha256 == digest
    assert hashlib.sha256(script.recheck_for_staging()).hexdigest() == digest
