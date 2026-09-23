"""Static inspector adversarial and real-feed regressions; no host extraction."""

from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import struct
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.profiles import load_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = load_profile(ROOT / "profiles/generic/generic-aarch64.yaml")


def archive(entries: list[tuple[str, bytes, int, str, bytes | None]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as tar:
        for name, content, mode, kind, link in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.type = kind.encode("ascii")
            if kind in "12":
                info.linkname = (link or b"").decode()
                info.size = 0
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def fixture(
    tmp_path: Path,
    *,
    data: list[tuple[str, bytes, int, str, bytes | None]] | None = None,
    control: bytes = (
        b"Package: hello\nVersion: 1.0\nArchitecture: aarch64-3.10\n"
        b"Depends: libc (>= 2.0) | libalt, libssp\n"
    ),
    wrapper: str = "tar",
    debian: bytes = b"2.0\n",
    postinst: bytes | None = None,
) -> Path:
    data = (
        data
        if data is not None
        else [("./opt/bin/hello", b"#!/bin/sh\nexit 0\n", 0o755, "0", None)]
    )
    control_entries = [("./control", control, 0o644, "0", None)]
    if postinst is not None:
        control_entries.append(("./postinst", postinst, 0o755, "0", None))
    members = [
        ("./debian-binary", debian, 0o644, "0", None),
        (
            "./control.tar.gz",
            gzip.compress(archive(control_entries)),
            0o644,
            "0",
            None,
        ),
        ("./data.tar.gz", gzip.compress(archive(data)), 0o644, "0", None),
    ]
    if wrapper == "tar":
        content = gzip.compress(archive(members))
    elif wrapper == "ar":
        content = b"!<arch>\n"
        for name, payload, _, _, _ in members:
            label = name.removeprefix("./") + "/"
            header = (
                f"{label:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n"
            ).encode()
            assert len(header) == 60
            content += header + payload + (b"\n" if len(payload) % 2 else b"")
    else:
        content = archive(members)
    file = tmp_path / "hello.ipk"
    file.write_bytes(content)
    return file


@pytest.mark.parametrize("wrapper", ["tar", "ar", "plain"])
def test_format_metadata_and_cli(tmp_path: Path, wrapper: str) -> None:
    package = fixture(tmp_path, wrapper=wrapper)
    result = inspect_ipk(package, profile=PROFILE)
    assert result.format == {"tar": "tar.gz", "ar": "ar", "plain": "tar"}[wrapper]
    assert result.status == "PASS"
    assert result.dependencies == (("libc (>= 2.0)", "libalt"), ("libssp",))
    assert result.entries[0].path == "opt/bin/hello"
    invocation = CliRunner().invoke(
        cli,
        [
            "inspect",
            str(package),
            "--profile",
            "generic-aarch64",
            "--profiles-dir",
            str(ROOT / "profiles/generic"),
        ],
    )
    assert invocation.exit_code == 0, invocation.output
    assert json.loads(invocation.output)["status"] == "PASS"
    assert list(tmp_path.iterdir()) == [package]


@pytest.mark.parametrize(
    "name,kind,link",
    [
        ("../escape", "0", None),
        ("/outside", "0", None),
        ("opt/../escape", "0", None),
        ("opt/link", "2", b"../../outside"),
        ("opt/link", "1", b"opt/missing"),
        ("opt/dev", "3", None),
    ],
)
def test_unsafe_members_rejected(
    tmp_path: Path, name: str, kind: str, link: bytes | None
) -> None:
    package = fixture(tmp_path, data=[(name, b"hello", 0o755, kind, link)])
    with pytest.raises(IPKError):
        inspect_ipk(package)
    assert list(tmp_path.iterdir()) == [package]


def test_symlink_parent_even_when_listed_later(tmp_path: Path) -> None:
    package = fixture(
        tmp_path,
        data=[
            ("opt/link/inside", b"x", 0o644, "0", None),
            ("opt/link", b"", 0o777, "2", b"/opt/safe"),
        ],
    )
    with pytest.raises(IPKError, match="non-directory"):
        inspect_ipk(package)


def test_link_cycle_and_duplicate_rejected(tmp_path: Path) -> None:
    package = fixture(
        tmp_path,
        data=[
            ("opt/a", b"", 0o777, "2", b"b"),
            ("opt/b", b"", 0o777, "2", b"a"),
        ],
    )
    with pytest.raises(IPKError, match="cycle"):
        inspect_ipk(package)
    package = fixture(tmp_path, data=[("opt/a", b"x", 0o644, "0", None)] * 2)
    with pytest.raises(IPKError, match="duplicate"):
        inspect_ipk(package)


@pytest.mark.parametrize(
    "control",
    [
        b"Package: hello\nVersion: 1\nArchitecture: aarch64-3.10\nDepends: lib (>=)\n",
        b"Package: hello\nPackage: evil\nVersion: 1\nArchitecture: all\n",
        b"Package: hello\nArchitecture: all\n",
    ],
)
def test_invalid_metadata(tmp_path: Path, control: bytes) -> None:
    with pytest.raises(IPKError):
        inspect_ipk(fixture(tmp_path, control=control))


def test_architecture_permissions_and_scripts(tmp_path: Path) -> None:
    package = fixture(
        tmp_path,
        control=b"Package: hello\nVersion: 1\nArchitecture: mips-3.4\n",
        data=[
            ("opt/bin/hello", b"#!/missing/interpreter\n", 0o777, "0", None),
        ],
    )
    result = inspect_ipk(package, profile=PROFILE)
    assert result.status == "FAIL"
    assert {x.code for x in result.findings} >= {
        "architecture",
        "unsafe-mode",
        "shebang-interpreter",
    }


def test_bounded_and_corrupt_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = fixture(tmp_path)
    with pytest.raises(IPKError, match="debian-binary"):
        inspect_ipk(fixture(tmp_path, debian=b"bogus"))
    package = fixture(tmp_path)
    monkeypatch.setattr("keemu.ipk_inspect.MAX_ENTRIES", 2)
    with pytest.raises(IPKError, match="too many"):
        inspect_ipk(package)
    monkeypatch.undo()
    monkeypatch.setattr("keemu.ipk_inspect.MAX_EXPANDED", 1000)
    with pytest.raises(IPKError, match="limit"):
        inspect_ipk(package)
    monkeypatch.undo()
    package.write_bytes(b"!<arch>\n" + b"bad")
    with pytest.raises(IPKError):
        inspect_ipk(package)
    package.write_bytes(gzip.compress(b"x" * 100))
    with pytest.raises(IPKError):
        inspect_ipk(package)
    package.write_bytes(b"garbage")
    with pytest.raises(IPKError):
        inspect_ipk(package)
    symlink = tmp_path / "link.ipk"
    symlink.symlink_to(package)
    with pytest.raises(OSError):
        inspect_ipk(symlink)


@pytest.mark.parametrize(
    "suffix,compress", [("xz", lzma.compress), ("bz2", bz2.compress)]
)
def test_nested_compression_detected(
    tmp_path: Path, suffix: str, compress: object
) -> None:
    control = archive(
        [
            (
                "control",
                b"Package: hello\nVersion: 1\nArchitecture: all\n",
                0o644,
                "0",
                None,
            )
        ]
    )
    data = archive([("opt/readme", b"text", 0o644, "0", None)])
    outer = archive(
        [
            ("debian-binary", b"2.0\n", 0o644, "0", None),
            (f"control.tar.{suffix}", compress(control), 0o644, "0", None),
            (f"data.tar.{suffix}", compress(data), 0o644, "0", None),
        ]
    )
    package = tmp_path / "compressed.ipk"
    package.write_bytes(outer)
    assert inspect_ipk(package).status == "PASS"


def test_truncated_compression_and_trailing_member(tmp_path: Path) -> None:
    package = fixture(tmp_path)
    package.write_bytes(package.read_bytes()[:-4])
    with pytest.raises(IPKError, match="truncated compressed"):
        inspect_ipk(package)
    package = fixture(tmp_path)
    package.write_bytes(package.read_bytes() + b"trailing")
    with pytest.raises(IPKError, match="trailing compressed"):
        inspect_ipk(package)


def synthetic_elf(runpath: str | None = None) -> bytes:
    """Small ELF64 AArch64 with a real PT_INTERP and DT_NEEDED string table."""
    binary = bytearray(1024)
    binary[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH", binary, 16, 2, 183, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0
    )
    struct.pack_into("<IIQQQQQQ", binary, 64, 1, 5, 0, 0x400000, 0, 1024, 1024, 4096)
    loader = b"/opt/lib/ld.so\x00"
    binary[232 : 232 + len(loader)] = loader
    struct.pack_into(
        "<IIQQQQQQ",
        binary,
        120,
        3,
        4,
        232,
        0x400000 + 232,
        0,
        len(loader),
        len(loader),
        1,
    )
    entries = [(1, 1), (5, 0x400000 + 352)]
    strings = b"\x00libfoo.so\x00"
    if runpath is not None:
        entries.append((29, len(strings)))
        strings += runpath.encode() + b"\x00"
    entries.extend([(10, len(strings)), (0, 0)])
    segment_size = 16 * len(entries)
    struct.pack_into(
        "<IIQQQQQQ",
        binary,
        176,
        2,
        4,
        256,
        0x400000 + 256,
        0,
        segment_size,
        segment_size,
        8,
    )
    binary[352 : 352 + len(strings)] = strings
    for index, (tag, value) in enumerate(entries):
        struct.pack_into("<qQ", binary, 256 + 16 * index, tag, value)
    return bytes(binary)


def test_elf_dependency_interpreter_and_postinst_defer(tmp_path: Path) -> None:
    payload = [("opt/bin/app", synthetic_elf(), 0o755, "0", None)]
    package = fixture(tmp_path, data=payload)
    no_rootfs = inspect_ipk(package, profile=PROFILE)
    assert no_rootfs.status == "BLOCKED"
    assert no_rootfs.elves[0].interpreter == "/opt/lib/ld.so"
    assert no_rootfs.elves[0].needed == ("libfoo.so",)
    rootfs = tmp_path / "rootfs"
    (rootfs / "opt/lib").mkdir(parents=True)
    absent = inspect_ipk(package, profile=PROFILE, rootfs=rootfs)
    assert absent.status == "FAIL"
    assert {f.code for f in absent.findings} >= {
        "missing-interpreter",
        "missing-dependency",
    }
    (rootfs / "opt/lib/ld.so").write_bytes(b"loader")
    (rootfs / "opt/lib/libfoo.so").write_bytes(b"library")
    assert inspect_ipk(package, profile=PROFILE, rootfs=rootfs).status == "PASS"
    (rootfs / "opt/lib/ld.so").unlink()
    (rootfs / "opt/lib/libfoo.so").unlink()
    package = fixture(tmp_path, data=payload, postinst=b"#!/bin/sh\n")
    assert inspect_ipk(package, profile=PROFILE, rootfs=rootfs).status == "BLOCKED"


def test_elf_runpath_and_unknown_loader_variable(tmp_path: Path) -> None:
    package = fixture(
        tmp_path,
        data=[("opt/bin/app", synthetic_elf("$ORIGIN/../libextra"), 0o755, "0", None)],
    )
    rootfs = tmp_path / "rootfs"
    (rootfs / "opt/lib").mkdir(parents=True)
    (rootfs / "opt/libextra").mkdir()
    (rootfs / "opt/lib/ld.so").write_bytes(b"loader")
    (rootfs / "opt/libextra/libfoo.so").write_bytes(b"library")
    assert inspect_ipk(package, profile=PROFILE, rootfs=rootfs).status == "PASS"
    package = fixture(
        tmp_path,
        data=[("opt/bin/app", synthetic_elf("$LIB/unknown"), 0o755, "0", None)],
    )
    assert inspect_ipk(package, profile=PROFILE, rootfs=rootfs).status == "BLOCKED"


def test_portable_elf_arch_abi_and_bounds(tmp_path: Path) -> None:
    wrong = bytearray(synthetic_elf())
    struct.pack_into("<H", wrong, 18, 62)
    package = fixture(tmp_path, data=[("opt/bin/app", bytes(wrong), 0o755, "0", None)])
    assert "elf-architecture" in {
        f.code for f in inspect_ipk(package, profile=PROFILE).findings
    }
    wrong = bytearray(synthetic_elf())
    wrong[7] = 255
    package = fixture(tmp_path, data=[("opt/bin/app", bytes(wrong), 0o755, "0", None)])
    assert "elf-abi" in {f.code for f in inspect_ipk(package, profile=PROFILE).findings}
    corrupt = bytearray(synthetic_elf())
    struct.pack_into("<Q", corrupt, 64 + 56 + 32, 4096)
    package = fixture(
        tmp_path, data=[("opt/bin/app", bytes(corrupt), 0o755, "0", None)]
    )
    with pytest.raises(IPKError, match="ELF segment"):
        inspect_ipk(package, profile=PROFILE)


def test_bad_shebang_mode_and_hardcoded_path(tmp_path: Path) -> None:
    package = fixture(
        tmp_path,
        data=[
            ("opt/bin/app", b"#!relative/sh\n", 0o777, "0", None),
        ],
    )
    assert {f.code for f in inspect_ipk(package).findings} >= {"shebang", "unsafe-mode"}
    package = fixture(
        tmp_path,
        data=[
            ("opt/etc/example", b"#!/bin/sh\ncat /etc/host.conf\n", 0o644, "0", None),
        ],
    )
    assert {f.code for f in inspect_ipk(package).findings} >= {
        "script-permission",
        "hardcoded-path",
    }


def test_dangling_symlink_with_complete_rootfs(tmp_path: Path) -> None:
    package = fixture(
        tmp_path, data=[("opt/lib/missing.so", b"", 0o777, "2", b"real.so")]
    )
    assert inspect_ipk(package).status == "WARN"
    rootfs = tmp_path / "rootfs"
    (rootfs / "opt/lib").mkdir(parents=True)
    result = inspect_ipk(package, rootfs=rootfs)
    assert result.status == "FAIL"
    assert any(f.code == "unresolved-link" for f in result.findings)
    package = fixture(
        tmp_path,
        data=[("opt/lib/missing.so", b"", 0o777, "2", b"real.so")],
        postinst=b"#!/bin/sh\n",
    )
    assert inspect_ipk(package, rootfs=rootfs).status == "BLOCKED"


def test_real_locked_aarch64_feed_if_cached() -> None:
    cache = ROOT / ".runtime/p0/aarch64-k3.10/packages"
    if not cache.is_dir():
        pytest.skip("locked P0 cache absent")
    packages = sorted(cache.glob("*.ipk"))
    if not packages:
        pytest.skip("locked P0 packages absent")
    for package in packages:
        result = inspect_ipk(package, profile=PROFILE)
        assert result.format == "tar.gz"
        assert result.sha256
        assert result.status in {"PASS", "WARN", "BLOCKED"}, package.name


def test_elf_from_locked_rootfs_if_cached(tmp_path: Path) -> None:
    binary = ROOT / ".runtime/p0/aarch64-k3.10/rootfs/opt/bin/busybox"
    if not binary.is_file():
        pytest.skip("locked P0 rootfs absent")
    package = fixture(
        tmp_path, data=[("opt/bin/demo", binary.read_bytes(), 0o755, "0", None)]
    )
    result = inspect_ipk(package, profile=PROFILE)
    assert result.elves[0].machine == 183
    assert result.elves[0].interpreter == "/opt/lib/ld-linux-aarch64.so.1"
    assert result.elves[0].needed
    assert result.status == "BLOCKED"
    # Header tampering changes machine; the structural check still runs.
    wrong = bytearray(binary.read_bytes())
    struct.pack_into("<H", wrong, 18, 62)
    package = fixture(tmp_path, data=[("opt/bin/demo", bytes(wrong), 0o755, "0", None)])
    assert "elf-architecture" in [
        f.code for f in inspect_ipk(package, profile=PROFILE).findings
    ]
