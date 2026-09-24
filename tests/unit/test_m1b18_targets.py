"""Portable contracts and opt-in offline checks for frozen MIPS targets."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from keemu.profiles import load_profile
from scripts.build_m1b18_images import checked_elf
from scripts.verify_m1b18 import verify

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("target", "endian", "qemu"),
    [("mipsel", "little", "qemu-mipsel"), ("mips", "big", "qemu-mips")],
)
def test_generic_profiles_are_target_bound(target: str, endian: str, qemu: str) -> None:
    profile = load_profile(REPO / "profiles/generic" / f"generic-{target}.yaml")
    assert profile.entware_target == f"{target}-3.4"
    assert profile.cpu.arch == target
    assert profile.cpu.endian == endian
    assert profile.cpu.elf_class == 32
    assert profile.cpu.qemu == qemu


def test_mips_elf_rejects_wrong_endianness_machine_abi_and_isa(tmp_path: Path) -> None:
    binary = tmp_path / "test-elf"
    data = bytearray(52)
    data[:6] = b"\x7fELF\x01\x01"
    data[18:20] = (8).to_bytes(2, "little")
    data[36:40] = (0x70001005).to_bytes(4, "little")
    binary.write_bytes(data)
    with patch("scripts.build_m1b18_images.subprocess.run") as run:
        run.return_value.stdout = "ISA: MIPS32r2\nFP ABI: Soft float\n"
        assert checked_elf(binary, "mipsel-3.4")["abi"] == "o32"
        with pytest.raises(ValueError, match="endianness"):
            checked_elf(binary, "mips-3.4")
        data[18:20] = (62).to_bytes(2, "little")
        binary.write_bytes(data)
        with pytest.raises(ValueError, match="machine"):
            checked_elf(binary, "mipsel-3.4")
        data[18:20] = (8).to_bytes(2, "little")
        data[36:40] = (0x70002005).to_bytes(4, "little")
        binary.write_bytes(data)
        with pytest.raises(ValueError, match="ABI/ISA flags"):
            checked_elf(binary, "mipsel-3.4")
        data[36:40] = (0x70001005).to_bytes(4, "little")
        binary.write_bytes(data)
        run.return_value.stdout = "ISA: MIPS32r1\nFP ABI: Hard float\n"
        with pytest.raises(ValueError, match="ISA/FPU"):
            checked_elf(binary, "mipsel-3.4")


@pytest.mark.docker
@pytest.mark.skipif(
    os.environ.get("KEEMU_RUN_M1B18") != "1",
    reason="set KEEMU_RUN_M1B18=1 with pinned artifacts and Docker image IDs",
)
@pytest.mark.parametrize("target", ["mipsel-3.4", "mips-3.4"])
def test_locked_target_image_and_offline_inventory(target: str) -> None:
    result = verify(target)
    assert result["package_count"] == 20
    assert result["target_elf_count"] >= 31
    assert result["status"].startswith("PASS (offline")
