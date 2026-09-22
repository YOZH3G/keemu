from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from keemu.profiles import ProfileError, load_profile

VALID_PROFILE = """schema_version: 1
id: generic-aarch64
revision: 1
kind: generic
entware_target: aarch64-3.10
cpu:
  arch: aarch64
  endian: little
  elf_class: 64
  qemu: qemu-aarch64
kernel:
  execution: host
  reported_release: null
filesystem:
  entware_root: /opt
ndm:
  mode: strict
  fixtures: []
network:
  logical_to_linux:
    ISP: wan0
    Bridge0: br0
"""


def test_loads_strict_generic_profile(tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(VALID_PROFILE, encoding="utf-8")

    profile = load_profile(path)

    assert profile.id == "generic-aarch64"
    assert profile.cpu.arch == "aarch64"
    assert profile.cpu.endian == "little"
    assert profile.network.logical_to_linux == {"ISP": "wan0", "Bridge0": "br0"}


def test_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(VALID_PROFILE + "id: duplicate\n", encoding="utf-8")

    with pytest.raises(ProfileError, match="duplicate YAML key: id"):
        load_profile(path)


def test_rejects_target_and_cpu_architecture_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(
        VALID_PROFILE.replace("arch: aarch64", "arch: mipsel"),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="entware target/cpu mismatch"):
        load_profile(path)
