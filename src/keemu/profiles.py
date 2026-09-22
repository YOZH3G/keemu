from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProfileError(ValueError):
    """Raised when profile YAML is ambiguous or malformed."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ProfileError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CPUProfile(StrictModel):
    arch: Literal["aarch64", "mipsel", "mips"]
    endian: Literal["little", "big"]
    elf_class: Literal[32, 64]
    qemu: str = Field(pattern=r"^qemu-[a-z0-9_]+$")


class KernelProfile(StrictModel):
    execution: Literal["host"]
    reported_release: str | None


class FilesystemProfile(StrictModel):
    entware_root: Literal["/opt"]


class NDMProfile(StrictModel):
    mode: Literal["strict"]
    fixtures: list[str]


class NetworkProfile(StrictModel):
    logical_to_linux: dict[str, str]


class GenericProfile(StrictModel):
    schema_version: Literal[1]
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}[a-z0-9]$")
    revision: int = Field(ge=1)
    kind: Literal["generic"]
    entware_target: Literal["aarch64-3.10", "mipsel-3.4", "mips-3.4"]
    cpu: CPUProfile
    kernel: KernelProfile
    filesystem: FilesystemProfile
    ndm: NDMProfile
    network: NetworkProfile

    @model_validator(mode="after")
    def validate_target_cpu_pair(self) -> Self:
        expected = {
            "aarch64-3.10": ("aarch64", "little", 64, "qemu-aarch64"),
            "mipsel-3.4": ("mipsel", "little", 32, "qemu-mipsel"),
            "mips-3.4": ("mips", "big", 32, "qemu-mips"),
        }[self.entware_target]
        actual = (
            self.cpu.arch,
            self.cpu.endian,
            self.cpu.elf_class,
            self.cpu.qemu,
        )
        if actual != expected:
            raise ValueError(
                "entware target/cpu mismatch: "
                f"target={self.entware_target} expected={expected} actual={actual}"
            )
        return self


def load_profile(path: Path) -> GenericProfile:
    loader = _UniqueKeyLoader(path.read_text(encoding="utf-8"))
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    return GenericProfile.model_validate(data)
