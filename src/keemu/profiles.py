from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProfileError(ValueError):
    """Raised when profile YAML is ambiguous or malformed."""


MAX_YAML_BYTES = 1024 * 1024


class _UniqueKeyLoader(yaml.SafeLoader):
    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node | None:
        if self.check_event(yaml.AliasEvent):
            raise ProfileError("YAML aliases are not allowed")
        return super().compose_node(parent, index)


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


def load_yaml_unique_bytes(data: bytes) -> object:
    """Parse one bounded YAML document without aliases or duplicate keys."""
    if len(data) > MAX_YAML_BYTES:
        raise ProfileError("YAML input exceeds 1 MiB")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ProfileError("YAML input is not UTF-8") from exc
    loader = _UniqueKeyLoader(text)
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    return data


def load_yaml_unique(path: Path) -> object:
    """Read a single YAML document without aliases, duplicate keys or custom tags."""
    return load_yaml_unique_bytes(_read_yaml(path))


def load_profile_bytes(data: bytes) -> GenericProfile:
    return GenericProfile.model_validate(load_yaml_unique_bytes(data))


def load_profile(path: Path) -> GenericProfile:
    return load_profile_bytes(_read_yaml(path))


def _read_yaml(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_YAML_BYTES + 1)
    if len(data) > MAX_YAML_BYTES:
        raise ProfileError("YAML input exceeds 1 MiB")
    return data
