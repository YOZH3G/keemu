"""Strict versioned production lock and persistent-environment input contracts.

P0 diagnostic locks remain historical formats; no implicit migration or rewriting.
The runtime must verify actual files/digests and Docker ownership separately.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from keemu.input_paths import HostInputPath, SafeName, UnsafePath, resolve_input_path
from keemu.scenarios import InputModel, Scenario, Sha256


class LockError(ValueError):
    """Malformed JSON lock or unsupported version."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise LockError(f"duplicate JSON key: {name}")
        result[name] = value
    return result


def _reject_constant(value: str) -> None:
    raise LockError(f"invalid JSON constant: {value}")


def read_json_unique(path: Path) -> object:
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise LockError("JSON input exceeds 2 MiB")
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LockError(f"invalid JSON input: {path}") from exc


class SourceLock(InputModel):
    id: SafeName
    kind: Literal["ipk", "pinned-bundle"]
    path: HostInputPath
    sha256: Sha256
    origin: str = Field(min_length=1, max_length=2048)
    release: str = Field(min_length=1, max_length=256)
    architecture: Literal["aarch64", "mips", "mipsel", "all"]

    @field_validator("release")
    @classmethod
    def exact_release(cls, value: str) -> str:
        if value.strip() != value or value.lower() in {
            "latest",
            "head",
            "main",
            "master",
            "unknown",
            "unlocked",
        }:
            raise ValueError("source release must be an exact version or commit")
        return value


class ScenarioLock(InputModel):
    schema_version: Literal[1]
    kind: Literal["scenario-lock"]
    scenario_id: SafeName
    scenario_sha256: Sha256
    profile_id: SafeName
    profile_revision: int = Field(ge=1)
    profile_sha256: Sha256
    entware_target: Literal["aarch64-3.10", "mipsel-3.4", "mips-3.4"]
    oci_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    qemu_version: str = Field(min_length=1, max_length=128)
    feed_lock_sha256: Sha256
    sources: tuple[SourceLock, ...] = Field(min_length=1, max_length=256, strict=False)

    @model_validator(mode="after")
    def validate_sources(self) -> Self:
        ids = [s.id for s in self.sources]
        paths = [s.path for s in self.sources]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("duplicate source id or path")
        arch = self.entware_target.split("-", 1)[0]
        if any(s.architecture not in {arch, "all"} for s in self.sources):
            raise ValueError("lock source architecture does not match target")
        return self


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_scenario_lock(
    path: Path,
    *,
    project_root: Path,
    scenario: Scenario | None = None,
    scenario_path: Path | None = None,
) -> ScenarioLock:
    source = resolve_input_path(
        path.name, scenario_dir=path.parent, project_root=project_root
    )
    lock = ScenarioLock.model_validate(read_json_unique(source))
    paths: dict[str, Path] = {}
    for item in lock.sources:
        resolved = resolve_input_path(
            item.path, scenario_dir=source.parent, project_root=project_root
        )
        if resolved in paths.values():
            raise LockError("duplicate resolved source path")
        paths[item.id] = resolved
        if _file_digest(resolved) != item.sha256:
            raise LockError(f"source hash mismatch: {item.id}")
    if scenario is not None:
        if scenario_path is None:
            raise LockError("scenario path required to bind lock")
        scenario_source = resolve_input_path(
            scenario_path.name,
            scenario_dir=scenario_path.parent,
            project_root=project_root,
        )
        if _file_digest(scenario_source) != lock.scenario_sha256:
            raise LockError("scenario hash mismatch")
        if lock.scenario_id != scenario.id or lock.profile_id != scenario.profile:
            raise LockError("lock scenario or profile identity mismatch")
        install = scenario.install
        installed_path = resolve_input_path(
            install.path,
            scenario_dir=scenario_source.parent,
            project_root=project_root,
        )
        source_item = next(
            (item for item in lock.sources if paths[item.id] == installed_path), None
        )
        if source_item is None:
            raise LockError("installed artifact absent from lock")
        if (install.kind == "ipk" and source_item.kind != "ipk") or (
            install.kind == "pinned-installer"
            and (
                source_item.kind != "pinned-bundle"
                or source_item.id != install.source_lock
            )
        ):
            raise LockError("install kind or source reference mismatch")
    return lock


class ResourceIdentity(InputModel):
    container_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_label: Literal["keemu"]
    run_id_label: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class PersistentEnvironment(InputModel):
    schema_version: Literal[1]
    kind: Literal["persistent-environment"]
    name: SafeName
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    state: Literal[
        "creating",
        "installing",
        "stopped",
        "starting",
        "running",
        "stopping",
        "failed",
        "destroyed",
    ]
    scenario_id: SafeName
    scenario_sha256: Sha256
    profile_id: SafeName
    profile_sha256: Sha256
    lock_sha256: Sha256
    oci_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource: ResourceIdentity | None

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.resource is not None and self.resource.run_id_label != self.run_id:
            raise ValueError("resource run ID differs from persistent environment")
        if (
            self.state in {"running", "starting", "stopping", "stopped"}
            and self.resource is None
        ):
            raise ValueError("existing environment needs a container identity")
        return self


def load_persistent_environment(
    path: Path, *, state_root: Path
) -> PersistentEnvironment:
    """Read only a project-owned registry entry; mutation is a later subtask."""
    try:
        source = resolve_input_path(
            path.name, scenario_dir=path.parent, project_root=state_root
        )
    except UnsafePath as exc:
        raise LockError("unsafe persistent-environment path") from exc
    return PersistentEnvironment.model_validate(read_json_unique(source))
