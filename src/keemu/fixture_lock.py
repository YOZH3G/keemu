from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FixtureLockError(ValueError):
    """Raised when a fixture provenance lock is invalid or no longer matches files."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checked_relative_path(value: object, *, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise FixtureLockError(f"{field} must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise FixtureLockError(f"unsafe {field}: {value!r}")
    return path


def _verify_file(root: Path, entry: Mapping[str, object], *, field: str) -> None:
    path = _checked_relative_path(entry.get("path"), field=field)
    expected = entry.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise FixtureLockError(f"invalid sha256: {path.as_posix()}")
    candidate = root / path
    if not candidate.is_file():
        raise FixtureLockError(f"missing artifact: {path.as_posix()}")
    if _sha256_file(candidate) != expected:
        raise FixtureLockError(f"hash mismatch: {path.as_posix()}")


def _expect_string_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise FixtureLockError(f"{field} must be a list of non-empty strings")
    return value


def verify_fixture_lock(
    lock_path: Path, root: Path, *, verify_external: bool = False
) -> list[str]:
    """Verify project-owned fixture sources, recipes, and external provenance hashes.

    The lock stores paths relative to ``root``. It never downloads artifacts; callers
    must stage external toolchain inputs separately. Set ``verify_external`` to
    verify those staged inputs as well; default unit validation remains portable.
    """
    try:
        data: Any = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixtureLockError(f"unable to read fixture lock: {lock_path}") from exc
    if not isinstance(data, dict):
        raise FixtureLockError("fixture lock must be an object")
    if data.get("schema_version") != 1 or data.get("kind") != "keemu-fixture-lock":
        raise FixtureLockError("unsupported fixture lock")
    if data.get("target") != "aarch64-3.10":
        raise FixtureLockError("unsupported fixture target")

    architecture = data.get("architecture")
    if not isinstance(architecture, Mapping) or architecture != {
        "elf_machine": "AArch64",
        "elf_class": 64,
        "endian": "little",
    }:
        raise FixtureLockError("fixture architecture metadata is inconsistent")

    toolchain = data.get("toolchain")
    if (
        not isinstance(toolchain, Mapping)
        or toolchain.get("kind") != "debian-cross-gcc"
    ):
        raise FixtureLockError("unsupported fixture toolchain")
    artifacts = toolchain.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise FixtureLockError("toolchain artifacts must be a non-empty list")
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            raise FixtureLockError("toolchain artifact must be an object")
        _checked_relative_path(artifact.get("path"), field="toolchain artifact path")
        expected = artifact.get("sha256")
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise FixtureLockError("invalid toolchain artifact sha256")
        if verify_external:
            _verify_file(root, artifact, field="toolchain artifact path")

    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise FixtureLockError("fixtures must be a non-empty list")
    verified: list[str] = []
    for fixture in fixtures:
        if not isinstance(fixture, Mapping):
            raise FixtureLockError("fixture must be an object")
        fixture_id = fixture.get("id")
        if not isinstance(fixture_id, str) or not re.fullmatch(
            r"[a-z0-9-]+", fixture_id
        ):
            raise FixtureLockError("fixture id is invalid")
        sources = fixture.get("sources")
        if not isinstance(sources, Sequence) or not sources:
            raise FixtureLockError(f"fixture {fixture_id} has no sources")
        for source in sources:
            if not isinstance(source, Mapping):
                raise FixtureLockError(f"fixture {fixture_id} source must be an object")
            _verify_file(root, source, field="source path")
        recipe = _checked_relative_path(fixture.get("recipe"), field="recipe")
        recipe_sha256 = fixture.get("recipe_sha256")
        if not isinstance(recipe_sha256, str) or not _SHA256.fullmatch(recipe_sha256):
            raise FixtureLockError(f"invalid recipe sha256: {fixture_id}")
        recipe_path = root / recipe
        if not recipe_path.is_file():
            raise FixtureLockError(f"missing recipe: {recipe.as_posix()}")
        if _sha256_file(recipe_path) != recipe_sha256:
            raise FixtureLockError(f"recipe hash mismatch: {recipe.as_posix()}")
        recipe_inputs = fixture.get("recipe_inputs")
        if not isinstance(recipe_inputs, list) or not recipe_inputs:
            raise FixtureLockError(f"fixture {fixture_id} has no recipe inputs")
        for recipe_input in recipe_inputs:
            if not isinstance(recipe_input, Mapping):
                raise FixtureLockError(
                    f"fixture {fixture_id} recipe input must be an object"
                )
            _verify_file(root, recipe_input, field="recipe input path")
        _expect_string_list(
            fixture.get("runtime_dependencies"), field="runtime_dependencies"
        )
        _expect_string_list(
            fixture.get("kernel_requirements"), field="kernel_requirements"
        )
        verified.append(fixture_id)
    if len(verified) != len(set(verified)):
        raise FixtureLockError("fixture ids must be unique")
    return verified
