from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote


class PackageIndexError(ValueError):
    """Raised when an Entware package index is incomplete or inconsistent."""


class ArtifactIntegrityError(ValueError):
    """Raised when a locked artifact is missing, unsafe, or corrupt."""


@dataclass(frozen=True, slots=True)
class PackageRecord:
    name: str
    version: str
    architecture: str
    filename: str
    sha256: str
    depends: tuple[str, ...] = ()


def parse_package_index(content: bytes | str) -> dict[str, PackageRecord]:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    packages: dict[str, PackageRecord] = {}
    for paragraph in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in paragraph.splitlines():
            if line[:1].isspace() and current is not None:
                fields[current] += " " + line.strip()
                continue
            if ": " not in line:
                continue
            current, value = line.split(": ", 1)
            fields[current] = value
        if "Package" not in fields:
            continue
        required = ("Version", "Architecture", "Filename", "SHA256sum")
        missing = [field for field in required if not fields.get(field)]
        if missing:
            raise PackageIndexError(
                f"package {fields['Package']!r} missing fields: {', '.join(missing)}"
            )
        digest = fields["SHA256sum"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PackageIndexError(
                f"package {fields['Package']!r} has invalid SHA256sum"
            )
        dependencies = tuple(
            dependency.strip()
            for dependency in fields.get("Depends", "").split(",")
            if dependency.strip()
        )
        record = PackageRecord(
            name=fields["Package"],
            version=fields["Version"],
            architecture=fields["Architecture"],
            filename=fields["Filename"],
            sha256=digest,
            depends=dependencies,
        )
        packages[record.name] = record
    return packages


def _dependency_candidates(requirement: str) -> tuple[str, ...]:
    return tuple(
        re.sub(r"\s*\([^)]*\)\s*$", "", alternative).strip()
        for alternative in requirement.split("|")
    )


def resolve_dependency_closure(
    packages: dict[str, PackageRecord], roots: list[str] | tuple[str, ...]
) -> list[PackageRecord]:
    queue = list(roots)
    resolved: list[PackageRecord] = []
    seen: set[str] = set()
    while queue:
        requirement = queue.pop(0)
        candidates = _dependency_candidates(requirement)
        name = next(
            (candidate for candidate in candidates if candidate in packages), None
        )
        if name is None:
            raise PackageIndexError(f"dependency not found: {requirement}")
        if name in seen:
            continue
        seen.add(name)
        package = packages[name]
        resolved.append(package)
        queue.extend(package.depends)
    return resolved


def build_entware_lock(
    index_content: bytes,
    *,
    target: str,
    roots: list[str] | tuple[str, ...],
    index_url: str,
    base_url: str,
    captured_at: str,
) -> dict[str, object]:
    packages = parse_package_index(index_content)
    closure = resolve_dependency_closure(packages, roots)
    incompatible = [
        package.name
        for package in closure
        if package.architecture not in {"all", target}
    ]
    if incompatible:
        raise PackageIndexError(
            f"packages incompatible with {target}: {', '.join(incompatible)}"
        )
    artifacts = [
        {
            "name": package.name,
            "version": package.version,
            "architecture": package.architecture,
            "filename": package.filename,
            "sha256": package.sha256,
            "url": f"{base_url.rstrip('/')}/{quote(package.filename)}",
        }
        for package in closure
    ]
    return {
        "schema_version": 1,
        "kind": "entware-rootfs-lock",
        "target": target,
        "captured_at": captured_at,
        "root_packages": list(roots),
        "source": {
            "index_url": index_url,
            "index_sha256": hashlib.sha256(index_content).hexdigest(),
            "base_url": base_url.rstrip("/"),
        },
        "packages": artifacts,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact_cache(lock: Mapping[str, Any], cache: Path) -> list[str]:
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise ArtifactIntegrityError("lock packages must be a list")
    verified: list[str] = []
    for artifact in packages:
        if not isinstance(artifact, Mapping):
            raise ArtifactIntegrityError("lock package entry must be an object")
        filename = artifact.get("filename")
        expected = artifact.get("sha256")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ArtifactIntegrityError(f"unsafe filename: {filename!r}")
        if not isinstance(expected, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected
        ):
            raise ArtifactIntegrityError(f"invalid sha256: {filename}")
        path = cache / filename
        if not path.is_file():
            raise ArtifactIntegrityError(f"missing artifact: {filename}")
        if _sha256_file(path) != expected:
            raise ArtifactIntegrityError(f"hash mismatch: {filename}")
        verified.append(filename)
    return verified
