"""Lexical and filesystem boundaries for untrusted scenario inputs.

Validation is not an open-file authorization: consumers need to recheck and open inputs
without following links at use time to close validation-to-use races.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Annotated

from pydantic import AfterValidator


class UnsafePath(ValueError):
    """An input path is ambiguous or leaves its allowed boundary."""


def _parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise UnsafePath("path must be a nonempty bounded string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise UnsafePath("control character in path")
    if "\\" in value:
        raise UnsafePath("backslash in POSIX path")
    if "//" in value or value.endswith("/"):
        raise UnsafePath("noncanonical path")
    parts = PurePosixPath(value).parts
    if any(part in {".", ".."} for part in value.split("/")):
        raise UnsafePath("dot component in path")
    if any(part in {"proc", "sys", "dev"} for part in parts):
        raise UnsafePath("special filesystem in path")
    return parts


def target_path(value: str) -> str:
    """Only the Entware /opt subtree can be a mutable target path."""
    parts = _parts(value)
    if not value.startswith("/") or parts[:2] != ("/", "opt") or len(parts) < 3:
        raise UnsafePath("target path must be below /opt")
    return value


def target_directory(value: str) -> str:
    if value == "/opt":
        return value
    return target_path(value)


def host_input_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or any(c in {"", "."} for c in value.split("/"))
    ):
        raise UnsafePath("invalid relative input path")
    # ../ is allowed only after resolve_input_path proves containment in project_root.
    return value


def safe_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 63
        or len(value) < 2
        or not value[0].islower()
        or not value[0].isascii()
        or not value[-1].isascii()
        or not value[-1].isalnum()
        or any(
            not (c.isascii() and (c.islower() or c.isdigit() or c == "-"))
            for c in value
        )
    ):
        raise ValueError("name must be a lowercase ASCII identifier")
    return value


TargetPath = Annotated[str, AfterValidator(target_path)]
TargetDirectory = Annotated[str, AfterValidator(target_directory)]
HostInputPath = Annotated[str, AfterValidator(host_input_path)]
SafeName = Annotated[str, AfterValidator(safe_name)]


def resolve_input_path(
    value: str, *, scenario_dir: Path, project_root: Path, must_exist: bool = True
) -> Path:
    """Resolve an input relative to scenario, allowing .. only within project.

    Reject symlinks throughout the portion of the path below project_root,
    including the scenario directory and the input file. This is a validation
    boundary, not protection from concurrent replacement during a later open.
    """
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
    ):
        raise UnsafePath("input path must be relative to the scenario directory")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "//" in value:
        raise UnsafePath("unsafe input path")
    components = value.split("/")
    if any(not c or c == "." for c in components):
        raise UnsafePath("noncanonical input path")
    root = Path(os.path.abspath(project_root))
    base = Path(os.path.abspath(scenario_dir))
    if not base.is_relative_to(root):
        raise UnsafePath("scenario directory outside project root")
    candidate = Path(os.path.normpath(str(base / value)))
    if not candidate.is_relative_to(root) or candidate == root:
        raise UnsafePath("input path escapes project root")
    for parent in (base, candidate):
        relative = parent.relative_to(root)
        current = root
        for component in relative.parts:
            current /= component
            if current.is_symlink():
                raise UnsafePath(f"symlink in input path: {current}")
    if must_exist and not candidate.is_file():
        raise UnsafePath(f"missing regular input: {candidate}")
    return candidate
