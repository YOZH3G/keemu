"""Bounded, project-contained script snapshots; no target staging or execution here.

A validated pathname is not authority to copy it later. Call recheck_for_staging
immediately before transferring the returned immutable bytes, never reopen the
host pathname for the transfer. Changes after validation fail closed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

MAX_SCRIPT_BYTES = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_FILE_FLAGS |= os.O_NOCTTY


class ScriptInputError(ValueError):
    """The input cannot be validated safely; do not run it."""


class ScriptInputChanged(ScriptInputError):
    """The validated input is no longer the same; report BLOCKED."""


@dataclass(frozen=True)
class ScriptFileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> ScriptFileIdentity:
        return cls(
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )


@dataclass(frozen=True)
class ScriptInput:
    source_path: Path
    project_root: Path
    sha256: str
    size: int
    identity: ScriptFileIdentity
    _request: str = field(repr=False)
    _bytes: bytes = field(repr=False)
    _directories: tuple[tuple[int, int, int, int, int, int], ...] = field(repr=False)
    _limit: int = field(repr=False)

    @classmethod
    def validate(
        cls,
        path: str | Path,
        *,
        project_root: Path,
        max_bytes: int = MAX_SCRIPT_BYTES,
    ) -> ScriptInput:
        """Pin exact regular .sh bytes, file metadata and directory identities."""
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 1 <= max_bytes <= MAX_SCRIPT_BYTES
        ):
            raise ScriptInputError("invalid script size limit")
        root = Path(os.path.abspath(project_root))
        request, components, source = _source_parts(path, root)
        try:
            data, identity, directories = _stable_read(root, components, max_bytes)
        except (OSError, ScriptInputError) as exc:
            raise ScriptInputError("unsafe or unavailable script input") from exc
        return cls(
            source_path=source,
            project_root=root,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            identity=identity,
            _request=request,
            _bytes=data,
            _directories=directories,
            _limit=max_bytes,
        )

    def recheck_for_staging(self) -> bytes:
        """Reopen the original path without links; return only validated bytes.

        The returned bytes are an immutable private snapshot, not a pathname to
        reopen in a later staging operation. Never copy from source_path.
        """
        try:
            _, components, source = _source_parts(self._request, self.project_root)
            if source != self.source_path:
                raise ScriptInputChanged("script input path changed")
            data, identity, directories = _stable_read(
                self.project_root, components, self._limit
            )
            if (
                identity != self.identity
                or directories != self._directories
                or len(data) != self.size
                or hashlib.sha256(data).hexdigest() != self.sha256
                or data != self._bytes
            ):
                raise ScriptInputChanged("script input changed since validation")
        except (OSError, ScriptInputError) as exc:
            raise ScriptInputChanged("script input changed since validation") from exc
        return self._bytes


def _source_parts(path: str | Path, root: Path) -> tuple[str, tuple[str, ...], Path]:
    value = os.fspath(path)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ScriptInputError("invalid script input path")
    if value.startswith("/"):
        prefix = str(root) + "/"
        if not value.startswith(prefix):
            raise ScriptInputError("script input outside project")
        relative = value[len(prefix) :]
    else:
        relative = value
    components = tuple(relative.split("/"))
    if components[-1] in {"", ".", ".."} or not components[-1].endswith(".sh"):
        raise ScriptInputError("script input must name a .sh file")
    names: list[str] = []
    for component in components:
        if component == ".":
            continue
        if component == "..":
            if not names:
                raise ScriptInputError("script input escapes project")
            names.pop()
        elif component:
            names.append(component)
        else:
            raise ScriptInputError("invalid script input path")
    return value, components, root.joinpath(*names)


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_ctime_ns,
    )


def _read_once(
    root: Path, components: tuple[str, ...], limit: int
) -> tuple[bytes, ScriptFileIdentity, tuple[tuple[int, int, int, int, int, int], ...]]:
    # Hold each ancestor FD while traversing. Even a component later cancelled
    # by '..' is opened no-follow, so link/../file.sh cannot mask a symlink.
    fds: list[int] = []
    visited: list[tuple[int, int, int, int, int, int]] = []
    try:
        fds.append(os.open(root, _DIRECTORY_FLAGS))
        visited.append(_directory_identity(os.fstat(fds[-1])))
        for component in components[:-1]:
            if component == ".":
                continue
            if component == "..":
                if len(fds) == 1:
                    raise ScriptInputError("script input escapes project")
                os.close(fds.pop())
                continue
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=fds[-1])
            fds.append(child)
            visited.append(_directory_identity(os.fstat(child)))
        name = components[-1]
        before_path = ScriptFileIdentity.from_stat(
            os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
        )
        if (
            not stat.S_ISREG(before_path.mode)
            or before_path.links != 1
            or before_path.size > limit
        ):
            raise ScriptInputError("script must be a bounded regular file")
        fd = os.open(name, _FILE_FLAGS, dir_fd=fds[-1])
        try:
            before = ScriptFileIdentity.from_stat(os.fstat(fd))
            if before != before_path:
                raise ScriptInputError("script input changed during open")
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = ScriptFileIdentity.from_stat(os.fstat(fd))
            after_path = ScriptFileIdentity.from_stat(
                os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
            )
            if (
                before != after
                or after != after_path
                or total != before.size
                or total > limit
            ):
                raise ScriptInputError("script input changed during read")
            return b"".join(chunks), before, tuple(visited)
        finally:
            os.close(fd)
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _stable_read(
    root: Path, components: tuple[str, ...], limit: int
) -> tuple[bytes, ScriptFileIdentity, tuple[tuple[int, int, int, int, int, int], ...]]:
    first = _read_once(root, components, limit)
    second = _read_once(root, components, limit)
    if first != second:
        raise ScriptInputError("script input changed during validation")
    return first
