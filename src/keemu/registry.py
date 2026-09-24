"""Project-owned persistent environments: per-name locking and atomic state.

A registry record is never Docker ownership authority. Every Docker operation must
independently verify full ID, labels, base image and actual running state.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from keemu.input_locks import PersistentEnvironment, _reject_constant, _unique_object
from keemu.input_paths import safe_name

MAX_STATE = 2 * 1024 * 1024


class RegistryError(RuntimeError):
    """A record is absent, busy, incomplete, or has changed identity."""


def _directory(path: Path, *, create: bool = False) -> int:
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=fd)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            os.close(fd)
            fd = child
    except Exception:
        os.close(fd)
        raise
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise RegistryError(f"untrusted registry directory: {path}")
    return fd


def _read(fd: int, name: str) -> tuple[bytes, os.stat_result]:
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(handle)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size > MAX_STATE
            or before.st_mode & 0o077
        ):
            raise RegistryError("unsafe registry entry")
        data = os.read(handle, MAX_STATE + 1)
        after = os.fstat(handle)
        if (
            len(data) != before.st_size
            or len(data) > MAX_STATE
            or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size)
            != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)
        ):
            raise RegistryError("registry entry changed during read")
        return data, after
    finally:
        os.close(handle)


def _atomic(
    fd: int,
    name: str,
    data: bytes,
    *,
    original: tuple[bytes, os.stat_result] | None,
) -> None:
    if len(data) > MAX_STATE:
        raise RegistryError("registry entry too large")
    temporary = ".pending-" + uuid.uuid4().hex
    handle = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=fd,
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if original is None:
            # Hard link publishes no-replace, even against a dangling symlink.
            os.link(
                temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False
            )
        else:
            current, info = _read(fd, name)
            if current != original[0] or (info.st_dev, info.st_ino) != (
                original[1].st_dev,
                original[1].st_ino,
            ):
                raise RegistryError("registry entry replaced or modified")
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


class Registry:
    def __init__(self, root: Path):
        self.root = root

    @contextmanager
    def locked(self, name: str) -> Iterator[Entry]:
        safe_name(name)
        root_fd = _directory(self.root, create=True)
        try:
            locks_fd = _directory(self.root / "locks", create=True)
            try:
                lock_fd = os.open(
                    name + ".lock",
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=locks_fd,
                )
                try:
                    info = os.fstat(lock_fd)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()
                        or info.st_nlink != 1
                        or info.st_mode & 0o077
                    ):
                        raise RegistryError("unsafe registry lock")
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as exc:
                        raise RegistryError(f"environment busy: {name}") from exc
                    yield Entry(self.root, name)
                finally:
                    os.close(lock_fd)
            finally:
                os.close(locks_fd)
        finally:
            os.close(root_fd)


class Entry:
    def __init__(self, root: Path, name: str):
        self.root = root
        self.name = name
        self.directory = root / name
        self._last_read: tuple[bytes, os.stat_result] | None = None

    def _open(self) -> int:
        try:
            return _directory(self.directory)
        except FileNotFoundError as exc:
            raise RegistryError(f"environment not found: {self.name}") from exc

    def create(self, record: PersistentEnvironment, scenario: bytes) -> None:
        if (
            record.name != self.name
            or record.state != "creating"
            or len(scenario) > MAX_STATE
            or hashlib.sha256(scenario).hexdigest() != record.scenario_sha256
        ):
            raise RegistryError("invalid initial environment")
        try:
            os.mkdir(self.directory, 0o700)
        except FileExistsError as exc:
            raise RegistryError(f"environment already exists: {self.name}") from exc
        fd = self._open()
        try:
            _atomic(fd, "scenario.yaml", scenario, original=None)
            _atomic(fd, "environment.json", self._encode(record), original=None)
            os.fsync(fd)
            self._last_read = _read(fd, "environment.json")
        finally:
            os.close(fd)

    @staticmethod
    def _encode(record: PersistentEnvironment) -> bytes:
        return (
            json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n"
        ).encode()

    def read(self) -> PersistentEnvironment:
        fd = self._open()
        try:
            raw, info = _read(fd, "environment.json")
            data = json.loads(
                raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant
            )
            record = PersistentEnvironment.model_validate(data)
            if record.name != self.name:
                raise RegistryError("registry name mismatch")
            self._last_read = (raw, info)
            return record
        finally:
            os.close(fd)

    def scenario(self, digest: str) -> bytes:
        fd = self._open()
        try:
            raw, _ = _read(fd, "scenario.yaml")
            if hashlib.sha256(raw).hexdigest() != digest:
                raise RegistryError("saved scenario replaced or modified")
            return raw
        finally:
            os.close(fd)

    def update(
        self, previous: PersistentEnvironment, current: PersistentEnvironment
    ) -> None:
        if (
            previous.name != self.name
            or current.name != self.name
            or current.schema_version != previous.schema_version
            or current.kind != previous.kind
            or (
                previous.run_id != current.run_id
                or previous.scenario_id != current.scenario_id
                or previous.profile_id != current.profile_id
                or previous.oci_digest != current.oci_digest
                or previous.scenario_sha256 != current.scenario_sha256
                or previous.profile_sha256 != current.profile_sha256
                or previous.lock_sha256 != current.lock_sha256
                or previous.resource is not None
                and current.resource != previous.resource
            )
        ):
            raise RegistryError("environment identity replacement rejected")
        if (
            previous.state == "creating"
            and current.state == "installing"
            and current.resource is None
        ) or (
            previous.resource is None
            and current.resource is not None
            and (previous.state, current.state) != ("creating", "installing")
        ):
            raise RegistryError("invalid resource assignment")
        if (
            current.state
            not in {
                "creating": {"installing", "failed"},
                "installing": {"stopped", "failed"},
                "stopped": {"starting", "destroyed", "failed"},
                "starting": {"running", "failed"},
                "running": {"stopping", "failed"},
                "stopping": {"stopped", "failed"},
                "failed": {"destroyed"},
                "destroyed": set(),
            }[previous.state]
        ):
            raise RegistryError(
                f"invalid state transition: {previous.state} -> {current.state}"
            )
        fd = self._open()
        try:
            raw, info = _read(fd, "environment.json")
            if (
                raw != self._encode(previous)
                or self._last_read is None
                or (
                    self._last_read[0] != raw
                    or (self._last_read[1].st_dev, self._last_read[1].st_ino)
                    != (info.st_dev, info.st_ino)
                )
            ):
                raise RegistryError("registry entry replaced or modified")
            _atomic(fd, "environment.json", self._encode(current), original=(raw, info))
            self._last_read = _read(fd, "environment.json")
        finally:
            os.close(fd)
