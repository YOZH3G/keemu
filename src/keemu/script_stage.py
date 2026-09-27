"""Typed, no-clobber staging of checked script bytes in an owned target.

This is staging only: no user script is executed here. A private directory
reserves a run-unique digest name; shell noclobber creates its single file.
The target is an owned, running Docker container, not an untrusted host path.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import stat
from dataclasses import dataclass

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, Output
from keemu.script_input import ScriptInput

_SCRIPT_PATH = re.compile(
    r"/opt/tmp/keemu-script-[0-9a-f]{64}-[0-9a-f]{24}/script\.sh\Z"
)
_DECIMAL = re.compile(rb"[0-9]+\Z")
_HEX = re.compile(rb"[0-9a-fA-F]+\Z")


class ScriptStageError(DockerBoundaryError):
    """Staging failed. cleanup records whether safe rollback succeeded."""

    def __init__(self, message: str, cleanup: ScriptCleanup | None = None):
        super().__init__(message)
        self.cleanup = cleanup


@dataclass(frozen=True)
class TargetIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    uid: int

    @classmethod
    def parse(cls, raw: bytes, path: str) -> TargetIdentity:
        # Entware BusyBox stat has -t, not GNU stat -c. Its terse fields are
        # name,size,blocks,mode(hex),uid,gid,device(hex),inode,links,...
        fields = raw.removesuffix(b"\n").split(b" ")
        if (
            raw.count(b"\n") != 1
            or not raw.endswith(b"\n")
            or len(fields) != 15
            or fields[0] != path.encode("ascii")
            or any(not _DECIMAL.fullmatch(fields[i]) for i in (1, 2, 4, 5, 7, 8))
            or any(not _HEX.fullmatch(fields[i]) for i in (3, 6))
        ):
            raise ScriptStageError("invalid target stat readback")
        return cls(
            int(fields[6], 16),
            int(fields[7]),
            int(fields[3], 16),
            int(fields[8]),
            int(fields[1]),
            int(fields[4]),
        )


@dataclass(frozen=True)
class StagedScript:
    container_id: str
    run_id: str
    image_id: str
    target: str
    path: str
    sha256: str
    size: int
    tmp_identity: TargetIdentity
    directory_identity: TargetIdentity
    file_identity: TargetIdentity


@dataclass(frozen=True)
class ScriptCleanup:
    success: bool
    error: str | None = None


class ScriptStager:
    """One runtime's in-memory staging authority; no pathname-only cleanup."""

    def __init__(self, runtime: DockerRuntime):
        self.runtime = runtime
        self._issued: dict[str, StagedScript] = {}

    @staticmethod
    def _same_directory(left: TargetIdentity, right: TargetIdentity) -> bool:
        # Adding/removing an owned child may change parent size and link count.
        return (left.device, left.inode, left.mode, left.uid) == (
            right.device,
            right.inode,
            right.mode,
            right.uid,
        )

    def _running(self, container_id: str) -> None:
        item = self.runtime.inspect("container", container_id)
        if item.get("State", {}).get("Running") is not True:
            raise ScriptStageError("script staging requires an owned running container")

    def _exec(
        self,
        container_id: str,
        command: str,
        *args: str,
        input_data: bytes | None = None,
    ) -> Output:
        self._running(container_id)
        try:
            return self.runtime.exec(
                container_id,
                ["/bin/sh", "-c", command, "keemu-stage", *args],
                input_data=input_data,
                timeout=90 if input_data is not None else 30,
            )
        finally:
            # A failed command (including a timed-out transfer) can still mutate.
            self._running(container_id)

    def _identity(
        self, container_id: str, path: str, *, directory: bool
    ) -> TargetIdentity:
        if path != "/opt/tmp" and not _SCRIPT_PATH.fullmatch(
            path + "/script.sh" if directory else path
        ):
            raise ScriptStageError("unsafe script staging path")
        kind = "-d" if directory else "-f"
        output = self._exec(
            container_id,
            'test ! -L "$1" && test '
            + kind
            + ' "$1" && /opt/bin/busybox stat -t -- "$1"',
            path,
        )
        identity = TargetIdentity.parse(output.stdout, path)
        if not (
            stat.S_ISDIR(identity.mode) if directory else stat.S_ISREG(identity.mode)
        ):
            raise ScriptStageError("unsafe target object type")
        if directory and path != "/opt/tmp" and identity.links != 2:
            # Directories with unexpectedly added entries are not private.
            raise ScriptStageError("target staging directory has unexpected links")
        if not directory and identity.links != 1:
            raise ScriptStageError("target script has multiple links")
        if directory and path != "/opt/tmp" and identity.mode & 0o077:
            raise ScriptStageError("target staging directory is not private")
        return identity

    def stage(self, script: ScriptInput, container_id: str) -> StagedScript:
        """Recheck source; reserve absent dir, create absent file and hash readback."""
        if not isinstance(script, ScriptInput):
            raise ScriptStageError("invalid script input")
        data = script.recheck_for_staging()  # changed input propagates BLOCKED
        if (
            len(data) != script.size
            or hashlib.sha256(data).hexdigest() != script.sha256
        ):
            raise ScriptStageError("script input snapshot mismatch")
        path = (
            f"/opt/tmp/keemu-script-{script.sha256}-{secrets.token_hex(12)}/script.sh"
        )
        if not _SCRIPT_PATH.fullmatch(path):
            raise ScriptStageError("unsafe script staging path")
        directory = path.rsplit("/", 1)[0]
        self._running(container_id)
        tmp = self._identity(container_id, "/opt/tmp", directory=True)
        # mkdir is exclusive even for a pre-existing symlink; never docker cp.
        try:
            self._exec(
                container_id,
                "test ! -L /opt/tmp && test -d /opt/tmp && "
                '/opt/bin/busybox mkdir -m 700 -- "$1"',
                directory,
            )
        except DockerBoundaryError as exc:
            # A collision is never authority to delete the existing object.
            raise ScriptStageError("script staging reservation failed") from exc
        owned_dir: TargetIdentity | None = None
        staged: StagedScript | None = None
        try:
            owned_dir = self._identity(container_id, directory, directory=True)
            if not self._same_directory(
                self._identity(container_id, "/opt/tmp", directory=True), tmp
            ):
                raise ScriptStageError("target staging parent changed")
            self._exec(
                container_id,
                'test ! -L /opt/tmp && test ! -L "$1" && test -d "$1" && '
                'umask 077 && set -C && /opt/bin/busybox cat > "$2"',
                directory,
                path,
                input_data=data,
            )
            file_id = self._identity(container_id, path, directory=False)
            staged = StagedScript(
                container_id,
                self.runtime.run_id,
                self.runtime.image_id,
                self.runtime.target,
                path,
                script.sha256,
                len(data),
                tmp,
                owned_dir,
                file_id,
            )
            self._issued[path] = staged
            if file_id.uid != owned_dir.uid or file_id.mode & 0o077:
                raise ScriptStageError("target script permissions or owner mismatch")
            if file_id.size != len(data):
                raise ScriptStageError("target script size mismatch")
            self.verify(staged)
            return staged
        except (DockerBoundaryError, OSError) as exc:
            if staged is not None:
                cleanup = self.cleanup(staged)
            elif owned_dir is not None:
                cleanup = self._empty_directory(container_id, directory, tmp, owned_dir)
            else:
                cleanup = ScriptCleanup(False, "target directory identity unavailable")
            raise ScriptStageError("script staging failed", cleanup) from exc

    def _check(self, staged: StagedScript) -> str:
        if self._issued.get(staged.path) is not staged or not _SCRIPT_PATH.fullmatch(
            staged.path
        ):
            raise ScriptStageError("script staging authority missing")
        if (staged.run_id, staged.image_id, staged.target) != (
            self.runtime.run_id,
            self.runtime.image_id,
            self.runtime.target,
        ):
            raise ScriptStageError("script staging runtime identity changed")
        directory = staged.path.rsplit("/", 1)[0]
        self._running(staged.container_id)
        if not self._same_directory(
            self._identity(staged.container_id, "/opt/tmp", directory=True),
            staged.tmp_identity,
        ):
            raise ScriptStageError("target staging parent changed")
        if not self._same_directory(
            self._identity(staged.container_id, directory, directory=True),
            staged.directory_identity,
        ):
            raise ScriptStageError("target staging directory changed")
        if (
            self._identity(staged.container_id, staged.path, directory=False)
            != staged.file_identity
        ):
            raise ScriptStageError("target script identity changed")
        return directory

    def verify(self, staged: StagedScript) -> None:
        """Read back exact target bytes, with full object/owner checks on both sides."""
        self._check(staged)
        output = self._exec(
            staged.container_id, '/opt/bin/busybox cat -- "$1"', staged.path
        )
        self._check(staged)
        if (
            output.truncated_stdout
            or output.truncated_stderr
            or len(output.stdout) != staged.size
            or hashlib.sha256(output.stdout).hexdigest() != staged.sha256
        ):
            raise ScriptStageError("target script digest mismatch")

    def _empty_directory(
        self,
        container_id: str,
        directory: str,
        tmp: TargetIdentity,
        owned_dir: TargetIdentity,
    ) -> ScriptCleanup:
        try:
            self._running(container_id)
            if not self._same_directory(
                self._identity(container_id, "/opt/tmp", directory=True), tmp
            ):
                raise ScriptStageError("target staging parent changed")
            if not self._same_directory(
                self._identity(container_id, directory, directory=True), owned_dir
            ):
                raise ScriptStageError("target staging directory changed")
            # rmdir refuses any partial/foreign entry; never sweep a directory.
            self._exec(container_id, '/opt/bin/busybox rmdir -- "$1"', directory)
            self._running(container_id)
            return ScriptCleanup(True)
        except DockerBoundaryError as exc:
            return ScriptCleanup(False, str(exc))

    def cleanup(self, staged: StagedScript) -> ScriptCleanup:
        """Unlink only the issued inode in the issued private directory."""
        try:
            directory = self._check(staged)
            expected = (
                f"{staged.file_identity.size}:{staged.file_identity.mode:x}:"
                f"{staged.file_identity.uid}:{staged.file_identity.device:x}:"
                f"{staged.file_identity.inode}:{staged.file_identity.links}"
            )
            self._exec(
                staged.container_id,
                'test ! -L /opt/tmp && test ! -L "$1" && test -d "$1" && '
                'test ! -L "$2" && test -f "$2" && '
                "dir=$1; file=$2; expected=$3; set -f; "
                'set -- $(/opt/bin/busybox stat -t -- "$file") && '
                'test "$2:$4:$5:$7:$8:$9" = "$expected" && '
                '/opt/bin/busybox rm -- "$file" && '
                '/opt/bin/busybox rmdir -- "$dir"',
                directory,
                staged.path,
                expected,
            )
            self._running(staged.container_id)
            if not self._same_directory(
                self._identity(staged.container_id, "/opt/tmp", directory=True),
                staged.tmp_identity,
            ):
                raise ScriptStageError("target staging parent changed after cleanup")
            # Both absent: no alternate object may be adopted by this cleanup.
            self._exec(
                staged.container_id,
                'test ! -e "$1" && test ! -L "$1" && test ! -e "$2" && test ! -L "$2"',
                staged.path,
                directory,
            )
            del self._issued[staged.path]
            return ScriptCleanup(True)
        except DockerBoundaryError as exc:
            return ScriptCleanup(False, str(exc))
