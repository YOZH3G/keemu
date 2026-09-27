"""Native subreaper for a single staged script in an owner-verified target.

No host shell executes the script. The pinned, static amd64 helper runs inside
Docker's target PID namespace, launches the target /bin/sh, reaps orphans and
returns a bounded length-framed response. A lost response is never cleanup proof.
"""

from __future__ import annotations

import hashlib
import re
import stat
import subprocess
import tempfile
from pathlib import Path

from keemu.docker_runtime import COMMAND_LIMIT, DockerBoundaryError, DockerRuntime
from keemu.script_results import ScriptExecutionResult
from keemu.script_stage import ScriptStager, StagedScript, TargetIdentity

_SOURCE_SHA256 = "60f3a70cb94477ec113b31315de6a0dd2b06f60934ca8121f597b96612b96cab"
_BINARY_SHA256 = "40eadb77d1b8f84ee6c7d976df4cf566b8444e3034699f4ed4227800be1e7e37"
_HEADER = re.compile(
    rb"KEEMU1 (-?\d+) ([01]) ([01]) (\d+) (\d+) (\d+) ([01]) ([01])\n\Z"
)


class ScriptProcessError(DockerBoundaryError):
    """Runner or cleanup contract failed; no PASS or survivor proof inferred."""


def _helper_bytes() -> bytes:
    source = (
        Path(__file__).resolve().parents[2] / "fixtures/sources/script-runner/runner.c"
    )
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != _SOURCE_SHA256:
        raise ScriptProcessError("script supervisor source identity changed")
    # Compile only the pinned native helper, not the user script. The resulting
    # bytes are independently pinned; changed compiler/toolchain fails closed.
    with tempfile.TemporaryDirectory(prefix="keemu-script-runner-") as folder:
        binary = Path(folder) / "runner"
        try:
            subprocess.run(  # noqa: S603 -- pinned compiler argv, no shell
                [
                    "/usr/bin/gcc",
                    "-static",
                    "-O2",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-o",
                    str(binary),
                    str(source),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            with binary.open("rb") as stream:
                result = stream.read(COMMAND_LIMIT + 1)
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise ScriptProcessError(
                "pinned script supervisor build unavailable"
            ) from exc
    if (
        len(result) > COMMAND_LIMIT
        or hashlib.sha256(result).hexdigest() != _BINARY_SHA256
    ):
        raise ScriptProcessError("script supervisor binary identity mismatch")
    return result


def _decode(data: bytes) -> ScriptExecutionResult:
    header, sep, payload = data.partition(b"\n")
    match = _HEADER.fullmatch(header + sep)
    if not match:
        raise ScriptProcessError("script supervisor response header invalid")
    code, timed, clean, millis, stdout_size, stderr_size, trunc_out, trunc_err = (
        int(group) for group in match.groups()
    )
    if (
        code < -1
        or code > 255
        or millis > 660000
        or stdout_size > COMMAND_LIMIT
        or stderr_size > COMMAND_LIMIT
        or len(payload) != stdout_size + stderr_size
        or (not timed and code == -1)
    ):
        raise ScriptProcessError("script supervisor response bounds invalid")
    return ScriptExecutionResult(
        state="executed",
        exit_code=None if code == -1 else code,
        timed_out=bool(timed),
        process_tree_clean=bool(clean),
        duration_seconds=millis / 1000,
        stdout=payload[:stdout_size],
        stderr=payload[stdout_size:],
        truncated_stdout=bool(trunc_out),
        truncated_stderr=bool(trunc_err),
    )


class ScriptProcessRunner:
    """Stages only the pinned helper next to an issued script; exact cleanup."""

    def __init__(self, stager: ScriptStager):
        self.stager = stager
        self.runtime: DockerRuntime = stager.runtime

    def _stat(self, staged: StagedScript, path: str) -> TargetIdentity:
        output = self.stager._exec(
            staged.container_id,
            'test ! -L "$1" && test -f "$1" && /opt/bin/busybox stat -t -- "$1"',
            path,
        )
        return TargetIdentity.parse(output.stdout, path)

    def _cleanup(
        self, staged: StagedScript, path: str, identity: TargetIdentity
    ) -> None:
        self.stager._check(staged)
        if self._stat(staged, path) != identity:
            raise ScriptProcessError(
                "script supervisor identity changed before removal"
            )
        expected = (
            f"{identity.size}:{identity.mode:x}:{identity.uid}:"
            f"{identity.device:x}:{identity.inode}:{identity.links}"
        )
        self.stager._exec(
            staged.container_id,
            'test ! -L "$1" && test -f "$1" && '
            "file=$1; expected=$2; set -f; "
            'set -- $(/opt/bin/busybox stat -t -- "$file") && '
            'test "$2:$4:$5:$7:$8:$9" = "$expected" && '
            '/opt/bin/busybox rm -- "$file"',
            path,
            expected,
        )
        self.stager._check(staged)
        self.stager._exec(staged.container_id, 'test ! -e "$1" && test ! -L "$1"', path)

    def run(
        self,
        staged: StagedScript,
        *,
        timeout_seconds: int = 60,
        cwd: str = "/opt",
        argv: tuple[str, ...] = (),
    ) -> ScriptExecutionResult:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            raise ScriptProcessError("invalid script timeout")
        if cwd != "/opt" and (
            not cwd.startswith("/opt/")
            or any(part in {"", ".", ".."} for part in cwd[5:].split("/"))
        ):
            raise ScriptProcessError("invalid target working directory")
        if (
            len(argv) > 126
            or any(
                not isinstance(arg, str) or not arg or "\0" in arg or len(arg) > 4096
                for arg in argv
            )
            or sum(len(arg.encode("utf-8")) for arg in argv) > 65536
        ):
            raise ScriptProcessError("invalid bounded script arguments")
        self.stager.verify(staged)
        binary = _helper_bytes()
        path = staged.path.rsplit("/", 1)[0] + "/runner"
        self.stager._check(staged)
        try:
            self.stager._exec(
                staged.container_id,
                'test ! -L "$1" && test -d "$1" && '
                'umask 077 && set -C && /opt/bin/busybox cat > "$2" && '
                '/opt/bin/busybox chmod 700 -- "$2"',
                path.rsplit("/", 1)[0],
                path,
                input_data=binary,
            )
        except DockerBoundaryError as exc:
            # Partial transfer lacks established inode authority: retain it.
            raise ScriptProcessError("script supervisor transfer uncertain") from exc
        identity = self._stat(staged, path)
        if (
            not stat.S_ISREG(identity.mode)
            or identity.mode != 0o100700
            or identity.links != 1
            or identity.uid != staged.file_identity.uid
            or identity.size != len(binary)
        ):
            raise ScriptProcessError("script supervisor target identity invalid")
        try:
            self.stager._check(staged)
            output = self.stager._exec(
                staged.container_id, '/opt/bin/busybox cat -- "$1"', path
            )
            if (
                output.stdout != binary
                or output.truncated_stdout
                or output.truncated_stderr
            ):
                raise ScriptProcessError("script supervisor target bytes changed")
            self.stager._check(staged)
            output = self.runtime.exec(
                staged.container_id,
                [path, str(timeout_seconds), *argv],
                cwd=cwd,
                timeout=timeout_seconds + 8,
                capture_limit=2 * COMMAND_LIMIT + 256,
                allow_failure=False,
            )
            self.stager._running(staged.container_id)
            if output.truncated_stdout or output.truncated_stderr or output.stderr:
                raise ScriptProcessError("script supervisor protocol output invalid")
            return _decode(output.stdout)
        finally:
            # The helper is scoped to this issued directory; on an uncertain
            # exec result this removal is not process-tree survivor proof.
            self._cleanup(staged, path, identity)
