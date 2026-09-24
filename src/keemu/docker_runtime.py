"""MVP 1A Docker boundary. No registry or application lifecycle policy lives here.

Only full IDs are mutation targets; a name or label query is never deletion authority.
The base image is addressed by immutable Docker-local ID, and Docker gives each
created container a fresh writable overlay. This is not a disk quota.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Literal

OWNER = "org.keemu.owner"
RUN = "org.keemu.run-id"
KIND = "org.keemu.kind"
BASE = "org.keemu.base-image"
ID = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{1,62}\Z")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z")
LOG_LIMIT = 20 * 1024 * 1024
COMMAND_LIMIT = 1024 * 1024
WRITABLE_THRESHOLD = 512 * 1024 * 1024
STAGED_IPK = re.compile(
    r"/opt/tmp/[a-z][a-z0-9+.-]*_[A-Za-z0-9+~._-]+_[a-z0-9.-]+\.ipk\Z"
)


class DockerBoundaryError(RuntimeError):
    """Docker failure or a failed ownership/security invariant."""


@dataclass(frozen=True)
class Output:
    stdout: bytes
    stderr: bytes
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    exit_code: int = 0


def _valid(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DockerBoundaryError(f"invalid {what}")
    return value


def _exec(
    argv: list[str],
    *,
    timeout: float = 30,
    limit: int = COMMAND_LIMIT,
    truncate: bool = False,
    allow_failure: bool = False,
) -> Output:
    """Read both pipes concurrently with a deadline and per-stream byte cap."""
    if (
        not argv
        or argv[0] != "docker"
        or any(not isinstance(a, str) or "\0" in a for a in argv)
    ):
        raise DockerBoundaryError("invalid Docker argv")
    if timeout <= 0 or timeout > 600 or limit <= 0:
        raise DockerBoundaryError("invalid command bounds")
    try:
        process = subprocess.Popen(  # noqa: S603 -- fixed executable, argv only
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
    except OSError as exc:
        raise DockerBoundaryError(f"Docker launch failed: {exc}") from exc
    selector = selectors.DefaultSelector()
    chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    excess = {"stdout": False, "stderr": False}
    try:
        if process.stdout is None or process.stderr is None:
            raise DockerBoundaryError("Docker pipes unavailable")
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise DockerBoundaryError(f"Docker command timed out: {argv[1]}")
            for key, _ in selector.select(min(left, 0.5)):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                available = limit - len(chunks[name])
                chunks[name].extend(data[:available])
                if len(data) > available:
                    excess[name] = True
                    if not truncate:
                        raise DockerBoundaryError(f"Docker {name} exceeded byte cap")
        left = deadline - time.monotonic()
        if left <= 0:
            raise DockerBoundaryError(f"Docker command timed out: {argv[1]}")
        code = process.wait(timeout=left)
        if code and not allow_failure:
            message = bytes(chunks["stderr"][:4096]).decode("utf-8", "replace")
            raise DockerBoundaryError(f"Docker {argv[1]} failed: {message}")
        return Output(
            bytes(chunks["stdout"]),
            bytes(chunks["stderr"]),
            excess["stdout"],
            excess["stderr"],
            code,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DockerBoundaryError(f"Docker command failed: {argv[1]}") from exc
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _json(argv: list[str]) -> object:
    try:
        return json.loads(_exec(argv).stdout)
    except (UnicodeError, ValueError) as exc:
        raise DockerBoundaryError("invalid Docker JSON") from exc


class DockerRuntime:
    """A single run's resource boundary, with deliberately no implicit cleanup."""

    def __init__(self, run_id: str, image_id: str, *, target: str = "aarch64-3.10"):
        self.run_id = _valid(RUN_ID, run_id, "run ID")
        self.image_id = _valid(SHA, image_id, "immutable image ID")
        if target not in {"aarch64-3.10", "mips-3.4", "mipsel-3.4"}:
            raise DockerBoundaryError("unsupported target")
        self.target = target

    def _labels(self, kind: Literal["container", "network"]) -> list[str]:
        labels = {
            OWNER: "keemu",
            RUN: self.run_id,
            KIND: kind,
            BASE: self.image_id,
            "org.keemu.target": self.target,
        }
        return [item for pair in labels.items() for item in ("--label", "=".join(pair))]

    def image(self) -> dict:
        info = _json(["docker", "image", "inspect", "--", self.image_id])
        if not isinstance(info, list) or len(info) != 1:
            raise DockerBoundaryError("missing immutable base image")
        image = info[0]
        labels = image.get("Config", {}).get("Labels") or {}
        if (
            image.get("Id") != self.image_id
            or image.get("Os") != "linux"
            or image.get("Architecture") != "amd64"
            or image.get("Config", {}).get("Entrypoint") != ["/__keemu/init"]
            or labels.get(OWNER) != "keemu"
            or labels.get("org.keemu.target") != self.target
            or image.get("Config", {}).get("Volumes")
        ):
            raise DockerBoundaryError("base image identity/config mismatch")
        return image

    def inspect(self, kind: Literal["container", "network"], identifier: str) -> dict:
        _valid(ID, identifier, f"{kind} ID")
        argv = (
            ["docker", "container", "inspect", "--", identifier]
            if kind == "container"
            else ["docker", "network", "inspect", "--", identifier]
        )
        data = _json(argv)
        if (
            not isinstance(data, list)
            or len(data) != 1
            or data[0].get("Id") != identifier
        ):
            raise DockerBoundaryError(f"{kind} disappeared or changed identity")
        item = data[0]
        labels = (
            item.get("Config", {}).get("Labels")
            if kind == "container"
            else item.get("Labels")
        ) or {}
        if (
            labels.get(OWNER),
            labels.get(RUN),
            labels.get(KIND),
            labels.get(BASE),
            labels.get("org.keemu.target"),
        ) != (
            "keemu",
            self.run_id,
            kind,
            self.image_id,
            self.target,
        ):
            raise DockerBoundaryError(f"{kind} ownership labels mismatch")
        if kind == "container" and item.get("Image") != self.image_id:
            raise DockerBoundaryError("container base image mismatch")
        if kind == "network" and (
            item.get("Driver") != "bridge" or item.get("Scope") != "local"
        ):
            raise DockerBoundaryError("network driver/scope mismatch")
        return item

    def create_network(self, name: str) -> str:
        _valid(NAME, name, "network name")
        if not name.startswith("keemu-"):
            raise DockerBoundaryError("network name must be project-prefixed")
        raw = (
            _exec(
                [
                    "docker",
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    *self._labels("network"),
                    "--",
                    name,
                ]
            )
            .stdout.decode()
            .strip()
        )
        identifier = _valid(ID, raw, "created network ID")
        if self.inspect("network", identifier).get("Name") != name:
            raise DockerBoundaryError("created network name mismatch")
        return identifier

    def create(self, name: str, *, network_id: str | None = None) -> str:
        _valid(NAME, name, "container name")
        if not name.startswith("keemu-"):
            raise DockerBoundaryError("container name must be project-prefixed")
        self.image()
        if network_id is not None:
            self.inspect("network", _valid(ID, network_id, "network ID"))
        # Fresh writable overlay; never mount host paths, volumes, or Docker socket.
        # Explicit limits prevent reverting to Docker's unbounded defaults.
        argv = [
            "docker",
            "container",
            "create",
            "--name",
            name,
            "--pull",
            "never",
            "--platform",
            "linux/amd64",
            "--restart",
            "no",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--cpus",
            "2",
            "--pids-limit",
            "256",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--log-driver",
            "json-file",
            "--log-opt",
            "max-size=20m",
            "--log-opt",
            "max-file=1",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=16m",  # noqa: S108 -- container tmpfs
            "--tmpfs",
            "/run:rw,nosuid,nodev,size=4m",
            "--network",
            network_id or "none",
            *self._labels("container"),
            "--",
            self.image_id,
        ]
        identifier = _valid(
            ID, _exec(argv).stdout.decode().strip(), "created container ID"
        )
        item = self.inspect("container", identifier)
        host = item.get("HostConfig", {})
        config = item.get("Config", {})
        if (
            item.get("Name") != "/" + name
            or host.get("ReadonlyRootfs")
            or host.get("Privileged")
            or host.get("NetworkMode") != (network_id or "none")
            or host.get("PidMode")
            or host.get("IpcMode") == "host"
            or host.get("UTSMode")
            or host.get("CgroupnsMode") == "host"
            or host.get("Binds")
            or host.get("Mounts")
            or host.get("Devices")
            or config.get("Volumes")
            or host.get("CapAdd")
            or host.get("Memory") != 1073741824
            or host.get("MemorySwap") != 1073741824
            or host.get("NanoCpus") != 2000000000
            or host.get("PidsLimit") != 256
            or "ALL" not in (host.get("CapDrop") or [])
            or "no-new-privileges" not in (host.get("SecurityOpt") or [])
            or set(host.get("Tmpfs") or {}) != {"/tmp", "/run"}  # noqa: S108
            or host.get("LogConfig")
            != {"Type": "json-file", "Config": {"max-file": "1", "max-size": "20m"}}
            or host.get("PortBindings")
            or host.get("RestartPolicy", {}).get("Name") != "no"
        ):
            raise DockerBoundaryError("Docker did not apply bounded isolation settings")
        return identifier

    def start(self, identifier: str) -> None:
        self.inspect("container", identifier)
        self.check_writable_layer(identifier)
        _exec(["docker", "container", "start", identifier])
        self.inspect("container", identifier)

    def stop(self, identifier: str) -> None:
        item = self.inspect("container", identifier)
        if item.get("State", {}).get("Running"):
            _exec(
                ["docker", "container", "stop", "--time", "5", identifier], timeout=20
            )
        self.inspect("container", identifier)

    def exec(
        self,
        identifier: str,
        argv: list[str],
        *,
        timeout: float = 30,
        allow_failure: bool = False,
        cwd: str | None = None,
    ) -> Output:
        if (
            not argv
            or len(argv) > 128
            or any(
                not isinstance(arg, str) or not arg or len(arg) > 4096 or "\0" in arg
                for arg in argv
            )
        ):
            raise DockerBoundaryError("invalid target argv")
        self.inspect("container", identifier)
        self.check_writable_layer(identifier)
        if cwd is not None and (
            cwd != "/opt" and (not cwd.startswith("/opt/") or ".." in cwd.split("/"))
        ):
            raise DockerBoundaryError("invalid target cwd")
        try:
            return _exec(
                [
                    "docker",
                    "container",
                    "exec",
                    *(["--workdir", cwd] if cwd else []),
                    identifier,
                    *argv,
                ],
                timeout=timeout,
                allow_failure=allow_failure,
            )
        finally:
            self.check_writable_layer(identifier)

    def check_writable_layer(self, identifier: str) -> int:
        """Stop on observed excess; this check is not a continuous disk quota."""
        self.inspect("container", identifier)
        data = _json(["docker", "container", "inspect", "--size", "--", identifier])
        if (
            not isinstance(data, list)
            or len(data) != 1
            or data[0].get("Id") != identifier
        ):
            raise DockerBoundaryError("writable layer inspection identity mismatch")
        size = data[0].get("SizeRw")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise DockerBoundaryError("writable layer size unavailable")
        if size >= WRITABLE_THRESHOLD:
            self.stop(identifier)
            raise DockerBoundaryError("writable layer exceeded 512 MiB threshold")
        return size

    def logs(self, identifier: str, *, timeout: float = 30) -> Output:
        self.inspect("container", identifier)
        output = _exec(
            ["docker", "container", "logs", identifier],
            timeout=timeout,
            limit=LOG_LIMIT,
            truncate=True,
        )
        marker = b"\n[KEEMU log stream truncated at 20 MiB]\n"
        return Output(
            output.stdout + (marker if output.truncated_stdout else b""),
            output.stderr + (marker if output.truncated_stderr else b""),
            output.truncated_stdout,
            output.truncated_stderr,
        )

    def copy_file(self, identifier: str, source: str, destination: str) -> None:
        """Stage a private regular local input at a fixed fresh-container /opt path."""
        import stat

        info = os.lstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
            raise DockerBoundaryError("unsafe staged input")
        if not STAGED_IPK.fullmatch(destination) or len(destination) > 200:
            raise DockerBoundaryError("unsafe target staging path")
        self.inspect("container", identifier)
        _exec(
            ["docker", "container", "cp", "--", source, f"{identifier}:{destination}"],
            timeout=90,
        )
        self.inspect("container", identifier)

    def read_staged_file(self, identifier: str, source: str, destination: str) -> None:
        """Read back a fixed target IPK into a private, absent local path."""
        if not STAGED_IPK.fullmatch(source) or len(source) > 200:
            raise DockerBoundaryError("unsafe target staging path")
        parent = os.path.dirname(destination)
        if (
            not os.path.isdir(parent)
            or os.path.islink(parent)
            or os.path.lexists(destination)
        ):
            raise DockerBoundaryError("unsafe local readback destination")
        self.inspect("container", identifier)
        _exec(
            ["docker", "container", "cp", "--", f"{identifier}:{source}", destination],
            timeout=90,
        )
        self.inspect("container", identifier)

    def diff(self, identifier: str) -> tuple[str, ...]:
        self.inspect("container", identifier)
        output = _exec(["docker", "container", "diff", identifier], timeout=60)
        if output.truncated_stdout or output.truncated_stderr:
            raise DockerBoundaryError("filesystem diff truncated")
        lines = output.stdout.decode("utf-8").splitlines()
        if any(not re.fullmatch(r"[ACD] /[^\n\r]+", line) for line in lines):
            raise DockerBoundaryError("invalid Docker filesystem diff")
        return tuple(sorted(lines))

    def remove_container(self, identifier: str) -> None:
        self.stop(identifier)
        self.inspect("container", identifier)  # recheck immediately before mutation
        _exec(["docker", "container", "rm", identifier])
        self._absent("container", identifier)

    def remove_network(self, identifier: str) -> None:
        item = self.inspect("network", identifier)
        if item.get("Containers"):
            raise DockerBoundaryError("network has attached containers; refuse removal")
        self.inspect("network", identifier)
        _exec(["docker", "network", "rm", identifier])
        self._absent("network", identifier)

    @staticmethod
    def _absent(kind: str, identifier: str) -> None:
        args = (
            ["docker", kind, "ls", "--all", "--no-trunc", "--quiet"]
            if kind == "container"
            else ["docker", "network", "ls", "--no-trunc", "--quiet"]
        )
        if identifier in _exec(args).stdout.decode().splitlines():
            raise DockerBoundaryError(f"removed {kind} still listed")

    def reconcile(
        self,
        expected_containers: set[str] | frozenset[str] = frozenset(),
        expected_networks: set[str] | frozenset[str] = frozenset(),
    ) -> dict[str, list[str]]:
        """Read-only comparison; never silently delete or adopt unexpected resources."""
        for identifier in expected_containers | expected_networks:
            _valid(ID, identifier, "expected resource ID")
        result: dict[str, list[str]] = {}
        for kind, expected in (
            ("container", expected_containers),
            ("network", expected_networks),
        ):
            args = (
                ["docker", "container", "ls", "--all", "--no-trunc", "--quiet"]
                if kind == "container"
                else ["docker", "network", "ls", "--no-trunc", "--quiet"]
            )
            args += [
                "--filter",
                f"label={OWNER}=keemu",
                "--filter",
                f"label={RUN}={self.run_id}",
            ]
            listed = _exec(args).stdout.decode().splitlines()
            verified = {
                identifier
                for identifier in listed
                if _valid(ID, identifier, "listed resource ID")
                and self.inspect(kind, identifier)
            }
            result[f"{kind}_owned"] = sorted(verified)
            result[f"{kind}_unexpected"] = sorted(verified - expected)
            result[f"{kind}_missing"] = sorted(expected - verified)
        return result
