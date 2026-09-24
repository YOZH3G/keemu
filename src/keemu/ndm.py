"""Strict, process-level NDM fixture shim. No physical-device behavior is implied.

Invoke as ``python -m keemu.ndm --contract FILE --state FILE --log FILE
--run-id ID -- ndmc -c 'command'``. The input after ``--`` is the *exact*
process argv; unknown invocations fail closed. All state and logs are local.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from keemu.input_locks import _reject_constant, _unique_object
from keemu.scenarios import InputModel

_MAX_CONTRACT = 1024 * 1024
_MAX_STATE = 1024 * 1024
_MAX_OUTPUT = 64 * 1024
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z")


class NDMError(ValueError):
    """Malformed fixture, unsafe state, or failed local I/O."""


class Response(InputModel):
    stdout: str = Field(max_length=_MAX_OUTPUT)
    stderr: str = Field(max_length=_MAX_OUTPUT)
    exit_code: int = Field(ge=0, le=255)


class NDMCommand(InputModel):
    argv: tuple[str, ...] = Field(min_length=1, max_length=16, strict=False)
    source: str = Field(pattern=r"^(synthetic|observed):[A-Za-z0-9._/-]{1,245}$")
    kind: Literal["read", "write"]
    state_key: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    state_value: str | None = Field(default=None, max_length=256)
    responses: dict[str, Response] | None = None
    response: Response | None = None

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        if (
            self.argv[0] != "ndmc"
            or len(self.argv) != 3
            or self.argv[1] != "-c"
            or not self.argv[2]
            or any("\x00" in arg for arg in self.argv)
        ):
            raise ValueError("only exact ndmc -c argv is supported")
        if self.kind == "read":
            if (
                self.state_value is not None
                or not self.responses
                or self.response is not None
            ):
                raise ValueError("read requires state responses only")
            if any(
                response.exit_code in {64, 65} for response in self.responses.values()
            ):
                raise ValueError("read response uses a reserved shim exit code")
        elif (
            self.state_value is None
            or self.responses is not None
            or self.response is None
            or self.response.exit_code != 0
        ):
            raise ValueError("write requires a state value and successful response")
        return self


class NDMContract(InputModel):
    schema_version: Literal[1]
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    initial_state: dict[str, str]
    commands: tuple[NDMCommand, ...] = Field(min_length=1, max_length=128, strict=False)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if len({command.argv for command in self.commands}) != len(self.commands):
            raise ValueError("duplicate NDM argv")
        if any(
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key)
            for key in self.initial_state
        ):
            raise ValueError("invalid state key")
        if any(len(value) > 256 for value in self.initial_state.values()):
            raise ValueError("state value too long")
        values: dict[str, set[str]] = {
            key: {value} for key, value in self.initial_state.items()
        }
        for command in self.commands:
            if not command.source.startswith(("synthetic:", "observed:")):
                raise ValueError(
                    "fixture source must identify synthetic or observed origin"
                )
            if command.state_key not in self.initial_state:
                raise ValueError("command references missing initial state")
            if command.kind == "write":
                if command.state_value is None:
                    raise ValueError("missing write state value")
                values[command.state_key].add(command.state_value)
        read_keys = {c.state_key for c in self.commands if c.kind == "read"}
        if any(
            c.kind == "write" and c.state_key not in read_keys for c in self.commands
        ):
            raise ValueError("write requires an observable read command")
        for command in self.commands:
            if (
                command.kind == "read"
                and set(command.responses or {}) != values[command.state_key]
            ):
                raise ValueError("read responses must cover every declared state value")
            if command.kind == "read" and command.responses is not None:
                outputs = {
                    (response.stdout, response.stderr, response.exit_code)
                    for response in command.responses.values()
                }
                if len(outputs) != len(command.responses):
                    raise ValueError(
                        "state values must have distinguishable read responses"
                    )
        return self


def _read_json(path: Path, limit: int, *, private: bool = False) -> object:
    fd = _owned_file(path, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > limit
            or (private and info.st_mode & 0o077)
        ):
            raise NDMError("invalid or oversized NDM file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise NDMError("invalid or oversized NDM file")
        return json.loads(
            data, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    finally:
        os.close(fd)


def load_contract(path: Path) -> NDMContract:
    try:
        return NDMContract.model_validate(_read_json(path, _MAX_CONTRACT))
    except (OSError, UnicodeError, ValueError) as exc:
        raise NDMError("invalid NDM contract") from exc


def _owned_file(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or (path.name.endswith((".jsonl", ".lock")) and info.st_mode & 0o077)
    ):
        os.close(fd)
        raise NDMError("unsafe NDM file")
    return fd


def _write_state(path: Path, payload: dict[str, object]) -> None:
    # Lock serializes cooperative processes; never follow a replaced state link.
    if path.is_symlink():
        raise NDMError("unsafe NDM state")
    fd, name = tempfile.mkstemp(prefix=".ndm-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _state(path: Path, contract: NDMContract, digest: str) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        return {
            "contract": contract.id,
            "digest": digest,
            "values": dict(contract.initial_state),
        }
    data = _read_json(path, _MAX_STATE, private=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"contract", "digest", "values"}
        or data["contract"] != contract.id
        or data["digest"] != digest
        or not isinstance(data["values"], dict)
        or set(data["values"]) != set(contract.initial_state)
        or any(not isinstance(v, str) or len(v) > 256 for v in data["values"].values())
    ):
        raise NDMError("NDM state does not match contract")
    return data


def _log(log: Path, record: dict[str, object]) -> None:
    fd = _owned_file(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    try:
        line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
        if len(line) > 4096:
            raise NDMError("NDM log entry too large")
        if os.write(fd, line) != len(line):
            raise NDMError("short NDM log write")
        os.fsync(fd)
    finally:
        os.close(fd)


def invoke(
    contract_path: Path,
    state_path: Path,
    log_path: Path,
    run_id: str,
    argv: tuple[str, ...],
) -> Response:
    """One exact process invocation with serialized state and secret-free JSONL."""
    if not _RUN_ID.fullmatch(run_id):
        raise NDMError("invalid run ID")
    if state_path == log_path or state_path.parent != log_path.parent:
        raise NDMError("state and log must be distinct files in one directory")
    contract = load_contract(contract_path)
    digest = hashlib.sha256(contract.model_dump_json().encode("utf-8")).hexdigest()
    started = time.monotonic()
    lock = _owned_file(
        state_path.with_name(state_path.name + ".lock"), os.O_RDWR | os.O_CREAT
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = _state(state_path, contract, digest)
        # Refuse an unsafe log destination before making any state change.
        log_probe = _owned_file(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        os.close(log_probe)
        command = next((item for item in contract.commands if item.argv == argv), None)
        event = "ndm-command"
        if command is None:
            result = Response(
                stdout="", stderr="unsupported NDM command\n", exit_code=64
            )
            event = "unsupported-ndm-command"
        else:
            values = state["values"]
            if not isinstance(values, dict):
                raise NDMError("invalid state values")
            if command.kind == "read":
                response = (command.responses or {}).get(values[command.state_key])
                if response is None:
                    raise NDMError("unrecognized NDM state value")
                result = response
            else:
                if command.state_value is None or command.response is None:
                    raise NDMError("invalid write contract")
                if values[command.state_key] == command.state_value:
                    result = Response(
                        stdout="", stderr="NDM state unchanged\n", exit_code=65
                    )
                    event = "ndm-no-effect"
                else:
                    values[command.state_key] = command.state_value
                    result = command.response
                    _write_state(state_path, state)
        # Never log arbitrary argv or process environment values. Even known -c
        # arguments can contain credentials; only command identity is retained.
        _log(
            log_path,
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "run_id": run_id,
                "argv": ["ndmc", "-c", "[REDACTED]"]
                if argv[:2] == ("ndmc", "-c")
                else ["[REDACTED]"],
                "env": {},
                "exit_code": result.exit_code,
                "duration_seconds": time.monotonic() - started,
                "fixture": command.source if command is not None else None,
                "event": event,
            },
        )
        return result
    finally:
        os.close(lock)


def required_check(exit_code: int, *, required: bool = True):
    """Map unsupported process exit to an environment gap, never package FAIL."""
    from keemu.models import CheckResult

    if exit_code == 64:
        status, cause, evidence = (
            "BLOCKED",
            "environment",
            "environment-gap: unsupported-ndm-command",
        )
    elif exit_code == 0:
        status, cause, evidence = "PASS", "unknown", "known NDM fixture completed"
    elif exit_code == 65:
        status, cause, evidence = (
            "BLOCKED",
            "environment",
            "NDM state effect unavailable",
        )
    else:
        status, cause, evidence = "FAIL", "unknown", "NDM process returned nonzero"
    return CheckResult(
        id="ndm-command",
        status=status,
        cause_class=cause,
        evidence=(evidence,),
        mode="shim",
        required=required,
        duration_seconds=0,
        limitations=() if status == "PASS" else (evidence,),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Strict local NDM process shim")
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.argv or args.argv[0] != "--":
        parser.error("supply exact process argv after --")
    try:
        result = invoke(
            args.contract, args.state, args.log, args.run_id, tuple(args.argv[1:])
        )
    except (OSError, ValueError, KeyError):
        print("NDM shim input/state failure", file=sys.stderr)
        return 3
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
