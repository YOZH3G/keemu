"""Opt-in, host-local synthetic event harness; never a device/target hook.

Only explicitly hash-pinned scripts in an owner-only fixture directory run.
No Docker, kernel firewall, host event directory, or inherited environment is used.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from keemu.input_locks import _reject_constant, _unique_object
from keemu.scenarios import InputModel


class EventError(ValueError):
    """Unsafe or inconsistent synthetic event fixture."""


class Handler(InputModel):
    name: str = Field(pattern=r"^[0-9]{2}-[a-z0-9-]{1,64}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable: bool


class EventContract(InputModel):
    schema_version: Literal[1]
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    source: str = Field(pattern=r"^synthetic:[a-z0-9][a-z0-9._-]{0,127}$")
    event: Literal["boot", "netfilter"]
    handler_dir: Literal["handlers"]
    selector: Literal["[0-9][0-9]-*"]
    cwd: Literal["work"]
    path: Literal["/usr/bin:/bin"]
    type: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    table: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    timeout_seconds: int = Field(ge=1, le=30)
    nonexecutable: Literal["skip", "fail"]
    on_error: Literal["stop", "continue"]
    handlers: tuple[Handler, ...] = Field(min_length=1, max_length=64, strict=False)
    before: tuple[Annotated[tuple[str, ...], Field(strict=False)], ...] = Field(
        min_length=1, max_length=8, strict=False
    )
    after: tuple[str, ...] = Field(max_length=128, strict=False)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if (self.event == "netfilter") != (
            self.type is not None and self.table is not None
        ) or (self.event == "boot" and (self.type or self.table)):
            raise ValueError(
                "netfilter requires both type and table; boot requires neither"
            )
        names = [item.name for item in self.handlers]
        if names != sorted(set(names)):
            raise ValueError("handlers must be unique and in filename order")
        if not any(handler.executable for handler in self.handlers):
            raise ValueError("event requires an executable handler")
        if len(set(self.after)) != len(self.after) or not self.after:
            raise ValueError("expected state must contain unique rules")
        for state in self.before:
            if len(state) > 128 or len(state) != len(set(state)):
                raise ValueError("before state contains duplicate rules")
        if tuple(self.after) not in self.before:
            raise ValueError("repeat must accept already restored state")
        for rule in (*self.after, *(r for state in self.before for r in state)):
            if not re.fullmatch(r"[a-z][a-z0-9:_-]{0,127}", rule):
                raise ValueError("invalid synthetic rule identifier")
        return self


def _read(path: Path, limit: int) -> object:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink != 1:
            raise EventError("unsafe or oversized event file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise EventError("oversized event file")
        return json.loads(
            data, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    finally:
        os.close(fd)


def load_contract(path: Path) -> EventContract:
    try:
        return EventContract.model_validate(_read(path, 1024 * 1024))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EventError("invalid synthetic event contract") from exc


def _private_file(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        os.close(fd)
        raise EventError("unsafe event state or log")
    return fd


def _log(path: Path, **fields: object) -> None:
    fd = _private_file(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    try:
        line = (
            json.dumps(
                {"timestamp": datetime.now(UTC).isoformat(), **fields},
                sort_keys=True,
            )
            + "\n"
        ).encode()
        if len(line) > 4096 or os.write(fd, line) != len(line):
            raise EventError("event log write failed")
        os.fsync(fd)
    finally:
        os.close(fd)


def _state(path: Path) -> tuple[str, ...]:
    data = _read(path, 64 * 1024)
    if (
        not isinstance(data, dict)
        or set(data) != {"rules"}
        or not isinstance(data["rules"], list)
        or any(not isinstance(rule, str) for rule in data["rules"])
    ):
        raise EventError("invalid synthetic state")
    return tuple(data["rules"])


def _directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise EventError("fixture directories must be owner-only and not symlinks")


def _verify_handlers(
    directory: Path, contract: EventContract
) -> list[tuple[Path, Handler]]:
    paths = sorted(directory.iterdir(), key=lambda p: p.name)
    if [p.name for p in paths] != [h.name for h in contract.handlers]:
        raise EventError("handler selection differs from pinned manifest")
    selected = []
    for path, handler in zip(paths, contract.handlers, strict=True):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size > 64 * 1024
                or bool(info.st_mode & 0o111) != handler.executable
            ):
                raise EventError("handler type/mode differs from pinned manifest")
            with os.fdopen(os.dup(fd), "rb") as stream:
                digest = hashlib.sha256(stream.read(64 * 1024 + 1)).hexdigest()
            if digest != handler.sha256:
                raise EventError("handler hash differs from pinned manifest")
        finally:
            os.close(fd)
        selected.append((path, handler))
    return selected


def dispatch(
    contract_path: Path, root: Path, log_path: Path, run_id: str, event: str
) -> str:
    """Dispatch one opted-in synthetic fixture; return PASS, FAIL or BLOCKED."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", run_id):
        raise EventError("invalid run ID")
    if not root.is_absolute() or not log_path.is_absolute():
        raise EventError("synthetic fixture root and log must be absolute")
    _directory(root)
    if log_path.parent != root or log_path.name != "events.jsonl":
        raise EventError("event log must be root/events.jsonl")
    contract = load_contract(contract_path)
    if event != contract.event:
        _log(
            log_path,
            run_id=run_id,
            event="[unsupported]",
            fixture=contract.source,
            handler=None,
            argv=[],
            env={},
            exit_code=4,
            status="BLOCKED",
            reason="unsupported-event",
            duration_seconds=0,
        )
        return "BLOCKED"  # No handler for an undeclared event; no fallback.
    directory, cwd = root / contract.handler_dir, root / contract.cwd
    _directory(directory)
    _directory(cwd)
    lock = _private_file(root / ".events.lock", os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        event_started = time.monotonic()
        selected = _verify_handlers(directory, contract)
        before = _state(root / "state.json")
        if before not in contract.before or len(set(before)) != len(before):
            raise EventError("unrecognized pre-event synthetic state")
        # Caller environment is deliberately discarded. Only declared nonsecret
        # event values and the isolated fixture-state path reach each handler.
        env = {
            "PATH": contract.path,
            "KEEMU_EVENT": event,
            "KEEMU_STATE_PATH": str(root / "state.json"),
        }
        if contract.type is not None and contract.table is not None:
            env.update(KEEMU_TYPE=contract.type, KEEMU_TABLE=contract.table)
        status = "PASS"
        for path, handler in selected:
            started = time.monotonic()
            code: int | None = None
            timed_out = False
            if not handler.executable:
                outcome = "SKIP" if contract.nonexecutable == "skip" else "FAIL"
            else:
                # Start a separate process group so a timed-out script and its
                # children cannot outlive this timeout as a group.
                process = subprocess.Popen(  # noqa: S603 -- SHA-256 pinned fixture
                    [str(path)],
                    cwd=cwd,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    code = process.wait(timeout=contract.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                outcome = "PASS" if code == 0 and not timed_out else "FAIL"
            _log(
                log_path,
                run_id=run_id,
                event=event,
                fixture=contract.source,
                handler=handler.name,
                argv=[handler.name],
                cwd=contract.cwd,
                env={
                    key: env[key]
                    for key in ("KEEMU_EVENT", "KEEMU_TYPE", "KEEMU_TABLE")
                    if key in env
                },
                exit_code=code,
                timed_out=timed_out,
                status=outcome,
                duration_seconds=time.monotonic() - started,
            )
            if outcome == "FAIL":
                status = "FAIL"
                if contract.on_error == "stop":
                    break
        after = _state(root / "state.json")
        if after != contract.after or len(set(after)) != len(after):
            status = "FAIL"
        _log(
            log_path,
            run_id=run_id,
            event=event,
            fixture=contract.source,
            handler=None,
            argv=[],
            env={},
            exit_code=0 if status == "PASS" else 1,
            status=status,
            before_matches=True,
            after_matches=after == contract.after,
            duration_seconds=time.monotonic() - event_started,
        )
        return status
    finally:
        os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Opt-in synthetic event fixture runner"
    )
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--event", required=True)
    args = parser.parse_args()
    try:
        result = dispatch(args.contract, args.root, args.log, args.run_id, args.event)
    except (OSError, ValueError) as exc:
        print(f"synthetic event input/execution failure: {exc}", file=sys.stderr)
        return 3
    print(result)
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 4}[result]


if __name__ == "__main__":
    raise SystemExit(main())
