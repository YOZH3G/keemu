"""Bounded p0-05 Docker/binfmt lifecycle probe; run explicitly, not via discover.

Only the locked mixed image and three labeled project containers
are used. No host registration, network, public port or foreign resource is changed.
Evidence is written incrementally under the ignored reports/ directory.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from keemu.p0_image import container_create_argv
from keemu.p0_runtime_image import verify as verify_runtime_image

ROOT = Path(__file__).resolve().parents[2]
IMAGE_LOCK = ROOT / "locks/p0-mixed-image-aarch64-p005.json"


def now() -> str:
    return datetime.now(UTC).isoformat()


def main() -> int:
    image = json.loads(IMAGE_LOCK.read_text())
    verified_image = verify_runtime_image(ROOT)
    run_id = "p005-" + uuid4().hex[:12]
    name = "keemu-" + run_id
    report_dir = (
        ROOT / "reports" / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + run_id)
    )
    report_dir.mkdir(parents=True, exist_ok=False)
    report_file = report_dir / "probe.json"
    evidence = {
        "schema_version": 1,
        "run_id": run_id,
        "container_name": name,
        "started_at": now(),
        "image_id": image["image_id"],
        "image_verification": verified_image,
        "scope": (
            "p0-05 only: network=none, no privileged container or host mutation; "
            "/tmp tmpfs exec for shebang test"
        ),
        "steps": [],
    }

    def save() -> None:
        report_file.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def run(label: str, argv: list[str], timeout: int = 30) -> dict:
        if argv[0] != "docker":
            raise ValueError("probe may invoke only Docker via fixed argv")
        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 -- fixed docker executable, no shell.
                argv, capture_output=True, timeout=timeout, check=False
            )
            step = {
                "label": label,
                "argv": argv,
                "rc": proc.returncode,
                "stdout": proc.stdout.decode(errors="replace").strip(),
                "stderr": proc.stderr.decode(errors="replace").strip(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except subprocess.TimeoutExpired as exc:
            step = {
                "label": label,
                "argv": argv,
                "timeout_seconds": timeout,
                "error": str(exc),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        evidence["steps"].append(step)
        save()
        return step

    def require(step: dict, token: str | None = None) -> str:
        if step.get("rc") != 0 or (token and token not in step["stdout"]):
            raise AssertionError(
                f"{step['label']}: rc={step.get('rc')} "
                f"stdout={step.get('stdout')!r} stderr={step.get('stderr')!r}"
            )
        return step["stdout"]

    def create_args(
        container: str, identity: str, *, executable_tmpfs: bool = False
    ) -> list[str]:
        argv = container_create_argv(container, image["image_id"], identity)
        phase = "org.keemu.phase=p0-04"
        assert argv.count(phase) == 1
        argv[argv.index(phase)] = "org.keemu.phase=p0-05"
        if executable_tmpfs:
            # Docker applies noexec to /tmp by default; limit exec to this
            # disposable test mount for actual kernel shebang execution.
            tmpfs = "--tmpfs=/tmp:rw,nosuid,nodev,size=16m"
            assert argv.count(tmpfs) == 1
            argv[argv.index(tmpfs)] = "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=16m"
        return argv

    created = False
    failure: str | None = None
    server_version: str | None = None
    try:
        server_info = require(
            run(
                "docker_server",
                ["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"],
            ),
            "x86_64",
        )
        server_version = server_info.split()[0]
        require(run("create", create_args(name, run_id, executable_tmpfs=True)))
        created = True
        require(run("start", ["docker", "start", name]))
        inspected = json.loads(
            require(run("running_inspect", ["docker", "inspect", name]))
        )[0]
        assert inspected["Image"] == image["image_id"]
        assert inspected["State"]["Running"] and inspected["State"]["Pid"] > 0
        assert inspected["Config"]["Labels"]["org.keemu.run-id"] == run_id
        assert inspected["Config"]["Labels"]["org.keemu.owner"] == "keemu"
        assert inspected["HostConfig"]["NetworkMode"] == "none"
        assert inspected["HostConfig"]["Privileged"] is False
        assert inspected["HostConfig"]["Memory"] == 256 * 1024 * 1024
        assert inspected["HostConfig"]["PidsLimit"] == 128
        evidence["running_summary"] = {
            "id": inspected["Id"],
            "state": inspected["State"],
            "host_config": {
                k: inspected["HostConfig"][k]
                for k in (
                    "NetworkMode",
                    "Privileged",
                    "Memory",
                    "PidsLimit",
                    "NanoCpus",
                    "ReadonlyRootfs",
                    "CapDrop",
                )
            },
        }
        save()
        shell_script = (
            "set -eu; echo TARGET_SHELL_OK; /opt/bin/opkg --version; "
            "/opt/bin/busybox uname -m; /opt/bin/busybox echo CHILD_ELF_OK; "
            "printf '#!/bin/sh\\nexec /opt/bin/busybox echo SHEBANG_OK\\n' "
            "> /tmp/p0-shebang; "
            "/opt/bin/busybox chmod 755 /tmp/p0-shebang; /tmp/p0-shebang"
        )
        target_output = require(
            run(
                "shell_child_elf_shebang",
                ["docker", "exec", name, "/bin/sh", "-c", shell_script],
                30,
            )
        )
        assert all(
            token in target_output
            for token in ("TARGET_SHELL_OK", "CHILD_ELF_OK", "SHEBANG_OK")
        )
        assert "aarch64" in target_output.lower(), target_output
        # The parent docker-exec shell exits; these target children must survive it.
        daemon_pid = int(
            require(
                run(
                    "spawn_target_daemon",
                    [
                        "docker",
                        "exec",
                        name,
                        "/bin/sh",
                        "-c",
                        "(/opt/bin/busybox sleep 30) </dev/null "
                        ">/dev/null 2>&1 & echo $!",
                    ],
                )
            ).splitlines()[-1]
        )
        short_pid = int(
            require(
                run(
                    "spawn_short_orphan",
                    [
                        "docker",
                        "exec",
                        name,
                        "/bin/sh",
                        "-c",
                        "(/opt/bin/busybox sleep 2) </dev/null "
                        ">/dev/null 2>&1 & echo $!",
                    ],
                )
            ).splitlines()[-1]
        )
        evidence["daemon_pid"] = daemon_pid
        evidence["short_orphan_pid"] = short_pid
        save()
        short_state = require(
            run(
                "short_orphan_adopted_before_exit",
                [
                    "docker",
                    "exec",
                    name,
                    "/bin/sh",
                    "-c",
                    f"/opt/bin/busybox grep -E '^(State|PPid):' "
                    f"/proc/{short_pid}/status",
                ],
            )
        )
        assert "PPid:\t1" in short_state and "State:\tS" in short_state, short_state
        state = require(
            run(
                "daemon_after_parent_exit",
                [
                    "docker",
                    "exec",
                    name,
                    "/bin/sh",
                    "-c",
                    f"/opt/bin/busybox grep -E '^(Name|State|PPid):' "
                    f"/proc/{daemon_pid}/status",
                ],
            )
        )
        assert "PPid:\t1" in state and "State:\tZ" not in state, state
        reaped = False
        for attempt in range(30):
            step = run(
                f"orphan_reaped_poll_{attempt}",
                [
                    "docker",
                    "exec",
                    name,
                    "/bin/sh",
                    "-c",
                    f"test ! -e /proc/{short_pid}/status",
                ],
            )
            if step["rc"] == 0:
                reaped = True
                break
            time.sleep(0.2)
        assert reaped, f"adopted child {short_pid} remained in procfs after exit"
        require(
            run(
                "daemon_still_alive",
                [
                    "docker",
                    "exec",
                    name,
                    "/bin/sh",
                    "-c",
                    f"/opt/bin/busybox grep -E '^(State|PPid):' "
                    f"/proc/{daemon_pid}/status",
                ],
            ),
            "PPid:\t1",
        )
        evidence["target_and_reaping_verified"] = True
        save()
    except Exception as exc:
        failure = repr(exc)
        evidence["failure"] = failure
        save()
    finally:
        if created:
            step = run(
                "owner_check_before_cleanup",
                ["docker", "inspect", name, "--format", "{{json .Config.Labels}}"],
            )
            labels = json.loads(step["stdout"]) if step.get("rc") == 0 else {}
            if (
                labels.get("org.keemu.owner") == "keemu"
                and labels.get("org.keemu.run-id") == run_id
            ):
                if (
                    run("stop_SIGTERM", ["docker", "stop", "-t", "5", name], 20).get(
                        "rc"
                    )
                    != 0
                ):
                    failure = failure or "docker stop failed"
                state = run(
                    "stopped_state",
                    ["docker", "inspect", name, "--format", "{{json .State}}"],
                )
                if state.get("rc") == 0:
                    stopped = json.loads(state["stdout"])
                    evidence["stopped_summary"] = stopped
                    if (
                        stopped["Running"]
                        or stopped["ExitCode"] != 0
                        or stopped["OOMKilled"]
                    ):
                        failure = failure or f"unclean container shutdown: {stopped}"
                else:
                    failure = failure or "stopped inspect failed"
                if run("remove_owned_container", ["docker", "rm", name]).get("rc") != 0:
                    failure = failure or "docker rm failed"
                absent = run(
                    "verify_container_absent", ["docker", "container", "inspect", name]
                )
                if absent.get("rc") == 0 or "No such container" not in absent.get(
                    "stderr", ""
                ):
                    failure = failure or "container absence not verified"
            else:
                failure = failure or "ownership mismatch; refused container removal"

    def signal_case(suffix: str, *, expected_exit: int, signal_pid1: bool) -> None:
        case_run = run_id + "-" + suffix
        case_name = "keemu-" + case_run
        case_created = False
        try:
            require(run(suffix + "_create", create_args(case_name, case_run)))
            case_created = True
            require(run(suffix + "_start", ["docker", "start", case_name]))
            children = require(
                run(
                    suffix + "_pid1_children",
                    [
                        "docker",
                        "exec",
                        case_name,
                        "/bin/sh",
                        "-c",
                        "/opt/bin/busybox cat /proc/1/task/1/children",
                    ],
                )
            )
            keeper_pid = int(children.split()[0])
            keeper_status = require(
                run(
                    suffix + "_keeper_status",
                    [
                        "docker",
                        "exec",
                        case_name,
                        "/bin/sh",
                        "-c",
                        f"/opt/bin/busybox grep -E '^(Name|PPid):' "
                        f"/proc/{keeper_pid}/status",
                    ],
                )
            )
            assert "PPid:\t1" in keeper_status and "Name:\tinit" in keeper_status, (
                keeper_status
            )
            if signal_pid1:
                require(
                    run(
                        suffix + "_signal_pid1",
                        ["docker", "kill", "--signal=SIGINT", case_name],
                    )
                )
            else:
                killed = run(
                    suffix + "_kill_keeper",
                    [
                        "docker",
                        "exec",
                        case_name,
                        "/opt/bin/busybox",
                        "kill",
                        "-TERM",
                        str(keeper_pid),
                    ],
                )
                # PID 1 may exit as the exec process returns, tearing down its
                # namespace and giving docker exec 137. The container exit is
                # checked independently below; exec status alone is not proof.
                assert killed.get("rc") in (0, 137), killed
            waited = require(run(suffix + "_wait", ["docker", "wait", case_name], 10))
            assert waited == str(expected_exit), waited
            state = json.loads(
                require(
                    run(
                        suffix + "_exited_state",
                        ["docker", "inspect", case_name, "--format", "{{json .State}}"],
                    )
                )
            )
            assert state["Status"] == "exited" and state["ExitCode"] == expected_exit
            assert (
                not state["Running"] and not state["OOMKilled"] and not state["Dead"]
            ), state
            evidence[suffix + "_summary"] = {"keeper_pid": keeper_pid, "state": state}
            save()
        finally:
            if case_created:
                labels_step = run(
                    suffix + "_owner_check",
                    [
                        "docker",
                        "inspect",
                        case_name,
                        "--format",
                        "{{json .Config.Labels}}",
                    ],
                )
                labels = (
                    json.loads(labels_step["stdout"])
                    if labels_step.get("rc") == 0
                    else {}
                )
                if (
                    labels.get("org.keemu.owner") != "keemu"
                    or labels.get("org.keemu.run-id") != case_run
                ):
                    raise RuntimeError(
                        "signal probe ownership mismatch; refused removal"
                    )
                running = run(
                    suffix + "_running_before_cleanup",
                    ["docker", "inspect", case_name, "--format", "{{.State.Running}}"],
                )
                if running.get("stdout") == "true":
                    require(
                        run(
                            suffix + "_stop_after_failure",
                            ["docker", "stop", "-t", "5", case_name],
                            20,
                        )
                    )
                require(run(suffix + "_remove", ["docker", "rm", case_name]))
                absent = run(
                    suffix + "_verify_absent",
                    ["docker", "container", "inspect", case_name],
                )
                assert absent.get("rc") != 0 and "No such container" in absent.get(
                    "stderr", ""
                ), "signal probe container absence not verified"

    if not failure:
        try:
            # Killing the keeper alone must be a failure; signaling PID 1 must
            # take the successful forwarding path in the locked native source.
            signal_case("keeper_death", expected_exit=1, signal_pid1=False)
            signal_case("pid1_SIGINT", expected_exit=0, signal_pid1=True)
            evidence["signal_forwarding_differential_verified"] = True
        except Exception as exc:
            failure = repr(exc)
    try:
        require(
            run(
                "daemon_survival", ["docker", "info", "--format", "{{.ServerVersion}}"]
            ),
            server_version,
        )
    except Exception as exc:
        failure = failure or repr(exc)
    evidence["finished_at"] = now()
    evidence["result"] = "FAIL" if failure else "PASS"
    if failure:
        evidence["failure"] = failure
    save()
    print(report_file)
    print(
        f"result={evidence['result']} "
        f"target={evidence.get('target_and_reaping_verified', False)} "
        f"failure={failure}"
    )
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main())
