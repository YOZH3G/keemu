"""Bounded P0-06 localhost-publish and persistent-state Docker probe.

Only one labeled KEEMU container is created. It binds fixed test ports to
127.0.0.1, uses no host namespaces or mounts, and is owner-verified before
cleanup. The generated report is runtime evidence under ignored reports/.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from keemu.p0_host_observer import verify as verify_host_observer
from keemu.p0_web_demo import STATE_PATH
from keemu.p0_web_demo import verify as verify_web_image

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "locks/p0-web-demo-aarch64-p006.json"
HTTP_PORT = 18080
UDP_PORT = 18081
TARGET_HTTP_PORT = 8080
TARGET_UDP_PORT = 8081


def now() -> str:
    return datetime.now(UTC).isoformat()


def _state_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def main() -> int:
    image = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    verified_image = verify_web_image(ROOT)
    run_id = "p006-" + uuid4().hex[:12]
    name = "keemu-" + run_id
    report_dir = ROOT / "reports" / (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + run_id
    )
    report_dir.mkdir(parents=True, exist_ok=False)
    report_file = report_dir / "probe.json"
    evidence: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "container_name": name,
        "started_at": now(),
        "image_id": image["image_id"],
        "image_verification": verified_image,
        "scope": (
            "p0-06 only: explicit 127.0.0.1 TCP/UDP publishing, target AArch64 "
            "web-demo, persisted container writable layer, and owner-only cleanup"
        ),
        "ports": {
            "http": {
                "host_ip": "127.0.0.1",
                "host_port": HTTP_PORT,
                "target_port": TARGET_HTTP_PORT,
            },
            "udp": {
                "host_ip": "127.0.0.1",
                "host_port": UDP_PORT,
                "target_port": TARGET_UDP_PORT,
            },
        },
        "steps": [],
    }

    def save() -> None:
        report_file.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def run(label: str, argv: list[str], timeout: int = 30) -> dict[str, object]:
        if argv[0] != "docker":
            raise ValueError("p0-06 probe may invoke only Docker via fixed argv")
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 -- fixed Docker executable and argv.
                argv,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            step: dict[str, object] = {
                "label": label,
                "argv": argv,
                "rc": completed.returncode,
                "stdout": completed.stdout.decode(errors="replace").strip(),
                "stderr": completed.stderr.decode(errors="replace").strip(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        except subprocess.TimeoutExpired as error:
            step = {
                "label": label,
                "argv": argv,
                "timeout_seconds": timeout,
                "error": str(error),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        steps = evidence["steps"]
        assert isinstance(steps, list)
        steps.append(step)
        save()
        return step

    def require(step: dict[str, object], token: str | None = None) -> str:
        stdout = str(step.get("stdout", ""))
        if step.get("rc") != 0 or (token and token not in stdout):
            raise AssertionError(
                f"{step['label']}: rc={step.get('rc')} "
                f"stdout={stdout!r} stderr={step.get('stderr')!r}"
            )
        return stdout

    observer_names: set[str] = set()

    def cleanup_observer(observer_name: str, label: str) -> None:
        ownership = run(
            label + "_observer_owner_check",
            [
                "docker",
                "inspect",
                observer_name,
                "--format",
                "{{json .Config.Labels}}",
            ],
        )
        labels = (
            json.loads(str(ownership["stdout"])) if ownership.get("rc") == 0 else {}
        )
        if (
            labels.get("org.keemu.owner") != "keemu"
            or labels.get("org.keemu.run-id") != run_id
            or labels.get("org.keemu.role") != "host-vantage-observer"
        ):
            raise AssertionError("observer ownership mismatch; refusing removal")
        running = run(
            label + "_observer_running_check",
            ["docker", "inspect", observer_name, "--format", "{{.State.Running}}"],
        )
        if running.get("stdout") == "true":
            require(
                run(
                    label + "_observer_stop",
                    ["docker", "stop", "-t", "5", observer_name],
                )
            )
        require(run(label + "_observer_remove", ["docker", "rm", observer_name]))
        absent = run(
            label + "_observer_absence",
            ["docker", "container", "inspect", observer_name],
        )
        if absent.get("rc") == 0 or "No such container" not in str(
            absent.get("stderr", "")
        ):
            raise AssertionError("observer absence not verified")
        observer_names.discard(observer_name)

    def observe_from_docker_host(expected_state: str, label: str) -> None:
        observer_name = name + "-observer-" + label
        create = [
            "docker",
            "create",
            "--name",
            observer_name,
            "--platform",
            "linux/amd64",
            "--network",
            "host",
            "--read-only",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            "org.keemu.phase=p0-06",
            "--label",
            "org.keemu.role=host-vantage-observer",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--memory=64m",
            "--memory-swap=64m",
            "--cpus=0.5",
            "--pids-limit=32",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            observer_image["image_id"],
            str(HTTP_PORT),
            str(UDP_PORT),
            expected_state,
        ]
        require(run(label + "_observer_create", create))
        observer_names.add(observer_name)
        try:
            observed = json.loads(
                require(
                    run(
                        label + "_observer_inspect",
                        ["docker", "inspect", observer_name],
                    )
                )
            )[0]
            assert observed["Image"] == observer_image["image_id"]
            assert observed["Config"]["Labels"]["org.keemu.owner"] == "keemu"
            assert observed["Config"]["Labels"]["org.keemu.run-id"] == run_id
            assert observed["HostConfig"]["NetworkMode"] == "host"
            assert observed["HostConfig"]["Privileged"] is False
            assert observed["HostConfig"]["ReadonlyRootfs"] is True
            assert observed["HostConfig"]["Binds"] in (None, [])
            assert observed["HostConfig"]["PortBindings"] in (None, {})
            assert observed["HostConfig"]["Memory"] == 64 * 1024 * 1024
            assert observed["HostConfig"]["PidsLimit"] == 32
            require(run(label + "_observer_start", ["docker", "start", observer_name]))
            require(
                run(label + "_observer_wait", ["docker", "wait", observer_name]), "0"
            )
            output = require(
                run(label + "_observer_logs", ["docker", "logs", observer_name]),
                "host-observer HTTP_OK UDP_OK state=" + expected_state,
            )
            observations = evidence.setdefault("docker_host_observations", {})
            assert isinstance(observations, dict)
            observations[label] = {
                "output": output,
                "network_mode": observed["HostConfig"]["NetworkMode"],
                "read_only": observed["HostConfig"]["ReadonlyRootfs"],
                "port_bindings": observed["HostConfig"]["PortBindings"],
            }
            save()
        finally:
            cleanup_observer(observer_name, label)

    def start_service(expected_state: str, label: str) -> int:
        service_pid = int(
            require(
                run(
                    label + "_start_target_service",
                    [
                        "docker",
                        "exec",
                        name,
                        "/bin/sh",
                        "-c",
                        "/opt/bin/web-demo-p006 8080 8081 "
                        + STATE_PATH
                        + " >/opt/var/web-demo-p006.log 2>&1 & echo $!",
                    ],
                )
            ).splitlines()[-1]
        )
        target_loopback = require(
            run(
                label + "_target_loopback_http",
                [
                    "docker",
                    "exec",
                    name,
                    "/opt/bin/busybox",
                    "wget",
                    "-qO-",
                    "http://127.0.0.1:8080/health",
                ],
            )
        )
        expected = f"keemu-web-demo\nstate={expected_state}"
        assert target_loopback == expected
        evidence[label + "_target_loopback_http"] = target_loopback
        save()
        return service_pid

    def stop_service(service_pid: int, label: str) -> None:
        require(
            run(
                label + "_stop_target_service",
                [
                    "docker",
                    "exec",
                    name,
                    "/opt/bin/busybox",
                    "kill",
                    "-TERM",
                    str(service_pid),
                ],
            )
        )
        reaped = False
        for attempt in range(30):
            step = run(
                label + f"_service_exit_poll_{attempt}",
                [
                    "docker",
                    "exec",
                    name,
                    "/bin/sh",
                    "-c",
                    f"test ! -e /proc/{service_pid}/status",
                ],
            )
            if step.get("rc") == 0:
                reaped = True
                break
            time.sleep(0.2)
        if not reaped:
            raise AssertionError(f"service {service_pid} did not exit after SIGTERM")

    created = False
    failure: str | None = None
    try:
        observer_image = verify_host_observer(ROOT)
        evidence["host_observer_verification"] = observer_image
        evidence["host_vantage_scope"] = (
            "explicitly approved, owner-labeled Docker --network=host HTTP/UDP "
            "observer only; no host mutation"
        )
        server = require(
            run(
                "docker_server",
                ["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"],
            ),
            "x86_64",
        )
        evidence["docker_server"] = server
        create = [
            "docker",
            "create",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            "org.keemu.phase=p0-06",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--publish",
            f"127.0.0.1:{HTTP_PORT}:{TARGET_HTTP_PORT}/tcp",
            "--publish",
            f"127.0.0.1:{UDP_PORT}:{TARGET_UDP_PORT}/udp",
            image["image_id"],
        ]
        require(run("create", create))
        created = True
        require(run("start", ["docker", "start", name]))
        inspected = json.loads(
            require(run("running_inspect", ["docker", "inspect", name]))
        )[0]
        assert inspected["Id"]
        assert inspected["Image"] == image["image_id"]
        assert inspected["State"]["Running"] is True
        assert inspected["Config"]["Labels"]["org.keemu.owner"] == "keemu"
        assert inspected["Config"]["Labels"]["org.keemu.run-id"] == run_id
        assert inspected["HostConfig"]["NetworkMode"] == "bridge"
        assert inspected["HostConfig"]["Privileged"] is False
        assert inspected["HostConfig"]["Memory"] == 256 * 1024 * 1024
        assert inspected["HostConfig"]["PidsLimit"] == 128
        assert inspected["HostConfig"]["Binds"] in (None, [])
        expected_ports = {
            "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(HTTP_PORT)}],
            "8081/udp": [{"HostIp": "127.0.0.1", "HostPort": str(UDP_PORT)}],
        }
        assert inspected["HostConfig"]["PortBindings"] == expected_ports
        assert inspected["NetworkSettings"]["Ports"] == expected_ports
        evidence["running_summary"] = {
            "container_id": inspected["Id"],
            "state": inspected["State"],
            "host_config": {
                key: inspected["HostConfig"][key]
                for key in (
                    "NetworkMode",
                    "Privileged",
                    "Memory",
                    "PidsLimit",
                    "Binds",
                    "CapDrop",
                )
            },
            "port_bindings": expected_ports,
        }
        save()
        require(run("docker_port", ["docker", "port", name]))

        first_pid = start_service("initial", "first")
        observe_from_docker_host("initial", "first")

        persisted_state = "p006-" + run_id.rsplit("-", 1)[1]
        state_write = require(
            run(
                "state_write_target_loopback",
                [
                    "docker",
                    "exec",
                    name,
                    "/opt/bin/busybox",
                    "wget",
                    "-qO-",
                    "--post-data=",
                    "http://127.0.0.1:8080/state?value=" + persisted_state,
                ],
            )
        )
        assert state_write == f"keemu-web-demo\nstate={persisted_state}"
        evidence["state_write_target_loopback"] = state_write
        observe_from_docker_host(persisted_state, "state_write")
        state_before_restart = require(
            run(
                "state_before_service_restart",
                ["docker", "exec", name, "/opt/bin/busybox", "cat", STATE_PATH],
            )
        )
        assert state_before_restart == persisted_state
        evidence["state_before_service_restart_sha256"] = _state_sha256(
            state_before_restart + "\n"
        )
        save()

        stop_service(first_pid, "service_restart")
        second_pid = start_service(persisted_state, "service_restart")
        observe_from_docker_host(persisted_state, "service_restart")
        stop_service(second_pid, "pre_down")

        require(run("down_stop", ["docker", "stop", "-t", "5", name], 20))
        down_state = json.loads(
            require(
                run(
                    "down_state",
                    ["docker", "inspect", name, "--format", "{{json .State}}"],
                )
            )
        )
        assert down_state["Status"] == "exited" and down_state["ExitCode"] == 0
        assert down_state["Running"] is False and down_state["OOMKilled"] is False
        evidence["down_summary"] = down_state
        save()

        require(run("up_start_same_container", ["docker", "start", name]))
        after_up = json.loads(
            require(run("up_inspect", ["docker", "inspect", name]))
        )[0]
        assert after_up["Id"] == inspected["Id"]
        assert after_up["State"]["Running"] is True
        assert after_up["HostConfig"]["PortBindings"] == expected_ports
        state_after_up = require(
            run(
                "state_after_down_up",
                ["docker", "exec", name, "/opt/bin/busybox", "cat", STATE_PATH],
            )
        )
        assert state_after_up == persisted_state
        assert _state_sha256(state_after_up + "\n") == evidence[
            "state_before_service_restart_sha256"
        ]
        evidence["state_after_down_up_sha256"] = _state_sha256(state_after_up + "\n")
        final_pid = start_service(persisted_state, "after_down_up")
        observe_from_docker_host(persisted_state, "after_down_up")
        stop_service(final_pid, "final_service")
        evidence["target_http_udp_and_persistence_verified"] = True
        save()
    except Exception as error:
        failure = repr(error)
        evidence["failure"] = failure
        save()
    finally:
        for observer_name in sorted(observer_names):
            try:
                cleanup_observer(observer_name, "final_cleanup")
            except Exception as error:  # pragma: no cover - defensive cleanup evidence.
                failure = failure or repr(error)
        if created:
            ownership = run(
                "owner_check_before_cleanup",
                ["docker", "inspect", name, "--format", "{{json .Config.Labels}}"],
            )
            labels = (
                json.loads(str(ownership["stdout"]))
                if ownership.get("rc") == 0
                else {}
            )
            if (
                labels.get("org.keemu.owner") == "keemu"
                and labels.get("org.keemu.run-id") == run_id
            ):
                running = run(
                    "running_before_cleanup",
                    ["docker", "inspect", name, "--format", "{{.State.Running}}"],
                )
                if running.get("stdout") == "true":
                    if run(
                        "cleanup_stop", ["docker", "stop", "-t", "5", name], 20
                    ).get("rc") != 0:
                        failure = failure or "cleanup docker stop failed"
                if run("cleanup_remove", ["docker", "rm", name]).get("rc") != 0:
                    failure = failure or "cleanup docker rm failed"
                absent = run(
                    "verify_container_absent",
                    ["docker", "container", "inspect", name],
                )
                if absent.get("rc") == 0 or "No such container" not in str(
                    absent.get("stderr", "")
                ):
                    failure = failure or "container absence not verified"
            else:
                failure = failure or "ownership mismatch; refused container removal"
    evidence["finished_at"] = now()
    evidence["result"] = "FAIL" if failure else "PASS"
    if failure:
        evidence["failure"] = failure
    save()
    print(report_file)
    print(
        f"result={evidence['result']} "
        f"verified={evidence.get('target_http_udp_and_persistence_verified', False)} "
        f"failure={failure}"
    )
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main())
