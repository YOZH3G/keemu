"""Bounded P0-06 localhost-publish and persistent-state Docker probe.

Only one labeled KEEMU container is created. It binds fixed test ports to
127.0.0.1, uses no host namespaces or mounts, and is owner-verified before
cleanup. The generated report is runtime evidence under ignored reports/.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

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


def _port_preflight() -> None:
    for kind, port in ((socket.SOCK_STREAM, HTTP_PORT), (socket.SOCK_DGRAM, UDP_PORT)):
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.bind(("127.0.0.1", port))


def _http(method: str, path: str) -> tuple[int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=2)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def _udp(payload: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(payload, ("127.0.0.1", UDP_PORT))
        response, peer = client.recvfrom(1024)
    if peer[0] != "127.0.0.1":
        raise AssertionError(f"unexpected UDP source: {peer!r}")
    return response


def _tcp_refused() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=1):
            return False
    except OSError:
        return True


def _wait_http(expected: str, timeout: float = 15) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            status, body = _http("GET", "/health")
            if status == 200 and body == expected:
                return {"status": status, "body": body}
            last_error = f"status={status} body={body!r}"
        except OSError as error:
            last_error = repr(error)
        time.sleep(0.2)
    raise AssertionError(f"HTTP readiness failed: {last_error}")


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
        ready = _wait_http(f"keemu-web-demo\nstate={expected_state}\n")
        evidence[label + "_http_readiness"] = ready
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
        _port_preflight()
        evidence["port_preflight"] = "127.0.0.1 TCP and UDP ports available"
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
        first_udp = _udp(b"first-udp")
        assert first_udp == b"keemu-udp:first-udp"
        evidence["first_udp"] = first_udp.decode("ascii")
        save()

        persisted_state = "p006-" + run_id.rsplit("-", 1)[1]
        status, body = _http("POST", "/state?value=" + persisted_state)
        assert status == 200 and body == f"keemu-web-demo\nstate={persisted_state}\n"
        evidence["state_write"] = {"status": status, "body": body}
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
        assert _tcp_refused(), "localhost HTTP port still accepted after docker stop"
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
        final_udp = _udp(b"after-down-up")
        assert final_udp == b"keemu-udp:after-down-up"
        evidence["after_down_up_udp"] = final_udp.decode("ascii")
        stop_service(final_pid, "final_service")
        evidence["target_http_udp_and_persistence_verified"] = True
        save()
    except Exception as error:
        failure = repr(error)
        evidence["failure"] = failure
        save()
    finally:
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
