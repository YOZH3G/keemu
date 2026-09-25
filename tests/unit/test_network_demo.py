"""Network-demo fixture tests. Packet verdicts require separate m1c-26 proof."""

import hashlib
import http.client
import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError
from keemu.network_demo import flow, rule
from keemu.topology import Topology

BINARY = Path(".runtime/m1c24/network-demo-native")


def request(port, method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        return response.status, response.read().decode()
    finally:
        connection.close()


def start(port, state):
    process = subprocess.Popen(  # noqa: S603 -- locally built fixture only
        [
            str(BINARY.resolve()),
            "--queue",
            "42",
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--state",
            str(state),
            "--api-only",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for _ in range(50):
        if process.poll() is not None:
            raise AssertionError(process.communicate())
        try:
            if request(port, "GET", "/api/state")[0] == 200:
                return process
        except (OSError, http.client.HTTPException):
            time.sleep(0.02)
    process.terminate()
    process.wait(timeout=3)
    raise AssertionError("API readiness timeout")


def test_native_api_only_state_ui_and_service_restart(tmp_path):
    if not BINARY.exists():
        pytest.skip("build native network-demo with gcc first")
    state = tmp_path / "mode"
    state.write_text("accept\n")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = start(port, state)
    try:
        status, raw = request(port, "GET", "/api/state")
        assert status == 200
        assert json.loads(raw) == {
            "mode": "accept",
            "queue_ready": False,
            "accepted": 0,
            "dropped": 0,
        }
        status, page = request(port, "GET", "/")
        assert status == 200 and "Network-demo" in page and "mode" in page
        assert request(port, "GET", "/health") == (503, "queue-unavailable\n")
        status, raw = request(port, "POST", "/api/mode", "mode=drop")
        assert status == 200 and json.loads(raw)["mode"] == "drop", raw
        assert state.read_text() == "drop\n"
        assert request(port, "POST", "/api/mode", "mode=invalid")[0] == 400
        assert state.read_text() == "drop\n"
    finally:
        process.terminate()
        process.wait(timeout=3)
        process.communicate(timeout=3)
    process = start(port, state)
    try:
        status, raw = request(port, "GET", "/api/state")
        assert status == 200 and json.loads(raw)["mode"] == "drop"
        assert json.loads(raw)["queue_ready"] is False
    finally:
        process.terminate()
        process.wait(timeout=3)
        process.communicate(timeout=3)


def test_scoped_flow_excludes_control_health_and_cannot_bypass():
    topo = Topology("m1c24-test", "10.224.0.0/24", "10.224.1.0/24", {}, {})
    assert flow(topo).router == "10.224.0.2"
    assert rule(topo) == [
        "/opt/sbin/iptables",
        "-I",
        "FORWARD",
        "-s",
        "10.224.0.3/32",
        "-d",
        "10.224.1.3/32",
        "-p",
        "tcp",
        "--dport",
        "8080",
        "-j",
        "NFQUEUE",
        "--queue-num",
        "42",
    ]
    assert rule(topo, delete=True)[1] == "-D"
    assert "9090" not in rule(topo)
    assert "--queue-bypass" not in rule(topo)
    with pytest.raises(DockerBoundaryError, match="invalid network-demo topology"):
        rule(Topology("bad", "10.224.0.0/24", "10.224.0.0/24", {}, {}))


def test_p0_consumer_is_unmodified():
    original = Path("fixtures/sources/nfqueue/nfqueue_consumer.c")
    assert hashlib.sha256(original.read_bytes()).hexdigest() == (
        "01c077324c48fe467ae69410e01f32348c8a394f210ab9717ba0b1698a2e1078"
    )


def test_fixture_lock_and_flow_contract():
    lock = json.loads(Path("locks/m1c24-network-demo-aarch64.json").read_text())
    for item in (*lock["sources"], lock["recipe"]):
        assert (
            hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        )
    assert (
        hashlib.sha256(Path("locks/m1a-init-aarch64.json").read_bytes()).hexdigest()
        == (lock["base_lock_sha256"])
    )
    scenario = json.loads(Path("fixtures/network-demo/scenario.json").read_text())
    assert scenario["flow"]["queue_bypass"] is False
    assert scenario["flow"]["destination_port"] != scenario["api"]["port"]
    assert scenario["persistence"] == ["/opt/etc/network-demo/mode"]
