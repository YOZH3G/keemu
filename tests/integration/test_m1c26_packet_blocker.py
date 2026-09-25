"""Opt-in routed packet preflight; never substitute API-only state for verdicts.

No queue bind or rule is attempted while host NFQUEUE modules are not loaded.
The test captures bounded baseline traffic and the target/native socket differential.
"""

import hashlib
import ipaddress
import json
import os
import platform
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, _exec
from keemu.network_demo import NetworkDemo, flow
from keemu.topology import BUSYBOX, cleanup, create

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"
DEMO = Path(".runtime/m1c24/network-demo-aarch64")
WEB = Path(".runtime/p0/fixtures/aarch64/web-demo-p006")
SOCKETS = Path(".runtime/p0/p007-1ed1391a9dd4")
SOCKET_HASHES = {
    "native": "378db5054cec52bc8422845c3bef0fe7dec032188a7c35a3adf32b8113e28167",
    "target": "c82cf028a2eceb93e45b54e3bb883ca3a6edde2b0949b73884d3ed1f96857655",
}
MODULES = ("nfnetlink_queue", "xt_NFQUEUE", "nft_queue")
EVIDENCE = Path("docs/evidence/m1c26-packet-blocker.json")
EVIDENCE_SHA256 = "911a88be488b03c380779181c41d7b5e282dcd37a12a0f04d03083f5579bb100"


def test_frozen_packet_blocker_record():
    raw = EVIDENCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EVIDENCE_SHA256
    record = json.loads(raw)
    assert record["result"] == "BLOCKED"
    assert (
        record["baseline_only"]["router_forwarded_datagrams"][1]
        > (record["baseline_only"]["router_forwarded_datagrams"][0])
    )
    assert record["native_socket"]["exit_code"] == 0
    assert record["target_socket"]["exit_code"] == 1
    assert "Protocol not supported" in record["target_queue_start"]
    assert record["module_before"] == record["module_after"]
    assert record["consumer_counters"].startswith("NOT RUN:")
    assert record["kernel_queue_counters"].startswith("NOT RUN:")
    local = Path("reports") / f"{record['run_id']}-packet-blocker.json"
    if local.exists():
        assert local.read_bytes() == raw


def _modules():
    names = {line.split()[0] for line in Path("/proc/modules").read_text().splitlines()}
    return {
        name: {
            "proc_modules": name in names,
            "sys_module": Path("/sys/module", name).exists(),
        }
        for name in MODULES
    }


def _forwarded(runtime, router):
    text = runtime.exec(router, [BUSYBOX, "cat", "/proc/net/snmp"]).stdout.decode()
    lines = [line.split() for line in text.splitlines() if line.startswith("Ip:")]
    return int(dict(zip(lines[0][1:], lines[1][1:], strict=True))["ForwDatagrams"])


def _copy(runtime, router, source, target):
    runtime.inspect("container", router)
    _exec(["docker", "container", "cp", "--", str(source), f"{router}:{target}"])
    runtime.inspect("container", router)
    observed = (
        runtime.exec(router, [BUSYBOX, "sha256sum", target]).stdout.decode().split()[0]
    )
    assert observed == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.docker
def test_routed_baseline_and_target_queue_blocker():
    if os.getenv("KEEMU_TEST_PACKET_M1C26") != "1":
        pytest.skip("opt in to m1c-26 bounded packet preflight")
    before_modules = _modules()
    assert all(not any(value.values()) for value in before_modules.values()), (
        "NFQUEUE modules already loaded: require a separately reviewed packet procedure"
    )
    lock = json.loads(Path("locks/m1c24-network-demo-aarch64.json").read_text())
    demo_hash = hashlib.sha256(DEMO.read_bytes()).hexdigest()
    assert demo_hash == lock["binary"]["sha256"]
    assert hashlib.sha256(WEB.read_bytes()).hexdigest() == (
        "0856c7af577b6fb1675ca6266686853863aee23e1cbe15a207c64ed0089cbf36"
    )
    for kind, expected in SOCKET_HASHES.items():
        assert (
            hashlib.sha256((SOCKETS / f"{kind}_socket").read_bytes()).hexdigest()
            == expected
        )
    run_id = "m1c26-" + uuid.uuid4().hex[:12]
    containers_before = DockerRuntime.listed_ids("container")
    networks_before = DockerRuntime.listed_ids("network")
    evidence = {
        "run_id": run_id,
        "result": "BLOCKED",
        "kernel": platform.release(),
        "image_id": IMAGE,
        "network_demo_sha256": demo_hash,
        "socket_probe_sha256": SOCKET_HASHES,
        "module_before": before_modules,
        "scope": (
            "routed baseline and same-router native/target socket differential; "
            "no queue bind, rule, verdict or pcap"
        ),
    }
    try:
        topo = create(run_id, IMAGE)
        runtime = DockerRuntime(run_id, IMAGE)
        router, client, server = (
            topo.containers[role] for role in ("router", "client", "server")
        )
        selected = flow(topo)
        assert selected.server == str(
            ipaddress.IPv4Network(topo.wan).network_address + 3
        )
        evidence["topology"] = {
            "lan": topo.lan,
            "wan": topo.wan,
            "container_ids": topo.containers,
            "network_ids": topo.networks,
            "router_routes": runtime.exec(
                router, [BUSYBOX, "ip", "route"]
            ).stdout.decode()[:4096],
            "client_routes": runtime.exec(
                client, [BUSYBOX, "ip", "route"]
            ).stdout.decode()[:4096],
            "server_routes": runtime.exec(
                server, [BUSYBOX, "ip", "route"]
            ).stdout.decode()[:4096],
        }
        _copy(runtime, server, WEB, "/opt/tmp/web-demo-p006")
        runtime.exec(
            server,
            [
                "/bin/sh",
                "-c",
                "printf 'routed\\n' > /opt/tmp/m1c26-state; "
                "/opt/tmp/web-demo-p006 8080 8081 /opt/tmp/m1c26-state "
                ">/opt/tmp/m1c26-server.log 2>&1 &",
            ],
        )
        before_forward = _forwarded(runtime, router)
        result = runtime.exec(
            client,
            [BUSYBOX, "wget", "-qO-", f"http://{selected.server}:8080/health"],
        )
        after_forward = _forwarded(runtime, router)
        assert b"routed" in result.stdout and after_forward > before_forward
        evidence["baseline_only"] = {
            "client_http_body": result.stdout.decode()[:1024],
            "router_forwarded_datagrams": [before_forward, after_forward],
            "queue_rule_installed": False,
        }
        for kind in SOCKET_HASHES:
            target = f"/opt/tmp/m1c26-{kind}-socket"
            _copy(runtime, router, SOCKETS / f"{kind}_socket", target)
            response = runtime.exec(router, [target], allow_failure=True)
            evidence[f"{kind}_socket"] = {
                "exit_code": response.exit_code,
                "stdout": response.stdout.decode("utf-8", "replace")[:1024],
                "stderr": response.stderr.decode("utf-8", "replace")[:1024],
            }
        assert evidence["native_socket"]["exit_code"] == 0
        assert evidence["target_socket"]["exit_code"] == 1
        assert "Protocol not supported" in evidence["target_socket"]["stderr"]
        demo = NetworkDemo(topo, IMAGE, demo_hash)
        demo.install(DEMO)
        with pytest.raises(DockerBoundaryError, match="startup/queue unavailable"):
            demo.start()
        service_log = runtime.exec(
            router, [BUSYBOX, "cat", "/opt/etc/network-demo/service.log"]
        )
        evidence["target_queue_start"] = service_log.stdout.decode("utf-8", "replace")[
            :2048
        ]
        assert (
            "network-demo NFQUEUE: Protocol not supported"
            in evidence["target_queue_start"]
        )
        # A failed real startup has no listener; use the explicit diagnostic
        # mode to prove the rule hook still refuses a non-ready queue.
        demo.start(api_only=True)
        with pytest.raises(DockerBoundaryError, match="target queue not ready"):
            demo.install_rule()
        evidence["rule_install"] = "refused: target queue not ready"
        evidence["consumer_counters"] = "NOT RUN: target queue never ready"
        evidence["kernel_queue_counters"] = "NOT RUN: no queue or rule installed"
        evidence["accept_drop_restore"] = "BLOCKED: no target queue bind ACK"
        demo.remove()
    finally:
        cleanup(run_id, IMAGE)
    assert DockerRuntime.listed_ids("container") == containers_before
    assert DockerRuntime.listed_ids("network") == networks_before
    after_modules = _modules()
    assert after_modules == before_modules
    evidence["module_after"] = after_modules
    evidence["cleanup"] = "owner-verified absent; foreign Docker IDs unchanged"
    path = Path("reports") / f"{run_id}-packet-blocker.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, sort_keys=True)
        output.write("\n")
    print(path)
