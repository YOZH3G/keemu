"""Opt-in m1c-26 native transport / AArch64 decision integration probe."""

import hashlib
import ipaddress
import json
import os
import re
import struct
import time
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, _exec
from keemu.network_demo import flow, rule
from keemu.topology import BUSYBOX, cleanup, create

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"
TARGET = Path(".runtime/m1c26/network-demo-ipc-aarch64")
ADAPTER = Path(".runtime/m1c26/nfqueue-transport-amd64")
FIREWALL = "sha256:e9f36bf1e977d745f19873637490078724402c5fd3015d770d1dfba055237be9"


def _copy(runtime, container, source, destination):
    runtime.inspect("container", container)
    _exec(
        ["docker", "container", "cp", "--", str(source), f"{container}:{destination}"]
    )
    runtime.inspect("container", container)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    observed = (
        runtime.exec(container, [BUSYBOX, "sha256sum", destination])
        .stdout.decode()
        .split()[0]
    )
    assert observed == digest
    return digest


def _get(runtime, container, ip):
    result = runtime.exec(
        container,
        [BUSYBOX, "wget", "-qO-", f"http://{ip}:9090/api/state"],
        allow_failure=True,
    )
    if result.exit_code:
        return None
    return json.loads(result.stdout)


def _flow_request(runtime, client, address):
    try:
        result = runtime.exec(
            client,
            [BUSYBOX, "wget", "-qO-", f"http://{address}:8080/health"],
            allow_failure=True,
            timeout=8,
        )
    except DockerBoundaryError as exc:
        if "timed out" not in str(exc):
            raise
        return {"exit_code": "TIMEOUT", "body": "", "stderr": str(exc)}
    return {
        "exit_code": result.exit_code,
        "body": result.stdout.decode("utf-8", "replace")[:1024],
        "stderr": result.stderr.decode("utf-8", "replace")[:1024],
    }


def _mode(runtime, client, address, selected):
    result = runtime.exec(
        client,
        [
            BUSYBOX,
            "wget",
            "-qO-",
            "--post-data",
            f"mode={selected}",
            f"http://{address}:9090/api/mode",
        ],
    )
    observed = json.loads(result.stdout)
    assert observed["mode"] == selected
    return observed


def _iptables(runtime, router, *arguments):
    runtime.inspect("container", router)
    result = _exec(
        [
            "docker",
            "container",
            "run",
            "--rm",
            "--pull=never",
            "--network",
            f"container:{router}",
            "--read-only",
            "--tmpfs",
            "/run",
            "--cap-drop=ALL",
            "--cap-add=NET_ADMIN",
            "--cap-add=NET_RAW",
            "--security-opt",
            "no-new-privileges",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            f"org.keemu.run-id={runtime.run_id}",
            "--entrypoint",
            "/usr/sbin/iptables-legacy",
            FIREWALL,
            "-w",
            "2",
            "--modprobe=/bin/false",
            *arguments,
        ],
        allow_failure=True,
        timeout=20,
    )
    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout.decode("utf-8", "replace")[:8192],
        "stderr": result.stderr.decode("utf-8", "replace")[:2048],
    }


def _queue(runtime, router):
    return runtime.exec(
        router,
        [BUSYBOX, "cat", "/proc/net/netfilter/nfnetlink_queue"],
        allow_failure=True,
    ).stdout.decode()[:4096]


def _sequence(snapshot):
    rows = [line.split() for line in snapshot.splitlines()]
    selected = [row for row in rows if row and row[0] == "42"]
    assert len(selected) == 1 and len(selected[0]) >= 8, snapshot
    assert selected[0][5:7] == ["0", "0"], snapshot
    return int(selected[0][7])


def _rule_packets(snapshot, source, destination):
    rows = [line.split() for line in snapshot["stdout"].splitlines()]
    selected = [row for row in rows if "NFQUEUE" in row]
    assert len(selected) == 1, snapshot
    row = selected[0]
    assert row[:1] == ["1"] and row[3:5] == ["NFQUEUE", "tcp"]
    assert row[8:10] == [source, destination]
    assert "dpt:8080" in row and row[-3:] == ["NFQUEUE", "num", "42"]
    assert "bypass" not in snapshot["stdout"].lower()
    return int(row[1])


def _decisions(log, prefix):
    pattern = rf"{prefix} accepted=(\d+) dropped=(\d+) id=(\d+)"
    rows = [tuple(map(int, item)) for item in re.findall(pattern, log)]
    assert rows and [item[2] for item in rows] == list(range(1, len(rows) + 1))
    return rows


def _pcap(path, source, destination):
    data = path.read_bytes()
    assert 24 < len(data) <= 24 + 64 * (16 + 256)
    assert struct.unpack_from("<IHHIIII", data) == (0xA1B2C3D4, 2, 4, 0, 0, 256, 101)
    cursor = 24
    found = 0
    while cursor < len(data):
        _, _, copied, original = struct.unpack_from("<IIII", data, cursor)
        assert 20 <= copied <= 256 and original >= copied
        cursor += 16
        payload = data[cursor : cursor + copied]
        assert len(payload) == copied and payload[0] >> 4 == 4
        assert payload[12:16] == ipaddress.IPv4Address(source).packed
        assert payload[16:20] == ipaddress.IPv4Address(destination).packed
        assert payload[9] == 6
        header_length = (payload[0] & 15) * 4
        assert header_length >= 20 and copied >= header_length + 4
        assert struct.unpack_from("!H", payload, header_length + 2)[0] == 8080
        cursor += copied
        found += 1
    assert cursor == len(data) and found > 0
    return {
        "records": found,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@pytest.mark.docker
def test_target_decision_packet_flow():
    if os.getenv("KEEMU_TEST_IPC_M1C26") != "1":
        pytest.skip("opt in to owned m1c-26 target/native transport probe")
    run_id = "m1c26ipc-" + uuid.uuid4().hex[:12]
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    evidence: dict[str, object] = {"run_id": run_id, "result": "INCOMPLETE"}
    runtime = DockerRuntime(run_id, IMAGE)
    rule_attempted = False
    router = None
    topology = None
    try:
        topology = create(run_id, IMAGE)
        router = topology.containers["router"]
        addresses = flow(topology)
        evidence["topology"] = {"lan": topology.lan, "wan": topology.wan}
        evidence["binary_hashes"] = {
            "target": _copy(
                runtime, router, TARGET, "/opt/tmp/network-demo-ipc-aarch64"
            ),
            "adapter": _copy(
                runtime, router, ADAPTER, "/opt/tmp/nfqueue-transport-amd64"
            ),
        }
        runtime.exec(router, [BUSYBOX, "mkdir", "-p", "/opt/etc/network-demo"])
        runtime.exec(
            router,
            ["/bin/sh", "-c", "printf 'accept\\n' > /opt/etc/network-demo/mode"],
        )
        runtime.exec(
            router,
            [
                "/bin/sh",
                "-c",
                "/opt/tmp/network-demo-ipc-aarch64 "
                f"--bind {addresses.router} --client {addresses.client} "
                f"--server {addresses.server} --state /opt/etc/network-demo/mode "
                ">/opt/etc/network-demo/target.log 2>&1 & "
                "echo $! > /opt/etc/network-demo/target.pid",
            ],
        )
        for _ in range(12):
            if _get(runtime, router, addresses.router) is not None:
                break
            time.sleep(0.2)
        evidence["initial_target"] = _get(runtime, router, addresses.router)
        evidence["target_log_before_adapter"] = runtime.exec(
            router, [BUSYBOX, "cat", "/opt/etc/network-demo/target.log"]
        ).stdout.decode()[:2048]
        if evidence["initial_target"] is not None:
            assert evidence["initial_target"]["queue_ready"] is False
            runtime.exec(
                router,
                [
                    "/bin/sh",
                    "-c",
                    "/opt/tmp/nfqueue-transport-amd64 --queue 42 "
                    ">/opt/etc/network-demo/adapter.log 2>&1 & "
                    "echo $! > /opt/etc/network-demo/adapter.pid",
                ],
            )
            for _ in range(12):
                state = _get(runtime, router, addresses.router)
                if state is not None and state["queue_ready"] is True:
                    break
                time.sleep(0.2)
            evidence["after_adapter"] = _get(runtime, router, addresses.router)
            evidence["adapter_log"] = runtime.exec(
                router, [BUSYBOX, "cat", "/opt/etc/network-demo/adapter.log"]
            ).stdout.decode()[:2048]
            evidence["kernel_queue"] = runtime.exec(
                router,
                [BUSYBOX, "cat", "/proc/net/netfilter/nfnetlink_queue"],
                allow_failure=True,
            ).stdout.decode()[:2048]
            evidence["result"] = (
                "QUEUE_READY"
                if evidence["after_adapter"]
                and evidence["after_adapter"]["queue_ready"]
                else "BLOCKED"
            )
        else:
            evidence["result"] = "BLOCKED: target IPC API unavailable"
        if evidence["result"] == "QUEUE_READY":
            server = topology.containers["server"]
            client = topology.containers["client"]
            web = Path(".runtime/p0/fixtures/aarch64/web-demo-p006")
            assert hashlib.sha256(web.read_bytes()).hexdigest() == (
                "0856c7af577b6fb1675ca6266686853863aee23e1cbe15a207c64ed0089cbf36"
            )
            _copy(runtime, server, web, "/opt/tmp/web-demo-p006")
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
            evidence["baseline"] = _flow_request(runtime, client, addresses.server)
            assert evidence["baseline"]["exit_code"] == 0
            assert "state=routed" in evidence["baseline"]["body"]
            image = json.loads(_exec(["docker", "image", "inspect", FIREWALL]).stdout)[
                0
            ]
            assert image["Id"] == FIREWALL
            assert image["Config"]["Labels"]["org.keemu.owner"] == "keemu"
            evidence["firewall_image"] = FIREWALL
            evidence["iptables_before"] = _iptables(
                runtime, router, "-nvxL", "FORWARD", "--line-numbers"
            )
            if (
                evidence["iptables_before"]["exit_code"] == 3
                and "Permission denied" in evidence["iptables_before"]["stderr"]
            ):
                evidence["result"] = "BLOCKED: owner-scoped legacy filter read denied"
                pytest.skip("legacy filter read denied; no rule or verdict attempted")
            assert evidence["iptables_before"]["exit_code"] == 0, evidence
            exact = rule(topology)[2:]
            assert _iptables(runtime, router, "-C", *exact)["exit_code"] != 0
            rule_attempted = True
            evidence["insert"] = _iptables(runtime, router, "-I", *exact)
            assert evidence["insert"]["exit_code"] == 0, evidence
            assert _iptables(runtime, router, "-C", *exact)["exit_code"] == 0
            evidence["iptables_after_install"] = _iptables(
                runtime, router, "-nvxL", "FORWARD", "--line-numbers"
            )
            evidence["accept"] = _flow_request(runtime, client, addresses.server)
            evidence["accept_state"] = _get(runtime, client, addresses.router)
            evidence["accept_queue"] = _queue(runtime, router)
            assert evidence["accept"]["exit_code"] == 0, evidence
            assert evidence["accept_state"]["accepted"] > 0
            _mode(runtime, client, addresses.router, "drop")
            evidence["drop"] = _flow_request(runtime, client, addresses.server)
            evidence["drop_state"] = _get(runtime, client, addresses.router)
            evidence["drop_queue"] = _queue(runtime, router)
            assert evidence["drop"]["exit_code"] != 0, evidence
            assert evidence["drop_state"]["dropped"] > 0
            _mode(runtime, client, addresses.router, "accept")
            evidence["restored"] = _flow_request(runtime, client, addresses.server)
            evidence["restored_state"] = _get(runtime, client, addresses.router)
            evidence["restored_queue"] = _queue(runtime, router)
            assert evidence["restored"]["exit_code"] == 0, evidence
            assert evidence["restored_state"] is not None
            assert evidence["accept_state"] is not None
            assert (
                evidence["restored_state"]["accepted"]
                > evidence["accept_state"]["accepted"]
            )
            evidence["iptables_after_flow"] = _iptables(
                runtime, router, "-nvxL", "FORWARD", "--line-numbers"
            )
            evidence["target_log"] = runtime.exec(
                router, [BUSYBOX, "cat", "/opt/etc/network-demo/target.log"]
            ).stdout.decode()[-4096:]
            evidence["adapter_log"] = runtime.exec(
                router, [BUSYBOX, "cat", "/opt/etc/network-demo/adapter.log"]
            ).stdout.decode()[-4096:]
            capture = Path("reports") / f"{run_id}-packets.pcap"
            runtime.inspect("container", router)
            _exec(
                [
                    "docker",
                    "container",
                    "cp",
                    "--",
                    f"{router}:/opt/etc/network-demo/packets.pcap",
                    str(capture),
                ]
            )
            evidence["pcap"] = _pcap(capture, addresses.client, addresses.server)
            target_rows = _decisions(evidence["target_log"], "target")
            adapter_rows = _decisions(evidence["adapter_log"], "transport")
            assert target_rows == adapter_rows
            accepted, dropped, last_id = target_rows[-1]
            restored_state = evidence["restored_state"]
            accept_state = evidence["accept_state"]
            drop_state = evidence["drop_state"]
            assert isinstance(restored_state, dict)
            assert isinstance(accept_state, dict)
            assert isinstance(drop_state, dict)
            assert (accepted, dropped) == (
                restored_state["accepted"],
                restored_state["dropped"],
            )
            assert accepted > accept_state["accepted"] > 0
            assert dropped == drop_state["dropped"] > 0
            assert accept_state["dropped"] == 0
            assert drop_state["accepted"] == accept_state["accepted"]
            assert _sequence(evidence["accept_queue"]) < _sequence(
                evidence["drop_queue"]
            )
            assert _sequence(evidence["drop_queue"]) < _sequence(
                evidence["restored_queue"]
            )
            assert last_id == accepted + dropped == evidence["pcap"]["records"]
            assert _sequence(evidence["restored_queue"]) == last_id
            assert (
                _rule_packets(
                    evidence["iptables_after_flow"], addresses.client, addresses.server
                )
                == last_id
            )
            evidence["correlation"] = {
                "target_accepted": accepted,
                "target_dropped": dropped,
                "adapter_verdicts": len(adapter_rows),
                "kernel_sequence": last_id,
                "rule_packets": last_id,
                "pcap_records": last_id,
            }
            runtime.exec(
                router,
                [
                    "/bin/sh",
                    "-c",
                    "read -r pid < /opt/etc/network-demo/adapter.pid; "
                    "case \"$pid\" in ''|*[!0-9]*) exit 2;; esac; "
                    f"{BUSYBOX} grep -aq 'nfqueue-transport-amd64' /proc/$pid/cmdline "
                    '&& kill -TERM "$pid"',
                ],
            )
            for _ in range(20):
                if not _queue(runtime, router).strip():
                    break
                time.sleep(0.1)
            evidence["no_listener_queue"] = _queue(runtime, router)
            assert not evidence["no_listener_queue"].strip()
            evidence["no_listener"] = _flow_request(runtime, client, addresses.server)
            assert evidence["no_listener"]["exit_code"] != 0
            evidence["no_listener_state"] = _get(runtime, client, addresses.router)
            no_listener_state = evidence["no_listener_state"]
            assert isinstance(no_listener_state, dict)
            assert no_listener_state["accepted"] == accepted
            assert no_listener_state["dropped"] == dropped
            evidence["no_listener_rule"] = _iptables(
                runtime, router, "-nvxL", "FORWARD", "--line-numbers"
            )
            assert (
                _rule_packets(
                    evidence["no_listener_rule"], addresses.client, addresses.server
                )
                > last_id
            )
            evidence["remove"] = _iptables(runtime, router, "-D", *exact)
            assert evidence["remove"]["exit_code"] == 0
            rule_attempted = False
            evidence["iptables_after_remove"] = _iptables(
                runtime, router, "-nvxL", "FORWARD", "--line-numbers"
            )
            assert _iptables(runtime, router, "-C", *exact)["exit_code"] != 0
            evidence["post_remove"] = _flow_request(runtime, client, addresses.server)
            assert evidence["post_remove"]["exit_code"] == 0
            evidence["result"] = "PASS: target IPC decisions and routed verdicts"
    finally:
        if rule_attempted and topology is not None and router is not None:
            exact = rule(topology)[2:]
            try:
                if _iptables(runtime, router, "-C", *exact)["exit_code"] == 0:
                    evidence["emergency_rule_removal"] = _iptables(
                        runtime, router, "-D", *exact
                    )
            except DockerBoundaryError as exc:
                evidence["emergency_rule_removal_error"] = str(exc)
        cleanup(run_id, IMAGE)
        evidence["cleanup"] = {
            "foreign_containers_unchanged": DockerRuntime.listed_ids("container")
            == before_containers,
            "foreign_networks_unchanged": DockerRuntime.listed_ids("network")
            == before_networks,
        }
        path = Path("reports") / f"{run_id}-packet-flow.json"
        with path.open("x", encoding="utf-8") as output:
            json.dump(evidence, output, indent=2, sort_keys=True)
            output.write("\n")
        print(path)
    assert all(evidence["cleanup"].values())
    assert evidence["result"] == "PASS: target IPC decisions and routed verdicts", (
        evidence
    )
