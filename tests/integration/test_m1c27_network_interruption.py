"""Opt-in real SIGKILL topology recovery and foreign namespace isolation proof."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import selectors
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, _exec, _json
from keemu.network_demo import flow
from keemu.topology import cleanup, create

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"
# Exact locally inspected native image; no mounts, host namespaces or firewall use.
NATIVE = "sha256:7956ad1f365ad2ce4454673cb3f3ab31798703b2a3ea1d1329c509250f974bee"
ROOT = Path(__file__).resolve().parents[2]

# Interrupt the actual topology creation path after a network, after a node,
# and after full setup. No child gets a Docker socket mount or host namespace.
CHILD = """
import json, sys, time
from keemu.docker_runtime import DockerRuntime
from keemu import topology
run, image, point = sys.argv[1:]
def ready(identifier):
    print('READY ' + json.dumps({'point': point, 'id': identifier}), flush=True)
    time.sleep(180)
if point == 'network':
    original = DockerRuntime.create_network
    def interrupted(self, *args, **kwargs):
        identifier = original(self, *args, **kwargs)
        ready(identifier)
        return identifier
    DockerRuntime.create_network = interrupted
elif point == 'container':
    original = DockerRuntime.create
    def interrupted(self, *args, **kwargs):
        identifier = original(self, *args, **kwargs)
        ready(identifier)
        return identifier
    DockerRuntime.create = interrupted
result = topology.create(run, image)
if point == 'ready':
    ready(result.containers['router'])
"""

# Linux rtnetlink UAPI: RTM_NEWRULE=32, RTM_GETRULE=34, FRA_DST=1,
# FRA_PRIORITY=6. Only a test-owned foreign-run namespace is accessed.
RULES_HELPER = """
import ipaddress, json, socket, struct, sys
action, destination = sys.argv[1:]
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.settimeout(10)
s.bind((0, 0))
def header(payload, kind, flags):
    return struct.pack('IHHII', 16+len(payload), kind, flags, 1, 0) + payload
def attr(kind, data):
    blob = struct.pack('HH', len(data)+4, kind) + data
    return blob + bytes((-len(blob)) % 4)
def receive():
    while True:
        data = s.recv(65536)
        offset = 0
        while offset + 16 <= len(data):
            length, kind, flags, seq, pid = struct.unpack_from('IHHII', data, offset)
            if length < 16 or offset + length > len(data) or seq != 1:
                raise RuntimeError('invalid rtnetlink reply')
            payload = data[offset+16:offset+length]
            if kind == 2:
                error, = struct.unpack_from('i', payload)
                if error:
                    raise OSError(-error, 'rtnetlink rule operation failed')
                return
            if kind == 3:
                return
            yield kind, payload
            offset += (length + 3) & ~3
if action == 'add':
    rule = struct.pack('BBBBBBBBI', 2, 32, 0, 0, 254, 0, 0, 1, 0)
    rule += attr(1, ipaddress.IPv4Address(destination).packed)
    rule += attr(6, struct.pack('I', 17271))
    s.sendto(header(rule, 32, 1|4|0x200|0x400), (0, 0))
    list(receive())
elif action == 'dump':
    query = struct.pack('BBBBBBBBI', 2, 0, 0, 0, 0, 0, 0, 0, 0)
    s.sendto(header(query, 34, 1|0x300), (0, 0))
    print(json.dumps(sorted(payload.hex() for kind, payload in receive()
                            if kind == 32 and payload[0] == 2)))
else:
    raise ValueError('unsupported action')
"""


def _barrier(process: subprocess.Popen[str], point: str) -> str:
    selector = selectors.DefaultSelector()
    try:
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(120):
            raise AssertionError("network creator missed interruption barrier")
        line = process.stdout.readline().strip()
        if not line.startswith("READY "):
            assert process.stderr is not None
            raise AssertionError("network creator failed: " + process.stderr.read(4096))
        observed = json.loads(line[6:])
        assert observed["point"] == point
        return observed["id"]
    finally:
        selector.close()


def _inventory() -> dict:
    """Read every resource ID and foreign identity/state, without modifying any."""
    result = {}
    for kind in ("container", "network"):
        result[kind] = {}
        for identifier in sorted(DockerRuntime.listed_ids(kind)):
            response = _json(["docker", kind, "inspect", "--", identifier])
            assert isinstance(response, list) and len(response) == 1
            item = response[0]
            assert isinstance(item, dict)
            assert item["Id"] == identifier
            if kind == "container":
                labels = item["Config"].get("Labels") or {}
                value = {
                    "name": item["Name"],
                    "image": item["Image"],
                    "running": item["State"]["Running"],
                    "network_mode": item["HostConfig"]["NetworkMode"],
                }
            else:
                labels = item.get("Labels") or {}
                value = {
                    "name": item["Name"],
                    "driver": item["Driver"],
                    "internal": item["Internal"],
                    "ipam": item["IPAM"]["Config"],
                }
            result[kind][identifier] = {"owner": labels.get("org.keemu.owner"), **value}
    return result


def _rules(runtime: DockerRuntime, identifier: str, action: str, destination: str):
    """Native policy-rule dump/add in a verified foreign-run namespace."""
    runtime.inspect("container", identifier)
    arguments = [
        "docker",
        "container",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        f"container:{identifier}",
        "--read-only",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--pids-limit",
        "64",
        "--cap-drop=ALL",
        *(["--cap-add=NET_ADMIN"] if action == "add" else []),
        "--security-opt",
        "no-new-privileges",
        "--label",
        "org.keemu.owner=keemu",
        "--label",
        f"org.keemu.run-id={runtime.run_id}",
        "--entrypoint",
        "python3",
        NATIVE,
        "-B",
        "-c",
        RULES_HELPER,
        action,
        destination,
    ]
    result = _exec(arguments, timeout=40)
    runtime.inspect("container", identifier)
    return json.loads(result.stdout) if action == "dump" else None


def _isolation(runtime: DockerRuntime, owned: dict) -> None:
    for identifier in owned["container_owned"]:
        item = runtime.inspect("container", identifier)
        host = item["HostConfig"]
        assert host["Privileged"] is False
        assert host["NetworkMode"] != "host"
        assert not host["PidMode"] and host["IpcMode"] != "host"
        assert host["CgroupnsMode"] != "host"
        assert not host.get("Binds") and not host.get("Mounts")
        allowed_mounts = {"/tmp", "/run"}  # noqa: S108 -- container tmpfs only
        assert all(
            mount["Type"] == "tmpfs" and mount["Destination"] in allowed_mounts
            for mount in item.get("Mounts", [])
        )
        assert not host["Devices"] and not host["PortBindings"]
        assert host["CapAdd"] == ["NET_ADMIN"]
        assert "ALL" in host["CapDrop"]
        assert "SYS_MODULE" not in host["CapAdd"]
        assert "no-new-privileges" in host["SecurityOpt"]
        assert (host["Memory"], host["NanoCpus"], host["PidsLimit"]) == (
            1073741824,
            2000000000,
            256,
        )
        assert host["LogConfig"] == {
            "Type": "json-file",
            "Config": {"max-file": "1", "max-size": "20m"},
        }
    for identifier in owned["network_owned"]:
        item = runtime.inspect("network", identifier)
        assert item["Internal"] is True and item["Driver"] == "bridge"


@pytest.mark.docker
def test_sigkill_network_allocation_and_foreign_rules_survive():
    if os.getenv("KEEMU_TEST_M1C27") != "1":
        pytest.skip("opt in to live m1c-27 interruption/isolation probe")
    before = _inventory()
    foreign_id = "m1c27-other-" + uuid.uuid4().hex[:12]
    foreign = DockerRuntime(foreign_id, IMAGE)
    probes = []
    active = None
    other = None
    try:
        other = create(foreign_id, IMAGE)
        foreign_client = other.containers["client"]
        # A real policy rule exists only inside the test-owned foreign-run netns.
        target = flow(other).server
        _rules(foreign, foreign_client, "add", target)
        foreign_rules = _rules(foreign, foreign_client, "dump", target)
        assert isinstance(foreign_rules, list)
        assert any(
            ipaddress.IPv4Address(target).packed in bytes.fromhex(item)
            and (17271).to_bytes(4, "little") in bytes.fromhex(item)
            for item in foreign_rules
        )
        foreign_resources = _inventory()
        for point, counts in (
            ("network", (0, 1)),
            ("container", (1, 2)),
            ("ready", (3, 2)),
        ):
            run = "m1c27-kill-" + uuid.uuid4().hex[:12]
            active = (run, DockerRuntime(run, IMAGE))
            process = subprocess.Popen(  # noqa: S603 -- fixed Python test child
                [sys.executable, "-u", "-c", CHILD, run, IMAGE, point],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                identifier = _barrier(process, point)
            finally:
                process.kill()
                process.wait(timeout=20)
                assert process.returncode == -9
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
            runtime = active[1]
            owned = runtime.reconcile()
            observed_counts = (
                len(owned["container_owned"]),
                len(owned["network_owned"]),
            )
            assert observed_counts == counts
            assert identifier in owned["container_owned"] + owned["network_owned"]
            _isolation(runtime, owned)
            # Neither wrong run can erase the other's exact full IDs.
            with pytest.raises(DockerBoundaryError, match="ownership labels mismatch"):
                runtime.remove_container(foreign_client)
            rules_after_kill = _rules(foreign, foreign_client, "dump", target)
            assert rules_after_kill == foreign_rules
            assert _inventory()["network"].keys() >= foreign_resources["network"].keys()
            cleanup(run, IMAGE)
            cleanup(run, IMAGE)
            assert runtime.reconcile()["container_owned"] == []
            assert runtime.reconcile()["network_owned"] == []
            assert _inventory() == foreign_resources
            rules_after_recovery = _rules(foreign, foreign_client, "dump", target)
            assert rules_after_recovery == foreign_rules
            probes.append(
                {
                    "point": point,
                    "interrupted_id": identifier,
                    "observed_before_recovery": owned,
                    "recovery": "explicit owner-only, idempotent; owned IDs absent",
                    "foreign_policy_rules_after_kill": rules_after_kill,
                    "foreign_policy_rules_after_recovery": rules_after_recovery,
                    "foreign_resources_unchanged": True,
                }
            )
            active = None
    finally:
        if active is not None:
            cleanup(active[0], IMAGE)
        if other is not None:
            cleanup(foreign_id, IMAGE)
    after = _inventory()
    assert after == before
    assert len(probes) == 3
    evidence = {
        "scope": (
            "owned AArch64 Docker topologies; foreign routing rules, not firewall rules"
        ),
        "image_id": IMAGE,
        "native_observer_image_id": NATIVE,
        "cases": probes,
        "foreign_rules": foreign_rules,
        "baseline": before,
        "postflight": after,
        "host_firewall_rules": (
            "NOT RUN: no host namespace firewall mutation or host-module load"
        ),
        "interrupted_report": "NOT IMPLEMENTED: explicit topology recovery only",
    }
    path = ROOT / "reports" / f"m1c27-{foreign_id}-interruption.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "evidence": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    )
