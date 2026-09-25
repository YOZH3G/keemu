"""Opt-in topology proof on project-owned, internal Docker bridges only."""

import hashlib
import ipaddress
import json
import os
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerRuntime
from keemu.topology import BUSYBOX, cleanup, create

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"


def _target(runtime, identifier, *args):
    return runtime.exec(identifier, [BUSYBOX, *args]).stdout.decode()


def _forwarded(runtime, identifier):
    text = _target(runtime, identifier, "cat", "/proc/net/snmp")
    lines = [line.split() for line in text.splitlines() if line.startswith("Ip:")]
    return int(dict(zip(lines[0][1:], lines[1][1:], strict=True))["ForwDatagrams"])


@pytest.mark.docker
def test_internal_routed_topology_and_owner_cleanup():
    if os.getenv("KEEMU_TEST_TOPOLOGY") != "1":
        pytest.skip("opt in to live topology proof")
    run = "m1c23-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run, IMAGE)
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    evidence: dict[str, object] = {"run_id": run, "image_id": IMAGE}
    try:
        topo = create(run, IMAGE)
        lan = ipaddress.IPv4Network(topo.lan)
        wan = ipaddress.IPv4Network(topo.wan)
        assert not lan.overlaps(wan)
        evidence["subnets"] = {"lan": topo.lan, "wan": topo.wan}
        evidence["networks"] = {}
        for role, identifier in topo.networks.items():
            item = runtime.inspect("network", identifier)
            assert item["Internal"] is True
            evidence["networks"][role] = {
                "id": identifier,
                "internal": item["Internal"],
                "ipam": item["IPAM"]["Config"],
            }
        evidence["nodes"] = {}
        for role, identifier in topo.containers.items():
            item = runtime.inspect("container", identifier)
            endpoints = item["NetworkSettings"]["Networks"]
            assert len(endpoints) == (2 if role == "router" else 1)
            assert item["HostConfig"]["CapAdd"] == ["NET_ADMIN"]
            assert not item["HostConfig"]["Privileged"]
            assert not item["HostConfig"]["PortBindings"]
            evidence["nodes"][role] = {
                "id": identifier,
                "endpoints": {
                    key: value["IPAddress"] for key, value in endpoints.items()
                },
                "routes": _target(runtime, identifier, "ip", "route"),
            }
        router = topo.containers["router"]
        client = topo.containers["client"]
        server = topo.containers["server"]
        assert (
            f"default via {lan.network_address + 2}"
            in evidence["nodes"]["client"]["routes"]
        )
        assert (
            f"{lan} via {wan.network_address + 2}"
            in evidence["nodes"]["server"]["routes"]
        )
        assert f"{lan} dev br0" in evidence["nodes"]["router"]["routes"]
        assert f"{wan} dev wan0" in evidence["nodes"]["router"]["routes"]
        link = _target(runtime, router, "ip", "link")
        assert "master br0" in link and "wan0" in link
        evidence["router_links"] = link
        assert (
            _target(runtime, router, "cat", "/proc/sys/net/ipv4/ip_forward").strip()
            == "1"
        )
        before_forward = _forwarded(runtime, router)
        binary = Path(".runtime/p0/fixtures/aarch64/web-demo-p006")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        assert (
            digest == "0856c7af577b6fb1675ca6266686853863aee23e1cbe15a207c64ed0089cbf36"
        )
        runtime.inspect("container", server)
        from keemu.docker_runtime import _exec

        _exec(
            [
                "docker",
                "container",
                "cp",
                "--",
                str(binary),
                f"{server}:/opt/tmp/web-demo-p006",
            ]
        )
        runtime.inspect("container", server)
        runtime.exec(
            server,
            [
                "/bin/sh",
                "-c",
                "echo routed > /opt/tmp/topology-state; "
                "/opt/tmp/web-demo-p006 8080 8081 /opt/tmp/topology-state "
                ">/opt/tmp/topology-log 2>&1 &",
            ],
        )
        response = _target(
            runtime,
            client,
            "wget",
            "-qO-",
            f"http://{wan.network_address + 3}:8080/health",
        )
        after_forward = _forwarded(runtime, router)
        assert "routed" in response
        assert after_forward > before_forward
        evidence["http_response"] = response.strip()
        evidence["router_forwarded_before_after"] = [before_forward, after_forward]
        # Recovery refuses other run IDs; only exact owned IDs are removable.
        assert not DockerRuntime("foreign-" + run, IMAGE).reconcile()["container_owned"]
    finally:
        cleanup(run, IMAGE)
        cleanup(run, IMAGE)
    assert not runtime.reconcile()["container_owned"]
    assert not runtime.reconcile()["network_owned"]
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
    evidence["cleanup"] = "owner-verified absent; foreign IDs unchanged"
    path = Path("reports") / f"{run}-topology.json"
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(path)


@pytest.mark.docker
def test_parallel_allocation_and_failure_rollback(monkeypatch):
    if os.getenv("KEEMU_TEST_TOPOLOGY") != "1":
        pytest.skip("opt in to live topology proof")
    from keemu import topology as top
    from keemu.docker_runtime import DockerBoundaryError

    first = "m1c23-" + uuid.uuid4().hex[:12]
    second = "m1c23-" + uuid.uuid4().hex[:12]
    baseline_containers = DockerRuntime.listed_ids("container")
    baseline_networks = DockerRuntime.listed_ids("network")
    try:
        one = create(first, IMAGE)
        two = create(second, IMAGE)
        for left in (one.lan, one.wan):
            for right in (two.lan, two.wan):
                assert not ipaddress.IPv4Network(left).overlaps(
                    ipaddress.IPv4Network(right)
                )
        assert one.networks.keys() == two.networks.keys()
        cleanup(first, IMAGE)
        assert set(DockerRuntime(second, IMAGE).reconcile()["container_owned"]) == set(
            two.containers.values()
        )
        assert set(DockerRuntime(second, IMAGE).reconcile()["network_owned"]) == set(
            two.networks.values()
        )
        with pytest.raises(DockerBoundaryError, match="already owns"):
            create(second, IMAGE)
    finally:
        cleanup(first, IMAGE)
        cleanup(second, IMAGE)
    # Inject a failure after allocation to exercise automatic owner-only rollback.
    broken = "m1c23-" + uuid.uuid4().hex[:12]
    original = top._target

    def fail_after_network_setup(runtime, identifier, *args):
        if args[:3] == ("ip", "link", "add"):
            raise DockerBoundaryError("injected pre-bridge failure")
        return original(runtime, identifier, *args)

    monkeypatch.setattr(top, "_target", fail_after_network_setup)
    with pytest.raises(DockerBoundaryError, match="injected pre-bridge failure"):
        create(broken, IMAGE)
    cleanup(broken, IMAGE)
    assert DockerRuntime.listed_ids("container") == baseline_containers
    assert DockerRuntime.listed_ids("network") == baseline_networks
