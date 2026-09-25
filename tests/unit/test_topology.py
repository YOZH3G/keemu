"""Allocator, ownership and fail-closed topology checks without Docker mutation."""

import hashlib
import ipaddress
import json
from pathlib import Path

import pytest

from keemu import topology as top
from keemu.docker_runtime import DockerBoundaryError, DockerRuntime

IMAGE = "sha256:" + "a" * 64
CID = "b" * 64
NID = "c" * 64


def test_allocator_skips_all_overlapping_existing_routes(monkeypatch):
    monkeypatch.setattr(
        top,
        "_occupied",
        lambda: [
            ipaddress.IPv4Network("10.224.0.0/23"),
            ipaddress.IPv4Network("10.224.2.0/24"),
        ],
    )
    lan, wan = top._allocate()
    assert str(lan) == "10.224.3.0/24"
    assert str(wan) == "10.224.4.0/24"
    assert not lan.overlaps(wan)


def test_network_inventory_rejects_missing_identity(monkeypatch):
    monkeypatch.setattr(DockerRuntime, "listed_ids", lambda kind: {NID})
    monkeypatch.setattr(top, "_json", lambda argv: [{"Id": CID}])
    with pytest.raises(DockerBoundaryError, match="inventory changed"):
        top._occupied()


def test_foreign_or_unexpected_owned_resource_refuses_cleanup(monkeypatch, tmp_path):
    runtime = DockerRuntime("top-test", IMAGE)
    monkeypatch.setattr(
        runtime, "reconcile", lambda: {"container_owned": [CID], "network_owned": []}
    )
    monkeypatch.setattr(
        runtime, "inspect", lambda kind, identifier: {"Name": "keemu-other"}
    )
    monkeypatch.setattr(
        runtime,
        "remove_container",
        lambda identifier: pytest.fail("removed unexpected resource"),
    )
    with pytest.raises(DockerBoundaryError, match="unexpected owned"):
        top._cleanup_locked(runtime)
    with pytest.raises(DockerBoundaryError, match="symlink"):
        target = tmp_path / "real"
        target.mkdir()
        alias = tmp_path / "alias"
        alias.symlink_to(target)
        with top._lock(alias):
            pass


def test_invalid_connect_never_mutates_docker(monkeypatch):
    runtime = DockerRuntime("top-test", IMAGE)
    monkeypatch.setattr(
        runtime,
        "inspect",
        lambda kind, identifier: {
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.224.0.0/24"}]},
        },
    )
    monkeypatch.setattr(
        "keemu.docker_runtime._exec",
        lambda *args, **kwargs: pytest.fail("Docker mutated"),
    )
    for ip in ("192.168.0.2", "10.224.0.0", "10.224.0.255"):
        with pytest.raises(DockerBoundaryError, match="outside"):
            runtime.connect(NID, CID, ip)
    with pytest.raises(DockerBoundaryError, match="only wan0"):
        runtime.connect(NID, CID, "10.224.0.2", interface="eth0")


def test_forwarding_requires_narrow_capability_without_docker(monkeypatch):
    runtime = DockerRuntime("top-test", IMAGE)
    monkeypatch.setattr(runtime, "image", lambda: {})
    monkeypatch.setattr(
        "keemu.docker_runtime._exec",
        lambda *args, **kwargs: pytest.fail("Docker mutated"),
    )
    with pytest.raises(DockerBoundaryError, match="requires NET_ADMIN"):
        runtime.create("keemu-top-test", forwarding=True)


def test_frozen_live_topology_evidence():
    raw = Path("docs/evidence/m1c23-topology.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "9e8ce09bc0e8f0bc4689af5a03bac36393e58d17309b92b394c3cec30787dfe0"
    )
    report = json.loads(raw)
    before, after = report["router_forwarded_before_after"]
    assert after > before
    assert report["http_response"] == "keemu-web-demo\nstate=routed"
    assert report["networks"]["lan"]["internal"] is True
    assert report["networks"]["wan"]["internal"] is True
    assert len(report["nodes"]["client"]["endpoints"]) == 1
    assert len(report["nodes"]["server"]["endpoints"]) == 1
