"""Opt-in live Docker boundary exercise, restricted to project-owned resources."""

import json
import os
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"


@pytest.mark.docker
def test_owned_runtime_boundary():
    if os.getenv("KEEMU_TEST_DOCKER_RUNTIME") != "1":
        pytest.skip("opt in to live Docker runtime test")
    run = "m1a12-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run, IMAGE)
    network = None
    container = None
    second = None
    events = []
    try:
        network = runtime.create_network("keemu-" + run)
        assert (
            runtime.reconcile(expected_networks={network})["network_unexpected"] == []
        )
        container = runtime.create("keemu-" + run, network_id=network)
        assert runtime.reconcile({container}, {network})["container_missing"] == []
        item = runtime.inspect("container", container)
        assert item["HostConfig"]["ReadonlyRootfs"] is False
        assert not item["HostConfig"]["Privileged"]
        assert item["HostConfig"]["Binds"] is None
        runtime.start(container)
        output = runtime.exec(
            container,
            [
                "/bin/sh",
                "-c",
                "echo boundary > /opt/tmp/keemu-boundary; "
                'read v < /opt/tmp/keemu-boundary; echo "$v"',
            ],
        )
        assert output.stdout.strip() == b"boundary"
        assert runtime.logs(container).truncated_stdout is False
        runtime.stop(container)
        runtime.start(container)
        assert (
            runtime.exec(
                container,
                ["/bin/sh", "-c", 'read v < /opt/tmp/keemu-boundary; echo "$v"'],
            ).stdout.strip()
            == b"boundary"
        )
        events.append("same container retained writable overlay after stop/start")
        runtime.remove_container(container)
        container = None
        second = runtime.create("keemu-fresh-" + run, network_id=network)
        runtime.start(second)
        fresh = runtime.exec(
            second, ["/bin/sh", "-c", "test ! -e /opt/tmp/keemu-boundary && echo fresh"]
        )
        assert fresh.stdout.strip() == b"fresh"
        events.append(
            "fresh container had separate writable overlay; immutable base unchanged"
        )
        with pytest.raises(DockerBoundaryError, match="ownership"):
            DockerRuntime("other-" + run, IMAGE).remove_container(second)
        runtime.remove_container(second)
        second = None
        runtime.remove_network(network)
        network = None
        assert not runtime.reconcile()["container_owned"]
        assert not runtime.reconcile()["network_owned"]
        events.append("owned resources removed and independently absent")
    finally:
        # Never remove anything without the boundary's exact ownership verification.
        for identifier in (second, container):
            if identifier:
                runtime.remove_container(identifier)
        if network:
            runtime.remove_network(network)
    path = Path("reports") / (run + "-docker-boundary.json")
    path.write_text(
        json.dumps({"run_id": run, "image_id": IMAGE, "events": events}, indent=2)
        + "\n"
    )
