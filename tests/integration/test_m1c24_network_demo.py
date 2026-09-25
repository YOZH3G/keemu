"""Opt-in target fixture smoke; no rule/packet/verdict is asserted here."""

import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.network_demo import NetworkDemo, flow
from keemu.topology import BUSYBOX, cleanup, create

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"


@pytest.mark.docker
def test_target_build_and_api_only_smoke():
    if os.getenv("KEEMU_TEST_NETWORK_DEMO") != "1":
        pytest.skip("opt in to target network-demo fixture smoke")
    binary = Path(".runtime/m1c24/network-demo-aarch64")
    assert binary.exists()
    locked = json.loads(Path("locks/m1c24-network-demo-aarch64.json").read_text())
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert digest == locked["binary"]["sha256"]
    run_id = "m1c24-" + uuid.uuid4().hex[:12]
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    topo = None
    evidence: dict[str, object] = {
        "run_id": run_id,
        "image_id": IMAGE,
        "binary_sha256": digest,
    }
    try:
        topo = create(run_id, IMAGE)
        demo = NetworkDemo(topo, IMAGE, digest)
        demo.install(binary)
        router = topo.containers["router"]
        client = topo.containers["client"]
        demo.start(api_only=True)
        response = demo.runtime.exec(
            client,
            [BUSYBOX, "wget", "-qO-", f"http://{flow(topo).router}:9090/api/state"],
        ).stdout.decode()
        assert json.loads(response) == {
            "mode": "accept",
            "queue_ready": False,
            "accepted": 0,
            "dropped": 0,
        }
        with pytest.raises(DockerBoundaryError, match="target queue not ready"):
            demo.install_rule()
        evidence["target_api_only"] = json.loads(response)
        demo.stop()
        stopped = demo.runtime.exec(
            client,
            [BUSYBOX, "wget", "-qO-", f"http://{flow(topo).router}:9090/api/state"],
            allow_failure=True,
        )
        assert stopped.exit_code != 0, "stop hook left API reachable"
        with pytest.raises(DockerBoundaryError, match="startup/queue unavailable"):
            demo.start()
        log = demo.runtime.exec(
            router, [BUSYBOX, "cat", "/opt/etc/network-demo/service.log"]
        ).stdout.decode()
        assert "Protocol not supported" in log
        evidence["target_real_queue_start"] = {"status": "BLOCKED", "log": log}
        persisted = demo.runtime.exec(
            router, [BUSYBOX, "cat", "/opt/etc/network-demo/mode"]
        ).stdout.decode()
        assert persisted == "accept\n"
        evidence["mode_after_failed_queue"] = persisted
        demo.remove()
        demo.runtime.exec(
            router,
            [
                "/bin/sh",
                "-c",
                "test ! -e /opt/etc/network-demo && "
                "test ! -e /opt/tmp/network-demo-aarch64",
            ],
        )
    finally:
        cleanup(run_id, IMAGE)
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
    evidence["cleanup"] = "owner-verified absent; foreign Docker IDs unchanged"
    path = Path("reports") / f"{run_id}-network-demo-smoke.json"
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(path)
