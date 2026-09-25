"""Opt-in target queue capability recheck after approved host module preparation.

No firewall rule or packet is sent. An absent xt_NFQUEUE handler blocks next step.
"""

import hashlib
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
BINARY = Path(".runtime/m1c24/network-demo-aarch64")
SOCKETS = Path(".runtime/p0/p007-1ed1391a9dd4")
EXPECTED = {
    "native_socket": "378db5054cec52bc8422845c3bef0fe7dec032188a7c35a3adf32b8113e28167",
    "target_socket": "c82cf028a2eceb93e45b54e3bb883ca3a6edde2b0949b73884d3ed1f96857655",
}
MODULES = ("nfnetlink", "nfnetlink_queue", "xt_NFQUEUE", "nft_queue")


def _modules():
    loaded = {
        line.split()[0] for line in Path("/proc/modules").read_text().splitlines()
    }
    return {
        name: {
            "proc_modules": name in loaded,
            "sys_module": Path("/sys/module", name).exists(),
        }
        for name in MODULES
    }


@pytest.mark.docker
def test_target_queue_capability_after_approved_module():
    if os.getenv("KEEMU_TEST_QUEUE_RECHECK_M1C26") != "1":
        pytest.skip("opt in to approved m1c-26 target queue capability recheck")
    modules_before = _modules()
    assert modules_before["nfnetlink_queue"] == {
        "proc_modules": True,
        "sys_module": True,
    }
    for name in ("xt_NFQUEUE", "nft_queue"):
        assert not any(modules_before[name].values()), "review other module state first"
    binary_sha = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    lock = json.loads(Path("locks/m1c24-network-demo-aarch64.json").read_text())
    assert binary_sha == lock["binary"]["sha256"]
    for name, digest in EXPECTED.items():
        assert hashlib.sha256((SOCKETS / name).read_bytes()).hexdigest() == digest
    run_id = "m1c26q-" + uuid.uuid4().hex[:12]
    containers_before = DockerRuntime.listed_ids("container")
    networks_before = DockerRuntime.listed_ids("network")
    evidence = {
        "run_id": run_id,
        "kernel": platform.release(),
        "image_id": IMAGE,
        "binary_sha256": binary_sha,
        "socket_sha256": EXPECTED,
        "module_before": modules_before,
        "scope": "same-router native/target socket and target queue binding only; no rule, packet, verdict or host mutation",
    }
    try:
        topology = create(run_id, IMAGE)
        runtime = DockerRuntime(run_id, IMAGE)
        router = topology.containers["router"]
        evidence["router_id"] = router
        evidence["router_ip"] = flow(topology).router
        for name in EXPECTED:
            source = SOCKETS / name
            destination = f"/opt/tmp/m1c26-{name}"
            runtime.inspect("container", router)
            _exec(
                [
                    "docker",
                    "container",
                    "cp",
                    "--",
                    str(source),
                    f"{router}:{destination}",
                ]
            )
            runtime.inspect("container", router)
            assert (
                runtime.exec(router, [BUSYBOX, "sha256sum", destination])
                .stdout.decode()
                .split()[0]
                == EXPECTED[name]
            )
            observed = runtime.exec(router, [destination], allow_failure=True)
            evidence[name] = {
                "exit_code": observed.exit_code,
                "stdout": observed.stdout.decode("utf-8", "replace")[:1024],
                "stderr": observed.stderr.decode("utf-8", "replace")[:1024],
            }
        assert evidence["native_socket"]["exit_code"] == 0
        demo = NetworkDemo(topology, IMAGE, binary_sha)
        demo.install(BINARY)
        try:
            demo.start()
        except DockerBoundaryError as exc:
            evidence["startup_error"] = str(exc)[:1024]
            log = runtime.exec(
                router,
                [BUSYBOX, "cat", "/opt/etc/network-demo/service.log"],
                allow_failure=True,
            )
            evidence["startup_log"] = log.stdout.decode("utf-8", "replace")[:2048]
            evidence["result"] = "BLOCKED: target queue unavailable"
        else:
            state = runtime.exec(
                router,
                [
                    BUSYBOX,
                    "wget",
                    "-qO-",
                    f"http://{flow(topology).router}:9090/api/state",
                ],
            )
            evidence["target_state"] = json.loads(state.stdout)
            assert evidence["target_state"]["queue_ready"] is True
            evidence["result"] = (
                "TARGET_QUEUE_READY; rule not authorized without xt_NFQUEUE preflight"
            )
            demo.stop()
        evidence["rule"] = "NOT RUN"
        evidence["packets"] = "NOT RUN"
    finally:
        cleanup(run_id, IMAGE)
    assert DockerRuntime.listed_ids("container") == containers_before
    assert DockerRuntime.listed_ids("network") == networks_before
    evidence["module_after"] = _modules()
    assert evidence["module_after"] == modules_before
    evidence["cleanup"] = "owner resources absent; foreign Docker IDs unchanged"
    path = Path("reports") / f"{run_id}-queue-recheck.json"
    with path.open("x", encoding="utf-8") as out:
        json.dump(evidence, out, indent=2, sort_keys=True)
        out.write("\n")
    print(path)
