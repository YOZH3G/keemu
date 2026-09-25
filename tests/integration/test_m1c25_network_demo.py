"""Opt-in AArch64 API-only web/state and restart evidence, not packet proof."""

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
BINARY = Path(".runtime/m1c24/network-demo-aarch64")
LOCK = Path("locks/m1c24-network-demo-aarch64.json")
MODE = "/opt/etc/network-demo/mode"
RECORD_HASHES = {
    "web-api": "150b32bee85ae0621576fdd29be639b4d1e71b986941d3da5528e6ed8b9ecab4",
    "persistence": "1728e3977fa3c0ead36c5294d5be3db7683f78dfcfe0d1f540b7e66e21b5eab4",
}


def _request(runtime, client, address, path, *, mode=None):
    command = [BUSYBOX, "wget", "-qO-"]
    if mode is not None:
        command.extend(["--post-data", f"mode={mode}"])
    command.append(f"http://{address}:9090{path}")
    result = runtime.exec(client, command, allow_failure=True)
    return {
        "exit_code": result.exit_code,
        "body": result.stdout.decode("utf-8", "replace"),
        "stderr": result.stderr.decode("utf-8", "replace"),
    }


def _state(runtime, client, address, mode):
    observed = _request(runtime, client, address, "/api/state")
    assert observed["exit_code"] == 0, observed
    assert json.loads(observed["body"]) == {
        "mode": mode,
        "queue_ready": False,
        "accepted": 0,
        "dropped": 0,
    }, observed
    return observed


def _mode_file(runtime, router):
    return runtime.exec(router, [BUSYBOX, "cat", MODE]).stdout.decode()


def _save(name, record):
    path = Path("reports") / f"{name}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(record, output, indent=2, sort_keys=True)
        output.write("\n")
    return path


def test_frozen_web_and_persistence_evidence():
    records = {}
    for kind, digest in RECORD_HASHES.items():
        raw = Path(f"docs/evidence/m1c25-{kind}.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        record = json.loads(raw)
        assert record["slice_result"] == "PASS"
        assert record["whole_id"] == "PARTIAL"
        assert record["mode"] == "api-only"
        assert (
            record["fixture_sha256"] == json.loads(LOCK.read_text())["binary"]["sha256"]
        )
        local_report = Path(f"reports/{record['run_id']}-{kind}.json")
        if local_report.exists():
            assert raw == local_report.read_bytes()
        records[kind] = record
    web, persistence = records["web-api"], records["persistence"]
    assert web["run_id"] == persistence["run_id"]
    assert web["observations"]["mode_file"] == "drop\n"
    assert persistence["observations"]["mode_file"] == "drop\n"
    assert (
        json.loads(persistence["observations"]["service_restart"]["body"])["mode"]
        == "drop"
    )
    assert (
        json.loads(persistence["observations"]["environment_restart"]["body"])["mode"]
        == "drop"
    )
    assert web["network_backend"].startswith("BLOCKED:")
    assert persistence["network_backend"].startswith("BLOCKED:")


@pytest.mark.docker
def test_target_web_api_and_distinct_persistence_records():
    if os.getenv("KEEMU_TEST_NETWORK_DEMO_M1C25") != "1":
        pytest.skip("opt in to target API-only web/persistence observation")
    lock = json.loads(LOCK.read_text())
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    assert digest == lock["binary"]["sha256"]
    run_id = "m1c25-" + uuid.uuid4().hex[:12]
    containers_before = DockerRuntime.listed_ids("container")
    networks_before = DockerRuntime.listed_ids("network")
    web: dict[str, object] = {
        "run_id": run_id,
        "fixture_sha256": digest,
        "mode": "api-only",
        "slice_result": "PASS",
        "whole_id": "PARTIAL",
        "network_backend": "BLOCKED: target queue not ready; no packet path",
    }
    persistence: dict[str, object] = {
        "run_id": run_id,
        "fixture_sha256": digest,
        "mode": "api-only",
        "slice_result": "PASS",
        "whole_id": "PARTIAL",
        "network_backend": "BLOCKED: mode survives restarts, but queue cannot apply it",
    }
    try:
        topo = create(run_id, IMAGE)
        demo = NetworkDemo(topo, IMAGE, digest)
        demo.install(BINARY)
        router, client = topo.containers["router"], topo.containers["client"]
        address = flow(topo).router
        demo.start(api_only=True)
        initial = _state(demo.runtime, client, address, "accept")
        page = _request(demo.runtime, client, address, "/")
        assert page["exit_code"] == 0, page
        assert all(
            token in page["body"]
            for token in ("Network-demo", "value='accept'", "value='drop'")
        )
        health = _request(demo.runtime, client, address, "/health")
        assert health["exit_code"] != 0, health
        drop = _request(demo.runtime, client, address, "/api/mode", mode="drop")
        assert drop["exit_code"] == 0, drop
        assert json.loads(drop["body"])["mode"] == "drop", drop
        changed = _state(demo.runtime, client, address, "drop")
        invalid = _request(demo.runtime, client, address, "/api/mode", mode="invalid")
        assert invalid["exit_code"] != 0, invalid
        assert _state(demo.runtime, client, address, "drop") == changed
        accept = _request(demo.runtime, client, address, "/api/mode", mode="accept")
        assert accept["exit_code"] == 0, accept
        assert json.loads(accept["body"])["mode"] == "accept", accept
        _state(demo.runtime, client, address, "accept")
        drop_again = _request(demo.runtime, client, address, "/api/mode", mode="drop")
        assert drop_again["exit_code"] == 0, drop_again
        assert json.loads(drop_again["body"])["mode"] == "drop", drop_again
        with pytest.raises(DockerBoundaryError, match="target queue not ready"):
            demo.install_rule()
        on_disk = _mode_file(demo.runtime, router)
        assert on_disk == "drop\n"
        web["observations"] = {
            "initial": initial,
            "page": page,
            "health": health,
            "change_to_drop": drop,
            "changed": changed,
            "invalid": invalid,
            "change_to_accept": accept,
            "change_back_to_drop": drop_again,
            "rule_install": "refused: target queue not ready",
            "mode_file": on_disk,
        }
        demo.stop()
        stopped = _request(demo.runtime, client, address, "/api/state")
        assert stopped["exit_code"] != 0, stopped
        demo.start(api_only=True)
        service = _state(demo.runtime, client, address, "drop")
        assert _mode_file(demo.runtime, router) == on_disk
        demo.stop()
        demo.runtime.stop(router)
        assert not demo.runtime.inspect("container", router)["State"]["Running"]
        demo.runtime.start(router)
        assert demo.runtime.inspect("container", router)["State"]["Running"]
        demo.start(api_only=True)
        environment = _state(demo.runtime, client, address, "drop")
        assert _mode_file(demo.runtime, router) == on_disk
        persistence["observations"] = {
            "service_stop_refused": stopped,
            "service_restart": service,
            "environment_restart": environment,
            "container_id_unchanged": router,
            "mode_file": on_disk,
        }
        persistence["scope"] = (
            "same Docker container stopped/started; API-only service relaunched; "
            "br0 routing not reconfigured or asserted after restart"
        )
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
    assert DockerRuntime.listed_ids("container") == containers_before
    assert DockerRuntime.listed_ids("network") == networks_before
    web["cleanup"] = persistence["cleanup"] = (
        "owner-verified absent; foreign IDs unchanged"
    )
    print(_save(run_id + "-web-api", web))
    print(_save(run_id + "-persistence", persistence))
