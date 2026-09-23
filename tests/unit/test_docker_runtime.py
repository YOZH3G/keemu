"""Portable adversarial tests for the Docker ownership boundary."""

import json

import pytest

from keemu import docker_runtime as dr

IMAGE = "sha256:" + "a" * 64
CID = "b" * 64
NID = "c" * 64


def test_invalid_untrusted_identifiers_never_reach_docker(monkeypatch):
    monkeypatch.setattr(dr, "_exec", lambda *_a, **_kw: pytest.fail("Docker called"))
    for run_id in ("x", "evil; rm -rf /", "a\nlabel", ""):
        with pytest.raises(dr.DockerBoundaryError):
            dr.DockerRuntime(run_id, IMAGE)
    for image in ("latest", "sha256:abc", "sha256:" + "Z" * 64):
        with pytest.raises(dr.DockerBoundaryError):
            dr.DockerRuntime("valid-run", image)
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    for identifier in ("keemu-name", "b" * 12, "--all"):
        with pytest.raises(dr.DockerBoundaryError):
            runtime.remove_container(identifier)
    for name in ("evil;touch /tmp/x", "a b", "--help"):
        with pytest.raises(dr.DockerBoundaryError):
            runtime.create(name)
    with pytest.raises(dr.DockerBoundaryError):
        runtime.exec(CID, [])  # ownership probe is allowed; execution is not


def test_foreign_labels_refuse_stop_remove_and_exec(monkeypatch):
    calls = []

    def fake_json(argv):
        calls.append(argv)
        return [
            {
                "Id": CID,
                "Image": IMAGE,
                "Config": {
                    "Labels": {
                        dr.OWNER: "other",
                        dr.RUN: "valid-run",
                        dr.KIND: "container",
                        dr.BASE: IMAGE,
                    }
                },
            }
        ]

    monkeypatch.setattr(dr, "_json", fake_json)
    monkeypatch.setattr(dr, "_exec", lambda *_a, **_kw: pytest.fail("Docker mutated"))
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    for operation in (
        runtime.stop,
        runtime.remove_container,
        lambda c: runtime.exec(c, ["/bin/sh"]),
    ):
        with pytest.raises(dr.DockerBoundaryError, match="ownership"):
            operation(CID)
    assert len(calls) == 3


def test_reconciliation_never_adopts_wrong_base_or_foreign_resources(monkeypatch):
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    seen = []

    def fake_exec(argv, **kwargs):
        seen.append(argv)
        return dr.Output((CID + "\n").encode() if argv[1] == "container" else b"", b"")

    monkeypatch.setattr(dr, "_exec", fake_exec)
    monkeypatch.setattr(
        runtime,
        "inspect",
        lambda kind, identifier: {"Id": identifier}
        if kind == "container"
        else pytest.fail("unexpected inspect"),
    )
    state = runtime.reconcile(frozenset({CID, NID}), frozenset())
    assert state["container_unexpected"] == []
    assert state["container_missing"] == [NID]
    assert all(command[2] in {"ls"} for command in seen)
    assert all(
        any("label=org.keemu.run-id=valid-run" == arg for arg in command)
        for command in seen
    )


def test_command_bounds_and_per_stream_truncation(monkeypatch):
    with pytest.raises(dr.DockerBoundaryError, match="invalid Docker argv"):
        dr._exec(["sh", "-c", "docker ps"])
    with pytest.raises(dr.DockerBoundaryError, match="invalid Docker argv"):
        dr._exec(["docker", "ps\0x"])
    assert json.loads(json.dumps({"limit": dr.LOG_LIMIT})) == {
        "limit": 20 * 1024 * 1024
    }


def test_logs_mark_each_truncated_stream_without_exposing_unbounded_data(monkeypatch):
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    monkeypatch.setattr(runtime, "inspect", lambda kind, identifier: {"Id": identifier})
    monkeypatch.setattr(
        dr,
        "_exec",
        lambda argv, **kwargs: (
            dr.Output(b"a", b"b", True, False)
            if kwargs.get("truncate") and kwargs.get("limit") == dr.LOG_LIMIT
            else pytest.fail("unbounded logs request")
        ),
    )
    result = runtime.logs(CID)
    assert result.stdout == b"a\n[KEEMU log stream truncated at 20 MiB]\n"
    assert result.stderr == b"b"
    assert result.truncated_stdout and not result.truncated_stderr


def test_writable_threshold_stops_only_verified_container(monkeypatch):
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    inspected = []
    stopped = []
    monkeypatch.setattr(
        runtime, "inspect", lambda kind, identifier: inspected.append(identifier)
    )
    monkeypatch.setattr(runtime, "stop", lambda identifier: stopped.append(identifier))
    monkeypatch.setattr(
        dr,
        "_json",
        lambda argv: [{"Id": CID, "SizeRw": dr.WRITABLE_THRESHOLD}],
    )
    with pytest.raises(dr.DockerBoundaryError, match="threshold"):
        runtime.check_writable_layer(CID)
    assert inspected == [CID]
    assert stopped == [CID]
    stopped.clear()
    monkeypatch.setattr(dr, "_json", lambda argv: [{"Id": NID, "SizeRw": 0}])
    with pytest.raises(dr.DockerBoundaryError, match="identity"):
        runtime.check_writable_layer(CID)
    assert stopped == []


def test_unexpected_labeled_resource_is_reported_not_removed(monkeypatch):
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    calls = []

    def fake_exec(argv, **kwargs):
        calls.append(argv)
        return dr.Output((CID + "\n").encode() if argv[1] == "container" else b"", b"")

    monkeypatch.setattr(dr, "_exec", fake_exec)
    monkeypatch.setattr(runtime, "inspect", lambda kind, identifier: {"Id": identifier})
    result = runtime.reconcile()
    assert result["container_unexpected"] == [CID]
    assert result["network_unexpected"] == []
    assert all("rm" not in command and "stop" not in command for command in calls)


def test_attached_network_never_removed(monkeypatch):
    runtime = dr.DockerRuntime("valid-run", IMAGE)
    monkeypatch.setattr(
        runtime, "inspect", lambda kind, identifier: {"Containers": {CID: {}}}
    )
    monkeypatch.setattr(dr, "_exec", lambda *_a, **_kw: pytest.fail("network removed"))
    with pytest.raises(dr.DockerBoundaryError, match="attached"):
        runtime.remove_network(NID)
