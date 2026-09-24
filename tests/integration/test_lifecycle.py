"""Opt-in real Docker/binfmt IPK lifecycle from generated inputs."""

# ruff: noqa: E501
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.lifecycle import run_scenario

ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package(
    *,
    failed_postinst: bool = False,
    architecture: str = "aarch64-3.10",
    hello: bytes = b"#!/bin/sh\necho KEEMU-HELLO\n",
    web_demo: bool = False,
) -> bytes:
    script = (
        b"#!/bin/sh\nexit 13\n"
        if failed_postinst
        else b"#!/bin/sh\nn=0\n[ -f /opt/etc/keemu-count ] && read n < /opt/etc/keemu-count\necho $((n+1)) > /opt/etc/keemu-count\n"
    )
    metadata = (
        f"Package: keemu-hello\nVersion: 1.0\nArchitecture: {architecture}\n".encode()
        + b"Source: fixtures/keemu-hello\nSourceName: keemu-hello\nSection: utils\n"
        b"SourceDateEpoch: 1770000000\nURL: https://example.invalid/\n"
        b"Maintainer: KEEMU test fixture\nInstalled-Size: 100\n"
        b"Description:  test-only hello\n"
    )
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime") as folder:
        root = Path(folder)
        control_dir = root / "control-src"
        data_dir = root / "data-src"
        (data_dir / "opt/bin").mkdir(parents=True)
        control_dir.mkdir()
        (control_dir / "control").write_bytes(metadata)
        (control_dir / "postinst").write_bytes(script)
        (control_dir / "postinst").chmod(0o755)
        (data_dir / "opt/bin/keemu-hello").write_bytes(hello)
        (data_dir / "opt/bin/keemu-hello").chmod(0o755)
        if web_demo:
            locked = json.loads(
                (ROOT / "locks/p0-web-demo-aarch64-p006.json").read_text()
            )
            binary = (ROOT / ".runtime/p0/fixtures/aarch64/web-demo-p006").read_bytes()
            assert digest(binary) == locked["binary_sha256"]
            (data_dir / "opt/bin/web-demo").write_bytes(binary)
            (data_dir / "opt/bin/web-demo").chmod(0o755)
        for source, name in (
            (control_dir, "control.tar.gz"),
            (data_dir, "data.tar.gz"),
        ):
            members = ["control", "postinst"] if name == "control.tar.gz" else ["."]
            subprocess.run(  # noqa: S603 -- fixed fixture archive builder
                [
                    "/usr/bin/tar",
                    "--format=gnu",
                    "--owner=0",
                    "--group=0",
                    "-czf",
                    str(root / name),
                    "-C",
                    str(source),
                    *members,
                ],
                check=True,
            )
        (root / "debian-binary").write_bytes(b"2.0\n")
        subprocess.run(  # noqa: S603 -- fixed fixture archive builder
            [
                "/usr/bin/tar",
                "--format=gnu",
                "--owner=0",
                "--group=0",
                "-czf",
                str(root / "hello.ipk"),
                "-C",
                str(root),
                "./debian-binary",
                "./data.tar.gz",
                "./control.tar.gz",
            ],
            check=True,
        )
        return (root / "hello.ipk").read_bytes()


def inputs(directory: Path, **package_options) -> tuple[Path, Path]:
    base = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())
    name = "hello.ipk"
    blob = package(**package_options)
    (directory / name).write_bytes(blob)
    scenario = directory / "scenario.yaml"
    scenario.write_text("""schema_version: 1
id: keemu-hello
profile: generic-aarch64
install: {kind: ipk, path: hello.ipk, package_name: keemu-hello}
service: null
runtime: {env: {}, cwd: /opt, settle_seconds: 0, publish: []}
requirements: {capabilities: [], ndm_fixtures: []}
checks:
  - id: postinst-once
    kind: command
    command: {argv: [/bin/sh, -c, 'read n < /opt/etc/keemu-count; test "$n" = 1'], timeout_seconds: 10}
    expected_exit_code: 0
  - id: executable
    kind: command
    command: {argv: [/opt/bin/keemu-hello], timeout_seconds: 10}
    expected_exit_code: 0
persistence: {paths: []}
cleanup: {allowed_residual_paths: [/opt/etc/keemu-count]}
""")
    lock = directory / "scenario-lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "scenario-lock",
                "scenario_id": "keemu-hello",
                "scenario_sha256": digest(scenario.read_bytes()),
                "profile_id": "generic-aarch64",
                "profile_revision": 1,
                "profile_sha256": digest(
                    (ROOT / "profiles/generic/generic-aarch64.yaml").read_bytes()
                ),
                "entware_target": "aarch64-3.10",
                "oci_digest": base["oci_digest"],
                "qemu_version": "10.0.13",
                "feed_lock_sha256": base["input_lock_sha256"],
                "sources": [
                    {
                        "id": "keemu-hello",
                        "kind": "ipk",
                        "path": name,
                        "sha256": digest(blob),
                        "origin": "project-test-fixture",
                        "release": "1.0",
                        "architecture": "aarch64",
                    }
                ],
            }
        )
    )
    return scenario, lock


def bind_scenario(lock: Path, scenario: Path) -> None:
    data = json.loads(lock.read_text())
    data["scenario_sha256"] = digest(scenario.read_bytes())
    lock.write_text(json.dumps(data))


def assert_failed_run(result, *, stage: str, status: str) -> None:
    report = result.report
    assert report.overall == status, result.paths.json
    assert report.partial_failure is not None
    assert report.partial_failure.operation == stage
    assert report.partial_failure.cleanup_status == "PASS"
    assert report.checks[-1].status == "PASS"
    assert json.loads(result.paths.json.read_text())["overall"] == status
    assert f"**{status}**" in result.paths.markdown.read_text()
    entries = [
        json.loads(line) for line in result.paths.operation_log.read_text().splitlines()
    ]
    assert entries[report.partial_failure.operation_sequence - 1]["operation"] == stage


@pytest.mark.docker
def test_real_ipk_success_and_failed_postinst():
    if os.getenv("KEEMU_TEST_LIFECYCLE") != "1":
        pytest.skip("opt in to disposable Docker lifecycle test")
    runtime_root = ROOT / ".runtime"
    runtime_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runtime_root, prefix="m1a13-") as folder:
        directory = Path(folder)
        for fail in (False, True):
            scenario, lock = inputs(directory, failed_postinst=fail)
            result = run_scenario(
                scenario,
                lock,
                project_root=ROOT,
                report_root=ROOT / "reports",
                run_id="m1a13-" + uuid.uuid4().hex[:12],
            )
            report = result.report
            assert report.overall == ("FAIL" if fail else "PASS"), result.paths.json
            assert result.paths.markdown.read_text().find(report.overall) >= 0
            assert (
                json.loads(result.paths.json.read_text())["overall"] == report.overall
            )
            assert report.checks[-1].id == "cleanup"
            assert report.checks[-1].status == "PASS"
            assert (
                report.partial_failure is not None
                if fail
                else report.partial_failure is None
            )
            assert result.paths.operation_log.read_text()
            assert (
                digest(
                    (result.paths.json.parent / "resolved-scenario.yaml").read_bytes()
                )
                == report.scenario.sha256
            )
            assert (result.paths.json.parent / "lock.json").is_file()
            if fail:
                install = next(
                    op for op in report.operation_log if op.operation == "install"
                )
                assert install.exit_code != 0
                assert (result.paths.json.parent / install.stderr_path).is_file()
            else:
                diff = json.loads(
                    (result.paths.json.parent / "filesystem.diff.json").read_text()
                )
                assert diff["kind"] == "docker-diff-metadata"
                assert diff["baseline"] != diff["after"]
            print(
                json.dumps(
                    {
                        "report": str(result.paths.json),
                        "overall": report.overall,
                        "checks": [(c.id, c.status) for c in report.checks],
                    }
                )
            )

        # A real startup failure and a bounded target-command timeout must each
        # preserve their own partial report and remove the disposable container.
        scenario, lock = inputs(directory)
        scenario.write_text(
            scenario.read_text().replace(
                "service: null",
                "service: {start: [/opt/bin/busybox, 'false'], "
                "stop: [/opt/bin/busybox, 'true'], readiness: {kind: http, "
                "vantage: target_loopback, url: 'http://127.0.0.1:18765/health', "
                "expected_status: [200], body_contains: ready}}",
            )
        )
        bind_scenario(lock, scenario)
        startup = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-startup-" + uuid.uuid4().hex[:12],
        )
        assert_failed_run(startup, stage="service-start", status="FAIL")

        scenario, lock = inputs(directory)
        scenario.write_text(
            scenario.read_text().replace(
                "argv: [/bin/sh, -c, 'read n < /opt/etc/keemu-count; test \"$n\" = 1'], timeout_seconds: 10",
                "argv: [/opt/bin/busybox, sleep, '10'], timeout_seconds: 1",
            )
        )
        bind_scenario(lock, scenario)
        timed = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-timeout-" + uuid.uuid4().hex[:12],
        )
        assert_failed_run(timed, stage="check-postinst-once", status="ERROR")
        assert timed.report.operation_log[
            timed.report.partial_failure.operation_sequence - 1
        ].timed_out

        scenario, lock = inputs(directory, web_demo=True)
        scenario.write_text(
            scenario.read_text().replace(
                "service: null",
                "service:\n"
                "  start: [/bin/sh, -c, "
                "'/opt/bin/web-demo 18765 18766 /opt/etc/keemu-count "
                ">/dev/null 2>&1 & echo $! > /opt/tmp/web-demo.pid']\n"
                "  stop: [/bin/sh, -c, "
                '\'read pid < /opt/tmp/web-demo.pid; kill -TERM "$pid"; '
                "/opt/bin/busybox rm -f /opt/tmp/web-demo.pid']\n"
                "  readiness: {kind: http, vantage: target_loopback, "
                "url: 'http://127.0.0.1:18765/health', "
                "expected_status: [200], body_contains: 'state=1', "
                "timeout_seconds: 5}",
            )
        )
        bind_scenario(lock, scenario)
        service = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-service-" + uuid.uuid4().hex[:12],
        )
        assert service.report.overall == "PASS", service.paths.json
        assert {"readiness", "service-closed", "residual"}.issubset(
            {check.id for check in service.report.checks if check.status == "PASS"}
        )


@pytest.mark.parametrize(
    ("options", "finding"),
    [
        ({"architecture": "mipsel-3.4"}, "architecture"),
        ({"hello": b"#!relative-interpreter\n"}, "shebang"),
    ],
)
def test_static_defect_reports_fail_before_docker(options, finding):
    # Inputs must live beneath the project for the no-follow confinement check.
    runtime_root = ROOT / ".runtime"
    runtime_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=runtime_root, prefix="m1a13-static-"
    ) as folder:
        scenario, lock = inputs(Path(folder), **options)
        result = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-static-" + uuid.uuid4().hex[:12],
        )
    report = result.report
    assert report.overall == "FAIL"
    assert report.partial_failure.operation == "inspect"
    assert finding in report.partial_failure.message
    assert report.checks[-1].status == "PASS"
    assert report.checks[-1].evidence == ("no Docker resources allocated by this run",)
    assert result.paths.json.exists() and result.paths.markdown.exists()


def test_malformed_package_cli_returns_2_and_keeps_report():
    runtime_root = ROOT / ".runtime"
    runtime_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=runtime_root, prefix="m1a13-invalid-"
    ) as folder:
        scenario, lock = inputs(Path(folder))
        blob = b"invalid fixture archive"
        (Path(folder) / "hello.ipk").write_bytes(blob)
        lock_data = json.loads(lock.read_text())
        lock_data["sources"][0]["sha256"] = digest(blob)
        lock.write_text(json.dumps(lock_data))
        result = CliRunner().invoke(
            cli,
            [
                "test",
                "--scenario",
                str(scenario),
                "--lock",
                str(lock),
                "--repo",
                str(ROOT),
            ],
        )
    assert result.exit_code == 2, result.output
    report = json.loads(result.output)
    assert report["overall"] == "ERROR"
    assert report["partial_failure"]["operation"] == "inspect"
    assert report["checks"][-1]["status"] == "PASS"
    assert (ROOT / "reports" / report["run_id"] / "report.json").is_file()


def test_run_id_collision_never_removes_preexisting_resource(monkeypatch):
    from keemu import lifecycle
    from keemu.docker_runtime import DockerRuntime

    runtime_root = ROOT / ".runtime"
    runtime_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=runtime_root, prefix="m1a13-collision-"
    ) as folder:
        scenario, lock = inputs(Path(folder))
        base = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())
        monkeypatch.setattr(lifecycle, "init_locked", lambda *_args, **_kw: base)
        monkeypatch.setattr(DockerRuntime, "image", lambda self: {})
        monkeypatch.setattr(
            DockerRuntime,
            "reconcile",
            lambda self: {"container_owned": ["a" * 64], "network_owned": []},
        )

        def forbidden(*_args, **_kwargs):
            raise AssertionError("pre-existing resource was mutated")

        monkeypatch.setattr(DockerRuntime, "create", forbidden)
        monkeypatch.setattr(DockerRuntime, "remove_container", forbidden)
        result = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-collision-" + uuid.uuid4().hex[:12],
        )
    assert result.report.overall == "BLOCKED"
    assert result.report.partial_failure.operation == "create"
    assert result.report.checks[-1].status == "PASS"


@pytest.mark.docker
def test_cleanup_failure_preserves_primary_failure(monkeypatch):
    if os.getenv("KEEMU_TEST_LIFECYCLE") != "1":
        pytest.skip("opt in to disposable Docker lifecycle test")
    from keemu.docker_runtime import DockerRuntime

    original_remove = DockerRuntime.remove_container

    def remove_then_report_failure(runtime, identifier):
        original_remove(runtime, identifier)
        raise RuntimeError("injected cleanup error after removal")

    runtime_root = ROOT / ".runtime"
    runtime_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=runtime_root, prefix="m1a13-cleanup-"
    ) as folder:
        scenario, lock = inputs(Path(folder), failed_postinst=True)
        monkeypatch.setattr(
            DockerRuntime, "remove_container", remove_then_report_failure
        )
        result = run_scenario(
            scenario,
            lock,
            project_root=ROOT,
            run_id="m1a13-cleanup-" + uuid.uuid4().hex[:12],
        )
    assert result.report.overall == "ERROR"
    assert result.report.partial_failure is not None
    assert result.report.partial_failure.operation == "install"
    assert result.report.partial_failure.status == "FAIL"
    assert result.report.partial_failure.cleanup_status == "ERROR"
    assert result.report.checks[-1].id == "cleanup"
    assert result.report.checks[-1].status == "ERROR"
    assert result.paths.json.is_file()
