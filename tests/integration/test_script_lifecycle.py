"""Opt-in real locked AArch64 one-shot script lifecycle and owned cleanup."""

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu.cli import cli
from keemu.docker_runtime import DockerRuntime
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_stage import ScriptStager

IMAGE = "sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224"
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.docker
def test_one_shot_live_cases(tmp_path: Path, monkeypatch):
    if os.getenv("KEEMU_TEST_SCRIPT_LIFECYCLE") != "1":
        pytest.skip("opt in to locked AArch64 script one-shot Docker/binfmt probe")
    foreign_id = "m1d05-foreign-" + uuid.uuid4().hex[:12]
    foreign = DockerRuntime(foreign_id, IMAGE)
    foreign_container = foreign.create("keemu-" + foreign_id)
    try:
        foreign.start(foreign_container)
        foreign_before = foreign.inspect("container", foreign_container)
        cases = (
            ("success.sh", (), 0, 60, "PASS", 0, b"KEEMU_OK", b""),
            ("exit-7.sh", (), 0, 60, "FAIL", 7, b"", b"expected failure"),
            ("exit-7.sh", (), 7, 60, "PASS", 7, b"", b"expected failure"),
            (
                "argv.sh",
                ("literal;$(false)", "two words"),
                0,
                60,
                "PASS",
                0,
                b"two words",
                b"",
            ),
            ("streams.sh", (), 0, 60, "PASS", 0, b"", b""),
            ("filesystem.sh", (), 0, 60, "PASS", 0, b"", b""),
            ("timeout-process.sh", (), 0, 1, "FAIL", None, b"child=", b""),
        )
        for name, args, expected, timeout, status, code, stdout, stderr in cases:
            run_id = "m1d05-" + uuid.uuid4().hex[:12]
            with monkeypatch.context() as patch:
                if name == "filesystem.sh":
                    original_cleanup = ScriptStager.cleanup

                    def check_effect(self, staged, cleanup=original_cleanup):
                        content = self.runtime.exec(
                            staged.container_id,
                            [
                                "/opt/bin/busybox",
                                "cat",
                                "/opt/tmp/keemu-script-test-result",
                            ],
                        )
                        assert content.stdout == b"KEEMU_SCRIPT_TEST\n"
                        return cleanup(self, staged)

                    patch.setattr(ScriptStager, "cleanup", check_effect)
                if name == "success.sh":
                    original_stage = ScriptStager.stage

                    def check_isolation(self, source, container, stage=original_stage):
                        host = self.runtime.inspect("container", container)[
                            "HostConfig"
                        ]
                        assert host["Privileged"] is False
                        assert host["NetworkMode"] == "none" and not host["PidMode"]
                        assert not host.get("Binds") and not host.get("Mounts")
                        assert "ALL" in host["CapDrop"] and not host.get("CapAdd")
                        assert not host.get("PortBindings")
                        target = self.runtime.exec(
                            container,
                            ["/bin/sh", "-c", "test ! -e /var/run/docker.sock"],
                        )
                        assert target.exit_code == 0
                        return stage(self, source, container)

                    patch.setattr(ScriptStager, "stage", check_isolation)
                result = run_one_shot_script(
                    f"fixtures/scripts/mvp1d/{name}",
                    project_root=ROOT,
                    argv=args,
                    timeout_seconds=timeout,
                    expected_exit_code=expected,
                    run_id=run_id,
                    report_root=tmp_path,
                )
            script = result.script
            assert result.report.overall == script.status == status, name
            if code is not None:
                assert script.outcome.exit_code == code, name
            assert stdout in script.outcome.stdout and stderr in script.outcome.stderr
            if name == "argv.sh":
                assert script.outcome.stdout == (
                    b"argc=2\narg1=<literal;$(false)>\narg2=<two words>\n"
                )
            assert script.outcome.process_tree_clean
            assert script.outcome.timed_out == (name == "timeout-process.sh")
            assert all(item.verified for item in script.cleanup)
            assert (
                script.spec.sha256
                == hashlib.sha256(
                    (ROOT / "fixtures/scripts/mvp1d" / name).read_bytes()
                ).hexdigest()
            )
            assert script.spec.container_id and script.spec.target_path
            payload = result.paths.json.read_text()
            assert (
                json.loads(payload)["script"]["outcome"]["stdout"]["sha256"]
                == hashlib.sha256(script.outcome.stdout).hexdigest()
            )
            assert "literal;$(false)" not in payload
            assert DockerRuntime(run_id, IMAGE).reconcile() == {
                "container_owned": [],
                "container_unexpected": [],
                "container_missing": [],
                "network_owned": [],
                "network_unexpected": [],
                "network_missing": [],
            }
            assert (
                foreign.inspect("container", foreign_container)["Id"]
                == foreign_before["Id"]
            )
        # Mutation after validation, before stage: never execute changed input.
        original = ScriptStager.stage

        def mutate(self, script, container):
            path = script.source_path
            path.write_bytes(b"exit 99\n")
            return original(self, script, container)

        test_dir = ROOT / ".runtime" / ("script-mutation-" + uuid.uuid4().hex)
        test_dir.mkdir(mode=0o700)
        try:
            (test_dir / "cwd.sh").write_bytes(
                b'test -z "${KEEMU_HOST_SECRET_SENTINEL+x}" || exit 99\n'
                b"test ! -e /var/run/docker.sock || exit 98\npwd\n"
            )
            monkeypatch.setenv("KEEMU_HOST_SECRET_SENTINEL", "host-only-value")
            cwd_id = "m1d05-" + uuid.uuid4().hex[:12]
            cwd_result = run_one_shot_script(
                str((test_dir / "cwd.sh").relative_to(ROOT)),
                project_root=ROOT,
                run_id=cwd_id,
                cwd="/opt/etc",
                report_root=tmp_path,
            )
            assert cwd_result.script.status == "PASS"
            assert cwd_result.script.outcome.stdout == b"/opt/etc\n"
            assert "host-only-value" not in cwd_result.paths.json.read_text()
            assert DockerRuntime(cwd_id, IMAGE).reconcile()["container_owned"] == []
            (test_dir / "mutation.sh").write_bytes(b"echo original\n")
            with monkeypatch.context() as patch:
                patch.setattr(ScriptStager, "stage", mutate)
                run_id = "m1d05-" + uuid.uuid4().hex[:12]
                blocked = run_one_shot_script(
                    str((test_dir / "mutation.sh").relative_to(ROOT)),
                    project_root=ROOT,
                    run_id=run_id,
                    report_root=tmp_path,
                )
        finally:
            shutil.rmtree(test_dir)
        assert blocked.report.overall == "BLOCKED"
        assert blocked.script.outcome.state == "blocked"
        assert (
            blocked.script.cleanup[0].kind == "container"
            and blocked.script.cleanup[0].verified
        )
        assert DockerRuntime(run_id, IMAGE).reconcile()["container_owned"] == []
    finally:
        foreign.remove_container(foreign_container)
        assert foreign.reconcile()["container_owned"] == []


@pytest.mark.docker
def test_one_shot_collision_and_cleanup_retry(tmp_path: Path, monkeypatch):
    if os.getenv("KEEMU_TEST_SCRIPT_LIFECYCLE") != "1":
        pytest.skip("opt in to locked AArch64 script cleanup probe")
    run_id = "m1d05-" + uuid.uuid4().hex[:12]
    runtime = DockerRuntime(run_id, IMAGE)
    container = runtime.create("keemu-" + run_id)
    try:
        runtime.start(container)
        blocked = run_one_shot_script(
            "fixtures/scripts/mvp1d/success.sh",
            project_root=ROOT,
            run_id=run_id,
            report_root=tmp_path,
        )
        assert blocked.report.overall == "BLOCKED"
        assert blocked.script.spec.container_id is None
        assert runtime.inspect("container", container)["State"]["Running"]
    finally:
        runtime.remove_container(container)

    retry_id = "m1d05-" + uuid.uuid4().hex[:12]
    original = DockerRuntime.remove_container

    def fail_once(self, identifier):
        if self.run_id == retry_id:
            raise RuntimeError("injected cleanup refusal")
        return original(self, identifier)

    with monkeypatch.context() as patch:
        patch.setattr(DockerRuntime, "remove_container", fail_once)
        result = run_one_shot_script(
            "fixtures/scripts/mvp1d/success.sh",
            project_root=ROOT,
            run_id=retry_id,
            report_root=tmp_path,
        )
    retry = DockerRuntime(retry_id, IMAGE)
    owned = retry.reconcile()["container_owned"]
    try:
        assert result.report.overall == "ERROR"
        assert result.script.cleanup[-1].reason_code == "container-cleanup-unverified"
        assert owned == [result.script.spec.container_id]
        retry.remove_container(owned[0])
    finally:
        for identifier in retry.reconcile()["container_owned"]:
            retry.remove_container(identifier)
    assert retry.reconcile()["container_owned"] == []


@pytest.mark.docker
def test_script_cli_runs_locked_one_shot_contract(tmp_path: Path) -> None:
    if os.getenv("KEEMU_TEST_SCRIPT_LIFECYCLE") != "1":
        pytest.skip("opt in to locked AArch64 script one-shot Docker/binfmt probe")

    result = CliRunner().invoke(
        cli,
        [
            "script",
            "fixtures/scripts/mvp1d/argv.sh",
            "--profile",
            "generic-aarch64",
            "--repo",
            str(ROOT),
            "--cwd",
            "/opt/etc",
            "--expect-exit-code",
            "0",
            "--",
            "literal;$(false)",
            "two words",
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["overall"] == "PASS"
    assert report["script"]["execution"] == {
        "architecture": "aarch64-3.10",
        "argv": [
            {
                "byte_count": len(b"literal;$(false)"),
                "sha256": hashlib.sha256(b"literal;$(false)").hexdigest(),
            },
            {
                "byte_count": len(b"two words"),
                "sha256": hashlib.sha256(b"two words").hexdigest(),
            },
        ],
        "container_id": report["script"]["execution"]["container_id"],
        "cwd": "/opt/etc",
        "image_id": IMAGE,
        "interpreter": "/bin/sh",
        "mode": "one-shot",
        "profile_id": "generic-aarch64",
        "profile_revision": report["profile"]["revision"],
        "sha256": hashlib.sha256(
            (ROOT / "fixtures/scripts/mvp1d/argv.sh").read_bytes()
        ).hexdigest(),
        "source": "fixtures/scripts/mvp1d/argv.sh",
        "target_path": report["script"]["execution"]["target_path"],
        "timeout_seconds": 60,
    }
    assert "literal;$(false)" not in result.output
    assert DockerRuntime(report["run_id"], IMAGE).reconcile()["container_owned"] == []
