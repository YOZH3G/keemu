"""Frozen E07: real bounded three-target adversity, not D02/D07 hardening."""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime
from keemu.lifecycle import run_scenario
from keemu.persistent import create, operate, recover
from keemu.registry import Registry, RegistryError
from keemu.script_input import ScriptInput, ScriptInputChanged
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_persistent import run_persistent_script
from keemu.script_stage import ScriptStager
from tests.integration.m1e06_support import (
    ROOT,
    TARGETS,
    case_dir,
    destroy,
    digest,
    kill,
    no_report,
    pin,
    preserve,
    publish,
    recover_one_shot,
    scenario,
    snapshot,
    wait_barrier,
    worker,
)

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("KEEMU_TEST_M1E06") != "1",
        reason="opt in to frozen real E07",
    ),
]


@pytest.fixture
def foreign():
    """Exact test-owned foreign run and unattached internal bridge sentinels."""
    before = snapshot()
    run = "m1e06-foreign-" + uuid4().hex[:12]
    runtime = DockerRuntime(run, pin("generic-aarch64")["oci_digest"])
    identifier = runtime.create("keemu-" + run)
    network = None
    try:
        runtime.start(identifier)
        network = runtime.create_network("keemu-" + run, internal=True)
        sentinel = snapshot()
        yield sentinel
        preserve(sentinel)
    finally:
        runtime.remove_container(identifier)
        if network is not None:
            runtime.remove_network(network)
    assert snapshot() == before


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_stage_mutation_collision_exact_retry(
    profile, target, lock_name, monkeypatch, foreign
):
    directory = case_dir("stage-" + profile)
    runtime = DockerRuntime(
        "m1e06-stage-" + uuid4().hex[:12], pin(profile)["oci_digest"], target=target
    )
    identifier = runtime.create("keemu-" + runtime.run_id)
    try:
        runtime.start(identifier)
        host = runtime.inspect("container", identifier)["HostConfig"]
        assert host["NetworkMode"] == "none" and not host["Privileged"]
        assert not host["PidMode"] and not host.get("Binds")
        assert not host.get("Mounts") and not host.get("CapAdd")
        assert not host.get("PortBindings") and "ALL" in host["CapDrop"]
        source_path = directory / "source.sh"
        original = b"#!/bin/sh\nprintf 'checked-input\\n'\n"
        source_path.write_bytes(original)
        source = ScriptInput.validate(source_path, project_root=ROOT)
        replacement = directory / "replacement.sh"
        replacement.write_bytes(original)
        os.replace(replacement, source_path)
        with pytest.raises(ScriptInputChanged):
            source.recheck_for_staging()
        source = ScriptInput.validate(source_path, project_root=ROOT)
        stager = ScriptStager(runtime)
        original_identity = stager._identity
        changed = False

        def mutate_after_recheck(container, path, *, directory):
            nonlocal changed
            if path == "/opt/tmp" and not changed:
                changed = True
                source_path.write_bytes(b"#!/bin/sh\nexit 99\n")
            return original_identity(container, path, directory=directory)

        with monkeypatch.context() as scoped:
            scoped.setattr("keemu.script_stage.secrets.token_hex", lambda _: "a" * 24)
            scoped.setattr(stager, "_identity", mutate_after_recheck)
            staged = stager.stage(source, identifier)
            assert changed and staged.sha256 == digest(original)
            stager.verify(staged)
            with pytest.raises(ScriptInputChanged):
                source.recheck_for_staging()
            source_path.write_bytes(original)
            with pytest.raises(DockerBoundaryError):
                stager.stage(
                    ScriptInput.validate(source_path, project_root=ROOT), identifier
                )
            stager.verify(staged)
        original_exec = stager._exec

        def refuse(container, command, *args, **kwargs):
            if 'rm -- "$file"' in command:
                raise DockerBoundaryError("injected exact target cleanup refusal")
            return original_exec(container, command, *args, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(stager, "_exec", refuse)
            assert not stager.cleanup(staged).success
        stager.verify(staged)
        assert stager.cleanup(staged).success
        assert (
            runtime.exec(
                identifier,
                ["/opt/bin/busybox", "test", "-e", staged.path],
                allow_failure=True,
            ).exit_code
            == 1
        )
        replaced = stager.stage(
            ScriptInput.validate(source_path, project_root=ROOT), identifier
        )
        parent = replaced.path.rsplit("/", 1)[0]
        runtime.exec(
            identifier,
            [
                "/bin/sh",
                "-c",
                'printf foreign > "$1"; /opt/bin/busybox mv -- "$1" "$2"',
                "test-owned",
                parent + "/replacement",
                replaced.path,
            ],
        )
        assert not stager.cleanup(replaced).success
        assert (
            runtime.exec(identifier, ["/opt/bin/busybox", "cat", replaced.path]).stdout
            == b"foreign"
        )
        preserve(foreign)
        record = {
            "profile": profile,
            "target": target,
            "container": identifier,
            "source_inode_swap": "BLOCKED",
            "immutable_snapshot_sha256": staged.sha256,
            "collision": "preserved_no_overwrite",
            "cleanup": "refused_then_exact_issued_retry_PASS",
            "target_inode_replacement": "refused_foreign_bytes_preserved",
            "host_config": host,
            "foreign_preserved": True,
            "atomic_hostile_same_uid_race": "BLOCKED_not_proved",
        }
    finally:
        removal = recover_one_shot(runtime, identifier)
    record["container_teardown"] = removal
    publish(directory / "observation.json", record)


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_ipk_and_script_collisions_reports(profile, target, lock_name, foreign):
    directory = case_dir("lifecycle-" + profile)
    source, lock = scenario(directory / "ipk", profile, target)
    image = pin(profile)["oci_digest"]
    result = run_scenario(
        source, lock, project_root=ROOT, run_id="m1e06-ipk-" + uuid4().hex[:12]
    )
    assert result.report.overall == "PASS"
    assert result.report.runtime.entware_target == target
    assert result.report.checks[-1].status == "PASS"
    records = [
        {
            "case": "ipk-success",
            "path": str(result.paths.json),
            "sha256": digest(result.paths.json.read_bytes()),
            "status": "PASS",
        }
    ]
    run = "m1e06-collision-" + uuid4().hex[:12]
    runtime = DockerRuntime(run, image, target=target)
    identifier = runtime.create("keemu-" + run)
    try:
        before = runtime.inspect("container", identifier)
        ipk = run_scenario(source, lock, project_root=ROOT, run_id=run)
        assert ipk.report.overall == "BLOCKED"
        script = run_one_shot_script(
            "fixtures/scripts/mvp1d/success.sh",
            project_root=ROOT,
            profile_id=profile,
            run_id=run,
            report_root=directory / "script-reports",
        )
        assert script.report.overall == "BLOCKED"
        assert runtime.inspect("container", identifier) == before
        for case, item in (("ipk-collision", ipk), ("script-collision", script)):
            records.append(
                {
                    "case": case,
                    "path": str(item.paths.json),
                    "sha256": digest(item.paths.json.read_bytes()),
                    "status": item.report.overall,
                }
            )
    finally:
        recover_one_shot(runtime, identifier)
    preserve(foreign)
    publish(
        directory / "observation.json",
        {
            "profile": profile,
            "target": target,
            "reports": records,
            "exact_cleanup": True,
            "foreign_preserved": True,
        },
    )


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_sigkill_three_one_shot_boundaries(profile, target, lock_name, foreign):
    directory = case_dir("one-shot-kill-" + profile)
    active = directory / "active.sh"
    active.write_bytes(
        b"#!/bin/sh\nprintf '%s\\n' \"$$\" > /opt/tmp/e07-shell\n"
        b"/opt/bin/busybox sleep 120 &\n"
        b"printf '%s\\n' \"$!\" > /opt/tmp/e07-child\nwait\n"
    )
    records = []
    for phase in ("after-create", "after-stage", "active"):
        run = "m1e06-kill-" + uuid4().hex[:12]
        runtime = DockerRuntime(run, pin(profile)["oci_digest"], target=target)
        source = active if phase == "active" else "fixtures/scripts/mvp1d/success.sh"
        proc, marker, reports = worker(
            "one-shot", profile, run, source, "unused", phase, directory
        )
        identifier = None
        pids = []
        alive = []
        removal = None
        try:
            if phase != "active":
                evidence = wait_barrier(proc, marker)
                identifier = evidence["container"]
            else:
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    assert proc.poll() is None, proc.returncode
                    owned = runtime.reconcile()["container_owned"]
                    if len(owned) == 1:
                        identifier = owned[0]
                        probe = runtime.exec(
                            identifier,
                            [
                                "/bin/sh",
                                "-c",
                                "test -s /opt/tmp/e07-child && "
                                "/opt/bin/busybox cat /opt/tmp/e07-shell "
                                "/opt/tmp/e07-child",
                            ],
                            allow_failure=True,
                        )
                        if probe.exit_code == 0:
                            pids = [int(x) for x in probe.stdout.splitlines()]
                            assert len(pids) == 2
                            break
                    time.sleep(0.1)
                else:
                    pytest.fail("active target deadline expired")
                evidence = {"container": identifier, "target_pids": pids}
            assert identifier in runtime.reconcile()["container_owned"]
            if phase == "after-stage":
                assert (
                    runtime.exec(
                        identifier, ["/opt/bin/busybox", "test", "-f", evidence["path"]]
                    ).exit_code
                    == 0
                )
            kill(proc)
            no_report(reports)
            if phase == "active":
                tick = time.monotonic()
                while time.monotonic() - tick < 12:
                    alive = [
                        pid
                        for pid in pids
                        if runtime.exec(
                            identifier,
                            ["/opt/bin/busybox", "kill", "-0", str(pid)],
                            allow_failure=True,
                        ).exit_code
                        == 0
                    ]
                    if not alive:
                        break
                    time.sleep(0.2)
                assert not alive, "target descendants survived bounded timeout"
                evidence["descendants_absent_seconds"] = time.monotonic() - tick
            preserve(foreign)
            evidence.update(
                phase=phase,
                worker_returncode=proc.returncode,
                interrupted_report="absent_no_PASS",
                foreign_preserved=True,
            )
        finally:
            if proc.poll() is None:
                kill(proc)
            if identifier is not None:
                removal = recover_one_shot(runtime, identifier)
        assert removal is not None
        evidence["explicit_test_recovery"] = removal
        records.append(evidence)
        publish(directory / (phase + "-observation.json"), evidence)
    publish(
        directory / "observation.json",
        {
            "profile": profile,
            "target": target,
            "phases": records,
            "automatic_recovery": "not_implemented",
        },
    )


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_persistent_create_sigkill_production_recovery(
    profile, target, lock_name, monkeypatch, foreign
):
    directory = case_dir("persistent-create-kill-" + profile)
    source, lock = scenario(directory / "inputs", profile, target)
    records = []
    for phase in ("creating", "installing"):
        name = "m1e06-create-" + uuid4().hex[:12]
        proc, marker, reports = worker(
            "create", profile, name, source, lock, phase, directory
        )
        try:
            wait_barrier(proc, marker)
            with pytest.raises(RegistryError, match="busy"):
                with Registry(ROOT / ".runtime/registry").locked(name):
                    pytest.fail("per-name lock not held")
        finally:
            kill(proc)
        with Registry(ROOT / ".runtime/registry").locked(name) as entry:
            interrupted = entry.read()
        assert interrupted.state == phase
        runtime = DockerRuntime(
            interrupted.run_id, interrupted.oci_digest, target=target
        )
        owned = runtime.reconcile()["container_owned"]
        assert len(owned) == 1
        identifier = owned[0]
        extra = runtime.create("keemu-" + interrupted.run_id + "-extra")
        try:
            with pytest.raises(RegistryError, match="extra owned|ambiguous"):
                recover(ROOT, name)
            assert runtime.inspect("container", identifier)["Id"] == identifier
        finally:
            runtime.remove_container(extra)
        with monkeypatch.context() as scoped:

            def refuse(_runtime, _identifier):
                raise DockerBoundaryError("injected recovery removal refusal")

            scoped.setattr(DockerRuntime, "remove_container", refuse)
            with pytest.raises(DockerBoundaryError, match="injected recovery"):
                recover(ROOT, name)
        with Registry(ROOT / ".runtime/registry").locked(name) as entry:
            assert entry.read().state == phase
        recovered = recover(ROOT, name)
        assert recovered["removed"] == [identifier]
        assert recovered["state"] == "destroyed"
        assert recover(ROOT, name)["retry"] is True
        assert operate(ROOT, name, "status")["consistent"]
        assert not runtime.reconcile()["container_owned"]
        assert identifier not in DockerRuntime.listed_ids("container")
        no_report(reports)
        preserve(foreign)
        record = {
            "phase": phase,
            "name": name,
            "container": identifier,
            "run_id": interrupted.run_id,
            "worker_returncode": proc.returncode,
            "per_name_lock": "busy",
            "ambiguous_extra": "refused_preserved",
            "removal_error": "retained_transitional_state_then_retry",
            "production_recovery": recovered,
            "idempotent": True,
            "tombstone_consistent": True,
            "foreign_preserved": True,
        }
        records.append(record)
        publish(directory / (phase + "-observation.json"), record)
    publish(
        directory / "observation.json",
        {"profile": profile, "target": target, "phases": records},
    )


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_persistent_timeout_service_and_sigkill_artifact(
    profile, target, lock_name, foreign
):
    directory = case_dir("persistent-script-" + profile)
    source, lock = scenario(directory / "inputs", profile, target, service=True)
    name = "m1e06-service-" + uuid4().hex[:12]
    created = create(ROOT, name, source, lock)
    assert created.resource is not None
    identifier = created.resource.container_id
    runtime = DockerRuntime(created.run_id, created.oci_digest, target=target)
    proc = None
    try:
        state = runtime.inspect("container", identifier)["State"]
        service_pid = runtime.exec(
            identifier, ["/opt/bin/busybox", "cat", "/opt/tmp/web-demo.pid"]
        ).stdout
        unrelated = int(
            runtime.exec(
                identifier,
                [
                    "/bin/sh",
                    "-c",
                    "/opt/bin/busybox sleep 120 </dev/null >/dev/null 2>&1 & echo $!",
                ],
            ).stdout
        )
        results = []
        for fixture, expected in (
            ("streams.sh", "PASS"),
            ("timeout-process.sh", "FAIL"),
        ):
            result = run_persistent_script(
                name,
                "fixtures/scripts/mvp1d/" + fixture,
                project_root=ROOT,
                timeout_seconds=1,
                report_root=directory / "reports",
            )
            assert result.report.overall == result.script.status == expected
            assert result.script.outcome.process_tree_clean
            assert all(x.verified for x in result.script.cleanup)
            if fixture == "timeout-process.sh":
                assert result.script.outcome.timed_out
                child = int(result.script.outcome.stdout.split(b"=", 1)[1])
                assert (
                    runtime.exec(
                        identifier,
                        ["/opt/bin/busybox", "kill", "-0", str(child)],
                        allow_failure=True,
                    ).exit_code
                    != 0
                )
            assert (
                runtime.exec(
                    identifier,
                    ["/opt/bin/busybox", "kill", "-0", str(unrelated)],
                    allow_failure=True,
                ).exit_code
                == 0
            )
            results.append(
                {
                    "case": fixture,
                    "status": result.report.overall,
                    "path": str(result.paths.json),
                    "sha256": digest(result.paths.json.read_bytes()),
                    "process_tree_clean": True,
                    "exact_target_cleanup": True,
                }
            )
        proc, marker, reports = worker(
            "persistent",
            profile,
            name,
            "fixtures/scripts/mvp1d/success.sh",
            "unused",
            "after-stage",
            directory,
        )
        artifact = wait_barrier(proc, marker)
        assert artifact["container"] == identifier
        with pytest.raises(RegistryError, match="busy"):
            operate(ROOT, name, "down")
        kill(proc)
        no_report(reports)
        assert runtime.inspect("container", identifier)["State"] == state
        assert operate(ROOT, name, "status")["consistent"]
        checked = ScriptInput.validate(
            "fixtures/scripts/mvp1d/success.sh", project_root=ROOT
        )
        assert (
            runtime.exec(
                identifier, ["/opt/bin/busybox", "cat", artifact["path"]]
            ).stdout
            == checked.recheck_for_staging()
        )
        with pytest.raises(RegistryError, match="healthy"):
            recover(ROOT, name)
        # No deletion/adoption of crash artifact: production whole-environment
        # down/destroy in finally removes the test-owned container and tombstones.
        assert (
            runtime.exec(
                identifier, ["/opt/bin/busybox", "cat", "/opt/tmp/web-demo.pid"]
            ).stdout
            == service_pid
        )
        assert (
            runtime.exec(
                identifier,
                ["/opt/bin/busybox", "kill", "-0", service_pid.decode().strip()],
            ).exit_code
            == 0
        )
        health = runtime.exec(
            identifier,
            ["/opt/bin/busybox", "wget", "-qO-", "http://127.0.0.1:18765/health"],
        )
        assert (
            b"state=1" if target == "aarch64-3.10" else b"keemu-web-demo"
        ) in health.stdout
        assert (
            runtime.exec(
                identifier, ["/opt/bin/busybox", "cat", "/opt/etc/keemu-count"]
            ).stdout
            == b"1\n"
        )
        preserve(foreign)
        observation = {
            "profile": profile,
            "target": target,
            "name": name,
            "container": identifier,
            "service_pid": service_pid.decode().strip(),
            "unrelated_pid": unrelated,
            "service_and_postinst_preserved": True,
            "reports": results,
            "persistent_SIGKILL": artifact,
            "worker_returncode": proc.returncode,
            "same_name_concurrency": "busy",
            "persistent_interrupted_report": "absent_no_PASS",
            "automatic_artifact_recovery": "BLOCKED_not_implemented",
            "healthy_recover": "refused_no_artifact_adoption",
            "foreign_preserved": True,
        }
    finally:
        if proc is not None and proc.poll() is None:
            kill(proc)
        tombstone = destroy(name, runtime, identifier)
    observation["production_down_destroy_tombstone"] = tombstone
    publish(directory / "observation.json", observation)


@pytest.mark.parametrize(("profile", "target", "lock_name"), TARGETS)
def test_one_shot_script_outcomes_and_cleanup(profile, target, lock_name, foreign):
    directory = case_dir("one-shot-outcomes-" + profile)
    records = []
    cases = (
        ("argv.sh", 0, "PASS", ("literal;$(false)", "two words")),
        ("exit-7.sh", 0, "FAIL", ()),
        ("exit-7.sh", 7, "PASS", ()),
        ("timeout-process.sh", 0, "FAIL", ()),
    )
    for fixture, expected_exit, status, argv in cases:
        result = run_one_shot_script(
            "fixtures/scripts/mvp1d/" + fixture,
            project_root=ROOT,
            profile_id=profile,
            argv=argv,
            expected_exit_code=expected_exit,
            timeout_seconds=1,
            run_id="m1e06-outcome-" + uuid4().hex[:12],
            report_root=directory / "reports",
        )
        assert result.report.overall == result.script.status == status
        assert result.script.outcome.process_tree_clean
        assert all(item.verified for item in result.script.cleanup)
        if argv:
            assert result.script.outcome.stdout == (
                b"argc=2\narg1=<literal;$(false)>\narg2=<two words>\n"
            )
            assert "literal;$(false)" not in result.paths.json.read_text()
        if fixture == "timeout-process.sh":
            assert result.script.outcome.timed_out
        assert result.script.spec.architecture == target
        assert result.script.spec.container_id not in DockerRuntime.listed_ids(
            "container"
        )
        records.append(
            {
                "case": fixture,
                "expected_exit": expected_exit,
                "status": status,
                "path": str(result.paths.json),
                "sha256": digest(result.paths.json.read_bytes()),
                "process_tree_clean": True,
                "target_and_container_cleanup": True,
            }
        )
        preserve(foreign)
    publish(
        directory / "observation.json",
        {
            "profile": profile,
            "target": target,
            "reports": records,
            "foreign_preserved": True,
            "exact_cleanup": True,
        },
    )


def test_three_target_concurrent_script_isolation(monkeypatch, foreign):
    directory = case_dir("concurrent-three-target")
    barrier = threading.Barrier(3, timeout=90)
    original_stage = ScriptStager.stage
    observed = []
    mutex = threading.Lock()

    def synchronized_stage(self, source, container):
        staged = original_stage(self, source, container)
        with mutex:
            observed.append(
                {
                    "container": container,
                    "path": staged.path,
                    "target": self.runtime.target,
                }
            )
        barrier.wait()
        return staged

    source = directory / "isolation.sh"
    source.write_bytes(
        b"#!/bin/sh\ntest ! -e /opt/tmp/e07-isolation || exit 91\n"
        b"printf '%s' \"$1\" > /opt/tmp/e07-isolation\n"
        b"/opt/bin/busybox sleep 1\n"
        b'test "$(/opt/bin/busybox cat /opt/tmp/e07-isolation)" = "$1"\n'
        b"test ! -e /var/run/docker.sock\n"
        b"test ! -e /opt/data/workspace/keemu\n"
        b'test -z "${KEEMU_HOST_SECRET_SENTINEL+x}"\n'
    )
    monkeypatch.setenv("KEEMU_HOST_SECRET_SENTINEL", "host-not-target")
    monkeypatch.setattr(ScriptStager, "stage", synchronized_stage)

    def run(item):
        profile, target, _ = item
        return run_one_shot_script(
            source,
            project_root=ROOT,
            profile_id=profile,
            argv=(target,),
            timeout_seconds=10,
            run_id="m1e06-concurrent-" + uuid4().hex[:12],
            report_root=directory / "reports",
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(run, TARGETS))
    assert len({x["container"] for x in observed}) == 3
    assert len({x["path"] for x in observed}) == 3
    assert len({x["target"] for x in observed}) == 3
    reports = []
    for item, result in zip(TARGETS, results, strict=True):
        assert result.report.overall == result.script.status == "PASS"
        assert result.script.spec.architecture == item[1]
        assert result.script.outcome.process_tree_clean
        assert all(x.verified for x in result.script.cleanup)
        assert result.script.spec.container_id not in DockerRuntime.listed_ids(
            "container"
        )
        reports.append(
            {
                "profile": item[0],
                "target": item[1],
                "path": str(result.paths.json),
                "sha256": digest(result.paths.json.read_bytes()),
                "status": result.report.overall,
            }
        )
    preserve(foreign)
    publish(
        directory / "observation.json",
        {
            "simultaneous_stage_barrier": True,
            "independent_common_path_files": True,
            "foreign_preserved": True,
            "stages": observed,
            "reports": reports,
            "exact_cleanup": True,
        },
    )
