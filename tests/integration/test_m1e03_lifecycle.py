"""Real common one-shot lifecycle on both locked MIPS-family bases."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from keemu.docker_runtime import DockerRuntime
from keemu.lifecycle import run_scenario
from tests.integration.test_lifecycle import ROOT, bind_scenario, inputs

TARGETS = (("generic-mips", "mips-3.4"), ("generic-mipsel", "mipsel-3.4"))


def target_inputs(directory: Path, profile: str, target: str, **options):
    scenario, lock = inputs(
        directory, architecture=options.pop("architecture", target), **options
    )
    scenario.write_text(scenario.read_text().replace("generic-aarch64", profile))
    base_name = (
        "m1e-init-mips.json" if profile == "generic-mips" else "m1e-init-mipsel.json"
    )
    base = json.loads((ROOT / "locks" / base_name).read_text())
    data = json.loads(lock.read_text())
    data.update(
        profile_id=profile,
        profile_sha256=hashlib.sha256(
            (ROOT / "profiles/generic" / f"{profile}.yaml").read_bytes()
        ).hexdigest(),
        entware_target=target,
        oci_digest=base["oci_digest"],
        feed_lock_sha256=base["input_lock_sha256"],
    )
    data["sources"][0]["architecture"] = target.split("-", 1)[0]
    lock.write_text(json.dumps(data))
    bind_scenario(lock, scenario)
    return scenario, lock


@pytest.mark.docker
@pytest.mark.parametrize(("profile", "target"), TARGETS)
def test_locked_mips_one_shot_success_negative_and_cleanup(
    profile, target, monkeypatch
):
    if os.getenv("KEEMU_TEST_M1E03") != "1":
        pytest.skip("opt in to locked MIPS/MIPSEL Docker lifecycle")
    (ROOT / ".runtime").mkdir(exist_ok=True)
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    base_name = (
        "m1e-init-mips.json" if profile == "generic-mips" else "m1e-init-mipsel.json"
    )
    image_id = json.loads((ROOT / "locks" / base_name).read_text())["oci_digest"]
    observations = []

    def observe(label, result):
        observations.append(
            {
                "case": label,
                "report": str(result.paths.json.relative_to(ROOT)),
                "sha256": hashlib.sha256(result.paths.json.read_bytes()).hexdigest(),
                "overall": result.report.overall,
                "failure_operation": (
                    result.report.partial_failure.operation
                    if result.report.partial_failure
                    else None
                ),
                "cleanup": result.report.checks[-1].status,
            }
        )

    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime", prefix="m1e03-") as folder:
        directory = Path(folder)
        for failure in (False, True):
            scenario, lock = target_inputs(
                directory, profile, target, failed_postinst=failure
            )
            run_id = "m1e03-" + uuid4().hex[:20]
            result = run_scenario(scenario, lock, project_root=ROOT, run_id=run_id)
            report = result.report
            assert report.overall == ("FAIL" if failure else "PASS"), result.paths.json
            assert report.runtime.entware_target == target
            assert report.runtime.oci_digest == image_id
            assert report.profile.id == profile
            assert report.checks[-1].id == "cleanup"
            assert report.checks[-1].status == "PASS"
            if failure:
                assert report.partial_failure is not None
                assert report.partial_failure.operation == "install"
            else:
                assert report.partial_failure is None
            assert (
                json.loads(result.paths.json.read_text())["overall"] == report.overall
            )
            assert not DockerRuntime(run_id, image_id, target=target).reconcile()[
                "container_owned"
            ]
            observe("postinst-fail" if failure else "success", result)
        # A foreign run with the same image is not this run's cleanup authority.
        foreign_run = "m1e03-foreign-" + uuid4().hex[:12]
        foreign = DockerRuntime(foreign_run, image_id, target=target)
        foreign_id = foreign.create("keemu-" + foreign_run)
        try:
            scenario, lock = target_inputs(directory, profile, target)
            collision_id = "m1e03-collision-" + uuid4().hex[:12]
            collision = DockerRuntime(collision_id, image_id, target=target)
            existing_id = collision.create("keemu-" + collision_id)
            try:
                refused = run_scenario(
                    scenario, lock, project_root=ROOT, run_id=collision_id
                )
                assert refused.report.overall == "BLOCKED", refused.paths.json
                assert refused.report.partial_failure is not None
                assert refused.report.partial_failure.operation == "create"
                assert collision.inspect("container", existing_id)["Id"] == existing_id
                assert refused.report.checks[-1].status == "PASS"
                observe("collision", refused)
            finally:
                collision.remove_container(existing_id)
                assert not collision.reconcile()["container_owned"]
            # Lock source bytes are rechecked before any new Docker allocation.
            (directory / "hello.ipk").write_bytes(b"changed after lock")
            changed = run_scenario(scenario, lock, project_root=ROOT)
            assert changed.report.overall == "BLOCKED", changed.paths.json
            assert changed.report.partial_failure is not None
            assert changed.report.partial_failure.operation == "validate"
            assert changed.report.checks[-1].status == "PASS"
            assert foreign.inspect("container", foreign_id)["Id"] == foreign_id
            observe("input-changed", changed)
            scenario, lock = target_inputs(
                directory, profile, target, architecture="aarch64-3.10"
            )
            result = run_scenario(scenario, lock, project_root=ROOT)
            assert result.report.overall == "FAIL", result.paths.json
            assert result.report.partial_failure is not None
            assert result.report.partial_failure.operation == "inspect"
            assert "architecture" in result.report.partial_failure.message
            assert foreign.inspect("container", foreign_id)["Id"] == foreign_id
            observe("wrong-architecture", result)
            scenario, lock = target_inputs(
                directory, profile, target, failed_postinst=True
            )
            original = DockerRuntime.remove_container

            def fail_after_remove(runtime, identifier):
                original(runtime, identifier)
                raise RuntimeError("injected cleanup readback error")

            with monkeypatch.context() as patch:
                patch.setattr(DockerRuntime, "remove_container", fail_after_remove)
                result = run_scenario(scenario, lock, project_root=ROOT)
            assert result.report.overall == "ERROR"
            assert result.report.partial_failure is not None
            assert result.report.partial_failure.operation == "install"
            assert result.report.partial_failure.cleanup_status == "ERROR"
            assert result.report.checks[-1].status == "ERROR"
            assert foreign.inspect("container", foreign_id)["Id"] == foreign_id
            observe("cleanup-error", result)
        finally:
            foreign.remove_container(foreign_id)
            assert not foreign.reconcile()["container_owned"]
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
    (ROOT / "reports" / f"m1e03-{profile}-observations.json").write_text(
        json.dumps(
            {"profile": profile, "target": target, "cases": observations},
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
