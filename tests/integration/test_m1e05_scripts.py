"""Real common one-shot and persistent script paths on MIPS-family bases."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from keemu.docker_runtime import DockerRuntime
from keemu.persistent import create, operate
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_persistent import run_persistent_script
from tests.integration.test_lifecycle import ROOT
from tests.integration.test_m1e03_lifecycle import TARGETS, target_inputs


@pytest.mark.docker
@pytest.mark.parametrize(("profile", "target"), TARGETS)
def test_mips_common_one_shot_and_persistent_script_paths(
    profile: str, target: str
) -> None:
    if os.getenv("KEEMU_TEST_M1E05") != "1":
        pytest.skip("opt in to MIPS/MIPSEL common script lifecycle")
    before_containers = DockerRuntime.listed_ids("container")
    before_networks = DockerRuntime.listed_ids("network")
    base_name = (
        "m1e-init-mips.json" if profile == "generic-mips" else "m1e-init-mipsel.json"
    )
    image_id = json.loads((ROOT / "locks" / base_name).read_text())["oci_digest"]
    (ROOT / ".runtime").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / ".runtime", prefix="m1e05-") as folder:
        directory = Path(folder)
        run_id = "m1e05-script-" + uuid4().hex[:16]
        one_shot = run_one_shot_script(
            "fixtures/scripts/mvp1d/argv.sh",
            project_root=ROOT,
            profile_id=profile,
            argv=("literal;$(false)", "two words"),
            run_id=run_id,
            report_root=directory / "reports",
        )
        assert one_shot.report.overall == one_shot.script.status == "PASS"
        assert one_shot.script.spec.architecture == target
        assert one_shot.script.spec.image_id == image_id
        assert one_shot.script.outcome.stdout == (
            b"argc=2\narg1=<literal;$(false)>\narg2=<two words>\n"
        )
        assert one_shot.script.outcome.process_tree_clean
        assert all(item.verified for item in one_shot.script.cleanup)
        assert "literal;$(false)" not in one_shot.paths.json.read_text()
        assert (
            DockerRuntime(run_id, image_id, target=target).reconcile()[
                "container_owned"
            ]
            == []
        )

        scenario, lock = target_inputs(directory, profile, target)
        name = "m1e05-persist-" + uuid4().hex[:16]
        created = create(ROOT, name, scenario, lock)
        assert created.state == "running" and created.resource is not None
        runtime = DockerRuntime(created.run_id, image_id, target=target)
        identifier = created.resource.container_id
        try:
            persistent = run_persistent_script(
                name,
                "fixtures/scripts/mvp1d/streams.sh",
                project_root=ROOT,
                expectations=None,
                report_root=directory / "reports",
            )
            assert persistent.report.overall == persistent.script.status == "PASS"
            assert persistent.script.spec.architecture == target
            assert persistent.script.spec.image_id == image_id
            assert persistent.script.spec.container_id == identifier
            assert persistent.script.outcome.stdout == b"stdout-token\n"
            assert persistent.script.outcome.stderr == b"stderr-token\n"
            assert persistent.script.outcome.process_tree_clean
            assert all(item.verified for item in persistent.script.cleanup)
            assert "stdout-token" not in persistent.paths.json.read_text()
            assert operate(ROOT, name, "status")["consistent"]
            assert (
                runtime.exec(
                    identifier,
                    ["/bin/sh", "-c", 'read n < /opt/etc/keemu-count; test "$n" = 1'],
                ).exit_code
                == 0
            )
        finally:
            try:
                operate(ROOT, name, "destroy")
            except Exception:
                for owned in runtime.reconcile()["container_owned"]:
                    runtime.remove_container(owned)
        assert runtime.reconcile()["container_owned"] == []
    assert DockerRuntime.listed_ids("container") == before_containers
    assert DockerRuntime.listed_ids("network") == before_networks
