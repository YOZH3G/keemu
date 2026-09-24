"""Opt-in real AArch64 child plus truthful unsupported MIPS matrix cases."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from keemu.matrix import run_matrix
from tests.unit.test_matrix import setup

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.docker
def test_matrix_real_child_and_unsupported_targets() -> None:
    if os.getenv("KEEMU_TEST_MATRIX") != "1":
        pytest.skip("opt in to locked AArch64 Docker/binfmt matrix run")
    staging = ROOT / ".runtime"
    staging.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=staging, prefix="m1b19-") as folder:
        directory = Path(folder)
        matrix = setup(directory)
        scenario = directory / "cases/generic-aarch64/scenario.yaml"
        scenario.write_text(
            scenario.read_text().replace(
                "allowed_residual_paths: []",
                "allowed_residual_paths: [/opt/etc/keemu-count]",
            )
        )
        lock_file = scenario.with_name("scenario-lock.json")
        lock = json.loads(lock_file.read_text())
        base = json.loads((ROOT / "locks/m1a-init-aarch64.json").read_text())
        lock["scenario_sha256"] = hashlib.sha256(scenario.read_bytes()).hexdigest()
        lock["oci_digest"] = base["oci_digest"]
        lock["feed_lock_sha256"] = base["input_lock_sha256"]
        lock_file.write_text(json.dumps(lock))
        result = run_matrix(matrix, project_root=ROOT)
        assert result.report.overall == "BLOCKED", result.paths.json
        assert [check.status for check in result.report.checks] == [
            "PASS",
            "PASS",
            "BLOCKED",
            "BLOCKED",
        ]
        child = ROOT / "reports" / (result.report.run_id + "-case-1") / "report.json"
        assert json.loads(child.read_text())["overall"] == "PASS"
        assert (
            hashlib.sha256(child.read_bytes()).hexdigest()
            in (result.report.checks[1].evidence[0])
        )
        assert result.paths.json.is_file()
        assert result.paths.markdown.is_file()
        for kind in ("container", "network"):
            output = subprocess.run(  # noqa: S603 -- fixed read-only owner filter
                [
                    "/usr/bin/docker",
                    kind,
                    "ls",
                    "-q",
                    "--filter",
                    "label=org.keemu.owner=keemu",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            assert not output.stdout.strip(), (kind, output.stdout)
