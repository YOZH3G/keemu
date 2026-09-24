"""Matrix schema, completeness and aggregate truth without Docker."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from keemu.cli import cli
from keemu.matrix import Matrix, run_matrix
from keemu.models import RunReport
from tests.integration.test_lifecycle import package

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("generic-aarch64", "generic-mipsel", "generic-mips")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def setup(tmp_path: Path, targets=TARGETS, *, mismatch: str | None = None) -> Path:
    (ROOT / ".runtime").mkdir(exist_ok=True)
    (tmp_path / "profiles/generic").mkdir(parents=True)
    (tmp_path / "cases").mkdir()
    cases = []
    for target in targets:
        profile = ROOT / "profiles/generic" / f"{target}.yaml"
        dest = tmp_path / "profiles/generic" / profile.name
        dest.write_bytes(profile.read_bytes())
        arch = target.removeprefix("generic-")
        entware_target = {
            "aarch64": "aarch64-3.10",
            "mipsel": "mipsel-3.4",
            "mips": "mips-3.4",
        }[arch]
        folder = tmp_path / "cases" / target
        folder.mkdir()
        blob = package(
            architecture="aarch64-3.10" if mismatch == target else entware_target
        )
        (folder / "hello.ipk").write_bytes(blob)
        scenario = folder / "scenario.yaml"
        scenario.write_text(f"""schema_version: 1
id: hello
profile: {target}
install: {{kind: ipk, path: hello.ipk, package_name: keemu-hello}}
service: null
runtime: {{env: {{}}, cwd: /opt, settle_seconds: 0, publish: []}}
requirements: {{capabilities: [], ndm_fixtures: []}}
checks:
  - id: hello
    kind: command
    command: {{argv: [/opt/bin/keemu-hello]}}
    expected_exit_code: 0
persistence: {{paths: []}}
cleanup: {{allowed_residual_paths: []}}
""")
        lock = folder / "scenario-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "scenario-lock",
                    "scenario_id": "hello",
                    "scenario_sha256": digest(scenario.read_bytes()),
                    "profile_id": target,
                    "profile_revision": 1,
                    "profile_sha256": digest(dest.read_bytes()),
                    "entware_target": entware_target,
                    "oci_digest": "sha256:" + "a" * 64,
                    "qemu_version": "10.0.13",
                    "feed_lock_sha256": "b" * 64,
                    "sources": [
                        {
                            "id": "hello",
                            "kind": "ipk",
                            "path": "hello.ipk",
                            "sha256": digest(blob),
                            "origin": "test fixture",
                            "release": "1.0",
                            "architecture": arch,
                        }
                    ],
                }
            )
        )
        cases.append(
            f"  - profile: {target}\n"
            f"    scenario: cases/{target}/scenario.yaml\n"
            f"    lock: cases/{target}/scenario-lock.json"
        )
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        "schema_version: 1\nid: hello-matrix\ncases:\n" + "\n".join(cases) + "\n"
    )
    return matrix


def test_matrix_incomplete_is_blocked_and_does_not_claim_pass(
    tmp_path: Path, monkeypatch
) -> None:
    matrix = setup(tmp_path, targets=("generic-mipsel",))
    monkeypatch.setattr(
        "keemu.matrix.run_scenario",
        lambda *a, **kw: pytest.fail("unsupported target executed"),
    )
    result = run_matrix(matrix, project_root=tmp_path)
    assert result.report.overall == "BLOCKED"
    assert result.report.coverage.blocked == 2
    assert [c.id for c in result.report.checks] == ["completeness", "generic-mipsel"]
    assert "generic-aarch64" in result.report.checks[0].evidence[0]
    assert RunReport.model_validate_json(result.paths.json.read_text()) == result.report
    assert "**BLOCKED**" in result.paths.markdown.read_text()


def test_required_unsupported_target_exits_four_even_with_strict(
    tmp_path: Path,
) -> None:
    matrix = setup(tmp_path, targets=("generic-mipsel",))
    outcome = CliRunner().invoke(
        cli, ["test", "--matrix", str(matrix), "--repo", str(tmp_path), "--strict"]
    )
    assert outcome.exit_code == 4, outcome.output
    report = RunReport.model_validate(json.loads(outcome.output))
    assert report.overall == "BLOCKED"
    assert report.coverage.blocked == 2


def test_mismatch_is_fail_and_overrides_unsupported_target(
    tmp_path: Path, monkeypatch
) -> None:
    matrix = setup(
        tmp_path, targets=("generic-mipsel", "generic-mips"), mismatch="generic-mips"
    )
    monkeypatch.setattr(
        "keemu.matrix.run_scenario",
        lambda *a, **kw: pytest.fail("wrong target executed"),
    )
    result = CliRunner().invoke(
        cli, ["test", "--matrix", str(matrix), "--repo", str(tmp_path), "--strict"]
    )
    assert result.exit_code == 1, result.output
    report = RunReport.model_validate(json.loads(result.output))
    assert report.overall == "FAIL"
    assert [c.status for c in report.checks] == ["BLOCKED", "BLOCKED", "FAIL"]
    assert "architecture-mismatch" in report.checks[-1].evidence[0]
    assert report.checks[-1].cause_class == "package"


def test_complete_matrix_visits_cases_in_order_and_preserves_child_results(
    tmp_path: Path, monkeypatch
) -> None:
    matrix = setup(tmp_path)
    visited = []

    def child(scenario, lock, *, project_root, report_root, run_id):
        visited.append((scenario, lock, run_id))
        report_file = report_root / run_id / "report.json"
        report_file.parent.mkdir(parents=True)
        report_file.write_bytes(b'{"overall":"WARN"}')
        return SimpleNamespace(
            paths=SimpleNamespace(json=report_file),
            report=SimpleNamespace(
                overall="WARN",
                partial_failure=None,
                checks=(SimpleNamespace(id="fresh-environment", status="PASS"),),
            ),
        )

    monkeypatch.setattr("keemu.matrix.run_scenario", child)
    result = run_matrix(matrix, project_root=tmp_path)
    assert len(visited) == 1
    assert visited[0][0].parent.name == "generic-aarch64"
    assert [c.status for c in result.report.checks] == [
        "PASS",
        "WARN",
        "BLOCKED",
        "BLOCKED",
    ]
    assert result.report.overall == "BLOCKED"
    assert result.report.operation_log[0].operation == "case-generic-aarch64"
    assert "sha256=" in result.report.checks[1].evidence[0]
    assert result.paths.json.exists()
    with pytest.raises(FileExistsError):
        run_matrix(matrix, project_root=tmp_path, run_id=result.report.run_id)
    assert result.paths.json.exists()


@pytest.mark.parametrize(
    "edit",
    [
        lambda text: text + "unknown: 1\n",
        lambda text: text.replace("schema_version: 1", "schema_version: 2"),
        lambda text: text.replace("schema_version: 1", "schema_version: true"),
        lambda text: text + "id: duplicate\n",
        lambda text: text.replace("generic-mips\n", "generic-mipsel\n"),
        lambda text: text.replace(
            "cases/generic-aarch64/scenario.yaml", "../../etc/passwd"
        ),
    ],
)
def test_malformed_matrix_rejected_before_execution(
    tmp_path: Path, monkeypatch, edit
) -> None:
    matrix = setup(tmp_path)
    matrix.write_text(edit(matrix.read_text()))
    monkeypatch.setattr(
        "keemu.matrix.run_scenario", lambda *a, **kw: pytest.fail("executed")
    )
    result = CliRunner().invoke(
        cli, ["test", "--matrix", str(matrix), "--repo", str(tmp_path)]
    )
    assert result.exit_code == 2, result.output
    assert not (tmp_path / "reports").exists()


def test_swapped_case_profile_and_source_replacement_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    matrix = setup(tmp_path)
    monkeypatch.setattr(
        "keemu.matrix.run_scenario", lambda *a, **kw: pytest.fail("executed")
    )
    matrix.write_text(
        matrix.read_text().replace(
            "profile: generic-aarch64", "profile: generic-mipsel", 1
        )
    )
    assert (
        CliRunner()
        .invoke(cli, ["test", "--matrix", str(matrix), "--repo", str(tmp_path)])
        .exit_code
        == 2
    )
    matrix.write_text(
        matrix.read_text().replace(
            "profile: generic-mipsel\n    scenario: cases/generic-aarch64",
            "profile: generic-aarch64\n    scenario: cases/generic-aarch64",
            1,
        )
    )
    source = tmp_path / "cases/generic-mips/hello.ipk"
    source.write_bytes(source.read_bytes() + b"corrupt")
    assert (
        CliRunner()
        .invoke(cli, ["test", "--matrix", str(matrix), "--repo", str(tmp_path)])
        .exit_code
        == 2
    )
    assert not (tmp_path / "reports").exists()


def test_schema_is_strict() -> None:
    with pytest.raises(ValidationError):
        Matrix.model_validate(
            {
                "schema_version": 1,
                "id": "matrix",
                "cases": [
                    {
                        "profile": "generic-aarch64",
                        "scenario": "one.yaml",
                        "lock": "one.json",
                        "extra": True,
                    }
                ],
            }
        )


def test_committed_schema_matches_model() -> None:
    assert json.loads((ROOT / "schemas/matrix.schema.json").read_text()) == (
        Matrix.model_json_schema()
    )


def test_unknown_target_is_blocked_not_package_failure(tmp_path: Path) -> None:
    matrix = setup(tmp_path, targets=("generic-aarch64",))
    folder = tmp_path / "cases/generic-aarch64"
    scenario = folder / "scenario.yaml"
    scenario.write_text(
        scenario.read_text().replace("generic-aarch64", "generic-riscv")
    )
    lock_file = folder / "scenario-lock.json"
    lock = json.loads(lock_file.read_text())
    lock["profile_id"] = "generic-riscv"
    lock["scenario_sha256"] = digest(scenario.read_bytes())
    lock_file.write_text(json.dumps(lock))
    matrix.write_text(
        matrix.read_text().replace("profile: generic-aarch64", "profile: generic-riscv")
    )
    result = run_matrix(matrix, project_root=tmp_path)
    assert result.report.overall == "BLOCKED"
    assert result.report.checks[1].status == "BLOCKED"
    assert result.report.checks[1].cause_class == "environment"
    assert "unsupported target" in result.report.checks[1].evidence[0]


def test_child_runtime_error_does_not_hide_required_blocked_cases(
    tmp_path: Path, monkeypatch
) -> None:
    matrix = setup(tmp_path)

    def broken_child(*args, **kwargs):
        raise RuntimeError("Docker unavailable")

    monkeypatch.setattr("keemu.matrix.run_scenario", broken_child)
    result = run_matrix(matrix, project_root=tmp_path)
    assert result.report.overall == "ERROR"
    assert [check.status for check in result.report.checks] == [
        "PASS",
        "ERROR",
        "BLOCKED",
        "BLOCKED",
    ]
    assert result.report.checks[1].cause_class == "harness"
    assert result.report.checks[1].mode == "static"
    assert result.report.coverage.errors == 1
    assert result.report.coverage.blocked == 2
