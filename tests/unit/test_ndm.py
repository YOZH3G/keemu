"""Process-level NDM shim contracts: bytes, state, unsupported calls, redaction."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from keemu.models import ProfileMetadata, RuntimeMetadata
from keemu.ndm import NDMError, load_contract, required_check
from keemu.reports import build_report


def contract(tmp_path: Path) -> Path:
    path = tmp_path / "contract.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "synthetic-demo",
                "initial_state": {"enabled": "off"},
                "commands": [
                    {
                        "argv": ["ndmc", "-c", "show demo"],
                        "source": "synthetic:demo-v1",
                        "kind": "read",
                        "state_key": "enabled",
                        "responses": {
                            "off": {"stdout": "off\n", "stderr": "", "exit_code": 0},
                            "on": {"stdout": "on\n", "stderr": "", "exit_code": 0},
                        },
                    },
                    {
                        "argv": ["ndmc", "-c", "set demo on"],
                        "source": "synthetic:demo-v1",
                        "kind": "write",
                        "state_key": "enabled",
                        "state_value": "on",
                        "response": {"stdout": "done\n", "stderr": "", "exit_code": 0},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def call(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- local module, test-controlled argv
        [
            sys.executable,
            "-m",
            "keemu.ndm",
            "--contract",
            str(tmp_path / "contract.json"),
            "--state",
            str(tmp_path / "state.json"),
            "--log",
            str(tmp_path / "ndmc.jsonl"),
            "--run-id",
            "run-ndm-1",
            "--",
            *argv,
        ],
        capture_output=True,
        check=False,
    )


def test_exact_process_and_persistent_state(tmp_path: Path) -> None:
    contract(tmp_path)
    assert (r := call(tmp_path, "ndmc", "-c", "show demo")).returncode == 0
    assert (r.stdout, r.stderr) == (b"off\n", b"")
    assert (r := call(tmp_path, "ndmc", "-c", "set demo on")).returncode == 0
    assert (r.stdout, r.stderr) == (b"done\n", b"")
    assert (r := call(tmp_path, "ndmc", "-c", "show demo")).stdout == b"on\n"
    assert (r := call(tmp_path, "ndmc", "-c", "set demo on")).returncode == 65
    assert r.stderr == b"NDM state unchanged\n"
    assert (r := call(tmp_path, "ndmc", "-c", "show demo")).stdout == b"on\n"
    assert json.loads((tmp_path / "state.json").read_text())["values"] == {
        "enabled": "on"
    }
    logs = [
        json.loads(line) for line in (tmp_path / "ndmc.jsonl").read_text().splitlines()
    ]
    assert len(logs) == 5
    assert [row["exit_code"] for row in logs] == [0, 0, 0, 65, 0]
    assert all(row["fixture"] == "synthetic:demo-v1" for row in logs)
    assert all(row["env"] == {} and row["duration_seconds"] >= 0 for row in logs)
    assert all(row["timestamp"] and row["run_id"] == "run-ndm-1" for row in logs)
    assert os.stat(tmp_path / "state.json").st_mode & 0o777 == 0o600
    assert os.stat(tmp_path / "ndmc.jsonl").st_mode & 0o777 == 0o600


def test_unknown_is_not_success_and_required_check_blocks(tmp_path: Path) -> None:
    contract(tmp_path)
    sentinel = "marker-no-log-739"
    r = call(tmp_path, "ndmc", "-c", sentinel)
    assert (r.returncode, r.stdout, r.stderr) == (64, b"", b"unsupported NDM command\n")
    log = (tmp_path / "ndmc.jsonl").read_text()
    assert sentinel not in log and sentinel not in r.stderr.decode()
    assert json.loads(log)["event"] == "unsupported-ndm-command"
    assert json.loads(log)["fixture"] is None
    assert not (tmp_path / "state.json").exists()
    check = required_check(r.returncode)
    assert (check.status, check.cause_class, check.mode, check.required) == (
        "BLOCKED",
        "environment",
        "shim",
        True,
    )
    assert "environment-gap" in check.evidence[0]
    report = build_report(
        run_id="run-ndm-1",
        created_at="2026-09-24T00:00:00Z",
        operation="ndm",
        profile=ProfileMetadata(
            id="generic-aarch64", revision=1, kind="generic", sha256=None
        ),
        runtime=RuntimeMetadata(
            keemu_version="test",
            git_commit=None,
            git_dirty=None,
            oci_digest=None,
            qemu_version=None,
            binfmt_configuration=(),
            host_kernel="test",
            entware_target="aarch64-3.10",
            feed_lock_sha256=None,
            versions=(),
            network_fidelity=None,
            native_tools=(),
        ),
        checks=(check,),
    )
    assert report.overall == "BLOCKED"
    assert report.checks[0].cause_class != "package"
    assert (required_check(65).status, required_check(1).cause_class) == (
        "BLOCKED",
        "unknown",
    )


def test_exact_argv_unknown_even_similar_and_no_env_leak(
    tmp_path: Path, monkeypatch
) -> None:
    contract(tmp_path)
    monkeypatch.setenv("SENTINEL_ENV", "marker-no-log-739")
    for argv in [
        ("ndmc", "show demo"),
        ("ndmc", "-c", "show demo "),
        ("/opt/bin/ndmc", "-c", "show demo"),
    ]:
        assert call(tmp_path, *argv).returncode == 64
    assert "marker-no-log-739" not in (tmp_path / "ndmc.jsonl").read_text()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(schema_version=2),
        lambda doc: doc["commands"].append(doc["commands"][0]),
        lambda doc: doc["commands"][1].update(
            response={"stdout": "", "stderr": "", "exit_code": 1}
        ),
        lambda doc: doc["commands"][0]["responses"].pop("on"),
        lambda doc: doc["commands"][0]["responses"].update(
            on={"stdout": "off\n", "stderr": "", "exit_code": 0}
        ),
        lambda doc: doc["commands"][0]["responses"]["on"].update(exit_code=64),
        lambda doc: doc["commands"][1].pop("state_value"),
        lambda doc: doc["commands"][0].update(source=""),
        lambda doc: doc["commands"][0].update(unexpected="ignored"),
    ],
)
def test_invalid_contract_fails_before_logs(tmp_path: Path, mutate) -> None:
    path = contract(tmp_path)
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc))
    assert call(tmp_path, "ndmc", "-c", "show demo").returncode == 3
    assert not (tmp_path / "ndmc.jsonl").exists()


def test_symlinks_and_corrupt_state_fail_closed(tmp_path: Path) -> None:
    contract(tmp_path)
    (tmp_path / "state.json").symlink_to(tmp_path / "contract.json")
    assert call(tmp_path, "ndmc", "-c", "show demo").returncode == 3
    (tmp_path / "state.json").unlink()
    (tmp_path / "state.json").write_text(
        '{"contract": "synthetic-demo", "values": {"enabled": "illegal"}}'
    )
    assert call(tmp_path, "ndmc", "-c", "show demo").returncode == 3
    assert not (tmp_path / "ndmc.jsonl").exists()
    (tmp_path / "state.json").unlink()
    (tmp_path / "ndmc.jsonl").symlink_to(tmp_path / "contract.json")
    assert call(tmp_path, "ndmc", "-c", "show demo").returncode == 3
    assert load_contract(tmp_path / "contract.json").id == "synthetic-demo"


def test_duplicate_json_keys_rejected(tmp_path: Path) -> None:
    path = contract(tmp_path)
    path.write_text(
        path.read_text().replace(
            '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'
        )
    )
    with pytest.raises(NDMError):
        load_contract(path)


def test_changed_contract_refuses_prior_state(tmp_path: Path) -> None:
    path = contract(tmp_path)
    assert call(tmp_path, "ndmc", "-c", "set demo on").returncode == 0
    doc = json.loads(path.read_text())
    doc["commands"][0]["responses"]["on"]["stdout"] = "changed\n"
    path.write_text(json.dumps(doc))
    r = call(tmp_path, "ndmc", "-c", "show demo")
    assert r.returncode == 3
    assert b"changed" not in r.stdout
    assert json.loads((tmp_path / "state.json").read_text())["values"] == {
        "enabled": "on"
    }
