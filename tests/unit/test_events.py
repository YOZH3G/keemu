"""Host-local synthetic event contracts, never physical-device or firewall proof."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from keemu.events import EventError, load_contract


def fixture(tmp_path: Path, *, event: str = "netfilter") -> tuple[Path, Path]:
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    handlers = root / "handlers"
    handlers.mkdir(mode=0o700)
    (root / "work").mkdir(mode=0o700)
    check = (
        (
            '[ "$KEEMU_EVENT" = netfilter ] || exit 4\n'
            '[ "$KEEMU_TYPE" = filter ] || exit 4\n'
            '[ "$KEEMU_TABLE" = ipv4 ] || exit 4\n'
        )
        if event == "netfilter"
        else '[ "$KEEMU_EVENT" = boot ] || exit 4\n'
    )
    scripts = {
        "10-first": "#!/bin/sh\nprintf 'first\\n' >> order\n",
        "20-ignored": "non-executable synthetic note\n",
        "30-restore": (
            "#!/bin/sh\n"
            + check
            + '[ -z "${SENTINEL_ENV:-}" ] || exit 4\n'
            + "printf 'restored\\n' >> order\n"
            + 'printf \'{"rules":["chain:input","rule:allow"]}\\n\' '
            + '> "$KEEMU_STATE_PATH"\n'
        ),
    }
    manifest = []
    for name, script in scripts.items():
        path = handlers / name
        path.write_text(script)
        executable = name != "20-ignored"
        path.chmod(0o700 if executable else 0o600)
        manifest.append(
            {
                "name": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "executable": executable,
            }
        )
    doc = {
        "schema_version": 1,
        "id": "synthetic-rules",
        "source": "synthetic:rules-v1",
        "event": event,
        "handler_dir": "handlers",
        "selector": "[0-9][0-9]-*",
        "cwd": "work",
        "path": "/usr/bin:/bin",
        "type": "filter" if event == "netfilter" else None,
        "table": "ipv4" if event == "netfilter" else None,
        "timeout_seconds": 1,
        "nonexecutable": "skip",
        "on_error": "stop",
        "handlers": manifest,
        "before": [
            ["chain:input"],
            ["chain:input", "rule:changed"],
            ["chain:input", "rule:allow"],
        ],
        "after": ["chain:input", "rule:allow"],
    }
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(doc))
    (root / "state.json").write_text('{"rules":["chain:input"]}')
    (root / "state.json").chmod(0o600)
    return contract, root


def call(contract: Path, root: Path, event: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- local module, synthetic fixture
        [
            sys.executable,
            "-m",
            "keemu.events",
            "--contract",
            str(contract),
            "--root",
            str(root),
            "--log",
            str(root / "events.jsonl"),
            "--run-id",
            "run-events-1",
            "--event",
            event,
        ],
        capture_output=True,
        check=False,
    )


def records(root: Path) -> list[dict]:
    return [
        json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()
    ]


def pin(contract: Path, root: Path, name: str) -> dict:
    doc = json.loads(contract.read_text())
    entry = next(h for h in doc["handlers"] if h["name"] == name)
    entry["sha256"] = hashlib.sha256(
        (root / "handlers" / name).read_bytes()
    ).hexdigest()
    contract.write_text(json.dumps(doc))
    return doc


@pytest.mark.parametrize("event", ["boot", "netfilter"])
def test_order_environment_repeat_restores_without_duplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    contract, root = fixture(tmp_path, event=event)
    monkeypatch.setenv("SENTINEL_ENV", "do-not-pass-or-log")
    assert (result := call(contract, root, event)).returncode == 0, result.stderr
    assert result.stdout == b"PASS\n"
    assert (root / "work/order").read_text().splitlines() == ["first", "restored"]
    (root / "state.json").write_text('{"rules":["chain:input","rule:changed"]}')
    assert call(contract, root, event).returncode == 0
    assert call(contract, root, event).returncode == 0
    assert json.loads((root / "state.json").read_text())["rules"] == [
        "chain:input",
        "rule:allow",
    ]
    assert (root / "work/order").read_text().splitlines() == ["first", "restored"] * 3
    rows = records(root)
    assert [r["handler"] for r in rows] == [
        "10-first",
        "20-ignored",
        "30-restore",
        None,
    ] * 3
    assert [r["status"] for r in rows[:4]] == ["PASS", "SKIP", "PASS", "PASS"]
    assert rows[3]["argv"] == [] and rows[3]["exit_code"] == 0
    assert all(
        r["timestamp"]
        and r["run_id"] == "run-events-1"
        and r["fixture"] == "synthetic:rules-v1"
        for r in rows
    )
    expected_env = {"KEEMU_EVENT": event}
    if event == "netfilter":
        expected_env.update(KEEMU_TYPE="filter", KEEMU_TABLE="ipv4")
    assert rows[2]["env"] == expected_env
    assert "do-not-pass-or-log" not in (root / "events.jsonl").read_text()
    assert os.stat(root / "events.jsonl").st_mode & 0o777 == 0o600


def test_unknown_event_no_execution(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    assert call(contract, root, "usb-add").returncode == 4
    assert not (root / "work/order").exists()
    assert records(root)[0]["reason"] == "unsupported-event"
    assert records(root)[0]["event"] == "[unsupported]"
    assert records(root)[0]["exit_code"] == 4


def test_failure_stop_and_continue(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    (root / "handlers/10-first").write_text("#!/bin/sh\nexit 7\n")
    doc = pin(contract, root, "10-first")
    assert call(contract, root, "netfilter").returncode == 1
    assert [r["handler"] for r in records(root)] == ["10-first", None]
    assert records(root)[0]["exit_code"] == 7
    doc["on_error"] = "continue"
    contract.write_text(json.dumps(doc))
    assert call(contract, root, "netfilter").returncode == 1
    assert [r["handler"] for r in records(root)[-4:]] == [
        "10-first",
        "20-ignored",
        "30-restore",
        None,
    ]
    assert records(root)[-1]["status"] == "FAIL"


def test_timeout_kills_group_and_marks_fail(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    (root / "handlers/10-first").write_text("#!/bin/sh\nsleep 3\n")
    pin(contract, root, "10-first")
    assert call(contract, root, "netfilter").returncode == 1
    assert records(root)[0]["timed_out"] is True
    assert [r["handler"] for r in records(root)] == ["10-first", None]


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version=2),
        lambda d: d.update(event="usb-add"),
        lambda d: d.update(source="observed:unproven"),
        lambda d: d["handlers"].reverse(),
        lambda d: d["handlers"].append(d["handlers"][0]),
        lambda d: d.update(before=[["chain:input"]]),
        lambda d: d.update(type=None),
        lambda d: d.update(path="/not-an-allowed-path"),
        lambda d: d.update(on_error="ignore"),
        lambda d: [h.update(executable=False) for h in d["handlers"]],
    ],
)
def test_invalid_contract_refused(tmp_path: Path, change) -> None:
    contract, root = fixture(tmp_path)
    doc = json.loads(contract.read_text())
    change(doc)
    contract.write_text(json.dumps(doc))
    assert call(contract, root, "netfilter").returncode == 3
    assert not (root / "events.jsonl").exists()


def test_duplicate_keys_and_unsafe_selection(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    original = contract.read_text()
    contract.write_text(
        original.replace(
            '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'
        )
    )
    with pytest.raises(EventError):
        load_contract(contract)
    contract.write_text(original)
    (root / "handlers/15-extra").write_text("#!/bin/sh\n")
    assert call(contract, root, "netfilter").returncode == 3
    (root / "handlers/15-extra").unlink()
    (root / "handlers/10-first").unlink()
    (root / "handlers/10-first").symlink_to(root / "handlers/30-restore")
    assert call(contract, root, "netfilter").returncode == 3
    assert not (root / "events.jsonl").exists()


def test_no_false_pass_when_state_not_restored_and_nonexec_policy(
    tmp_path: Path,
) -> None:
    contract, root = fixture(tmp_path)
    doc = json.loads(contract.read_text())
    doc["nonexecutable"] = "fail"
    contract.write_text(json.dumps(doc))
    assert call(contract, root, "netfilter").returncode == 1
    assert records(root)[-1]["after_matches"] is False
    doc["nonexecutable"] = "skip"
    contract.write_text(json.dumps(doc))
    (root / "handlers/30-restore").write_text("#!/bin/sh\nexit 0\n")
    pin(contract, root, "30-restore")
    assert call(contract, root, "netfilter").returncode == 1
    assert records(root)[-1]["status"] == "FAIL"


def test_state_symlink_and_modified_handler_refused(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    path = root / "handlers/30-restore"
    original = path.read_text()
    path.write_text("#!/bin/sh\nexit 0\n")
    assert call(contract, root, "netfilter").returncode == 3
    path.write_text(original)
    (root / "state.json").unlink()
    (root / "state.json").symlink_to(contract)
    assert call(contract, root, "netfilter").returncode == 3
    assert not (root / "events.jsonl").exists()


def test_undeclared_or_duplicate_pre_event_state_refused(tmp_path: Path) -> None:
    contract, root = fixture(tmp_path)
    state = root / "state.json"
    for rules in (["chain:input", "foreign:rule"], ["chain:input", "chain:input"]):
        state.write_text(json.dumps({"rules": rules}))
        assert call(contract, root, "netfilter").returncode == 3
        assert not (root / "work/order").exists()
    assert not (root / "events.jsonl").exists()
