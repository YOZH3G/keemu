"""Validate frozen m1b-18 provenance without a Docker/host mutation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs/evidence/m1b18-targets.json"


def test_m1b18_ledger_binds_both_distinct_target_locks() -> None:
    data = json.loads(LEDGER.read_text())
    assert data["subtask"] == "m1b-18"
    assert data["a01_three_target"] == "BLOCKED"
    assert data["a10_matrix"].startswith("NOT RUN")
    assert data["slice_status"] == "BLOCKED"
    assert [entry["target"] for entry in data["targets"]] == ["mipsel-3.4", "mips-3.4"]
    assert [entry["endianness"] for entry in data["targets"]] == ["little", "big"]
    for entry in data["targets"]:
        assert entry["direct_qemu_proot"] == "PASS"
        assert entry["docker_binfmt"] == "BLOCKED"
        assert entry["docker_error"] == "exec /bin/sh: exec format error\n"
        assert entry["owned_container_cleanup"] == "PASS"
        assert entry["root_packages"] == 20
        assert entry["target_elf_count"] == 31
        assert set(entry["fixture_hashes"]) == {"hello", "web-demo", "nfqueue-consumer"}
        for name, expected in entry["locks"].items():
            assert (
                hashlib.sha256((REPO / "locks" / name).read_bytes()).hexdigest()
                == expected
            )
        image = json.loads(
            (REPO / "locks" / f"m1b18-image-{entry['target']}.json").read_text()
        )
        assert image["image_id"] == entry["image_id"]
        assert image["archive_sha256"] == entry["saved_archive_sha256"]


def test_m1b18_ignored_raw_probe_hash_when_available() -> None:
    data = json.loads(LEDGER.read_text())
    raw = REPO / data["raw_probe"]
    if raw.exists():
        assert hashlib.sha256(raw.read_bytes()).hexdigest() == data["raw_probe_sha256"]
        results = json.loads(raw.read_text())["results"]
        assert [entry["target"] for entry in results] == ["mipsel-3.4", "mips-3.4"]
        assert all(entry["docker_status"] == "BLOCKED" for entry in results)
