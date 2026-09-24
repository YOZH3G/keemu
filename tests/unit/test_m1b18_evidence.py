"""Validate frozen m1b-18 provenance without a Docker/host mutation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LEDGER = REPO / "docs/evidence/m1b18-targets.json"
PASS_LEDGER = REPO / "docs/evidence/m1b18-targets-pass.json"


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
    else:
        followup = json.loads(PASS_LEDGER.read_text())
        assert (
            followup["historical_blocked_ledger_sha256"]
            == hashlib.sha256(LEDGER.read_bytes()).hexdigest()
        )
        assert "old raw bytes are unavailable" in followup["limitation"]


def test_m1b18_pass_ledger_binds_real_docker_probe_and_old_evidence() -> None:
    data = json.loads(PASS_LEDGER.read_text())
    assert data["slice_status"] == "PASS"
    assert data["a01_target_exec_three_generic"].startswith("PASS")
    assert data["a10_matrix"].startswith("NOT RUN")
    assert data["owned_docker_resources_after"] == 0
    assert (
        data["historical_blocked_ledger_sha256"]
        == hashlib.sha256(LEDGER.read_bytes()).hexdigest()
    )
    aarch64 = REPO / data["aarch64_ledger"]
    assert (
        hashlib.sha256(aarch64.read_bytes()).hexdigest()
        == data["aarch64_ledger_sha256"]
    )
    assert (
        json.loads(aarch64.read_text())["acceptance"]["A01"]["aarch64_slice"] == "PASS"
    )
    probe_file = REPO / data["raw_probe"]
    assert probe_file.is_file()
    assert (
        hashlib.sha256(probe_file.read_bytes()).hexdigest() == data["raw_probe_sha256"]
    )
    probe = json.loads(probe_file.read_text())
    assert [r["target"] for r in probe["results"]] == [
        "mipsel-3.4",
        "mips-3.4",
    ]
    for row, raw in zip(data["targets"], probe["results"], strict=True):
        assert row["target"] == raw["target"]
        assert row["endianness"] == (
            "little" if row["target"] == "mipsel-3.4" else "big"
        )
        assert (row["elf_class"], row["abi"], row["isa"], row["fpu"]) == (
            32,
            "o32",
            "MIPS32r2",
            "soft-float",
        )
        assert row["target_elf_count"] == 31
        assert row["package_count"] == 20
        assert row["docker_binfmt"] == row["direct_qemu_proot"] == "PASS"
        assert row["owned_container_cleanup"] == "PASS"
        for key in ("direct_qemu_proot", "docker_exec"):
            assert raw[key]["exit"] == 0
            assert "opkg version " in raw[key]["stdout"]
            assert "keemu-hello" in raw[key]["stdout"]
            assert "fixture-argument-check-ok" in raw[key]["stdout"]
        assert "nested-elf-ok" in raw["direct_qemu_proot"]["stdout"]
        assert "direct-shebang-ok" in raw["direct_qemu_proot"]["stdout"]
        assert "nested-fixture-ok" in raw["docker_exec"]["stdout"]
        assert raw["cleanup"]["absent"]["stdout"] == ""
        for name, expected in row["locks"].items():
            assert (
                hashlib.sha256((REPO / "locks" / name).read_bytes()).hexdigest()
                == expected
            )
        image = json.loads(
            (REPO / "locks" / f"m1b18-image-{row['target']}.json").read_text()
        )
        assert image["image_id"] == row["image_id"]
        assert image["audit"]["target_elf_count"] == row["target_elf_count"]
