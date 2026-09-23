from __future__ import annotations

import json
from pathlib import Path

import pytest

from keemu.fixture_lock import FixtureLockError, verify_fixture_lock

REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "locks" / "p0-fixtures-aarch64.json"


def test_p0_fixture_lock_covers_sources_recipes_and_external_provenance() -> None:
    verified = verify_fixture_lock(LOCK, REPO)

    assert verified == [
        "hello",
        "web-demo",
        "nfqueue-consumer",
    ]
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["target"] == "aarch64-3.10"
    assert lock["architecture"]["elf_machine"] == "AArch64"
    assert lock["toolchain"]["kind"] == "debian-cross-gcc"
    assert lock["fixtures"][2]["runtime_dependencies"] == ["libc"]
    assert lock["fixtures"][2]["kernel_requirements"] == ["NFQUEUE"]


def test_fixture_lock_rejects_tampered_source(tmp_path: Path) -> None:
    lock = {
        "schema_version": 1,
        "kind": "keemu-fixture-lock",
        "target": "aarch64-3.10",
        "architecture": {
            "elf_machine": "AArch64",
            "elf_class": 64,
            "endian": "little",
        },
        "toolchain": {
            "kind": "debian-cross-gcc",
            "artifacts": [
                {"path": "toolchain.deb", "sha256": "0" * 64},
            ],
        },
        "fixtures": [
            {
                "id": "hello",
                "sources": [
                    {"path": "hello.c", "sha256": "0" * 64},
                ],
                "recipe": "hello.mk",
                "recipe_sha256": "0" * 64,
                "runtime_dependencies": ["libc"],
                "kernel_requirements": [],
            }
        ],
    }
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    (tmp_path / "hello.c").write_text("tampered", encoding="utf-8")
    (tmp_path / "hello.mk").write_text("recipe", encoding="utf-8")

    with pytest.raises(FixtureLockError, match="hash mismatch: hello.c"):
        verify_fixture_lock(path, tmp_path)
