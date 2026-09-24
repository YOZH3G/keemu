"""Freeze verified m1b-18 slice; never promote a binfmt blocker to A01 PASS."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts.verify_m1b18 import verify

REPO = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze() -> Path:
    destination = REPO / "docs/evidence/m1b18-targets.json"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    probe_path = REPO / ".runtime/m1b18/probe.json"
    probe = json.loads(probe_path.read_text())
    if probe["subtask"] != "m1b-18" or len(probe["results"]) != 2:
        raise ValueError("incomplete target probe")
    rows = []
    for entry, target in zip(probe["results"], ("mipsel-3.4", "mips-3.4"), strict=True):
        result = verify(target)
        if (
            entry["target"] != target
            or entry["direct_status"] != "PASS"
            or entry["docker_status"] not in {"PASS", "BLOCKED"}
            or entry["cleanup"]["absent"]["stdout"]
            or entry["cleanup"]["remove"]["exit"]
        ):
            raise ValueError(f"unverified or incomplete target evidence: {target}")
        lock_files = {}
        for kind in ("", "sdk-", "fixtures-", "image-"):
            name = f"m1b18-{kind}{target}.json"
            lock_files[name] = sha(REPO / "locks" / name)
        image_lock = json.loads(
            (REPO / "locks" / f"m1b18-image-{target}.json").read_text()
        )
        fixtures_lock = json.loads(
            (REPO / "locks" / f"m1b18-fixtures-{target}.json").read_text()
        )
        rows.append(
            {
                "target": target,
                "profile": f"generic-{target[:-4]}",
                "root_packages": result["package_count"],
                "target_elf_count": result["target_elf_count"],
                "endianness": "little" if target.startswith("mipsel") else "big",
                "elf_class": 32,
                "abi": "o32",
                "isa": "MIPS32r2",
                "fpu": "soft-float",
                "image_id": result["image_id"],
                "saved_archive_sha256": image_lock["archive_sha256"],
                "fixture_hashes": {
                    name: item["sha256"]
                    for name, item in fixtures_lock["fixtures"].items()
                },
                "locks": lock_files,
                "offline_integrity": "PASS",
                "direct_qemu_proot": "PASS",
                "docker_binfmt": entry["docker_status"],
                "docker_error": entry["docker_exec"]["stderr"],
                "owned_container_cleanup": "PASS",
            }
        )
    status = (
        "PASS" if all(row["docker_binfmt"] == "PASS" for row in rows) else "BLOCKED"
    )
    bundle = {
        "schema_version": 1,
        "subtask": "m1b-18",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "raw_probe": str(probe_path.relative_to(REPO)),
        "raw_probe_sha256": sha(probe_path),
        "targets": rows,
        "a01_three_target": "BLOCKED",
        "a10_matrix": "NOT RUN (scheduled for m1b-19)",
        "slice_status": status,
        "limitation": "Direct QEMU/PRoot proves diagnostic behavior only; Docker "
        "target exec is blocked by unusable MIPS binfmt in Docker. No host "
        "registration was authorized or changed. AArch64 and full A01 remain "
        "as in the m1a-17 ledger; this is not matrix acceptance.",
    }
    destination.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    return destination


if __name__ == "__main__":
    path = freeze()
    print(path.relative_to(REPO), sha(path))
