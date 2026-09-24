"""Publish a no-replace, hash-bound m1b-18 Docker PASS observation."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from scripts.verify_m1b18 import verify

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "docs/evidence/m1b18-probe-pass.json"
LEDGER = REPO / "docs/evidence/m1b18-targets-pass.json"
TARGETS = ("mipsel-3.4", "mips-3.4")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def no_owned_resources() -> bool:
    for command in (
        ["docker", "ps", "-aq", "--filter", "label=org.keemu.owner=keemu"],
        ["docker", "network", "ls", "-q", "--filter", "label=org.keemu.owner=keemu"],
    ):
        output = subprocess.run(  # noqa: S603 -- fixed local Docker read-only argv.
            command, capture_output=True, text=True, timeout=30, check=True
        )
        if output.stdout.strip():
            return False
    return True


def freeze(probe_path: Path) -> Path:
    runtime = (REPO / ".runtime/m1b18").resolve()
    if (
        probe_path.is_symlink()
        or not probe_path.is_file()
        or probe_path.resolve().parent != runtime
        or RAW.exists()
        or RAW.is_symlink()
        or LEDGER.exists()
        or LEDGER.is_symlink()
    ):
        raise ValueError(
            "probe must be a regular m1b18 runtime file; evidence refuses overwrite"
        )
    probe = json.loads(probe_path.read_text())
    if probe.get("schema_version") != 1 or probe.get("subtask") != "m1b-18":
        raise ValueError("wrong probe schema/subtask")
    rows = probe.get("results")
    if not isinstance(rows, list) or len(rows) != len(TARGETS):
        raise ValueError("missing target result")
    if not no_owned_resources():
        raise ValueError("project-owned Docker resources remain")
    aarch64 = REPO / "docs/evidence/m1a17-acceptance.json"
    historic = REPO / "docs/evidence/m1b18-targets.json"
    old = json.loads(historic.read_text())
    prior = json.loads(aarch64.read_text())
    if (
        prior["acceptance"]["A01"]["aarch64_slice"] != "PASS"
        or old["slice_status"] != "BLOCKED"
        or old["a01_three_target"] != "BLOCKED"
    ):
        raise ValueError("previous AArch64 or historical blocked evidence mismatch")
    evidence = []
    for target, row in zip(TARGETS, rows, strict=True):
        if row.get("target") != target:
            raise ValueError("target ordering/mapping mismatch")
        for key in ("direct_qemu_proot", "docker_exec"):
            result = row[key]
            markers = (
                (
                    "target-shell-ok",
                    "opkg version ",
                    "nested-elf-ok",
                    "direct-shebang-ok",
                    "keemu-hello",
                    "fixture-argument-check-ok",
                )
                if key == "direct_qemu_proot"
                else (
                    "shell-ok",
                    "opkg version ",
                    "keemu-hello",
                    "nested-fixture-ok",
                    "fixture-argument-check-ok",
                )
            )
            if (
                result["exit"]
                or result["stderr"]
                or any(m not in result["stdout"] for m in markers)
            ):
                raise ValueError(f"{target}: incomplete {key} evidence")
        cleanup = row["cleanup"]
        if (
            row["direct_status"] != row["docker_status"]
            or row["docker_status"] != "PASS"
            or len(row["container_id"]) != 64
            or any(cleanup[k]["exit"] for k in ("stop", "remove", "absent"))
            or cleanup["absent"]["stdout"]
            or cleanup["remove"]["stdout"].strip() != row["container_id"]
        ):
            raise ValueError(f"{target}: status or cleanup mismatch")
        verified = verify(target)
        locks = {
            name: sha(REPO / "locks" / name)
            for name in (
                f"m1b18-{target}.json",
                f"m1b18-sdk-{target}.json",
                f"m1b18-fixtures-{target}.json",
                f"m1b18-image-{target}.json",
            )
        }
        image = json.loads((REPO / "locks" / f"m1b18-image-{target}.json").read_text())
        if (
            verified["status"].split(" ")[0] != "PASS"
            or verified["image_id"] != image["image_id"]
        ):
            raise ValueError(f"{target}: offline image check failed")
        evidence.append(
            {
                "target": target,
                "profile": f"generic-{target[:-4]}",
                "endianness": "little" if target.startswith("mipsel") else "big",
                "elf_class": 32,
                "abi": "o32",
                "isa": "MIPS32r2",
                "fpu": "soft-float",
                "package_count": verified["package_count"],
                "target_elf_count": verified["target_elf_count"],
                "image_id": verified["image_id"],
                "locks": locks,
                "direct_qemu_proot": "PASS",
                "docker_binfmt": "PASS",
                "owned_container_cleanup": "PASS",
            }
        )
    # Preserve the exact observed probe in Git: ignored runtime files can be replaced.
    with RAW.open("xb") as output, probe_path.open("rb") as source:
        shutil.copyfileobj(source, output)
    if sha(RAW) != sha(probe_path):
        raise ValueError("published raw probe hash differs")
    payload = {
        "schema_version": 1,
        "subtask": "m1b-18",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "historical_blocked_ledger": str(historic.relative_to(REPO)),
        "historical_blocked_ledger_sha256": sha(historic),
        "aarch64_ledger": str(aarch64.relative_to(REPO)),
        "aarch64_ledger_sha256": sha(aarch64),
        "raw_probe": str(RAW.relative_to(REPO)),
        "raw_probe_sha256": sha(RAW),
        "targets": evidence,
        "a01_target_exec_three_generic": (
            "PASS (AArch64 previous ledger plus both current MIPS Docker probes)"
        ),
        "a10_matrix": "NOT RUN (m1b-19)",
        "slice_status": "PASS",
        "owned_docker_resources_after": 0,
        "limitation": (
            "A01 target ELF/shell/nested execution only; MIPS/MIPSEL general init/test "
            "lifecycle, A10 matrix validation and MVP 1B gate are not implemented. "
            "Historical blocked observation is immutable and its ignored raw "
            "probe was overwritten during approved host remediation; the old "
            "digest is retained but old raw bytes are unavailable. Current "
            "probe bytes are tracked and hash-bound. Host binfmt registration "
            "was separately approved, not performed by this probe."
        ),
    }
    with LEDGER.open("x") as output:
        output.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return LEDGER


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("probe", type=Path)
    args = parser.parse_args()
    path = freeze(args.probe)
    print(path.relative_to(REPO), sha(path))
