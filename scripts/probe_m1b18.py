"""Bounded MIPS target probe: direct QEMU/PRoot and Docker/binfmt differential."""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUNTIME = REPO / ".runtime/m1b18"


def cmd(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 90
) -> dict:
    result = subprocess.run(  # noqa: S603 -- constrained project argv only.
        argv, capture_output=True, text=True, timeout=timeout, env=env
    )
    return {
        "exit": result.returncode,
        "stdout": result.stdout[-200000:],
        "stderr": result.stderr[-2000:],
    }


def docker(argv: list[str], *, timeout: int = 90) -> dict:
    return cmd(["docker", *argv], timeout=timeout)


def probe(target: str) -> dict:
    lock = json.loads((REPO / "locks" / f"m1b18-image-{target}.json").read_text())
    work = RUNTIME / target
    root = work / "image-rootfs"
    qemu = REPO / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{target[:-4]}"
    proot = REPO / ".runtime/p0/proot-root/usr/bin/proot"
    lib = REPO / ".runtime/p0/proot-root/usr/lib/x86_64-linux-gnu"
    env = {
        "HOME": "/root",
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LD_LIBRARY_PATH": str(lib.resolve()),
    }
    script = root / "opt/tmp/m1b18-shebang.sh"
    script.write_text("#!/bin/sh\necho direct-shebang-ok\n/opt/bin/busybox true\n")
    script.chmod(0o755)
    target_run = cmd(
        [
            str(proot),
            "-R",
            str(root),
            "-q",
            str(qemu),
            "-w",
            "/opt",
            "/bin/sh",
            "-c",
            "set -e; echo target-shell-ok; "
            "/opt/bin/opkg --version; /opt/bin/opkg list-installed; "
            "/opt/bin/busybox true; echo nested-elf-ok; "
            "/opt/tmp/m1b18-shebang.sh; "
            "/opt/keemu/fixtures/hello; "
            "/opt/keemu/fixtures/web-demo wrong >/dev/null 2>&1 "
            "&& exit 17 || test $? -eq 2; "
            "/opt/keemu/fixtures/nfqueue-consumer wrong >/dev/null 2>&1 "
            "&& exit 18 || test $? -eq 2; "
            "echo fixture-argument-check-ok",
        ],
        env=env,
        timeout=120,
    )
    script.unlink()
    direct_ok = target_run["exit"] == 0 and all(
        marker in target_run["stdout"]
        for marker in (
            "target-shell-ok",
            "nested-elf-ok",
            "direct-shebang-ok",
            "keemu-hello",
            "fixture-argument-check-ok",
        )
    )
    run_id = uuid.uuid4().hex
    name = f"keemu-m1b18-{target[:-4]}-{run_id[:10]}"
    created = docker(
        [
            "create",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            "org.keemu.phase=m1b-18",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--label",
            f"org.keemu.target={target}",
            "--network=none",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs=/opt/tmp:rw,nosuid,nodev,size=16m",
            lock["image_id"],
        ]
    )
    if created["exit"]:
        raise RuntimeError(f"Docker create failed: {created['stderr']}")
    cid = created["stdout"].strip()
    if len(cid) != 64:
        raise RuntimeError("Docker returned non-full container ID")
    proof = None
    cleanup = None
    try:
        started = docker(["start", cid])
        proof = (
            docker(
                [
                    "exec",
                    cid,
                    "/bin/sh",
                    "-c",
                    "set -e; echo shell-ok; /opt/bin/opkg --version; "
                    "/opt/bin/busybox true; /opt/keemu/fixtures/hello; "
                    "echo nested-fixture-ok",
                ],
                timeout=120,
            )
            if started["exit"] == 0
            else started
        )
    finally:
        inspected = docker(["inspect", cid])
        if inspected["exit"]:
            raise RuntimeError("refused cleanup: container inspect failed")
        info = json.loads(inspected["stdout"])[0]
        labels = info["Config"]["Labels"]
        if (
            info["Id"] != cid
            or info["Image"] != lock["image_id"]
            or labels.get("org.keemu.owner") != "keemu"
            or labels.get("org.keemu.run-id") != run_id
            or labels.get("org.keemu.target") != target
        ):
            raise RuntimeError("refused cleanup: container identity mismatch")
        stopped = docker(["stop", "-t", "5", cid], timeout=30)
        removed = docker(["rm", cid], timeout=30)
        absent = docker(["ps", "-aq", "--filter", f"id={cid}"])
        cleanup = {"stop": stopped, "remove": removed, "absent": absent}
        if stopped["exit"] or removed["exit"] or absent["exit"] or absent["stdout"]:
            raise RuntimeError("owned container cleanup failed")
    return {
        "target": target,
        "direct_status": "PASS" if direct_ok else "FAIL",
        "direct_qemu_proot": target_run,
        "docker_status": (
            "PASS"
            if proof["exit"] == 0
            else "BLOCKED"
            if "exec format error" in proof["stderr"]
            else "FAIL"
        ),
        "docker_exec": proof,
        "container_id": cid,
        "cleanup": cleanup,
        "scope": (
            "Direct QEMU/PRoot is diagnostic only; Docker shell requires host "
            "binfmt. No binfmt entry, privilege, host network, or public port "
            "was changed."
        ),
    }


if __name__ == "__main__":
    bundle = {
        "schema_version": 1,
        "subtask": "m1b-18",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "results": [probe(t) for t in ("mipsel-3.4", "mips-3.4")],
    }
    report = RUNTIME / "probe.json"
    report.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            [
                {
                    "target": x["target"],
                    "direct": x["direct_status"],
                    "docker": x["docker_status"],
                    "docker_error": x["docker_exec"]["stderr"],
                }
                for x in bundle["results"]
            ],
            indent=2,
        )
    )
    print("probe_sha256", hashlib.sha256(report.read_bytes()).hexdigest())
