"""Non-mutating three-target capability differential in disposable owned containers.

Socket creation is not queue binding, a verdict, or an iptables/ipset probe.
No rule, queue, module, or host network is changed. The amd64 control is an
explicit diagnostic binary outside target PATH, not part of the target rootfs.
"""

# ruff: noqa: E501, S607 -- bounded probe commands and fixed local Docker
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts.build_m1b18_fixtures import CFLAGS
from scripts.build_m1b18_images import checked_elf

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "fixtures/sources/nfqueue/nfqueue_socket_p007.c"
TARGETS = ("aarch64-3.10", "mipsel-3.4", "mips-3.4")
MODULES = ("nfnetlink_queue", "xt_NFQUEUE", "nft_queue")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 90
) -> dict:
    try:
        result = subprocess.run(  # noqa: S603 -- fixed project/compiler/docker argv
            argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout
        )
        return {
            "exit": result.returncode,
            "stdout": result.stdout[-200000:],
            "stderr": result.stderr[-4096:],
        }
    except subprocess.TimeoutExpired:
        return {"timeout_seconds": timeout, "status": "ERROR"}


def require(argv: list[str], **kwargs) -> str:
    result = run(argv, **kwargs)
    if result.get("exit") != 0:
        raise RuntimeError(f"{argv[:3]}: {result}")
    return result["stdout"].strip()


def stage(cid: str, label: str, source: Path) -> None:
    # Docker cp refuses even a writable tmpfs beneath a read-only rootfs.
    # Stream pinned bytes through the already running target shell instead.
    result = subprocess.run(  # noqa: S603, S607 -- fixed Docker argv, owned container
        [
            "docker",
            "exec",
            "-i",
            cid,
            "/bin/sh",
            "-c",
            f"/opt/bin/busybox cat > /opt/tmp/m1b22-{label} && /opt/bin/busybox chmod 755 /opt/tmp/m1b22-{label}",
        ],
        input=source.read_bytes(),
        capture_output=True,
        timeout=90,
    )
    if result.returncode:
        raise RuntimeError(f"binary staging failed: {result.stderr[-1024:]!r}")


def modules() -> dict:
    names = {line.split()[0] for line in Path("/proc/modules").read_text().splitlines()}
    return {name: name in names for name in MODULES}


def build(target: str, directory: Path) -> Path:
    dest = directory / f"socket-{target}"
    if target == "aarch64-3.10":
        tc = ROOT / ".runtime/p0/cross-toolchain/root"
        gcc = tc / "usr/bin/aarch64-linux-gnu-gcc"
        env = {**os.environ, "LD_LIBRARY_PATH": str(tc / "usr/lib/x86_64-linux-gnu")}
        require(
            [
                str(gcc),
                "--sysroot=" + str(tc),
                "-static",
                "-O2",
                "-o",
                str(dest),
                str(SOURCE),
            ],
            env=env,
        )
        header = dest.read_bytes()[:20]
        if (
            header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != 183
        ):
            raise ValueError("AArch64 probe ELF mismatch")
    else:
        arch = target.removesuffix("-3.4")
        sdk = ROOT / ".runtime/m1b18" / target / "sdk-rootfs"
        src = sdk / "opt/tmp/keemu-build/m1b22-socket.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        if src.exists() and src.read_bytes() != SOURCE.read_bytes():
            raise ValueError("existing SDK probe source differs")
        if not src.exists():
            src.write_bytes(SOURCE.read_bytes())
        qemu = ROOT / ".runtime/p0/qemu-user-root/usr/bin" / f"qemu-{arch}"
        proot = ROOT / ".runtime/p0/proot-root/usr/bin/proot"
        env = {
            "HOME": "/root",
            "PATH": "/opt/bin:/opt/sbin:/usr/bin:/bin",
            "LANG": "C",
            "LD_LIBRARY_PATH": str(
                (ROOT / ".runtime/p0/proot-root/usr/lib/x86_64-linux-gnu").resolve()
            ),
        }
        require(
            [
                str(proot),
                "-R",
                str(sdk),
                "-q",
                str(qemu),
                "-w",
                "/opt",
                "/opt/bin/gcc",
                *CFLAGS,
                "-o",
                "/opt/tmp/keemu-build/m1b22-socket",
                "/opt/tmp/keemu-build/m1b22-socket.c",
            ],
            env=env,
            timeout=300,
        )
        shutil.copyfile(sdk / "opt/tmp/keemu-build/m1b22-socket", dest)
        checked_elf(dest, target)
    dest.chmod(0o755)
    return dest


def image(target: str) -> str:
    lock = (
        "m1a-init-aarch64.json"
        if target == "aarch64-3.10"
        else f"m1b18-image-{target}.json"
    )
    value = json.loads((ROOT / "locks" / lock).read_text())[
        "oci_digest" if target == "aarch64-3.10" else "image_id"
    ]
    info = json.loads(require(["docker", "image", "inspect", value]))[0]
    if (
        info["Id"] != value
        or info["Config"]["Labels"].get("org.keemu.owner") != "keemu"
        or info["Config"]["Labels"].get("org.keemu.target") != target
    ):
        raise ValueError("image identity mismatch")
    return value


def probe(target: str, binary: Path, control: Path) -> dict:
    run_id = "m1b22-" + uuid.uuid4().hex
    name = "keemu-" + run_id
    img = image(target)
    cid = require(
        [
            "docker",
            "create",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            "org.keemu.phase=m1b-22",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--label",
            f"org.keemu.target={target}",
            "--network=none",
            "--read-only",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs=/opt/tmp:rw,nosuid,nodev,exec,size=16m",
            img,
        ]
    )
    if len(cid) != 64:
        raise ValueError(
            "Docker returned non-full ID; manual ownership reconciliation required"
        )
    result: dict[str, object] = {
        "target": target,
        "image_id": img,
        "container_id": cid,
        "target_probe_sha256": sha(binary),
        "native_control_sha256": sha(control),
        "network": "none",
        "capabilities": "drop ALL",
        "queue_bind": "NOT RUN",
        "iptables_backend": "BLOCKED",
        "ipset_create": "BLOCKED",
        "conntrack": "BLOCKED",
        "forwarding": "BLOCKED",
        "packet_verdict": "BLOCKED",
    }
    try:
        inspect = json.loads(require(["docker", "inspect", cid]))[0]
        config = inspect["HostConfig"]
        if (
            inspect["Id"] != cid
            or inspect["Image"] != img
            or config["NetworkMode"] != "none"
            or config["Privileged"]
            or config["CapAdd"] not in (None, [])
            or "ALL" not in config["CapDrop"]
            or config["PortBindings"] not in (None, {})
            or config["Binds"] not in (None, [])
        ):
            raise ValueError("container controls mismatch")
        require(["docker", "start", cid])
        for label, source in (("target", binary), ("native", control)):
            stage(cid, label, source)
        result["target_socket"] = run(["docker", "exec", cid, "/opt/tmp/m1b22-target"])
        result["native_socket"] = run(["docker", "exec", cid, "/opt/tmp/m1b22-native"])
        result["target_tools"] = run(
            [
                "docker",
                "exec",
                cid,
                "/bin/sh",
                "-c",
                "for tool in iptables ipset conntrack; do command -v $tool || true; done",
            ]
        )
        target_socket = result["target_socket"]
        native_socket = result["native_socket"]
        if not isinstance(target_socket, dict) or not isinstance(native_socket, dict):
            raise TypeError("socket evidence is not a command result")
        result["socket_status"] = (
            "PASS"
            if target_socket.get("exit") == 0
            else "BLOCKED"
            if target_socket.get("exit") == 1
            else "ERROR"
        )
        result["native_control_status"] = (
            "PASS" if native_socket.get("exit") == 0 else "ERROR"
        )
        result["reason"] = (
            "Target socket creation only; no queue bind, packet or verdict."
            if result["socket_status"] == "PASS"
            else "Target socket unavailable or rejected; native same-namespace control recorded. "
            "No queue bind, packet or verdict."
        )
    finally:
        info = json.loads(require(["docker", "inspect", cid]))[0]
        labels = info["Config"]["Labels"]
        if (
            info["Id"] != cid
            or info["Image"] != img
            or labels.get("org.keemu.owner") != "keemu"
            or labels.get("org.keemu.run-id") != run_id
            or labels.get("org.keemu.target") != target
        ):
            raise RuntimeError("cleanup refused: ownership mismatch")
        if info["State"]["Running"]:
            require(["docker", "stop", "-t", "5", cid], timeout=30)
        require(["docker", "rm", cid], timeout=30)
        if require(["docker", "ps", "-aq", "--filter", f"id={cid}"]):
            raise RuntimeError("container not absent after cleanup")
        result["cleanup"] = "PASS"
    return result


def main() -> None:
    folder = ROOT / ".runtime/m1b22" / uuid.uuid4().hex
    folder.mkdir(parents=True, exist_ok=False)
    before = modules()
    source = sha(SOURCE)
    native = folder / "socket-amd64"
    require(["gcc", "-static", "-O2", "-o", str(native), str(SOURCE)])
    native.chmod(0o755)
    results = []
    try:
        for target in TARGETS:
            results.append(probe(target, build(target, folder), native))
    finally:
        after = modules()
        evidence = {
            "schema_version": 1,
            "subtask": "m1b-22",
            "created_at": datetime.now(UTC).isoformat(),
            "kernel": platform.release(),
            "source_sha256": source,
            "modules_before": before,
            "modules_after": after,
            "results": results,
            "scope": "Socket creation/native control only; backend presence is not functional testing; no queue bind, rule, ipset, packet, module loading, host networking or public publish.",
        }
        output = folder / "capabilities.json"
        with output.open("x") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(
            output.relative_to(ROOT),
            sha(output),
            [(x["target"], x.get("socket_status"), x["cleanup"]) for x in results],
            "modules_unchanged",
            before == after,
        )
    if (
        before != after
        or len(results) != 3
        or any(r["cleanup"] != "PASS" for r in results)
    ):
        raise RuntimeError("incomplete or changed-host capability probe")


if __name__ == "__main__":
    main()
