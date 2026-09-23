"""P0-07 bounded NFQUEUE preflight, without host-module or firewall mutation.

This script intentionally cannot bind a queue or add a firewall rule. If the
host NFQUEUE components are not already active, doing either could autoload a
host module, which requires separate approval under TASK.md. It compares
native and AArch64 netlink socket behavior inside one disposable network-none
container and records the blocked ACCEPT/DROP gate truthfully.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
BASE_LOCK = ROOT / "locks/p0-mixed-image-aarch64-p005.json"
FIXTURE_LOCK = ROOT / "locks/p0-fixtures-aarch64.json"
SOURCE = ROOT / "fixtures/sources/nfqueue/nfqueue_socket_p007.c"
CONSUMER = ROOT / "fixtures/sources/nfqueue/nfqueue_consumer.c"
MODULES = ("nfnetlink_queue", "xt_NFQUEUE", "nft_queue")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 60
) -> dict:
    try:
        result = subprocess.run(  # noqa: S603 -- fixed local compilers and Docker argv.
            argv,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "rc": result.returncode,
            "stdout": result.stdout[-65536:],
            "stderr": result.stderr[-2048:],
        }
    except subprocess.TimeoutExpired as exc:
        return {"argv": argv, "timeout_seconds": timeout, "error": str(exc)}


def require(result: dict) -> str:
    if result.get("rc") != 0:
        raise RuntimeError(f"{result['argv']!r}: {result!r}")
    return result["stdout"].strip()


def module_snapshot() -> dict:
    loaded = {
        line.split()[0] for line in Path("/proc/modules").read_text().splitlines()
    }
    return {
        "loaded": {name: name in loaded for name in MODULES},
        "sys_module": {name: Path("/sys/module", name).exists() for name in MODULES},
        "proc_nfnetlink_queue": Path("/proc/net/netfilter/nfnetlink_queue").exists(),
        "modules_disabled": Path("/proc/sys/kernel/modules_disabled")
        .read_text()
        .strip(),
    }


def main() -> int:
    run_id = "p007-" + uuid4().hex[:12]
    name = "keemu-" + run_id
    folder = (
        ROOT / "reports" / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + run_id)
    )
    folder.mkdir(parents=True, exist_ok=False)
    output = folder / "preflight.json"
    build = ROOT / ".runtime/p0" / run_id
    build.mkdir(parents=True, exist_ok=False)
    report: dict = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "scope": (
            "p0-07 native/target NFNETLINK preflight only; no NFQUEUE bind, "
            "verdict, firewall or host module mutation"
        ),
        "kernel": platform.release(),
        "module_before": module_snapshot(),
        "source_hashes": {"socket_probe": digest(SOURCE), "consumer": digest(CONSUMER)},
        "steps": [],
        "result": "INCOMPLETE",
    }

    def step(
        argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 60
    ) -> dict:
        value = run(argv, env=env, timeout=timeout)
        report["steps"].append(value)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return value

    created = False
    cleanup_error: str | None = None
    failure: str | None = None
    try:
        # This bounded diagnosis assumes the queue handler is not preloaded.
        # A different host needs a separately scoped packet-flow procedure.
        assert not any(report["module_before"]["loaded"].values())
        assert not any(report["module_before"]["sys_module"].values())
        base = json.loads(BASE_LOCK.read_text())
        fixtures = json.loads(FIXTURE_LOCK.read_text())
        target_fixture = next(
            item for item in fixtures["fixtures"] if item["id"] == "nfqueue-consumer"
        )
        assert digest(CONSUMER) == target_fixture["sources"][0]["sha256"]
        assert (
            digest(ROOT / target_fixture["recipe"]) == target_fixture["recipe_sha256"]
        )
        original = ROOT / target_fixture["verified_output"]["path"]
        assert digest(original) == target_fixture["verified_output"]["sha256"]
        report["original_fixture_sha256"] = digest(original)
        inspected = json.loads(
            require(step(["docker", "image", "inspect", base["image_id"]]))
        )[0]
        assert (
            inspected["Id"] == base["image_id"]
            and inspected["Config"]["Labels"]["org.keemu.owner"] == "keemu"
        )
        report["base_image_id"] = base["image_id"]
        report["docker_version"] = require(
            step(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"])
        ).strip()
        tc = ROOT / ".runtime/p0/cross-toolchain/root"
        gcc = tc / "usr/bin/aarch64-linux-gnu-gcc"
        lib = tc / "usr/lib/x86_64-linux-gnu"
        env = {**os.environ, "LD_LIBRARY_PATH": str(lib)}
        assert gcc.is_file() and lib.is_dir()
        built = {
            "native_socket": (SOURCE, ["gcc", "-static", "-O2", "-o"]),
            "target_socket": (
                SOURCE,
                [str(gcc), "--sysroot=" + str(tc), "-static", "-O2", "-o"],
            ),
            "native_consumer": (CONSUMER, ["gcc", "-static", "-O2", "-o"]),
            "target_consumer": (
                CONSUMER,
                [str(gcc), "--sysroot=" + str(tc), "-static", "-O2", "-o"],
            ),
        }
        report["built_binaries"] = {}
        for key, (src, prefix) in built.items():
            dest = build / key
            require(
                step(
                    [*prefix, str(dest), str(src)],
                    env=env if key.startswith("target") else None,
                )
            )
            header = dest.read_bytes()[:20]
            assert header[:6] == b"\x7fELF\x02\x01"
            machine = int.from_bytes(header[18:20], "little")
            assert machine == (183 if key.startswith("target") else 62)
            report["built_binaries"][key] = {
                "sha256": digest(dest),
                "elf_machine": machine,
                "source_sha256": digest(src),
                "static_build": True,
            }
        context = build / "image"
        payload = context / "payload/opt/bin"
        payload.mkdir(parents=True)
        for key, source in (
            ("dynamic_target", original),
            *((key, build / key) for key in built),
        ):
            shutil.copy2(source, payload / ("p007-" + key))
        (context / "Dockerfile").write_text(
            f"FROM {base['image_id']}\nCOPY payload/ /\n"
            'LABEL org.keemu.phase="p0-07"\n'
            f'LABEL org.keemu.p007-socket-source-sha256="{digest(SOURCE)}"\n'
            f'LABEL org.keemu.p007-consumer-source-sha256="{digest(CONSUMER)}"\n'
        )
        image_ref = "keemu/p0-aarch64:" + run_id
        require(
            step(
                [
                    "docker",
                    "build",
                    "--network=none",
                    "--platform",
                    "linux/amd64",
                    "-t",
                    image_ref,
                    str(context),
                ],
                timeout=180,
            )
        )
        image_id = require(
            step(["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"])
        )
        report["diagnostic_image_id"] = image_id
        # NET_ADMIN is deliberately absent. Network and mount namespaces are
        # Docker-owned; no host network, port publish, or bind mount is used.
        create = [
            "docker",
            "create",
            "--name",
            name,
            "--network=none",
            "--read-only",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            "org.keemu.phase=p0-07",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            image_id,
        ]
        require(step(create))
        created = True
        inspect = json.loads(require(step(["docker", "inspect", name])))[0]
        assert inspect["Image"] == image_id
        assert inspect["HostConfig"]["NetworkMode"] == "none"
        assert inspect["HostConfig"]["Privileged"] is False
        assert inspect["HostConfig"]["ReadonlyRootfs"] is True
        assert inspect["HostConfig"]["CapAdd"] in (None, [])
        assert "ALL" in inspect["HostConfig"]["CapDrop"]
        assert inspect["HostConfig"]["Binds"] in (None, [])
        assert inspect["HostConfig"]["PortBindings"] in (None, {})
        report["container_controls"] = {
            k: inspect["HostConfig"][k]
            for k in (
                "NetworkMode",
                "Privileged",
                "ReadonlyRootfs",
                "CapAdd",
                "CapDrop",
                "Binds",
                "PortBindings",
                "Memory",
                "PidsLimit",
            )
        }
        require(step(["docker", "start", name]))
        report["execution"] = {}
        for key in (
            "dynamic_target",
            "native_socket",
            "target_socket",
            "native_consumer",
            "target_consumer",
        ):
            argv = ["docker", "exec", name, "/opt/bin/p007-" + key]
            if "consumer" in key or key == "dynamic_target":
                # Argument-parser smoke only; no queue bind or module autoload.
                argv += ["--queue", "0", "--mode", "invalid"]
            report["execution"][key] = step(argv)
        assert report["execution"]["native_consumer"]["rc"] == 2
        assert report["execution"]["target_consumer"]["rc"] == 2
        assert report["execution"]["native_socket"]["rc"] == 0
        assert report["execution"]["target_socket"]["rc"] == 1
        assert (
            "Protocol not supported" in report["execution"]["target_socket"]["stderr"]
        )
        assert "GLIBC_2.34" in report["execution"]["dynamic_target"]["stderr"]
        report["module_after_execution"] = module_snapshot()
        if (
            report["module_after_execution"]["loaded"]
            != report["module_before"]["loaded"]
        ):
            raise AssertionError("unexpected host NFQUEUE module change; stop")
        report["result"] = "BLOCKED"
        report["blocker"] = (
            "In the same isolated Docker namespace, a native static "
            "NETLINK_NETFILTER socket opens, but the static AArch64 socket "
            "call returns EPROTONOSUPPORT (Protocol not supported). The "
            "original locked dynamic AArch64 fixture cannot launch with "
            "the Entware libc (GLIBC_2.34 unavailable); a separately built "
            "static target variant executes its argument parser but not a "
            "verdict. This differentiates target execution from the "
            "native socket control, not QEMU emulation from seccomp/kernel causality. "
            "Host nfnetlink_queue/xt_NFQUEUE/nft_queue are not preloaded. "
            "Binding a queue or installing a rule may autoload a host "
            "kernel module, requiring separate approval under TASK.md. "
            "No queue bind, rule, packet or verdict was attempted. "
            "A13/A14/A17 are NOT PASS; MVP 1C remains blocked on the "
            "target socket and kernel gate."
        )
    except Exception as exc:
        failure = repr(exc)
        report["failure"] = failure
        report["result"] = "ERROR"
    finally:
        if created:
            owner = step(
                ["docker", "inspect", name, "--format", "{{json .Config.Labels}}"]
            )
            labels = json.loads(owner["stdout"]) if owner.get("rc") == 0 else {}
            if (
                labels.get("org.keemu.owner") == "keemu"
                and labels.get("org.keemu.run-id") == run_id
            ):
                if (
                    require(
                        step(
                            [
                                "docker",
                                "inspect",
                                name,
                                "--format",
                                "{{.State.Running}}",
                            ]
                        )
                    )
                    == "true"
                ):
                    stopped = step(["docker", "stop", "-t", "5", name], timeout=20)
                    if stopped.get("rc") != 0:
                        cleanup_error = "stop failed"
                if step(["docker", "rm", name]).get("rc") != 0:
                    cleanup_error = "remove failed"
                if step(["docker", "container", "inspect", name]).get("rc") == 0:
                    cleanup_error = "absence not verified"
            else:
                cleanup_error = "ownership mismatch: removal refused"
        report["module_final"] = module_snapshot()
        if report["module_final"]["loaded"] != report["module_before"]["loaded"]:
            cleanup_error = "host module set changed"
        if cleanup_error:
            report["cleanup_error"] = cleanup_error
            report["result"] = "ERROR"
        report["finished_at"] = datetime.now(UTC).isoformat()
        output.write_text(json.dumps(report, indent=2) + "\n")
    print(output)
    print(f"result={report['result']} failure={failure} cleanup={cleanup_error}")
    return 0 if report["result"] == "BLOCKED" else 1


if __name__ == "__main__":
    sys.exit(main())
