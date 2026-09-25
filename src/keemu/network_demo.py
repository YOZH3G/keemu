"""Bounded network-demo fixture hooks on an existing owner-checked topology.

This is a fixture lifecycle, not a general `keemu up` integration. API-only
is explicitly diagnostic: it never installs a rule or claims a queue verdict.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, _exec
from keemu.topology import Topology

BINARY = Path(".runtime/m1c24/network-demo-aarch64")
TARGET_BINARY = "/opt/tmp/network-demo-aarch64"
STATE = "/opt/etc/network-demo/mode"
PID = "/opt/etc/network-demo/service.pid"
RULE_MARKER = "/opt/etc/network-demo/rule-installed"
API_PORT = 9090
FLOW_PORT = 8080
QUEUE = 42


@dataclass(frozen=True)
class Flow:
    client: str
    server: str
    router: str


def flow(topo: Topology) -> Flow:
    lan = ipaddress.IPv4Network(topo.lan, strict=True)
    wan = ipaddress.IPv4Network(topo.wan, strict=True)
    if lan.prefixlen != 24 or wan.prefixlen != 24 or lan.overlaps(wan):
        raise DockerBoundaryError("invalid network-demo topology")
    return Flow(
        str(lan.network_address + 3),
        str(wan.network_address + 3),
        str(lan.network_address + 2),
    )


def rule(topo: Topology, *, delete: bool = False) -> list[str]:
    """Only client→server:8080 forwarding enters queue; control/health stay out."""
    selected = flow(topo)
    return [
        "/opt/sbin/iptables",
        "-D" if delete else "-I",
        "FORWARD",
        "-s",
        selected.client + "/32",
        "-d",
        selected.server + "/32",
        "-p",
        "tcp",
        "--dport",
        str(FLOW_PORT),
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(QUEUE),
    ]


class NetworkDemo:
    def __init__(self, topo: Topology, image_id: str, expected_sha256: str):
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise DockerBoundaryError("invalid fixture hash")
        self.topo = topo
        self.runtime = DockerRuntime(topo.run_id, image_id)
        self.expected_sha256 = expected_sha256

    def _router(self) -> str:
        identifier = self.topo.containers["router"]
        item = self.runtime.inspect("container", identifier)
        if not item["State"]["Running"] or item["HostConfig"].get("PortBindings"):
            raise DockerBoundaryError("network-demo router must run without publish")
        if set(self.runtime.reconcile()["container_owned"]) != set(
            self.topo.containers.values()
        ):
            raise DockerBoundaryError("network-demo topology owner set changed")
        return identifier

    def install(self, binary: Path = BINARY) -> None:
        identifier = self._router()
        if not binary.is_file() or binary.is_symlink():
            raise DockerBoundaryError("missing or unsafe network-demo artifact")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != self.expected_sha256:
            raise DockerBoundaryError("network-demo artifact hash mismatch")
        self.runtime.inspect("container", identifier)
        _exec(
            [
                "docker",
                "container",
                "cp",
                "--",
                str(binary),
                f"{identifier}:{TARGET_BINARY}",
            ]
        )
        self.runtime.inspect("container", identifier)
        result = self.runtime.exec(
            identifier, ["/opt/bin/busybox", "sha256sum", TARGET_BINARY]
        )
        if result.stdout.decode().split()[0] != self.expected_sha256:
            raise DockerBoundaryError("network-demo target copy hash mismatch")
        self.runtime.exec(
            identifier,
            ["/opt/bin/busybox", "mkdir", "-p", "/opt/etc/network-demo"],
        )
        self.runtime.exec(
            identifier,
            ["/bin/sh", "-c", f"test -f {STATE} || printf 'accept\\n' > {STATE}"],
        )

    def start(self, *, api_only: bool = False) -> None:
        identifier = self._router()
        address = flow(self.topo).router
        # All interpolated values derive from validated IPv4/network constants.
        script = (
            f"if test -f {PID}; then "
            f"read -r old < {PID}; "
            "case \"$old\" in ''|*[!0-9]*) exit 1;; esac; "
            "if test -e /proc/$old; then exit 1; fi; "
            f"/opt/bin/busybox rm -f {PID}; fi; "
            f"if test -x {TARGET_BINARY} && test -f {STATE} && "
            f"test ! -e {PID}; then "
            f"{TARGET_BINARY} --queue {QUEUE} --bind {address} "
            f"--port {API_PORT} --state {STATE}"
            + (" --api-only" if api_only else "")
            + f" > /opt/etc/network-demo/service.log 2>&1 & echo $! > {PID}; "
            "else exit 1; fi"
        )
        self.runtime.exec(identifier, ["/bin/sh", "-c", script])
        # A failed target socket must not be represented as a live service.
        probe = self.runtime.exec(
            identifier,
            [
                "/opt/bin/busybox",
                "wget",
                "-qO-",
                f"http://{address}:{API_PORT}/api/state",
            ],
            allow_failure=True,
        )
        if probe.exit_code or b'"queue_ready":' not in probe.stdout:
            self.stop()
            raise DockerBoundaryError("network-demo startup/queue unavailable")
        if api_only and b'"queue_ready":false' not in probe.stdout:
            self.stop()
            raise DockerBoundaryError("API-only probe claimed queue readiness")
        if not api_only and b'"queue_ready":true' not in probe.stdout:
            self.stop()
            raise DockerBoundaryError("target queue not ready")

    def stop(self) -> None:
        identifier = self._router()
        marker = self.runtime.exec(
            identifier,
            ["/opt/bin/busybox", "cat", RULE_MARKER],
            allow_failure=True,
        )
        if marker.exit_code == 0:
            self.remove_rule()
        # PID file belongs to this container's private writable layer. Do not
        # stop the container or remove the mode; service restart must preserve it.
        script = (
            f"if test -f {PID}; then "
            f"read -r pid < {PID}; "
            "case \"$pid\" in ''|*[!0-9]*) exit 1;; esac; "
            f"if test -r /proc/$pid/cmdline && "
            f"/opt/bin/busybox grep -aq '{TARGET_BINARY}' /proc/$pid/cmdline; "
            'then kill "$pid"; fi; '
            f"/opt/bin/busybox rm -f {PID}; fi"
        )
        self.runtime.exec(identifier, ["/bin/sh", "-c", script])

    def remove(self) -> None:
        self.stop()
        self.runtime.exec(
            self._router(),
            [
                "/opt/bin/busybox",
                "rm",
                "-f",
                TARGET_BINARY,
                STATE,
                "/opt/etc/network-demo/service.log",
            ],
        )
        self.runtime.exec(
            self._router(),
            ["/opt/bin/busybox", "rmdir", "/opt/etc/network-demo"],
        )

    def install_rule(self) -> None:
        """Fail closed if target firewall/extension missing; never touch host rules."""
        identifier = self._router()
        status = self.runtime.exec(
            identifier,
            [
                "/opt/bin/busybox",
                "wget",
                "-qO-",
                f"http://{flow(self.topo).router}:{API_PORT}/api/state",
            ],
        )
        try:
            ready = json.loads(status.stdout)["queue_ready"] is True
        except (ValueError, KeyError, TypeError) as exc:
            raise DockerBoundaryError("invalid network-demo queue status") from exc
        if not ready:
            raise DockerBoundaryError("target queue not ready; refuse NFQUEUE rule")
        marker = self.runtime.exec(
            identifier,
            ["/opt/bin/busybox", "cat", RULE_MARKER],
            allow_failure=True,
        )
        if marker.exit_code == 0:
            raise DockerBoundaryError("flow rule marker already present")
        if (
            self.runtime.exec(
                identifier,
                [rule(self.topo)[0], "-C", *rule(self.topo)[2:]],
                allow_failure=True,
            ).exit_code
            == 0
        ):
            raise DockerBoundaryError("flow rule already present; refuse duplicate")
        self.runtime.exec(identifier, rule(self.topo))
        self.runtime.exec(
            identifier,
            ["/bin/sh", "-c", f"printf 'installed\\n' > {RULE_MARKER}"],
        )

    def remove_rule(self) -> None:
        identifier = self._router()
        marker = self.runtime.exec(
            identifier,
            ["/opt/bin/busybox", "cat", RULE_MARKER],
            allow_failure=True,
        )
        if marker.exit_code or marker.stdout != b"installed\n":
            raise DockerBoundaryError("no owned flow rule marker; refuse deletion")
        self.runtime.exec(identifier, rule(self.topo, delete=True))
        self.runtime.exec(identifier, ["/opt/bin/busybox", "rm", "-f", RULE_MARKER])
