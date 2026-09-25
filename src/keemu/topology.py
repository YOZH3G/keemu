"""Disposable, owner-checked client/router/server Docker topology.

No management network is attached. Docker exec by verified ID is the sole control
plane; this module does not publish ports, add NAT or touch host firewall rules.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from keemu.docker_runtime import DockerBoundaryError, DockerRuntime, _json

POOL = ipaddress.IPv4Network("10.224.0.0/12")
BUSYBOX = "/opt/bin/busybox"


@dataclass(frozen=True)
class Topology:
    run_id: str
    lan: str
    wan: str
    networks: dict[str, str]
    containers: dict[str, str]


def _name(run_id: str, role: str) -> str:
    suffix = hashlib.sha256(run_id.encode()).hexdigest()[:20]
    return f"keemu-top-{suffix}-{role}"


@contextmanager
def _lock(root: Path) -> Iterator[None]:
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise DockerBoundaryError("topology lock root is a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise DockerBoundaryError("topology lock root is not private")
    fd = os.open(
        root / "allocation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        if os.fstat(fd).st_mode & 0o077:
            raise DockerBoundaryError("topology lock is not private")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _occupied() -> list[ipaddress.IPv4Network]:
    """Refuse unknown IPAM; Docker rejects concurrent overlapping create too."""
    ids = DockerRuntime.listed_ids("network")
    networks = []
    for identifier in sorted(ids):
        data = _json(["docker", "network", "inspect", "--", identifier])
        if (
            not isinstance(data, list)
            or len(data) != 1
            or data[0].get("Id") != identifier
        ):
            raise DockerBoundaryError("network inventory changed during allocation")
        for entry in (data[0].get("IPAM") or {}).get("Config") or []:
            subnet = entry.get("Subnet")
            if subnet:
                try:
                    networks.append(ipaddress.ip_network(subnet, strict=False))
                except ValueError as exc:
                    raise DockerBoundaryError("invalid existing Docker subnet") from exc
    # Worker-visible routes supplement Docker IPAM; host-vantage route coverage
    # is not asserted from a separate container namespace.
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            for line in list(routes)[1:]:
                fields = line.split()
                address = int.from_bytes(bytes.fromhex(fields[1]), "little")
                mask = int.from_bytes(bytes.fromhex(fields[7]), "little")
                if mask:
                    networks.append(
                        ipaddress.IPv4Network(
                            (address, str(ipaddress.IPv4Address(mask))), strict=False
                        )
                    )
    except (OSError, ValueError, IndexError) as exc:
        raise DockerBoundaryError("cannot inspect worker routes") from exc
    return networks


def _allocate() -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]:
    occupied = _occupied()
    selected = []
    for candidate in POOL.subnets(new_prefix=24):
        if all(not candidate.overlaps(used) for used in occupied):
            selected.append(candidate)
            occupied.append(candidate)
        if len(selected) == 2:
            return selected[0], selected[1]
    raise DockerBoundaryError("no collision-free topology subnets")


def _owned(runtime: DockerRuntime) -> tuple[dict[str, str], dict[str, str]]:
    state = runtime.reconcile()
    containers: dict[str, str] = {}
    networks: dict[str, str] = {}
    for kind, found in (("container", containers), ("network", networks)):
        for identifier in state[kind + "_owned"]:
            item = runtime.inspect(kind, identifier)
            name = item["Name"].lstrip("/")
            roles = (
                ("client", "router", "server")
                if kind == "container"
                else ("lan", "wan")
            )
            matches = [role for role in roles if name == _name(runtime.run_id, role)]
            if len(matches) != 1 or matches[0] in found:
                raise DockerBoundaryError(
                    "unexpected owned topology resource; refuse cleanup"
                )
            found[matches[0]] = identifier
    return containers, networks


def _cleanup_locked(runtime: DockerRuntime) -> None:
    containers, networks = _owned(runtime)
    for role in ("client", "router", "server"):
        if role in containers:
            runtime.remove_container(containers[role])
    for role in ("wan", "lan"):
        if role in networks:
            runtime.remove_network(networks[role])
    if any(runtime.reconcile()[kind + "_owned"] for kind in ("container", "network")):
        raise DockerBoundaryError("topology cleanup left owned resources")


def cleanup(
    run_id: str, image_id: str, *, root: Path = Path(".runtime/topology")
) -> None:
    """Idempotent explicit recovery, including an interrupted pre-ID allocation."""
    runtime = DockerRuntime(run_id, image_id)
    with _lock(root):
        _cleanup_locked(runtime)


def _check_endpoints(runtime: DockerRuntime, topo: Topology) -> None:
    expected = {
        "client": {topo.networks["lan"]},
        "router": set(topo.networks.values()),
        "server": {topo.networks["wan"]},
    }
    for role, identifier in topo.containers.items():
        item = runtime.inspect("container", identifier)
        actual = {v["NetworkID"] for v in item["NetworkSettings"]["Networks"].values()}
        if actual != expected[role] or item["HostConfig"].get("PortBindings"):
            raise DockerBoundaryError("management bypass or unexpected endpoint")
        host = item["HostConfig"]
        if (
            host.get("Privileged")
            or host.get("CapAdd") != ["NET_ADMIN"]
            or host.get("NetworkMode") == "host"
        ):
            raise DockerBoundaryError("topology capability/namespace mismatch")


def _target(runtime: DockerRuntime, identifier: str, *argv: str) -> str:
    result = runtime.exec(identifier, [BUSYBOX, *argv])
    return result.stdout.decode("utf-8", "replace")


def _interface(runtime: DockerRuntime, identifier: str, address: str) -> str:
    current = ""
    for line in _target(runtime, identifier, "ip", "addr").splitlines():
        match = re.match(r"\d+: (eth[0-9]+)(?:@[^:]+)?:", line)
        if match:
            current = match[1]
        if re.search(rf"\binet {re.escape(address)}/24\b", line):
            if not current:
                raise DockerBoundaryError("address on unexpected interface")
            return current
    raise DockerBoundaryError("Docker-assigned interface address missing")


def create(
    run_id: str, image_id: str, *, root: Path = Path(".runtime/topology")
) -> Topology:
    """Create two internal bridges and three bounded nodes; rollback on failure."""
    runtime = DockerRuntime(run_id, image_id)
    with _lock(root):
        if any(
            runtime.reconcile()[kind + "_owned"] for kind in ("container", "network")
        ):
            raise DockerBoundaryError("run already owns resources; recover explicitly")
        if not Path("/sys/module/bridge").is_dir():
            raise DockerBoundaryError(
                "bridge kernel support not loaded; no module load authorized"
            )
        runtime.image()
        try:
            lan, wan = _allocate()
            lans, wans = str(lan), str(wan)
            ids = {}
            for role, net in (("lan", lan), ("wan", wan)):
                ids[role] = runtime.create_network(
                    _name(run_id, role),
                    subnet=str(net),
                    gateway=str(net.network_address + 1),
                    internal=True,
                )
            containers = {
                "client": runtime.create(
                    _name(run_id, "client"),
                    network_id=ids["lan"],
                    network_ip=str(lan.network_address + 3),
                    net_admin=True,
                ),
                "router": runtime.create(
                    _name(run_id, "router"),
                    network_id=ids["lan"],
                    network_ip=str(lan.network_address + 2),
                    net_admin=True,
                    forwarding=True,
                ),
                "server": runtime.create(
                    _name(run_id, "server"),
                    network_id=ids["wan"],
                    network_ip=str(wan.network_address + 3),
                    net_admin=True,
                ),
            }
            runtime.connect(
                ids["wan"], containers["router"], str(wan.network_address + 2)
            )
            topo = Topology(run_id, lans, wans, ids, containers)
            for identifier in containers.values():
                runtime.start(identifier)
            _check_endpoints(runtime, topo)
            router = containers["router"]
            # Docker may reorder endpoints. Match addresses, not eth numbering.
            lan_if = _interface(runtime, router, str(lan.network_address + 2))
            if (
                _target(runtime, router, "ip", "addr", "show", "wan0").find(
                    f"inet {wan.network_address + 2}/24"
                )
                < 0
            ):
                raise DockerBoundaryError("Docker wan0 address missing")
            _target(
                runtime, router, "ip", "link", "add", "name", "br0", "type", "bridge"
            )
            _target(
                runtime,
                router,
                "ip",
                "addr",
                "del",
                f"{lan.network_address + 2}/24",
                "dev",
                lan_if,
            )
            _target(runtime, router, "ip", "link", "set", lan_if, "master", "br0")
            _target(
                runtime,
                router,
                "ip",
                "addr",
                "add",
                f"{lan.network_address + 2}/24",
                "dev",
                "br0",
            )
            _target(runtime, router, "ip", "link", "set", "br0", "up")

            _target(
                runtime,
                containers["client"],
                "ip",
                "route",
                "add",
                "default",
                "via",
                str(lan.network_address + 2),
            )
            _target(
                runtime,
                containers["server"],
                "ip",
                "route",
                "add",
                lans,
                "via",
                str(wan.network_address + 2),
            )
            _check_endpoints(runtime, topo)
            return topo
        except BaseException:
            try:
                _cleanup_locked(runtime)
            except Exception as cleanup_error:
                raise DockerBoundaryError(
                    f"topology creation failed; cleanup failed: {cleanup_error}"
                ) from cleanup_error
            raise
