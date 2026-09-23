# Limitations

## Current verified boundary

An AArch64 direct-QEMU/PRoot diagnostic and a Docker-built mixed image are verified. P0-05 ran two short-lived, project-owned native-init containers; target shell execution inside Docker failed with `exec format error`, so the target/binfmt runtime is not verified.

## Known limitations

- Docker Engine 29.7.2 is reachable in the current execution environment; its access is privileged host access. P0-05 created and cleaned only two labeled, project-owned probe containers; no privileged target container or public port was used.
- A working AArch64 host binfmt setup is absent for Docker target execution: `/bin/sh` returned exit 255 with `exec /bin/sh: exec format error`. The Hermes container's binfmt procfs is not mounted, so the exact Docker host registration cannot be determined by reading this container's procfs. No host binfmt setting was modified.
- Image metadata, native static init ELF, target ELF inventory, and image ownership labels are verified by inspect and saved-layer audit. Runtime inspection verified the native init remained running after the failed target exec; `docker stop` produced an exited container with code 0 and owner-checked cleanup removed it. Signal forwarding and orphan reaping, localhost publishing, down/up persistence, interruption recovery, and full isolation remain untested. OCI images cannot enforce per-container CPU/memory/PID limits; one p0-05 container's applied memory/PID/nonprivileged/network-none settings were inspected, not the complete security envelope.
- Project-owned AArch64 hello, web-demo, and NFQUEUE-consumer sources compile from a locked cross-toolchain, but no fixture IPK, service lifecycle, web publish, HTTPS/UDP endpoint, or persistence experiment has run.
- NFQUEUE source uses the locked Linux UAPI headers, but NFQUEUE kernel support, iptables backend, ipset, conntrack, forwarding, raw sockets, routing topology, packet counters, and native control are untested.
- MIPS and MIPSEL artifacts and execution are untested.
- IPK archive safety analysis, lifecycle scripts, scenario execution, matrices, NDM fixtures, event contracts, persistent registry, filesystem diff, and full acceptance runs are not implemented. Common `RunReport` schema version 2 metadata and failed-run bundle primitives exist, but most runtime producers do not yet populate them.
- PRoot is not treated as a security or container isolation boundary.
- A generic AArch64 diagnostic does not establish compatibility with any Keenetic device model or KeeneticOS release.

## Truthfulness rule

None of these missing checks is a PASS. P0 and acceptance IDs A01–A21 remain incomplete until their required environments and evidence exist.
