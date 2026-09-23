# Limitations

## Current verified boundary

An AArch64 direct-QEMU/PRoot diagnostic and a Docker-built mixed image are verified. The image was only built, inspected and audited offline; it has not been run as a container.

## Known limitations

- Docker Engine 29.7.2 is reachable in the current execution environment; its access is privileged host access. Only the authorized project image build/inspect was performed.
- No target binfmt registration is present, and no host binfmt setting was modified.
- Image metadata, native static init ELF, target ELF inventory, and image ownership labels are verified by inspect and saved-layer audit. Native PID 1 behavior, child reaping, signal forwarding, container-applied resource limits and labels, mounts, localhost publishing, down/up persistence, and cleanup remain untested. OCI images cannot enforce per-container CPU/memory/PID limits; the recorded create template is not runtime evidence.
- Project-owned AArch64 hello, web-demo, and NFQUEUE-consumer sources compile from a locked cross-toolchain, but no fixture IPK, service lifecycle, web publish, HTTPS/UDP endpoint, or persistence experiment has run.
- NFQUEUE source uses the locked Linux UAPI headers, but NFQUEUE kernel support, iptables backend, ipset, conntrack, forwarding, raw sockets, routing topology, packet counters, and native control are untested.
- MIPS and MIPSEL artifacts and execution are untested.
- IPK archive safety analysis, lifecycle scripts, scenario execution, matrices, NDM fixtures, event contracts, persistent registry, filesystem diff, and full acceptance runs are not implemented. Common `RunReport` schema version 2 metadata and failed-run bundle primitives exist, but most runtime producers do not yet populate them.
- PRoot is not treated as a security or container isolation boundary.
- A generic AArch64 diagnostic does not establish compatibility with any Keenetic device model or KeeneticOS release.

## Truthfulness rule

None of these missing checks is a PASS. P0 and acceptance IDs A01–A21 remain incomplete until their required environments and evidence exist.
