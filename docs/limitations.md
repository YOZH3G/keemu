# Limitations

## Current verified boundary

The implemented result is an AArch64 direct-QEMU/PRoot diagnostic. It verifies real target binaries and locked Entware package content, but it is not the Docker runtime required by MVP 1.

## Known limitations

- Docker daemon access is unavailable in the current execution environment.
- No target binfmt registration is present, and no host binfmt setting was modified.
- Docker image metadata, native PID 1, child reaping, signal forwarding, resource limits, labels, mounts, localhost publishing, down/up persistence, and cleanup are untested.
- Project-owned AArch64 hello, web-demo, and NFQUEUE-consumer sources compile from a locked cross-toolchain, but no fixture IPK, service lifecycle, web publish, HTTPS/UDP endpoint, or persistence experiment has run.
- NFQUEUE source uses the locked Linux UAPI headers, but NFQUEUE kernel support, iptables backend, ipset, conntrack, forwarding, raw sockets, routing topology, packet counters, and native control are untested.
- MIPS and MIPSEL artifacts and execution are untested.
- IPK archive safety analysis, lifecycle scripts, scenario execution, matrices, NDM fixtures, event contracts, persistent registry, filesystem diff, and full acceptance runs are not implemented. Common `RunReport` schema version 2 metadata and failed-run bundle primitives exist, but most runtime producers do not yet populate them.
- PRoot is not treated as a security or container isolation boundary.
- A generic AArch64 diagnostic does not establish compatibility with any Keenetic device model or KeeneticOS release.

## Truthfulness rule

None of these missing checks is a PASS. P0 and acceptance IDs A01–A21 remain incomplete until their required environments and evidence exist.
