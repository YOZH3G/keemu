# Limitations

## Current verified boundary

An AArch64 direct-QEMU/PRoot diagnostic and Docker/binfmt target execution are verified. The first Docker probe failed before binfmt activation; a later approved single-architecture registration enabled real target execution. A derived, separately locked image corrected the original native init's signal bug. See `docs/decisions/0003-p0-init-signal.md`.

## Known limitations

- Docker Engine 29.7.2 is reachable; its socket is privileged host access. The approved host `qemu-aarch64` binfmt registration was independently read back with interpreter `/usr/bin/qemu-aarch64` and flags `POCF`. The Hermes container's local binfmt procfs is unmounted, so current registration must be revalidated on host changes. No privileged target container or public port was used.
- Original P0-04 native init inherited signal handlers in its keeper and failed a keeper-death differential (retained FAIL evidence). P0-05 preserves that image and layers a separately locked static native init correction. The derived image passed actual target shell/opkg/child/shebang execution, adopted daemon and short-orphan reaping, SIGTERM stop/0, keeper-death/1 and PID 1 SIGINT/0; exact report is `reports/20260923T080109Z-p005-e6653acf4ef7/probe.json`. Three containers in the successful probe were removed with verified owner/run-id labels, and Docker and foreign containers survived. The direct shebang test used an explicitly executable disposable `/tmp` tmpfs because the baseline noexec tmpfs cannot execute test files.
- Full interruption recovery, localhost publishing, down/up persistence and complete isolation remain untested. OCI images cannot enforce per-container CPU/memory/PID limits; the p0-05 probe inspected applied nonprivileged/network-none/memory/PID settings, not the entire security envelope.
- Project-owned AArch64 hello, web-demo, and NFQUEUE-consumer sources compile from a locked cross-toolchain, but no fixture IPK, service lifecycle, web publish, HTTPS/UDP endpoint, or persistence experiment has run.
- NFQUEUE source uses the locked Linux UAPI headers, but NFQUEUE kernel support, iptables backend, ipset, conntrack, forwarding, raw sockets, routing topology, packet counters, and native control are untested.
- MIPS and MIPSEL artifacts and execution are untested.
- IPK archive safety analysis, lifecycle scripts, scenario execution, matrices, NDM fixtures, event contracts, persistent registry, filesystem diff, and full acceptance runs are not implemented. Common `RunReport` schema version 2 metadata and failed-run bundle primitives exist, but most runtime producers do not yet populate them.
- PRoot is not treated as a security or container isolation boundary.
- A generic AArch64 diagnostic does not establish compatibility with any Keenetic device model or KeeneticOS release.

## Truthfulness rule

None of these missing checks is a PASS. P0 and acceptance IDs A01–A21 remain incomplete until their required environments and evidence exist.
