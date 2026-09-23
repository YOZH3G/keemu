# Progress

## Current phase

P0 technical-risk experiments are in progress on branch `agent/keemu`.

## Verified work

The first locked AArch64 artifact and execution slice is implemented:

- Entware `aarch64-3.10` package index captured from `https://bin.entware.net/aarch64-k3.10/Packages.gz`.
- Twenty packages in the `entware-opt`, `busybox`, and `ca-bundle` dependency closure downloaded and verified against upstream SHA-256 values.
- Standalone target `opkg`, installer, configuration, QEMU 10.0.13, PRoot 5.1.0, and libtalloc inputs recorded with actual hashes in `locks/p0-aarch64.json`.
- Real target `opkg` installed the locked local packages into an AArch64 rootfs.
- Target BusyBox shell, target `opkg`, nested AArch64 BusyBox execution, and a target-shebang script passed through direct QEMU/PRoot diagnostic execution.
- Current `RunReport` schema version 2 covers run, artifact, scenario, profile, runtime, capability, substitution, coverage, operation-log, and partial-failure metadata with strict frozen models.
- Report validation rejects forged aggregate status, inconsistent coverage, non-contiguous operation logs, and partial failures whose referenced operation sequence is missing or disagrees on operation name or failure status.
- Failed-run bundles preserve JSON, Markdown, and JSONL operation records and atomically publish to a new immutable run directory with Linux `renameat2(..., RENAME_NOREPLACE)`; existing entries survive, and unavailable no-replace support fails closed.
- Portable tests after p0-04: 30 passed, 1 Docker-independent diagnostic integration test skipped by default.
- P0 diagnostic integration: 1 passed when explicitly enabled.
- Ruff: clean.
- Project-owned hello, web-demo, and NFQUEUE-consumer sources compiled into AArch64 ELF64/little-endian binaries with a 12-artifact Debian cross-toolchain lock; source, recipe, toolchain, dependency, and output hashes are in `locks/p0-fixtures-aarch64.json`.
- P0-04 built and inspected `keemu/p0-aarch64:mixed-v1` on Docker Engine 29.7.2. The `linux/amd64` image has a static amd64 `__keemu/init` entrypoint, an AArch64 Entware shell/opkg/rootfs from the verified 20-package closure, explicit image ownership/target/provenance labels, and an unexecuted bounded container-create template. A saved-layer audit found 28 AArch64 ELFs and one amd64 ELF (the init), with no foreign application ELF. Exact daemon image ID, exported layer/config hashes, and audit are in `locks/p0-mixed-image-aarch64.json`.

Evidence report:

- `reports/20260922T080151Z-p0diag-61f167a83d33/report.json`
- `reports/20260922T080151Z-p0diag-61f167a83d33/report.md`

Reports and the saved image archive `.runtime/p0/mixed-image.tar` are runtime artifacts excluded from Git. Committed reproducibility anchors are `locks/p0-aarch64.json`, `locks/p0-fixtures-aarch64.json`, and `locks/p0-mixed-image-aarch64.json`.

## Acceptance status

No acceptance ID A01–A21 is complete. A21 has report primitives but no full acceptance run. A01 has partial image and diagnostic evidence on AArch64, but target execution in Docker, host binfmt, MIPS, and MIPSEL are not verified. A18/A20 have only image labels and a static container-create template; no runtime recovery or isolation proof.

## Blockers

Docker Engine 29.7.2 is reachable. Host binfmt changes remain outside the approved p0-04 scope. Container execution, publish, down/up persistence, isolation inspection, and NFQUEUE/native-control experiments have not run and belong to later subtasks.

## Next concrete operation

Stop at the p0-04 boundary. The next worker (p0-05) must independently verify the locked mixed image and obtain approval before any host binfmt change; it must not infer target runtime success from this image audit.

## Cleanup

Downloaded artifacts, rootfs data, and saved OCI image are under `.runtime/p0/`. Diagnostic evidence is under `reports/`. One KEEMU-owned image was created; no container, network, firewall rule, binfmt registration, kernel module, or public port was created by p0-04. Foreign Docker resources were retained.
