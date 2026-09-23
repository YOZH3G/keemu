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
- Portable tests: 25 passed, 1 Docker-independent diagnostic integration test skipped by default.
- P0 diagnostic integration: 1 passed when explicitly enabled.
- Ruff: clean.
- Project-owned hello, web-demo, and NFQUEUE-consumer sources compiled into AArch64 ELF64/little-endian binaries with a 12-artifact Debian cross-toolchain lock; source, recipe, toolchain, dependency, and output hashes are in `locks/p0-fixtures-aarch64.json`.

Evidence report:

- `reports/20260922T080151Z-p0diag-61f167a83d33/report.json`
- `reports/20260922T080151Z-p0diag-61f167a83d33/report.md`

Reports are runtime artifacts and are intentionally excluded from Git. Committed reproducibility anchors are `locks/p0-aarch64.json` and `locks/p0-fixtures-aarch64.json`.

## Acceptance status

No acceptance ID A01–A21 is complete. A21 now has verified report-schema, derived-status, immutable-publication, operation-log, and failed-run metadata primitives, but no full acceptance run exists. The diagnostic supports part of A01 on AArch64 but does not use the required Docker runtime, does not prove host binfmt operation, and does not cover MIPS or MIPSEL.

## Blockers

The current Hermes container has Docker CLI 26.1.5 but no `/var/run/docker.sock`; `docker info` cannot connect to a daemon. Host binfmt entries for target architectures are absent. Mandatory Docker publish, down/up persistence, isolation inspection, and NFQUEUE/native-control experiments cannot run here.

## Next concrete operation

Proceed only to the next supervised P0 subtask. When an approved Docker-capable Linux host is available, run the locked AArch64 rootfs in the specified mixed image, then verify localhost web publishing and persistence before the NFQUEUE experiment.

## Cleanup

Downloaded artifacts and generated rootfs data are under `.runtime/p0/`. Generated diagnostic evidence is under `reports/`. No container, network, firewall rule, binfmt registration, kernel module, or public port was created by this slice.
