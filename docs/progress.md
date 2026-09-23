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
- Portable tests after p0-05: 30 passed, 2 opt-in integration tests skipped by default; explicit Docker/binfmt probe passed separately.
- P0 diagnostic integration: 1 passed when explicitly enabled.
- Ruff: clean.
- Project-owned hello, web-demo, and NFQUEUE-consumer sources compiled into AArch64 ELF64/little-endian binaries with a 12-artifact Debian cross-toolchain lock; source, recipe, toolchain, dependency, and output hashes are in `locks/p0-fixtures-aarch64.json`.
- P0-04 built and inspected `keemu/p0-aarch64:mixed-v1` on Docker Engine 29.7.2. The `linux/amd64` image has a static amd64 `__keemu/init` entrypoint, an AArch64 Entware shell/opkg/rootfs from the verified 20-package closure, explicit image ownership/target/provenance labels, and an unexecuted bounded container-create template. A saved-layer audit found 28 AArch64 ELFs and one amd64 ELF (the init), with no foreign application ELF. Exact daemon image ID, exported layer/config hashes, and audit are in `locks/p0-mixed-image-aarch64.json`.
- P0-05 verified the locked image again, then created and started a project-owned, network-isolated nonprivileged container with inspected memory/PID create bounds; the create argv also requested a CPU bound, not independently inspected. Native init stayed running after an AArch64 `/bin/sh` exec failed (exit 255, `exec format error`). A five-second-grace `docker stop` returned exit code 0; owner/run-id-checked removal succeeded and the container was absent on independent inspect. Runtime evidence: `reports/20260923T060100Z-p005-cd7142bf3557/probe.json` (excluded from Git). No host binfmt registration was changed.
- After explicit approval, the Docker host received only a pinned `qemu-aarch64` binfmt registration; the host entry was independently read back as enabled, interpreter `/usr/bin/qemu-aarch64`, flags `POCF`. A first target runtime probe proved shell/opkg, nested BusyBox ELF, executable shebang, daemon survival, orphan reaping and clean SIGTERM shutdown. A differential then exposed an inherited-signal-handler bug in the original native keeper; the failed result is retained under `reports/20260923T075436Z-p005-303e5d4292e3/probe.json`.
- A separately locked derived P0-05 image fixes the keeper's signal dispositions and waits for its exact signaled exit, preserving the original P0-04 image and AArch64 rootfs. The derived image ID is `sha256:66efaedcbd42ac56db30122762ebf73bcfb41a17dd6404bf22f7af067047b6f6`; exact source, binary, layer and archive hashes are in `locks/p0-mixed-image-aarch64-p005.json`. The full bounded Docker/binfmt probe passed: shell, opkg, nested target ELF, direct shebang, adopted daemon, adopted short-child reaping, SIGTERM exit 0, unexpected keeper death exit 1, PID 1 SIGINT exit 0, verified owner-only removal of all three containers, and live Docker daemon afterward. Local runtime evidence: `reports/20260923T080109Z-p005-e6653acf4ef7/probe.json`. The disposable shebang-test container explicitly used executable `/tmp` tmpfs; baseline `/tmp` is noexec. See `docs/decisions/0003-p0-init-signal.md`.

Evidence report:

- `reports/20260922T080151Z-p0diag-61f167a83d33/report.json`
- `reports/20260922T080151Z-p0diag-61f167a83d33/report.md`

Reports and the saved image archive `.runtime/p0/mixed-image.tar` are runtime artifacts excluded from Git. Committed reproducibility anchors are `locks/p0-aarch64.json`, `locks/p0-fixtures-aarch64.json`, and `locks/p0-mixed-image-aarch64.json`.

## Acceptance status

No acceptance ID A01–A21 is complete. A21 has report primitives but no full acceptance run. A01 now has real Docker/binfmt nested execution on AArch64, but MIPS/MIPSEL remain unverified. A18 has bounded native-init signal/reap and clean owner-verified shutdown evidence, not full interruption recovery. A20 has limited applied container configuration evidence, not full isolation proof. P0 still requires later web publishing/persistence and NFQUEUE experiments.

## Blockers

Docker Engine 29.7.2 and the approved single AArch64 binfmt entry are verified on this host; recheck after a reboot or runner change. Publishing, down/up persistence, complete isolation, and NFQUEUE/native-control experiments have not run and belong to later subtasks.

## Next concrete operation

P0-05 implementation and bounded Docker/binfmt verification are complete. Commit the coherent evidence and source slice and return only its exact completion marker; the supervisor is configured to pause before launching p0-06.

## Cleanup

Downloaded artifacts, rootfs data, and both saved OCI images are under `.runtime/p0/`. Probe evidence is under `reports/`. Two KEEMU-owned images exist; all short-lived KEEMU-owned probe containers were removed after label/run-id checks. The approved single `qemu-aarch64` host binfmt entry remains registered; no network, firewall rule, kernel module, public port, or foreign Docker resource was changed.
