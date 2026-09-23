# Progress

## Current phase

P0 technical-risk experiments are complete on branch `agent/keemu`. The next frozen subtask is MVP 1A work; no MVP 1A implementation is claimed here.

## P0 verified results

- Locked Entware AArch64 rootfs inputs, package closure, cross-toolchain, project fixture sources, mixed runtime images, web-demo image, and host-observer image have committed lock records with SHA-256 values.
- Real Docker/binfmt AArch64 execution passed target `/bin/sh`, real `opkg`, nested AArch64 ELF, and executable target shebang. The derived P0-05 init also passed bounded daemon adoption, child reaping, signal forwarding, and owner-only cleanup.
- Real P0-06 execution passed explicit `127.0.0.1:18080→8080/tcp` and `127.0.0.1:18081→8081/udp` Docker publishing, host-vantage HTTP/UDP observation, state write, service restart, Docker stop/start persistence, and verified cleanup.
- P0-07 produced a bounded NFQUEUE BLOCKED diagnosis. Native NFNETLINK socket creation succeeded while equivalent static AArch64 creation returned `EPROTONOSUPPORT`; no queue bind, rule, verdict, packet, kernel-module load, or host-network topology was attempted.
- The report model is schema version 2 with immutable metadata and atomic write-once JSON/Markdown/JSONL bundles. Current portable verification passes: 30 passed, 3 skipped; Ruff and whitespace checks pass.

## Evidence package

`docs/evidence/p0-evidence-manifest.md` binds the committed locks and ignored runtime reports to their independently recomputed SHA-256 digests. ADR-0001 through ADR-0005 record the diagnostic runtime, mixed image, native-init correction, NFQUEUE blocker, and constrained localhost-observer decision.

## Acceptance status

P0 is complete as a technical-risk gate. A07–A09 pass only for the exact P0 AArch64 web-demo slice. A13/A14/A17 are BLOCKED, not PASS. A01, A18, A19, A20, and A21 remain PARTIAL; all remaining acceptance statuses and gaps are in `docs/traceability.md`. MVP 1A, MVP 1B, MVP 1C, and MVP 1 are not complete.

## Cleanup and retained state

Runtime reports and saved images remain ignored under `reports/` and `.runtime/p0/`; their manifest digests permit retention verification. P0 probes removed their project-owned containers after owner/run-id checks. The approved single `qemu-aarch64` host binfmt entry remains registered; no public port, firewall rule, kernel module, or foreign Docker resource was changed.
