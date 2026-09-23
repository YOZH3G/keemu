# Progress

## Current phase

P0 technical-risk experiments are complete on branch `agent/keemu`. MVP 1A subtasks m1a-09 through m1a-12 add versioned input schemas, bounded static IPK inspection, a locked AArch64 base-init/cache and an owned Docker runtime boundary. No scenario lifecycle or full MVP 1A acceptance is claimed.

## P0 verified results

- Locked Entware AArch64 rootfs inputs, package closure, cross-toolchain, project fixture sources, mixed runtime images, web-demo image, and host-observer image have committed lock records with SHA-256 values.
- Real Docker/binfmt AArch64 execution passed target `/bin/sh`, real `opkg`, nested AArch64 ELF, and executable target shebang. The derived P0-05 init also passed bounded daemon adoption, child reaping, signal forwarding, and owner-only cleanup.
- Real P0-06 execution passed explicit `127.0.0.1:18080→8080/tcp` and `127.0.0.1:18081→8081/udp` Docker publishing, host-vantage HTTP/UDP observation, state write, service restart, Docker stop/start persistence, and verified cleanup.
- P0-07 produced a bounded NFQUEUE BLOCKED diagnosis. Native NFNETLINK socket creation succeeded while equivalent static AArch64 creation returned `EPROTONOSUPPORT`; no queue bind, rule, verdict, packet, kernel-module load, or host-network topology was attempted.
- The report model is schema version 2 with immutable metadata and atomic write-once JSON/Markdown/JSONL bundles. The P0 baseline portable suite passed 30 tests with 3 skipped; schema-slice results are recorded below.

## MVP 1A schema slice

Schema-version-1 scenario, production lock and persistent-environment models and generated JSON schemas are implemented. Tests cover duplicate keys, unknown fields/versions, pinned-installer contracts, explicit localhost publish and vantage, CA-backed HTTPS, safe project-relative inputs, symlinks, source/scenario hashes, environment ownership metadata and parser bounds. Static `inspect` validates bounded IPK archive structure, metadata, target architecture/ELF, interpreters, dependencies, shebangs and permissions without extraction or host `ldd`. The selected locked AArch64 feed's 20 IPKs were inspected read-only. This does not install a package, execute a target app, mutate the registry, or prove the full A01/A02 gates; uncertain dependency/loader paths remain BLOCKED until complete target-state proof.

## MVP 1A locked base init slice

`keemu init --profile generic-aarch64 --locked` verified all 20 real local IPKs, index, bootstrap, QEMU and native-init inputs; installed the closure with target opkg; checked exact inventory and default feed config; normalized volatile installed times; built and audited a scratch mixed-architecture image; and published an atomic, hash-bound cache. Two independent builds yielded the same rootfs tree, saved archive and Docker-local image ID `sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224`. `--offline` revalidated the prepared cache and image without fetch or build. Bounded Docker/binfmt target shell, opkg list-installed, nested ELF and bridge DNS passed; HTTPS passed only from the Hermes process network namespace with CA validation, not inside target. An opt-in integration suite exercised real Docker smoke and corruption rejection; no owned container remained. This is AArch64 base preparation, not fixture installation or full A01/A19 acceptance.

## MVP 1A Docker runtime boundary slice

`src/keemu/docker_runtime.py` now creates project/run/base/target-labeled containers and isolated project bridge networks using argv-only Docker calls, a verified immutable local image ID, 2 CPU/1 GiB/256 PID bounds, no privilege/host namespaces/binds/socket, and capped daemon/retrieval logs. Full-ID, re-inspected ownership gates every mutation; read-only reconciliation reports owned, missing and unexpected resources. A 512 MiB observed writable-layer threshold stops the owned container on checks; it is not a continuous disk quota. Opt-in live Docker test passed the target shell write/read, stop/start persistence, clean new container layer, foreign-run deletion refusal, and readback/absence after owner-verified cleanup. Evidence `reports/m1a12-8055e7faa94b-docker-boundary.json` has SHA-256 `d56d3e156876a139c970fda7b72259dc150a1317d8649fa2cabbba7fdf240bf4`; 97 portable tests passed with 11 opt-in skips, 9 focused portable/live tests passed. There is still no application lifecycle, atomic registry, interruption injection, hard disk quota or full A18/A20 acceptance. See ADR-0006.

## Evidence package

`docs/evidence/p0-evidence-manifest.md` binds the committed locks and ignored runtime reports to their independently recomputed SHA-256 digests. ADR-0001 through ADR-0005 record the diagnostic runtime, mixed image, native-init correction, NFQUEUE blocker, and constrained localhost-observer decision.

## Acceptance status

P0 is complete as a technical-risk gate. A07–A09 pass only for the exact P0 AArch64 web-demo slice. A13/A14/A17 are BLOCKED, not PASS. A01, A18, A19, A20, and A21 remain PARTIAL; all remaining acceptance statuses and gaps are in `docs/traceability.md`. MVP 1A, MVP 1B, MVP 1C, and MVP 1 are not complete.

## Cleanup and retained state

Runtime reports and saved images remain ignored under `reports/` and `.runtime/`; committed lock digests permit retention verification. P0 probes, m1a-11 smoke and m1a-12 runtime test removed their project-owned containers after owner/run-id checks; m1a-12 also removed its project network. Final Docker owner-label queries returned no KEEMU container or network. The approved single `qemu-aarch64` host binfmt entry remains registered; no public port or foreign Docker resource was changed by m1a-12. Docker-managed bridge setup/teardown may transiently alter host networking rules; no direct host firewall/binfmt/module operation was attempted.
