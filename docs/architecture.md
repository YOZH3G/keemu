# Architecture

## Status

This document describes the implemented P0 diagnostic, report-foundation, and mixed-image build/inspect slices. Docker container execution and later MVP components remain unverified.

## Implemented components

- `src/keemu/entware.py` parses an Entware package index, resolves a dependency closure, creates lock data, and verifies cached artifacts by SHA-256.
- `src/keemu/p0.py` constructs an AArch64 diagnostic rootfs with the real target `opkg` under direct QEMU user-mode and runs nested target execution through unprivileged PRoot.
- `src/keemu/cli.py` exposes `keemu p0 verify-lock` for offline verification of the committed package lock.
- `locks/p0-aarch64.json` records the exact Entware package closure and diagnostic tool artifacts used by the first experiment.
- `fixtures/sources/` contains project-owned AArch64 hello, web-demo, and raw-NFQUEUE-consumer sources. `fixtures/recipes/aarch64/` compiles them with a staged, SHA-256-locked Debian cross toolchain. `locks/p0-fixtures-aarch64.json` records source, recipe, toolchain, dependency, architecture, and verified-output hashes; `keemu p0 verify-fixture-lock` validates those records without downloading.
- `src/keemu/models.py` defines current `RunReport` schema version 2 with strict, frozen metadata for checked artifacts, scenarios, profiles, runtime provenance, capabilities, substitutions, checks, coverage, operation records, and partial failures. Each partial failure references an exact operation-log sequence; validation requires the referenced record's operation name and failure status to match.
- `src/keemu/reports.py` derives aggregate status and coverage, rejects inconsistent report payloads, renders Markdown from the JSON source object, and atomically publishes immutable run bundles with a JSONL operation log using Linux `renameat2(..., RENAME_NOREPLACE)`.
- `src/keemu/doctor.py` emits the common report model with a canonical profile hash, profile revision, host kernel, Entware target, Python version, and explicit capability results. Uncollected OCI, QEMU, Git, feed-lock, and network-fidelity values remain `null` rather than being invented.
- `src/keemu/p0_image.py` rebuilds the locked AArch64 rootfs, compiles a static amd64 PID 1 from `fixtures/recipes/aarch64/keemu-init.c`, audits every rootfs ELF, and builds a scratch `linux/amd64` image with the target architecture in ownership/provenance labels. The content-addressed image ID, saved-layer hash, architecture inventory, and an unexecuted, bounded container-create template are recorded in `locks/p0-mixed-image-aarch64.json`.

## P0 diagnostic data flow

1. A committed lock names every package, version, URL, architecture, and expected SHA-256.
2. Downloaded artifacts remain under `.runtime/` and are never committed.
3. `verify_artifact_cache` rejects missing, unsafe, or hash-mismatched package files.
4. `build_diagnostic_rootfs` invokes the real AArch64 bootstrap `opkg` through QEMU with argv only and installs the locked local IPK files into a temporary rootfs.
5. The completed rootfs is atomically renamed into place. Failed construction removes the temporary directory.
6. `run_proot_smoke` uses a minimal environment and verifies target shell, target `opkg`, a nested target ELF, and a target-shebang script.

## Required production architecture not yet implemented

The accepted runtime remains Docker Engine on Linux x86_64. The first image is built and inspected, but PID 1 behavior, target execution through binfmt, container limits, and isolation are not yet runtime-verified. The future container-create argv specifies ownership labels, memory/CPU/PID limits, dropped capabilities, read-only rootfs, no-new-privileges, and no host network or Docker-socket mount. Persistent environments will be tracked by an atomic registry and reconciled against Docker labels in later subtasks.

The required network topology remains client/router/server in project-owned namespaces or internal Docker networks. No network implementation choice is accepted until a Docker-capable host can execute the P0 publish, persistence, routing, and NFQUEUE experiments.

## Trust boundaries

- Package input is untrusted. Hash verification precedes use; archive safety checks are still unimplemented.
- Commands are argv arrays. Shell execution is limited to an explicit trusted diagnostic script inside the target environment.
- The PRoot path is diagnostic only and is not a container isolation boundary.
- Reports and runtime state are generated outside Git; lock files, recipes, schemas, and tests belong in Git.
- Published report directories are write-once evidence: atomic no-replace publication preserves any existing destination entry and fails closed when the required Linux primitive is unavailable.
