# Agent checkpoint

## Current status

P0 technical-risk work is in progress. A locked AArch64 Entware artifact set and direct-QEMU/PRoot diagnostic vertical slice are implemented and verified. The P0 gate is not complete because mandatory Docker, localhost web publishing, persistence, binfmt, and NFQUEUE/native-control experiments have not run.

## Verified

- Active branch is `agent/keemu`; the authoritative specification remains unchanged.
- Durable supervisor/router validation passes all 52 tests when run from `/opt/data/hermes-durable-vps-hostinger-router-v1`.
- The worker command explicitly selected `gpt-5.6-sol` with reasoning `xhigh`; supervisor attestation remains pending until terminal worker completion.
- Graphify index contains 90 nodes and 86 edges; its query confirmed that the repository initially contained specifications/control files but no product implementation.
- Docker CLI 26.1.5 is present, but `/var/run/docker.sock` is absent and the daemon is unreachable.
- Public artifact access works; no host firewall, binfmt, kernel module, service, public port, OAuth state, credential, or deploy key was changed.
- `locks/p0-aarch64.json` records 20 real Entware package artifacts plus bootstrap and diagnostic tooling with SHA-256 values derived from downloaded files.
- `uv sync --python 3.12` created a project-local environment using CPython 3.12.13 and generated `uv.lock`.
- `uv run keemu p0 verify-lock --lock locks/p0-aarch64.json --cache .runtime/p0/aarch64-k3.10/packages` verified all 20 packages.
- Direct QEMU/PRoot diagnostic verified target shell, real target `opkg`, nested target ELF execution, target shebang execution, and reported `aarch64`.
- Diagnostic evidence exists at `reports/20260922T080151Z-p0diag-61f167a83d33/` and is correctly excluded from Git.
- `uv run ruff check .` passes.
- Portable suite: 5 passed, 1 diagnostic test skipped by default.
- Explicit P0 diagnostic integration: 1 passed.

## Acceptance truth

- A01: PARTIAL diagnostic evidence on AArch64 only; not PASS.
- A19 and A21: PARTIAL supporting evidence only; not PASS.
- All other A02–A18 and A20 requirements are NOT RUN or BLOCKED as mapped in `docs/traceability.md`.
- No TASK.md gate is complete.

## Next operation

Commit the coherent P0 diagnostic slice after diff/secret review. Then implement the read-only `doctor` command and portable schema/report primitives while keeping P0 incomplete. On an approved Docker-capable Linux host, resume P0 with the locked mixed-image runtime, localhost web-demo publish, down/up persistence, and NFQUEUE/native-control experiments in that order.

## Blockers

Mandatory Docker-backed P0 evidence cannot be produced in the current Hermes container because no Docker daemon socket is available. Host binfmt changes require explicit human approval and were not attempted. Independent portable implementation work remains possible.
