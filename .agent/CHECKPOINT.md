# Agent checkpoint

## Current status

P0 technical-risk work is in progress. A locked AArch64 Entware artifact set and direct-QEMU/PRoot diagnostic vertical slice are implemented and verified. The p0-01 profile/doctor slice, p0-02 immutable report-metadata and failed-run bundle primitives, and p0-03 reproducible fixture-source slice are implemented and verified. The P0 gate is not complete because mandatory Docker, localhost web publishing, persistence, binfmt, and NFQUEUE/native-control experiments have not run.

## Verified

- Active branch is `agent/keemu`; the authoritative specification remains unchanged.
- Durable supervisor/router validation passes all 52 tests when run from `/opt/data/hermes-durable-vps-hostinger-router-v1`.
- p0-02 completed with supervisor attestation for `gpt-5.6-sol` / `high`; its disposable worker session was deleted. The active p0-03 boundary is paused before launch for a model-policy refresh.
- Graphify index contains 90 nodes and 86 edges; its query confirmed that the repository initially contained specifications/control files but no product implementation.
- Docker CLI 26.1.5 is present, but `/var/run/docker.sock` is absent and the daemon is unreachable.
- Public artifact access works; no host firewall, binfmt, kernel module, service, public port, OAuth state, credential, or deploy key was changed.
- `locks/p0-aarch64.json` records 20 real Entware package artifacts plus bootstrap and diagnostic tooling with SHA-256 values derived from downloaded files.
- `uv sync --python 3.12` created a project-local environment using CPython 3.12.13 and generated `uv.lock`.
- `uv run keemu p0 verify-lock --lock locks/p0-aarch64.json --cache .runtime/p0/aarch64-k3.10/packages` verified all 20 packages.
- Direct QEMU/PRoot diagnostic verified target shell, real target `opkg`, nested target ELF execution, target shebang execution, and reported `aarch64`.
- Diagnostic evidence exists at `reports/20260922T080151Z-p0diag-61f167a83d33/` and is correctly excluded from Git.
- `uv run ruff check .` passes.
- Generic AArch64 profile YAML is strict, rejects duplicate keys and target/CPU mismatches, and its committed JSON schema equals `GenericProfile.model_json_schema()`.
- `keemu doctor` builds the common strict `RunReport`; report aggregation implements required-SKIP → BLOCKED and priority ERROR → FAIL → BLOCKED → WARN → PASS. Markdown and JSON use the same report object.
- `keemu doctor --profile generic-aarch64` produced a schema-valid real-mode `BLOCKED` report and exit 4 because `/var/run/docker.sock` is unavailable; no capability was claimed as PASS without evidence.
- Report-status exit codes are centralized: FAIL=1, ERROR=3, BLOCKED=4, PASS/WARN=0. Invalid doctor profile input exits 2.
- Portable suite: 16 passed, 1 diagnostic test skipped by default. `uv run ruff check .` passes.
- The coherent p0-01 implementation and durable state were committed as `573a2df` (`feat: add P0 doctor and report primitives`).
- Strict frozen A21 metadata models cover artifacts, scenarios, profile revision/hash, runtime provenance, capability results, substitutions, coverage, operation records, checks, and partial failures.
- Current `RunReport` schema version 2 validation rejects inconsistent aggregate status or coverage, non-contiguous operation sequences, and partial failures whose referenced operation sequence is missing or disagrees on operation name or failure status.
- Report bundles atomically publish `report.json`, `report.md`, and `operation-log.jsonl` with Linux `renameat2(..., RENAME_NOREPLACE)`; existing directories/files/symlinks survive races, unavailable no-replace support fails closed, and failed-run tests verify all three artifacts survive with cleanup metadata.
- The committed `schemas/run-report.schema.json` matches the expanded schema-version-2 model.
- Real `keemu doctor --profile generic-aarch64` remains truthfully BLOCKED/exit 4 and now includes profile hash/revision, host kernel, Entware target, Python runtime version, and six explicit capability results.
- Portable suite: 25 passed, 1 diagnostic test skipped by default. `uv run ruff check .` passes.
- Final independent staged-diff review found no remaining security concern or blocking logic error after two TDD fix cycles.
- The coherent p0-02 implementation and durable state are committed as `e4d2ad2` (`[verified] feat: expand A21 report metadata primitives`).
- `locks/p0-fixtures-aarch64.json` records a real 12-artifact Debian trixie AArch64 cross-toolchain, project-owned hello/web-demo/NFQUEUE-consumer source and recipe hashes, AArch64 ELF metadata, runtime dependencies, kernel requirements, and reproducibly rebuilt output hashes.
- Rebuilding the three fixture sources with the extracted locked toolchain reproduced their recorded SHA-256 values: hello `334fd4454f3cdbcc4556704dec766e66426e9a75876c1f1f27e6d5fd3156955c`, web-demo `aa45036ae479cc1901492d64d534d72789d48e1e419897ee51ae91d413ffd10b`, and NFQUEUE consumer `0d5a85fabecd3754633fa513712a1cc7b2be2871fd31a9d08c58ae68a15b3886`; `readelf` confirmed ELF64/little-endian/AArch64 for all three.
- `keemu p0 verify-fixture-lock --lock locks/p0-fixtures-aarch64.json --root . --verify-external` verified all sources, recipes, and staged toolchain artifacts. Portable suite: 28 passed, 1 skipped; `uv run ruff check .` passes.

## Acceptance truth

- A01: PARTIAL diagnostic evidence on AArch64 only; not PASS.
- A19: PARTIAL supporting evidence only; not PASS.
- A21: PARTIAL supporting evidence now includes schema-valid doctor JSON, Markdown generated from the same common model, immutable metadata, parity and consistency validation, atomic write-once bundles, JSONL operation records, and failed-run artifact coverage. Full lifecycle reports and complete runtime provenance remain later work.
- All other A02–A18 and A20 requirements are NOT RUN or BLOCKED as mapped in `docs/traceability.md`.
- No TASK.md gate is complete.

## Next operation

The p0-03 technical deliverable is ready for commit, but supervisor outcome completion remains blocked by its earlier runtime model-attestation failure (`.agent/STATE.json`). Do not advance to p0-04 until the durable supervisor records a valid p0-03 attestation and session lifecycle. On an approved Docker-capable Linux host, then resume P0 with the locked mixed-image runtime, localhost web-demo publish, down/up persistence, and NFQUEUE/native-control experiments in that order.

## Blockers

Mandatory Docker-backed P0 evidence cannot be produced in the current Hermes container because no Docker daemon socket is available. Host binfmt changes require explicit human approval and were not attempted. Independent portable implementation work remains possible.
