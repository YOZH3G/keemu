# Agent memory

- KEEMU is implemented in `/opt/data/workspace/keemu`; `/opt/data/hermes-projects/keemu` is only a compatibility symlink.
- `KEEMU_MVP1_updated.md` revision 2.2 is the authoritative specification.
- Development proceeds by vertical gates P0 → 1A → 1B → 1C and uses acceptance IDs A01–A21.
- A successful generic target test does not prove compatibility with a physical Keenetic model.
- The current Hermes container has no usable Docker daemon socket; Docker integration evidence requires a separate approved runner or host if this remains true.
- No Git remote was configured when the durable stack was activated.
- The first P0 lock is `locks/p0-aarch64.json`: 20 Entware `aarch64-3.10` packages plus hashed bootstrap and diagnostic tooling.
- Direct QEMU 10.0.13 with PRoot 5.1.0 can execute the locked AArch64 shell, real opkg, nested target ELF and target-shebang smoke test; this is diagnostic evidence only and does not satisfy A01 or P0.
- Generated runtime artifacts live under `.runtime/`; generated reports live under `reports/`; both are excluded from Git.
- `profiles/generic/generic-aarch64.yaml` is the strict current generic profile; `schemas/generic-profile.schema.json` is generated from `GenericProfile` and parity-tested.
- `keemu doctor` emits current schema-version-2 `RunReport` JSON and returns BLOCKED/exit 4 when the required Docker socket is unavailable; Docker, binfmt, and QEMU checks remain real-mode host evidence.
- Run reports use frozen nested metadata and derived status/coverage validation. Partial failures reference an exact operation-log sequence whose operation name and failure status must match. `write_report_bundle` atomically creates a new immutable run directory containing `report.json`, `report.md`, and `operation-log.jsonl`; existing directories are never overwritten.
- Future Luna/Sol assignments use `gpt-6-luna`/`gpt-6-sol`; historical attested events retain actual pre-refresh model IDs. Active p0-03 remains locked to `gpt-5.6-terra` / `high`; updated model IDs require runtime attestation at their new-worker boundary.
- `locks/p0-fixtures-aarch64.json` locks the project-owned AArch64 hello, web-demo and raw NFQUEUE-consumer fixture sources/recipes plus a 12-DEB Debian cross-toolchain; `keemu p0 verify-fixture-lock --verify-external` validates their hashes without network access.
