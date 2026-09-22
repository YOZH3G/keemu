# KEEMU

KEEMU is a reproducible verification harness for Entware applications. The authoritative scope and acceptance criteria are in `KEEMU_MVP1_updated.md` revision 2.2.

## Current status

Implementation is in the P0 technical-risk phase.

Verified in the current Debian container:

- the AArch64 Entware package index and 20-package bootstrap closure were downloaded and SHA-256 verified;
- the real AArch64 Entware `opkg` and BusyBox shell execute through QEMU user-mode;
- an unprivileged PRoot diagnostic executes shell → child AArch64 ELF → shell script with a target shebang;
- the committed lock records exact Entware artifacts and the diagnostic QEMU/PRoot inputs;
- current `RunReport` schema version 2 uses immutable metadata models for artifacts, scenarios, profiles, runtimes, capabilities, substitutions, checks, operation logs, coverage, and partial failures; each partial failure references one operation-log sequence whose operation name and failure status must match;
- report bundles use Linux `renameat2(..., RENAME_NOREPLACE)` to atomically publish `report.json`, `report.md`, and `operation-log.jsonl`; existing destination entries are preserved, and publication fails closed if the no-replace primitive is unavailable.

Not yet verified:

- Docker image/container execution, binfmt integration, localhost port publishing, persistent container down/up, or NFQUEUE;
- any MIPS/MIPSEL runtime;
- MVP 1A, 1B, or 1C acceptance gates.

The PRoot result is diagnostic evidence only. It does not replace the required Docker runtime proof and does not establish compatibility with a physical Keenetic device.

## Development

Requirements: Python 3.12 and `uv`.

```text
uv sync --python 3.12
uv run pytest -q
uv run ruff check .
```

The P0 diagnostic integration test additionally needs the locked artifacts in `.runtime/p0`:

```text
KEEMU_RUN_P0_DIAGNOSTIC=1 uv run pytest -q tests/integration/test_p0_diagnostic.py
```

Generated reports, downloaded IPK files, root filesystems, and runtime state are excluded from Git. Exact committed artifact metadata lives in `locks/p0-aarch64.json`.

## Safety

KEEMU never treats a skipped check or missing capability as PASS. It must not use privileged target containers, host networking/PID namespaces, Docker-socket mounts, `SYS_MODULE`, global firewall resets, or `docker system prune`.
