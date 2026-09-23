# KEEMU

KEEMU is a reproducible verification harness for Entware applications. The authoritative scope and acceptance criteria are in `KEEMU_MVP1_updated.md` revision 2.2.

## Current status

Implementation is in the P0 technical-risk phase.

Verified in the current Debian/Docker environment:

- the AArch64 Entware package index and 20-package bootstrap closure were downloaded and SHA-256 verified;
- the real AArch64 Entware `opkg` and BusyBox shell execute through QEMU user-mode;
- an unprivileged PRoot diagnostic executes shell → child AArch64 ELF → shell script with a target shebang;
- the committed lock records exact Entware artifacts and the diagnostic QEMU/PRoot inputs;
- current `RunReport` schema version 2 uses immutable metadata models for artifacts, scenarios, profiles, runtimes, capabilities, substitutions, checks, operation logs, coverage, and partial failures; each partial failure references one operation-log sequence whose operation name and failure status must match;
- report bundles use Linux `renameat2(..., RENAME_NOREPLACE)` to atomically publish `report.json`, `report.md`, and `operation-log.jsonl`; existing destination entries are preserved, and publication fails closed if the no-replace primitive is unavailable.
- on a Docker Engine 29.7.2 host with an explicitly approved AArch64 binfmt registration, the separately locked mixed image executes the target shell, opkg, nested AArch64 ELF and direct shebang; a bounded P0-05 probe also verifies daemon survival, native init signal forwarding/reaping and clean owner-checked shutdown. The original P0-04 image is retained unchanged.

Not yet verified:

- localhost port publishing, persistent container down/up and NFQUEUE; complete isolation and interruption recovery also remain later work;
- any MIPS/MIPSEL runtime;
- MVP 1A, 1B, or 1C acceptance gates.

The PRoot result is diagnostic evidence only. The separate Docker/binfmt proof covers AArch64 P0-05, not the full P0 gate or compatibility with a physical Keenetic device.

## Development

Requirements: Python 3.12 and `uv`.

```text
uv sync --python 3.12
uv run pytest -q
uv run ruff check .
```

Static IPK inspection (no installation or package execution):

```text
uv run keemu inspect path/to/package.ipk --profile generic-aarch64
uv run keemu inspect path/to/package.ipk --profile generic-aarch64 --rootfs path/to/dependency-complete-rootfs
```

The command emits JSON with `mode=static`, SHA-256, metadata, archive entries, ELF details, findings, status and limitations. A rootfs must include the package's resolved dependencies; unresolved or postinst-created paths remain BLOCKED until a later installation check. Static PASS is not A01 or A02 acceptance. Input must be reopened and rehashed before installing; `inspect` is not an install authorization.

The P0 diagnostic integration test additionally needs the locked artifacts in `.runtime/p0`:

```text
KEEMU_RUN_P0_DIAGNOSTIC=1 uv run pytest -q tests/integration/test_p0_diagnostic.py
```

The p0-04 image audit requires the already-built project image and the saved archive:

```text
KEEMU_RUN_P0_IMAGE_AUDIT=1 uv run pytest -q tests/integration/test_p0_image.py
```

The P0-05 probe requires the locked derived image and a separately authorized Docker/binfmt runner; it creates and cleans only labeled KEEMU containers:

```text
uv run python tests/integration/p0_runtime_probe.py
```

Generated reports, downloaded IPK files, root filesystems, saved images, and runtime state are excluded from Git. Exact committed artifact metadata lives in `locks/p0-aarch64.json`, `locks/p0-fixtures-aarch64.json`, `locks/p0-mixed-image-aarch64.json`, and `locks/p0-mixed-image-aarch64-p005.json`. The original image lock records a static create template, not runtime behavior; the P0-05 derived-image lock and ignored report record the bounded real probe.

## Safety

KEEMU never treats a skipped check or missing capability as PASS. It must not use privileged target containers, host networking/PID namespaces, Docker-socket mounts, `SYS_MODULE`, global firewall resets, or `docker system prune`.
