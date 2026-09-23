# KEEMU

KEEMU is a reproducible verification harness for Entware applications. The authoritative scope and acceptance criteria are in `KEEMU_MVP1_updated.md` revision 2.2.

## Current status

P0 technical-risk experiments are complete. MVP 1A is in progress: strict input
schemas, static IPK inspection, and locked AArch64 base `init` are implemented;
scenario lifecycle and persistent-environment commands are later subtasks.

Verified in the current Debian/Docker environment:

- the AArch64 Entware package index and 20-package bootstrap closure were downloaded and SHA-256 verified;
- the real AArch64 Entware `opkg` and BusyBox shell execute through QEMU user-mode;
- an unprivileged PRoot diagnostic executes shell → child AArch64 ELF → shell script with a target shebang;
- the committed lock records exact Entware artifacts and the diagnostic QEMU/PRoot inputs;
- current `RunReport` schema version 2 uses immutable metadata models for artifacts, scenarios, profiles, runtimes, capabilities, substitutions, checks, operation logs, coverage, and partial failures; each partial failure references one operation-log sequence whose operation name and failure status must match;
- report bundles use Linux `renameat2(..., RENAME_NOREPLACE)` to atomically publish `report.json`, `report.md`, and `operation-log.jsonl`; existing destination entries are preserved, and publication fails closed if the no-replace primitive is unavailable.
- on a Docker Engine 29.7.2 host with an explicitly approved AArch64 binfmt registration, the separately locked mixed image executes the target shell, opkg, nested AArch64 ELF and direct shebang; a bounded P0-05 probe also verifies daemon survival, native init signal forwarding/reaping and clean owner-checked shutdown. The original P0-04 image is retained unchanged.

Not yet verified:

- general scenario-driven localhost publication and persistent-environment commands, complete isolation and interruption recovery; the P0 web-demo did prove an exact localhost publish and stop/start persistence;
- NFQUEUE ACCEPT/DROP is BLOCKED on the documented target socket/kernel capability, not PASS;
- any MIPS/MIPSEL runtime;
- MVP 1A, 1B, or 1C acceptance gates.

The PRoot result is diagnostic evidence only. P0 Docker/binfmt and web-demo
experiments close the technical-risk gate, not full A01/A19 or compatibility
with a physical Keenetic device.

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

Locked AArch64 base preparation (requires the exact staged P0 package/index,
bootstrap opkg, QEMU and native-init inputs, Docker Engine and AArch64 binfmt):

```text
uv run keemu init --profile generic-aarch64 --locked
uv run keemu init --profile generic-aarch64 --locked --offline
KEEMU_RUN_INIT_CACHE=1 uv run pytest -q tests/integration/test_init_cache.py
```

`init` only uses the pre-verified 20 local IPKs; it never updates the live
Entware feed or installs host packages. It canonicalizes opkg's volatile
`Installed-Time`, records the exact target `list-installed` inventory and
default `/opt/etc/opkg.conf`, audits the rootfs and saved scratch-image layer,
and writes a no-replace, lock-bound cache under `.runtime/init-cache/` after a
bounded labeled Docker smoke. `--offline` rechecks all inputs, the saved image,
live image identity and metadata without a network probe or build. The frozen
Docker-local image ID is `sha256:8f91e88ba865d6eea1f37b3d592fdd8c788273c11202a9e4194ff6c5ef4e6224`
in `locks/m1a-init-aarch64.json`; it is not a registry manifest digest.
Target shell, opkg inventory, nested ELF and DNS passed in Docker bridge;
HTTPS passed using the Hermes process CA/hostname verification, **not** in
the target container, whose locked BusyBox wget lacks TLS. Neither fixture
installation nor the complete A01/A19 acceptance is claimed.

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

Generated reports, downloaded IPK files, root filesystems, saved images, and runtime state are excluded from Git. Committed source and image metadata lives in `locks/` (including `locks/m1a-init-aarch64.json`). The original P0 image lock records a static create template, not runtime behavior; the P0-05 derived-image lock and ignored report record its bounded real probe.

## Safety

KEEMU never treats a skipped check or missing capability as PASS. It must not use privileged target containers, host networking/PID namespaces, Docker-socket mounts, `SYS_MODULE`, global firewall resets, or `docker system prune`.
