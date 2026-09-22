# ADR-0001: Use direct QEMU/PRoot only as an early diagnostic

- Status: accepted for diagnostic use; not accepted as the MVP runtime
- Date: 2026-09-22

## Context

The accepted MVP runtime is Docker Engine with QEMU user-mode and host binfmt. The current Hermes container has Docker CLI but no Docker daemon socket and no usable target binfmt registrations. Public artifact access is available.

P0 still needs early evidence that the selected Entware artifacts are authentic AArch64 binaries and that the target shell and package manager execute.

## Decision

Use a project-local QEMU binary and unprivileged PRoot to perform a narrow diagnostic:

- install the locked local IPK closure with the real AArch64 `opkg`;
- execute target BusyBox shell and target `opkg`;
- execute a nested target ELF and a target-shebang script;
- record the mode as `diagnostic`, not Docker acceptance.

The Docker design remains unchanged. PRoot will not be used as an automatic fallback for acceptance, isolation, publishing, persistence, or networking.

## Consequences

This gives reproducible artifact and target-execution evidence without changing host binfmt or requiring root. It does not satisfy A01 or the P0 gate because the required container, binfmt, web, persistence, and NFQUEUE checks remain absent.
