# ADR-0002: P0 mixed image has native amd64 entrypoint and target AArch64 rootfs

- Status: accepted for image build/inspect; container-runtime behavior remains unverified
- Date: 2026-09-23

## Decision

Build a `FROM scratch` image with Docker platform `linux/amd64`. The sole native ELF is a project-owned, statically linked amd64 PID 1 under `/__keemu/init`; the 20 locked Entware packages and `/bin/sh`/`opkg` are AArch64. The native control binary is outside the application PATH. The image carries explicit KEEMU ownership, target, native platform, source, package-lock, and rootfs labels. `locks/p0-mixed-image-aarch64.json` records the daemon image ID, saved-layer/config hashes, and whole-image ELF inventory.

CPU, memory, PID, read-only root, tmpfs and capability restrictions belong to Docker container creation, not OCI image metadata. A static, argv-only create template records them with ownership/run labels and no privileged, host namespace, public port, or Docker socket. It was not executed in p0-04. The baseline template uses `--network=none`; network-enabled scenarios require a separate, explicit later decision.

## Evidence and limits

Docker Engine 29.7.2 built and inspected the image. An independent saved-layer audit found 28 AArch64 ELF files and one amd64 init; `/bin/sh` points to target BusyBox. The saved config digest differs from Docker's live image ID, so the lock records these as separate values, not interchangeable claims. No container was created or run, no binfmt entry was changed, and PID 1 signals/reaping, target nested execution, runtime limits/isolation, and A18/A20 recovery remain unverified until later supervised subtasks. A01 remains PARTIAL; P0 is not complete.
