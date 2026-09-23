# ADR-0003: Correct native keeper signal handling in a derived P0 image

- Status: accepted for p0-05 Docker/binfmt runtime proof
- Date: 2026-09-23

## Evidence and decision

The P0-04 image remains immutable under `locks/p0-mixed-image-aarch64.json`. Its native PID 1 installed SIGTERM/SIGINT handlers before `fork()`, so its keeper inherited those handlers. A Docker probe killed the keeper but the container stayed running beyond a 10-second wait: the keeper returned to `pause()` instead of terminating. This is a real signal-forwarding bug, not a missing binfmt registration.

`fixtures/recipes/aarch64/keemu-init-p005.c` resets the keeper's stop-signal dispositions to `SIG_DFL`; PID 1 forwards the received signal, waits for the keeper and returns 0 only after confirming that child exited from the same signal. Unexpected keeper death returns 1. This correction is compiled as a static amd64 ELF and layered over the locked original image, without changing the AArch64 application rootfs. The new image is `keemu/p0-aarch64:mixed-p005`, ID `sha256:66efaedcbd42ac56db30122762ebf73bcfb41a17dd6404bf22f7af067047b6f6`. `locks/p0-mixed-image-aarch64-p005.json` records the native source/binary hashes, original base image ID/layer, replacement layer, saved archive/config hashes, labels, and compiler. Independent saved-image audit found exactly two layers: the original locked base layer and one replacement native init file. The prior image, source, lock and saved archive remain available unchanged.

## Runtime proof and limits

`reports/20260923T080109Z-p005-e6653acf4ef7/probe.json` records a nonprivileged, network-none Docker/binfmt target shell, real opkg, nested AArch64 BusyBox ELF, direct executable shebang, daemon remaining alive after its `docker exec` parent exits, adoption of a short-lived child by PID 1 and its subsequent disappearance from procfs, graceful SIGTERM shutdown (exit 0), unexpected keeper death (exit 1), and PID 1 SIGINT forwarding path (exit 0). All three labeled probe containers were removed after owner/run-id verification; the Docker daemon and foreign containers remained running. The probe used an explicitly executable 16 MiB `/tmp` tmpfs because the baseline noexec tmpfs cannot host a directly executed test shebang; this exception was limited to that disposable container. No host binfmt change was made by the p0-05 probe; the separately approved single AArch64 registration remains host configuration and must be revalidated after reboot or runner change.

This proves the frozen p0-05 slice on AArch64 only. It does not complete P0, full cross-target A01, full interruption-recovery A18, or later web/persistence/NFQUEUE work.
