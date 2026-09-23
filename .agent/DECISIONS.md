# Agent decisions

## D-001 — Reuse the existing repository

The durable supervisor uses `/opt/data/workspace/keemu` directly. `/opt/data/hermes-projects/keemu` is a compatibility symlink, not a second checkout. This avoids splitting project state.

## D-002 — Fixed current-model route

Supervised work is fixed to tier C5: `gpt-5.6-sol` with reasoning `xhigh`. Router mode is `auto` only to provide explicit per-run overrides and model-lock attestation; both minimum and maximum tiers are C5 and Astra is disabled. Dynamic model switching is not enabled.

## D-007 — ChatGPT 6 Luna/Sol policy refresh

At the verified p0-02 boundary, future Luna/Sol routes move from `gpt-5.6-luna`/`gpt-5.6-sol` to `gpt-6-luna`/`gpt-6-sol`. Existing attested route and outcome records retain the literal models that actually ran. The active p0-03 lock remains `gpt-5.6-terra` / `high`; all subsequent frozen plan entries and live policy/config use the updated IDs. Runtime attestation remains mandatory before a new model is treated as active.

## D-003 — Local Git until a private remote exists

Git auto-pull and auto-push are disabled. Local commits remain the durable boundary; adding a private remote and deploy key requires a separate explicit operation.

## D-004 — Preserve the Hostinger baseline

The deployment reuses the installed Hermes binary, OAuth state, RTK, Graphify, Caveman and router runtime. It does not reinstall or reconfigure those components.

## D-005 — Direct QEMU/PRoot is diagnostic only

When Docker is unavailable, project-local QEMU and unprivileged PRoot may verify locked target artifacts, target shell/opkg, nested target ELF and shebang behavior. This path is not a replacement for the accepted Docker runtime and cannot satisfy container, binfmt, publishing, persistence, isolation or networking acceptance requirements.

## D-006 — Reports are frozen objects and write-once bundles

The current common report schema is version 2 and uses frozen nested metadata and immutable sequences. Aggregate status and coverage are derived and revalidated from checks and partial-failure state. Each partial failure references an exact operation-log sequence, and the referenced record must match its operation name and failure status. A report bundle is assembled in a sibling temporary directory and published with Linux `renameat2(..., RENAME_NOREPLACE)`. Publication atomically succeeds only when the destination entry is absent; any existing directory, file, or symlink is preserved and reported as `FileExistsError`. If the no-replace primitive is unavailable, publication fails closed and removes the temporary bundle rather than falling back to overwrite-capable rename. This keeps JSON, Markdown, and operation-log evidence aligned and preserves failed runs.

## D-008 — P0 fixtures use a locked host cross-toolchain

P0 fixture compilation uses a project-staged Debian trixie `aarch64-linux-gnu-gcc` toolchain whose exact DEB inputs and SHA-256 values are recorded in `locks/p0-fixtures-aarch64.json`. This creates reproducible AArch64 ELF sources without pretending that the host compiler or PRoot diagnostic is the required Docker/binfmt runtime. The raw NFQUEUE fixture uses locked Linux UAPI headers rather than an unpinned library SDK; kernel capability and packet-flow correctness remain later, separately bounded experiments.

## D-009 — Mixed-image architecture and deferred container limits

P0-04 uses a scratch `linux/amd64` image with a project-owned, statically linked amd64 PID 1 in `/__keemu` and locked AArch64 Entware application files elsewhere. The native binary is outside application PATH; labels separate the native platform from the target. Docker image ID and saved archive config digest are recorded distinctly because the Engine export produced different values. Resource limits and per-run ownership are represented in an argv-only Docker create template, not falsely attributed to immutable OCI image properties. Image build/inspect and saved-layer ELF audit are verified; runtime execution, applied limits, recovery and isolation await later subtasks. See `docs/decisions/0002-p0-mixed-image.md`.

## D-010 — Derived P0-05 image fixes inherited keeper signal dispositions

The original P0-04 init's keeper inherited handled SIGTERM/SIGINT and remained alive after a direct signal, so the old image could not prove forwarding. Preserve the original image, source, lock and audit. Derive a separately locked P0-05 image by replacing only the static amd64 init: the keeper restores default stop-signal dispositions; PID 1 returns success only after the forwarded signal is observed as the keeper's exact signaled exit. A real Docker/binfmt differential verified unexpected keeper death exits 1, while SIGINT to PID 1 exits 0; a full target/runtime probe verified nested execution, reaping and clean SIGTERM stop. No target app files, host binfmt entry, network, public port or foreign container was modified in the derived-image probe. See `docs/decisions/0003-p0-init-signal.md`.
