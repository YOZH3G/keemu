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
