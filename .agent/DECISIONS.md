# Agent decisions

## D-001 — Reuse the existing repository

The durable supervisor uses `/opt/data/workspace/keemu` directly. `/opt/data/hermes-projects/keemu` is a compatibility symlink, not a second checkout. This avoids splitting project state.

## D-002 — Fixed current-model route

Supervised work is fixed to tier C5: `gpt-5.6-sol` with reasoning `xhigh`. Router mode is `auto` only to provide explicit per-run overrides and model-lock attestation; both minimum and maximum tiers are C5 and Astra is disabled. Dynamic model switching is not enabled.

## D-003 — Local Git until a private remote exists

Git auto-pull and auto-push are disabled. Local commits remain the durable boundary; adding a private remote and deploy key requires a separate explicit operation.

## D-004 — Preserve the Hostinger baseline

The deployment reuses the installed Hermes binary, OAuth state, RTK, Graphify, Caveman and router runtime. It does not reinstall or reconfigure those components.

## D-005 — Direct QEMU/PRoot is diagnostic only

When Docker is unavailable, project-local QEMU and unprivileged PRoot may verify locked target artifacts, target shell/opkg, nested target ELF and shebang behavior. This path is not a replacement for the accepted Docker runtime and cannot satisfy container, binfmt, publishing, persistence, isolation or networking acceptance requirements.
