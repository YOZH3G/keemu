# Agent journal

- 2026-09-22T07:31:31Z — Read-only preflight confirmed the existing Docker-managed Hermes baseline, active `keemu` project, optimization tools and separate running `hermes-workspace` supervisor.
- 2026-09-22T07:31:31Z — Created backup `/opt/data/backups/keemu-stack-20260922T073131Z` before project mutations.
- 2026-09-22T07:31:31Z — Created branch `agent/keemu` and began installing the durable project protocol without modifying OAuth or the existing supervisor.
- 2026-09-22T07:37:55+00:00 — Supervisor stopped: git sync failed because `sync_ff_only()` fetched `origin` even when `git_auto_pull=false` and no remote exists.
- 2026-09-22T07:39:00Z — Added a failing regression test, fixed `sync_ff_only()` to skip remote access when auto-pull is disabled, and verified all 52 supervisor/router tests pass.
- 2026-09-22T07:43:14Z — Resume preflight confirmed the model-locked worker command, 52 passing supervisor/router tests, Graphify index, reachable Entware source, absent Docker socket, absent target binfmt entries and 85 GiB free disk.
- 2026-09-22T07:54:33Z — Captured and verified the AArch64 Entware bootstrap closure: 20 IPK files plus installer/opkg inputs and project-local QEMU/PRoot artifacts; wrote `locks/p0-aarch64.json` from real versions and SHA-256 values.
- 2026-09-22T08:01:51Z — Real direct-QEMU/PRoot diagnostic passed target shell, target opkg, nested target ELF and target-shebang checks; wrote runtime evidence `p0diag-61f167a83d33` without claiming Docker or acceptance completion.
- 2026-09-22T08:03:48Z — Portable tests and explicit diagnostic integration passed; Ruff reported no issues. P0 remains blocked on Docker-backed web/persistence/NFQUEUE experiments.
