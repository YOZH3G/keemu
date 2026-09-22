# Agent journal

- 2026-09-22T07:31:31Z — Read-only preflight confirmed the existing Docker-managed Hermes baseline, active `keemu` project, optimization tools and separate running `hermes-workspace` supervisor.
- 2026-09-22T07:31:31Z — Created backup `/opt/data/backups/keemu-stack-20260922T073131Z` before project mutations.
- 2026-09-22T07:31:31Z — Created branch `agent/keemu` and began installing the durable project protocol without modifying OAuth or the existing supervisor.
- 2026-09-22T07:37:55+00:00 — Supervisor stopped: git sync failed because `sync_ff_only()` fetched `origin` even when `git_auto_pull=false` and no remote exists.
- 2026-09-22T07:39:00Z — Added a failing regression test, fixed `sync_ff_only()` to skip remote access when auto-pull is disabled, and verified all 52 supervisor/router tests pass.
