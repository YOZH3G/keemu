# Project Context

## Project

- Name: KEEMU
- Root: `/opt/data/workspace/keemu`
- Durable compatibility path: `/opt/data/hermes-projects/keemu` (symlink to the project root)
- Active branch: `staging`
- Frozen pre-MVP-1D baseline: `post-mvp`. `main` contains the completed, audited MVP 1D branch state; this publication does not change its truthful `BLOCKED` release verdict.
- Active specification: `docs/specifications/KEEMU_MVP1E_mips_lifecycle.md`
- Frozen predecessor task/state: `docs/milestones/KEEMU_MVP1D_TASK_FROZEN.md` and `.agent/STATE_MVP1D.json`.
- Frozen original specification: `KEEMU_MVP1_updated.md`, revision 2.2
- Git remote: `git@github.com:YOZH3G/keemu.git`; repository-local SSH configuration isolates the KEEMU deploy key from unrelated GitHub keys.

## Current runtime

- Hermes home: `/opt/data`
- Hermes binary: `/usr/local/bin/hermes`
- Hermes installation: Docker-managed; preserve existing OAuth and baseline installation.
- Container userspace: Debian 13; host kernel: Linux 6.8 x86_64.
- Docker Engine 29.7.2 and a usable Docker socket supported the approved project-owned AArch64/binfmt MVP 1D integration runs through `m1d-11`; this is privileged host access. Revalidate socket/binfmt and ownership before any new Docker mutation. `m1d-12` documentation verification is portable/read-only; MIPS/MIPSEL general script lifecycle remains unavailable.
- Available optimization tools: RTK 0.49.0 and Graphify 0.9.62. Caveman is installed as a global Hermes skill.
- Supervisor runtime: `/opt/data/hermes-durable-vps-hostinger-router-v1`
- Project supervisor config: `/opt/data/hermes-supervisor-configs/keemu.json`
- Router policy: `/opt/data/hermes-durable-vps-hostinger-router-v1/router/models.json`

## Execution policy

- MVP 1E supervised work follows the user-approved frozen table in `docs/model-routing-plan-mvp1e.md`: C3=3, C4=5, C5=2, Astra=0. Router learning remains shadow-only, while `routing.apply_approved_subtask_routes=true` applies each frozen plan row as the explicit worker lock.
- Each subtask receives an explicit disposable-worker lock for provider, model and reasoning. Switching is permitted only after an exact completion marker, runtime attestation, durable outcome, and verified session deletion.
- Astra is disabled for MVP 1E; later use requires explicit evidenced C5 failure or a separately approved read-only shadow review.
- Quota pauses retain the same subtask, session, provider, model and reasoning; they are not escalation signals.
- Before launching every new frozen subtask, the supervisor must fetch live OAuth account usage and persist a subtask-bound admission record. Below 11% remaining it warns; below 5% it checkpoints and waits until the stored absolute reset-plus-margin time. Same-subtask session continuations do not repeat the preflight.
- All ten MVP 1E subtasks `m1e-00` through `m1e-08` (including `m1e-05r`) are authorized in frozen order, subject to fresh per-subtask quota admission and runtime attestation. C3 scope expansion fails closed to a new C4 session at a verified boundary.
- Policy learning remains observational (`shadow`); canary promotion is disabled.
- Git auto-pull remains disabled to avoid hidden remote integration. Git checkpoints stage the complete task result (excluding secret-like paths) and auto-push `staging` after each verified subtask boundary.
- All 14 MVP 1D subtasks are attested complete and published on `main` and `staging`; the independent audit remains frozen and D02/D07 still block MVP 1D release. MVP 1E begins from that synchronized commit on `staging` and must not modify historical ledgers or verdicts.

## Verification commands

```bash
git status --short --branch
python3 -m json.tool .agent/STATE_MVP1E.json
python3 -m json.tool /opt/data/hermes-supervisor-configs/keemu.json
python3 -m unittest discover -s /opt/data/hermes-durable-vps-hostinger-router-v1/tests -v
graphify hook status --project-root /opt/data/workspace/keemu
```

When code exists, verify `graphify-out/graph.json` has nonzero nodes or edges before using it as an architectural signal.

## Safety notes

Do not place passwords, private keys, OAuth tokens, API keys, authorization headers or raw secret-bearing logs in this file or under `.agent/`.
