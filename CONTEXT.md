# Project Context

## Project

- Name: KEEMU
- Root: `/opt/data/workspace/keemu`
- Durable compatibility path: `/opt/data/hermes-projects/keemu` (symlink to the project root)
- Branch: `agent/keemu`
- Specification: `KEEMU_MVP1_updated.md`, revision 2.2
- Git remote: none configured at stack activation time; local Git is the durable source until a private remote is supplied.

## Current runtime

- Hermes home: `/opt/data`
- Hermes binary: `/usr/local/bin/hermes`
- Hermes installation: Docker-managed; preserve existing OAuth and baseline installation.
- Container userspace: Debian 13; host kernel: Linux 6.8 x86_64.
- Docker CLI exists, but the Hermes container currently has no usable `/var/run/docker.sock`. Integration tests needing Docker may therefore be BLOCKED until a separate approved Docker-capable runner/host is provided.
- Available optimization tools: RTK 0.49.0 and Graphify 0.9.62. Caveman is installed as a global Hermes skill.
- Supervisor runtime: `/opt/data/hermes-durable-vps-hostinger-router-v1`
- Project supervisor config: `/opt/data/hermes-supervisor-configs/keemu.json`
- Router policy: `/opt/data/hermes-durable-vps-hostinger-router-v1/router/models.json`

## Execution policy

- Supervised work follows the reviewed per-subtask table in `docs/model-routing-plan.md`; bounds are C0–C7 and routing mode is `auto`.
- Each subtask receives an explicit disposable-worker lock for provider, model and reasoning. Switching is permitted only after an exact completion marker, runtime attestation, durable outcome, and verified session deletion.
- C6/C7 (`gpt-6-astra`) are unlocked for frontier escalation at a new audited subtask boundary; if unavailable, the configured fallback is C5 (`gpt-5.6-sol`, `xhigh`).
- Quota pauses retain the same subtask, session, provider, model and reasoning; they are not escalation signals.
- Policy learning remains observational (`shadow`); canary promotion is disabled.
- Git auto-pull and auto-push are disabled because no remote exists.

## Verification commands

```bash
git status --short --branch
python3 -m json.tool .agent/STATE.json
python3 -m json.tool /opt/data/hermes-supervisor-configs/keemu.json
python3 -m unittest discover -s /opt/data/hermes-durable-vps-hostinger-router-v1/tests -v
graphify hook status --project-root /opt/data/workspace/keemu
```

When code exists, verify `graphify-out/graph.json` has nonzero nodes or edges before using it as an architectural signal.

## Safety notes

Do not place passwords, private keys, OAuth tokens, API keys, authorization headers or raw secret-bearing logs in this file or under `.agent/`.
