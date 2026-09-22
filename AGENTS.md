# Durable Hermes Agent Protocol

This repository is controlled by an external durable supervisor. Treat Git plus `.agent/` as the durable source of truth. A Hermes conversation is useful context, but it is not authoritative after a pause, reboot, crash, or quota reset.

## Mandatory startup / resume sequence

1. Read `TASK.md`, `CONTEXT.md`, `.agent/CHECKPOINT.md`, `.agent/MEMORY.md`, `.agent/DECISIONS.md`, and recent `.agent/JOURNAL.md` entries.
2. Inspect `git status`, the current branch, recent commits, and the real runtime/environment relevant to the task.
3. Revalidate assumptions before destructive or irreversible operations. Never assume an interrupted command completed.
4. Continue from the first unfinished **verified** operation.

## Optimization stack: RTK + Graphify + Caveman

These are acceleration/compression layers. They never replace source verification or durable state.

### Graphify — understand before reading broadly

When `graphify-out/graph.json` exists and the question spans multiple files/components, prefer a scoped graph query before broad grep/file reading:

- `graphify query "<question>"` for impact/architecture scope;
- `graphify path A B` for dependency/call paths;
- `graphify explain "<symbol>"` for a focused neighborhood.

Use Graphify to narrow the search space, then inspect the exact source/config before editing. Never treat an inferred graph edge as sufficient proof for a destructive change. If the graph is missing/stale or Graphify fails, fall back to normal source inspection immediately.

### RTK — compact terminal output

RTK is installed as a Hermes terminal-rewrite plugin. Normal supported terminal commands may be transparently rewritten to compact equivalents. This is expected. If compact output hides information required for diagnosis, inspect the full failure tee path reported by RTK, use a more verbose RTK mode, or bypass filtering for that one command. Never re-run an expensive/destructive command merely to obtain prettier output.

### Caveman — compact narrative only

Load the `caveman` skill and use **full** intensity for ordinary conversational/status prose to reduce output tokens. Compression applies only to narrative. Keep these exact and uncompressed:

- source code and configuration;
- commands, paths, identifiers and API names;
- error strings and decisive logs;
- security/destructive-action warnings;
- `.agent/CHECKPOINT.md`, `.agent/MEMORY.md`, `.agent/DECISIONS.md`, `.agent/JOURNAL.md`;
- acceptance criteria and verification evidence.

Never sacrifice ordering, causality, constraints, or recovery information for brevity.

## Atomic execution discipline

For each meaningful operation:

1. Inspect current state.
2. Decide the smallest safe change.
3. Execute it.
4. Verify the result independently.
5. Update `.agent/CHECKPOINT.md` with what is now verified and what comes next.
6. Record durable decisions in `.agent/DECISIONS.md` when they will matter later.
7. Record stable project facts in `.agent/MEMORY.md` when they will matter in later sessions.
8. Commit coherent project changes to the current agent branch. Push when network/authentication permit.

Do not claim completion from command output alone when an independent verification is possible.

## Interruption and quota safety

The model/provider may stop at any time because of a ChatGPT/Codex usage window. Therefore:

- Keep the repository recoverable at all times.
- Do not leave important semantic state only in chat history.
- Never continue an interrupted tool call by assumption. Inspect the environment first.
- Keep `.agent/CHECKPOINT.md` current enough that a brand-new Hermes session could continue safely.
- If a command is long-running, prefer idempotent operations and capture enough state to determine whether it completed.

## Git rules

- Work only on the branch prepared for the autonomous task unless `TASK.md` explicitly says otherwise.
- Never force-push.
- Never rewrite published history.
- Do not merge to `main` automatically unless `TASK.md` explicitly authorizes it.
- Before every push, inspect the diff for secrets and unintended files.
- Do not commit credentials, OAuth tokens, SSH private keys, `.env` files, private certificates, or secret material.

## Memory policy

Use:

- `.agent/MEMORY.md` for stable facts and constraints that should survive future sessions.
- `.agent/DECISIONS.md` for architectural/technical decisions and their rationale.
- `.agent/CHECKPOINT.md` for the exact current operational position.
- `.agent/JOURNAL.md` for concise chronological events.

Do not store secrets in any of these files.

## Completion protocol

Only when **every acceptance criterion in `TASK.md` is completed and verified**, print this exact line in the final response:

`@@HERMES_TASK_COMPLETE@@`

If progress is impossible without human input, print this exact line followed by a concise reason:

`@@HERMES_NEEDS_HUMAN@@`

Do not emit the completion marker for partial progress, an unverified result, or a best-effort approximation.

## Supervisor model routing

The external supervisor may select the model and reasoning effort for each continuation. Do not change the global Hermes model/provider configuration and do not attempt to bypass provider quota by switching models. Treat the supervisor's per-run model choice as an execution policy, not as a durable architectural decision.

Astra is an experimental top-tier route. If it is rejected by the live provider route, the supervisor may transparently fall back to Sol. Continue from durable state normally; do not repeatedly probe Astra availability yourself.
