# Autonomous Task: KEEMU MVP 1E — MIPS/MIPSEL Production Lifecycle

## Objective

Deliver full locked production lifecycle support for `generic-mips` and `generic-mipsel` through the existing common KEEMU contracts: deterministic init cache, one-shot IPK lifecycle, persistent lifecycle and recovery, script execution, three-target verification, evidence reconciliation and independent audit.

## Authoritative specification

- `docs/specifications/KEEMU_MVP1E_mips_lifecycle.md`
- `docs/model-routing-plan-mvp1e.md`
- Frozen predecessor: `docs/milestones/KEEMU_MVP1D_TASK_FROZEN.md`
- Frozen predecessor state: `.agent/STATE_MVP1D.json`

## Frozen scope

- Architectures: `generic-aarch64`, `generic-mips`, `generic-mipsel`.
- MIPS/MIPSEL must use the common production contracts; target probes or architecture-specific bypasses cannot satisfy lifecycle gates.
- Use existing locked MVP 1B inputs and existing AArch64 lifecycle patterns as immutable prerequisites.
- Existing MIPS/MIPSEL binfmt handlers may be observed and used after exact preflight. Do not install, replace or modify host binfmt without new explicit human approval.
- MVP 1D D02/D07 remain separate blockers. This milestone must not claim to fix them through architecture enablement.

## Acceptance criteria

- [ ] E01 scope/lock/capability review freezes exact prerequisites, seams, safety boundaries and routes.
- [ ] E02 deterministic offline-verifiable locked `generic-mips` init cache passes real target smoke.
- [ ] E03 deterministic offline-verifiable locked `generic-mipsel` init cache passes real target smoke.
- [ ] E04 common one-shot IPK lifecycle passes required real MIPS/MIPSEL success, negative and cleanup cases without regressing AArch64.
- [ ] E05 persistent lifecycle and explicit recovery pass real MIPS/MIPSEL service/state/interruption/foreign-resource cases.
- [ ] E06 common one-shot and persistent script execution pass on MIPS/MIPSEL with the existing input/stage/process/assertion/report contracts.
- [ ] E07 three-target adversarial matrix records exact interruption, timeout, collision, recovery, cleanup and isolation outcomes.
- [ ] E08 evidence/docs and independent final audit publish exact PASS/FAIL/BLOCKED/ERROR milestone truth while preserving prior history.

## Controlled C3 experiment

- `m1e-00`, `m1e-05`, and `m1e-07` use frozen C3 locks for telemetry.
- `m1e-05` may touch at most five source/test files and may only integrate existing common script primitives with the newly available lifecycle.
- `m1e-05` must not change `ScriptInput`, `ScriptStager`, `ScriptProcessRunner`, ownership/cleanup/recovery primitives, process-tree semantics or report-status mapping; if such a change is needed, stop fail-closed.
- `m1e-05r` performs a separate C4 read-only review. Any corrective implementation requires a new approved worker boundary and route.
- C3 telemetry cannot promote routing policy automatically.

## Execution constraints

- Work only on `staging`; push each coherent verified subtask to `origin/staging`.
- Do not merge/push `main`, rewrite history or alter `post-mvp` automatically.
- Follow strict TDD for production changes: observe RED before implementation, then GREEN and full relevant regression.
- Preserve all MVP 1/MVP 1D tasks, states, ledgers, evidence hashes and runtime attestations.
- No credentials, OAuth, deploy-key, host firewall, kernel-module, public exposure, host namespace, global prune or foreign-resource changes.
- Cleanup only exact project/run-owned resources; ambiguous ownership fails closed.
- Every worker launch requires fresh quota admission. Runtime provider/model/reasoning metadata must match its frozen lock; mismatch is `MODEL_ATTESTATION_FAILED`.
- Model switching is allowed only at a verified subtask boundary with a new disposable session.

## Completion

MVP 1E is complete only when every frozen subtask is terminally attested, all sessions are deleted, `origin/staging` contains every verified deliverable, E01–E08 have an independently audited verdict, and no project-owned runtime resources remain.