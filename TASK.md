# Autonomous Task: KEEMU MVP 1D — Script Execution

## Objective

Implement and experimentally verify a reproducible, bounded, ownership-safe shell-script runner inside KEEMU target Entware environments. This is a new milestone. It must not alter the frozen MVP 1 evidence, acceptance ledger, or release result.

## Authoritative specification

- `docs/specifications/KEEMU_MVP1D_script_execution.md` is the product specification.
- `docs/specifications/KEEMU_MVP1D_script_execution_verdict.md` defines the approved implementation strategy and risk boundaries.
- `docs/milestones/KEEMU_MVP1_TASK_FROZEN.md` and all final-28/final-29/final-31 evidence remain immutable historical inputs.

## Frozen scope

- Primary mandatory architecture: `generic-aarch64` through the existing verified Docker/binfmt runtime.
- `generic-mips` and `generic-mipsel` must use the same script execution contract. If their general lifecycle remains unavailable, return truthful `BLOCKED`; do not create architecture-specific bypasses.
- Implement one-shot `keemu script SCRIPT --profile PROFILE` and persistent `keemu exec NAME --script SCRIPT -- ARGS...`.
- Add secure host input validation, SHA-256 identity, target staging under `/opt/tmp`, target-copy integrity, no-overwrite behavior, argv/cwd/timeout handling, bounded separate stdout/stderr, typed reporting, assertions, scenario `kind: script`, cleanup, interruption and isolation evidence.
- Do not inherit arbitrary host environment or execute script content through a host shell.

## Constraints

- Work only on branch `staging`; push every coherent verified subtask to `origin/staging`.
- `main` and `post-mvp` are frozen baselines for this milestone. Never merge or force-push automatically.
- Preserve all original MVP 1 evidence and historical route/model attestations; do not reclassify A01–A21.
- Never store credentials, OAuth data, deploy keys, `.env` files, private keys, or raw secret-like input in Git or reports.
- Never use `docker system prune`, host PID/network namespaces for script execution, public exposure, target `--privileged`, Docker socket mounts, unrestricted host mounts, or arbitrary host environment inheritance.
- Do not modify host binfmt, firewall, kernel modules, DNS, physical routers, cloud/billing resources, credentials, OAuth, or deploy keys without explicit human approval.
- Cleanup may mutate only exact project/run-owned resources and exact staged paths. Ambiguous ownership must fail closed.
- Every worker launch requires a fresh quota admission. Quota waits resume the same subtask/session/model lock and never create a new routing decision.
- Runtime provider/model/reasoning metadata is authoritative; mismatch is `MODEL_ATTESTATION_FAILED`.
- Routing remains fixed/shadow for `m1d-00`. No implementation subtask may start until its visible route table and threat/acceptance ledger are independently reviewed and approved.

## Acceptance criteria

### D01 — Secure input

- [ ] Regular-file-only, project-contained, bounded, no-follow script input is opened safely and hash-identified.
- [ ] Symlink, FIFO, device, traversal, oversized input, inode/metadata/byte replacement, and validation-to-stage mutation fail closed.

### D02 — Typed staging and integrity

- [ ] Target path is KEEMU-generated from SHA-256 and confined to `/opt/tmp`.
- [ ] Existing target objects are never overwritten.
- [ ] Container identity is checked before and after mutation; target bytes match the source digest.
- [ ] Cleanup removes only the exact staged object and records failure honestly.

### D03 — Execution and process cleanup

- [ ] `/bin/sh TARGET_SCRIPT` receives bounded argv without host-side shell reparse.
- [ ] CWD is explicit and target-path validated; arbitrary host environment is absent.
- [ ] Timeout is 1..runtime maximum, default 60 seconds, with bounded TERM/KILL of only the target process tree.
- [ ] Timeout evidence proves no script descendants remain and does not kill unrelated persistent-environment processes.

### D04 — Results and status semantics

- [ ] Typed result/report records source/digest, target path/profile/architecture/runtime identity, interpreter, argv, cwd, timeout, duration, exit code, timeout, separate bounded stdout/stderr and truncation, assertions, and cleanup.
- [ ] Unexpected script/assertion results are `FAIL`; unavailable capability or changed locked input is `BLOCKED`; harness contract failure is `ERROR`; verified execution plus assertions and cleanup is `PASS`.

### D05 — One-shot and persistent lifecycle

- [ ] `keemu script` passes successful, exit-7, timeout, argv, filesystem-effect, input-mutation, and cleanup cases on AArch64.
- [ ] `keemu exec NAME --script` works only for owner-verified `running` environments and preserves unrelated environment state/services.
- [ ] One-shot removes its owned container/resources; persistent mode removes only exact temporary script artifacts.

### D06 — Scenario and schema

- [ ] `kind: script` is a backward-compatible discriminated check with committed JSON schema parity and immutable-input locking.
- [ ] Scenario execution uses the same secure input/staging/execution path; it never converts file content to `/bin/sh -c`.

### D07 — Architecture and isolation

- [ ] AArch64 real execution is mandatory.
- [ ] MIPS/MIPSEL use the same contract and produce real PASS or truthful BLOCKED evidence.
- [ ] Script execution cannot directly mutate host OS, access Docker socket, gain host privileges, inherit secrets, or alter foreign resources.
- [ ] Race, interruption, cleanup retry, collision, and foreign-resource preservation tests are recorded.

### D08 — Completion evidence

- [ ] Portable tests, applicable Docker/binfmt integration tests, lint/format/diff checks, and a dedicated MVP 1D evidence ledger pass or preserve exact blockers.
- [ ] README, architecture, limitations, progress, traceability, ADRs, and durable `.agent/` files match verified behavior.
- [ ] Independent final audit maps D01–D08 to tests/evidence without changing the original MVP 1 status.

## Human approval boundaries

Explicit approval is required before any host binfmt, firewall, kernel-module, public-network, DNS, physical-device, cloud/billing, credential/OAuth, deploy-key, or non-project repository mutation. Script execution itself must remain inside project-owned target environments.
