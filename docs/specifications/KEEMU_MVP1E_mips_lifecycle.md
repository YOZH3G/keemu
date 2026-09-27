# KEEMU MVP 1E — MIPS/MIPSEL production lifecycle

Status: approved implementation milestone on `staging`.

## Objective

Extend the existing locked KEEMU lifecycle from `generic-aarch64` to `generic-mips` and `generic-mipsel` without architecture-specific bypasses. Deliver locked init caches, one-shot IPK lifecycle, persistent lifecycle and script execution through the common contracts, then verify a three-architecture matrix.

This milestone enables architectures. It does not redesign or close MVP 1D D02/D07.

## Existing inputs

- Strict profiles: `generic-aarch64`, `generic-mips`, `generic-mipsel`.
- MIPS/MIPSEL package, SDK, fixture, image and target-execution locks from MVP 1B.
- Existing AArch64 `init_cache`, one-shot, registry/persistent and script lifecycle contracts.
- Existing MIPS/MIPSEL binfmt handlers may be observed and used if their exact current state passes preflight. They must not be installed, replaced or modified in this milestone without new explicit human approval.

## Required gates

### E01 — Scope, locks and capability review

- Rehash and validate all MIPS/MIPSEL profile, package, image, fixture and binfmt prerequisites.
- Map the exact AArch64 implementation seams that must become architecture-generic.
- Freeze architecture, ownership, cleanup, recovery, reporting and route boundaries before product mutation.
- Record truthful `PASS`, `BLOCKED` or `NOT_RUN`; do not repair host prerequisites.

### E02 — MIPS locked init cache

- Build and atomically publish a deterministic offline-verifiable `generic-mips` init cache from exact locked inputs.
- Verify package inventory, image/rootfs/archive identities, native init identity and bounded target smoke.
- Preserve existing AArch64 cache behavior and refuse ambiguous or foreign artifacts.

### E03 — MIPSEL locked init cache

- Apply the same common cache contract to `generic-mipsel` with independent locks and evidence.
- No target-specific bypass, unpinned network input or overwrite of an existing cache object.

### E04 — Common one-shot lifecycle

- Generalize the production one-shot IPK lifecycle to all three generic architectures through one dispatch path.
- Preserve typed reports, exact owner cleanup, use-time input verification, static inspection and target opkg behavior.
- Real MIPS and MIPSEL successful/negative/cleanup cases are required; probes alone are insufficient.

### E05 — Persistent lifecycle and recovery

- Generalize registry-backed `up`, `down`, `restart`, `destroy`, `status`, `ports`, `logs`, `exec` and explicit recovery to MIPS/MIPSEL.
- Preserve per-name locking, atomic registry transitions, full-ID/label checks, tombstones and foreign-resource refusal.
- Test interruption boundaries and idempotent recovery without adopting ambiguous resources.

### E06 — Script integration

- Remove only the MIPS/MIPSEL capability gate needed to route existing one-shot and persistent script execution through the common lifecycle.
- Reuse `ScriptInput`, `ScriptStager`, `ScriptProcessRunner`, typed assertions/status mapping and redacted reports unchanged unless the higher-tier review first proves a necessary bounded correction.
- The C3 implementation trial may change at most five source/test files. It must not introduce an architecture-specific runner, new ownership/cleanup/recovery primitive, host configuration change or report-status reinterpretation.
- Any needed scope expansion must stop fail-closed and restart as a new C4 session; never switch route inside the C3 session.

### E07 — Three-target adversarial verification

- Run applicable real AArch64/MIPS/MIPSEL init, one-shot, persistent and script tests.
- Verify collision, input mutation, timeout, interruption, recovery, exact cleanup and foreign-resource preservation.
- Preserve D02/D07 as `BLOCKED` unless a separate explicitly approved hardening milestone actually closes them.

### E08 — Evidence and independent audit

- Reconcile exact source/evidence hashes, test counts, architecture matrix, limitations, README/architecture/progress/traceability/ADR and durable records.
- Independent final audit maps E01–E08 and publishes exact milestone status without product mutation.
- Historical MVP 1 and MVP 1D records remain immutable.

## Safety boundaries

- Work only on branch `staging`; push every coherent verified subtask to `origin/staging`.
- Do not merge or force-push `main` or alter `post-mvp` automatically.
- No host binfmt installation/replacement, firewall rules, kernel modules, public exposure, host namespaces, Docker socket mounts into targets, credentials/OAuth/deploy-key changes, global prune or foreign-resource mutation.
- Docker mutations must be project/run-owned, label-verified and independently cleaned.
- Every product behavior change follows test-first RED → GREEN → regression verification.
- Every worker launch requires fresh quota admission, frozen provider/model/reasoning lock and runtime attestation.

## C3 calibration contract

C3 samples: `m1e-00`, `m1e-05`, `m1e-07`.

Record for each sample: first-pass verification, continuations/failures, scope violations, blocking findings, corrective diff, runtime attestation and quota observation. `m1e-05r` is a separate C4 read-only review of the C3 engineering trial. C3 results remain shadow telemetry and cannot promote routing policy automatically.