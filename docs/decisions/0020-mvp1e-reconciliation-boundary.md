# ADR-0020 — MVP 1E reconciliation preserves scoped evidence and defers final audit

## Context

MVP 1E completed bounded E01–E05 implementation evidence, a blocked independent E06 review, and scoped E07 three-target adversarial verification. These records contain different scopes and historical timestamps. E08 requires both reconciliation and a separate independent final audit.

## Decision

`m1e-07` records a hash-bound E01–E08 reconciliation only. It publishes one architecture matrix, C3 shadow telemetry, documentation/traceability alignment and durable-record preservation checks. Its status is `RECONCILIATION_PASS_FINAL_AUDIT_PENDING`.

`m1e-08` remains the sole frozen owner of an independent audit and final MVP 1E status. The reconciliation must not relabel E06 `BLOCKED`, E07 `SCOPED_PASS`, MVP 1D D02/D07 `BLOCKED`, or any original MVP/release verdict.

## Consequences

- Documentation may state that MIPS/MIPSEL use common locked init, one-shot and persistent contracts where E02–E05 prove them.
- Documentation must state that E06 is acceptance-blocked by R1/R2/R3 even though E07 includes newer common-path script observations.
- E07's historical `E08=NOT_EVALUATED` field remains frozen; later reconciliation is recorded in a new ledger rather than editing E07 evidence.
- C3 telemetry remains shadow-only. Runtime attestation is recorded only when independently present; a planned lock is not substituted for it.
- Frozen MVP 1D and original MVP evidence hashes are rechecked, not regenerated.

## Verification

`uv run python -m scripts.validate_m1e07` rehashes reconciled evidence and predecessor records, checks E01–E08 status relationships, verifies C3 shadow telemetry constraints and ensures required documentation/ADR markers exist. `uv run python -m scripts.validate_m1e06` remains the retained E07 raw-evidence validator.
