# Autorouting audit correction — 2026-09-25

## Scope

This change applies the approved variant A prospectively: use `gpt-6-sol/high` (C4) for bounded engineering, evidence, release, and audit work; reserve `gpt-6-sol/xhigh` (C5) for an explicit bounded C5 factor; keep Astra escalation-only; preserve safety floors and historical runtime truth.

Historical frozen routes and terminal outcomes were not rewritten. The completed project state remains 32/32 with the recorded historical distribution C0=1, C2=2, C3=3, C4=11, C5=15 and 32 attested outcomes.

## Backup and changed runtime

Pre-change backup:

`/opt/data/backups/keemu-stack-20260922T073131Z/autorouting-audit-fix-20260925T184213Z`

Live runtime root:

`/opt/data/hermes-durable-vps-hostinger-router-v1`

Live project config:

`/opt/data/hermes-supervisor-configs/keemu.json`

The exact runtime/config diff is retained in `docs/evidence/autorouting-runtime-patch-2026-09-25.diff`.

SHA-256:

- runtime/config patch: `5816d750092421bb10aba6a2124b6c3af49a555d79213db8230f46fb582d3caf`
- live KEEMU supervisor config: `eaafaa088d2fef6fc7cdaea847fc2a0f63268adabde043bd19df6960237ef3b1`
- live `router/signals.py`: `6feb5334313f39c28d3560e145038d2bd92876058bb25d81cb3f9ee24a286b0a`
- live `router/router.py`: `08cd695ef9a08c9aa6de5b887281b853b910e6d58aeba5dda75cfac953d2c3d8`
- read-only shadow replay: `eb8aa48311c51acecd90e04e2474549c740ddb623c84a963ac4da192aa185eba`

## Corrections

1. Active-subtask objective and metadata are authoritative for complexity scoring. Aggregate `TASK.md`, project backlog, checkpoints, long prose, repository size, and Graphify size no longer inflate the active route.
2. Normalized safety context remains available only as fixed labels and binds to an affirmative mutating action. Constraint/prohibition text, documentation, mocks, local fixtures, and the noun `implementation` do not create protected intent. Real production/SSH/credential/firewall/kernel actions retain a C4 floor.
3. Blast radius counts changed source/config files only; `.agent/`, `graphify-out/`, backups, docs, and generated bookkeeping are excluded.
4. Structural complexity is explicit through `planned_change_count` and `component_count`; low gate-closure plus low diagnostic risk can reduce unprotected evidence work by one score step.
5. C5 requires a bounded factor. Explicit validated `c5_factors` create the C5 floor; lexical factor detection can justify a score-derived C5 but cannot create a C5 floor by itself. Score-only promotion without a factor is capped at C4.
6. Planned C5 items fail closed when `require_c5_justification=true` and no recognized factor is present.
7. Astra requires explicit approval with basis `evidenced_c5_failure` or `shadow_review`; global availability alone is insufficient.
8. Continuations reuse the original route-decision event. Learning accepts only unique linked `supervisor` → `supervisor_outcome` pairs with terminal evidence, exact route linkage, successful runtime attestation, session deletion, and no quota/human/timeout state. Fixtures cannot authorize policy promotion.
9. Learning remains shadow-only and canary remains disabled.

## Prospective plan calibration

The supervisor config is explicitly `routing.mode=shadow` with `require_c5_justification=true`.

Prospective frozen plan distribution:

- C0: 1
- C2: 2
- C3: 3
- C4 / `gpt-6-sol/high`: 15
- C5 / `gpt-6-sol/xhigh`: 11

C5 falls from 15 historical assignments to 11 prospective assignments: four bounded audit/evidence/event tasks move to C4, a 26.7% relative reduction. The retained 11 C5 items carry explicit factors for kernel/network namespaces, security boundaries, crash recovery, concurrency, cross-component invariants, high side-effect risk, or foreign-resource preservation.

Historical `.agent/STATE.json` remains unchanged: `final-31` still records its actual C5/xhigh route.

## Verification

Runtime tests, executed inside the live Hermes container and venv:

```text
Ran 92 tests in 2.545s
OK
```

Additional checks:

- `python -m compileall -q router supervisor tests`: PASS
- config JSON parse and fresh 32-item plan initialization: PASS
- every prospective C5 item has a recognized explicit factor: PASS
- active-subtask source used for all 32 replayed items: PASS
- shadow replay C5 without explicit factor: 0
- shadow replay Astra recommendations: 0
- shadow replay distribution on the current project context: C0=13, C4=8, C5=11
- no matching live KEEMU supervisor process found in the current container namespace
- runtime/config secret scan found only regex/test-fixture literals, no credential value

The OAuth usage observation during final verification was 4% remaining in the five-hour window. No new worker or independent model-review task was launched below the 5% threshold. This does not alter the completed local test and shadow evidence; live automatic routing remains disabled pending later reviewed shadow telemetry.

## Unchanged release truth

This router correction does not change product acceptance:

- A01: PASS only for the defined three-target execution check
- A02–A21: BLOCKED
- Release/MVP 1: BLOCKED
- historical route events, model attestations, and quota incidents remain immutable
