# KEEMU MVP 1E amended subtask and routing plan

Original freeze: 2026-09-27
Prospective Sol migration: 2026-09-30
Branch: `staging`
Current policy boundary: C3=`gpt-5.6-terra/high`; C4=`gpt-6.1-sol/high`; C5=`gpt-6.1-sol/xhigh`; Astra not planned.

User approved controlled C3 calibration before launch. On 2026-09-30 the user explicitly replaced every current and future Sol route with `gpt-6.1-sol`. Router and learning remain shadow-only; `routing.apply_approved_subtask_routes=true` applies these rows as explicit worker locks.

Completed runtime history remains immutable: route events and completed state rows retain the model that actually ran, including earlier `gpt-6-sol` attestations. The pending `m1e-05r` `gpt-6-sol` session never attested and was superseded by a new-session requirement.

| # | ID | Objective | Route | Bounded basis |
|---:|---|---|---|---|
| 0 | `m1e-00` | Read-only scope, lock, capability and route review | C3 / Terra high | No product/runtime/config mutation; deterministic hashes and capability inventory |
| 1 | `m1e-01` | Implement deterministic locked `generic-mips` init cache | C4 / Sol 6.1 high | Bounded extension of verified AArch64 cache pattern |
| 2 | `m1e-02` | Implement deterministic locked `generic-mipsel` init cache | C4 / Sol 6.1 high | Same common cache contract with independent target evidence |
| 3 | `m1e-03` | Generalize one-shot production lifecycle to MIPS/MIPSEL | C4 / Sol 6.1 high | Multi-component lifecycle integration through existing contracts |
| 4 | `m1e-04` | Generalize persistent lifecycle and explicit recovery | C5 / Sol 6.1 xhigh | `crash_recovery`, `foreign_resource_preservation` |
| 5 | `m1e-05` | Integrate MIPS/MIPSEL script execution through existing common primitives | C3 / Terra high | Controlled engineering trial: ≤5 source/test files; no primitive or boundary redesign |
| 6 | `m1e-05r` | Independent read-only review of the C3 engineering trial | C4 / Sol 6.1 high | Validate scope, tests, parity and blockers before acceptance |
| 7 | `m1e-06` | Run three-target interruption/recovery/isolation verification | C5 / Sol 6.1 xhigh | `concurrency_control`, `crash_recovery`, `foreign_resource_preservation` |
| 8 | `m1e-07` | Reconcile evidence and documentation | C3 / Terra high | No runtime mutation; deterministic hash/test/doc reconciliation |
| 9 | `m1e-08` | Independent final audit and milestone verdict | C4 / Sol 6.1 high | Cross-target audit; no product mutation |

Distribution: C3=3, C4=5, C5=2, Astra=0.

## Fail-closed C3 escalation

A C3 worker must stop with typed blocker/failure evidence if work requires architecture redesign, more than the frozen file/component limit, changes to ownership/cleanup/recovery/process-tree/report semantics, host binfmt mutation, or cannot satisfy deterministic tests. Retry is a new C4 worker session after a durable boundary; no mid-session model switch.

One successful sample does not change policy. Telemetry is retrospective/shadow-only.