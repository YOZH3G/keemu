# KEEMU MVP 1D frozen subtask and routing plan

Date: 2026-09-26
Branch: `staging`
Policy boundary: C4=`gpt-6-sol/high`; C5=`gpt-6-sol/xhigh`; Astra not planned.

`m1d-00` is the only authorized launch before route-table approval. It runs as a fixed C4 shadow review and pauses at its terminal boundary. Implementation items remain inert until independent review and explicit approval.

| # | ID | Objective | Route | Bounded basis |
|---:|---|---|---|---|
| 0 | `m1d-00` | Freeze threat model, D01–D08 ledger, architecture boundary, fixtures, and review this plan | C4 / Sol high | Bounded architecture/evidence review |
| 1 | `m1d-01` | Implement `ScriptInput`, no-follow secure open, containment, bounds, digest, and mutation detection | C5 / Sol xhigh | `complex_security_boundary` |
| 2 | `m1d-02` | Implement typed `/opt/tmp` staging, no-overwrite, identity/readback integrity, and exact cleanup | C5 / Sol xhigh | `complex_security_boundary` |
| 3 | `m1d-03` | Add typed execution/result/report models and deterministic status mapping | C4 / Sol high | Bounded multi-component model change |
| 4 | `m1d-04` | Implement bounded target process-tree timeout, TERM/KILL, reaping, and survivor proof | C5 / Sol xhigh | `concurrency_control`, `crash_recovery` |
| 5 | `m1d-05` | Implement and verify one-shot AArch64 script lifecycle through existing runtime | C4 / Sol high | Bounded integration using verified runtime |
| 6 | `m1d-06` | Add `keemu script` CLI with argv/cwd/timeout/expected-exit contracts | C3 / Terra high | Local CLI integration |
| 7 | `m1d-07` | Add persistent `keemu exec --script` without disturbing unrelated environment state | C5 / Sol xhigh | `foreign_resource_preservation` |
| 8 | `m1d-08` | Add exit/stdout/stderr/filesystem assertions and PASS/FAIL/BLOCKED/ERROR tests | C4 / Sol high | Bounded report/assertion integration |
| 9 | `m1d-09` | Add scenario `kind: script`, immutable-input lock, JSON schema parity, and compatibility tests | C4 / Sol high | Bounded schema/runtime integration |
| 10 | `m1d-10` | Exercise MIPS/MIPSEL through the common contract; record PASS or truthful BLOCKED | C4 / Sol high | Cross-target verification, no bypass |
| 11 | `m1d-11` | Verify TOCTOU races, interruption, cleanup retry, collision, host isolation, and foreign preservation | C5 / Sol xhigh | `concurrency_control`, `crash_recovery`, `foreign_resource_preservation` |
| 12 | `m1d-12` | Reconcile D01–D08 evidence and update docs/ADRs/traceability | C4 / Sol high | Bounded release evidence closure |
| 13 | `m1d-13` | Independent final audit and release decision for MVP 1D only | C4 / Sol high | Evidence audit; no product mutation |

Distribution: C3=1, C4=8, C5=5. C5 is factor-bound; no percentage target or Astra route.
