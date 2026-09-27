# ADR-0019: MVP 1D documentation is a pre-final, bounded reconciliation

Status: accepted for `m1d-12`; independent `m1d-13` audit remains pending.

## Decision

Keep MVP 1D D01–D08 separate from the frozen original MVP 1 A01–A21 and
final-28/final-29/final-31 results. Publish a new hash-bound reconciliation at
`docs/evidence/mvp1d-m1d12-reconciliation.json`; do not edit the m1d-00
NOT_RUN scope snapshot or any original MVP 1 ledger. Its `SCOPED_PASS` entries
(D01/D03/D04/D05/D06) describe the bounded tested implementation, not an
independent final gate decision. D02/D07 are BLOCKED despite their passing
routine and adversarial subcases. D08 remains PENDING_FINAL_AUDIT until m1d-13.

The actual AArch64 Docker/binfmt JUnit at `reports/m1d11-live.xml` records
39 PASS/0 FAIL/0 SKIP; the portable JUnit records 339 PASS/0 FAIL/44
intentional SKIP. The MIPS/MIPSEL CLI reports are actual BLOCKED/exit 4 before
Docker allocation; target-ELF probes do not supply a general locked script
lifecycle. Source locks, schema parity, one-shot/persistent CLI, typed redacted
reports, scenario checks and ordinary timeout cleanup are bounded evidence.

Untrusted raw script stdout/stderr, argv and assertion values remain in memory:
published reports use byte counts, SHA-256 identities and truncation flags. A
failed/uncertain cleanup is ERROR rather than PASS. Test-owned explicit cleanup
after SIGKILL is not a production recovery mechanism. The persistent crash
left an exact target artifact despite preserving the running service; no
interrupted report was written. A checked target inode before unlink does not
prove an atomic conditional unlink against a hostile concurrent same-UID
process. Do not claim D02/D07 whole-gate success or infer normal timeout proof
from an interrupted worker's eventual observed shell absence.

## Consequences

README, architecture, limitations, progress, traceability, D-066 and durable
checkpoint/journal describe only already observed behavior. No product code,
Docker image, host configuration, original MVP 1 status or historical evidence
is changed by this documentation subtask. The m1d-13 reviewer must assess the
remaining race/recovery/report gaps and publish the independent D01–D08
release status without silently promoting `SCOPED_PASS` or test-owned teardown.

## Verification

Rehash all bound source/raw paths and recount JUnit cases; check D01–D08
exactly once, source/test paths and documentation links. Run portable pytest,
Ruff lint, applicable format checks, `git diff --check`, and original final-28/
final-29 validators. Retain missing integration or format prerequisites as
explicit blockers instead of fabricating results.
