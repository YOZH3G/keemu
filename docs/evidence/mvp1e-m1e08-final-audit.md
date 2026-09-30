# MVP 1E — m1e-08 independent final audit

Frozen subtask: `m1e-08`.
Digest: `29349c92ec0deee393e5c03aa48f863e4e0ab02e5fcc47267a07cc8d6ffbc97e`.
Audit date: 2026-09-30. Reviewed branch: `staging` at
`51f0b411a200fc94c84dce10fced833fd57807b1`.

Audit completion: PASS. MVP 1E milestone: BLOCKED. MVP 1E release: BLOCKED.
Release checks: FAIL. Evidence closure does not mean product acceptance or
completion of the supervisor's final publication/session boundary.

## Exact E01–E08 verdicts

| Gate | Final status | Independently checked scope / decisive evidence |
|---|---|---|
| E01 | PASS | Scope/lock/capability/route review froze architecture seams and safety boundaries before implementation. Two profile and eight predecessor lock hashes rechecked; historical missing-image/binfmt-visibility observations remain at their original timestamp. `mvp1e-m1e00-acceptance.json` and `mvp1e-m1e00-scope-review.md`. |
| E02 | PASS | Common schema-5 deterministic MIPS cache: independently guarded rebuild, target smoke, exact inventory/native-init/rootfs/OCI/archive binding, no-replace and corruption refusal. Retained JUnit: guarded rebuild 1 PASS, real suite 15 PASS. Current read-only offline verification PASS. `mvp1e-m1e01-init-mips.json`. |
| E03 | PASS | Same schema-5 common cache with independent MIPSEL locks and little-endian ELF audit. Retained real JUnit 22 PASS, independently rebuilt canonical identity, current read-only offline verification PASS. AArch64 schema-4 and MIPS locks preserved. `mvp1e-m1e02-init-mipsel.json`. |
| E04 | PASS | Common three-target one-shot IPK dispatch, real target opkg, success/negative/input/collision/cleanup outcomes and AArch64 regression. Retained JUnit 4 PASS; both original observation files and 12 typed reports rehashed and validated. Injected cleanup ERROR and primary install FAIL are preserved, not acceptance-test failures. `mvp1e-m1e03-one-shot.json`. |
| E05 | PASS | Common persistent IPK service/state/lifecycle and explicit owner-verified recovery, full-ID/name/label binding, flock, tombstones and foreign/extra-resource refusal. Retained MIPS-family JUnit 2 PASS; AArch64 lifecycle 3 PASS and recovery 1 PASS. Source and real interruption/recovery assertions inspected. `mvp1e-m1e04-persistent.json`. |
| E06 | BLOCKED | R1 defective teardown/stale registry, R2 missing independent historical C3 RED/GREEN evidence, R3 obsolete current-tree architecture regression. Source/test limit 4/5 and unchanged primitives/common-path parity pass, but do not accept engineering. `mvp1e-m1e05r-independent-review.json`; later E07 raw results preserve the findings. |
| E07 | PASS | Named bounded verification-observation gate: 19 unique real adversarial PASS across all three targets, 47 typed reports, 142 core raw artifacts and three supplements; exact collision/mutation/timeout/SIGKILL/explicit recovery/cleanup/concurrency/isolation/foreign preservation outcomes audited. Historical source verdict remains SCOPED_PASS. Two actual obsolete architecture-test FAILs and diagnostic harness failures are retained separately. This is not a whole product-hardening or all-regressions-green PASS. `mvp1e-m1e06-adversarial.json`. |
| E08 | PASS | m1e-07 reconciliation plus this independent final audit publishes all eight exact statuses, architecture matrix, hashes/counts, limitations, quality failures, C3 telemetry and preserved predecessor verdicts. Current README pair, architecture, limitations, progress and traceability identify this separate final verdict. No product correction or history replacement. |

PASS means the named bounded gate has verified evidence. FAIL means an
executed check contradicted its expected result. BLOCKED means a required
acceptance proof/resolution is absent. ERROR means a harness or required
cleanup contract failed; no new unhandled final-audit ERROR was observed.
These meanings preserve negative package/timeout/cleanup reports rather than
rewriting them to PASS because their verifier test passed.

## Three-target matrix

| Profile | Init | One-shot IPK | Persistent IPK/recovery | Scripts | Adversarial observation |
|---|---|---|---|---|---|
| generic-aarch64 | PASS, retained schema-4 base/current offline check | PASS regression | PASS regression | Common path has retained current E07 execution; E06 acceptance BLOCKED globally | PASS at bounded E07 gate |
| generic-mips | PASS, E02/current offline check | PASS, E04 | PASS, E05 | Common path exercised in E07, not a target-probe bypass; E06 acceptance BLOCKED globally | PASS at bounded E07 gate |
| generic-mipsel | PASS, E03/current offline check | PASS, E04 | PASS, E05 | Common path exercised in E07, not a target-probe bypass; E06 acceptance BLOCKED globally | PASS at bounded E07 gate |

The audit directly called `_inputs` and `_verify_cache` on all three pinned
prepared caches, validating package/feed/bootstrap/QEMU/native bytes, rootfs,
inventory, saved image and Docker-local image identity. It did not call
`init_locked`, whose offline entry point writes a cache lock file. No image
load/build, target execution, binfmt observer allocation or host mutation was
performed. Latest retained E07 exact-handler readbacks are historical; this
read-only audit does not invent a fresh host-handler observation.

Four MIPS source/test hashes in the E02 ledger legitimately differ from the
current tree because E03 added MIPSEL support. All four match their original
Git blobs at E02 publication commit `ccd731a5217e35d8fbbadbf0446f55ea469ce0bc`;
the later E03 source hashes match the current tree. Fourteen historical
source bindings were independently reverified against their publication
commits, not silently compared with a different revision. Thirty-five
profile/lock/protected bindings and 13 earlier JUnit files were checked.
Historical test runs overlap; no misleading aggregate total is claimed.

## Acceptance blockers, not audit blockers

R1 remains reproducible in unchanged source: `test_m1e05_scripts.py:93-99`
calls destroy while running, catches the common refusal and removes Docker
resources directly. `persistent.py:681-685` requires down first. Six exact
prior M1E05 registry records remain running while their recorded containers
are absent; their hashes are unchanged. Docker 0/0 is not registry consistency.
No stale record was repaired by this audit.

R2 remains historical: original m1e-05 reports were written to temporary
paths and deleted. Its claimed RED 0 PASS/2 FAIL, live GREEN 2 PASS and full
355 PASS/63 SKIP cannot be independently reverified. New E07 immutable
reports prove current bounded execution, not the original TDD ordering or
C3 first-pass calibration. No backfilled historical result is claimed.

R3 now has actual retained FAIL evidence: the unchanged opt-in architecture
test expects BLOCKED but enabled MIPS/MIPSEL execution returns PASS.
Retained JUnit is 0 PASS/2 FAIL/0 ERROR/0 SKIP. Fresh portable skips do not
replace this result. No old test assertion was edited.

MVP 1D D02/D07 remain separately BLOCKED: hostile concurrent same-UID target
stat-to-unlink safety is not atomic, and persistent worker SIGKILL leaves a
staged artifact without production crash-artifact recovery or an interrupted
report. One-shot SIGKILL cleanup is explicit test-owned recovery; persistent
IPK recovery is not script-artifact recovery. E07's test-owned teardown of
one newly issued legacy AArch64 stale-running record is not a public recovery
feature. Architecture enablement does not close these predecessor blockers.

## Verification and retained failures

- Fresh portable: 353 PASS, 0 FAIL, 0 ERROR, 84 opt-in SKIP; actual JUnit retained.
- Retained unique adversarial acceptance: 12 boundary + 4 persistent + 3
  one-shot-outcome cases = 19 unique PASS, independently deduplicated.
- Retained applicable E07 regressions: init 22 PASS; IPK lifecycle 17 PASS/1
  SKIP; script/stage/process/recovery 8 PASS; stale architecture 2 FAIL.
- The 47 typed E07 reports retain 19 PASS, 13 FAIL, 13 BLOCKED and 2 ERROR.
  The 12 original E04 reports retain success and expected negative outcomes,
  including two injected cleanup ERROR reports. Report status is not verifier
  test status. Earlier diagnostic failures/tool interruptions are not counted
  as successful adversarial acceptance cases.
- Existing m1e-06, m1e-07, final-28 and final-29 read-only validators exit 0.
  The predecessor final-29 sweep remains 233 PASS/2 prerequisite FAIL/3 SKIP.
- Repository lint: FAIL, three E501 errors at unchanged
  `scripts/validate_m1e07.py:48`, `:71` and `:86`. Audit finding F1.
- Repository format: FAIL, eight untouched files: `scripts/validate_m1e07.py`,
  `src/keemu/doctor.py`, `src/keemu/entware.py`, `src/keemu/models.py`,
  `src/keemu/p0_web_demo.py`, `tests/integration/p0_web_demo_probe.py`,
  `tests/integration/test_lifecycle.py`, `tests/integration/test_m1a16_recovery.py`.
  Audit finding F2. No formatting correction is authorized here.
- New read-only audit validator lint/format PASS. Its positive replay and
  in-memory negative verdict/hash/count/promotion probes are published
  separately in the final verification supplement.

The portable suite is not entirely read-only: its two existing static-defect
cases (`test_lifecycle.py:648-672`) create zero-byte random per-name registry
lock files before refusing the defective input. Both exact new paths were
absent at baseline; no environment directory was created. Cleanup checked
regular/single-link/current-UID/private-mode/zero-byte inode identity and
acquired exclusive nonblocking flock, then unlinked only those two new test
locks and independently verified absence. Audit finding F3, captured in
`raw/mvp1e-m1e08/portable-lock-cleanup.json`. All 1,035 prior registry files
remain byte-identical and final inventory matches baseline exactly. This
incidental test-side-effect/cleanup is disclosed, not labelled zero runtime
writes or a production stale-state repair.

## Preservation and C3 telemetry

All 168 protected product/test/profile/lock/schema/fixture/config inputs and
229 previously tracked evidence/milestone/script/predecessor files remain
byte-identical. Frozen original MVP 1 and MVP 1D task/state/audit hashes match
m1e-07 reconciliation. Original MVP 1 and MVP 1D release remain BLOCKED;
prior E07 E08=NOT_EVALUATED and m1e-07 final-audit-pending fields are preserved
at their historical timestamps. Current docs add the later verdict separately.

Docker before/after: the same two unrelated containers, four networks and
52 volumes; no project-owned containers/networks. No Docker, image-store,
host binfmt/module/firewall/namespace/public-exposure/credential/routing-policy
mutation occurred. Six prior stale registry records are preserved, not erased.

Nine predecessor subtask rows and linked route/outcome events record terminal
ATTESTED and session_deleted=true. Their actual historical models are retained;
all nine supervisor learning outcomes have empty verification_evidence,
completed_verified=false and learning_accepted=false. Independently bound
product evidence is distinct from this telemetry limitation. No C3 scorer or
learning policy was promoted. C3 samples remain m1e-00, m1e-05 and m1e-07;
this audit adds F1/F2 quality observations for the unchanged m1e-07 validator
rather than rewriting that sample's earlier record.

Actual current session metadata independently read from the local session
database: `20260930_113730_31360a`, `openai-codex/gpt-6.1-sol`, reasoning
`{enabled: true, effort: high}`. This matches the frozen C4 lock. Fresh
subtask-bound admission is 85% at `2026-09-30T11:37:23+00:00`. Matching runtime
metadata is not an invented terminal supervisor attestation.

## Publication boundary

The audited parent was independently read back from origin/staging as
`51f0b411a200fc94c84dce10fced833fd57807b1`; main and post-mvp were observed,
not changed. This worker publishes only new audit evidence/validator, current
MVP 1E documentation and additive durable records in the staging worktree.
The external supervisor alone owns terminal attestation, coherent commit/push,
remote readback and disposable-session deletion after the exact frozen marker.
No later subtask, remediation, merge, history rewrite or full-task completion
is claimed. The audit is complete even though its truthful product/release
verdict is BLOCKED.
