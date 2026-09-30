# MVP 1E — m1e-06 / E07 bounded three-target adversarial verification

Date: 2026-09-30. Branch: `staging`. Starting commit: `c736422`.
Frozen digest: `1bd33eb6b7da79a9a2848c43efc11290dcd8548870be20cddd43c6ed9f317eff`.

## Verdict and boundary

This verification subtask is complete. E07 is `SCOPED_PASS` for the named real bounded matrix below. This is not E06 acceptance, product hardening, automatic crash recovery, or a milestone release verdict. E06 remains `BLOCKED` by the frozen independent review; MVP 1D D02/D07 remain `BLOCKED`. E08 and the milestone release verdict are `NOT_EVALUATED`; no later subtask was performed.

Machine-readable ledger: `docs/evidence/mvp1e-m1e06-adversarial.json`, SHA-256 `8ec2a6dce775eddefe5d7b498adbe07d6cb17efc7b0c02116d401108bf974a00`.
Independent verification supplement: `docs/evidence/mvp1e-m1e06-verification.json`.

The write-once ledger retains 142 exact raw artifacts, including 47 schema-validated `RunReport` JSON files, under `docs/evidence/raw/mvp1e-m1e06/`. Three final verification supplements are separately hash-bound in the verification supplement. Original paths, retained paths and exact SHA-256 values are recorded. New execution is not presented as recovered historical C3 RED/GREEN.

Final publication preflight found the unchanged root `reports/` ignore rule also excluded nested archived report copies. A subtask-local `.gitignore` unignores only archived `reports/` beneath `docs/evidence/raw/mvp1e-m1e06/`; root policy and live reports remain ignored. `docs/evidence/mvp1e-m1e06-publication.json` binds that rule and records independent Git visibility of all 142 core plus three supplemental retained artifacts and zero high-confidence secret findings. Supervisor owns staging, terminal attestation and commit/push after the worker marker; no worker commit is claimed.

Only four new verification/evidence Python files were added:

- `tests/integration/m1e06_support.py`
- `tests/integration/test_m1e06_adversarial.py`
- `scripts/freeze_m1e06.py`
- `scripts/validate_m1e06.py`

Product code, existing tests, profiles, locks, schemas, host handlers and historical ledgers were unchanged. In particular, the protected script input/stage/process/assertion/report and registry/ownership/recovery primitives were not redesigned.

## Actual test results

| Retained JUnit | PASS | FAIL | ERROR | SKIP | Meaning |
|---|---:|---:|---:|---:|---|
| `adversarial-boundaries.xml` | 12 | 0 | 0 | 0 | Three-target stage/input/collision, IPK/script collision, one-shot interruption and persistent-create recovery |
| `adversarial-remainder.xml` | 4 | 0 | 0 | 0 | Three-target persistent timeout/service/interruption plus simultaneous cross-target isolation |
| `one-shot-outcomes.xml` | 3 | 0 | 0 | 0 | Three-target literal argv, exit mismatch/expected exit and cleaned timeout |
| `init-regression.xml` | 22 | 0 | 0 | 0 | Actual offline verification, target smoke, independent MIPS-family builds, corruption/no-replace/handler-negative cases |
| `lifecycle-regression.xml` | 17 | 0 | 0 | 1 | MIPS/MIPSEL one-shot and persistent lifecycle, AArch64 lifecycle/service/script regressions; historical persistent SIGKILL test intentionally not repeated |
| `script-regression.xml` | 8 | 0 | 0 | 0 | Existing AArch64 staging/process/one-shot and explicit recovery tests; two stale architecture cases deselected here and run separately |
| `portable.xml` and final supplement `portable-final.xml` | 353 | 0 | 0 | 84 | Portable suite; live opt-ins intentionally skipped |
| `stale-architecture-regression.xml` | 0 | 2 | 0 | 0 | Actual current-tree regression failure: removed BLOCKED expectation conflicts with enabled MIPS/MIPSEL execution |

The three adversarial JUnits contain exactly 19 unique PASS cases, verified programmatically with no double-counting. Negative target outcomes retain their own `FAIL`, `BLOCKED` or `ERROR`; a passing verifier does not rewrite those reports to PASS.

Two initial new-harness failures are retained separately: `adversarial-initial.xml` has 1 FAIL; `adversarial-final.xml` has 12 PASS/1 FAIL. These are not acceptance PASS totals. Two interrupted foreground attempts have no completed JUnit and are not counted from progress dots.

## Matrix observed on every target

Targets: `generic-aarch64` / `aarch64-3.10`, `generic-mips` / `mips-3.4`, and `generic-mipsel` / `mipsel-3.4`. Each used its own offline-verified production init image and the existing common APIs, not the old target-probe image or a separate architecture executor.

1. Same-byte host source inode replacement was rejected. Mutation after the secure recheck could not change the pinned target digest. A deterministic staging nonce collision preserved the existing target object and did not acquire cleanup authority.
2. Injected exact target cleanup refusal retained the issued object; retry with the original in-memory staging authority succeeded. Replacing the target inode with different test-owned bytes caused cleanup refusal and preserved those bytes. Whole test-owned container teardown, not pathname adoption, removed the replacement afterward.
3. Real IPK install/check/remove succeeded. A pre-existing exact run container was preserved across both IPK and script collision reports, which remained `BLOCKED`; only its test owner removed it.
4. Exact host workers were SIGKILLed after one-shot allocation, after target staging, and during active target execution. No interrupted PASS/report was fabricated. In the active case the independently observed shell and child PIDs became absent within the bounded 12-second wait. Recovery verified the full container ID, deterministic name and owner/run/base/target labels before explicit test-owned removal and absence readback.
5. Real persistent creators were SIGKILLed before container ID publication and after start/before install. A second process could not acquire the held name lock. Extra same-run resources caused recovery refusal without removing the legitimate resource. Injected removal refusal retained transitional state; subsequent public `recover` removed exactly the expected ID, yielded a consistent tombstone, and was idempotent.
6. Persistent script success and cleaned timeout used the common runner and retained typed reports. Timeout was `FAIL` with process-tree-clean proof and independently absent child PID; an unrelated target process, original service PID/container state, HTTP health and postinst count were preserved.
7. Persistent host-worker SIGKILL after stage retained the running environment/service and the exact staged artifact, with no report. The healthy public recovery path refused adoption. Public `down` then `destroy` removed the entire test-owned environment and produced a consistent tombstone. This is not automatic artifact recovery.
8. One-shot literal argv succeeded without shell reinterpretation; unexpected exit 7 was `FAIL`, expected exit 7 was `PASS`, and cleaned timeout was `FAIL`. Target and container cleanup were verified independently of the primary result.

A simultaneous three-worker barrier proved that all three target stages coexisted before execution. They had different full container IDs and generated target paths, and the same target pathname held only its own target's value. All three executions passed, cleaned their resources, and observed no host sentinel environment, Docker socket or host project path. Persistent same-name concurrency was separately refused while the real worker held the registry lock.

## Preservation and exact cleanup

Preflight and postflight snapshots are retained, not inferred from test exit codes:

- KEEMU-owned Docker containers/networks: 0/0 before and after.
- The same two unrelated containers retained their exact IDs, image/name/label/state snapshots.
- The same four existing networks retained identity, configuration and original endpoints; the same 52 volume IDs remained.
- Test-owned foreign-run containers and internal bridge sentinels were checked unchanged during each live case, then removed by their own exact IDs.
- All 182 protected tracked source/test/lock/profile/historical-evidence files and all 880 pre-existing registry files were byte-preserved.
- All 47 newly issued test environment records ended as consistent destroyed tombstones. This includes explicitly recorded extra teardown of two legacy regression records described below; it is not a claim that every old harness tears down its registry correctly.
- All three locked production caches remained offline-verifiable with the same pinned image IDs. Fresh approved read-only host `qemu-mips`/`qemu-mipsel` readbacks matched the locks and their preflight bytes; observer containers and anonymous volumes were absent afterward. No handler was installed, replaced or modified.

## Failures, harness incidents and unresolved limitations

### Frozen E06 findings remain

The unchanged legacy architecture regression actually failed twice at `tests/integration/test_script_lifecycle.py:419`: runtime returned `PASS`, while the test still requires `BLOCKED`. Both runtime reports and the failure JUnit/log are retained. This establishes the previously source-only R3 finding with real current-tree evidence, without correcting that old test or rewriting MVP 1D's historical BLOCKED observation.

The defective `m1e-05` teardown test was not rerun merely to create more stale records. Fresh E07 common-path tests used public down/destroy and retained their reports and tombstone checks. The six prior `m1e05` stale records and all other prior registry files were untouched. Missing historical C3 RED/GREEN evidence remains missing; these fresh results do not retrospectively validate its TDD ordering or calibration sample.

### Additional legacy registry teardown observation

The existing AArch64 persistent script regression (`tests/integration/test_lifecycle.py:999-1004`) directly removes its container after script checks, leaving the newly issued `persist-script-224799cdba3f` record `running` with an absent recorded container. Public `recover` correctly refused with `healthy environment; recovery refused`. This is retained as a cleanup/recovery limitation, not hidden by its passing test JUnit.

Only that exact newly issued test record received explicit test-owner teardown: prove its full recorded ID and run, preserve the scenario/record identity under the per-name flock, verify the full Docker ID and owned-resource absence, then use the existing compare-checked `running -> failed` registry transition followed by public recovery. The separate newly issued failed-postinst record was tombstoned using ordinary public recovery. `legacy-registry-teardown.json` retains both results and the distinction. This manual test-owner repair is not public stale-running recovery, and no pre-existing record was repaired.

### New harness corrections and tool deadlines

The first harness comparison wrongly counted new network-none Docker endpoints as changes to unrelated endpoints on the built-in `none` network. The corrected comparison still requires every prior endpoint/configuration to remain identical, permits only new exact project-owned endpoints during the test, and requires complete snapshot equality after teardown.

The second harness omitted the immutable AArch64 web fixture's UDP port/state arguments. Only the new harness invocation/readiness expectation was corrected to match that existing fixture. The failed new environment was explicitly recovered and the failure retained; no fixture or product change was made.

Foreground 420/300-second tool deadlines interrupted two larger sweeps. Each exact remaining new test container/network was inspected, owner/ID/name verified, removed and read back absent. Their progress dots are not test counts. Completed bounded batches and background commands subsequently produced the three acceptance JUnits. Raw deadline cleanup records are retained.

The unchanged older MIPS lifecycle regression overwrote its two fixed ignored observation paths. Fresh regression bytes were saved under E07 paths. Original bytes were reconstructed only from the preserved original report bundles, required to match the exact frozen original SHA-256 before any restoration, and independently rechecked afterward. Both original raw observations, their original source reports, fresh observations and the restoration record are retained. Historical ledgers/hashes were not changed.

### Product limitations not promoted

Hostile concurrent same-UID stat-to-unlink safety is not atomically proved; persistent SIGKILL artifacts lack automatic production recovery/interrupted reports; one-shot crash cleanup is explicit test-owned recovery. D02/D07 remain BLOCKED. No whole firewall/socket census, hard disk quota, fresh-Ubuntu runner, direct target HTTPS or host-firewall parity is claimed. No binfmt/module/firewall/namespace/credential/routing-policy mutation was performed; Docker-managed firewall changes were not enumerated.

## Independent verification and runtime

`uv run python -m scripts.validate_m1e06` independently rehashes all retained artifacts and source bindings, schema-validates 47 typed reports, checks declared JUnit counts and 19-case uniqueness, validates all three matrix dimensions, verifies actual SIGKILL/recovery/tombstone records, preserves blockers and checks complete pre/post preservation.

Positive validation PASS. Wrong declared JUnit counts, duplicate cases and false failure totals were rejected. Manifest wrong-count, wrong-source-hash and D07-to-PASS promotion probes were also rejected. Their exact errors are retained. The freezer was exercised to produce the real write-once artifact, not just supplied as a command.

Final portable suite: 353 PASS/84 intentional SKIP. Ruff lint/format on all four new Python files and `git diff --check` PASS. Original final-28/final-29 read-only validators PASS with their frozen `BLOCKED` release results; final-29 retains its original 233 PASS/2 prerequisite FAIL/3 SKIP truth.

Actual canonical runtime metadata: session `20260930_065401_5153d2`, billing provider `openai-codex`, model `gpt-6.1-sol`, reasoning `{enabled: true, effort: xhigh}`. The supervisor's exact subtask-bound admission was at `2026-09-30T06:53:55+00:00`, 58% remaining. Terminal attestation, boundary commit/push and disposable-session deletion remain supervisor-owned. No E08 documentation reconciliation or final audit was attempted.
