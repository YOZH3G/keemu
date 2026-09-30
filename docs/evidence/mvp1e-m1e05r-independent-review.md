# MVP 1E — m1e-05r independent C3 engineering review

Date: 2026-09-30. Reviewed engineering boundary: `3978cc001aec7d871ce0ba8d80bb38fae6b462ae`, parent `84d4f66`. Review checkout: `f9c299d9bc4daf361a01de0b6a5235397b057a9f`, branch `staging`.

## Verdict

The independent review is complete. Frozen file-limit compliance, unchanged primitives and common-path source parity PASS. E06 acceptance is BLOCKED by findings R1–R3 below. This is a completed review with blocking findings, not acceptance of the engineering result, a release verdict, or permission to implement corrections in this worker.

Machine-readable evidence: `docs/evidence/mvp1e-m1e05r-independent-review.json`. It embeds the independently collected source/lock hashes, AST checks, current read-only cache results, parsed JUnit counts, exact Docker resource IDs, runtime metadata, historical route/outcome records, and six retained persistent environment records.

No product, test, lock, profile, schema, host configuration or Docker resource was changed by this review. Only review evidence and durable checkpoint/journal publication are authorized. No later subtask was executed. The supervisor retains ownership of terminal attestation, commit/push, disposable-session deletion and any approved corrective boundary.

## R1 — P1: persistent test teardown hides a deterministic failure

Locations: `tests/integration/test_m1e05_scripts.py:93-99`; `src/keemu/persistent.py:681-685`.

The new integration test creates a running persistent environment, then calls `operate(..., "destroy")` without first calling `down`. The existing common contract explicitly rejects a running environment with `RegistryError: destroy needs stopped environment; use down first`. Its broad exception handler hides this error and directly removes every container returned by the run-owned reconciliation query. That fallback does not transition the registry to a destroyed tombstone.

Independent readback found six retained `m1e05-persist-*` records, three for each MIPS-family profile. Every record still says `running`; all recorded containers are absent from the current complete Docker container inventory. These are stale running records, not tombstones. The test's Docker-only final assertions can therefore pass while registry cleanup is wrong. A host-only probe of the exact common `operate()` path, with a mocked running container and all Docker removal prohibited, reproduced the precise stopped-environment refusal. No stale record was altered or recovered.

Required correction in a separately approved worker: use `down` then `destroy`, surface unexpected teardown errors, and independently assert destroyed/consistent registry state as well as exact Docker absence. Any recovery of the six existing stale records must follow an approved exact-ownership recovery path; this review grants no cleanup authority. The fallback is test teardown, not a new production recovery contract.

## R2 — P1: live/TDD evidence is not retained for independent verification

Locations: `tests/integration/test_m1e05_scripts.py:35-45,69-75`; engineering checkpoint/journal; `.agent/runs/20260929T182704Z.log:1-4`; engineering outcome `evt_91ada37246efe4ed54927b7d`.

The engineering checkpoint claims real test-first RED `0 passed, 2 failed`, focused MIPS/MIPSEL GREEN `2 passed`, and a full sweep `355 passed, 63 skipped`. Preserve these historical claims, but do not label them independently verified raw observations in this review.

Both one-shot and persistent report bundles are written beneath a `TemporaryDirectory` and deleted when the test ends. No historical `m1e05` JUnit, RunReport or raw execution artifact was found under `reports/` or `.runtime/`. The surviving files are registry records, scenario snapshots and lock files; they do not establish script execution/assertion/process-tree outcomes. The engineering run log retains the launch command, exact completion marker and session ID, but no RED/GREEN test output. Historical session `20260929_182707_1e903d` is absent from the canonical session database and no matching retained transcript was found. The exported superseded review session contains inspections and worker claims, not the missing engineering execution records.

The linked supervisor outcome is truthful: model attestation is `ATTESTED`, session deletion is true, exit code is zero and continuations are zero; however, `verification_evidence=[]`, `completed_verified=false` and `learning_accepted=false`. Runtime model attestation is not test acceptance evidence. The engineering quota admission was at `2026-09-29T18:27:01+00:00`, 76% remaining, under the exact `m1e-05` digest. The explicit launch was `openai-codex/gpt-5.6-terra/high`, matching the supervisor-recorded attestation. Direct historical runtime metadata cannot be re-read after deletion.

Fresh portable tests and current offline cache verification do not replace missing live script evidence or establish historical RED-before-implementation ordering. Required resolution: recover original raw records if available, or capture new authorized common-path runtime tests with immutable redacted report bundles, JUnit, exact hashes and owner/registry readback. New runs must not be presented as recovered historical RED/GREEN. This read-only review deliberately did not rerun Docker-mutating integration tests.

## R3 — P2: an opt-in architecture regression still expects the removed gate

Locations: `tests/integration/test_script_lifecycle.py:391-437`; `src/keemu/script_lifecycle.py:205-221`.

The current `KEEMU_TEST_SCRIPT_ARCHITECTURES` test still requires both MIPS profiles to return `BLOCKED`, with no container allocation and partial-failure message `ScriptCapabilityUnavailable`. The engineering change removed the only raising site for that gate. With a healthy verified base, the same common lifecycle now proceeds to allocation and execution. Even an unavailable cache now fails with the cache exception type rather than the removed unconditional gate.

The reported full engineering sweep enabled only `KEEMU_TEST_M1E05`; this separate two-case opt-in regression remained skipped. Source inspection establishes incompatible current-tree expectations; no actual live FAIL was executed or invented in this review.

Required correction in a new approved boundary: make the current-tree test cover enabled common execution and explicitly unavailable-cache no-allocation behavior. Preserve frozen MVP 1D evidence and historical BLOCKED observations rather than rewriting them. Three host-only mocked unavailable-cache checks in this review independently verified `BLOCKED` before any Docker access for AArch64, MIPS and MIPSEL.

## File limit and common-path parity

Exactly four source/test files changed at the engineering boundary, within the frozen maximum of five:

- `src/keemu/script_lifecycle.py`
- `src/keemu/script_persistent.py`
- `tests/integration/test_m1e05_scripts.py`
- `tests/unit/test_script_architectures.py`

The remaining four changed files are checkpoint/journal and supervisor-owned state/router records, not source/test files. There is no source/test/lock/profile/schema/fixture drift between the engineering boundary and this review checkout.

The one-shot change maps MIPS/MIPSEL to their actual `m1e-init-*` bases and passes the profile target to common offline cache validation. Persistent execution removes only the AArch64 gate, selects the existing `_image_lock_path()` and passes the same target to offline validation. Both still instantiate the same `ScriptInput`, `ScriptStager`, `ScriptProcessRunner`, `ScriptExpectations` and typed report/status models. There is no architecture-specific executor or target-probe substitution.

Byte comparisons and SHA-256 verified unchanged input, staging, process, assertions, results, Docker boundary, registry, persistent lifecycle, report writer, report models, scenario script dispatcher, native process helper and CLI. AST comparisons independently verified the execution/assertion/exception/finally-cleanup blocks of both script adapters are identical after excluding only their changed capability functions. Existing owner checks, full-ID reconciliation, persistent per-name lock and environment revalidation remain in their common source paths. No primitive redesign or frozen source-limit violation was found.

AArch64 keeps the same base and effective target as the old default. Its offline cache/image verification and portable regression PASS; a new live AArch64 script regression was not run. The duplicated one-shot profile/base target check and now-unused capability exception class are not acceptance-blocking safety defects; no cleanup/refactor was performed.

## Independently executed verification

- `uv run pytest -q --junitxml=reports/m1e05r-portable.xml`: 353 PASS, 65 intentional SKIP, 0 FAIL, 0 ERROR; 418 cases parsed.
- `uv run pytest -q tests/unit/test_script_*.py --junitxml=reports/m1e05r-script-unit.xml`: 117 PASS, 0 SKIP, 0 FAIL, 0 ERROR.
- Ruff lint and formatter checks on all four engineering source/test files: PASS.
- `git diff --check`: PASS before evidence publication; repeated at completion.
- Read-only `_inputs()` plus `_verify_cache()` for all three targets: PASS. The verifier allowed only `docker image inspect`; no init lock-file write, fetch, build, load, smoke or binfmt helper was used.
- Three host-only mocked missing-cache checks: target-specific `offline=True`, common typed `BLOCKED`, no container identity and no Docker image/exec/create/reconcile access: PASS.
- Host-only teardown policy reproduction: PASS as a reproduction of R1, not a successful teardown or target-runtime PASS.
- Complete Docker identity snapshots before/after read-only probes: identical, two unrelated containers and four networks; exact `org.keemu.owner=keemu` container/network counts 0/0.

Current reviewer metadata was read directly from the canonical database: session `20260930_063504_dd91c7`, provider `openai-codex`, model `gpt-6.1-sol`, reasoning `high`. The fresh review admission at `2026-09-30T06:34:57+00:00` was subtask-bound with 75% remaining. Terminal attestation/session deletion still belong to the supervisor after the exact completion boundary; a planned state lock was not substituted for runtime evidence.

## C3 telemetry and preserved boundaries

Recorded engineering continuations: 0. Recorded quota pause for the engineering outcome: false. Source/test files: 4/5. Primitive/file-limit violations found: 0. Independent blocking findings: R1, R2, R3. First-pass live verification is not independently recoverable; do not promote the successful historical worker claim into a validated C3 calibration sample. Corrective product diff in this review: none. Learning remains shadow-only, the historical outcome remains excluded from accepted learning, and no routing policy was promoted.

Original MVP 1 and MVP 1D task/state/audit evidence remains byte-preserved. MVP 1D D02/D07 stay BLOCKED. Target timeout/interruption/collision/assertion/service-isolation adversarial coverage is not claimed by this narrow review and belongs to later frozen verification. Scope compliance and source parity are not proof of full E06/E07 acceptance.

The review is complete because every requested review dimension was inspected and findings have reproducible evidence. E06 remains BLOCKED. Stop at this boundary; no corrective implementation, stale-registry mutation, successor launch or milestone completion is authorized here.
