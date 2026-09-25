# Final-31 independent evidence audit — 2026-09-25 UTC

Scope: frozen `TASK.md` Completion and A01–A21 against `KEEMU_MVP1_updated.md` revision 2.2, §§14, 18–20. No script-execution addendum or later milestone was evaluated. This is an audit of retained evidence plus read-only current-state checks, not a new three-target or packet integration run. Runner: shared Docker Engine 29.7.2, not a fresh Ubuntu VM or physical Keenetic.

## Verdict

**MVP 1 and Completion: BLOCKED; no auditable MVP-complete statement.** P0 technical-risk gate is complete on its explicitly documented NFQUEUE-blocker alternative. The specified A01 three-generic-target ELF/shell/nested-exec check is PASS. **A02–A21 remain BLOCKED as whole acceptance IDs.** MVP 1A, 1B and 1C are each BLOCKED. Earlier A14/A17 PASS means only the bounded AArch64 fixture with declared native NFQUEUE transport and native firewall-installer substitutions; direct target NFNETLINK failed `Protocol not supported`. An expected defective-package report remains FAIL even if the harness test that expects that failure PASSes. The final-29 release sweep itself is FAIL; required missing or skipped checks cannot be promoted to release PASS.

The authoritative whole-ID ledger is `docs/evidence/final28-acceptance.json`, SHA-256 `7d3c0b10dc0c0436b18d4a028bb4e27b80d113fc734adac009784f13dfd74c4c`. It contains exactly 21 IDs, 1 PASS/20 BLOCKED, each with an observed slice, exact gap, test path and retained evidence key. Its 15 source digests were independently rehashed and matched. The subsequent release record `docs/evidence/final29-release.json`, SHA-256 `a53b0bd54b94b0d7b2e54cc241d361228b2b8ed2fb8e4fd8bcd2a4c5f0b86fba`, and all seven retained raw-log digests matched. Historical ledgers are not rewritten by this verdict.

## Exact remaining BLOCKED IDs

Each line names the missing mandatory proof; prior bounded observations and test/evidence paths are in the hash-bound final-28 ledger and `docs/traceability.md`.

- A02 — Independent postinst exit and installed-file byte equality; MIPS/MIPSEL package lifecycle.
- A03 — Full process lineage/socket census and start/stop/remove on MIPS/MIPSEL.
- A04 — End-to-end wrong-ELF, missing-loader and missing-dependency cases on all three targets (unit/static checks and AArch64 wrong-architecture report are narrower).
- A05 — End-to-end permissions and broken-link failures and required cross-target cases (AArch64 bad-shebang/static checks are narrower).
- A06 — Persistent failure report bundle, one-shot SIGKILL partial report/recovery, and MIPS/MIPSEL failure paths.
- A07 — General `keemu test`/`up` scenario-driven host publication and HTTPS; only separately published AArch64 fixture passed.
- A08 — General scenario lifecycle UDP publish/probe; only separately published AArch64 fixture passed.
- A09 — General published persistent scenario down/up; fixture-only state and restricted registry evidence are narrower.
- A10 — Actual MIPS/MIPSEL package lifecycle children with distinct verified artifacts; complete matrix currently has AArch64 PASS, two required BLOCKED children and aggregate BLOCKED.
- A11 — Observed physical NDM responses, installed target `ndmc` and lifecycle integration; existing shim is synthetic host-side only.
- A12 — Target/device event contract and actual firewall rule restoration on repeat; JSON rules-mock is synthetic only.
- A13 — Generic scenario routing and hostile route-change/bypass resistance; bounded internal LAN/router/WAN HTTP traversal does not prove these.
- A14 — Direct target NFNETLINK/iptables capability and generic package path; target socket fails, while only the declared native-transport/firewall substituted AArch64 fixture has correlated ACCEPT/DROP proof.
- A15 — General network-demo lifecycle/backend; API-only run had no backend and later packet decisions belong to substituted diagnostic fixture.
- A16 — Restored `br0`, post-environment-restart queued packet effect and generic persistence; API-only mode file/readback survived restart without route restoration.
- A17 — Generic scenario packet processing and direct target queue path; substituted fixture passed a bounded ACCEPT→DROP→ACCEPT flow, but readiness remained stale after adapter death.
- A18 — Automatic recovery, one-shot crash journal/partial report, foreign firewall-rule parity and cross-target topology; explicit owned cleanup after three SIGKILL boundaries is narrower.
- A19 — General published fixture offline repeat and cross-target lifecycle repeat; prepared AArch64 offline cache and two hello runs are narrower, not a clean air-gapped install.
- A20 — Hard/continuous writable-layer disk limit, hostile NET_ADMIN bypass, complete security/socket audit and foreign firewall census; bounded inspect/resource checks are narrower.
- A21 — Uniform reports for persistent, network and interrupted runs, including complete provenance, evidence, substitutions, skips and coverage; schema-v2 one-shot write-once bundles alone do not satisfy every run.

## Release and Completion blockers independently checked

- Retained full-sweep `reports/final29/release-pytest.xml`: SHA-256 matches final-29; independent XML traversal counted **238 cases: 233 PASS, 2 FAIL, 3 SKIP**. The two FAIL cases are `tests/integration/test_m1a15_https.py::test_https_aarch64_with_local_ca` and `tests/integration/test_p0_image.py::P0ImageIntegrationTests::test_live_image_and_saved_layer_match_lock`: the exact locked Docker-local images `sha256:fa618afa80cab7d081e8012ed8209cf16d95507263c412ba119d131510e888bc` and `sha256:bfc44a226f962eb35251bb51c33caada4a9e0d44b2bb63567a5fff18b35b1f04` were absent on fresh readback. These are prerequisite failures, not proof that target TLS or image contents failed. Saved export config digests differ from the locked image IDs; no import or lock rewrite was attempted.
- The three SKIPs were `tests/integration/test_m1c26_ipc.py::test_target_decision_packet_flow` (prepared kernel modules absent), `tests/integration/test_m1c26_packet_blocker.py::test_routed_baseline_and_target_queue_blocker` (obsolete no-module preflight), and `tests/integration/test_p0_web_demo.py::P0WebDemoIntegrationTests::test_live_p0_web_demo_probe_passes` (not opted in, locked web image absent). These are not new PASS. Fresh kernel packet verdict and fresh Ubuntu checks were NOT RUN. Historical, hash-bound m1c-26 fixture proof is retained but not substituted for either fresh check.
- Independent binary pcap traversal found 17 bounded records in 1420 bytes, SHA-256 `e8081be081e6b068b02eed7f02a11a0bc1d97fb730d3cebb390e741c1677c445`. Historical m1c-26 JSON separately records 10 target ACCEPT/7 DROP and 17 adapter/kernel/rule/pcap events; correlation is limited to the approved fixture substitution. Final-29 target socket probes remain BLOCKED on AArch64/MIPS/MIPSEL, with native same-namespace controls PASS. MIPS/MIPSEL direct+Docker execution is PASS, but general package lifecycle is not.
- On this audit's read-only host check: Docker Engine 29.7.2; `docker ps -aq --filter label=org.keemu.owner=keemu` and `docker network ls -q --filter label=org.keemu.owner=keemu` returned no IDs. `nfnetlink_queue` loaded, `xt_NFQUEUE`/`iptable_filter`/`nft_queue` absent; kernel taint `0`. This is a shared-host ownership snapshot, not a complete foreign firewall census or fresh Ubuntu proof. No host module, firewall, image, binfmt or Docker resource was changed by this audit.
- Fresh default `uv run pytest -q`: **208 PASS, 30 opt-in SKIP, 0 FAIL**. `uv run python -m scripts.validate_final28` and `uv run python -m scripts.validate_final29` PASS (21 IDs/15 sources and 233/2/3 respectively); `uv run ruff check .` and `git diff --check` PASS. `uv run ruff format --check .` FAIL on six previously committed, unchanged files (`src/keemu/doctor.py`, `src/keemu/entware.py`, `src/keemu/models.py`, `src/keemu/p0_web_demo.py`, `tests/integration/p0_web_demo_probe.py`, `tests/integration/test_m1a16_recovery.py`). Formatting was not changed in the audit.
- The spec's MVP 1A clean-Ubuntu instruction and some generic CLI contracts are not implemented or not verified: read-only `uv run keemu --help` lists no `shell`, `install`, `event`, `service`, `clean` or `profiles` command. This is additional Completion scope, not an invented acceptance PASS. No missing integration was rerun or silently removed from scope.

Reproduction without host mutation: run `uv run python -m scripts.validate_final28`, `uv run python -m scripts.validate_final29`, `uv run pytest -q`, `uv run ruff check .`, `uv run ruff format --check .`, `git diff --check`; inspect the two hash-bound ledgers and retained JUnit/pcap. Live tests require their documented opt-in and prerequisite host capabilities; do not treat the portable skips as release execution. Retained raw files under ignored `reports/` and `.runtime/` must remain available to reproduce historical hash checks. This audit did not prepare a release or resolve the 20 blocked IDs.
