# Acceptance traceability

Status values in this file describe verified evidence only. `PARTIAL` is not PASS.

| ID | Current status | Test or scenario | Latest evidence | Gap |
|---|---|---|---|---|
| A01 | PARTIAL | `tests/integration/p0_runtime_probe.py`; `verify_image_lock`; derived-image audit | Real AArch64 Docker/binfmt target shell, opkg, child ELF and direct shebang in `reports/20260923T080109Z-p005-e6653acf4ef7/probe.json`; original pre-binfmt failure retained | MIPS/MIPSEL and full cross-target acceptance absent |
| A02 | NOT RUN | — | — | hello fixture and opkg lifecycle not implemented |
| A03 | NOT RUN | — | — | service lifecycle not implemented |
| A04 | NOT RUN | — | — | negative ELF fixtures not implemented |
| A05 | NOT RUN | — | — | shebang/permission/symlink negative fixtures not implemented |
| A06 | NOT RUN | — | — | postinst/startup/timeout failure paths not implemented |
| A07 | NOT RUN | — | Docker image available; no container run authorized for p0-04 | web-demo and localhost publish not implemented |
| A08 | NOT RUN | — | Docker image available; no container run authorized for p0-04 | UDP fixture/publish not implemented |
| A09 | NOT RUN | — | Docker image available; no container run authorized for p0-04 | persistent Docker environment not implemented |
| A10 | NOT RUN | — | — | target matrix not implemented |
| A11 | NOT RUN | — | — | strict NDM shim not implemented |
| A12 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | event contract and firewall experiment absent |
| A13 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | `reports/20260923T130017Z-p007-1ed1391a9dd4/preflight.json` records isolated capability diagnosis only | client/router/server topology and no-bypass routing not tested; no packet path |
| A14 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | Same report: native NFNETLINK socket succeeds; static AArch64 socket gets `EPROTONOSUPPORT`; no active host NFQUEUE module | no native/target queue bind, ACCEPT/DROP or counters; original dynamic target needs unavailable `GLIBC_2.34`; host module mutation needs separate approval |
| A15 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | network-demo web/API absent |
| A16 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | network-demo persistence absent |
| A17 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | Same bounded blocker, no verdict or packet sent | network-demo packet processing and observed ACCEPT/DROP effect absent |
| A18 | PARTIAL | `tests/integration/p0_runtime_probe.py`; `fixtures/recipes/aarch64/keemu-init-p005.c` | Adopted daemon/short child, reap after exit, SIGTERM shutdown/0, differential keeper-death/1 vs PID 1 SIGINT/0, owner/run-id checked removal and independent absence in `reports/20260923T080109Z-p005-e6653acf4ef7/probe.json`; original keeper bug retained | interruption/stale-resource recovery not proven; no full A18 PASS |
| A19 | PARTIAL | `keemu p0 verify-lock`; `keemu p0 verify-fixture-lock --verify-external` | Entware closure plus 12 staged cross-toolchain and all fixture source/recipe hashes verified | complete locked fixture repeat and runtime execution remain unimplemented |
| A20 | PARTIAL | `tests/unit/test_p0_image.py`; p0-05 Docker probe | Created container inspected as nonprivileged, network-none, 256 MiB memory and 128 PID limit | full capability/mount/socket/isolation and runtime enforcement not proven |
| A21 | PARTIAL | `tests/unit/test_reports.py`; `tests/unit/test_doctor.py`; `tests/unit/test_cli.py` | current `RunReport` schema version 2; strict frozen metadata; exact partial-failure operation-sequence/name/status validation; schema parity; derived status/coverage validation; atomic JSON/Markdown/operation-log bundle; failed-run preservation test; real doctor BLOCKED report | full lifecycle/acceptance runs and complete runtime provenance absent |
