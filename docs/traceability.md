# Acceptance traceability

Status values in this file describe verified evidence only. `PARTIAL` is not PASS.

| ID | Current status | Test or scenario | Latest evidence | Gap |
|---|---|---|---|---|
| A01 | PARTIAL | `tests/integration/p0_runtime_probe.py`; `verify_image_lock`; derived-image audit | Real AArch64 Docker/binfmt target shell, opkg, child ELF and direct shebang in `reports/20260923T080109Z-p005-e6653acf4ef7/probe.json` (SHA-256 `86a81d2c33de6c68663871f4e2ff49e1c1c0920055408e123169744a9d52209b`) | MIPS/MIPSEL and full cross-target acceptance absent |
| A02 | NOT RUN | — | — | hello fixture and opkg lifecycle not implemented |
| A03 | NOT RUN | — | — | service lifecycle not implemented |
| A04 | NOT RUN | — | — | negative ELF fixtures not implemented |
| A05 | NOT RUN | — | — | shebang/permission/symlink negative fixtures not implemented |
| A06 | NOT RUN | — | — | postinst/startup/timeout failure paths not implemented |
| A07 | PASS (P0 AArch64 slice) | `tests/integration/p0_web_demo_probe.py` | Exact `127.0.0.1:18080→8080/tcp` publish, Docker-host-vantage HTTP health, inspect/`docker port`, and owner-only cleanup in `reports/20260923T125140Z-p006-aa4677e64b41/probe.json` (SHA-256 `af6a9d03c1f084ba3257cbfab4f81de8aa4af761bbc62ae66de362ba897fd669`) | General scenario lifecycle is not implemented |
| A08 | PASS (P0 AArch64 slice) | `tests/integration/p0_web_demo_probe.py` | Exact `127.0.0.1:18081→8081/udp` publish and Docker-host-vantage UDP echo in the same P0-06 report | General scenario lifecycle is not implemented |
| A09 | PASS (P0 AArch64 slice) | `tests/integration/p0_web_demo_probe.py` | State SHA-256 matched before/after service restart and Docker stop/start; final host-vantage HTTP/UDP readback passed in the same P0-06 report | General persistent-environment commands are not implemented |
| A10 | NOT RUN | — | — | target matrix not implemented |
| A11 | NOT RUN | — | — | strict NDM shim not implemented |
| A12 | NOT RUN | — | — | event contract and firewall experiment absent |
| A13 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | `reports/20260923T130017Z-p007-1ed1391a9dd4/preflight.json` (SHA-256 `b858e1629dd05c9af4ce8f82c9e33a6ee7cecc83a533716fc68844b18599049b`) records isolated capability diagnosis only | client/router/server topology and no-bypass routing not tested; no packet path |
| A14 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | Native NFNETLINK socket succeeds; static AArch64 socket gets `EPROTONOSUPPORT`; no active host NFQUEUE module | no native/target queue bind, ACCEPT/DROP or counters; original dynamic target needs unavailable `GLIBC_2.34`; host module mutation needs separate approval |
| A15 | NOT RUN | — | — | network-demo web/API absent |
| A16 | NOT RUN | — | — | network-demo persistence absent |
| A17 | BLOCKED | `tests/integration/p0_nfqueue_preflight.py` | Same bounded blocker; no verdict or packet was sent | network-demo packet processing and observed ACCEPT/DROP effect absent |
| A18 | PARTIAL | `tests/integration/p0_runtime_probe.py`; `fixtures/recipes/aarch64/keemu-init-p005.c` | Adopted daemon/short child, reap after exit, SIGTERM shutdown/0, differential keeper-death/1 vs PID 1 SIGINT/0, owner/run-id checked removal and independent absence in P0-05 report | interruption/stale-resource recovery not proven; no full A18 PASS |
| A19 | PARTIAL | `keemu p0 verify-lock`; `keemu p0 verify-fixture-lock --verify-external`; P0 evidence manifest | Entware closure, staged cross-toolchain, fixture source/recipe hashes, and P0 image/web-observer locks are recorded in `docs/evidence/p0-evidence-manifest.md` | Complete locked fixture repeat and production lifecycle execution remain unimplemented |
| A20 | PARTIAL | `tests/unit/test_p0_image.py`; P0-05 Docker probe; P0-06 probe | Applied nonprivileged/network-none create controls were inspected for P0-05; P0-06 application/observers used bounded project-owned controls | full capability/mount/socket/isolation and runtime enforcement not proven |
| A21 | PARTIAL | `tests/unit/test_reports.py`; `tests/unit/test_doctor.py`; `tests/unit/test_cli.py` | Schema-version-2 report model, strict metadata, schema parity, derived validation, write-once JSON/Markdown/operation-log bundles, failed-run preservation, and P0 report digests are documented | full lifecycle/acceptance runs and complete runtime provenance remain absent |

## P0 gate summary

The P0 technical-risk gate is evidenced: AArch64 target execution is real, localhost TCP/UDP publish plus down/up persistence is real, and NFQUEUE is reproducibly BLOCKED rather than substituted. This does not make A01, A18, A19, A20, A21, A13, A14, or A17 complete beyond the exact statuses above, and it does not complete MVP 1A, 1B, 1C, or MVP 1.
