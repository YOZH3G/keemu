# Acceptance traceability

Status values in this file describe verified evidence only. `PARTIAL` is not PASS.

| ID | Current status | Test or scenario | Latest evidence | Gap |
|---|---|---|---|---|
| A01 | PARTIAL | `tests/integration/test_p0_diagnostic.py`; locked fixture build | AArch64 diagnostic plus three verified AArch64 ELF64/little-endian fixture outputs | Docker/binfmt and MIPS/MIPSEL absent |
| A02 | NOT RUN | — | — | hello fixture and opkg lifecycle not implemented |
| A03 | NOT RUN | — | — | service lifecycle not implemented |
| A04 | NOT RUN | — | — | negative ELF fixtures not implemented |
| A05 | NOT RUN | — | — | shebang/permission/symlink negative fixtures not implemented |
| A06 | NOT RUN | — | — | postinst/startup/timeout failure paths not implemented |
| A07 | BLOCKED | — | Docker daemon unavailable | web-demo and localhost publish not implemented |
| A08 | BLOCKED | — | Docker daemon unavailable | UDP fixture/publish not implemented |
| A09 | BLOCKED | — | Docker daemon unavailable | persistent Docker environment not implemented |
| A10 | NOT RUN | — | — | target matrix not implemented |
| A11 | NOT RUN | — | — | strict NDM shim not implemented |
| A12 | BLOCKED | — | Docker daemon unavailable | event contract and firewall experiment absent |
| A13 | BLOCKED | — | Docker daemon unavailable | client/router/server topology absent |
| A14 | BLOCKED | — | Docker daemon unavailable | AArch64 NFQUEUE and native control absent |
| A15 | BLOCKED | — | Docker daemon unavailable | network-demo web/API absent |
| A16 | BLOCKED | — | Docker daemon unavailable | network-demo persistence absent |
| A17 | BLOCKED | — | Docker daemon unavailable | packet-processing evidence absent |
| A18 | NOT RUN | — | — | runtime recovery/ownership cleanup not implemented |
| A19 | PARTIAL | `keemu p0 verify-lock`; `keemu p0 verify-fixture-lock --verify-external` | Entware closure plus 12 staged cross-toolchain and all fixture source/recipe hashes verified | complete locked fixture repeat and runtime execution remain unimplemented |
| A20 | BLOCKED | — | Docker daemon unavailable | container isolation inspection absent |
| A21 | PARTIAL | `tests/unit/test_reports.py`; `tests/unit/test_doctor.py`; `tests/unit/test_cli.py` | current `RunReport` schema version 2; strict frozen metadata; exact partial-failure operation-sequence/name/status validation; schema parity; derived status/coverage validation; atomic JSON/Markdown/operation-log bundle; failed-run preservation test; real doctor BLOCKED report | full lifecycle/acceptance runs and complete runtime provenance absent |
