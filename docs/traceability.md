# Acceptance traceability

Status values in this file describe verified evidence only. `PARTIAL` is not PASS.

| ID | Current status | Test or scenario | Latest evidence | Gap |
|---|---|---|---|---|
| A01 | PARTIAL | `tests/integration/test_p0_diagnostic.py`; locked fixture build; `verify_image_lock` | AArch64 diagnostic, three fixture ELF outputs, mixed OCI image with target shell/opkg and saved-layer architecture audit | Docker target execution/binfmt and MIPS/MIPSEL absent |
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
| A13 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | client/router/server topology absent |
| A14 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | AArch64 NFQUEUE and native control absent |
| A15 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | network-demo web/API absent |
| A16 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | network-demo persistence absent |
| A17 | NOT RUN | — | Docker image available; no network experiment authorized for p0-04 | packet-processing evidence absent |
| A18 | NOT RUN | `tests/unit/test_p0_image.py` (template only) | Image owner labels and bounded, unexecuted create argv | runtime recovery/ownership cleanup not implemented or run |
| A19 | PARTIAL | `keemu p0 verify-lock`; `keemu p0 verify-fixture-lock --verify-external` | Entware closure plus 12 staged cross-toolchain and all fixture source/recipe hashes verified | complete locked fixture repeat and runtime execution remain unimplemented |
| A20 | NOT RUN | `tests/unit/test_p0_image.py` (template only) | No target container was created | container isolation/resource-limit inspection absent |
| A21 | PARTIAL | `tests/unit/test_reports.py`; `tests/unit/test_doctor.py`; `tests/unit/test_cli.py` | current `RunReport` schema version 2; strict frozen metadata; exact partial-failure operation-sequence/name/status validation; schema parity; derived status/coverage validation; atomic JSON/Markdown/operation-log bundle; failed-run preservation test; real doctor BLOCKED report | full lifecycle/acceptance runs and complete runtime provenance absent |
