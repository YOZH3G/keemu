# Acceptance traceability

Status values in this file describe verified evidence only. `PARTIAL` is not PASS.

| ID | Current status | Test or scenario | Latest evidence | Gap |
|---|---|---|---|---|
| A01 | PARTIAL | `tests/integration/test_p0_diagnostic.py`; locked fixture build; `verify_image_lock`; p0-05 Docker probe | AArch64 diagnostic, three fixture ELF outputs, mixed OCI image/saved-layer audit; Docker target shell failed exit 255 with `exec format error` in `reports/20260923T060100Z-p005-cd7142bf3557/probe.json` | Host binfmt approval and working registration needed for Docker target shell/child/shebang; MIPS/MIPSEL absent |
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
| A18 | PARTIAL | `tests/unit/test_p0_image.py`; p0-05 Docker probe | Native init survived failed target exec; owner/run-id checked stop (exit code 0), remove, and independent absence in `reports/20260923T060100Z-p005-cd7142bf3557/probe.json` | signal forwarding, orphan reaping and recovery not proven; no full A18 PASS |
| A19 | PARTIAL | `keemu p0 verify-lock`; `keemu p0 verify-fixture-lock --verify-external` | Entware closure plus 12 staged cross-toolchain and all fixture source/recipe hashes verified | complete locked fixture repeat and runtime execution remain unimplemented |
| A20 | PARTIAL | `tests/unit/test_p0_image.py`; p0-05 Docker probe | Created container inspected as nonprivileged, network-none, 256 MiB memory and 128 PID limit | full capability/mount/socket/isolation and runtime enforcement not proven |
| A21 | PARTIAL | `tests/unit/test_reports.py`; `tests/unit/test_doctor.py`; `tests/unit/test_cli.py` | current `RunReport` schema version 2; strict frozen metadata; exact partial-failure operation-sequence/name/status validation; schema parity; derived status/coverage validation; atomic JSON/Markdown/operation-log bundle; failed-run preservation test; real doctor BLOCKED report | full lifecycle/acceptance runs and complete runtime provenance absent |
