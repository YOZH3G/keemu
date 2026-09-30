# KEEMU

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/runtime-Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
![AArch64](https://img.shields.io/badge/AArch64-supported-success)
![MIPSEL](https://img.shields.io/badge/MIPSEL-partial-yellow)
![MIPS](https://img.shields.io/badge/MIPS-partial-yellow)
![Status](https://img.shields.io/badge/status-audited%20%2F%20release%20blocked-orange)

**Reproducible verification harness for Entware applications — without requiring a physical Keenetic router.**

KEEMU runs locked target environments through Docker and QEMU, installs and exercises Entware packages, executes declared checks, and preserves evidence tied to exact input hashes.

> KEEMU is **not** a full Keenetic firmware emulator. A successful KEEMU run is evidence for the tested scenario, not proof of complete compatibility with a physical router.

[Русская версия](README_RU.md) · [MVP specification](KEEMU_MVP1_updated.md) · [Traceability](docs/traceability.md) · [Evidence](docs/evidence/)

---

## Why KEEMU?

Testing Entware software on real routers is slow, hardware-dependent, and difficult to reproduce. KEEMU moves most package-level verification into a controlled environment while keeping unsupported behavior explicit.

It is designed around five principles:

- **Locked inputs** — packages, profiles, images, and important artifacts are hash-bound.
- **Real target execution** — target `opkg`, BusyBox, ELF binaries, and scripts execute through QEMU/binfmt where supported.
- **Disposable and persistent environments** — use one-shot test runs or keep an owned environment alive for investigation.
- **Evidence first** — reports record what actually ran and what could not be verified.
- **Fail closed** — a skipped, unavailable, or unsupported check never silently becomes `PASS`.

---

## Architecture status

| Target | Current status | General `init` / single `test` | Target execution |
| --- | --- | --- | --- |
| **AArch64** | Supported MVP path | ✅ Yes | ✅ QEMU/binfmt verified |
| **MIPSEL** | MVP 1E bounded lifecycle evidence | ✅ locked `init`, one-shot and persistent IPK paths | ✅ QEMU/binfmt verified |
| **MIPS** | MVP 1E bounded lifecycle evidence | ✅ locked `init`, one-shot and persistent IPK paths | ✅ QEMU/binfmt verified |

MIPSEL/MIPS now have generic profiles, deterministic locked init caches, common one-shot and persistent IPK paths, ELF32 audits, and verified target execution. The independent `docs/evidence/mvp1e-m1e08-final-audit.json` records E01–E05, E07 and E08 `PASS` at their named bounded gates; E06 and the MVP 1E milestone/release remain `BLOCKED`. The earlier E07 ledger retains `SCOPED_PASS`; this does not hide its two actual architecture-regression `FAIL` results or accept script integration.

### MVP 1E MIPS/MIPSEL lifecycle reconciliation

**Final status:** all frozen execution and audit subtasks are complete; release remains blocked.

All 10 frozen MVP 1E subtasks are complete, runtime-attested, published, and have no retained worker session. The retained m1e-07 reconciliation is documentation/evidence-only. The separate m1e-08 final audit publishes the milestone verdict:

- E01 scope/lock review, E02 MIPS init, E03 MIPSEL init, E04 one-shot lifecycle, and E05 persistent/recovery are `PASS` at their named scopes;
- E06 is `BLOCKED` by R1 defective persistent-test teardown, R2 missing independently verifiable historical C3 RED/GREEN evidence, and R3 an obsolete opt-in architecture regression;
- E07 final verification-observation gate is `PASS` for 19 unique bounded real adversarial cases across all three targets; its historical ledger remains `SCOPED_PASS`;
- E08 independent evidence audit is `PASS`, but MVP 1E milestone/release is `BLOCKED`. Fresh portable tests are 353 `PASS`/84 opt-in `SKIP`; repository lint and format checks `FAIL` on untouched files.

See `docs/evidence/mvp1e-m1e08-final-audit.md`, the retained `docs/evidence/mvp1e-m1e07-reconciliation.md`, and `docs/limitations.md`. Orchestration is complete; product and release acceptance remain blocked by the gates above.

### Planned blocker closure

The next hardening boundary must preserve the completed MVP 1D/1E evidence rather than rewrite it:

1. fix persistent test teardown to perform `down` then `destroy`, reject hidden cleanup errors, and verify a consistent destroyed registry tombstone;
2. replace the obsolete MIPS/MIPSEL `BLOCKED` regression with healthy-cache execution and unavailable-cache/no-allocation cases;
3. capture a new immutable live evidence bundle with JUnit, typed reports, source/lock hashes, Docker and registry snapshots, while leaving the historical C3 sample excluded from accepted learning;
4. replace pathname-based temporary script/helper staging with a pinned runner and descriptor-backed sealed script input, removing the hostile same-UID `stat`/`rm` race rather than adding another pathname check;
5. add a crash-safe operation journal and automatic interrupted-report recovery so persistent `SIGKILL` leaves neither a target artifact nor an unreported operation.

Only a new three-target adversarial run and independent audit may promote E06 and the superseding D02/D07 hardening gates to `PASS`.

---

## What KEEMU can do

### Run bounded shell scripts

MVP 1D adds a common, ownership-checked script runner for one-shot AArch64 environments and already-running persistent environments.

One-shot execution:

```bash
uv run keemu script fixtures/scripts/mvp1d/success.sh \
  --profile generic-aarch64 \
  --repo . \
  -- arg1
```

Execution inside an owner-verified persistent environment:

```bash
uv run keemu exec demo \
  --script fixtures/scripts/mvp1d/success.sh \
  --repo . \
  -- arg1
```

Both forms support `--timeout`, `--cwd`, `--expect-exit-code`, repeatable `--stdout-contains`, `--stderr-not-contains`, `--expect-file`, and `--expect-file-absent` options.

The script path must reference a project-contained regular `.sh` file. KEEMU opens it without following symlinks, binds it to SHA-256, rechecks it before staging, and transfers only the checked bytes into a private no-clobber path below target `/opt/tmp`. Target `/bin/sh` receives literal argv and a minimal environment; script content is never passed through a host shell. Reports retain typed status, byte counts, hashes, truncation, assertions, and cleanup results without storing raw argv or output.

Version-1 scenarios may also declare a SHA-256-locked `kind: script` check. The MVP 1E common lifecycle now reaches all three target profiles, and E07 retained bounded script observations for all three. That does not close E06: its independent review found R1/R2/R3, so MIPS/MIPSEL script-integration acceptance remains `BLOCKED` pending a separately approved corrective boundary and final evidence.

The independent MVP 1D audit records D01/D03/D04/D05/D06/D08 `PASS` at bounded scope. D02/D07 and the MVP 1D release remain `BLOCKED` by two explicit gaps: atomic cleanup safety against a hostile concurrent same-UID target process, and production recovery/reporting for persistent script artifacts left by `SIGKILL`.

See:

- `docs/specifications/KEEMU_MVP1D_script_execution.md`
- `docs/evidence/mvp1d-m1d13-final-audit.md`
- `docs/limitations.md`

### Static IPK inspection

Inspect package metadata, archive contents, ELF objects, dependencies, findings, and limitations without installing or executing the package:

```bash
uv run keemu inspect path/to/package.ipk --profile generic-aarch64
```

With a dependency-complete rootfs:

```bash
uv run keemu inspect path/to/package.ipk \
  --profile generic-aarch64 \
  --rootfs path/to/dependency-complete-rootfs
```

A static `PASS` is **not** runtime acceptance and does not authorize installation by itself.

### Prepare a locked AArch64 base

```bash
uv run keemu init --profile generic-aarch64 --locked
uv run keemu init --profile generic-aarch64 --locked --offline
```

The locked path uses the pre-verified local Entware bootstrap set. It does not update the live feed and does not install packages on the host.

### Run a one-shot package scenario

```bash
uv run keemu test \
  --scenario path/to/scenario.yaml \
  --lock path/to/scenario-lock.json \
  --repo .
```

A one-shot run can:

1. validate and rehash locked inputs;
2. statically inspect the IPK;
3. create a fresh owned target container;
4. install the package through target `opkg`;
5. execute declared checks;
6. stop the service when required;
7. remove the package;
8. inspect residual filesystem changes;
9. perform owner-checked cleanup even after failure.

Reports are written under:

```text
reports/<run-id>/
├── report.json
├── report.md
└── operation-log.jsonl
```

### Keep a target environment alive

```bash
uv run keemu up \
  --name demo \
  --scenario path/to/scenario.yaml \
  --lock path/to/scenario-lock.json \
  --repo .

uv run keemu status demo --repo .
uv run keemu exec demo --repo . -- /opt/bin/example
uv run keemu logs demo --repo .
uv run keemu restart demo --repo .
uv run keemu down demo --repo .
```

Destroy a stopped environment:

```bash
uv run keemu destroy demo --repo .
```

Explicitly recover an interrupted/failed owned environment:

```bash
uv run keemu recover demo --repo . --yes
```

KEEMU refuses foreign/replaced containers and ambiguous ownership instead of attempting unsafe cleanup.

### Run an architecture matrix

```bash
uv run keemu test \
  --matrix path/to/matrix.yaml \
  --strict \
  --repo .
```

Matrix v1 expects one `profile`, `scenario`, and explicit `lock` per case.

For complete target coverage, include:

- `generic-aarch64`
- `generic-mipsel`
- `generic-mips`

Unsupported required cases remain `BLOCKED`; they are never converted to success.

---

## Scenario checks

The current scenario model supports checks such as:

- target commands with expected exit codes;
- file existence;
- HTTP/HTTPS probes;
- UDP probes;
- service readiness and stop verification.

Example command check:

```yaml
checks:
  - id: version
    kind: command
    command:
      argv:
        - /opt/bin/example
        - --version
      timeout_seconds: 30
    expected_exit_code: 0
```

Shell interpretation is intentionally explicit. Reviewed scenarios may use:

```yaml
argv:
  - /bin/sh
  - -c
  - 'test -f /opt/etc/example.conf'
```

The persistent runner also exposes explicit argv execution through `keemu exec`.

---

## Result model

KEEMU distinguishes different kinds of incomplete or failed verification:

| Status | Meaning |
| --- | --- |
| `PASS` | The declared check ran and matched its expectation |
| `WARN` | The check completed but produced a non-fatal concern |
| `BLOCKED` | Required verification could not be performed with the available capability/input |
| `FAIL` | The target/package behavior contradicted the expected result |
| `ERROR` | The harness or execution path failed unexpectedly |

Aggregate precedence is:

```text
ERROR → FAIL → BLOCKED → WARN → PASS
```

Typical matrix exits include:

- wrong-architecture IPK → `FAIL`, exit `1`;
- unsupported required MIPS/MIPSEL lifecycle → `BLOCKED`, exit `4`;
- WARN-only strict run → exit `5`.

---

## Quick start for development

Requirements:

- Python 3.12
- `uv`
- Docker Engine
- target binfmt registration for workflows that execute foreign-architecture binaries

Install the development environment:

```bash
uv sync --python 3.12
```

Run the portable test suite:

```bash
uv run pytest -q
```

Run linting:

```bash
uv run ruff check .
```

Some integration suites are opt-in because they require locked local artifacts, Docker images, binfmt handlers, or other prepared prerequisites.

---

## Current verification snapshot

The P0 technical-risk experiments are complete, and bounded MVP 1A/1B/1C slices are implemented. **MVP 1 as a whole is not complete.**

The retained acceptance snapshot currently records:

- A01 `PASS` for the specified three-generic-target execution check;
- A02–A21 `BLOCKED` in the final-28 whole-ID ledger;
- final-29 overall `BLOCKED`;
- 238 retained final-29 cases:
  - 233 `PASS`
  - 2 `FAIL` because required locked images were missing
  - 3 intentional `SKIP`
- original MVP 1 default portable run:
  - 208 `PASS`
  - 30 opt-in `SKIP`
- MVP 1D portable run:
  - 339 `PASS`
  - 44 intentional opt-in `SKIP`
- MVP 1D real AArch64 retained suite:
  - 39 `PASS`
  - 0 `FAIL`
  - 0 `SKIP`
- MVP 1D release: `BLOCKED`, while its bounded evidence audit is complete.
- MVP 1E execution: 10/10 frozen subtasks complete and runtime-attested; final gates E01–E05 `PASS`, E06 `BLOCKED`, E07 `PASS` at its named bounded verification-observation scope, and E08 `PASS`; milestone/release remains `BLOCKED`.

Authoritative details:

- `docs/evidence/final28-acceptance.json`
- `docs/evidence/final29-release.json`
- `docs/traceability.md`

---

## Verified target behavior

In the current Debian/Docker verification environment, KEEMU has evidence for:

- SHA-256-verified AArch64 Entware package index and 20-package bootstrap closure;
- real AArch64 Entware `opkg` and BusyBox execution through QEMU user-mode;
- an unprivileged PRoot chain of `shell → child AArch64 ELF → target-shebang shell script`;
- locked QEMU/PRoot inputs and Entware artifacts;
- AArch64 Docker/binfmt execution of target shell, `opkg`, nested ELF, and direct shebang;
- native-init signal forwarding/reaping and controlled owner-checked shutdown in the bounded P0-05 probe;
- MIPSEL/MIPS target shell, `opkg`, nested ELF/shebang, hello, and fixture-argument probes;
- MIPSEL/MIPS bounded Docker/binfmt probes after separately approved host binfmt registration.

Recheck the MIPS/MIPSEL target assets offline:

```bash
uv run python -m scripts.verify_m1b18
```

See:

- `docs/evidence/m1b18-targets-pass.json`
- `docs/evidence/m1b18-targets.md`

---

## Network verification

KEEMU has bounded evidence for localhost HTTP/HTTPS/UDP behavior through dedicated fixtures.

Example AArch64 fixture test:

```bash
make -f fixtures/recipes/aarch64/https-frontend-m1a15.mk \
  KEEMU_TOOLCHAIN_ROOT="$PWD/.runtime/p0/cross-toolchain/root"

KEEMU_M1A15_LIVE=1 \
  uv run pytest -q tests/integration/test_m1a15_https.py
```

The fixture:

- does not fetch during the recipe;
- uses pinned SDK artifacts and a static AArch64 TLS binary;
- creates an ephemeral local CA/certificate;
- publishes only to localhost;
- checks trusted TLS;
- rejects wrong hostnames and untrusted CAs;
- repeats HTTP/HTTPS/UDP after service/container restart;
- repeats locked one-shot package execution against the offline-verified base.

This does **not** mean generic `test`/`up` HTTPS, UDP, or host publication is complete.

Direct target NFQUEUE remains:

```text
BLOCKED: Protocol not supported
```

A separate AArch64 packet fixture passes only through declared transport/firewall substitutions and is not evidence of generic target NFQUEUE compatibility.

---

## P0 diagnostics

PRoot diagnostic:

```bash
KEEMU_RUN_P0_DIAGNOSTIC=1 \
  uv run pytest -q tests/integration/test_p0_diagnostic.py
```

P0-04 image audit:

```bash
KEEMU_RUN_P0_IMAGE_AUDIT=1 \
  uv run pytest -q tests/integration/test_p0_image.py
```

P0-05 runtime probe:

```bash
uv run python tests/integration/p0_runtime_probe.py
```

The P0-05 probe requires the locked derived image and a separately authorized Docker/binfmt runner. It creates and cleans only KEEMU-owned labeled resources.

---

## Reproducibility and reports

KEEMU binds runtime evidence to exact inputs wherever the current slice supports it.

`RunReport` schema v2 records immutable metadata for:

- artifacts;
- scenarios;
- profiles;
- runtimes;
- capabilities;
- substitutions;
- checks;
- operation logs;
- coverage;
- partial failures.

Report bundles use Linux `renameat2(..., RENAME_NOREPLACE)` for atomic no-replace publication. Existing report entries are preserved, and publication fails closed if the required no-replace primitive is unavailable.

Generated reports, downloaded IPKs, root filesystems, saved images, and runtime state are excluded from Git. Committed locks and image metadata live under `locks/`.

---

## Safety boundary

KEEMU deliberately constrains target execution.

Target environments must not use:

- privileged containers;
- host network namespace;
- host PID namespace;
- Docker socket mounts;
- `SYS_MODULE`;
- global firewall resets;
- `docker system prune`.

Host networking is reserved for bounded owner-labeled evidence observers that verify Docker-host loopback behavior. The package under test does not run there.

KEEMU also refuses to treat missing capability as successful compatibility evidence.

---

## Known limitations

The following are still incomplete or intentionally out of scope for the current MVP:

- full Keenetic firmware emulation;
- proof of compatibility with every physical Keenetic model;
- E06 script-integration acceptance despite bounded common-path execution on AArch64/MIPS/MIPSEL;
- complete scenario-driven localhost publication;
- complete isolation guarantees;
- automatic one-shot interruption recovery;
- atomic script-artifact cleanup against a hostile concurrent same-UID target process;
- automatic recovery and interrupted reporting for persistent script artifacts after `SIGKILL`;
- correction and immutable rerun evidence for E06 findings R1/R2/R3;
- generic target NFQUEUE;
- complete A10 matrix acceptance;
- strict final NDM/event contracts;
- final MVP 1 / release acceptance.

---

## Repository map

```text
profiles/generic/        Generic target profiles
locks/                   Locked artifacts and image metadata
docs/evidence/           Retained verification evidence
docs/traceability.md     Requirement → test → evidence mapping
src/keemu/               KEEMU implementation
tests/                   Unit and integration tests
fixtures/                Bounded target/network fixtures
reports/                 Generated write-once reports (not committed)
.runtime/                Local runtime state and locked working assets
```

---

## Source of truth

The authoritative MVP scope and acceptance criteria are defined in:

```text
KEEMU_MVP1_updated.md
docs/specifications/KEEMU_MVP1D_script_execution.md
docs/specifications/KEEMU_MVP1E_mips_lifecycle.md
docs/evidence/mvp1e-m1e08-final-audit.md
```

`KEEMU_MVP1_updated.md` governs the original MVP 1 acceptance history. The MVP 1D and MVP 1E specifications govern their bounded milestones; the independent final audits record their verified verdicts. If this README disagrees with the applicable specification or audit, that source takes precedence.
