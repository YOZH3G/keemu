# Autonomous Task: KEEMU MVP 1

## Objective

Implement and experimentally verify KEEMU MVP 1 according to `KEEMU_MVP1_updated.md` revision 2.2. Work in the prescribed order: P0, MVP 1A, MVP 1B, then MVP 1C. Do not claim a phase or acceptance ID complete without real evidence.

## Authoritative specification

- `KEEMU_MVP1_updated.md` is the source of product scope, architecture constraints, acceptance IDs A01–A21, and truthfulness requirements.
- If implementation evidence conflicts with an assumption in the specification, record the evidence and update an ADR/limitations document; never fabricate compatibility.

## Scope

- May create and modify files only inside this repository and its test-owned runtime/report directories.
- May fetch public source artifacts needed for P0 only when provenance and SHA-256 are recorded.
- May create project-owned containers, networks, images and temporary resources when a usable Docker host is available.
- Must begin with the smallest vertical P0 slice: AArch64 target shell/opkg, web-demo through localhost publishing, persistence, then NFQUEUE capability experiments.
- Must continue through 1A, 1B and 1C only after each preceding gate has real evidence.

## Constraints

- Work only on branch `agent/keemu`; never merge or force-push automatically.
- Preserve `KEEMU_MVP1_updated.md` as the accepted specification unless an explicit, evidence-backed correction is required.
- Never store credentials, OAuth data, deploy keys, `.env` files or private keys in Git or durable agent files.
- Never use `docker system prune`, clear the host firewall, expose services publicly, mount the Docker socket inside a target container, or use `--privileged` for target packages.
- Do not alter host binfmt, firewall, kernel modules, public ports, DNS, physical routers or cloud infrastructure without explicit human approval.
- Keep real execution, shim behavior, static analysis, SKIP, BLOCKED and untested claims distinct in every report.
- Use pinned versions and hashes obtained from real artifacts; do not invent versions, API commands, fixtures or successful results.
- Revalidate the environment after every resume, crash, reboot or quota pause.

## Acceptance criteria

### P0 gate

- [ ] A minimal AArch64 Entware rootfs runs the target shell, opkg and nested child execution with recorded provenance.
- [ ] A target web-demo is reachable through an explicit `127.0.0.1` publish and persistence survives down/up.
- [ ] NFQUEUE ACCEPT/DROP and native-control experiments produce evidence, or MVP 1C is explicitly BLOCKED with a reproducible capability diagnosis.
- [ ] First real lock data and ADRs for runtime/network decisions are committed.

### MVP 1A gate

- [ ] Schemas, `doctor`, `init`, `inspect`, scenario lifecycle and persistent-environment commands are implemented and tested.
- [ ] AArch64 acceptance evidence covers applicable A01–A09, A18–A21 requirements.
- [ ] JSON is the report source and Markdown is generated from the same object.

### MVP 1B gate

- [ ] MIPS and MIPSEL rootfs/fixtures, matrix validation, strict NDM shim and required event contracts are implemented.
- [ ] Required cross-target checks A01–A06, A10 and A11 have real results with correct PASS/FAIL/BLOCKED semantics.

### MVP 1C gate

- [ ] Network-demo verifies web/API behavior, persistence and packet processing on AArch64.
- [ ] A13–A17 produce real network evidence, or each unmet capability is reported as BLOCKED without false PASS.
- [ ] Cleanup/isolation requirements A18–A20 are verified against project-owned resources only.

### Completion gate

- [ ] All A01–A21 results are mapped in `docs/traceability.md` to tests and evidence.
- [ ] Portable tests, required integration tests and applicable network tests pass; every unrun test is labeled accurately.
- [ ] README, architecture, progress, decisions and limitations match verified behavior.
- [ ] `.agent/CHECKPOINT.md`, `.agent/MEMORY.md`, `.agent/DECISIONS.md` and `.agent/JOURNAL.md` are current.

## Human approval boundaries

Explicit approval is required before modifying host binfmt registration, firewall rules outside disposable project namespaces, kernel modules, public network exposure, DNS, physical Keenetic devices, billing/cloud resources, credentials, OAuth state, deploy keys, or any non-project repository. Destructive operations may target only resources carrying verified KEEMU ownership labels.
