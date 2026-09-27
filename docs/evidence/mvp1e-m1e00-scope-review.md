# MVP 1E — m1e-00 MIPS/MIPSEL scope, lock, capability and routing review

Date: 2026-09-27. Scope: strictly read-only review plus this evidence publication. Governing inputs are `TASK.md`, `docs/specifications/KEEMU_MVP1E_mips_lifecycle.md`, `docs/model-routing-plan-mvp1e.md`, `.agent/STATE_MVP1E.json`, and the preserved MVP 1D records. No product code, test, profile, lock, supervisor config, Docker resource, host binfmt entry, module, firewall, or durable-state record was changed by this review.

## E01 outcome

`E01` is PASS as a scope/lock/capability review: exact implementation seams, frozen routes, present prerequisites, and present blockers are recorded before product mutation. This is not an E02–E08 implementation or a current target-runtime PASS.

`docs/evidence/mvp1e-m1e00-acceptance.json` freezes E02–E08 as NOT_RUN. MVP 1D D02/D07 remain BLOCKED and outside this milestone.

## Locked target identities

| Profile | Target | CPU/ELF/QEMU | SHA-256 |
|---|---|---|---|
| `generic-mips` | `mips-3.4` | MIPS, big-endian, ELF32, `qemu-mips` | `profiles/generic/generic-mips.yaml` = `d80853a851daa5ebaa378e2481595e604cb853a74f227cccba0abbcb4c664257` |
| `generic-mipsel` | `mipsel-3.4` | MIPSEL, little-endian, ELF32, `qemu-mipsel` | `profiles/generic/generic-mipsel.yaml` = `6b80d1ee6ec39ffb0d99c1031d5d144383097db1b03a8c89bb5be5cefecf3e3b` |

## Lock and offline artifact review

The existing `scripts/verify_m1b18.py` verifies captured feed indexes and package closures, bootstrap/QEMU bytes, SDK lock bindings, fixture source/binary hashes and ELF attributes, rootfs audit, canonical target-opkg inventory, and saved single-layer image archive/tree identity. It then requires the exact Docker-local image ID.

| Target | Root lock | SDK lock | Fixture lock | Image lock |
|---|---|---|---|---|
| `mipsel-3.4` | `aad4b3b1638bcb197aa860ec2e6fbd2f2443309da22d8e56c7a723fe962a1888` | `77d0607e2e09452cccef54846a6571e917fb65fc7f14f5b7bd580304bbf8f701` | `84485a7581a47887624146609db997eaf7895a89e8206dfdc3d1b73f82c0073f` | `7b5c34b1f43c4df63fa0c2f23ced532660e385f47209ee327a2383da08909f5f` |
| `mips-3.4` | `00fb78ea7199f2d10d0c6f31220c8ce18be3ba69df83e7c45f1c3910b76289d6` | `a6cf99629947dcdedc5acd1b16a55fe52b263146099cc5a162e1cdd6a3dba122` | `fb8a21ce4511ddf0a21f0177e22363fb23645473fb53530fbf1e1bba9103aad2` | `bafc09e003314250aa1328f9de3f705ae4f75acee98612ec84b0fb81463b1266` |

Read-only targeted execution of that verifier reached its live-image check only after offline lock/rootfs/fixture/saved-image verification. Both targets therefore have verified offline lock inputs and saved-image integrity. This review deliberately stopped at the live inspect boundary; it does not simulate a live image result.

Current live-image prerequisite is BLOCKED:

- MIPSEL locked image `sha256:9822813438c56f173491a7b205b0c536e632582493282f77e0049da8d5276e2c` is absent.
- MIPS locked image `sha256:1767195564c09eeb7e0eb7eccb31b3fd4fe0aa8725e2005677a07abad99d09c1` is absent.

The historical `docs/evidence/m1b18-targets-pass.json` remains valid historical target-execution evidence, but it cannot substitute for a current live-image or binfmt preflight. No image was imported or rebuilt here.

## Current capability prerequisites

- Docker Engine is reachable as `29.7.2/linux/amd64`.
- Project-owned Docker resources are absent: containers `0`, networks `0`.
- The current worker namespace exposes an empty `/proc/sys/fs/binfmt_misc`; its `status`, `qemu-mips`, and `qemu-mipsel` entries are unreadable. This is a BLOCKED current observation of handler visibility, not a claim that the host handlers are absent. No binfmt handler was installed, replaced, removed, or otherwise changed.
- The exact live MIPS/MIPSEL image and exact handler preflight must be repeated by the later real target-smoke subtasks before any lifecycle claim.

## Frozen architecture seams

The generic profile model and `DockerRuntime` already admit `mips-3.4` and `mipsel-3.4`; they are not the architecture-enablement blockers. The production lifecycle is still AArch64-only at these exact seams:

| Contract | Current seam | Frozen later owner |
|---|---|---|
| Init cache | `src/keemu/init_cache.py:29-31` fixes schema target `aarch64-3.10`; `_inputs()` binds P0 AArch64 locks and QEMU; `src/keemu/cli.py:451-459` rejects every profile except `generic-aarch64`. | `m1e-01` MIPS, then `m1e-02` MIPSEL. |
| One-shot IPK lifecycle | `src/keemu/lifecycle.py:57` fixes `BASE_LOCK` to `m1a-init-aarch64`; `:410-479` blocks a non-AArch64 target and binds the AArch64 base/feed lock. | `m1e-03`, through one common path; no probe substitution. |
| Persistent lifecycle/recovery | `src/keemu/persistent.py:90-111` rejects a target other than `aarch64-3.10` and binds `BASE_LOCK`; `:279-282` hard-codes the staged AArch64 package filename. Registry locking, full-ID reconciliation, tombstones, and foreign-resource refusal already exist and must be preserved. | `m1e-04`, C5 due explicit crash recovery and foreign-resource preservation. |
| Script one-shot | `src/keemu/script_lifecycle.py:45-50` maps both MIPS locks and `:127-161` binds profile/image identity, but `:210-230` raises `ScriptCapabilityUnavailable` before allocation for either non-AArch64 target. | `m1e-05` only after the common lifecycle exists. |
| Script persistent | `src/keemu/script_persistent.py:97,182-187` remains AArch64-base specific. The existing secure `ScriptInput`, `ScriptStager`, `ScriptProcessRunner`, assertions, cleanup, process-tree, and report-status primitives are frozen. | `m1e-05`, if the five-file C3 limit can be met without a primitive redesign; otherwise stop fail-closed. |

`tests/unit/test_init_cache.py` proves the current `keemu init --profile generic-mips --locked` rejection. `tests/unit/test_script_architectures.py` proves MIPS/MIPSEL script reports are `BLOCKED` before Docker allocation, with no target path or container identity. These are truthful pre-enablement gates, not failures to be bypassed.

## Acceptance and route freeze

- `E01`: PASS — this review and gate ledger are published.
- `E02`–`E08`: NOT_RUN — no product, runtime, host, or later-subtask work was performed.
- No E02/E03 cache, E04 one-shot, E05 persistent/recovery, E06 script, E07 adversarial, or E08 reconciliation result is inferred from MIPS target probes or this review.
- Frozen distribution is C3=3, C4=5, C5=2, Astra=0. Routes are: `m1e-00` C3/Terra high; `m1e-01`/`m1e-02`/`m1e-03` C4/Sol high; `m1e-04` C5/Sol xhigh; `m1e-05` C3/Terra high; `m1e-05r` C4/Sol high; `m1e-06` C5/Sol xhigh; `m1e-07` C3/Terra high; `m1e-08` C4/Sol high.
- `m1e-04` C5 factors are `crash_recovery` and `foreign_resource_preservation`. `m1e-06` adds `concurrency_control`.
- `m1e-05` may modify at most five source/test files and must not change `ScriptInput`, `ScriptStager`, `ScriptProcessRunner`, ownership/cleanup/recovery primitives, process-tree semantics, or report-status mapping. `m1e-05r` is the mandatory separate C4 read-only review.
- State/config parity is verified: `routing.mode=shadow`, approved route application is enabled, learning remains `shadow`, canary is disabled, and Astra is disabled. The active state locks `m1e-00` to `openai-codex/gpt-5.6-terra/high` and exact digest `21a2965fac518ce0efadb46e0569c88ed9a7aa8035e8862cafba926eca01ac8b`; `model_attested` remains `null` and attestation is `PENDING`. This is a planned/state lock, not a runtime-attestation claim.

## C3 telemetry record

- Sample: `m1e-00`.
- Scope: read-only inspection plus two evidence files; no source/test/config/runtime change.
- State telemetry before supervisor boundary: continuations `0`, consecutive failures `0`, quota admission `32%` at `2026-09-27T19:24:37+00:00`.
- Verification: 13 relevant unit tests passed; 2 intentionally skipped. Profile parse and route/state/config parity passed. Offline MIPS/MIPSEL lock/rootfs/fixture/saved-image checks passed through the exact live-image boundary.
- Blocking findings: both exact live images absent; current worker cannot observe host binfmt entries.
- Corrective product diff: none. C3 telemetry remains observational and cannot promote routing automatically.

## Verification record

Read-only commands and decisive results:

- `uv run pytest -q tests/unit/test_init_cache.py tests/unit/test_script_architectures.py tests/unit/test_m1b18_evidence.py tests/unit/test_m1b18_targets.py` → `13 passed, 2 skipped`.
- `PYTHONPATH=. uv run python -m scripts.verify_m1b18` → stopped at exact absent MIPSEL live image after its offline verification path.
- Targeted offline-only boundary check for both targets → `OFFLINE_LOCK_ROOTFS_FIXTURE_SAVED_IMAGE=PASS`; live images unavailable as listed above.
- Route/state/config assertion → PASS; planned m1e-00 runtime attestation remains PENDING.
- Docker preflight → Engine `29.7.2/linux/amd64`; KEEMU-owned containers/networks `0/0`.
- `git diff --check` → PASS before evidence publication. Pre-existing supervisor-owned worktree entries were only `.agent/router-events.jsonl` modified and `.agent/STATE_MVP1E.json` untracked; this review did not modify either.

No successor subtask was started.
