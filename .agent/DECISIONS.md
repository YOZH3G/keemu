# Agent decisions

## D-001 — Reuse the existing repository

The durable supervisor uses `/opt/data/workspace/keemu` directly. `/opt/data/hermes-projects/keemu` is a compatibility symlink, not a second checkout. This avoids splitting project state.

## D-002 — Fixed current-model route

Supervised work is fixed to tier C5: `gpt-5.6-sol` with reasoning `xhigh`. Router mode is `auto` only to provide explicit per-run overrides and model-lock attestation; both minimum and maximum tiers are C5 and Astra is disabled. Dynamic model switching is not enabled.

## D-007 — ChatGPT 6 Luna/Sol policy refresh

At the verified p0-02 boundary, future Luna/Sol routes move from `gpt-5.6-luna`/`gpt-5.6-sol` to `gpt-6-luna`/`gpt-6-sol`. Existing attested route and outcome records retain the literal models that actually ran. The active p0-03 lock remains `gpt-5.6-terra` / `high`; all subsequent frozen plan entries and live policy/config use the updated IDs. Runtime attestation remains mandatory before a new model is treated as active.

## D-003 — Local Git until a private remote exists

Git auto-pull and auto-push are disabled. Local commits remain the durable boundary; adding a private remote and deploy key requires a separate explicit operation.

## D-004 — Preserve the Hostinger baseline

The deployment reuses the installed Hermes binary, OAuth state, RTK, Graphify, Caveman and router runtime. It does not reinstall or reconfigure those components.

## D-005 — Direct QEMU/PRoot is diagnostic only

When Docker is unavailable, project-local QEMU and unprivileged PRoot may verify locked target artifacts, target shell/opkg, nested target ELF and shebang behavior. This path is not a replacement for the accepted Docker runtime and cannot satisfy container, binfmt, publishing, persistence, isolation or networking acceptance requirements.

## D-006 — Reports are frozen objects and write-once bundles

The current common report schema is version 2 and uses frozen nested metadata and immutable sequences. Aggregate status and coverage are derived and revalidated from checks and partial-failure state. Each partial failure references an exact operation-log sequence, and the referenced record must match its operation name and failure status. A report bundle is assembled in a sibling temporary directory and published with Linux `renameat2(..., RENAME_NOREPLACE)`. Publication atomically succeeds only when the destination entry is absent; any existing directory, file, or symlink is preserved and reported as `FileExistsError`. If the no-replace primitive is unavailable, publication fails closed and removes the temporary bundle rather than falling back to overwrite-capable rename. This keeps JSON, Markdown, and operation-log evidence aligned and preserves failed runs.

## D-008 — P0 fixtures use a locked host cross-toolchain

P0 fixture compilation uses a project-staged Debian trixie `aarch64-linux-gnu-gcc` toolchain whose exact DEB inputs and SHA-256 values are recorded in `locks/p0-fixtures-aarch64.json`. This creates reproducible AArch64 ELF sources without pretending that the host compiler or PRoot diagnostic is the required Docker/binfmt runtime. The raw NFQUEUE fixture uses locked Linux UAPI headers rather than an unpinned library SDK; kernel capability and packet-flow correctness remain later, separately bounded experiments.

## D-009 — Mixed-image architecture and deferred container limits

P0-04 uses a scratch `linux/amd64` image with a project-owned, statically linked amd64 PID 1 in `/__keemu` and locked AArch64 Entware application files elsewhere. The native binary is outside application PATH; labels separate the native platform from the target. Docker image ID and saved archive config digest are recorded distinctly because the Engine export produced different values. Resource limits and per-run ownership are represented in an argv-only Docker create template, not falsely attributed to immutable OCI image properties. Image build/inspect and saved-layer ELF audit are verified; runtime execution, applied limits, recovery and isolation await later subtasks. See `docs/decisions/0002-p0-mixed-image.md`.

## D-010 — Derived P0-05 image fixes inherited keeper signal dispositions

The original P0-04 init's keeper inherited handled SIGTERM/SIGINT and remained alive after a direct signal, so the old image could not prove forwarding. Preserve the original image, source, lock and audit. Derive a separately locked P0-05 image by replacing only the static amd64 init: the keeper restores default stop-signal dispositions; PID 1 returns success only after the forwarded signal is observed as the keeper's exact signaled exit. A real Docker/binfmt differential verified unexpected keeper death exits 1, while SIGINT to PID 1 exits 0; a full target/runtime probe verified nested execution, reaping and clean SIGTERM stop. No target app files, host binfmt entry, network, public port or foreign container was modified in the derived-image probe. See `docs/decisions/0003-p0-init-signal.md`.

## D-011 — Live quota admission before every frozen subtask

KEEMU uses `quota_admission_scope=every_subtask`. Before each new frozen subtask receives a worker launch, the supervisor fetches live OAuth account usage and persists an admission key containing the subtask ID and digest. A supervisor restart may reuse that same subtask observation before launch, but advancing the active index forces a new observation. Existing same-subtask sessions resume without another preflight. Remaining quota below 11% warns; below 5% stores an absolute wake time, checkpoints and waits. Usage-observer failure remains fail-open without inventing a percentage or reset time.

## D-012 — P0-06 localhost proof uses a constrained Docker-host observer

The Hermes worker network namespace cannot directly observe Docker daemon host loopback, so P0-06 retains explicit `127.0.0.1` TCP/UDP publishing on the AArch64 application container and uses one separate, project-owned native amd64 scratch observer only under the user-approved `--network=host` scope. The observer has no host mutation path, bind mounts, published ports, privilege, writable root, or retained runtime state; it has owner/run-id labels, `cap-drop=ALL`, no-new-privileges and bounded memory/CPU/PID limits. It independently reads the published HTTP health endpoint and UDP echo, records Docker inspect/log evidence, and is owner-checked/removed/absence-verified after each observation. This validates Docker-host loopback reachability without widening the application publish or authorizing later work.

## D-013 — P0-07 NFQUEUE blocker is not a verdict substitution

In project-owned isolation, the native NFNETLINK socket opens but the statically linked AArch64 socket returns `EPROTONOSUPPORT`. The original dynamically linked target consumer also fails the Entware libc version check; static target execution alone does not establish queue support. Host NFQUEUE modules were not active and host-module mutation requires separate approval. No queue binding or rule was attempted. This is an explicit bounded P0 blocker, not A13/A14/A17 PASS; MVP 1C stays blocked. `docs/decisions/0004-p0-nfqueue-gate.md` has the evidence and scope.

## D-014 — P0 closure distinguishes gate completion from acceptance completion

P0 is closed when its `TASK.md` technical-risk conditions have exact evidence: real AArch64 execution, explicit localhost publish plus down/up persistence, and either NFQUEUE ACCEPT/DROP evidence or a reproducible capability blocker, with committed locks and ADRs. P0-07 supplied the latter blocker; it does not make A13/A14/A17 PASS. `docs/evidence/p0-evidence-manifest.md` records recomputed SHA-256 digests for all committed P0 locks and retained ignored runtime reports. ADR-0005 limits the P0-06 Docker-host observer to localhost-evidence collection; it is not a general host-network component or later network-topology authorization.

## D-015 — MVP 1A inputs are versioned and do not confer runtime authority

Scenario, production scenario lock, and persistent-environment inputs use strict version-1 Pydantic models with committed JSON-schema parity. Historical P0 locks retain their original formats; no migration or rewrite is implied. Unknown fields/versions, duplicate YAML/JSON keys and aliases fail closed. Scenario-relative file references may use `..` only when normalized inside the project root and all checked path components are non-symlinks. Target persistence/cleanup paths are canonical absolute `/opt` descendants; host publishing is localhost-only by default and in this schema cannot request public exposure. Lock loading verifies local source bytes and, when bound to a scenario path, scenario bytes against SHA-256, but profile/feed/OCI/QEMU facts and real Docker ownership labels still require later runtime evidence. Loader checks alone do not close validation-to-use races; later consumers need no-follow file opens and rechecks. The persistent-environment model is read-only here: registry writes, locking, reconciliation and cleanup are separate frozen subtasks.

## D-016 — Static IPK inspection is bounded input triage, not installation proof

The m1a-10 inspector reads each IPK with a regular-file/no-follow open, 64 MiB compressed-input cap, 32 MiB member cap, 128 MiB expanded-content cap and 8192-entry cap. It detects the actual selected feed's gzip-tar outer wrapper and supported ar/plain-tar/xz/bzip2 variants from signatures, requires unique `debian-binary`/control/data members, validates tar end markers and never writes archive content to a host tree. It rejects special members, unsafe/duplicate paths, link escapes, symlink-parent traversal, cycles and malformed control/ELF metadata. The bounded ELF parser reads PT_INTERP, DT_NEEDED and limited loader search paths without host `ldd`; optional rootfs lookups never intentionally follow links outside the target `/opt` tree. A rootfs must include resolved dependencies before missing `/opt` loaders/libraries can be package FAIL; absent/non-`/opt` paths and postinst-created links are BLOCKED or WARN rather than false pre-install FAIL. World-writable regular entries fail; setuid/setgid and shebang files not known to be invoked are reported for review rather than assumed fatal. Static PASS only certifies this inspection pass. Install-time input reopening/rehashing, opkg state, exactly-once postinst and target execution remain later subtasks; no A02 acceptance is inferred.

## D-017 — Locked AArch64 base init uses an immutable, audited image cache

For m1a-11, only the existing 20-package P0 AArch64 Entware closure, SHA-256-pinned feed index/bootstrap/QEMU inputs and separately locked corrected native init are accepted. `keemu init --profile generic-aarch64 --locked` invokes real target opkg on local IPKs in a staging rootfs, requires exact installed package names and versions, normalizes only opkg's volatile `Installed-Time` fields, and writes a default target `/opt/etc/opkg.conf`. The origin URL is HTTPS but not an immutable upstream snapshot; init never runs `opkg update`, and later installation must use locally hash-verified IPKs. The static amd64 native init binary is rebuilt and matched to the P0-05 binary SHA-256. The saved single-layer scratch image is audited against every rootfs file/link/mode; Docker COPY strips exactly one setuid bit on `/opt/bin/busybox`, and no other difference is accepted. The committed `locks/m1a-init-aarch64.json` binds the schema-4 cache key, rootfs tree, installed inventory, feed config/index, QEMU binary, saved archive/config/layer and Docker-local image ID (not a registry manifest digest). Build/cache publication uses an interprocess file lock and `renameat2(RENAME_NOREPLACE)` after a bounded, labeled Docker/binfmt smoke; an existing incomplete or divergent cache fails closed. Offline repeat rehashes prepared artifacts and inspects the live image without fetch/build; it requires the local image to remain present. Target shell, default opkg inventory, nested ELF and DNS passed in Docker bridge. TLS was verified only in the Hermes process namespace with default CA/hostname validation because locked target BusyBox wget cannot do HTTPS; this is not target HTTPS evidence. No application fixture install, scenario lifecycle, registry mutation, host configuration or cross-target acceptance is inferred. Two independent builds matched all pinned rootfs/image/archive hashes; SHA-256-bound ignored evidence is in `reports/20260923T202746Z-m1a11-base-init/init-evidence.json`.

## D-018 — Docker boundary is ID-verified and reconciliation is read-only

m1a-12 uses an immutable Docker-local image ID, inspected project/target/native-init labels and a new writable overlay per project/run-labeled container. Fixed argv-only Docker calls impose CPU/RAM/PID/tmpfs/log-driver bounds and prohibit mounts, privileged/host namespaces and added caps; bridge networks are independently owned resources. Exact full-ID inspect with owner, run ID, kind, base and target labels precedes mutation; network removal refuses attachments. Reconciliation enumerates and individually inspects labeled IDs but never auto-deletes unexpected resources or adopts missing resources. A 512 MiB observed writable-layer check can stop an owned container at operation boundaries, but is not a hard/continuous disk quota; Docker log-driver rotation is not detectable by the per-stream retrieval truncation marker. Full registry reconciliation, interruption recovery, host disk budgeting and lifecycle policy remain later tasks. See `docs/decisions/0006-m1a-docker-boundary.md` for live evidence and limitations.
