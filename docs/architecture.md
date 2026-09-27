# Architecture

## Status

This document describes verified P0 foundations and bounded MVP 1A, MVP 1B and
MVP 1C slices. It is not a production-complete architecture: final-28 marks
only the specified A01 three-target execution check PASS; A02–A21 whole release
IDs remain BLOCKED, and final-29 release verification is BLOCKED.
MVP 1D is separate on `staging`. Its independent final D01–D08 verdict is in
`docs/evidence/mvp1d-m1d13-final-audit.json`: D01/D03/D04/D05/D06/D08
PASS at bounded scope; D02/D07 and MVP 1D release BLOCKED. No original MVP 1
release result changes.

## Implemented components

- `src/keemu/scenarios.py`, `src/keemu/input_locks.py`, and `src/keemu/input_paths.py` define strict, frozen schema-version-1 input models for scenarios, production source locks, persistent-environment entries, explicit TCP/UDP publication, vantage-aware checks, persistence, cleanup and bounded safe paths. The committed JSON schemas are generated from these models and parity-tested. Duplicate YAML/JSON keys, unknown fields and unsupported versions fail closed. The loaders confine scenario-relative inputs to the project, reject symlink components, and compare source/scenario SHA-256 values against production lock metadata; runtime profile/image/ownership proof and mutation remain later tasks. Historical P0 locks are unchanged.
- `src/keemu/entware.py` parses an Entware package index, resolves a dependency closure, creates lock data, and verifies cached artifacts by SHA-256.
- `src/keemu/ipk_inspect.py` implements bounded, in-memory, no-extraction IPK inspection. `keemu inspect PACKAGE [--profile ID] [--rootfs DIR]` detects ar, gzip/xz/bzip2 tar and plain tar by signature; validates the outer `debian-binary`, control and data members, archive limits, paths, links and types before examining control metadata and scripts, ELF machine/class/endian/OSABI/flags, PT_INTERP, DT_NEEDED and limited RUNPATH/RPATH, shebangs and file modes. It never calls host `ldd` or executes package content. A supplied rootfs must contain resolved dependencies; unprovided or non-`/opt` interpreter paths and uncertain postinst-created paths remain BLOCKED until later runtime checks. Inspection output carries `mode=static` and scope limitations; it is not an A02 installation result or a full A01 proof.
- `src/keemu/p0.py` constructs an AArch64 diagnostic rootfs with the real target `opkg` under direct QEMU user-mode and runs nested target execution through unprivileged PRoot.
- `src/keemu/cli.py` exposes `keemu p0 verify-lock` for offline verification of the committed package lock.
- `locks/p0-aarch64.json` records the exact Entware package closure and diagnostic tool artifacts used by the first experiment.
- `fixtures/sources/` contains project-owned AArch64 hello, web-demo, and raw-NFQUEUE-consumer sources. `fixtures/recipes/aarch64/` compiles them with a staged, SHA-256-locked Debian cross toolchain. `locks/p0-fixtures-aarch64.json` records source, recipe, toolchain, dependency, architecture, and verified-output hashes; `keemu p0 verify-fixture-lock` validates those records without downloading.
- `src/keemu/models.py` defines current `RunReport` schema version 2 with strict, frozen metadata for checked artifacts, scenarios, profiles, runtime provenance, capabilities, substitutions, checks, coverage, operation records, and partial failures. Each partial failure references an exact operation-log sequence; validation requires the referenced record's operation name and failure status to match.
- `src/keemu/reports.py` derives aggregate status and coverage, rejects inconsistent report payloads, renders Markdown from the JSON source object, and atomically publishes immutable run bundles with a JSONL operation log using Linux `renameat2(..., RENAME_NOREPLACE)`.
- `src/keemu/doctor.py` emits the common report model with a canonical profile hash, profile revision, host kernel, Entware target, Python version, and explicit capability results. Uncollected OCI, QEMU, Git, feed-lock, and network-fidelity values remain `null` rather than being invented.
- `src/keemu/p0_image.py` rebuilds the locked AArch64 rootfs, compiles a static amd64 PID 1 from `fixtures/recipes/aarch64/keemu-init.c`, audits every rootfs ELF, and builds a scratch `linux/amd64` image with the target architecture in ownership/provenance labels. The content-addressed image ID, saved-layer hash, architecture inventory, and an unexecuted, bounded container-create template are recorded in `locks/p0-mixed-image-aarch64.json`.
- `src/keemu/init_cache.py` and `keemu init --profile generic-aarch64 --locked` rehash the 20 P0 IPKs, compressed/uncompressed feed index, bootstrap opkg, QEMU DEB and extracted binary, and corrected native-init source/binary. Real target opkg installs the local closure; exact versions/names are checked from `list-installed`. The variable `Installed-Time` fields are normalized to zero after installation. The finished rootfs contains a default `/opt/etc/opkg.conf` and a JSON inventory. A scratch `linux/amd64` image is built without Docker build networking, and every saved-layer file, symlink, byte and mode is compared against the input tree. Docker COPY strips the setuid bit from `/opt/bin/busybox`; that single attenuation is explicit and locked. `locks/m1a-init-aarch64.json` pins the rootfs tree, installed inventory, QEMU binary, feed index/config, saved archive/config/layer and Docker-local content-addressed image ID. A file lock serializes builds and `renameat2(RENAME_NOREPLACE)` publishes only a complete immutable cache directory; offline repeat rehashes it without fetching. The live Docker smoke uses owner/run-id-labeled, resource-bounded, read-only bridge containers and verifies target shell, nested ELF, default opkg inventory and DNS before owner-checked removal. HTTPS is checked separately in the Hermes process network namespace with CA/hostname verification, not in the target container (locked BusyBox wget has no TLS support).
- `src/keemu/docker_runtime.py` implements a narrow argv-only Docker boundary: immutable local image-ID and label validation, project/run/base/target-labeled bridge networks and containers, bounded CPU/RAM/PID/tmpfs/log settings with Docker inspect readback, fresh writable layer per container, full-ID ownership-gated start/stop/exec/removal, read-only Docker-label reconciliation, and an observed writable-layer threshold check. No host bind/volume/socket, host namespace, privileged container, capability addition or port publication is accepted. See ADR-0006.
- `src/keemu/lifecycle.py` runs one-shot, disposable, locked IPKs: validation with no-follow read/rehash, static inspection, offline cache and image verification, owner-checked Docker create, target opkg install, inventory/check/readiness/stop/remove/residual stages, finally cleanup and write-once evidence. Unexpected exits and timeouts retain their primary failure plus independent cleanup status. Metadata-only Docker diff is not a file-content or full process/socket census; network vantage and general persistent acceptance are later. See ADR-0007.
- `src/keemu/matrix.py` and `schemas/matrix.schema.json` bind each named target to its own strict scenario and production lock, reject duplicate profiles and malformed inputs before Docker, and mark missing required targets BLOCKED. The preflight reopens locked IPK/profile inputs and uses static inspection for architecture mismatch FAIL; MIPS/MIPSEL general lifecycle is still unsupported and thus BLOCKED. Supported child runs execute sequentially through the existing one-shot runner, retaining independent immutable reports; parent `RunReport` aggregates per-case checks using the established ERROR → FAIL → BLOCKED → WARN → PASS rule, with child report path/hash and source matrix bytes. No target-specific PASS is inferred from the earlier MIPS root probes. See ADR-0011.
- `src/keemu/registry.py`, `src/keemu/persistent.py`, and CLI `up/down/restart/destroy/status/ports/logs/exec/recover` provide a limited persistent AArch64 IPK environment without host publication. Owner-only per-name flock serializes transitions; no-replace creation, fsynced atomic JSON replacement, frozen scenario snapshot, immutable identity checks, and permanent tombstones reject replacement. Every ordinary operation rechecks Docker full ID, run/base/target labels and actual state. Explicit `recover --yes` reconciles a failed/interrupted record, admits at most one unrecorded container only with the exact deterministic name and matching run ownership, rejects foreign/extra resources, verifies absence and tombstones; it never retries uncertain install/service actions. The one-shot report pipeline is not reused for persistent commands. See ADR-0008 and ADR-0010.
- `src/keemu/ndm.py` and `src/keemu/events.py` provide strict host-local synthetic process/event contracts only. They do not establish target `ndmc`, physical-device behavior, a kernel firewall hook, or A11/A12 acceptance.
- `src/keemu/topology.py` creates owner-labeled internal LAN/WAN Docker bridges and an AArch64 client/router/server topology with target `br0`, endpoint-named `wan0`, namespace forwarding and explicit full-ID cleanup. `src/keemu/network_demo.py` stages the locked AArch64 network-demo fixture and its diagnostic API. The m1c-26 packet slice uses declared native NFQUEUE transport and native `iptables-legacy` substitutions inside the owned router; direct target `NETLINK_NETFILTER` and target iptables remain unsupported.

## Separate MVP 1D script path

`ScriptInput` in `src/keemu/script_input.py` confines `.sh` files to the
project root with descriptor-relative no-follow opens, regular-file/single-link
and 1 MiB bounds, SHA-256 identity and a use-time inode/metadata/byte recheck.
`ScriptStager` transfers only its frozen bytes via bounded Docker stdin into a
new `/opt/tmp/keemu-script-<sha256>-<nonce>/script.sh`; private directory and
shell noclobber prohibit ordinary overwrite. Full-ID/label, target inode and
byte-readback checks surround target operations. It does not broaden the
IPK-only `docker cp` path.

`ScriptProcessRunner` stages a SHA-256-pinned static native helper next to the
issued script. Inside the owned container PID namespace it starts target
`/bin/sh` with explicit cwd, minimal environment and separate bounded streams;
subreaper, process ancestry, pidfds, TERM/KILL and reaping prove normal timeout
descendants absent without signaling unrelated processes. `script_results.py`
and `script_assertions.py` keep raw output, argv and expected needles only in
memory; `RunReport.script` serializes identities/counts/hashes/truncation,
typed assertions and cleanup, not secret-bearing plaintext. Filesystem checks
use constant target shell code with a separate validated `/opt` path argument.

`script_lifecycle.py` owns a fresh locked AArch64 container for `keemu script`;
`script_persistent.py` holds a registry name lock and verifies the running
environment before/after `keemu exec NAME --script`, removing no container or
service. `script_scenario.py` dispatches version-1 SHA-256-locked `kind: script`
checks via the same stager/runner/assertions inside the one-shot IPK scenario;
schemas retain parity. MIPS/MIPSEL enter the same host input/typed report path
but stop at a truthful capability BLOCKED before allocation, not a separate
target-probe executor. Host-worker SIGKILL is distinct from target timeout:
one-shot recovery was explicit in tests, while persistent SIGKILL retains an
artifact with no automatic recovery or interrupted report. Target shell
stat-to-unlink cannot atomically exclude a hostile concurrent same-UID swap.
See ADR-0019 and the m1d-12 ledger; m1d-13 final audit remains separate.

## P0 diagnostic data flow

1. A committed lock names every package, version, URL, architecture, and expected SHA-256.
2. Downloaded artifacts remain under `.runtime/` and are never committed.
3. `verify_artifact_cache` rejects missing, unsafe, or hash-mismatched package files.
4. `build_diagnostic_rootfs` invokes the real AArch64 bootstrap `opkg` through QEMU with argv only and installs the locked local IPK files into a temporary rootfs.
5. The completed rootfs is atomically renamed into place. Failed construction removes the temporary directory.
6. `run_proot_smoke` uses a minimal environment and verifies target shell, target `opkg`, a nested target ELF, and a target-shebang script.

## Required production architecture not yet implemented

The accepted runtime remains Docker Engine on Linux x86_64. P0 image/target/init probes and the m1a-12 runtime boundary were exercised on the approved AArch64 binfmt runner. Each created container gets a new writable overlay; persistent down/up and restart retain the same full container ID and layer. The atomic registry and explicit failed/interrupted persistent cleanup have real SIGKILL evidence for this bounded IPK path. Automatic recovery, one-shot crash journaling, complete host/disk isolation and network-resource recovery remain open.

The verified network topology is a bounded client/router/server implementation
in project-owned internal Docker networks. It proved routed HTTP, controlled
SIGKILL cleanup and one substituted packet fixture, but not generic scenario
network lifecycle, direct target NFQUEUE, hostile-route isolation, automatic
recovery, or full MVP 1C acceptance.

## Trust boundaries

- Package input is untrusted. The inspector rejects oversized and malformed wrappers, files, special members, path escapes, symlink traversal/cycles, bad control fields and ELF structures without extracting to the project or executing anything. One-shot `test` reopens and rehashes the pinned IPK, statically inspects a private copy, and hashes a target copy-back before opkg install. These in-process bounds are not an OS sandbox for package execution; other consumers must independently revalidate at use.
- Commands are argv arrays. In MVP 1D, user script bytes execute only as a staged target file through `/bin/sh` in an owned environment, not through the host shell or a content-derived `-c` command. Existing trusted diagnostic shell commands and target opkg maintainer scripts retain their separate scope; untrusted application/fixture installation is not part of `init`.
- The PRoot path is diagnostic only and is not a container isolation boundary.
- Reports and runtime state are generated outside Git; lock files, recipes, schemas, and tests belong in Git.
- Published report directories are write-once evidence: atomic no-replace publication preserves any existing destination entry and fails closed when the required Linux primitive is unavailable.
