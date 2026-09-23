# Limitations

## Current verified boundary

The P0 technical-risk gate has real AArch64 evidence for Docker/binfmt target execution, localhost-only HTTP/UDP publishing, and state persistence across service restart and Docker stop/start. Its NFQUEUE requirement is closed as a reproducible BLOCKED capability diagnosis, not an ACCEPT/DROP result. Exact inputs and report digests are in `docs/evidence/p0-evidence-manifest.md`.

## Known limitations

- Docker Engine 29.7.2 is reachable through a privileged host socket. The separately approved `qemu-aarch64` binfmt registration must be revalidated after reboot or runner change. No privileged target container or public port was used.
- P0-05 proves AArch64 target shell/opkg/child/shebang execution and bounded native-init signal/reaping behavior. It does not prove cross-target support or interruption/stale-resource recovery. The direct-shebang check used an explicitly executable disposable `/tmp` tmpfs because the baseline noexec tmpfs cannot run test files.
- P0-06 proves only the locked web-demo slice: explicit `127.0.0.1` TCP/UDP publishes, Docker-host-vantage HTTP/UDP observation through an explicitly approved constrained host-network observer, and persisted state. It is not a general `up`/`down` lifecycle implementation and does not expose a public service.
- The host observer is an evidence instrument, not an application or general network-runtime component. It had no mounts, privilege, published port, retained state, or host mutation path; it was owner-checked and removed after each observation.
- The NFQUEUE diagnostic did not bind a queue, install a rule, send a packet, produce a verdict, load a host module, or create a network topology. Native socket creation does not prove target NFQUEUE capability; the static target socket returned `EPROTONOSUPPORT`, and the original dynamic target consumer needs unavailable `GLIBC_2.34`.
- MIPS and MIPSEL artifacts and execution are untested. IPK archive safety analysis, lifecycle scripts, scenario execution, matrices, NDM fixtures, event contracts, persistent registry, filesystem diff, and full acceptance runs are not implemented.
- Common `RunReport` schema-version-2 metadata and immutable bundle primitives exist, but most later runtime producers do not yet populate full lifecycle provenance.
- PRoot is not a security or container-isolation boundary. A generic AArch64 result does not establish compatibility with a Keenetic model or KeeneticOS release.

## Truthfulness rule

P0 completion means its four technical-risk conditions have evidence or an explicit reproducible blocker. It is not a claim that every acceptance ID is PASS, that NFQUEUE ACCEPT/DROP works, or that MVP 1 is complete. Missing checks remain NOT RUN, PARTIAL, or BLOCKED as shown in `docs/traceability.md`.
