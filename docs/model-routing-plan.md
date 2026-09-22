# KEEMU model-routing plan

This table is encoded in the supervisor configuration. The supervisor applies an exact provider/model/reasoning lock per subtask and switches only after an attested completion boundary.

| # | ID | Phase / acceptance | Tier | Model | Reasoning | Objective |
|---:|---|---|---|---|---|---|
| 1 | `preflight` | P0, resume-safety | C0 | `gpt-5.6-luna` *(actual)* | `low` | Read-only revalidate the current repository, environment, Docker/binfmt/kernel capability gates, locked artifacts, and durable checkpoint before implementation |
| 2 | `p0-01` | P0, A21 | C3 | `gpt-5.6-terra` | `high` | Stabilize the current profile, doctor, common report model, schema parity, aggregation, exit-code, and CLI test slice with an honest no-Docker BLOCKED report |
| 3 | `p0-02` | P0, A21 | C4 | `gpt-5.6-sol` *(actual)* | `high` | Expand A21 report primitives for immutable run, artifact, scenario, profile, runtime, capability, coverage, operation-log, and partial-failure metadata |
| 4 | `p0-03` | P0, A01, A19 | C3 | `gpt-5.6-terra` | `high` | Build reproducible hello, web-demo, and NFQUEUE fixture sources and recipes with real provenance, architecture metadata, dependencies, and SHA-256 locks |
| 5 | `p0-04` | P0, A01, A18, A20 | C4 | `gpt-6-sol` | `high` | Create and lock the mixed AArch64 OCI image with native init, target rootfs, explicit ownership labels, resource limits, and architecture audit |
| 6 | `p0-05` | P0, A01, A18 | C4 | `gpt-6-sol` | `high` | Prove Docker/binfmt target shell, child ELF, shebang, daemon survival, signal forwarding, process reaping, and clean container shutdown |
| 7 | `p0-06` | P0, A07, A08, A09 | C3 | `gpt-5.6-terra` | `high` | Prove web-demo localhost-only publishing and persistent state across down/up with reproducible evidence and cleanup |
| 8 | `p0-07` | P0, A13, A14, A17 | C5 | `gpt-6-sol` | `xhigh` | Run native-control and target AArch64 NFQUEUE ACCEPT/DROP experiments in project-owned isolation and record evidence or a bounded blocker |
| 9 | `p0-08` | P0, A19, A21 | C2 | `gpt-5.6-terra` | `medium` | Close the P0 evidence package with real digests, ADRs, limitations, progress, and traceability without overstating blocked capabilities |
| 10 | `m1a-09` | MVP1A, A18, A21 | C4 | `gpt-6-sol` | `high` | Implement strict versioned input schemas for scenarios, locks, persistent environments, publishing, checks, persistence, cleanup, and safe paths |
| 11 | `m1a-10` | MVP1A, A01, A02 | C5 | `gpt-6-sol` | `xhigh` | Implement safe bounded IPK inspection including format detection, extraction defenses, metadata, architecture, ELF, interpreter, dependency, shebang, and permission checks |
| 12 | `m1a-11` | MVP1A, A01, A19 | C4 | `gpt-6-sol` | `high` | Implement locked init plus rootfs and image cache with hash verification, atomic publication, installed-package inventory, network smoke, and OCI digest recording |
| 13 | `m1a-12` | MVP1A, A18, A20 | C5 | `gpt-6-sol` | `xhigh` | Implement the Docker runtime boundary with argv-only execution, labels, limits, immutable bases, writable layers, bounded logs, ownership-verified cleanup, and reconciliation |
| 14 | `m1a-13` | MVP1A, A02, A03, A04, A05, A06, A18, A21 | C5 | `gpt-6-sol` | `xhigh` | Implement lifecycle pipeline and truthful failure semantics from validation and inspection through install, checks, remove, residual comparison, report, and guaranteed cleanup |
| 15 | `m1a-14` | MVP1A, A03, A04, A05, A06, A18 | C5 | `gpt-6-sol` | `xhigh` | Implement atomic persistent registry and safe CLI lifecycle operations with concurrency control and replacement rejection |
| 16 | `m1a-15` | MVP1A, A02, A03, A04, A05, A06, A07, A08, A09, A19 | C4 | `gpt-6-sol` | `high` | Complete AArch64 hello, HTTP, trusted-local-CA HTTPS, UDP, explicit-vantage, restart, persistence, and offline locked-repeat fixtures |
| 17 | `m1a-16` | MVP1A, A18, A20 | C5 | `gpt-6-sol` | `xhigh` | Verify interruption recovery, collisions, timeout, stale registry, cleanup retries, isolation, capabilities, sockets, limits, and foreign-resource preservation |
| 18 | `m1a-17` | MVP1A, A01-A09, A18-A21 | C4 | `gpt-6-sol` | `high` | Run and freeze the MVP 1A acceptance bundle on a suitable clean Docker/binfmt runner with exact PASS, FAIL, SKIP, and BLOCKED results |
| 19 | `m1b-18` | MVP1B, A01, A10 | C5 | `gpt-6-sol` | `xhigh` | Add locked MIPSEL and MIPS targets and verify architecture, endianness, ABI, ISA, FPU, shell, nested execution, opkg, and applicable fixtures |
| 20 | `m1b-19` | MVP1B, A10 | C4 | `gpt-6-sol` | `high` | Implement matrix validation and sequential execution with honest architecture-mismatch, unsupported-target, and aggregate status semantics |
| 21 | `m1b-20` | MVP1B, A11 | C4 | `gpt-6-sol` | `high` | Implement the strict stateful NDM shim with exact process contracts, redacted logs, unknown-call failure, and environment-gap propagation |
| 22 | `m1b-21` | MVP1B, A12 | C5 | `gpt-6-sol` | `xhigh` | Implement only evidenced synthetic event contracts with deterministic handler order, environment, timeouts, and repeat restoration |
| 23 | `m1b-22` | MVP1B, A01-A06, A10, A11 | C5 | `gpt-6-sol` | `xhigh` | Run full three-target acceptance and per-target capability probes with immutable evidence and honest BLOCKED results |
| 24 | `m1c-23` | MVP1C, A13, A18, A20 | C5 | `gpt-6-sol` | `xhigh` | Implement isolated client-router-server topology with collision-free subnets, br0 and wan0, routes, forwarding, ownership, no management bypass, and safe cleanup |
| 25 | `m1c-24` | MVP1C, A14, A15, A16, A17 | C5 | `gpt-6-sol` | `xhigh` | Build network-demo around the proven target NFQUEUE consumer with API, web UI, state, counters, persistence, health-flow exclusion, and lifecycle hooks |
| 26 | `m1c-25` | MVP1C, A15, A16 | C4 | `gpt-6-sol` | `high` | Verify network-demo web and API behavior plus service and environment persistence using distinct result records |
| 27 | `m1c-26` | MVP1C, A14, A17 | C5 | `gpt-6-sol` | `xhigh` | Verify target packet processing end to end with routed flow, consumer and kernel counters, ACCEPT, DROP, restored ACCEPT, and bounded packet evidence |
| 28 | `m1c-27` | MVP1C, A18, A20 | C5 | `gpt-6-sol` | `xhigh` | Run controlled interruption and isolation regressions for network resources while proving foreign containers, networks, and rules remain untouched |
| 29 | `final-28` | Completion, A01-A21 | C4 | `gpt-6-sol` | `high` | Generate and validate the final A01-A21 acceptance ledger against existing immutable reports, tests, targets, statuses, and contradictions |
| 30 | `final-29` | Completion, A01-A21 | C5 | `gpt-6-sol` | `xhigh` | Run release verification once across portable, three-target, applicable network, schema, static, offline-repeat, and clean-host checks |
| 31 | `final-30` | Completion, A21 | C2 | `gpt-5.6-terra` | `medium` | Close documentation and durable state so README, architecture, decisions, limitations, progress, traceability, checkpoints, and cleanup match verified behavior |
| 32 | `final-31` | Completion, A01-A21 | C5 | `gpt-6-sol` | `xhigh` | Perform an independent evidence audit and produce either an auditable MVP completion statement or an exact remaining-BLOCKED list |

## History

Rows marked *(actual)* are attested historical workers and intentionally preserve the IDs that ran. All unmarked future Luna/Sol assignments use the refreshed ChatGPT 6 policy.

## Escalation policy

- C6/C7 (`gpt-6-astra`) are unlocked but are not primary assignments in this initial plan. They are reserved for a new worker after an evidenced C5 failure and an audited subtask boundary.
- If Astra is unavailable on the live OAuth route, the configured fallback is C5 (`gpt-6-sol`, `xhigh`).
- Protected production, security, destructive, or remote operations retain a non-bypassable C4 floor.
- Quota pauses do not switch models: the same provider, model, reasoning, session, and subtask lock are resumed.
