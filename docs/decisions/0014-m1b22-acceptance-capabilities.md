# ADR-0014 — Freeze blocked cross-target acceptance with non-mutating socket differentials

Date: 2026-09-24

## Context

MIPS/MIPSEL roots and Docker/binfmt target execution passed m1b-18, but `keemu init/test` support only AArch64. m1b-19's complete matrix recorded unsupported MIPS lifecycles as BLOCKED. A11 has only a synthetic host-local shim. A three-target acceptance observation must preserve those distinctions and compare network capabilities without crossing TASK.md's host module/firewall approval boundary.

## Decision

Run all currently applicable opt-in real Docker tests together with offline MIPS root/image verification and the real complete matrix. Independently capture portable tests and each profile's read-only doctor. In three separately owned, network-none, cap-drop-all, read-only-root containers, stage a freshly compiled target socket probe and a clearly identified native control into bounded executable tmpfs; attempt only `NETLINK_NETFILTER` socket creation. Do not bind a queue, change iptables/ipset, start packet flow, autoload modules or change host state. Preserve exact per-target exit/stderr, native control, source/binary hashes, module snapshots, full Docker identities and cleanup. Publish no-replace tracked raw JUnit, matrix parent/child, doctor and probe plus a SHA-256-bound ledger. Retain historical ledgers unchanged.

## Result and boundary

All three target sockets returned `Protocol not supported`/1; native same-namespace controls opened/0; no loaded NFQUEUE module changed. This does not establish whether QEMU translation, seccomp or kernel behavior is causal. Target backend presence is not backend/extension function proof. No ipset create, conntrack, forwarding, raw socket, queue, verdict or packet acceptance was tested. Doctor BLOCKED/4 in worker binfmt namespace coexists with proven Docker target exec. A01 specified target-exec PASS; A02–A06/A10/A11 and MVP 1B BLOCKED. No physical Keenetic observation, MIPS lifecycle or S1/S2 network acceptance follows. Raw/ledger paths and SHA-256 digests: `docs/evidence/m1b22-acceptance.md`.

A first attempt clipped Docker inspect JSON; later attempts found Docker `cp` refused even writable tmpfs below a read-only root and bare `cat` was not installed. Each created container was owner-verified and removed; the successful probe used the target BusyBox `cat` applet through `docker exec -i`, without relaxing the container root or host namespace. Those initial attempts are not counted as evidence of a working capability.
