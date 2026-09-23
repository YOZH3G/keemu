# ADR-0005: Constrained Docker-host observer validates P0 localhost publishing

- Status: accepted for the P0-06 evidence slice only
- Date: 2026-09-23
- Evidence: `reports/20260923T125140Z-p006-aa4677e64b41/probe.json`, SHA-256 `af6a9d03c1f084ba3257cbfab4f81de8aa4af761bbc62ae66de362ba897fd669` (ignored runtime artifact; retain separately)

## Context

The Hermes worker namespace cannot directly observe the Docker daemon host's `127.0.0.1` publishes. P0 requires evidence that the AArch64 web-demo is reachable through explicit localhost TCP and UDP publishes, without widening the application bind or publishing a public port.

## Decision

Use one separately locked, static amd64 scratch observer only under the explicit P0-06 approval for Docker-host network vantage. The observer has project owner/run labels, read-only root, no bind mounts, no published ports, no privilege, all capabilities dropped, no-new-privileges, bounded memory/CPU/PID controls, and no retained state. It performs only HTTP health and UDP echo observations against the exact localhost publishes. Every instance is owner-checked, removed, and independently verified absent.

The application remains a separate bounded bridge-network container with exact `127.0.0.1:18080→8080/tcp` and `127.0.0.1:18081→8081/udp` publishes. The observer source, binary, image, and archive are locked in `locks/p0-host-observer-p006.json`; the web-demo slice is locked in `locks/p0-web-demo-aarch64-p006.json`.

## Consequences and limits

The P0-06 report proves Docker-host-loopback reachability for this locked fixture, plus state persistence across service restart and Docker stop/start. This observer is not a target component, a general production host-network permission, or a network-topology implementation. It does not prove client/router/server routing, NFQUEUE, external LAN reachability, public exposure, or later MVP 1C behavior.
