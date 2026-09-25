# ADR-0018: Final release documentation preserves observed status

Status: accepted for frozen `final-30` documentation closure.

## Decision

Documentation and durable state use only verified final-28 and final-29 evidence.
`docs/evidence/final28-acceptance.json` remains authoritative for whole release
IDs: A01 is PASS only for its specified three-generic-target execution check;
A02–A21 remain BLOCKED. `docs/evidence/final29-release.json` records the later
release observation: 233 PASS, 2 missing-image prerequisite FAIL and 3
intentional SKIP cases in the retained full sweep; portable checks passed 208
with 30 opt-in skips. Release remains BLOCKED.

The release documents retain the fresh-check boundaries: direct target NFNETLINK
is BLOCKED on all three targets, the packet-verdict job and fresh Ubuntu check
were NOT RUN, and the shared host had 0 KEEMU owner containers/networks, taint
0, retained `nfnetlink_queue`, and absent `xt_NFQUEUE`, `iptable_filter` and
`nft_queue`. Repository-wide formatting still fails on six unchanged committed
files.

## Consequences

No missing historical Docker image is imported or replaced because saved export
config digests do not establish the locked Docker-local IDs. No historical
ledger, lock, raw evidence, module state, firewall state or test outcome is
rewritten to improve release status. Final-31 remains a separate independent
audit and is paused pending explicit human continuation.

## Verification

`uv run python -m scripts.validate_final28` and
`uv run python -m scripts.validate_final29` validate retained evidence without
new privileged execution. Documentation closure additionally runs portable tests,
Ruff, whitespace and reference checks.
