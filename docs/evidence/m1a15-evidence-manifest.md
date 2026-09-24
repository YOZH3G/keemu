# m1a-15 AArch64 fixture evidence manifest

Verified 2026-09-24 on `agent/keemu`. Generated reports and local SDK/images are ignored runtime artifacts; no private key is retained in Git.

| Artifact | SHA-256 | Verified meaning |
|---|---|---|
| `locks/m1a15-https-frontend-aarch64.json` | `d262750456cfbe31cfbe69fb098bcdc400b95895a3bb93a5b16c246c1bae5b0c` | Source/recipe/binary/SDK hashes and local image IDs |
| `.runtime/m1a15/https-frontend-aarch64` | `857719c919b01eb1091c83ef31a620ec06e0849d51ce7e56ced449cd95b3b4f0` | Offline clean rebuild from hash-checked SDK and locked cross-toolchain; static ELF64 AArch64 |
| `.runtime/m1a15/live-m1a15-0303315534cc/evidence.json` | `6758497e7db513891b6f2f9ae089518903293edda6793cee50172e625d8843a3` | Docker-host-loopback HTTP/HTTPS/UDP (HTTP 200 and marker), trusted-CA and wrong-hostname/untrusted-CA negative checks, service and same-ID container restart, state persistence, no remaining target container or runtime private keys |
| `reports/m1a15-hello-a87c53187c26/report.json` | `8531be7800fbb991d38eb2ec4b74c70199dc465fba9641b3525c543e131932e7` | First offline locked hello one-shot PASS |
| `reports/m1a15-hello-145ba7fe0533/report.json` | `4cbcb1dc7228d94b73522659cad2e500e88cb603641d531733134e393fb2a962` | Second independent offline locked hello one-shot PASS |

Both hello reports bind scenario SHA-256 `aaf707d649668855612f5e4304c5fa88a67e21d33d9b810cdcfcb90f11deebac` and IPK SHA-256 `edc908200824a64ea3347f7fc29a8f8eb3fc1b214078eff55b12e45c02ecba7f`. The test used `init_locked(..., offline=True)`, rejected `urllib.request.urlopen`, and verified complete owner cleanup. These are local prepared-cache repeats, not proof of an air-gapped Docker daemon. The fixture-only TLS probe is not a `keemu up`/`test` published-service report.

Verification: `KEEMU_M1A15_LIVE=1 KEEMU_TEST_LIFECYCLE=1 KEEMU_TEST_PERSISTENT=1 uv run pytest -q tests/integration/test_m1a15_https.py tests/integration/test_lifecycle.py` returned 13 passed; default portable suite returned 124 passed, 18 opt-in skipped. Ruff, formatter check and `git diff --check` passed; Docker owner-label container/network queries returned empty. Existing A04/A05/A06 defect/failure cases are in the live lifecycle suite; broader cross-target and generic host-published lifecycle acceptance remains PARTIAL.
