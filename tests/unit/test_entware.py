from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from keemu.entware import (
    ArtifactIntegrityError,
    build_entware_lock,
    parse_package_index,
    resolve_dependency_closure,
    verify_artifact_cache,
)

INDEX = b"""Package: app
Version: 1.0-1
Depends: libc (>= 2.0), helper | helper-alt
Architecture: aarch64-3.10
Filename: app_1.0-1_aarch64-3.10.ipk
SHA256sum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Package: libc
Version: 2.27-12
Architecture: aarch64-3.10
Filename: libc_2.27-12_aarch64-3.10.ipk
SHA256sum: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

Package: helper
Version: 3-2
Depends: libc
Architecture: all
Filename: helper_3-2_all.ipk
SHA256sum: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
"""


class PackageIndexTests(unittest.TestCase):
    def test_resolves_transitive_dependencies_and_first_available_alternative(
        self,
    ) -> None:
        packages = parse_package_index(INDEX)

        closure = resolve_dependency_closure(packages, ["app"])

        self.assertEqual(
            [package.name for package in closure], ["app", "libc", "helper"]
        )
        self.assertEqual(closure[0].version, "1.0-1")
        self.assertEqual(closure[2].architecture, "all")

    def test_builds_deterministic_lock_with_source_urls_and_index_hash(
        self,
    ) -> None:
        lock = build_entware_lock(
            INDEX,
            target="aarch64-3.10",
            roots=["app"],
            index_url="https://example.invalid/aarch64/Packages.gz",
            base_url="https://example.invalid/aarch64",
            captured_at="2026-09-22T07:00:00Z",
        )

        self.assertEqual(lock["schema_version"], 1)
        self.assertEqual(lock["kind"], "entware-rootfs-lock")
        self.assertEqual(lock["root_packages"], ["app"])
        self.assertEqual(
            lock["source"]["index_sha256"],
            "0c0b84dca4422dd710a831e190bdc235e65efc2bff5d81e5a25418a675f94c35",
        )
        self.assertEqual(
            [artifact["url"] for artifact in lock["packages"]],
            [
                "https://example.invalid/aarch64/app_1.0-1_aarch64-3.10.ipk",
                "https://example.invalid/aarch64/libc_2.27-12_aarch64-3.10.ipk",
                "https://example.invalid/aarch64/helper_3-2_all.ipk",
            ],
        )


class ArtifactCacheTests(unittest.TestCase):
    def test_verifies_every_locked_artifact(self) -> None:
        payloads = {"one.ipk": b"first", "two.ipk": b"second"}
        lock = {
            "packages": [
                {"filename": name, "sha256": hashlib.sha256(payload).hexdigest()}
                for name, payload in payloads.items()
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in payloads.items():
                (root / name).write_bytes(payload)

            verified = verify_artifact_cache(lock, root)

        self.assertEqual(verified, ["one.ipk", "two.ipk"])

    def test_rejects_corrupt_locked_artifact(self) -> None:
        lock = {"packages": [{"filename": "one.ipk", "sha256": "0" * 64}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.ipk").write_bytes(b"corrupt")

            with self.assertRaisesRegex(
                ArtifactIntegrityError, "hash mismatch: one.ipk"
            ):
                verify_artifact_cache(lock, root)


if __name__ == "__main__":
    unittest.main()
