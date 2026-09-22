from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from keemu.p0 import build_diagnostic_rootfs, run_proot_smoke

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / ".runtime" / "p0"


@unittest.skipUnless(
    os.environ.get("KEEMU_RUN_P0_DIAGNOSTIC") == "1",
    "set KEEMU_RUN_P0_DIAGNOSTIC=1 after fetching locked P0 artifacts",
)
class P0DiagnosticIntegrationTests(unittest.TestCase):
    def test_aarch64_shell_opkg_child_elf_and_shebang(self) -> None:
        with tempfile.TemporaryDirectory(dir=RUNTIME) as directory:
            rootfs = Path(directory) / "rootfs"
            result = build_diagnostic_rootfs(
                lock_path=REPO / "locks" / "p0-aarch64.json",
                package_cache=RUNTIME / "aarch64-k3.10" / "packages",
                destination=rootfs,
                qemu=RUNTIME / "qemu-user-root" / "usr" / "bin" / "qemu-aarch64",
                bootstrap_opkg=RUNTIME / "aarch64-k3.10" / "opkg",
            )

            smoke = run_proot_smoke(
                rootfs=rootfs,
                qemu=RUNTIME / "qemu-user-root" / "usr" / "bin" / "qemu-aarch64",
                proot=RUNTIME / "proot-root" / "usr" / "bin" / "proot",
                proot_library_path=RUNTIME
                / "proot-root"
                / "usr"
                / "lib"
                / "x86_64-linux-gnu",
            )

        self.assertEqual(result.package_count, 20)
        self.assertIn("busybox - 1.37.0-6", result.installed_packages)
        self.assertEqual(
            smoke.stdout.splitlines(),
            [
                "target-shell-ok",
                "opkg version 80503d94e356476250adaf1f669ee955ec26de76 (2025-11-05)",
                "nested-elf-ok",
                "shebang-child-ok",
                "aarch64",
            ],
        )


if __name__ == "__main__":
    unittest.main()
