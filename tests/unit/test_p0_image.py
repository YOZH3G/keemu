from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from keemu.p0_image import CONTAINER_LIMITS, audit_tree, container_create_argv


class P0ImageTests(unittest.TestCase):
    def test_container_template_has_identity_and_limits_without_forbidden_flags(
        self,
    ) -> None:
        args = container_create_argv("keemu-p0", "sha256:" + "a" * 64, "p0run")
        self.assertIn("--platform", args)
        self.assertIn("linux/amd64", args)
        self.assertIn("--label", args)
        self.assertIn("org.keemu.run-id=p0run", args)
        for limit in CONTAINER_LIMITS:
            self.assertIn(limit, args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--network=host", args)
        self.assertNotIn("--pid=host", args)
        self.assertNotIn("--mount", args)
        with self.assertRaises(ValueError):
            container_create_argv("foreign", "sha256:" + "a" * 64, "p0run")

    def test_architecture_audit_rejects_foreign_application_elf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("bin/sh", "opt/bin/opkg", "opt/bin/busybox", "__keemu/init"):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"\x7fELF" + bytes([2, 1]) + bytes(12) + b"\x3e\x00")
            with self.assertRaisesRegex(ValueError, "wrong ELF architecture"):
                audit_tree(root)


if __name__ == "__main__":
    unittest.main()
