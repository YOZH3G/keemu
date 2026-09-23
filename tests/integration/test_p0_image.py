from __future__ import annotations

import os
import unittest
from pathlib import Path

from keemu.p0_image import verify_image_lock

REPO = Path(__file__).resolve().parents[2]


@unittest.skipUnless(
    os.environ.get("KEEMU_RUN_P0_IMAGE_AUDIT") == "1",
    "set KEEMU_RUN_P0_IMAGE_AUDIT=1 after building and saving the locked image",
)
class P0ImageIntegrationTests(unittest.TestCase):
    def test_live_image_and_saved_layer_match_lock(self) -> None:
        counts = verify_image_lock(
            REPO / "locks/p0-mixed-image-aarch64.json",
            REPO / ".runtime/p0/mixed-image.tar",
        )
        self.assertEqual(counts, {"aarch64": 28, "amd64": 1})


if __name__ == "__main__":
    unittest.main()
