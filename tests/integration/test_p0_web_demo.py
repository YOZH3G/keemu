from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


@unittest.skipUnless(
    os.environ.get("KEEMU_RUN_P0_WEB_DEMO_PROBE") == "1",
    "set KEEMU_RUN_P0_WEB_DEMO_PROBE=1 after building the p0-06 locked image",
)
class P0WebDemoIntegrationTests(unittest.TestCase):
    def test_live_p0_web_demo_probe_passes(self) -> None:
        result = subprocess.run(  # noqa: S603 -- fixed interpreter and test script.
            [sys.executable, "tests/integration/p0_web_demo_probe.py"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("result=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
