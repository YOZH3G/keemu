from __future__ import annotations

import hashlib
import json
from pathlib import Path

from click.testing import CliRunner

from keemu.cli import cli


def test_p0_verify_lock_reports_verified_artifacts(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    payload = b"locked package"
    (cache / "fixture.ipk").write_bytes(payload)
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "entware-rootfs-lock",
                "target": "aarch64-3.10",
                "packages": [
                    {
                        "filename": "fixture.ipk",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["p0", "verify-lock", "--lock", str(lock), "--cache", str(cache)],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "artifact_count": 1,
        "status": "verified",
        "target": "aarch64-3.10",
    }
