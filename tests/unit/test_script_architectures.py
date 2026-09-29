"""MIPS-family script profiles bind the verified general lifecycle bases."""

import hashlib
import json
from pathlib import Path

from click.testing import CliRunner

from keemu.cli import cli
from keemu.script_lifecycle import SCRIPT_IMAGE_LOCKS

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "fixtures/scripts/mvp1d/success.sh"


def test_mips_profiles_bind_verified_general_script_bases() -> None:
    for profile, target, lock_name in (
        ("generic-mips", "mips-3.4", "m1e-init-mips.json"),
        ("generic-mipsel", "mipsel-3.4", "m1e-init-mipsel.json"),
    ):
        assert SCRIPT_IMAGE_LOCKS[profile] == f"locks/{lock_name}"
        base = json.loads((ROOT / SCRIPT_IMAGE_LOCKS[profile]).read_text())
        profile_bytes = (ROOT / "profiles/generic" / f"{profile}.yaml").read_bytes()
        assert base["target"] == target
        assert base["oci_digest"].startswith("sha256:")
        assert base["profile_sha256"] == hashlib.sha256(profile_bytes).hexdigest()


def test_unknown_profile_still_rejects_invalid_input(tmp_path: Path) -> None:
    response = CliRunner().invoke(
        cli,
        ["script", SCRIPT, "--profile", "generic-unknown", "--repo", str(ROOT)],
    )
    assert response.exit_code == 2
    assert "unsupported script profile" in response.output
    assert not list(tmp_path.iterdir())
