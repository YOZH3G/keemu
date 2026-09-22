from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from keemu.entware import ArtifactIntegrityError, verify_artifact_cache


@click.group()
def cli() -> None:
    """Verify Entware applications in locked target environments."""


@cli.group()
def p0() -> None:
    """Run or verify P0 technical-risk experiments."""


@p0.command("verify-lock")
@click.option(
    "lock_path",
    "--lock",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "cache",
    "--cache",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
def verify_lock(lock_path: Path, cache: Path) -> None:
    """Verify every cached package against an Entware rootfs lock."""
    try:
        lock: dict[str, Any] = json.loads(lock_path.read_text(encoding="utf-8"))
        verified = verify_artifact_cache(lock, cache)
    except (OSError, json.JSONDecodeError, ArtifactIntegrityError) as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        json.dumps(
            {
                "artifact_count": len(verified),
                "status": "verified",
                "target": lock.get("target"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    cli()
