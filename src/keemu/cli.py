from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError
from yaml import YAMLError

from keemu.doctor import collect_doctor
from keemu.entware import ArtifactIntegrityError, verify_artifact_cache
from keemu.fixture_lock import FixtureLockError, verify_fixture_lock
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.profiles import ProfileError, load_profile
from keemu.reports import exit_code_for_status


class InputError(click.ClickException):
    exit_code = 2


@click.group()
def cli() -> None:
    """Verify Entware applications in locked target environments."""


@cli.command()
@click.option("profile_id", "--profile", required=True)
@click.option(
    "profiles_dir",
    "--profiles-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("profiles/generic"),
    show_default=True,
)
@click.option(
    "docker_socket",
    "--docker-socket",
    type=click.Path(path_type=Path),
    default=Path("/var/run/docker.sock"),
    show_default=True,
)
@click.option(
    "binfmt_root",
    "--binfmt-root",
    type=click.Path(path_type=Path),
    default=Path("/proc/sys/fs/binfmt_misc"),
    show_default=True,
)
@click.option("search_path", "--search-path", default=None, hidden=True)
@click.pass_context
def doctor(
    context: click.Context,
    profile_id: str,
    profiles_dir: Path,
    docker_socket: Path,
    binfmt_root: Path,
    search_path: str | None,
) -> None:
    """Run read-only host checks for a generic target profile."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}[a-z0-9]", profile_id):
        raise InputError(f"invalid profile ID: {profile_id}")
    profile_path = profiles_dir / f"{profile_id}.yaml"
    try:
        profile = load_profile(profile_path)
        report = collect_doctor(
            profile,
            search_path=search_path,
            docker_socket=docker_socket,
            binfmt_root=binfmt_root,
        )
    except (OSError, ProfileError, ValidationError, YAMLError) as error:
        raise InputError(str(error)) from error
    click.echo(json.dumps(report.model_dump(mode="json"), sort_keys=True))
    context.exit(exit_code_for_status(report.overall))


@cli.command()
@click.argument("package", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("profile_id", "--profile", default=None)
@click.option(
    "profiles_dir",
    "--profiles-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("profiles/generic"),
)
@click.option(
    "rootfs", "--rootfs", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.pass_context
def inspect(
    context: click.Context,
    package: Path,
    profile_id: str | None,
    profiles_dir: Path,
    rootfs: Path | None,
) -> None:
    """Statically inspect a bounded IPK without installing or executing it.

    --rootfs must include already-resolved dependencies; absent paths are not
    definitive until the installation stage. This command never runs host ldd.
    """
    if profile_id is not None and not re.fullmatch(
        r"[a-z][a-z0-9-]{1,62}[a-z0-9]", profile_id
    ):
        raise InputError(f"invalid profile ID: {profile_id}")
    try:
        profile = (
            load_profile(profiles_dir / f"{profile_id}.yaml") if profile_id else None
        )
        result = inspect_ipk(package, profile=profile, rootfs=rootfs)
    except (OSError, IPKError, ProfileError, ValidationError, YAMLError) as error:
        raise InputError(str(error)) from error
    click.echo(json.dumps(result.to_dict(), sort_keys=True))
    context.exit(exit_code_for_status(result.status))


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


@p0.command("verify-fixture-lock")
@click.option(
    "lock_path",
    "--lock",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "root",
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
)
@click.option("verify_external", "--verify-external", is_flag=True)
def verify_fixture(lock_path: Path, root: Path, verify_external: bool) -> None:
    """Verify fixture sources and recipes; optionally staged toolchain inputs."""
    try:
        verified = verify_fixture_lock(lock_path, root, verify_external=verify_external)
    except FixtureLockError as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        json.dumps(
            {
                "fixture_count": len(verified),
                "fixtures": verified,
                "status": "verified",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    cli()
