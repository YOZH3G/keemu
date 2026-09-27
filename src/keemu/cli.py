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
from keemu.init_cache import InitError, init_locked
from keemu.ipk_inspect import IPKError, inspect_ipk
from keemu.lifecycle import run_scenario
from keemu.matrix import run_matrix
from keemu.persistent import PersistentError, operate
from keemu.persistent import create as create_environment
from keemu.persistent import recover as recover_environment
from keemu.profiles import ProfileError, load_profile
from keemu.registry import RegistryError
from keemu.reports import exit_code_for_status
from keemu.script_assertions import ScriptExpectations
from keemu.script_input import ScriptInputError
from keemu.script_lifecycle import run_one_shot_script
from keemu.script_persistent import run_persistent_script


class InputError(click.ClickException):
    exit_code = 2


class RuntimeFailure(click.ClickException):
    exit_code = 3


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


@cli.command("test")
@click.option("scenario", "--scenario", type=click.Path(path_type=Path))
@click.option("lock", "--lock", type=click.Path(path_type=Path))
@click.option("matrix", "--matrix", type=click.Path(path_type=Path))
@click.option("--strict", is_flag=True, help="Treat WARN-only runs as exit 5.")
@click.option("repo", "--repo", type=click.Path(path_type=Path), default=Path("."))
@click.pass_context
def test_scenario(
    context: click.Context,
    scenario: Path | None,
    lock: Path | None,
    matrix: Path | None,
    strict: bool,
    repo: Path,
) -> None:
    """Run a locked IPK scenario or sequential three-target matrix."""
    if (
        (matrix is None) == (scenario is None)
        or (matrix is not None and lock is not None)
        or (scenario is not None and lock is None)
    ):
        raise InputError("supply --matrix alone, or --scenario and --lock together")
    try:
        if matrix is not None:
            result = run_matrix(matrix, project_root=repo)
        else:
            if scenario is None or lock is None:
                raise InputError("--scenario requires --lock")
            result = run_scenario(scenario, lock, project_root=repo)
    except (OSError, ValueError) as error:
        # Publication itself can fail closed (e.g. an existing report directory).
        raise InputError(str(error)) from error
    click.echo(json.dumps(result.report.model_dump(mode="json"), sort_keys=True))
    failure = result.report.partial_failure
    if failure and failure.message.startswith(
        (
            "invalid scenario input:",
            "invalid scenario/lock input:",
            "invalid package input:",
        )
    ):
        context.exit(2)
    if strict and result.report.overall == "WARN":
        context.exit(5)
    context.exit(exit_code_for_status(result.report.overall))


@cli.command("script")
@click.argument("script", type=click.Path(path_type=Path))
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
@click.option("profile_id", "--profile", required=True)
@click.option(
    "timeout_seconds",
    "--timeout",
    type=click.IntRange(1, 600),
    default=60,
    show_default=True,
)
@click.option("cwd", "--cwd", default="/opt", show_default=True)
@click.option(
    "expected_exit_code",
    "--expect-exit-code",
    type=click.IntRange(0, 255),
    default=0,
    show_default=True,
)
@click.option("stdout_contains", "--stdout-contains", multiple=True)
@click.option("stderr_not_contains", "--stderr-not-contains", multiple=True)
@click.option("files_exist", "--expect-file", multiple=True)
@click.option("files_absent", "--expect-file-absent", multiple=True)
@click.option(
    "repo",
    "--repo",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("."),
    show_default=True,
)
@click.pass_context
def script(
    context: click.Context,
    script: Path,
    argv: tuple[str, ...],
    profile_id: str,
    timeout_seconds: int,
    cwd: str,
    expected_exit_code: int,
    repo: Path,
    stdout_contains: tuple[str, ...],
    stderr_not_contains: tuple[str, ...],
    files_exist: tuple[str, ...],
    files_absent: tuple[str, ...],
) -> None:
    """Run one project-contained .sh file in a fresh locked target container.

    Use `--` before literal script argv. Execution, target-path, and aggregate
    argv bounds are revalidated by the common script lifecycle before allocation.
    """
    try:
        extras = {}
        if stdout_contains or stderr_not_contains or files_exist or files_absent:
            extras["expectations"] = ScriptExpectations(
                stdout_contains, stderr_not_contains, files_exist, files_absent
            )
        result = run_one_shot_script(
            script,
            project_root=repo,
            profile_id=profile_id,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            expected_exit_code=expected_exit_code,
            **extras,
        )
    except (ScriptInputError, ValueError) as exc:
        raise InputError(str(exc)) from exc
    except OSError as exc:
        raise RuntimeFailure(str(exc)) from exc
    click.echo(json.dumps(result.report.model_dump(mode="json"), sort_keys=True))
    context.exit(exit_code_for_status(result.report.overall))


@cli.command()
@click.option("--name", required=True)
@click.option("--scenario", type=click.Path(path_type=Path))
@click.option("--lock", type=click.Path(path_type=Path))
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def up(name: str, scenario: Path | None, lock: Path | None, repo: Path) -> None:
    """Create a locked persistent IPK environment, or start a stopped one."""
    if (scenario is None) != (lock is None):
        raise InputError("--scenario and --lock must be supplied together")
    try:
        if scenario is not None and lock is not None:
            result = {
                "environment": create_environment(
                    repo, name, scenario, lock
                ).model_dump(mode="json")
            }
        else:
            result = operate(repo, name, "up")
    except (OSError, ValueError, RegistryError, PersistentError) as exc:
        raise InputError(str(exc)) from exc
    except RuntimeError as exc:
        raise RuntimeFailure(str(exc)) from exc
    click.echo(json.dumps(result, sort_keys=True))


def _environment_command(
    action: str, name: str, repo: Path, argv: tuple[str, ...] = ()
) -> None:
    try:
        result = operate(repo, name, action, argv=argv)
    except (OSError, ValueError, RegistryError, PersistentError) as exc:
        raise InputError(str(exc)) from exc
    except RuntimeError as exc:
        raise RuntimeFailure(str(exc)) from exc
    click.echo(json.dumps(result, sort_keys=True))
    if action == "status" and not result["consistent"]:
        raise SystemExit(3)
    if action == "exec" and result["exit_code"]:
        raise SystemExit(1)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def down(name: str, repo: Path) -> None:
    """Stop a running, ID-verified environment."""
    _environment_command("down", name, repo)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def restart(name: str, repo: Path) -> None:
    """Stop and start the same ID-verified container."""
    _environment_command("restart", name, repo)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def destroy(name: str, repo: Path) -> None:
    """Remove a stopped owned container; retain its registry tombstone."""
    _environment_command("destroy", name, repo)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
@click.option(
    "--yes",
    is_flag=True,
    required=True,
    help="Remove only verified run-owned resources.",
)
def recover(name: str, repo: Path, yes: bool) -> None:
    """Explicitly discard an interrupted/failed environment; retain its tombstone."""
    try:
        result = recover_environment(repo, name)
    except (OSError, ValueError, RegistryError, PersistentError) as exc:
        raise InputError(str(exc)) from exc
    except RuntimeError as exc:
        raise RuntimeFailure(str(exc)) from exc
    click.echo(json.dumps(result, sort_keys=True))


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def status(name: str, repo: Path) -> None:
    """Compare registry with Docker labels and actual state without mutation."""
    _environment_command("status", name, repo)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def ports(name: str, repo: Path) -> None:
    """Show only the inspected container's port map."""
    _environment_command("ports", name, repo)


@cli.command()
@click.argument("name")
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
def logs(name: str, repo: Path) -> None:
    """Read bounded logs from the inspected owned container."""
    _environment_command("logs", name, repo)


@cli.command("exec", context_settings={"ignore_unknown_options": True})
@click.argument("name")
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
@click.option("--repo", type=click.Path(path_type=Path), default=Path("."))
@click.option("script_path", "--script", type=click.Path(path_type=Path))
@click.option("timeout_seconds", "--timeout", type=click.IntRange(1, 600), default=60)
@click.option("cwd", "--cwd", default="/opt")
@click.option(
    "expected_exit_code", "--expect-exit-code", type=click.IntRange(0, 255), default=0
)
@click.option("stdout_contains", "--stdout-contains", multiple=True)
@click.option("stderr_not_contains", "--stderr-not-contains", multiple=True)
@click.option("files_exist", "--expect-file", multiple=True)
@click.option("files_absent", "--expect-file-absent", multiple=True)
@click.pass_context
def exec_environment(
    context: click.Context,
    name: str,
    argv: tuple[str, ...],
    repo: Path,
    script_path: Path | None,
    timeout_seconds: int,
    cwd: str,
    expected_exit_code: int,
    stdout_contains: tuple[str, ...],
    stderr_not_contains: tuple[str, ...],
    files_exist: tuple[str, ...],
    files_absent: tuple[str, ...],
) -> None:
    """Run argv, or a checked script in an owner-verified running environment."""
    if script_path is None:
        if (
            timeout_seconds != 60
            or cwd != "/opt"
            or expected_exit_code != 0
            or stdout_contains
            or stderr_not_contains
            or files_exist
            or files_absent
        ):
            raise InputError("script options require --script")
        _environment_command("exec", name, repo, argv)
        return
    try:
        extras = {}
        if stdout_contains or stderr_not_contains or files_exist or files_absent:
            extras["expectations"] = ScriptExpectations(
                stdout_contains, stderr_not_contains, files_exist, files_absent
            )
        result = run_persistent_script(
            name,
            script_path,
            project_root=repo,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            expected_exit_code=expected_exit_code,
            **extras,
        )
    except (ScriptInputError, ValueError, RegistryError) as exc:
        raise InputError(str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise RuntimeFailure(str(exc)) from exc
    click.echo(json.dumps(result.report.model_dump(mode="json"), sort_keys=True))
    context.exit(exit_code_for_status(result.report.overall))


@cli.command("init")
@click.option("profile_id", "--profile", required=True)
@click.option(
    "repo",
    "--repo",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("."),
)
@click.option(
    "--locked",
    is_flag=True,
    required=True,
    help="Require exactly the pinned offline artifact set.",
)
@click.option(
    "--offline",
    is_flag=True,
    help="Verify an existing cache without any build or network probe.",
)
def init(profile_id: str, repo: Path, locked: bool, offline: bool) -> None:
    """Prepare a locked generic base cache from pinned package bytes."""
    targets = {"generic-aarch64": "aarch64-3.10", "generic-mips": "mips-3.4"}
    if profile_id not in targets:
        raise InputError(
            "only verified generic-aarch64/generic-mips bases are available"
        )
    try:
        profile = load_profile(repo / "profiles/generic" / f"{profile_id}.yaml")
        if profile.id != profile_id or profile.entware_target != targets[profile_id]:
            raise InitError("profile identity mismatch")
        result = init_locked(repo, offline=offline, target=targets[profile_id])
    except (OSError, ValueError, ValidationError, YAMLError, TimeoutError) as error:
        raise InputError(str(error)) from error
    click.echo(json.dumps(result, sort_keys=True))


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
