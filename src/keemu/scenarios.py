"""Version 1 scenario input contract. Parsing alone does not run a scenario."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from keemu.input_paths import (
    HostInputPath,
    SafeName,
    TargetDirectory,
    TargetPath,
    resolve_input_path,
)
from keemu.profiles import load_yaml_unique


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def strict_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value


def validate_argv(value: tuple[str, ...]) -> tuple[str, ...]:
    # Shell interpretation is only permitted as an explicit, reviewed scenario.
    shells = {"sh", "bash", "dash", "ash", "zsh"}
    if value[0].rsplit("/", 1)[-1] in shells and (
        value[0] != "/bin/sh" or len(value) != 3 or value[1] != "-c"
    ):
        raise ValueError("shell requires explicit /bin/sh -c with one script argument")
    return value


Argv = Annotated[
    tuple[Annotated[str, StringConstraints(min_length=1, max_length=8192)], ...],
    Field(min_length=1, strict=False),
    AfterValidator(validate_argv),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Command(InputModel):
    argv: Argv
    timeout_seconds: int = Field(default=60, ge=1, le=3600)


class IPKInstall(InputModel):
    kind: Literal["ipk"]
    path: HostInputPath
    package_name: SafeName


class PinnedInstaller(InputModel):
    kind: Literal["pinned-installer"]
    path: HostInputPath
    source_lock: SafeName
    entrypoint: Argv
    working_directory: TargetDirectory
    timeout_seconds: int = Field(ge=1, le=3600)
    verify_install: Command
    uninstall: Command


Install = Annotated[IPKInstall | PinnedInstaller, Field(discriminator="kind")]


class Publish(InputModel):
    host_ip: Literal["127.0.0.1"] = "127.0.0.1"
    host_port: int = Field(ge=1, le=65535)
    target_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]


class HTTPProbe(InputModel):
    kind: Literal["http", "https"]
    vantage: Literal["target_loopback", "host_publish", "client"]
    url: str = Field(min_length=8, max_length=2048)
    expected_status: tuple[int, ...] = Field(min_length=1, strict=False)
    body_contains: str = Field(min_length=1, max_length=8192)
    ca_cert: HostInputPath | None = None
    timeout_seconds: int = Field(default=30, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_address(self) -> Self:
        parsed = urlsplit(self.url)
        if (
            parsed.scheme != self.kind
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or not parsed.path.startswith("/")
            or any(ch.isspace() for ch in self.url)
        ):
            raise ValueError("invalid HTTP check URL")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid HTTP check port") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid HTTP check port")
        if any(not 100 <= status <= 599 for status in self.expected_status):
            raise ValueError("invalid HTTP status")
        if self.kind == "https" and self.ca_cert is None:
            raise ValueError("HTTPS requires a trusted local CA certificate")
        if self.kind == "http" and self.ca_cert is not None:
            raise ValueError("HTTP must not specify ca_cert")
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname.lower() == "localhost"
        if self.vantage == "client" and loopback:
            raise ValueError("client vantage cannot use loopback")
        if self.vantage == "host_publish" and not loopback:
            raise ValueError("host_publish must use loopback")
        if self.vantage == "target_loopback" and not loopback:
            raise ValueError("target_loopback must use loopback")
        return self


class HTTPCheck(HTTPProbe):
    id: SafeName


class UDPProbe(InputModel):
    kind: Literal["udp"]
    vantage: Literal["target_loopback", "host_publish", "client"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    request: str = Field(min_length=1, max_length=8192)
    expected_response: str = Field(min_length=1, max_length=8192)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_vantage(self) -> Self:
        try:
            loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            loopback = self.host.lower() == "localhost"
        if (self.vantage == "client") == loopback:
            raise ValueError("UDP check host does not match vantage")
        return self


class UDPCheck(UDPProbe):
    id: SafeName


class CommandCheck(InputModel):
    id: SafeName
    kind: Literal["command"]
    command: Command
    expected_exit_code: int


class FileCheck(InputModel):
    id: SafeName
    kind: Literal["file"]
    path: TargetPath
    exists: bool


Check = Annotated[
    HTTPCheck | UDPCheck | CommandCheck | FileCheck, Field(discriminator="kind")
]


class Service(InputModel):
    start: Argv
    stop: Argv
    readiness: HTTPProbe | UDPProbe


EnvName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]


class Runtime(InputModel):
    env: dict[EnvName, str]
    cwd: TargetDirectory
    settle_seconds: int = Field(ge=0, le=300)
    publish: tuple[Publish, ...] = Field(max_length=64, strict=False)

    @model_validator(mode="after")
    def validate_environment(self) -> Self:
        # Only references to supplied secrets, never literal secret values in YAML.
        for name, reference in self.env.items():
            if not reference.startswith("${") or not reference.endswith("}"):
                raise ValueError(f"environment {name} must be a variable reference")
            if reference[2:-1] != name:
                raise ValueError(f"environment {name} reference does not match name")
        endpoints = [(p.host_ip, p.host_port, p.protocol) for p in self.publish]
        if len(endpoints) != len(set(endpoints)):
            raise ValueError("duplicate published port")
        return self


class Requirements(InputModel):
    capabilities: tuple[Literal["NET_ADMIN", "NET_RAW"], ...] = Field(strict=False)
    ndm_fixtures: tuple[SafeName, ...] = Field(strict=False)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> Self:
        if len(set(self.capabilities)) != len(self.capabilities) or len(
            set(self.ndm_fixtures)
        ) != len(self.ndm_fixtures):
            raise ValueError("duplicate capability or NDM fixture")
        return self


class Persistence(InputModel):
    paths: tuple[TargetPath, ...] = Field(max_length=512, strict=False)


class Cleanup(InputModel):
    allowed_residual_paths: tuple[TargetPath, ...] = Field(max_length=512, strict=False)


class Scenario(InputModel):
    schema_version: Literal[1]
    id: SafeName
    profile: SafeName
    install: Install
    service: Service | None
    runtime: Runtime
    requirements: Requirements
    checks: tuple[Check, ...] = Field(min_length=1, max_length=128, strict=False)
    persistence: Persistence
    cleanup: Cleanup

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        ids = [c.id for c in self.checks]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate check id")
        probes: list[object] = list(self.checks)
        if self.service is not None:
            probes.append(self.service.readiness)
        for probe in probes:
            if isinstance(probe, HTTPProbe) and probe.vantage == "host_publish":
                parsed = urlsplit(probe.url)
                port = parsed.port or (443 if probe.kind == "https" else 80)
                if not any(
                    p.host_port == port and p.protocol == "tcp"
                    for p in self.runtime.publish
                ):
                    raise ValueError("host_publish HTTP check has no TCP publication")
            if isinstance(probe, UDPProbe) and probe.vantage == "host_publish":
                if not any(
                    p.host_port == probe.port and p.protocol == "udp"
                    for p in self.runtime.publish
                ):
                    raise ValueError("host_publish UDP check has no UDP publication")
        for label, paths in (
            ("persistence", self.persistence.paths),
            ("cleanup", self.cleanup.allowed_residual_paths),
        ):
            if len(paths) != len(set(paths)):
                raise ValueError(f"duplicate {label} path")
        return self


def load_scenario(path: Path, *, project_root: Path) -> Scenario:
    """Load trusted-project scenario, then confine every referenced host input."""
    source = resolve_input_path(
        path.name, scenario_dir=path.parent, project_root=project_root
    )
    scenario = Scenario.model_validate(load_yaml_unique(source))
    resolve_input_path(
        scenario.install.path, scenario_dir=source.parent, project_root=project_root
    )
    checks: list[object] = list(scenario.checks)
    if scenario.service is not None:
        checks.append(scenario.service.readiness)
    for check in checks:
        if isinstance(check, HTTPProbe) and check.ca_cert:
            resolve_input_path(
                check.ca_cert, scenario_dir=source.parent, project_root=project_root
            )
    return scenario
