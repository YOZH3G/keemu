"""Recovery refuses ambiguity and retries only exact run-owned cleanup."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from click.testing import CliRunner

from keemu import persistent
from keemu.cli import cli
from keemu.input_locks import PersistentEnvironment, ResourceIdentity
from keemu.registry import Registry, RegistryError

IMAGE = "sha256:" + "a" * 64
CID = "b" * 64
FOREIGN = "c" * 64


def seed(root: Path, state: str = "installing", *, bound: bool = True) -> None:
    registry = Registry(root / ".runtime/registry")
    with registry.locked("fixture") as entry:
        first = PersistentEnvironment(
            schema_version=1,
            kind="persistent-environment",
            name="fixture",
            run_id="env-test-recovery",
            state="creating",
            scenario_id="fixture",
            scenario_sha256=hashlib.sha256(b"scenario").hexdigest(),
            profile_id="generic-aarch64",
            profile_sha256="a" * 64,
            lock_sha256="b" * 64,
            oci_digest=IMAGE,
            resource=None,
        )
        entry.create(first, b"scenario")
        if state != "creating":
            if bound:
                resource = ResourceIdentity(
                    container_id=CID,
                    owner_label="keemu",
                    run_id_label=first.run_id,
                )
                first = first.model_copy(
                    update={"state": "installing", "resource": resource}
                )
                entry.update(entry.read(), first)
            else:
                first = first.model_copy(update={"state": "failed"})
                entry.update(entry.read(), first)
            if state != first.state:
                updated = first.model_copy(update={"state": state})
                entry.update(first, updated)


class FakeDocker:
    owned = [CID]
    all_ids = {CID, FOREIGN}
    removed: list[str] = []
    fail_once = False
    extra_networks: list[str] = []
    name = "/keemu-env-test-recovery"

    def __init__(self, run_id, image_id):
        assert run_id == "env-test-recovery" and image_id == IMAGE

    def reconcile(self):
        return {
            "container_owned": list(self.owned),
            "network_owned": list(self.extra_networks),
        }

    def inspect(self, kind, identifier):
        assert kind == "container" and identifier == CID
        return {"Name": self.name}

    def remove_container(self, identifier):
        assert identifier == CID
        if self.fail_once:
            type(self).fail_once = False
            raise RuntimeError("injected cleanup failure")
        self.removed.append(identifier)
        self.owned.remove(identifier)
        self.all_ids.remove(identifier)

    @classmethod
    def listed_ids(cls, kind):
        assert kind == "container"
        return set(cls.all_ids)


@pytest.fixture
def fake(monkeypatch):
    FakeDocker.owned = [CID]
    FakeDocker.all_ids = {CID, FOREIGN}
    FakeDocker.removed = []
    FakeDocker.fail_once = False
    FakeDocker.extra_networks = []
    FakeDocker.name = "/keemu-env-test-recovery"
    monkeypatch.setattr(persistent, "DockerRuntime", FakeDocker)
    return FakeDocker


def test_recovery_requires_explicit_cli_confirmation_and_retries(tmp_path, fake):
    seed(tmp_path)
    cmd = ["recover", "fixture", "--repo", str(tmp_path)]
    assert CliRunner().invoke(cli, cmd).exit_code == 2
    fake.fail_once = True
    with pytest.raises(RuntimeError, match="injected cleanup failure"):
        persistent.recover(tmp_path, "fixture")
    with Registry(tmp_path / ".runtime/registry").locked("fixture") as entry:
        assert entry.read().state == "installing"
    result = persistent.recover(tmp_path, "fixture")
    assert result["removed"] == [CID] and result["state"] == "destroyed"
    assert fake.all_ids == {FOREIGN} and fake.removed == [CID]
    assert persistent.recover(tmp_path, "fixture")["retry"] is True
    with Registry(tmp_path / ".runtime/registry").locked("fixture") as entry:
        assert entry.read().state == "destroyed"


@pytest.mark.parametrize("state", ["creating", "failed"])
def test_unbound_orphan_recovered_only_with_expected_name(tmp_path, fake, state):
    seed(tmp_path, state, bound=False)
    fake.name = "/wrong-name"
    with pytest.raises(RegistryError, match="name mismatch"):
        persistent.recover(tmp_path, "fixture")
    assert fake.removed == []
    fake.name = "/keemu-env-test-recovery"
    assert persistent.recover(tmp_path, "fixture")["removed"] == [CID]


def test_stale_registry_with_foreign_id_refuses_mutation(tmp_path, fake):
    seed(tmp_path)
    fake.owned = []
    with pytest.raises(RegistryError, match="without matching ownership"):
        persistent.recover(tmp_path, "fixture")
    assert fake.removed == []
    with Registry(tmp_path / ".runtime/registry").locked("fixture") as entry:
        assert entry.read().state == "installing"


def test_extra_resources_and_network_refuse_cleanup(tmp_path, fake):
    seed(tmp_path)
    fake.owned = [CID, FOREIGN]
    with pytest.raises(RegistryError, match="extra owned"):
        persistent.recover(tmp_path, "fixture")
    fake.owned = [CID]
    fake.extra_networks = [FOREIGN]
    with pytest.raises(RegistryError, match="network"):
        persistent.recover(tmp_path, "fixture")
    assert fake.removed == []


def test_healthy_environment_never_recovered(tmp_path, fake):
    seed(tmp_path, "stopped")
    with pytest.raises(RegistryError, match="healthy"):
        persistent.recover(tmp_path, "fixture")
    assert fake.removed == []
