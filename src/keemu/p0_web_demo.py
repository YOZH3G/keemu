"""P0-06 locked web-demo image builder and local-only publish/persistence probe."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

from keemu.p0_runtime_image import verify as verify_runtime_image

REFERENCE = "keemu/p0-aarch64:web-p006"
SOURCE = "fixtures/sources/web-demo/web_demo_p006.c"
RECIPE = "fixtures/recipes/aarch64/web-demo-p006.mk"
BINARY = "web-demo-p006"
STATE_PATH = "/opt/etc/web-demo/state.txt"
MAKE = "/usr/bin/make"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], *, cwd: Path | None = None, timeout: int = 300) -> str:
    if argv[0] not in {"docker", "make"}:
        raise ValueError("only fixed Docker and make argv are allowed")
    result = subprocess.run(  # noqa: S603 -- fixed executable and argv; no shell.
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed rc={result.returncode}: {argv!r}; "
            f"stderr={result.stderr[-3000:]!r}; stdout={result.stdout[-3000:]!r}"
        )
    return result.stdout.strip()


def _saved_inspect(
    archive: Path,
    reference: str,
    base_layers: list[str],
    binary_hash: str,
    state_hash: str,
) -> dict:
    with tarfile.open(archive) as tar:
        manifest_stream = tar.extractfile("manifest.json")
        if manifest_stream is None:
            raise ValueError("saved image has no manifest")
        manifest = json.load(manifest_stream)[0]
        if (
            reference not in manifest["RepoTags"]
            or len(manifest["Layers"]) != len(base_layers) + 1
        ):
            raise ValueError("saved web image layer layout differs from lock")
        config_stream = tar.extractfile(manifest["Config"])
        if config_stream is None:
            raise ValueError("saved image has no config")
        config = config_stream.read()
        layer_hashes: list[str] = []
        for layer_path in manifest["Layers"]:
            layer = tar.extractfile(layer_path)
            if layer is None:
                raise ValueError("saved image layer missing")
            layer_hashes.append(hashlib.sha256(layer.read()).hexdigest())
        if layer_hashes[:-1] != base_layers:
            raise ValueError("base runtime image layers changed")
        extension = tar.extractfile(manifest["Layers"][-1])
        if extension is None:
            raise ValueError("web extension layer missing")
        expected = {
            "opt/bin/web-demo-p006": binary_hash,
            "opt/etc/web-demo/state.txt": state_hash,
        }
        actual: dict[str, str] = {}
        with tarfile.open(fileobj=extension) as extension_tar:
            for member in extension_tar:
                if not member.isfile():
                    continue
                stream = extension_tar.extractfile(member)
                if stream is None:
                    raise ValueError("web extension file unreadable")
                actual[member.name.lstrip("./")] = hashlib.sha256(
                    stream.read()
                ).hexdigest()
        if actual != expected:
            raise ValueError("web extension layer has unexpected files or hashes")
        return {
            "saved_config_sha256": hashlib.sha256(config).hexdigest(),
            "saved_layer_sha256": layer_hashes,
            "saved_labels": json.loads(config)["config"]["Labels"],
        }


def build(repo: Path) -> dict:
    """Build and lock a derived image containing only p0-06 web-demo inputs."""
    repo = repo.resolve()
    base = verify_runtime_image(repo)
    base_lock_path = repo / "locks/p0-mixed-image-aarch64-p005.json"
    base_lock = json.loads(base_lock_path.read_text(encoding="utf-8"))
    source = repo / SOURCE
    recipe = repo / RECIPE
    toolchain = repo / ".runtime/p0/cross-toolchain/root"
    context = repo / ".runtime/p0/p006-web-image-build"
    if context.exists():
        raise FileExistsError(context)
    if not toolchain.is_dir():
        raise FileNotFoundError(f"locked toolchain absent: {toolchain}")
    context.mkdir(parents=True)
    try:
        payload = context / "payload"
        binary = payload / "opt/bin" / BINARY
        toolchain_library = toolchain / "usr/lib/x86_64-linux-gnu"
        if not toolchain_library.is_dir():
            raise FileNotFoundError(
                f"locked toolchain library absent: {toolchain_library}"
            )
        result = subprocess.run(  # noqa: S603 -- fixed make executable and argv.
            [
                MAKE,
                "-f",
                RECIPE,
                f"OUT={binary}",
                f"KEEMU_TOOLCHAIN_ROOT={toolchain}",
            ],
            cwd=repo,
            env={**os.environ, "LD_LIBRARY_PATH": str(toolchain_library)},
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"locked web-demo build failed rc={result.returncode}; "
                f"stderr={result.stderr[-3000:]!r}; stdout={result.stdout[-3000:]!r}"
            )
        header = binary.read_bytes()[:20]
        if (
            header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack("<H", header[18:20])[0] != 183
        ):
            raise ValueError("web-demo is not ELF64 little-endian AArch64")
        binary_hash = sha256(binary)
        source_hash = sha256(source)
        recipe_hash = sha256(recipe)
        state = payload / "opt/etc/web-demo/state.txt"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text("initial\n", encoding="ascii")
        state_hash = sha256(state)
        dockerfile = (
            f"FROM {base_lock['image_id']}\n"
            "COPY payload/ /\n"
            'LABEL org.keemu.phase="p0-06"\n'
            f'LABEL org.keemu.base-image-id="{base_lock["image_id"]}"\n'
            f'LABEL org.keemu.web-source-sha256="{source_hash}"\n'
            f'LABEL org.keemu.web-recipe-sha256="{recipe_hash}"\n'
            f'LABEL org.keemu.web-binary-sha256="{binary_hash}"\n'
            f'LABEL org.keemu.web-state-sha256="{state_hash}"\n'
        )
        (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        run(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                "-t",
                REFERENCE,
                str(context),
            ],
            timeout=300,
        )
        inspected = json.loads(run(["docker", "image", "inspect", REFERENCE]))[0]
        labels = inspected["Config"]["Labels"]
        required_labels = {
            "org.keemu.owner": "keemu",
            "org.keemu.target": "aarch64-3.10",
            "org.keemu.base-image-id": base_lock["image_id"],
            "org.keemu.web-source-sha256": source_hash,
            "org.keemu.web-recipe-sha256": recipe_hash,
            "org.keemu.web-binary-sha256": binary_hash,
            "org.keemu.web-state-sha256": state_hash,
        }
        if (
            inspected["Architecture"] != "amd64"
            or inspected["Os"] != "linux"
            or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
            or any(labels.get(key) != value for key, value in required_labels.items())
        ):
            raise ValueError("derived web image inspect differs from locked inputs")
        archive = repo / ".runtime/p0/web-demo-p006-image.tar"
        if archive.exists():
            raise FileExistsError(archive)
        run(["docker", "save", "-o", str(archive), REFERENCE], timeout=300)
        saved = _saved_inspect(
            archive,
            REFERENCE,
            base_lock["saved_layer_sha256"],
            binary_hash,
            state_hash,
        )
        if saved["saved_labels"] != labels:
            raise ValueError("saved web image labels differ from live image")
        lock = {
            "schema_version": 1,
            "kind": "p0-web-demo-runtime-image-lock",
            "image_reference": REFERENCE,
            "image_id": inspected["Id"],
            "base_image_id": base_lock["image_id"],
            "base_lock": str(base_lock_path.relative_to(repo)),
            "source_path": SOURCE,
            "source_sha256": source_hash,
            "recipe_path": RECIPE,
            "recipe_sha256": recipe_hash,
            "binary_path": BINARY,
            "binary_sha256": binary_hash,
            "initial_state_path": STATE_PATH,
            "initial_state_sha256": state_hash,
            "platform": "linux/amd64",
            "entrypoint": inspected["Config"]["Entrypoint"],
            "labels": labels,
            "saved_image": str(archive.relative_to(repo)),
            "saved_archive_sha256": sha256(archive),
            "saved_config_sha256": saved["saved_config_sha256"],
            "saved_layer_sha256": saved["saved_layer_sha256"],
            "build_inputs": {
                "runtime_image": base,
                "toolchain": str(toolchain.relative_to(repo)),
            },
            "scope": "p0-06 web-demo HTTP/UDP and persisted-state experiment only",
        }
        (repo / "locks/p0-web-demo-aarch64-p006.json").write_text(
            json.dumps(lock, indent=2) + "\n", encoding="utf-8"
        )
        return lock
    finally:
        shutil.rmtree(context)


def verify(repo: Path) -> dict:
    """Verify the p0-06 source, saved image and Docker image against its lock."""
    repo = repo.resolve()
    lock = json.loads(
        (repo / "locks/p0-web-demo-aarch64-p006.json").read_text(encoding="utf-8")
    )
    base_lock = json.loads((repo / lock["base_lock"]).read_text(encoding="utf-8"))
    if base_lock["image_id"] != lock["base_image_id"]:
        raise ValueError("base runtime image ID changed")
    for field, relative in (
        ("source_sha256", lock["source_path"]),
        ("recipe_sha256", lock["recipe_path"]),
    ):
        if sha256(repo / relative) != lock[field]:
            raise ValueError(f"locked build input changed: {relative}")
    if verify_runtime_image(repo)["image_id"] != lock["base_image_id"]:
        raise ValueError(
            "base runtime image verification disagrees with p0-06 lock"
        )
    archive = repo / lock["saved_image"]
    if sha256(archive) != lock["saved_archive_sha256"]:
        raise ValueError("saved web image archive changed")
    inspected = json.loads(run(["docker", "image", "inspect", lock["image_id"]]))[0]
    if (
        inspected["Id"] != lock["image_id"]
        or inspected["Architecture"] != "amd64"
        or inspected["Os"] != "linux"
        or inspected["Config"]["Entrypoint"] != lock["entrypoint"]
        or inspected["Config"]["Labels"] != lock["labels"]
    ):
        raise ValueError("live web image differs from lock")
    saved = _saved_inspect(
        archive,
        lock["image_reference"],
        base_lock["saved_layer_sha256"],
        lock["binary_sha256"],
        lock["initial_state_sha256"],
    )
    if (
        saved["saved_config_sha256"] != lock["saved_config_sha256"]
        or saved["saved_layer_sha256"] != lock["saved_layer_sha256"]
        or saved["saved_labels"] != lock["labels"]
    ):
        raise ValueError("saved web image differs from lock")
    return {
        "image_id": lock["image_id"],
        "base_image_id": lock["base_image_id"],
        "binary_sha256": lock["binary_sha256"],
        "layers": len(saved["saved_layer_sha256"]),
    }
