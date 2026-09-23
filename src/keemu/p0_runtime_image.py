"""P0-05 derived native-init image; preserve the immutable p0-04 image lock."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

from keemu.p0_image import verify_image_lock

REFERENCE = "keemu/p0-aarch64:mixed-p005"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], timeout: int = 90) -> str:
    if argv[0] not in {"gcc", "docker"}:
        raise ValueError("only the fixed compiler and Docker CLI are allowed")
    result = subprocess.run(  # noqa: S603 -- fixed executable and argv; no shell.
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed rc={result.returncode}: {argv!r}; "
            f"stderr={result.stderr[-3000:]!r}; stdout={result.stdout[-3000:]!r}"
        )
    return result.stdout.strip()


def _saved_inspect(
    archive: Path, reference: str, base_layer: str, binary_hash: str
) -> dict:
    with tarfile.open(archive) as tar:
        manifest_stream = tar.extractfile("manifest.json")
        if manifest_stream is None:
            raise ValueError("saved image has no manifest")
        manifest = json.load(manifest_stream)[0]
        if reference not in manifest["RepoTags"] or len(manifest["Layers"]) != 2:
            raise ValueError("derived image must have base and one replacement layer")
        config_file = tar.extractfile(manifest["Config"])
        if config_file is None:
            raise ValueError("saved image has no config")
        config = config_file.read()
        hashes = []
        for layer_path in manifest["Layers"]:
            layer = tar.extractfile(layer_path)
            if layer is None:
                raise ValueError("saved layer missing")
            hashes.append(hashlib.sha256(layer.read()).hexdigest())
        if hashes[0] != base_layer:
            raise ValueError("base image layer changed")
        replacement = tar.extractfile(manifest["Layers"][1])
        if replacement is None:
            raise ValueError("replacement layer missing")
        with tarfile.open(fileobj=replacement) as layer_tar:
            files = [member for member in layer_tar if member.isfile()]
            if len(files) != 1 or files[0].name.lstrip("./") != "__keemu/init":
                raise ValueError("replacement layer changed application files")
            init = layer_tar.extractfile(files[0])
            if init is None or hashlib.sha256(init.read()).hexdigest() != binary_hash:
                raise ValueError("replacement init differs from compiled input")
        return {
            "saved_config_sha256": hashlib.sha256(config).hexdigest(),
            "saved_layer_sha256": hashes,
            "saved_labels": json.loads(config)["config"]["Labels"],
        }


def build(repo: Path) -> dict:
    repo = repo.resolve()
    previous_lock = json.loads((repo / "locks/p0-mixed-image-aarch64.json").read_text())
    verify_image_lock(
        repo / "locks/p0-mixed-image-aarch64.json", repo / ".runtime/p0/mixed-image.tar"
    )
    source = repo / "fixtures/recipes/aarch64/keemu-init-p005.c"
    context = repo / ".runtime/p0/p005-image-build"
    if context.exists():
        raise FileExistsError(context)
    context.mkdir(parents=True)
    try:
        binary = context / "init"
        run(
            [
                "gcc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-static",
                "-o",
                str(binary),
                str(source),
            ]
        )
        head = binary.read_bytes()[:20]
        if head[:6] != b"\x7fELF\x02\x01" or struct.unpack("<H", head[18:20])[0] != 62:
            raise ValueError("replacement init is not amd64 ELF64 little-endian")
        binary_hash = sha256(binary)
        source_hash = sha256(source)
        dockerfile = (
            f"FROM {previous_lock['image_id']}\n"
            "COPY init /__keemu/init\n"
            'LABEL org.keemu.phase="p0-05"\n'
            f'LABEL org.keemu.base-image-id="{previous_lock["image_id"]}"\n'
            f'LABEL org.keemu.init-source-sha256="{source_hash}"\n'
            f'LABEL org.keemu.init-binary-sha256="{binary_hash}"\n'
        )
        (context / "Dockerfile").write_text(dockerfile)
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
        if (
            inspected["Architecture"] != "amd64"
            or inspected["Os"] != "linux"
            or inspected["Config"]["Entrypoint"] != ["/__keemu/init"]
            or labels["org.keemu.owner"] != "keemu"
            or labels["org.keemu.target"] != "aarch64-3.10"
            or labels["org.keemu.init-source-sha256"] != source_hash
            or labels["org.keemu.init-binary-sha256"] != binary_hash
            or labels["org.keemu.base-image-id"] != previous_lock["image_id"]
            or labels["org.keemu.rootfs-sha256"] != previous_lock["tree_sha256"]
        ):
            raise ValueError("derived image inspect differs from locked base")
        archive = repo / ".runtime/p0/mixed-image-p005.tar"
        if archive.exists():
            raise FileExistsError(archive)
        run(["docker", "save", "-o", str(archive), REFERENCE], timeout=300)
        saved = _saved_inspect(
            archive, REFERENCE, previous_lock["saved_layer_sha256"], binary_hash
        )
        if saved["saved_labels"] != labels:
            raise ValueError("saved image labels differ from live image")
        lock = {
            "schema_version": 1,
            "kind": "p0-derived-runtime-image-lock",
            "image_reference": REFERENCE,
            "image_id": inspected["Id"],
            "base_image_id": previous_lock["image_id"],
            "base_lock": "locks/p0-mixed-image-aarch64.json",
            "source_path": str(source.relative_to(repo)),
            "source_sha256": source_hash,
            "binary_sha256": binary_hash,
            "platform": "linux/amd64",
            "entrypoint": inspected["Config"]["Entrypoint"],
            "labels": labels,
            "saved_image": str(archive.relative_to(repo)),
            "saved_archive_sha256": sha256(archive),
            "saved_config_sha256": saved["saved_config_sha256"],
            "saved_layer_sha256": saved["saved_layer_sha256"],
            "native_compiler": run(["gcc", "-dumpfullversion"]),
            "docker_server": run(
                ["docker", "version", "--format", "{{.Server.Version}}"]
            ),
            "scope": (
                "p0-05 native signal fix only; original p0-04 image "
                "and target rootfs retained"
            ),
        }
        (repo / "locks/p0-mixed-image-aarch64-p005.json").write_text(
            json.dumps(lock, indent=2) + "\n"
        )
        return lock
    finally:
        shutil.rmtree(context)


def verify(repo: Path) -> dict:
    repo = repo.resolve()
    lock = json.loads((repo / "locks/p0-mixed-image-aarch64-p005.json").read_text())
    old = json.loads((repo / lock["base_lock"]).read_text())
    verify_image_lock(repo / lock["base_lock"], repo / ".runtime/p0/mixed-image.tar")
    if old["image_id"] != lock["base_image_id"]:
        raise ValueError("base image changed")
    if sha256(repo / lock["source_path"]) != lock["source_sha256"]:
        raise ValueError("native source changed")
    archive = repo / lock["saved_image"]
    if sha256(archive) != lock["saved_archive_sha256"]:
        raise ValueError("derived image archive changed")
    inspected = json.loads(run(["docker", "image", "inspect", lock["image_id"]]))[0]
    if (
        inspected["Id"] != lock["image_id"]
        or inspected["Os"] != "linux"
        or inspected["Architecture"] != "amd64"
        or inspected["Config"]["Labels"] != lock["labels"]
        or inspected["Config"]["Entrypoint"] != lock["entrypoint"]
    ):
        raise ValueError("live image differs from derived lock")
    saved = _saved_inspect(
        archive,
        lock["image_reference"],
        old["saved_layer_sha256"],
        lock["binary_sha256"],
    )
    if (
        saved["saved_config_sha256"] != lock["saved_config_sha256"]
        or saved["saved_layer_sha256"] != lock["saved_layer_sha256"]
        or saved["saved_labels"] != lock["labels"]
    ):
        raise ValueError("saved derived image differs from lock")
    return {
        "image_id": lock["image_id"],
        "base_image_id": old["image_id"],
        "binary_sha256": lock["binary_sha256"],
        "layers": len(saved["saved_layer_sha256"]),
    }
