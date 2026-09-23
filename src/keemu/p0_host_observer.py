"""P0-06 locked native observer for the explicitly approved host-network vantage."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

from keemu.p0_web_demo import verify as verify_web_image

REFERENCE = "keemu/p0-host-observer:p006"
SOURCE = "fixtures/sources/p0-host-observer/host_observer.c"
BINARY = "host-observer"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], timeout: int = 300) -> str:
    if argv[0] != "docker":
        raise ValueError("only the fixed Docker CLI is allowed")
    result = subprocess.run(  # noqa: S603 -- fixed Docker executable and argv.
        argv,
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


def _saved_inspect(archive: Path, source_hash: str, binary_hash: str) -> dict:
    with tarfile.open(archive) as tar:
        manifest_stream = tar.extractfile("manifest.json")
        if manifest_stream is None:
            raise ValueError("saved observer image has no manifest")
        manifest = json.load(manifest_stream)[0]
        if REFERENCE not in manifest["RepoTags"] or len(manifest["Layers"]) != 1:
            raise ValueError("saved observer image layout differs from lock")
        config_stream = tar.extractfile(manifest["Config"])
        layer_stream = tar.extractfile(manifest["Layers"][0])
        if config_stream is None or layer_stream is None:
            raise ValueError("saved observer image is incomplete")
        config = config_stream.read()
        layer = layer_stream.read()
    with tarfile.open(fileobj=__import__("io").BytesIO(layer)) as layer_tar:
        files = [member for member in layer_tar if member.isfile()]
        if len(files) != 1 or files[0].name.lstrip("./") != BINARY:
            raise ValueError("observer layer contains unexpected files")
        stream = layer_tar.extractfile(files[0])
        if stream is None or hashlib.sha256(stream.read()).hexdigest() != binary_hash:
            raise ValueError("observer binary differs from compiled input")
    labels = json.loads(config)["config"]["Labels"]
    if labels.get("org.keemu.host-observer-source-sha256") != source_hash:
        raise ValueError("observer source label differs from source input")
    return {
        "saved_config_sha256": hashlib.sha256(config).hexdigest(),
        "saved_layer_sha256": hashlib.sha256(layer).hexdigest(),
        "saved_labels": labels,
    }


def build(repo: Path) -> dict:
    """Build an immutable scratch image containing only the native observer."""
    repo = repo.resolve()
    web_image = verify_web_image(repo)
    source = repo / SOURCE
    context = repo / ".runtime/p0/p006-host-observer-build"
    if context.exists():
        raise FileExistsError(context)
    context.mkdir(parents=True)
    try:
        binary = context / BINARY
        result = subprocess.run(  # noqa: S603 -- fixed compiler argv and local source.
            [
                "/usr/bin/gcc",
                "-std=c17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fno-ident",
                "-static",
                "-Wl,--build-id=none",
                "-o",
                str(binary),
                str(source),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"host observer compilation failed rc={result.returncode}; "
                f"stderr={result.stderr[-3000:]!r}; stdout={result.stdout[-3000:]!r}"
            )
        header = binary.read_bytes()[:20]
        if (
            header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack("<H", header[18:20])[0] != 62
        ):
            raise ValueError("host observer is not ELF64 little-endian amd64")
        source_hash = sha256(source)
        binary_hash = sha256(binary)
        dockerfile = (
            "FROM scratch\n"
            'LABEL org.keemu.owner="keemu"\n'
            'LABEL org.keemu.phase="p0-06"\n'
            'LABEL org.keemu.role="host-vantage-observer"\n'
            f'LABEL org.keemu.host-observer-source-sha256="{source_hash}"\n'
            f'LABEL org.keemu.host-observer-binary-sha256="{binary_hash}"\n'
            "COPY host-observer /host-observer\n"
            'ENTRYPOINT ["/host-observer"]\n'
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
        expected = {
            "org.keemu.owner": "keemu",
            "org.keemu.phase": "p0-06",
            "org.keemu.role": "host-vantage-observer",
            "org.keemu.host-observer-source-sha256": source_hash,
            "org.keemu.host-observer-binary-sha256": binary_hash,
        }
        if (
            inspected["Architecture"] != "amd64"
            or inspected["Os"] != "linux"
            or inspected["Config"]["Entrypoint"] != ["/host-observer"]
            or labels != expected
        ):
            raise ValueError("live observer image differs from locked input")
        archive = repo / ".runtime/p0/host-observer-p006-image.tar"
        if archive.exists():
            raise FileExistsError(archive)
        run(["docker", "save", "-o", str(archive), REFERENCE], timeout=300)
        saved = _saved_inspect(archive, source_hash, binary_hash)
        if saved["saved_labels"] != labels:
            raise ValueError("saved observer labels differ from live image")
        lock = {
            "schema_version": 1,
            "kind": "p0-host-vantage-observer-lock",
            "image_reference": REFERENCE,
            "image_id": inspected["Id"],
            "source_path": SOURCE,
            "source_sha256": source_hash,
            "binary_path": BINARY,
            "binary_sha256": binary_hash,
            "platform": "linux/amd64",
            "entrypoint": inspected["Config"]["Entrypoint"],
            "labels": labels,
            "saved_image": str(archive.relative_to(repo)),
            "saved_archive_sha256": sha256(archive),
            "saved_config_sha256": saved["saved_config_sha256"],
            "saved_layer_sha256": saved["saved_layer_sha256"],
            "web_demo_image_id": web_image["image_id"],
            "scope": (
                "p0-06 only: explicitly approved, owner-labeled host-network "
                "HTTP/UDP observation client; no host mutation"
            ),
        }
        (repo / "locks/p0-host-observer-p006.json").write_text(
            json.dumps(lock, indent=2) + "\n", encoding="utf-8"
        )
        return lock
    finally:
        shutil.rmtree(context)


def verify(repo: Path) -> dict:
    repo = repo.resolve()
    lock = json.loads(
        (repo / "locks/p0-host-observer-p006.json").read_text(encoding="utf-8")
    )
    if sha256(repo / lock["source_path"]) != lock["source_sha256"]:
        raise ValueError("locked observer source changed")
    web_image = verify_web_image(repo)
    if web_image["image_id"] != lock["web_demo_image_id"]:
        raise ValueError("observer lock binds a different web-demo image")
    archive = repo / lock["saved_image"]
    if sha256(archive) != lock["saved_archive_sha256"]:
        raise ValueError("saved observer archive changed")
    inspected = json.loads(run(["docker", "image", "inspect", lock["image_id"]]))[0]
    if (
        inspected["Id"] != lock["image_id"]
        or inspected["Architecture"] != "amd64"
        or inspected["Os"] != "linux"
        or inspected["Config"]["Entrypoint"] != lock["entrypoint"]
        or inspected["Config"]["Labels"] != lock["labels"]
    ):
        raise ValueError("live observer image differs from lock")
    saved = _saved_inspect(archive, lock["source_sha256"], lock["binary_sha256"])
    if (
        saved["saved_config_sha256"] != lock["saved_config_sha256"]
        or saved["saved_layer_sha256"] != lock["saved_layer_sha256"]
        or saved["saved_labels"] != lock["labels"]
    ):
        raise ValueError("saved observer image differs from lock")
    return {
        "image_id": lock["image_id"],
        "binary_sha256": lock["binary_sha256"],
        "web_demo_image_id": lock["web_demo_image_id"],
    }
