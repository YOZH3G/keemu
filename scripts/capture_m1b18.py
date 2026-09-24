"""Capture the two Entware MIPS package closures; never run fetched installers.

Run explicitly while online. Published locks and cached bytes are later checked
by the offline m1b-18 verifier; the feed is mutable, not a reproducible snapshot.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from keemu.entware import build_entware_lock, parse_package_index

REPO = Path(__file__).resolve().parents[1]
SOURCES = {
    "mipsel-3.4": "mipselsf-k3.4",
    "mips-3.4": "mipssf-k3.4",
}


def fetch(url: str, path: Path) -> bytes:
    if path.exists():
        return path.read_bytes()
    if not url.startswith("https://bin.entware.net/"):
        raise ValueError("only Entware HTTPS artifact URLs are accepted")
    with urllib.request.urlopen(url, timeout=90) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {url}")
        content = response.read(64 * 1024 * 1024 + 1)
    if len(content) > 64 * 1024 * 1024:
        raise RuntimeError(f"artifact too large: {url}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return content


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture(target: str, directory: str) -> None:
    base = f"https://bin.entware.net/{directory}"
    cache = REPO / ".runtime/m1b18" / target
    raw = fetch(f"{base}/Packages.gz", cache / "Packages.gz")
    index = gzip.decompress(raw)
    destination = REPO / "locks" / f"m1b18-{target}.json"
    prior = json.loads(destination.read_text()) if destination.exists() else None
    lock: dict[str, Any] = build_entware_lock(
        index,
        target=target,
        roots=["entware-opt", "busybox", "ca-bundle"],
        index_url=f"{base}/Packages.gz",
        base_url=base,
        captured_at=prior["captured_at"]
        if prior
        else datetime.now(UTC).replace(microsecond=0).isoformat(),
    )
    lock["source"]["index_content_encoding"] = "gzip"
    lock["source"]["index_compressed_sha256"] = digest(raw)
    records = parse_package_index(index)
    for artifact in lock["packages"]:
        payload = fetch(artifact["url"], cache / "packages" / artifact["filename"])
        if digest(payload) != artifact["sha256"]:
            raise RuntimeError(f"feed index hash mismatch: {artifact['filename']}")
        print(target, artifact["name"], artifact["version"], len(payload), flush=True)
    for name in ("generic.sh", "opkg", "opkg.conf"):
        url = f"{base}/installer/{name}"
        payload = fetch(url, cache / name)
        if name == "opkg":
            (cache / name).chmod(0o755)
        lock.setdefault("bootstrap_artifacts", []).append(
            {
                "filename": name,
                "url": url,
                "sha256": digest(payload),
                "size": len(payload),
            }
        )
    lock["evidence_scope"] = (
        "Captured and SHA-256-verified feed closure and installer bytes only; "
        "feed URL is mutable; target execution and image verification are separate."
    )
    if prior is not None and prior != lock:
        raise RuntimeError(f"refusing to replace existing rootfs lock: {target}")
    if prior is None:
        destination.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(target, "index", len(records), "closure", len(lock["packages"]), flush=True)


def capture_sdk(target: str, directory: str) -> None:
    base = f"https://bin.entware.net/{directory}"
    cache = REPO / ".runtime/m1b18" / target
    raw = (cache / "Packages.gz").read_bytes()
    index = gzip.decompress(raw)
    destination = REPO / "locks" / f"m1b18-sdk-{target}.json"
    prior = json.loads(destination.read_text()) if destination.exists() else None
    lock: dict[str, Any] = build_entware_lock(
        index,
        target=target,
        roots=["gcc"],
        index_url=f"{base}/Packages.gz",
        base_url=base,
        captured_at=prior["captured_at"]
        if prior
        else datetime.now(UTC).replace(microsecond=0).isoformat(),
    )
    lock["source"]["index_compressed_sha256"] = digest(raw)
    for artifact in lock["packages"]:
        payload = fetch(artifact["url"], cache / "packages" / artifact["filename"])
        if digest(payload) != artifact["sha256"]:
            raise RuntimeError(f"feed index hash mismatch: {artifact['filename']}")
        print(target, "SDK", artifact["name"], len(payload), flush=True)
    if prior is not None and prior != lock:
        raise RuntimeError(f"refusing to replace existing SDK lock: {target}")
    if prior is None:
        destination.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    for target, directory in SOURCES.items():
        capture(target, directory)
        capture_sdk(target, directory)
