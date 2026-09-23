"""Bounded, no-extraction static IPK inspection. Nothing from an IPK is executed.

This is an input gate, not an opkg install or proof of target execution. Callers
must reopen/re-hash the package before use; an inspection is not a file lock.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import os
import posixpath
import re
import stat
import struct
import tarfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

from keemu.models import Status
from keemu.profiles import GenericProfile

MAX_IPK = 64 * 1024 * 1024
MAX_ENTRY = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_ENTRIES = 8192
MAX_NAME = 4096
MAGICS = {b"\x1f\x8b": ".gz", b"\xfd7zXZ\x00": ".xz", b"BZh": ".bz2"}
MEMBERS = {
    "control.tar.gz",
    "data.tar.gz",
    "control.tar.xz",
    "data.tar.xz",
    "control.tar.bz2",
    "data.tar.bz2",
    "control.tar",
    "data.tar",
    "debian-binary",
}
METADATA = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9+._-]*$")
DEPENDENCY = re.compile(
    r"^([a-z0-9][a-z0-9+._-]*)(?:\s*\((>=|<=|=|>>|<<)\s*([^()\s]+)\))?$", re.I
)
ARCH_ELF = {
    "aarch64-3.10": (183, 2, "little"),
    "mipsel-3.4": (8, 1, "little"),
    "mips-3.4": (8, 1, "big"),
}


class IPKError(ValueError):
    """Malformed or unsafe input. No file was extracted."""


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: int
    size: int
    link: str | None = None


@dataclass(frozen=True)
class ELFInfo:
    path: str
    elf_class: int
    endian: str
    machine: int
    osabi: int
    abi_version: int
    flags: int
    interpreter: str | None
    needed: tuple[str, ...]
    search_paths: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    path: str
    detail: str


@dataclass(frozen=True)
class Inspection:
    format: str
    sha256: str
    metadata: dict[str, str]
    dependencies: tuple[tuple[str, ...], ...]
    control_scripts: tuple[str, ...]
    entries: tuple[Entry, ...]
    elves: tuple[ELFInfo, ...]
    findings: tuple[Finding, ...]
    status: Status
    mode: str = "static"
    limitations: tuple[str, ...] = (
        "PASS means static checks only; no installation or target execution",
        "dependency checks need a complete target rootfs; postinst paths need recheck",
        "reopen and rehash the input at install time to prevent replacement",
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _bounded_file(path: Path) -> bytes:
    # Do not follow the final symlink. A caller supplying a directory as root
    # should also protect its ancestors against replacement at use time.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IPK:
            raise IPKError("IPK must be a bounded regular file")
        with os.fdopen(os.dup(fd), "rb") as source:
            data = source.read(MAX_IPK + 1)
        if len(data) > MAX_IPK:
            raise IPKError("IPK exceeds size limit")
        return data
    finally:
        os.close(fd)


def _clean(name: str, *, outer: bool = False) -> str:
    if (
        not name
        or len(name) > MAX_NAME
        or "\\" in name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    ):
        raise IPKError("invalid archive path")
    if name.endswith("//"):
        raise IPKError(f"noncanonical archive path: {name!r}")
    raw = name.removeprefix("./").rstrip("/")
    if raw in {".", ""} and name in {".", "./"} and not outer:
        return "."
    if (
        not raw
        or raw.startswith("/")
        or any(c in {"", ".", ".."} for c in raw.split("/"))
    ):
        raise IPKError(f"unsafe archive path: {name!r}")
    if outer and "/" in raw:
        raise IPKError(f"nested outer member: {name!r}")
    return raw


def _archive_kind(data: bytes) -> str:
    for magic, suffix in MAGICS.items():
        if data.startswith(magic):
            return suffix
    if len(data) >= 262 and data[257:262] == b"ustar":
        return ""
    raise IPKError("unrecognized tar compression/signature")


def _inflate(data: bytes, compression: str, budget: list[int]) -> bytes:
    if not compression:
        return data
    decoder = {
        ".gz": lambda: zlib.decompressobj(16 + zlib.MAX_WBITS),
        ".xz": lzma.LZMADecompressor,
        ".bz2": bz2.BZ2Decompressor,
    }[compression]()
    output = bytearray()
    try:
        for offset in range(0, len(data), 65536):
            block = data[offset : offset + 65536]
            while block:
                remaining = MAX_EXPANDED - budget[2] - len(output)
                if remaining <= 0:
                    raise IPKError("decompressed archive exceeds limit")
                part = decoder.decompress(block, max_length=min(remaining, 65536))
                output.extend(part)
                block = decoder.unconsumed_tail if compression == ".gz" else b""
                if compression != ".gz":
                    while not decoder.eof and not decoder.needs_input:
                        remaining = MAX_EXPANDED - budget[2] - len(output)
                        if remaining <= 0:
                            raise IPKError("decompressed archive exceeds limit")
                        output.extend(
                            decoder.decompress(b"", max_length=min(remaining, 65536))
                        )
                if decoder.eof:
                    if decoder.unused_data or offset + 65536 < len(data):
                        raise IPKError("trailing compressed archive data")
                    break
        if not decoder.eof:
            raise IPKError("truncated compressed archive")
    except (zlib.error, lzma.LZMAError, OSError, EOFError) as exc:
        raise IPKError("corrupt compressed archive") from exc
    budget[2] += len(output)
    return bytes(output)


def _tar(
    data: bytes, *, role: str, budget: list[int]
) -> tuple[dict[str, tuple[Entry, bytes]], str]:
    compression = _archive_kind(data)
    plain = _inflate(data, compression, budget)
    found: dict[str, tuple[Entry, bytes]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
            for member in archive:
                budget[0] += 1
                if budget[0] > MAX_ENTRIES:
                    raise IPKError("too many archive entries")
                name = _clean(member.name, outer=role == "outer")
                if name == "." and member.isdir():
                    continue
                if name in found:
                    raise IPKError(f"duplicate member: {role}/{name}")
                if role == "outer" and name not in MEMBERS:
                    raise IPKError(f"unexpected outer member: {name}")
                if role == "data" and not (name == "opt" or name.startswith("opt/")):
                    raise IPKError(f"data member outside /opt: {name}")
                if role == "control" and (
                    "/" in name or member.issym() or member.islnk()
                ):
                    raise IPKError(f"unsafe control member: {name}")
                if member.size < 0 or member.size > MAX_ENTRY:
                    raise IPKError(f"oversized archive member: {name}")
                budget[1] += member.size
                if budget[1] > MAX_EXPANDED:
                    raise IPKError("expanded archive exceeds limit")
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise IPKError(f"unreadable archive member: {name}")
                    content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        raise IPKError(f"truncated archive member: {name}")
                    kind, link = "file", None
                elif member.isdir():
                    content, kind, link = b"", "dir", None
                elif role == "data" and (member.issym() or member.islnk()):
                    content = b""
                    kind = "symlink" if member.issym() else "hardlink"
                    link = member.linkname
                else:
                    raise IPKError(f"special file in {role}: {name}")
                found[name] = (
                    Entry(name, kind, member.mode, member.size, link),
                    content,
                )
            trailer = plain[archive.offset :]
            if len(trailer) < 1024 or len(trailer) % 512 or any(trailer):
                raise IPKError(f"missing or corrupt {role} tar end marker")
    except (tarfile.TarError, EOFError, OSError, OverflowError) as exc:
        raise IPKError(f"corrupt {role} archive: {exc}") from exc
    return found, compression


def _ar(data: bytes, budget: list[int]) -> dict[str, tuple[Entry, bytes]]:
    if not data.startswith(b"!<arch>\n"):
        raise IPKError("invalid ar signature")
    result: dict[str, tuple[Entry, bytes]] = {}
    offset = 8
    while offset < len(data):
        budget[0] += 1
        if budget[0] > MAX_ENTRIES or len(data) - offset < 60:
            raise IPKError("truncated or oversized ar header")
        header = data[offset : offset + 60]
        if header[58:] != b"`\n":
            raise IPKError("invalid ar header")
        try:
            name = _clean(header[:16].decode("ascii").strip().rstrip("/"), outer=True)
            size = int(header[48:58].decode("ascii").strip())
            mode = int(header[40:48].decode("ascii").strip(), 8)
        except (UnicodeError, ValueError) as exc:
            raise IPKError("invalid ar member metadata") from exc
        if name not in MEMBERS or name in result or size < 0 or size > MAX_ENTRY:
            raise IPKError(f"invalid or duplicate ar member: {name}")
        budget[1] += size
        if budget[1] > MAX_EXPANDED or offset + 60 + size > len(data):
            raise IPKError("oversized or truncated ar member")
        content = data[offset + 60 : offset + 60 + size]
        result[name] = (Entry(name, "file", mode, size), content)
        if size % 2 and data[offset + 60 + size : offset + 61 + size] != b"\n":
            raise IPKError("invalid ar padding")
        offset += 60 + size + (size % 2)
    if offset != len(data):
        raise IPKError("truncated ar padding")
    return result


def _metadata(content: bytes) -> tuple[dict[str, str], tuple[tuple[str, ...], ...]]:
    if len(content) > 65536:
        raise IPKError("control metadata exceeds limit")
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        raise IPKError("invalid control encoding") from exc
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += " " + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            if (
                not METADATA.fullmatch(key)
                or key.casefold() in {k.casefold() for k in fields}
                or not value.strip()
            ):
                raise IPKError("invalid or duplicate control field")
            fields[key] = value.strip()
            current = key
        else:
            raise IPKError("malformed control field")
    for key in ("Package", "Version", "Architecture"):
        if not fields.get(key):
            raise IPKError(f"missing control {key}")
    if not PKG_NAME.fullmatch(fields["Package"]) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.+_:~-]*", fields["Version"]
    ):
        raise IPKError("invalid package name or version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fields["Architecture"]):
        raise IPKError("invalid Architecture")
    deps: list[tuple[str, ...]] = []
    if fields.get("Depends"):
        for requirement in fields["Depends"].split(","):
            alternatives = tuple(x.strip() for x in requirement.split("|"))
            if not alternatives or any(
                not DEPENDENCY.fullmatch(x) for x in alternatives
            ):
                raise IPKError("invalid Depends expression")
            deps.append(alternatives)
    return fields, tuple(deps)


def _link_target(path: str, link: str, *, hard: bool) -> str:
    if (
        not link
        or len(link) > MAX_NAME
        or "\\" in link
        or any(ord(c) < 32 or ord(c) == 127 for c in link)
    ):
        raise IPKError(f"invalid link at {path}")
    # tar hardlinks are archive-root relative; symbolic links are parent-relative.
    base = "" if hard or link.startswith("/") else posixpath.dirname(path)
    target = posixpath.normpath(posixpath.join(base, link.lstrip("/")))
    if not (target == "opt" or target.startswith("opt/")):
        raise IPKError(f"link escapes /opt: {path} -> {link}")
    return target


def _validate_links(entries: dict[str, tuple[Entry, bytes]]) -> None:
    for name, (entry, _) in entries.items():
        if entry.kind not in {"symlink", "hardlink"}:
            continue
        target = _link_target(name, entry.link or "", hard=entry.kind == "hardlink")
        if entry.kind == "hardlink" and (
            target not in entries or entries[target][0].kind != "file"
        ):
            raise IPKError(f"hardlink target is not a regular member: {name}")
        # Reject paths that traverse *any* archive symlink, including links
        # appearing after this entry in tar order. An ordinary symlink target
        # may be supplied by a later install, but cycles in-package are unsafe.
        seen: set[str] = {name}
        for _ in range(32):
            if target in seen:
                raise IPKError(f"link cycle at {name}")
            seen.add(target)
            next_entry = entries.get(target)
            if next_entry is None or next_entry[0].kind != "symlink":
                break
            target = _link_target(target, next_entry[0].link or "", hard=False)
        else:
            raise IPKError(f"link chain too deep at {name}")
    for name in entries:
        for part in Path(name).parents:
            parent = part.as_posix()
            if parent in entries and entries[parent][0].kind != "dir":
                raise IPKError(f"non-directory path component: {name}")


def _package_file(entries: dict[str, tuple[Entry, bytes]], path: str) -> bool:
    name = path.removeprefix("/")
    for _ in range(32):
        entry = entries.get(name)
        if entry is None:
            return False
        if entry[0].kind == "file":
            return True
        if entry[0].kind not in {"symlink", "hardlink"}:
            return False
        name = _link_target(name, entry[0].link or "", hard=entry[0].kind == "hardlink")
    return False


def _elf(path: str, data: bytes) -> ELFInfo:
    if (
        len(data) < 52
        or data[:4] != b"\x7fELF"
        or data[4] not in (1, 2)
        or data[5] not in (1, 2)
    ):
        raise IPKError(f"malformed ELF: {path}")
    cls = data[4]
    endian = "little" if data[5] == 1 else "big"
    order = "<" if endian == "little" else ">"
    hdr = order + ("HHIIIIIHHHHHH" if cls == 1 else "HHIQQQIHHHHHH")
    try:
        fields = struct.unpack_from(hdr, data, 16)
        machine, flags = fields[1], fields[6]
        if data[6] != 1 or fields[2] != 1:
            raise IPKError(f"invalid ELF version: {path}")
        phoff, phentsize, phnum = fields[4], fields[8], fields[9]
        expected_ph = 32 if cls == 1 else 56
        if phnum > 4096 or (
            phnum and (phentsize < expected_ph or phoff + phnum * phentsize > len(data))
        ):
            raise IPKError(f"invalid ELF program table: {path}")
        ph = order + ("IIIIIIII" if cls == 1 else "IIQQQQQQ")
        loads: list[tuple[int, int, int]] = []
        dynamic: tuple[int, int] | None = None
        interpreter: str | None = None
        for i in range(phnum):
            row = struct.unpack_from(ph, data, phoff + i * phentsize)
            kind = row[0]
            off, vaddr, size = (
                (row[1], row[2], row[4]) if cls == 1 else (row[2], row[3], row[5])
            )
            if off + size > len(data):
                raise IPKError(f"invalid ELF segment bounds: {path}")
            if kind == 1:
                loads.append((vaddr, off, size))
            elif kind == 2:
                dynamic = (off, size)
            elif kind == 3:
                raw = data[off : off + size]
                if not raw.endswith(b"\x00") or b"\x00" in raw[:-1]:
                    raise IPKError(f"invalid PT_INTERP: {path}")
                interpreter = raw[:-1].decode("utf-8")
                if not interpreter.startswith("/") or ".." in interpreter.split("/"):
                    raise IPKError(f"unsafe PT_INTERP: {path}")
        needed: list[str] = []
        search_paths: list[str] = []
        if dynamic:
            off, size = dynamic
            stride = 8 if cls == 1 else 16
            if size % stride or size > 65536:
                raise IPKError(f"invalid ELF dynamic segment: {path}")
            entries = [
                struct.unpack_from(order + ("iI" if cls == 1 else "qQ"), data, off + n)
                for n in range(0, size, stride)
            ]
            straddr = next((v for tag, v in entries if tag == 5), None)
            strsize = next((v for tag, v in entries if tag == 10), None)
            refs = [v for tag, v in entries if tag == 1]
            path_refs = [v for tag, v in entries if tag in (15, 29)]
            if (refs or path_refs) and (
                straddr is None or strsize is None or strsize > 1024 * 1024
            ):
                raise IPKError(f"missing ELF string table: {path}")
            if refs or path_refs:
                str_off = next(
                    (
                        fileoff + straddr - addr
                        for addr, fileoff, length in loads
                        if addr <= straddr and straddr + strsize <= addr + length
                    ),
                    None,
                )
                if str_off is None or str_off + strsize > len(data):
                    raise IPKError(f"invalid ELF string table: {path}")
                strings = data[str_off : str_off + strsize]

                def string_at(ref: int) -> str:
                    if ref >= len(strings):
                        raise IPKError(f"invalid dynamic string offset: {path}")
                    end = strings.find(b"\x00", ref)
                    if end < 0:
                        raise IPKError(f"unterminated dynamic string: {path}")
                    return strings[ref:end].decode("utf-8")

                for ref in refs:
                    name = string_at(ref)
                    if not name or "/" in name or "\\" in name:
                        raise IPKError(f"unsafe DT_NEEDED: {path}")
                    needed.append(name)
                for ref in path_refs:
                    search_paths.extend(string_at(ref).split(":"))
                if len(search_paths) > 128 or any(
                    len(item) > MAX_NAME for item in search_paths
                ):
                    raise IPKError(f"oversized ELF search path: {path}")
    except (struct.error, UnicodeError) as exc:
        raise IPKError(f"malformed ELF: {path}") from exc
    return ELFInfo(
        path,
        cls * 32,
        endian,
        machine,
        data[7],
        data[8],
        flags,
        interpreter,
        tuple(needed),
        tuple(search_paths),
    )


def _exists(root: Path, target: str, *, regular: bool = True) -> bool:
    """Conservative, no-follow rootfs lookup: no host escape, no execution."""
    try:
        parts = target.removeprefix("/").split("/")
        if parts[0] != "opt":
            return False
        candidate = root
        seen: set[str] = set()
        for _ in range(32):
            if not parts:
                return False
            component = parts.pop(0)
            candidate = candidate / component
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(candidate)
                # Interpret the link inside the target rootfs, never on host.
                relative = candidate.relative_to(root).as_posix()
                resolved = _link_target(relative, link, hard=False)
                if resolved in seen:
                    return False
                seen.add(resolved)
                parts = resolved.split("/") + parts
                candidate = root
            elif parts and not stat.S_ISDIR(info.st_mode):
                return False
            elif not parts:
                return (
                    stat.S_ISREG(info.st_mode)
                    if regular
                    else (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                )
        return False
    except (OSError, ValueError):
        return False


def _library_candidates(elf: ELFInfo, name: str) -> tuple[list[str], bool]:
    directories = ["/opt/lib", "/opt/usr/lib"]
    unresolved = False
    for item in elf.search_paths:
        if item in {"$ORIGIN", "${ORIGIN}"}:
            directory = "/" + posixpath.dirname(elf.path)
        elif item.startswith(("$ORIGIN/", "${ORIGIN}/")):
            relative = item.split("/", 1)[1]
            try:
                directory = "/" + _link_target(elf.path, relative, hard=False)
            except IPKError:
                unresolved = True
                continue
        elif item.startswith("/opt/") and not any(
            part in {".", ".."} for part in item.split("/")
        ):
            directory = item
        else:
            # Unknown loader variable, relative path or out-of-scope mount:
            # don't invent a missing-library FAIL from an incomplete lookup.
            unresolved = True
            continue
        directories.append(directory)
    return [directory.rstrip("/") + "/" + name for directory in directories], unresolved


def inspect_ipk(
    path: Path, *, profile: GenericProfile | None = None, rootfs: Path | None = None
) -> Inspection:
    """Inspect a bounded local IPK; rootfs, when given, is dependency-inclusive.

    A missing library without that *complete* rootfs is BLOCKED, not a false
    package FAIL. Post-install-created paths are likewise deferred to install.
    """
    blob = _bounded_file(path)
    budget = [0, 0, 0]
    if blob.startswith(b"!<arch>\n"):
        outer = _ar(blob, budget)
        wrapper = "ar"
    else:
        outer, compression = _tar(blob, role="outer", budget=budget)
        wrapper = "tar" + compression
    for required in ("control", "data"):
        options = [name for name in outer if name.startswith(required + ".tar")]
        if len(options) != 1:
            raise IPKError(f"expected exactly one {required} archive")
    if "debian-binary" not in outer or outer["debian-binary"][1] != b"2.0\n":
        raise IPKError("missing or invalid debian-binary")
    control_name = next(n for n in outer if n.startswith("control.tar"))
    data_name = next(n for n in outer if n.startswith("data.tar"))
    control, control_compression = _tar(
        outer[control_name][1], role="control", budget=budget
    )
    data, data_compression = _tar(outer[data_name][1], role="data", budget=budget)
    if (
        control_name != "control.tar" + control_compression
        or data_name != "data.tar" + data_compression
    ):
        raise IPKError("nested archive suffix disagrees with signature")
    if "control" not in control or control["control"][0].kind != "file":
        raise IPKError("missing regular control metadata")
    _validate_links(data)
    metadata, dependencies = _metadata(control["control"][1])
    findings: list[Finding] = []

    def add(code: str, status: Status, member: str, detail: str) -> None:
        findings.append(Finding(code, status, member, detail))

    architecture = metadata["Architecture"]
    if profile and architecture not in (profile.entware_target, "all"):
        add(
            "architecture",
            "FAIL",
            "control",
            f"{architecture} != {profile.entware_target}",
        )
    if not profile and architecture not in {*ARCH_ELF, "all"}:
        add("unsupported-architecture", "BLOCKED", "control", architecture)
    for name, (entry, _) in control.items():
        if name == "control" or entry.kind == "dir":
            continue
        if name not in {"preinst", "postinst", "prerm", "postrm", "conffiles"}:
            add("unknown-control", "WARN", name, "unrecognized control member")
        if (
            name in {"preinst", "postinst", "prerm", "postrm"}
            and not entry.mode & 0o111
        ):
            add("script-permission", "FAIL", name, "maintainer script not executable")
    scripts = tuple(
        n for n in ("preinst", "postinst", "prerm", "postrm") if n in control
    )
    elves: list[ELFInfo] = []
    expected = ARCH_ELF.get(profile.entware_target if profile else architecture)
    for name, (entry, content) in (*control.items(), *data.items()):
        if entry.kind != "symlink" and entry.mode & stat.S_IWOTH:
            add("unsafe-mode", "FAIL", name, "world-writable entry")
        elif entry.kind != "symlink" and entry.mode & (stat.S_ISUID | stat.S_ISGID):
            add(
                "privileged-mode",
                "WARN",
                name,
                "setuid/setgid bit: review package policy",
            )
        if entry.kind != "file":
            continue
        if content.startswith(b"\x7fELF"):
            elf = _elf(name, content)
            elves.append(elf)
            if expected and (elf.machine, elf.elf_class // 32, elf.endian) != expected:
                description = (
                    f"machine={elf.machine} class={elf.elf_class} "
                    f"endian={elf.endian}; expected {expected}"
                )
                add(
                    "elf-architecture",
                    "FAIL",
                    name,
                    description,
                )
            if expected and elf.osabi not in {0, 3}:
                add("elf-abi", "FAIL", name, f"unsupported OS ABI {elf.osabi}")
            if (
                expected
                and elf.machine == 8
                and elf.flags & 0xF000 in {0x2000, 0x3000, 0x4000}
            ):
                add("elf-abi", "FAIL", name, "unsupported MIPS ABI flags")
            if architecture == "all" and name in data:
                add(
                    "architecture-all-elf",
                    "FAIL",
                    name,
                    "Architecture: all contains ELF",
                )
            for kind, needed in (
                [("interpreter", elf.interpreter)] if elf.interpreter else []
            ) + [("dependency", n) for n in elf.needed]:
                candidates, uncertain = (
                    ([needed], False)
                    if kind == "interpreter"
                    else _library_candidates(elf, needed)
                )
                if any(_package_file(data, c) for c in candidates) or (
                    rootfs and any(_exists(rootfs, c) for c in candidates)
                ):
                    continue
                # A postinst may create a loader/library link; do not turn this
                # static uncertainty into a definitive pre-install package FAIL.
                status = (
                    "BLOCKED"
                    if rootfs is None
                    or "postinst" in scripts
                    or uncertain
                    or any(not c.startswith("/opt/") for c in candidates)
                    else "FAIL"
                )
                reason = (
                    "post-install recheck needed"
                    if "postinst" in scripts
                    else "not found in package or supplied rootfs"
                )
                add(
                    "missing-" + kind,
                    status,
                    name,
                    f"{needed}: {reason}",
                )
        elif content.startswith(b"#!"):
            first = content.split(b"\n", 1)[0]
            if len(first) > 256 or b"\x00" in first:
                add("shebang", "FAIL", name, "invalid shebang")
            else:
                interpreter = (
                    first[2:].strip().split(b" ", 1)[0].decode("utf-8", "replace")
                )
                if not interpreter.startswith("/") or ".." in interpreter.split("/"):
                    add("shebang", "FAIL", name, f"unsafe interpreter {interpreter}")
                elif interpreter == "/bin/sh" or _package_file(data, interpreter):
                    pass
                elif rootfs is None:
                    add(
                        "shebang-interpreter",
                        "BLOCKED",
                        name,
                        f"{interpreter}: target rootfs not supplied",
                    )
                elif not _exists(rootfs, interpreter):
                    add(
                        "shebang-interpreter",
                        "FAIL"
                        if "postinst" not in scripts and interpreter.startswith("/opt/")
                        else "BLOCKED",
                        name,
                        f"{interpreter}: target interpreter not found",
                    )
            if name in data and not entry.mode & 0o111:
                add(
                    "script-permission",
                    "WARN",
                    name,
                    "script with shebang is not executable; may be sourced",
                )
            for line_number, line in enumerate(content[:8192].splitlines(), 1):
                if re.search(rb"(?<![\w/])/(?:etc|usr/local|home)/[\w./-]+", line):
                    add(
                        "hardcoded-path",
                        "WARN",
                        name,
                        f"host-style absolute path in script line {line_number}; "
                        "review target mapping",
                    )
        elif entry.mode & 0o111 and content:
            add(
                "unknown-executable",
                "WARN",
                name,
                "executable is neither ELF nor shebang script",
            )
        if (
            name in data
            and content.startswith(b"\x7fELF")
            and not entry.mode & 0o111
            and _elf(name, content).interpreter
        ):
            add(
                "elf-permission",
                "WARN",
                name,
                "dynamic ELF lacks executable bit; may be shared library",
            )
    for name, (entry, _) in data.items():
        if entry.kind == "symlink":
            target = _link_target(name, entry.link or "", hard=False)
            if target not in data and not (
                rootfs and _exists(rootfs, "/" + target, regular=False)
            ):
                add(
                    "unresolved-link",
                    "BLOCKED"
                    if rootfs and "postinst" in scripts
                    else "FAIL"
                    if rootfs
                    else "WARN",
                    name,
                    "link target absent; post-install recheck required"
                    if "postinst" in scripts
                    else "link target absent in package/rootfs",
                )
    priority: tuple[Status, ...] = ("FAIL", "BLOCKED", "WARN")
    status: Status = "PASS"
    for candidate in priority:
        if any(f.status == candidate for f in findings):
            status = candidate
            break
    return Inspection(
        wrapper,
        hashlib.sha256(blob).hexdigest(),
        metadata,
        dependencies,
        scripts,
        tuple(e for e, _ in data.values()),
        tuple(elves),
        tuple(findings),
        status,
    )
