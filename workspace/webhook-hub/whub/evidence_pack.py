"""Frozen, offline-verifiable evidence export bundles."""
from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Any, BinaryIO

CHUNK_SIZE = 64 * 1024
MAGIC = b"WHUBPAK1"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def chunk_hashes(raw: bytes, chunk_size: int = CHUNK_SIZE) -> list[dict]:
    out = []
    offset = 0
    for index in range(0, len(raw), chunk_size):
        part = raw[index:index + chunk_size]
        out.append({"index": len(out), "offset": offset,
                    "length": len(part),
                    "sha256": hashlib.sha256(part).hexdigest()})
        offset += len(part)
    return out


def write_pack(path: str, files: dict[str, bytes]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(MAGIC)
        for name, raw in files.items():
            nb = name.encode("utf-8")
            f.write(struct.pack(">I", len(nb)))
            f.write(nb)
            f.write(struct.pack(">Q", len(raw)))
            f.write(raw)
        f.write(struct.pack(">I", 0))
        f.write(struct.pack(">Q", 0))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_exact(f: BinaryIO, n: int, what: str) -> bytes:
    raw = f.read(n)
    if len(raw) != n:
        raise ValueError(f"truncated pack while reading {what}")
    return raw


def read_pack(path: str) -> dict[str, bytes]:
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("bad pack magic")
        files = {}
        while True:
            nl = struct.unpack(">I", _read_exact(f, 4, "name length"))[0]
            if nl == 0:
                _read_exact(f, 8, "end marker")
                break
            name = _read_exact(f, nl, "file name").decode("utf-8")
            length = struct.unpack(">Q", _read_exact(f, 8, "data length"))[0]
            files[name] = _read_exact(f, length, name)
        if f.read(1):
            raise ValueError("trailing bytes after end marker")
    return files


def damage(path: str, offset: int, seq: int | None, reason: str) -> dict:
    return {"ok": False, "file": os.path.basename(path), "offset": offset,
            "length": 1, "seq": seq, "reason": reason}


def verify_pack_structure(path: str, manifest: dict) -> dict:
    """Verify hashed frames and return first deterministic damage position."""
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            return damage(path, 0, None, "bad magic")
        listed = {x["name"]: x for x in manifest.get("files", [])}
        seen = set()
        while True:
            nl_raw = f.read(4)
            if len(nl_raw) != 4:
                return damage(path, f.tell(), None, "truncated name length")
            nl = struct.unpack(">I", nl_raw)[0]
            if nl == 0:
                marker_off = f.tell()
                if f.read(8) != b"\0" * 8:
                    return damage(path, marker_off, None, "bad end marker")
                break
            name = f.read(nl).decode("utf-8", errors="replace")
            len_raw = f.read(8)
            if len(len_raw) != 8:
                return damage(path, f.tell(), None, "truncated data length")
            length = struct.unpack(">Q", len_raw)[0]
            data_off = f.tell()
            seen.add(name)
            expected = listed.get(name)
            if expected is not None:
                if length != expected.get("length"):
                    return damage(path, data_off, expected.get("first_seq"),
                                  f"declared length mismatch in {name}")
                for ch in expected.get("chunks", []):
                    off = data_off + ch["offset"]
                    f.seek(off)
                    raw = f.read(ch["length"])
                    if hashlib.sha256(raw).hexdigest() != ch["sha256"]:
                        return damage(path, off, ch.get("first_seq"),
                                      f"chunk hash mismatch in {name}")
            f.seek(data_off + length)
        missing = set(listed) - seen
        if missing:
            return damage(path, 0, None, f"missing files: {sorted(missing)}")
        if f.read(1):
            return damage(path, f.tell() - 1, None, "trailing bytes")
    return {"ok": True}
