#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent
MANIFEST = ROOT / "seed-manifest.json"

def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def digest(path: pathlib.Path) -> str:
    return digest_bytes(path.read_bytes())

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    parts = sorted(ROOT.glob("archive.b64.part*"))
    if len(parts) != manifest["archive_parts"]:
        raise SystemExit(f"archive part count mismatch: {len(parts)}")
    encoded = "".join(part.read_text().strip() for part in parts)
    archive_bytes = base64.b64decode(encoded, validate=True)
    if digest_bytes(archive_bytes) != manifest["archive_sha256"]:
        raise SystemExit("archive digest mismatch")
    destination = args.destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if destination not in target.parents:
                raise SystemExit(f"unsafe archive path: {member.name}")
        archive.extractall(destination, filter="data")
    expected = {entry["path"]: entry for entry in manifest["source_files"]}
    actual = {
        p.relative_to(destination).as_posix(): p
        for p in destination.rglob("*")
        if p.is_file()
    }
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise SystemExit(f"materialized tree mismatch; missing={missing}, extra={extra}")
    for relative, path in actual.items():
        if digest(path) != expected[relative]["sha256"]:
            raise SystemExit(f"file digest mismatch: {relative}")
    print(f"materialized {len(actual)} files into {destination}")

if __name__ == "__main__":
    main()
