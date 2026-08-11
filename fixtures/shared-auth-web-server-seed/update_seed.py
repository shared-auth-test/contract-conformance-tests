#!/usr/bin/env python3
"""Create a deterministic, credential-free exact-source canary archive."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "seed-manifest.json"
REPOSITORY = "shared-auth/shared-auth-web-server.js"
EXCLUDED_PARTS = {
    ".astro",
    ".git",
    ".pytest_cache",
    "__pycache__",
    "dist",
    "env/dec",
    "node_modules",
    "target",
}
SECRET_SHAPES = re.compile(
    rb"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|"
    rb"cfat_[A-Za-z0-9]{20,}|BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def excluded(relative: Path) -> bool:
    value = relative.as_posix()
    return (
        any(value == part or value.startswith(f"{part}/") for part in EXCLUDED_PARTS)
        or any(part in {".pytest_cache", "__pycache__"} for part in relative.parts)
        or relative.suffix in {".pyc", ".pyo"}
    )


def collect(source: Path) -> list[tuple[str, bytes, int]]:
    files: list[tuple[str, bytes, int]] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if excluded(relative):
            continue
        name = relative.name
        dotenv_shaped = name != ".env.example" and (
            name == ".env"
            or name.startswith(".env.")
            or name.endswith(".env")
            or ".env." in name
        )
        if dotenv_shaped and not relative.as_posix().startswith("env/enc/"):
            raise SystemExit(f"plaintext dotenv-shaped path is forbidden: {relative}")
        if path.is_symlink():
            raise SystemExit(f"symlink is forbidden in certified source: {relative}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        if SECRET_SHAPES.search(data):
            raise SystemExit(f"credential-shaped material found in {relative}")
        mode = stat.S_IMODE(path.stat().st_mode) & 0o777
        files.append((relative.as_posix(), data, mode))
    if not files:
        raise SystemExit("source tree is empty")
    return files


def archive(files: list[tuple[str, bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for relative, data, mode in files:
                info = tarfile.TarInfo(relative)
                info.size = len(data)
                info.mode = mode
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def write_parts(payload: bytes, chunk_size: int) -> int:
    if chunk_size <= 0 or chunk_size % 4:
        raise SystemExit("--chunk-size must be a positive multiple of four")
    encoded = base64.b64encode(payload).decode("ascii")
    parts = [encoded[index : index + chunk_size] for index in range(0, len(encoded), chunk_size)]
    for old in ROOT.glob("archive.b64.part*"):
        old.unlink()
    for index, part in enumerate(parts):
        (ROOT / f"archive.b64.part{index:02d}").write_text(part + "\n", encoding="ascii")
    return len(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--chunk-size", type=int, default=12_000)
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.is_dir():
        raise SystemExit(f"source is not a directory: {source}")
    head = git(source, "rev-parse", "HEAD")
    if head != args.commit or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SystemExit(f"source head mismatch: expected {args.commit}, found {head}")
    if git(source, "status", "--porcelain"):
        raise SystemExit("source worktree must be clean before certification")

    files = collect(source)
    payload = archive(files)
    part_count = write_parts(payload, args.chunk_size)
    manifest = {
        "schema": "shared-auth-web-server-seed/v2",
        "repository": REPOSITORY,
        "source_commit": head,
        "source_tree": git(source, "rev-parse", "HEAD^{tree}"),
        "archive_sha256": sha256(payload),
        "archive_parts": part_count,
        "archive_bytes": len(payload),
        "file_count": len(files),
        "uncompressed_bytes": sum(len(data) for _, data, _ in files),
        "excluded_paths": sorted(EXCLUDED_PARTS),
        "source_files": [
            {
                "path": relative,
                "sha256": sha256(data),
                "bytes": len(data),
                "mode": format(mode, "04o"),
            }
            for relative, data, mode in files
        ],
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "source_commit": head,
                "source_tree": manifest["source_tree"],
                "archive_sha256": manifest["archive_sha256"],
                "archive_parts": part_count,
                "file_count": len(files),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
