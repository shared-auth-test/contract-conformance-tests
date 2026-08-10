from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "canaries/shared-auth-web-server-seed"
EXPECTED_BLOBS = {
    "archive.b64.part00": "b082a59c841c74022d0faa90cfa3a2492d21d15f",
    "archive.b64.part01": "0c05fa9778308a44ae0d82d195ef41ef2a62451d",
    "archive.b64.part02": "1d4f119bb7941a2e1d1cdf3151edf94c7d8e63b8",
    "archive.b64.part03": "7ec31dec8b3b106b5c9cafb91961651af97188ed",
    "archive.b64.part04": "400e3ee09a1d7d766219886ad68109c6be569d7b",
    "archive.b64.part05": "e32c1ef5b4ff1648095d333361f84363a9ea23d6",
    "archive.b64.part06": "c67da32f91f3a446f59b9e3382d74f05b7cb4771",
    "archive.b64.part07": "87c420c92d2564e7d62630e9a62cae405924e877",
    "archive.b64.part08": "e555adc9d930275ab90be2a1d9fc6861dd95d4c2",
    "materialize.py": "67a5450cfcbae16623e9ba5c42950a6a7581a377",
    "seed-manifest.json": "7844294f2434abab37846f550daaea89a047ff48",
}
CREDENTIAL = re.compile(
    rb"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|"
    rb"BEGIN [A-Z ]*PRIVATE KEY"
)
ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
FORBIDDEN_BINARY_SUFFIXES = {
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".npy",
    ".onnx",
    ".png",
    ".tiff",
    ".webp",
}


def git_blob_sha(path: Path) -> str:
    payload = path.read_bytes()
    return hashlib.sha1(f"blob {len(payload)}\0".encode("ascii") + payload).hexdigest()


def load_archive() -> tuple[dict, bytes]:
    manifest = json.loads((BUNDLE / "seed-manifest.json").read_text(encoding="utf-8"))
    encoded = "".join(
        (BUNDLE / f"archive.b64.part{index:02d}").read_text(encoding="utf-8").strip()
        for index in range(manifest["archive_parts"])
    )
    return manifest, base64.b64decode(encoded, validate=True)


class SharedAuthWebServerSeedCanary(unittest.TestCase):
    def test_bundle_files_are_exact_source_blobs(self) -> None:
        regular_files = {path.name for path in BUNDLE.iterdir() if path.is_file()}
        self.assertEqual(set(EXPECTED_BLOBS), regular_files)
        for relative, expected in EXPECTED_BLOBS.items():
            path = BUNDLE / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(git_blob_sha(path), expected, relative)

    def test_manifest_is_complete_and_normalized(self) -> None:
        manifest, _ = load_archive()
        self.assertEqual(manifest["schema"], "shared-auth/repository-seed/v1")
        self.assertEqual(manifest["repository"], "shared-auth/shared-auth-web-server.js")
        self.assertEqual(manifest["archive_parts"], 9)
        self.assertEqual(manifest["file_count"], 38)
        self.assertEqual(manifest["uncompressed_bytes"], 89521)
        self.assertEqual(manifest["archive_bytes"], 26410)
        self.assertEqual(
            manifest["archive_sha256"],
            "095c5e0c464aae73b85f399614c0ad11be1acfb67fd2a40a4da4ee1da83cc848",
        )
        entries = manifest["source_files"]
        paths = [entry["path"] for entry in entries]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len(paths), manifest["file_count"])
        self.assertEqual(sum(entry["bytes"] for entry in entries), manifest["uncompressed_bytes"])
        for entry in entries:
            path = PurePosixPath(entry["path"])
            self.assertFalse(path.is_absolute(), entry["path"])
            self.assertNotIn("..", path.parts, entry["path"])
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(entry["mode"], {"644", "755"})
            self.assertNotIn(path.suffix.lower(), FORBIDDEN_BINARY_SUFFIXES, entry["path"])
        self.assertEqual(
            sorted(path for path in paths if path.startswith("env/dec/")),
            ["env/dec/README.md"],
        )

    def test_archive_and_every_embedded_file_match_manifest(self) -> None:
        manifest, archive_bytes = load_archive()
        self.assertEqual(len(archive_bytes), manifest["archive_bytes"])
        self.assertEqual(hashlib.sha256(archive_bytes).hexdigest(), manifest["archive_sha256"])
        expected = {entry["path"]: entry for entry in manifest["source_files"]}
        actual: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                self.assertFalse(path.is_absolute(), member.name)
                self.assertNotIn("..", path.parts, member.name)
                self.assertFalse(member.issym() or member.islnk(), member.name)
                self.assertFalse(member.isdev() or member.isfifo(), member.name)
                if member.isdir():
                    continue
                self.assertTrue(member.isfile(), member.name)
                extracted = archive.extractfile(member)
                self.assertIsNotNone(extracted, member.name)
                actual[member.name] = extracted.read()
        self.assertEqual(set(actual), set(expected))
        for relative, payload in actual.items():
            entry = expected[relative]
            self.assertEqual(len(payload), entry["bytes"], relative)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"], relative)
            self.assertIsNone(CREDENTIAL.search(payload), relative)

    def test_security_and_dependency_surfaces_are_present(self) -> None:
        _, archive_bytes = load_archive()
        selected: dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for name in (
                "Cargo.toml",
                ".zpkg.toml",
                ".sops.yaml",
                "justfile",
                "flake.nix",
                "docs/SECURITY_MODEL.md",
                "config/capability-baseline.json",
            ):
                member = archive.getmember(name)
                extracted = archive.extractfile(member)
                self.assertIsNotNone(extracted, name)
                selected[name] = extracted.read().decode("utf-8")
        cargo = selected["Cargo.toml"]
        for dependency in ("axum", "maud", "sea-orm", "leptos", "dioxus"):
            self.assertIn(dependency, cargo)
        zed = selected[".zpkg.toml"]
        self.assertIn("ores-otel/ores-lib-core", zed)
        self.assertIn("oresoftware/next-loggers", zed)
        self.assertIn("ores-otel/ores.otel.log", selected["docs/SECURITY_MODEL.md"])
        self.assertIn("env/enc", selected["justfile"])
        self.assertIn("creation_rules", selected[".sops.yaml"])
        self.assertIn("nixpkgs", selected["flake.nix"])
        capabilities = json.loads(selected["config/capability-baseline.json"])
        serialized = json.dumps(capabilities, sort_keys=True).lower()
        for method in ("openpgp", "kerberos", "ssh", "webauthn"):
            self.assertIn(method, serialized)

    def test_canary_workflow_is_immutable_and_least_privilege(self) -> None:
        workflow = (
            ROOT / ".github/workflows/shared-auth-web-server-seed.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 3)
        actions = [
            line.split("uses:", 1)[1].strip()
            for line in workflow.splitlines()
            if "uses:" in line
        ]
        self.assertGreaterEqual(len(actions), 6)
        self.assertTrue(all(ACTION.fullmatch(action) for action in actions), actions)
        self.assertIn(
            "cachix/install-nix-action@630ae543ea3a38a9a4166f03376c02c50f408342",
            actions,
        )
        self.assertNotRegex(workflow, r"uses:\s+[^\n]+@v[0-9]")


if __name__ == "__main__":
    unittest.main()
