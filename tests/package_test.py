#!/usr/bin/env python3
"""Exercise the real release packager with Linux ELF and Git/export fixtures."""
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent
VERSION = re.search(r'^#define CINCTA_VERSION "([^"]+)"',
                    (ROOT / "include/cincta.h").read_text(), re.M).group(1)
REVISION = "1" * 40


@unittest.skipUnless(sys.platform.startswith("linux"), "release packaging requires real Linux ELF")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilation = tempfile.TemporaryDirectory(prefix="cincta-package-elf-")
        cls.addClassCleanup(cls.compilation.cleanup)
        directory = Path(cls.compilation.name)
        source = directory / "version.c"
        source.write_text('#include <stdio.h>\n#include "cincta.h"\n'
                          'int main(void) { puts("cincta " CINCTA_VERSION); return 0; }\n')
        cls.binaries = {}
        for name, flags in (("static", ["-static"]), ("dynamic", ["-pie"])):
            binary = directory / name
            subprocess.run(["cc", "-I", str(ROOT / "include"), str(source), *flags, "-o", str(binary)],
                           capture_output=True, text=True, check=True)
            cls.binaries[name] = binary
        wrong_source = directory / "wrong.c"
        wrong_source.write_text('#include <stdio.h>\nint main(void) { puts("cincta 999.0"); return 0; }\n')
        binary = directory / "wrong-version"
        subprocess.run(["cc", "-static", str(wrong_source), "-o", str(binary)],
                       capture_output=True, text=True, check=True)
        cls.binaries["wrong-version"] = binary

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cincta-package-tree-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md", "AGENTS.md",
                     "Makefile", "Dockerfile", ".gitignore", ".dockerignore"):
            shutil.copy2(ROOT / name, self.root / name)
        for name in ("src", "include", "tests", "scripts", "docs", "examples", ".github"):
            shutil.copytree(ROOT / name, self.root / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "._*"))
        (self.root / "reports").mkdir()
        for name in ("README.md", "v02-summary.json"):
            shutil.copy2(ROOT / "reports" / name, self.root / "reports" / name)
        (self.root / "build").mkdir()
        for name, binary in self.binaries.items():
            shutil.copy2(binary, self.root / "build" / name)
        for name in ("实施计划.txt", ".local/development.txt", ".env", "reports/raw-secret.log",
                     "docs/.private/local-note.txt"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("LOCAL_ONLY_FIXTURE\n")
        self.env = {**os.environ, "CINCTA_SOURCE_REVISION": REVISION}
        for name in ("CINCTA_PACKAGE_VERSION", "CINCTA_PACKAGE_ARCH", "CINCTA_BINARY_SOURCE_REVISION",
                     "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(name, None)

    def package(self, binary="static", success=True, **environment):
        result = subprocess.run(["sh", "scripts/package.sh", "build/" + binary], cwd=self.root,
                                env={**self.env, **environment}, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.DEVNULL).decode().strip()

    def init_git(self):
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false",
                 "commit", "-qm", "Public fixture")

    def contents(self):
        archives = list((self.root / "dist").glob("*.tar.gz"))
        self.assertEqual(len(archives), 1)
        archive = archives[0]
        with tarfile.open(archive) as tar:
            return {str(Path(member.name).relative_to(Path(member.name).parts[0])):
                    tar.extractfile(member).read() for member in tar.getmembers() if member.isfile()}

    def test_rejects_dynamic_architecture_and_version_mismatches(self):
        self.assertIn("interpreter", self.package("dynamic", success=False).stderr)
        other = "x86_64" if platform.machine() in ("aarch64", "arm64") else "aarch64"
        self.assertIn("architecture", self.package(success=False, CINCTA_PACKAGE_ARCH=other).stderr)
        self.assertIn("version", self.package("wrong-version", success=False).stderr)
        self.assertIn("version", self.package(success=False, CINCTA_PACKAGE_VERSION="999.0").stderr)

    def test_export_requires_revision_and_checks_declared_binary_revision(self):
        self.env.pop("CINCTA_SOURCE_REVISION")
        self.assertIn("CINCTA_SOURCE_REVISION", self.package(success=False).stderr)
        self.env["CINCTA_SOURCE_REVISION"] = "short"
        self.assertIn("40-character", self.package(success=False).stderr)
        self.env["CINCTA_SOURCE_REVISION"] = REVISION
        self.assertIn("CINCTA_BINARY_SOURCE_REVISION",
                      self.package(success=False, CINCTA_BINARY_SOURCE_REVISION="short").stderr)
        self.package(CINCTA_PACKAGE_VERSION=VERSION)
        contents = self.contents()
        self.assertEqual(contents["SOURCE_REVISION"].decode().strip(), REVISION)
        self.assertEqual(contents["BINARY_SOURCE_REVISION"].decode().strip(), "unknown")
        self.assertIn(b"export-declaration", contents["PACKAGE_INFO"])

    def test_git_requires_clean_staged_unstaged_and_untracked_state(self):
        self.init_git()
        self.package()
        contents = self.contents()
        self.assertEqual(contents["SOURCE_REVISION"].decode().strip(), self.git("rev-parse", "HEAD"))
        self.assertEqual(contents["BINARY_SOURCE_REVISION"].decode().strip(), "unknown")
        readme = self.root / "README.md"
        original = readme.read_bytes()
        readme.write_bytes(original + b"\nUnstaged fixture\n")
        self.assertIn("clean Git", self.package(success=False).stderr)
        self.git("add", "README.md")
        self.assertIn("clean Git", self.package(success=False).stderr)
        self.git("reset", "-q", "HEAD", "README.md")
        readme.write_bytes(original)
        (self.root / "untracked.txt").write_text("fixture")
        self.assertIn("clean Git", self.package(success=False).stderr)

    def test_public_archive_checksums_and_offline_document_links(self):
        self.package()
        contents = self.contents()
        source_manifest = contents["SOURCE_SHA256"].decode()
        for excluded in ("实施计划.txt", ".local", ".env", "raw-secret.log", ".private", "LOCAL_ONLY_FIXTURE"):
            self.assertNotIn(excluded, source_manifest)
            self.assertFalse(any(excluded in name for name in contents), excluded)
        self.assertEqual({name for name in contents if name.startswith("reports/")},
                         {"reports/README.md", "reports/v02-summary.json"})
        self.assertEqual({line.split("  ", 1)[1] for line in source_manifest.splitlines()
                          if line.split("  ", 1)[1].startswith("reports/")},
                         {"reports/README.md", "reports/v02-summary.json"})
        for manifest_name in ("BINARY_SHA256", "SOURCE_SHA256"):
            for line in contents[manifest_name].decode().splitlines():
                digest, name = line.split("  ", 1)
                self.assertIn(name, contents)
                self.assertEqual(hashlib.sha256(contents[name]).hexdigest(), digest, name)
        archive = next((self.root / "dist").glob("*.tar.gz"))
        digest, name = archive.with_name(archive.name + ".sha256").read_text().split()
        self.assertEqual(name, archive.name)
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
        missing = []
        for name, data in contents.items():
            if not name.endswith(".md"):
                continue
            for target in re.findall(r'\]\(([^)\s]+)\)', data.decode()):
                url = urlsplit(target.strip("<>"))
                if url.scheme or url.netloc or not url.path:
                    continue
                relative = os.path.normpath(str(Path(name).parent / unquote(url.path)))
                if relative not in contents:
                    missing.append(f"{name}: {target}")
        self.assertEqual(missing, [], "archive contains broken offline links")


if __name__ == "__main__":
    unittest.main()
