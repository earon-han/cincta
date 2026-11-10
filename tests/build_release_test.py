#!/usr/bin/env python3
"""Portable build/release regressions; no sandbox kernel features required."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class BuildReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cincta-build-release-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def executable(self, path, content):
        path.write_text(content)
        path.chmod(0o755)
        return path

    def fixture(self):
        shutil.copy(ROOT / "Makefile", self.root / "Makefile")
        for directory in ("src", "include", "tests", "scripts"):
            (self.root / directory).mkdir()
        (self.root / "src/main.c").write_text("int main(void) { return 0; }\n")
        (self.root / "include/cincta.h").write_text("/* fixture */\n")
        (self.root / "tests/adversary.c").write_text("int main(void) { return 0; }\n")
        compiler = self.executable(self.root / "compiler", f"#!{sys.executable}\n" + '''
import json,pathlib,sys
with open("invocations.jsonl","a") as stream:
    stream.write(json.dumps(sys.argv[1:])+"\\n")
output=pathlib.Path(sys.argv[sys.argv.index("-o")+1])
output.write_text("fixture artifact\\n")
output.chmod(0o755)
''')
        return compiler

    def make(self, compiler, *args):
        return subprocess.run(["make", f"CC={compiler}", *args], cwd=self.root,
                              capture_output=True, text=True, check=True)

    def calls(self):
        return [json.loads(line) for line in (self.root / "invocations.jsonl").read_text().splitlines()]

    def test_build_settings_and_mode_invalidate_shared_directory(self):
        compiler = self.fixture()
        self.make(compiler, "BUILD=shared")
        initial = len(self.calls())
        self.make(compiler, "BUILD=shared")
        self.assertEqual(len(self.calls()), initial)
        for setting in ("STATIC=1", "CFLAGS=-O0", "CPPFLAGS=-Iinclude -DREGRESSION", "LDFLAGS=-static"):
            self.make(compiler, "BUILD=shared")
            before = len(self.calls())
            self.make(compiler, "BUILD=shared", setting)
            calls = self.calls()[before:]
            self.assertEqual(len(calls), initial, setting)
            self.assertTrue(any("-c" in call for call in calls), setting)
        self.assertTrue(any("-static" in call for call in self.calls()))
        replacement = self.root / "other-compiler"
        shutil.copy(compiler, replacement)
        before = len(self.calls())
        self.make(replacement, "BUILD=shared", "LDFLAGS=-static")
        self.assertEqual(len(self.calls()) - before, initial)

    def test_default_static_and_package_use_separate_directories(self):
        compiler = self.fixture()
        self.make(compiler)
        self.make(compiler, "STATIC=1")
        self.assertTrue((self.root / "build/cincta").exists())
        self.assertTrue((self.root / "build-static/cincta").exists())
        self.executable(self.root / "scripts/package.sh", '#!/bin/sh\nprintf "%s\\n" "$1" > packaged-input\n')
        self.make(compiler, "package")
        self.assertEqual((self.root / "packaged-input").read_text().strip(), "build-release/cincta")
        self.assertIn("STATIC=1", (self.root / "build-release/.build-config").read_text())
        release_calls = [call for call in self.calls() if "build-release/cincta" in call]
        self.assertIn("-static", release_calls[-1])

    @unittest.skipUnless(sys.platform.startswith("linux"), "real ELF validation requires Linux")
    def test_real_elf_switches_between_dynamic_and_static(self):
        self.fixture()
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        self.make(compiler, "BUILD=shared")
        binary = self.root / "shared/cincta"
        before = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
        self.assertIn("INTERP", before)
        self.make(compiler, "BUILD=shared", "STATIC=1")
        after = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
        self.assertNotIn("INTERP", after)
        subprocess.run([str(binary)], check=True)

    def test_failed_suite_cannot_reuse_previous_report(self):
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "workspace-module.json").write_text(json.dumps({"counts": {"PASS": 100, "FAIL": 0, "BLOCKED": 0}}))
        (reports / "unrelated.txt").write_text("preserve me")
        (reports / "independent-artifacts").mkdir()
        (reports / "independent-artifacts/old.txt").write_text("stale")
        binary = self.executable(self.root / "cincta", '#!/bin/sh\necho \'{"strict_supported":true}\'\n')
        self.executable(self.root / "python3", f"#!{sys.executable}\n" + '''
import json,os,pathlib,sys
if len(sys.argv)>1 and sys.argv[1].startswith("tests/"):
    if sys.argv[1]=="tests/workspace_test.py":sys.exit(1)
    path=pathlib.Path(sys.argv[sys.argv.index("--report")+1])
    path.write_text(json.dumps({"counts":{"PASS":1,"FAIL":0,"BLOCKED":0}}))
else:
    os.execv(sys.executable,[sys.executable,*sys.argv[1:]])
''')
        env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
               "CINCTA_BINARY": str(binary), "CINCTA_REPORT_DIR": str(reports)}
        result = subprocess.run(["sh", str(ROOT / "scripts/test_all.sh")], cwd=self.root,
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        summary = json.loads((reports / "summary.json").read_text())
        self.assertEqual(summary["suites"]["workspace-module"]["FAIL"], 1)
        self.assertEqual(summary["suites"]["workspace-module"]["PASS"], 0)
        self.assertEqual((reports / "unrelated.txt").read_text(), "preserve me")
        self.assertFalse((reports / "independent-artifacts/old.txt").exists())

    def test_ci_collects_remaining_evidence_and_cleans_up_after_copy_failure(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("- name: Collect Docker reports\n", 1)[1].split("      - uses:", 1)[0]
        script = "\n".join(line[10:] for line in step.splitlines() if line.startswith("          "))
        self.executable(self.root / "docker", '#!/bin/sh\necho "$1" >> docker-calls\n[ "$1" != cp ]\n')
        env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"]}
        result = subprocess.run(["sh", "-e", "-c", script], cwd=self.root, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "docker-calls").read_text().splitlines(), ["logs", "cp", "inspect", "rm"])


if __name__ == "__main__":
    unittest.main()
