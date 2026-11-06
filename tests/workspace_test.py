#!/usr/bin/env python3
"""Independent real-filesystem tests for the workspace isolation module.

Compiles only the workspace module plus a thin opaque-pointer C ABI adapter.
Linux VM and Docker should execute this separately from CLI integration tests.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


ADAPTER = r'''
#include "workspace.h"
#include <stdlib.h>
void *ws_new(void) { return calloc(1, sizeof(struct workspace_ctx)); }
int ws_prepare(void *p, const char *source, const char *parent,
               unsigned long long files, unsigned long long bytes,
               char *error, size_t size) {
    return workspace_prepare(source, parent, files, bytes, p, error, size);
}
const char *ws_path(void *p, int which) {
    struct workspace_ctx *ctx = p;
    return which == 0 ? ctx->root : which == 1 ? ctx->tree : ctx->source;
}
int ws_finish(void *p, const char *diff, const char *export, int keep,
              char *error, size_t size) {
    return workspace_finish(p, diff, export, keep != 0, error, size);
}
int ws_discard(void *p, char *error, size_t size) {
    return workspace_discard(p, error, size);
}
unsigned long long ws_count(void *p, int which) {
    struct workspace_ctx *ctx = p;
    return which == 0 ? ctx->copied_files : which == 1 ? ctx->copied_bytes : ctx->changes;
}
void ws_free(void *p) { free(p); }
'''


class Workspace:
    def __init__(self, lib, source, parent, files=0, size=0, expect_failure=False):
        self.lib = lib
        self.ctx = lib.ws_new()
        assert self.ctx, "allocation failed"
        self.error = ctypes.create_string_buffer(1024)
        rc = lib.ws_prepare(self.ctx, os.fsencode(source), os.fsencode(parent),
                            files, size, self.error, len(self.error))
        self.root = Path(os.fsdecode(lib.ws_path(self.ctx, 0)))
        self.tree = Path(os.fsdecode(lib.ws_path(self.ctx, 1)))
        if expect_failure:
            assert rc < 0, "unsafe snapshot unexpectedly prepared"
            if str(self.root) != ".":
                assert not self.root.exists(), f"failed preparation leaked {self.root}"
        else:
            assert rc == 0, self.error.value.decode(errors="replace")

    def finish(self, diff=None, export=None, keep=False, expect_failure=False):
        rc = self.lib.ws_finish(self.ctx, os.fsencode(diff) if diff else None,
                                os.fsencode(export) if export else None,
                                keep, self.error, len(self.error))
        if expect_failure:
            assert rc < 0, "unsafe/conflicting finish unexpectedly succeeded"
            assert self.root.is_dir(), "failed finish did not retain review snapshot"
        else:
            assert rc == 0, self.error.value.decode(errors="replace")
        return self.error.value.decode(errors="replace")

    def close(self):
        if self.ctx:
            rc = self.lib.ws_discard(self.ctx, self.error, len(self.error))
            assert rc == 0, self.error.value.decode(errors="replace")
            self.lib.ws_free(self.ctx)
            self.ctx = None


def configure(lib):
    lib.ws_new.restype = ctypes.c_void_p
    lib.ws_prepare.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_ulonglong, ctypes.c_ulonglong,
                              ctypes.c_void_p, ctypes.c_size_t]
    lib.ws_path.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ws_path.restype = ctypes.c_char_p
    lib.ws_finish.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                             ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    lib.ws_discard.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.ws_count.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ws_count.restype = ctypes.c_ulonglong
    lib.ws_free.argtypes = [ctypes.c_void_p]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--report")
    parser.add_argument("--environment", default="native")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("real Linux filesystem and openat2 are required")
    results = []
    with tempfile.TemporaryDirectory(prefix="cincta-workspace-tests-") as tmp:
        root = Path(tmp)
        adapter = root / "adapter.c"
        adapter.write_text(ADAPTER)
        library = root / "workspace.so"
        command = [args.cc, "-std=c17", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                   "-fPIC", "-shared", "-Iinclude", "src/workspace.c", str(adapter), "-o", str(library)]
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(f"workspace adapter build failed:\n{built.stderr}")
        lib = ctypes.CDLL(str(library))
        configure(lib)
        count = 0

        def case(name, function):
            nonlocal count
            count += 1
            area = root / f"case-{count}"
            area.mkdir()
            source = area / "source"
            source.mkdir()
            parent = area / "scratch"
            parent.mkdir()
            record = {"name": name}
            try:
                evidence = function(area, source, parent)
                record.update(outcome="PASS", evidence=evidence)
            except Exception as error:
                record.update(outcome="FAIL", reason=str(error))
            results.append(record)
            print(f"{record['outcome']:5} {name}", flush=True)
            if record["outcome"] == "FAIL":
                print(record["reason"], flush=True)

        def independent(area, source, parent):
            (source / "a").write_text("original")
            os.link(source / "a", source / "hardlink")
            ws = Workspace(lib, source, parent)
            try:
                assert (ws.root.stat().st_mode & 0o777) == 0o700
                assert (ws.tree / "a").stat().st_ino != (ws.root / "baseline/a").stat().st_ino
                assert (ws.tree / "a").stat().st_ino != (ws.tree / "hardlink").stat().st_ino
                (ws.tree / "a").write_text("modified")
                assert (source / "a").read_text() == "original"
                assert (source / "hardlink").read_text() == "original"
                assert (ws.tree / "hardlink").read_text() == "original"
                ws.finish()
                assert not ws.root.exists()
                return {"source_unchanged": True, "hardlinks_independent": True}
            finally:
                ws.close()

        def diff_export(area, source, parent):
            (source / "modified").write_text("aaaa")
            (source / "deleted").write_text("remove-in-snapshot")
            (source / "unchanged").write_text("stable")
            (source / "目录").mkdir()
            (source / '目录/引号"换行\n').write_text("UTF-8")
            (source / "relative").symlink_to("unchanged")
            ws = Workspace(lib, source, parent)
            try:
                original = (ws.tree / "modified").stat()
                original_root = ws.tree.stat()
                (ws.tree / "modified").write_text("bbbb")
                os.utime(ws.tree / "modified", ns=(original.st_atime_ns, original.st_mtime_ns))
                (ws.tree / "deleted").unlink()
                (ws.tree / "added").write_text("new")
                os.utime(ws.tree, ns=(original_root.st_atime_ns,
                                     original_root.st_mtime_ns + 2000000017))
                diff = area / "diff.json"
                export = area / "export"
                ws.finish(diff, export)
                report = json.loads(diff.read_text())
                changes = {item["path"]: item["status"] for item in report["changes"]}
                assert changes["modified"] == "modified", report
                assert changes["deleted"] == "deleted", report
                assert changes["added"] == "added", report
                assert changes["."] == "modified" and report["count"] == 4, report
                assert "unchanged" not in changes and '目录/引号"换行\n' not in changes
                assert report["exported"] is True
                assert (export / "modified").read_text() == "bbbb"
                assert (export / "relative").is_symlink()
                assert (source / "modified").read_text() == "aaaa"
                assert (source / "deleted").exists()
                assert not ws.root.exists()
                return report
            finally:
                ws.close()

        def root_metadata(area, source, parent, kind):
            source.chmod(0o755)
            os.utime(source, ns=(1700000000123456789, 1700000000123456789))
            initial = source.stat()
            # The root must not consume the one-entry budget, even when there
            # is already one real child and the root appears in the diff.
            if kind == "budget":
                (source / "file").write_text("x")
                os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
            ws = Workspace(lib, source, parent, files=1, size=1)
            try:
                before = ws.tree.stat()
                if kind == "chmod":
                    ws.tree.chmod(0o700)
                elif kind in ("mtime", "budget"):
                    os.utime(ws.tree, ns=(before.st_atime_ns,
                                         before.st_mtime_ns + 11000000003))
                modified = ws.tree.stat()
                diff, export = area / "diff.json", area / "export"
                ws.finish(diff, export)
                report = json.loads(diff.read_text())
                expected = 0 if kind == "unchanged" else 1
                assert report["count"] == expected, report
                assert lib.ws_count(ws.ctx, 2) == expected
                if expected:
                    change, = report["changes"]
                    assert change["path"] == "." and change["status"] == "modified", report
                    assert change["before"]["type"] == change["after"]["type"] == "directory", change
                    assert change["before"]["mode"] == before.st_mode & 0o777
                    assert change["after"]["mode"] == modified.st_mode & 0o777
                else:
                    assert report["changes"] == [], report
                assert export.stat().st_mode & 0o777 == modified.st_mode & 0o777
                assert export.stat().st_mtime_ns == modified.st_mtime_ns
                assert source.stat().st_mode == initial.st_mode
                assert source.stat().st_mtime_ns == initial.st_mtime_ns
                copied = 1 if kind == "budget" else 0
                assert lib.ws_count(ws.ctx, 0) == lib.ws_count(ws.ctx, 1) == copied
                if kind == "budget":
                    assert (export / "file").read_text() == (source / "file").read_text() == "x"
                assert not ws.root.exists()
                return {"operation": kind, "diff": report, "root_mode": modified.st_mode & 0o777,
                        "root_mtime_ns": modified.st_mtime_ns, "copied_files": copied,
                        "copied_bytes": copied, "source_unchanged": True}
            finally:
                ws.close()

        def unchanged(area, source, parent):
            (source / "file").write_text("stable")
            (source / "dir").mkdir()
            (source / "dir/link").symlink_to("../file")
            ws = Workspace(lib, source, parent)
            try:
                diff = area / "diff.json"
                ws.finish(diff, keep=True)
                report = json.loads(diff.read_text())
                assert report["count"] == 0, report
                assert ws.root.exists()
                return report
            finally:
                ws.close()

        def invalid_link(area, source, parent, kind):
            if kind == "absolute":
                (source / "link").symlink_to("/etc/passwd")
            elif kind == "escape":
                (source / "link").symlink_to("../outside")
            elif kind == "dangling":
                (source / "link").symlink_to("not-present")
            elif kind == "loop":
                (source / "one").symlink_to("two")
                (source / "two").symlink_to("one")
            else:
                (area / "secret").write_text("outside")
                (source / "dir").mkdir()
                (source / "d").symlink_to(".")
                (source / "dir/link").symlink_to("../d/../secret")
            ws = Workspace(lib, source, parent, expect_failure=True)
            ws.close()
            assert list(parent.iterdir()) == []
            return {"rejected": kind, "no_snapshot_residue": True}

        def special(area, source, parent):
            os.mkfifo(source / "fifo")
            ws = Workspace(lib, source, parent, expect_failure=True)
            ws.close()
            assert list(parent.iterdir()) == []
            return {"fifo_rejected_without_blocking": True}

        def limits(area, source, parent, kind):
            (source / "one").write_text("123")
            (source / "two").write_text("456")
            ws = Workspace(lib, source, parent, files=1 if kind == "files" else 0,
                           size=2 if kind == "bytes" else 0, expect_failure=True)
            ws.close()
            return {"limit_rejected": kind}

        def output_conflict(area, source, parent, kind):
            (source / "a").write_text("original")
            ws = Workspace(lib, source, parent)
            try:
                target = area / "existing"
                if kind == "diff":
                    target.write_text("do-not-overwrite")
                    ws.finish(diff=target, expect_failure=True)
                    assert target.read_text() == "do-not-overwrite"
                elif kind == "export":
                    target.mkdir()
                    (target / "sentinel").write_text("keep")
                    ws.finish(export=target, expect_failure=True)
                    assert (target / "sentinel").read_text() == "keep"
                else:
                    ws.finish(export=source / "new-export", expect_failure=True)
                    assert not (source / "new-export").exists()
                return {"output_conflict_rejected": kind}
            finally:
                ws.close()

        def payload_symlink(area, source, parent):
            outside = area / "outside"
            outside.write_text("must-not-change")
            ws = Workspace(lib, source, parent)
            try:
                (ws.tree / "escape").symlink_to(outside)
                ws.finish(export=area / "export", expect_failure=True)
                assert not (area / "export").exists()
                ws.close()
                assert outside.read_text() == "must-not-change"
                return {"unsafe_final_link_rejected": True, "cleanup_did_not_follow": True}
            finally:
                ws.close()

        def readonly_cleanup(area, source, parent):
            ws = Workspace(lib, source, parent)
            try:
                (ws.tree / "locked").mkdir()
                (ws.tree / "locked/file").write_text("data")
                (ws.tree / "locked").chmod(0)
                ws.close()
                assert not ws.root.exists()
                return {"mode_000_cleanup": True}
            finally:
                ws.close()

        def private_identity(area, source, parent):
            ws = Workspace(lib, source, parent)
            moved = area / "moved-private-root"
            ws.root.rename(moved)
            ws.root.mkdir()
            (ws.root / "sentinel").write_text("replacement")
            try:
                rc = lib.ws_discard(ws.ctx, ws.error, len(ws.error))
                assert rc < 0, "replacement root accepted"
                assert (ws.root / "sentinel").read_text() == "replacement"
                shutil.rmtree(ws.root)
                moved.rename(ws.root)
                return {"replaced_root_rejected": True}
            finally:
                if moved.exists() and not ws.root.exists():
                    moved.rename(ws.root)
                ws.close()

        case("workspace.independent-copy-and-discard", independent)
        case("workspace.diff-export-immutable-source", diff_export)
        case("workspace.unchanged-and-safe-relative-link", unchanged)
        for kind in ("chmod", "mtime", "unchanged", "budget"):
            case("workspace.root-" + kind, lambda a, s, p, k=kind: root_metadata(a, s, p, k))
        for kind in ("absolute", "escape", "dangling", "loop", "intermediate-dotdot"):
            case("workspace.symlink-" + kind, lambda a, s, p, k=kind: invalid_link(a, s, p, k))
        case("workspace.special-file-rejected", special)
        for kind in ("files", "bytes"):
            case("workspace.limit-" + kind, lambda a, s, p, k=kind: limits(a, s, p, k))
        for kind in ("diff", "export", "source-subtree"):
            case("workspace.output-conflict-" + kind, lambda a, s, p, k=kind: output_conflict(a, s, p, k))
        case("workspace.payload-symlink-revalidated", payload_symlink)
        case("workspace.mode000-discard", readonly_cleanup)
        case("workspace.private-root-identity", private_identity)

    report = {"schema_version": 1, "environment": args.environment,
              "kernel": platform.release(), "architecture": platform.machine(),
              "uid": os.getuid(), "build_command": command,
              "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (Path("src/workspace.c"), Path("include/workspace.h"))},
              "counts": {state: sum(row["outcome"] == state for row in results)
                         for state in ("PASS", "FAIL", "BLOCKED")}, "results": results}
    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report["counts"]))
    return int(report["counts"]["FAIL"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
