#!/usr/bin/env python3
"""Real bind-mount output-boundary tests (fixtures prepared by host admin).

Default runs report BLOCKED rather than create mounts or disable profiles.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--fixtures", default=os.environ.get("CINCTA_ALIAS_FIXTURES"))
    parser.add_argument("--environment", default="native-output-boundaries")
    parser.add_argument("--report", default="reports/output-boundaries.json")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    probe = json.loads(subprocess.check_output([binary, "probe"], text=True))
    mode = [] if probe.get("strict_supported") else ["--compat"]
    runtime = [value for path in ("/usr/bin", "/usr/lib") for value in ("--rx", str(Path(path).resolve()))]
    rows = []
    for kind in ("direct-bind-result", "direct-bind-audit", "nested-bind-result", "workspace-export-source-bind", "workspace-nested-source-bind", "workspace-parent-source-bind",
                 "reverse-subdir-bind-outputs", "workspace-export-source-subdir-bind", "workspace-parent-source-subdir-bind",
                 "workspace-source-subdir-ro-bind", "workspace-source-subdir-rx-bind", "workspace-broad-tmp-ro-bind"):
        row = {"name": kind}
        if not args.fixtures:
            row.update(outcome="BLOCKED", reason="requires explicit host-prepared bind aliases")
        else:
            root = Path(args.fixtures)
            try:
                for path in (root / "out", root / "alias", root / "rw/nested", root / "source", root / "source-alias"):
                    assert path.is_dir(), path
                assert os.path.samefile(root / "out", root / "alias")
                assert os.path.samefile(root / "out", root / "rw/nested")
                assert os.path.samefile(root / "source", root / "source-alias")
                if kind == "reverse-subdir-bind-outputs":
                    assert os.path.samefile(root / "rw/sub", root / "rw-sub-alias")
                if kind in ("workspace-export-source-subdir-bind", "workspace-parent-source-subdir-bind",
                            "workspace-source-subdir-ro-bind", "workspace-source-subdir-rx-bind"):
                    assert os.path.samefile(root / "source/sub", root / "source-sub-alias")
                if kind == "workspace-broad-tmp-ro-bind":
                    relative = Path(os.environ.get("CINCTA_ALIAS_SOURCE_RELATIVE", root.name + "/source"))
                    assert not relative.is_absolute() and ".." not in relative.parts
                    assert os.path.samefile(root / "tmp-alias" / relative, root / "source")
                source_entries = sorted(p.name for p in (root / "source").iterdir())
                source_sub_entries = sorted(p.name for p in (root / "source/sub").iterdir()) if (root / "source/sub").is_dir() else None
                with ExitStack() as temporary:
                    temp = temporary.enter_context(tempfile.TemporaryDirectory(prefix="cincta-output-boundary-"))
                    unique = Path(temp).name
                    private_source = private_parent = None
                    command = [binary, "run", *runtime, *mode]
                    if kind == "direct-bind-result":
                        command += ["--rw", str(root / "alias"), "--result", str(root / "out" / unique)]
                    elif kind == "direct-bind-audit":
                        command += ["--rw", str(root / "alias"), "--audit", str(root / "out" / unique)]
                    elif kind == "nested-bind-result":
                        command += ["--rw", str(root / "rw"), "--result", str(root / "out" / unique)]
                    elif kind == "workspace-export-source-bind":
                        command += ["--workspace", str(root / "source"), "--workspace-export", str(root / "source-alias" / unique)]
                    elif kind == "workspace-nested-source-bind":
                        assert os.path.samefile(root / "out", root / "source-nested" / "nested")
                        command += ["--workspace", str(root / "source-nested"), "--workspace-export", str(root / "out" / unique)]
                    elif kind == "reverse-subdir-bind-outputs":
                        command += ["--rw", str(root / "rw"), "--result", str(root / "rw-sub-alias" / unique)]
                    elif kind == "workspace-export-source-subdir-bind":
                        command += ["--workspace", str(root / "source"), "--workspace-export", str(root / "source-sub-alias" / unique)]
                    elif kind == "workspace-parent-source-subdir-bind":
                        command += ["--workspace", str(root / "source"), "--workspace-parent", str(root / "source-sub-alias")]
                    elif kind in ("workspace-source-subdir-ro-bind", "workspace-source-subdir-rx-bind"):
                        option = "--ro" if kind == "workspace-source-subdir-ro-bind" else "--rx"
                        command += ["--workspace", str(root / "source"), option, str(root / "source-sub-alias")]
                    elif kind == "workspace-broad-tmp-ro-bind":
                        # Keep source off /tmp so the source check cannot hide
                        # a failure to protect the private baseline itself.
                        private_source = Path(temporary.enter_context(tempfile.TemporaryDirectory(
                            prefix="cincta-source-boundary-", dir="/dev/shm")))
                        (private_source / "sentinel").write_text("original")
                        private_parent = Path(temporary.enter_context(tempfile.TemporaryDirectory(
                            prefix="cincta-private-parent-", dir=root / "out")))
                        command += ["--workspace", str(root / "source"), "--ro", str(root / "tmp-alias")]
                    else:
                        command += ["--workspace", str(root / "source"), "--workspace-parent", str(root / "source-alias")]
                    command += ["--", "/bin/sh", "-c", "printf must-not-execute"]
                    commands = [command]
                    if kind == "reverse-subdir-bind-outputs":
                        commands.append([binary, "run", *runtime, *mode, "--rw", str(root / "rw"),
                                         "--audit", str(root / "rw-sub-alias" / (unique + "-audit")),
                                         "--", "/bin/sh", "-c", "printf must-not-execute"])
                    if kind == "workspace-broad-tmp-ro-bind":
                        commands.append([binary, "run", *runtime, *mode, "--workspace", str(private_source),
                                         "--workspace-parent", str(private_parent), "--ro", str(root / "tmp-alias"),
                                         "--", "/bin/sh", "-c", "printf must-not-execute"])
                    attempts = []
                    for command in commands:
                        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                        assert result.returncode == 125, (result.returncode, result.stdout, result.stderr)
                        assert "must-not-execute" not in result.stdout
                        assert any(stage in result.stderr for stage in ("trusted output identity", "cgroup isolation", "workspace layout",
                                                                       "grant overlaps original workspace", "grant exposes private workspace")), result.stderr
                        attempts.append({"returncode": result.returncode, "stderr": result.stderr})
                    assert not (root / "source" / unique).exists(), "export changed original source through bind alias"
                    assert not (root / "out" / unique).exists(), "rejected output created a file through a writable alias"
                    if kind == "reverse-subdir-bind-outputs":
                        assert not (root / "rw/sub" / unique).exists(), "result was created inside a writable subtree"
                        assert not (root / "rw/sub" / (unique + "-audit")).exists(), "audit was created inside a writable subtree"
                    if source_sub_entries is not None:
                        assert source_sub_entries == sorted(p.name for p in (root / "source/sub").iterdir()), "preparation/export modified source subdirectory through bind alias"
                    if private_source is not None:
                        assert (private_source / "sentinel").read_text() == "original"
                        assert sorted(p.name for p in private_source.iterdir()) == ["sentinel"]
                        assert list(private_parent.iterdir()) == [], "private workspace remained after grant rejection"
                    assert source_entries == sorted(p.name for p in (root / "source").iterdir()), "preparation modified source via parent alias"
                    row.update(outcome="PASS", evidence={"attempts": attempts})
                    (root / "out" / unique).unlink(missing_ok=True)
            except Exception as error:
                row.update(outcome="FAIL", reason=str(error))
        rows.append(row)
        print(row["outcome"], kind, row.get("reason", ""), flush=True)
    report = {"schema_version": 1, "environment": args.environment, "kernel": platform.release(),
              "architecture": platform.machine(), "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "counts": {state: sum(r["outcome"] == state for r in rows) for state in ("PASS", "FAIL", "BLOCKED")}, "results": rows}
    path = Path(args.report); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))
    return int(report["counts"]["FAIL"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
