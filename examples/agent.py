#!/usr/bin/env python3
"""Linux-only Agent example: private workspace, explicit policy, separate outputs.

The source is never automatically updated. --export chooses a new persistent
review directory; without it, only the printed diff/result is retained.
"""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="cincta")
    parser.add_argument("--workspace", required=True, help="existing source directory")
    parser.add_argument("--compat", action="store_true")
    parser.add_argument("--allow-net", action="append", default=[], metavar="RULE")
    parser.add_argument("--metadata", action="store_true")
    parser.add_argument("--workspace-exec", action="store_true",
                        help="explicitly allow execution of generated files inside the snapshot")
    parser.add_argument("--audit-syscalls", action="store_true")
    parser.add_argument("--export", help="new persistent directory for the final tree")
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()
    if args.timeout_ms < 0:
        parser.error("timeout must be nonnegative")
    workspace = Path(args.workspace).resolve(strict=True)
    if not workspace.is_dir():
        parser.error("workspace must be a directory")
    with tempfile.TemporaryDirectory(prefix="cincta-agent-result-") as temp:
        output = Path(temp)
        result, diff, audit = output / "result.json", output / "diff.json", output / "audit.jsonl"
        command = [args.binary, "run", "--workspace", str(workspace),
                   "--timeout-ms", str(args.timeout_ms), "--result", str(result),
                   "--workspace-diff", str(diff), "--audit", str(audit)]
        if args.compat:
            command += ["--compat"]
        if args.metadata:
            command += ["--metadata"]
        if args.workspace_exec:
            command += ["--workspace-exec"]
        if args.audit_syscalls:
            command += ["--audit-syscalls"]
        if args.export:
            command += ["--workspace-export", str(Path(args.export).resolve())]
        if args.allow_net:
            command += ["--network", "allowlist"]
            for rule in args.allow_net:
                command += ["--allow-net", rule]
        runtime = {str(Path(p).resolve()) for p in
                   ("/usr/bin", "/usr/lib", "/usr/lib64", "/lib64") if Path(p).exists()}
        for path in sorted(runtime):
            command += ["--rx", path]
        command += ["--", "/bin/sh", "-c",
                    "printf agent-output; printf diagnostic >&2; printf sandbox-change > agent-output.txt"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # The CLI owns the business wall timer. This outer bound also
            # allows preparation/cleanup; production callers choose their own.
            outer_timeout = args.timeout_ms / 1000 + 30 if args.timeout_ms else None
            stdout, stderr = process.communicate(timeout=outer_timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
        try:
            report = json.loads(result.read_text())
        except (OSError, ValueError):
            report = {"status": "early_error", "cleanup_complete": False}
        changes = json.loads(diff.read_text()) if diff.exists() else None
        print(json.dumps({"returncode": process.returncode, "stdout": stdout,
                          "stderr": stderr, "sandbox": report, "changes": changes},
                         indent=2, ensure_ascii=False))
        success = report.get("status") == "ok" and report.get("cleanup_complete") is True
        if report.get("audit", {}).get("enabled"):
            success = success and report["audit"].get("complete") is True
        return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
