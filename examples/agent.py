#!/usr/bin/env python3
"""Linux Agent example with explicit grants and separate business/result data."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="cincta")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--compat", action="store_true")
    args = parser.parse_args()
    workspace = Path(args.workspace).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="cincta-agent-result-") as temp:
        result = Path(temp) / "result.json"
        command = [args.binary, "run", "--cwd", str(workspace), "--rw", str(workspace),
                   "--timeout-ms", "5000", "--result", str(result)]
        if args.compat:
            command += ["--compat"]
        paths = {str(Path(p).resolve()) for p in ("/usr/bin", "/usr/lib", "/usr/lib64", "/lib64")
                 if Path(p).exists()}
        for path in sorted(paths):
            command += ["--rx", path]
        command += ["--", "/bin/sh", "-c", "printf agent-output; printf diagnostic >&2"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=4)
        report = json.loads(result.read_text()) if result.exists() else {"status": "early_error"}
        print(json.dumps({"returncode": process.returncode, "stdout": stdout,
                          "stderr": stderr, "sandbox": report}, indent=2))
        return 0 if report.get("status") == "ok" and report.get("cleanup_complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
