#!/usr/bin/env python3
"""Repeat combined real-kernel workspace, notification, network and audit runs."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        data = b""
        while not data.endswith(b"\n"):
            part = self.request.recv(4096 - len(data))
            if not part or len(data) + len(part) > 4096:
                return
            data += part
        self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--environment", default="native-stress")
    parser.add_argument("--report", default="reports/local-stress.json")
    args = parser.parse_args()
    if args.samples < 1 or args.concurrency < 1:
        parser.error("samples and concurrency must be positive")
    binary = str(Path(args.binary).resolve())
    probe = json.loads(subprocess.check_output([binary, "probe"], text=True))
    mode = [] if probe.get("strict_supported") else ["--compat"]
    runtime = [word for path in sorted({str(Path(p).resolve()) for p in
               ("/usr/bin", "/usr/lib", "/usr/lib64") if Path(p).exists()})
               for word in ("--rx", path)]
    rows = []
    with tempfile.TemporaryDirectory(prefix="cincta-stress-") as temporary, Server(("127.0.0.1", 0), Echo) as server:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        original = b"unchanged source\n"
        (source / "input").write_bytes(original)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]

        def run(index):
            start = time.monotonic_ns()
            area = root / str(index)
            area.mkdir()
            result, audit, diff, export = [area / name for name in ("result.json", "audit.jsonl", "diff.json", "export")]
            token = "run-" + str(index) + "\n"
            script = (
                "import os,socket\n"
                "assert open('input').read()=='unchanged source\\n'\n"
                f"open('output','w').write({token!r})\n"
                "os.chmod('output',0o640)\n"
                "s=socket.socket();s.settimeout(5)\n"
                f"s.connect(('127.0.0.1',{port}));s.sendall({token.encode()!r})\n"
                "data=b''\n"
                f"while len(data)<{len(token.encode())}:\n"
                f" part=s.recv({len(token.encode())}-len(data));assert part;data+=part\n"
                f"assert data=={token.encode()!r}\n"
                "s.close()\n"
            )
            command = [binary, "run", *runtime, *mode, "--timeout-ms", "15000", "--metadata",
                       "--workspace", str(source), "--workspace-diff", str(diff), "--workspace-export", str(export),
                       "--audit", str(audit), "--audit-syscalls", "--result", str(result),
                       "--allow-net", f"tcp:127.0.0.1:{port}", "--", "/usr/bin/python3", "-c", script]
            row = {"index": index}
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=25)
                assert process.returncode == 0, (process.returncode, process.stdout, process.stderr)
                report = json.loads(result.read_text())
                assert report["cleanup_complete"] and report["status"] == "ok", report
                assert report["audit"]["complete"] and report["audit"]["delivery_pending"] == 0, report
                events = [json.loads(line) for line in audit.read_text().splitlines()]
                assert events[0]["event"] == "start" and events[-1]["event"] == "finish"
                assert len(events) == report["audit"]["records"]
                assert (export / "output").read_text() == token
                assert (export / "output").stat().st_mode & 0o777 == 0o640
                assert (export / "input").read_bytes() == original
                assert not Path(report["workspace"]["root"]).exists(), report
                container = Path(report["workspace"]["root"]).parent
                assert container.name.startswith("cincta-preparation-") and not container.exists(), report
                assert (source / "input").read_bytes() == original and sorted(p.name for p in source.iterdir()) == ["input"]
                row.update(outcome="PASS", audit_records=len(events), audit_bytes=audit.stat().st_size,
                           changes=report["workspace"]["changes"], phase_ms=report["phase_ms"])
            except Exception as error:
                row.update(outcome="FAIL", reason=str(error))
                artifacts = Path(args.report).with_suffix("").with_name(Path(args.report).stem + "-failures") / str(index)
                artifacts.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(area, artifacts, dirs_exist_ok=True)
            row["elapsed_ms"] = (time.monotonic_ns() - start) / 1e6
            return row

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            rows = list(executor.map(run, range(args.samples)))
        server.shutdown()
    report = {"schema_version": 1, "environment": args.environment, "architecture": platform.machine(),
              "kernel": platform.release(), "uid": os.getuid(), "probe": probe,
              "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "samples": args.samples, "concurrency": args.concurrency,
              "counts": {state: sum(row["outcome"] == state for row in rows) for state in ("PASS", "FAIL", "BLOCKED")},
              "scope": "Each sample combines copied workspace, actual file open/write/chmod, TCP echo, syscall audit, export and cleanup; original source is checked after every sample.",
              "results": rows}
    target = Path(args.report)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"]))
    return int(report["counts"]["FAIL"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
