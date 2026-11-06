#!/usr/bin/env python3
"""Preserve raw direct/sandbox timing samples and failures; no invented stages."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--compat", action="store_true")
    parser.add_argument("--report", default="reports/local-benchmark.json")
    args = parser.parse_args()
    if args.samples < 1 or args.concurrency < 1:
        parser.error("samples and concurrency must be positive")
    binary = Path(args.binary).resolve()
    policy = [str(binary), "run"]
    if args.compat:
        policy += ["--compat"]
    seen = set()
    for path in ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64"):
        resolved = str(Path(path).resolve())
        if Path(path).exists() and resolved not in seen:
            policy += ["--rx", resolved]
            seen.add(resolved)
    policy += ["--", "/bin/true"]
    commands = {"direct": ["/bin/true"], "sandbox": policy}
    samples = {}
    with tempfile.TemporaryDirectory(prefix="cincta-benchmark-") as directory:
        for name, command in commands.items():
            def measure(index):
                result_path = Path(directory) / f"sample-{index}.json"
                invocation = command
                if name == "sandbox":
                    separator = command.index("--")
                    invocation = [*command[:separator], "--result", str(result_path), *command[separator:]]
                start = time.perf_counter_ns()
                result = subprocess.run(invocation, capture_output=True, text=True, timeout=15)
                elapsed = (time.perf_counter_ns() - start) / 1e6
                row = {"index": index, "elapsed_ms": elapsed,
                       "exit_code": result.returncode, "stderr": result.stderr}
                if name == "sandbox" and result_path.exists():
                    sandbox_result = json.loads(result_path.read_text())
                    row["phase_ms"] = sandbox_result.get("phase_ms")
                    row["cleanup_complete"] = sandbox_result.get("cleanup_complete")
                return row
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                samples[name] = list(executor.map(measure, range(args.samples)))
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = os.environ.get("CINCTA_SOURCE_REVISION", "unavailable")
    source_root = Path(__file__).resolve().parent.parent
    fingerprint = hashlib.sha256()
    source_paths = [*source_root.glob("src/*.c"), *source_root.glob("include/*.h"), source_root / "Makefile"]
    for path in sorted(source_paths):
        fingerprint.update(str(path.relative_to(source_root)).encode() + b"\0" + path.read_bytes())
    report = {
        "schema_version": 1, "source_revision": revision,
        "source_fingerprint_sha256": fingerprint.hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "kernel": platform.release(), "architecture": platform.machine(), "uid": os.getuid(),
        "policy": policy, "concurrency": args.concurrency,
        "probe": json.loads(subprocess.check_output([str(binary), "probe"], text=True)),
        "summary": {}, "raw_samples": samples,
        "measurement_boundary": "wall clock around subprocess.run includes spawn/setup/exec/cleanup/result fsync; phase_ms contains monitor's measured setup/run/cleanup (millisecond resolution)",
    }
    for name, rows in samples.items():
        elapsed = sorted(row["elapsed_ms"] for row in rows)
        report["summary"][name] = {
            "samples": len(rows), "failures": sum(row["exit_code"] != 0 for row in rows),
            "median_ms": statistics.median(elapsed),
            "p95_ms": elapsed[min(len(elapsed) - 1, int(len(elapsed) * 0.95))],
            "max_ms": max(elapsed),
        }
        if name == "sandbox":
            phases = [row["phase_ms"] for row in rows if row.get("phase_ms")]
            report["summary"][name]["phase_median_ms"] = {
                stage: statistics.median(phase[stage] for phase in phases)
                for stage in ("setup", "run", "cleanup")
            } if phases else None
    path = Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))
    return int(any(row["exit_code"] for row in samples["sandbox"]))


if __name__ == "__main__":
    raise SystemExit(main())
