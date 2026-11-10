#!/usr/bin/env python3
"""Real cgroup-v2 CLI acceptance; run from INSIDE a delegated parent subtree.

Default/no-delegation failures are tested everywhere. Positive cases require
--cgroup-parent and keep PASS/FAIL/BLOCKED distinct; no ordinary-directory mock
can stand in for a real controller. This script never creates delegation or
changes host controllers, and requires no Python dependencies.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class Suite:
    def __init__(self, args):
        self.args = args
        self.binary = str(Path(args.binary).resolve())
        self.root = Path(tempfile.mkdtemp(prefix="cincta-resources-"))
        self.work = self.root / "work"
        self.work.mkdir()
        self.rows = []
        self.sequence = 0
        self.runtime = []
        seen = set()
        for p in ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64",
                  str(Path(sys.executable).resolve().parent),
                  str(Path(sys.prefix) / "lib")):
            if Path(p).exists():
                real = str(Path(p).resolve())
                if real not in seen:
                    self.runtime += ["--rx", real]
                    seen.add(real)
        self.probe = json.loads(subprocess.check_output([self.binary, "probe"], text=True))
        self.compat = [] if self.probe.get("strict_supported") else ["--compat"]

    def case(self, name, function, blocked=None):
        row = {"name": name}
        if blocked:
            row.update(outcome="BLOCKED", reason=blocked)
        else:
            try:
                row.update(outcome="PASS", evidence=function())
            except Exception as exc:
                row.update(outcome="FAIL", reason=str(exc))
        self.rows.append(row)
        print(f"{row['outcome']:7} {name}", flush=True)
        if row["outcome"] == "FAIL":
            print("       " + row["reason"], flush=True)

    def command(self, code, options=()):
        self.sequence += 1
        result = self.root / f"result-{self.sequence}.json"
        command = [self.binary, "run", *self.runtime, *self.compat,
                   "--result", str(result), *map(str, options), "--",
                   str(Path(sys.executable).resolve()), "-c", code]
        return command, result

    def run(self, code, options=(), expected=None):
        command, result = self.command(code, options)
        proc = subprocess.run(command, capture_output=True, text=True, timeout=20)
        if expected is not None:
            assert proc.returncode == expected, (proc.returncode, proc.stdout, proc.stderr)
        data = json.loads(result.read_text()) if result.exists() and result.stat().st_size else None
        return proc, data

    def negative(self, options):
        sentinel = self.work / f"must-not-execute-{self.sequence}"
        proc, data = self.run(f"open({str(sentinel)!r}, 'w').write('bad')",
                              ["--rw", self.work, *options], expected=125)
        assert "outputs must have existing trusted parents" not in proc.stderr, "fixture did not reach cgroup validation"
        assert not sentinel.exists(), "payload executed despite unavailable tree protection"
        if data:
            assert data["status"] == "setup_error", data
            assert data["cleanup_complete"] is True, data
        return {"exit_code": proc.returncode, "stderr": proc.stderr, "result": data}

    def positive(self, code, options=(), expected=0):
        before = set(Path(self.args.cgroup_parent).glob("cincta-*"))
        proc, data = self.run(code, ["--cgroup-parent", self.args.cgroup_parent, *options], expected)
        assert data and data["cleanup_complete"] is True, data
        resource = data.get("resources", data.get("resource", data.get("cgroup")))
        assert isinstance(resource, dict) and resource.get("enabled") is True, data
        assert resource.get("removed") is True, resource
        path = resource.get("path")
        if path:
            assert not Path(path).exists(), "private cgroup survived completed run"
        after = set(Path(self.args.cgroup_parent).glob("cincta-*"))
        assert not (after - before), f"new cgroup residue: {after - before}"
        return proc, data, resource

    @staticmethod
    def field(resource, *names):
        for name in names:
            if name in resource:
                return resource[name]
        raise AssertionError(f"resource result missing any of {names}: {resource}")

    def pids(self):
        code = """import errno,json,os,time
children=[]
observed=0
for _ in range(20):
    try:
        pid=os.fork()
    except OSError as exc:
        observed=exc.errno
        break
    if pid==0:
        time.sleep(0.35)
        os._exit(0)
    children.append(pid)
for pid in children:
    os.waitpid(pid,0)
print(json.dumps({'created':len(children),'errno':observed}))
"""
        proc, data, resource = self.positive(code, ["--tree-pids", "4"])
        output = json.loads(proc.stdout)
        assert output == {"created": 3, "errno": errno.EAGAIN}, output
        assert self.field(resource, "pids_limit_hits") >= 1, resource
        return {"workload": output, "result": data}

    def memory(self):
        code = """import os,time
for _ in range(3):
    pid=os.fork()
    if pid==0:
        data=bytearray(48*1024*1024)
        for i in range(0,len(data),4096): data[i]=1
        time.sleep(3)
        os._exit(0)
time.sleep(5)
"""
        proc, data, resource = self.positive(code, ["--tree-memory-mb", "96"], expected=None)
        assert proc.returncode != 0, (proc.returncode, proc.stdout, proc.stderr)
        assert self.field(resource, "memory_oom_kill", "oom_kill") >= 1, resource
        assert self.field(resource, "memory_peak", "memory_peak_bytes") >= 48 * 1024 * 1024, resource
        return data

    def bandwidth(self):
        code = "import time; end=time.monotonic()+0.65\nwhile time.monotonic()<end: pass\n"
        _, data, resource = self.positive(code, ["--tree-cpu-percent", "25"])
        assert self.field(resource, "cpu_nr_throttled", "nr_throttled") >= 1, resource
        assert self.field(resource, "cpu_usage_usec") >= 30000, resource
        return data

    def budget(self):
        code = """import os
for _ in range(2):
    if os.fork()==0:
        while True: pass
while True: pass
"""
        proc, data, resource = self.positive(code,
            ["--tree-cpu-ms", "120", "--tree-cpu-percent", "200", "--timeout-ms", "5000"], expected=None)
        assert proc.returncode != 0, proc.returncode
        assert not data["timed_out"], "wall timeout substituted for aggregate CPU budget"
        assert self.field(resource, "cpu_usage_usec") >= 120000, resource
        return data

    def cancel(self):
        marker = self.work / "running"
        code = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(30)"
        command, result = self.command(code, ["--rw", self.work,
            "--cgroup-parent", self.args.cgroup_parent, "--tree-pids", "8"])
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 8
            while not marker.exists() and time.monotonic() < deadline:
                assert proc.poll() is None, proc.communicate()
                time.sleep(0.02)
            assert marker.exists(), "payload never passed cgroup attach barrier"
            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=8)
            assert proc.returncode == 128 + signal.SIGTERM, (proc.returncode, stdout, stderr)
            data = json.loads(result.read_text())
            assert data["cleanup_complete"] is True and data["cancelled"] is True, data
            resource = data.get("resources", data.get("resource", data.get("cgroup")))
            assert resource and resource["removed"] is True, data
            return data
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)

    def finish(self):
        counts = {name: sum(row["outcome"] == name for row in self.rows)
                  for name in ("PASS", "FAIL", "BLOCKED")}
        report = {"schema_version": 1, "environment": self.args.environment,
                  "kernel": platform.release(), "architecture": platform.machine(),
                  "uid": os.getuid(), "cgroup_parent": self.args.cgroup_parent,
                  "probe": self.probe, "counts": counts, "results": self.rows}
        if self.args.report:
            output = Path(self.args.report)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if counts["FAIL"]:
            print(f"Failure fixtures retained: {self.root}")
        else:
            shutil.rmtree(self.root)
        print(json.dumps(counts))
        return int(counts["FAIL"] > 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--cgroup-parent", help="existing delegated cgroup; launcher must be inside its subtree")
    parser.add_argument("--environment", default="native-resources")
    parser.add_argument("--report")
    args = parser.parse_args()
    suite = Suite(args)
    suite.case("resources.limits-without-parent-fail-closed", lambda: suite.negative(["--tree-pids", "2"]))
    fake = suite.root / "fake-cgroup"
    fake.mkdir()
    for name in ("cgroup.procs", "cgroup.events", "memory.max", "pids.max", "cpu.max"):
        (fake / name).write_text("0\n")
    suite.case("resources.fake-filesystem-rejected", lambda: suite.negative(["--cgroup-parent", fake, "--tree-pids", "2"]))
    if not os.access("/sys/fs/cgroup", os.W_OK):
        suite.case("resources.no-delegation-fail-closed", lambda: suite.negative(["--cgroup-parent", "/sys/fs/cgroup", "--tree-pids", "2"]))
    else:
        suite.case("resources.no-delegation-fail-closed", None,
                   blocked="cgroup root appears writable; this environment is not a no-delegation case")
    if not suite.probe.get("compat_supported"):
        unavailable = "base Landlock/seccomp requirements are unavailable; resource execution cannot be verified"
    else:
        unavailable = None if args.cgroup_parent else "positive cases require a real delegated cgroup parent and migration permissions"
    suite.case("resources.prepare-attach-cleanup", lambda: suite.positive("pass", ["--tree-pids", "8"])[1], blocked=unavailable)
    suite.case("resources.aggregate-pids", suite.pids, blocked=unavailable)
    suite.case("resources.aggregate-memory", suite.memory, blocked=unavailable)
    suite.case("resources.cpu-bandwidth", suite.bandwidth, blocked=unavailable)
    suite.case("resources.aggregate-cpu-budget", suite.budget, blocked=unavailable)
    suite.case("resources.cancel-and-remove", suite.cancel, blocked=unavailable)
    return suite.finish()


if __name__ == "__main__":
    raise SystemExit(main())
