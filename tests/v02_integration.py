#!/usr/bin/env python3
"""Independent v0.2 acceptance: workspace, metadata, audit and failure isolation.

Run on actual Linux VM and default-profile Docker separately. Expectations use
observable filesystem/process effects, not implementation function calls.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time


class Suite:
    def __init__(self, args):
        self.args = args
        self.binary = str(Path(args.binary).resolve())
        self.mode = "compat" if args.compat else "strict"
        self.temp = tempfile.TemporaryDirectory(prefix="cincta-v02-")
        self.root = Path(self.temp.name)
        self.counter = 0
        self.records = []
        self.runtime = []
        for path in sorted({str(Path(p).resolve()) for p in
                            ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64")
                            if Path(p).exists()}):
            self.runtime += ["--rx", path]

    def area(self):
        self.counter += 1
        area = self.root / str(self.counter)
        area.mkdir()
        return area

    def command(self, area, script, options=(), command=None):
        result = area / "result.json"
        args = [self.binary, "run", *self.runtime, "--timeout-ms", "15000",
                "--result", str(result)]
        if self.args.compat:
            args += ["--compat"]
        args += [str(v) for v in options]
        args += ["--", *(command if command is not None else ["/usr/bin/python3", "-c", script])]
        return args, result

    def execute(self, area, script="", options=(), expected=0, status=None,
                command=None, **kwargs):
        args, result_path = self.command(area, script, options, command)
        proc = subprocess.run(args, capture_output=True, text=True, timeout=22, **kwargs)
        accepted = expected if isinstance(expected, tuple) else (expected,)
        assert proc.returncode in accepted, (proc.returncode, proc.stdout, proc.stderr)
        report = json.loads(result_path.read_text()) if result_path.exists() and result_path.stat().st_size else None
        if status:
            assert report and report["status"] == status, (report, proc.stderr)
        if report:
            assert report["schema_version"] == 1 and report["cleanup_complete"] is True, report
            assert {"setup", "run", "cleanup"} == set(report["phase_ms"]), report
            assert all(v >= 0 for v in report["phase_ms"].values()), report
        if expected == 0:
            assert report and report["status"] == "ok", (report, proc.stderr)
            assert report["protections"]["seccomp"] is True
            assert report["protections"]["landlock_abi"] >= 3
        return proc, report

    def test(self, name, fn, blocked=None):
        record = {"name": name, "mode": self.mode}
        if blocked:
            record.update(outcome="BLOCKED", reason=blocked)
        else:
            try:
                record.update(outcome="PASS", evidence=fn())
            except Exception as error:
                record.update(outcome="FAIL", reason=str(error))
        self.records.append(record)
        print(f"{record['outcome']:7} {name}", flush=True)
        if record["outcome"] == "FAIL":
            print(record["reason"], flush=True)

    @staticmethod
    def completed(path):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                return json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.01)
        raise AssertionError(f"completed result unavailable: {path}")

    @staticmethod
    def gone(pid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            if not Path(f"/proc/{pid}").exists():
                return
            time.sleep(0.01)
        raise AssertionError(f"PID {pid} remains, including zombie")

    def workspace_case(self):
        area = self.area()
        source = area / "source"
        source.mkdir()
        (source / "base").write_text("original")
        original = (source / "base").stat()
        diff = area / "changes.json"
        export = area / "export"
        script = "from pathlib import Path; p=Path('base'); assert p.read_text()=='original'; p.write_text('sandbox'); Path('new').write_text('created')"
        _, report = self.execute(area, script, ["--workspace", source,
                                               "--workspace-diff", diff,
                                               "--workspace-export", export])
        assert (source / "base").read_text() == "original"
        assert (source / "base").stat().st_ino == original.st_ino
        assert not (source / "new").exists()
        assert (export / "base").read_text() == "sandbox"
        assert (export / "new").read_text() == "created"
        changes = {row["path"]: row["status"] for row in json.loads(diff.read_text())["changes"]}
        assert changes["base"] == "modified" and changes["new"] == "added", changes
        w = report["workspace"]
        assert w["enabled"] and w["exported"] and not w["retained"], report
        assert not Path(w["root"]).exists(), report
        assert w["copied_files"] == 1 and w["copied_bytes"] == len("original"), report
        return report

    def workspace_keep(self):
        area = self.area()
        source = area / "source"
        source.mkdir()
        _, report = self.execute(area, "from pathlib import Path; Path('retained').write_text('review')",
                                 ["--workspace", source, "--workspace-keep"])
        w = report["workspace"]
        try:
            assert w["retained"] and Path(w["tree"], "retained").read_text() == "review", report
            assert not (source / "retained").exists()
        finally:
            private = Path(w["root"])
            removable = private.parent if private.parent.name.startswith("cincta-preparation-") else private
            shutil.rmtree(removable, ignore_errors=True)
        return report

    def workspace_invalid(self, kind):
        area = self.area()
        source = area / "source"
        source.mkdir()
        (source / "nested").mkdir()
        (source / "nested/file").write_text("source")
        sibling = area / "sibling"
        sibling.mkdir()
        options = ["--workspace", source]
        if kind == "cwd":
            options += ["--cwd", source]
        elif kind == "extra-rw":
            options += ["--rw", sibling]
        elif kind == "source-ro":
            options += ["--ro", source]
        elif kind == "ancestor-ro":
            options += ["--ro", area]
        elif kind == "descendant-rx":
            options += ["--rx", source / "nested/file"]
        elif kind == "intermediate-symlink-grant":
            alias = area / "alias"
            alias.symlink_to(source, target_is_directory=True)
            options += ["--ro", alias / "nested"]
        elif kind == "parent-inside-source":
            options += ["--workspace-parent", source / "nested"]
        else:
            raise AssertionError(kind)
        proc, report = self.execute(area, "raise RuntimeError('must-not-execute')", options, expected=125)
        assert "must-not-execute" not in proc.stderr
        assert (source / "nested/file").read_text() == "source"
        return {"rejected": kind, "stderr": proc.stderr, "result": report}

    def workspace_stdio_alias(self):
        area = self.area()
        source = area / "source"
        source.mkdir()
        original = source / "file"
        original.write_text("unchanged")
        alias = area / "alias"
        os.link(original, alias)
        command, result_path = self.command(area, "print('must-not-run')", ["--workspace", source])
        with alias.open("a") as output:
            proc = subprocess.run(command, stdout=output, stderr=subprocess.PIPE, text=True, timeout=10)
        assert proc.returncode == 125, (proc.returncode, proc.stderr)
        assert original.read_text() == "unchanged"
        return {"stderr": proc.stderr, "result_created": result_path.exists(), "source_unchanged": True}

    def workspace_original_denied(self):
        area = self.area()
        source = area / "source"
        source.mkdir()
        target = source / "original"
        target.write_text("private")
        script = f"import errno\ntry:\n open({str(target)!r}).read()\nexcept OSError as e:\n assert e.errno==errno.EACCES,e\nelse:\n raise AssertionError('original source accessible')"
        return self.execute(area, script, ["--workspace", source])[1]

    def workspace_lifecycle(self, kind):
        area = self.area()
        source = area / "source"
        source.mkdir()
        (source / "base").write_text("original")
        export = area / "export"
        script = (
            "import os,time\n"
            "from pathlib import Path\n"
            "Path('base').write_text('changed')\n"
            "child=os.fork()\n"
            "if child==0:\n time.sleep(60); os._exit(0)\n"
            "Path('pid').write_text(str(child))\n"
            "print(os.getcwd(),flush=True)\n"
            "time.sleep(60)\n")
        args, result_path = self.command(area, script, ["--workspace", source,
                                                       "--workspace-export", export])
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        payload = None
        root = None
        try:
            import select
            assert select.select([proc.stdout], [], [], 8)[0], "workload did not publish cwd"
            cwd = Path(proc.stdout.readline().strip())
            assert cwd.name == "tree" and cwd.parent.name.startswith("cincta-workspace-"), cwd
            root = cwd.parent
            payload = int((cwd / "pid").read_text())
            if kind == "cli-kill":
                proc.kill()
            else:
                children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
                assert len(children) == 1, children
                os.kill(int(children[0]), signal.SIGKILL)
            _, stderr = proc.communicate(timeout=10)
            expected = -signal.SIGKILL if kind == "cli-kill" else 125
            assert proc.returncode == expected, (proc.returncode, stderr)
            report = self.completed(result_path)
            assert report["cleanup_complete"] is True, report
            self.gone(payload)
            assert not root.exists(), report
            assert (source / "base").read_text() == "original"
            assert (export / "base").read_text() == "changed", report
            assert report["workspace"]["exported"] is True, report
            if kind == "monitor-kill":
                assert report["stage"] == "monitor" and report["status"] == "setup_error", report
            else:
                assert report["status"] == "cancelled", report
            return report
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            if payload and Path(f"/proc/{payload}").exists():
                try:
                    os.kill(payload, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if root and root.exists():
                shutil.rmtree(root, ignore_errors=True)

    def metadata(self, kind):
        area = self.area()
        rw = area / "rw"
        rw.mkdir()
        ro = area / "ro"
        ro.mkdir()
        target = rw / "file"
        target.write_text("rw")
        target.chmod(0o644)
        protected = ro / "file"
        protected.write_text("readonly")
        protected.chmod(0o644)
        (rw / "outside-link").symlink_to(protected)
        (rw / "inside-link").symlink_to("file")
        audit = area / "audit.jsonl"
        options = ["--metadata", "--rw", rw, "--ro", ro, "--audit", audit]
        prefix = "import os,errno,stat,json\n"
        path = str(target)
        expected_error = None
        if kind == "chmod":
            action = f"os.chmod({path!r},0o640)"
        elif kind == "fchmod":
            action = f"fd=os.open({path!r},os.O_RDONLY); os.fchmod(fd,0o604); os.close(fd)"
        elif kind == "utimensat":
            action = f"os.utime({path!r},ns=(1234567890000000000,1234567891000000000))"
        elif kind == "xattr":
            action = f"os.setxattr({path!r},'user.cincta',b'data'); assert os.getxattr({path!r},'user.cincta')==b'data'; os.removexattr({path!r},'user.cincta')"
        elif kind == "same-owner":
            action = f"os.chown({path!r},os.geteuid(),os.getegid())"
        elif kind == "suid":
            action = f"os.chmod({path!r},0o4755)"
            expected_error = (errno.EPERM,)
        elif kind == "external-owner":
            action = f"os.chown({path!r},os.geteuid()+1,os.getegid())"
            expected_error = (errno.EPERM,)
        elif kind == "readonly":
            action = f"os.chmod({str(protected)!r},0o600)"
            expected_error = (errno.EACCES, errno.EPERM)
        elif kind in ("outside-link", "inside-link"):
            action = f"os.chmod({str(rw / kind)!r},0o600)"
            expected_error = (errno.EACCES, errno.ELOOP, errno.EPERM)
        elif kind == "dotdot-escape":
            action = f"os.chmod({str(rw / '..' / 'ro' / 'file')!r},0o600)"
            expected_error = (errno.EACCES, errno.EXDEV, errno.EPERM)
        elif kind == "security-xattr":
            action = f"os.setxattr({path!r},'security.cincta',b'data')"
            expected_error = (errno.EPERM,)
        elif kind == "unicode-long-target":
            directory = rw
            for index in range(5):
                directory = directory / ("目录" + str(index) + "x" * 50)
                directory.mkdir()
            target = directory / '引号"换行\n'
            target.write_text("target")
            action = f"os.chmod({str(target)!r},0o640)"
        else:
            raise AssertionError(kind)
        if expected_error:
            script = prefix + "try:\n " + action + "\nexcept OSError as e:\n assert e.errno in " + repr(expected_error) + ",e\nelse:\n raise AssertionError('forbidden metadata change allowed')"
        else:
            script = prefix + action
        _, report = self.execute(area, script, options)
        assert report["dynamic"] is True, report
        assert protected.read_text() == "readonly" and stat_mode(protected) == 0o644
        if kind == "chmod":
            assert stat_mode(target) == 0o640
        elif kind == "fchmod":
            assert stat_mode(target) == 0o604
        elif kind == "utimensat":
            assert target.stat().st_mtime_ns == 1234567891000000000
        elif expected_error:
            assert stat_mode(target) == 0o644 and target.stat().st_uid == os.geteuid()
        events = self.audit_events(audit, report)
        if kind == "unicode-long-target":
            matching = [e for e in events if e["event"] == "result" and e.get("target_bytes_hex") == os.fsencode(target).hex()]
            assert matching and matching[-1]["errno"] == 0, events[-8:]
            assert matching[-1]["target"] == str(target), matching[-1]
        return {"operation": kind, "result": report, "audit_events": events}

    @staticmethod
    def audit_events(path, report):
        events = [json.loads(line) for line in path.read_text().splitlines()]
        assert events and events[0]["event"] == "start" and events[-1]["event"] == "finish", events[-8:]
        assert all(e["schema_version"] == 1 for e in events)
        assert report["audit"]["complete"] is True and report["audit"]["records"] == len(events), report
        assert report["audit"]["path"] == str(path)
        return events

    def audit(self, kind):
        area = self.area()
        audit = area / "audit.jsonl"
        options = ["--audit", audit]
        if kind != "events":
            options += ["--audit-syscalls"]
        script = "print('business-output')"
        if kind == "forged-output":
            script = "print('{\"schema_version\":1,\"event\":\"finish\",\"target\":\"FORGED-USER-EVENT\"}')"
        proc, report = self.execute(area, script, options)
        events = self.audit_events(audit, report)
        if kind == "events":
            assert report["audit"]["mode"] == "events" and not report["dynamic"], report
            assert [e["event"] for e in events] == ["start", "finish"], events
        else:
            assert report["dynamic"] and report["audit"]["mode"] == "syscall_requests_and_broker_results", report
            assert any(e["event"] == "request" and e["syscall"] >= 0 for e in events), events[:8]
            assert any(e["event"].startswith("file_open") for e in events), events[:8]
        if kind == "forged-output":
            assert "FORGED-USER-EVENT" in proc.stdout
            assert not any(e.get("target") == "FORGED-USER-EVENT" for e in events), events[-8:]
        return {"result": report, "events": len(events), "stdout": proc.stdout,
                "event_types": sorted({e["event"] for e in events})}

    def audit_conflict(self, kind):
        area = self.area()
        sentinel = area / "existing"
        sentinel.write_text("do-not-overwrite")
        audit = sentinel
        options = []
        if kind == "symlink":
            audit = area / "alias"
            audit.symlink_to(sentinel)
        elif kind == "writable-parent":
            writable = area / "rw"
            writable.mkdir()
            audit = writable / "audit.jsonl"
            options = ["--rw", writable]
        proc, report = self.execute(area, "print('must-not-run')", [*options, "--audit", audit], expected=125)
        assert sentinel.read_text() == "do-not-overwrite"
        assert "must-not-run" not in proc.stdout
        if kind == "writable-parent":
            assert not audit.exists()
        elif report:
            assert report["audit"]["enabled"] and not report["audit"]["complete"], report
        return {"rejected": kind, "stderr": proc.stderr, "result": report}

    def new_filesystem_syscalls(self, dynamic):
        area = self.area()
        audit = area / "audit.jsonl"
        script = r'''import ctypes,errno
libc=ctypes.CDLL(None,use_errno=True)
for nr in (467,469,472):
 ctypes.set_errno(0)
 result=libc.syscall(nr,-1,ctypes.c_char_p(b""),0,0,0,0)
 assert result==-1 and ctypes.get_errno()==errno.EPERM,(nr,result,ctypes.get_errno())
print('new-filesystem-syscalls-denied')
'''
        options = ["--metadata", "--audit", audit, "--audit-syscalls"] if dynamic else []
        proc, report = self.execute(area, script, options)
        assert "new-filesystem-syscalls-denied" in proc.stdout
        if dynamic:
            events = self.audit_events(audit, report)
            for nr in (467, 469, 472):
                assert any(e.get("syscall") == nr and e.get("errno") == errno.EPERM for e in events), nr
        return {"syscalls": [467, 469, 472], "dynamic": dynamic, "result": report}

    def nested_filter(self):
        area = self.area()
        audit = area / "audit.jsonl"
        script = r'''import ctypes,errno,platform
class Instruction(ctypes.Structure):
 _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
 _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Instruction))]
instructions=(Instruction*1)(Instruction(6,0,0,0x7fff0000))
program=Program(1,instructions)
libc=ctypes.CDLL(None,use_errno=True)
nr={'x86_64':317,'aarch64':277}[platform.machine()]
result=libc.syscall(nr,1,8,ctypes.byref(program))
assert result==-1 and ctypes.get_errno()==errno.EPERM,(result,ctypes.get_errno())
result=libc.prctl(22,2,ctypes.byref(program),0,0)
assert result==-1 and ctypes.get_errno()==errno.EPERM,(result,ctypes.get_errno())
print('nested-listener-denied')
'''
        proc, report = self.execute(area, script, ["--metadata", "--audit", audit])
        assert "nested-listener-denied" in proc.stdout
        self.audit_events(audit, report)
        return report

    def broker_failure(self):
        area = self.area()
        writable = area / "rw"
        writable.mkdir()
        target = writable / "file"
        target.write_text("data")
        audit = area / "audit.jsonl"
        script = f"import os,time\nos.chmod({str(target)!r},0o640)\nprint('ready',flush=True)\ntime.sleep(60)"
        args, result_path = self.command(area, script, ["--metadata", "--rw", writable, "--audit", audit])
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        payload = None
        try:
            import select
            assert select.select([proc.stdout], [], [], 10)[0], "metadata broker not ready"
            assert proc.stdout.readline().strip() == "ready"
            monitors = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
            assert len(monitors) == 1, monitors
            monitor = int(monitors[0])
            children = [int(p) for p in Path(f"/proc/{monitor}/task/{monitor}/children").read_text().split()]
            broker = None
            for pid in children:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[0]
                if os.fsdecode(cmdline) == self.binary:
                    broker = pid
                else:
                    payload = pid
            assert broker and payload, (children, broker, payload)
            os.kill(broker, signal.SIGKILL)
            _, stderr = proc.communicate(timeout=10)
            assert proc.returncode == 125, (proc.returncode, stderr)
            report = self.completed(result_path)
            assert report["status"] == "setup_error" and report["stage"] == "broker", report
            assert report["cleanup_complete"] is True
            self.gone(payload)
            self.gone(broker)
            return report
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)

    def configuration_result(self):
        area = self.area()
        fake = area / "fake-cgroup"
        fake.mkdir()
        audit = area / "audit.jsonl"
        proc, report = self.execute(area, "print('must-not-execute')", ["--cgroup-parent", fake, "--tree-pids", "2", "--audit", audit],
                                    expected=125, status="setup_error")
        assert "must-not-execute" not in proc.stdout
        assert report["protections"]["seccomp"] is False and report["protections"]["landlock_abi"] == 0
        self.audit_events(audit, report)
        audit_only = area / "audit-only.jsonl"
        mode = ["--compat"] if self.args.compat else []
        proc = subprocess.run([self.binary, "run", *self.runtime, *mode, "--audit", str(audit_only),
                               "--cgroup-parent", str(fake), "--tree-pids", "2", "--", "/bin/true"],
                              capture_output=True, text=True, timeout=15)
        assert proc.returncode == 125, (proc.returncode, proc.stderr)
        events = [json.loads(line) for line in audit_only.read_text().splitlines()]
        assert [event["event"] for event in events] == ["start", "finish"], events
        return report

    def missing_dynamic_audit_output(self):
        area = self.area()
        proc, report = self.execute(area, "print('must-not-execute')", ["--audit-syscalls"], expected=125)
        assert "must-not-execute" not in proc.stdout
        return {"stderr": proc.stderr, "result": report}

    def closed_stdio(self, closed):
        area = self.area()
        writable = area / "rw"
        writable.mkdir()
        target = writable / "file"
        target.write_text("safe")
        audit = area / "audit.jsonl"
        script = (
            "import os,stat\n"
            f"for fd in {closed!r}:\n"
            " assert stat.S_ISCHR(os.fstat(fd).st_mode),('trusted descriptor leaked',fd)\n"
            f"os.chmod({str(target)!r},0o640)\n"
            "for fd in (0,1,2):\n"
            " try: os.write(fd,b'FORGED-RESULT-AND-AUDIT\\n')\n"
            " except OSError: pass\n")
        command, result = self.command(area, script, ["--metadata", "--audit", audit, "--rw", writable])

        def close_in_child():
            for fd in closed:
                os.close(fd)

        proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=20, preexec_fn=close_in_child)
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        report = json.loads(result.read_text())
        assert report["status"] == "ok" and report["cleanup_complete"] is True, report
        events = self.audit_events(audit, report)
        assert not any(e.get("target") == "FORGED-RESULT-AND-AUDIT" for e in events)
        assert stat_mode(target) == 0o640
        return {"closed_fds": closed, "result": report, "audit_records": len(events)}

    def audit_limit(self, records=False):
        area = self.area(); audit = area / "audit.jsonl"
        option, limit = ("--audit-max-records", 12) if records else ("--audit-max-bytes", 4096)
        proc, report = self.execute(area, "for i in range(10000): pass",
            ["--audit", audit, "--audit-syscalls", option, limit], expected=125, status="setup_error")
        assert report["audit"]["limit_exceeded"] and not report["audit"]["complete"], report
        lines = audit.read_bytes().splitlines()
        for line in lines: json.loads(line)
        assert (len(lines) <= limit) if records else (audit.stat().st_size <= limit)
        return report

    def closed_stream(self, fd):
        area = self.area(); audit = area / "audit.jsonl"
        _, report = self.execute(area, "import os;os.write(1,b'business-output');os.write(2,b'business-error')",
            ["--audit", audit], preexec_fn=lambda: os.close(fd))
        events = [json.loads(line) for line in audit.read_text().splitlines()]
        assert all(row["event"] in ("start", "finish") for row in events), events
        assert report["audit"]["complete"]
        return report

    def workspace_execute(self, permitted):
        area = self.area(); source = area / "source"; source.mkdir()
        original = source / "program"
        original.write_bytes(Path("/bin/true").read_bytes()); original.chmod(0o755)
        options = ["--workspace", source]
        if permitted: options += ["--workspace-exec"]
        _, report = self.execute(area, options=options, command=["./program"],
            expected=0 if permitted else 126, status="ok" if permitted else "setup_error")
        assert report["workspace"]["executable"] == permitted, report
        assert original.read_bytes() == Path("/bin/true").read_bytes()
        return report

    def workspace_compile(self):
        area = self.area(); source = area / "source"; source.mkdir()
        (source / "hello.c").write_text('#include <stdio.h>\nint main(void){puts("compiled-in-snapshot");return 0;}\n')
        options = ["--workspace", source, "--workspace-exec", "--metadata",
            "--ro", "/usr/include", "--env", "TMPDIR=."]
        if Path("/usr/libexec").exists(): options += ["--rx", "/usr/libexec"]
        proc, report = self.execute(area, options=options,
            command=["/bin/sh", "-c", "cc hello.c -o hello && ./hello"])
        assert "compiled-in-snapshot" in proc.stdout, proc.stdout
        assert not (source / "hello").exists(), "compiler wrote back to original source"
        return report

    def finish(self, probe):
        if self.args.artifacts:
            artifacts = Path(self.args.artifacts)
            artifacts.mkdir(parents=True, exist_ok=True)
            for path in self.root.rglob("*"):
                if path.is_file() and not path.is_symlink() and path.suffix in (".json", ".jsonl"):
                    relative = path.relative_to(self.root)
                    destination = artifacts / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
        report = {"schema_version": 1, "environment": self.args.environment,
                  "mode": self.mode, "kernel": platform.release(), "architecture": platform.machine(),
                  "uid": os.getuid(), "probe": probe,
                  "binary_sha256": hashlib.sha256(Path(self.binary).read_bytes()).hexdigest(),
                  "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                    for folder in ("src", "include")
                                    for p in sorted(Path(folder).glob("*")) if p.is_file()},
                  "counts": {state: sum(row["outcome"] == state for row in self.records)
                             for state in ("PASS", "FAIL", "BLOCKED")}, "results": self.records}
        if self.args.report:
            path = Path(self.args.report)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        while True:
            try:
                child, _ = os.waitpid(-1, os.WNOHANG)
                if child <= 0:
                    break
            except ChildProcessError:
                break
        print(json.dumps(report["counts"]))
        self.temp.cleanup()
        return int(report["counts"]["FAIL"] > 0)


def stat_mode(path):
    return path.stat().st_mode & 0o7777


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--compat", action="store_true")
    parser.add_argument("--report")
    parser.add_argument("--artifacts")
    parser.add_argument("--environment", default="native")
    args = parser.parse_args()
    suite = Suite(args)
    probe = json.loads(subprocess.check_output([suite.binary, "probe"], text=True))
    mode = "compat" if args.compat else "strict"
    if not probe.get(mode + "_supported"):
        suite.test("v02.effective-suite", None, blocked=f"{mode} kernel requirements absent: {probe}")
        return suite.finish(probe)
    suite.test("workspace.cli-isolation-diff-export", suite.workspace_case)
    suite.test("workspace.explicit-keep", suite.workspace_keep)
    for kind in ("cwd", "extra-rw", "source-ro", "ancestor-ro", "descendant-rx",
                 "intermediate-symlink-grant", "parent-inside-source"):
        suite.test("workspace.reject-" + kind, lambda k=kind: suite.workspace_invalid(k))
    suite.test("workspace.writable-stdio-hardlink-denied", suite.workspace_stdio_alias)
    suite.test("workspace.original-source-content-denied", suite.workspace_original_denied)
    suite.test("workspace.cli-kill-cleanup-export", lambda: suite.workspace_lifecycle("cli-kill"))
    suite.test("workspace.monitor-kill-cleanup-export", lambda: suite.workspace_lifecycle("monitor-kill"))
    for kind in ("chmod", "fchmod", "utimensat", "xattr", "same-owner", "suid", "external-owner",
                 "readonly", "outside-link", "inside-link", "dotdot-escape", "security-xattr", "unicode-long-target"):
        suite.test("metadata." + kind, lambda k=kind: suite.metadata(k))
    for kind in ("events", "syscalls", "forged-output"):
        suite.test("audit." + kind, lambda k=kind: suite.audit(k))
    for kind in ("existing", "symlink", "writable-parent"):
        suite.test("audit.reject-" + kind, lambda k=kind: suite.audit_conflict(k))
    suite.test("dynamic.nested-listener-lockdown", suite.nested_filter)
    suite.test("seccomp.new-filesystem-syscalls-static", lambda: suite.new_filesystem_syscalls(False))
    suite.test("seccomp.new-filesystem-syscalls-dynamic", lambda: suite.new_filesystem_syscalls(True))
    suite.test("dynamic.broker-sigkill-fail-closed", suite.broker_failure)
    suite.test("results.configuration-error-json", suite.configuration_result)
    suite.test("audit.requests-require-output", suite.missing_dynamic_audit_output)
    for closed in ((0,), (1,), (2,), (0, 1, 2)):
        suite.test("stdio.closed-" + "-".join(map(str, closed)), lambda c=closed: suite.closed_stdio(c))
    suite.test("audit.byte-budget-fail-closed", lambda: suite.audit_limit(False))
    suite.test("audit.record-budget-fail-closed", lambda: suite.audit_limit(True))
    suite.test("stdio.closed-stdout-keeps-trusted-fds-private", lambda: suite.closed_stream(1))
    suite.test("stdio.closed-stdin-keeps-trusted-fds-private", lambda: suite.closed_stream(0))
    suite.test("workspace.direct-exec-default-denied", lambda: suite.workspace_execute(False))
    suite.test("workspace.direct-exec-explicit", lambda: suite.workspace_execute(True))
    suite.test("workspace.compile-and-run", suite.workspace_compile,
        blocked=None if shutil.which("cc") and Path("/usr/include/stdio.h").exists() else "C compiler/development headers unavailable")
    return suite.finish(probe)


if __name__ == "__main__":
    raise SystemExit(main())
