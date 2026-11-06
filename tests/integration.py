#!/usr/bin/env python3
"""Real-kernel acceptance tests; unavailable protection is BLOCKED, never PASS.

No root, namespaces, credentials or external network service is required.
Use --report to preserve environment, each result, and observed CLI evidence.
"""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import tempfile
import threading
import time


class Suite:
    def __init__(self, args):
        self.args = args
        self.binary = str(Path(args.binary).resolve())
        self.helper = str(Path(args.helper).resolve())
        self.results = []
        self.root = Path(tempfile.mkdtemp(prefix="cincta-tests-"))
        self.counter = 0
        self.mode = "compat"
        self.runtime = []
        seen = set()
        for path in ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64"):
            resolved = str(Path(path).resolve())
            if Path(path).exists() and resolved not in seen:
                self.runtime += ["--rx", resolved]
                seen.add(resolved)

    def test(self, name, function, blocked=None):
        record = {"name": name, "mode": self.mode}
        if blocked:
            record.update(outcome="BLOCKED", reason=blocked)
        else:
            try:
                evidence = function()
                record.update(outcome="PASS", evidence=evidence)
            except Exception as error:  # retain later cases after one failure
                record.update(outcome="FAIL", reason=str(error))
        self.results.append(record)
        print(f"{record['outcome']:7} {self.mode:6} {name}", flush=True)
        if record["outcome"] == "FAIL":
            print(f"        {record['reason']}", flush=True)

    def command(self, command, options=(), helper_grant=True):
        self.counter += 1
        result = self.root / f"result-{self.counter}.json"
        args = [self.binary, "run", *self.runtime]
        if helper_grant:
            args += ["--rx", self.helper]
        if self.mode == "compat":
            args += ["--compat"]
        args += ["--result", str(result), *map(str, options), "--", *map(str, command)]
        return args, result

    def run(self, command, options=(), expected=0, status=None, pass_fds=(), env=None):
        args, result_path = self.command(command, options)
        proc = subprocess.run(args, capture_output=True, text=True, timeout=15,
                              pass_fds=pass_fds, env=env)
        accepted = expected if isinstance(expected, tuple) else (expected,)
        assert proc.returncode in accepted, (
            f"exit={proc.returncode}, expected={expected}, stdout={proc.stdout!r}, stderr={proc.stderr!r}")
        assert result_path.exists(), f"result JSON missing: {proc.stderr}"
        result = json.loads(result_path.read_text())
        assert result["schema_version"] == 1, result
        assert set(result["phase_ms"]) == {"setup", "run", "cleanup"}, result
        assert all(isinstance(value, (int, float)) and value >= 0
                   for value in result["phase_ms"].values()), result
        if status:
            assert result["status"] == status, result
        assert result["cleanup_complete"] is True, result
        if result["status"] != "setup_error":
            protection = result["protections"]
            assert protection["landlock_abi"] >= 3, result
            assert protection["seccomp"] is True, result
            assert isinstance(result["unsupported"], list), result
        return proc, result

    def action(self, operation, *arguments, options=(), expected=0):
        proc, result = self.run([self.helper, operation, *arguments], options, expected)
        observed = json.loads(proc.stdout)
        accepted = expected if isinstance(expected, tuple) else (expected,)
        assert observed["errno"] in accepted, observed
        return {"operation": observed, "result": result}

    @staticmethod
    def stopped(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            return stat[stat.rfind(")") + 2] == "Z"
        except FileNotFoundError:
            return True

    def wait_gone(self, pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            # A Docker PID-1 test driver can adopt the orphan CLI/monitor. Reap
            # those deliberately; a zombie is NOT proof of complete cleanup.
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            if not Path(f"/proc/{pid}").exists():
                return
            time.sleep(0.02)
        raise AssertionError(f"process {pid} survived cleanup (including zombies)")

    @staticmethod
    def read_completed_result(path):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                return json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.01)
        raise AssertionError(f"completed result unavailable: {path}")

    def lifecycle(self, action, preexec_fn=None):
        marker_dir = Path(tempfile.mkdtemp(dir=self.root, prefix="lifecycle-"))
        marker = marker_dir / "pid"
        options = ["--rw", marker_dir]
        if action == "timeout":
            options += ["--timeout-ms", "200"]
        args, result_path = self.command([self.helper, "tree", marker], options)
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                preexec_fn=preexec_fn)
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                assert proc.poll() is None, proc.communicate()
                time.sleep(0.01)
            assert marker.exists(), "workload did not publish descendant PID"
            child_pid = int(marker.read_text())
            if action == "cancel":
                proc.send_signal(signal.SIGTERM)
            elif action == "cli-kill":
                proc.kill()
            elif action == "monitor-kill":
                children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
                assert len(children) == 1, f"expected one monitor, found {children}"
                os.kill(int(children[0]), signal.SIGKILL)
            stdout, stderr = proc.communicate(timeout=8)
            self.wait_gone(child_pid)
            if action == "cli-kill":
                assert proc.returncode == -signal.SIGKILL, (proc.returncode, stderr)
                result = self.read_completed_result(result_path)
                assert result["cleanup_complete"] is True, result
                assert result["status"] == "cancelled", result
                return {"signal": "SIGKILL", "descendant_reaped": True, "result": result}
            if action == "monitor-kill":
                assert proc.returncode == 125, (proc.returncode, stdout, stderr)
                result = self.read_completed_result(result_path)
                assert result["status"] == "setup_error" and result["stage"] == "monitor", result
                assert result["cleanup_complete"] is True, result
                return result
            expected = 124 if action == "timeout" else 128 + signal.SIGTERM
            assert proc.returncode == expected, (proc.returncode, stdout, stderr)
            result = json.loads(result_path.read_text())
            assert result["status"] == ("timeout" if action == "timeout" else "cancelled"), result
            assert result["cleanup_complete"] is True, result
            return result
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            if child_pid and not self.stopped(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    def cases(self):
        area = Path(tempfile.mkdtemp(dir=self.root, prefix=self.mode + "-"))
        allowed = area / "allowed"
        allowed.mkdir()
        secret = area / "secret"
        secret.write_text("private")
        readable = allowed / "readable"
        readable.write_text("permitted")
        nested = allowed / "nested"
        nested.mkdir()
        link = allowed / "escape"
        link.symlink_to(secret)
        self.test("workload.success", lambda: self.run(["/bin/true"], status="ok")[1])
        self.test("workload.nonzero", lambda: self.run(["/bin/sh", "-c", "exit 17"], expected=17, status="exit")[1])
        self.test("workload.stdout-stderr", self.output_test)
        self.test("filesystem.default-deny", lambda: self.action("read", secret, expected=errno.EACCES))
        self.test("filesystem.read-allowed", lambda: self.action("read", readable, options=["--ro", allowed]))
        self.test("filesystem.ro-write-denied", lambda: self.action("write", readable, options=["--ro", allowed], expected=errno.EACCES))
        self.test("filesystem.truncate-denied", lambda: self.action("truncate", readable, options=["--ro", allowed], expected=errno.EACCES))
        self.test("filesystem.create-allowed", lambda: self.action("write", allowed / "created", options=["--rw", allowed]))
        self.test("filesystem.traverse-dotdot-denied", lambda: self.action("read", allowed / ".." / "secret", options=["--ro", allowed], expected=errno.EACCES))
        self.test("filesystem.symlink-escape-denied", lambda: self.action("read", link, options=["--ro", allowed], expected=errno.EACCES))
        self.test("filesystem.cross-tree-link-denied", lambda: self.action("link", secret, allowed / "linked", options=["--rw", allowed], expected=(errno.EACCES, errno.EXDEV)))
        self.test("filesystem.cross-tree-rename-denied", lambda: self.action("rename", secret, allowed / "moved", options=["--rw", allowed], expected=(errno.EACCES, errno.EXDEV)))
        self.test("filesystem.overlap-additive", lambda: self.action("write", nested / "writable", options=["--ro", allowed, "--rw", nested]))
        self.test("filesystem.single-file-grant", lambda: self.action("read", readable, options=["--ro", readable]))
        for operation in ("chmod", "chown", "utime", "xattr"):
            self.test("filesystem.metadata-" + operation, lambda op=operation: self.action(op, readable, options=["--rw", allowed], expected=errno.EPERM))
        self.test("filesystem.grant-missing-fail-closed", lambda: self.run(["/bin/true"], ["--ro", area / "missing"], expected=125, status="setup_error")[1])
        self.test("setup.add-rule-denial-fails-closed", lambda: self.injected_setup_test("deny-add-rule-exec", area, "security"))
        self.test("setup.landlock-denial-fails-closed", lambda: self.injected_setup_test("deny-landlock-exec", area, "capabilities"))
        self.test("setup.seccomp-denial-fails-closed", lambda: self.injected_setup_test("deny-seccomp-exec", area, "capabilities"))
        self.test("filesystem.rw-does-not-grant-execute", lambda: self.exec_permission_test(allowed))
        self.test("fd.inherited-closed", lambda: self.fd_test(secret))
        self.test("seccomp.no-new-privs", lambda: self.action("get-nnp"))
        for operation in ("ptrace", "bpf", "unshare", "setsid", "setpgid", "clone-ns", "clone-parent", "io-uring", "ioctl", "fcntl-setown", "fcntl-async"):
            self.test("seccomp." + operation, lambda op=operation: self.action(op, expected=errno.EPERM))
        self.test("seccomp.clone3-fallback", lambda: self.action("clone3", expected=errno.ENOSYS))
        self.test("seccomp.external-signal-denied", lambda: self.action("kill-external", str(os.getpid()), expected=errno.EPERM))
        if platform.machine() in ("x86_64", "amd64"):
            self.test("seccomp.x32-killed", lambda: self.run([self.helper, "x32"], expected=128 + signal.SIGSYS, status="signal")[1])
            self.test("seccomp.i386-entry-killed", lambda: self.run([self.helper, "i386-entry"], expected=128 + signal.SIGSYS, status="signal")[1])
        for family in ("inet", "inet6", "unix", "netlink"):
            self.test("network.none-" + family, lambda f=family: self.action("socket", f, expected=errno.EPERM))
        self.test("network.none-udp", lambda: self.action("socket", "inet", "udp", expected=errno.EPERM))
        self.test("network.none-socketpair", lambda: self.action("socketpair", expected=errno.EPERM))
        self.test("network.host-explicit", lambda: self.action("socket", "inet", options=["--network", "host"]))
        self.test("network.host-udp", lambda: self.action("socket", "inet", "udp", options=["--network", "host"]))
        self.test("network.host-ipv6", lambda: self.action("socket", "inet6", options=["--network", "host"]))
        self.test("network.host-unix-denied", lambda: self.action("socket", "unix", options=["--network", "host"], expected=errno.EPERM))
        self.test("network.host-netlink-denied", lambda: self.action("socket", "netlink", options=["--network", "host"], expected=errno.EPERM))
        self.test("network.host-socketpair-denied", lambda: self.action("socketpair", options=["--network", "host"], expected=errno.EPERM))
        self.test("environment.clean", self.environment_test)
        self.test("environment.explicit", lambda: self.run(["/bin/sh", "-c", '[ "$TASK_VALUE" = "a=b" ]'], ["--env", "TASK_VALUE=a=b"])[1])
        self.test("workdir.explicit", lambda: self.cwd_test(allowed))
        self.test("limits.nofile", lambda: self.action("limit-fd", "64", options=["--nofile", "64"]))
        self.test("limits.memory", lambda: self.action("allocate", "1024", options=["--memory-mb", "64"], expected=errno.ENOMEM))
        self.test("limits.processes", lambda: self.action("fork", options=["--processes", "1"], expected=errno.EAGAIN),
                  blocked="RLIMIT_NPROC does not apply to UID 0" if os.getuid() == 0 else None)
        self.test("limits.cpu", lambda: self.run([self.helper, "cpu"], ["--cpu-seconds", "1", "--timeout-ms", "5000"], expected=137, status="signal")[1])
        self.test("lifecycle.timeout", lambda: self.lifecycle("timeout"))
        self.test("lifecycle.cancel", lambda: self.lifecycle("cancel"))
        self.test("lifecycle.normal-background-cleanup", lambda: self.background_test(allowed))
        self.test("lifecycle.clone-zero-signal-cleanup", lambda: self.background_test(allowed, "spawn-clone-zero"))
        self.test("lifecycle.inherited-sigchld-ignore", self.ignored_sigchld_test)
        self.test("lifecycle.inherited-signal-mask", lambda: self.lifecycle("cancel", lambda: signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGCHLD})))
        self.test("lifecycle.cli-sigkill-cleanup", lambda: self.lifecycle("cli-kill"))
        self.test("lifecycle.monitor-sigkill-cleanup", lambda: self.lifecycle("monitor-kill"))
        self.test("lifecycle.caller-exit-cleanup", self.caller_exit_test)
        self.test("lifecycle.caller-thread-exit-not-process-exit", self.caller_thread_test)
        self.test("result.exclusive-no-overwrite", self.exclusive_result_test)
        self.test("stdio.missing-output-descriptor", self.closed_stdout_test)
        self.test("exec.not-found", lambda: self.run(["/does/not/exist"], expected=127, status="setup_error")[1])
        self.test("stability.repeated-concurrent", self.concurrent_test)

    def output_test(self):
        proc, result = self.run(["/bin/sh", "-c", "printf business-out; printf business-err >&2"])
        assert proc.stdout == "business-out", proc.stdout
        assert "business-err" in proc.stderr, proc.stderr
        return result

    def injected_setup_test(self, operation, area, expected_stage):
        marker = area / (operation + ".payload-ran")
        command = ["/bin/sh", "-c", 'printf ran > "$1"', "sh", str(marker)]
        args, result_path = self.command(command, ["--rw", area])
        proc = subprocess.run([self.helper, operation, *args], capture_output=True, text=True, timeout=10)
        assert proc.returncode == 125, (operation, proc.returncode, proc.stdout, proc.stderr)
        assert not marker.exists(), "payload executed after restriction installation failed"
        result = self.read_completed_result(result_path)
        assert result["status"] == "setup_error" and result["stage"] == expected_stage, result
        assert result["protections"]["landlock_abi"] == 0 and result["protections"]["seccomp"] is False, result
        assert result["cleanup_complete"] is True, result
        return {"injected_denial": operation, "payload_ran": False, "result": result}

    def fd_test(self, secret):
        fd = os.open(secret, os.O_RDONLY)
        try:
            proc, result = self.run([self.helper, "fd-read", str(fd)], expected=errno.EBADF, pass_fds=(fd,))
            assert json.loads(proc.stdout)["errno"] == errno.EBADF, proc.stdout
            return result
        finally:
            os.close(fd)

    def exec_permission_test(self, allowed):
        program = allowed / "no-exec"
        program.write_bytes(Path(self.helper).read_bytes())
        program.chmod(0o755)
        return self.run([str(program), "get-nnp"], ["--rw", allowed], expected=126, status="setup_error")[1]

    def environment_test(self):
        environment = dict(os.environ, CINCTA_TEST_SECRET="must-not-leak")
        proc, result = self.run(["/usr/bin/env"], env=environment)
        assert "CINCTA_TEST_SECRET" not in proc.stdout, proc.stdout
        assert "PATH=/usr/bin:/bin" in proc.stdout, proc.stdout
        return result

    def cwd_test(self, allowed):
        proc, result = self.run(["/bin/pwd"], ["--cwd", allowed, "--ro", allowed])
        assert Path(proc.stdout.strip()).resolve() == allowed.resolve(), proc.stdout
        return result

    def background_test(self, allowed, operation="spawn"):
        marker = allowed / (operation + "-pid")
        _, result = self.run([self.helper, operation, str(marker)], ["--rw", allowed])
        self.wait_gone(int(marker.read_text()))
        return result

    def ignored_sigchld_test(self):
        args, result_path = self.command(["/bin/true"])
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10,
                              preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        result = self.read_completed_result(result_path)
        assert result["status"] == "ok" and result["cleanup_complete"] is True, result
        return result

    def concurrent_test(self):
        # Build commands sequentially; only independent process execution is parallel.
        commands = [self.command(["/bin/true"]) for _ in range(16)]
        def one(item):
            command, result_path = item
            proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
            assert proc.returncode == 0, (proc.returncode, proc.stderr)
            result = json.loads(result_path.read_text())
            assert result["cleanup_complete"] is True, result
            return result["status"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            statuses = list(executor.map(one, commands))
        assert statuses == ["ok"] * 16, statuses
        return {"runs": 16, "concurrency": 4, "failures": 0}

    def caller_exit_test(self):
        area = Path(tempfile.mkdtemp(dir=self.root, prefix="caller-exit-"))
        marker = area / "child.pid"
        cli_marker = area / "cli.pid"
        args, result_path = self.command([self.helper, "tree", marker], ["--rw", area])
        caller = os.fork()
        if caller == 0:
            with open(area / "output", "w") as log:
                cli = subprocess.Popen(args, stdout=log, stderr=log)
                cli_marker.write_text(str(cli.pid))
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
            os._exit(0 if marker.exists() else 125)
        _, status = os.waitpid(caller, 0)
        assert os.waitstatus_to_exitcode(status) == 0, (area / "output").read_text()
        child_pid = int(marker.read_text())
        cli_pid = int(cli_marker.read_text())
        try:
            result = self.read_completed_result(result_path)
            assert result["status"] == "cancelled", result
            assert result["cleanup_complete"] is True, result
            self.wait_gone(child_pid)
            self.wait_gone(cli_pid)
            return result
        finally:
            for pid in (child_pid, cli_pid):
                if not self.stopped(pid):
                    os.kill(pid, signal.SIGKILL)

    def exclusive_result_test(self):
        args, result_path = self.command(["/bin/true"])
        result_path.write_text("untouched")
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        assert proc.returncode == 125, (proc.returncode, proc.stderr)
        assert result_path.read_text() == "untouched", "existing result was overwritten"
        return {"exit_code": proc.returncode, "existing_result_preserved": True}

    def caller_thread_test(self):
        area = Path(tempfile.mkdtemp(dir=self.root, prefix="caller-thread-"))
        marker = area / "child.pid"
        args, result_path = self.command([self.helper, "tree", marker], ["--rw", area])
        processes = []
        def launch():
            processes.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        thread = threading.Thread(target=launch)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive() and len(processes) == 1, "launcher thread did not finish"
        proc = processes[0]
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                assert proc.poll() is None, proc.communicate()
                time.sleep(0.01)
            assert marker.exists(), "thread-launched workload did not start"
            child_pid = int(marker.read_text())
            time.sleep(0.1)
            assert proc.poll() is None, "caller thread termination cancelled a live caller process"
            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 128 + signal.SIGTERM, (proc.returncode, stdout, stderr)
            result = self.read_completed_result(result_path)
            assert result["cleanup_complete"] is True and result["status"] == "cancelled", result
            self.wait_gone(child_pid)
            return result
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            if child_pid and not self.stopped(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    def closed_stdout_test(self):
        args, result_path = self.command(["/bin/true"])
        # This executes only close(1) in the forked subprocess before exec.
        proc = subprocess.run(args, stderr=subprocess.PIPE, text=True, timeout=10,
                              preexec_fn=lambda: os.close(1))
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        result = json.loads(result_path.read_text())
        assert result["status"] == "ok", result
        return result

    def finish(self, probe):
        report = {
            "schema_version": 1,
            "environment": self.args.environment,
            "kernel": platform.release(), "architecture": platform.machine(),
            "uid": os.getuid(), "probe": probe,
            "evidence_note": "The observed policy is the composition of cincta and outer kernel/container policy. bpf, unshare and privileged operations can already be denied by the outer environment; direct socket and metadata baselines establish effective differential cases.",
            "counts": {state: sum(item["outcome"] == state for item in self.results)
                       for state in ("PASS", "FAIL", "BLOCKED")},
            "results": self.results,
        }
        if self.args.report:
            path = Path(self.args.report)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if report["counts"]["FAIL"]:
            print(f"Retained failure fixtures: {self.root}")
        else:
            shutil.rmtree(self.root)
        # Reap any monitor orphaned by a deliberate CLI SIGKILL when the test
        # runner is container PID 1. No unrelated jobs are created by this suite.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid <= 0:
                    break
            except ChildProcessError:
                break
        print(json.dumps(report["counts"]))
        return 1 if report["counts"]["FAIL"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--helper", default="build/adversary")
    parser.add_argument("--environment", default="native")
    parser.add_argument("--report")
    parser.add_argument("--mode", choices=("both", "strict", "compat"), default="both")
    args = parser.parse_args()
    suite = Suite(args)
    probe_proc = subprocess.run([suite.binary, "probe"], capture_output=True, text=True, timeout=10)
    try:
        probe = json.loads(probe_proc.stdout)
        assert probe["schema_version"] == 1, probe
    except Exception as error:
        suite.test("probe.valid-json", lambda: (_ for _ in ()).throw(AssertionError(f"{error}; {probe_proc.stdout}; {probe_proc.stderr}")))
        return suite.finish({})
    suite.test("probe.valid-json", lambda: probe)
    def baseline(operation, *arguments):
        proc = subprocess.run([suite.helper, operation, *map(str, arguments)], capture_output=True, text=True, timeout=5)
        assert proc.returncode == 0, (operation, proc.returncode, proc.stdout, proc.stderr)
        return json.loads(proc.stdout)
    suite.test("baseline.unconfined-ip-socket", lambda: baseline("socket", "inet"))
    baseline_file = suite.root / "metadata-baseline"
    baseline_file.write_text("baseline")
    suite.test("baseline.unconfined-metadata-write", lambda: baseline("chmod", baseline_file))
    def invalid_arguments(arguments):
        proc = subprocess.run([suite.binary, *arguments], capture_output=True, text=True, timeout=10)
        assert proc.returncode == 125, (arguments, proc.returncode, proc.stderr)
        return {"exit_code": proc.returncode, "diagnostic": proc.stderr}
    for name, arguments in (
        ("missing-command", ["run", "--"]),
        ("relative-grant", ["run", "--ro", "relative", "--", "/bin/true"]),
        ("invalid-network", ["run", "--network", "partial", "--", "/bin/true"]),
        ("invalid-env", ["run", "--env", "1BAD=value", "--", "/bin/true"]),
        ("negative-limit", ["run", "--timeout-ms", "-1", "--", "/bin/true"]),
        ("overflow-limit", ["run", "--memory-mb", "9999999999999999999999", "--", "/bin/true"]),
        ("unknown-option", ["run", "--unknown", "value", "--", "/bin/true"]),
    ):
        suite.test("cli." + name, lambda a=arguments: invalid_arguments(a))
    for mode in ("strict", "compat"):
        if args.mode not in ("both", mode):
            continue
        suite.mode = mode
        supported = probe.get(mode + "_supported", False)
        if not supported:
            suite.test("protection.effective-suite", None,
                       blocked=f"{mode} requirements unavailable: ABI={probe.get('landlock_abi')}, seccomp={probe.get('seccomp')}")
            suite.test("protection.unavailable-fails-closed", lambda: suite.run(["/bin/true"], expected=125, status="setup_error")[1])
        else:
            suite.cases()
    return suite.finish(probe)


if __name__ == "__main__":
    raise SystemExit(main())
