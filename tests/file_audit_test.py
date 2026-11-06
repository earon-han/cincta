#!/usr/bin/env python3
"""Real-kernel acceptance of audited file-open emulation.

Run separately in Linux VM and Docker; no root or credentials needed. Builds a
small static probe so loader opens cannot obscure which operation is tested.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time


PROBE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    pid_t original_pid = getpid();
    int fork_write = !strcmp(argv[1], "fork-write");
    if (fork_write) {
        pid_t child = fork();
        if (child < 0) return 3;
        if (child > 0) {
            int status;
            pid_t got;
            do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
            return got == child && WIFEXITED(status) ? WEXITSTATUS(status) : 4;
        }
    }
    int fd = -1, saved = 0, flags = 0, mode = 0, read_error = 0;
    char bytes[64] = {0};
    if (!strcmp(argv[1], "read")) fd = open(argv[2], O_RDONLY);
    else if (!strcmp(argv[1], "create") || fork_write) fd = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0600);
    else if (!strcmp(argv[1], "umask")) { umask(0077); fd = open(argv[2], O_CREAT | O_WRONLY | O_EXCL, 0666); }
    else if (!strcmp(argv[1], "cloexec")) fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    else if (!strcmp(argv[1], "path")) fd = open(argv[2], O_PATH);
    else if (!strcmp(argv[1], "nofollow")) fd = open(argv[2], O_RDONLY | O_NOFOLLOW);
    else if (!strcmp(argv[1], "openat") || !strcmp(argv[1], "inroot")) {
        int dir = open(argv[2], O_PATH | O_DIRECTORY);
        if (dir < 0) { printf("{\"errno\":%d,\"directory_error\":true}\n", errno); return 0; }
        if (!strcmp(argv[1], "openat")) fd = openat(dir, argv[3], O_RDONLY);
        else {
            struct open_how how = {.flags = O_RDONLY, .resolve = RESOLVE_IN_ROOT};
            fd = (int)syscall(SYS_openat2, dir, argv[3], &how, sizeof(how));
        }
        saved = fd < 0 ? errno : 0; close(dir); errno = saved;
    } else if (!strcmp(argv[1], "small-how")) {
        struct open_how how = {.flags = O_RDONLY};
        fd = (int)syscall(SYS_openat2, AT_FDCWD, argv[2], &how, sizeof(how) - 1);
    } else if (!strcmp(argv[1], "extended-how") || !strcmp(argv[1], "bad-extension")) {
        struct { struct open_how how; unsigned long extra; } h = {{.flags = O_RDONLY}, 0};
        if (!strcmp(argv[1], "bad-extension")) h.extra = 1;
        fd = (int)syscall(SYS_openat2, AT_FDCWD, argv[2], &h, sizeof(h));
    } else if (!strcmp(argv[1], "bad-flags")) {
        struct open_how how = {.flags = 1ULL << 63};
        fd = (int)syscall(SYS_openat2, AT_FDCWD, argv[2], &how, sizeof(how));
    } else if (!strcmp(argv[1], "bad-pointer")) {
        fd = (int)syscall(SYS_openat, AT_FDCWD, (const char *)1, O_RDONLY, 0);
    } else return 2;
    saved = fd < 0 ? errno : 0;
    if (fd >= 0) {
        flags = fcntl(fd, F_GETFD);
        struct stat st;
        if (fstat(fd, &st) == 0) mode = st.st_mode & 0777;
        if (!strcmp(argv[1], "create") || !strcmp(argv[1], "umask") || fork_write) {
            if (write(fd, "created", 7) != 7) read_error = errno;
        } else {
            if (read(fd, bytes, sizeof(bytes) - 1) < 0) read_error = errno;
        }
        close(fd);
    }
    printf("{\"errno\":%d,\"flags\":%d,\"mode\":%d,\"io_errno\":%d,\"content\":\"%s\","
           "\"pid\":%ld,\"original_pid\":%ld}\n",
           saved, flags, mode, read_error, bytes, (long)getpid(), (long)original_pid);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--environment", default="linux")
    parser.add_argument("--report", default="reports/v02-file-audit.json")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--helper", help="prebuilt native static probe for minimal validation VMs")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    records = []
    probe = json.loads(subprocess.check_output([binary, "probe"], text=True))
    with tempfile.TemporaryDirectory(prefix="cincta-file-audit-") as temp:
        area = Path(temp)
        source = area / "probe.c"
        source.write_text(PROBE)
        helper = Path(args.helper).resolve() if args.helper else area / "probe"
        if not args.helper:
            subprocess.run([args.cc, "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-static", str(source), "-o", str(helper)], check=True)
        allowed = area / "allowed"
        allowed.mkdir()
        (allowed / "readable").write_text("permitted")
        secret = area / "secret"
        secret.write_text("private")
        (allowed / "escape").symlink_to(secret)
        runtime = []
        seen = set()
        for path in ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64"):
            if Path(path).exists():
                resolved = str(Path(path).resolve())
                if resolved not in seen:
                    runtime += ["--rx", resolved]
                    seen.add(resolved)

        def run(name, operation, path, *extra, expected=0, options=(), assert_io=None, mode=None):
            audit = area / (name + ".jsonl")
            result = area / (name + ".result.json")
            command = [binary, "run", *runtime, "--rx", str(helper), "--rw", str(allowed),
                       "--audit", str(audit), "--audit-syscalls", "--result", str(result)]
            if not probe.get("strict_supported"):
                command += ["--compat"]
            command += list(map(str, options)) + ["--", str(helper), operation, str(path), *map(str, extra)]
            row = {"name": name}
            try:
                proc = subprocess.run(command, text=True, capture_output=True, timeout=20)
                assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
                observed = json.loads(proc.stdout)
                assert observed["errno"] == expected, observed
                if assert_io is not None:
                    assert observed["io_errno"] == assert_io, observed
                if mode is not None:
                    assert observed["mode"] == mode, observed
                report = json.loads(result.read_text())
                assert report["cleanup_complete"] is True, report
                assert report["audit"]["enabled"] is True and report["audit"]["complete"] is True, report
                assert report["audit"]["delivery_pending"] == 0, report
                events = [json.loads(line) for line in audit.read_text().splitlines()]
                assert events and events[0]["event"] == "start", events[:2]
                assert report["audit"]["native_open_fallbacks"] == sum(
                    event["event"] == "file_open_native_fallback" for event in events), report
                if expected == 0:
                    actual = [e for e in events if e["event"] == "file_open_result" and e["errno"] == 0]
                    deliveries = [e for e in events if e["event"] == "file_open_delivery" and e["errno"] == 0]
                    fallbacks = [e for e in events if e["event"] == "file_open_native_fallback" and e["errno"] == errno.EBADF]
                    assert actual and (deliveries or (operation == "path" and fallbacks)), {
                        "missing": "actual open/delivery or explicit native O_PATH fallback evidence", "events": len(events),
                                                   "tail": [(e["event"], e["errno"]) for e in events[-8:]]}
                    if operation == "cloexec":
                        assert observed["flags"] & 1, observed
                    if operation in ("read", "openat", "inroot", "extended-how"):
                        assert observed["content"] == "permitted", observed
                    if operation == "fork-write":
                        assert observed["pid"] != observed["original_pid"], observed
                        assert Path(path).read_text() == "created", "fork child did not write the file"
                        for kind in ("file_open_snapshot", "file_open_result", "file_open_delivery"):
                            assert any(e["event"] == kind and e["tid"] == observed["pid"] and
                                       e["target"] == str(path) and e["errno"] == 0 for e in events), {
                                "missing": "fork child actual open/delivery audit", "event": kind,
                                "child_pid": observed["pid"]}
                if expected == errno.EACCES and operation in ("read", "create"):
                    assert any(e["event"] == "file_open_result" and e["errno"] == errno.EACCES for e in events), {
                        "missing": "actual kernel denial evidence", "events": len(events),
                        "tail": [(e["event"], e["errno"]) for e in events[-8:]]}
                row.update(outcome="PASS", operation=observed, result=report,
                           event_count=len(events), events=events)
            except Exception as exc:
                row.update(outcome="FAIL", reason=str(exc))
            records.append(row)
            print(row["outcome"], name, row.get("reason", ""), flush=True)

        def killed_worker_is_incomplete():
            """Kill a worker inside open, before ADDFD/result bookkeeping.

            A FIFO without a reader makes the O_CREAT|O_TRUNC writer open
            block deterministically. Counted only around ADDFD, the old code
            incorrectly returned audit.complete=true after this injection.
            """
            name = "killed-file-worker-leaves-audit-incomplete"
            row = {"name": name}
            audit = area / (name + ".jsonl")
            result = area / (name + ".result.json")
            fifo = allowed / "blocked-writer"
            os.mkfifo(fifo, 0o600)
            command = [binary, "run", *runtime, "--rx", str(helper), "--rw", str(allowed),
                       "--audit", str(audit), "--audit-syscalls", "--result", str(result),
                       "--timeout-ms", "10000"]
            if not probe.get("strict_supported"):
                command += ["--compat"]
            command += ["--", str(helper), "create", str(fifo)]
            proc = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                worker = None
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline and proc.poll() is None:
                    # CLI -> monitor -> broker -> file worker. No application
                    # child in this probe forks, so only trusted workers can
                    # occur at this depth. Verify the blocking kernel wait too.
                    level = [proc.pid]
                    for _ in range(3):
                        following = []
                        for parent in level:
                            try:
                                following.extend(map(int, Path(
                                    f"/proc/{parent}/task/{parent}/children").read_text().split()))
                            except FileNotFoundError:
                                pass
                        level = following
                    for candidate in level:
                        try:
                            if "wait_for_partner" in Path(f"/proc/{candidate}/wchan").read_text():
                                worker = candidate
                                break
                        except FileNotFoundError:
                            pass
                    if worker is not None:
                        break
                    time.sleep(0.01)
                assert worker is not None, "file worker did not enter blocking FIFO open"
                before = [json.loads(line) for line in audit.read_text().splitlines()]
                assert any(e["event"] == "file_open_snapshot" and e["target"] == str(fifo)
                           for e in before), "missing copied FIFO request"
                assert not any(e["event"] == "file_open_result" and e["target"] == str(fifo)
                               for e in before), "worker was not interrupted before result logging"
                os.kill(worker, signal.SIGKILL)
                # Trigger ordinary monitor cleanup rather than waiting for
                # the wall timeout. It must retain the killed worker's debt.
                proc.send_signal(signal.SIGTERM)
                stdout, stderr = proc.communicate(timeout=8)
                report = json.loads(result.read_text())
                events = [json.loads(line) for line in audit.read_text().splitlines()]
                assert proc.returncode == 125, (proc.returncode, stdout, stderr, report)
                assert report["cleanup_complete"] is True, report
                assert report["audit"]["complete"] is False, report
                assert report["audit"]["delivery_pending"] > 0, report
                assert not any(e["event"] == "file_open_result" and e["target"] == str(fifo)
                               for e in events), "killed worker invented an actual-open result"
                row.update(outcome="PASS", injected_signal="SIGKILL", worker_pid=worker,
                           result=report, event_count=len(events), events=events)
            except Exception as exc:
                row.update(outcome="FAIL", reason=str(exc))
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.communicate(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate(timeout=3)
            records.append(row)
            print(row["outcome"], name, row.get("reason", ""), flush=True)

        run("read-allowed", "read", allowed / "readable")
        run("read-denied", "read", secret, expected=errno.EACCES)
        run("create-allowed", "create", allowed / "created")
        run("create-denied", "create", area / "forbidden", expected=errno.EACCES)
        run("relative-openat", "openat", allowed, "readable")
        run("openat2-in-root", "inroot", allowed, "/readable")
        run("fd-cloexec-preserved", "cloexec", allowed / "readable")
        run("o-path-remains-non-readable", "path", allowed / "readable", assert_io=errno.EBADF)
        run("symlink-outside-denied", "read", allowed / "escape", expected=errno.EACCES)
        run("symlink-nofollow", "nofollow", allowed / "escape", expected=errno.ELOOP)
        run("creation-umask", "umask", allowed / "masked", mode=0o600)
        run("openat2-small-size", "small-how", allowed / "readable", expected=errno.EINVAL)
        run("openat2-zero-extension", "extended-how", allowed / "readable")
        run("openat2-nonzero-extension", "bad-extension", allowed / "readable", expected=errno.E2BIG)
        run("openat2-invalid-flags", "bad-flags", allowed / "readable", expected=errno.EINVAL)
        run("invalid-pointer", "bad-pointer", allowed / "readable", expected=errno.EFAULT)
        run("procfs-worker-memory-not-injected", "read", "/proc/self/mem", expected=errno.EOPNOTSUPP,
            options=["--ro", "/proc"])
        run("magic-links-not-followed", "read", "/proc/self/fd/0", expected=errno.ELOOP,
            options=["--ro", "/proc"])
        run("fork-child-open-write-audited", "fork-write", allowed / "fork-created", assert_io=0)
        killed_worker_is_incomplete()
        assert secret.read_text() == "private"
        assert not (area / "forbidden").exists()
    counts = {state: sum(row["outcome"] == state for row in records) for state in ("PASS", "FAIL", "BLOCKED")}
    report = {"schema_version": 1, "environment": args.environment, "kernel": platform.release(),
              "architecture": platform.machine(), "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "probe": probe, "counts": counts, "results": records}
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(counts), flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
