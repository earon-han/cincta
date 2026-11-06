#!/usr/bin/env python3
"""Real preparation cancellation tests; never replace guard effects with mocks."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time


HELPER = r'''
#define _GNU_SOURCE
#include "cincta.h"
#include "preparation.h"
#include "resources.h"
#include "workspace.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    struct preparation_guard guard;
    struct workspace_ctx *w;
    struct resource_ctx *r;
    char error[512] = {0};
    if (preparation_start(&w,&r,argv[2],&guard,error,sizeof(error)) < 0) {
        fprintf(stderr,"start: %s\n",error); return 3;
    }
    printf("{\"guardian\":%ld,\"container\":\"%s\"}\n",(long)guard.pid,preparation_workspace_parent(&guard));
    fflush(stdout);
    if (!strcmp(argv[1],"resource-fail")) {
        struct config cfg = {.cgroup_parent=argv[3],.tree_pids=4,.resources=r};
        if (preparation_resources(&guard,&cfg,error,sizeof(error)) == 0) return 4;
        if (preparation_finish(&guard,error,sizeof(error)) < 0) { fprintf(stderr,"finish: %s\n",error); return 5; }
        return 0;
    }
    if (!strcmp(argv[1],"guardian-death")) {
        kill(guard.pid,SIGKILL);
        usleep(10000);
        struct config cfg = {.resources=r};
        if (preparation_resources(&guard,&cfg,error,sizeof(error)) == 0) return 6;
        if (preparation_finish(&guard,error,sizeof(error)) == 0) return 7;
        return 0;
    }
    if (!strcmp(argv[1],"partial")) {
        if (snprintf(w->root,sizeof(w->root),"%s/cincta-workspace-XXXXXX",preparation_workspace_parent(&guard)) >= (int)sizeof(w->root)) return 8;
        if (!mkdtemp(w->root)) return 9;
        char link[4096];
        if (snprintf(link,sizeof(link),"%s/outside",w->root) >= (int)sizeof(link) || symlink(argv[3],link)<0) return 10;
        puts("partial-unprepared-root"); fflush(stdout);
        for (;;) pause();
    }
    if (workspace_prepare(argv[3],preparation_workspace_parent(&guard),0,0,w,error,sizeof(error)) < 0) {
        fprintf(stderr,"workspace: %s\n",error); preparation_finish(&guard,error,sizeof(error)); return 11;
    }
    if (!strcmp(argv[1],"copy-wait")) { puts("copy-finished"); fflush(stdout); for (;;) pause(); }
    if (!strcmp(argv[1],"buffered-handover")) {
        pid_t monitor=fork();
        if (monitor<0) return 22;
        if (monitor==0) {
            close(guard.control_fd);
            for (;;) {
                char bytes[1024]; ssize_t n=read(guard.status_fd,bytes,sizeof(bytes));
                if (n==0) break;
                if (n<0 && errno!=EINTR && errno!=EAGAIN) _exit(23);
                if (n<0 && errno==EAGAIN) { struct pollfd p={.fd=guard.status_fd,.events=POLLIN|POLLHUP}; if (poll(&p,1,-1)<0 && errno!=EINTR) _exit(24); }
            }
            if (!w->prepared || access(w->root,F_OK)<0) _exit(25);
            if (workspace_discard(w,error,sizeof(error))<0 || preparation_cleanup_container(&guard,false,error,sizeof(error))<0) _exit(26);
            puts("buffered-handover-owned-by-monitor"); fflush(stdout); _exit(0);
        }
        if (kill(guard.pid,SIGSTOP)<0) return 27;
        int status;
        if (waitpid(guard.pid,&status,WUNTRACED)!=guard.pid || !WIFSTOPPED(status)) return 28;
        struct { unsigned char operation; pid_t monitor; } command={.operation='D',.monitor=monitor};
        if (write(guard.control_fd,&command,sizeof(command))!=(ssize_t)sizeof(command)) return 29;
        printf("{\"monitor\":%ld}\n",(long)monitor); fflush(stdout);
        _exit(0);
    }
    if (!strcmp(argv[1],"handover-bad")) {
        if (preparation_handover(&guard,0,error,sizeof(error)) == 0) return 12;
        if (workspace_discard(w,error,sizeof(error)) < 0 || preparation_finish(&guard,error,sizeof(error)) < 0) return 13;
        return 0;
    }
    int gate[2];
    if (pipe(gate)<0) return 14;
    pid_t monitor=fork();
    if (monitor<0) return 15;
    int keep=!strcmp(argv[1],"handover-keep");
    if (monitor==0) {
        close(gate[1]); char byte;
        if (read(gate[0],&byte,1)!=1 || byte!='G') _exit(16);
        close(gate[0]);
        if (workspace_finish(w,NULL,NULL,keep,error,sizeof(error))<0 ||
            preparation_cleanup_container(&guard,keep,error,sizeof(error))<0) {
            fprintf(stderr,"monitor: %s\n",error); _exit(17);
        }
        _exit(0);
    }
    close(gate[0]);
    if (preparation_handover(&guard,monitor,error,sizeof(error))<0) return 18;
    if (write(gate[1],"G",1)!=1) return 19;
    close(gate[1]); int status;
    if (waitpid(monitor,&status,0)!=monitor || !WIFEXITED(status) || WEXITSTATUS(status)) return 20;
    printf("{\"root\":\"%s\",\"retained\":%s}\n",w->root,w->retained?"true":"false");
    if (preparation_finish(&guard,error,sizeof(error))<0) { fprintf(stderr,"finish: %s\n",error); return 21; }
    return 0;
}
'''


class Suite:
    def __init__(self, args, root, helper):
        self.args, self.root, self.helper = args, root, helper
        self.rows = []
        self.counter = 0
        self.binary = str(Path(args.binary).resolve())
        self.runtime = []
        for p in sorted({str(Path(p).resolve()) for p in
                         ("/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64") if Path(p).exists()}):
            self.runtime += ["--rx", p]
        self.compat = []
        if not args.module_only:
            probe = json.loads(subprocess.check_output([self.binary, "probe"], text=True))
            self.compat = [] if probe.get("strict_supported") else ["--compat"]

    def case(self, name, function):
        self.counter += 1
        area = self.root / str(self.counter)
        area.mkdir()
        source, scratch = area / "source", area / "scratch"
        source.mkdir(); scratch.mkdir()
        (source / "file").write_text("unchanged-source")
        record = {"name": name}
        try:
            record.update(outcome="PASS", evidence=function(area, source, scratch))
        except Exception as error:
            record.update(outcome="FAIL", reason=str(error))
        self.rows.append(record)
        print(f"{record['outcome']:5} {name}", flush=True)
        if record["outcome"] == "FAIL":
            print(record["reason"], flush=True)

    @staticmethod
    def wait_gone(pid):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            if not Path(f"/proc/{pid}").exists():
                return
            time.sleep(0.01)
        raise AssertionError(f"guardian {pid} remains, including zombie")

    def helper_normal(self, area, source, scratch, mode):
        proc = subprocess.run([str(self.helper), mode, str(scratch), str(source)],
                              capture_output=True, text=True, timeout=12)
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        rows = [json.loads(line) for line in proc.stdout.splitlines()]
        self.wait_gone(rows[0]["guardian"])
        container = Path(rows[0]["container"])
        if mode == "handover-keep":
            assert container.is_dir() and rows[-1]["retained"] is True, rows
            assert Path(rows[-1]["root"], "tree/file").read_text() == "unchanged-source"
            shutil.rmtree(container)
        else:
            assert not container.exists(), (mode, rows)
        assert list(scratch.iterdir()) == [], (mode, list(scratch.iterdir()))
        assert (source / "file").read_text() == "unchanged-source"
        return {"mode": mode, "protocol": rows, "guardian_reaped": True}

    def partial_cancel(self, area, source, scratch):
        outside = area / "outside"
        outside.write_text("external-file-unchanged")
        foreign = scratch / "foreign-0700"
        foreign.mkdir(mode=0o700)
        (foreign / "sentinel").write_text("preserve")
        proc = subprocess.Popen([str(self.helper), "partial", str(scratch), str(outside)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        guardian = None
        try:
            import select
            assert select.select([proc.stdout], [], [], 8)[0], "guardian did not report READY"
            ready = json.loads(proc.stdout.readline())
            guardian = ready["guardian"]
            assert proc.stdout.readline().strip() == "partial-unprepared-root"
            container = Path(ready["container"])
            assert container.is_dir()
            proc.kill()
            _, stderr = proc.communicate(timeout=10)
            assert proc.returncode == -signal.SIGKILL, stderr
            self.wait_gone(guardian)
            assert not container.exists(), stderr
            assert outside.read_text() == "external-file-unchanged"
            assert (foreign / "sentinel").read_text() == "preserve"
            assert list(scratch.iterdir()) == [foreign]
            return {"unprepared_root_removed": True, "external_symlink_not_followed": True,
                    "foreign_directory_preserved": True, "guardian_reaped": True}
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate(timeout=8)

    def buffered_handover(self, area, source, scratch):
        proc = subprocess.Popen([str(self.helper), "buffered-handover", str(scratch), str(source)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        guardian = monitor = None
        try:
            ready = json.loads(proc.stdout.readline())
            guardian = ready["guardian"]
            monitor = json.loads(proc.stdout.readline())["monitor"]
            assert proc.wait(timeout=8) == 0
            os.kill(guardian, signal.SIGCONT)
            stdout, stderr = proc.communicate(timeout=10)
            assert "buffered-handover-owned-by-monitor" in stdout, (stdout, stderr)
            self.wait_gone(guardian)
            self.wait_gone(monitor)
            assert not Path(ready["container"]).exists()
            assert list(scratch.iterdir()) == []
            assert (source / "file").read_text() == "unchanged-source"
            return {"parent_died_with_D_buffered": True, "monitor_retained_cleanup_ownership": True,
                    "guardian_and_monitor_reaped": True}
        finally:
            if guardian and Path(f"/proc/{guardian}").exists():
                try:
                    os.kill(guardian, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            if proc.poll() is None:
                proc.kill(); proc.communicate(timeout=8)

    def large_copy_cancel(self, area, source, scratch, cli):
        large = source / "large"
        size = 512 * 1024 * 1024
        with large.open("wb") as stream:
            stream.truncate(size)
            stream.seek(0); stream.write(b"SOURCE-BEGIN")
            stream.seek(size - 10); stream.write(b"SOURCE-END")
        if cli:
            command = [self.binary, "run", *self.runtime, *self.compat,
                       "--workspace", str(source), "--workspace-parent", str(scratch),
                       "--", "/bin/true"]
        else:
            command = [str(self.helper), "copy-wait", str(scratch), str(source)]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        guardian = None
        try:
            deadline = time.monotonic() + 10
            observed = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError(f"copy ended before cancellation: {proc.communicate()}")
                for container in scratch.glob("cincta-preparation-*"):
                    for root in container.glob("cincta-workspace-*"):
                        for phase in ("baseline", "tree"):
                            copying = root / phase / "large"
                            try:
                                copied = copying.stat().st_size
                            except FileNotFoundError:
                                continue
                            if 0 < copied < size:
                                observed = {"container": str(container), "phase": phase,
                                            "copied_bytes_at_kill": copied, "source_bytes": size}
                                break
                        if observed:
                            break
                    if observed:
                        break
                if observed:
                    children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
                    assert len(children) == 1, ("expected preparation guardian only", children)
                    guardian = int(children[0])
                    proc.kill()
                    break
                time.sleep(0.0005)
            assert observed, "did not observe an actual partial file copy"
            _, stderr = proc.communicate(timeout=12)
            assert proc.returncode == -signal.SIGKILL, (proc.returncode, stderr)
            self.wait_gone(guardian)
            assert not Path(observed["container"]).exists(), (observed, stderr)
            assert list(scratch.iterdir()) == []
            assert large.stat().st_size == size
            with large.open("rb") as stream:
                assert stream.read(12) == b"SOURCE-BEGIN"
                stream.seek(size - 10); assert stream.read() == b"SOURCE-END"
            assert (source / "file").read_text() == "unchanged-source"
            return observed
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate(timeout=12)

    def cli_preparation_error(self, area, source, scratch):
        os.mkfifo(source / "fifo")
        proc = subprocess.run([self.binary, "run", *self.runtime, *self.compat,
                               "--workspace", str(source), "--workspace-parent", str(scratch),
                               "--", "/bin/true"], capture_output=True, text=True, timeout=12)
        assert proc.returncode == 125, (proc.returncode, proc.stdout, proc.stderr)
        assert list(scratch.iterdir()) == [], (list(scratch.iterdir()), proc.stderr)
        return {"exit_code": proc.returncode, "stderr": proc.stderr, "no_private_directory_residue": True}

    def cli_keep(self, area, source, scratch):
        result = area / "result.json"
        proc = subprocess.run([self.binary, "run", *self.runtime, *self.compat,
                               "--workspace", str(source), "--workspace-parent", str(scratch),
                               "--workspace-keep", "--result", str(result), "--", "/bin/true"],
                              capture_output=True, text=True, timeout=12)
        assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
        report = json.loads(result.read_text())
        assert report["cleanup_complete"] is True and report["workspace"]["retained"] is True, report
        root = Path(report["workspace"]["root"])
        assert root.parent in list(scratch.iterdir()) and (root / "tree/file").read_text() == "unchanged-source"
        shutil.rmtree(root.parent)
        assert list(scratch.iterdir()) == []
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--binary", default="build/cincta")
    parser.add_argument("--module-only", action="store_true")
    parser.add_argument("--report")
    parser.add_argument("--environment", default="native")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("actual Linux pidfd and procfs are required")
    with tempfile.TemporaryDirectory(prefix="cincta-preparation-tests-") as temp:
        root = Path(temp)
        adapter = root / "adapter.c"
        adapter.write_text(HELPER)
        helper = root / "helper"
        command = [args.cc, "-std=c17", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2", "-Iinclude",
                   "src/preparation.c", "src/workspace.c", "src/resources.c", str(adapter), "-o", str(helper)]
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(built.stderr)
        suite = Suite(args, root, helper)
        suite.case("preparation.partial-before-prepared-sigkill", suite.partial_cancel)
        suite.case("preparation.real-copy-sigkill", lambda a, s, p: suite.large_copy_cancel(a, s, p, False))
        suite.case("preparation.buffered-D-parent-death", suite.buffered_handover)
        for mode in ("handover-discard", "handover-keep", "handover-bad", "resource-fail", "guardian-death"):
            suite.case("preparation." + mode, lambda a, s, p, m=mode: suite.helper_normal(a, s, p, m))
        if not args.module_only:
            suite.case("preparation.cli-real-copy-sigkill", lambda a, s, p: suite.large_copy_cancel(a, s, p, True))
            suite.case("preparation.cli-copy-error-no-residue", suite.cli_preparation_error)
            suite.case("preparation.cli-keep-after-handover", suite.cli_keep)
        report = {"schema_version": 1, "environment": args.environment,
                  "kernel": platform.release(), "architecture": platform.machine(), "uid": os.getuid(),
                  "module_only": args.module_only, "build_command": command,
                  "counts": {state: sum(row["outcome"] == state for row in suite.rows)
                             for state in ("PASS", "FAIL", "BLOCKED")}, "results": suite.rows}
        if args.report:
            target = Path(args.report)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        print(json.dumps(report["counts"]))
        return int(report["counts"]["FAIL"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
