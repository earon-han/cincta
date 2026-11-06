#!/usr/bin/env python3
"""Run on a Linux Docker host: verify exec with a namespace-hidden caller."""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess
import time


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=check, timeout=40)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="cincta-test:v02-final")
    parser.add_argument("--binary", required=True, help="host static binary, mounted read-only")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    binary = pathlib.Path(args.binary).resolve()
    cid = docker("run", "-d", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--network", "none", "--mount", f"type=bind,source={binary},target=/tested/cincta,readonly",
                 args.image, "sleep", "120").stdout.strip()
    process = None
    rows = []
    try:
        probe = json.loads(docker("exec", cid, "/tested/cincta", "probe").stdout)
        mode = [] if probe["strict_supported"] else ["--compat"]
        base = ["/tested/cincta", "run", *mode, "--rx", "/usr/bin", "--rx", "/usr/lib"]
        first = docker("exec", cid, *base, "--result", "/tmp/exec-normal.json", "--", "/bin/true")
        report = json.loads(docker("exec", cid, "cat", "/tmp/exec-normal.json").stdout)
        assert first.returncode == 0 and report["status"] == "ok", report
        assert report["protections"]["caller_bound"] is False, report
        assert "caller_lifetime_unavailable_in_pid_namespace" in report["unsupported"], report
        rows.append({"name": "hidden-caller-exec-success", "outcome": "PASS", "result": report})
        docker("exec", cid, "mkdir", "-p", "/tmp/exec-work")
        process = subprocess.Popen(["docker", "exec", cid, *base, "--rw", "/tmp/exec-work",
            "--result", "/tmp/exec-cancel.json", "--", "/bin/sh", "-c",
            'printf "%s" "$$" > /tmp/exec-work/pid; sleep 60'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            marker = docker("exec", cid, "cat", "/tmp/exec-work/pid", check=False)
            if marker.returncode == 0 and marker.stdout.strip().isdigit():
                break
            time.sleep(0.02)
        else:
            raise AssertionError("exec workload did not start")
        payload = int(marker.stdout)
        controller = r'''import json,os,pathlib,signal
matches=[]
for item in pathlib.Path('/proc').iterdir():
 if not item.name.isdigit(): continue
 try:
  state=dict(line.split(':',1) for line in (item/'status').read_text().splitlines() if ':' in line)
  if os.readlink(item/'exe')=='/tested/cincta' and int(state['PPid'])==0:
   matches.append(int(item.name))
 except (FileNotFoundError,ProcessLookupError): pass
assert len(matches)==1,matches
fd=os.pidfd_open(matches[0]);signal.pidfd_send_signal(fd,signal.SIGTERM);os.close(fd)
print(json.dumps({'cli':matches[0],'ppid':0}))
'''
        identity = json.loads(docker("exec", cid, "python3", "-c", controller).stdout)
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 143, (process.returncode, stdout, stderr)
        cancelled = json.loads(docker("exec", cid, "cat", "/tmp/exec-cancel.json").stdout)
        assert cancelled["status"] == "cancelled" and cancelled["cleanup_complete"], cancelled
        assert cancelled["protections"]["caller_bound"] is False, cancelled
        rows.append({"name": "hidden-caller-runtime-signal-cancel", "outcome": "PASS",
                     "identity": identity, "result": cancelled})
        assert docker("exec", cid, "test", "!", "-e", f"/proc/{payload}", check=False).returncode == 0
        rows.append({"name": "exec-payload-actually-reaped", "outcome": "PASS", "pid": payload})
    except Exception as error:
        rows.append({"name": "docker-exec-regression", "outcome": "FAIL", "reason": str(error)})
    finally:
        inspected = json.loads(docker("inspect", cid).stdout)[0]
        security = {"image": inspected["Image"], "user": inspected["Config"]["User"],
                    "privileged": inspected["HostConfig"]["Privileged"],
                    "cap_drop": inspected["HostConfig"]["CapDrop"],
                    "security_opt": inspected["HostConfig"]["SecurityOpt"],
                    "apparmor": inspected["AppArmorProfile"], "mounts": inspected["Mounts"]}
        docker("rm", "-f", cid, check=False)
        if process is not None and process.poll() is None:
            process.communicate(timeout=10)
    result = {"schema_version": 1, "kernel": platform.release(), "architecture": platform.machine(),
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "test_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
              "security": security, "results": rows,
              "counts": {key: sum(r["outcome"] == key for r in rows) for key in ("PASS", "FAIL", "BLOCKED")}}
    target = pathlib.Path(args.report); target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["counts"]))
    return bool(result["counts"]["FAIL"])


if __name__ == "__main__":
    raise SystemExit(main())
