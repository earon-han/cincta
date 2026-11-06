#!/bin/sh
# Run on the Linux Docker host as root. Delegation must already exist.
# This changes neither controller configuration nor existing cgroup ownership.
set -eu
if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
  echo 'usage (Linux host root): validate_delegated_docker.sh IMAGE EXISTING_DELEGATED_PARENT NEW_REPORT_DIR' >&2
  exit 2
fi
if [ "$(uname -s)" != Linux ]; then
  echo 'a Linux Docker host is required' >&2
  exit 2
fi
image=$1
parent=$(realpath -e -- "$2")
requested_reports=$3
case "$requested_reports" in
  /*) ;;
  *) echo 'NEW_REPORT_DIR must be an absolute, new path' >&2; exit 2 ;;
esac
report_parent=$(realpath -e -- "$(dirname -- "$requested_reports")")
report_name=$(basename -- "$requested_reports")
case "$report_name" in
  ''|.|..) echo 'invalid report directory name' >&2; exit 2 ;;
esac
reports=$report_parent/$report_name
if [ "$(stat -f -c %T -- "$parent")" != cgroup2fs ] ||
   [ ! -d "$parent/manager" ] || [ ! -f "$parent/manager/cgroup.procs" ]; then
  echo 'requires an existing cgroup-v2 parent with its existing manager child' >&2
  exit 2
fi
delegate_uid=$(stat -c %u -- "$parent")
delegate_gid=$(stat -c %g -- "$parent")
if [ "$delegate_uid" -eq 0 ] ||
   [ "$(stat -c %u -- "$parent/cgroup.procs")" != "$delegate_uid" ] ||
   [ "$(stat -c %u -- "$parent/manager/cgroup.procs")" != "$delegate_uid" ]; then
  echo 'parent and migration files must already be delegated to a non-root UID' >&2
  exit 2
fi
controllers=$(cat "$parent/cgroup.subtree_control")
for controller in cpu memory pids; do
  case " $controllers " in
    *" $controller "*) ;;
    *) echo "required controller is not already enabled: $controller" >&2; exit 2 ;;
  esac
done
# mkdir is exclusive: never chown an existing report directory.
mkdir -m 0700 -- "$reports"
chown "$delegate_uid:$delegate_gid" -- "$reports"
private=$(mktemp -d /tmp/cincta-delegated-docker.XXXXXX)
container=
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -z "$container" ] && [ -s "$private/container.id" ]; then
    container=$(cat "$private/container.id")
  fi
  if [ -n "$container" ]; then
    timeout 20 docker logs "$container" > "$private/container.log" 2>&1 || :
    timeout 20 docker inspect --format \
      '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"privileged":{{json .HostConfig.Privileged}},"cap_drop":{{json .HostConfig.CapDrop}},"security_opt":{{json .HostConfig.SecurityOpt}},"cgroupns_mode":{{json .HostConfig.CgroupnsMode}},"apparmor_profile":{{json .AppArmorProfile}},"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}}}' \
      "$container" > "$private/security.json" 2> "$private/inspect-error.log" || :
    # Only the container ID created by this invocation is ever removed.
    timeout 20 docker rm -f "$container" > "$private/remove.log" 2>&1 || :
  fi
  # Publish after stopping the container; do not follow output symlinks.
  for name in container.log security.json inspect-error.log remove.log docker-security-options.json launcher.json container-exit.txt; do
    if [ -f "$private/$name" ]; then
      cp --remove-destination -- "$private/$name" "$reports/$name"
    fi
  done
  rm -rf -- "$private"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

timeout 20 docker info --format '{{json .SecurityOptions}}' > "$private/docker-security-options.json"
python3 - "$private/docker-security-options.json" <<'PY'
import json,sys
options=json.load(open(sys.argv[1]))
if not any("name=seccomp" in item and "profile=builtin" in item for item in options):
    sys.exit("Docker builtin seccomp must already be enabled")
if not any("name=apparmor" in item for item in options):
    sys.exit("Docker AppArmor must already be enabled")
PY
container=$(timeout 30 docker run -d --cidfile "$private/container.id" \
  --user "$delegate_uid:$delegate_gid" --cap-drop ALL \
  --security-opt no-new-privileges --cgroupns=host \
  --mount "type=bind,source=$parent,target=/cincta-cgroup" \
  --mount "type=bind,source=$reports,target=/reports" \
  --entrypoint sh "$image" -c '
    count=0
    while [ ! -f /reports/start ]; do
      count=$((count + 1))
      if [ "$count" -ge 600 ]; then echo "host migration barrier timed out" >&2; exit 124; fi
      sleep 0.1
    done
    exec python3 tests/resources_test.py --binary build/cincta \
      --cgroup-parent /cincta-cgroup --environment delegated-docker \
      --report /reports/resources.json
  ')
pid=$(timeout 20 docker inspect --format '{{.State.Pid}}' "$container")
case "$pid" in
  ''|*[!0-9]*) echo 'invalid container PID' >&2; exit 1 ;;
esac
if [ "$pid" -le 1 ] || [ ! -d "/proc/$pid" ]; then
  echo 'container exited before the migration barrier' >&2
  exit 1
fi
profile=$(timeout 20 docker inspect --format '{{.AppArmorProfile}}' "$container")
if [ "$profile" != docker-default ]; then
  echo 'container must use the default Docker AppArmor profile' >&2
  exit 1
fi
printf '%s\n' "$pid" > "$parent/manager/cgroup.procs"
python3 - "$private/launcher.json" "$delegate_uid" "$delegate_gid" "$parent" "$pid" "$0" <<'PY'
import hashlib,json,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({"schema_version":1,
    "delegated_uid":int(sys.argv[2]),"delegated_gid":int(sys.argv[3]),
    "existing_cgroup_parent":sys.argv[4],"container_host_pid":int(sys.argv[5]),
    "launcher_sha256":hashlib.sha256(pathlib.Path(sys.argv[6]).read_bytes()).hexdigest(),
    "security":"non-root, cap-drop ALL, no-new-privileges, builtin seccomp, docker-default AppArmor",
    "controllers_changed":False,"existing_cgroup_ownership_changed":False},indent=2)+"\n")
PY
touch "$reports/start"
timeout 180 docker wait "$container" > "$private/container-exit.txt"
if [ "$(cat "$private/container-exit.txt")" != 0 ]; then
  echo 'delegated Docker resource suite failed; inspect preserved container.log' >&2
  exit 1
fi
python3 - "$reports/resources.json" <<'PY'
import json,sys
report=json.load(open(sys.argv[1]))
counts=report["counts"]
print(json.dumps(counts))
if counts != {"PASS":9,"FAIL":0,"BLOCKED":0}:
    sys.exit("expected all nine real resource checks to pass")
PY
printf '%s\n' "$reports"
