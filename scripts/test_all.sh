#!/bin/sh
# Real-kernel suites, kept separate so an unavailable feature is never a PASS.
# TESTFLAGS intentionally belongs to make test-legacy, not to this dispatcher.
set -u
label=${1:-${CINCTA_TEST_LABEL:-native}}
case "$label" in
  *[!a-zA-Z0-9_-]*|'') echo 'environment label must contain only letters, digits, - or _' >&2; exit 2 ;;
esac
build=${BUILD:-build}
binary=${CINCTA_BINARY:-$build/cincta}
helper=${CINCTA_HELPER:-$build/adversary}
reports=${CINCTA_REPORT_DIR:-reports/v02-$label}
mkdir -p "$reports"
# Only discard this dispatcher's known outputs; preserve unrelated user files.
# A crashed suite must never inherit a previous run's successful JSON.
for name in probe summary legacy workspace-module preparation output-boundaries network independent file-audit resources; do
  rm -f -- "$reports/$name.json"
done
rm -rf -- "$reports/independent-artifacts"
failed=0
run_suite() {
  "$@"
  code=$?
  if [ "$code" -ne 0 ]; then failed=1; fi
}

if ! "$binary" probe > "$reports/probe.json"; then
  echo 'probe failed; cannot establish the real-kernel test prerequisites' >&2
  exit 1
fi
mode=$(python3 - "$reports/probe.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
print("strict" if p.get("strict_supported") else "compat" if p.get("compat_supported") else "unavailable")
PY
)
compat=
if [ "$mode" = compat ]; then compat=--compat; fi
run_suite python3 tests/integration.py --binary "$binary" --helper "$helper" \
  --environment "$label-legacy" --report "$reports/legacy.json"
run_suite python3 tests/workspace_test.py --environment "$label-workspace-module" \
  --report "$reports/workspace-module.json"
run_suite python3 tests/preparation_test.py --binary "$binary" \
  --environment "$label-preparation" --report "$reports/preparation.json"
run_suite python3 tests/output_boundary_test.py --binary "$binary" \
  --environment "$label-output-boundaries" --report "$reports/output-boundaries.json"

if [ "$mode" != unavailable ]; then
  # compat expands to either zero words or the one fixed flag above.
  run_suite python3 tests/network_test.py --binary "$binary" $compat \
    --environment "$label-network" --report "$reports/network.json"
  run_suite python3 tests/v02_integration.py --binary "$binary" $compat \
    --environment "$label-independent" --report "$reports/independent.json" \
    --artifacts "$reports/independent-artifacts"
  run_suite python3 tests/file_audit_test.py --binary "$binary" \
    --environment "$label-file-audit" --report "$reports/file-audit.json"
else
  python3 - "$reports" <<'PY'
import json,pathlib,sys
for name in ("network","independent","file-audit"):
    report={"schema_version":1,"counts":{"PASS":0,"FAIL":0,"BLOCKED":1},
            "results":[{"name":name+".effective-suite","outcome":"BLOCKED",
                        "reason":"base Landlock/seccomp execution prerequisites are unavailable"}]}
    pathlib.Path(sys.argv[1],name+".json").write_text(json.dumps(report,indent=2)+"\n")
PY
fi

if [ -n "${CINCTA_CGROUP_PARENT:-}" ]; then
  run_suite python3 tests/resources_test.py --binary "$binary" \
    --cgroup-parent "$CINCTA_CGROUP_PARENT" --environment "$label-resources-delegated" \
    --report "$reports/resources.json"
else
  run_suite python3 tests/resources_test.py --binary "$binary" \
    --environment "$label-resources-no-delegation" --report "$reports/resources.json"
fi

python3 - "$reports" "$binary" "$label" <<'PY'
import hashlib,json,os,pathlib,platform,subprocess,sys
directory=pathlib.Path(sys.argv[1]); counts={state:0 for state in ("PASS","FAIL","BLOCKED")}
suites={}
for name in ("legacy","workspace-module","preparation","output-boundaries",
             "network","independent","file-audit","resources"):
    path=directory/(name+".json")
    if not path.exists():
        suites[name]={"PASS":0,"FAIL":1,"BLOCKED":0,"reason":"suite did not produce its report"}
    else:
        try:
            suites[name]=json.loads(path.read_text())["counts"]
        except (OSError,ValueError,KeyError):
            suites[name]={"PASS":0,"FAIL":1,"BLOCKED":0,"reason":"suite produced an invalid report"}
    for state in counts: counts[state]+=suites[name].get(state,0)
try:
    revision=subprocess.check_output(["git","rev-parse","HEAD"],text=True,stderr=subprocess.DEVNULL).strip()
except (OSError,subprocess.CalledProcessError):
    revision=os.environ.get("CINCTA_SOURCE_REVISION","unavailable")
sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest()
         for root in ("src","include","tests") for p in sorted(pathlib.Path(root).glob("*"))
         if p.is_file() and p.suffix in (".c",".h",".py")}
summary={"schema_version":1,"environment":sys.argv[3],"kernel":platform.release(),
         "architecture":platform.machine(),"uid":os.getuid(),"source_revision":revision,
         "binary_sha256":hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
         "source_sha256":sources,"counts":counts,"suites":suites}
(directory/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps({"environment":sys.argv[3],"counts":counts,"report":str(directory/"summary.json")}))
sys.exit(bool(counts["FAIL"]))
PY
summary_code=$?
if [ "$summary_code" -ne 0 ]; then failed=1; fi
exit "$failed"
