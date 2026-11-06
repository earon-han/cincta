#!/bin/sh
# Run INSIDE the target Linux VM/container. Caller supplies an honest label.
set -eu
label=${1:-native}
case "$label" in
  *[!a-zA-Z0-9_-]*|'') echo 'environment label must contain only letters, digits, - or _' >&2; exit 2 ;;
esac
build=${BUILD:-build}
reports=${CINCTA_REPORT_DIR:-reports/v02-$label}
make BUILD="$build" check
BUILD="$build" CINCTA_REPORT_DIR="$reports" sh scripts/test_all.sh "$label"
if "$build/cincta" probe | python3 -c 'import json,sys; sys.exit(not json.load(sys.stdin)["strict_supported"])'; then
  python3 scripts/benchmark.py --binary "$build/cincta" --samples 100 --report "$reports/benchmark.json"
  python3 scripts/benchmark.py --binary "$build/cincta" --samples 100 --concurrency 8 --report "$reports/concurrent.json"
else
  python3 scripts/benchmark.py --binary "$build/cincta" --samples 100 --compat --report "$reports/benchmark.json"
  python3 scripts/benchmark.py --binary "$build/cincta" --samples 100 --concurrency 8 --compat --report "$reports/concurrent.json"
fi
python3 tests/stress_test.py --binary "$build/cincta" --samples 100 --concurrency 8 \
  --environment "$label-combined-stress" --report "$reports/stress.json"
