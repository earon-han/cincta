#!/bin/sh
# Run INSIDE the target Linux VM/container. Caller supplies an honest label.
set -eu
label=${1:-native}
case "$label" in
  *[!a-zA-Z0-9_-]*|'') echo 'environment label must contain only letters, digits, - or _' >&2; exit 2 ;;
esac
make check
python3 tests/integration.py --environment "$label" --report "reports/$label-tests.json"
if build/cincta probe | python3 -c 'import json,sys; sys.exit(not json.load(sys.stdin)["strict_supported"])'; then
  python3 scripts/benchmark.py --samples 100 --report "reports/$label-benchmark.json"
else
  python3 scripts/benchmark.py --samples 100 --compat --report "reports/$label-benchmark.json"
fi
