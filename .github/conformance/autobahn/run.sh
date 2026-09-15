#!/usr/bin/env bash
set -euo pipefail

# Autobahn retains every case's wire log until reporting. Release that memory after at most
# 16 cases, discovered from the installed suite so new cases remain covered.
image=crossbario/autobahn-testsuite
case_ids="$(docker run --rm --entrypoint python "$image" -c '
from autobahntestsuite.case import Cases
print(" ".join(sorted(case.__name__[4:].replace("_", ".") for case in Cases)))
')"
if [[ -z "$case_ids" ]]; then
    echo '::error::Autobahn did not enumerate any cases'
    exit 1
fi

config_dir="$(mktemp -d)"
trap 'rm -rf "$config_dir"' EXIT
python3 - "$case_ids" "$config_dir" <<'PY'
import json
import pathlib
import re
import sys

spec = json.loads(pathlib.Path('.github/conformance/autobahn/fuzzingclient.json').read_text())
cases = sys.argv[1].split()
assert all(re.fullmatch(r'\d+(?:\.\d+)+', case) for case in cases), 'Invalid Autobahn case ID'
assert len(cases) == len(set(cases)), 'Duplicate Autobahn case IDs'
for offset in range(0, len(cases), 16):
    spec['cases'] = cases[offset:offset + 16]
    path = pathlib.Path(sys.argv[2]) / f'{offset // 16:04d}.json'
    path.write_text(json.dumps(spec))
PY
for config in "$config_dir"/*.json; do
    batch="$(basename "$config" .json)"
    mkdir -p "reports/$batch"
    docker run --rm --network host \
        -v "$config_dir:/config:ro" \
        -v "$PWD/reports/$batch:/reports" \
        "$image" wstest -m fuzzingclient -s "/config/$batch.json"
    python3 - "$config" "reports/$batch/index.json" <<'PY'
import json
import sys

expected = set(json.load(open(sys.argv[1]))['cases'])
report = json.load(open(sys.argv[2]))
assert report, 'Autobahn produced no agents'
for agent, results in report.items():
    assert set(results) == expected, f'{agent}: missing or unexpected Autobahn cases'
PY
    python3 .github/conformance/autobahn/check.py "reports/$batch/index.json"
done
