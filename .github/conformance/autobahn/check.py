#!/usr/bin/env python3
#
#  check.py — gate the Autobahn TestSuite report (RFC 6455 WebSocket conformance).
#
#  Reads the fuzzingclient's index.json and fails (exit 1) if any case's `behavior` or `behaviorClose`
#  is FAILED. OK / INFORMATIONAL / NON-STRICT / UNIMPLEMENTED all pass (NON-STRICT and INFORMATIONAL are
#  advisory; UNIMPLEMENTED is for optional features such as permessage-deflate cases a server may decline).
#
#  Usage: check.py [path/to/index.json]   (default: reports/index.json)
#
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "reports/index.json")
if not report.is_file():
    print(f"::error::Autobahn report not found at {report} — the run did not produce results")
    sys.exit(1)

data = json.loads(report.read_text())
failed = [
    f"{agent} case {case}: {key}={result.get(key)}"
    for agent, cases in data.items()
    for case, result in cases.items()
    for key in ("behavior", "behaviorClose")
    if result.get(key) == "FAILED"
]
total = sum(len(cases) for cases in data.values())

if failed:
    print(f"::error::Autobahn reported {len(failed)} FAILED case(s):")
    print("\n".join(failed))
    sys.exit(1)

print(f"Autobahn: no FAILED cases ({total} cases across {len(data)} agent(s)).")
