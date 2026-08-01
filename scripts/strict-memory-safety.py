#!/usr/bin/env python3
"""Census + ratchet for SE-0458 strict memory safety.

Builds the package with `-strict-memory-safety`, counts the un-annotated unsafe expressions per
target, and compares each count against the committed budget in
`.github/strict-memory-safety-budget.tsv`. A count may FALL freely; it may never RISE. See
docs/adr/0009-strict-memory-safety-staged-gate.md for why the gate is staged rather than global.

The targets already at zero are additionally hard-gated by the manifest (`.strictMemorySafety()` on
the target + `HTTP_WARNINGS_AS_ERRORS`), which turns a new unsafe expression there into a build
error. This script is the other half: it holds the line on the targets that are not there yet.

Usage:
    scripts/strict-memory-safety.py                # build, census, enforce the budget
    scripts/strict-memory-safety.py --update       # rewrite the budget from the census
    scripts/strict-memory-safety.py --log FILE     # census a build log captured elsewhere
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUDGET = os.path.join(REPO, ".github", "strict-memory-safety-budget.tsv")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A primary diagnostic line: `<abs path>.swift:<line>:<col>: warning: <message>`. The compiler also
# echoes the message on the source-snippet continuation lines, hence the anchored match.
DIAG = re.compile(r"^(/[^\s:]+\.swift):(\d+):(\d+): warning: (.*)$")
CATEGORY = "StrictMemorySafety"


def census(log_path):
    """Return {target: sorted[(relpath, line, col, message)]} from a build log."""
    sites = set()
    with open(log_path, errors="replace") as handle:
        for raw in handle:
            match = DIAG.match(ANSI.sub("", raw))
            if not match or CATEGORY not in match.group(4):
                continue
            path = match.group(1)
            if not path.startswith(REPO + os.sep):
                continue  # a dependency's source — not ours to annotate
            relative = os.path.relpath(path, REPO)
            message = match.group(4).split("[#")[0].strip()
            sites.add((relative, int(match.group(2)), int(match.group(3)), message))
    by_target = {}
    for site in sites:
        by_target.setdefault(target_of(site[0]), []).append(site)
    return {name: sorted(rows) for name, rows in by_target.items()}


def target_of(relative):
    """The SwiftPM target owning a `Sources/<tier>/<Target>/…` path."""
    parts = relative.split(os.sep)
    if parts[0] == "Sources" and len(parts) > 3:
        return parts[2]
    if parts[0] == "Sources" and len(parts) > 1:
        return parts[1]
    return parts[0]


def build(log_path):
    """Build every product with `-strict-memory-safety`, teeing the diagnostics to `log_path`."""
    environment = dict(os.environ)
    # The census needs the diagnostics as WARNINGS: as errors the build stops at the first target
    # and the count is a lie. The zero-count targets are gated as errors by the regular build jobs.
    environment.pop("HTTP_WARNINGS_AS_ERRORS", None)
    with tempfile.TemporaryDirectory() as scratch, open(log_path, "w") as log:
        command = [
            "swift", "build", "-Xswiftc", "-strict-memory-safety", "--scratch-path", scratch
        ]
        result = subprocess.run(command, cwd=REPO, env=environment, stdout=log, stderr=log)
    if result.returncode != 0:
        with open(log_path, errors="replace") as handle:
            sys.stderr.write(handle.read())
        sys.exit(f"::error::the -strict-memory-safety build failed (exit {result.returncode})")


def read_budget():
    budgets = {}
    with open(BUDGET) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, count = line.split("\t")
            budgets[name] = int(count)
    return budgets


def write_budget(counts):
    with open(BUDGET, "w") as handle:
        handle.write(BUDGET_HEADER)
        for name in sorted(counts, key=lambda n: (-counts[n], n)):
            handle.write(f"{name}\t{counts[name]}\n")


BUDGET_HEADER = """\
# SE-0458 strict-memory-safety budget — the ratchet (ADR 0009).
#
# One row per target: the number of expressions that use unsafe constructs without an `unsafe`
# marker, as counted by `scripts/strict-memory-safety.py`. The number may FALL freely; CI fails if
# it RISES. A target reaching 0 graduates out of this file and into `strictMemorySafeTargets` in
# Package.swift, where the compiler enforces it as a build error instead of a count.
#
# Regenerate after reducing a count:  scripts/strict-memory-safety.py --update
# Targets absent from this file must be at 0 — a new target with unsafe sites fails the gate until
# it is either annotated or added here deliberately.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="rewrite the budget from the census")
    parser.add_argument("--log", help="census this build log instead of building")
    parser.add_argument("--verbose", action="store_true", help="list every site")
    options = parser.parse_args()

    log_path = options.log
    if log_path is None:
        handle, log_path = tempfile.mkstemp(prefix="strict-memory-safety-", suffix=".log")
        os.close(handle)
        build(log_path)

    found = census(log_path)
    counts = {name: len(rows) for name, rows in found.items()}
    total = sum(counts.values())

    if options.update:
        write_budget(counts)
        print(f"wrote {BUDGET} — {total} sites across {len(counts)} targets")
        return 0

    budgets = read_budget()
    width = max([len(n) for n in set(budgets) | set(counts)] + [6])
    failures = []
    slack = []
    for name in sorted(set(budgets) | set(counts)):
        count, budget = counts.get(name, 0), budgets.get(name, 0)
        mark = "ok"
        if count > budget:
            mark = "OVER"
            failures.append((name, count, budget))
        elif count < budget:
            mark = "under"
            slack.append((name, count, budget))
        print(f"{name:<{width}}  {count:>4} / {budget:<4}  {mark}")
        if options.verbose:
            for site in found.get(name, []):
                print(f"    {site[0]}:{site[1]}:{site[2]}")
    print(f"\ntotal: {total} un-annotated unsafe sites")

    for name, count, budget in slack:
        print(f"::notice::{name} is at {count}, budget {budget} — tighten it (--update)")
    for name, count, budget in failures:
        print(f"::error::{name} has {count} un-annotated unsafe sites, budget {budget}. Mark the "
              f"new site with `unsafe` and state its safety argument, or lower another count first.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
