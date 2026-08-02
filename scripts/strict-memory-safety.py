#!/usr/bin/env python3
"""Census + ratchet for SE-0458 strict memory safety.

Builds the package with `-strict-memory-safety`, counts the un-annotated unsafe expressions per
target, and compares each count against the committed budget in
`.github/strict-memory-safety-budget.tsv`. A count may FALL freely; it may never RISE. See
docs/adr/0009-strict-memory-safety-staged-gate.md for why the gate is staged rather than global.

The targets already at zero are additionally hard-gated by the manifest (`.strictMemorySafety()` on
the target + `HTTP_WARNINGS_AS_ERRORS`), which turns a new unsafe expression there into a build
error. This script is the other half: it holds the line on the targets that are not there yet.

WHY THERE IS A SECOND CATEGORY
------------------------------
Counting only un-annotated sites made SUPPRESSION read as improvement. The compiler stops asking
about an expression the moment you write `unsafe` in front of it, and it never asked at all about
`@unchecked Sendable`, `nonisolated(unsafe)`, `@unsafe` or `unsafeBitCast` — so the cheapest way to
make this gate greener was to silence the question rather than answer it, and the number went down
either way. A ratchet that rewards that is worse than no ratchet, because it converts review
pressure into an incentive.

So suppressions are censused separately (`SUPPRESSIONS` below) and ratcheted separately, and the
trade is now visible: replacing an un-annotated expression with `@unchecked Sendable` lowers the
first count and raises the second, which fails. The suppression column is held at EXACT equality
rather than "may fall": a fall is a real change worth re-baselining deliberately, and slack is how a
ratchet stops ratcheting.

New suppressions must also argue for themselves. `.github/strict-memory-safety-suppressions.tsv`
inventories what is already in the tree, per file and kind — that inventory IS the review record,
and adding to it is a diff line a human has to approve. Any site beyond the inventoried count must
carry a `// SAFETY:` comment on the same line or within the five lines above it.

WHAT THIS DOES NOT CATCH
------------------------
Stated plainly, because a guard whose limits are unwritten is a guard people trust too far.

  * A justification that is present but WRONG. `// SAFETY:` is checked for existence and placement,
    never for truth. This buys a deliberate act and a greppable marker, not a proof.
  * Moving unsafe code OUT of `Sources/` — into a C shim target, a dependency, or a test target.
    Both censuses stop at this repo's `Sources/`, so the total falls and reads as progress.
  * Moving a site between targets that both have slack in the first column. The per-target ceiling
    catches a rise, not a transfer, and only the first column tolerates slack at all.
  * COARSENING. One `unsafe` marker can cover a whole expression, so merging three marked
    sub-expressions into one statement lowers the count without lowering the unsafety. The compiler
    reports expressions, and this script can only count what it reports.
  * Unsafe constructs neither the compiler diagnoses nor `SUPPRESSIONS` names — `@_spi`,
    `@_silgen_name`, withMemoryRebound and friends, or anything added to the language after this
    list was written. The list is an allowlist of known silencers, not a definition of "unsafe".
  * Removing `.strictMemorySafety()` from a target in `Package.swift`. That is caught, but by the
    build gate rather than here: this script passes `-strict-memory-safety` to every target itself.

Usage:
    scripts/strict-memory-safety.py                # build, census, enforce both ratchets
    scripts/strict-memory-safety.py --update       # rewrite the budget + inventory from the census
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
INVENTORY = os.path.join(REPO, ".github", "strict-memory-safety-suppressions.tsv")
SOURCES = os.path.join(REPO, "Sources")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A primary diagnostic line: `<abs path>.swift:<line>:<col>: warning: <message>`. The compiler also
# echoes the message on the source-snippet continuation lines, hence the anchored match.
DIAG = re.compile(r"^(/[^\s:]+\.swift):(\d+):(\d+): warning: (.*)$")
CATEGORY = "StrictMemorySafety"

# The silencers. Each of these makes the compiler stop asking a question rather than answer it, so
# each is a way to lower the un-annotated count without making anything safer. Keyed by the name
# reported in diagnostics and written to the inventory.
SUPPRESSIONS = {
    "@unchecked Sendable": re.compile(r"@unchecked\s+Sendable"),
    "nonisolated(unsafe)": re.compile(r"nonisolated\(unsafe\)"),
    "@unsafe": re.compile(r"@unsafe\b"),
    "unsafeBitCast": re.compile(r"\bunsafeBitCast\("),
    "unsafeDowncast": re.compile(r"\bunsafeDowncast\("),
    "@_unsafeInheritExecutor": re.compile(r"@_unsafeInheritExecutor"),
}
# The justification a NEW suppression must carry, on its own line or within the five above it.
SAFETY = re.compile(r"//.*\bSAFETY:")
SAFETY_WINDOW = 5


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


def census_suppressions():
    """Return (by_file, sites) for every suppression under `Sources/`.

    `by_file` is {relpath: {kind: count}}; `sites` is the flat list of (relpath, line, kind,
    justified) so the caller can name the offenders. Lines that are wholly a comment are skipped:
    the doc comment above `@unchecked Sendable` almost always names the attribute, and counting the
    explanation as a second occurrence would make every documented suppression look like two.
    """
    by_file, sites = {}, []
    for root, _, names in os.walk(SOURCES):
        for name in sorted(names):
            if not name.endswith(".swift"):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, REPO)
            with open(path, errors="replace") as handle:
                lines = handle.read().split("\n")
            for index, line in enumerate(lines):
                if line.lstrip().startswith("//"):
                    continue
                for kind, pattern in SUPPRESSIONS.items():
                    if not pattern.search(line):
                        continue
                    window = lines[max(0, index - SAFETY_WINDOW): index + 1]
                    justified = any(SAFETY.search(each) for each in window)
                    by_file.setdefault(relative, {}).setdefault(kind, 0)
                    by_file[relative][kind] += 1
                    sites.append((relative, index + 1, kind, justified))
    return by_file, sites


def read_inventory():
    """Return {(relpath, kind): count} — the suppressions already reviewed into the tree."""
    if not os.path.exists(INVENTORY):
        return {}
    inventory = {}
    with open(INVENTORY) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            relative, kind, count = line.split("\t")
            inventory[(relative, kind)] = int(count)
    return inventory


def write_inventory(by_file):
    with open(INVENTORY, "w") as handle:
        handle.write(INVENTORY_HEADER)
        for relative in sorted(by_file):
            for kind in sorted(by_file[relative]):
                handle.write(f"{relative}\t{kind}\t{by_file[relative][kind]}\n")


def unjustified_new_sites(by_file, sites, inventory):
    """The suppressions beyond what the inventory records that carry no `// SAFETY:`.

    Counting rather than matching line numbers on purpose: a suppression that merely MOVES within
    its file is not a new suppression, and an inventory keyed by line number would churn on every
    edit above it and teach everyone to re-run `--update` without reading the diff.
    """
    offenders = []
    for relative in sorted(by_file):
        for kind, count in sorted(by_file[relative].items()):
            surplus = count - inventory.get((relative, kind), 0)
            if surplus <= 0:
                continue
            unjustified = [
                site
                for site in sites
                if site[0] == relative and site[2] == kind and not site[3]
            ]
            offenders.extend(unjustified[:surplus])
    return offenders


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
    """Return {target: (unannotated, suppressed)}; a one-column row predates the second census."""
    budgets = {}
    with open(BUDGET) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            budgets[fields[0]] = (int(fields[1]), int(fields[2]) if len(fields) > 2 else 0)
    return budgets


def write_budget(counts, suppressed):
    with open(BUDGET, "w") as handle:
        handle.write(BUDGET_HEADER)
        for name in sorted(set(counts) | set(suppressed), key=lambda n: (-counts.get(n, 0), n)):
            handle.write(f"{name}\t{counts.get(name, 0)}\t{suppressed.get(name, 0)}\n")


BUDGET_HEADER = """\
# SE-0458 strict-memory-safety budget — the ratchet (ADR 0009).
#
# One row per target, TWO columns:
#
#   target <TAB> un-annotated <TAB> suppressed
#
# UN-ANNOTATED — expressions using unsafe constructs with no `unsafe` marker, counted from the
# compiler's own diagnostics. May FALL freely; CI fails if it RISES. A target reaching 0 graduates
# out of this file and into `strictMemorySafeTargets` in Package.swift, where the compiler enforces
# it as a build error instead of a count.
#
# SUPPRESSED — constructs that make the compiler stop ASKING rather than answer: `@unchecked
# Sendable`, `nonisolated(unsafe)`, `@unsafe`, `unsafeBitCast`, `unsafeDowncast`,
# `@_unsafeInheritExecutor`. Held at EXACT equality, in both directions. Without this column,
# replacing an un-annotated expression with `@unchecked Sendable` lowered the first number and read
# as progress; now it lowers the first and raises the second, and fails. Equality rather than a
# ceiling because slack is how a ratchet stops ratcheting, and a genuine removal is worth the one
# deliberate `--update` it costs.
#
# Regenerate after either count changes:  scripts/strict-memory-safety.py --update
# Targets absent from this file must be at 0 in both columns — a new target with unsafe sites fails
# the gate until it is either annotated or added here deliberately.
"""

INVENTORY_HEADER = """\
# The suppressions already in the tree, per file and kind (ADR 0009).
#
#   path <TAB> kind <TAB> count
#
# This file is the review record. Counting per file rather than per line on purpose: a suppression
# that merely MOVES within its file is not a new suppression, and a line-keyed inventory would churn
# on every edit above it and teach everyone to re-run `--update` without reading the diff.
#
# A suppression BEYOND the count recorded here must carry a `// SAFETY:` comment on its own line or
# within the five lines above it. Existing entries are grandfathered: they were argued in prose when
# they were written, and rewriting other people's justifications into a new format would be churn
# that proves nothing. New ones argue in the format.
#
# Regenerate:  scripts/strict-memory-safety.py --update
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
    by_file, sites = census_suppressions()
    suppressed = {}
    for relative, kinds in by_file.items():
        suppressed[target_of(relative)] = suppressed.get(target_of(relative), 0) + sum(kinds.values())

    if options.update:
        write_budget(counts, suppressed)
        write_inventory(by_file)
        print(f"wrote {BUDGET} — {total} un-annotated across {len(counts)} targets")
        print(f"wrote {INVENTORY} — {sum(suppressed.values())} suppressions across {len(by_file)} files")
        return 0

    budgets = read_budget()
    width = max([len(n) for n in set(budgets) | set(counts) | set(suppressed)] + [6])
    failures, slack = [], []
    print(f"{'target':<{width}}  un-annotated  suppressed")
    for name in sorted(set(budgets) | set(counts) | set(suppressed)):
        count, budget = counts.get(name, 0), budgets.get(name, (0, 0))[0]
        silenced, allowed = suppressed.get(name, 0), budgets.get(name, (0, 0))[1]
        mark = "ok"
        if count > budget:
            mark = "OVER"
            failures.append(
                f"{name} has {count} un-annotated unsafe sites, budget {budget}. Mark the new site "
                f"with `unsafe` and state its safety argument, or lower another count first."
            )
        elif count < budget:
            mark = "under"
            slack.append((name, count, budget))
        if silenced != allowed:
            mark = "SUPPRESSION"
            failures.append(
                f"{name} has {silenced} suppression(s), recorded {allowed}. A suppression silences "
                f"the question instead of answering it, so it may not move without review: justify "
                f"the new one with `// SAFETY:` and re-baseline (--update), or remove it."
            )
        print(f"{name:<{width}}  {count:>6} / {budget:<4}  {silenced:>4} / {allowed:<4}  {mark}")
        if options.verbose:
            for site in found.get(name, []):
                print(f"    {site[0]}:{site[1]}:{site[2]}")

    inventory = read_inventory()
    for relative, line, kind, _ in unjustified_new_sites(by_file, sites, inventory):
        failures.append(
            f"{relative}:{line} adds `{kind}` beyond the reviewed inventory with no justification. "
            f"State why it is sound in a `// SAFETY:` comment on that line or the five above it, "
            f"then re-baseline (--update). A suppression the ratchet accepts silently is a "
            f"suppression nobody read."
        )

    print(f"\ntotal: {total} un-annotated unsafe sites, {sum(suppressed.values())} suppressions")
    for name, count, budget in slack:
        print(f"::notice::{name} is at {count}, budget {budget} — tighten it (--update)")
    for message in failures:
        print(f"::error::{message}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
