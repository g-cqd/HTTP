#!/usr/bin/env python3
"""Assert the ADFoundation dependency is reproducible: exact revision, resolved file untracked.

The standing decision (2026-07-31 audit) is a two-part one, and each half is load-bearing only if
the other holds:

  * `ADFoundation` is unversioned and was taken from `branch: "main"`. A moving branch means two
    checkouts of the SAME HTTP commit can resolve different dependency code — so a build is not
    reproducible, a benchmark number is not attributable to a commit, and a green CI run is not
    evidence about any particular input. It is pinned to an exact revision instead.
  * `Package.resolved` stays gitignored. This is a reusable library; committing a lockfile would
    publish one resolution of the whole graph to every consumer, who must resolve their own. Which
    is exactly why the manifest pin has to be exact: with no committed lockfile, the manifest is the
    ONLY thing making this package's own builds deterministic.

This script is what stops either half from being quietly undone — a `branch:` slipped back into the
manifest, or a `Package.resolved` committed "to fix CI".

Usage: scripts/dependency-pinning.py
"""

import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO, "Package.swift")
RESOLVED = os.path.join(REPO, "Package.resolved")
PACKAGE = "adfoundation"
REVISION = re.compile(r'^let adFoundationRevision = "([0-9a-f]{40})"$', re.MULTILINE)


def fail(message):
    print(f"::error::{message}")
    return 1


def check_manifest():
    """The manifest pins ADFoundation to a 40-hex revision, and to nothing else."""
    source = open(MANIFEST).read()
    match = REVISION.search(source)
    if match is None:
        return None, fail(
            "Package.swift has no `let adFoundationRevision = \"<40-hex sha>\"`. The ADFoundation "
            "pin must be an exact revision — not a branch, not a version range."
        )
    declaration = re.search(r"\.package\(\s*url:[^)]*ADFoundation[^)]*\)", source, re.DOTALL)
    if declaration is None:
        return None, fail("Package.swift declares no ADFoundation dependency to check.")
    body = declaration.group(0)
    if "revision: adFoundationRevision" not in body:
        return None, fail(f"the ADFoundation dependency is not `revision: adFoundationRevision`:\n{body}")
    for forbidden in ("branch:", "from:", "exact:", "upToNextMajor", "upToNextMinor"):
        if forbidden in body:
            return None, fail(
                f"the ADFoundation dependency uses `{forbidden}`. It is unversioned and first-party; "
                "a moving reference makes two checkouts of the same HTTP commit resolve different code."
            )
    print(f"manifest: ADFoundation pinned to {match.group(1)}")
    return match.group(1), 0


def check_resolved_is_ignored():
    """`Package.resolved` is untracked and gitignored.

    Tracked is tested FIRST: `git check-ignore` reports a tracked file as not-ignored, so testing
    ignored first would blame .gitignore for a file that .gitignore is powerless over.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "Package.resolved"],
        cwd=REPO, capture_output=True
    ).returncode == 0
    if tracked:
        return fail("Package.resolved is TRACKED. Gitignoring a file git already tracks does "
                    "nothing; remove it with `git rm --cached Package.resolved`. This is a "
                    "reusable library — consumers resolve their own graph.")
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "Package.resolved"], cwd=REPO
    ).returncode == 0
    if not ignored:
        return fail("Package.resolved is not gitignored — a stray `swift build` would leave it "
                    "committable (see the .gitignore comment and Package.swift).")
    print("Package.resolved: untracked and gitignored")
    return 0


def check_resolution_matches(expected):
    """Resolving the graph actually lands on the pinned revision, with no branch or version."""
    result = subprocess.run(["swift", "package", "resolve"], cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return fail("`swift package resolve` failed — the pin does not resolve.")
    if not os.path.exists(RESOLVED):
        return fail("`swift package resolve` produced no Package.resolved to verify against.")
    pins = json.load(open(RESOLVED)).get("pins", [])
    pin = next((p for p in pins if p.get("identity") == PACKAGE), None)
    if pin is None:
        return fail(f"the resolved graph contains no `{PACKAGE}` pin.")
    state = pin.get("state", {})
    if state.get("revision") != expected:
        return fail(f"{PACKAGE} resolved to {state.get('revision')}, manifest pins {expected}.")
    for floating in ("branch", "version"):
        if state.get(floating) is not None:
            return fail(f"{PACKAGE} resolved with a {floating} ({state[floating]}) — not a pure "
                        "revision pin, so the resolution can move under the same manifest.")
    print(f"resolution: {PACKAGE} -> {expected} (revision pin, no branch, no version)")
    return 0


def main():
    expected, status = check_manifest()
    status |= check_resolved_is_ignored()
    if expected is not None:
        status |= check_resolution_matches(expected)
    if status == 0:
        print("\ndependency pinning is reproducible")
    return status


if __name__ == "__main__":
    sys.exit(main())
