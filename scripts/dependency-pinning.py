#!/usr/bin/env python3
"""Check Aemi's family-wide main-branch requirement and the untracked library lockfile.

SwiftPM rejects mixed branch/revision requirements for this shared dependency. Package.swift
records why every sibling must use the same Aemi main branch. This gate checks compatibility;
a floating branch does not promise identical dependency commits across future resolutions.
"""

import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESOLVED = os.path.join(REPO, "Package.resolved")
PACKAGE = "aemi"
LOCATION = "https://github.com/Aemi-Studio/aemi.git"
BRANCH = "main"


def fail(message):
    print(f"::error::{message}")
    return 1


def validate_manifest(manifest):
    """Require the canonical Aemi source and the same branch as sibling packages."""
    dependencies = [
        source
        for dependency in manifest.get("dependencies", [])
        for source in dependency.get("sourceControl", [])
        if source.get("identity") == PACKAGE
    ]
    if len(dependencies) != 1:
        return fail("Package.swift must declare exactly one Aemi dependency.")
    dependency = dependencies[0]
    if dependency.get("location", {}).get("remote") != [{"urlString": LOCATION}]:
        return fail(f"Aemi must use its canonical source: {LOCATION}")
    if dependency.get("requirement") != {"branch": [BRANCH]}:
        return fail("Aemi must use branch main, matching the sibling package graph.")
    print(f"manifest: {PACKAGE} uses {LOCATION}, branch {BRANCH}")
    return 0


def check_manifest():
    """Check the evaluated manifest so comments and inactive declarations cannot satisfy the gate."""
    result = subprocess.run(
        ["swift", "package", "dump-package"], cwd=REPO, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return fail("`swift package dump-package` failed.")
    return validate_manifest(json.loads(result.stdout))


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


def validate_resolution(pins):
    """Require a resolved commit on the declared branch, rather than a version or revision override."""
    pin = next((pin for pin in pins if pin.get("identity") == PACKAGE), None)
    if pin is None:
        return fail(f"The resolved graph contains no `{PACKAGE}` pin.")
    state = pin.get("state", {})
    if state.get("branch") != BRANCH or state.get("version") is not None:
        return fail(f"{PACKAGE} must resolve on branch {BRANCH}, without a version constraint.")
    revision = state.get("revision", "")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        return fail(f"{PACKAGE} has no valid resolved commit.")
    print(f"resolution: {PACKAGE} -> {revision} (branch {BRANCH})")
    return 0


def check_resolution_matches():
    """Resolve the graph and verify its Aemi branch and concrete commit."""
    result = subprocess.run(["swift", "package", "resolve"], cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return fail("`swift package resolve` failed.")
    if not os.path.exists(RESOLVED):
        return fail("`swift package resolve` produced no Package.resolved to verify against.")
    return validate_resolution(json.load(open(RESOLVED)).get("pins", []))


def main():
    status = check_manifest()
    status |= check_resolved_is_ignored()
    if status == 0:
        status |= check_resolution_matches()
    if status == 0:
        print("\ndependency requirements match the shared Aemi graph")
    return status


if __name__ == "__main__":
    sys.exit(main())
