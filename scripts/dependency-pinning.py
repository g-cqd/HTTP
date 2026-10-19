#!/usr/bin/env python3
"""Check Aemi's family-wide pinned-revision requirement and the untracked library lockfile.

SwiftPM allows one revision of a package in a graph, and rejects mixed branch/revision requirements for it.
Every Aemi-family package (AemiJSON, TerminalKit, ask, this one) therefore pins Aemi by the SAME full commit,
so a push to Aemi cannot change the C kernels and unsafe code under an existing build. This gate checks that
the manifest pins a full commit and that the resolved graph is that commit.
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
HEX40 = re.compile(r"[0-9a-f]{40}")


def fail(message):
    print(f"::error::{message}")
    return 1


def validate_manifest(manifest):
    """Require the canonical Aemi source pinned to one full commit. Returns 0 (valid) or 1."""
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
    requirement = dependency.get("requirement", {})
    revisions = requirement.get("revision", [])
    if list(requirement) != ["revision"] or len(revisions) != 1 or not HEX40.fullmatch(revisions[0]):
        return fail("Aemi must be pinned by `revision:` to a full lowercase 40-hex commit.")
    print(f"manifest: {PACKAGE} uses {LOCATION}, revision {revisions[0]}")
    return 0


def pinned_revision(manifest):
    """The revision the manifest pins (call only after `validate_manifest` accepted it)."""
    for dependency in manifest.get("dependencies", []):
        for source in dependency.get("sourceControl", []):
            if source.get("identity") == PACKAGE:
                return source["requirement"]["revision"][0]
    return ""


def check_manifest():
    """Check the evaluated manifest so comments and inactive declarations cannot satisfy the gate."""
    result = subprocess.run(
        ["swift", "package", "dump-package"], cwd=REPO, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return fail("`swift package dump-package` failed.")
    manifest = json.loads(result.stdout)
    status = validate_manifest(manifest)
    check_manifest.pinned = pinned_revision(manifest) if status == 0 else ""
    return status


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


def validate_resolution(pins, pinned):
    """Require the resolved commit to be the pinned one, with no branch or version in the way."""
    pin = next((pin for pin in pins if pin.get("identity") == PACKAGE), None)
    if pin is None:
        return fail(f"The resolved graph contains no `{PACKAGE}` pin.")
    state = pin.get("state", {})
    if state.get("branch") is not None or state.get("version") is not None:
        return fail(f"{PACKAGE} must resolve by revision, without a branch or version constraint.")
    revision = state.get("revision", "")
    if not isinstance(revision, str) or not HEX40.fullmatch(revision):
        return fail(f"{PACKAGE} has no valid resolved commit.")
    if revision != pinned:
        return fail(f"{PACKAGE} resolved to {revision}, not the pinned {pinned}.")
    print(f"resolution: {PACKAGE} -> {revision}")
    return 0


def check_resolution_matches():
    """Resolve the graph and verify that Aemi resolved to the pinned commit."""
    result = subprocess.run(["swift", "package", "resolve"], cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return fail("`swift package resolve` failed.")
    if not os.path.exists(RESOLVED):
        return fail("`swift package resolve` produced no Package.resolved to verify against.")
    return validate_resolution(json.load(open(RESOLVED)).get("pins", []), check_manifest.pinned)


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
