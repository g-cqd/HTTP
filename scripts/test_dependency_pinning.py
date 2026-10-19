"""Regression checks for the family-wide Aemi dependency contract: one pinned revision per graph."""

import contextlib
import importlib.util
import io
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "dependency_pinning", pathlib.Path(__file__).with_name("dependency-pinning.py")
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

PINNED = "a" * 40


class DependencyPolicyTests(unittest.TestCase):
    def manifest(self, requirement=None, url="https://github.com/Aemi-Studio/aemi.git"):
        return {"dependencies": [{"sourceControl": [{
            "identity": "aemi",
            "location": {"remote": [{"urlString": url}]},
            "requirement": requirement or {"revision": [PINNED]},
        }]}]}

    def test_a_pinned_revision_is_accepted(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.validate_manifest(self.manifest()), 0)

    def test_floating_requirements_and_foreign_sources_are_rejected(self):
        invalid = [
            self.manifest({"branch": ["main"]}),
            self.manifest({"range": [{"lowerBound": "1.0.0", "upperBound": "2.0.0"}]}),
            self.manifest({"revision": ["not-a-commit"]}),
            self.manifest({"revision": ["A" * 40]}),
            self.manifest(url="https://github.com/another-owner/aemi.git"),
            {"dependencies": []},
        ]
        for manifest in invalid:
            with self.subTest(manifest=manifest), contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(policy.validate_manifest(manifest), 0)

    def test_the_resolved_commit_is_the_pinned_one(self):
        pins = [{"identity": "aemi", "state": {"revision": PINNED}}]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.validate_resolution(pins, PINNED), 0)
        for invalid in [
            {"revision": "b" * 40},
            {"revision": PINNED, "branch": "main"},
            {"revision": PINNED, "version": "1.0.0"},
            {"revision": "not-a-commit"},
        ]:
            with self.subTest(state=invalid), contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(
                    policy.validate_resolution([{"identity": "aemi", "state": invalid}], PINNED), 0
                )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(policy.validate_resolution([], PINNED), 0)


if __name__ == "__main__":
    unittest.main()
