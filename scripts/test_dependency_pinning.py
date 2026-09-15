"""Regression checks for the family-wide Aemi dependency contract."""

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


class DependencyPolicyTests(unittest.TestCase):
    def manifest(self, requirement=None, url="https://github.com/Aemi-Studio/aemi.git"):
        return {"dependencies": [{"sourceControl": [{
            "identity": "aemi",
            "location": {"remote": [{"urlString": url}]},
            "requirement": requirement or {"branch": ["main"]},
        }]}]}

    def test_family_main_requirement_is_accepted(self):
        self.assertEqual(policy.validate_manifest(self.manifest()), 0)

    def test_incompatible_requirements_and_sources_are_rejected(self):
        invalid = [
            self.manifest({"revision": ["a" * 40]}),
            self.manifest({"branch": ["develop"]}),
            self.manifest(url="https://github.com/another-owner/aemi.git"),
            {"dependencies": []},
        ]
        for manifest in invalid:
            with self.subTest(manifest=manifest), contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(policy.validate_manifest(manifest), 0)

    def test_resolved_main_requires_an_actual_commit(self):
        state = {"branch": "main", "revision": "a" * 40}
        pins = [{"identity": "aemi", "state": state}]
        self.assertEqual(policy.validate_resolution(pins), 0)
        for invalid in [
            {"branch": "develop", "revision": "a" * 40},
            {"revision": "a" * 40},
            {"branch": "main", "revision": "not-a-commit"},
            {"branch": "main", "revision": "a" * 40, "version": "1.0.0"},
        ]:
            with self.subTest(state=invalid), contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(
                    policy.validate_resolution([{"identity": "aemi", "state": invalid}]), 0
                )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(policy.validate_resolution([]), 0)


if __name__ == "__main__":
    unittest.main()
