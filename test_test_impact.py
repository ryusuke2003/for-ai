import tempfile
import unittest
from pathlib import Path

from impact_analyzer import analyze, discover_test_files, format_report


class TestImpactAnalyzerTest(unittest.TestCase):
    def test_source_change_without_test_change_is_visible(self):
        result = analyze(
            b"M\0src/auth.py\0",
            ("tests/test_auth.py",),
        )
        self.assertEqual(result.signal, "source-without-test-change")
        self.assertEqual(result.source_changes, ("src/auth.py",))
        self.assertEqual(result.impacts[0].candidates[0].path, "tests/test_auth.py")

    def test_source_and_test_change_are_linked(self):
        result = analyze(
            b"M\0src/auth.py\0M\0tests/test_auth.py\0",
            ("tests/test_auth.py",),
        )
        self.assertEqual(result.signal, "tests-changed")
        self.assertEqual(result.test_changes, ("tests/test_auth.py",))

    def test_analyzer_filename_is_not_misclassified_as_test(self):
        result = analyze(
            b"M\0impact_analyzer.py\0M\0test_test_impact.py\0",
            ("test_test_impact.py",),
        )
        self.assertEqual(result.source_changes, ("impact_analyzer.py",))
        self.assertEqual(result.test_changes, ("test_test_impact.py",))
        self.assertEqual(result.signal, "tests-changed")

    def test_javascript_test_naming_is_matched(self):
        result = analyze(
            b"M\0src/session.ts\0",
            ("src/__tests__/session.test.ts",),
        )
        self.assertEqual(result.impacts[0].candidates[0].score, 100)

    def test_document_change_does_not_require_tests(self):
        result = analyze(b"M\0docs/guide.md\0", ())
        self.assertEqual(result.signal, "no-source-change")
        self.assertEqual(result.source_changes, ())

    def test_deleted_test_counts_as_test_change(self):
        result = analyze(
            b"M\0src/auth.py\0D\0tests/test_auth.py\0",
            (),
        )
        self.assertEqual(result.signal, "tests-changed")
        self.assertEqual(result.test_changes, ("tests/test_auth.py",))

    def test_discovery_uses_paths_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_safe.py").write_text("ignored contents", encoding="utf-8")

            external = Path(outside) / "test_external.py"
            external.write_text("ignored contents", encoding="utf-8")
            (root / "linked-tests").symlink_to(Path(outside), target_is_directory=True)

            self.assertEqual(discover_test_files(root), ("tests/test_safe.py",))

    def test_report_escapes_repository_paths(self):
        raw_path = "src/<tag>|module.py"
        result = analyze(
            b"M\0" + raw_path.encode() + b"\0",
            (),
        )
        output = format_report(result)
        self.assertNotIn(raw_path, output)
        self.assertIn("src/\\<tag\\>\\|module.py", output)

    def test_unrelated_test_is_not_suggested(self):
        result = analyze(
            b"M\0src/auth.py\0",
            ("tests/test_payment.py",),
        )
        self.assertEqual(result.impacts[0].candidates, ())


if __name__ == "__main__":
    unittest.main()
