import tempfile
import unittest
from pathlib import Path

from dependency_guard import format_report, read_tracked_paths, scan


class DependencyGuardTest(unittest.TestCase):
    def _scan_files(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return scan(root, tuple(files))

    def test_normal_npm_dependencies_with_lockfile_are_allowed(self):
        findings = self._scan_files(
            {
                "package.json": '{"dependencies":{"example":"^1.2.3"}}',
                "package-lock.json": "{}",
            }
        )
        self.assertEqual(findings, ())

    def test_remote_npm_dependency_is_blocked_without_echoing_value(self):
        remote = "git+https://example.invalid/example/repo.git"
        findings = self._scan_files({"package.json": '{"dependencies":{"example":"' + remote + '"}}'})
        categories = {item.category for item in findings if item.severity == "block"}
        self.assertIn("direct-remote-dependency", categories)
        self.assertNotIn(remote, format_report(findings))

    def test_npm_install_hook_and_missing_lock_are_warnings(self):
        findings = self._scan_files(
            {"package.json": '{"dependencies":{"example":"1.2.3"},"scripts":{"postinstall":"node setup.js"}}'}
        )
        categories = {item.category for item in findings}
        self.assertIn("install-lifecycle-script", categories)
        self.assertIn("package-manifest-without-lockfile", categories)
        self.assertFalse(any(item.severity == "block" for item in findings))

    def test_requirements_custom_index_and_remote_dependency_are_blocked(self):
        findings = self._scan_files(
            {
                "requirements.txt": "--extra-index-url https://example.invalid/simple\n"
                "example @ https://example.invalid/example.whl\n"
            }
        )
        categories = {item.category for item in findings if item.severity == "block"}
        self.assertIn("custom-or-insecure-package-index", categories)
        self.assertIn("direct-remote-dependency", categories)

    def test_unbounded_requirement_is_warning(self):
        findings = self._scan_files({"requirements-dev.txt": "example\n"})
        self.assertEqual(findings[0].severity, "warn")
        self.assertEqual(findings[0].category, "unbounded-dependency-version")

    def test_pyproject_direct_url_is_blocked(self):
        findings = self._scan_files(
            {"pyproject.toml": '[project]\ndependencies = ["example @ https://example.invalid/example.whl"]\n'}
        )
        self.assertIn("direct-remote-dependency", {item.category for item in findings})

    def test_poetry_outside_path_is_blocked(self):
        findings = self._scan_files(
            {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.12"\nexample = { path = "../example" }\n'}
        )
        self.assertIn("outside-repository-dependency", {item.category for item in findings})

    def test_cargo_git_and_outside_path_are_blocked(self):
        findings = self._scan_files(
            {
                "Cargo.toml": '[dependencies]\nremote = { git = "https://example.invalid/repo.git" }\n'
                'local = { path = "../local" }\n'
            }
        )
        categories = {item.category for item in findings if item.severity == "block"}
        self.assertIn("alternate-dependency-source", categories)
        self.assertIn("outside-repository-dependency", categories)

    def test_go_local_replace_is_classified_by_boundary(self):
        inside = self._scan_files({"go.mod": "module example.invalid/app\nreplace example.invalid/lib => ./lib\n"})
        outside = self._scan_files({"go.mod": "module example.invalid/app\nreplace example.invalid/lib => ../lib\n"})
        self.assertIn("local-path-dependency", {item.category for item in inside})
        self.assertFalse(any(item.severity == "block" for item in inside))
        self.assertIn("outside-repository-dependency", {item.category for item in outside})

    def test_manifest_symlink_is_blocked_without_following_it(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            target = Path(outside) / "package.json"
            target.write_text('{"dependencies":{"example":"1.0.0"}}', encoding="utf-8")
            (root / "package.json").symlink_to(target)
            findings = scan(root, ("package.json",))
            self.assertIn("manifest-unreadable-or-unsafe", {item.category for item in findings})

    def test_tracked_path_metadata_rejects_parent_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "paths"
            path.write_bytes(b"../package.json\0")
            with self.assertRaises(ValueError):
                read_tracked_paths(path)

    def test_report_escapes_path_and_never_prints_manifest_content(self):
        findings = self._scan_files({"nested/<unsafe>|package.json": '{"dependencies":{"example":"*"}}'})
        report = format_report(findings)
        self.assertIn("nested/\\<unsafe\\>\\|package.json", report)
        self.assertNotIn('"example":"*"', report)


if __name__ == "__main__":
    unittest.main()
