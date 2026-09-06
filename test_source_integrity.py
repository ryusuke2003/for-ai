import tempfile
import unittest
from pathlib import Path

from source_integrity import format_report, read_changed_paths, scan


class SourceIntegrityTest(unittest.TestCase):
    def _scan_text(self, relative: str, content: str):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return scan(root, (relative,))

    def test_normal_source_is_allowed(self):
        findings = self._scan_text(
            "src/example.py",
            "message = 'こんにちは 🌊'\nprint(message)\n",
        )
        self.assertEqual(findings, ())

    def test_bidi_control_in_source_is_blocked(self):
        bidi = chr(0x202E)
        findings = self._scan_text("src/example.py", "value = 'safe" + bidi + "text'\n")
        self.assertIn("unicode-bidi-control", {item.category for item in findings if item.severity == "block"})

    def test_bidi_control_in_document_is_still_blocked(self):
        bidi = chr(0x2067)
        findings = self._scan_text("README.md", "visible" + bidi + "text\n")
        self.assertIn("unicode-bidi-control", {item.category for item in findings if item.severity == "block"})

    def test_zero_width_in_source_is_blocked(self):
        invisible = chr(0x200B)
        findings = self._scan_text("src/example.js", "const user" + invisible + "Id = 1;\n")
        self.assertIn("zero-width-character", {item.category for item in findings if item.severity == "block"})

    def test_zero_width_in_document_is_warning(self):
        invisible = chr(0x200D)
        findings = self._scan_text("notes.md", "emoji" + invisible + "sequence\n")
        matches = [item for item in findings if item.category == "zero-width-character"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "warn")

    def test_utf8_bom_at_start_is_allowed(self):
        findings = self._scan_text("config.toml", chr(0xFEFF) + "name = 'example'\n")
        self.assertEqual(findings, ())

    def test_utf8_bom_inside_source_is_blocked(self):
        findings = self._scan_text("config.toml", "name" + chr(0xFEFF) + " = 'example'\n")
        self.assertIn("zero-width-character", {item.category for item in findings if item.severity == "block"})

    def test_raw_control_character_is_blocked(self):
        findings = self._scan_text("src/example.py", "value = 'a" + chr(0x1B) + "b'\n")
        self.assertIn("unexpected-control-character", {item.category for item in findings if item.severity == "block"})

    def test_binary_file_is_not_treated_as_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "asset.bin"
            path.write_bytes(b"\x00\xff\x10" + chr(0x202E).encode("utf-8"))
            self.assertEqual(scan(root, ("asset.bin",)), ())

    def test_nul_in_known_text_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "script.py"
            path.write_bytes(b"print('safe')\n\x00hidden")
            findings = scan(root, ("script.py",))
            self.assertIn("binary-content-in-text-file", {item.category for item in findings})

    def test_env_variant_with_nul_is_blocked_as_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / ".env.production"
            path.write_bytes(b"KEY=value\n\x00hidden")
            findings = scan(root, (".env.production",))
            self.assertIn("binary-content-in-text-file", {item.category for item in findings})

    def test_codeowners_non_utf8_is_blocked_as_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "CODEOWNERS"
            path.write_bytes(b"* @team\n\xff")
            findings = scan(root, ("CODEOWNERS",))
            self.assertIn("non-utf8-text-file", {item.category for item in findings})

    def test_non_utf8_known_text_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "script.py"
            path.write_bytes(b"print('x')\n\xff")
            findings = scan(root, ("script.py",))
            self.assertIn("non-utf8-text-file", {item.category for item in findings})

    def test_symlink_is_blocked_without_following_target(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            target = Path(outside) / "target.py"
            target.write_text("print('outside')\n", encoding="utf-8")
            (root / "linked.py").symlink_to(target)
            findings = scan(root, ("linked.py",))
            self.assertIn("changed-symlink-not-inspected", {item.category for item in findings})

    def test_broken_symlink_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "broken.py").symlink_to(root / "missing.py")
            findings = scan(root, ("broken.py",))
            self.assertIn("changed-symlink-not-inspected", {item.category for item in findings})

    def test_invisible_character_in_path_is_blocked_without_opening_file(self):
        path = "src/user" + chr(0x200B) + "name.py"
        with tempfile.TemporaryDirectory() as temp:
            findings = scan(Path(temp), (path,))
            self.assertIn("invisible-format-control-in-path", {item.category for item in findings})

    def test_changed_path_metadata_rejects_parent_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "paths"
            path.write_bytes(b"../outside.py\0")
            with self.assertRaises(ValueError):
                read_changed_paths(path)

    def test_report_escapes_path_and_does_not_print_content(self):
        relative = "src/<unsafe>|example.py"
        secret_like_content = "do-not-print-this-value"
        findings = self._scan_text(relative, secret_like_content + chr(0x202E) + "\n")
        report = format_report(findings)
        self.assertIn("src/\\<unsafe\\>\\|example.py", report)
        self.assertNotIn(secret_like_content, report)


if __name__ == "__main__":
    unittest.main()
