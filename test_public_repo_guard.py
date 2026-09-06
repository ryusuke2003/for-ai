import tempfile
import unittest
from pathlib import Path

from public_repo_guard import format_findings, scan_file, scan_repository


class PublicRepoGuardTest(unittest.TestCase):
    def test_clean_repository_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text("public sample only\n", encoding="utf-8")
            self.assertEqual(scan_repository(root), [])

    def test_detects_secret_without_echoing_matched_value(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "gh" + "p_" + "A" * 30
            (root / "config.txt").write_text(secret, encoding="utf-8")

            findings = scan_repository(root)
            output = format_findings(findings)

            self.assertTrue(any(item.category == "github-token" for item in findings))
            self.assertNotIn(secret, output)

    def test_detects_fine_grained_github_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "github" + "_pat_" + "A" * 30
            (root / "config.txt").write_text(secret, encoding="utf-8")

            findings = scan_repository(root)
            self.assertTrue(
                any(item.category == "github-fine-grained-token" for item in findings)
            )

    def test_detects_generic_secret_assignment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            value = "A" * 24
            (root / "config.txt").write_text("password = " + value, encoding="utf-8")

            findings = scan_repository(root)
            self.assertTrue(
                any(item.category == "generic-secret-assignment" for item in findings)
            )

    def test_detects_aws_secret_assignment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            value = "A" * 40
            content = "AWS" + "_SECRET_ACCESS_KEY=" + value
            (root / "config.txt").write_text(content, encoding="utf-8")

            findings = scan_repository(root)
            self.assertTrue(
                any(item.category == "generic-secret-assignment" for item in findings)
            )

    def test_detects_email_without_echoing_address(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            address = "user" + "@" + "example.com"
            (root / "note.txt").write_text(address, encoding="utf-8")

            findings = scan_repository(root)
            output = format_findings(findings)

            self.assertTrue(any(item.category == "email-address" for item in findings))
            self.assertNotIn(address, output)

    def test_detects_phone_number(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            number = "090" + "-" + "1234" + "-" + "5678"
            (root / "note.txt").write_text(number, encoding="utf-8")

            findings = scan_repository(root)
            self.assertTrue(any(item.category == "phone-number" for item in findings))

    def test_risky_filename_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".env").write_text("placeholder\n", encoding="utf-8")

            findings = scan_repository(root)
            self.assertTrue(any(item.category == "risky-filename" for item in findings))

    def test_large_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "large.txt"
            path.write_text("0123456789", encoding="utf-8")

            findings = scan_file(path, root, max_file_bytes=5)
            self.assertIn("unscanned-large-file", {item.category for item in findings})

    def test_binary_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "blob.bin").write_bytes(b"abc\x00def")

            findings = scan_repository(root)
            self.assertTrue(
                any(item.category == "unscanned-binary-file" for item in findings)
            )

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            outside_file = Path(outside) / "outside.txt"
            outside_file.write_text("gh" + "p_" + "A" * 30, encoding="utf-8")
            (root / "link.txt").symlink_to(outside_file)

            self.assertEqual(scan_repository(root), [])


if __name__ == "__main__":
    unittest.main()
