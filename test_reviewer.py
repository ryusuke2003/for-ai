import unittest

from reviewer import finding_count, format_report, review_text, split_sentences


class ReviewerTest(unittest.TestCase):
    def test_split_sentences_handles_japanese_without_spaces(self):
        text = "これは一文です。これは二文です！最後です"
        self.assertEqual(split_sentences(text), ["これは一文です。", "これは二文です！", "最後です"])

    def test_split_sentences_handles_newlines(self):
        text = "first line\nsecond line"
        self.assertEqual(split_sentences(text), ["first line", "second line"])

    def test_review_detects_duplicates_vagueness_and_placeholders(self):
        text = "たぶん動きます。TODO: 要確認です。たぶん動きます。"
        report = review_text(text)

        self.assertEqual(report["characters"], len(text))
        self.assertEqual(report["sentences"], 3)
        self.assertEqual(report["duplicate_sentences"], ["たぶん動きます。"])
        self.assertIn("たぶん", report["vague_patterns"])
        self.assertIn("TODO", report["placeholders"])
        self.assertIn("要確認", report["placeholders"])
        self.assertEqual(finding_count(report), 4)

    def test_clean_text_has_no_findings(self):
        report = review_text("結論です。根拠を示します。")
        self.assertEqual(finding_count(report), 0)

    def test_format_report_is_readable(self):
        report = review_text("probably fine. probably fine.")
        output = format_report(report)
        self.assertIn("# Self review", output)
        self.assertIn("Findings: 2", output)
        self.assertIn("Duplicate sentences: 1", output)
        self.assertIn("Vague expressions: 1", output)


if __name__ == "__main__":
    unittest.main()
