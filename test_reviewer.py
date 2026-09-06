import unittest

from reviewer import format_report, review_text, split_sentences


class ReviewerTest(unittest.TestCase):
    def test_split_sentences_handles_japanese_and_newlines(self):
        text = "これは一文です。\nこれは二文です！\n最後です"
        self.assertEqual(split_sentences(text), ["これは一文です。", "これは二文です！", "最後です"])

    def test_review_detects_duplicates_vagueness_and_placeholders(self):
        text = "たぶん動きます。\nTODO: 要確認です。\nたぶん動きます。"
        report = review_text(text)

        self.assertEqual(report["characters"], len(text))
        self.assertEqual(report["sentences"], 3)
        self.assertEqual(report["duplicate_sentences"], ["たぶん動きます。"])
        self.assertIn("たぶん", report["vague_patterns"])
        self.assertIn("TODO", report["placeholders"])
        self.assertIn("要確認", report["placeholders"])

    def test_clean_text_has_no_findings(self):
        report = review_text("結論です。根拠を示します。")
        self.assertEqual(report["duplicate_sentences"], [])
        self.assertEqual(report["vague_patterns"], [])
        self.assertEqual(report["placeholders"], [])

    def test_format_report_is_readable(self):
        report = review_text("probably fine.\nprobably fine.")
        output = format_report(report)
        self.assertIn("# Self review", output)
        self.assertIn("Duplicate sentences: 1", output)
        self.assertIn("Vague expressions: 1", output)


if __name__ == "__main__":
    unittest.main()
