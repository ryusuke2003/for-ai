#!/usr/bin/env python3
"""Tiny self-review CLI for AI-generated text."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

VAGUE_PATTERNS = [
    r"\bmaybe\b",
    r"\bprobably\b",
    r"\bsomehow\b",
    r"\betc\.?\b",
    r"たぶん",
    r"おそらく",
    r"なんとなく",
    r"などなど",
]
PLACEHOLDER_PATTERNS = [r"TODO", r"FIXME", r"TBD", r"XXX", r"要確認", r"仮置き"]


def split_sentences(text: str) -> list[str]:
    """Split Japanese/English prose even when punctuation has no trailing space."""
    parts = re.findall(r"[^。！？.!?\n]+[。！？.!?]?", text)
    return [part.strip() for part in parts if part.strip()]


def review_text(text: str) -> dict[str, object]:
    sentences = split_sentences(text)
    counts = Counter(sentences)
    duplicates = sorted(sentence for sentence, count in counts.items() if count > 1)

    vague_hits = sorted(
        {pattern for pattern in VAGUE_PATTERNS if re.search(pattern, text, re.IGNORECASE)}
    )
    placeholder_hits = sorted(
        {pattern for pattern in PLACEHOLDER_PATTERNS if re.search(pattern, text, re.IGNORECASE)}
    )

    return {
        "characters": len(text),
        "sentences": len(sentences),
        "duplicate_sentences": duplicates,
        "vague_patterns": vague_hits,
        "placeholders": placeholder_hits,
    }


def finding_count(report: dict[str, object]) -> int:
    return sum(
        len(report[key])
        for key in ("duplicate_sentences", "vague_patterns", "placeholders")
    )


def format_report(report: dict[str, object]) -> str:
    lines = [
        "# Self review",
        f"- Characters: {report['characters']}",
        f"- Sentences: {report['sentences']}",
        f"- Findings: {finding_count(report)}",
    ]

    for label, key in (
        ("Duplicate sentences", "duplicate_sentences"),
        ("Vague expressions", "vague_patterns"),
        ("Placeholders", "placeholders"),
    ):
        items = report[key]
        lines.append(f"- {label}: {len(items)}")
        for item in items:
            lines.append(f"  - {item}")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review text before an AI answer is shipped.")
    parser.add_argument("file", nargs="?", help="Text file to review. Reads stdin when omitted.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 when any finding is detected.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    text = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    report = review_text(text)
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else format_report(report))
    return 1 if args.strict and finding_count(report) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
