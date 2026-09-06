#!/usr/bin/env python3
"""Tiny self-review CLI for AI-generated text.

Reads text from a file or stdin and reports simple, deterministic signals that are
useful before sending an answer: length, vague expressions, repeated sentences,
and TODO-like placeholders.
"""

from __future__ import annotations

import argparse
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
    parts = re.split(r"(?<=[。！？.!?])\s+|\n+", text)
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


def format_report(report: dict[str, object]) -> str:
    lines = [
        "# Self review",
        f"- Characters: {report['characters']}",
        f"- Sentences: {report['sentences']}",
    ]

    duplicates = report["duplicate_sentences"]
    vague = report["vague_patterns"]
    placeholders = report["placeholders"]

    lines.append(f"- Duplicate sentences: {len(duplicates)}")
    for item in duplicates:
        lines.append(f"  - {item}")

    lines.append(f"- Vague expressions: {len(vague)}")
    for item in vague:
        lines.append(f"  - /{item}/")

    lines.append(f"- Placeholders: {len(placeholders)}")
    for item in placeholders:
        lines.append(f"  - /{item}/")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review text before an AI answer is shipped.")
    parser.add_argument("file", nargs="?", help="Text file to review. Reads stdin when omitted.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    text = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    print(format_report(review_text(text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
