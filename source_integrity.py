#!/usr/bin/env python3
"""Detect review-hostile invisible Unicode and control characters without executing code."""

from __future__ import annotations

import argparse
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_PATH_LIST_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_CHANGED_FILES = 5000
MAX_FINDINGS = 200

BIDI_CONTROLS = {
    0x202A,  # LRE
    0x202B,  # RLE
    0x202C,  # PDF
    0x202D,  # LRO
    0x202E,  # RLO
    0x2066,  # LRI
    0x2067,  # RLI
    0x2068,  # FSI
    0x2069,  # PDI
}
ZERO_WIDTH_CONTROLS = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
}
DOC_SUFFIXES = {".md", ".markdown", ".rst", ".adoc", ".txt"}
TEXT_SUFFIXES = {
    ".bash",
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".env",
    ".go",
    ".gradle",
    ".graphql",
    ".groovy",
    ".h",
    ".hcl",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".md",
    ".markdown",
    ".php",
    ".properties",
    ".proto",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".rst",
    ".scss",
    ".sh",
    ".sql",
    ".svelte",
    ".swift",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}
TEXT_NAMES = {
    "dockerfile",
    "gemfile",
    "go.mod",
    "go.sum",
    "go.work",
    "makefile",
    "pipfile",
    "procfile",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    path: str
    line: int | None = None


def _safe_path(path: str) -> str:
    escaped = path.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    for old, new in (("`", "\\`"), ("<", "\\<"), (">", "\\>"), ("|", "\\|")):
        escaped = escaped.replace(old, new)
    return escaped[:240] + ("..." if len(escaped) > 240 else "")


def _read_limited(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file exceeds inspection limit")
    return data


def read_changed_paths(path: Path) -> tuple[str, ...]:
    data = _read_limited(path, MAX_PATH_LIST_BYTES)
    values: list[str] = []
    for raw in data.split(b"\0"):
        if not raw:
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("changed path is not UTF-8") from exc
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError("unsafe changed path metadata")
        values.append(value)
    if len(values) > MAX_CHANGED_FILES:
        raise ValueError("changed file count exceeds inspection limit")
    return tuple(values)


def _is_noncharacter(codepoint: int) -> bool:
    return 0xFDD0 <= codepoint <= 0xFDEF or (codepoint & 0xFFFF) in {0xFFFE, 0xFFFF}


def _is_text_hint(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix.lower() in TEXT_SUFFIXES or pure.name.lower() in TEXT_NAMES


def _is_document(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in DOC_SUFFIXES


def _path_findings(path: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for char in path:
        codepoint = ord(char)
        category: str | None = None
        if codepoint in BIDI_CONTROLS:
            category = "unicode-bidi-control-in-path"
        elif codepoint in ZERO_WIDTH_CONTROLS or unicodedata.category(char) == "Cf":
            category = "invisible-format-control-in-path"
        elif unicodedata.category(char) in {"Cc", "Cs"} or _is_noncharacter(codepoint):
            category = "invalid-control-character-in-path"
        if category and category not in seen:
            findings.append(Finding("block", category, path))
            seen.add(category)
    return findings


def _content_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    line = 1
    document = _is_document(path)

    for index, char in enumerate(text):
        codepoint = ord(char)
        category: str | None = None
        severity = "block"

        if codepoint in BIDI_CONTROLS:
            category = "unicode-bidi-control"
        elif codepoint in ZERO_WIDTH_CONTROLS:
            if codepoint == 0xFEFF and index == 0:
                category = None
            else:
                category = "zero-width-character"
                severity = "warn" if document else "block"
        elif unicodedata.category(char) == "Cf":
            category = "unicode-format-control"
            severity = "warn" if document else "block"
        elif (unicodedata.category(char) == "Cc" and char not in {"\t", "\n", "\r"}) or _is_noncharacter(codepoint):
            category = "unexpected-control-character"

        if category and category not in seen:
            findings.append(Finding(severity, category, path, line))
            seen.add(category)

        if char == "\n":
            line += 1

    return findings


def _resolve_changed_file(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError("unsafe repository path")
    candidate = root.joinpath(*pure.parts)
    root_real = root.resolve()
    candidate_real = candidate.resolve(strict=False)
    if os.path.commonpath((str(root_real), str(candidate_real))) != str(root_real):
        raise ValueError("changed file escapes repository root")
    return candidate


def scan(root: Path, changed_paths: tuple[str, ...]) -> tuple[Finding, ...]:
    root = root.resolve()
    findings: list[Finding] = []

    for relative in changed_paths:
        findings.extend(_path_findings(relative))
        if len(findings) >= MAX_FINDINGS:
            break

        try:
            candidate = _resolve_changed_file(root, relative)
        except ValueError:
            findings.append(Finding("block", "unsafe-changed-path", relative))
            continue

        if not candidate.exists():
            continue
        if candidate.is_symlink():
            findings.append(Finding("block", "changed-symlink-not-inspected", relative))
            continue
        if not candidate.is_file():
            continue

        try:
            raw = _read_limited(candidate, MAX_FILE_BYTES)
        except (OSError, ValueError):
            if _is_text_hint(relative):
                findings.append(Finding("block", "text-file-unreadable-or-too-large", relative))
            continue

        if b"\x00" in raw[:8192]:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if _is_text_hint(relative):
                findings.append(Finding("block", "non-utf8-text-file", relative))
            continue

        findings.extend(_content_findings(relative, text))
        if len(findings) >= MAX_FINDINGS:
            break

    unique = {(item.severity, item.category, item.path, item.line): item for item in findings}
    ordered = sorted(
        unique.values(),
        key=lambda item: (0 if item.severity == "block" else 1, item.path, item.line or 0, item.category),
    )
    return tuple(ordered[:MAX_FINDINGS])


def format_report(findings: tuple[Finding, ...]) -> str:
    blocks = sum(item.severity == "block" for item in findings)
    warnings = sum(item.severity == "warn" for item in findings)
    lines = [
        "# Source integrity",
        f"- Blocking findings: {blocks}",
        f"- Warnings: {warnings}",
    ]
    if not findings:
        lines.append("- Findings: none")
        return "\n".join(lines)

    lines.append("- Findings:")
    for item in findings:
        location = _safe_path(item.path)
        if item.line is not None:
            location += f":{item.line}"
        lines.append(f"  - {item.severity.upper()} {item.category} ({location})")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect invisible Unicode and control characters in changed files.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--paths", required=True, help="NUL-delimited changed-path file")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when a blocking finding exists")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print("BLOCK: repository root must be a directory.")
        return 2
    try:
        changed_paths = read_changed_paths(Path(args.paths))
        findings = scan(root, changed_paths)
    except (OSError, ValueError):
        print("BLOCK: unable to inspect source integrity.")
        return 2

    print(format_report(findings))
    if args.strict and any(item.severity == "block" for item in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
