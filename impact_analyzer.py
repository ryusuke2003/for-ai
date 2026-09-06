#!/usr/bin/env python3
"""Summarize test impact from Git change metadata without reading source contents."""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path

from change_risk import parse_name_status

MAX_NAMES_BYTES = 1024 * 1024
MAX_DISCOVERED_FILES = 20_000
MAX_REPORTED_SOURCES = 20
MAX_CANDIDATES_PER_SOURCE = 3

SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}
SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}


@dataclass(frozen=True)
class Candidate:
    path: str
    score: int


@dataclass(frozen=True)
class SourceImpact:
    path: str
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True)
class Result:
    source_changes: tuple[str, ...]
    test_changes: tuple[str, ...]
    impacts: tuple[SourceImpact, ...]
    signal: str


def _safe_path(path: str) -> str:
    escaped = path.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    for old, new in (("`", "\\`"), ("<", "\\<"), (">", "\\>"), ("|", "\\|")):
        escaped = escaped.replace(old, new)
    return escaped[:240] + ("..." if len(escaped) > 240 else "")


def _is_test_path(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    name = Path(lowered).name
    return (
        "/test/" in f"/{lowered}/"
        or "/tests/" in f"/{lowered}/"
        or "/__tests__/" in f"/{lowered}/"
        or name.startswith("test_")
        or name.startswith("test-")
        or name.endswith("_test.py")
        or name.endswith("_test.go")
        or ".test." in name
        or ".spec." in name
    )


def _is_source_path(path: str) -> bool:
    return Path(path).suffix.lower() in SOURCE_SUFFIXES and not _is_test_path(path)


def _normalized_stem(path: str) -> str:
    name = Path(path).name.lower()
    for suffix in sorted(SOURCE_SUFFIXES, key=len, reverse=True):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    name = re.sub(r"(?:\.test|\.spec|_test|-test)$", "", name)
    name = re.sub(r"^(?:test_|test-)", "", name)
    return re.sub(r"[^a-z0-9]+", "", name)


def _shared_parent_component(source: str, test: str) -> bool:
    source_parts = {part.lower() for part in Path(source).parts[:-1] if len(part) >= 3}
    test_parts = {part.lower() for part in Path(test).parts[:-1] if len(part) >= 3}
    ignored = {"src", "lib", "app", "test", "tests", "__tests__"}
    return bool((source_parts - ignored) & (test_parts - ignored))


def _candidate_score(source: str, test: str) -> int:
    source_stem = _normalized_stem(source)
    test_stem = _normalized_stem(test)
    if not source_stem or not test_stem:
        return 0

    score = 0
    if source_stem == test_stem:
        score = 100
    elif min(len(source_stem), len(test_stem)) >= 4 and (
        source_stem in test_stem or test_stem in source_stem
    ):
        score = 60

    if score and _shared_parent_component(source, test):
        score += 10
    return score


def discover_test_files(root: Path) -> tuple[str, ...]:
    root = root.resolve()
    found: list[str] = []
    visited_files = 0

    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in SKIP_DIRS and not (current_path / name).is_symlink()
        )
        for name in sorted(files):
            visited_files += 1
            if visited_files > MAX_DISCOVERED_FILES:
                raise ValueError("repository file count exceeds discovery limit")
            path = current_path / name
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if _is_test_path(relative):
                found.append(relative)

    return tuple(found)


def analyze(name_status: bytes, test_files: tuple[str, ...]) -> Result:
    changes = parse_name_status(name_status)
    source_changes = tuple(
        sorted(change.path for change in changes if _is_source_path(change.path))
    )
    test_changes = tuple(
        sorted(change.path for change in changes if _is_test_path(change.path))
    )

    impacts: list[SourceImpact] = []
    for source in source_changes:
        candidates = [
            Candidate(path=test, score=_candidate_score(source, test))
            for test in test_files
        ]
        candidates = [candidate for candidate in candidates if candidate.score > 0]
        candidates.sort(key=lambda item: (-item.score, item.path))
        impacts.append(
            SourceImpact(
                path=source,
                candidates=tuple(candidates[:MAX_CANDIDATES_PER_SOURCE]),
            )
        )

    if not source_changes:
        signal = "no-source-change"
    elif test_changes:
        signal = "tests-changed"
    else:
        signal = "source-without-test-change"

    return Result(
        source_changes=source_changes,
        test_changes=test_changes,
        impacts=tuple(impacts),
        signal=signal,
    )


def format_report(result: Result) -> str:
    lines = [
        "# Test impact",
        f"- Signal: {result.signal}",
        f"- Source files changed: {len(result.source_changes)}",
        f"- Test files changed: {len(result.test_changes)}",
    ]

    if result.signal == "source-without-test-change":
        lines.append("- Review note: source changed but no test file changed")

    if not result.impacts:
        return "\n".join(lines)

    lines.append("- Suggested test review:")
    for impact in result.impacts[:MAX_REPORTED_SOURCES]:
        source = _safe_path(impact.path)
        if not impact.candidates:
            lines.append(f"  - {source}: no filename-based candidate")
            continue
        candidates = ", ".join(_safe_path(item.path) for item in impact.candidates)
        lines.append(f"  - {source}: {candidates}")

    remaining = len(result.impacts) - MAX_REPORTED_SOURCES
    if remaining > 0:
        lines.append(f"  - ... {remaining} more source file(s) omitted")
    return "\n".join(lines)


def _read_limited(path: Path, limit: int = MAX_NAMES_BYTES) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("change metadata exceeds size limit")
    return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize test impact from Git metadata without reading source contents."
    )
    parser.add_argument("--names", required=True, help="`git diff --name-status -z` output file")
    parser.add_argument("--root", default=".", help="Repository root used only to discover test paths")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print("BLOCK: repository root must be a directory.")
        return 2

    try:
        names = _read_limited(Path(args.names))
        test_files = discover_test_files(root)
        result = analyze(names, test_files)
    except (OSError, ValueError) as exc:
        print(f"BLOCK: unable to analyze test impact ({type(exc).__name__}).")
        return 2

    print(format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
