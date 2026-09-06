#!/usr/bin/env python3
"""Score pull-request changes without executing repository code.

The scorer consumes Git-generated metadata and patch text. Reports contain only
risk categories and escaped file paths; added source lines are never echoed.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

LEVELS = ("low", "medium", "high", "critical")
MAX_NAMES_BYTES = 1024 * 1024
MAX_PATCH_BYTES = 8 * 1024 * 1024
VALID_STATUSES = {"A", "B", "C", "D", "M", "R", "T", "U", "X"}

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "requirements.txt",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
}
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
SECURITY_WORDS = ("auth", "credential", "permission", "secret", "security", "token")
INFRA_WORDS = ("deploy", "dockerfile", "k8s", "kubernetes", "terraform", "cloudformation")

CONTENT_RULES: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    (
        "pull-request-target-event",
        55,
        re.compile(r"(?i)\bon\s*:\s*(?:\[[^\]]*\bpull_request_target\b|\{[^}]*\bpull_request_target\b)"),
    ),
    (
        "write-permission-added",
        45,
        re.compile(r"(?i)\b(?:permissions\s*:\s*write-all|[A-Za-z0-9_-]+\s*:\s*write\b)"),
    ),
    (
        "secret-context-added",
        35,
        re.compile(r"\$\{\{\s*secrets(?:\s*\.|\s*\[)"),
    ),
    (
        "download-and-execute-added",
        55,
        re.compile(r"(?i)\b(?:curl|wget)\b[^|'\"\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b"),
    ),
    ("shell-true-added", 45, re.compile(r"\bshell\s*=\s*True\b")),
    (
        "tls-verification-disabled",
        35,
        re.compile(r"(?i)(?:\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|\bcurl\s+-[^\s]*k)"),
    ),
)


@dataclass(frozen=True)
class Change:
    status: str
    path: str
    previous_path: str | None = None


@dataclass(frozen=True)
class Finding:
    category: str
    points: int
    path: str | None = None


@dataclass(frozen=True)
class Result:
    score: int
    level: str
    changed_files: int
    added_lines: int
    deleted_lines: int
    findings: tuple[Finding, ...]


def _decode_path(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


def parse_name_status(data: bytes) -> list[Change]:
    """Parse `git diff --name-status -z` output and reject malformed metadata."""
    fields = data.split(b"\0")
    changes: list[Change] = []
    index = 0

    while index < len(fields):
        raw_status = fields[index]
        index += 1
        if not raw_status:
            continue

        status_text = raw_status.decode("ascii", errors="replace")
        status = status_text[:1]
        if status not in VALID_STATUSES:
            raise ValueError("unknown change status")

        if status in {"R", "C"}:
            if index + 1 >= len(fields):
                raise ValueError("truncated rename/copy entry")
            old_raw = fields[index]
            new_raw = fields[index + 1]
            index += 2
            if not old_raw or not new_raw:
                raise ValueError("empty rename/copy path")
            changes.append(Change(status, _decode_path(new_raw), _decode_path(old_raw)))
            continue

        if index >= len(fields):
            raise ValueError("truncated name-status entry")
        path_raw = fields[index]
        index += 1
        if not path_raw:
            raise ValueError("empty change path")
        changes.append(Change(status, _decode_path(path_raw)))

    return changes


def _safe_path(path: str) -> str:
    """Escape control/markup characters before showing a repository path in CI logs."""
    escaped = path.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    for old, new in (("`", "\\`"), ("<", "\\<"), (">", "\\>"), ("|", "\\|")):
        escaped = escaped.replace(old, new)
    return escaped[:240] + ("..." if len(escaped) > 240 else "")


def _is_dependency_path(path: str) -> bool:
    name = Path(path).name.lower()
    return name in DEPENDENCY_FILES or name.startswith("requirements-") and name.endswith(".txt")


def _is_test_path(path: str) -> bool:
    lowered = path.lower()
    name = Path(lowered).name
    return (
        "/test/" in f"/{lowered}/"
        or "/tests/" in f"/{lowered}/"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _path_findings(change: Change) -> list[Finding]:
    path = change.path
    lowered = path.lower()
    name = Path(lowered).name
    findings: list[Finding] = []

    if lowered.startswith(".github/workflows/"):
        findings.append(Finding("workflow-change", 30, path))
    if lowered.startswith(".github/actions/"):
        findings.append(Finding("local-action-change", 25, path))
    if _is_dependency_path(path):
        findings.append(Finding("dependency-change", 20, path))
    if Path(lowered).suffix in SCRIPT_SUFFIXES:
        findings.append(Finding("script-change", 15, path))
    if any(word in lowered for word in SECURITY_WORDS):
        findings.append(Finding("security-sensitive-path", 15, path))
    if any(word in lowered or word == name for word in INFRA_WORDS):
        findings.append(Finding("infrastructure-change", 20, path))
    if change.status == "D" and _is_test_path(path):
        findings.append(Finding("test-deletion", 30, path))
    elif change.status == "D":
        findings.append(Finding("file-deletion", 5, path))

    return findings


def _patch_metrics(patch: str) -> tuple[int, int, list[Finding]]:
    added = 0
    deleted = 0
    categories: set[str] = set()
    findings: list[Finding] = []

    for line in patch.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        if line.startswith("+"):
            added += 1
            content = line[1:]
            for category, points, pattern in CONTENT_RULES:
                if category not in categories and pattern.search(content):
                    categories.add(category)
                    findings.append(Finding(category, points))
        elif line.startswith("-"):
            deleted += 1

    volume = added + deleted
    if volume >= 1000:
        findings.append(Finding("very-large-change", 20))
    elif volume >= 300:
        findings.append(Finding("large-change", 10))
    elif volume >= 100:
        findings.append(Finding("moderate-change", 5))

    return added, deleted, findings


def _level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _collapse_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    """Charge each risk category once, using one representative path for the report."""
    grouped: dict[str, Finding] = {}
    for item in findings:
        current = grouped.get(item.category)
        if current is None:
            grouped[item.category] = item
            continue

        # Category weights are fixed; keep the highest defensively and the smallest
        # path for deterministic, non-inflating reports.
        points = max(current.points, item.points)
        paths = [path for path in (current.path, item.path) if path is not None]
        representative = min(paths) if paths else None
        grouped[item.category] = Finding(item.category, points, representative)

    return tuple(
        sorted(grouped.values(), key=lambda item: (-item.points, item.category, item.path or ""))
    )


def analyze(name_status: bytes, patch: str) -> Result:
    changes = parse_name_status(name_status)
    findings: list[Finding] = []
    for change in changes:
        findings.extend(_path_findings(change))

    added, deleted, patch_findings = _patch_metrics(patch)
    findings.extend(patch_findings)

    ordered = _collapse_findings(findings)
    score = sum(item.points for item in ordered)

    return Result(
        score=score,
        level=_level(score),
        changed_files=len(changes),
        added_lines=added,
        deleted_lines=deleted,
        findings=ordered,
    )


def format_report(result: Result) -> str:
    lines = [
        "# Change risk",
        f"- Level: {result.level.upper()}",
        f"- Score: {result.score}",
        f"- Changed files: {result.changed_files}",
        f"- Lines: +{result.added_lines} / -{result.deleted_lines}",
    ]
    if not result.findings:
        lines.append("- Findings: none")
        return "\n".join(lines)

    lines.append("- Findings:")
    for finding in result.findings:
        location = f" ({_safe_path(finding.path)})" if finding.path else ""
        lines.append(f"  - +{finding.points} {finding.category}{location}")
    return "\n".join(lines)


def _read_limited(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds size limit")
    return data


def load_inputs(
    names_path: Path,
    patch_path: Path,
    max_names_bytes: int = MAX_NAMES_BYTES,
    max_patch_bytes: int = MAX_PATCH_BYTES,
) -> tuple[bytes, str]:
    """Read bounded scanner inputs so a huge PR cannot consume unbounded memory."""
    names = _read_limited(names_path, max_names_bytes)
    patch_bytes = _read_limited(patch_path, max_patch_bytes)
    return names, patch_bytes.decode("utf-8", errors="replace")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score the risk of a Git diff without executing it.")
    parser.add_argument("--names", required=True, help="File containing `git diff --name-status -z` output.")
    parser.add_argument("--patch", required=True, help="File containing a unified Git diff.")
    parser.add_argument(
        "--fail-level",
        choices=("none", "high", "critical"),
        default="critical",
        help="Exit 1 at or above this risk level. Default: critical.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        name_status, patch = load_inputs(Path(args.names), Path(args.patch))
        result = analyze(name_status, patch)
    except (OSError, ValueError) as exc:
        print(f"BLOCK: unable to score change metadata ({type(exc).__name__}).")
        return 2

    print(format_report(result))
    if args.fail_level == "none":
        return 0
    return 1 if LEVELS.index(result.level) >= LEVELS.index(args.fail_level) else 0


if __name__ == "__main__":
    raise SystemExit(main())
