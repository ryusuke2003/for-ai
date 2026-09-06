#!/usr/bin/env python3
"""Static security guard for GitHub Actions workflows.

The guard never executes workflow content. It reports only file names, line numbers,
and finding categories so CI logs do not unnecessarily echo sensitive configuration.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

WORKFLOW_SUFFIXES = {".yml", ".yaml"}
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)")
WRITE_PERMISSION = re.compile(
    r"^\s*['\"]?[A-Za-z0-9_-]+['\"]?\s*:\s*write\s*(?:#.*)?$"
)
WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\s*(?:#.*)?$")
INLINE_WRITE_PERMISSION = re.compile(
    r"^\s*permissions\s*:\s*\{[^}\n]*['\"]?[A-Za-z0-9_-]+['\"]?\s*:\s*write\b"
)
PULL_REQUEST_TARGET_KEY = re.compile(r"^\s*['\"]?pull_request_target['\"]?\s*:")
PULL_REQUEST_TARGET_INLINE_LIST = re.compile(
    r"^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b"
)
PULL_REQUEST_TARGET_INLINE_MAP = re.compile(
    r"^\s*on\s*:\s*\{[^}\n]*['\"]?pull_request_target['\"]?\s*:"
)
SECRET_REFERENCE = re.compile(r"\$\{\{\s*secrets(?:\.|\s*\[)")
DOWNLOAD_AND_EXECUTE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    category: str


def _workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(
        path
        for path in workflow_dir.iterdir()
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def _checkout_has_safe_credentials(lines: list[str], uses_index: int) -> bool:
    """Require persist-credentials: false in the same checkout step."""
    uses_indent = len(lines[uses_index]) - len(lines[uses_index].lstrip())
    for line in lines[uses_index + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        if indent <= uses_indent and stripped.startswith("-"):
            break
        if indent <= uses_indent and re.match(r"(?:uses|run|name)\s*:", stripped):
            break
        if re.match(r"persist-credentials\s*:\s*false\s*(?:#.*)?$", stripped):
            return True
    return False


def _has_pull_request_target(line: str) -> bool:
    return bool(
        PULL_REQUEST_TARGET_KEY.match(line)
        or PULL_REQUEST_TARGET_INLINE_LIST.match(line)
        or PULL_REQUEST_TARGET_INLINE_MAP.match(line)
    )


def scan_workflow(path: Path, root: Path) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [Finding(relative, 0, "unreadable-workflow")]

    lines = text.splitlines()
    findings: list[Finding] = []
    has_permissions = False

    for index, line in enumerate(lines):
        line_number = index + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^\s*permissions\s*:", line):
            has_permissions = True
        if WRITE_ALL.match(line) or WRITE_PERMISSION.match(line) or INLINE_WRITE_PERMISSION.match(line):
            findings.append(Finding(relative, line_number, "write-permission"))
        if _has_pull_request_target(line):
            findings.append(Finding(relative, line_number, "pull-request-target"))
        if SECRET_REFERENCE.search(line):
            findings.append(Finding(relative, line_number, "secret-reference"))
        if DOWNLOAD_AND_EXECUTE.search(line):
            findings.append(Finding(relative, line_number, "download-and-execute"))
        if re.search(r"(?i)(?:^|\s)sudo(?:\s|$)", line):
            findings.append(Finding(relative, line_number, "sudo-command"))
        if re.search(r"\bchmod\s+(?:-R\s+)?777\b", line):
            findings.append(Finding(relative, line_number, "world-writable-permission"))

        match = USES_LINE.match(line)
        if not match:
            continue

        target = match.group(1).strip("'\"")
        if target.startswith("./"):
            continue
        if "@" not in target:
            findings.append(Finding(relative, line_number, "action-without-ref"))
            continue

        action, ref = target.rsplit("@", 1)
        if not FULL_SHA.fullmatch(ref):
            findings.append(Finding(relative, line_number, "unpinned-action"))

        if action == "actions/checkout" and not _checkout_has_safe_credentials(lines, index):
            findings.append(Finding(relative, line_number, "checkout-persists-credentials"))

    if not has_permissions:
        findings.append(Finding(relative, 0, "missing-explicit-permissions"))

    return sorted(set(findings))


def scan_repository(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for path in _workflow_files(root):
        findings.extend(scan_workflow(path, root))
    return sorted(set(findings))


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "OK: workflow security guard found no blocking issues."

    lines = [f"BLOCK: {len(findings)} workflow security finding(s)."]
    for finding in findings:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(f"- {location} [{finding.category}]")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Statically inspect GitHub Actions workflows.")
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.path)
    if not root.is_dir():
        print("BLOCK: scan target must be a directory.")
        return 2

    findings = scan_repository(root)
    print(format_findings(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
