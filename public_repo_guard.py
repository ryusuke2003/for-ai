#!/usr/bin/env python3
"""Fail closed on common secret/privacy mistakes before they reach a public repo.

The guard intentionally never prints matched values. CI logs should contain only the
file, line number, and finding category so that a discovered secret is not copied
into another public surface.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
SAFE_ENV_FILENAMES = {".env.example", ".env.sample", ".env.template"}
RISKY_FILENAMES = {
    ".env",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "id_ed25519",
    "id_rsa",
}
RISKY_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    (
        "github-fine-grained-token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    ("sk-prefixed-token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    (
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "authorization-bearer-token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}"),
    ),
    (
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(?:"
            r"api[_-]?key|"
            r"aws[_-]?secret[_-]?access[_-]?key|"
            r"client[_-]?secret|"
            r"private[_-]?key|"
            r"secret|"
            r"secret[_-]?access[_-]?key|"
            r"token|"
            r"access[_-]?token|"
            r"password"
            r")\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
    (
        "email-address",
        re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone-number",
        re.compile(r"(?<!\d)0\d{1,4}-\d{1,4}-\d{3,4}(?!\d)"),
    ),
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    category: str


def _is_risky_filename(path: Path) -> bool:
    name = path.name.lower()
    if name in SAFE_ENV_FILENAMES:
        return False
    return name in RISKY_FILENAMES or path.suffix.lower() in RISKY_SUFFIXES


def _iter_files(root: Path):
    """Walk without following symlinks or known generated/dependency directories."""
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in dirs
            if name not in SKIP_DIRS and not (current_path / name).is_symlink()
        ]
        for name in files:
            path = current_path / name
            if not path.is_symlink():
                yield path


def scan_file(path: Path, root: Path, max_file_bytes: int = MAX_FILE_BYTES) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []

    if _is_risky_filename(path):
        findings.append(Finding(relative, 0, "risky-filename"))

    try:
        size = path.stat().st_size
    except OSError:
        findings.append(Finding(relative, 0, "unreadable-file"))
        return findings

    if size > max_file_bytes:
        findings.append(Finding(relative, 0, "unscanned-large-file"))
        return findings

    try:
        data = path.read_bytes()
    except OSError:
        findings.append(Finding(relative, 0, "unreadable-file"))
        return findings

    if b"\x00" in data:
        findings.append(Finding(relative, 0, "unscanned-binary-file"))
        return findings

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(Finding(relative, 0, "unscanned-non-utf8-file"))
        return findings

    for line_number, line in enumerate(text.splitlines(), start=1):
        for category, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(Finding(relative, line_number, category))

    return findings


def scan_repository(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for path in _iter_files(root):
        findings.extend(scan_file(path, root))
    return sorted(set(findings))


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "OK: public repository guard found no blocking issues."

    lines = [f"BLOCK: {len(findings)} finding(s). Matched values are intentionally hidden."]
    for finding in findings:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(f"- {location} [{finding.category}]")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect common secrets and personal data before publishing a repository."
    )
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
