#!/usr/bin/env python3
"""Statically review dependency manifests without installing or executing anything."""

from __future__ import annotations

import argparse
import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MAX_PATH_LIST_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_MANIFESTS = 200
SEVERITIES = {"warn": 1, "block": 2}

LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
INSTALL_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
REMOTE_PREFIXES = (
    "http://",
    "https://",
    "git://",
    "git+http://",
    "git+https://",
    "git+ssh://",
    "ssh://",
    "github:",
    "gitlab:",
    "bitbucket:",
)


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
        raise ValueError("input exceeds size limit")
    return data


def read_tracked_paths(path: Path) -> tuple[str, ...]:
    data = _read_limited(path, MAX_PATH_LIST_BYTES)
    result: list[str] = []
    for raw in data.split(b"\0"):
        if not raw:
            continue
        value = raw.decode("utf-8", errors="surrogateescape")
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError("unsafe repository path metadata")
        result.append(value)
    return tuple(result)


def _manifest_kind(path: str) -> str | None:
    name = PurePosixPath(path).name
    lower = name.lower()
    if lower == "package.json":
        return "npm"
    if lower == "pyproject.toml":
        return "pyproject"
    if lower == "cargo.toml":
        return "cargo"
    if lower == "go.mod":
        return "go"
    if re.fullmatch(r"requirements(?:[-_.][a-z0-9_-]+)?\.txt", lower):
        return "requirements"
    return None


def _manifest_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError("unsafe manifest path")
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise ValueError("manifest is a symlink")
    root_real = root.resolve()
    candidate_real = candidate.resolve(strict=False)
    if os.path.commonpath((str(root_real), str(candidate_real))) != str(root_real):
        raise ValueError("manifest escapes repository root")
    return candidate


def _is_remote(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith(REMOTE_PREFIXES) or bool(re.match(r"^[^\s@]+@[^\s:]+:", value.strip()))


def _local_ref_kind(value: str) -> str | None:
    raw = value.strip()
    lowered = raw.lower()
    for prefix in ("file:", "link:"):
        if lowered.startswith(prefix):
            raw = raw[len(prefix) :]
            break
    if raw.startswith("../") or raw == ".." or os.path.isabs(raw):
        return "outside"
    if raw.startswith("./") or raw == ".":
        return "inside"
    return None


def _npm_findings(path: str, text: str, tracked: set[str]) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [Finding("block", "manifest-parse-error", path)]
    if not isinstance(data, dict):
        return [Finding("block", "manifest-parse-error", path)]

    findings: list[Finding] = []
    has_dependencies = False
    for section in NPM_SECTIONS:
        dependencies = data.get(section)
        if not isinstance(dependencies, dict):
            continue
        if dependencies:
            has_dependencies = True
        for spec in dependencies.values():
            if not isinstance(spec, str):
                findings.append(Finding("block", "invalid-dependency-spec", path))
                continue
            stripped = spec.strip()
            if _is_remote(stripped):
                findings.append(Finding("block", "direct-remote-dependency", path))
            local_kind = _local_ref_kind(stripped)
            if local_kind == "outside":
                findings.append(Finding("block", "outside-repository-dependency", path))
            elif local_kind == "inside":
                findings.append(Finding("warn", "local-path-dependency", path))
            elif stripped.lower() in {"*", "latest"}:
                findings.append(Finding("warn", "floating-dependency-version", path))

    scripts = data.get("scripts")
    if isinstance(scripts, dict) and any(name in scripts for name in INSTALL_SCRIPTS):
        findings.append(Finding("warn", "install-lifecycle-script", path))

    if has_dependencies:
        parent = PurePosixPath(path).parent
        candidates = {str(parent / name) if str(parent) != "." else name for name in LOCKFILES}
        if not (candidates & tracked or LOCKFILES & tracked):
            findings.append(Finding("warn", "package-manifest-without-lockfile", path))
    return findings


def _python_requirement_findings(path: str, entries: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    operators = ("==", "~=", ">=", "<=", ">", "<", "!=", "===")
    for entry in entries:
        value = entry.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith(("--index-url", "--extra-index-url", "--trusted-host")):
            findings.append(Finding("block", "custom-or-insecure-package-index", path))
            continue
        if value.startswith("--find-links"):
            findings.append(Finding("warn", "alternate-package-source", path))
            continue
        if value.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            continue

        editable = value
        is_editable = editable.startswith("-e ") or editable.startswith("--editable ")
        if is_editable:
            editable = editable.split(maxsplit=1)[1] if " " in editable else ""
        elif value.startswith("-"):
            # Normal pip options such as --hash/--only-binary are not dependencies.
            continue

        if _is_remote(editable) or " @ http://" in editable.lower() or " @ https://" in editable.lower() or " @ git+" in editable.lower():
            findings.append(Finding("block", "direct-remote-dependency", path))
            continue
        local_kind = _local_ref_kind(editable)
        if local_kind == "outside":
            findings.append(Finding("block", "outside-repository-dependency", path))
            continue
        if local_kind == "inside":
            findings.append(Finding("warn", "local-path-dependency", path))
            continue

        package_part = re.split(r"\s*;\s*", value, maxsplit=1)[0]
        if package_part and not any(operator in package_part for operator in operators) and " @ " not in package_part:
            findings.append(Finding("warn", "unbounded-dependency-version", path))
    return findings


def _requirements_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line_findings = _python_requirement_findings(path, [line])
        findings.extend(Finding(item.severity, item.category, item.path, line_number) for item in line_findings)
    return findings


def _pyproject_findings(path: str, text: str) -> list[Finding]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [Finding("block", "manifest-parse-error", path)]

    findings: list[Finding] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        dependencies = project.get("dependencies", [])
        if isinstance(dependencies, list):
            findings.extend(_python_requirement_findings(path, [item for item in dependencies if isinstance(item, str)]))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    findings.extend(_python_requirement_findings(path, [item for item in values if isinstance(item, str)]))

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for section_name in ("dependencies", "group"):
            findings.extend(_poetry_table_findings(path, poetry.get(section_name, {})))
    return findings


def _poetry_table_findings(path: str, value: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(value, dict):
        return findings
    for key, spec in value.items():
        if key == "python":
            continue
        if isinstance(spec, str):
            if spec.strip() == "*":
                findings.append(Finding("warn", "floating-dependency-version", path))
        elif isinstance(spec, dict):
            if any(source in spec for source in ("git", "url")):
                findings.append(Finding("block", "direct-remote-dependency", path))
            if "path" in spec and isinstance(spec["path"], str):
                kind = _local_ref_kind(spec["path"])
                if kind == "outside":
                    findings.append(Finding("block", "outside-repository-dependency", path))
                else:
                    findings.append(Finding("warn", "local-path-dependency", path))
    nested = value.get("dependencies")
    if isinstance(nested, dict):
        findings.extend(_poetry_table_findings(path, nested))
    for group in value.values():
        if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
            findings.extend(_poetry_table_findings(path, group["dependencies"]))
    return findings


def _cargo_findings(path: str, text: str) -> list[Finding]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [Finding("block", "manifest-parse-error", path)]

    findings: list[Finding] = []

    def visit(node: Any, section: str = "") -> None:
        if not isinstance(node, dict):
            return
        dependency_section = section.lower() in {"dependencies", "dev-dependencies", "build-dependencies"}
        if dependency_section:
            for spec in node.values():
                if isinstance(spec, str) and spec.strip() == "*":
                    findings.append(Finding("warn", "floating-dependency-version", path))
                elif isinstance(spec, dict):
                    if "git" in spec or "registry" in spec:
                        findings.append(Finding("block", "alternate-dependency-source", path))
                    if isinstance(spec.get("path"), str):
                        kind = _local_ref_kind(spec["path"])
                        findings.append(
                            Finding(
                                "block" if kind == "outside" else "warn",
                                "outside-repository-dependency" if kind == "outside" else "local-path-dependency",
                                path,
                            )
                        )
                    if spec.get("version") == "*":
                        findings.append(Finding("warn", "floating-dependency-version", path))
        for key, child in node.items():
            if isinstance(child, dict):
                visit(child, key)

    visit(data)
    return findings


def _go_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line.startswith("replace ") or "=>" not in line:
            continue
        target = line.split("=>", 1)[1].strip().split()[0]
        kind = _local_ref_kind(target)
        if kind == "outside":
            findings.append(Finding("block", "outside-repository-dependency", path, line_number))
        elif kind == "inside":
            findings.append(Finding("warn", "local-path-dependency", path, line_number))
    return findings


def scan(root: Path, tracked_paths: tuple[str, ...]) -> tuple[Finding, ...]:
    root = root.resolve()
    tracked = set(tracked_paths)
    manifests = [(path, _manifest_kind(path)) for path in tracked_paths if _manifest_kind(path)]
    if len(manifests) > MAX_MANIFESTS:
        raise ValueError("manifest count exceeds limit")

    findings: list[Finding] = []
    for relative, kind in sorted(manifests):
        try:
            manifest = _manifest_path(root, relative)
            raw = _read_limited(manifest, MAX_MANIFEST_BYTES)
        except (OSError, ValueError):
            findings.append(Finding("block", "manifest-unreadable-or-unsafe", relative))
            continue
        text = raw.decode("utf-8", errors="replace")
        if kind == "npm":
            findings.extend(_npm_findings(relative, text, tracked))
        elif kind == "requirements":
            findings.extend(_requirements_findings(relative, text))
        elif kind == "pyproject":
            findings.extend(_pyproject_findings(relative, text))
        elif kind == "cargo":
            findings.extend(_cargo_findings(relative, text))
        elif kind == "go":
            findings.extend(_go_findings(relative, text))

    unique = {(item.severity, item.category, item.path, item.line): item for item in findings}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (-SEVERITIES[item.severity], item.path, item.line or 0, item.category),
        )
    )


def format_report(findings: tuple[Finding, ...]) -> str:
    blocks = sum(item.severity == "block" for item in findings)
    warnings = sum(item.severity == "warn" for item in findings)
    lines = ["# Dependency policy", f"- Blocking findings: {blocks}", f"- Warnings: {warnings}"]
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
    parser = argparse.ArgumentParser(description="Statically review dependency manifests.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--paths", required=True, help="NUL-delimited `git ls-files -z` output")
    parser.add_argument("--strict", action="store_true", help="Exit 1 when a blocking finding exists")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print("BLOCK: repository root must be a directory.")
        return 2
    try:
        tracked = read_tracked_paths(Path(args.paths))
        findings = scan(root, tracked)
    except (OSError, ValueError):
        print("BLOCK: unable to inspect dependency metadata.")
        return 2
    print(format_report(findings))
    if args.strict and any(item.severity == "block" for item in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
