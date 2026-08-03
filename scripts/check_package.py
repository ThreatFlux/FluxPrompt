#!/usr/bin/env python3
"""Verify that the crates.io archive contains only intentional files."""

from __future__ import annotations

import re
# Cargo is a trusted developer tool invoked by this package contract check.
import subprocess  # nosec B404
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
GENERATED_FILES = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
}
ROOT_FILES = {
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
}
REQUIRED_FILES = GENERATED_FILES - {".cargo_vcs_info.json"} | ROOT_FILES
ALLOWED_PREFIXES = ("benches/", "docs/", "examples/", "src/")
INLINE_LINK_RE = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(?P<target><[^>\n]+>|[^\s)]+)", re.MULTILINE
)
REFERENCE_LINK_RE = re.compile(
    r"^\s{0,3}\[[^\]\n]+\]:\s*(?P<target><[^>\n]+>|\S+)", re.MULTILINE
)
FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def package_files() -> set[str]:
    # The executable and arguments are fixed, and subprocess never invokes a shell.
    result = subprocess.run(  # nosec B603, B607
        ["cargo", "package", "--list", "--allow-dirty"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr, end="")
        print(result.stderr, file=sys.stderr, end="")
        raise SystemExit(result.returncode)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def without_fenced_code(markdown: str) -> str:
    output: list[str] = []
    closing_marker: str | None = None
    for line in markdown.splitlines(keepends=True):
        fence = FENCE_RE.match(line)
        if closing_marker is None and fence is not None:
            closing_marker = fence.group(1)[0]
            output.append("\n" if line.endswith(("\n", "\r")) else "")
            continue
        if closing_marker is not None:
            if fence is not None and fence.group(1)[0] == closing_marker:
                closing_marker = None
            output.append("\n" if line.endswith(("\n", "\r")) else "")
            continue
        output.append(line)
    return "".join(output)


def markdown_targets(markdown: str) -> list[tuple[int, str]]:
    prose = without_fenced_code(markdown)
    matches = list(INLINE_LINK_RE.finditer(prose))
    matches.extend(REFERENCE_LINK_RE.finditer(prose))
    matches.sort(key=lambda match: match.start())
    targets: list[tuple[int, str]] = []
    for match in matches:
        target = match.group("target").strip()
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        line = prose.count("\n", 0, match.start("target")) + 1
        targets.append((line, target))
    return targets


def packaged_link_errors(files: set[str]) -> list[str]:
    errors: list[str] = []
    for package_path in sorted(path for path in files if path.endswith(".md")):
        source_path = ROOT / package_path
        for line, target in markdown_targets(source_path.read_text(encoding="utf-8")):
            if not target or target.startswith(("#", "/")):
                continue
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            resolved = (source_path.parent / unquote(parsed.path)).resolve()
            try:
                relative = resolved.relative_to(ROOT).as_posix()
            except ValueError:
                errors.append(f"{package_path}:{line}: link escapes package: {target}")
                continue
            prefix = f"{relative.rstrip('/')}/"
            if relative not in files and not any(path.startswith(prefix) for path in files):
                errors.append(f"{package_path}:{line}: target is not packaged: {target}")
    return errors


def main() -> int:
    files = package_files()
    unexpected = sorted(
        path
        for path in files
        if path not in GENERATED_FILES | ROOT_FILES
        and not (
            path.startswith(ALLOWED_PREFIXES)
            and (path.endswith(".rs") or path.endswith(".md"))
        )
    )
    missing = sorted(REQUIRED_FILES - files)
    link_errors = packaged_link_errors(files)
    if unexpected or missing or link_errors:
        for heading, entries in (
            ("Unexpected package files", unexpected),
            ("Missing package files", missing),
            ("Broken packaged Markdown links", link_errors),
        ):
            if entries:
                print(f"{heading}:", file=sys.stderr)
                for entry in entries:
                    print(f"  - {entry}", file=sys.stderr)
        return 1
    print(f"Cargo package contents verified ({len(files)} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
