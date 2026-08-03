"""Validate maintained Markdown links and the README quickstart copy."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
QUICKSTART = re.compile(
    r"<!-- quickstart-source: examples/basic_detection\.rs -->\s*"
    r"```rust\n(?P<code>.*?)```",
    re.DOTALL,
)


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if ".git" not in path.parts and "target" not in path.parts
    )


def slug(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return re.sub(r"[ -]+", "-", text).strip("-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    for heading in HEADING.findall(path.read_text(encoding="utf-8")):
        base = slug(heading)
        occurrence = seen.get(base, 0)
        seen[base] = occurrence + 1
        result.add(base if occurrence == 0 else f"{base}-{occurrence}")
    return result


def split_destination(raw: str) -> tuple[str, str]:
    destination = raw.strip()
    if destination.startswith("<") and destination.endswith(">"):
        destination = destination[1:-1]
    destination = destination.split(maxsplit=1)[0]
    path, separator, fragment = destination.partition("#")
    return unquote(path), unquote(fragment) if separator else ""


def check_links(files: list[Path]) -> list[str]:
    failures: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}

    for source in files:
        text = source.read_text(encoding="utf-8")
        for raw in MARKDOWN_LINK.findall(text):
            path_text, fragment = split_destination(raw)
            if path_text.startswith(("http://", "https://", "mailto:")):
                continue

            target = source if not path_text else (source.parent / path_text).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)}: link escapes repository: {raw}")
                continue

            if not target.exists():
                failures.append(f"{source.relative_to(ROOT)}: missing link target: {raw}")
                continue

            if fragment and target.suffix.lower() == ".md":
                target_anchors = anchor_cache.setdefault(target, anchors(target))
                if fragment not in target_anchors:
                    failures.append(
                        f"{source.relative_to(ROOT)}: missing anchor #{fragment} in "
                        f"{target.relative_to(ROOT)}"
                    )

    return failures


def check_quickstart() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = QUICKSTART.search(readme)
    if match is None:
        return ["README.md: quickstart source marker or Rust block is missing"]

    copied = match.group("code")
    source = (ROOT / "examples/basic_detection.rs").read_text(encoding="utf-8")
    if copied != source:
        return [
            "README.md: quickstart block differs from examples/basic_detection.rs; "
            + "update both together"
        ]
    return []


def check_docs_index() -> list[str]:
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    failures = []
    for path in sorted((ROOT / "docs").glob("*.md")):
        if path.name != "README.md" and f"({path.name})" not in index:
            failures.append(f"docs/README.md: missing index entry for docs/{path.name}")
    return failures


def main() -> int:
    files = markdown_files()
    failures = check_links(files) + check_quickstart() + check_docs_index()
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1

    print(
        f"documentation checks passed: {len(files)} Markdown files, "
        "local links, anchors, docs index, and README quickstart"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
