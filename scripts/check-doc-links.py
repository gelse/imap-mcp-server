#!/usr/bin/env python3
"""Check relative links and backticked repository paths in the tracked docs.

Scope: the tracked documentation set — `README.md` plus every `docs/*.md`
listed by git — so a fresh clone carries exactly the files checked here.

What is checked:

- Every Markdown link with a relative target resolves against the
  directory of the file containing it.
- Every `#fragment` link (Markdown or inline-code) resolves against the
  target file's headings, slugified the way GitHub renders heading
  anchors; a `#fragment`-only target checks against the containing file.
- Every backticked token that names a repository path — no spaces, either
  slash-separated or ending in a known repository extension, and rooted at
  a name tracked at the repository's top level — exists in the working
  tree, resolved first against the containing file's directory, then
  against the repository root. Paths outside the tracked tree (runtime
  data, URL paths, plans/) never qualify, because their first segment is
  not tracked.

Absolute URLs (http/https/mailto) are skipped. Exit status is 0 when every
check passes, 1 otherwise. Standard library only; run from the repository
root as `python3 scripts/check-doc-links.py`.
"""

from __future__ import annotations

import functools
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DOC_PATTERNS = ("README.md", "docs/*.md")

REPO_EXTENSIONS = (
    ".py", ".md", ".yml", ".yaml", ".json", ".toml",
    ".mjs", ".ts", ".vue", ".ini", ".lock", ".sh",
)
REPO_PATH_RE = re.compile(r"[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)+")
REPO_PATH_CHARS_RE = re.compile(r"[A-Za-z0-9_./@+-]+")
URL_PREFIXES = ("http://", "https://", "mailto:")

INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)[^)]*\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


def tracked_files() -> list[str]:
    """The tracked doc set, as git lists it."""
    listing = subprocess.run(
        ["git", "ls-files", *DOC_PATTERNS],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return sorted(line for line in listing.splitlines() if line)


@functools.cache
def tracked_top_level_names() -> set[str]:
    """Every top-level name (file or directory) tracked at the repo root."""
    listing = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    return {line.split("/", 1)[0] for line in listing.splitlines() if line}


def github_slug(heading: str) -> str:
    """Slugify one heading the way GitHub renders its anchor."""
    slug = heading.strip().lower()
    out: list[str] = []
    for ch in slug:
        if ch.isalnum() or ch in "_-":
            out.append(ch)
        elif ch == " ":
            out.append("-")
    return "".join(out)


def heading_slugs(path: Path) -> set[str]:
    """The GitHub slugs of one file's ATX headings (fences excluded)."""
    slugs: set[str] = []
    fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            slugs.append(github_slug(match.group(2)))
    return set(slugs)


def is_repo_path_candidate(token: str) -> bool:
    """A token names a repo path when it is space-free, path-shaped, and
    rooted at a name tracked at the repository's top level."""
    if " " in token or token.startswith(("/", "#")) or token.startswith(URL_PREFIXES):
        return False
    token = token.removeprefix("./")
    if not (REPO_PATH_RE.fullmatch(token) or token.endswith(REPO_EXTENSIONS)):
        return False
    if not REPO_PATH_CHARS_RE.fullmatch(token):
        return False
    top = tracked_top_level_names()
    return token.split("/", 1)[0] in top


class Counter:
    """Per-file and total counts, plus the failure list."""

    def __init__(self) -> None:
        self.per_file: dict[str, dict[str, int]] = {}
        self.failures: list[str] = []

    def count(self, file: str, kind: str) -> None:
        stats = self.per_file.setdefault(
            file, {"relative link targets checked": 0,
                   "heading anchors checked": 0,
                   "backticked repo paths checked": 0}
        )
        stats[kind] += 1

    def fail(self, message: str) -> None:
        self.failures.append(message)


def check_fragment(
    counter: Counter, file: str, lineno: int, slug_target: Path, fragment: str
) -> None:
    """Check one `#fragment` against a file's heading slugs."""
    kind = "heading anchors checked"
    counter.count(file, kind)
    if fragment.lstrip("#") not in heading_slugs(slug_target):
        counter.fail(
            f"{file}:{lineno}: heading anchor not found in "
            f"{slug_target}: #{fragment.lstrip('#')}"
        )


def check_file(counter: Counter, path: Path) -> None:
    """Scan one doc file: Markdown links, then inline-code tokens."""
    name = path.relative_to(REPO_ROOT).as_posix()
    own_slugs = heading_slugs(path)
    fence = False
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        spans = INLINE_CODE_RE.findall(line)
        masked = INLINE_CODE_RE.sub(lambda m: "`" + " " * len(m.group(1)) + "`", line)

        for target in MARKDOWN_LINK_RE.findall(masked):
            if target.startswith(("/", *URL_PREFIXES)):
                continue
            stem, _, fragment = target.partition("#")
            if not stem:
                if fragment.lstrip("#") not in own_slugs:
                    counter.fail(
                        f"{name}:{lineno}: heading anchor not found here: "
                        f"#{fragment.lstrip('#')}"
                    )
                counter.count(name, "heading anchors checked")
                continue
            resolved = (path.parent / stem).resolve()
            counter.count(name, "relative link targets checked")
            if not resolved.exists():
                counter.fail(f"{name}:{lineno}: relative link target not found: {stem}")
            elif fragment:
                check_fragment(counter, name, lineno, resolved, fragment)

        for token in spans:
            if token.startswith("#"):
                if token.lstrip("#") not in own_slugs:
                    counter.fail(
                        f"{name}:{lineno}: heading anchor not found here: {token}"
                    )
                counter.count(name, "heading anchors checked")
                continue
            if not is_repo_path_candidate(token):
                continue
            stem, _, fragment = token.partition("#")
            counter.count(name, "backticked repo paths checked")
            rel = Path(stem.removeprefix("./"))
            if (path.parent / rel).exists():
                resolved = (path.parent / rel).resolve()
            elif (REPO_ROOT / rel).exists():
                resolved = (REPO_ROOT / rel).resolve()
            else:
                counter.fail(f"{name}:{lineno}: backticked repo path not found: {stem}")
                continue
            if fragment:
                check_fragment(counter, name, lineno, resolved, fragment)


def main() -> int:
    counter = Counter()
    files = tracked_files()
    for entry in files:
        check_file(counter, REPO_ROOT / entry)

    kinds = ("relative link targets checked", "heading anchors checked",
             "backticked repo paths checked")
    for name, stats in counter.per_file.items():
        print(name)
        for kind in kinds:
            print(f"  {kind}: {stats[kind]}")
    print(f"files scanned: {len(files)}")
    for kind in kinds:
        total = sum(stats[kind] for stats in counter.per_file.values())
        print(f"total {kind}: {total}")
    print(f"failures: {len(counter.failures)}")
    for failure in counter.failures:
        print(f"  {failure}")
    return 1 if counter.failures else 0


if __name__ == "__main__":
    sys.exit(main())
