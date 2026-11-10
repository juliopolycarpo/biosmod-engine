#!/usr/bin/env python3
"""Check reviewed documentation pairs and their local Markdown links.

Run `python3 tools/check-doc-translations.py` from any directory.
"""

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path("docs/i18n-manifest.json")
LINK = re.compile(r"!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$")


def source_paths(root):
    """Return the English documents in scope, e.g. README.md and docs/guide/gui.md."""
    docs = (root / "docs").rglob("*.md")
    return {Path("README.md"), Path("CONTRIBUTING.md")} | {
        p.relative_to(root) for p in docs if "pt-BR" not in p.relative_to(root / "docs").parts
    }


def translation_path(source):
    """Return the counterpart path, e.g. docs/a.md becomes docs/pt-BR/a.md."""
    if source.parent == Path("."):
        return source.with_name(source.stem + ".pt-BR.md")
    return Path("docs/pt-BR") / source.relative_to("docs")


def visible_lines(contents):
    """Yield Markdown lines outside fenced code blocks, e.g. skip ```sh examples."""
    fence = None
    for line in contents.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            current = marker.group(1)
            if fence is None:
                fence = current
            elif current[0] == fence[0] and len(current) >= len(fence):
                fence = None
            continue
        if fence is None:
            yield line


def anchors(contents):
    """Return GitHub-style heading anchors, including duplicate suffixes."""
    counts = {}
    result = set()
    for line in visible_lines(contents):
        match = HEADING.match(line)
        if not match:
            continue
        title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", match.group(1)).lower()
        title = re.sub(r"<[^>]+>|[`*_~]", "", title)
        slug = "".join(c for c in title if c in "-_ " or unicodedata.category(c)[0] in "LN")
        slug = slug.replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        result.add(slug if count == 0 else f"{slug}-{count}")
    return result


def check_links(root, path):
    """Return errors for local links in one Markdown file, including heading fragments."""
    errors = []
    inside = False
    marker = None
    for line_number, line in enumerate((root / path).read_text(encoding="utf-8").splitlines(), 1):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence:
            token = fence.group(1)
            if not inside:
                marker, inside = token, True
            elif token[0] == marker[0] and len(token) >= len(marker):
                inside = False
            continue
        if inside:
            continue
        for match in LINK.finditer(line):
            url = urlsplit(match.group(1).strip("<>"))
            if url.scheme or url.netloc:
                continue
            target = (root / path).parent / unquote(url.path) if url.path else root / path
            target = target.resolve()
            if not target.is_relative_to(root.resolve()) or not target.exists():
                errors.append(f"{path}:{line_number}: missing local target {match.group(1)}")
            elif url.fragment and target.is_file() and target.suffix == ".md":
                if unquote(url.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    errors.append(f"{path}:{line_number}: missing heading {match.group(1)}")
    return errors


def check(root):
    """Check manifest coverage, reviewed source hashes, and links; return diagnostics."""
    errors = []
    try:
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        if manifest.get("version") != 1 or not isinstance(manifest.get("pairs"), list):
            return [f"{MANIFEST}: expected version 1 and pairs array"]
    except (OSError, ValueError, AttributeError) as error:
        return [f"{MANIFEST}: {error}"]
    expected = source_paths(root)
    seen_sources, seen_translations = set(), set()
    for pair in manifest["pairs"]:
        try:
            source, translation, digest = Path(pair["source"]), Path(pair["translation"]), pair["sha256"]
        except (KeyError, TypeError):
            errors.append(f"{MANIFEST}: invalid pair {pair!r}")
            continue
        if source in seen_sources or translation in seen_translations:
            errors.append(f"{MANIFEST}: duplicate source or translation: {source}, {translation}")
        seen_sources.add(source)
        seen_translations.add(translation)
        if source not in expected or translation != translation_path(source):
            errors.append(f"{MANIFEST}: unexpected mapping {source} -> {translation}")
            continue
        if not (root / translation).is_file():
            errors.append(f"{MANIFEST}: missing translation {translation}")
        source_bytes = (root / source).read_bytes()
        if b"\r" in source_bytes or hashlib.sha256(source_bytes).hexdigest() != digest:
            errors.append(f"{MANIFEST}: source changed or has non-LF line endings: {source}")
    for missing in sorted(expected - seen_sources):
        errors.append(f"{MANIFEST}: missing source {missing}")
    actual_translations = {p.relative_to(root) for p in (root / "docs/pt-BR").rglob("*.md")}
    actual_translations |= {p.relative_to(root) for p in root.glob("*.pt-BR.md")}
    for orphan in sorted(actual_translations - seen_translations):
        errors.append(f"{MANIFEST}: orphan translation {orphan}")
    for path in sorted(expected | seen_translations):
        if (root / path).is_file():
            errors.extend(check_links(root, path))
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository or extracted archive root")
    problems = check(parser.parse_args().root.resolve())
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print("Documentation translations: coverage, freshness and local links OK")
