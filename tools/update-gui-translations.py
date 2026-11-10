#!/usr/bin/env python3
"""Extract Slint messages and check or update the bundled Portuguese catalog.

Install the extractor with `cargo install slint-tr-extractor --version 1.18.1 --locked`,
then run `python3 tools/update-gui-translations.py` or add `--check` in CI.
New or changed messages require translation review after updating.
"""

import argparse
import ast
import collections
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "crates/biosmod-gui"
TEMPLATE = GUI / "i18n/biosmod-gui.pot"
CATALOG = GUI / "i18n/pt-BR/LC_MESSAGES/biosmod-gui.po"


def fields(block):
    """Parse gettext fields emitted by the extractor, including continuation lines."""
    result = {}
    current = None
    for line in block.splitlines():
        match = re.match(r'^(msgctxt|msgid_plural|msgid|msgstr(?:\[\d+\])?)\s+(".*")$', line)
        if match:
            current = match[1]
            result[current] = ast.literal_eval(match[2])
        elif line.startswith('"') and current:
            result[current] += ast.literal_eval(line)
    return result


def key(block):
    entry = fields(block)
    return (entry.get("msgctxt", ""), entry.get("msgid", ""), entry.get("msgid_plural", ""))


def entries(content):
    return [block for block in content.strip().split("\n\n") if fields(block).get("msgid")]


def placeholders(value):
    # Slint permits positional arguments to be reordered using {0}, {1}, ….
    implicit = 0
    result = []
    for item in re.findall(r'\{(?:\d+|[A-Za-z_][\w]*)?\}', value):
        if item == '{}':
            result.append(str(implicit))
            implicit += 1
        else:
            result.append(item[1:-1])
    return collections.Counter(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if shutil.which("slint-tr-extractor") is None:
        raise SystemExit("slint-tr-extractor 1.18.1 is required; install it with "
                         "cargo install slint-tr-extractor --version 1.18.1 --locked")
    version = subprocess.check_output(["slint-tr-extractor", "--version"], text=True).strip()
    if version != "slint-tr-extractor 1.18.1":
        raise SystemExit(f"expected slint-tr-extractor 1.18.1 | received {version}")
    with tempfile.TemporaryDirectory(prefix="biosmod-i18n-") as temp:
        result = Path(temp) / "messages.pot"
        subprocess.run(["slint-tr-extractor", "-d", "biosmod-gui", "-o", str(result),
                        *[str(path.relative_to(GUI)) for path in sorted((GUI / "ui").glob("*.slint"))]],
                       cwd=GUI, check=True)
        template = re.sub(r'"POT-Creation-Date: .*?\\n"\n', '', result.read_text())
    source = entries(template)
    old = CATALOG.read_text() if CATALOG.exists() else ''
    catalog_entries = entries(old)
    existing = {key(block): block for block in catalog_entries}
    errors = []
    if len(existing) != len(catalog_entries):
        errors.append("catalog contains duplicate message contexts and IDs")
    for block in source:
        entry = fields(block)
        match = existing.get(key(block))
        if not match:
            errors.append(f"missing: {key(block)}")
            continue
        translated = fields(match)
        if re.search(r'^#,.*\bfuzzy\b', match, re.M):
            errors.append(f"fuzzy: {key(block)}")
        names = ("msgstr[0]", "msgstr[1]") if entry.get("msgid_plural") else ("msgstr",)
        for name in names:
            value = translated.get(name, '')
            original = entry['msgid'] if name != "msgstr[1]" else entry['msgid_plural']
            if not value or placeholders(value) != placeholders(original):
                errors.append(f"invalid {name}: {key(block)} | received {value!r}")
    if args.check:
        if not TEMPLATE.exists() or TEMPLATE.read_text() != template:
            errors.append("template is stale; run tools/update-gui-translations.py")
        extra = existing.keys() - {key(block) for block in source}
        errors.extend(f"obsolete: {item}" for item in extra)
        if errors:
            raise SystemExit("\n".join(errors))
        print(f"GUI translations: {len(source)} messages validated")
        return
    TEMPLATE.write_text(template)
    header = ('msgid ""\nmsgstr ""\n'
              '"Content-Type: text/plain; charset=UTF-8\\n"\n'
              '"Language: pt-BR\\n"\n'
              '"Plural-Forms: nplurals=2; plural=(n > 1);\\n"')
    # Keep translator comments and translations intact for unchanged messages.
    merged = [existing.get(key(block), block) for block in source]
    source_keys = {key(block) for block in source}
    obsolete = [block for item, block in existing.items() if item not in source_keys]
    # Retain removed messages as obsolete, so changes can be reviewed against them.
    old_obsolete = [block for block in old.strip().split("\n\n") if block.startswith("#~ ")]
    obsolete = old_obsolete + ["\n".join("#~ " + line for line in block.splitlines())
                               for block in obsolete]
    CATALOG.parent.mkdir(parents=True, exist_ok=True)
    CATALOG.write_text(header + "\n\n" + "\n\n".join(merged + obsolete) + "\n")
    if errors:
        print("\n".join(errors))


if __name__ == "__main__":
    main()
