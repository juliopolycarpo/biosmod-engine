#!/usr/bin/env python3
"""Collect license texts and copyright notices for the Linux runtime graph."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def license_candidates(source, files, declared_license):
    """Select notice files, including LICENSES trees and a declared license.

    Example: license_candidates(root, [root / "LICENSE"], None).
    """
    candidates = {
        path for path in files
        if path.name.lower().startswith(("license", "licence", "copying", "notice", "copyright"))
        or "LICENSES" in path.relative_to(source).parts[:-1]
    }
    if declared_license:
        candidates.add(source / declared_license)
    return sorted(candidates)


def source_copyrights(files):
    """Collect short copyright lines from source and documentation files.

    Example: source_copyrights([Path("src/lib.rs")]).
    """
    copyrights = set()
    for path in files:
        if path.suffix.lower() not in {".rs", ".c", ".h", ".s", ".toml", ".md", ".txt"}:
            continue
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if "copyright" in line.lower() and len(line) < 500:
                    copyrights.add(line.strip())
        except (OSError, UnicodeError):
            continue
    return copyrights


def main():
    """Collect the runtime dependency notices. Example: collect-notices.py /tmp/notices."""
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: collect-notices.py <destination-directory> [cargo-metadata.json]")

    destination = Path(sys.argv[1])
    if destination.exists():
        sys.exit(f"notice destination {destination}: expected a new directory")
    destination.mkdir(parents=True, exist_ok=False)
    target = "x86_64-unknown-linux-gnu"
    metadata = json.loads(Path(sys.argv[2]).read_text()) if len(sys.argv) == 3 else json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
            text=True,
        )
    )
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "-p", "biosmod-cli", "-p", "biosmod-gui",
         "--target", target, "-e", "normal", "--prefix", "none", "--format", "{p}"],
        text=True,
    )
    dependencies = set()
    for line in tree.splitlines():
        if not line:
            continue
        match = re.match(r"([^ ]+) v([^ ]+)", line)
        if not match:
            sys.exit(f"unrecognized cargo tree row: {line!r}")
        dependencies.add(match.groups())

    records = []
    unmatched = set(dependencies)
    for package in metadata["packages"]:
        key = (package["name"], package["version"])
        if key not in dependencies:
            continue
        unmatched.discard(key)
        if package["source"] is None:
            continue
        source = Path(package["manifest_path"]).parent
        name = f"{key[0]}-{key[1]}"
        target_dir = destination / "crates" / name
        files = [path for path in source.rglob("*") if path.is_file()]
        candidates = license_candidates(source, files, package["license_file"])
        target_dir.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            if not candidate.is_file():
                sys.exit(f"{name}: declared license file is missing: {candidate}")
            resolved = candidate.resolve()
            if not resolved.is_relative_to(source.resolve()):
                sys.exit(f"{name}: expected a license file inside its package | received {candidate}")
            relative = resolved.relative_to(source.resolve())
            output = target_dir / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, output)

        # Some crates omit workspace-level license files from their published
        # tarball. The checked-in copies are pinned to the crate's VCS revision.
        vcs_file = source / ".cargo_vcs_info.json"
        if vcs_file.is_file():
            revision = json.loads(vcs_file.read_text(encoding="utf-8"))["git"]["sha1"]
            upstream = Path(__file__).parent / "upstream-notices" / revision
            if upstream.is_dir():
                for notice in upstream.iterdir():
                    shutil.copyfile(notice, target_dir / notice.name)

        copyrights = source_copyrights(files)
        if copyrights:
            (target_dir / "source-copyrights.txt").write_text("\n".join(sorted(copyrights)) + "\n")
        expression = package["license"] or "license file"
        if not any(p.name.lower().startswith(("license", "licence", "copying")) or
                   p.name.lower() in {"mit.txt", "apache-2.0.txt"} for p in target_dir.rglob("*") if p.is_file()):
            sys.exit(f"{name}: no license file for {expression}; add its license text before packaging")
        records.append(f"{name}: {expression}\n  Authors: {', '.join(package['authors']) or 'not specified'}\n")

    if unmatched:
        sys.exit(f"cargo tree packages missing from metadata: {sorted(unmatched)!r}")
    (destination / "THIRD-PARTY.txt").write_text(
        "Runtime Rust dependencies (Cargo.lock, Linux x86_64).\n"
        "License files and source copyright notices, where present, are in crates/<name>-<version>/.\n"
        "Shared MIT and Apache-2.0 license texts are in the parent directory.\n\n"
        + "\n".join(sorted(records)), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
