#!/usr/bin/env python3
"""Check that the bundled catalog equals the board catalogs it was merged from.

`catalog/catalog.json` lists each source with its repository, commit and the digest of
its `catalog.json`. This fetches every pinned commit and runs
`bme catalog merge catalog <checkouts> --check`. It fails when a source has no
repository or commit, when a shared record differs, or when a pin reads `moved`.

Run `python3 tools/check-bundled-catalog-sources.py` from any directory. It needs git
and network access to the source repositories.
"""

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BME = "cargo run --locked --quiet --"


class CheckFailed(Exception):
    """A source that cannot be checked, or a catalog that does not match its sources."""


def pinned_sources(manifest):
    """Return (id, repository, commit) of every source, e.g. [("pr9-b85", "https://...", "1a2b...")].

    A source with no repository or commit cannot be fetched, so it fails the check.
    """
    sources = manifest.get("sources") or []
    if not sources:
        raise CheckFailed("catalog.json sources: expected at least one source | received none")
    pinned = []
    for source in sources:
        missing = [key for key in ("repository", "commit") if not source.get(key)]
        if missing:
            raise CheckFailed(
                f"source {source.get('id')}: expected repository and commit | "
                f"received no {' and no '.join(missing)}"
            )
        pinned.append((source["id"], source["repository"], source["commit"]))
    return pinned


def fetch_commands(repository, commit):
    """The git commands that check out one commit without the rest of the history."""
    return [
        ["git", "init", "--quiet", "."],
        ["git", "fetch", "--quiet", "--depth", "1", repository, commit],
        ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]


def moved_pins(output):
    """The pin lines of `merge --check` that report a moved source."""
    return [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith("pin ") and ": moved" in line
    ]


def check(catalog, bme, run, workspace):
    """Fetch every pinned source into `workspace` and compare the catalog with them.

    `run(command, cwd)` returns (exit code, output); the tests pass a fake.
    Returns the output of `bme catalog merge --check`.
    """
    manifest = json.loads((catalog / "catalog.json").read_text())
    checkouts = []
    for identifier, repository, commit in pinned_sources(manifest):
        target = workspace / identifier
        target.mkdir()
        for command in fetch_commands(repository, commit):
            code, output = run(command, target)
            if code != 0:
                raise CheckFailed(
                    f"source {identifier}: expected `{' '.join(command)}` to succeed | "
                    f"received exit {code}: {output.strip()}"
                )
        checkouts.append(str(target))
    command = [*bme, "catalog", "merge", str(catalog), *checkouts, "--check"]
    code, output = run(command, ROOT)
    if code != 0:
        raise CheckFailed(
            f"bundled catalog: expected the same records as its sources | received: {output.strip()}"
        )
    moved = moved_pins(output)
    if moved:
        raise CheckFailed(
            "bundled catalog: expected every source pinned | received " + "; ".join(moved)
        )
    return output


def run_process(command, cwd):
    """Run a command and return (exit code, stdout plus stderr)."""
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--catalog", type=Path, default=ROOT / "catalog")
    parser.add_argument("--bme", default=DEFAULT_BME, help="command that runs bme")
    args = parser.parse_args(argv)
    try:
        with tempfile.TemporaryDirectory(prefix="bme-sources-") as workspace:
            output = check(args.catalog.resolve(), shlex.split(args.bme), run_process, Path(workspace))
    except CheckFailed as error:
        print(f"check-bundled-catalog-sources: {error}", file=sys.stderr)
        return 1
    print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
