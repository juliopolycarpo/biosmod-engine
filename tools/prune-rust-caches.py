#!/usr/bin/env python3
"""Delete Swatinem/rust-cache generations on main that a newer generation replaced.

Every rust-cache step saves only on refs/heads/main under a key shaped like
`v0-rust-<job>-<OS>-<arch>-<envhash>-<lockhash>`. A toolchain, `.cargo/config.toml` or
Cargo.lock change saves a new generation, and the old ones are never restored again. A
family is the key without its last two hash segments, e.g. `v0-rust-gui-linux-Linux-x64`.
On refs/heads/main this keeps the most recently created entry of each family and deletes
the others. Caches on any other ref and keys outside that grammar are never selected.

Run `python3 tools/prune-rust-caches.py` for a dry run that lists what it would keep and
delete. Pass `--delete` to delete. It needs an authenticated `gh`; the repository defaults
to $GITHUB_REPOSITORY, then to the one `gh repo view` reports.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass

MAIN_REF = "refs/heads/main"
KEY_PREFIX = "v0-rust-"
PAGE_SIZE = 100

# rust-cache builds the key as prefix, job, os.type(), os.arch(), then two 8-hex hashes
# (compiler/environment, then Cargo.lock and manifests). Job names hold hyphens and
# underscores (`gui-linux`) and the OS can too (`Windows_NT`), so anchor on the OS names
# instead of splitting on hyphens.
KEY_GRAMMAR = re.compile(
    r"^(?P<family>v0-rust-(?P<job>[A-Za-z0-9_-]+)-(?P<os>Linux|Darwin|Windows_NT)-(?P<arch>[a-z0-9_]+))"
    r"-(?P<environment>[a-f0-9]{8})-(?P<lockfile>[a-f0-9]{8})$"
)
ENTRY_FIELDS = {"id": int, "key": str, "ref": str, "created_at": str, "size_in_bytes": int}


@dataclass(frozen=True)
class Decision:
    """What to do with one cache entry and why. `family` is None outside the grammar."""

    entry: dict
    action: str  # "keep" or "delete"
    reason: str
    family: str | None = None


def family_of(key):
    """Return the family of a rust-cache key, or None, e.g. `v0-rust-test-Windows_NT-x64-6a930898-7d7c5a16`
    gives `v0-rust-test-Windows_NT-x64`."""
    match = KEY_GRAMMAR.match(key)
    return match.group("family") if match else None


def check_entry(entry):
    """Raise ValueError unless the entry has the fields the selection reads."""
    if not isinstance(entry, dict):
        raise ValueError(f"cache entry {entry!r}: expected an object with {', '.join(ENTRY_FIELDS)}")
    for field, kind in ENTRY_FIELDS.items():
        value = entry.get(field)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise ValueError(f"cache entry {entry!r}: expected {field} to be {kind.__name__}, received {value!r}")
    if entry["id"] < 1 or entry["size_in_bytes"] < 0:
        raise ValueError(f"cache entry {entry!r}: expected a positive id and a non-negative size")
    if not re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", entry["created_at"]):
        raise ValueError(f"cache entry {entry!r}: expected created_at as UTC ISO 8601, received {entry['created_at']!r}")


def select_caches(entries):
    """Decide keep or delete for every entry; the input order is preserved in the output.

    Only entries on refs/heads/main whose key matches the rust-cache grammar are candidates.
    Within a family the newest `created_at` is kept (the higher id breaks a tie) and the rest
    are deleted. Duplicate ids are rejected: one id must never be both kept and deleted.
    """
    entries = list(entries)
    for entry in entries:
        check_entry(entry)
    ids = [entry["id"] for entry in entries]
    if len(set(ids)) != len(ids):
        duplicate = next(i for i in ids if ids.count(i) > 1)
        raise ValueError(f"cache listing: expected unique ids, received id {duplicate} more than once")

    decisions = {}
    families = defaultdict(list)
    for entry in entries:
        if entry["ref"] != MAIN_REF:
            decisions[entry["id"]] = Decision(entry, "keep", f"ref {entry['ref']} is not {MAIN_REF}")
            continue
        family = family_of(entry["key"])
        if family is None:
            decisions[entry["id"]] = Decision(entry, "keep", "key does not match the rust-cache grammar")
            continue
        families[family].append(entry)

    for family, members in families.items():
        # ISO 8601 UTC strings with the same shape sort chronologically; fractions are
        # compared as text, so pad them to a fixed width first.
        members.sort(key=lambda e: (_created_sort_key(e["created_at"]), e["id"]), reverse=True)
        newest, older = members[0], members[1:]
        reason = "newest of its family" if older else "only entry of its family"
        decisions[newest["id"]] = Decision(newest, "keep", reason, family)
        for entry in older:
            decisions[entry["id"]] = Decision(entry, "delete", f"superseded by cache {newest['id']} {newest['key']}", family)
    return [decisions[entry["id"]] for entry in entries]


def _created_sort_key(created_at):
    """Return (seconds, fraction digits padded to 9) so equal-width strings compare in time order."""
    seconds, _, fraction = created_at.rstrip("Z").partition(".")
    return seconds, fraction.ljust(9, "0")


class GhCli:
    """Reads and deletes caches through `gh api`. Tests substitute a fake with the same methods."""

    def run(self, args):
        """Run `gh <args>` and return stdout; raise RuntimeError with stderr on failure."""
        result = subprocess.run(["gh", *args], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args)} exited {result.returncode}: {result.stderr.strip()}")
        return result.stdout

    def default_repository(self):
        """Return owner/name from $GITHUB_REPOSITORY or the current directory's remote."""
        return os.environ.get("GITHUB_REPOSITORY") or self.run(
            ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]
        ).strip()

    def list_caches(self, repository):
        """Return every rust-cache entry on main, following all pages."""
        endpoint = f"repos/{repository}/actions/caches?ref={MAIN_REF}&key={KEY_PREFIX}&per_page={PAGE_SIZE}"
        return parse_pages(self.run(["api", "--paginate", "--slurp", endpoint]))

    def delete_cache(self, repository, cache_id):
        """Delete one cache by id; return False when it was already gone (HTTP 404)."""
        try:
            self.run(["api", "--method", "DELETE", f"repos/{repository}/actions/caches/{cache_id}"])
        except RuntimeError as error:
            if "HTTP 404" in str(error):
                return False
            raise
        return True


def parse_pages(slurped):
    """Flatten the JSON array `gh api --paginate --slurp` prints into one entry list.

    Raises ValueError when a page has no `actions_caches` array or when the entries read
    differ from the `total_count` GitHub reported, since selecting from a partial listing
    could keep a stale generation.
    """
    try:
        pages = json.loads(slurped)
    except ValueError as error:
        raise ValueError(f"cache listing: expected a JSON array of pages, received {slurped[:80]!r}") from error
    if not isinstance(pages, list):
        raise ValueError(f"cache listing: expected a JSON array of pages, received {type(pages).__name__}")
    entries = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("actions_caches"), list):
            raise ValueError(f"cache listing page {str(page)[:80]!r}: expected an object with an actions_caches array")
        entries.extend(page["actions_caches"])
    total = pages[-1].get("total_count") if pages else 0
    if total != len(entries):
        raise ValueError(f"cache listing: expected {total} entries (total_count), received {len(entries)}")
    return entries


def human_size(size):
    """Format bytes with binary units, e.g. 1830174068 gives `1.70 GiB`."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024


def render_plan(decisions):
    """Return the report lines for a selection: per family keep/delete, then totals."""
    lines = []
    by_family = defaultdict(list)
    untouched = []
    for decision in decisions:
        (by_family[decision.family] if decision.family else untouched).append(decision)
    for family in sorted(by_family):
        lines.append(family)
        for decision in sorted(by_family[family], key=lambda d: d.entry["created_at"], reverse=True):
            entry = decision.entry
            lines.append(
                f"  {decision.action.upper():6} {entry['id']} {entry['key']} "
                f"{entry['created_at']} {human_size(entry['size_in_bytes'])} ({decision.reason})"
            )
    for decision in untouched:
        entry = decision.entry
        lines.append(f"untouched {entry['id']} {entry['key']} {entry['ref']} ({decision.reason})")
    kept = [d for d in decisions if d.action == "keep"]
    doomed = [d for d in decisions if d.action == "delete"]
    reclaim = sum(d.entry["size_in_bytes"] for d in doomed)
    lines.append(
        f"keep {len(kept)} ({human_size(sum(d.entry['size_in_bytes'] for d in kept))}), "
        f"delete {len(doomed)} ({human_size(reclaim)})"
    )
    return lines


def prune(gh, repository, delete):
    """List, select and optionally delete. Returns (decisions, deleted ids, failure messages)."""
    decisions = select_caches(gh.list_caches(repository))
    deleted, failures = [], []
    if delete:
        for decision in decisions:
            if decision.action != "delete":
                continue
            cache_id = decision.entry["id"]
            try:
                existed = gh.delete_cache(repository, cache_id)
            except RuntimeError as error:
                failures.append(f"cache {cache_id} {decision.entry['key']}: {error}")
                continue
            if existed:
                deleted.append(cache_id)
            else:
                print(f"cache {cache_id} was already deleted", file=sys.stderr)
    return decisions, deleted, failures


def main(argv=None, gh=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", help="owner/name; defaults to $GITHUB_REPOSITORY or the current repository")
    parser.add_argument("--delete", action="store_true", help="delete the superseded caches (default: dry run)")
    args = parser.parse_args(argv)
    gh = gh or GhCli()
    try:
        repository = args.repo or gh.default_repository()
        decisions, deleted, failures = prune(gh, repository, args.delete)
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{repository}: {'delete' if args.delete else 'dry run'}")
    print("\n".join(render_plan(decisions)))
    if args.delete:
        print(f"deleted {len(deleted)} caches")
    else:
        print("dry run: nothing deleted; pass --delete to delete")
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
