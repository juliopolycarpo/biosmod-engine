"""Bundled-catalog source check, with a named fake in place of git and bme."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/check-bundled-catalog-sources.py"
SPEC = importlib.util.spec_from_file_location("check_bundled_catalog_sources", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

COMMIT = "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b"
AGREE = (
    "The catalogs agree: official, pr9-b85\n"
    "  pin      official lists pr9-b85 0.1.0: pinned\n"
)


class FakeGitAndBme:
    """Record every command and answer `bme` with a fixed result.

    Example: FakeGitAndBme(merge=(0, AGREE)) lets git succeed and the merge agree.
    """

    def __init__(self, merge, git_failure=None):
        self.merge = merge
        self.git_failure = git_failure
        self.commands = []

    def __call__(self, command, cwd):
        self.commands.append((command, Path(cwd).name))
        if command[0] == "git":
            if self.git_failure and command[1] == self.git_failure:
                return 128, "fatal: remote error: upload-pack: not our ref"
            return 0, ""
        return self.merge


def catalog_with(root, sources):
    """Write a catalog.json that lists `sources` and return its directory."""
    catalog = root / "catalog"
    catalog.mkdir()
    (catalog / "catalog.json").write_text(json.dumps({"sources": sources}))
    return catalog


def source(**overrides):
    entry = {"id": "pr9-b85", "repository": "https://example.org/pr9", "commit": COMMIT}
    entry.update(overrides)
    return {key: value for key, value in entry.items() if value is not None}


class PinnedSourcesTests(unittest.TestCase):
    def test_returns_id_repository_and_commit_in_order(self):
        manifest = {"sources": [source(), source(id="mr9a", repository="https://example.org/mr9a")]}
        self.assertEqual(
            CHECKER.pinned_sources(manifest),
            [("pr9-b85", "https://example.org/pr9", COMMIT), ("mr9a", "https://example.org/mr9a", COMMIT)],
        )

    def test_refuses_a_catalog_without_sources(self):
        with self.assertRaises(CHECKER.CheckFailed) as raised:
            CHECKER.pinned_sources({})
        self.assertEqual(
            str(raised.exception),
            "catalog.json sources: expected at least one source | received none",
        )

    def test_refuses_a_source_without_repository_or_commit(self):
        with self.assertRaises(CHECKER.CheckFailed) as raised:
            CHECKER.pinned_sources({"sources": [source(repository=None, commit=None)]})
        self.assertEqual(
            str(raised.exception),
            "source pr9-b85: expected repository and commit | received no repository and no commit",
        )


class MovedPinsTests(unittest.TestCase):
    def test_lists_only_the_moved_pin_lines(self):
        output = AGREE + "  pin      official lists mr9a 0.1.0: moved (pinned aa, current bb)\n"
        self.assertEqual(
            CHECKER.moved_pins(output),
            ["pin      official lists mr9a 0.1.0: moved (pinned aa, current bb)"],
        )
        self.assertEqual(CHECKER.moved_pins(AGREE), [])


class CheckTests(unittest.TestCase):
    def run_check(self, fake, sources=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = catalog_with(root, [source()] if sources is None else sources)
            workspace = root / "work"
            workspace.mkdir()
            return CHECKER.check(catalog, ["bme"], fake, workspace)

    def test_fetches_the_pinned_commit_then_merges_with_the_checkout(self):
        fake = FakeGitAndBme(merge=(0, AGREE))
        self.assertEqual(self.run_check(fake), AGREE)
        git = [command for command, _ in fake.commands if command[0] == "git"]
        self.assertEqual(git, CHECKER.fetch_commands("https://example.org/pr9", COMMIT))
        self.assertEqual({cwd for command, cwd in fake.commands if command[0] == "git"}, {"pr9-b85"})
        merge = fake.commands[-1][0]
        self.assertEqual(merge[:3], ["bme", "catalog", "merge"])
        self.assertEqual(merge[-1], "--check")
        self.assertTrue(merge[4].endswith("/work/pr9-b85"), merge)

    def test_a_failed_fetch_names_the_source_and_the_command(self):
        fake = FakeGitAndBme(merge=(0, AGREE), git_failure="fetch")
        with self.assertRaises(CHECKER.CheckFailed) as raised:
            self.run_check(fake)
        self.assertEqual(
            str(raised.exception),
            "source pr9-b85: expected `git fetch --quiet --depth 1 https://example.org/pr9 "
            f"{COMMIT}` to succeed | received exit 128: fatal: remote error: upload-pack: not our ref",
        )

    def test_a_disagreement_fails_with_the_output_of_bme(self):
        fake = FakeGitAndBme(merge=(1, "bme: patch B05: title: expected the same value\n"))
        with self.assertRaises(CHECKER.CheckFailed) as raised:
            self.run_check(fake)
        self.assertEqual(
            str(raised.exception),
            "bundled catalog: expected the same records as its sources | "
            "received: bme: patch B05: title: expected the same value",
        )

    def test_a_moved_pin_fails_although_the_records_agree(self):
        moved = "The catalogs agree\n  pin      official lists pr9-b85 0.1.0: moved (pinned aa, current bb)\n"
        with self.assertRaises(CHECKER.CheckFailed) as raised:
            self.run_check(FakeGitAndBme(merge=(0, moved)))
        self.assertEqual(
            str(raised.exception),
            "bundled catalog: expected every source pinned | "
            "received pin      official lists pr9-b85 0.1.0: moved (pinned aa, current bb)",
        )


if __name__ == "__main__":
    unittest.main()
