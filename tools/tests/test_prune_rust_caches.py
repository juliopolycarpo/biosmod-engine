"""Tests for tools/prune-rust-caches.py: selection, paging, dry run and deletion."""

import contextlib
import importlib.util
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "prune-rust-caches.py"
spec = importlib.util.spec_from_file_location("prune_rust_caches", SCRIPT)
prune = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prune)

MAIN = "refs/heads/main"
_next_id = [100]


def cache(key, created_at, ref=MAIN, size=1000, cache_id=None):
    """Build an entry shaped like one item of GitHub's `actions_caches` array."""
    if cache_id is None:
        _next_id[0] += 1
        cache_id = _next_id[0]
    return {"id": cache_id, "key": key, "ref": ref, "created_at": created_at, "size_in_bytes": size,
            "version": "f" * 64, "last_accessed_at": created_at}


def by_id(decisions):
    return {d.entry["id"]: d for d in decisions}


class FakeGh:
    """In-memory stand-in for GhCli: serves a fixed listing and records delete calls."""

    def __init__(self, entries, missing=(), failing=()):
        self.entries = entries
        self.missing = set(missing)  # ids that answer HTTP 404
        self.failing = set(failing)  # ids that answer a server error
        self.deleted = []
        self.listed = []

    def default_repository(self):
        return "owner/repo"

    def list_caches(self, repository):
        self.listed.append(repository)
        return list(self.entries)

    def delete_cache(self, repository, cache_id):
        if cache_id in self.failing:
            raise RuntimeError(f"gh api DELETE {cache_id} exited 1: HTTP 500")
        self.deleted.append(cache_id)
        return cache_id not in self.missing


class ScriptedGh(prune.GhCli):
    """GhCli whose subprocess layer replays canned stdout and records the gh arguments."""

    def __init__(self, stdout="[]", failure=None):
        self.stdout = stdout
        self.failure = failure
        self.calls = []

    def run(self, args):
        self.calls.append(args)
        if self.failure:
            raise RuntimeError(self.failure)
        return self.stdout


class FamilyKeyTests(unittest.TestCase):
    def test_family_drops_the_two_hash_segments(self):
        self.assertEqual(prune.family_of("v0-rust-test-Windows_NT-x64-6a930898-7d7c5a16"), "v0-rust-test-Windows_NT-x64")
        self.assertEqual(prune.family_of("v0-rust-gui-linux-Linux-x64-264d3fa1-1cba4c9e"), "v0-rust-gui-linux-Linux-x64")
        self.assertEqual(prune.family_of("v0-rust-archive-linux-Linux-x64-a5cc1cd7-7d7c5a16"), "v0-rust-archive-linux-Linux-x64")
        self.assertEqual(prune.family_of("v0-rust-test-Darwin-arm64-2d458045-1cba4c9e"), "v0-rust-test-Darwin-arm64")

    def test_keys_outside_the_grammar_have_no_family(self):
        for key in (
            "Linux-cargo-registry-abc",
            "v0-rust-gui-linux-Linux-x64-264d3fa1",  # one hash segment
            "v0-rust-gui-linux-Linux-x64-264d3fa1-1cba4c9",  # 7 hex digits
            "v0-rust-gui-linux-Linux-x64-264D3FA1-1cba4c9e",  # upper-case hex
            "v0-rust-gui-linux-FreeBSD-x64-264d3fa1-1cba4c9e",  # unknown OS
            "v1-rust-test-Linux-x64-264d3fa1-1cba4c9e",  # other cache version
            "v0-rust-test-Linux-x64-264d3fa1-1cba4c9e-extra",
            "",
        ):
            self.assertIsNone(prune.family_of(key), key)


class SelectionTests(unittest.TestCase):
    def test_newest_kept_and_older_generations_deleted(self):
        old = cache("v0-rust-test-Linux-x64-cdee7d24-4fb24c92", "2026-11-13T07:05:37.393763Z")
        mid = cache("v0-rust-test-Linux-x64-c7ddb2ea-f9b8cb2e", "2026-11-15T00:18:25.163408Z")
        new = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:15:31.628127Z")
        decisions = by_id(prune.select_caches([old, new, mid]))
        self.assertEqual(decisions[new["id"]].action, "keep")
        self.assertEqual(decisions[new["id"]].reason, "newest of its family")
        for entry in (old, mid):
            self.assertEqual(decisions[entry["id"]].action, "delete")
            self.assertIn(f"superseded by cache {new['id']}", decisions[entry["id"]].reason)

    def test_output_keeps_input_order(self):
        entries = [cache("v0-rust-lint-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-15T01:00:00Z"),
                   cache("v0-rust-lint-Linux-x64-a5cc1cd7-7d7c5a16", "2026-11-15T02:00:00Z")]
        self.assertEqual([d.entry for d in prune.select_caches(entries)], entries)

    def test_sole_entry_is_kept(self):
        only = cache("v0-rust-msrv-Linux-x64-47b586dd-1cba4c9e", "2026-11-15T01:14:46Z")
        [decision] = prune.select_caches([only])
        self.assertEqual((decision.action, decision.reason), ("keep", "only entry of its family"))

    def test_families_are_independent(self):
        entries = [
            cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00Z"),
            cache("v0-rust-test-Windows_NT-x64-6a930898-1cba4c9e", "2026-11-14T01:00:00Z"),
            cache("v0-rust-test-Darwin-arm64-2d458045-1cba4c9e", "2026-11-13T01:00:00Z"),
            cache("v0-rust-lint-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-12T01:00:00Z"),
        ]
        self.assertEqual({d.action for d in prune.select_caches(entries)}, {"keep"})

    def test_multi_segment_job_names_and_windows_os_group_correctly(self):
        gui_new = cache("v0-rust-gui-linux-Linux-x64-264d3fa1-1cba4c9e", "2026-11-15T01:09:56Z")
        gui_old = cache("v0-rust-gui-linux-Linux-x64-264d3fa1-6d8f5649", "2026-11-13T06:51:05Z")
        archive_new = cache("v0-rust-archive-linux-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-15T01:06:11Z")
        archive_old = cache("v0-rust-archive-linux-Linux-x64-264d3fa1-4fb24c92", "2026-11-13T07:23:18Z")
        win_new = cache("v0-rust-test-Windows_NT-x64-6a930898-1cba4c9e", "2026-11-15T01:08:02Z")
        win_old = cache("v0-rust-test-Windows_NT-x64-6e22454c-4fb24c92", "2026-11-13T07:05:59Z")
        # A job named `gui` must not be confused with the `gui-linux` family.
        gui_plain = cache("v0-rust-gui-Linux-x64-264d3fa1-1cba4c9e", "2026-11-10T00:00:00Z")
        decisions = by_id(prune.select_caches([gui_new, gui_old, archive_new, archive_old, win_new, win_old, gui_plain]))
        self.assertEqual({i: d.action for i, d in decisions.items()}, {
            gui_new["id"]: "keep", gui_old["id"]: "delete",
            archive_new["id"]: "keep", archive_old["id"]: "delete",
            win_new["id"]: "keep", win_old["id"]: "delete",
            gui_plain["id"]: "keep",
        })
        self.assertEqual(decisions[win_old["id"]].family, "v0-rust-test-Windows_NT-x64")

    def test_other_refs_are_kept_even_when_a_main_entry_is_newer(self):
        main = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00Z")
        pr = cache("v0-rust-test-Linux-x64-c7ddb2ea-7d7c5a16", "2026-11-10T01:00:00Z", ref="refs/pull/12/merge")
        branch = cache("v0-rust-test-Linux-x64-cdee7d24-7d7c5a16", "2026-11-09T01:00:00Z", ref="refs/heads/feature")
        decisions = by_id(prune.select_caches([main, pr, branch]))
        self.assertEqual(decisions[main["id"]].action, "keep")
        for entry in (pr, branch):
            self.assertEqual(decisions[entry["id"]].action, "keep")
            self.assertEqual(decisions[entry["id"]].reason, f"ref {entry['ref']} is not refs/heads/main")
            self.assertIsNone(decisions[entry["id"]].family)

    def test_non_main_ref_never_becomes_the_replacement(self):
        # The newest entry is on a PR ref; the main entry must not be deleted because of it.
        main = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-09T01:00:00Z")
        pr = cache("v0-rust-test-Linux-x64-c7ddb2ea-7d7c5a16", "2026-11-15T01:00:00Z", ref="refs/pull/12/merge")
        self.assertEqual({d.action for d in prune.select_caches([main, pr])}, {"keep"})

    def test_keys_outside_the_grammar_are_kept(self):
        foreign = [cache("Linux-cargo-registry-1", "2026-11-01T00:00:00Z"),
                   cache("Linux-cargo-registry-2", "2026-11-02T00:00:00Z"),
                   cache("v0-rust-test-Linux-x64-c7ddb2ea", "2026-11-03T00:00:00Z")]
        for decision in prune.select_caches(foreign):
            self.assertEqual((decision.action, decision.reason), ("keep", "key does not match the rust-cache grammar"))

    def test_equal_timestamps_keep_the_higher_id(self):
        low = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00Z", cache_id=5)
        high = cache("v0-rust-test-Linux-x64-cdee7d24-7d7c5a16", "2026-11-15T01:00:00Z", cache_id=9)
        decisions = by_id(prune.select_caches([low, high]))
        self.assertEqual((decisions[9].action, decisions[5].action), ("keep", "delete"))

    def test_fractional_seconds_order_correctly(self):
        a = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00.5Z")
        b = cache("v0-rust-test-Linux-x64-cdee7d24-7d7c5a16", "2026-11-15T01:00:00.123456Z")
        decisions = by_id(prune.select_caches([b, a]))
        self.assertEqual((decisions[a["id"]].action, decisions[b["id"]].action), ("keep", "delete"))

    def test_every_family_keeps_exactly_one_main_entry(self):
        entries = [cache(f"v0-rust-test-Linux-x64-{env}-{lock}", f"2026-11-{day:02d}T00:00:00Z")
                   for day, (env, lock) in enumerate([("aaaaaaaa", "11111111"), ("bbbbbbbb", "22222222"), ("cccccccc", "33333333")], 1)]
        decisions = prune.select_caches(entries)
        self.assertEqual([d.action for d in decisions].count("keep"), 1)
        self.assertEqual(by_id(decisions)[entries[2]["id"]].action, "keep")

    def test_duplicate_ids_are_rejected(self):
        one = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00Z", cache_id=7)
        two = cache("v0-rust-test-Linux-x64-cdee7d24-7d7c5a16", "2026-11-14T01:00:00Z", cache_id=7)
        with self.assertRaisesRegex(ValueError, r"expected unique ids, received id 7 more than once"):
            prune.select_caches([one, two])

    def test_malformed_entries_name_the_received_value(self):
        good = cache("v0-rust-test-Linux-x64-c7ddb2ea-1cba4c9e", "2026-11-15T01:00:00Z")
        cases = [
            (dict(good, id="7"), r"expected id to be int, received '7'"),
            (dict(good, size_in_bytes=None), r"expected size_in_bytes to be int, received None"),
            (dict(good, created_at="yesterday"), r"expected created_at as UTC ISO 8601, received 'yesterday'"),
            (dict(good, key=None), r"expected key to be str, received None"),
            (dict(good, id=0), r"expected a positive id"),
            ("not-an-object", r"expected an object with id, key, ref"),
        ]
        for entry, message in cases:
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, message):
                prune.select_caches([entry])


class PagingTests(unittest.TestCase):
    def pages(self, *page_entries, total=None):
        total = sum(len(p) for p in page_entries) if total is None else total
        return json.dumps([{"total_count": total, "actions_caches": p} for p in page_entries])

    def test_entries_from_every_page_are_returned(self):
        a = cache("v0-rust-lint-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-15T01:00:00Z")
        b = cache("v0-rust-msrv-Linux-x64-47b586dd-1cba4c9e", "2026-11-15T01:00:00Z")
        self.assertEqual(prune.parse_pages(self.pages([a], [b])), [a, b])

    def test_empty_listing(self):
        self.assertEqual(prune.parse_pages(self.pages([])), [])
        self.assertEqual(prune.parse_pages("[]"), [])

    def test_short_listing_is_rejected(self):
        a = cache("v0-rust-lint-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-15T01:00:00Z")
        with self.assertRaisesRegex(ValueError, r"expected 3 entries \(total_count\), received 1"):
            prune.parse_pages(self.pages([a], total=3))

    def test_wrong_shapes_are_rejected(self):
        for text, message in (
            ("not json", r"expected a JSON array of pages, received 'not json'"),
            ('{"actions_caches": []}', r"expected a JSON array of pages, received dict"),
            ('[{"total_count": 0}]', r"expected an object with an actions_caches array"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                prune.parse_pages(text)

    def test_list_caches_requests_main_rust_caches_with_pagination(self):
        gh = ScriptedGh(self.pages([]))
        self.assertEqual(gh.list_caches("owner/repo"), [])
        [args] = gh.calls
        self.assertEqual(args[:3], ["api", "--paginate", "--slurp"])
        self.assertEqual(args[3], "repos/owner/repo/actions/caches?ref=refs/heads/main&key=v0-rust-&per_page=100")

    def test_delete_cache_names_one_id_and_treats_404_as_gone(self):
        gh = ScriptedGh()
        self.assertTrue(gh.delete_cache("owner/repo", 42))
        self.assertEqual(gh.calls, [["api", "--method", "DELETE", "repos/owner/repo/actions/caches/42"]])
        self.assertFalse(ScriptedGh(failure="gh api exited 1: gh: Not Found (HTTP 404)").delete_cache("owner/repo", 42))
        with self.assertRaisesRegex(RuntimeError, "HTTP 500"):
            ScriptedGh(failure="gh api exited 1: HTTP 500").delete_cache("owner/repo", 42)


class DefaultRepositoryTests(unittest.TestCase):
    def test_environment_wins_without_calling_gh(self):
        gh = ScriptedGh()
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/from-env"}):
            self.assertEqual(gh.default_repository(), "owner/from-env")
        self.assertEqual(gh.calls, [])

    def test_falls_back_to_the_current_repository(self):
        gh = ScriptedGh(stdout="owner/from-gh\n")
        with mock.patch.dict(os.environ):
            os.environ.pop("GITHUB_REPOSITORY", None)
            self.assertEqual(gh.default_repository(), "owner/from-gh")
        self.assertEqual(gh.calls, [["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]])


class PruneTests(unittest.TestCase):
    def setUp(self):
        self.new = cache("v0-rust-gui-linux-Linux-x64-264d3fa1-1cba4c9e", "2026-11-15T01:09:56Z", size=3 * 1024**3)
        self.old = cache("v0-rust-gui-linux-Linux-x64-264d3fa1-6d8f5649", "2026-11-13T06:51:05Z", size=2 * 1024**3)
        self.pr = cache("v0-rust-gui-linux-Linux-x64-264d3fa1-7d7c5a16", "2026-11-14T06:51:05Z", ref="refs/pull/3/merge")
        self.entries = [self.new, self.old, self.pr]

    def run_main(self, gh, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = prune.main(list(argv), gh=gh)
        return code, out.getvalue(), err.getvalue()

    def test_default_is_a_dry_run(self):
        gh = FakeGh(self.entries)
        code, out, _ = self.run_main(gh)
        self.assertEqual((code, gh.deleted), (0, []))
        self.assertIn("owner/repo: dry run", out)
        self.assertIn("dry run: nothing deleted; pass --delete to delete", out)
        self.assertIn(f"KEEP   {self.new['id']} {self.new['key']}", out)
        self.assertIn(f"DELETE {self.old['id']} {self.old['key']}", out)
        self.assertIn("2.00 GiB", out)
        self.assertIn("keep 2 (3.00 GiB), delete 1 (2.00 GiB)", out)
        self.assertIn(f"untouched {self.pr['id']}", out)

    def test_delete_flag_deletes_only_superseded_main_entries(self):
        gh = FakeGh(self.entries)
        code, out, _ = self.run_main(gh, "--delete")
        self.assertEqual((code, gh.deleted), (0, [self.old["id"]]))
        self.assertIn("deleted 1 caches", out)

    def test_repo_flag_is_passed_through(self):
        gh = FakeGh(self.entries)
        self.run_main(gh, "--repo", "someone/else")
        self.assertEqual(gh.listed, ["someone/else"])

    def test_already_deleted_cache_is_not_an_error(self):
        gh = FakeGh(self.entries, missing={self.old["id"]})
        code, out, err = self.run_main(gh, "--delete")
        self.assertEqual(code, 0)
        self.assertIn("deleted 0 caches", out)
        self.assertIn(f"cache {self.old['id']} was already deleted", err)

    def test_failed_deletion_is_reported_and_exits_nonzero(self):
        other_new = cache("v0-rust-lint-Linux-x64-a5cc1cd7-1cba4c9e", "2026-11-15T01:00:00Z")
        other_old = cache("v0-rust-lint-Linux-x64-a74c6f26-4fb24c92", "2026-11-13T01:00:00Z")
        gh = FakeGh(self.entries + [other_new, other_old], failing={self.old["id"]})
        code, out, err = self.run_main(gh, "--delete")
        self.assertEqual(code, 1)
        self.assertEqual(gh.deleted, [other_old["id"]])  # one failure does not stop the rest
        self.assertIn(f"cache {self.old['id']} {self.old['key']}", err)

    def test_invalid_listing_deletes_nothing(self):
        gh = FakeGh([dict(self.new, size_in_bytes="big")])
        code, _, err = self.run_main(gh, "--delete")
        self.assertEqual((code, gh.deleted), (1, []))
        self.assertIn("expected size_in_bytes to be int, received 'big'", err)

    def test_human_size(self):
        self.assertEqual(prune.human_size(512), "512 B")
        self.assertEqual(prune.human_size(1024), "1.00 KiB")
        self.assertEqual(prune.human_size(1830174068), "1.70 GiB")


if __name__ == "__main__":
    unittest.main()
