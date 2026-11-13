//! `bme catalog split` and `bme catalog merge` against the bundled catalog in `catalog/`.

mod common;

use common::{Run, Sandbox, s};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A dropped variant: patch id, firmware build, owning board.
type DroppedVariant = (&'static str, &'static str, &'static str);

/// An edit applied to one record document.
type Edit = dyn Fn(&mut Value);

const MR9A: &str = "machinist-mr9a-pro-q87-rev-1.2";
const PR9: &str = "machinist-pr9-b85";
const MR9A_BUILD: &str = "mnx99mr9apro-230322";
const PR9_BUILD: &str = "x99ha00m-20221202";
const MR9A_CATALOG: &str = "mr9a-pro-rev1.2";
const PR9_CATALOG: &str = "pr9-b85";

fn bundled() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog")
}

/// Every file below `root` as `(relative path, bytes)`.
fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for (relative, bytes) in read_tree(from) {
        let target = to.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
}

fn json_file(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn ok(run: Run) -> Run {
    assert_eq!(
        run.code, 0,
        "(exit code): expected 0\nstdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    run
}

fn split(sandbox: &Sandbox, board: &str, name: &str, id: &str) -> (PathBuf, Value) {
    let dir = sandbox.path(name);
    let run = ok(sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        board,
        "-o",
        s(&dir),
        "--id",
        id,
        "--json",
    ]));
    (dir, run.json()["data"].clone())
}

/// Both splits of the bundled catalog, ready to merge.
fn both_splits(sandbox: &Sandbox) -> (PathBuf, PathBuf) {
    (
        split(sandbox, MR9A, "mr9a", MR9A_CATALOG).0,
        split(sandbox, PR9, "pr9", PR9_CATALOG).0,
    )
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

fn assert_valid_and_indexed(sandbox: &Sandbox, dir: &Path) -> Value {
    let validate = ok(sandbox.run(["catalog", "validate", s(dir), "--json"]));
    ok(sandbox.run(["catalog", "index", s(dir), "--check"]));
    validate.json()["data"].clone()
}

#[test]
fn splitting_the_mr9a_board_keeps_17_patches_38_findings_and_6_evidence_records() {
    let sandbox = Sandbox::new();
    let (dir, reply) = split(&sandbox, MR9A, "mr9a", MR9A_CATALOG);
    let summary = assert_valid_and_indexed(&sandbox, &dir);
    assert_eq!(summary["boards"], json!([MR9A]));
    assert_eq!(
        (
            summary["patches"].clone(),
            summary["findings"].clone(),
            summary["evidence"].clone()
        ),
        (json!(17), json!(38), json!(6))
    );
    assert_eq!(reply["dropped"]["patches"], json!(["S01", "S02"]));
    assert_eq!(reply["dropped"]["findings"], json!(["S01", "S02"]));
    assert_eq!(reply["dropped"]["evidence"], json!([]));
    assert_eq!(reply["dropped"]["provenance"], json!([]));
    assert_eq!(
        reply["kept"]["provenance"],
        json!(["provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm"])
    );
}

#[test]
fn splitting_the_pr9_board_keeps_17_patches_27_findings_and_no_evidence() {
    let sandbox = Sandbox::new();
    let (dir, reply) = split(&sandbox, PR9, "pr9", PR9_CATALOG);
    let summary = assert_valid_and_indexed(&sandbox, &dir);
    assert_eq!(summary["boards"], json!([PR9]));
    assert_eq!(
        (
            summary["patches"].clone(),
            summary["findings"].clone(),
            summary["evidence"].clone()
        ),
        (json!(17), json!(27), json!(0))
    );
    assert_eq!(
        reply["dropped"]["patches"],
        json!(["H01", "MRC-BREADCRUMBS"])
    );
    assert_eq!(
        reply["dropped"]["findings"],
        json!([
            "A01", "A04", "A05", "A06", "B12", "H01", "H03", "H04", "H06", "H13", "H14", "H15",
            "R02"
        ])
    );
    assert_eq!(reply["dropped"]["evidence"].as_array().unwrap().len(), 6);
    assert_eq!(
        reply["dropped"]["provenance"],
        json!(["provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm"])
    );
    assert!(
        !dir.join("provenance/MRC-BREADCRUMBS").exists(),
        "(PR9 split): expected the dropped patch's provenance directory absent"
    );
}

#[test]
fn split_text_lists_what_it_dropped() {
    let sandbox = Sandbox::new();
    let dir = sandbox.path("pr9");
    let run = ok(sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        PR9,
        "-o",
        s(&dir),
        "--id",
        PR9_CATALOG,
    ]));
    let first = format!("Split board {PR9} of official 1.3.0 into {}", s(&dir));
    for expected in [
        first.as_str(),
        "kept      17 patches, 27 findings, 0 evidence records, 0 provenance files",
        "dropped   patches: H01 MRC-BREADCRUMBS",
        "dropped   provenance files: provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm",
    ] {
        assert!(
            run.stdout.contains(expected),
            "(split text): expected {expected:?} | received:\n{}",
            run.stdout
        );
    }
}

#[test]
fn split_writes_the_scaffold_that_catalog_init_writes() {
    let sandbox = Sandbox::new();
    let (dir, reply) = split(&sandbox, MR9A, "mr9a", MR9A_CATALOG);
    let init = sandbox.path("init");
    ok(sandbox.run(["catalog", "init", s(&init), "--id", MR9A_CATALOG]));
    for name in ["README.md", ".gitignore", ".gitattributes"] {
        assert_eq!(
            fs::read(dir.join(name)).unwrap(),
            fs::read(init.join(name)).unwrap(),
            "({name}): expected the bytes `catalog init` writes"
        );
    }
    for name in [
        "boards",
        "evidence",
        "findings",
        "notes",
        "patches",
        "provenance",
        "work",
    ] {
        assert!(dir.join(name).is_dir(), "({name}/): expected a directory");
    }
    assert!(fs::read_dir(dir.join("notes")).unwrap().next().is_none());
    let manifest = json_file(&dir.join("catalog.json"));
    assert_eq!(manifest["version"], "0.1.0");
    assert_eq!(
        manifest["engine"],
        json_file(&init.join("catalog.json"))["engine"]
    );
    assert_eq!(
        reply["files"],
        json!(["README.md", ".gitignore", ".gitattributes", "catalog.json"])
    );
}

#[test]
fn split_reads_a_catalog_directory_and_names_it_in_the_reply() {
    let sandbox = Sandbox::new();
    let (mr9a, _) = split(&sandbox, MR9A, "mr9a", MR9A_CATALOG);
    // The MR9A split holds one board, so splitting it again keeps everything.
    let again = sandbox.path("again");
    let run = ok(sandbox.run([
        "catalog",
        "split",
        s(&mr9a),
        "--board",
        MR9A,
        "-o",
        s(&again),
        "--id",
        "again",
        "--title",
        "Again",
        "--json",
    ]));
    let data = &run.json()["data"];
    assert_eq!(data["source"]["catalog"], MR9A_CATALOG);
    assert_eq!(data["dropped"]["patches"], json!([]));
    assert_eq!(data["title"], "Again");
    assert_eq!(
        read_tree(&again)
            .into_iter()
            .filter(|(p, _)| p.contains('/'))
            .collect::<Vec<_>>(),
        read_tree(&mr9a)
            .into_iter()
            .filter(|(p, _)| p.contains('/'))
            .collect::<Vec<_>>(),
        "(second split): expected the same records byte for byte"
    );
}

#[test]
fn merging_the_two_splits_agrees_and_reports_the_shared_records() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let run = ok(sandbox.run(["catalog", "merge", s(&mr9a), s(&pr9), "--check", "--json"]));
    let data = &run.json()["data"];
    assert_eq!(data["agree"], true);
    assert_eq!(data["catalogs"], json!([MR9A_CATALOG, PR9_CATALOG]));
    assert_eq!(
        data["merged"],
        json!({"boards": 2, "patches": 19, "findings": 40, "evidence": 6, "provenance": 1})
    );
    assert_eq!(data["shared"]["boards"], json!([]));
    assert_eq!(data["shared"]["patches"].as_array().unwrap().len(), 15);
    assert_eq!(data["shared"]["findings"].as_array().unwrap().len(), 25);
    let patches = strings(&data["shared"]["patches"]);
    assert!(
        patches.contains(&"B02-B03"),
        "(shared patches): expected B02-B03 | received {patches:?}"
    );
    assert!(!patches.contains(&"H01") && !patches.contains(&"S01"));

    let text = ok(sandbox.run(["catalog", "merge", s(&pr9), s(&mr9a), "--check"]));
    assert_eq!(
        text.stdout,
        format!(
            "The catalogs agree: {PR9_CATALOG}, {MR9A_CATALOG}\n  merged   2 boards, 19 patches, 40 findings, 6 evidence records, 1 provenance files\n  shared   0 boards, 15 patches, 25 findings, 0 evidence records, 0 provenance files\n"
        )
    );
}

#[test]
fn merge_check_writes_nothing() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let before = (read_tree(&mr9a), read_tree(&pr9));
    ok(sandbox.run(["catalog", "merge", s(&mr9a), s(&pr9), "--check"]));
    assert_eq!((read_tree(&mr9a), read_tree(&pr9)), before);
    let entries: Vec<_> = fs::read_dir(sandbox.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        !entries.iter().any(|name| name == "merge-check"),
        "(--check): expected no output directory | received {entries:?}"
    );
}

/// The bundled catalog's documents by path, without `catalog.json`.
fn documents(root: &Path) -> BTreeMap<String, Value> {
    read_tree(root)
        .into_iter()
        .filter(|(path, _)| path.ends_with(".json") && path != "catalog.json")
        .map(|(path, bytes)| (path, serde_json::from_slice(&bytes).unwrap()))
        .collect()
}

#[test]
fn merging_official_with_both_splits_reproduces_every_bundled_record() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let merged = sandbox.path("merged");
    ok(sandbox.run([
        "catalog",
        "merge",
        "official",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&merged),
        "--id",
        "rebuilt",
        "--title",
        "Rebuilt",
        "--version",
        "2.0.0",
    ]));
    assert_valid_and_indexed(&sandbox, &merged);

    assert_eq!(
        documents(&merged),
        documents(&bundled()),
        "(merged records): expected the bundled documents"
    );
    let (merged_files, bundled_files) = (read_tree(&merged), read_tree(&bundled()));
    let provenance = |tree: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, Vec<u8>> {
        tree.iter()
            .filter(|(p, _)| p.starts_with("provenance/"))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect()
    };
    assert_eq!(provenance(&merged_files), provenance(&bundled_files));
    assert!(!provenance(&bundled_files).is_empty());

    let (new, old) = (
        json_file(&merged.join("catalog.json")),
        json_file(&bundled().join("catalog.json")),
    );
    let identity = |mut manifest: Value| {
        let object = manifest.as_object_mut().unwrap();
        let files: Vec<Value> = object
            .remove("files")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].clone())
            .collect();
        for key in ["id", "title", "version", "description"] {
            object.remove(key);
        }
        (manifest, files)
    };
    assert_eq!(
        identity(new.clone()),
        identity(old),
        "(catalog.json): expected only id, title, version and description to differ"
    );
    assert_eq!(
        (
            new["id"].as_str(),
            new["title"].as_str(),
            new["version"].as_str()
        ),
        (Some("rebuilt"), Some("Rebuilt"), Some("2.0.0"))
    );
    assert!(new.get("description").is_none());
}

/// Findings whose code references the bundled catalog lists PR9 build first. A merge keeps
/// first-seen order, so `merge MR9A PR9` lists the MR9A reference first. The bundled
/// `affects.builds` lists MR9A first, so no source order reproduces both lists.
const REFERENCES_IN_PR9_FIRST_ORDER: [&str; 5] = ["B09", "H02", "H05", "H09", "H10"];

/// Sort `owner.references` of a finding, the one list the merge order changes.
fn references_sorted(mut document: Value) -> Value {
    if let Some(list) = document["owner"]["references"].as_array_mut() {
        list.sort_by_key(Value::to_string);
    }
    document
}

#[test]
fn merging_only_the_splits_loses_exactly_the_four_not_applicable_variants() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let merged = sandbox.path("merged");
    ok(sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&merged),
        "--id",
        "two-boards",
    ]));
    assert_valid_and_indexed(&sandbox, &merged);

    // The expectation: the bundled catalog minus the four variants and their board entries.
    let dropped: [DroppedVariant; 4] = [
        ("S01", MR9A_BUILD, MR9A),
        ("S02", MR9A_BUILD, MR9A),
        ("H01", PR9_BUILD, PR9),
        ("MRC-BREADCRUMBS", PR9_BUILD, PR9),
    ];
    let mut expected = documents(&bundled());
    for (patch, build, board) in dropped {
        let record = expected.get_mut(&format!("patches/{patch}.json")).unwrap();
        let variant = record["variants"]
            .as_object_mut()
            .unwrap()
            .remove(build)
            .unwrap();
        assert_eq!(
            variant["status"], "not-applicable",
            "(patch {patch} variant {build}): expected a not-applicable variant"
        );
        let patches = expected.get_mut(&format!("boards/{board}.json")).unwrap()["patches"]
            .as_array_mut()
            .unwrap();
        let before = patches.len();
        patches.retain(|id| id != patch);
        assert_eq!(
            patches.len(),
            before - 1,
            "(board {board} patches): expected {patch} listed once"
        );
    }
    let merged_documents = documents(&merged);
    assert_eq!(
        merged_documents.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "(merged record files)"
    );
    // Everything else is equal; only first-seen order may differ, in five findings.
    let reordered: Vec<&str> = expected
        .iter()
        .filter(|(path, document)| merged_documents[*path] != **document)
        .map(|(path, document)| {
            assert_eq!(
                references_sorted(merged_documents[path].clone()),
                references_sorted(document.clone()),
                "({path}): expected only the order of owner.references to differ"
            );
            path.strip_prefix("findings/")
                .unwrap()
                .strip_suffix(".json")
                .unwrap()
        })
        .collect();
    assert_eq!(
        reordered, REFERENCES_IN_PR9_FIRST_ORDER,
        "(findings with reordered references)"
    );
    assert_eq!(
        read_tree(&merged)
            .keys()
            .filter(|p| p.starts_with("provenance/"))
            .count(),
        1
    );
}

/// Copy `source` to `name`, edit `edit(path, document)` for the records it names, and re-index it.
fn edited_copy(sandbox: &Sandbox, source: &Path, name: &str, edits: &[(&str, &Edit)]) -> PathBuf {
    let copy = sandbox.path(name);
    copy_tree(source, &copy);
    for (relative, edit) in edits {
        let path = copy.join(relative);
        let mut document = json_file(&path);
        edit(&mut document);
        fs::write(
            &path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
    }
    ok(sandbox.run(["catalog", "index", s(&copy)]));
    copy
}

#[test]
fn merge_check_names_the_record_field_values_and_catalogs_of_each_drift() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let original_title = json_file(&mr9a.join("patches/B02-B03.json"))["title"]
        .as_str()
        .unwrap()
        .to_string();
    let original_description = json_file(&mr9a.join("findings/B09.json"))["description"]
        .as_str()
        .unwrap()
        .to_string();
    let drifted = edited_copy(
        &sandbox,
        &pr9,
        "pr9-drifted",
        &[
            ("patches/B02-B03.json", &|d| {
                d["title"] = json!("Split DIMM counters")
            }),
            ("findings/B09.json", &|d| {
                d["description"] = json!("Reworded defect text")
            }),
        ],
    );
    let run = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&drifted),
        "--check",
        "--json",
    ]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    let message = run.json()["error"]["message"].as_str().unwrap().to_string();
    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(
        lines,
        [
            format!(
                "patch B02-B03: title: expected the same value in every catalog | received {} ({MR9A_CATALOG}) and \"Split DIMM counters\" ({PR9_CATALOG})",
                json!(original_title)
            ),
            format!(
                "finding B09: description: expected the same value in every catalog | received {} ({MR9A_CATALOG}) and \"Reworded defect text\" ({PR9_CATALOG})",
                json!(original_description)
            ),
        ],
        "(merge --check): expected one line per drifted field"
    );
}

#[test]
fn merge_output_is_refused_on_drift_and_nothing_is_written() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let drifted = edited_copy(
        &sandbox,
        &pr9,
        "pr9-drifted",
        &[("patches/B02-B03.json", &|d| {
            d["limits"] = json!("other limits")
        })],
    );
    let out = sandbox.path("out");
    let run = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&drifted),
        "-o",
        s(&out),
        "--id",
        "out",
        "--json",
    ]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    assert!(
        run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(
                "patch B02-B03: limits: expected the same value in every catalog | received "
            ),
        "{}",
        run.stdout
    );
    assert!(
        !out.exists(),
        "(output): expected nothing written on disagreement"
    );
}

#[test]
fn split_refuses_an_unknown_board_naming_the_known_ids() {
    let sandbox = Sandbox::new();
    let dir = sandbox.path("out");
    let run = sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        "nope",
        "-o",
        s(&dir),
        "--id",
        "x",
        "--json",
    ]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "TARGET_NOT_FOUND")
    );
    assert_eq!(
        run.json()["error"]["message"],
        format!("board: expected one of {MR9A}, {PR9} | received nope")
    );
    assert!(!dir.exists());
}

#[test]
fn split_and_merge_refuse_an_existing_output_directory() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let before = (read_tree(&mr9a), read_tree(&pr9));
    let split = sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        MR9A,
        "-o",
        s(&mr9a),
        "--id",
        "x",
        "--json",
    ]);
    assert_eq!(
        (split.code, split.error_code().as_str()),
        (1, "OUTPUT_EXISTS")
    );
    let merge = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&pr9),
        "--id",
        "x",
        "--json",
    ]);
    assert_eq!(
        (merge.code, merge.error_code().as_str()),
        (1, "OUTPUT_EXISTS")
    );
    assert_eq!(
        (read_tree(&mr9a), read_tree(&pr9)),
        before,
        "(existing directories): expected them untouched"
    );
}

#[test]
fn split_applies_the_catalog_id_rules_before_writing() {
    let sandbox = Sandbox::new();
    let dir = sandbox.path("out");
    let run = sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        MR9A,
        "-o",
        s(&dir),
        "--id",
        "official",
        "--json",
    ]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    assert_eq!(
        run.json()["error"]["message"],
        "catalog id: expected an id other than the reserved \"official\" | received: official"
    );
    assert!(!dir.exists());
}

#[test]
fn merge_refuses_fewer_than_two_sources() {
    let sandbox = Sandbox::new();
    let (mr9a, _) = both_splits(&sandbox);
    let run = sandbox.run(["catalog", "merge", s(&mr9a), "--check", "--json"]);
    assert_eq!((run.code, run.error_code().as_str()), (2, "USAGE"));
    assert_eq!(
        run.json()["error"]["message"],
        "sources: expected at least 2 catalogs | received 1"
    );
}

#[test]
fn merge_refuses_check_together_with_an_output_and_needs_one_of_them() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let out = sandbox.path("out");
    let both = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "--check",
        "-o",
        s(&out),
        "--id",
        "x",
        "--json",
    ]);
    assert_eq!((both.code, both.error_code().as_str()), (2, "USAGE"));
    let message = both.json()["error"]["message"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        message.starts_with("the argument '--check' cannot be used with"),
        "(clap message): expected a --check conflict | received {message}"
    );
    let neither = sandbox.run(["catalog", "merge", s(&mr9a), s(&pr9), "--json"]);
    assert_eq!((neither.code, neither.error_code().as_str()), (2, "USAGE"));
    assert!(!out.exists());
}

#[test]
fn merge_output_needs_an_id_and_a_semantic_version() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let out = sandbox.path("out");
    let no_id = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!((no_id.code, no_id.error_code().as_str()), (2, "USAGE"));
    let bad = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&out),
        "--id",
        "x",
        "--version",
        "one",
        "--json",
    ]);
    assert_eq!((bad.code, bad.error_code().as_str()), (2, "USAGE"));
    assert!(
        bad.json()["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("version: expected a semantic version | received \"one\""),
        "{}",
        bad.stdout
    );
    assert!(!out.exists());
}

#[test]
fn merge_names_the_source_that_cannot_be_read() {
    let sandbox = Sandbox::new();
    let (mr9a, _) = both_splits(&sandbox);
    let missing = sandbox.path("absent");
    let run = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&missing),
        "--check",
        "--json",
    ]);
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert!(
        run.json()["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!("catalog {}:", s(&missing))),
        "{}",
        run.stdout
    );
}

#[test]
fn capabilities_list_split_and_merge_without_network() {
    let sandbox = Sandbox::new();
    let capabilities = sandbox.run(["capabilities", "--json"]).json();
    let commands = capabilities["data"]["commands"].as_array().unwrap();
    let writes = |name: &str| -> Value {
        let command = commands
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("(capabilities): expected {name} | received {commands:?}"));
        assert_eq!(command["network"], false, "({name})");
        command["writes"].clone()
    };
    assert_eq!(
        writes("catalog split"),
        json!(["device repository directory"])
    );
    assert_eq!(writes("catalog merge --check"), json!([]));
    assert_eq!(writes("catalog merge -o"), json!(["catalog directory"]));
}
