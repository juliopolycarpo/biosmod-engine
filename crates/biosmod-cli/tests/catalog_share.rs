//! `bme catalog split` and `bme catalog merge` against the bundled catalog in `catalog/`.

mod common;

use biosmod_core::util::Digest256;
use common::{Run, Sandbox, s};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// An edit applied to one record document.
type Edit = dyn Fn(&mut Value);

const MR9A: &str = "machinist-mr9a-pro-q87-rev-1.2";
const PR9: &str = "machinist-pr9-b85";
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
fn splitting_the_mr9a_board_keeps_19_patches_40_findings_and_6_evidence_records() {
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
        (json!(19), json!(40), json!(6))
    );
    // S01 and S02 do not apply to the MR9A build: the board keeps each verdict and its finding.
    assert_eq!(reply["dropped"]["patches"], json!([]));
    assert_eq!(reply["dropped"]["findings"], json!([]));
    for id in ["S01", "S02"] {
        let finding = json_file(&dir.join(format!("findings/{id}.json")));
        assert_eq!(
            finding["affects"]["builds"],
            json!([]),
            "(finding {id} affects.builds in the MR9A split)"
        );
        let patch = json_file(&dir.join(format!("patches/{id}.json")));
        assert_eq!(
            patch["variants"]["mnx99mr9apro-230322"]["status"], "not-applicable",
            "(patch {id} variant for the MR9A build)"
        );
        let board = json_file(&dir.join(format!("boards/{MR9A}.json")));
        assert!(
            board["patches"].as_array().unwrap().contains(&json!(id))
                && !board["findings"].as_array().unwrap().contains(&json!(id)),
            "(board {MR9A}): expected patch {id} listed and finding {id} not listed"
        );
    }
    assert_eq!(reply["dropped"]["evidence"], json!([]));
    assert_eq!(reply["dropped"]["provenance"], json!([]));
    assert_eq!(
        reply["kept"]["provenance"],
        json!(["provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm"])
    );
}

#[test]
fn splitting_the_pr9_board_keeps_19_patches_28_findings_and_no_evidence() {
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
        (json!(19), json!(28), json!(0))
    );
    // H01 and MRC-BREADCRUMBS do not apply to the PR9 build: the board keeps both verdicts.
    assert_eq!(reply["dropped"]["patches"], json!([]));
    assert_eq!(
        reply["dropped"]["findings"],
        json!([
            "A01", "A04", "A05", "A06", "B12", "H03", "H04", "H06", "H13", "H14", "H15", "R02"
        ])
    );
    assert_eq!(reply["dropped"]["evidence"].as_array().unwrap().len(), 6);
    assert_eq!(reply["dropped"]["provenance"], json!([]));
    assert!(
        dir.join("provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm")
            .is_file(),
        "(PR9 split): expected the provenance of the kept MRC-BREADCRUMBS verdict"
    );
    let h01 = json_file(&dir.join("findings/H01.json"));
    assert_eq!(h01["affects"]["builds"], json!([]), "(finding H01 builds)");
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
    let first = format!("Split board {PR9} of official 1.4.0 into {}", s(&dir));
    for expected in [
        first.as_str(),
        "kept      19 patches, 28 findings, 0 evidence records, 1 provenance files",
        "dropped   patches: none",
        "dropped   findings: A01 A04 A05 A06 B12 H03 H04 H06 H13 H14 H15 R02",
        "dropped   provenance files: none",
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
    // Both splits keep all 19 patches, and 28 of the 40 findings are in both.
    assert_eq!(data["shared"]["patches"].as_array().unwrap().len(), 19);
    assert_eq!(data["shared"]["findings"].as_array().unwrap().len(), 28);
    let patches = strings(&data["shared"]["patches"]);
    for id in ["B02-B03", "H01", "S01", "MRC-BREADCRUMBS"] {
        assert!(
            patches.contains(&id),
            "(shared patches): expected {id} | received {patches:?}"
        );
    }
    assert_eq!(data["pins"], json!([]));

    let text = ok(sandbox.run(["catalog", "merge", s(&pr9), s(&mr9a), "--check"]));
    assert_eq!(
        text.stdout,
        format!(
            "The catalogs agree: {PR9_CATALOG}, {MR9A_CATALOG}\n  merged   2 boards, 19 patches, 40 findings, 6 evidence records, 1 provenance files\n  shared   0 boards, 19 patches, 28 findings, 0 evidence records, 1 provenance files\n"
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
        for key in ["id", "title", "version", "description", "sources"] {
            object.remove(key);
        }
        (manifest, files)
    };
    assert_eq!(
        identity(new.clone()),
        identity(old),
        "(catalog.json): expected only id, title, version, description and sources to differ"
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
    let source_ids: Vec<&str> = new["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| source["id"].as_str().unwrap())
        .collect();
    assert_eq!(source_ids, ["official", MR9A_CATALOG, PR9_CATALOG]);
}

#[test]
fn the_bundled_catalog_is_the_merge_of_its_board_splits() {
    // `catalog/` is generated with `bme catalog merge --bundled` from the board catalogs.
    // A record edited by hand in a way the merge would not write fails here.
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

    let records = |root: &Path| -> BTreeMap<String, Vec<u8>> {
        read_tree(root)
            .into_iter()
            .filter(|(path, _)| path != "catalog.json")
            .collect()
    };
    let (merged_records, bundled_records) = (records(&merged), records(&bundled()));
    assert_eq!(
        merged_records.keys().collect::<Vec<_>>(),
        bundled_records.keys().collect::<Vec<_>>(),
        "(merged record and provenance files)"
    );
    let different: Vec<&String> = bundled_records
        .iter()
        .filter(|(path, bytes)| merged_records[*path] != **bytes)
        .map(|(path, _)| path)
        .collect();
    assert!(
        different.is_empty(),
        "(catalog/): expected every file byte-identical to the merge of its board splits | received differences in {different:?}"
    );
    let sources = json_file(&bundled().join("catalog.json"))["sources"].clone();
    assert_eq!(
        sources.as_array().map(Vec::len),
        Some(2),
        "(catalog/catalog.json sources): expected the two board catalogs it was merged from | received {sources}"
    );
}

#[test]
fn split_writes_the_engine_requirement_of_its_source() {
    let sandbox = Sandbox::new();
    let (mr9a, _) = both_splits(&sandbox);
    // A requirement `catalog init` would never derive from this engine.
    let wide = edited_copy(
        &sandbox,
        &mr9a,
        "mr9a-wide",
        &[("catalog.json", &|d| {
            d["engine"] = json!(">=0.1.0");
        })],
    );
    let (again, _) = split_from(&sandbox, &wide, "again");
    assert_eq!(
        json_file(&again.join("catalog.json"))["engine"],
        ">=0.1.0",
        "(engine of a split of a catalog that declares >=0.1.0)"
    );
    let run = ok(sandbox.run(["catalog", "merge", s(&wide), s(&again), "--check"]));
    assert!(
        run.stdout.starts_with("The catalogs agree"),
        "{}",
        run.stdout
    );
}

/// Split the only board of `source`, a catalog directory, into `name`.
fn split_from(sandbox: &Sandbox, source: &Path, name: &str) -> (PathBuf, Value) {
    let dir = sandbox.path(name);
    let run = ok(sandbox.run([
        "catalog",
        "split",
        s(source),
        "--board",
        MR9A,
        "-o",
        s(&dir),
        "--id",
        name,
        "--json",
    ]));
    (dir, run.json()["data"].clone())
}

#[test]
fn merge_output_records_its_sources_and_the_description() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let merged = sandbox.path("merged");
    let run = ok(sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&merged),
        "--id",
        "two-boards",
        "--description",
        "Two board catalogs, merged.",
        "--json",
    ]));
    let digest = |dir: &Path| Digest256::of(&fs::read(dir.join("catalog.json")).unwrap());
    let expected = json!([
        {"id": MR9A_CATALOG, "version": "0.1.0", "manifest_sha256": digest(&mr9a).to_string()},
        {"id": PR9_CATALOG, "version": "0.1.0", "manifest_sha256": digest(&pr9).to_string()},
    ]);
    let manifest = json_file(&merged.join("catalog.json"));
    assert_eq!(manifest["sources"], expected, "(catalog.json sources)");
    assert_eq!(manifest["description"], "Two board catalogs, merged.");
    assert_eq!(run.json()["data"]["sources"], expected, "(reply sources)");

    // `catalog index` keeps the block and rewrites the same bytes.
    let before = fs::read(merged.join("catalog.json")).unwrap();
    ok(sandbox.run(["catalog", "index", s(&merged)]));
    assert_eq!(fs::read(merged.join("catalog.json")).unwrap(), before);
    assert_valid_and_indexed(&sandbox, &merged);

    // A split keeps the old shape: no sources, no description.
    let split = json_file(&mr9a.join("catalog.json"));
    assert!(split.get("sources").is_none() && split.get("description").is_none());
}

#[test]
fn merge_check_reports_whether_each_pinned_source_still_matches() {
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
    let pinned = ok(sandbox.run(["catalog", "merge", s(&merged), s(&mr9a), s(&pr9), "--check"]));
    assert_eq!(
        pinned.stdout,
        format!(
            "The catalogs agree: two-boards, {MR9A_CATALOG}, {PR9_CATALOG}\n  merged   2 boards, 19 patches, 40 findings, 6 evidence records, 1 provenance files\n  shared   2 boards, 19 patches, 40 findings, 6 evidence records, 1 provenance files\n  pin      two-boards lists {MR9A_CATALOG} 0.1.0: pinned\n  pin      two-boards lists {PR9_CATALOG} 0.1.0: pinned\n"
        )
    );

    // A new version of the PR9 catalog moves its digest; the records still agree.
    let pinned_digest = Digest256::of(&fs::read(pr9.join("catalog.json")).unwrap());
    let moved = edited_copy(
        &sandbox,
        &pr9,
        "pr9-moved",
        &[("catalog.json", &|d| {
            d["version"] = json!("0.2.0");
        })],
    );
    let current_digest = Digest256::of(&fs::read(moved.join("catalog.json")).unwrap());
    let run = ok(sandbox.run([
        "catalog",
        "merge",
        s(&merged),
        s(&mr9a),
        s(&moved),
        "--check",
    ]));
    assert!(
        run.stdout.ends_with(&format!(
            "  pin      two-boards lists {MR9A_CATALOG} 0.1.0: pinned\n  pin      two-boards lists {PR9_CATALOG} 0.1.0: moved (pinned {pinned_digest}, current {current_digest})\n"
        )),
        "(merge --check pin lines) | received:\n{}",
        run.stdout
    );
    let json = ok(sandbox.run([
        "catalog",
        "merge",
        s(&merged),
        s(&mr9a),
        s(&moved),
        "--check",
        "--json",
    ]))
    .json();
    let pins = json["data"]["pins"].as_array().unwrap();
    assert_eq!(
        pins.iter()
            .map(|p| p["state"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["pinned", "moved"]
    );
    assert_eq!(pins[1]["pinned"], pinned_digest.to_string());
    assert_eq!(pins[1]["current"], current_digest.to_string());
}

#[test]
fn merge_names_sources_with_one_catalog_id_by_position() {
    let sandbox = Sandbox::new();
    let (mr9a, _) = both_splits(&sandbox);
    let twin = edited_copy(
        &sandbox,
        &mr9a,
        "mr9a-twin",
        &[("patches/B02-B03.json", &|d| {
            d["title"] = json!("Twin title");
        })],
    );
    let run = sandbox.run(["catalog", "merge", s(&mr9a), s(&twin), "--check", "--json"]);
    assert_eq!(
        (run.code, run.error_code().as_str()),
        (1, "CATALOG_INVALID")
    );
    let message = run.json()["error"]["message"].as_str().unwrap().to_string();
    assert!(
        message.starts_with(
            "patch B02-B03: title: expected the same value in every catalog | received "
        ) && message.ends_with(&format!(
            "({MR9A_CATALOG} (#1)) and \"Twin title\" ({MR9A_CATALOG} (#2))"
        )),
        "(merge --check): expected both sources named by position | received {message}"
    );
}

#[test]
fn merge_description_must_not_be_blank_and_needs_an_output() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let out = sandbox.path("out");
    let blank = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&out),
        "--id",
        "x",
        "--description",
        " ",
        "--json",
    ]);
    assert_eq!((blank.code, blank.error_code().as_str()), (2, "USAGE"));
    assert_eq!(
        blank.json()["error"]["message"],
        "description: expected non-empty text | received an empty value"
    );
    let check = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "--check",
        "--description",
        "x",
        "--json",
    ]);
    assert_eq!((check.code, check.error_code().as_str()), (2, "USAGE"));
    assert!(!out.exists());
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
fn merge_bundled_writes_the_reserved_id_and_refuses_an_id_next_to_it() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    let out = sandbox.path("bundled");
    ok(sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&out),
        "--bundled",
        "--version",
        "1.4.0",
        "--description",
        "Both boards",
    ]));
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("catalog.json")).unwrap()).unwrap();
    assert_eq!(
        (&manifest["id"], &manifest["title"], &manifest["version"]),
        (&json!("official"), &json!("official"), &json!("1.4.0"))
    );
    ok(sandbox.run(["catalog", "validate", s(&out)]));

    let other = sandbox.path("other");
    let both = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&other),
        "--bundled",
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
        message.contains("--bundled") && message.contains("--id"),
        "(clap message): expected a --bundled/--id conflict | received {message}"
    );
    let neither = sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&other),
        "--json",
    ]);
    assert_eq!((neither.code, neither.error_code().as_str()), (2, "USAGE"));
    assert_eq!(
        neither.json()["error"]["message"],
        "merge: expected --check, or -o DIR with --id ID or --bundled | received another combination"
    );
    assert!(!other.exists());
}

#[test]
fn pin_lines_tell_apart_two_sources_with_one_catalog_id() {
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
    // The same catalog id twice: the original, and a copy whose manifest moved.
    let moved = edited_copy(
        &sandbox,
        &pr9,
        "pr9-moved",
        &[("catalog.json", &|d| {
            d["version"] = json!("0.2.0");
        })],
    );
    let run = ok(sandbox.run([
        "catalog",
        "merge",
        s(&merged),
        s(&pr9),
        s(&moved),
        "--check",
    ]));
    assert!(
        run.stdout.contains(&format!(
            "  pin      two-boards lists {PR9_CATALOG} (#2) 0.1.0: pinned\n"
        )),
        "(pin line of the unchanged source) | received:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains(&format!(
            "  pin      two-boards lists {PR9_CATALOG} (#3) 0.1.0: moved (pinned "
        )),
        "(pin line of the moved source) | received:\n{}",
        run.stdout
    );
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

const MR9A_URL: &str = "https://example.org/acme/mr9a-pro";
const PR9_URL: &str = "https://example.org/acme/pr9-b85";
const MR9A_COMMIT: &str = "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b";

/// Make `dir` look like a git checkout at `commit`: `.git/HEAD` names a branch whose
/// loose ref holds the hash. Nothing here runs git.
fn fake_checkout(dir: &Path, commit: &str) {
    fs::create_dir_all(dir.join(".git/refs/heads")).unwrap();
    fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(dir.join(".git/refs/heads/main"), format!("{commit}\n")).unwrap();
}

/// Split `board` of the bundled catalog into `name` with `--repository url`.
fn split_with_repository(
    sandbox: &Sandbox,
    board: &str,
    name: &str,
    id: &str,
    url: &str,
) -> PathBuf {
    let dir = sandbox.path(name);
    ok(sandbox.run([
        "catalog",
        "split",
        "official",
        "--board",
        board,
        "-o",
        s(&dir),
        "--id",
        id,
        "--repository",
        url,
    ]));
    dir
}

#[test]
fn init_repository_writes_the_url_and_the_catalog_validates_and_indexes() {
    let sandbox = Sandbox::new();
    let repo = sandbox.path("acme");
    let run = ok(sandbox.run([
        "catalog",
        "init",
        s(&repo),
        "--id",
        "acme-x99",
        "--repository",
        PR9_URL,
        "--json",
    ]));
    assert_eq!(run.json()["data"]["repository"], PR9_URL);
    assert_eq!(json_file(&repo.join("catalog.json"))["repository"], PR9_URL);
    assert_valid_and_indexed(&sandbox, &repo);

    // Without the flag the key is absent from the file and the reply.
    let plain = sandbox.path("plain");
    let run = ok(sandbox.run(["catalog", "init", s(&plain), "--id", "plain", "--json"]));
    assert!(run.json()["data"].get("repository").is_none());
    assert!(
        json_file(&plain.join("catalog.json"))
            .get("repository")
            .is_none()
    );
}

#[test]
fn split_repository_writes_the_url_and_the_catalog_validates_and_indexes() {
    let sandbox = Sandbox::new();
    let dir = split_with_repository(&sandbox, PR9, "pr9", PR9_CATALOG, PR9_URL);
    assert_eq!(json_file(&dir.join("catalog.json"))["repository"], PR9_URL);
    assert_valid_and_indexed(&sandbox, &dir);
    // `catalog index` rewrites the same bytes, so it keeps the field.
    let before = fs::read(dir.join("catalog.json")).unwrap();
    ok(sandbox.run(["catalog", "index", s(&dir)]));
    assert_eq!(fs::read(dir.join("catalog.json")).unwrap(), before);
}

#[test]
fn init_and_split_refuse_a_repository_that_is_not_an_https_url_and_write_nothing() {
    let sandbox = Sandbox::new();
    for url in [
        "http://example.org/acme",
        "git@github.com:acme/x99.git",
        "https://",
        "https://example.org/a b",
    ] {
        let expected = format!("catalog repository: expected an https URL | received {url:?}");
        let repo = sandbox.path("init-refused");
        let run = sandbox.run([
            "catalog",
            "init",
            s(&repo),
            "--id",
            "acme-x99",
            "--repository",
            url,
            "--json",
        ]);
        assert_eq!(
            (run.code, run.error_code().as_str()),
            (1, "CATALOG_INVALID"),
            "(init {url})"
        );
        assert_eq!(run.json()["error"]["message"], expected.as_str());
        assert!(!repo.exists(), "(init {url}): expected nothing written");

        let out = sandbox.path("split-refused");
        let run = sandbox.run([
            "catalog",
            "split",
            "official",
            "--board",
            PR9,
            "-o",
            s(&out),
            "--id",
            PR9_CATALOG,
            "--repository",
            url,
            "--json",
        ]);
        assert_eq!(
            (run.code, run.error_code().as_str()),
            (1, "CATALOG_INVALID"),
            "(split {url})"
        );
        assert_eq!(run.json()["error"]["message"], expected.as_str());
        assert!(!out.exists(), "(split {url}): expected nothing written");
    }
}

#[test]
fn merge_records_the_repository_and_the_checked_out_commit_of_each_source() {
    let sandbox = Sandbox::new();
    let mr9a = split_with_repository(&sandbox, MR9A, "mr9a", MR9A_CATALOG, MR9A_URL);
    let pr9 = split(&sandbox, PR9, "pr9", PR9_CATALOG).0;
    fake_checkout(&mr9a, MR9A_COMMIT);
    let merged = sandbox.path("merged");
    let run = ok(sandbox.run([
        "catalog",
        "merge",
        s(&mr9a),
        s(&pr9),
        "-o",
        s(&merged),
        "--id",
        "two-boards",
        "--json",
    ]));
    let digest = |dir: &Path| Digest256::of(&fs::read(dir.join("catalog.json")).unwrap());
    let expected = json!([
        {
            "id": MR9A_CATALOG,
            "version": "0.1.0",
            "manifest_sha256": digest(&mr9a).to_string(),
            "repository": MR9A_URL,
            "commit": MR9A_COMMIT,
        },
        {"id": PR9_CATALOG, "version": "0.1.0", "manifest_sha256": digest(&pr9).to_string()},
    ]);
    assert_eq!(json_file(&merged.join("catalog.json"))["sources"], expected);
    assert_eq!(run.json()["data"]["sources"], expected);
    assert_valid_and_indexed(&sandbox, &merged);
}

#[test]
fn merge_from_directories_that_are_not_checkouts_records_no_commit() {
    let sandbox = Sandbox::new();
    let (mr9a, pr9) = both_splits(&sandbox);
    // A malformed HEAD is "no commit", not an error.
    fs::create_dir_all(mr9a.join(".git")).unwrap();
    fs::write(mr9a.join(".git/HEAD"), "ref: refs/heads/nowhere\n").unwrap();
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
    for entry in json_file(&merged.join("catalog.json"))["sources"]
        .as_array()
        .unwrap()
    {
        assert!(
            entry.get("commit").is_none() && entry.get("repository").is_none(),
            "(sources entry): expected no commit and no repository | received {entry}"
        );
    }
}

#[test]
fn merge_check_adds_the_commit_to_a_moved_pin_and_keeps_a_pinned_line_short() {
    let sandbox = Sandbox::new();
    let mr9a = split_with_repository(&sandbox, MR9A, "mr9a", MR9A_CATALOG, MR9A_URL);
    let pr9 = split(&sandbox, PR9, "pr9", PR9_CATALOG).0;
    fake_checkout(&mr9a, MR9A_COMMIT);
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
    let pinned = ok(sandbox.run(["catalog", "merge", s(&merged), s(&mr9a), s(&pr9), "--check"]));
    assert!(
        pinned.stdout.ends_with(&format!(
            "  pin      two-boards lists {MR9A_CATALOG} 0.1.0: pinned\n  pin      two-boards lists {PR9_CATALOG} 0.1.0: pinned\n"
        )),
        "(pinned lines): expected no commit | received:\n{}",
        pinned.stdout
    );

    let pinned_digest = Digest256::of(&fs::read(mr9a.join("catalog.json")).unwrap());
    let moved = edited_copy(
        &sandbox,
        &mr9a,
        "mr9a-moved",
        &[("catalog.json", &|d| {
            d["version"] = json!("0.2.0");
        })],
    );
    let current_digest = Digest256::of(&fs::read(moved.join("catalog.json")).unwrap());
    let run = ok(sandbox.run([
        "catalog",
        "merge",
        s(&merged),
        s(&moved),
        s(&pr9),
        "--check",
    ]));
    assert!(
        run.stdout.contains(&format!(
            "  pin      two-boards lists {MR9A_CATALOG} 0.1.0: moved (pinned {pinned_digest} at commit 1a2b3c4d5e6f, current {current_digest})\n"
        )),
        "(merge --check moved line) | received:\n{}",
        run.stdout
    );
    let json = ok(sandbox.run([
        "catalog",
        "merge",
        s(&merged),
        s(&moved),
        s(&pr9),
        "--check",
        "--json",
    ]))
    .json();
    assert_eq!(json["data"]["pins"][0]["commit"], MR9A_COMMIT);
    assert!(json["data"]["pins"][1].get("commit").is_none());
}
