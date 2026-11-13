//! A catalog split for one board scans a firmware image to the same patch rows, `n/a` rows
//! included, as the multi-board catalog it was cut from.

use biosmod_core::analysis;
use biosmod_core::catalog::{
    CATALOG_SCHEMA, Catalog, FileKind, Manifest, MemorySource, Records, Scope, index_files,
    split_board,
};
use biosmod_core::firmware::Image;
use biosmod_core::json::pretty;
use biosmod_core::synthetic::{self, Fixture};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const OTHER_BUILD: &str = "other-board-fw";
const OTHER_BOARD: &str = "other-board";

/// Load `files` plus a `catalog.json` that indexes them.
fn load(id: &str, mut files: Vec<(String, Vec<u8>)>) -> Catalog {
    let manifest = Manifest {
        schema: CATALOG_SCHEMA.into(),
        id: id.into(),
        version: semver::Version::new(1, 0, 0),
        title: id.into(),
        engine: semver::VersionReq::parse(">=0.1.0").unwrap(),
        description: None,
        sources: vec![],
        files: index_files(&files).unwrap(),
    };
    files.push(("catalog.json".into(), pretty(&manifest)));
    Catalog::load(&MemorySource::new(files), Scope::All).unwrap()
}

/// The synthetic catalog plus a second board with its own build, where `PB` does not apply
/// to the synthetic build and `PA` does not apply to the second board's build.
fn two_board_catalog() -> Catalog {
    let mut files = Fixture::new(7).catalog_files();
    files.retain(|(path, _)| path != "catalog.json");
    let document = |files: &[(String, Vec<u8>)], path: &str| -> Value {
        let (_, bytes) = files.iter().find(|(p, _)| p == path).unwrap();
        serde_json::from_slice(bytes).unwrap()
    };
    let applicable = document(&files, "patches/PA.json")["variants"][synthetic::FIRMWARE].clone();
    assert_eq!(applicable["status"], "applicable");
    let mut edit = |path: &str, edit: &dyn Fn(&mut Value)| {
        let entry = files.iter_mut().find(|(p, _)| p == path).unwrap();
        let mut doc: Value = serde_json::from_slice(&entry.1).unwrap();
        edit(&mut doc);
        entry.1 = pretty(&doc);
    };
    let not_applicable = json!({"status": "not-applicable", "reason": "the other board's build"});
    edit("patches/PA.json", &|doc| {
        doc["variants"][OTHER_BUILD] = not_applicable.clone();
    });
    edit("patches/PB.json", &|doc| {
        doc["variants"] = json!({
            synthetic::FIRMWARE: not_applicable,
            OTHER_BUILD: applicable.clone(),
        });
    });
    let mut board = document(&files, &format!("boards/{}.json", synthetic::BOARD));
    board["id"] = json!(OTHER_BOARD);
    board["firmware"] = json!([{"id": OTHER_BUILD, "title": "Other board build"}]);
    board["patches"] = json!(["PB"]);
    board["findings"] = json!([]);
    board["facts"] = json!([]);
    files.push((format!("boards/{OTHER_BOARD}.json"), pretty(&board)));
    load("two-boards", files)
}

/// The catalog files of `records`, indexed and loaded again.
fn reload(id: &str, records: &Records) -> Catalog {
    fn documents<T: serde::Serialize>(
        kind: FileKind,
        map: &BTreeMap<String, T>,
    ) -> Vec<(String, Vec<u8>)> {
        map.iter()
            .map(|(name, doc)| (format!("{}/{name}.json", kind.directory()), pretty(doc)))
            .collect()
    }
    let mut files = documents(FileKind::Board, &records.boards);
    files.extend(documents(FileKind::Patch, &records.patches));
    files.extend(documents(FileKind::Finding, &records.findings));
    files.extend(documents(FileKind::Evidence, &records.evidence));
    load(id, files)
}

#[test]
fn board_split_scans_to_the_patch_rows_of_the_catalog_it_was_cut_from() {
    let whole = two_board_catalog();
    let split = split_board(&Records::of(&whole), synthetic::BOARD).unwrap();
    let board_catalog = reload("synthetic-only", &split.records);
    let image = Image::parse(Fixture::new(7).image).unwrap();

    let rows = |catalog: &Catalog| -> Vec<Value> {
        let report = analysis::scan(&image, catalog, Some(synthetic::FIRMWARE));
        report
            .patches
            .iter()
            .map(|row| serde_json::to_value(row).unwrap())
            .collect()
    };
    let (whole_rows, split_rows) = (rows(&whole), rows(&board_catalog));
    let verdict = split_rows.iter().find(|row| row["id"] == "PB").expect(
        "(split scan rows): expected a row for PB, whose only variant here is not-applicable",
    );
    assert_eq!(
        verdict["state"], "not-applicable",
        "(PB state in the split)"
    );
    assert_eq!(
        verdict["detail"], "the other board's build",
        "(PB reason in the split)"
    );
    assert_eq!(
        split_rows, whole_rows,
        "(scan rows of the split): expected the rows of the two-board catalog"
    );
}
