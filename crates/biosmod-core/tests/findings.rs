//! `bme.finding/1` documents: loading, cross-references with patches and boards, and scan output.

use biosmod_core::analysis;
use biosmod_core::catalog::{
    CATALOG_SCHEMA, Catalog, FindingStatus, Manifest, MemorySource, Scope, index_files,
};
use biosmod_core::firmware::Image;
use biosmod_core::json::{parse_strict, pretty};
use biosmod_core::synthetic::{self, Fixture};
use biosmod_core::{Code, Error};
use serde_json::{Value, json};

/// Synthetic catalog files with `edit` applied to one JSON document and the index rebuilt.
fn load_edited(path: &str, scope: Scope, edit: impl FnOnce(&mut Value)) -> Result<Catalog, Error> {
    let mut files: Vec<(String, Vec<u8>)> = Fixture::new(7)
        .catalog_files()
        .into_iter()
        .filter(|(p, _)| p != "catalog.json")
        .collect();
    let entry = files
        .iter_mut()
        .find(|(p, _)| p == path)
        .unwrap_or_else(|| panic!("{path}: not a synthetic catalog file"));
    let mut doc: Value = serde_json::from_slice(&entry.1).unwrap();
    edit(&mut doc);
    entry.1 = serde_json::to_vec_pretty(&doc).unwrap();
    let manifest = Manifest {
        schema: CATALOG_SCHEMA.into(),
        id: "synthetic".into(),
        version: semver::Version::new(1, 0, 0),
        title: "edited".into(),
        engine: semver::VersionReq::parse(">=0.1.0").unwrap(),
        description: None,
        files: index_files(&files).unwrap(),
    };
    files.push(("catalog.json".into(), pretty(&manifest)));
    Catalog::load(&MemorySource::new(files), scope)
}

fn rejects(result: Result<Catalog, Error>, expected: &str) {
    let error = result.expect_err("expected the catalog to be refused");
    assert_eq!(error.code, Code::CatalogInvalid, "{error}");
    assert!(
        error.message.contains(expected),
        "expected message containing {expected:?} | received {:?}",
        error.message
    );
}

#[test]
fn synthetic_catalog_loads_its_findings_and_links_them_to_the_patch() {
    let catalog = Catalog::load(
        &MemorySource::new(Fixture::new(7).catalog_files()),
        Scope::All,
    )
    .unwrap();
    assert_eq!(catalog.findings.keys().collect::<Vec<_>>(), ["OPEN1", "PA"]);
    assert_eq!(catalog.patches["PA"].fixes, ["PA"]);
    assert_eq!(catalog.findings["PA"].status, FindingStatus::FixedByPatch);
    assert_eq!(catalog.findings_for(synthetic::FIRMWARE).count(), 2);
    assert_eq!(catalog.findings_for("other-build").count(), 0);
}

#[test]
fn board_scope_loads_patchless_findings_and_the_findings_patches_fix() {
    let catalog = load_edited(
        &format!("boards/{}.json", synthetic::BOARD),
        Scope::Board(format!("boards/{}.json", synthetic::BOARD)),
        |_| {},
    )
    .unwrap();
    assert_eq!(
        catalog.findings.keys().collect::<Vec<_>>(),
        ["OPEN1", "PA"],
        "board-scoped load must reach the patchless finding through board.findings"
    );
}

#[test]
fn board_scope_without_listing_the_patchless_finding_still_loads_fixed_ones() {
    let board = format!("boards/{}.json", synthetic::BOARD);
    let catalog = load_edited(&board, Scope::Board(board.clone()), |doc| {
        doc["findings"] = json!([]);
    })
    .unwrap();
    assert_eq!(
        catalog.findings.keys().collect::<Vec<_>>(),
        ["PA"],
        "the patch's fixes pull in its finding even when the board lists none"
    );
}

#[test]
fn fixed_by_patch_without_a_patch_is_refused() {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["status"] = json!("fixed-by-patch");
        }),
        "finding OPEN1: status fixed-by-patch expects at least one patch",
    );
}

#[test]
fn listed_patches_with_another_status_are_refused() {
    rejects(
        load_edited("findings/PA.json", Scope::All, |doc| {
            doc["status"] = json!("open");
        }),
        "finding PA: status expected fixed-by-patch while patches are listed | received open",
    );
}

#[test]
fn finding_naming_a_patch_that_does_not_fix_it_is_refused() {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["status"] = json!("fixed-by-patch");
            doc["patches"] = json!(["PB"]);
        }),
        "finding OPEN1: lists patch PB, but PB does not list OPEN1 in fixes",
    );
}

#[test]
fn patch_fixing_an_unknown_finding_is_refused() {
    rejects(
        load_edited("patches/PB.json", Scope::All, |doc| {
            doc["findings"] = json!(["GHOST"]);
            doc["fixes"] = json!(["GHOST"]);
        }),
        "patch PB: fixes unknown finding GHOST",
    );
}

#[test]
fn patch_fixing_a_finding_outside_its_findings_is_refused() {
    rejects(
        load_edited("patches/PB.json", Scope::All, |doc| {
            doc["fixes"] = json!(["OPEN1"]);
        }),
        "patch PB: fixes OPEN1, which is not in findings",
    );
}

#[test]
fn patch_fixing_a_finding_that_does_not_list_it_is_refused() {
    rejects(
        load_edited("patches/PB.json", Scope::All, |doc| {
            doc["findings"] = json!(["PB", "OPEN1"]);
            doc["fixes"] = json!(["OPEN1"]);
        }),
        "patch PB: fixes OPEN1, but finding OPEN1 does not list PB in patches",
    );
}

#[test]
fn patch_grade_must_lead_with_the_finding_grade() {
    rejects(
        load_edited("patches/PA.json", Scope::All, |doc| {
            doc["confidence"]["findings"]["PA"] = json!("C2 conditional");
        }),
        "patch PA: confidence for PA expected leading grade C0 (as in the finding) | received \"C2 conditional\"",
    );
}

#[test]
fn grades_outside_c0_to_c3_are_refused() {
    for bad in ["C4", "c1", "C", "C10", "high"] {
        rejects(
            load_edited("findings/OPEN1.json", Scope::All, |doc| {
                doc["confidence"]["condition"]["grade"] = json!(bad);
            }),
            &format!("expected C0 | C1 | C2 | C3 | received {bad:?}"),
        );
    }
}

#[test]
fn finding_on_an_unknown_build_or_unknown_evidence_is_refused() {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["affects"]["builds"] = json!([synthetic::FIRMWARE, "no-such-build"]);
        }),
        "finding OPEN1: affects unknown firmware no-such-build",
    );
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["evidence"] = json!(["no-such-evidence"]);
        }),
        "finding OPEN1: references unknown evidence no-such-evidence",
    );
}

#[test]
fn code_reference_must_name_an_affected_build() {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["owner"]["references"][0]["build"] = json!("other-build");
        }),
        "names build other-build, which is not in affects.builds",
    );
}

#[test]
fn board_listing_a_finding_for_another_build_is_refused() {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            doc["affects"]["builds"] = json!(["other-build"]);
        }),
        "lists finding OPEN1, which affects none of its firmware builds",
    );
}

#[test]
fn board_listing_an_unknown_finding_is_refused() {
    rejects(
        load_edited(
            &format!("boards/{}.json", synthetic::BOARD),
            Scope::All,
            |doc| doc["findings"] = json!(["GHOST"]),
        ),
        "references unknown finding GHOST",
    );
}

#[test]
fn unknown_finding_fields_are_refused_by_the_strict_parser() {
    let mut doc: Value = serde_json::from_slice(&pretty(&Fixture::new(7).findings()[0])).unwrap();
    doc["severity"] = json!("high");
    let error = parse_strict::<biosmod_core::catalog::Finding>(
        &serde_json::to_vec(&doc).unwrap(),
        "findings/OPEN1.json",
    )
    .expect_err("unknown field must fail");
    assert!(error.message.contains("severity"), "{error}");
}

#[test]
fn scan_reports_only_open_findings_for_the_detected_build() {
    let fixture = Fixture::new(7);
    let catalog = Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All).unwrap();
    let image = Image::parse(fixture.image.clone()).unwrap();
    let report = analysis::scan(&image, &catalog, None);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["OPEN1"], "fixed findings must not be listed as open");
    assert_eq!(report.findings[0].confidence, "C0 code; C3 trigger");
    assert!(analysis::open_findings(&catalog, "other-build").is_empty());
}

#[test]
fn open_findings_sort_by_priority_then_id() {
    use biosmod_core::catalog::Priority;
    let fixture = Fixture::new(7);
    let mut catalog =
        Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All).unwrap();
    let template = catalog.findings["OPEN1"].clone();
    for (id, priority) in [
        ("B", Priority::P3),
        ("A", Priority::P3),
        ("Z", Priority::P1),
    ] {
        let mut finding = template.clone();
        finding.id = id.into();
        finding.priority = priority;
        catalog.findings.insert(id.into(), finding);
    }
    let order: Vec<String> = analysis::open_findings(&catalog, synthetic::FIRMWARE)
        .into_iter()
        .map(|f| f.id)
        .collect();
    assert_eq!(order, ["Z", "OPEN1", "A", "B"]);
}
