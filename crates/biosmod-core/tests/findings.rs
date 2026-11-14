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

/// An edit to one JSON document of the synthetic catalog.
type Edit<'a> = (&'a str, &'a dyn Fn(&mut Value));

/// Synthetic catalog files with `edit` applied to one JSON document and the index rebuilt.
fn load_edited(path: &str, scope: Scope, edit: impl Fn(&mut Value)) -> Result<Catalog, Error> {
    load_edits(scope, &[(path, &edit)])
}

/// Synthetic catalog files with each of `edits` applied and the index rebuilt.
fn load_edits(scope: Scope, edits: &[Edit<'_>]) -> Result<Catalog, Error> {
    let mut files: Vec<(String, Vec<u8>)> = Fixture::new(7)
        .catalog_files()
        .into_iter()
        .filter(|(p, _)| p != "catalog.json")
        .collect();
    for (path, edit) in edits {
        let entry = files
            .iter_mut()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("{path}: not a synthetic catalog file"));
        let mut doc: Value = serde_json::from_slice(&entry.1).unwrap();
        edit(&mut doc);
        entry.1 = serde_json::to_vec_pretty(&doc).unwrap();
    }
    let manifest = Manifest {
        schema: CATALOG_SCHEMA.into(),
        id: "synthetic".into(),
        version: semver::Version::new(1, 0, 0),
        title: "edited".into(),
        engine: semver::VersionReq::parse(">=0.1.0").unwrap(),
        description: None,
        repository: None,
        sources: vec![],
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
fn patch_listing_an_unknown_finding_is_refused_naming_every_unknown_id() {
    rejects(
        load_edited("patches/PB.json", Scope::All, |doc| {
            doc["findings"] = json!(["OPEN1", "TYPO-1", "TYPO-2"]);
        }),
        "patch PB: findings: expected ids of findings in this catalog | received TYPO-1, TYPO-2",
    );
}

#[test]
fn board_scope_refuses_an_unknown_finding_a_patch_lists() {
    rejects(
        load_edited("patches/PA.json", Scope::Board(BOARD_FILE.into()), |doc| {
            doc["findings"] = json!(["PA", "TYPO-1"]);
        }),
        "patch PA: findings: expected ids of findings in this catalog | received TYPO-1",
    );
}

#[test]
fn board_scope_accepts_a_finding_a_patch_lists_outside_the_closure() {
    // OPEN1 is indexed but neither the board nor a `fixes` list reaches it, so the closure
    // does not load it; the full load of the same files accepts it too.
    let edits: [Edit<'_>; 2] = [
        ("patches/PA.json", &|doc| {
            doc["findings"] = json!(["PA", "OPEN1"]);
        }),
        (BOARD_FILE, &|doc| doc["findings"] = json!([])),
    ];
    let scoped = load_edits(Scope::Board(BOARD_FILE.into()), &edits).unwrap();
    assert_eq!(scoped.findings.keys().collect::<Vec<_>>(), ["PA"]);
    let full = load_edits(Scope::All, &edits).unwrap();
    assert_eq!(full.findings.len(), 2);
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
            doc["findings"] = json!(["OPEN1"]);
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

/// Edit the first detector of OPEN1 and expect the catalog to be refused with `expected`.
fn rejects_detector(edit: impl Fn(&mut Value), expected: &str) {
    rejects(
        load_edited("findings/OPEN1.json", Scope::All, |doc| {
            edit(&mut doc["detectors"][0])
        }),
        expected,
    );
}

#[test]
fn detector_with_wildcard_outside_its_bytes_is_refused() {
    rejects_detector(
        |d| d["signatures"][0]["defect"]["wild"] = json!([8]),
        "wild index expected unique and below 8 | received 8",
    );
}

#[test]
fn detector_with_duplicate_wildcard_index_is_refused() {
    rejects_detector(
        |d| d["signatures"][0]["defect"]["wild"] = json!([3, 3]),
        "received 3",
    );
}

#[test]
fn detector_pattern_with_fewer_than_four_fixed_bytes_is_refused() {
    rejects_detector(
        |d| d["signatures"][0]["defect"]["wild"] = json!([0, 1, 2, 3, 4, 5, 6, 7]),
        "expected at least 4 fixed (non-wild) bytes | received 0 of 8",
    );
    rejects_detector(
        |d| d["signatures"][0]["defect"]["wild"] = json!([0, 1, 2, 3, 4]),
        "expected at least 4 fixed (non-wild) bytes | received 3 of 8",
    );
    rejects_detector(
        |d| d["signatures"][0]["fixed"]["wild"] = json!([0, 1, 2, 3, 4]),
        "fixed: expected at least 4 fixed (non-wild) bytes | received 3 of 8",
    );
}

#[test]
fn detector_pattern_with_exactly_four_fixed_bytes_is_accepted() {
    let catalog = load_edited("findings/OPEN1.json", Scope::All, |doc| {
        doc["detectors"][0]["signatures"][0]["defect"]["wild"] = json!([0, 1, 2, 3]);
        doc["detectors"][0]["signatures"][0]["fixed"]["wild"] = json!([0, 1, 2, 3]);
    })
    .unwrap();
    assert_eq!(catalog.findings["OPEN1"].detectors.len(), 1);
}

#[test]
fn detector_without_signatures_or_with_empty_bytes_is_refused() {
    rejects_detector(
        |d| d["signatures"] = json!([]),
        "signatures expects at least one signature",
    );
    rejects_detector(
        |d| d["signatures"][0]["defect"] = json!({"bytes": ""}),
        "bytes must not be empty",
    );
}

#[test]
fn detector_expect_range_must_be_ordered_and_positive() {
    rejects_detector(
        |d| d["expect"] = json!({"min_per_module": 3, "max_per_module": 2}),
        "received min 3 max 2",
    );
    rejects_detector(
        |d| d["expect"] = json!({"min_per_module": 0, "max_per_module": 0}),
        "received min 0 max 0",
    );
}

#[test]
fn detector_fixed_pattern_identical_to_its_defect_is_refused() {
    rejects_detector(
        |d| {
            let defect = d["signatures"][0]["defect"].clone();
            d["signatures"][0]["fixed"] = defect;
        },
        "fixed expects a pattern different from defect",
    );
}

#[test]
fn detector_ids_and_signature_labels_must_be_unique_identifiers() {
    rejects_detector(|d| d["id"] = json!("bad id"), "id");
    rejects_detector(
        |d| {
            let signature = d["signatures"][0].clone();
            d["signatures"] = json!([signature.clone(), signature]);
        },
        "duplicate \"site\"",
    );
}

#[test]
fn detector_with_unknown_field_or_anchor_is_refused_at_parse() {
    rejects_detector(|d| d["surprise"] = json!(1), "surprise");
    rejects_detector(|d| d["anchor"] = json!({"in": "heap"}), "heap");
}

// ---- findings with no affected build: the verdict of a patch that does not apply here ----

const BOARD_FILE: &str = "boards/synthetic-board.json";

fn board_without_the_verdict_finding(doc: &mut Value) {
    doc["findings"] = json!(["PA"]);
}

/// OPEN1 as another board's defect: no build and no code reference of a build.
fn open1_without_a_build(doc: &mut Value) {
    doc["affects"]["builds"] = json!([]);
    doc["owner"]["references"] = json!([]);
}

/// PB names OPEN1 and does not apply to the synthetic build.
fn pb_not_applicable_naming_open1(doc: &mut Value) {
    doc["findings"] = json!(["OPEN1"]);
    doc["variants"] = json!({
        synthetic::FIRMWARE: {"status": "not-applicable", "reason": "the other board's build has the defect"}
    });
}

#[test]
fn finding_without_a_build_is_accepted_when_a_patch_that_does_not_apply_names_it() {
    let catalog = load_edits(
        Scope::All,
        &[
            ("findings/OPEN1.json", &open1_without_a_build),
            ("patches/PB.json", &pb_not_applicable_naming_open1),
            (BOARD_FILE, &board_without_the_verdict_finding),
        ],
    )
    .unwrap();
    assert!(catalog.findings["OPEN1"].affects.builds.is_empty());
}

#[test]
fn finding_without_a_build_and_without_a_patch_is_refused_naming_the_finding_and_the_shape() {
    rejects(
        load_edits(
            Scope::All,
            &[
                ("findings/OPEN1.json", &open1_without_a_build),
                (BOARD_FILE, &board_without_the_verdict_finding),
            ],
        ),
        "finding OPEN1: affects.builds expected at least one firmware build, or a patch that lists OPEN1 in findings and has no applicable variant in this catalog | received no build and no such patch",
    );
}

#[test]
fn finding_without_a_build_named_by_an_applicable_patch_is_refused() {
    rejects(
        load_edits(
            Scope::All,
            &[
                ("findings/OPEN1.json", &open1_without_a_build),
                ("patches/PB.json", &|doc| {
                    doc["findings"] = json!(["OPEN1"]);
                }),
                (BOARD_FILE, &board_without_the_verdict_finding),
            ],
        ),
        "finding OPEN1: affects.builds expected at least one firmware build",
    );
}

#[test]
fn finding_without_a_build_is_refused_while_any_naming_patch_is_applicable() {
    // PB does not apply, but PA names OPEN1 too and does.
    rejects(
        load_edits(
            Scope::All,
            &[
                ("findings/OPEN1.json", &open1_without_a_build),
                ("patches/PB.json", &pb_not_applicable_naming_open1),
                ("patches/PA.json", &|doc| {
                    doc["findings"] = json!(["PA", "OPEN1"]);
                }),
                (BOARD_FILE, &board_without_the_verdict_finding),
            ],
        ),
        "finding OPEN1: affects.builds expected at least one firmware build",
    );
}

#[test]
fn board_listing_a_finding_without_a_build_is_still_refused() {
    rejects(
        load_edits(
            Scope::All,
            &[
                ("findings/OPEN1.json", &open1_without_a_build),
                ("patches/PB.json", &pb_not_applicable_naming_open1),
            ],
        ),
        "lists finding OPEN1, which affects none of its firmware builds",
    );
}

#[test]
fn board_scope_loads_a_verdict_finding_through_the_fixes_of_a_patch_that_does_not_apply() {
    // The shape `bme catalog split` writes: the finding stays fixed-by-patch and lists the
    // patch whose only variant says it does not apply to this board's build.
    let catalog = load_edits(
        Scope::Board(BOARD_FILE.into()),
        &[
            ("findings/OPEN1.json", &|doc| {
                open1_without_a_build(doc);
                doc["status"] = json!("fixed-by-patch");
                doc["patches"] = json!(["PB"]);
            }),
            ("patches/PB.json", &|doc| {
                pb_not_applicable_naming_open1(doc);
                doc["fixes"] = json!(["OPEN1"]);
            }),
            (BOARD_FILE, &board_without_the_verdict_finding),
        ],
    )
    .unwrap();
    assert!(catalog.findings["OPEN1"].affects.builds.is_empty());
    assert_eq!(catalog.findings["OPEN1"].patches, ["PB"]);
}

#[test]
fn scan_and_findings_for_never_list_a_finding_without_a_build() {
    let catalog = load_edits(
        Scope::All,
        &[
            ("findings/OPEN1.json", &open1_without_a_build),
            ("patches/PB.json", &pb_not_applicable_naming_open1),
            (BOARD_FILE, &board_without_the_verdict_finding),
        ],
    )
    .unwrap();
    let fixture = Fixture::new(7);
    let image = Image::parse(fixture.image.clone()).unwrap();
    let report = analysis::scan(&image, &catalog, None);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        Vec::<&str>::new(),
        "(open findings of the detected build): an open finding with no build is not one"
    );
    assert_eq!(catalog.findings_for(synthetic::FIRMWARE).count(), 1);
    let register = biosmod_core::register::render(&[&catalog.findings["OPEN1"]]);
    let rows = biosmod_core::register::parse(&register).unwrap();
    assert_eq!(rows[0].id, "OPEN1");
}
