//! Cases: drafting from an image, status checks and catalog export, on vendor-free fixtures.

use biosmod_core::case::{
    ARTIFACT_DIRECTORY, Artifact, ArtifactFile, ArtifactKind, CASE_SCHEMA, Case, CaseInput,
    CatalogSnapshot, Current, Verdict, bounded_id, evidence_id, status, submission_files,
    tree_blob, tree_changes, utc_timestamp,
};
use biosmod_core::catalog::{Catalog, FindingStatus, MemorySource, RevisionStatus, Scope};
use biosmod_core::draft::{
    DRAFT_NOTICE, DraftRequest, draft, draft_finding, firmware_id, identity_strings,
    module_inventory, smbios_matches,
};
use biosmod_core::firmware::Image;
use biosmod_core::plan::document::Blob;
use biosmod_core::synthetic::{self, BANNER, Fixture};
use biosmod_core::util::Digest256;
use biosmod_core::{Code, detect};
use std::collections::BTreeMap;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn digest(byte: u8) -> Digest256 {
    Digest256([byte; 32])
}

fn snapshot(version: &str, byte: u8) -> CatalogSnapshot {
    CatalogSnapshot {
        alias: "official".into(),
        id: "official".into(),
        version: version.into(),
        manifest_sha256: digest(byte),
    }
}

fn artifact(id: &str, byte: u8) -> Artifact {
    Artifact {
        id: id.into(),
        path: format!("{ARTIFACT_DIRECTORY}/{id}.json"),
        kind: ArtifactKind::Output,
        sha256: digest(byte),
        length: 10,
        command: vec!["scan".into(), "/home/someone/dump.bin".into()],
        bme_version: "0.1.0".into(),
        catalogs: vec![snapshot("1.0.0", 7)],
        inputs: vec![CaseInput {
            name: "dump.bin".into(),
            sha256: digest(1),
            length: 4,
        }],
        recorded: "2026-11-12T10:00:00Z".into(),
        files: vec![],
    }
}

fn case_with(artifacts: Vec<Artifact>) -> Case {
    Case {
        schema: CASE_SCHEMA.into(),
        id: "draft-board".into(),
        engine: "0.1.0".into(),
        created: "2026-11-12T10:00:00Z".into(),
        catalogs: vec![snapshot("1.0.0", 7)],
        inputs: vec![CaseInput {
            name: "dump.bin".into(),
            sha256: digest(1),
            length: 4,
        }],
        artifacts,
    }
}

fn observed(
    case: &Case,
) -> (
    BTreeMap<String, Option<Blob>>,
    BTreeMap<String, Option<Blob>>,
) {
    let inputs = case
        .inputs
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                Some(Blob {
                    sha256: i.sha256,
                    length: i.length,
                }),
            )
        })
        .collect();
    let artifacts = case
        .artifacts
        .iter()
        .map(|a| {
            (
                a.path.clone(),
                Some(Blob {
                    sha256: a.sha256,
                    length: a.length,
                }),
            )
        })
        .collect();
    (inputs, artifacts)
}

const CURRENT_CATALOGS: &[CatalogSnapshot] = &[];

#[test]
fn utc_timestamp_formats_known_instants() {
    assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc_timestamp(1_794_484_800), "2026-11-12T12:00:00Z");
    assert_eq!(utc_timestamp(1_709_251_199), "2024-02-29T23:59:59Z");
}

#[test]
fn bounded_id_trims_the_prefix_to_sixty_four_characters() {
    assert_eq!(bounded_id("board", "001-scan"), "board-001-scan");
    let long = bounded_id(&"x".repeat(80), "001-scan");
    assert_eq!(long.len(), 64, "{long}");
    assert!(long.ends_with("-001-scan"), "{long}");
    assert_eq!(evidence_id("draft-x", "001-scan"), "draft-x-001-scan");
}

#[test]
fn identity_strings_find_banners_and_prefer_dated_ones() {
    let mut bytes = vec![0xFFu8; 64];
    bytes.extend_from_slice(b"\0Setup Ver:2 only\0");
    bytes.extend_from_slice(b"\0X99H BIOS Date: 12/02/2022 Ver: X99HA00M\0");
    bytes.extend_from_slice(b"\0Ver:\0short\0");
    assert_eq!(
        identity_strings(&bytes),
        [
            "X99H BIOS Date: 12/02/2022 Ver: X99HA00M",
            "Setup Ver:2 only"
        ]
    );
}

#[test]
fn identity_strings_ignore_runs_that_are_too_long_to_be_banners() {
    let mut bytes = b"Ver:".to_vec();
    bytes.extend(std::iter::repeat_n(b'a', 200));
    assert!(identity_strings(&bytes).is_empty());
}

#[test]
fn firmware_id_uses_version_and_date_from_the_banner() {
    assert_eq!(
        firmware_id(Some("X99H BIOS Date: 12/02/2022 Ver: X99HA00M"), b""),
        "x99ha00m-20221202"
    );
    assert_eq!(
        firmware_id(Some("BIOS Message: X9R9P Ver:005 03/22/2023 19:30:19"), b""),
        "x9r9p-005-20230322"
    );
    assert_eq!(firmware_id(Some("Ver: V9"), b""), "v9");
}

#[test]
fn firmware_id_without_a_banner_names_the_image_digest() {
    let id = firmware_id(None, b"abc");
    assert_eq!(id, "fw-ba7816bf8f01", "expected fw- and 12 digest digits");
    assert_eq!(firmware_id(Some("no version here"), b"abc"), id);
}

#[test]
fn module_inventory_lists_pe32_and_dsdt_modules() {
    let fixture = Fixture::new(0x07);
    let image = Image::parse(fixture.image.clone()).unwrap();
    let modules = module_inventory(&image);
    let peim = modules
        .iter()
        .find(|m| m.ffs_guid == synthetic::PEIM_GUID)
        .expect("synthetic PEIM in the inventory");
    assert_eq!(peim.length, fixture.peim.len() as u64);
    assert_eq!(peim.sha256, Digest256::of(&fixture.peim));
    assert!(
        modules
            .iter()
            .any(|m| m.ffs_guid == synthetic::TABLE_GUID
                && m.sha256 == Digest256::of(&fixture.table)),
        "(inventory): expected the DSDT table module | received {modules:?}"
    );
}

#[test]
fn smbios_matches_only_when_the_bios_date_is_in_a_banner() {
    let banners = vec!["X9R9P Ver:005 03/22/2023 19:30:19".to_string()];
    assert!(smbios_matches(
        &banners,
        &map(&[("bios_date", "03/22/2023")])
    ));
    assert!(
        !smbios_matches(&banners, &map(&[("bios_date", "12/02/2022")])),
        "(smbios): expected a different BIOS date to stay unmatched"
    );
    assert!(!smbios_matches(&banners, &map(&[])));
    assert!(!smbios_matches(&banners, &map(&[("bios_date", "")])));
}

fn drafted(
    smbios: &BTreeMap<String, String>,
    board_id: Option<&str>,
) -> (Image, FirmwareDraftPair) {
    let fixture = Fixture::new(0x07).with_banner(BANNER);
    let image = Image::parse(fixture.image).unwrap();
    let pair = {
        let request = DraftRequest {
            image: &image,
            board_id,
            smbios,
            matches_catalog_build: Some("known-build"),
        };
        draft(&request).unwrap()
    };
    (image, pair)
}

type FirmwareDraftPair = (
    biosmod_core::catalog::Board,
    biosmod_core::draft::FirmwareDraft,
);

#[test]
fn draft_marks_everything_unreviewed_and_names_the_build() {
    let (image, (board, firmware)) = drafted(&map(&[]), None);
    assert_eq!(firmware.build.id, "syn1a00-20261112");
    assert_eq!(board.id, "draft-syn1a00-20261112");
    assert_eq!(firmware.build.version_string.as_deref(), Some(BANNER));
    assert_eq!(firmware.build.image_size, Some(image.bytes.len() as u64));
    assert_eq!(
        firmware.matches_catalog_build.as_deref(),
        Some("known-build")
    );
    assert!(firmware.draft && firmware.smbios.is_empty());
    assert_eq!(board.vendor, "Unknown");
    assert_eq!(board.revision.status, RevisionStatus::Unknown);
    for text in [
        board.description.as_deref().unwrap(),
        board.revision.note.as_deref().unwrap(),
        firmware.build.note.as_deref().unwrap(),
    ] {
        assert!(text.starts_with(DRAFT_NOTICE), "{text}");
    }
}

#[test]
fn draft_takes_smbios_identity_only_when_the_image_matches() {
    let matching = map(&[
        ("board_vendor", "ACME"),
        ("board_name", "X1"),
        ("board_version", "V2"),
        ("bios_date", "11/12/2026"),
    ]);
    let (_, (board, firmware)) = drafted(&matching, Some("acme-x1"));
    assert_eq!(board.id, "acme-x1");
    assert_eq!(
        (board.vendor.as_str(), board.model.as_str()),
        ("ACME", "X1")
    );
    assert_eq!(board.revision.label.as_deref(), Some("V2"));
    assert_eq!(board.revision.status, RevisionStatus::Unverified);
    assert_eq!(firmware.smbios, matching);

    let other = map(&[("board_vendor", "ACME"), ("bios_date", "01/01/2020")]);
    let (_, (board, firmware)) = drafted(&other, None);
    assert_eq!(board.vendor, "Unknown");
    assert!(
        firmware.smbios.is_empty(),
        "(smbios): expected none kept for another image"
    );
}

#[test]
fn draft_rejects_an_invalid_board_id_naming_it() {
    let image = Image::parse(Fixture::new(0x07).image).unwrap();
    let smbios = map(&[]);
    let error = draft(&DraftRequest {
        image: &image,
        board_id: Some("bad id"),
        smbios: &smbios,
        matches_catalog_build: None,
    })
    .unwrap_err();
    assert_eq!(error.code, Code::CatalogInvalid);
    assert!(error.message.contains("\"bad id\""), "{error}");
}

#[test]
fn draft_finding_is_open_and_stands_alone() {
    let fixture = Fixture::new(0x07);
    let source = fixture
        .findings()
        .into_iter()
        .find(|f| f.status == FindingStatus::FixedByPatch)
        .unwrap();
    let finding = draft_finding(&source, "fw-new", "001-scan");
    assert_eq!(finding.status, FindingStatus::Open);
    assert!(finding.patches.is_empty() && finding.detectors.is_empty());
    assert_eq!(finding.affects.builds, ["fw-new"]);
    assert!(finding.owner.references.iter().all(|r| r.build.is_none()));
    assert_eq!(finding.evidence, ["001-scan"]);
    assert!(finding.description.starts_with(DRAFT_NOTICE));
}

#[test]
fn status_is_clean_when_everything_matches() {
    let case = case_with(vec![artifact("001-scan", 5)]);
    let (inputs, artifacts) = observed(&case);
    let report = status(
        &case,
        &inputs,
        &artifacts,
        &Current {
            bme_version: "0.1.0",
            catalogs: &[snapshot("1.0.0", 7)],
        },
    );
    assert!(report.clean && report.drifted().is_empty() && report.stale().is_empty());
}

#[test]
fn status_reports_changed_and_missing_files_by_name() {
    let case = case_with(vec![artifact("001-scan", 5), artifact("002-ifr", 6)]);
    let (mut inputs, mut artifacts) = observed(&case);
    inputs.insert(
        "dump.bin".into(),
        Some(Blob {
            sha256: digest(9),
            length: 4,
        }),
    );
    artifacts.insert("artifacts/002-ifr.json".into(), None);
    let report = status(
        &case,
        &inputs,
        &artifacts,
        &Current {
            bme_version: "0.1.0",
            catalogs: CURRENT_CATALOGS,
        },
    );
    assert!(!report.clean);
    assert_eq!(
        report.drifted(),
        [
            "input dump.bin: changed",
            "artifact artifacts/002-ifr.json: missing"
        ]
    );
    assert_eq!(report.inputs[0].state, Verdict::Changed);
}

#[test]
fn status_treats_an_unobserved_name_as_missing() {
    let case = case_with(vec![artifact("001-scan", 5)]);
    let report = status(
        &case,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &Current {
            bme_version: "0.1.0",
            catalogs: CURRENT_CATALOGS,
        },
    );
    assert_eq!(
        report.drifted(),
        [
            "input dump.bin: missing",
            "artifact artifacts/001-scan.json: missing"
        ]
    );
}

#[test]
fn status_marks_older_engine_and_catalog_results_stale_without_failing() {
    let case = case_with(vec![artifact("001-scan", 5)]);
    let (inputs, artifacts) = observed(&case);
    let report = status(
        &case,
        &inputs,
        &artifacts,
        &Current {
            bme_version: "0.2.0",
            catalogs: &[snapshot("1.1.0", 8)],
        },
    );
    assert!(
        report.clean,
        "(stale): expected staleness to leave the case clean"
    );
    let stale = report.stale();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].stale.len(), 2, "{:?}", stale[0].stale);
    assert!(stale[0].stale[0].contains("expected 0.2.0 | recorded 0.1.0"));
    assert!(stale[0].stale[1].starts_with("catalog official expected 1.1.0"));
}

#[test]
fn status_marks_a_result_stale_when_its_input_differs_from_the_case_input() {
    let mut old = artifact("001-scan", 5);
    old.inputs[0].sha256 = digest(2);
    let case = case_with(vec![old]);
    let (inputs, artifacts) = observed(&case);
    let report = status(
        &case,
        &inputs,
        &artifacts,
        &Current {
            bme_version: "0.1.0",
            catalogs: CURRENT_CATALOGS,
        },
    );
    assert!(report.stale()[0].stale[0].starts_with("input dump.bin expected sha256"));
}

#[test]
fn case_check_names_the_invalid_value() {
    let mut case = case_with(vec![artifact("001-scan", 5)]);
    assert!(case.check().is_ok());
    case.artifacts[0].path = "artifacts/../case.json".into();
    let error = case.check().unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid);
    assert!(error.message.contains("artifacts/../case.json"), "{error}");
    let mut case = case_with(vec![artifact("001-scan", 5), artifact("001-scan", 6)]);
    assert!(
        case.check()
            .unwrap_err()
            .message
            .contains("duplicate artifact id")
    );
    case.schema = "bme.case/9".into();
    assert!(case.check().unwrap_err().message.contains("bme.case/9"));
}

#[test]
fn next_artifact_number_follows_the_highest_prefix() {
    assert_eq!(case_with(vec![]).next_artifact_number(), 1);
    let case = case_with(vec![artifact("001-scan", 5), artifact("007-ifr", 6)]);
    assert_eq!(case.next_artifact_number(), 8);
}

/// A case over the synthetic image with a scan-like artifact and a drafted finding.
fn exportable() -> (
    Case,
    biosmod_core::catalog::Board,
    biosmod_core::draft::FirmwareDraft,
    Vec<biosmod_core::catalog::Finding>,
) {
    let fixture = Fixture::new(0x07).with_banner(BANNER);
    let image = Image::parse(fixture.image.clone()).unwrap();
    let smbios = map(&[]);
    let (board, firmware) = draft(&DraftRequest {
        image: &image,
        board_id: None,
        smbios: &smbios,
        matches_catalog_build: None,
    })
    .unwrap();
    let mut scan = artifact("001-scan", 5);
    scan.inputs[0].sha256 = firmware.image.sha256;
    let mut case = case_with(vec![scan]);
    case.id = board.id.clone();
    case.inputs[0].sha256 = firmware.image.sha256;
    let catalog_finding = fixture
        .findings()
        .into_iter()
        .find(|f| f.id == "OPEN1")
        .unwrap();
    let finding = draft_finding(&catalog_finding, &firmware.build.id, "001-scan");
    (case, board, firmware, vec![finding])
}

#[test]
fn submission_files_load_as_a_catalog_with_evidence_and_findings() {
    let (case, board, firmware, findings) = exportable();
    let files = submission_files(&case, board.clone(), &firmware, findings).unwrap();
    let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            format!("boards/{}.json", board.id),
            "findings/OPEN1.json".to_string(),
            format!("evidence/{}-001-scan.json", board.id),
            format!("provenance/{}-firmware-draft.json", board.id),
            "catalog.json".to_string(),
        ]
    );
    let catalog = Catalog::load(&MemorySource::new(files), Scope::All).unwrap();
    let board = &catalog.boards[&board.id];
    assert_eq!(board.firmware[0].id, firmware.build.id);
    assert_eq!(board.findings, ["OPEN1"]);
    assert_eq!(board.evidence.len(), 1);
    assert_eq!(catalog.findings["OPEN1"].evidence, board.evidence);
    let evidence = &catalog.evidence[&board.evidence[0]];
    assert_eq!(evidence.image_sha256, Some(firmware.image.sha256));
    assert!(evidence.title.starts_with("DRAFT"), "{}", evidence.title);
    assert!(
        evidence.observations[0] == "command: bme scan dump.bin",
        "(evidence): expected directories stripped from the command | received {:?}",
        evidence.observations
    );
    assert_eq!(catalog.manifest.version.to_string(), "0.1.0-draft");
}

#[test]
fn submission_rejects_a_finding_citing_an_unknown_artifact() {
    let (case, board, firmware, mut findings) = exportable();
    findings[0].evidence = vec!["009-missing".into()];
    let error = submission_files(&case, board, &firmware, findings).unwrap_err();
    assert_eq!(error.code, Code::CatalogInvalid);
    assert!(
        error.message.contains("\"009-missing\"") && error.message.contains("001-scan"),
        "{error}"
    );
}

#[test]
fn submission_turns_a_fixed_finding_into_an_open_one_without_patches() {
    let (case, board, firmware, _) = exportable();
    let fixed = Fixture::new(0x07)
        .findings()
        .into_iter()
        .find(|f| f.status == FindingStatus::FixedByPatch)
        .unwrap();
    let files = submission_files(&case, board, &firmware, vec![fixed]).unwrap();
    let catalog = Catalog::load(&MemorySource::new(files), Scope::All).unwrap();
    let finding = &catalog.findings["PA"];
    assert_eq!(finding.status, FindingStatus::Open);
    assert!(finding.patches.is_empty());
}

#[test]
fn detector_hits_on_the_synthetic_image_drive_a_draft_finding() {
    // The flow `case init` follows: run the catalog's detectors, draft one finding per hit.
    let fixture = Fixture::new(0x07);
    let image = Image::parse(fixture.image.clone()).unwrap();
    let findings = fixture.findings();
    let hits: Vec<&str> = findings
        .iter()
        .flat_map(|f| f.detectors.iter().map(move |d| (f, d)))
        .filter(|(f, d)| detect::run(&image, f, d).state == detect::DetectorState::LikelyPresent)
        .map(|(f, _)| f.id.as_str())
        .collect();
    assert_eq!(hits, ["OPEN1"]);
}

fn tree_file(path: &str, byte: u8) -> ArtifactFile {
    ArtifactFile {
        path: path.into(),
        sha256: digest(byte),
        length: 5,
    }
}

/// A recorded directory artifact holding `a.bin` and `tables/DSDT.aml`.
fn directory_artifact() -> Artifact {
    let files = vec![tree_file("a.bin", 1), tree_file("tables/DSDT.aml", 2)];
    let blob = tree_blob(&files);
    Artifact {
        id: "002-capture".into(),
        path: format!("{ARTIFACT_DIRECTORY}/002-capture"),
        kind: ArtifactKind::Directory,
        sha256: blob.sha256,
        length: blob.length,
        files,
        ..artifact("002-capture", 0)
    }
}

#[test]
fn tree_blob_ignores_listing_order_and_covers_names_and_bytes() {
    let forward = tree_blob(&[tree_file("a", 1), tree_file("b", 2)]);
    assert_eq!(forward, tree_blob(&[tree_file("b", 2), tree_file("a", 1)]));
    assert_eq!(forward.length, 10);
    assert_ne!(forward, tree_blob(&[tree_file("a", 1), tree_file("c", 2)]));
    assert_ne!(forward, tree_blob(&[tree_file("a", 1), tree_file("b", 3)]));
}

#[test]
fn tree_changes_names_changed_missing_and_unrecorded_files() {
    let recorded = [tree_file("a", 1), tree_file("b", 2), tree_file("d", 4)];
    let found = [tree_file("a", 9), tree_file("c", 3), tree_file("d", 4)];
    let states: Vec<(String, Verdict)> = tree_changes(&recorded, &found)
        .into_iter()
        .map(|c| (c.path, c.state))
        .collect();
    assert_eq!(
        states,
        [
            ("a".to_string(), Verdict::Changed),
            ("b".to_string(), Verdict::Missing),
            ("c".to_string(), Verdict::Changed),
        ]
    );
    assert!(tree_changes(&recorded, &recorded).is_empty());
}

#[test]
fn a_directory_artifact_passes_the_consistency_check_and_round_trips() {
    let case = case_with(vec![directory_artifact()]);
    case.check().unwrap();
    let text = serde_json::to_string(&case).unwrap();
    let back: Case = serde_json::from_str(&text).unwrap();
    assert_eq!(back, case);
    assert_eq!(back.artifacts[0].files.len(), 2);
}

#[test]
fn a_directory_artifact_whose_digest_does_not_cover_its_files_is_refused() {
    let mut tampered = directory_artifact();
    tampered.files[0].sha256 = digest(9);
    let error = case_with(vec![tampered]).check().unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid, "{error}");
    assert!(error.message.contains("002-capture"), "{error}");
    assert!(error.message.contains("over its files"), "{error}");
}

#[test]
fn file_lists_are_refused_on_other_kinds_and_for_unsafe_paths() {
    let mut on_output = artifact("002-scan", 5);
    on_output.files = vec![tree_file("a", 1)];
    let error = case_with(vec![on_output]).check().unwrap_err();
    assert!(
        error.message.contains("unless kind is directory"),
        "{error}"
    );
    for bad in ["../escape", "/abs", "a//b", ".hidden", "a\\b", ""] {
        let mut directory = directory_artifact();
        directory.files.push(tree_file(bad, 7));
        let blob = tree_blob(&directory.files);
        (directory.sha256, directory.length) = (blob.sha256, blob.length);
        let error = case_with(vec![directory]).check().unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{bad:?}: {error}");
        assert!(error.message.contains("file path"), "{bad:?}: {error}");
    }
    let mut twice = directory_artifact();
    twice.files.push(tree_file("a.bin", 1));
    let blob = tree_blob(&twice.files);
    (twice.sha256, twice.length) = (blob.sha256, blob.length);
    assert!(case_with(vec![twice]).check().is_err());
}

#[test]
fn input_names_must_be_single_path_components() {
    for bad in [
        "/etc/hostname",
        "../x",
        "a/b",
        "a\\b",
        "..",
        ".",
        "",
        "C:\\dump.bin",
    ] {
        let mut case = case_with(vec![artifact("001-scan", 1)]);
        case.inputs[0].name = bad.into();
        let error = case.check().unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{bad:?}: {error}");
        assert!(
            error.message.contains("input name") && error.message.contains(&format!("{bad:?}")),
            "(input name {bad:?}): expected the invalid value named | received {error}"
        );

        let mut case = case_with(vec![artifact("001-scan", 1)]);
        case.artifacts[0].inputs[0].name = bad.into();
        let error = case.check().unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{bad:?}: {error}");
        assert!(
            error.message.contains("001-scan") && error.message.contains(&format!("{bad:?}")),
            "(artifact input name {bad:?}): expected the artifact and value named | received {error}"
        );
    }
}

#[test]
fn input_names_with_spaces_and_inner_dots_are_plain_file_names() {
    let mut case = case_with(vec![artifact("001-scan", 1)]);
    case.inputs[0].name = "my dump v1.2.bin".into();
    case.artifacts[0].inputs[0].name = "my dump v1.2.bin".into();
    case.check().unwrap();
}
