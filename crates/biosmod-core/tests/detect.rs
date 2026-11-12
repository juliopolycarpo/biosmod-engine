//! Defect-class detectors on synthetic images: states, anchors, counts and scan output.

use biosmod_core::analysis;
use biosmod_core::catalog::{
    Anchor, Catalog, Detector, Expect, MemorySource, ModuleKind, Pattern, Scope,
};
use biosmod_core::detect::{self, DetectorState};
use biosmod_core::firmware::Image;
use biosmod_core::synthetic::{self, Fixture, PEIM_GUID};
use biosmod_core::util::{Guid, HexBytes};

/// An image holding only a PEIM volume with `peim` as the PE32 body.
fn peim_image(peim: &[u8]) -> Image {
    peim_image_as(peim, 0x06)
}

fn peim_image_as(peim: &[u8], file_kind: u8) -> Image {
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(synthetic::volume(
        &[synthetic::ffs(
            PEIM_GUID,
            file_kind,
            &synthetic::section(0x10, peim),
            0,
        )],
        0x4000,
    ));
    Image::parse(bytes).expect("synthetic image parses")
}

fn finding_with(detector: Detector) -> biosmod_core::catalog::Finding {
    let mut finding = Fixture::new(7).findings().remove(0);
    finding.detectors = vec![detector];
    finding
}

fn state_of(image: &Image, detector: Detector) -> DetectorState {
    let finding = finding_with(detector.clone());
    detect::run(image, &finding, &detector).state
}

#[test]
fn defect_pattern_is_likely_present_at_its_site_and_wildcards_ignore_their_byte() {
    let fixture = Fixture::new(7);
    let mut peim = fixture.peim.clone();
    // Index 3 of the pattern is wild: any byte there still matches.
    peim[Fixture::DETECTOR_SITE + 3] ^= 0x55;
    let detector = fixture.detector();
    let report = detect::run(
        &peim_image(&peim),
        &finding_with(detector.clone()),
        &detector,
    );
    assert_eq!(report.state, DetectorState::LikelyPresent);
    assert_eq!(report.finding, "OPEN1");
    assert_eq!(report.modules.len(), 1);
    let module = &report.modules[0];
    assert_eq!(module.ffs_guid, PEIM_GUID);
    assert_eq!(module.state, DetectorState::LikelyPresent);
    assert_eq!(module.defect.len(), 1);
    assert_eq!(module.defect[0].offset, Fixture::DETECTOR_SITE);
    assert_eq!(module.defect[0].signature, "site");
    assert!(module.fixed.is_empty());
}

#[test]
fn corrected_pattern_alone_reports_fixed_pattern_not_present() {
    let fixture = Fixture::new(7);
    let mut peim = fixture.peim.clone();
    peim[Fixture::DETECTOR_SITE] ^= 0xFF;
    let report = detect::run(
        &peim_image(&peim),
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.state, DetectorState::FixedPattern);
    assert!(report.modules[0].defect.is_empty());
    assert_eq!(report.modules[0].fixed[0].offset, Fixture::DETECTOR_SITE);
}

#[test]
fn image_without_either_pattern_reports_absent_with_no_modules() {
    let fixture = Fixture::new(7);
    let mut peim = fixture.peim.clone();
    peim[Fixture::DETECTOR_SITE + 1] ^= 0x01;
    let report = detect::run(
        &peim_image(&peim),
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.state, DetectorState::Absent);
    assert!(report.modules.is_empty() && report.unsupported.is_empty());
}

#[test]
fn match_count_outside_the_expected_range_is_unexpected_count() {
    let fixture = Fixture::new(7);
    let mut detector = fixture.detector();
    detector.expect = Expect {
        min_per_module: 2,
        max_per_module: 3,
    };
    let state = state_of(&peim_image(&fixture.peim), detector);
    assert_eq!(state, DetectorState::UnexpectedCount);
}

#[test]
fn one_signature_hitting_twice_in_a_module_counts_both_sites() {
    let fixture = Fixture::new(7);
    let mut peim = fixture.peim.clone();
    let site = peim[Fixture::DETECTOR_SITE..Fixture::DETECTOR_SITE + 8].to_vec();
    peim[200..208].copy_from_slice(&site);
    let mut detector = fixture.detector();
    detector.expect = Expect {
        min_per_module: 2,
        max_per_module: 2,
    };
    let report = detect::run(
        &peim_image(&peim),
        &finding_with(detector.clone()),
        &detector,
    );
    assert_eq!(report.state, DetectorState::LikelyPresent);
    let offsets: Vec<usize> = report.modules[0].defect.iter().map(|s| s.offset).collect();
    assert_eq!(offsets, [Fixture::DETECTOR_SITE, 200]);
}

#[test]
fn anchor_limits_the_search_by_module_kind_and_by_ffs_guid() {
    let fixture = Fixture::new(7);
    let image = peim_image(&fixture.peim);
    let mut detector = fixture.detector();
    let anchored = |module_kind, ffs_guid| Anchor::Pe32 {
        module_kind,
        ffs_guid,
    };

    detector.anchor = anchored(Some(ModuleKind::Smm), None);
    assert_eq!(state_of(&image, detector.clone()), DetectorState::Absent);

    detector.anchor = anchored(None, Some(PEIM_GUID));
    assert_eq!(
        state_of(&image, detector.clone()),
        DetectorState::LikelyPresent
    );

    detector.anchor = anchored(None, Some(synthetic::DXE_GUID));
    assert_eq!(state_of(&image, detector.clone()), DetectorState::Absent);

    // The same bytes in an SMM-typed file (0x0A) match the SMM anchor only.
    let smm = peim_image_as(&fixture.peim, 0x0A);
    detector.anchor = anchored(Some(ModuleKind::Smm), None);
    assert_eq!(
        state_of(&smm, detector.clone()),
        DetectorState::LikelyPresent
    );
    detector.anchor = anchored(Some(ModuleKind::Peim), None);
    assert_eq!(state_of(&smm, detector), DetectorState::Absent);
}

#[test]
fn dsdt_anchor_searches_the_acpi_table_and_ignores_pe_modules() {
    let fixture = Fixture::new(7);
    let image = Image::parse(fixture.image.clone()).unwrap();
    let site = 36 + 20;
    let detector = Detector {
        id: "table-site".into(),
        title: "synthetic table bytes".into(),
        anchor: Anchor::Dsdt,
        signatures: vec![biosmod_core::catalog::Signature {
            label: "table".into(),
            defect: Pattern {
                bytes: HexBytes(fixture.table[site..site + 6].to_vec()),
                wild: vec![],
            },
            fixed: None,
        }],
        expect: Expect::default(),
    };
    let report = detect::run(&image, &finding_with(detector.clone()), &detector);
    assert_eq!(report.state, DetectorState::LikelyPresent);
    assert_eq!(report.modules[0].ffs_guid, synthetic::TABLE_GUID);
    assert_eq!(report.modules[0].defect[0].offset, site);
}

#[test]
fn unreadable_encapsulation_makes_the_result_unsupported_not_absent() {
    let fixture = Fixture::new(7);
    // A GUID-defined section with an unknown GUID cannot be decoded.
    let mut body = vec![0x42; 16];
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&[0x11; 32]);
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(synthetic::volume(
        &[synthetic::ffs(
            PEIM_GUID,
            0x06,
            &synthetic::section(0x02, &body),
            0,
        )],
        0x4000,
    ));
    let image = Image::parse(bytes).unwrap();
    let report = detect::run(
        &image,
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.state, DetectorState::Unsupported);
    assert_eq!(report.unsupported, [PEIM_GUID]);
}

#[test]
fn scan_runs_every_catalog_detector_whatever_the_build() {
    let fixture = Fixture::new(7);
    let catalog = Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All).unwrap();
    let stock = Image::parse(fixture.image.clone()).unwrap();
    let report = analysis::scan(&stock, &catalog, None);
    assert_eq!(report.detectors.len(), 1);
    assert_eq!(report.detectors[0].detector, "peim-site");
    assert_eq!(report.detectors[0].state, DetectorState::LikelyPresent);
    let reports = detect::run_all(&stock, &catalog);
    assert_eq!(reports, report.detectors);
}

#[test]
fn state_labels_are_distinct_human_text() {
    let labels: Vec<&str> = [
        DetectorState::LikelyPresent,
        DetectorState::UnexpectedCount,
        DetectorState::FixedPattern,
        DetectorState::Unsupported,
        DetectorState::Absent,
    ]
    .into_iter()
    .map(DetectorState::label)
    .collect();
    assert_eq!(
        labels,
        [
            "likely present",
            "unexpected count",
            "fixed pattern",
            "unsupported",
            "absent"
        ]
    );
}

/// An image with one PE32 file per `(guid, file kind, body)` entry.
fn image_of(files: &[(Guid, u8, &[u8])]) -> Image {
    let files: Vec<Vec<u8>> = files
        .iter()
        .map(|(guid, kind, body)| synthetic::ffs(*guid, *kind, &synthetic::section(0x10, body), 0))
        .collect();
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(synthetic::volume(&files, 0x4000));
    Image::parse(bytes).expect("synthetic image parses")
}

/// A PEIM-typed file whose only section is an encapsulation this engine cannot decode.
fn unreadable_file(guid: Guid) -> Vec<u8> {
    let mut body = vec![0x42; 16];
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&[0x11; 32]);
    synthetic::ffs(guid, 0x06, &synthetic::section(0x02, &body), 0)
}

/// The synthetic PEIM with its defect site copied to `extra` offsets.
fn peim_with_copies(extra: &[usize]) -> Vec<u8> {
    let mut peim = Fixture::new(7).peim;
    let site = peim[Fixture::DETECTOR_SITE..Fixture::DETECTOR_SITE + 8].to_vec();
    for at in extra {
        peim[*at..*at + 8].copy_from_slice(&site);
    }
    peim
}

#[test]
fn an_unexpected_count_in_any_module_outranks_likely_present_elsewhere() {
    let fixture = Fixture::new(7);
    let good = fixture.peim.clone();
    let doubled = peim_with_copies(&[200]);
    let image = image_of(&[
        (PEIM_GUID, 0x06, &good),
        (synthetic::NEXT_GUID, 0x06, &doubled),
    ]);
    let report = detect::run(
        &image,
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    let states: Vec<DetectorState> = report.modules.iter().map(|m| m.state).collect();
    assert!(
        states.contains(&DetectorState::LikelyPresent)
            && states.contains(&DetectorState::UnexpectedCount),
        "expected one module per state | received {states:?}"
    );
    assert_eq!(report.state, DetectorState::UnexpectedCount);
}

#[test]
fn fixed_pattern_is_not_claimed_overall_while_a_candidate_module_is_unreadable() {
    let fixture = Fixture::new(7);
    let mut fixed = fixture.peim.clone();
    fixed[Fixture::DETECTOR_SITE] ^= 0xFF;
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(synthetic::volume(
        &[
            synthetic::ffs(PEIM_GUID, 0x06, &synthetic::section(0x10, &fixed), 0),
            unreadable_file(synthetic::NEXT_GUID),
        ],
        0x4000,
    ));
    let image = Image::parse(bytes).unwrap();
    let report = detect::run(
        &image,
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.modules[0].state, DetectorState::FixedPattern);
    assert_eq!(report.unsupported, [synthetic::NEXT_GUID]);
    assert_eq!(report.state, DetectorState::Unsupported);
}

#[test]
fn likely_present_keeps_its_state_and_lists_the_unreadable_modules() {
    let fixture = Fixture::new(7);
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(synthetic::volume(
        &[
            synthetic::ffs(PEIM_GUID, 0x06, &synthetic::section(0x10, &fixture.peim), 0),
            unreadable_file(synthetic::NEXT_GUID),
        ],
        0x4000,
    ));
    let image = Image::parse(bytes).unwrap();
    let report = detect::run(
        &image,
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.state, DetectorState::LikelyPresent);
    assert_eq!(report.unsupported, [synthetic::NEXT_GUID]);
}

#[test]
fn sites_stop_one_past_the_expected_maximum_and_flag_the_truncation() {
    let fixture = Fixture::new(7);
    let peim = peim_with_copies(&[8, 16, 24, 200]);
    let report = detect::run(
        &peim_image(&peim),
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert_eq!(report.state, DetectorState::UnexpectedCount);
    let module = &report.modules[0];
    assert_eq!(
        module.defect.len(),
        2,
        "expected max_per_module + 1 sites | received {:?}",
        module.defect
    );
    assert!(module.truncated);
    let untruncated = detect::run(
        &peim_image(&fixture.peim),
        &finding_with(fixture.detector()),
        &fixture.detector(),
    );
    assert!(!untruncated.modules[0].truncated);
}
