//! Engine behaviour on the synthetic fixture (ported from the reference suite and extended).

use biosmod_core::analysis::{self, State};
use biosmod_core::catalog::{Catalog, MemorySource, Scope};
use biosmod_core::firmware::{Image, checksum16_ok};
use biosmod_core::plan::{Request, build, changed_bytes};
use biosmod_core::synthetic::{self, Fixture, NEXT_GUID};
use biosmod_core::{Code, Error};
use std::collections::BTreeMap;

struct Case {
    fixture: Fixture,
    catalog: Catalog,
}

impl Case {
    fn new() -> Case {
        Case::with(Fixture::new(0x07))
    }

    fn with(fixture: Fixture) -> Case {
        let catalog = Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All)
            .expect("synthetic catalog validates");
        Case { fixture, catalog }
    }

    fn image(&self) -> Image {
        Image::parse(self.fixture.image.clone()).unwrap()
    }

    fn build(&self, image: &Image, ids: &[&str]) -> Result<Vec<u8>, Error> {
        let request = Request {
            select: ids.iter().map(|s| s.to_string()).collect(),
            ..Request::default()
        };
        build(image, &self.catalog, &request).map(|b| b.image)
    }

    fn states(&self, bytes: &[u8]) -> BTreeMap<String, State> {
        let image = Image::parse(bytes.to_vec()).unwrap();
        analysis::scan(&image, &self.catalog, Some(synthetic::FIRMWARE))
            .patches
            .into_iter()
            .map(|p| (p.id, p.state))
            .collect()
    }
}

fn expect_err(result: Result<Vec<u8>, Error>, code: Code, text: &str) {
    let error = result.expect_err("expected a refusal");
    assert_eq!(error.code, code, "{error}");
    assert!(
        error.message.contains(text),
        "message {:?} should contain {text:?}",
        error.message
    );
}

#[test]
fn parser_finds_both_volumes_with_valid_checksums() {
    let case = Case::new();
    let image = case.image();
    assert_eq!(
        image.volumes.iter().map(|v| v.offset).collect::<Vec<_>>(),
        vec![0x1000, 0x5000]
    );
    assert!(
        image
            .volumes
            .iter()
            .all(|v| checksum16_ok(&image.bytes[v.offset..v.offset + v.header_size]))
    );
}

#[test]
fn unpatched_image_reports_every_defect_present_and_detects_the_build() {
    let case = Case::new();
    let report = analysis::scan(&case.image(), &case.catalog, None);
    assert_eq!(report.firmware.as_deref(), Some(synthetic::FIRMWARE));
    assert!(
        report.patches.iter().all(|p| p.state == State::Present),
        "{:?}",
        report.patches
    );
    assert_eq!(report.recommended, vec!["PA", "PB"]);
    let ld = report.patches.iter().find(|p| p.id == "LD").unwrap();
    assert!(!ld.plannable && ld.blocked.as_deref().unwrap().contains("requires PA"));
}

#[test]
fn corrupt_unselected_file_prevents_parsing() {
    let case = Case::new();
    let mut damaged = case.fixture.image.clone();
    let file = case.image().volumes[0].files[0].offset;
    damaged[file + 16] ^= 1;
    let error = Image::parse(damaged).unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid);
    assert!(error.message.contains("invalid header checksum"));
}

#[test]
fn subset_of_an_installed_superset_is_fixed_and_a_noop() {
    let case = Case::new();
    let first = case.build(&case.image(), &["PS"]).unwrap();
    assert_eq!(case.states(&first)["PA"], State::Fixed);
    let again = case
        .build(&Image::parse(first.clone()).unwrap(), &["PA"])
        .unwrap();
    assert_eq!(again, first);
    let combined = case.build(&case.image(), &["PS", "PB"]).unwrap();
    let stepped = case
        .build(&Image::parse(first).unwrap(), &["PA", "PB"])
        .unwrap();
    assert_eq!(combined, stepped);
}

#[test]
fn disjoint_patches_compose_in_any_order_and_stepwise() {
    let case = Case::new();
    let both = case.build(&case.image(), &["PA", "PB"]).unwrap();
    let reverse = case.build(&case.image(), &["PB", "PA"]).unwrap();
    let first = case.build(&case.image(), &["PA"]).unwrap();
    let stepwise = case.build(&Image::parse(first).unwrap(), &["PB"]).unwrap();
    assert_eq!(both, reverse);
    assert_eq!(both, stepwise);
    let states = case.states(&both);
    assert_eq!((states["PA"], states["PB"]), (State::Fixed, State::Fixed));
}

#[test]
fn in_place_patch_changes_only_hunk_and_checksum_bytes() {
    let case = Case::new();
    let image = case.build(&case.image(), &["PA"]).unwrap();
    // The PEIM file has no data checksum, and the header checksum excludes the body.
    assert_eq!(changed_bytes(&case.fixture.image, &image), 2);
}

#[test]
fn superset_replaces_a_fix_already_in_the_image() {
    let case = Case::new();
    let first = case.build(&case.image(), &["PA"]).unwrap();
    let upgraded = case.build(&Image::parse(first).unwrap(), &["PS"]).unwrap();
    assert_eq!(case.states(&upgraded)["PS"], State::Fixed);
}

#[test]
fn conflicting_fix_already_in_the_image_is_refused() {
    let case = Case::new();
    let first = case.build(&case.image(), &["PB"]).unwrap();
    expect_err(
        case.build(&Image::parse(first).unwrap(), &["CX"]),
        Code::PatchConflict,
        "already contains PB",
    );
}

#[test]
fn growing_dxe_driver_moves_following_files() {
    let case = Case::new();
    let request = Request {
        select: vec!["DG".into()],
        ..Request::default()
    };
    let built = build(&case.image(), &case.catalog, &request).unwrap();
    assert!(
        built
            .notes
            .iter()
            .any(|n| n.contains(&NEXT_GUID.to_string())),
        "{:?}",
        built.notes
    );
    assert_eq!(case.states(&built.image)["DG"], State::Fixed);
    assert_eq!(&built.image[0x5000..], &case.fixture.image[0x5000..]);
}

#[test]
fn growth_that_would_move_an_xip_peim_is_refused() {
    let case = Case::with(Fixture::new(0x06));
    expect_err(
        case.build(&case.image(), &["DG"]),
        Code::PackingRefused,
        "PEI-phase image (file type 0x6) that executes in place",
    );
}

#[test]
fn growth_beyond_free_space_is_refused() {
    let case = Case::with(Fixture::with_dxe_length(0x07, 0x2000));
    expect_err(
        case.build(&case.image(), &["DG"]),
        Code::PackingRefused,
        "more bytes than its free space",
    );
}

#[test]
fn acpi_table_patch_round_trips() {
    let case = Case::new();
    let image = case.build(&case.image(), &["TB"]).unwrap();
    assert_eq!(case.states(&image)["TB"], State::Fixed);
}

#[test]
fn module_from_another_build_is_refused() {
    let case = Case::new();
    let mut other = case.fixture.image.clone();
    let at = other
        .windows(32)
        .position(|w| w == &case.fixture.peim[..32])
        .unwrap();
    other[at..at + 32].copy_from_slice(&synthetic::module(7, 32));
    let image = Image::parse(other).unwrap();
    expect_err(
        case.build(&image, &["PA"]),
        Code::PatchSourceMismatch,
        "differs from the synthetic-fw original",
    );
}

#[test]
fn superseded_selection_is_dropped_with_a_note() {
    let case = Case::new();
    let request = Request {
        select: vec!["PA".into(), "PS".into()],
        ..Request::default()
    };
    let built = build(&case.image(), &case.catalog, &request).unwrap();
    assert_eq!(built.selected, vec!["PS"]);
    assert!(built.notes[0].contains("PA dropped"));
}

#[test]
fn conflicts_hold_diagnostic_facts_and_unknown_ids_are_refused() {
    let case = Case::new();
    let image = case.image();
    expect_err(
        case.build(&image, &["PB", "CX"]),
        Code::PatchConflict,
        "conflicts",
    );
    expect_err(
        case.build(&image, &["HD"]),
        Code::SelectionInvalid,
        "on hold",
    );
    expect_err(
        case.build(&image, &["ZZ"]),
        Code::TargetNotFound,
        "[\"ZZ\"]",
    );
    expect_err(
        case.build(&image, &["FR"]),
        Code::AssertionRequired,
        "synthetic-superio",
    );
    let hold = Request {
        select: vec!["HD".into()],
        allow_hold: true,
        ..Request::default()
    };
    assert!(build(&image, &case.catalog, &hold).is_ok());
    let fact = Request {
        select: vec!["FR".into()],
        facts: [synthetic::FACT.to_string()].into(),
        ..Request::default()
    };
    assert!(build(&image, &case.catalog, &fact).is_ok());
}

#[test]
fn layered_diagnostic_needs_its_base_and_is_recognized_afterwards() {
    let case = Case::new();
    let image = case.image();
    let diag = |ids: &[&str]| Request {
        select: ids.iter().map(|s| s.to_string()).collect(),
        allow_diagnostic: true,
        ..Request::default()
    };
    expect_err(
        case.build(&image, &["LD"]),
        Code::SelectionInvalid,
        "diagnostic",
    );
    assert_eq!(
        build(&image, &case.catalog, &diag(&["LD"]))
            .unwrap_err()
            .code,
        Code::SelectionInvalid
    );
    let layered = build(&image, &case.catalog, &diag(&["PA", "LD"]))
        .unwrap()
        .image;
    let states = case.states(&layered);
    assert_eq!((states["PA"], states["LD"]), (State::Fixed, State::Fixed));
    // A fix in another module keeps the layered diagnostic and its base.
    let more = case
        .build(&Image::parse(layered.clone()).unwrap(), &["TB"])
        .unwrap();
    let states = case.states(&more);
    assert_eq!(
        (states["PA"], states["LD"], states["TB"]),
        (State::Fixed, State::Fixed, State::Fixed)
    );
    // Any other fix in the diagnostic's module changes its exact input: refused.
    for extra in ["PB", "PS"] {
        expect_err(
            case.build(&Image::parse(layered.clone()).unwrap(), &[extra]),
            Code::PatchSourceMismatch,
            "written against exactly",
        );
    }
}

#[test]
fn every_patch_builds_alone_and_reads_fixed() {
    let case = Case::new();
    for patch in case.catalog.patches.values() {
        let mut request = Request {
            select: vec![patch.id.clone()],
            allow_hold: true,
            allow_diagnostic: true,
            ..Request::default()
        };
        request.facts.insert(synthetic::FACT.into());
        if patch.id == "LD" {
            request.select.insert(0, "PA".into());
        }
        let built = build(&case.image(), &case.catalog, &request)
            .unwrap_or_else(|e| panic!("{}: {e}", patch.id));
        assert_eq!(
            case.states(&built.image)[&patch.id],
            State::Fixed,
            "{}",
            patch.id
        );
    }
}

#[test]
fn signature_scan_finds_a_moved_defect_in_another_build() {
    let case = Case::new();
    let mut other = case.fixture.image.clone();
    // Change bytes far from PB's hunk so the exact hash fails but the signature still matches.
    let at = other
        .windows(32)
        .position(|w| w == &case.fixture.peim[..32])
        .unwrap();
    other[at + 240] ^= 0xFF;
    let image = Image::parse(rebuild_checksums(other)).unwrap();
    let report = analysis::scan(&image, &case.catalog, Some(synthetic::FIRMWARE));
    let pb = report.patches.iter().find(|p| p.id == "PB").unwrap();
    assert_eq!(pb.state, State::LikelyPresent, "{pb:?}");
    assert!(!pb.plannable);
}

/// Recompute every top-level FFS checksum after a deliberate edit.
fn rebuild_checksums(mut bytes: Vec<u8>) -> Vec<u8> {
    let offsets: Vec<(usize, usize, usize)> = {
        let mut found = Vec::new();
        let mut cursor = 0;
        while let Some(p) = bytes[cursor..].windows(4).position(|w| w == b"_FVH") {
            let fv = cursor + p - 40;
            let length = u64::from_le_bytes(bytes[fv + 32..fv + 40].try_into().unwrap()) as usize;
            let mut file = fv + 0x48;
            while file + 24 <= fv + length && bytes[file..file + 24] != [0xFF; 24] {
                let size =
                    u32::from_le_bytes([bytes[file + 20], bytes[file + 21], bytes[file + 22], 0])
                        as usize;
                found.push((file, 24, size));
                file = (file + size).div_ceil(8) * 8;
            }
            cursor = fv + length;
        }
        found
    };
    for (file, header, size) in offsets {
        let body = bytes[file + header..file + size].to_vec();
        biosmod_core::firmware::rebuild::file_checksum(&mut bytes[file..file + header], &body);
    }
    bytes
}

/// The standard fixture with the file after the DXE driver replaced by `follower`.
fn fixture_with_follower(follower: Vec<u8>, dxe_length: usize) -> Fixture {
    use synthetic::{
        DXE_GUID, PAD_GUID, PEIM_GUID, TABLE_GUID, acpi, ffs, lzma_section, module, section, volume,
    };
    let base = Fixture::new(0x07);
    let pei = volume(
        &[ffs(PEIM_GUID, 0x06, &section(0x10, &base.peim), 0)],
        0x4000,
    );
    let dxe = volume(
        &[
            ffs(
                DXE_GUID,
                0x07,
                &lzma_section(&section(0x10, &base.driver)),
                0,
            ),
            ffs(PAD_GUID, 0xF0, &[], 0),
            follower,
            ffs(TABLE_GUID, 0x02, &section(0x19, &acpi(&module(3, 96))), 0),
        ],
        dxe_length,
    );
    let mut image = vec![0xFF; 0x1000];
    image.extend(dxe);
    image.extend(pei);
    Fixture { image, ..base }
}

#[test]
fn growth_that_would_move_an_uncompressed_nested_volume_is_refused() {
    use synthetic::{ffs, module, section, volume};
    let inner_guid = "21212121-3434-5656-7878-909090909090".parse().unwrap();
    let nested = volume(
        &[ffs(inner_guid, 0x06, &section(0x10, &module(9, 128)), 0)],
        0x1000,
    );
    let follower = ffs(NEXT_GUID, 0x0B, &section(0x17, &nested), 0);
    let case = Case::with(fixture_with_follower(follower, 0x6000));
    expect_err(
        case.build(&case.image(), &["DG"]),
        Code::PackingRefused,
        "uncompressed firmware volume",
    );
}

#[test]
fn duplicated_module_is_ambiguous_not_half_patched() {
    let case = Case::new();
    let mut bytes = case.fixture.image.clone();
    let pei = bytes[bytes.len() - 0x4000..].to_vec();
    bytes.extend(pei);
    let image = Image::parse(bytes).unwrap();
    expect_err(
        case.build(&image, &["PA"]),
        Code::TargetAmbiguous,
        "occurs 2 times",
    );
    let report = analysis::scan(&image, &case.catalog, Some(synthetic::FIRMWARE));
    let pa = report.patches.iter().find(|p| p.id == "PA").unwrap();
    assert_eq!(pa.state, State::Unsupported, "{pa:?}");
}

#[test]
fn a_conflicting_fix_in_the_image_blocks_planning_in_scan() {
    let case = Case::new();
    let with_cx = Image::parse(case.build(&case.image(), &["CX"]).unwrap()).unwrap();
    let report = analysis::scan(&with_cx, &case.catalog, Some(synthetic::FIRMWARE));
    let pb = report.patches.iter().find(|p| p.id == "PB").unwrap();
    assert!(!pb.plannable, "{pb:?}");
    assert!(
        pb.blocked.as_deref().unwrap_or_default().contains("CX"),
        "{pb:?}"
    );
    assert!(!report.recommended.contains(&"PB".to_string()));
}

#[test]
fn extended_header_beyond_the_volume_is_invalid() {
    let mut fv = synthetic::volume(&[], 0x2000);
    fv[52..54].copy_from_slice(&0x48u16.to_le_bytes());
    fv[0x48 + 16..0x48 + 20].copy_from_slice(&0x3000u32.to_le_bytes());
    fv[50..52].copy_from_slice(&[0, 0]);
    let sum = fv[..0x48].chunks(2).fold(0u16, |a, w| {
        a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
    });
    fv[50..52].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
    let error = Image::parse(fv).unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid, "{error}");
    assert!(error.message.contains("extended header"), "{error}");
}

#[test]
fn allowlist_spans_outside_the_image_are_rejected() {
    use biosmod_core::plan::{Span, outside_allowlist_unchanged};
    let data = vec![0u8; 16];
    for span in [
        Span { start: 10, end: 5 },
        Span { start: 4, end: 17 },
        Span { start: 17, end: 20 },
    ] {
        let error = outside_allowlist_unchanged(&data, &data, &[span]).unwrap_err();
        assert_eq!(error.code, Code::PlanInvalid, "{error}");
    }
    assert!(outside_allowlist_unchanged(&data, &data, &[Span { start: 0, end: 16 }]).is_ok());
}
