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
fn acpi_table_offset_near_usize_max_is_not_found_instead_of_overflowing() {
    use biosmod_core::catalog::LeafKind;
    let image = Case::new().image();
    let leaves: Vec<_> = image.leaves.values().flatten().collect();
    let found = |offset: usize| {
        leaves
            .iter()
            .filter(|l| analysis::module_bytes(&image, l, LeafKind::AcpiTable, offset).is_some())
            .count()
    };
    assert_eq!(
        found(0),
        1,
        "control: the fixture DSDT is found at offset 0"
    );
    for offset in [usize::MAX - 3, usize::MAX - 7, usize::MAX] {
        assert_eq!(
            found(offset),
            0,
            "table_offset {offset:#x}: expected no table"
        );
    }
}

#[test]
fn overlapping_acpi_table_offsets_are_not_composed() {
    use biosmod_core::catalog::Variant;
    let mut case = Case::new();
    let mut other = case.catalog.patches["TB"].clone();
    other.id = "TB2".into();
    let Variant::Applicable(variant) = other.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("expected synthetic applicable variant");
    };
    variant.components[0].table_offset = 8;
    case.catalog.patches.insert(other.id.clone(), other);
    let error = case
        .build(&case.image(), &["TB"])
        .expect_err("distinct table offsets require explicit support");
    assert_eq!(error.code, Code::FormatUnsupported, "{error}");
    assert!(error.message.contains("table offset"), "{error}");
    assert!(error.message.contains("0x8"), "{error}");
    let scan = analysis::scan(&case.image(), &case.catalog, Some(synthetic::FIRMWARE));
    let row = scan.patches.iter().find(|p| p.id == "TB").unwrap();
    assert_eq!(row.state, State::Unsupported, "{row:?}");
    assert!(row.detail.contains("table offset"), "{}", row.detail);
}

#[test]
fn boards_for_lists_shipping_boards_and_is_empty_for_unknown_firmware() {
    let case = Case::new();
    assert_eq!(
        case.catalog.boards_for(synthetic::FIRMWARE),
        vec![synthetic::BOARD.to_string()]
    );
    assert!(case.catalog.boards_for("NOPE").is_empty());
}

#[test]
fn every_file_kind_maps_to_its_own_directory() {
    use biosmod_core::catalog::FileKind;
    let dirs: Vec<&str> = FileKind::ALL.iter().map(|k| k.directory()).collect();
    assert_eq!(dirs, ["boards", "patches", "evidence", "provenance"]);
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
fn installed_conflicts_in_other_modules_are_refused_in_either_order() {
    let fixture = Fixture::new(0x07);
    let mut files = fixture.catalog_files();
    for (path, bytes) in &mut files {
        let other = match path.as_str() {
            "patches/PA.json" => "TB",
            "patches/TB.json" => "PA",
            _ => continue,
        };
        let mut patch: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        patch["conflicts"] = serde_json::json!([other]);
        *bytes = synthetic::pretty(&patch);
    }
    let content: Vec<_> = files
        .iter()
        .filter(|(path, _)| path != "catalog.json")
        .cloned()
        .collect();
    let (_, bytes) = files
        .iter_mut()
        .find(|(path, _)| path == "catalog.json")
        .unwrap();
    let mut manifest: biosmod_core::catalog::Manifest = serde_json::from_slice(bytes).unwrap();
    manifest.files = biosmod_core::catalog::index_files(&content).unwrap();
    *bytes = synthetic::pretty(&manifest);
    let catalog = Catalog::load(&MemorySource::new(files), Scope::All).unwrap();
    let case = Case { fixture, catalog };

    for (installed, selected) in [("TB", "PA"), ("PA", "TB")] {
        let image = Image::parse(case.build(&case.image(), &[installed]).unwrap()).unwrap();
        let report = analysis::scan(&image, &case.catalog, Some(synthetic::FIRMWARE));
        let entry = report.patches.iter().find(|p| p.id == selected).unwrap();
        assert!(
            !entry.plannable,
            "{selected} must be blocked by installed {installed}"
        );
        let error = case.build(&image, &[selected]).err().unwrap_or_else(|| {
            panic!(
                "{selected} with installed {installed}: expected PATCH_CONFLICT | received success"
            )
        });
        assert_eq!(error.code, Code::PatchConflict, "{error}");
        assert!(
            error
                .message
                .contains(&format!("already contains {installed}")),
            "{error}"
        );
    }
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

#[test]
fn table_overlap_reports_conflicting_offsets_for_each_component() {
    use biosmod_core::catalog::Variant;
    let mut case = Case::new();
    for (id, offset) in [("TA", 8), ("TC", 16), ("TD", 8)] {
        let mut patch = case.catalog.patches["TB"].clone();
        patch.id = id.into();
        let Variant::Applicable(variant) = patch.variants.get_mut(synthetic::FIRMWARE).unwrap()
        else {
            panic!("expected applicable variant")
        };
        variant.components[0].table_offset = offset;
        case.catalog.patches.insert(id.into(), patch);
    }
    let image = case.image();
    let scan = analysis::scan(&image, &case.catalog, Some(synthetic::FIRMWARE));
    for (id, own, other) in [("TA", 8, 0), ("TB", 0, 8), ("TC", 16, 8), ("TD", 8, 0)] {
        let row = scan.patches.iter().find(|p| p.id == id).unwrap();
        assert_eq!(row.state, State::Unsupported, "{id}: {row:?}");
        assert!(
            row.detail
                .contains(&format!("offsets {own:#x} and {other:#x}")),
            "{id}: {}",
            row.detail
        );
        let direct = analysis::patch_state(
            &image,
            &case.catalog,
            synthetic::FIRMWARE,
            &case.catalog.patches[id],
        );
        let context = analysis::PatchStateContext::new(&image, &case.catalog, synthetic::FIRMWARE);
        assert_eq!(
            context.patch_state(&case.catalog.patches[id]),
            direct,
            "{id}: context differs from direct state"
        );
        assert_eq!(
            direct.1, row.detail,
            "{id}: direct patch state differs from scan"
        );
    }
}

/// Two distinct synthetic DSDTs inside the fixture's existing RAW section.
fn two_table_case() -> Case {
    use biosmod_core::catalog::Variant;
    use biosmod_core::firmware::rebuild;
    use biosmod_core::util::Digest256;
    let mut case = Case::new();
    let make_table = |seed| {
        let mut table = synthetic::acpi(&synthetic::module(seed, 28));
        table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        table
    };
    let first = make_table(12);
    let second = make_table(13);
    let mut body = first.clone();
    body.extend_from_slice(&[0x5a; 4]);
    let second_offset = body.len();
    body.extend_from_slice(&second);
    assert_eq!(body.len(), case.fixture.table.len());
    let image = case.image();
    let leaf = image.leaves[&synthetic::TABLE_GUID][0].clone();
    let file = rebuild::rebuilt_file(&image, &leaf, &body).unwrap();
    rebuild::write_in_place(
        &mut case.fixture.image,
        &image.volumes[leaf.volume],
        &[(leaf.file, file)],
    );
    let Variant::Applicable(variant) = case
        .catalog
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable table patch")
    };
    let template = variant.components[0].clone();
    let make = |table: &[u8], offset, byte| {
        let mut component = template.clone();
        component.name = format!("DSDT-{offset}");
        component.table_offset = offset;
        let mut expected = table.to_vec();
        expected[40] = byte;
        expected[9] = expected[9].wrapping_sub(byte.wrapping_sub(table[40]));
        component.hunks = vec![
            synthetic::hunk(table, 9, &[expected[9]]),
            synthetic::hunk(table, 40, &[byte]),
        ];
        let result = biosmod_core::patch::apply(table, &component.hunks).unwrap();
        assert_eq!(result, expected);
        assert_eq!(
            result.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        component.source_sha256 = Digest256::of(table);
        component.source_size = table.len() as u64;
        component.result_sha256 = Digest256::of(&result);
        component.result_size = result.len() as u64;
        component
    };
    variant.components = vec![make(&first, 0, 0x91), make(&second, second_offset, 0x92)];
    case
}

#[test]
fn two_tables_in_one_patch_are_valid_and_built_together() {
    let case = two_table_case();
    biosmod_core::validation::catalog(&case.catalog)
        .expect("different table offsets are distinct components");
    let input = case.image();
    let table_components = case.catalog.patches["TB"].components(synthetic::FIRMWARE);
    for component in table_components {
        let related = analysis::related_component(&case.catalog, synthetic::FIRMWARE, component);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].1.table_offset, component.table_offset);
    }
    let request = Request {
        firmware: Some(synthetic::FIRMWARE.into()),
        select: vec!["TB".into()],
        ..Request::default()
    };
    let built = build(&input, &case.catalog, &request)
        .expect("two disjoint tables can be patched together");
    assert_eq!(built.components.len(), 2);
    assert_eq!(
        built
            .components
            .iter()
            .map(|c| c.table_offset)
            .collect::<Vec<_>>(),
        [0, 68]
    );
    let output = Image::parse(built.image.clone()).expect("rebuilt image parses");
    assert_eq!(
        analysis::patch_state(
            &output,
            &case.catalog,
            synthetic::FIRMWARE,
            &case.catalog.patches["TB"]
        )
        .0,
        State::Fixed
    );
    biosmod_core::plan::outside_allowlist_unchanged(&input.bytes, &built.image, &built.allowlist)
        .unwrap();
    let mut reverse = case.catalog.clone();
    let biosmod_core::catalog::Variant::Applicable(variant) = reverse
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    variant.components.reverse();
    let reversed = build(&input, &reverse, &request).expect("reversed component order");
    assert_eq!(
        built.image, reversed.image,
        "component order must not change output"
    );
    let detection = analysis::detect(&input, &case.catalog);
    let score = detection
        .scores
        .iter()
        .find(|score| score.firmware == synthetic::FIRMWARE)
        .unwrap();
    assert_eq!(
        score.total, 4,
        "two table offsets count as two independent components"
    );
    assert_eq!(score.matched, 4);
}

/// Split the two-table correction into separate patches for the same FFS file.
fn split_table_case() -> Case {
    use biosmod_core::catalog::Variant;
    let mut case = two_table_case();
    let mut second = case.catalog.patches["TB"].clone();
    second.id = "TZ".into();
    let Variant::Applicable(v) = second.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    let tail = v.components.pop().unwrap();
    v.components = vec![tail];
    let Variant::Applicable(v) = case
        .catalog
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    v.components.pop();
    case.catalog.patches.insert(second.id.clone(), second);
    case
}

#[test]
fn separate_table_patches_preserve_both_tables_and_order() {
    let case = split_table_case();
    let input = case.image();
    let make = |ids: &[&str]| {
        build(
            &input,
            &case.catalog,
            &Request {
                firmware: Some(synthetic::FIRMWARE.into()),
                select: ids.iter().map(|s| s.to_string()).collect(),
                ..Request::default()
            },
        )
        .unwrap()
    };
    let forward = make(&["TB", "TZ"]);
    let reverse = make(&["TZ", "TB"]);
    assert_eq!(
        forward.image, reverse.image,
        "selection order must not change output"
    );
    let output = Image::parse(forward.image.clone()).unwrap();
    let leaf = &output.leaves[&synthetic::TABLE_GUID][0];
    let body = output.leaf_body(leaf);
    assert_eq!(
        &body[64..68],
        &[0x5a; 4],
        "bytes between the tables remain unchanged"
    );
    for (id, offset) in [("TB", 0), ("TZ", 68)] {
        let table = analysis::module_bytes(
            &output,
            leaf,
            biosmod_core::catalog::LeafKind::AcpiTable,
            offset,
        )
        .unwrap();
        assert_eq!(
            table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0,
            "{id}: checksum"
        );
        assert_eq!(
            analysis::patch_state(
                &output,
                &case.catalog,
                synthetic::FIRMWARE,
                &case.catalog.patches[id]
            )
            .0,
            State::Fixed,
            "{id}: fixed state"
        );
    }
    biosmod_core::plan::outside_allowlist_unchanged(
        &input.bytes,
        &forward.image,
        &forward.allowlist,
    )
    .unwrap();
    assert_eq!(forward.components.len(), 2);
}

#[test]
fn same_table_carried_fix_survives_other_table_rebuild() {
    use biosmod_core::catalog::Variant;
    use biosmod_core::util::Digest256;
    let mut case = split_table_case();
    let mut extra = case.catalog.patches["TB"].clone();
    extra.id = "TX".into();
    let Variant::Applicable(v) = extra.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    let image = case.image();
    let leaf = &image.leaves[&synthetic::TABLE_GUID][0];
    let table = analysis::module_bytes(&image, leaf, biosmod_core::catalog::LeafKind::AcpiTable, 0)
        .unwrap();
    let first = table[50].wrapping_add(1);
    let second = table[51].wrapping_sub(1);
    v.components[0].hunks = vec![synthetic::hunk(table, 50, &[first, second])];
    let result = biosmod_core::patch::apply(table, &v.components[0].hunks).unwrap();
    v.components[0].result_sha256 = Digest256::of(&result);
    case.catalog.patches.insert(extra.id.clone(), extra);
    let first = case.build(&image, &["TB"]).unwrap();
    let patched = Image::parse(first).unwrap();
    let built = build(
        &patched,
        &case.catalog,
        &Request {
            firmware: Some(synthetic::FIRMWARE.into()),
            select: vec!["TX".into(), "TZ".into()],
            ..Request::default()
        },
    )
    .unwrap();
    assert_eq!(built.carried, ["TB"]);
    let output = Image::parse(built.image.clone()).unwrap();
    for id in ["TB", "TX", "TZ"] {
        assert_eq!(
            analysis::patch_state(
                &output,
                &case.catalog,
                synthetic::FIRMWARE,
                &case.catalog.patches[id]
            )
            .0,
            State::Fixed,
            "{id}: fixed after rebuild"
        );
    }
    biosmod_core::plan::outside_allowlist_unchanged(&patched.bytes, &built.image, &built.allowlist)
        .unwrap();
}

#[test]
fn overlapping_table_ranges_are_refused_before_composition() {
    use biosmod_core::catalog::Variant;
    let mut case = split_table_case();
    let Variant::Applicable(v) = case
        .catalog
        .patches
        .get_mut("TZ")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    v.components[0].table_offset = 60;
    let error = case.build(&case.image(), &["TB", "TZ"]).unwrap_err();
    assert_eq!(error.code, Code::FormatUnsupported);
    assert!(
        error.message.contains("overlapping ACPI table offsets"),
        "{error}"
    );
    let report = analysis::scan(&case.image(), &case.catalog, Some(synthetic::FIRMWARE));
    for id in ["TB", "TZ"] {
        let row = report.patches.iter().find(|p| p.id == id).unwrap();
        assert_eq!(row.state, State::Unsupported, "{id}: {row:?}");
    }
}

#[test]
fn resizing_one_of_multiple_tables_is_refused() {
    use biosmod_core::catalog::{HunkOp, Variant};
    use biosmod_core::util::{Digest256, HexBytes};
    let mut case = split_table_case();
    let image = case.image();
    let leaf = &image.leaves[&synthetic::TABLE_GUID][0];
    let table = analysis::module_bytes(&image, leaf, biosmod_core::catalog::LeafKind::AcpiTable, 0)
        .unwrap();
    let Variant::Applicable(v) = case
        .catalog
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    let component = &mut v.components[0];
    let mut checksum = table[9];
    checksum = checksum.wrapping_sub(4);
    component.hunks = vec![
        synthetic::hunk(table, 4, &68u32.to_le_bytes()),
        synthetic::hunk(table, 9, &[checksum]),
    ];
    let mut append = synthetic::hunk(table, 0, &[]);
    append.op = HunkOp::Append;
    append.offset = table.len();
    append.before = HexBytes::default();
    append.after = HexBytes(vec![0; 4]);
    append.context_before = HexBytes::default();
    append.context_after = HexBytes::default();
    component.hunks.push(append);
    let result = biosmod_core::patch::apply(table, &component.hunks).unwrap();
    component.result_size = result.len() as u64;
    component.result_sha256 = Digest256::of(&result);
    let error = case.build(&image, &["TB"]).unwrap_err();
    assert_eq!(error.code, Code::FormatUnsupported, "{error}");
    assert!(
        error.message.contains("cannot resize an ACPI table"),
        "{error}"
    );
}

#[test]
fn malformed_table_lengths_are_not_exposed_as_complete_tables() {
    use biosmod_core::catalog::LeafKind;
    use biosmod_core::firmware::rebuild;
    let case = two_table_case();
    let image = case.image();
    let leaf = image.leaves[&synthetic::TABLE_GUID][0].clone();
    for length in [8u32, 133, u32::MAX] {
        let mut body = image.leaf_body(&leaf).to_vec();
        body[4..8].copy_from_slice(&length.to_le_bytes());
        let file = rebuild::rebuilt_file(&image, &leaf, &body).unwrap();
        let mut bytes = image.bytes.clone();
        rebuild::write_in_place(
            &mut bytes,
            &image.volumes[leaf.volume],
            &[(leaf.file, file)],
        );
        let malformed = Image::parse(bytes).unwrap();
        let actual = analysis::module_bytes(&malformed, &leaf, LeafKind::AcpiTable, 0);
        assert!(
            actual.is_none(),
            "table length {length}: expected no complete ACPI table"
        );
    }
}

#[test]
fn catalog_rejects_overlapping_tables_in_one_variant() {
    use biosmod_core::catalog::Variant;
    let mut case = two_table_case();
    let Variant::Applicable(v) = case
        .catalog
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    v.components[1].table_offset = 60;
    let error = biosmod_core::validation::catalog(&case.catalog).unwrap_err();
    assert_eq!(error.code, Code::CatalogInvalid);
    assert!(
        error
            .message
            .contains("overlapping ACPI table offsets 0x0 and 0x3c"),
        "{error}"
    );
}

#[test]
fn mismatched_declared_table_size_cannot_match_a_larger_table() {
    use biosmod_core::catalog::Variant;
    let mut case = two_table_case();
    let image = case.image();
    let Variant::Applicable(v) = case
        .catalog
        .patches
        .get_mut("TB")
        .unwrap()
        .variants
        .get_mut(synthetic::FIRMWARE)
        .unwrap()
    else {
        panic!("applicable variant")
    };
    v.components[0].source_size = 63;
    v.components[0].result_size = 63;
    let component = &case.catalog.patches["TB"].components(synthetic::FIRMWARE)[0];
    assert!(
        analysis::match_component(&image, &case.catalog, synthetic::FIRMWARE, component).is_none(),
        "declared source_size 63 must not match a 64-byte table"
    );
}

#[test]
fn layered_table_larger_than_declared_extent_is_unsupported() {
    use biosmod_core::catalog::{HunkOp, Variant};
    use biosmod_core::firmware::rebuild;
    use biosmod_core::util::{Digest256, HexBytes};
    let mut case = split_table_case();
    let original = case.image();
    let leaf = original.leaves[&synthetic::TABLE_GUID][0].clone();
    let initial = case.build(&original, &["TB"]).unwrap();
    let first = Image::parse(initial).unwrap();
    let table =
        analysis::module_bytes(&first, &leaf, biosmod_core::catalog::LeafKind::AcpiTable, 0)
            .unwrap();
    let mut layer = case.catalog.patches["TB"].clone();
    layer.id = "TX".into();
    layer.requires = vec!["TB".into()];
    let Variant::Applicable(variant) = layer.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    let component = &mut variant.components[0];
    component.layer_on = vec!["TB".into()];
    component.input_sha256 = Some(Digest256::of(table));
    component.hunks = vec![
        synthetic::hunk(table, 4, &68u32.to_le_bytes()),
        synthetic::hunk(table, 9, &[table[9].wrapping_sub(4)]),
    ];
    let mut append = synthetic::hunk(table, 0, &[]);
    append.op = HunkOp::Append;
    append.offset = table.len();
    append.before = HexBytes::default();
    append.after = HexBytes(vec![0; 4]);
    append.context_before = HexBytes::default();
    append.context_after = HexBytes::default();
    component.hunks.push(append);
    let result = biosmod_core::patch::apply(table, &component.hunks).unwrap();
    component.result_sha256 = Digest256::of(&result);
    component.result_size = 64; // The actual layered result is 68 bytes.
    case.catalog.patches.insert(layer.id.clone(), layer);
    let mut body = first.leaf_body(&leaf).to_vec();
    body[..68].copy_from_slice(&result);
    let file = rebuild::rebuilt_file(&first, &leaf, &body).unwrap();
    let mut bytes = first.bytes.clone();
    rebuild::write_in_place(
        &mut bytes,
        &first.volumes[leaf.volume],
        &[(leaf.file, file)],
    );
    let image = Image::parse(bytes).unwrap();
    let (state, detail) = analysis::patch_state(
        &image,
        &case.catalog,
        synthetic::FIRMWARE,
        &case.catalog.patches["TX"],
    );
    assert_eq!(
        state,
        State::Unsupported,
        "a 68-byte table exceeds the declared 64-byte extent: {detail}"
    );
}

#[test]
fn layered_same_table_patch_composes_beside_another_table() {
    use biosmod_core::catalog::Variant;
    use biosmod_core::util::Digest256;
    let mut case = split_table_case();
    let original = case.image();
    let first = Image::parse(case.build(&original, &["TB"]).unwrap()).unwrap();
    let leaf = &first.leaves[&synthetic::TABLE_GUID][0];
    let table = analysis::module_bytes(&first, leaf, biosmod_core::catalog::LeafKind::AcpiTable, 0)
        .unwrap();
    let mut layer = case.catalog.patches["TB"].clone();
    layer.id = "TX".into();
    layer.requires = vec!["TB".into()];
    let Variant::Applicable(variant) = layer.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    let component = &mut variant.components[0];
    component.layer_on = vec!["TB".into()];
    component.input_sha256 = Some(Digest256::of(table));
    component.hunks = vec![synthetic::hunk(
        table,
        50,
        &[table[50].wrapping_add(1), table[51].wrapping_sub(1)],
    )];
    component.result_sha256 =
        Digest256::of(&biosmod_core::patch::apply(table, &component.hunks).unwrap());
    case.catalog.patches.insert(layer.id.clone(), layer);
    let request = Request {
        firmware: Some(synthetic::FIRMWARE.into()),
        select: vec!["TX".into(), "TZ".into()],
        ..Request::default()
    };
    let built = build(&first, &case.catalog, &request).expect("layer and second table compose");
    assert_eq!(built.carried, ["TB"]);
    let output = Image::parse(built.image).unwrap();
    for id in ["TB", "TX", "TZ"] {
        assert_eq!(
            analysis::patch_state(
                &output,
                &case.catalog,
                synthetic::FIRMWARE,
                &case.catalog.patches[id]
            )
            .0,
            State::Fixed,
            "{id}: fixed state"
        );
    }
}

#[test]
fn related_patch_with_wrong_source_size_is_not_composed() {
    use biosmod_core::catalog::Variant;
    let mut case = split_table_case();
    let mut extra = case.catalog.patches["TB"].clone();
    extra.id = "TX".into();
    let Variant::Applicable(variant) = extra.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    variant.components[0].source_size = 63;
    variant.components[0].result_size = 63;
    case.catalog.patches.insert(extra.id.clone(), extra);
    let error = case.build(&case.image(), &["TB", "TX"]).unwrap_err();
    assert_eq!(error.code, Code::PatchSourceMismatch, "{error}");
    assert!(
        error.message.contains("expected source size 63")
            && error.message.contains("received size 64"),
        "{error}"
    );
}

#[test]
fn patching_a_module_inside_a_decode_only_encoding_is_refused_naming_it() {
    let case = Case::with(Fixture::with_driver_encoding(
        0x07,
        0x4000,
        synthetic::brotli_section,
    ));
    let image = case.image();
    let leaf = &image.leaves[&synthetic::DXE_GUID][0];
    assert!(leaf.compressed, "the driver sits inside the Brotli section");
    assert_eq!(
        image.volumes[0].files[0].encodings(),
        [biosmod_core::firmware::Encoding::Brotli]
    );
    // DG edits the driver; the module is readable but cannot be re-encoded.
    let error = case
        .build(&image, &["DG"])
        .expect_err("rebuild must refuse");
    assert_eq!(error.code, Code::FormatUnsupported, "{error}");
    assert!(
        error.message.contains(
            "Brotli section at 0x1060: rebuild expected an LZMA or CRC32 encapsulation | received a decode-only Brotli section"
        ),
        "{error}"
    );
    let report = analysis::scan(&image, &case.catalog, Some(synthetic::FIRMWARE));
    let entry = report.patches.iter().find(|p| p.id == "DG").unwrap();
    assert_eq!(entry.state, State::Unsupported, "{entry:?}");
    assert!(!entry.plannable, "{entry:?}");
    assert!(
        entry
            .detail
            .contains("Driver sits inside a decode-only Brotli section at 0x1060"),
        "{entry:?}"
    );
}
