//! A firmware build is detected by its identity, not by the number of modules it shares.
//!
//! The synthetic catalog records three modules for `synthetic-fw` (Peim, Driver, Table).
//! Tests corrupt the Peim to get a partial match and give the build a recorded banner.

use biosmod_core::analysis::{self, BannerCheck, Detection};
use biosmod_core::catalog::{Catalog, MemorySource, Scope};
use biosmod_core::firmware::Image;
use biosmod_core::plan::{Request, build};
use biosmod_core::synthetic::{self, BANNER, Fixture};
use biosmod_core::{Code, Error};

const RECORDED_BANNER: &str = "X9R9P Ver:005 03/22/2023";
const SIBLING_BANNER: &str = "X9MRA Ver:002 08/11/2022";
const TWIN_BUILD: &str = "twin-fw";

/// The synthetic catalog with `synthetic-fw` recording `version_string`.
fn catalog_recording(version_string: Option<&str>) -> Catalog {
    let fixture = Fixture::new(0x07);
    let mut catalog = Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All)
        .expect("synthetic catalog validates");
    catalog
        .boards
        .get_mut(synthetic::BOARD)
        .expect("synthetic board")
        .firmware[0]
        .version_string = version_string.map(str::to_string);
    catalog
}

/// The same catalog with every patch removed, so the build has no recorded modules.
fn catalog_without_patches(version_string: Option<&str>) -> Catalog {
    let mut catalog = catalog_recording(version_string);
    catalog.patches.clear();
    catalog
}

/// The same catalog with a second build, `twin-fw`, that records the same modules.
fn catalog_with_twin_build(twin_version_string: Option<&str>) -> Catalog {
    let mut catalog = catalog_recording(None);
    for patch in catalog.patches.values_mut() {
        let variant = patch.variants[synthetic::FIRMWARE].clone();
        patch.variants.insert(TWIN_BUILD.into(), variant);
    }
    let board = catalog.boards.get_mut(synthetic::BOARD).unwrap();
    let mut twin = board.firmware[0].clone();
    twin.id = TWIN_BUILD.into();
    twin.version_string = twin_version_string.map(str::to_string);
    board.firmware.push(twin);
    catalog
}

fn image_with_banner(banner: Option<&str>) -> Image {
    let fixture = Fixture::new(0x07);
    let fixture = match banner {
        Some(banner) => fixture.with_banner(banner),
        None => fixture,
    };
    Image::parse(fixture.image).unwrap()
}

/// An image whose Peim differs from the recorded original: two of three modules match.
fn image_with_changed_peim(banner: Option<&str>) -> Image {
    let fixture = Fixture::new(0x07);
    let mut bytes = match banner {
        Some(banner) => fixture.clone().with_banner(banner).image,
        None => fixture.image.clone(),
    };
    let at = bytes
        .windows(fixture.peim.len())
        .position(|window| window == fixture.peim.as_slice())
        .expect("peim is stored plain in the synthetic image");
    bytes[at + fixture.peim.len() - 1] ^= 0xFF;
    Image::parse(bytes).unwrap()
}

fn build_score<'a>(detection: &'a Detection, firmware: &str) -> &'a analysis::BuildScore {
    detection
        .scores
        .iter()
        .find(|score| score.firmware == firmware)
        .expect("score for build")
}

#[test]
fn banner_mismatch_with_partial_module_match_is_not_detected_and_reports_closest() {
    let catalog = catalog_recording(Some(RECORDED_BANNER));
    let image = image_with_changed_peim(Some(SIBLING_BANNER));
    let detection = analysis::detect(&image, &catalog);
    assert_eq!(detection.firmware, None, "(detected build)");
    assert!(!detection.ambiguous);
    let closest = detection.closest.as_ref().expect("closest build");
    assert_eq!(
        (
            closest.firmware.as_str(),
            closest.matched,
            closest.total,
            closest.banner,
            closest.version_string.as_deref()
        ),
        (
            synthetic::FIRMWARE,
            2,
            3,
            BannerCheck::Differs,
            Some(RECORDED_BANNER)
        )
    );
    assert_eq!(detection.image_banner.as_deref(), Some(SIBLING_BANNER));
}

#[test]
fn banner_mismatch_is_not_overridden_by_a_full_module_match() {
    let catalog = catalog_recording(Some(RECORDED_BANNER));
    let image = image_with_banner(Some(SIBLING_BANNER));
    let detection = analysis::detect(&image, &catalog);
    assert_eq!(detection.firmware, None, "(detected build)");
    let closest = detection.closest.expect("closest build");
    assert_eq!((closest.matched, closest.total), (3, 3));
}

#[test]
fn banner_match_with_zero_patch_components_detects_the_build() {
    let catalog = catalog_without_patches(Some(RECORDED_BANNER));
    let image = image_with_banner(Some(RECORDED_BANNER));
    let detection = analysis::detect(&image, &catalog);
    assert_eq!(
        detection.firmware.as_deref(),
        Some(synthetic::FIRMWARE),
        "(detected build)"
    );
    let score = build_score(&detection, synthetic::FIRMWARE);
    assert_eq!((score.matched, score.total), (0, 0));
    assert!(detection.closest.is_none());
}

#[test]
fn banner_with_trailing_time_still_matches_the_recorded_string() {
    let catalog = catalog_recording(Some(RECORDED_BANNER));
    let image = image_with_changed_peim(Some("X9R9P Ver:005 03/22/2023 19:30:19"));
    let detection = analysis::detect(&image, &catalog);
    assert_eq!(
        detection.firmware.as_deref(),
        Some(synthetic::FIRMWARE),
        "(detected build)"
    );
}

#[test]
fn recorded_string_must_match_whole_tokens_not_a_prefix_of_one() {
    let catalog = catalog_recording(Some("X9R9P Ver:00"));
    let image = image_with_banner(Some("X9R9P Ver:005 03/22/2023"));
    let detection = analysis::detect(&image, &catalog);
    assert_eq!(
        (
            detection.firmware.clone(),
            build_score(&detection, synthetic::FIRMWARE).banner
        ),
        (None, BannerCheck::Differs),
        "(recorded `Ver:00` against banner `Ver:005`)"
    );
}

#[test]
fn banner_is_found_when_unrelated_ver_strings_precede_it() {
    // identity_strings keeps four banners; the comparison must not be limited to them.
    let fixture = Fixture::new(0x07);
    let mut bytes = fixture.image;
    for (index, noise) in [
        "AAAA Ver:1 x",
        "BBBB Ver:2 x",
        "CCCC Ver:3 x",
        "DDDD Ver:4 x",
    ]
    .iter()
    .enumerate()
    {
        let at = 0x200 + index * 0x20;
        bytes[at..at + noise.len()].copy_from_slice(noise.as_bytes());
    }
    let banner_at = 0x400;
    bytes[banner_at..banner_at + RECORDED_BANNER.len()].copy_from_slice(RECORDED_BANNER.as_bytes());
    let image = Image::parse(bytes).unwrap();
    let detection = analysis::detect(&image, &catalog_recording(Some(RECORDED_BANNER)));
    assert_eq!(
        detection.firmware.as_deref(),
        Some(synthetic::FIRMWARE),
        "(detected build)"
    );
}

#[test]
fn full_module_match_without_any_banner_is_detected() {
    for recorded in [None, Some(RECORDED_BANNER)] {
        let catalog = catalog_recording(recorded);
        let detection = analysis::detect(&image_with_banner(None), &catalog);
        assert_eq!(
            detection.firmware.as_deref(),
            Some(synthetic::FIRMWARE),
            "(detected build, recorded banner {recorded:?}, image without banner)"
        );
        assert_eq!(
            build_score(&detection, synthetic::FIRMWARE).banner,
            BannerCheck::Unchecked
        );
    }
}

#[test]
fn full_module_match_with_an_image_banner_and_no_recorded_string_is_detected() {
    let detection = analysis::detect(&image_with_banner(Some(BANNER)), &catalog_recording(None));
    assert_eq!(
        detection.firmware.as_deref(),
        Some(synthetic::FIRMWARE),
        "(detected build)"
    );
}

#[test]
fn partial_module_match_without_a_comparable_banner_is_closest_only() {
    for recorded in [None, Some(RECORDED_BANNER)] {
        let catalog = catalog_recording(recorded);
        let detection = analysis::detect(&image_with_changed_peim(None), &catalog);
        assert_eq!(
            detection.firmware, None,
            "(detected build, recorded banner {recorded:?})"
        );
        let closest = detection.closest.expect("closest build");
        assert_eq!((closest.matched, closest.total), (2, 3));
    }
}

#[test]
fn no_matching_module_and_no_banner_agreement_reports_no_closest() {
    let detection = analysis::detect(
        &Image::parse(synthetic::image_of_files(&[])).unwrap(),
        &catalog_recording(Some(RECORDED_BANNER)),
    );
    assert!(detection.firmware.is_none() && detection.closest.is_none());
}

#[test]
fn two_builds_that_match_every_module_are_ambiguous() {
    let catalog = catalog_with_twin_build(None);
    let detection = analysis::detect(&image_with_banner(None), &catalog);
    assert!(
        detection.ambiguous && detection.firmware.is_none() && detection.closest.is_none(),
        "(two full matches): expected ambiguous | received {detection:?}"
    );
}

#[test]
fn a_banner_confirmed_build_outranks_a_build_confirmed_by_modules_alone() {
    let catalog = catalog_with_twin_build(Some(RECORDED_BANNER));
    let detection = analysis::detect(&image_with_banner(Some(RECORDED_BANNER)), &catalog);
    assert_eq!(
        (detection.firmware.as_deref(), detection.ambiguous),
        (Some(TWIN_BUILD), false)
    );
}

fn expect_refusal(result: Result<biosmod_core::plan::Built, Error>, message: &str) {
    let error = result.expect_err("expected a refusal");
    assert_eq!(error.code, Code::PatchSourceMismatch, "{error}");
    assert_eq!(error.message, message, "(refusal message)");
}

fn request(firmware: Option<&str>) -> Request {
    Request {
        // TB edits the Table, which the changed Peim leaves intact.
        select: vec!["TB".into()],
        firmware: firmware.map(str::to_string),
        ..Request::default()
    }
}

#[test]
fn plan_refuses_a_closest_only_image_naming_both_banners() {
    let catalog = catalog_recording(Some(RECORDED_BANNER));
    let image = image_with_changed_peim(Some(SIBLING_BANNER));
    expect_refusal(
        build(&image, &catalog, &request(None)),
        "firmware build: expected banner \"X9R9P Ver:005 03/22/2023\" | received \"X9MRA Ver:002 08/11/2022\"; pass --firmware to override",
    );
}

#[test]
fn plan_refuses_a_closest_only_image_naming_the_module_counts_without_banners() {
    let catalog = catalog_recording(None);
    let image = image_with_changed_peim(None);
    expect_refusal(
        build(&image, &catalog, &request(None)),
        "firmware build: expected all 3 recorded modules of synthetic-fw | matched 2; pass --firmware to override",
    );
}

#[test]
fn plan_with_an_explicit_firmware_still_builds_a_closest_only_image() {
    let catalog = catalog_recording(Some(RECORDED_BANNER));
    let image = image_with_changed_peim(Some(SIBLING_BANNER));
    let built = build(&image, &catalog, &request(Some(synthetic::FIRMWARE)))
        .expect("--firmware overrides detection");
    assert_ne!(built.image, image.bytes, "(patched image)");
}

#[test]
fn plan_detects_by_banner_when_the_build_has_no_patch_components() {
    // Detection succeeds, so the failure is the unknown patch, not a firmware refusal.
    let catalog = catalog_without_patches(Some(RECORDED_BANNER));
    let image = image_with_banner(Some(RECORDED_BANNER));
    let error = build(&image, &catalog, &request(None)).expect_err("TB is not in the catalog");
    assert!(
        !error.message.starts_with("firmware build:"),
        "(refusal): expected a selection error, not a detection error | received {error}"
    );
}
