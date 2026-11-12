//! Malformed input: bounded failures, never panics, and strict catalog parsing.

use biosmod_core::aml::{fixture as aml_fixture, walk_table};
use biosmod_core::catalog::{Catalog, MemorySource, Scope};
use biosmod_core::firmware::Image;
use biosmod_core::synthetic::{self, Fixture, ffs, section, volume};
use biosmod_core::util::Guid;
use biosmod_core::{Code, json};
use proptest::prelude::*;

fn fixture_image() -> Vec<u8> {
    Fixture::new(0x07).image
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = Image::parse(bytes);
    }

    #[test]
    fn mutated_images_fail_cleanly_or_parse(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8), cut in any::<usize>()) {
        let mut bytes = fixture_image();
        for (at, value) in flips {
            let index = at % bytes.len();
            bytes[index] ^= value | 1;
        }
        let keep = bytes.len() - cut % (bytes.len() / 2);
        bytes.truncate(keep);
        if let Err(error) = Image::parse(bytes) {
            prop_assert!(matches!(error.code, Code::FormatInvalid | Code::FormatUnsupported), "unexpected code {:?}: {}", error.code, error);
        }
    }

    /// Random AML after a valid header: the walker may warn, never panic.
    #[test]
    fn arbitrary_aml_never_panics(aml in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = walk_table(&aml_fixture::table("DSDT", "FUZZ", &aml));
    }

    /// Random bytes biased toward real opcodes, so deeper arms are reached.
    #[test]
    fn opcode_heavy_aml_never_panics(
        aml in proptest::collection::vec(
            prop_oneof![
                proptest::sample::select(vec![0x10u8, 0x14, 0x08, 0x5B, 0x82, 0x83, 0x84, 0x85, 0x80, 0x81, 0x86, 0x87, 0x01, 0x02, 0x88, 0x13, 0x8A, 0x8B, 0x06, 0x15, 0xA0, 0x0A, 0x0B, 0x0C, 0x0D, 0x11, 0x12, 0x2E, 0x2F, 0x5C, 0x5E, 0x00, 0x01, 0x41]),
                any::<u8>(),
            ],
            0..256,
        )
    ) {
        let _ = walk_table(&aml_fixture::table("DSDT", "FUZZ", &aml));
    }

    /// A valid namespace with bytes flipped and the table cut anywhere.
    #[test]
    fn mutated_aml_never_panics(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..6)) {
        let mut aml = [
            aml_fixture::scope("\\_SB_", &[aml_fixture::device("PCI0", &[aml_fixture::method("SIOS", 1, &[0xA4, 0x00]), aml_fixture::name_byte("_ADR", 0)])]),
            aml_fixture::name_package("\\_S3_", &[5, 0]),
            aml_fixture::operation_region("OPR0", 0x100, 8),
        ].concat();
        for (at, value) in flips {
            let index = at % aml.len();
            aml[index] ^= value | 1;
        }
        let _ = walk_table(&aml_fixture::table("DSDT", "FUZZ", &aml));
    }

    #[test]
    fn hex_and_guid_parsers_reject_garbage(text in "\\PC{0,64}") {
        let _ = biosmod_core::util::unhex(&text);
        let _ = text.parse::<Guid>();
    }
}

#[test]
fn nesting_beyond_the_limit_is_refused() {
    let guid: Guid = "12345678-1234-1234-1234-123456789ABC".parse().unwrap();
    let mut inner = volume(&[], 0x1000);
    for _ in 0..20 {
        let file = ffs(guid, 0x0B, &section(0x17, &inner), 0);
        inner = volume(&[file], synthetic_align(inner.len() + 0x200));
    }
    let error = Image::parse(inner).unwrap_err();
    assert_eq!(error.code, Code::FormatUnsupported, "{error}");
    assert!(error.message.contains("nesting exceeds"), "{error}");
}

fn synthetic_align(size: usize) -> usize {
    size.div_ceil(0x1000) * 0x1000
}

fn files_with(path: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<(String, Vec<u8>)> {
    let mut files = Fixture::new(0x07).catalog_files();
    let at = files.iter().position(|(p, _)| p == path).unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&files[at].1).unwrap();
    edit(&mut doc);
    files[at].1 = synthetic::pretty(&doc);
    reindex(files)
}

/// Recompute the index so tests reach semantic validation, not hash checks.
fn reindex(mut files: Vec<(String, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    let at = files.iter().position(|(p, _)| p == "catalog.json").unwrap();
    let content: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter(|(p, _)| p != "catalog.json")
        .cloned()
        .collect();
    let mut manifest: serde_json::Value = serde_json::from_slice(&files[at].1).unwrap();
    manifest["files"] =
        serde_json::to_value(biosmod_core::catalog::index_files(&content).unwrap()).unwrap();
    files[at].1 = synthetic::pretty(&manifest);
    files
}

fn load(files: Vec<(String, Vec<u8>)>) -> biosmod_core::Result<Catalog> {
    Catalog::load(&MemorySource::new(files), Scope::All)
}

#[test]
fn catalog_rejects_cycles_unknown_fields_and_bad_references() {
    assert!(load(Fixture::new(0x07).catalog_files()).is_ok());
    let cycle = files_with("patches/PA.json", |p| {
        p["requires"] = serde_json::json!(["PS"])
    });
    let cycle = {
        let mut files = cycle;
        let at = files
            .iter()
            .position(|(p, _)| p == "patches/PS.json")
            .unwrap();
        let mut doc: serde_json::Value = serde_json::from_slice(&files[at].1).unwrap();
        doc["requires"] = serde_json::json!(["PA"]);
        files[at].1 = synthetic::pretty(&doc);
        reindex(files)
    };
    let error = load(cycle).unwrap_err();
    assert_eq!(error.code, Code::CatalogInvalid, "{error}");

    let unknown = load(files_with("patches/PA.json", |p| {
        p["auto_apply"] = true.into()
    }))
    .unwrap_err();
    assert!(unknown.message.contains("auto_apply"), "{unknown}");
    let dangling = load(files_with("patches/PA.json", |p| {
        p["conflicts"] = serde_json::json!(["ZZ"])
    }))
    .unwrap_err();
    assert_eq!(dangling.code, Code::CatalogInvalid, "{dangling}");
    let renamed = load(files_with("patches/PA.json", |p| p["id"] = "PZ".into())).unwrap_err();
    assert_eq!(renamed.code, Code::CatalogInvalid, "{renamed}");
}

#[test]
fn catalog_rejects_tampering_escapes_and_duplicate_keys() {
    let mut files = Fixture::new(0x07).catalog_files();
    let at = files
        .iter()
        .position(|(p, _)| p == "patches/PA.json")
        .unwrap();
    files[at].1.push(b' ');
    assert_eq!(load(files).unwrap_err().code, Code::CatalogInvalid);

    let mut escape = Fixture::new(0x07).catalog_files();
    let at = escape
        .iter()
        .position(|(p, _)| p == "catalog.json")
        .unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&escape[at].1).unwrap();
    manifest["files"][0]["path"] = "../outside.json".into();
    escape[at].1 = synthetic::pretty(&manifest);
    let error = load(escape).unwrap_err();
    assert!(error.message.contains("../outside.json"), "{error}");

    let duplicate = br#"{"a": 1, "nested": {"b": 2, "b": 3}}"#;
    let error = json::parse_strict::<serde_json::Value>(duplicate, "doc").unwrap_err();
    assert!(error.message.contains("duplicate key"), "{error}");
}
