use biosmod_core::Code;
use biosmod_core::catalog::{Catalog, MemorySource, Scope, index_files};
use biosmod_core::synthetic::{self, Fixture};

fn load_modified(edit: impl FnOnce(&mut serde_json::Value)) -> biosmod_core::Error {
    let mut files = Fixture::new(0x07).catalog_files();
    let patch = files
        .iter_mut()
        .find(|(path, _)| path == "patches/PA.json")
        .unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&patch.1).unwrap();
    let variants = doc["variants"].as_object_mut().unwrap();
    let variant = variants.values_mut().next().unwrap();
    edit(&mut variant["components"][0]);
    patch.1 = synthetic::pretty(&doc);
    let content: Vec<_> = files
        .iter()
        .filter(|(path, _)| path != "catalog.json")
        .cloned()
        .collect();
    let manifest = files
        .iter_mut()
        .find(|(path, _)| path == "catalog.json")
        .unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&manifest.1).unwrap();
    doc["files"] = serde_json::to_value(index_files(&content).unwrap()).unwrap();
    manifest.1 = synthetic::pretty(&doc);
    Catalog::load(&MemorySource::new(files), Scope::All).unwrap_err()
}

#[test]
fn catalog_rejects_overflowing_hunk_range() {
    let error =
        load_modified(|component| component["hunks"][0]["offset"] = serde_json::json!(usize::MAX));
    assert_eq!(error.code, Code::CatalogInvalid, "{error}");
    assert!(
        error.message.contains(&format!("{:#x}", usize::MAX)),
        "{error}"
    );
}

#[test]
fn catalog_rejects_overflowing_appended_size() {
    let error = load_modified(|component| {
        component["source_size"] = serde_json::json!(usize::MAX);
        component["result_size"] = serde_json::json!(usize::MAX);
        component["hunks"] = serde_json::json!([{"op": "append", "offset": usize::MAX, "before": "", "after": "01"}]);
    });
    assert_eq!(error.code, Code::CatalogInvalid, "{error}");
    assert!(error.message.contains(&usize::MAX.to_string()), "{error}");
}
