//! Embed the official catalog listed in `catalog/catalog.json` into the binary.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../catalog");
    let manifest = root.join("catalog.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let mut out = String::from(
        "/// Official catalog files embedded at build time: (relative path, bytes).\npub static FILES: &[(&str, &[u8])] = &[\n",
    );
    if manifest.exists() {
        out += &format!(
            "    (\"catalog.json\", include_bytes!({:?})),\n",
            manifest.canonicalize().unwrap()
        );
        let text = fs::read_to_string(&manifest).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("catalog/catalog.json is JSON");
        for entry in value["files"].as_array().expect("files array") {
            let path = entry["path"].as_str().expect("path string");
            assert!(
                !path.contains("..") && !path.starts_with('/'),
                "unsafe catalog path {path}"
            );
            let file = root.join(path);
            println!("cargo:rerun-if-changed={}", file.display());
            out += &format!(
                "    ({path:?}, include_bytes!({:?})),\n",
                file.canonicalize().unwrap()
            );
        }
    }
    out += "];\n";
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded.rs"),
        out,
    )
    .unwrap();
}
