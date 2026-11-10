//! Embed a fingerprint of source and build inputs into the engine.

mod build_identity;

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    assert!(
        root.to_str().is_some(),
        "workspace path must be UTF-8 for build identity tracking"
    );
    let inputs = [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates/biosmod-core/Cargo.toml",
        "crates/biosmod-core/build.rs",
        "crates/biosmod-core/build_identity.rs",
        "crates/biosmod-core/src",
        "crates/biosmod-cli/Cargo.toml",
        "crates/biosmod-cli/build.rs",
        "crates/biosmod-cli/src",
        "catalog",
        "tools/ghidra",
        "docs/guide",
        "schemas/envelope.schema.json",
    ];
    let entries = build_identity::collect_inputs(&root, &inputs).expect("build identity inputs");
    for entry in &entries {
        println!("cargo:rerun-if-changed={}", root.join(entry).display());
    }
    let rustc = env::var_os("RUSTC").expect("Cargo supplies RUSTC");
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    assert!(output.status.success(), "rustc -vV failed");
    let mut settings = BTreeMap::new();
    settings.insert(
        "rustc".into(),
        String::from_utf8(output.stdout).expect("rustc version UTF-8"),
    );
    // Cargo does not automatically watch arbitrary environment variables used here.
    let host = env::var("HOST").expect("Cargo supplies HOST");
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let native_names = build_identity::native_setting_names(&host, &target);
    for name in native_names.iter().map(String::as_str).chain([
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ]) {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for profile in ["DEV", "RELEASE", "TEST", "BENCH"] {
        for setting in [
            "OPT_LEVEL",
            "DEBUG",
            "LTO",
            "CODEGEN_UNITS",
            "PANIC",
            "DEBUG_ASSERTIONS",
            "OVERFLOW_CHECKS",
            "INCREMENTAL",
            "STRIP",
        ] {
            println!("cargo:rerun-if-env-changed=CARGO_PROFILE_{profile}_{setting}");
        }
    }
    for (name, value) in env::vars_os() {
        let Ok(name) = name.into_string() else {
            continue;
        };
        if matches!(
            name.as_str(),
            "TARGET"
                | "HOST"
                | "PROFILE"
                | "OPT_LEVEL"
                | "DEBUG"
                | "CARGO_CFG_TARGET_FEATURE"
                | "CARGO_CFG_PANIC"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "RUSTFLAGS"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "CC"
                | "AR"
                | "CFLAGS"
                | "CXXFLAGS"
                | "ARFLAGS"
        ) || name.starts_with("CARGO_FEATURE_")
            || name.starts_with("CARGO_PROFILE_")
            || name.starts_with("CARGO_CFG_")
            || native_names.contains(&name)
        {
            if name.starts_with("CARGO_PROFILE_") || native_names.contains(&name) {
                println!("cargo:rerun-if-env-changed={name}");
            }
            let value = build_identity::decode_setting(&name, value)
                .expect("decode build identity setting");
            let value = build_identity::normalize_setting(&root, &value);
            settings.insert(name, value);
        }
    }
    let digest =
        build_identity::fingerprint(&root, &entries, &settings).expect("fingerprint build inputs");
    println!("cargo:rustc-env=BME_BUILD_FINGERPRINT={digest}");
}
