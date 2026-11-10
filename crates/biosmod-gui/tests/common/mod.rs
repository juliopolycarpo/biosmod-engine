//! Shared CLI lookup and isolated synthetic fixtures for GUI integration tests.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the built CLI, honoring the test override.
/// Example: `let binary = common::test_engine();`.
pub fn test_engine() -> PathBuf {
    let binary = std::env::var_os("BME_TEST_ENGINE")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/bme"));
    binary.canonicalize().unwrap_or_else(|error| {
        panic!(
            "bme test engine {}: expected a built CLI executable; run cargo build -p biosmod-cli or set BME_TEST_ENGINE | received {error}",
            binary.display()
        )
    })
}

/// Create a synthetic image and register its catalog in the isolated root.
/// Example: `let image = common::setup_fixture(&binary, root.path());`.
pub fn setup_fixture(binary: &Path, root: &Path) -> PathBuf {
    let fixture = root.join("synthetic fixture ü");
    for args in [
        vec![
            OsString::from("dev"),
            "synthetic".into(),
            "-o".into(),
            fixture.as_os_str().into(),
        ],
        vec![
            OsString::from("catalog"),
            "add".into(),
            "lab".into(),
            fixture.join("catalog").into_os_string(),
            "--allow-unsigned-local".into(),
        ],
    ] {
        let result = Command::new(binary)
            .args(&args)
            .env("BME_CONFIG_HOME", root.join("config"))
            .env("BME_CACHE_HOME", root.join("cache"))
            .env("BME_DATA_HOME", root.join("data"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "synthetic setup {args:?}: expected success | received {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fixture.join("synthetic.bin")
}
