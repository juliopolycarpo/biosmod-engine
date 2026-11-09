//! Differential tests against real firmware dumps (not distributed).
//!
//! Each test runs only when its variable names a local file, for example:
//!
//! ```sh
//! BME_ROM_MR9A=~/bios/MNX99MR9APRO_230322_original_90DEDD1D.bin \
//! BME_ROM_PR9=~/bios/pr9-read1.bin cargo nextest run --locked --release --test real_roms --success-output final
//! ```
//!
//! Expected digests are the images built by x99-bios-fixes (Python) at commit
//! 765e7a80ae8337c0953dc0da41de5f28b56c5c92; three of them were flashed and read back.

mod common;

use common::{Sandbox, s};
use std::path::PathBuf;

/// Resolve the dump named by `var`, printing a skip notice when it is unset.
///
/// Example: `let Some(input) = rom("BME_ROM_PR9") else { return };`
fn rom(var: &str) -> Option<PathBuf> {
    let Some(path) = std::env::var_os(var) else {
        eprintln!("skipped: {var} is not set");
        return None;
    };
    let path = PathBuf::from(path);
    if path.is_file() {
        return Some(path);
    }
    panic!(
        "({var}): expected a readable file | received {}",
        path.display()
    );
}

/// Build `select` from the ROM in `var` and compare the output digest.
fn reproduces(var: &str, select: &[&str], extra: &[&str], expected: &str) {
    let Some(input) = rom(var) else { return };
    let sandbox = Sandbox::new();
    let out = sandbox.path("out.bin");
    let mut args = vec!["patch", s(&input), "-o", s(&out), "--json", "--select"];
    args.extend_from_slice(select);
    args.extend_from_slice(extra);
    let run = sandbox.run(args);
    assert_eq!(run.code, 0, "{}", run.stdout);
    let digest = biosmod_core::util::sha256_hex(&std::fs::read(&out).unwrap());
    assert_eq!(
        digest, expected,
        "({var} {select:?}): expected output sha256 {expected} | received {digest}"
    );
    let verified = sandbox.run(["verify", s(&input), s(&out), "--json"]).json();
    assert_eq!(verified["data"]["complete"], true, "{verified}");
}

#[test]
fn mr9a_stage1_flashed_image() {
    reproduces(
        "BME_ROM_MR9A_STAGE1",
        &["B01-B06", "B02-B03"],
        &[],
        "a5bdac305b59216d49ac8aac65a56056242e5fcecdaecf142d8a57d2bdb8f985",
    );
}

#[test]
fn mr9a_stage2_flashed_image() {
    reproduces(
        "BME_ROM_MR9A_STAGE2",
        &["B05", "B10", "B11", "R01"],
        &[],
        "1ecbe9b09619221556d16fa36427655ca2593ab13b2e4fd7c9b79334c45d03a1",
    );
}

#[test]
fn mr9a_breadcrumbs_flashed_image() {
    reproduces(
        "BME_ROM_MR9A_BREADCRUMBS",
        &["MRC-BREADCRUMBS"],
        &["--allow-diagnostic"],
        "105d05288932ec504e88858d95da78af0c6be1d9068de981494d81db6fd62ed6",
    );
}

const MR9A_ALL: &[&str] = &[
    "A02", "B01-B06", "B02-B03", "B05", "B08", "B09", "B10", "B11", "H05", "R01",
];

#[test]
fn mr9a_reference_full_build() {
    reproduces(
        "BME_ROM_MR9A",
        MR9A_ALL,
        &[],
        "ef7bfec44684ee75dfaa2535a9f09f23bf3d84435d428bfba40a8bbeb1d693c7",
    );
}

#[test]
fn pr9_reference_full_build() {
    let select = [MR9A_ALL, &["S01", "S02"]].concat();
    reproduces(
        "BME_ROM_PR9",
        &select,
        &[],
        "ecd86b22162b52bc74ecf9822e8b5d2f60d3eece9799d6703ca8388ac260c2f2",
    );
}

#[test]
fn stock_images_scan_as_their_builds() {
    for (var, firmware) in [
        ("BME_ROM_MR9A", "mnx99mr9apro-230322"),
        ("BME_ROM_PR9", "x99ha00m-20221202"),
    ] {
        let Some(input) = rom(var) else { continue };
        let report = Sandbox::new().run(["scan", s(&input), "--json"]).json();
        let report = &report["data"]["sources"][0]["report"];
        assert_eq!(report["firmware"], firmware);
        assert_eq!(
            report["recommended"],
            serde_json::json!(["B01-B06", "B02-B03"])
        );
    }
}
