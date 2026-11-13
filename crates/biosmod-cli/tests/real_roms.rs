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

const SETUP_GUID: &str = "899407D7-99FE-43D8-9A21-79EC328CAC21";
const SETUP_VARSTORE_GUID: &str = "EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9";

/// Every statement of the Setup PE in the ROM named by `var`, decoded by `bme ifr --guid`.
fn setup_statements(var: &str) -> Option<Vec<serde_json::Value>> {
    let input = rom(var)?;
    let run = Sandbox::new().run(["ifr", s(&input), "--guid", SETUP_GUID, "--json"]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    let doc = run.json();
    let modules = doc["data"]["modules"].as_array().unwrap();
    assert_eq!(modules.len(), 1, "({var} ifr): expected one module | {doc}");
    let statements = modules[0]["package_lists"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|list| list["form_sets"].as_array().unwrap())
        .flat_map(|set| set["forms"].as_array().unwrap())
        .flat_map(|form| form["statements"].as_array().unwrap().clone())
        .collect();
    Some(statements)
}

/// The only statement with `prompt` and `kind`, panicking with the match count otherwise.
fn only<'a>(
    statements: &'a [serde_json::Value],
    prompt: &str,
    kind: &str,
) -> &'a serde_json::Value {
    let hits: Vec<_> = statements
        .iter()
        .filter(|s| s["prompt"] == prompt && s["kind"] == kind)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "(ifr {kind} {prompt:?}): expected one statement | received {}",
        hits.len()
    );
    hits[0]
}

fn option_values(question: &serde_json::Value) -> Vec<u64> {
    question["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["value"].as_u64().unwrap())
        .collect()
}

#[test]
fn pr9_setup_sleep_state_offers_only_suspend_disabled() {
    let Some(statements) = setup_statements("BME_ROM_PR9") else {
        return;
    };
    let sleep = only(&statements, "ACPI Sleep State", "one_of");
    assert_eq!(sleep["varstore"]["name"], "Setup");
    assert_eq!(sleep["varstore"]["guid"], SETUP_VARSTORE_GUID);
    assert_eq!(sleep["var_offset"], 0x0A);
    assert_eq!(sleep["width"], 2);
    assert_eq!(option_values(sleep), [0]);
    let option = &sleep["options"][0];
    assert_eq!(option["label"], "Suspend Disabled");
    assert_eq!(option["standard_default"], true);
    assert_eq!(option["manufacturing_default"], true);
    let conditions: Vec<(&str, &str)> = sleep["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["kind"].as_str().unwrap(),
                c["expression"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        conditions,
        [
            ("suppress_if", "ideqval 0x17 == 1"),
            ("gray_out_if", "ideqval 0xd3 == 1")
        ]
    );
}

#[test]
fn mr9a_setup_sleep_state_offers_suspend_s1_and_s3() {
    let Some(statements) = setup_statements("BME_ROM_MR9A") else {
        return;
    };
    let sleep = only(&statements, "ACPI Sleep State", "one_of");
    assert_eq!(sleep["varstore"]["name"], "Setup");
    assert_eq!(sleep["var_offset"], 0x2A);
    assert_eq!(sleep["width"], 2);
    assert_eq!(option_values(sleep), [0, 1, 2]);
    assert_eq!(sleep["options"][2]["standard_default"], true);
    assert_eq!(sleep["options"][2]["manufacturing_default"], true);
}

#[test]
fn setup_hibernation_checkbox_keeps_its_explicit_default_opcodes() {
    for (var, offset) in [("BME_ROM_PR9", 0x0D), ("BME_ROM_MR9A", 0x2D)] {
        let Some(statements) = setup_statements(var) else {
            continue;
        };
        let hibernation = only(&statements, "Enable Hibernation", "check_box");
        assert_eq!(hibernation["var_offset"], offset, "({var})");
        assert_eq!(hibernation["width"], 1, "({var})");
        let defaults: Vec<(u64, u64)> = hibernation["defaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["default_id"].as_u64().unwrap(),
                    d["value"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(defaults, [(0, 1), (1, 1)], "({var})");
    }
}

#[test]
fn mr9a_setup_smart_fan_pwm_accepts_zero() {
    let Some(statements) = setup_statements("BME_ROM_MR9A") else {
        return;
    };
    let pwm = statements
        .iter()
        .find(|s| s["prompt"] == "Smart Fan PWM 1" && s["kind"] == "numeric")
        .expect("(ifr): expected a Smart Fan PWM 1 question | received none");
    assert_eq!(pwm["varstore"]["name"], "NCT5532D_SMF");
    assert_eq!(pwm["var_offset"], 6);
    assert_eq!(
        (pwm["min"].as_u64(), pwm["max"].as_u64()),
        (Some(0), Some(255))
    );
}

#[test]
fn stock_images_decode_every_setup_module_with_ifr() {
    for var in ["BME_ROM_PR9", "BME_ROM_MR9A"] {
        let Some(input) = rom(var) else { continue };
        let doc = Sandbox::new().run(["ifr", s(&input), "--json"]).json();
        let guids: Vec<&str> = doc["data"]["modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["guid"].as_str().unwrap())
            .collect();
        assert!(
            guids.contains(&SETUP_GUID),
            "({var} ifr): expected {SETUP_GUID} in {guids:?}"
        );
    }
}

const PLATFORM_GUID: &str = "ABBCE13D-E25A-4D9F-A1F9-2F7710786892";

/// Regression: AMI wraps whole Platform forms in a FormSet-level SuppressIf, which an
/// over-strict walker rejected, dropping the module (and Memory Frequency with it).
#[test]
fn stock_images_decode_every_ifr_module_without_diagnostics() {
    for var in ["BME_ROM_PR9", "BME_ROM_MR9A"] {
        let Some(input) = rom(var) else { continue };
        let doc = Sandbox::new().run(["ifr", s(&input), "--json"]).json();
        let diagnostics = &doc["data"]["diagnostics"];
        assert_eq!(
            diagnostics.as_array().map(Vec::len),
            Some(0),
            "({var} ifr): expected no diagnostics | received {diagnostics}"
        );
        let modules = doc["data"]["modules"].as_array().unwrap();
        let platform = modules
            .iter()
            .find(|m| m["guid"] == PLATFORM_GUID)
            .unwrap_or_else(|| panic!("({var} ifr): expected module {PLATFORM_GUID}"));
        let mut wrapped = 0;
        let mut memory_frequency = 0;
        for form in platform["package_lists"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|l| l["form_sets"].as_array().unwrap())
            .flat_map(|set| set["forms"].as_array().unwrap())
        {
            wrapped += usize::from(!form["conditions"].as_array().unwrap().is_empty());
            memory_frequency += form["statements"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|st| st["prompt"].as_str() == Some("Memory Frequency"))
                .count();
        }
        assert!(
            wrapped > 0,
            "({var} ifr): expected a Platform form under a condition | received none"
        );
        assert!(
            memory_frequency > 0,
            "({var} ifr): expected question \"Memory Frequency\" | received none"
        );
    }
}
