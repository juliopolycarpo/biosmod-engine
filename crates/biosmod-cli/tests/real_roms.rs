//! Differential tests against real firmware dumps (not distributed).
//!
//! Each test runs only when its variable names a local file, for example:
//!
//! ```sh
//! BME_ROM_MR9A=~/bios/MNX99MR9APRO_230322_original_90DEDD1D.bin \
//! BME_ROM_PR9=~/bios/pr9-read1.bin \
//! BME_ROM_MR9A_LIVE=path/to/a-dump-with-saved-setup.bin cargo nextest run --locked --release --test real_roms --success-output final
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

/// Names of the PE32 pairs that `bme compare` reports with `verdict` for two dumps.
fn compared_names(var_a: &str, var_b: &str, verdict: &str) -> Option<Vec<String>> {
    let (a, b) = (rom(var_a)?, rom(var_b)?);
    let sandbox = Sandbox::new();
    let run = sandbox.run(["compare", s(&a), s(&b), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    let doc = run.json();
    Some(
        doc["data"]["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["leaf"] == "pe32" && p["verdict"] == verdict)
            .filter_map(|p| p["name"].as_str().map(str::to_string))
            .collect(),
    )
}

#[test]
fn pr9_vs_mr9a_s3_modules_are_identical_after_normalization() {
    let Some(names) = compared_names(
        "BME_ROM_PR9",
        "BME_ROM_MR9A",
        "identical-after-normalization",
    ) else {
        return;
    };
    for module in ["S3Resume", "S3Resume2Pei", "MtrrS3SaveRestorePei"] {
        assert!(
            names.iter().any(|n| n == module),
            "(compare {module}): expected identical-after-normalization | received {names:?}"
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

const SETUP_VARIABLE_GUID: &str = "EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9";

/// `bme nvram --all-records --json` variables of the ROM named by `var`.
fn nvram_records(var: &str) -> Option<Vec<serde_json::Value>> {
    let input = rom(var)?;
    let run = Sandbox::new().run(["nvram", s(&input), "--all-records", "--json"]);
    assert_eq!(run.code, 0, "({var} nvram): {}", run.stdout);
    let doc = run.json();
    assert_eq!(
        doc["data"]["issues"],
        serde_json::json!([]),
        "({var} nvram issues): expected a clean walk"
    );
    Some(doc["data"]["variables"].as_array().unwrap().clone())
}

/// Records named `name` with variable GUID `guid`, as (store, state, size) triples.
fn named(records: &[serde_json::Value], name: &str, guid: &str) -> Vec<(String, String, u64)> {
    records
        .iter()
        .filter(|v| v["name"] == name && v["guid"] == guid)
        .map(|v| {
            (
                v["store"].as_str().unwrap().to_owned(),
                v["state"].as_str().unwrap().to_owned(),
                v["size"].as_u64().unwrap(),
            )
        })
        .collect()
}

/// One stored value of a field: (store, state, value).
type StoredValue = (String, String, u64);

/// `bme nvram --field PROMPT --all-records --json`: the `field` document and its values.
fn field_values(
    var: &str,
    prompt: &str,
    question_id: Option<&str>,
) -> Option<(serde_json::Value, Vec<StoredValue>)> {
    let input = rom(var)?;
    let mut args = vec![
        "nvram",
        s(&input),
        "--field",
        prompt,
        "--all-records",
        "--json",
    ];
    if let Some(id) = question_id {
        args.extend(["--question-id", id]);
    }
    let run = Sandbox::new().run(args);
    assert_eq!(
        run.code, 0,
        "({var} nvram --field {prompt:?}): {}",
        run.stdout
    );
    let field = run.json()["data"]["field"].clone();
    let values = field["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["store"].as_str().unwrap().to_owned(),
                v["state"].as_str().unwrap().to_owned(),
                v["value"].as_u64().unwrap(),
            )
        })
        .collect();
    Some((field, values))
}

#[test]
fn pr9_nvram_lists_setup_0x6c_with_history_and_zero_sleep_default() {
    let Some(records) = nvram_records("BME_ROM_PR9") else {
        return;
    };
    let setup = named(&records, "Setup", SETUP_VARIABLE_GUID);
    for store in ["nvar@0x800060", "nvar@0x840060"] {
        assert!(
            setup
                .iter()
                .any(|(s, state, size)| s == store && state == "active" && *size == 0x6C),
            "(PR9 Setup in {store}): expected an active 0x6C-byte record | received {setup:?}"
        );
    }
    assert!(
        setup
            .iter()
            .any(|(s, state, size)| s == "nvar@0x840060:StdDefaults"
                && state == "active"
                && *size == 0x6C),
        "(PR9 standard defaults): expected a 0x6C-byte Setup | received {setup:?}"
    );
    assert!(
        setup
            .iter()
            .filter(|(s, state, _)| s == "nvar@0x840060" && state == "superseded")
            .count()
            >= 2,
        "(PR9 live store history): expected superseded Setup records | received {setup:?}"
    );
    assert!(
        records.iter().any(|v| v["state"] == "deleted"),
        "(PR9 live store): expected deleted records"
    );
    assert!(
        records.iter().all(|v| v["state"] != "orphan"),
        "(PR9): expected no orphan data-only records"
    );

    let (field, values) = field_values("BME_ROM_PR9", "ACPI Sleep State", None).unwrap();
    assert_eq!(
        (
            &field["question_ids"],
            &field["offset"],
            &field["width"],
            &field["varstore_size"]
        ),
        (
            &serde_json::json!([0x19]),
            &serde_json::json!(0x0A),
            &serde_json::json!(2),
            &serde_json::json!(0x6C)
        )
    );
    assert_eq!(field["standard_default"], 0);
    let defaults: Vec<&(String, String, u64)> = values
        .iter()
        .filter(|(s, _, _)| s.ends_with(":StdDefaults"))
        .collect();
    assert!(
        !defaults.is_empty() && defaults.iter().all(|(_, _, value)| *value == 0),
        "(PR9 standard-default sleep word): expected 0 | received {values:?}"
    );
}

#[test]
fn pr9_live_store_sets_memory_frequency_away_from_the_auto_default() {
    // Recorded from the stock dump: the live NVRAM copy of IntelSetup holds Memory Frequency
    // 0xB (2133) while the standard default and the other store say 0 (Auto).
    let Some((field, values)) = field_values("BME_ROM_PR9", "Memory Frequency", None) else {
        return;
    };
    assert_eq!(field["offset"], 0x1248);
    assert_eq!(field["standard_default"], 0);
    let active = |store: &str| {
        values
            .iter()
            .find(|(s, state, _)| s == store && state == "active")
            .map(|(_, _, value)| *value)
    };
    assert_eq!(
        active("nvar@0x840060"),
        Some(0x0B),
        "(PR9 live IntelSetup): {values:?}"
    );
    assert_eq!(
        active("nvar@0x800060"),
        Some(0),
        "(PR9 first store IntelSetup): {values:?}"
    );
    assert_eq!(
        active("nvar@0x840060:StdDefaults"),
        Some(0),
        "(PR9 defaults IntelSetup): {values:?}"
    );
}

#[test]
fn mr9a_nvram_lists_setup_0x7d_smart_fan_and_two_sleep_default() {
    let Some(records) = nvram_records("BME_ROM_MR9A") else {
        return;
    };
    // The stock image has no live NVRAM: every record is the holder or inside StdDefaults.
    assert!(
        records.iter().all(
            |v| v["store"] == "nvar@0x800060" && v["name"] == "StdDefaults"
                || v["store"] == "nvar@0x800060:StdDefaults"
        ),
        "(MR9A stock stores): expected only the defaults store"
    );
    assert_eq!(
        named(&records, "Setup", SETUP_VARIABLE_GUID),
        [(
            "nvar@0x800060:StdDefaults".to_owned(),
            "active".to_owned(),
            0x7D
        )]
    );
    assert_eq!(
        named(
            &records,
            "NCT5532D_SMF",
            "2634D36A-335D-4312-B210-77E3134A61A6"
        ),
        [(
            "nvar@0x800060:StdDefaults".to_owned(),
            "active".to_owned(),
            28
        )],
        "(MR9A Smart Fan variable): expected the 28-byte NCT5532D_SMF"
    );

    let (field, values) = field_values("BME_ROM_MR9A", "ACPI Sleep State", None).unwrap();
    assert_eq!(
        (
            &field["question_ids"],
            &field["offset"],
            &field["varstore_size"]
        ),
        (
            &serde_json::json!([0x31]),
            &serde_json::json!(0x2A),
            &serde_json::json!(0x7D)
        )
    );
    assert_eq!(
        values,
        [(
            "nvar@0x800060:StdDefaults".to_owned(),
            "active".to_owned(),
            2
        )],
        "(MR9A standard-default sleep word)"
    );
}

#[test]
fn mr9a_stock_defaults_leave_memory_frequency_on_auto() {
    // H03 (active IntelSetup records with Memory Frequency 13) is not visible on the stock
    // image: it carries no live records. The defaults say Auto.
    let Some((field, values)) = field_values("BME_ROM_MR9A", "Memory Frequency", None) else {
        return;
    };
    assert_eq!(field["varstore_size"], 0x17CB);
    assert_eq!(
        values,
        [(
            "nvar@0x800060:StdDefaults".to_owned(),
            "active".to_owned(),
            0
        )],
        "(MR9A stock Memory Frequency)"
    );
}

#[test]
fn mr9a_installed_image_sets_memory_frequency_13_against_the_auto_default() {
    // H03, from the read of the board that ran the audit (a dump with saved Setup values).
    let Some((field, values)) = field_values("BME_ROM_MR9A_LIVE", "Memory Frequency", None) else {
        return;
    };
    assert_eq!(field["standard_default"], 0);
    let active: Vec<&(String, String, u64)> = values
        .iter()
        .filter(|(s, state, _)| state == "active" && !s.ends_with(":StdDefaults"))
        .collect();
    assert!(
        !active.is_empty() && active.iter().all(|(_, _, value)| *value == 13),
        "(MR9A installed active IntelSetup Memory Frequency): expected 13 (2400) | received {values:?}"
    );
    assert!(
        values
            .iter()
            .filter(|(s, _, _)| s.ends_with(":StdDefaults"))
            .all(|(_, _, value)| *value == 0),
        "(MR9A installed defaults): expected Auto (0) | received {values:?}"
    );
}

/// One stored table of a stock dump: signature, OEM table ID, length, SHA-256 and owning GUIDs.
type StoredRow = (String, String, u64, String, Vec<String>);

/// Stored tables of the stock dump `input`, from `bme inspect --acpi --json`.
fn stored_acpi(var: &str, input: &std::path::Path) -> Vec<StoredRow> {
    let listed = Sandbox::new()
        .run(["inspect", s(input), "--acpi", "--json"])
        .json();
    listed["data"]["acpi"]["tables"]
        .as_array()
        .unwrap_or_else(|| panic!("({var}): expected data.acpi.tables | received {listed}"))
        .iter()
        .map(|t| {
            let guids = t["locations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l["file_guid"].as_str().unwrap().to_string())
                .collect();
            (
                t["signature"].as_str().unwrap().to_string(),
                t["oem_table_id"].as_str().unwrap().to_string(),
                t["length"].as_u64().unwrap(),
                t["sha256"].as_str().unwrap().to_string(),
                guids,
            )
        })
        .collect()
}

/// Stored tables expected in a stock dump: signature, OEM table ID, length, SHA-256.
///
/// The first five of PR9 and the first four of MR9A plus `PttSsdt` come from the exploratory
/// Python inventory of the same dumps. `NITR` passes the same checksum rule and is not in
/// that inventory, which only kept tables it recognized.
const PR9_TABLES: &[(&str, &str, u64, &str)] = &[
    (
        "DSDT",
        "A M I",
        208_780,
        "f9ac4576906895417c5a272f8ff06994e34b6d3c031546a27d3c7d16e9b609f2",
    ),
    (
        "SSDT",
        "PmMgt",
        86_651,
        "d9e996cfc868de997317907a8bb564471ee1ea8c1a28c8c7d9b864408648b859",
    ),
    (
        "SSDT",
        "SSDT HWP",
        166_500,
        "cb452004729cecae32659a9e8c47d2dd14cb45708730142107cc8aea28d2b0cd",
    ),
    (
        "SSDT",
        "IdeTable",
        1_173,
        "6a6b1e4ef1e49cacfdd87877fad9a2608488c7f39069cc7da572e798a21e0c95",
    ),
    (
        "SSDT",
        "SataTabl",
        877,
        "db199e367aab6883bbbeec61aab06337ccaaaf3128d43013f7eb7cb75aeb89d4",
    ),
    (
        "NITR",
        "ACPI_OEM",
        113,
        "c6656d6a3f5255ced36cfe03e4e10f313638fd295546dc074df662caebbbb603",
    ),
];
const MR9A_TABLES: &[(&str, &str, u64, &str)] = &[
    (
        "DSDT",
        "A M I",
        210_445,
        "578fc629a1e4af887d54fb3f8c91fbb74fda0d84dce0a8881c67574ff6bad67e",
    ),
    (
        "SSDT",
        "PmMgt",
        86_915,
        "a71565d5f2cabc159f4c68e064742e38e734504937e62e8fcd2a002935a18df3",
    ),
    (
        "SSDT",
        "SSDT HWP",
        321_636,
        "4928101107db5db226576560345bc5d926e58eae7b01abc8cc7c62ccd5ae54e5",
    ),
    (
        "SSDT",
        "IdeTable",
        1_173,
        "6a6b1e4ef1e49cacfdd87877fad9a2608488c7f39069cc7da572e798a21e0c95",
    ),
    (
        "SSDT",
        "SataTabl",
        877,
        "db199e367aab6883bbbeec61aab06337ccaaaf3128d43013f7eb7cb75aeb89d4",
    ),
    (
        "SSDT",
        "PttSsdt",
        65,
        "33d3555c5a0a9b746db4349de660ba00083cff57c437bede9d7fe51a21b8b062",
    ),
    (
        "NITR",
        "ACPI_OEM",
        113,
        "c6656d6a3f5255ced36cfe03e4e10f313638fd295546dc074df662caebbbb603",
    ),
];

#[test]
fn stock_images_list_exactly_their_stored_acpi_tables() {
    for (var, expected) in [("BME_ROM_PR9", PR9_TABLES), ("BME_ROM_MR9A", MR9A_TABLES)] {
        let Some(input) = rom(var) else { continue };
        let mut listed: Vec<(String, String, u64, String)> = stored_acpi(var, &input)
            .into_iter()
            .map(|t| (t.0, t.1, t.2, t.3))
            .collect();
        let mut wanted: Vec<(String, String, u64, String)> = expected
            .iter()
            .map(|t| (t.0.to_string(), t.1.to_string(), t.2, t.3.to_string()))
            .collect();
        listed.sort();
        wanted.sort();
        assert_eq!(
            listed, wanted,
            "({var} stored ACPI tables): expected exactly the reference set | received a different set"
        );
    }
}

#[test]
fn every_listed_stock_acpi_table_extracts_unchanged() {
    for var in ["BME_ROM_PR9", "BME_ROM_MR9A"] {
        let Some(input) = rom(var) else { continue };
        let sandbox = Sandbox::new();
        for (n, (signature, oem_table_id, length, digest, guids)) in
            stored_acpi(var, &input).into_iter().enumerate()
        {
            for (k, guid) in guids.iter().enumerate() {
                let selectors = [
                    vec!["--sha256", digest.as_str()],
                    vec![
                        "--signature",
                        signature.as_str(),
                        "--oem-table-id",
                        oem_table_id.as_str(),
                    ],
                ];
                for (m, by) in selectors.into_iter().enumerate() {
                    let out = sandbox.path(&format!("table-{n}-{k}-{m}"));
                    let mut args = vec![
                        "extract",
                        s(&input),
                        "--guid",
                        guid,
                        "--leaf",
                        "acpi-table",
                        "-o",
                        s(&out),
                        "--json",
                    ];
                    args.extend(&by);
                    let run = sandbox.run(args);
                    let ctx = format!("({var} {signature} {oem_table_id} in {guid} via {by:?})");
                    assert_eq!(
                        run.code, 0,
                        "{ctx}: expected exit 0 | received {}",
                        run.stdout
                    );
                    let bytes = std::fs::read(&out).unwrap();
                    assert_eq!(
                        bytes.len() as u64,
                        length,
                        "{ctx}: expected length {length}"
                    );
                    assert_eq!(
                        biosmod_core::util::sha256_hex(&bytes),
                        digest,
                        "{ctx}: expected extracted sha256 {digest}"
                    );
                }
            }
        }
    }
}

/// The one EFI 1.1 compressed driver both stock dumps carry.
const EFI_COMPRESSED_DRIVER: &str = "91B4D9C1-141C-4824-8D02-3C298E36EB3F";
/// SHA-256 of its decoded PE32 image (211712 bytes), as extracted by `bme extract`.
const EFI_COMPRESSED_DRIVER_SHA256: &str =
    "1bd1e0bb5d85c706e2c266feae619a2de20a49688ca83ceb957b7eae65e0f0f4";

#[test]
fn stock_images_decode_their_efi_compressed_driver() {
    for var in ["BME_ROM_MR9A", "BME_ROM_PR9"] {
        let Some(input) = rom(var) else { continue };
        let sandbox = Sandbox::new();
        let inspect = sandbox
            .run(["inspect", s(&input), "--files", "--json"])
            .json();
        let files: Vec<&serde_json::Value> = inspect["data"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|v| v["files"].as_array().unwrap())
            .collect();
        let opaque = files.iter().filter(|f| f["opaque"] == true).count();
        assert_eq!(
            opaque, 0,
            "({var} opaque files): expected 0 | received {opaque}"
        );
        let efi: Vec<&&serde_json::Value> = files
            .iter()
            .filter(|f| f["encodings"] == serde_json::json!(["efi"]))
            .collect();
        assert_eq!(
            efi.len(),
            1,
            "({var} efi files): expected 1 | received {efi:?}"
        );
        assert_eq!(efi[0]["guid"], EFI_COMPRESSED_DRIVER);

        let module = sandbox.path("driver.pe");
        let extracted = sandbox
            .run([
                "extract",
                s(&input),
                "--guid",
                EFI_COMPRESSED_DRIVER,
                "-o",
                s(&module),
                "--json",
            ])
            .json();
        assert_eq!(
            extracted["data"]["sha256"], EFI_COMPRESSED_DRIVER_SHA256,
            "{var}"
        );
    }
}
#[test]
fn pr9_vs_mr9a_nct5532d_differs_after_normalization() {
    let Some(names) = compared_names("BME_ROM_PR9", "BME_ROM_MR9A", "different") else {
        return;
    };
    assert!(
        names.iter().any(|n| n == "NCT5532DPeiInit"),
        "(compare NCT5532DPeiInit): expected different | received {names:?}"
    );
}
