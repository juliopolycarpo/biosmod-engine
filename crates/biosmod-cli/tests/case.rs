//! `bme case` end to end on the synthetic image: init, record, status drift, export and catalog checks.

mod common;

use common::{Sandbox, s};
use serde_json::Value;
use std::fs;

/// Initialise a case from the synthetic image; returns (sandbox-relative case dir, image, catalog).
fn started(sandbox: &Sandbox) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let (image, catalog) = sandbox.synthetic();
    let case = sandbox.path("case");
    let run = sandbox.run([
        "case",
        "init",
        s(&image),
        "-o",
        s(&case),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--json",
    ]);
    assert_eq!(run.code, 0, "(case init): expected exit 0 | {}", run.stdout);
    (case, image, catalog)
}

fn status(
    sandbox: &Sandbox,
    case: &std::path::Path,
    image: &std::path::Path,
    catalog: &std::path::Path,
) -> common::Run {
    sandbox.run([
        "case",
        "status",
        s(case),
        "--input",
        s(image),
        "--catalog",
        s(catalog),
        "--allow-unsigned-local",
        "--json",
    ])
}

#[test]
fn init_writes_the_case_scan_and_drafts() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    for file in [
        "case.json",
        "artifacts/001-scan.json",
        "drafts/board.json",
        "drafts/firmware.json",
    ] {
        assert!(
            case.join(file).is_file(),
            "(case): expected {file} | missing"
        );
    }
    let document: Value =
        serde_json::from_slice(&fs::read(case.join("case.json")).unwrap()).unwrap();
    assert_eq!(document["schema"], "bme.case/1");
    for (file, schema) in [
        ("case.json", "case"),
        ("drafts/firmware.json", "firmware-draft"),
        ("drafts/board.json", "board"),
    ] {
        let doc: Value = serde_json::from_slice(&fs::read(case.join(file)).unwrap()).unwrap();
        let validator =
            jsonschema::validator_for(&biosmod_core::schema::generate(schema).unwrap()).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&doc)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "({file}): expected {schema} schema | errors: {errors:?}"
        );
    }
}

#[test]
fn init_refuses_an_existing_directory() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let again = sandbox.run([
        "case",
        "init",
        s(&image),
        "-o",
        s(&case),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--json",
    ]);
    assert_eq!(
        again.code, 1,
        "(case init again): expected exit 1 | {}",
        again.stdout
    );
    assert_eq!(again.error_code(), "OUTPUT_EXISTS");
}

#[test]
fn status_is_clean_then_reports_drift_after_a_byte_flip() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let clean = status(&sandbox, &case, &image, &catalog);
    assert_eq!(
        clean.code, 0,
        "(case status): expected clean | {}",
        clean.stdout
    );
    assert_eq!(clean.json()["data"]["clean"], true);

    let scan = case.join("artifacts/001-scan.json");
    let mut bytes = fs::read(&scan).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&scan, bytes).unwrap();

    let drifted = status(&sandbox, &case, &image, &catalog);
    assert_eq!(
        drifted.code, 1,
        "(case status): expected exit 1 | {}",
        drifted.stdout
    );
    assert_eq!(drifted.error_code(), "CASE_DRIFT");
    let details = &drifted.json()["error"]["details"];
    assert_eq!(details["artifacts"][0]["state"], "changed", "{details}");
}

#[test]
fn status_reports_a_missing_input_without_a_mapping() {
    let sandbox = Sandbox::new();
    let (case, _, catalog) = started(&sandbox);
    let elsewhere = sandbox.path("empty");
    fs::create_dir(&elsewhere).unwrap();
    let run = sandbox.run([
        "case",
        "status",
        s(&case),
        "--input",
        s(&elsewhere),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--json",
    ]);
    assert_eq!(
        run.code, 1,
        "(case status): expected exit 1 | {}",
        run.stdout
    );
    assert_eq!(run.error_code(), "CASE_DRIFT");
    assert_eq!(
        run.json()["error"]["details"]["inputs"][0]["state"],
        "missing"
    );
}

#[test]
fn a_moved_case_verifies_through_input_mapping() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let moved = sandbox.path("elsewhere/case");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&case, &moved).unwrap();
    let run = status(&sandbox, &moved, &image, &catalog);
    assert_eq!(
        run.code, 0,
        "(moved case status): expected clean | {}",
        run.stdout
    );
}

#[test]
fn record_stores_the_command_output_and_status_stays_clean() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let run = sandbox.run([
        "case",
        "record",
        s(&case),
        "--",
        "inspect",
        s(&image),
        "--json",
    ]);
    assert_eq!(
        run.code, 0,
        "(case record): expected exit 0 | {} {}",
        run.stdout, run.stderr
    );
    assert!(case.join("artifacts/002-inspect.json").is_file());
    let after = status(&sandbox, &case, &image, &catalog);
    assert_eq!(
        after.code, 0,
        "(case status): expected clean | {}",
        after.stdout
    );
    assert_eq!(
        after.json()["data"]["artifacts"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn record_keeps_nothing_when_the_command_fails() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let before = fs::read(case.join("case.json")).unwrap();
    let missing = sandbox.path("absent.bin");
    let run = sandbox.run([
        "case",
        "record",
        s(&case),
        "--",
        "inspect",
        s(&missing),
        "--json",
    ]);
    assert_ne!(
        run.code, 0,
        "(case record): expected failure | {}",
        run.stdout
    );
    assert_eq!(fs::read(case.join("case.json")).unwrap(), before);
    assert!(!case.join("artifacts/002-inspect.json").exists());
}

#[test]
fn export_is_accepted_by_catalog_validate_and_index() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let _ = (image, catalog);
    let out = sandbox.path("submission");
    let export = sandbox.run(["case", "export", s(&case), "-o", s(&out), "--json"]);
    assert_eq!(
        export.code, 0,
        "(case export): expected exit 0 | {}",
        export.stdout
    );
    let validate = sandbox.run(["catalog", "validate", s(&out), "--json"]);
    assert_eq!(
        validate.code, 0,
        "(catalog validate): expected exit 0 | {}",
        validate.stdout
    );
    let index = sandbox.run(["catalog", "index", s(&out), "--check", "--json"]);
    assert_eq!(
        index.code, 0,
        "(catalog index --check): expected exit 0 | {}",
        index.stdout
    );
    let again = sandbox.run(["case", "export", s(&case), "-o", s(&out), "--json"]);
    assert_eq!(again.error_code(), "OUTPUT_EXISTS");
}

#[test]
fn export_refuses_a_changed_artifact() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let scan = case.join("artifacts/001-scan.json");
    let mut bytes = fs::read(&scan).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&scan, bytes).unwrap();
    let out = sandbox.path("submission");
    let run = sandbox.run(["case", "export", s(&case), "-o", s(&out), "--json"]);
    assert_eq!(
        run.code, 1,
        "(case export): expected exit 1 | {}",
        run.stdout
    );
    assert_eq!(run.error_code(), "CASE_DRIFT");
    assert!(!out.exists());
}
