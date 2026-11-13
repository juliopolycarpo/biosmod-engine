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

/// Record `argv` in `case`, expect success and return the stored output document.
fn recorded_document(
    sandbox: &Sandbox,
    case: &std::path::Path,
    artifact: &str,
    argv: &[&str],
) -> Value {
    let mut args = vec!["case", "record", s(case), "--"];
    args.extend_from_slice(argv);
    args.push("--json");
    let run = sandbox.run(args);
    assert_eq!(
        run.code, 0,
        "(case record -- {argv:?}): expected exit 0 | {} {}",
        run.stdout, run.stderr
    );
    let stored = fs::read_to_string(case.join("artifacts").join(artifact)).unwrap_or_else(|e| {
        panic!("(case record -- {argv:?}): expected artifacts/{artifact} | {e}")
    });
    serde_json::from_str(&stored).unwrap()
}

/// Fail when any text file of the case names a directory of this machine.
fn assert_case_names_no_local_paths(sandbox: &Sandbox, case: &std::path::Path) {
    let local = sandbox.dir.path().to_str().unwrap().to_string();
    let mut pending = vec![case.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(text) = fs::read_to_string(&path) {
                assert!(
                    !text.contains(&local),
                    "({}): expected no path below {local} | received {text}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn record_keeps_the_ifr_decode_of_a_setup_module() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let module = sandbox.path("setup.bin");
    fs::write(&module, biosmod_core::synthetic::ifr_setup_image()).unwrap();
    let doc = recorded_document(
        &sandbox,
        &case,
        "002-ifr.json",
        &["ifr", s(&module), "--language", "en-US"],
    );
    assert_eq!(doc["command"], "ifr");
    assert_eq!(doc["data"]["source"], "image");
    let text = doc.to_string();
    assert!(
        text.contains("ACPI Sleep State"),
        "(recorded ifr): expected the Setup question | received {text}"
    );
    assert_case_names_no_local_paths(&sandbox, &case);
}

#[test]
fn record_keeps_the_nvram_listing_and_the_input_digest() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let image = sandbox.path("nvram.bin");
    fs::write(
        &image,
        biosmod_core::synthetic::nvram_image(&[biosmod_core::synthetic::nvar_sample_store()]),
    )
    .unwrap();
    let doc = recorded_document(&sandbox, &case, "002-nvram.json", &["nvram", s(&image)]);
    assert_eq!(doc["command"], "nvram");
    let variables = doc["data"]["variables"].as_array().unwrap();
    assert!(
        variables.iter().any(|v| v["name"] == "Setup"),
        "(recorded nvram): expected the Setup variable | received {variables:?}"
    );
    let case_document: Value =
        serde_json::from_slice(&fs::read(case.join("case.json")).unwrap()).unwrap();
    let artifact = &case_document["artifacts"][1];
    assert_eq!(
        artifact["command"],
        serde_json::json!(["nvram", "nvram.bin", "--json"])
    );
    assert_eq!(artifact["inputs"][0]["name"], "nvram.bin");
    assert_case_names_no_local_paths(&sandbox, &case);
}

#[test]
fn record_keeps_the_stored_acpi_inventory() {
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let image = sandbox.path("acpi.bin");
    fs::write(
        &image,
        biosmod_core::synthetic::AcpiInventoryFixture::new().image,
    )
    .unwrap();
    let doc = recorded_document(
        &sandbox,
        &case,
        "002-inspect.json",
        &["inspect", s(&image), "--acpi"],
    );
    let tables = doc["data"]["acpi"]["tables"].as_array().unwrap();
    assert_eq!(
        tables.len(),
        2,
        "(recorded inspect --acpi): expected the PE and raw tables | received {tables:?}"
    );
    assert_case_names_no_local_paths(&sandbox, &case);
}

#[test]
fn record_keeps_a_comparison_of_two_images_with_both_inputs() {
    use biosmod_core::synthetic::{PEIM_GUID, ffs, image_of_files, relocatable_pe, section};
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let write = |name: &str, base: u32| {
        let path = sandbox.path(name);
        let files = [ffs(
            PEIM_GUID,
            0x06,
            &section(0x10, &relocatable_pe(base, b"same")),
            0,
        )];
        fs::write(&path, image_of_files(&files)).unwrap();
        path
    };
    let (a, b) = (write("a.bin", 0x1000_0000), write("b.bin", 0x2000_0000));
    let doc = recorded_document(
        &sandbox,
        &case,
        "002-compare.json",
        &["compare", s(&a), s(&b)],
    );
    assert_eq!(doc["data"]["summary"]["identical_after_normalization"], 1);
    let case_document: Value =
        serde_json::from_slice(&fs::read(case.join("case.json")).unwrap()).unwrap();
    let artifact = &case_document["artifacts"][1];
    assert_eq!(
        artifact["command"],
        serde_json::json!(["compare", "a.bin", "b.bin", "--json"]),
        "(recorded compare): expected the command with base names"
    );
    let inputs: Vec<&str> = artifact["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(inputs, ["a.bin", "b.bin"], "(recorded compare inputs)");
    assert_case_names_no_local_paths(&sandbox, &case);
}

#[test]
fn record_keeps_an_acpi_comparison_against_a_capture_directory() {
    use biosmod_core::aml::fixture::{method, scope, table};
    let sandbox = Sandbox::new();
    let (case, _, _) = started(&sandbox);
    let dsdt = |body: &[u8]| {
        table(
            "DSDT",
            "BMECASE",
            &scope("\\_SB_", &[method("WORK", 0, body)]),
        )
    };
    let stored = sandbox.path("stored.aml");
    fs::write(&stored, dsdt(&[0xA3])).unwrap();
    let capture = sandbox.path("capture");
    common::write_capture_directory(&capture, &[("DSDT", dsdt(&[0xA3, 0xA3]))]);
    let doc = recorded_document(
        &sandbox,
        &case,
        "002-compare.json",
        &["compare", "--acpi", s(&stored), s(&capture)],
    );
    assert_eq!(doc["data"]["b"]["kind"], "capture");
    assert_eq!(doc["data"]["pairs"][0]["changes"][0]["status"], "changed");
    assert_case_names_no_local_paths(&sandbox, &case);
}

/// A failed diagnostic is evidence too: its failure envelope is kept and the command still fails.
/// `--device` names a plain file, so no port is touched; a non-root run is refused and a root
/// run finds no chip in it, and both end in a failure the case must keep.
#[cfg(target_os = "linux")]
#[test]
fn record_keeps_the_failure_of_a_diagnostic_without_the_device_path() {
    let sandbox = Sandbox::new();
    let (case, image, catalog) = started(&sandbox);
    let device = sandbox.path("fake-port");
    fs::write(&device, vec![0u8; 0x1000]).unwrap();
    let run = sandbox.run([
        "case",
        "record",
        s(&case),
        "--",
        "diag",
        "superio",
        "read",
        "--device",
        s(&device),
        "--json",
    ]);
    assert_ne!(
        run.code, 0,
        "(case record -- diag superio read): expected the diagnostic's failure | {}",
        run.stdout
    );
    let stored = fs::read_to_string(case.join("artifacts/002-diag-superio-read.json"))
        .unwrap_or_else(|e| panic!("(case record -- diag): expected the failure envelope | {e}"));
    let doc: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(doc["ok"], false, "(stored envelope): {stored}");
    assert_eq!(doc["command"], "diag superio read");
    let code = doc["error"]["code"].as_str().unwrap();
    assert!(
        ["HOST_REFUSED", "HOST_FAILED"].contains(&code),
        "(stored diag error): expected HOST_REFUSED or HOST_FAILED | received {code}"
    );
    assert_case_names_no_local_paths(&sandbox, &case);
    let after = status(&sandbox, &case, &image, &catalog);
    assert_eq!(
        after.code, 0,
        "(case status): expected clean after the recorded failure | {}",
        after.stdout
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
