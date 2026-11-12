//! `bme diag` host commands through the real binary.
//!
//! Only paths that refuse before any host access run here: this binary would read
//! the real machine otherwise. The capture itself is tested against fakes in
//! `commands/host.rs`.

mod common;

use common::Sandbox;

#[test]
fn acpi_capture_refuses_an_existing_output_before_touching_the_host() {
    let sandbox = Sandbox::new();
    let existing = sandbox.path("capture");
    std::fs::create_dir(&existing).unwrap();
    let run = sandbox.run([
        "diag",
        "acpi",
        "capture",
        "-o",
        existing.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(run.code, 1, "{}", run.stdout);
    assert_eq!(run.error_code(), "OUTPUT_EXISTS");
    assert_eq!(run.json()["command"], "diag acpi capture");
    assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0);
}

#[test]
fn acpi_capture_requires_an_output_directory() {
    let run = Sandbox::new().run(["diag", "acpi", "capture", "--json"]);
    assert_eq!((run.code, run.error_code().as_str()), (2, "USAGE"));
}

#[test]
fn capabilities_list_the_host_diagnostics_as_read_only_captures() {
    let capabilities = Sandbox::new().run(["capabilities", "--json"]).json();
    let commands = capabilities["data"]["commands"].as_array().unwrap();
    let entry = commands
        .iter()
        .find(|c| c["name"] == "diag acpi capture")
        .unwrap_or_else(|| {
            panic!("(capabilities): expected diag acpi capture | received {commands:?}")
        });
    assert_eq!(entry["writes"], serde_json::json!(["capture directory"]));
}
