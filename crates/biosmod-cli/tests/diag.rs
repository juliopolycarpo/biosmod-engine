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

#[test]
fn superio_read_against_a_plain_file_never_reaches_a_chip() {
    // `--device` points at a temporary file, so even a root run cannot touch a port:
    // non-root is refused, root finds no chip answering in the file.
    let sandbox = Sandbox::new();
    let device = sandbox.path("fake-port");
    std::fs::write(&device, vec![0u8; 0x1000]).unwrap();
    let run = sandbox.run([
        "diag",
        "superio",
        "read",
        "--device",
        device.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(run.code, 1, "{}", run.stdout);
    let code = run.error_code();
    assert!(
        code == "HOST_REFUSED" || code == "TARGET_NOT_FOUND",
        "(error code): expected HOST_REFUSED | TARGET_NOT_FOUND | received {code}"
    );
    assert_eq!(run.json()["command"], "diag superio read");
}

#[test]
fn superio_read_refuses_an_existing_output_before_the_device_opens() {
    let sandbox = Sandbox::new();
    let existing = sandbox.path("fan");
    std::fs::create_dir(&existing).unwrap();
    let run = sandbox.run([
        "diag",
        "superio",
        "read",
        "--device",
        sandbox.path("no-such-device").to_str().unwrap(),
        "-o",
        existing.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(run.error_code(), "OUTPUT_EXISTS", "{}", run.stdout);
}
