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
    // Off Linux the command refuses before opening anything.
    let expected: &[&str] = if cfg!(target_os = "linux") {
        &["HOST_REFUSED", "TARGET_NOT_FOUND"]
    } else {
        &["PLATFORM_UNSUPPORTED"]
    };
    assert!(
        expected.contains(&code.as_str()),
        "(error code): expected {} | received {code}",
        expected.join(" | ")
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

// Every pm-test run below refuses before the host is touched. A valid stage with a new
// output directory would suspend the machine running the tests, so none exists here.

#[test]
fn pm_test_requires_the_suspend_confirmation() {
    let sandbox = Sandbox::new();
    let output = sandbox.path("pm");
    let run = sandbox.run([
        "diag",
        "suspend",
        "pm-test",
        "--stage",
        "freezer",
        "-o",
        output.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!((run.code, run.error_code().as_str()), (2, "USAGE"));
    assert!(!output.exists());
}

#[test]
fn pm_test_refuses_an_existing_output_before_the_stage_is_looked_at() {
    let sandbox = Sandbox::new();
    let existing = sandbox.path("pm");
    std::fs::create_dir(&existing).unwrap();
    let run = sandbox.run([
        "diag",
        "suspend",
        "pm-test",
        "--stage",
        "freezer",
        "-o",
        existing.to_str().unwrap(),
        "--i-understand-this-suspends",
        "--json",
    ]);
    assert_eq!(run.error_code(), "OUTPUT_EXISTS", "{}", run.stdout);
    assert_eq!(run.json()["command"], "diag suspend pm-test");
}

#[test]
fn pm_test_refuses_none_as_a_real_sleep_and_rejects_unknown_stages() {
    let sandbox = Sandbox::new();
    let output = sandbox.path("pm");
    for (stage, code) in [("none", "HOST_REFUSED"), ("warp", "USAGE")] {
        let run = sandbox.run([
            "diag",
            "suspend",
            "pm-test",
            "--stage",
            stage,
            "-o",
            output.to_str().unwrap(),
            "--i-understand-this-suspends",
            "--json",
        ]);
        assert_eq!(run.error_code(), code, "{stage}: {}", run.stdout);
        assert!(!output.exists());
    }
}

#[test]
fn capabilities_list_pm_test_with_its_sysfs_writes() {
    let capabilities = Sandbox::new().run(["capabilities", "--json"]).json();
    let commands = capabilities["data"]["commands"].as_array().unwrap();
    let entry = commands
        .iter()
        .find(|c| c["name"] == "diag suspend pm-test")
        .unwrap_or_else(|| {
            panic!("(capabilities): expected diag suspend pm-test | received {commands:?}")
        });
    assert!(
        entry["writes"][0]
            .as_str()
            .unwrap()
            .contains("/sys/power/pm_test")
    );
}

#[test]
fn smbios_refuses_an_existing_output_before_reading_the_table() {
    let sandbox = Sandbox::new();
    let existing = sandbox.path("smbios");
    std::fs::create_dir(&existing).unwrap();
    let run = sandbox.run(["diag", "smbios", "-o", existing.to_str().unwrap(), "--json"]);
    assert_eq!(run.error_code(), "OUTPUT_EXISTS", "{}", run.stdout);
    assert_eq!(run.json()["command"], "diag smbios");
    assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0);
}

#[test]
fn capabilities_list_smbios_as_needing_no_privilege_to_write() {
    let capabilities = Sandbox::new().run(["capabilities", "--json"]).json();
    let commands = capabilities["data"]["commands"].as_array().unwrap();
    let entry = commands
        .iter()
        .find(|c| c["name"] == "diag smbios")
        .unwrap_or_else(|| panic!("(capabilities): expected diag smbios | received {commands:?}"));
    assert_eq!(
        entry["writes"],
        serde_json::json!(["capture directory (optional)"])
    );
}
