//! `diag` commands that read the running machine through `biosmod-host`.
//!
//! These run before per-user configuration loads: they need root, and under
//! `sudo` or `pkexec` the home directory is root's. Each command refuses on a
//! platform without the surface it needs and checks its output path before it
//! touches the host, so a refusal never costs a hardware read.

use crate::AcpiCommand;
use crate::output::{Reply, display_path};
use crate::publish::{check_outputs, publish_directory};
use biosmod_core::Result;
use biosmod_host::bundle::{Bundle, EVIDENCE_FILE, MANIFEST_FILE};
use biosmod_host::{HostSurfaces, acpi};
use serde_json::json;
use std::path::Path;

pub fn run_acpi(command: AcpiCommand) -> Result<Reply> {
    match command {
        AcpiCommand::Capture { output } => acpi_capture(&output),
    }
}

#[cfg(target_os = "linux")]
fn acpi_capture(output: &Path) -> Result<Reply> {
    use biosmod_host::kmsg::DevKmsg;
    use biosmod_host::{ProcessPrivilege, RootedFiles, SystemClock};
    check_outputs(&[output], &[])?;
    capture_acpi_to(
        &HostSurfaces {
            files: &RootedFiles::system(),
            kernel_log: &DevKmsg::system(),
            privilege: &ProcessPrivilege,
            clock: &SystemClock,
        },
        output,
    )
}

#[cfg(not(target_os = "linux"))]
fn acpi_capture(output: &Path) -> Result<Reply> {
    check_outputs(&[output], &[])?;
    Err(unsupported("diag acpi capture"))
}

/// The refusal for platforms without sysfs and `/dev/port`.
#[cfg(not(target_os = "linux"))]
fn unsupported(command: &str) -> biosmod_core::Error {
    biosmod_core::Error::new(
        biosmod_core::Code::PlatformUnsupported,
        format!("{command}: only Linux is supported (it reads sysfs, procfs and /dev/kmsg)"),
    )
}

/// Capture through `surfaces` and publish the bundle as the new directory `output`.
///
/// Example: with fake surfaces, `capture_acpi_to(&surfaces, Path::new("capture"))`
/// writes `capture/acpi/tables/DSDT`, `capture/manifest.json` and `capture/evidence.json`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
pub fn capture_acpi_to(surfaces: &HostSurfaces, output: &Path) -> Result<Reply> {
    let bundle = acpi::capture(surfaces)?;
    publish_bundle(output, &bundle)?;
    let tables: Vec<&str> = bundle
        .files
        .iter()
        .filter_map(|file| file.path.strip_prefix("acpi/tables/"))
        .collect();
    let manifest_sha256 = biosmod_core::util::sha256_hex(
        bundle
            .get(MANIFEST_FILE)
            .expect("a sealed bundle has a manifest"),
    );
    let text = format!(
        "Captured {} ACPI table files and {} files in total to {}\nmanifest.json SHA-256 {manifest_sha256}\nEvidence record: {}\n",
        tables.len(),
        bundle.files.len(),
        output.display(),
        output.join(EVIDENCE_FILE).display()
    );
    Ok(Reply::new(
        json!({
            "directory": display_path(output),
            "files": bundle.files.len(),
            "tables": tables,
            "manifest_sha256": manifest_sha256,
            "evidence": display_path(&output.join(EVIDENCE_FILE)),
        }),
        text,
    ))
}

/// Publish every bundle file; `evidence.json` is last, so it marks a complete capture.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
fn publish_bundle(output: &Path, bundle: &Bundle) -> Result<()> {
    let files: Vec<(&str, &[u8])> = bundle
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.bytes.as_slice()))
        .collect();
    debug_assert_eq!(files.last().map(|f| f.0), Some(EVIDENCE_FILE));
    publish_directory(output, &files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use biosmod_core::Code;
    use biosmod_host::testkit::{FakeKernelLog, FakePrivilege, FakeSysfs, FixedClock};

    fn sysfs() -> FakeSysfs {
        FakeSysfs::mr9a()
            .file("sys/firmware/acpi/tables/DSDT", b"DSDT-bytes")
            .file("sys/firmware/acpi/tables/dynamic/SSDT3", b"SSDT3")
            .file("sys/power/state", "freeze mem disk\n")
    }

    fn capture(sysfs: &FakeSysfs, privilege: &FakePrivilege, output: &Path) -> Result<Reply> {
        let files = sysfs.files();
        let log = FakeKernelLog::new().message(1, "PM: suspend entry (deep)");
        capture_acpi_to(
            &HostSurfaces {
                files: &files,
                kernel_log: &log,
                privilege,
                clock: &FixedClock,
            },
            output,
        )
    }

    #[test]
    fn publishes_a_new_directory_with_tables_manifest_and_evidence() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("capture");
        let reply = capture(&sysfs(), &FakePrivilege::root(), &target).unwrap();
        assert_eq!(
            std::fs::read(target.join("acpi/tables/dynamic/SSDT3")).unwrap(),
            b"SSDT3"
        );
        let manifest = std::fs::read(target.join(MANIFEST_FILE)).unwrap();
        assert_eq!(
            reply.data["manifest_sha256"],
            biosmod_core::util::sha256_hex(&manifest)
        );
        assert_eq!(reply.data["tables"], json!(["DSDT", "dynamic/SSDT3"]));
        // The evidence record parses as a bme.evidence/1 document.
        let evidence = std::fs::read(target.join(EVIDENCE_FILE)).unwrap();
        let parsed: biosmod_core::catalog::Evidence =
            biosmod_core::json::parse_strict(&evidence, "evidence.json").unwrap();
        assert_eq!(parsed.host.unwrap().boot_id, FakeSysfs::BOOT_ID);
    }

    #[test]
    fn an_existing_directory_is_never_overwritten() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("capture");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), "mine").unwrap();
        let error = capture(&sysfs(), &FakePrivilege::root(), &target).unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"mine");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    }

    #[test]
    fn a_refused_capture_leaves_no_directory_behind() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("capture");
        let error = capture(&sysfs(), &FakePrivilege::user(1000), &target).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(!target.exists());
    }
}
