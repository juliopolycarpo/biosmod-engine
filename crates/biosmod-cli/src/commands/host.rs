//! `diag` commands that read the running machine through `biosmod-host`.
//!
//! These run before per-user configuration loads: they need root, and under
//! `sudo` or `pkexec` the home directory is root's. Each command refuses on a
//! platform without the surface it needs and checks its output path before it
//! touches the host, so a refusal never costs a hardware read.

use crate::output::{Reply, display_path};
use crate::publish::{check_outputs, publish_directory};
use crate::{AcpiCommand, SuperioCommand, SuspendCommand};
use biosmod_core::{Code, Error, Result};
use biosmod_host::bundle::{Bundle, EVIDENCE_FILE, MANIFEST_FILE};
use biosmod_host::files::HostWrite;
use biosmod_host::ports::PortIo;
use biosmod_host::suspend::{self, Stage, Status};
use biosmod_host::{HostSurfaces, acpi, superio};
use serde_json::json;
use std::path::Path;

pub fn run_acpi(command: AcpiCommand) -> Result<Reply> {
    match command {
        AcpiCommand::Capture { output } => acpi_capture(&output),
    }
}

/// Run `body` against the real machine's surfaces.
#[cfg(target_os = "linux")]
fn on_this_machine<T>(body: impl FnOnce(&HostSurfaces) -> T) -> T {
    use biosmod_host::kmsg::DevKmsg;
    use biosmod_host::{ProcessPrivilege, RootedFiles, SystemClock};
    body(&HostSurfaces {
        files: &RootedFiles::system(),
        kernel_log: &DevKmsg::system(),
        privilege: &ProcessPrivilege,
        clock: &SystemClock,
    })
}

#[cfg(target_os = "linux")]
fn acpi_capture(output: &Path) -> Result<Reply> {
    check_outputs(&[output], &[])?;
    on_this_machine(|surfaces| capture_acpi_to(surfaces, output))
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

pub fn run_superio(command: SuperioCommand) -> Result<Reply> {
    match command {
        SuperioCommand::Read {
            device,
            output,
            unbound_only,
        } => superio_read(&device, output.as_deref(), unbound_only),
    }
}

#[cfg(target_os = "linux")]
fn superio_read(device: &Path, output: Option<&Path>, unbound_only: bool) -> Result<Reply> {
    use biosmod_host::ports::DevPort;
    if let Some(output) = output {
        check_outputs(&[output], &[])?;
    }
    // Before the device opens: a non-root user gets the refusal, not an open error.
    on_this_machine(|surfaces| {
        biosmod_host::privilege::require_root(surfaces.privilege, "diag superio read")
    })?;
    let mut ports = DevPort::open(device, "sudo bme diag superio read")?;
    on_this_machine(|surfaces| read_superio_to(surfaces, &mut ports, output, unbound_only))
}

#[cfg(not(target_os = "linux"))]
fn superio_read(_device: &Path, output: Option<&Path>, _unbound_only: bool) -> Result<Reply> {
    if let Some(output) = output {
        check_outputs(&[output], &[])?;
    }
    Err(unsupported("diag superio read"))
}

/// Read the chip through `ports` and optionally publish the bundle at `output`.
///
/// Example: with `FakeSuperIoPorts` and fake surfaces, the reply's `reading.chip_id` is `"0xc562"`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
pub fn read_superio_to(
    surfaces: &HostSurfaces,
    ports: &mut dyn PortIo,
    output: Option<&Path>,
    unbound_only: bool,
) -> Result<Reply> {
    let capture = superio::capture(surfaces, ports, superio::builtin(), unbound_only)?;
    if let Some(output) = output {
        publish_bundle(output, &capture.bundle)?;
    }
    let evidence: serde_json::Value =
        serde_json::from_slice(capture.bundle.get(EVIDENCE_FILE).expect("sealed bundle"))
            .expect("the evidence record is JSON");
    let mut text = render_superio(&capture.reading);
    if let Some(output) = output {
        text += &format!("Saved to {}\n", output.display());
    }
    Ok(Reply::new(
        json!({
            "reading": capture.reading,
            "evidence": evidence,
            "directory": output.map(display_path),
        }),
        text,
    ))
}

pub fn run_suspend(command: SuspendCommand) -> Result<Reply> {
    match command {
        SuspendCommand::PmTest {
            stage,
            output,
            i_understand_this_suspends: _,
        } => suspend_pm_test(&stage, &output),
    }
}

#[cfg(target_os = "linux")]
fn suspend_pm_test(stage: &str, output: &Path) -> Result<Reply> {
    use biosmod_host::RootedFiles;
    check_outputs(&[output], &[])?;
    // Parsed before the host is touched: `none` and typos never reach /sys/power.
    let stage = Stage::parse(stage)?;
    on_this_machine(|surfaces| pm_test_to(surfaces, &RootedFiles::system(), stage, output))
}

#[cfg(not(target_os = "linux"))]
fn suspend_pm_test(stage: &str, output: &Path) -> Result<Reply> {
    check_outputs(&[output], &[])?;
    Stage::parse(stage)?;
    Err(unsupported("diag suspend pm-test"))
}

/// Run one stage through `surfaces` and `power`, and publish the bundle at `output`.
///
/// The bundle is saved whatever the verdict. A pass is the reply; a fail or an error
/// is a `HOST_FAILED` error whose details carry the report, so the evidence of a failed
/// test is never lost.
///
/// Example: with `FakePowerSysfs`, `pm_test_to(&surfaces, &fake, Stage::Freezer, dir)`
/// replies with `report.status == "pass"`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
pub fn pm_test_to(
    surfaces: &HostSurfaces,
    power: &dyn HostWrite,
    stage: Stage,
    output: &Path,
) -> Result<Reply> {
    let run = suspend::pm_test(surfaces, power, stage)?;
    publish_bundle(output, &run.bundle)?;
    let report = &run.report;
    let change = |name: &str| report.delta.get(name).copied().unwrap_or(0);
    let summary = format!(
        "Stage {} ended {}: suspend success {:+}, fail {:+}; pm_test is {}",
        report.stage.name(),
        report.status.name(),
        change("success"),
        change("fail"),
        suspend::selected(&report.pm_test_after).unwrap_or("unknown"),
    );
    let data = json!({
        "report": report,
        "directory": display_path(output),
        "evidence": display_path(&output.join(EVIDENCE_FILE)),
    });
    if report.status != Status::Pass {
        return Err(Error::new(
            Code::HostFailed,
            format!(
                "diag suspend pm-test: {summary}{}; evidence saved to {}",
                report
                    .error
                    .as_ref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default(),
                output.display()
            ),
        )
        .with_details(data));
    }
    Ok(Reply::new(
        data,
        format!("{summary}\nSaved to {}\n", output.display()),
    ))
}

/// Human summary of a reading, whichever way it was taken.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
fn render_superio(reading: &superio::Reading) -> String {
    match reading {
        superio::Reading::RawPorts(reading) => render_raw_superio(reading),
        superio::Reading::Hwmon(reading) => render_hwmon(reading),
    }
}

/// What a bound driver publishes: the refusal reason first, then the attributes.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
fn render_hwmon(reading: &biosmod_host::hwmon::HwmonReading) -> String {
    let mut text = format!("{}\n", reading.raw_access_refused);
    text += &format!(
        "hwmon {} ({}): {} attributes\n",
        reading.driver.hwmon.as_deref().unwrap_or("none"),
        reading.name.as_deref().unwrap_or("unnamed"),
        reading.attributes.len()
    );
    for (name, value) in &reading.attributes {
        text += &format!("  {name} = {value}\n");
    }
    for name in &reading.unreadable {
        text += &format!("  {name}: unreadable\n");
    }
    text += &format!("Not available through sysfs: {}\n", reading.not_available);
    text
}

/// Raw reading: chip, logical devices, then one line per bank.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
fn render_raw_superio(reading: &superio::SuperIoReading) -> String {
    let mut text = format!(
        "{} {} (ID {}) on configuration port {}\n",
        reading.vendor, reading.chip, reading.chip_id, reading.config_port
    );
    for device in &reading.logical_devices {
        text += &format!(
            "  LDN {:#04x} {:<36} active {}{}\n",
            device.ldn,
            device.name,
            device.active,
            device
                .base
                .as_ref()
                .map(|base| format!(" base {base}"))
                .unwrap_or_default()
        );
    }
    if let (Some(active), Some(base)) = (reading.hwm_active, &reading.hwm_base) {
        text += &format!("Hardware monitor active {active} at {base}\n");
    }
    for (bank, registers) in &reading.registers {
        let values: Vec<String> = registers
            .iter()
            .map(|(register, value)| format!("{register}={value:02x}"))
            .collect();
        text += &format!("  bank {bank}: {}\n", values.join(" "));
    }
    text
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
    use biosmod_host::testkit::{
        FakeKernelLog, FakePowerSysfs, FakePrivilege, FakeSuperIoPorts, FakeSysfs, FixedClock,
    };

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

    fn read_chip(
        privilege: &FakePrivilege,
        ports: &mut FakeSuperIoPorts,
        output: Option<&Path>,
    ) -> Result<Reply> {
        read_chip_on(FakeSysfs::mr9a(), privilege, ports, output, false)
    }

    fn read_chip_on(
        sysfs: FakeSysfs,
        privilege: &FakePrivilege,
        ports: &mut FakeSuperIoPorts,
        output: Option<&Path>,
        unbound_only: bool,
    ) -> Result<Reply> {
        let files = sysfs.files();
        let log = FakeKernelLog::new();
        read_superio_to(
            &HostSurfaces {
                files: &files,
                kernel_log: &log,
                privilege,
                clock: &FixedClock,
            },
            ports,
            output,
            unbound_only,
        )
    }

    fn driver_bound() -> FakeSysfs {
        FakeSysfs::mr9a()
            .file("sys/class/hwmon/hwmon3/name", "nct6779\n")
            .file("sys/class/hwmon/hwmon3/pwm1", "128\n")
            .file("sys/class/hwmon/hwmon3/fan1_input", "1204\n")
    }

    #[test]
    fn a_bound_driver_is_read_through_sysfs_and_no_port_moves() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        let reply = read_chip_on(
            driver_bound(),
            &FakePrivilege::root(),
            &mut ports,
            None,
            false,
        )
        .unwrap();
        assert_eq!(reply.data["reading"]["source"], "hwmon-sysfs");
        assert_eq!(reply.data["reading"]["attributes"]["fan1_input"], "1204");
        assert!(reply.text.contains("fan1_input = 1204"), "{}", reply.text);
        assert!(
            reply.text.contains("sudo modprobe -r nct6775"),
            "{}",
            reply.text
        );
        assert!(
            reply.text.contains("Not available through sysfs"),
            "{}",
            reply.text
        );
        assert!(
            ports.trace.is_empty(),
            "(port trace): expected empty | received {:?}",
            ports.trace
        );
    }

    #[test]
    fn unbound_only_turns_a_bound_driver_into_a_refusal() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        let error = read_chip_on(
            driver_bound(),
            &FakePrivilege::root(),
            &mut ports,
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(error.message.contains("received nct6775"), "{error}");
        assert!(ports.trace.is_empty());
    }

    fn pm_test_run(
        fake: &FakePowerSysfs,
        privilege: &FakePrivilege,
        stage: Stage,
        output: &Path,
    ) -> Result<Reply> {
        pm_test_to(
            &HostSurfaces {
                files: fake,
                kernel_log: fake,
                privilege,
                clock: &FixedClock,
            },
            fake,
            stage,
            output,
        )
    }

    #[test]
    fn a_passing_stage_publishes_the_bundle_and_replies_with_the_report() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("freezer");
        let fake = FakePowerSysfs::mr9a_s2idle();
        let reply = pm_test_run(&fake, &FakePrivilege::root(), Stage::Freezer, &target).unwrap();
        assert_eq!(reply.data["report"]["status"], "pass");
        assert_eq!(reply.data["report"]["delta"]["success"], 1);
        assert!(
            reply.text.contains("Stage freezer ended pass"),
            "{}",
            reply.text
        );
        for file in [
            "pm-test.json",
            "kernel/delta.log",
            MANIFEST_FILE,
            EVIDENCE_FILE,
        ] {
            assert!(target.join(file).is_file(), "{file}");
        }
        assert_eq!(fake.pm_test(), "none");
    }

    #[test]
    fn a_failed_restore_publishes_the_bundle_then_reports_host_failed_with_the_repair() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("stuck");
        let fake = FakePowerSysfs::mr9a_deep().failing_pm_test_restore();
        let error =
            pm_test_run(&fake, &FakePrivilege::root(), Stage::Freezer, &target).unwrap_err();
        assert_eq!(error.code, Code::HostFailed, "{error}");
        assert!(
            error.message.contains("echo none > /sys/power/pm_test"),
            "(message): expected the manual repair | received {error}"
        );
        assert!(target.join("pm-test.json").is_file());
        assert!(target.join(EVIDENCE_FILE).is_file());
        assert_eq!(
            error.details.as_ref().unwrap()["report"]["restored_pm_test"],
            false
        );
    }

    #[test]
    fn a_failed_stage_still_publishes_its_evidence_and_reports_host_failed() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("devices");
        let fake = FakePowerSysfs::mr9a_deep().failing_suspend();
        let error =
            pm_test_run(&fake, &FakePrivilege::root(), Stage::Devices, &target).unwrap_err();
        assert_eq!(error.code, Code::HostFailed, "{error}");
        assert!(
            error.message.contains("Stage devices ended fail"),
            "{error}"
        );
        assert!(error.message.contains("evidence saved to"), "{error}");
        let details = error.details.as_ref().unwrap();
        assert_eq!(details["report"]["delta"]["fail"], 1);
        assert!(target.join(EVIDENCE_FILE).is_file());
        assert_eq!(fake.pm_test(), "none");
    }

    #[test]
    fn a_refused_stage_leaves_no_directory_behind() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("core");
        let fake = FakePowerSysfs::mr9a_s2idle();
        let error = pm_test_run(&fake, &FakePrivilege::root(), Stage::Core, &target).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(!target.exists());
        assert!(fake.writes().is_empty());
    }

    #[test]
    fn superio_reply_carries_the_reading_and_the_receipt() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        let reply = read_chip(&FakePrivilege::root(), &mut ports, None).unwrap();
        assert_eq!(reply.data["reading"]["source"], "raw-ports");
        assert_eq!(reply.data["reading"]["chip_id"], "0xc562");
        assert_eq!(reply.data["reading"]["registers"]["2"]["02"], 69);
        assert_eq!(
            reply.data["evidence"]["host"]["command"],
            "diag superio read"
        );
        assert_eq!(reply.data["directory"], serde_json::Value::Null);
        assert!(
            reply.text.contains("NCT5532D/NCT6779D (ID 0xc562)"),
            "{}",
            reply.text
        );
        assert!(
            reply.text.contains("bank 2: 00=10 01=32 02=45"),
            "{}",
            reply.text
        );
        assert!(ports.violations.is_empty(), "{:?}", ports.violations);
    }

    #[test]
    fn superio_output_directory_is_new_only_and_not_created_for_a_refusal() {
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("fan");
        let refused = read_chip(
            &FakePrivilege::user(1000),
            &mut FakeSuperIoPorts::mr9a_nct5532d(),
            Some(&target),
        )
        .unwrap_err();
        assert_eq!(refused.code, Code::HostRefused, "{refused}");
        assert!(!target.exists());
        read_chip(
            &FakePrivilege::root(),
            &mut FakeSuperIoPorts::mr9a_nct5532d(),
            Some(&target),
        )
        .unwrap();
        assert!(target.join("superio.json").is_file() && target.join(EVIDENCE_FILE).is_file());
        let again = read_chip(
            &FakePrivilege::root(),
            &mut FakeSuperIoPorts::mr9a_nct5532d(),
            Some(&target),
        )
        .unwrap_err();
        assert_eq!(again.code, Code::OutputExists, "{again}");
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
