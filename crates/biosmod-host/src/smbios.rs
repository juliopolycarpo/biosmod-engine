//! `diag smbios`: what the firmware's SMBIOS table says about the machine.
//!
//! Root reads the raw structure table (`/sys/firmware/dmi/tables/DMI`) and the
//! decoder in `biosmod-core` turns it into BIOS, system, baseboard and memory
//! device facts. Everyone else gets the model-level fields the kernel publishes in
//! `/sys/class/dmi/id`, and the report says that memory devices are unavailable
//! instead of listing none: an empty list would read as "no DIMMs".
//!
//! The raw table is never saved: it carries serial numbers and the system UUID.

use crate::HostSurfaces;
use crate::bundle::{Bundle, BundleBuilder};
use crate::files::{HostFiles, read_trimmed};
use crate::identity::{DMI_ROOT, HostIdentity};
use crate::receipt::Receipt;
use biosmod_core::smbios::{
    self, BaseboardInformation, BiosInformation, MemoryDevice, SystemInformation,
};
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::ErrorKind;

pub const DMI_TABLE_PATH: &str = "/sys/firmware/dmi/tables/DMI";

/// Where the facts came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Source {
    /// The raw SMBIOS structure table.
    #[serde(rename = "dmi-table")]
    DmiTable,
    /// The model-level fields in `/sys/class/dmi/id`.
    #[serde(rename = "sysfs-class-dmi")]
    SysfsClassDmi,
}

/// The decoded facts, and what could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmbiosReport {
    pub source: Source,
    pub bios: Option<BiosInformation>,
    pub system: Option<SystemInformation>,
    pub baseboard: Option<BaseboardInformation>,
    /// `None` means unavailable (see `unavailable`), never "no memory devices".
    pub memory_devices: Option<Vec<MemoryDevice>>,
    /// Why `memory_devices` is `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
    /// Structures in the table, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structures: Option<usize>,
}

/// A report and the bundle that preserves it.
#[derive(Debug)]
pub struct SmbiosCapture {
    pub report: SmbiosReport,
    pub bundle: Bundle,
}

/// Read the SMBIOS facts: the table when the user may read it, else the sysfs fields.
///
/// A table the user may not read (`PermissionDenied`) or the kernel does not publish
/// (`NotFound`) falls back; any other failure, and a table that does not decode, is an
/// error: guessing from a half-read table would hide a problem.
///
/// Example: as root on the MR9A, `read_report(&files)?.memory_devices.unwrap()[0]
/// .total_width_bits` is `Some(72)`.
pub fn read_report(files: &dyn HostFiles) -> Result<SmbiosReport> {
    match files.read(DMI_TABLE_PATH) {
        Ok(table) => {
            let parsed = smbios::parse(&table).map_err(|e| e.context(DMI_TABLE_PATH))?;
            Ok(SmbiosReport {
                source: Source::DmiTable,
                bios: parsed.bios,
                system: parsed.system,
                baseboard: parsed.baseboard,
                memory_devices: Some(parsed.memory_devices),
                unavailable: None,
                structures: Some(parsed.structures),
            })
        }
        Err(e) if matches!(e.kind(), ErrorKind::PermissionDenied | ErrorKind::NotFound) => {
            let reason = if e.kind() == ErrorKind::PermissionDenied {
                format!(
                    "{DMI_TABLE_PATH}: expected a readable table | received permission denied (the table is root-only; run as root to list memory devices)"
                )
            } else {
                format!(
                    "{DMI_TABLE_PATH}: expected a readable table | received no such file (the kernel does not publish SMBIOS)"
                )
            };
            sysfs_report(files, reason)
        }
        Err(e) => Err(Error::new(Code::Io, format!("{DMI_TABLE_PATH}: {e}"))),
    }
}

/// The identity-only report from `/sys/class/dmi/id`.
fn sysfs_report(files: &dyn HostFiles, unavailable: String) -> Result<SmbiosReport> {
    let field = |name: &str| read_trimmed(files, &format!("{DMI_ROOT}/{name}"));
    let bios = BiosInformation {
        vendor: field("bios_vendor"),
        version: field("bios_version"),
        release_date: field("bios_date"),
        rom_size_kib: None,
    };
    let system = SystemInformation {
        manufacturer: field("sys_vendor"),
        product_name: field("product_name"),
        version: field("product_version"),
        family: field("product_family"),
    };
    let baseboard = BaseboardInformation {
        manufacturer: field("board_vendor"),
        product: field("board_name"),
        version: field("board_version"),
    };
    let any = |values: [&Option<String>; 3]| values.iter().any(|v| v.is_some());
    if !any([&bios.vendor, &bios.version, &bios.release_date])
        && !any([&system.manufacturer, &system.product_name, &system.version])
        && !any([
            &baseboard.manufacturer,
            &baseboard.product,
            &baseboard.version,
        ])
    {
        return Err(Error::new(
            Code::TargetNotFound,
            format!("{DMI_ROOT}: expected DMI identity fields | received none ({unavailable})"),
        ));
    }
    Ok(SmbiosReport {
        source: Source::SysfsClassDmi,
        bios: Some(bios),
        system: Some(system),
        baseboard: Some(baseboard),
        memory_devices: None,
        unavailable: Some(unavailable),
        structures: None,
    })
}

/// One line per memory device for receipts and terminals.
///
/// Example: `describe_device(&device)` is `"DIMM_A1 (BANK 0): 8192 MiB DDR4 DIMM,
/// total width 72 bits, data width 72 bits, 2666 MT/s (configured 2133 MT/s)"`.
pub fn describe_device(device: &MemoryDevice) -> String {
    let bits = |label: &str, value: Option<u16>| {
        value.map_or(format!("{label} unknown"), |b| format!("{label} {b} bits"))
    };
    let slot = device.device_locator.as_deref().unwrap_or("slot");
    let bank = device
        .bank_locator
        .as_deref()
        .map(|b| format!(" ({b})"))
        .unwrap_or_default();
    let size = match device.size_kib {
        Some(0) => return format!("{slot}{bank}: empty"),
        Some(kib) if kib % 1024 == 0 => format!("{} MiB", kib / 1024),
        Some(kib) => format!("{kib} KiB"),
        None => "size unknown".into(),
    };
    let kind = [device.memory_type.as_deref(), device.form_factor.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let speed = match (device.speed_mts, device.configured_speed_mts) {
        (Some(rated), Some(configured)) => format!(", {rated} MT/s (configured {configured} MT/s)"),
        (Some(rated), None) => format!(", {rated} MT/s"),
        (None, Some(configured)) => format!(", configured {configured} MT/s"),
        (None, None) => String::new(),
    };
    format!(
        "{slot}{bank}: {size} {kind}, {}, {}{speed}",
        bits("total width", device.total_width_bits),
        bits("data width", device.data_width_bits),
    )
}

/// Read the facts and seal them with an evidence record. Needs no privilege.
///
/// The bundle holds `smbios.json`, the manifest and the evidence record; never the raw
/// table.
///
/// Example: `capture(&surfaces)?.bundle.get("smbios.json")`.
pub fn capture(host: &HostSurfaces) -> Result<SmbiosCapture> {
    let identity = HostIdentity::read(host.files)?;
    let at = host.clock.now();
    let report = read_report(host.files)?;
    let mut builder = BundleBuilder::new();
    builder.add("smbios.json", biosmod_core::json::pretty(&report))?;
    let mut observations = vec![match report.source {
        Source::DmiTable => format!(
            "Read {} SMBIOS structures from {DMI_TABLE_PATH}.",
            report.structures.unwrap_or(0)
        ),
        Source::SysfsClassDmi => format!("Read the model-level fields from {DMI_ROOT} only."),
    }];
    if let Some(bios) = &report.bios {
        observations.push(format!(
            "BIOS {} {} {}",
            bios.vendor.as_deref().unwrap_or("unknown"),
            bios.version.as_deref().unwrap_or("unknown"),
            bios.release_date.as_deref().unwrap_or("")
        ));
    }
    match (&report.memory_devices, &report.unavailable) {
        (Some(devices), _) => observations.extend(devices.iter().map(describe_device)),
        (None, reason) => observations.push(format!(
            "Memory devices unavailable: {}",
            reason.as_deref().unwrap_or("not reported")
        )),
    }
    let bundle = builder.seal(
        &identity,
        at,
        Receipt {
            command: "diag smbios",
            title: "SMBIOS identity and memory devices".into(),
            observations,
            limits: "SMBIOS is what the firmware chose to describe, not a measurement: slot widths and speeds are the firmware's claims about the modules, and a board can report a width its memory controller does not use. The raw table is not saved because it holds serial numbers and the system UUID.".into(),
            digests: BTreeMap::new(),
        },
    );
    Ok(SmbiosCapture { report, bundle })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeKernelLog, FakePrivilege, FakeSysfs, FixedClock, RootOnlyFiles};
    use biosmod_core::synthetic::{SMBIOS_SECRET, SmbiosSlot, smbios_table};

    fn sysfs_with_table() -> FakeSysfs {
        FakeSysfs::mr9a().file("sys/firmware/dmi/tables/DMI", smbios_table())
    }

    fn capture_from(files: &dyn HostFiles) -> Result<SmbiosCapture> {
        capture(&HostSurfaces {
            files,
            kernel_log: &FakeKernelLog::new(),
            privilege: &FakePrivilege::user(1000),
            clock: &FixedClock,
        })
    }

    #[test]
    fn the_table_gives_identity_and_both_memory_slots() {
        let sysfs = sysfs_with_table();
        let report = read_report(&sysfs.files()).unwrap();
        assert_eq!(report.source, Source::DmiTable);
        assert_eq!(report.structures, Some(7));
        assert_eq!(report.unavailable, None);
        let devices = report.memory_devices.unwrap();
        assert_eq!(devices.len(), 2);
        // MR9A finding R01: 72/72.
        assert_eq!(devices[0].total_width_bits, Some(72));
        assert_eq!(devices[0].data_width_bits, Some(72));
        assert_eq!(
            report.system.unwrap().product_name.as_deref(),
            Some("Synthetic System")
        );
    }

    #[test]
    fn a_non_root_user_gets_identity_and_an_explicit_unavailable_memory_list() {
        let sysfs = sysfs_with_table();
        let files = RootOnlyFiles::new(sysfs.files(), [DMI_TABLE_PATH]);
        let report = read_report(&files).unwrap();
        assert_eq!(report.source, Source::SysfsClassDmi);
        assert_eq!(
            report.memory_devices, None,
            "unavailable must not read as an empty list"
        );
        assert!(
            report
                .unavailable
                .as_deref()
                .unwrap()
                .contains("received permission denied"),
            "{report:?}"
        );
        assert_eq!(
            report.baseboard.unwrap().product.as_deref(),
            Some("E5-MR9A PRO")
        );
        assert_eq!(report.bios.unwrap().version.as_deref(), Some("5.11"));
        assert_eq!(report.structures, None);
        let json = serde_json::to_value(read_report(&files).unwrap()).unwrap();
        assert!(json["memory_devices"].is_null(), "{json}");
        assert!(json["unavailable"].is_string(), "{json}");
    }

    #[test]
    fn a_kernel_without_the_table_falls_back_and_says_so() {
        let sysfs = FakeSysfs::mr9a();
        let report = read_report(&sysfs.files()).unwrap();
        assert_eq!(report.source, Source::SysfsClassDmi);
        assert!(
            report
                .unavailable
                .unwrap()
                .contains("received no such file")
        );
    }

    #[test]
    fn no_table_and_no_identity_is_target_not_found() {
        let sysfs = FakeSysfs::new();
        let error = read_report(&sysfs.files()).unwrap_err();
        assert_eq!(error.code, Code::TargetNotFound, "{error}");
        assert!(
            error
                .message
                .contains("expected DMI identity fields | received none"),
            "{error}"
        );
    }

    #[test]
    fn a_table_that_does_not_decode_is_an_error_naming_the_file() {
        let truncated = smbios_table();
        let sysfs = FakeSysfs::mr9a().file(
            "sys/firmware/dmi/tables/DMI",
            &truncated[..truncated.len() - 1],
        );
        let error = read_report(&sysfs.files()).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
        assert!(error.to_string().contains(DMI_TABLE_PATH), "{error}");
    }

    #[test]
    fn a_device_reads_as_one_line_with_both_widths() {
        let devices = read_report(&sysfs_with_table().files())
            .unwrap()
            .memory_devices
            .unwrap();
        assert_eq!(
            describe_device(&devices[0]),
            "DIMM_A1 (BANK 0): 8192 MiB DDR4 DIMM, total width 72 bits, data width 72 bits, 2666 MT/s (configured 2133 MT/s)"
        );
        assert_eq!(describe_device(&devices[1]), "DIMM_B1 (BANK 1): empty");
        let odd = MemoryDevice {
            size_kib: Some(512),
            speed_mts: None,
            configured_speed_mts: Some(800),
            total_width_bits: None,
            ..devices[0].clone()
        };
        assert_eq!(
            describe_device(&odd),
            "DIMM_A1 (BANK 0): 512 KiB DDR4 DIMM, total width unknown, data width 72 bits, configured 800 MT/s"
        );
    }

    #[test]
    fn the_bundle_holds_the_report_and_receipt_but_never_the_raw_table_or_secrets() {
        let sysfs = sysfs_with_table();
        let capture = capture_from(&sysfs.files()).unwrap();
        let names: Vec<&str> = capture
            .bundle
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(names, ["smbios.json", "manifest.json", "evidence.json"]);
        for file in &capture.bundle.files {
            let text = String::from_utf8_lossy(&file.bytes);
            assert!(!text.contains(SMBIOS_SECRET), "{}", file.path);
        }
        let evidence: serde_json::Value =
            serde_json::from_slice(capture.bundle.get("evidence.json").unwrap()).unwrap();
        assert_eq!(evidence["host"]["command"], "diag smbios");
        let observations = evidence["observations"].to_string();
        assert!(
            observations.contains("total width 72 bits, data width 72 bits"),
            "{observations}"
        );
    }

    #[test]
    fn the_unprivileged_receipt_states_memory_devices_are_unavailable() {
        let sysfs = sysfs_with_table();
        let files = RootOnlyFiles::new(sysfs.files(), [DMI_TABLE_PATH]);
        let capture = capture_from(&files).unwrap();
        let evidence =
            String::from_utf8(capture.bundle.get("evidence.json").unwrap().to_vec()).unwrap();
        assert!(
            evidence.contains("Memory devices unavailable"),
            "{evidence}"
        );
        let slot = SmbiosSlot::populated_72_bit();
        assert!(!evidence.contains(slot.locator), "{evidence}");
    }
}
