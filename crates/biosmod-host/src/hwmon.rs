//! Kernel hardware-monitor drivers that own a Super I/O chip.
//!
//! A bound `nct6775`, `it87` or `f71882fg` driver caches the monitor's selected bank
//! and writes fan registers on its own schedule. Switching the bank behind its back
//! through `/dev/port` can send one of its writes to the wrong bank, and the
//! kernel's region claims do not cover `/dev/port`. So when a driver is bound,
//! `diag superio read` does not touch a port: it reads what the driver publishes in
//! `/sys/class/hwmon` and says what that cannot show.
//!
//! A driver is detected two ways, both without touching hardware: a hwmon device
//! whose `name` the chip table lists for the family, and a `/proc/ioports` resource
//! labelled with a listed module. Failing to list either is an error, not "no
//! driver": the safe answer to "cannot tell" is to stop.
//!
//! This module never unloads or loads a driver; the refusal names the command.

use crate::files::{EntryKind, HostFiles, read_trimmed};
use crate::superio::ChipMap;
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::ErrorKind;

pub const HWMON_ROOT: &str = "/sys/class/hwmon";
pub const IOPORTS_PATH: &str = "/proc/ioports";

/// A kernel driver that has claimed the chip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundDriver {
    /// The module to unload to get raw access, e.g. `nct6775`.
    pub module: String,
    /// The `hwmonN` device the driver registered, when one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwmon: Option<String>,
    /// How it was found, for the message and the receipt.
    pub found_by: String,
}

impl BoundDriver {
    /// The step that frees the chip, for a person to run. bme never runs it.
    ///
    /// Example: `sudo modprobe -r nct6775`.
    pub fn unload_command(&self) -> String {
        format!("sudo modprobe -r {}", self.module)
    }
}

/// Look for a driver the table says drives one of its chips.
///
/// Example: with `/sys/class/hwmon/hwmon3/name` holding `nct6779`,
/// `detect_bound_driver(&files, builtin())?.unwrap().module` is `"nct6775"`.
pub fn detect_bound_driver(
    files: &dyn HostFiles,
    chips: &[ChipMap],
) -> Result<Option<BoundDriver>> {
    let drivers: Vec<_> = chips.iter().flat_map(|chip| &chip.kernel_drivers).collect();
    match files.entries(HWMON_ROOT) {
        Ok(entries) => {
            for entry in entries.iter().filter(|e| e.name.starts_with("hwmon")) {
                let name = read_trimmed(files, &format!("{HWMON_ROOT}/{}/name", entry.name));
                let Some(name) = name else { continue };
                if let Some(driver) = drivers.iter().find(|d| d.hwmon_names.contains(&name)) {
                    return Ok(Some(BoundDriver {
                        module: driver.module.clone(),
                        hwmon: Some(entry.name.clone()),
                        found_by: format!("{HWMON_ROOT}/{}/name is {name:?}", entry.name),
                    }));
                }
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::new(
                Code::Io,
                format!(
                    "{HWMON_ROOT}: expected a readable listing to rule out a bound driver | received {e}"
                ),
            ));
        }
    }
    match files.read(IOPORTS_PATH) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                // `  0a20-0a2f : nct6775`
                let Some((range, label)) = line.trim().split_once(" : ") else {
                    continue;
                };
                if let Some(driver) = drivers.iter().find(|d| d.module == label.trim()) {
                    return Ok(Some(BoundDriver {
                        module: driver.module.clone(),
                        hwmon: None,
                        found_by: format!("{IOPORTS_PATH} holds {range} : {}", driver.module),
                    }));
                }
            }
            Ok(None)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::new(
            Code::Io,
            format!(
                "{IOPORTS_PATH}: expected a readable file to rule out a bound driver | received {e}"
            ),
        )),
    }
}

/// What a bound driver publishes, as `diag superio read` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HwmonReading {
    pub driver: BoundDriver,
    /// The hwmon device's `name` file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `pwmN`, `pwmN_enable`, `pwmN_auto_point*`, `fanN_input`, `tempN_input`,
    /// `tempN_label` and the other `pwm`, `fan` and `temp` files, by name.
    pub attributes: BTreeMap<String, String>,
    /// Files the driver refused to show.
    pub unreadable: Vec<String>,
    /// What this reading cannot show.
    pub not_available: String,
    /// Why no port was touched, and the step that would allow it.
    pub raw_access_refused: String,
}

/// Attribute families worth reading: fan control, fan speed and temperature.
fn is_wanted(name: &str) -> bool {
    ["pwm", "fan", "temp"].iter().any(|p| name.starts_with(p))
}

/// Read the bound driver's hwmon files. Read-only.
///
/// Example: `read_hwmon(&files, driver)?.attributes["fan1_input"]` is `"1204"`.
pub fn read_hwmon(files: &dyn HostFiles, driver: BoundDriver) -> Result<HwmonReading> {
    let mut reading = HwmonReading {
        raw_access_refused: format!(
            "{} is bound to the chip ({}); raw port access races its cached bank selection, so no port was touched. To read raw registers, unload it yourself with `{}`; bme never unloads a driver.",
            driver.module,
            driver.found_by,
            driver.unload_command()
        ),
        driver,
        name: None,
        attributes: BTreeMap::new(),
        unreadable: Vec::new(),
        not_available: "The logical device map, the hardware-monitor banks and registers the driver does not expose (for example the smart-fan tables beyond the auto_point files) are not available through sysfs.".into(),
    };
    let Some(hwmon) = reading.driver.hwmon.clone() else {
        reading.not_available = format!(
            "The driver is bound but no hwmon device with a known name was found, so nothing could be read from sysfs. {}",
            reading.not_available
        );
        return Ok(reading);
    };
    let directory = format!("{HWMON_ROOT}/{hwmon}");
    reading.name = read_trimmed(files, &format!("{directory}/name"));
    let entries = files
        .entries(&directory)
        .map_err(|e| Error::new(Code::Io, format!("{directory}: {e}")))?;
    for entry in entries
        .iter()
        .filter(|e| e.kind == EntryKind::File && is_wanted(&e.name))
    {
        match files.read(&format!("{directory}/{}", entry.name)) {
            Ok(bytes) => {
                reading.attributes.insert(
                    entry.name.clone(),
                    String::from_utf8_lossy(&bytes).trim().to_string(),
                );
            }
            Err(_) => reading.unreadable.push(entry.name.clone()),
        }
    }
    Ok(reading)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superio::builtin;
    use crate::testkit::FakeSysfs;

    fn bound_sysfs() -> FakeSysfs {
        FakeSysfs::mr9a()
            .file("sys/class/hwmon/hwmon0/name", "coretemp\n")
            .file("sys/class/hwmon/hwmon3/name", "nct6779\n")
            .file("sys/class/hwmon/hwmon3/pwm1", "128\n")
            .file("sys/class/hwmon/hwmon3/pwm1_enable", "5\n")
            .file("sys/class/hwmon/hwmon3/pwm1_auto_point1_temp", "30000\n")
            .file("sys/class/hwmon/hwmon3/fan1_input", "1204\n")
            .file("sys/class/hwmon/hwmon3/temp1_input", "41000\n")
            .file("sys/class/hwmon/hwmon3/temp1_label", "SYSTIN\n")
            .file("sys/class/hwmon/hwmon3/in0_input", "1200\n")
    }

    #[test]
    fn a_hwmon_device_named_for_the_family_is_a_bound_driver() {
        let sysfs = bound_sysfs();
        let driver = detect_bound_driver(&sysfs.files(), builtin())
            .unwrap()
            .unwrap();
        assert_eq!(driver.module, "nct6775");
        assert_eq!(driver.hwmon.as_deref(), Some("hwmon3"));
        assert!(
            driver.found_by.contains("hwmon3/name is \"nct6779\""),
            "{driver:?}"
        );
        assert_eq!(driver.unload_command(), "sudo modprobe -r nct6775");
    }

    #[test]
    fn an_ioports_claim_by_the_module_is_a_bound_driver_without_a_hwmon_device() {
        let sysfs = FakeSysfs::mr9a().file(
            "proc/ioports",
            "0000-0cf7 : PCI Bus 0000:00\n  002e-002f : pnp 00:03\n  0a20-0a2f : nct6775\n",
        );
        let driver = detect_bound_driver(&sysfs.files(), builtin())
            .unwrap()
            .unwrap();
        assert_eq!(
            (driver.module.as_str(), driver.hwmon.as_deref()),
            ("nct6775", None)
        );
        assert!(
            driver.found_by.contains("0a20-0a2f : nct6775"),
            "{driver:?}"
        );
    }

    #[test]
    fn other_hwmon_devices_and_other_claims_are_not_a_bound_driver() {
        let sysfs = FakeSysfs::mr9a()
            .file("sys/class/hwmon/hwmon0/name", "coretemp\n")
            .file("sys/class/hwmon/hwmon1/name", "acpitz\n")
            .file(
                "proc/ioports",
                "  002e-002f : pnp 00:03\n  0a20-0a2f : nct6775x\n",
            );
        assert_eq!(
            detect_bound_driver(&sysfs.files(), builtin()).unwrap(),
            None
        );
        // Neither surface present at all: also no driver.
        assert_eq!(
            detect_bound_driver(&FakeSysfs::new().files(), builtin()).unwrap(),
            None
        );
    }

    #[test]
    fn the_hwmon_reading_has_the_control_and_sensor_files_and_says_what_it_lacks() {
        let sysfs = bound_sysfs();
        let driver = detect_bound_driver(&sysfs.files(), builtin())
            .unwrap()
            .unwrap();
        let reading = read_hwmon(&sysfs.files(), driver).unwrap();
        assert_eq!(reading.name.as_deref(), Some("nct6779"));
        let names: Vec<&str> = reading.attributes.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "fan1_input",
                "pwm1",
                "pwm1_auto_point1_temp",
                "pwm1_enable",
                "temp1_input",
                "temp1_label"
            ]
        );
        assert_eq!(reading.attributes["temp1_label"], "SYSTIN");
        assert!(
            reading
                .not_available
                .contains("not available through sysfs")
        );
        assert!(
            reading
                .raw_access_refused
                .contains("`sudo modprobe -r nct6775`")
        );
        assert!(
            reading
                .raw_access_refused
                .contains("never unloads a driver")
        );
    }

    #[test]
    fn a_claim_without_a_hwmon_device_reads_nothing_and_says_so() {
        let driver = BoundDriver {
            module: "nct6775".into(),
            hwmon: None,
            found_by: "x".into(),
        };
        let reading = read_hwmon(&FakeSysfs::mr9a().files(), driver).unwrap();
        assert!(reading.attributes.is_empty());
        assert!(
            reading.not_available.contains("no hwmon device"),
            "{}",
            reading.not_available
        );
    }
}
