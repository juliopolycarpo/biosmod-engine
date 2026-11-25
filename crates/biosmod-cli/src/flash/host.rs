//! Read-only facts about the running system that decide whether flashing can work.
//!
//! On Linux everything comes from sysfs, procfs and efivarfs under [`Host::root`], so tests
//! point the same code at a directory tree instead of real hardware. On Windows the facts
//! come from [`WindowsFacts`], read once when the host is created, so tests pass plain values.

use super::flashrom::Chip;
use biosmod_host::windows::{UsbDevice, WindowsFacts};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// How one diagnosis line should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Nothing stands in the way.
    Pass,
    /// May stop an operation; the detail says what to try.
    Warn,
    /// Stops every chip operation until fixed.
    Fail,
    /// A fact worth knowing, neither good nor bad.
    Info,
}

/// One diagnosis line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub check: &'static str,
    pub state: State,
    pub detail: String,
}

/// The flashrom installation found on this system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flashrom {
    #[serde(serialize_with = "crate::output::serialize_display_path")]
    pub path: PathBuf,
    pub version: Option<String>,
}

/// The DMI fields the flash diagnosis shows, a subset of what `biosmod-host` reads.
const DMI_FIELDS: [&str; 8] = [
    "sys_vendor",
    "product_name",
    "board_vendor",
    "board_name",
    "board_version",
    "bios_vendor",
    "bios_version",
    "bios_date",
];

/// USB programmers flashrom drives: (vendor id, product id, name, flashrom programmer).
const USB_PROGRAMMERS: [(&str, &str, &str, &str); 4] = [
    ("1a86", "5512", "CH341A", "ch341a_spi"),
    ("0403", "6010", "FTDI FT2232H", "ft2232_spi:type=2232H"),
    ("0403", "6014", "FTDI FT232H", "ft2232_spi:type=232H"),
    ("0483", "dada", "Dediprog SF100/SF600", "dediprog"),
];

/// Windows drivers through which libusb, and so flashrom, reaches a USB programmer.
const LIBUSB_DRIVERS: [&str; 3] = ["winusb", "libusbk", "libusb0"];

/// The Windows driver that binds the interfaces of a composite USB device; it says nothing
/// about whether flashrom can reach the interface that matters.
const COMPOSITE_PARENT_DRIVER: &str = "usbccgp";

/// BIOS Control register in the PCH configuration space.
const BIOS_CONTROL_OFFSET: usize = 0xDC;

/// Whether `programmer` is flashrom's internal programmer, the chipset's own SPI controller.
///
/// Example: `is_internal("internal:laptop=this_is_not_a_laptop")` is `true`.
pub fn is_internal(programmer: &str) -> bool {
    programmer.split(':').next() == Some("internal")
}

/// The system being diagnosed.
#[derive(Debug, Clone)]
pub struct Host {
    /// Filesystem root holding `sys/` and `proc/`.
    pub root: PathBuf,
    pub os: &'static str,
    /// Effective user id, when the platform has one.
    pub euid: Option<u32>,
    /// What Windows reports, on Windows only: there is no sysfs under `root` to read.
    pub windows: Option<WindowsFacts>,
}

impl Host {
    /// The machine bme runs on.
    ///
    /// Example: `Host::current().dmi()["board_name"]` is the motherboard model.
    pub fn current() -> Host {
        Host {
            root: PathBuf::from("/"),
            os: std::env::consts::OS,
            euid: effective_user(),
            windows: windows_facts(),
        }
    }

    fn text(&self, relative: &str) -> Option<String> {
        fs::read_to_string(self.root.join(relative))
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    }

    fn entries(&self, relative: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.root.join(relative))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    /// Motherboard and firmware identity as the running firmware reports it.
    ///
    /// Example: `host.dmi().get("bios_version")` is `Some("5.11")` on the MR9A.
    pub fn dmi(&self) -> BTreeMap<&'static str, String> {
        if let Some(facts) = &self.windows {
            return facts
                .dmi
                .iter()
                .filter(|(field, _)| DMI_FIELDS.contains(field))
                .map(|(field, value)| (*field, value.clone()))
                .collect();
        }
        biosmod_host::identity::read_dmi_fields(
            &biosmod_host::RootedFiles::new(&self.root),
            &DMI_FIELDS,
        )
    }

    fn kernel_lockdown(&self) -> Option<String> {
        let modes = self.text("sys/kernel/security/lockdown")?;
        let active = modes.split('[').nth(1)?.split(']').next()?;
        Some(active.to_string())
    }

    fn secure_boot(&self) -> Option<bool> {
        // Four attribute bytes, then the value.
        let variable = fs::read(
            self.root
                .join("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        )
        .ok()?;
        variable.get(4).map(|value| *value == 1)
    }

    fn mtd_devices(&self) -> Vec<String> {
        self.entries("sys/class/mtd")
            .into_iter()
            .filter(|name| {
                name.strip_prefix("mtd")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })
            .map(|name| {
                let field = |key: &str| {
                    self.text(&format!("sys/class/mtd/{name}/{key}"))
                        .unwrap_or_else(|| "unknown".into())
                };
                format!(
                    "{name} {:?} {} bytes ({}): --programmer linux_mtd:dev={}",
                    field("name"),
                    field("size"),
                    field("type"),
                    &name[3..]
                )
            })
            .collect()
    }

    fn usb_programmers(&self) -> Vec<String> {
        let mut found = Vec::new();
        for device in self.entries("sys/bus/usb/devices") {
            let id = |key: &str| self.text(&format!("sys/bus/usb/devices/{device}/{key}"));
            let (Some(vendor), Some(product)) = (id("idVendor"), id("idProduct")) else {
                continue;
            };
            for (known_vendor, known_product, name, programmer) in USB_PROGRAMMERS {
                if vendor.eq_ignore_ascii_case(known_vendor)
                    && product.eq_ignore_ascii_case(known_product)
                {
                    found.push(format!(
                        "{name} ({vendor}:{product}): --programmer {programmer}"
                    ));
                }
            }
        }
        found
    }

    /// BIOS Control bits (write enable, lock enable, SMM write protect) of an Intel PCH.
    fn bios_control(&self) -> BiosControl {
        // 100-series and later PCHs moved the register from the LPC bridge to the SPI controller.
        for device in ["0000:00:1f.5", "0000:00:1f.0"] {
            let base = format!("sys/bus/pci/devices/{device}");
            if self.text(&format!("{base}/vendor")).as_deref() != Some("0x8086") {
                continue;
            }
            let Ok(config) = fs::read(self.root.join(format!("{base}/config"))) else {
                continue;
            };
            return match config.get(BIOS_CONTROL_OFFSET) {
                Some(value) => BiosControl::Read {
                    device,
                    value: *value,
                },
                // Unprivileged readers receive only the first 64 bytes.
                None => BiosControl::NeedsRoot,
            };
        }
        BiosControl::Absent
    }

    /// Diagnose what a chip operation through `programmer` will run into.
    ///
    /// Example: `host.checks("internal", flashrom.as_ref())` flags kernel lockdown as `fail`.
    pub fn checks(&self, programmer: &str, flashrom: Option<&Flashrom>) -> Vec<Check> {
        if let Some(facts) = &self.windows {
            return windows_checks(facts, programmer, flashrom);
        }
        let internal = is_internal(programmer);
        let mut checks = Vec::new();
        let mut add = |check, state, detail: String| {
            checks.push(Check {
                check,
                state,
                detail,
            })
        };
        if self.os == "linux" {
            add("platform", State::Pass, "linux".into());
        } else {
            add(
                "platform",
                State::Fail,
                format!(
                    "expected linux or windows | received {}; chip access is only supported there",
                    self.os
                ),
            );
        }
        let (state, detail) = flashrom_check(
            flashrom,
            false,
            "Debian/Ubuntu: sudo apt install flashrom, Fedora: sudo dnf install flashrom, Arch: sudo pacman -S flashrom",
        );
        add("flashrom", state, detail);
        match self.euid {
            Some(0) => add("privileges", State::Pass, "running as root".into()),
            Some(uid) => add(
                "privileges",
                State::Warn,
                format!(
                    "running as uid {uid}; probe, backup and write usually need root: use sudo, or let the desktop app ask through pkexec"
                ),
            ),
            None => add(
                "privileges",
                State::Info,
                "no user id on this platform".into(),
            ),
        }
        let secure_boot = self.secure_boot();
        match self.kernel_lockdown().as_deref() {
            Some("none") => add("kernel-lockdown", State::Pass, "none".into()),
            Some(mode) if internal => add(
                "kernel-lockdown",
                State::Fail,
                format!(
                    "{mode}: the kernel blocks raw hardware access, so the internal programmer cannot work; disable Secure Boot in firmware setup or use an external programmer"
                ),
            ),
            Some(mode) => add(
                "kernel-lockdown",
                State::Info,
                format!("{mode}: only affects the internal programmer"),
            ),
            None => add(
                "kernel-lockdown",
                State::Info,
                "not reported by this kernel".into(),
            ),
        }
        match secure_boot {
            Some(true) => add(
                "secure-boot",
                if internal { State::Warn } else { State::Info },
                "enabled; kernels usually turn on lockdown with it".into(),
            ),
            Some(false) => add("secure-boot", State::Pass, "disabled".into()),
            None => add(
                "secure-boot",
                State::Info,
                "no SecureBoot variable (legacy boot or efivarfs not mounted)".into(),
            ),
        }
        if internal {
            let relaxed = self
                .text("proc/cmdline")
                .is_some_and(|line| line.split_whitespace().any(|word| word == "iomem=relaxed"));
            let claimed: Vec<&str> = ["spi_intel", "lpc_ich"]
                .into_iter()
                .filter(|module| self.root.join(format!("sys/module/{module}")).is_dir())
                .collect();
            if relaxed {
                add(
                    "internal-access",
                    State::Pass,
                    "iomem=relaxed is set".into(),
                );
            } else if claimed.is_empty() {
                add(
                    "internal-access",
                    State::Info,
                    "no kernel driver claims the SPI controller".into(),
                );
            } else {
                add(
                    "internal-access",
                    State::Warn,
                    format!(
                        "{} loaded and may claim the SPI controller; if probing fails with a /dev/mem error, boot once with iomem=relaxed or use a linux_mtd programmer listed under mtd",
                        claimed.join(", ")
                    ),
                );
            }
            match self.bios_control() {
                BiosControl::Read { device, value } => {
                    let (lock_enable, smm_protect) = (value & 0x02 != 0, value & 0x20 != 0);
                    let bits = format!(
                        "BIOS_CNTL {value:#04x} at {device} (BIOSWE={} BLE={} SMM_BWP={})",
                        value & 1,
                        u8::from(lock_enable),
                        u8::from(smm_protect)
                    );
                    if smm_protect {
                        add(
                            "bios-write-protection",
                            State::Warn,
                            format!(
                                "{bits}: the BIOS region can only be written from SMM; backups work, writing needs an external programmer"
                            ),
                        );
                    } else if lock_enable {
                        add(
                            "bios-write-protection",
                            State::Warn,
                            format!(
                                "{bits}: firmware may veto write enable; if the write is refused, use an external programmer"
                            ),
                        );
                    } else {
                        add("bios-write-protection", State::Pass, bits);
                    }
                }
                BiosControl::NeedsRoot => add(
                    "bios-write-protection",
                    State::Info,
                    "BIOS_CNTL is only readable as root; run `sudo bme flash doctor`".into(),
                ),
                BiosControl::Absent => add(
                    "bios-write-protection",
                    State::Info,
                    "no Intel PCH at 00:1f; write protection cannot be read here".into(),
                ),
            }
        }
        let mtd = self.mtd_devices();
        add(
            "mtd",
            State::Info,
            if mtd.is_empty() {
                "no kernel MTD flash device".into()
            } else {
                mtd.join("; ")
            },
        );
        let usb = self.usb_programmers();
        add(
            "usb-programmer",
            if usb.is_empty() || internal {
                State::Info
            } else {
                State::Pass
            },
            if usb.is_empty() {
                "no known USB SPI programmer connected".into()
            } else {
                usb.join("; ")
            },
        );
        checks
    }
}

enum BiosControl {
    Read { device: &'static str, value: u8 },
    NeedsRoot,
    Absent,
}

/// The `flashrom` line: its version, or how to install it (`install` names the commands).
///
/// Example: without flashrom on Windows the detail starts `not found in PATH or the MSYS2 directories`.
fn flashrom_check(flashrom: Option<&Flashrom>, windows: bool, install: &str) -> (State, String) {
    match flashrom {
        Some(Flashrom {
            path,
            version: Some(version),
        }) => (State::Pass, format!("{version} at {}", path.display())),
        Some(Flashrom {
            path,
            version: None,
        }) => (
            State::Warn,
            format!(
                "{}: expected a `flashrom v<version>` banner | received none",
                path.display()
            ),
        ),
        None => (
            State::Fail,
            format!(
                "not found in PATH or {}; install it ({install}) or set {}",
                super::flashrom::directories_name(windows),
                super::flashrom::FLASHROM_OVERRIDE
            ),
        ),
    }
}

/// Diagnose a chip operation on Windows.
///
/// flashrom has no internal programmer there, so only external programmers can pass. They are
/// reached through libusb, which needs WinUSB (or libusbK, libusb0) bound to the device instead
/// of the vendor driver. Kernel lockdown, `iomem` and `BIOS_CNTL` do not apply: nothing on this
/// path touches the chipset.
/// Example: a CH341A bound to `CH341PAR` yields a `usb-programmer` warning that names Zadig.
fn windows_checks(
    facts: &WindowsFacts,
    programmer: &str,
    flashrom: Option<&Flashrom>,
) -> Vec<Check> {
    let internal = is_internal(programmer);
    let mut checks = vec![if internal {
        Check {
            check: "platform",
            state: State::Fail,
            detail: "windows: expected an external programmer | received internal; flashrom has no internal programmer on Windows, so clip a USB programmer such as ch341a_spi to the chip, or flash from Linux".into(),
        }
    } else {
        Check {
            check: "platform",
            state: State::Pass,
            detail: "windows (external programmers only)".into(),
        }
    }];
    let (state, detail) = flashrom_check(
        flashrom,
        true,
        &format!("MSYS2: {}", super::flashrom::MSYS2_FLASHROM_INSTALL),
    );
    checks.push(Check {
        check: "flashrom",
        state,
        detail,
    });
    checks.push(Check {
        check: "privileges",
        state: State::Info,
        detail: match facts.elevated {
            Some(true) => "administrator".into(),
            Some(false) => "standard user; USB programmers do not need administrator rights".into(),
            None => "elevation unknown; USB programmers do not need administrator rights".into(),
        },
    });
    let (state, detail) = windows_usb_programmers(&facts.usb, internal);
    checks.push(Check {
        check: "usb-programmer",
        state,
        detail,
    });
    checks
}

/// The `usb-programmer` line on Windows: each known programmer with the drivers bound to it.
///
/// A composite programmer (FT2232H) is several device nodes: the parent under `usbccgp` and
/// one per interface. It is reachable when any of its nodes is bound to a libusb driver.
/// Example: a CH341A under `WinUSB` passes with `--programmer ch341a_spi`.
fn windows_usb_programmers(usb: &[UsbDevice], internal: bool) -> (State, String) {
    let mut lines = Vec::new();
    let mut reachable = 0;
    for (known_vendor, known_product, name, programmer) in USB_PROGRAMMERS {
        let nodes: Vec<&UsbDevice> = usb
            .iter()
            .filter(|device| device.vendor == known_vendor && device.product == known_product)
            .collect();
        if nodes.is_empty() {
            continue;
        }
        let mut drivers: Vec<&str> = nodes
            .iter()
            .filter_map(|device| device.service.as_deref())
            .filter(|service| !service.eq_ignore_ascii_case(COMPOSITE_PARENT_DRIVER))
            .collect();
        drivers.sort_unstable();
        drivers.dedup();
        let usable = drivers.iter().any(|driver| {
            LIBUSB_DRIVERS
                .iter()
                .any(|known| driver.eq_ignore_ascii_case(known))
        });
        let id = format!("{name} ({known_vendor}:{known_product})");
        if usable {
            reachable += 1;
            lines.push(format!("{id}: --programmer {programmer}"));
        } else {
            let bound = if drivers.is_empty() {
                "has no driver".to_string()
            } else {
                format!("uses driver {}", drivers.join(", "))
            };
            lines.push(format!(
                "{id} {bound}; expected WinUSB for flashrom: bind WinUSB to it with Zadig (zadig.akeo.ie)"
            ));
        }
    }
    let state = if lines.is_empty() || internal {
        State::Info
    } else if reachable == lines.len() {
        State::Pass
    } else {
        State::Warn
    };
    let detail = if lines.is_empty() {
        "no known USB SPI programmer connected".into()
    } else {
        lines.join("; ")
    };
    (state, detail)
}

#[cfg(unix)]
fn effective_user() -> Option<u32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Some(unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
fn effective_user() -> Option<u32> {
    None
}

#[cfg(windows)]
fn windows_facts() -> Option<WindowsFacts> {
    Some(biosmod_host::windows::read())
}

#[cfg(not(windows))]
fn windows_facts() -> Option<WindowsFacts> {
    None
}

/// Whether a catalog board profile names the running motherboard.
///
/// Vendor and model compare case-insensitively against the DMI board fields; the
/// revision is reported separately because many boards leave it blank.
/// Example: DMI `MACHINIST` / `E5-MR9A PRO` matches the profile `Machinist` / `E5-MR9A PRO`.
pub fn board_matches(dmi: &BTreeMap<&'static str, String>, vendor: &str, model: &str) -> bool {
    let equal = |field: &str, expected: &str| {
        dmi.get(field)
            .is_some_and(|value| value.eq_ignore_ascii_case(expected.trim()))
    };
    equal("board_name", model) && equal("board_vendor", vendor)
}

/// A one-line description of a detected chip.
///
/// Example: `describe_chip(&chip)` is `Winbond W25Q128.V, 16777216 bytes, SPI`.
pub fn describe_chip(chip: &Chip) -> String {
    format!(
        "{} {}, {} bytes, {}",
        chip.vendor, chip.name, chip.size_bytes, chip.bus
    )
}
