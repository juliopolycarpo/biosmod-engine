//! Named fakes for the host surfaces, shared by this crate's and the CLI's tests.
//!
//! Nothing here touches the real machine: [`FakeSysfs`] is a temporary directory
//! tree, the rest are in-memory.

use crate::clock::{Clock, Timestamp};
use crate::files::RootedFiles;
use crate::kmsg::{KernelLog, KernelRecord};
use crate::privilege::Privilege;
use biosmod_core::Result;
use std::fs;
use std::path::PathBuf;

/// A directory tree standing in for `/sys`, `/proc` and `/dev`.
pub struct FakeSysfs {
    root: tempfile::TempDir,
}

impl FakeSysfs {
    /// Boot ID of [`FakeSysfs::mr9a`], as the MR9A reported it on 2026-11-04.
    pub const BOOT_ID: &'static str = "98d86da9-5410-4ce4-9463-5c2f92281b86";

    pub fn new() -> FakeSysfs {
        FakeSysfs {
            root: tempfile::tempdir().expect("temporary directory"),
        }
    }

    /// Add a file below the root, creating parents.
    ///
    /// Example: `FakeSysfs::new().file("sys/power/state", "freeze mem disk\n")`.
    pub fn file(self, path: &str, contents: impl AsRef<[u8]>) -> FakeSysfs {
        let target = self.path(path);
        fs::create_dir_all(target.parent().expect("has parent")).expect("create parents");
        fs::write(target, contents).expect("write fake file");
        self
    }

    /// Add an empty directory.
    pub fn directory(self, path: &str) -> FakeSysfs {
        fs::create_dir_all(self.path(path)).expect("create directory");
        self
    }

    /// The real path of `path` inside the tree.
    pub fn path(&self, path: &str) -> PathBuf {
        self.root.path().join(path.trim_start_matches('/'))
    }

    /// The tree's root directory.
    pub fn root(&self) -> &std::path::Path {
        self.root.path()
    }

    /// [`RootedFiles`] over the tree.
    pub fn files(&self) -> RootedFiles {
        RootedFiles::new(self.root.path())
    }

    /// The MR9A as it identifies itself, with an unlocked kernel.
    pub fn mr9a() -> FakeSysfs {
        FakeSysfs::new()
            .file("sys/class/dmi/id/board_vendor", "MACHINIST\n")
            .file("sys/class/dmi/id/board_name", "E5-MR9A PRO\n")
            .file("sys/class/dmi/id/board_version", "V1.2\n")
            .file("sys/class/dmi/id/bios_version", "5.11\n")
            .file(
                "sys/kernel/security/lockdown",
                "[none] integrity confidentiality\n",
            )
            .file("proc/cmdline", "ro quiet splash\n")
            .file(
                "proc/sys/kernel/random/boot_id",
                format!("{}\n", FakeSysfs::BOOT_ID),
            )
            .file("proc/sys/kernel/osrelease", "7.0.0-42-generic\n")
            .file(
                "proc/version",
                "Linux version 7.0.0-42-generic (buildd@lcy02) #42-Ubuntu SMP\n",
            )
    }
}

impl Default for FakeSysfs {
    fn default() -> FakeSysfs {
        FakeSysfs::new()
    }
}

/// Kernel records held in memory.
pub struct FakeKernelLog {
    records: Vec<KernelRecord>,
}

impl FakeKernelLog {
    pub fn new() -> FakeKernelLog {
        FakeKernelLog {
            records: Vec::new(),
        }
    }

    /// Append a record at `micros` since boot; the sequence number counts up.
    ///
    /// Example: `FakeKernelLog::new().message(5_140_900, "PM: suspend entry (deep)")`.
    pub fn message(mut self, micros: u64, message: &str) -> FakeKernelLog {
        self.records.push(KernelRecord {
            level: 6,
            sequence: self.records.len() as u64,
            micros,
            message: message.to_string(),
        });
        self
    }
}

impl Default for FakeKernelLog {
    fn default() -> FakeKernelLog {
        FakeKernelLog::new()
    }
}

impl KernelLog for FakeKernelLog {
    fn records(&self) -> Result<Vec<KernelRecord>> {
        Ok(self.records.clone())
    }
}

/// A fixed effective user.
pub struct FakePrivilege(Option<u32>);

impl FakePrivilege {
    pub fn root() -> FakePrivilege {
        FakePrivilege(Some(0))
    }

    pub fn user(uid: u32) -> FakePrivilege {
        FakePrivilege(Some(uid))
    }

    /// A platform without user ids.
    pub fn unknown() -> FakePrivilege {
        FakePrivilege(None)
    }
}

impl Privilege for FakePrivilege {
    fn effective_user(&self) -> Option<u32> {
        self.0
    }
}

/// A clock stopped at 2026-11-12T00:00:00Z.
pub struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            unix_seconds: 1_794_441_600,
        }
    }
}

/// One access recorded by [`RecordingPorts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortOp {
    Read(u16),
    Write(u16, u8),
}

/// Ports that answer from a table and remember every access.
#[derive(Default)]
pub struct RecordingPorts {
    values: std::collections::HashMap<u16, u8>,
    pub log: Vec<PortOp>,
}

impl RecordingPorts {
    pub fn new() -> RecordingPorts {
        RecordingPorts::default()
    }

    /// Make reads of `port` return `value`.
    pub fn with(mut self, port: u16, value: u8) -> RecordingPorts {
        self.values.insert(port, value);
        self
    }
}

impl crate::ports::PortIo for RecordingPorts {
    fn read(&mut self, port: u16) -> Result<u8> {
        self.log.push(PortOp::Read(port));
        Ok(self.values.get(&port).copied().unwrap_or(0xFF))
    }

    fn write(&mut self, port: u16, value: u8) -> Result<()> {
        self.log.push(PortOp::Write(port, value));
        Ok(())
    }
}

/// What the MR9A's NCT5532D reported on 2026-11-09, as recorded by hand.
pub const MR9A_LIVE_CONTROLLER: &str = r#"{
  "utc": "2026-11-09T07:52:19.842221+00:00",
  "chip_id": "0xc562",
  "hwm_active": 1,
  "hwm_base": "0xa20",
  "registers": {
    "0": {"01": 255, "03": 150, "04": 0, "ae": 3},
    "1": {"00": 17, "01": 0, "02": 0, "03": 0, "04": 0, "05": 1, "06": 1, "07": 60, "09": 255,
          "21": 0, "22": 0, "23": 0, "24": 0, "27": 0, "28": 0, "29": 0, "2a": 0,
          "35": 0, "36": 0, "37": 0, "38": 0},
    "2": {"00": 16, "01": 50, "02": 69, "03": 1, "04": 1, "05": 1, "06": 1, "07": 60, "09": 150,
          "21": 30, "22": 40, "23": 50, "24": 60, "27": 150, "28": 170, "29": 200, "2a": 255,
          "35": 60, "36": 0, "37": 4, "38": 0},
    "4": {"c0": 0, "c1": 0, "c2": 5, "c3": 48},
    "7": {"1f": 1, "20": 18, "23": 0, "24": 0, "25": 9, "26": 0, "27": 102, "28": 0, "29": 249}
  }
}"#;

/// A Nuvoton-style Super I/O behind configuration ports and an indexed hardware
/// monitor, modelled at the register level.
///
/// It enforces the safety contract instead of trusting the code under test: after
/// the entry key, the only data-port write allowed is the logical device selector;
/// in the hardware monitor, only the bank register may be written. Any other
/// access is recorded in [`violations`](FakeSuperIoPorts::violations) and returned
/// as an error. It starts with a nonzero logical device and a bank register with
/// high bits set, so "restored" means something.
pub struct FakeSuperIoPorts {
    config_port: u16,
    chip_id: u16,
    unlock_progress: usize,
    unlocked: bool,
    index: u8,
    ldn: u8,
    ldn_registers: std::collections::BTreeMap<(u8, u8), u8>,
    hwm_base: u16,
    hwm_index: u8,
    bank_register: u8,
    banks: std::collections::BTreeMap<(u8, u8), u8>,
    hwm_reads: usize,
    fail_hwm_read_at: Option<usize>,
    writes: usize,
    fail_write_at: Option<usize>,
    config_reads: usize,
    fail_config_read_at: Option<usize>,
    /// Accesses the fake refuses.
    pub violations: Vec<String>,
    /// Every access in order.
    pub trace: Vec<PortOp>,
}

impl FakeSuperIoPorts {
    /// The register an initial logical device selection holds.
    pub const INITIAL_LDN: u8 = 0x09;
    /// The initial bank register: high bits set, bank 5 selected.
    pub const INITIAL_BANK_REGISTER: u8 = 0x85;

    /// The MR9A's NCT5532D (ID 0xC562, configuration port 0x2E, monitor at 0xA20)
    /// holding the values of [`MR9A_LIVE_CONTROLLER`].
    pub fn mr9a_nct5532d() -> FakeSuperIoPorts {
        let live: serde_json::Value =
            serde_json::from_str(MR9A_LIVE_CONTROLLER).expect("fixture is JSON");
        let mut banks = std::collections::BTreeMap::new();
        for (bank, registers) in live["registers"].as_object().expect("registers") {
            for (register, value) in registers.as_object().expect("bank") {
                banks.insert(
                    (
                        bank.parse().expect("bank number"),
                        u8::from_str_radix(register, 16).expect("register"),
                    ),
                    value.as_u64().expect("value") as u8,
                );
            }
        }
        let mut ldn_registers = std::collections::BTreeMap::new();
        // UART A at 3F8h, hardware monitor at A20h; both active.
        for (ldn, active, base) in [(0x02, 1, 0x03F8u16), (0x0B, 1, 0x0A20)] {
            ldn_registers.insert((ldn, 0x30), active);
            ldn_registers.insert((ldn, 0x60), (base >> 8) as u8);
            ldn_registers.insert((ldn, 0x61), base as u8);
        }
        FakeSuperIoPorts {
            config_port: 0x2E,
            chip_id: 0xC562,
            unlock_progress: 0,
            unlocked: false,
            index: 0,
            ldn: FakeSuperIoPorts::INITIAL_LDN,
            ldn_registers,
            hwm_base: 0x0A20,
            hwm_index: 0,
            bank_register: FakeSuperIoPorts::INITIAL_BANK_REGISTER,
            banks,
            hwm_reads: 0,
            fail_hwm_read_at: None,
            writes: 0,
            fail_write_at: None,
            config_reads: 0,
            fail_config_read_at: None,
            violations: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// Answer with another chip ID.
    pub fn with_chip_id(mut self, chip_id: u16) -> FakeSuperIoPorts {
        self.chip_id = chip_id;
        self
    }

    /// Put the chip on the other configuration port (0x4E).
    pub fn at_port(mut self, config_port: u16) -> FakeSuperIoPorts {
        self.config_port = config_port;
        self
    }

    /// Mark the hardware monitor inactive.
    pub fn with_inactive_hardware_monitor(mut self) -> FakeSuperIoPorts {
        self.ldn_registers.insert((0x0B, 0x30), 0);
        self
    }

    /// Fail the `n`th (1-based) hardware-monitor data read.
    pub fn failing_hwm_read(mut self, n: usize) -> FakeSuperIoPorts {
        self.fail_hwm_read_at = Some(n);
        self
    }

    /// Fail the `n`th (1-based) port write of any kind without applying it.
    pub fn failing_write(mut self, n: usize) -> FakeSuperIoPorts {
        self.fail_write_at = Some(n);
        self
    }

    /// Fail the `n`th (1-based) configuration data-port read while in configuration
    /// mode. Reads 1 and 2 are the chip ID and 3 the saved logical device number; later
    /// ones belong to the logical device phase.
    pub fn failing_config_read(mut self, n: usize) -> FakeSuperIoPorts {
        self.fail_config_read_at = Some(n);
        self
    }

    fn injected(what: &str, n: usize) -> biosmod_core::Error {
        // An injected fault, not a protocol violation.
        biosmod_core::Error::new(
            biosmod_core::Code::Io,
            format!("(FakeSuperIoPorts): injected failure of {what} {n}"),
        )
    }

    /// Whether the chip is out of configuration mode.
    pub fn is_locked(&self) -> bool {
        !self.unlocked
    }

    /// The selected logical device.
    pub fn selected_ldn(&self) -> u8 {
        self.ldn
    }

    /// The hardware-monitor bank register.
    pub fn bank_register(&self) -> u8 {
        self.bank_register
    }

    fn refuse<T>(&mut self, message: String) -> Result<T> {
        self.violations.push(message.clone());
        Err(biosmod_core::Error::new(
            biosmod_core::Code::Internal,
            format!("(FakeSuperIoPorts): {message}"),
        ))
    }

    fn is_other_config_port(port: u16) -> bool {
        matches!(port, 0x2E | 0x2F | 0x4E | 0x4F)
    }
}

impl crate::ports::PortIo for FakeSuperIoPorts {
    fn read(&mut self, port: u16) -> Result<u8> {
        self.trace.push(PortOp::Read(port));
        let (index_port, data_port) = (self.config_port, self.config_port + 1);
        if port == data_port {
            if !self.unlocked {
                return Ok(0xFF);
            }
            self.config_reads += 1;
            if self.fail_config_read_at == Some(self.config_reads) {
                return Err(FakeSuperIoPorts::injected(
                    "configuration read",
                    self.config_reads,
                ));
            }
            return Ok(match self.index {
                0x20 => (self.chip_id >> 8) as u8,
                0x21 => self.chip_id as u8,
                0x07 => self.ldn,
                register => self
                    .ldn_registers
                    .get(&(self.ldn, register))
                    .copied()
                    .unwrap_or(0),
            });
        }
        if port == index_port {
            return Ok(self.index);
        }
        if port == self.hwm_base + 6 {
            self.hwm_reads += 1;
            if self.fail_hwm_read_at == Some(self.hwm_reads) {
                // An injected fault, not a protocol violation.
                return Err(biosmod_core::Error::new(
                    biosmod_core::Code::Io,
                    format!(
                        "(FakeSuperIoPorts): injected failure of hardware-monitor read {}",
                        self.hwm_reads
                    ),
                ));
            }
            if self.hwm_index == 0x4E {
                return Ok(self.bank_register);
            }
            return Ok(self
                .banks
                .get(&(self.bank_register & 0x0F, self.hwm_index))
                .copied()
                .unwrap_or(0));
        }
        if FakeSuperIoPorts::is_other_config_port(port) {
            return Ok(0xFF);
        }
        self.refuse(format!("read of port {port:#x}: expected only the configuration pair at {index_port:#x} and the monitor at {:#x}", self.hwm_base))
    }

    fn write(&mut self, port: u16, value: u8) -> Result<()> {
        self.trace.push(PortOp::Write(port, value));
        self.writes += 1;
        if self.fail_write_at == Some(self.writes) {
            return Err(FakeSuperIoPorts::injected("write", self.writes));
        }
        let (index_port, data_port) = (self.config_port, self.config_port + 1);
        if port == index_port {
            if self.unlocked {
                if value == 0xAA {
                    self.unlocked = false;
                    self.unlock_progress = 0;
                } else {
                    self.index = value;
                }
            } else if value == 0x87 {
                self.unlock_progress += 1;
                if self.unlock_progress == 2 {
                    self.unlocked = true;
                    self.unlock_progress = 0;
                }
            } else {
                self.unlock_progress = 0;
            }
            return Ok(());
        }
        if port == data_port {
            if !self.unlocked {
                return self.refuse(format!(
                    "write of {value:#04x} to the data port while locked"
                ));
            }
            if self.index != 0x07 {
                return self.refuse(format!(
                    "write of {value:#04x} to configuration register {:#04x}: expected only the logical device selector 0x07",
                    self.index
                ));
            }
            self.ldn = value;
            return Ok(());
        }
        if port == self.hwm_base + 5 {
            self.hwm_index = value;
            return Ok(());
        }
        if port == self.hwm_base + 6 {
            if self.hwm_index != 0x4E {
                return self.refuse(format!(
                    "write of {value:#04x} to hardware-monitor register {:#04x}: expected only the bank register 0x4E",
                    self.hwm_index
                ));
            }
            self.bank_register = value;
            return Ok(());
        }
        if FakeSuperIoPorts::is_other_config_port(port) {
            return Ok(());
        }
        self.refuse(format!("write of {value:#04x} to port {port:#x}: expected only the configuration pair at {index_port:#x} and the monitor at {:#x}", self.hwm_base))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PortIo;

    #[test]
    fn recording_ports_answer_from_the_table_and_log_in_order() {
        let mut ports = RecordingPorts::new().with(0x73, 0xA1);
        ports.write(0x72, 0xE0).unwrap();
        assert_eq!(ports.read(0x73).unwrap(), 0xA1);
        assert_eq!(ports.read(0x99).unwrap(), 0xFF);
        assert_eq!(
            ports.log,
            [
                PortOp::Write(0x72, 0xE0),
                PortOp::Read(0x73),
                PortOp::Read(0x99)
            ]
        );
    }
}
