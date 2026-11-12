//! Named fakes for the host surfaces, shared by this crate's and the CLI's tests.
//!
//! Nothing here touches the real machine: [`FakeSysfs`] is a temporary directory
//! tree, the rest are in-memory.

use crate::clock::{Clock, Timestamp};
use crate::files::{DirEntry, EntryKind, HostFiles, HostWrite, RootedFiles};
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

/// How [`FakePowerSysfs`] behaves when a test suspend is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuspendBehavior {
    Succeeds,
    /// The kernel counts a failure and the `state` write returns an error.
    CountsFailure,
    /// The `state` write returns an error and no counter moves.
    RejectsWrite,
}

struct PowerState {
    files: std::collections::BTreeMap<String, String>,
    records: Vec<KernelRecord>,
    writes: Vec<(String, String)>,
    real_sleeps: u32,
    violations: Vec<String>,
    ignore_pm_test_writes: bool,
    fail_pm_test_restore: bool,
    suspend: SuspendBehavior,
}

/// `/sys/power`, the suspend counters and the kernel log in memory, with the
/// kernel's rules for the test checkpoints.
///
/// It stands in for the real kernel when a pm-test is exercised, and it fails loudly
/// on the one thing the command must never do: a `mem` write while the machine would
/// really sleep (`pm_test` is `none`, or the stage lies past the point where
/// `s2idle` diverges). That counts in [`FakePowerSysfs::real_sleeps`]. Identity
/// files (boot ID, DMI) come from [`FakeSysfs::mr9a`].
pub struct FakePowerSysfs {
    identity: FakeSysfs,
    state: std::cell::RefCell<PowerState>,
}

impl FakePowerSysfs {
    const PM_TEST: &'static str = "/sys/power/pm_test";
    const STATE: &'static str = "/sys/power/state";
    const MEM_SLEEP: &'static str = "/sys/power/mem_sleep";
    const STATS: &'static str = "/sys/power/suspend_stats";
    const COUNTERS: [&'static str; 10] = [
        "success",
        "fail",
        "failed_freeze",
        "failed_prepare",
        "failed_suspend",
        "failed_suspend_late",
        "failed_suspend_noirq",
        "failed_resume",
        "failed_resume_early",
        "failed_resume_noirq",
    ];

    /// A machine whose `mem_sleep` is `[deep]`, `pm_test` is `none`, with zeroed counters.
    pub fn mr9a_deep() -> FakePowerSysfs {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            Self::PM_TEST.to_string(),
            "freezer devices platform processors core [none]\n".to_string(),
        );
        files.insert(Self::STATE.to_string(), "freeze mem disk\n".to_string());
        files.insert(Self::MEM_SLEEP.to_string(), "s2idle [deep]\n".to_string());
        for name in Self::COUNTERS {
            files.insert(format!("{}/{name}", Self::STATS), "0\n".to_string());
        }
        files.insert(format!("{}/last_failed_dev", Self::STATS), "\n".to_string());
        files.insert(
            format!("{}/last_failed_errno", Self::STATS),
            "0\n".to_string(),
        );
        FakePowerSysfs {
            identity: FakeSysfs::mr9a(),
            state: std::cell::RefCell::new(PowerState {
                files,
                records: vec![KernelRecord {
                    level: 6,
                    sequence: 0,
                    micros: 1_000_000,
                    message: "PM: hibernation: Registered nosave memory".into(),
                }],
                writes: Vec::new(),
                real_sleeps: 0,
                violations: Vec::new(),
                ignore_pm_test_writes: false,
                fail_pm_test_restore: false,
                suspend: SuspendBehavior::Succeeds,
            }),
        }
    }

    /// The MR9A as it boots: `mem_sleep` selects `s2idle`.
    pub fn mr9a_s2idle() -> FakePowerSysfs {
        let fake = FakePowerSysfs::mr9a_deep();
        fake.set(Self::MEM_SLEEP, "[s2idle] deep\n");
        fake
    }

    fn set(&self, path: &str, text: &str) {
        self.state
            .borrow_mut()
            .files
            .insert(path.to_string(), text.to_string());
    }

    /// Replace the `pm_test` listing, e.g. a kernel without the `core` stage.
    pub fn with_pm_test_listing(self, listing: &str) -> FakePowerSysfs {
        self.set(Self::PM_TEST, &format!("{listing}\n"));
        self
    }

    /// Replace the `state` listing, e.g. `freeze disk` without `mem`.
    pub fn with_states(self, listing: &str) -> FakePowerSysfs {
        self.set(Self::STATE, &format!("{listing}\n"));
        self
    }

    /// Remove the suspend counters, as on a kernel without them.
    pub fn without_suspend_stats(self) -> FakePowerSysfs {
        self.state
            .borrow_mut()
            .files
            .retain(|path, _| !path.starts_with(Self::STATS));
        self
    }

    /// `pm_test` writes succeed but leave the selection unchanged.
    pub fn ignoring_pm_test_writes(self) -> FakePowerSysfs {
        self.state.borrow_mut().ignore_pm_test_writes = true;
        self
    }

    /// The suspend fails: the kernel counts it and the `state` write errors.
    pub fn failing_suspend(self) -> FakePowerSysfs {
        self.state.borrow_mut().suspend = SuspendBehavior::CountsFailure;
        self
    }

    /// The `state` write errors without any counter moving (e.g. `EBUSY`).
    pub fn rejecting_state_write(self) -> FakePowerSysfs {
        self.state.borrow_mut().suspend = SuspendBehavior::RejectsWrite;
        self
    }

    /// Writing `none` back to `pm_test` fails, so the stage stays armed.
    pub fn failing_pm_test_restore(self) -> FakePowerSysfs {
        self.state.borrow_mut().fail_pm_test_restore = true;
        self
    }

    /// The current text of a fake file.
    pub fn text(&self, path: &str) -> String {
        self.state.borrow().files[path].clone()
    }

    /// The word `pm_test` selects.
    pub fn pm_test(&self) -> String {
        let text = self.text(Self::PM_TEST);
        let start = text.find('[').expect("a selection") + 1;
        let end = text.find(']').expect("a selection");
        text[start..end].to_string()
    }

    /// Every accepted write, in order, as (path, trimmed text).
    pub fn writes(&self) -> Vec<(String, String)> {
        self.state.borrow().writes.clone()
    }

    /// Times a suspend would really have slept the machine.
    pub fn real_sleeps(&self) -> u32 {
        self.state.borrow().real_sleeps
    }

    /// Writes the command must never make (unknown files, a real sleep).
    pub fn violations(&self) -> Vec<String> {
        self.state.borrow().violations.clone()
    }

    fn select(listing: &str, word: &str) -> String {
        let words: Vec<String> = listing
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '[' || c == ']').to_string())
            .collect();
        let rendered: Vec<String> = words
            .iter()
            .map(|w| {
                if w == word {
                    format!("[{w}]")
                } else {
                    w.clone()
                }
            })
            .collect();
        format!("{}\n", rendered.join(" "))
    }

    fn bump(state: &mut PowerState, name: &str) {
        let path = format!("{}/{name}", Self::STATS);
        let value: i64 = state.files[&path].trim().parse().unwrap_or(0);
        state.files.insert(path, format!("{}\n", value + 1));
    }

    fn selection_of(listing: &str) -> String {
        let start = listing.find('[').map(|i| i + 1).unwrap_or(0);
        let end = listing.find(']').unwrap_or(listing.len());
        listing[start..end].to_string()
    }
}

impl HostFiles for FakePowerSysfs {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        match self.state.borrow().files.get(path) {
            Some(text) => Ok(text.clone().into_bytes()),
            None if path.starts_with("/sys/power/") => {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            }
            None => self.identity.files().read(path),
        }
    }

    fn entries(&self, path: &str) -> std::io::Result<Vec<DirEntry>> {
        if path != Self::STATS {
            return self.identity.files().entries(path);
        }
        let prefix = format!("{}/", Self::STATS);
        let entries: Vec<DirEntry> = self
            .state
            .borrow()
            .files
            .keys()
            .filter_map(|file| file.strip_prefix(&prefix))
            .map(|name| DirEntry {
                name: name.to_string(),
                kind: EntryKind::File,
            })
            .collect();
        if entries.is_empty() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        Ok(entries)
    }
}

impl HostWrite for FakePowerSysfs {
    fn write(&self, path: &str, text: &str) -> std::io::Result<()> {
        let word = text.trim().to_string();
        let mut state = self.state.borrow_mut();
        let invalid =
            |message: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
        match path {
            Self::PM_TEST => {
                let listing = state.files[Self::PM_TEST].clone();
                if !listing
                    .split_whitespace()
                    .any(|w| w.trim_matches(|c| c == '[' || c == ']') == word)
                {
                    return Err(invalid(format!("{path}: EINVAL for {word:?}")));
                }
                if word == "none" && state.fail_pm_test_restore {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                state.writes.push((path.to_string(), word.clone()));
                if !state.ignore_pm_test_writes {
                    state
                        .files
                        .insert(path.to_string(), Self::select(&listing, &word));
                }
                Ok(())
            }
            Self::STATE => {
                state.writes.push((path.to_string(), word.clone()));
                if word != "mem" {
                    state.violations.push(format!(
                        "{path}: expected a write of mem | received {word:?}"
                    ));
                    return Err(invalid(format!("{path}: only mem is faked")));
                }
                let stage = Self::selection_of(&state.files[Self::PM_TEST]);
                let mode = Self::selection_of(&state.files[Self::MEM_SLEEP]);
                let past_s2idle_divergence =
                    matches!(stage.as_str(), "platform" | "processors" | "core") && mode != "deep";
                if stage == "none" || past_s2idle_divergence {
                    state.real_sleeps += 1;
                    state.violations.push(format!(
                        "{path}: the kernel would really sleep (pm_test {stage:?}, mem_sleep {mode:?})"
                    ));
                    return Err(invalid(format!("{path}: real sleep refused by the fake")));
                }
                match state.suspend {
                    SuspendBehavior::RejectsWrite => Err(std::io::Error::new(
                        std::io::ErrorKind::ResourceBusy,
                        format!("{path}: device or resource busy"),
                    )),
                    SuspendBehavior::CountsFailure => {
                        Self::bump(&mut state, "fail");
                        Self::bump(&mut state, "failed_suspend");
                        let sequence = state.records.len() as u64;
                        state.records.push(KernelRecord {
                            level: 3,
                            sequence,
                            micros: 90_000_000,
                            message:
                                "PM: Some devices failed to suspend, or early wake event detected"
                                    .into(),
                        });
                        Err(std::io::Error::other(format!("{path}: input/output error")))
                    }
                    SuspendBehavior::Succeeds => {
                        Self::bump(&mut state, "success");
                        for (offset, message) in [
                            "PM: suspend entry (deep)".to_string(),
                            format!("PM: suspend debug: Waiting for 5 second(s) at the {stage} test point."),
                            "PM: suspend exit".to_string(),
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            let sequence = state.records.len() as u64;
                            state.records.push(KernelRecord {
                                level: 6,
                                sequence,
                                micros: 90_000_000 + offset as u64,
                                message,
                            });
                        }
                        Ok(())
                    }
                }
            }
            other => {
                state.violations.push(format!(
                    "{other}: expected pm_test | state | received a write of {word:?}"
                ));
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }
    }
}

impl KernelLog for FakePowerSysfs {
    fn records(&self) -> Result<Vec<KernelRecord>> {
        Ok(self.state.borrow().records.clone())
    }
}

/// A kernel log the user may not read, as with `kernel.dmesg_restrict` set.
pub struct UnreadableKernelLog;

impl KernelLog for UnreadableKernelLog {
    fn records(&self) -> Result<Vec<KernelRecord>> {
        Err(biosmod_core::Error::new(
            biosmod_core::Code::Io,
            "/dev/kmsg: expected readable | received permission denied (kernel.dmesg_restrict)",
        ))
    }
}

/// A tree whose named files exist but read as permission denied, like the root-only
/// firmware tables seen by an unprivileged user.
pub struct RootOnlyFiles {
    inner: RootedFiles,
    denied: Vec<&'static str>,
}

impl RootOnlyFiles {
    /// `inner` with `denied` paths refused.
    ///
    /// Example: `RootOnlyFiles::new(sysfs.files(), ["/sys/firmware/dmi/tables/DMI"])`.
    pub fn new(
        inner: RootedFiles,
        denied: impl IntoIterator<Item = &'static str>,
    ) -> RootOnlyFiles {
        RootOnlyFiles {
            inner,
            denied: denied.into_iter().collect(),
        }
    }
}

impl HostFiles for RootOnlyFiles {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        if self.denied.contains(&path) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        self.inner.read(path)
    }

    fn entries(&self, path: &str) -> std::io::Result<Vec<DirEntry>> {
        self.inner.entries(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PortIo;

    #[test]
    fn root_only_files_refuse_the_named_paths_and_read_the_rest() {
        let sysfs = FakeSysfs::new().file("sys/a", "1").file("sys/b", "2");
        let files = RootOnlyFiles::new(sysfs.files(), ["/sys/a"]);
        let error = files.read("/sys/a").unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{error}"
        );
        assert_eq!(files.read("/sys/b").unwrap(), b"2");
        assert_eq!(files.entries("/sys").unwrap().len(), 2);
    }

    #[test]
    fn the_power_fake_counts_a_mem_write_that_would_really_sleep() {
        let fake = FakePowerSysfs::mr9a_s2idle();
        // pm_test is none: a real sleep.
        assert!(fake.write("/sys/power/state", "mem\n").is_err());
        // A late stage under s2idle is a real sleep too.
        fake.write("/sys/power/pm_test", "core\n").unwrap();
        assert!(fake.write("/sys/power/state", "mem\n").is_err());
        assert_eq!(fake.real_sleeps(), 2);
        assert_eq!(fake.violations().len(), 2);
        // An early stage under s2idle is a test.
        fake.write("/sys/power/pm_test", "devices\n").unwrap();
        fake.write("/sys/power/state", "mem\n").unwrap();
        assert_eq!(fake.real_sleeps(), 2);
        assert_eq!(fake.text("/sys/power/suspend_stats/success"), "1\n");
    }

    #[test]
    fn the_power_fake_rejects_unknown_stages_and_foreign_files() {
        let fake = FakePowerSysfs::mr9a_deep();
        let error = fake.write("/sys/power/pm_test", "warp\n").unwrap_err();
        assert!(error.to_string().contains("EINVAL for \"warp\""), "{error}");
        assert!(fake.write("/sys/power/disk", "reboot\n").is_err());
        assert_eq!(fake.violations().len(), 1);
        assert!(fake.read("/sys/power/absent").is_err());
        assert_eq!(fake.read("/proc/version").unwrap()[..5], *b"Linux");
    }

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
