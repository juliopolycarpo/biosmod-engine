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
