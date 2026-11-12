//! Reads of the running machine for `bme diag`.
//!
//! Every host surface is a trait so commands run against named fakes in tests:
//! [`HostFiles`] (sysfs, procfs), [`KernelLog`] (`/dev/kmsg`), [`PortIo`]
//! (`/dev/port`), [`Privilege`] (effective user) and [`Clock`]. The real
//! implementations are thin; the interpretation lives in the pure functions
//! around them. Like the core, this crate never prints, and it never opens a
//! device on its own: the CLI picks the real surfaces.
//!
//! The only hardware writes go through [`PortIo`], and only the access-selector
//! sequences documented where they are implemented use it.

pub mod acpi;
pub mod bundle;
pub mod clock;
pub mod files;
pub mod hwmon;
pub mod identity;
pub mod kmsg;
pub mod ports;
pub mod privilege;
pub mod receipt;
pub mod signals;
pub mod superio;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use clock::{Clock, SystemClock, Timestamp};
pub use files::{EntryKind, HostFiles, RootedFiles};
pub use kmsg::{KernelLog, KernelRecord};
pub use ports::PortIo;
pub use privilege::{Privilege, ProcessPrivilege};

/// The read-only surfaces a capture needs, borrowed from the caller.
///
/// Example: `HostSurfaces { files: &RootedFiles::system(), kernel_log: &log,
/// privilege: &ProcessPrivilege, clock: &SystemClock }`.
pub struct HostSurfaces<'a> {
    pub files: &'a dyn HostFiles,
    pub kernel_log: &'a dyn KernelLog,
    pub privilege: &'a dyn Privilege,
    pub clock: &'a dyn Clock,
}
