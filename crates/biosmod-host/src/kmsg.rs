//! The kernel message buffer.
//!
//! `/dev/kmsg` is the least privileged robust source: it needs no subprocess or
//! util-linux, carries a sequence number and a boot-relative timestamp per record,
//! and is readable by a non-root user whenever `kernel.dmesg_restrict` is 0 (and
//! by root otherwise). A read from a non-blocking descriptor returns one record
//! at a time and `EAGAIN` at the end, so the snapshot never waits.

use biosmod_core::Result;
#[cfg(target_os = "linux")]
use biosmod_core::{Code, Error};

/// One kernel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRecord {
    /// Syslog priority and facility, as the kernel stores them.
    pub level: u32,
    pub sequence: u64,
    /// Microseconds since boot.
    pub micros: u64,
    pub message: String,
}

impl KernelRecord {
    /// `[   12.345678] message`, the format of `dmesg`.
    ///
    /// Example: a record at 12 345 678 µs renders as `[   12.345678] PM: suspend entry`.
    pub fn render(&self) -> String {
        format!(
            "[{:>5}.{:06}] {}",
            self.micros / 1_000_000,
            self.micros % 1_000_000,
            self.message
        )
    }

    /// Whether the message concerns suspend, resume or sleep states.
    ///
    /// Example: `PM: suspend entry (deep)` and `ACPI: PM: Preparing to enter system
    /// sleep state S3` match; `usb 1-1: new device` does not.
    pub fn is_sleep_related(&self) -> bool {
        const MARKERS: [&str; 12] = [
            "pm:",
            "suspend",
            "resume",
            "resuming",
            "s2idle",
            "sleep state",
            "freezing",
            "restarting tasks",
            "low-level resume",
            "waking up from system sleep",
            "acpi: pm",
            "wakeup",
        ];
        let lowered = self.message.to_ascii_lowercase();
        MARKERS.iter().any(|marker| lowered.contains(marker))
    }
}

/// Read access to the kernel message buffer.
pub trait KernelLog {
    /// Every record the kernel still holds, oldest first.
    fn records(&self) -> Result<Vec<KernelRecord>>;
}

/// Parse `/dev/kmsg` text: `level,sequence,micros,flags;message`, with continuation
/// lines (leading space) carrying key=value device data that is skipped.
///
/// Example: `parse_kmsg("6,1,2000000,-;hello\n")` is one record at 2.000000 s.
pub fn parse_kmsg(text: &str) -> Vec<KernelRecord> {
    text.lines()
        .filter(|line| !line.starts_with(' '))
        .filter_map(|line| {
            let (header, message) = line.split_once(';')?;
            let mut fields = header.split(',');
            Some(KernelRecord {
                level: fields.next()?.parse().ok()?,
                sequence: fields.next()?.parse().ok()?,
                micros: fields.next()?.parse().ok()?,
                message: message.to_string(),
            })
        })
        .collect()
}

/// `/dev/kmsg` on Linux, or a file with the same record format.
#[cfg(target_os = "linux")]
pub struct DevKmsg {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl DevKmsg {
    pub fn new(path: impl Into<std::path::PathBuf>) -> DevKmsg {
        DevKmsg { path: path.into() }
    }

    /// The system's kernel log device.
    pub fn system() -> DevKmsg {
        DevKmsg::new("/dev/kmsg")
    }
}

#[cfg(target_os = "linux")]
impl KernelLog for DevKmsg {
    fn records(&self) -> Result<Vec<KernelRecord>> {
        use std::io::{ErrorKind, Read};
        use std::os::unix::fs::OpenOptionsExt;
        /// The buffer holds a few thousand records of at most 1 KiB; stop well above that.
        const MAX_BYTES: usize = 16 << 20;
        let mut device = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(|e| Error::new(Code::Io, format!("{}: {e}", self.path.display())))?;
        let mut text = Vec::new();
        // A read smaller than a record fails with EINVAL, so give it room.
        let mut record = [0u8; 16 << 10];
        while text.len() < MAX_BYTES {
            match device.read(&mut record) {
                Ok(0) => break,
                Ok(length) => text.extend_from_slice(&record[..length]),
                // End of the buffer for a non-blocking descriptor.
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                // The record being read was overwritten; the next read resumes after it.
                Err(e) if e.kind() == ErrorKind::BrokenPipe => continue,
                Err(e) => {
                    return Err(Error::new(
                        Code::Io,
                        format!("{}: {e}", self.path.display()),
                    ));
                }
            }
        }
        Ok(parse_kmsg(&String::from_utf8_lossy(&text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "6,100,5140900,-;PM: suspend entry (deep)\n SUBSYSTEM=acpi\n\
        4,101,5140950,-;ACPI: PM: Preparing to enter system sleep state S3\n\
        6,102,5141000,-;usb 1-1: new high-speed USB device\n\
        garbage without header\n";

    #[test]
    fn parse_skips_continuations_and_malformed_lines() {
        let records = parse_kmsg(SAMPLE);
        assert_eq!(
            records.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            [100, 101, 102],
            "sequence numbers"
        );
        assert_eq!(records[0].message, "PM: suspend entry (deep)");
        assert_eq!(records[0].micros, 5_140_900);
        assert_eq!(records[1].level, 4);
    }

    #[test]
    fn sleep_filter_keeps_power_messages_only() {
        let kept: Vec<_> = parse_kmsg(SAMPLE)
            .into_iter()
            .filter(KernelRecord::is_sleep_related)
            .map(|r| r.sequence)
            .collect();
        assert_eq!(kept, [100, 101]);
    }

    #[test]
    fn render_matches_the_dmesg_layout() {
        let record = &parse_kmsg(SAMPLE)[0];
        assert_eq!(record.render(), "[    5.140900] PM: suspend entry (deep)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dev_kmsg_reads_a_file_with_the_record_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kmsg");
        std::fs::write(&path, SAMPLE).unwrap();
        let records = DevKmsg::new(&path).records().unwrap();
        assert_eq!(records.len(), 3);
        let error = DevKmsg::new(dir.path().join("missing"))
            .records()
            .unwrap_err();
        assert_eq!(error.code, Code::Io, "{error}");
    }
}
