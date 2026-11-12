//! x86 I/O port access.

use biosmod_core::Result;

/// Byte-wide access to I/O ports.
///
/// Callers decide which ports they touch and document why each write is only an
/// access selector. Tests use fakes that model the device behind the ports.
pub trait PortIo {
    fn read(&mut self, port: u16) -> Result<u8>;
    fn write(&mut self, port: u16, value: u8) -> Result<()>;
}

/// `/dev/port` on Linux: the file offset is the port number.
#[cfg(target_os = "linux")]
pub struct DevPort {
    file: std::fs::File,
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl DevPort {
    /// Open `path` read-write. Needs root (or CAP_SYS_RAWIO).
    pub fn open(path: &std::path::Path, root_hint: &str) -> Result<DevPort> {
        use biosmod_core::{Code, Error};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!(" (run as root: {root_hint})")
                } else {
                    String::new()
                };
                Error::new(Code::Io, format!("{}: {e}{hint}", path.display()))
            })?;
        Ok(DevPort {
            file,
            path: path.to_path_buf(),
        })
    }

    fn fail(&self, error: std::io::Error) -> biosmod_core::Error {
        biosmod_core::Error::new(
            biosmod_core::Code::Io,
            format!("{}: {error}", self.path.display()),
        )
    }
}

#[cfg(target_os = "linux")]
impl PortIo for DevPort {
    fn read(&mut self, port: u16) -> Result<u8> {
        use std::os::unix::fs::FileExt;
        let mut value = [0u8];
        self.file
            .read_exact_at(&mut value, u64::from(port))
            .map_err(|e| self.fail(e))?;
        Ok(value[0])
    }

    fn write(&mut self, port: u16, value: u8) -> Result<()> {
        use std::os::unix::fs::FileExt;
        self.file
            .write_all_at(&[value], u64::from(port))
            .map_err(|e| self.fail(e))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A regular file stands in for `/dev/port`: offset N is port N.
    #[test]
    fn dev_port_maps_offsets_to_ports_and_names_the_device_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("port");
        std::fs::write(&path, vec![0u8; 0x100]).unwrap();
        let mut ports = DevPort::open(&path, "sudo bme").unwrap();
        ports.write(0x72, 0xE0).unwrap();
        assert_eq!(ports.read(0x72).unwrap(), 0xE0);
        let error = ports.read(0x4000).unwrap_err();
        assert!(
            error.message.starts_with(&path.display().to_string()),
            "{error}"
        );
        let error = DevPort::open(&dir.path().join("none"), "sudo bme")
            .err()
            .unwrap();
        assert_eq!(error.code, biosmod_core::Code::Io);
    }
}
