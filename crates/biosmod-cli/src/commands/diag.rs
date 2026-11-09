//! `diag breadcrumbs` and `dev synthetic`.

use crate::BreadcrumbCommand;
use crate::config::io_error;
use crate::output::Reply;
use crate::publish::check_outputs;
use biosmod_core::breadcrumbs::{self, Breadcrumbs, FIRST_INDEX, LENGTH};
use biosmod_core::synthetic::Fixture;
use biosmod_core::util::unhex;
use biosmod_core::{Code, Error, Result};
use serde_json::json;
use std::fs;
use std::path::Path;

/// Upper-bank CMOS access: select an index through 72h, read the value from 73h.
///
/// Port 70h is never touched (its index register also holds the NMI mask) and
/// no CMOS data byte is ever written.
pub trait UpperCmos {
    fn read(&mut self, index: u8) -> Result<u8>;
}

/// `/dev/port` on Linux.
#[cfg(target_os = "linux")]
pub struct DevPort {
    file: fs::File,
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl DevPort {
    pub fn open(path: &Path) -> Result<DevPort> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    " (run as root: sudo bme diag breadcrumbs read)"
                } else {
                    ""
                };
                Error::new(Code::Io, format!("{}: {e}{hint}", path.display()))
            })?;
        Ok(DevPort {
            file,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(target_os = "linux")]
impl UpperCmos for DevPort {
    fn read(&mut self, index: u8) -> Result<u8> {
        use std::os::unix::fs::FileExt;
        self.file
            .write_at(&[index], 0x72)
            .map_err(|e| io_error(&self.path, e))?;
        let mut value = [0u8];
        self.file
            .read_at(&mut value, 0x73)
            .map_err(|e| io_error(&self.path, e))?;
        Ok(value[0])
    }
}

/// Read E0-E9.
pub fn read_all(cmos: &mut dyn UpperCmos) -> Result<Vec<u8>> {
    (0..LENGTH as u8)
        .map(|i| cmos.read(FIRST_INDEX + i))
        .collect()
}

fn render(info: &Breadcrumbs) -> String {
    let Some(active) = &info.active else {
        return format!(
            "not armed (state {:#04x}): patched firmware not booted yet, or CMOS cleared\n",
            info.state
        );
    };
    let failures = info.failures.unwrap_or(0);
    let saturated = if failures == 0xFF { " (saturated)" } else { "" };
    let mut text = format!(
        "stored MRC pass: {}, pass ended: {}\nfailed MRC passes since arming: {failures}{saturated}\n",
        active.describe(),
        info.pass_ended.unwrap_or(false)
    );
    if let Some(last) = &info.last_failure {
        text += &format!("last failed pass stopped at: {}\n", last.describe());
    }
    text
}

fn reply(raw: &[u8]) -> Result<Reply> {
    let info = breadcrumbs::decode(raw)?;
    let text = render(&info);
    Ok(Reply::new(
        json!({"raw": biosmod_core::util::hex(raw), "breadcrumbs": info}),
        text,
    ))
}

pub fn breadcrumbs(command: BreadcrumbCommand) -> Result<Reply> {
    match command {
        BreadcrumbCommand::Decode { hex } => {
            let joined: String = hex
                .concat()
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
                .collect();
            let raw = unhex(&joined)
                .map_err(|e| Error::new(Code::Usage, format!("breadcrumbs: {}", e.message)))?;
            reply(&raw)
        }
        BreadcrumbCommand::Read { device } => read_device(&device),
    }
}

#[cfg(target_os = "linux")]
fn read_device(device: &Path) -> Result<Reply> {
    let raw = read_all(&mut DevPort::open(device)?)?;
    reply(&raw)
}

#[cfg(not(target_os = "linux"))]
fn read_device(_device: &Path) -> Result<Reply> {
    Err(Error::new(
        Code::PlatformUnsupported,
        "diag breadcrumbs read: only Linux /dev/port is supported; read E0-E9 another way and use `decode`",
    ))
}

/// Write `synthetic.bin` and a `catalog/` directory to try every command safely.
pub fn synthetic(output: &Path) -> Result<Reply> {
    if fs::symlink_metadata(output).is_ok() {
        return Err(Error::new(
            Code::OutputExists,
            format!(
                "{}: already exists; choose a new directory",
                output.display()
            ),
        ));
    }
    fs::create_dir_all(output).map_err(|e| io_error(output, e))?;
    let fixture = Fixture::new(0x07);
    let image = output.join("synthetic.bin");
    check_outputs(&[&image], &[])?;
    fs::write(&image, &fixture.image).map_err(|e| io_error(&image, e))?;
    let catalog = output.join("catalog");
    for (path, bytes) in fixture.catalog_files() {
        let target = catalog.join(&path);
        fs::create_dir_all(target.parent().expect("has parent"))
            .map_err(|e| io_error(&target, e))?;
        fs::write(&target, bytes).map_err(|e| io_error(&target, e))?;
    }
    let text = format!(
        "Wrote {} and {}\nTry: bme scan {} --catalog {} --allow-unsigned-local\n",
        image.display(),
        catalog.display(),
        image.display(),
        catalog.display()
    );
    Ok(Reply::new(
        json!({"image": image, "catalog": catalog}),
        text,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upper CMOS bank with fixed contents; records every index it is asked for.
    struct FakeCmos {
        bank: [u8; 128],
        asked: Vec<u8>,
    }

    impl UpperCmos for FakeCmos {
        fn read(&mut self, index: u8) -> Result<u8> {
            self.asked.push(index);
            Ok(self.bank[usize::from(index - 0x80)])
        }
    }

    #[test]
    fn reads_exactly_e0_to_e9() {
        let mut bank = [0u8; 128];
        bank[0x60..0x6A].copy_from_slice(&[0xA1, 0, 0, 0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0]);
        let mut cmos = FakeCmos {
            bank,
            asked: vec![],
        };
        let raw = read_all(&mut cmos).unwrap();
        assert_eq!(cmos.asked, (0xE0..=0xE9).collect::<Vec<u8>>());
        let text = render(&breadcrumbs::decode(&raw).unwrap());
        assert_eq!(
            text,
            "stored MRC pass: BF/00 location 0000, pass ended: true\nfailed MRC passes since arming: 0\n"
        );
    }

    #[test]
    fn decode_accepts_spaced_hex_and_rejects_bad_length() {
        let ok = breadcrumbs(BreadcrumbCommand::Decode {
            hex: vec!["a1 00 00 00 bf".into(), "ff:ff:ff:ff,00".into()],
        })
        .unwrap();
        assert_eq!(ok.data["breadcrumbs"]["armed"], true);
        let error = breadcrumbs(BreadcrumbCommand::Decode {
            hex: vec!["a1".into()],
        })
        .unwrap_err();
        assert_eq!(error.code, Code::Usage, "{error}");
    }
}
