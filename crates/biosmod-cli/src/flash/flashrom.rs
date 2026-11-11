//! flashrom lookup, command lines and output parsing.
//!
//! bme never talks to a programmer itself. Every chip access is one flashrom
//! process, built here so tests can assert the exact arguments.

use crate::toolchain::Invocation;
use biosmod_core::firmware::Region;
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable naming the flashrom executable (portable setups and tests).
pub const FLASHROM_OVERRIDE: &str = "BME_FLASHROM";

/// Directories searched after `PATH`: unprivileged shells often lack the sbin directories.
pub const SBIN_DIRECTORIES: [&str; 3] = ["/usr/sbin", "/sbin", "/usr/local/sbin"];

/// A full read of a 16 MiB chip takes minutes on a CH341A.
const READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Erase, write and flashrom's own verify. A stuck write is not helped by killing it early.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the flashrom executable was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashromOrigin {
    /// The `BME_FLASHROM` environment variable.
    Environment,
    /// `tools.flashrom` in the per-user configuration.
    Config,
    /// `PATH` or one of the sbin directories.
    Path,
}

impl FlashromOrigin {
    /// The label shown in `tools status`.
    pub fn label(self) -> &'static str {
        match self {
            FlashromOrigin::Environment => FLASHROM_OVERRIDE,
            FlashromOrigin::Config => "config",
            FlashromOrigin::Path => "PATH",
        }
    }
}

/// Find flashrom: `BME_FLASHROM`, then the configured path, then `PATH`, then the sbin directories.
///
/// Example: `resolve_flashrom(&|_| None, Some(Path::new("/opt/fr/flashrom")))` returns that path
/// with [`FlashromOrigin::Config`] when no environment override is set.
pub fn resolve_flashrom(
    get: &dyn Fn(&str) -> Option<OsString>,
    configured: Option<&Path>,
) -> Option<(PathBuf, FlashromOrigin)> {
    resolve_flashrom_in(get, configured, &SBIN_DIRECTORIES)
}

/// [`resolve_flashrom`] with the directories searched after `PATH` named by the caller.
///
/// Example: `resolve_flashrom_in(&|_| None, None, &[])` is `None` on every host.
pub fn resolve_flashrom_in(
    get: &dyn Fn(&str) -> Option<OsString>,
    configured: Option<&Path>,
    sbin: &[&str],
) -> Option<(PathBuf, FlashromOrigin)> {
    if let Some(chosen) = get(FLASHROM_OVERRIDE).filter(|value| !value.is_empty()) {
        return Some((PathBuf::from(chosen), FlashromOrigin::Environment));
    }
    if let Some(chosen) = configured {
        return Some((chosen.to_path_buf(), FlashromOrigin::Config));
    }
    let name = format!("flashrom{}", std::env::consts::EXE_SUFFIX);
    let path = get("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(sbin.iter().map(PathBuf::from))
        .map(|directory| directory.join(&name))
        .find(|candidate| candidate.is_file())
        .map(|found| (found, FlashromOrigin::Path))
}

/// Accept a flashrom programmer such as `internal`, `ch341a_spi` or `linux_mtd:dev=0`.
///
/// The value becomes one argument of a possibly privileged process, so it may not
/// look like an option or carry whitespace.
/// Example: `validate_programmer("ft2232_spi:type=2232H,port=A")?`.
pub fn validate_programmer(text: &str) -> Result<()> {
    let name = text.split(':').next().unwrap_or_default();
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"_:=,./-".contains(&byte);
    if name.is_empty()
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || !text.bytes().all(plain)
    {
        return Err(Error::new(
            Code::Usage,
            format!(
                "programmer {text:?}: expected a flashrom programmer such as internal, ch341a_spi or linux_mtd:dev=0"
            ),
        ));
    }
    Ok(())
}

/// Accept a flashrom chip definition name such as `W25Q128.V` or `MX25L6436E/MX25L6445E`.
///
/// Example: `validate_chip("W25Q128.V")?`.
pub fn validate_chip(text: &str) -> Result<()> {
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"._/+()- ".contains(&byte);
    if text.is_empty() || text.starts_with('-') || !text.bytes().all(plain) {
        return Err(Error::new(
            Code::Usage,
            format!(
                "chip {text:?}: expected a flashrom chip definition name such as W25Q128.V (see `bme flash probe`)"
            ),
        ));
    }
    Ok(())
}

/// One chip definition flashrom matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Chip {
    pub vendor: String,
    pub name: String,
    pub size_bytes: u64,
    pub bus: String,
}

/// Collect the `Found <vendor> flash chip "<name>" (<size> kB, <bus>)` lines of a flashrom run.
///
/// Example: `Found Winbond flash chip "W25Q128.V" (16384 kB, SPI) on ch341a_spi.` yields one
/// chip of 16 MiB. A chip matching several definitions yields one entry per definition.
pub fn parse_chips(output: &str) -> Vec<Chip> {
    let mut chips: Vec<Chip> = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("Found ") else {
            continue;
        };
        let Some((vendor, rest)) = rest.split_once(" flash chip \"") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once('"') else {
            continue;
        };
        let Some((size, bus)) = rest
            .trim_start()
            .strip_prefix('(')
            .and_then(|inner| inner.split_once(')'))
            .and_then(|(inner, _)| inner.split_once(" kB, "))
        else {
            continue;
        };
        let Ok(kilobytes) = size.trim().parse::<u64>() else {
            continue;
        };
        let chip = Chip {
            vendor: vendor.to_string(),
            name: name.to_string(),
            size_bytes: kilobytes * 1024,
            bus: bus.trim().to_string(),
        };
        if !chips.contains(&chip) {
            chips.push(chip);
        }
    }
    chips
}

/// The version from flashrom's banner, e.g. `1.6.0` from `flashrom v1.6.0 on Linux ...`.
///
/// Example: `parse_version("flashrom v1.6.0 on Linux 7.0 (x86_64)")` is `Some("1.6.0")`.
pub fn parse_version(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("flashrom ")?;
        let word = rest.split_whitespace().next()?;
        let version = word.strip_prefix('v').unwrap_or(word);
        version
            .starts_with(|c: char| c.is_ascii_digit())
            .then(|| version.to_string())
    })
}

/// A flashrom layout file: one `start:end name` line per region, end inclusive.
///
/// Example: a descriptor at 0..0x1000 becomes `00000000:00000fff descriptor`.
pub fn layout_text(regions: &[Region]) -> String {
    regions
        .iter()
        .map(|region| {
            format!(
                "{:08x}:{:08x} {}\n",
                region.start,
                region.end - 1,
                region.name
            )
        })
        .collect()
}

/// Which programmer and chip definition a flashrom process addresses.
#[derive(Debug, Clone)]
pub struct Target {
    pub flashrom: PathBuf,
    pub programmer: String,
    pub chip: Option<String>,
}

/// Restrict a read or write to named regions of a layout file.
#[derive(Debug, Clone, Copy)]
pub struct Selection<'a> {
    pub layout: &'a Path,
    pub regions: &'a [&'a str],
}

/// What one flashrom process does.
#[derive(Debug, Clone, Copy)]
pub enum Operation<'a> {
    /// Print the banner only.
    Version,
    /// Detect the chip without reading it.
    Probe,
    Read(&'a Path),
    Write(&'a Path),
}

impl Target {
    /// Build one flashrom command line.
    ///
    /// Example: reading the `bios` region through a CH341A gives
    /// `flashrom -p ch341a_spi -l layout.txt -i bios -r dump.bin`.
    pub fn invocation(&self, selection: Option<Selection>, operation: Operation) -> Invocation {
        let command = Invocation::new(&self.flashrom);
        if matches!(operation, Operation::Version) {
            return command.arg("--version").timeout(PROBE_TIMEOUT);
        }
        let mut command = command.arg("-p").arg(&self.programmer);
        if let Some(chip) = &self.chip {
            command = command.arg("-c").arg(chip);
        }
        if let Some(selection) = selection {
            command = command.arg("-l").arg(selection.layout);
            for region in selection.regions {
                command = command.arg("-i").arg(region);
            }
            if matches!(operation, Operation::Write(_)) {
                // Keep selected-region verification without reading locked regions (ME).
                command = command.arg("--noverify-all");
            }
        }
        match operation {
            Operation::Version | Operation::Probe => command.timeout(PROBE_TIMEOUT),
            Operation::Read(file) => command.arg("-r").arg(file).timeout(READ_TIMEOUT),
            Operation::Write(file) => command.arg("-w").arg(file).timeout(WRITE_TIMEOUT),
        }
    }
}
