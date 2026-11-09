//! Bounded, confined zip extraction.

use crate::config::io_error;
use biosmod_core::{Code, Error, Result};
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

/// Extraction limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    pub max_total: u64,
}

impl Limits {
    /// Generous bounds for tool distributions (Ghidra unpacks to about 1 GiB).
    pub const TOOL: Limits = Limits {
        max_entries: 200_000,
        max_total: 6 << 30,
    };
}

fn bad(archive: &Path, message: String) -> Error {
    Error::new(
        Code::ToolSetupFailed,
        format!("{}: {message}", archive.display()),
    )
}

/// Extract `archive` into the existing, empty directory `dest`.
///
/// Refuses absolute or parent-relative names, symlinks, duplicate files and
/// archives beyond `limits`. Unix permission bits are kept (setuid and
/// setgid bits are dropped).
pub fn extract_zip(archive: &Path, dest: &Path, limits: Limits) -> Result<u64> {
    let file = fs::File::open(archive).map_err(|e| io_error(archive, e))?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| bad(archive, format!("not a readable zip: {e}")))?;
    if zip.len() > limits.max_entries {
        return Err(bad(
            archive,
            format!(
                "{} entries exceed the limit of {}",
                zip.len(),
                limits.max_entries
            ),
        ));
    }
    let mut total = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| bad(archive, format!("entry {index}: {e}")))?;
        let name = entry
            .name()
            .map(|n| n.into_owned())
            .unwrap_or_else(|_| format!("entry {index}"));
        let relative = entry
            .enclosed_name()
            .filter(|p| p.components().all(|c| matches!(c, Component::Normal(_))))
            .ok_or_else(|| bad(archive, format!("{name:?}: unsafe path")))?;
        let mode = entry.unix_mode();
        if entry.is_symlink() || mode.is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(bad(
                archive,
                format!("{name:?}: symlinks are not extracted"),
            ));
        }
        let target = dest.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|e| io_error(&target, e))?;
            continue;
        }
        total = total.saturating_add(entry.size());
        if total > limits.max_total {
            return Err(bad(
                archive,
                format!(
                    "unpacked size exceeds the limit of {} bytes",
                    limits.max_total
                ),
            ));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| io_error(&target, e))?;
        let declared = entry.size();
        let written = std::io::copy(&mut (&mut entry).take(declared + 1), &mut out)
            .map_err(|e| bad(archive, format!("{name:?}: {e}")))?;
        if written != declared {
            return Err(bad(
                archive,
                format!("{name:?}: expected {declared} bytes | received {written}"),
            ));
        }
        set_mode(&target, mode)?;
    }
    Ok(total)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = mode else { return Ok(()) };
    fs::set_permissions(path, fs::Permissions::from_mode((mode & 0o777) | 0o600))
        .map_err(|e| io_error(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}
