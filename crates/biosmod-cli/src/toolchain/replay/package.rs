//! The `bme_replay` Python package, embedded in the binary.
//!
//! The package is MIT code that drives Unicorn through its Python API; it contains no
//! emulator. bme writes it next to the replay environment, in a directory named after the
//! embedded digest (`<data>/replay/package-<digest>`). A new bme release writes a new
//! directory and never renames or rewrites an existing one, so a run that is already using
//! a package, and two runs that start together, cannot break each other. An environment
//! chosen with `tools set replay` gets the same package without bme touching it.

use crate::config::{io_error, write_atomic};
use biosmod_core::{Code, Error, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Every file of the package, by name inside `bme_replay/`.
pub const FILES: [(&str, &str); 12] = [
    (
        "__init__.py",
        include_str!("../../../../../tools/replay/bme_replay/__init__.py"),
    ),
    (
        "__main__.py",
        include_str!("../../../../../tools/replay/bme_replay/__main__.py"),
    ),
    (
        "devices.py",
        include_str!("../../../../../tools/replay/bme_replay/devices.py"),
    ),
    (
        "errors.py",
        include_str!("../../../../../tools/replay/bme_replay/errors.py"),
    ),
    (
        "machine.py",
        include_str!("../../../../../tools/replay/bme_replay/machine.py"),
    ),
    (
        "msr.py",
        include_str!("../../../../../tools/replay/bme_replay/msr.py"),
    ),
    (
        "pe.py",
        include_str!("../../../../../tools/replay/bme_replay/pe.py"),
    ),
    (
        "ports.py",
        include_str!("../../../../../tools/replay/bme_replay/ports.py"),
    ),
    (
        "scenario.py",
        include_str!("../../../../../tools/replay/bme_replay/scenario.py"),
    ),
    (
        "services.py",
        include_str!("../../../../../tools/replay/bme_replay/services.py"),
    ),
    (
        "smbus.py",
        include_str!("../../../../../tools/replay/bme_replay/smbus.py"),
    ),
    (
        "trace.py",
        include_str!("../../../../../tools/replay/bme_replay/trace.py"),
    ),
];

/// File inside `bme_replay/` that records which embedded digest wrote the directory.
const DIGEST_FILE: &str = ".digest";

/// SHA-256 over every file name and body, in table order.
///
/// Example: `digest()` is 64 lowercase hex characters and changes when any embedded file does.
pub fn digest() -> String {
    let mut hash = Sha256::new();
    for (name, body) in FILES {
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((body.len() as u64).to_le_bytes());
        hash.update(body.as_bytes());
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Where the package lives for a data directory: the directory that goes on `sys.path`.
///
/// Example: `package_root(Path::new("/d"))` is `/d/replay/package-<digest>`.
pub fn package_root(data: &Path) -> PathBuf {
    data.join("replay").join(format!("package-{}", digest()))
}

/// Whether `root` holds a complete package written for this digest.
fn complete(root: &Path) -> bool {
    fs::read_to_string(root.join("bme_replay").join(DIGEST_FILE))
        .is_ok_and(|have| have.trim() == digest())
}

/// Write the package under `data` unless its digest directory exists, and return the
/// directory that holds `bme_replay/`.
///
/// The files go to a staging directory first and one `rename` publishes it, so a reader sees
/// either nothing or a complete package. When another run publishes first, its copy is the
/// same content and is used.
///
/// Example: the first call writes eleven files and `.digest`; a second call writes nothing.
pub fn ensure(data: &Path) -> Result<PathBuf> {
    let root = package_root(data);
    if complete(&root) {
        return Ok(root);
    }
    let parent = root.parent().expect("package root has a parent");
    fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(parent)
        .map_err(|e| io_error(parent, e))?;
    let staged = staging.path().join("package");
    let staged_package = staged.join("bme_replay");
    fs::create_dir_all(&staged_package).map_err(|e| io_error(&staged_package, e))?;
    for (name, body) in FILES {
        write_atomic(&staged_package.join(name), body.as_bytes())?;
    }
    write_atomic(&staged_package.join(DIGEST_FILE), digest().as_bytes())?;
    // The rename fails when the target exists; that is only fine if it is a complete copy.
    match fs::rename(&staged, &root) {
        Ok(()) => Ok(root),
        Err(_) if complete(&root) => Ok(root),
        Err(e) if root.exists() => Err(Error::new(
            Code::ToolFailed,
            format!(
                "{}: expected a complete replay package with digest {} | received a directory without it ({e})",
                root.display(),
                digest()
            ),
        )),
        Err(e) => Err(io_error(&root, e)),
    }
}

#[cfg(all(test, unix))]
mod tests;
