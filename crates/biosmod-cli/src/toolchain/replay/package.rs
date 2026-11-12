//! The `bme_replay` Python package, embedded in the binary.
//!
//! The package is MIT code that drives Unicorn through its Python API; it contains no
//! emulator. bme writes it next to the replay environment (`<data>/replay/package`) and
//! rewrites it when the embedded digest differs from the one on disk, so a new bme release
//! refreshes it without recreating the environment, and an environment chosen with
//! `tools set replay` gets the same package without bme touching it.

use super::super::{check_recovery, replace_dir};
use crate::config::{io_error, write_atomic};
use biosmod_core::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Every file of the package, by name inside `bme_replay/`.
pub const FILES: [(&str, &str); 11] = [
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
/// Example: `package_root(Path::new("/d"))` is `/d/replay/package`.
pub fn package_root(data: &Path) -> PathBuf {
    data.join("replay").join("package")
}

/// Write the package under `data` unless the digest on disk already matches, and return the
/// directory that holds `bme_replay/`.
///
/// Example: the first call writes eleven files and `.digest`; a second call writes nothing.
pub fn ensure(data: &Path) -> Result<PathBuf> {
    let root = package_root(data);
    let wanted = digest();
    let package = root.join("bme_replay");
    if fs::read_to_string(package.join(DIGEST_FILE)).is_ok_and(|have| have.trim() == wanted) {
        return Ok(root);
    }
    let parent = root.parent().expect("package root has a parent");
    fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    check_recovery(&root)?;
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
    write_atomic(&staged_package.join(DIGEST_FILE), wanted.as_bytes())?;
    replace_dir(&staged, &root)?;
    Ok(root)
}

#[cfg(all(test, unix))]
mod tests;
