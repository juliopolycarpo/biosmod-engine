//! Reproducible build-input fingerprint shared by the build script and its tests.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

/// Enumerate files and directories beneath relative inputs without following symlinks.
///
/// Example: `collect_inputs(root, &["crates/biosmod-core/src"])` includes every source file.
pub fn collect_inputs(root: &Path, inputs: &[&str]) -> io::Result<Vec<PathBuf>> {
    fn visit(root: &Path, relative: &Path, entries: &mut Vec<PathBuf>) -> io::Result<()> {
        let path = root.join(relative);
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{}: symlinks are not supported in build identity inputs",
                    relative.display()
                ),
            ));
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{}: expected file or directory", relative.display()),
            ));
        }
        entries.push(relative.to_path_buf());
        if kind.is_dir() {
            for entry in fs::read_dir(&path)? {
                visit(root, &relative.join(entry?.file_name()), entries)?;
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    for input in inputs {
        visit(root, Path::new(input), &mut entries)?;
    }
    entries.sort();
    entries.dedup();
    Ok(entries)
}

/// Return native tool settings recognized for Cargo's host and target triples.
///
/// Example: an `x86_64-unknown-linux-gnu` target watches `CC_x86_64_unknown_linux_gnu`.
pub fn native_setting_names(host: &str, target: &str) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for variable in [
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "ARFLAGS",
        "RANLIBFLAGS",
    ] {
        names.insert(variable.to_string());
        names.insert(format!("HOST_{variable}"));
        names.insert(format!("TARGET_{variable}"));
        for triple in [host, target] {
            names.insert(format!("{variable}_{triple}"));
            names.insert(format!("{variable}_{}", triple.replace(['-', '.'], "_")));
        }
    }
    names
}

/// Decode a captured environment setting without losing information.
///
/// Example: a non-UTF-8 compiler path returns an error naming the setting.
pub fn decode_setting(name: &str, value: std::ffi::OsString) -> io::Result<String> {
    value.into_string().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("{name}: build identity setting must be UTF-8"),
        )
    })
}

/// Replace checkout-root occurrences in a build setting with a stable marker.
///
/// Example: a flag containing `/work/project` normalizes the root to `<workspace>`.
pub fn normalize_setting(root: &Path, value: &str) -> String {
    value.replace(&root.to_string_lossy().to_string(), "<workspace>")
}

/// Hash relative input names, contents, and named build settings with length framing.
///
/// Example: identical inputs under two checkout roots produce the same digest.
pub fn fingerprint(
    root: &Path,
    entries: &[PathBuf],
    settings: &BTreeMap<String, String>,
) -> io::Result<String> {
    fn frame(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    frame(&mut hash, b"biosmod-engine-build-inputs-v1");
    for relative in entries {
        let path = root.join(relative);
        let name = relative
            .components()
            .map(|part| {
                part.as_os_str().to_str().ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "build identity input path is not UTF-8",
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("/");
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{name}: symlink in build identity inputs"),
            ));
        }
        frame(
            &mut hash,
            if kind.is_dir() { b"directory" } else { b"file" },
        );
        frame(&mut hash, name.as_bytes());
        if kind.is_file() {
            frame(&mut hash, &fs::read(path)?);
        } else if !kind.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{name}: expected file or directory"),
            ));
        }
    }
    for (name, value) in settings {
        frame(&mut hash, b"setting");
        frame(&mut hash, name.as_bytes());
        frame(&mut hash, value.as_bytes());
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
