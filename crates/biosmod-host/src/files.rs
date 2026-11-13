//! Reading sysfs and procfs.

use std::io::{self, Read};
use std::path::PathBuf;

/// Largest single file read. sysfs reports misleading sizes, so reads go to EOF
/// under this cap; ACPI tables are a few hundred KiB at most.
pub const MAX_FILE_BYTES: u64 = 16 << 20;

/// What a directory entry is, without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    /// Symlink, device node or anything else; never followed or copied.
    Other,
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
}

/// Read access to the host's files by absolute path such as `/sys/power/state`.
///
/// Example: `files.read("/proc/sys/kernel/random/boot_id")`.
pub trait HostFiles {
    /// The whole file, up to [`MAX_FILE_BYTES`].
    fn read(&self, path: &str) -> io::Result<Vec<u8>>;
    /// The entries of a directory, sorted by name.
    fn entries(&self, path: &str) -> io::Result<Vec<DirEntry>>;
}

/// [`HostFiles`] over a directory standing in for `/`; the real system uses `/`.
#[derive(Debug, Clone)]
pub struct RootedFiles {
    root: PathBuf,
}

impl RootedFiles {
    /// Files below `root`, which tests point at a temporary tree.
    pub fn new(root: impl Into<PathBuf>) -> RootedFiles {
        RootedFiles { root: root.into() }
    }

    /// The machine bme runs on.
    pub fn system() -> RootedFiles {
        RootedFiles::new("/")
    }

    fn resolve(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }
}

impl HostFiles for RootedFiles {
    fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let file = std::fs::File::open(self.resolve(path))?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{path}: expected at most {MAX_FILE_BYTES} bytes | received more"),
            ));
        }
        Ok(bytes)
    }

    fn entries(&self, path: &str) -> io::Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(self.resolve(path))? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let kind = if file_type.is_file() {
                EntryKind::File
            } else if file_type.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::Other
            };
            entries.push(DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

/// A file's text with surrounding whitespace removed; `None` when it is missing,
/// unreadable or empty.
///
/// Example: `read_trimmed(&files, "/sys/class/dmi/id/board_name")` is `Some("E5-MR9A PRO")`.
pub fn read_trimmed(files: &dyn HostFiles, path: &str) -> Option<String> {
    let bytes = files.read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakeSysfs;

    #[test]
    fn rooted_files_read_and_list_a_tree_without_following_symlinks() {
        let sysfs = FakeSysfs::new()
            .file("sys/a/two", "2")
            .file("sys/a/one", "1")
            .directory("sys/a/sub");
        #[cfg(unix)]
        std::os::unix::fs::symlink("one", sysfs.path("sys/a/link")).unwrap();
        let files = sysfs.files();
        let entries = files.entries("/sys/a").unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        #[cfg(unix)]
        {
            assert_eq!(names, ["link", "one", "sub", "two"]);
            assert_eq!(entries[0].kind, EntryKind::Other);
        }
        #[cfg(not(unix))]
        assert_eq!(names, ["one", "sub", "two"]);
        let sub = entries.iter().find(|e| e.name == "sub").unwrap();
        assert_eq!(sub.kind, EntryKind::Directory);
        assert_eq!(files.read("/sys/a/one").unwrap(), b"1");
    }

    #[test]
    fn read_trimmed_drops_whitespace_and_hides_missing_or_empty_files() {
        let sysfs = FakeSysfs::new()
            .file("sys/x", " value\n")
            .file("sys/empty", "\n");
        let files = sysfs.files();
        assert_eq!(read_trimmed(&files, "/sys/x").as_deref(), Some("value"));
        assert_eq!(read_trimmed(&files, "/sys/empty"), None);
        assert_eq!(read_trimmed(&files, "/sys/missing"), None);
    }

    #[test]
    fn oversized_files_are_refused_with_the_path() {
        let sysfs = FakeSysfs::new().file("sys/big", vec![0u8; MAX_FILE_BYTES as usize + 1]);
        let error = sysfs.files().read("/sys/big").unwrap_err();
        assert!(
            error.to_string().starts_with("/sys/big: expected at most"),
            "{error}"
        );
    }
}
