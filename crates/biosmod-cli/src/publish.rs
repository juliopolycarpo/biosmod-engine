//! Exclusive, staged publication of an image and its manifest.
//!
//! Both files are written to temporary files in the output directory and
//! synced first. The manifest is linked into place before the image, both
//! without replacing existing files, so an image never appears without its
//! manifest. If the image cannot be published, the manifest is removed again;
//! if that also fails, the result is `PUBLISH_INCOMPLETE` naming what remains.

use crate::config::io_error;
use biosmod_core::{Code, Error, Result};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Moves a staged file into place without replacing an existing one.
pub trait Persist {
    fn persist(
        &self,
        staged: NamedTempFile,
        target: &Path,
    ) -> std::result::Result<(), (NamedTempFile, std::io::Error)>;
    fn remove(&self, path: &Path) -> std::io::Result<()>;
}

/// The real filesystem.
pub struct Filesystem;

impl Persist for Filesystem {
    fn persist(
        &self,
        staged: NamedTempFile,
        target: &Path,
    ) -> std::result::Result<(), (NamedTempFile, std::io::Error)> {
        staged
            .persist_noclobber(target)
            .map(|_| ())
            .map_err(|e| (e.file, e.error))
    }

    fn remove(&self, path: &Path) -> std::io::Result<()> {
        fs::remove_file(path)
    }
}

/// The manifest path for an output image: `<output>.manifest.json`.
pub fn manifest_path(output: &Path) -> PathBuf {
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".manifest.json");
    output.with_file_name(name)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Refuse outputs that exist (including dangling symlinks) or alias an input.
pub fn check_outputs(outputs: &[&Path], inputs: &[&Path]) -> Result<()> {
    for (i, output) in outputs.iter().enumerate() {
        if fs::symlink_metadata(output).is_ok() {
            return Err(Error::new(
                Code::OutputExists,
                format!(
                    "{}: already exists; choose a new output name",
                    output.display()
                ),
            ));
        }
        if inputs
            .iter()
            .any(|input| same_file(input, output) || input == output)
            || outputs[..i].contains(output)
        {
            return Err(Error::new(
                Code::OutputExists,
                format!("{}: aliases an input or another output", output.display()),
            ));
        }
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            return Err(Error::new(
                Code::Io,
                format!("{}: output directory does not exist", parent.display()),
            ));
        }
    }
    Ok(())
}

fn stage(target: &Path, bytes: &[u8]) -> Result<NamedTempFile> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::Builder::new()
        .prefix(".bme-staging-")
        .tempfile_in(parent)
        .map_err(|e| io_error(parent, e))?;
    staged
        .write_all(bytes)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|e| io_error(staged.path(), e))?;
    Ok(staged)
}

fn persist_error(target: &Path, error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        Error::new(
            Code::OutputExists,
            format!(
                "{}: appeared during publication; nothing was replaced",
                target.display()
            ),
        )
    } else {
        io_error(target, error)
    }
}

/// Publish `image` at `output` and `manifest` at its manifest path.
pub fn publish(persist: &dyn Persist, output: &Path, image: &[u8], manifest: &[u8]) -> Result<()> {
    let manifest_target = manifest_path(output);
    let staged_manifest = stage(&manifest_target, manifest)?;
    let staged_image = stage(output, image)?;
    persist
        .persist(staged_manifest, &manifest_target)
        .map_err(|(_, e)| persist_error(&manifest_target, e))?;
    let Err((staged_image, error)) = persist.persist(staged_image, output) else {
        sync_parent(output);
        return Ok(());
    };
    let cause = persist_error(output, error);
    if persist.remove(&manifest_target).is_ok() {
        return Err(cause);
    }
    // Keep the verified image bytes recoverable and report every leftover.
    let kept = staged_image
        .keep()
        .map(|(_, p)| p.display().to_string())
        .unwrap_or_default();
    Err(Error::new(
        Code::PublishIncomplete,
        format!(
            "{}; the manifest {} was published but could not be removed",
            cause.message,
            manifest_target.display()
        ),
    )
    .with_details(json!({"manifest": manifest_target.to_string_lossy(), "staged_image": kept, "cause": cause.code})))
}

/// Publish one file at `output` without replacing anything.
///
/// The bytes are staged next to the target and synced before they appear under
/// the final name. Example: `publish_file(Path::new("dump.bin"), &chip_bytes)?`.
pub fn publish_file(output: &Path, bytes: &[u8]) -> Result<()> {
    let staged = stage(output, bytes)?;
    Filesystem
        .persist(staged, output)
        .map_err(|(_, e)| persist_error(output, e))?;
    sync_parent(output);
    Ok(())
}

/// Publish a set of files as a new directory, replacing nothing.
///
/// The directory itself is claimed with an exclusive `create_dir`, so a concurrent
/// creator loses instead of being merged into. Files are written in the order
/// given and each is synced; callers put the file that marks completeness last.
/// On any failure the directory is removed again; if that fails too, the result is
/// `PUBLISH_INCOMPLETE` naming it.
///
/// Example: `publish_directory(Path::new("capture"), &[("a/b.bin", &bytes[..])])?`.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "shared by the Linux commands and the fake-backed tests; other platforms refuse earlier"
    )
)]
pub fn publish_directory(output: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    check_outputs(&[output], &[])?;
    create_new_directory(output)?;
    let written = files.iter().try_for_each(|(relative, bytes)| {
        let target = output.join(relative);
        let parent = target.parent().expect("a file below the output directory");
        fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
            .map_err(|e| io_error(&target, e))
    });
    written.map_err(|cause| remove_failed_directory(output, cause))?;
    sync_parent(output);
    Ok(())
}

/// Create `directory` as a new, empty directory, refusing one that exists.
///
/// The refusal is the kernel's `mkdir` result, so two writers cannot both succeed.
/// The caller fills it and removes it again with [`remove_failed_directory`] if
/// filling fails. Example: `create_new_directory(Path::new("case-dir"))?`.
pub fn create_new_directory(directory: &Path) -> Result<()> {
    fs::create_dir(directory).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::new(
                Code::OutputExists,
                format!(
                    "{}: already exists; choose a new output name",
                    directory.display()
                ),
            )
        } else {
            io_error(directory, error)
        }
    })
}

/// Remove a directory this process created after filling it failed.
///
/// Returns `cause` unchanged, or `PUBLISH_INCOMPLETE` naming the directory when it
/// cannot be removed either. Example: `Err(remove_failed_directory(dir, error))`.
pub fn remove_failed_directory(directory: &Path, cause: Error) -> Error {
    match fs::remove_dir_all(directory) {
        Ok(()) => cause,
        Err(error) => Error::new(
            Code::PublishIncomplete,
            format!(
                "{}; the partly written directory {} remains ({error})",
                cause.message,
                directory.display()
            ),
        )
        .with_details(json!({"directory": directory.to_string_lossy(), "cause": cause.code})),
    }
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(dir) = fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Fails to persist the image (the second call); optionally also fails removal.
    struct FailingImage {
        calls: Cell<u32>,
        removal_fails: bool,
    }

    impl Persist for FailingImage {
        fn persist(
            &self,
            staged: NamedTempFile,
            target: &Path,
        ) -> std::result::Result<(), (NamedTempFile, std::io::Error)> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == 2 {
                return Err((staged, std::io::Error::other("simulated disk failure")));
            }
            Filesystem.persist(staged, target)
        }

        fn remove(&self, path: &Path) -> std::io::Result<()> {
            if self.removal_fails {
                Err(std::io::Error::other("simulated removal failure"))
            } else {
                fs::remove_file(path)
            }
        }
    }

    #[test]
    fn publishes_both_files_exclusively() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.rom");
        publish(&Filesystem, &out, b"image", b"{}").unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"image");
        assert_eq!(fs::read(manifest_path(&out)).unwrap(), b"{}");
        let error = publish(&Filesystem, &out, b"other", b"{}").unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert_eq!(fs::read(&out).unwrap(), b"image");
    }

    #[test]
    fn new_directory_is_created_once_and_refuses_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("case");
        create_new_directory(&target).unwrap();
        assert!(target.is_dir());
        let error = create_new_directory(&target).unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        let missing_parent = dir.path().join("absent/case");
        assert_eq!(
            create_new_directory(&missing_parent).unwrap_err().code,
            Code::Io
        );
    }

    #[test]
    fn failed_directory_is_removed_and_the_cause_returned() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("case");
        create_new_directory(&target).unwrap();
        fs::write(target.join("partial.json"), b"{}").unwrap();
        let returned = remove_failed_directory(&target, Error::new(Code::Io, "disk full"));
        assert_eq!(returned.code, Code::Io, "{returned}");
        assert!(!target.exists(), "{}: expected removal", target.display());
        let gone = remove_failed_directory(&target, Error::new(Code::Io, "again"));
        assert_eq!(
            gone.code,
            Code::PublishIncomplete,
            "(already removed directory): expected PUBLISH_INCOMPLETE | {gone}"
        );
    }

    #[test]
    fn single_file_publication_never_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dump.bin");
        publish_file(&out, b"first").unwrap();
        let error = publish_file(&out, b"second").unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert_eq!(fs::read(&out).unwrap(), b"first");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "(output directory): expected only dump.bin | staged files remain"
        );
    }

    #[test]
    fn image_failure_rolls_back_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.rom");
        let error = publish(
            &FailingImage {
                calls: Cell::new(0),
                removal_fails: false,
            },
            &out,
            b"image",
            b"{}",
        )
        .unwrap_err();
        assert_eq!(error.code, Code::Io, "{error}");
        assert!(!out.exists() && !manifest_path(&out).exists());
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "staged files are cleaned up"
        );
    }

    #[test]
    fn failed_rollback_reports_incomplete_with_recoverable_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.rom");
        let error = publish(
            &FailingImage {
                calls: Cell::new(0),
                removal_fails: true,
            },
            &out,
            b"image",
            b"{}",
        )
        .unwrap_err();
        assert_eq!(error.code, Code::PublishIncomplete, "{error}");
        let details = error.details.unwrap();
        let staged = PathBuf::from(details["staged_image"].as_str().unwrap());
        assert_eq!(fs::read(staged).unwrap(), b"image");
        assert!(manifest_path(&out).exists() && !out.exists());
    }

    // Linux permits raw-byte filenames; the macOS CI filesystem rejects them.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_failed_rollback_reports_remaining_artifacts() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let out = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"out-\xff.rom".to_vec()));
        let error = publish(
            &FailingImage {
                calls: Cell::new(0),
                removal_fails: true,
            },
            &out,
            b"image",
            b"{}",
        )
        .unwrap_err();
        assert_eq!(error.code, Code::PublishIncomplete, "{error}");
        assert!(manifest_path(&out).exists());
        let details = error.details.unwrap();
        assert!(details["manifest"].as_str().unwrap().contains("out-"));
        assert_eq!(
            fs::read(details["staged_image"].as_str().unwrap()).unwrap(),
            b"image"
        );
    }

    #[test]
    fn outputs_must_be_new_and_distinct_from_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.rom");
        fs::write(&input, b"x").unwrap();
        assert_eq!(
            check_outputs(&[&input], &[&input]).unwrap_err().code,
            Code::OutputExists
        );
        let fresh = dir.path().join("new.rom");
        assert!(check_outputs(&[&fresh], &[&input]).is_ok());
        #[cfg(unix)]
        {
            let link = dir.path().join("dangling");
            std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
            assert_eq!(
                check_outputs(&[&link], &[&input]).unwrap_err().code,
                Code::OutputExists
            );
        }
    }

    #[test]
    fn publish_directory_writes_nested_files_and_refuses_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("capture");
        publish_directory(&target, &[("a/b/c.bin", b"one"), ("done.json", b"{}")]).unwrap();
        assert_eq!(fs::read(target.join("a/b/c.bin")).unwrap(), b"one");
        let error = publish_directory(&target, &[("x", b"y")]).unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert!(
            !target.join("x").exists(),
            "an existing directory is not merged into"
        );
    }

    #[test]
    fn publish_directory_removes_what_it_created_when_a_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("capture");
        // "a" is a file when "a/b" is created, so the second write fails.
        let error = publish_directory(&target, &[("a", b"1"), ("a/b", b"2")]).unwrap_err();
        assert_eq!(error.code, Code::Io, "{error}");
        assert!(
            !target.exists(),
            "(publish): expected {} removed",
            target.display()
        );
    }
}
