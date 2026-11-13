//! A `bme diag acpi capture` directory as an input of `compare --acpi`.
//!
//! The directory is trusted only as far as its manifest: every table file the manifest lists
//! under `acpi/tables/` is read, checked against the recorded SHA-256 and then handed to the
//! core, which keeps the DSDT and SSDT tables. A directory without `evidence.json` is an
//! interrupted capture and is refused.

use super::{MAX_IMAGE_BYTES, read_bounded};
use biosmod_core::compare::acpi::{CaptureTables, tables_from_capture};
use biosmod_core::util::sha256_hex;
use biosmod_core::{Code, Error, Result};
use biosmod_host::bundle::{EVIDENCE_FILE, MANIFEST_FILE, MANIFEST_SCHEMA};
use serde_json::Value;
use std::path::{Component, Path};

/// Where the captured table files live inside the capture directory.
const TABLES_PREFIX: &str = "acpi/tables/";
/// Largest manifest accepted; a real one is a few KiB.
const MAX_MANIFEST_BYTES: u64 = 8 << 20;

fn invalid(dir: &Path, what: impl std::fmt::Display) -> Error {
    Error::new(
        Code::FormatInvalid,
        format!("{}: capture directory: {what}", dir.display()),
    )
}

/// Read the DSDT and SSDT tables of the capture in `dir`.
///
/// Fails with `FORMAT_INVALID` when the manifest is missing or not `bme.host-capture/1`, when
/// `evidence.json` is missing, when a listed table file is absent, a symbolic link or differs
/// from its recorded digest, and when no file lies under `acpi/tables/`.
///
/// Example: `let found = read_capture_tables(Path::new("capture-2026-11-12"))?;`
pub fn read_capture_tables(dir: &Path) -> Result<CaptureTables> {
    let manifest_path = dir.join(MANIFEST_FILE);
    if !manifest_path.is_file() {
        return Err(invalid(
            dir,
            format!("expected {MANIFEST_FILE} ({MANIFEST_SCHEMA}) | received none"),
        ));
    }
    if !dir.join(EVIDENCE_FILE).is_file() {
        return Err(invalid(
            dir,
            format!("expected {EVIDENCE_FILE} | received none (the capture was interrupted)"),
        ));
    }
    let manifest: Value =
        serde_json::from_slice(&read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?)
            .map_err(|e| invalid(dir, format!("{MANIFEST_FILE}: {e}")))?;
    if manifest["schema"] != MANIFEST_SCHEMA {
        return Err(invalid(
            dir,
            format!(
                "{MANIFEST_FILE} schema: expected {MANIFEST_SCHEMA} | received {}",
                manifest["schema"]
            ),
        ));
    }
    let listed = manifest["files"]
        .as_array()
        .ok_or_else(|| invalid(dir, format!("{MANIFEST_FILE} files: expected an array")))?;
    let mut files = Vec::new();
    for entry in listed {
        let (Some(path), Some(digest)) = (entry["path"].as_str(), entry["sha256"].as_str()) else {
            return Err(invalid(
                dir,
                format!("{MANIFEST_FILE} file entry: expected path and sha256 | received {entry}"),
            ));
        };
        let Some(name) = path.strip_prefix(TABLES_PREFIX) else {
            continue;
        };
        if !Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(invalid(
                dir,
                format!(
                    "{MANIFEST_FILE} path: expected a relative path below the capture | received {path:?}"
                ),
            ));
        }
        let file = dir.join(path);
        let is_link = std::fs::symlink_metadata(&file)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        if is_link {
            return Err(invalid(
                dir,
                format!("{path}: expected a regular file | received a symbolic link"),
            ));
        }
        let bytes = read_bounded(&file, MAX_IMAGE_BYTES)?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(digest) {
            return Err(invalid(
                dir,
                format!("{path}: expected sha256 {digest} | received {actual}"),
            ));
        }
        files.push((name.to_string(), bytes));
    }
    if files.is_empty() {
        return Err(invalid(
            dir,
            format!("expected files under {TABLES_PREFIX} | received none"),
        ));
    }
    tables_from_capture(files).map_err(|e| e.context(dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::host::capture_acpi_to;
    use biosmod_core::aml::fixture::{device, method, scope, table};
    use biosmod_host::HostSurfaces;
    use biosmod_host::testkit::{FakeKernelLog, FakePrivilege, FakeSysfs, FixedClock};

    fn live_dsdt() -> Vec<u8> {
        table(
            "DSDT",
            "LIVE",
            &scope(
                "\\_SB_",
                &[device("SIO1", &[method("SIOS", 1, &[0xA4, 0x01])])],
            ),
        )
    }

    /// A machine with a DSDT, one dynamic SSDT and a BERT table, as sysfs shows them.
    fn machine() -> FakeSysfs {
        FakeSysfs::mr9a()
            .file("sys/firmware/acpi/tables/DSDT", live_dsdt())
            .file(
                "sys/firmware/acpi/tables/dynamic/SSDT3",
                table("SSDT", "DYN", &[]),
            )
            .file(
                "sys/firmware/acpi/tables/data/BERT",
                table("BERT", "LIVE", &[]),
            )
    }

    fn capture_of(sysfs: &FakeSysfs, output: &Path) {
        let files = sysfs.files();
        let log = FakeKernelLog::new();
        capture_acpi_to(
            &HostSurfaces {
                files: &files,
                kernel_log: &log,
                privilege: &FakePrivilege::root(),
                clock: &FixedClock,
            },
            output,
        )
        .unwrap();
    }

    #[test]
    fn a_capture_made_from_fake_sysfs_yields_its_dsdt_and_ssdt() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("capture");
        capture_of(&machine(), &dir);
        let found = read_capture_tables(&dir).unwrap();
        let sources: Vec<&str> = found.tables.iter().map(|t| t.source.as_str()).collect();
        assert_eq!(sources.len(), 2, "{sources:?}");
        assert!(sources.iter().any(|s| s.ends_with("DSDT")), "{sources:?}");
        assert_eq!(found.skipped, ["data/BERT"]);
        let dsdt = found
            .tables
            .iter()
            .find(|t| t.header.signature == "DSDT")
            .unwrap();
        assert_eq!(dsdt.bytes(), &live_dsdt()[..]);
    }

    #[test]
    fn a_table_edited_after_the_capture_is_refused_naming_both_digests() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("capture");
        capture_of(&machine(), &dir);
        let edited = dir.join("acpi/tables/DSDT");
        let mut bytes = std::fs::read(&edited).unwrap();
        bytes[40] ^= 0xFF;
        std::fs::write(&edited, bytes).unwrap();
        let error = read_capture_tables(&dir).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error.message.contains("acpi/tables/DSDT: expected sha256")
                && error.message.contains("received"),
            "(edited table): expected the path and both digests | received {}",
            error.message
        );
    }

    #[test]
    fn a_capture_without_evidence_is_an_interrupted_capture() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("capture");
        capture_of(&machine(), &dir);
        std::fs::remove_file(dir.join(EVIDENCE_FILE)).unwrap();
        let error = read_capture_tables(&dir).unwrap_err();
        assert!(
            error.message.contains("expected evidence.json")
                && error.message.contains("interrupted"),
            "(no evidence): expected the interrupted-capture reason | received {}",
            error.message
        );
    }

    #[test]
    fn a_directory_that_is_not_a_capture_names_the_missing_manifest() {
        let out = tempfile::tempdir().unwrap();
        let error = read_capture_tables(out.path()).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error
                .message
                .contains("expected manifest.json (bme.host-capture/1) | received none"),
            "(plain directory): expected the manifest requirement | received {}",
            error.message
        );
    }

    #[test]
    fn a_manifest_path_that_leaves_the_capture_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path();
        std::fs::write(dir.join(EVIDENCE_FILE), "{}").unwrap();
        std::fs::write(
            dir.join(MANIFEST_FILE),
            format!(
                r#"{{"schema":"{MANIFEST_SCHEMA}","files":[{{"path":"acpi/tables/../../x","bytes":1,"sha256":"00"}}]}}"#
            ),
        )
        .unwrap();
        let error = read_capture_tables(dir).unwrap_err();
        assert!(
            error
                .message
                .contains("expected a relative path below the capture"),
            "(path escape): expected a refusal | received {}",
            error.message
        );
    }

    #[test]
    fn a_capture_without_table_files_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let dir = out.path();
        std::fs::write(dir.join(EVIDENCE_FILE), "{}").unwrap();
        std::fs::write(
            dir.join(MANIFEST_FILE),
            format!(r#"{{"schema":"{MANIFEST_SCHEMA}","files":[]}}"#),
        )
        .unwrap();
        let error = read_capture_tables(dir).unwrap_err();
        assert!(
            error
                .message
                .contains("expected files under acpi/tables/ | received none"),
            "(empty capture): {}",
            error.message
        );
    }
}
