//! A captured set of files with a SHA-256 manifest and an evidence record.
//!
//! The bundle is built in memory; the CLI publishes it to a new directory. Layout:
//! the captured files under their own relative paths, then `manifest.json`
//! (`bme.host-capture/1`, a digest of every captured file) and last
//! `evidence.json` (`bme.evidence/1`, holding the digest of `manifest.json`).
//! A directory without `evidence.json` is an interrupted capture.

use crate::clock::Timestamp;
use crate::identity::HostIdentity;
use crate::receipt::{Receipt, observation_record};
use biosmod_core::util::Digest256;
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;

pub const MANIFEST_SCHEMA: &str = "bme.host-capture/1";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const EVIDENCE_FILE: &str = "evidence.json";
/// Most bytes one bundle may hold; real captures are a few MiB.
pub const MAX_BUNDLE_BYTES: u64 = 128 << 20;

/// One captured file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    /// Relative, `/`-separated, never empty, absolute or containing `..`.
    pub path: String,
    pub bytes: Vec<u8>,
}

/// The files to publish.
#[derive(Debug, Clone, Default)]
pub struct Bundle {
    pub files: Vec<BundleFile>,
}

impl Bundle {
    /// The bytes captured under `path`.
    ///
    /// Example: `bundle.get("acpi/tables/DSDT")`.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|file| file.path == path)
            .map(|file| file.bytes.as_slice())
    }
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    path: String,
    bytes: u64,
    sha256: Digest256,
}

#[derive(Debug, Serialize)]
struct SkippedEntry {
    path: String,
    reason: String,
}

/// `manifest.json`.
#[derive(Debug, Serialize)]
struct Manifest {
    schema: &'static str,
    command: &'static str,
    created: String,
    boot_id: String,
    kernel_release: String,
    files: Vec<ManifestEntry>,
    /// Sources that were absent or not capturable, with the reason.
    skipped: Vec<SkippedEntry>,
}

/// Accumulates files and skipped sources, then seals the bundle.
#[derive(Debug, Default)]
pub struct BundleBuilder {
    files: Vec<BundleFile>,
    skipped: Vec<SkippedEntry>,
    total: u64,
}

impl BundleBuilder {
    pub fn new() -> BundleBuilder {
        BundleBuilder::default()
    }

    /// Add a file under a relative path; refuses unsafe or repeated paths and
    /// bundles over [`MAX_BUNDLE_BYTES`].
    ///
    /// Example: `builder.add("power/state", b"freeze mem disk\n".to_vec())?`.
    pub fn add(&mut self, path: &str, bytes: Vec<u8>) -> Result<()> {
        let safe = !path.is_empty()
            && !path.starts_with('/')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if !safe {
            return Err(Error::new(
                Code::Internal,
                format!("bundle path {path:?}: expected a relative path without . or .. parts"),
            ));
        }
        if self.files.iter().any(|file| file.path == path) {
            return Err(Error::new(
                Code::Internal,
                format!("bundle path {path:?}: already captured"),
            ));
        }
        self.total += bytes.len() as u64;
        if self.total > MAX_BUNDLE_BYTES {
            return Err(Error::new(
                Code::Io,
                format!(
                    "capture size at {path}: expected at most {MAX_BUNDLE_BYTES} bytes | received {}",
                    self.total
                ),
            ));
        }
        self.files.push(BundleFile {
            path: path.to_string(),
            bytes,
        });
        Ok(())
    }

    /// Note a source that was not captured and why.
    pub fn skip(&mut self, path: &str, reason: impl Into<String>) {
        self.skipped.push(SkippedEntry {
            path: path.to_string(),
            reason: reason.into(),
        });
    }

    /// Whether a file was added under `path`.
    pub fn contains(&self, path: &str) -> bool {
        self.files.iter().any(|file| file.path == path)
    }

    /// Append `manifest.json` and `evidence.json` and return the bundle.
    ///
    /// The evidence record's digests hold the SHA-256 of the manifest; the
    /// manifest holds the SHA-256 of every captured file, so one digest covers
    /// the whole bundle.
    pub fn seal(mut self, identity: &HostIdentity, at: Timestamp, mut receipt: Receipt) -> Bundle {
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA,
            command: receipt.command,
            created: at.rfc3339(),
            boot_id: identity.boot_id.clone(),
            kernel_release: identity.kernel_release.clone(),
            files: self
                .files
                .iter()
                .map(|file| ManifestEntry {
                    path: file.path.clone(),
                    bytes: file.bytes.len() as u64,
                    sha256: Digest256::of(&file.bytes),
                })
                .collect(),
            skipped: std::mem::take(&mut self.skipped),
        };
        let manifest_bytes = biosmod_core::json::pretty(&manifest);
        receipt.digests =
            BTreeMap::from([(MANIFEST_FILE.to_string(), Digest256::of(&manifest_bytes))]);
        let evidence = observation_record(identity, at, receipt);
        let mut files = self.files;
        files.push(BundleFile {
            path: MANIFEST_FILE.into(),
            bytes: manifest_bytes,
        });
        files.push(BundleFile {
            path: EVIDENCE_FILE.into(),
            bytes: biosmod_core::json::pretty(&evidence),
        });
        Bundle { files }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakeSysfs;

    fn receipt() -> Receipt {
        Receipt {
            command: "diag acpi capture",
            title: "t".into(),
            observations: vec![],
            limits: "l".into(),
            digests: BTreeMap::new(),
        }
    }

    #[test]
    fn add_refuses_unsafe_and_repeated_paths() {
        let mut builder = BundleBuilder::new();
        for bad in ["", "/abs", "a/../b", "a//b", "./a"] {
            let error = builder.add(bad, vec![]).unwrap_err();
            assert!(
                error.message.contains("expected a relative path"),
                "{bad:?}: {error}"
            );
        }
        builder.add("a/b", vec![1]).unwrap();
        let error = builder.add("a/b", vec![2]).unwrap_err();
        assert!(error.message.contains("already captured"), "{error}");
    }

    #[test]
    fn seal_lists_digests_and_binds_the_manifest_in_the_evidence() {
        let identity = HostIdentity::read(&FakeSysfs::mr9a().files()).unwrap();
        let mut builder = BundleBuilder::new();
        builder.add("acpi/tables/DSDT", b"DSDT".to_vec()).unwrap();
        builder.skip("power/disk", "missing");
        let bundle = builder.seal(&identity, Timestamp { unix_seconds: 0 }, receipt());
        let manifest: serde_json::Value =
            serde_json::from_slice(bundle.get(MANIFEST_FILE).unwrap()).unwrap();
        assert_eq!(manifest["schema"], MANIFEST_SCHEMA);
        assert_eq!(manifest["files"][0]["path"], "acpi/tables/DSDT");
        assert_eq!(
            manifest["files"][0]["sha256"],
            Digest256::of(b"DSDT").to_string()
        );
        assert_eq!(manifest["skipped"][0]["reason"], "missing");
        let evidence: serde_json::Value =
            serde_json::from_slice(bundle.get(EVIDENCE_FILE).unwrap()).unwrap();
        assert_eq!(
            evidence["host"]["digests"][MANIFEST_FILE],
            Digest256::of(bundle.get(MANIFEST_FILE).unwrap()).to_string()
        );
        assert_eq!(bundle.files.last().unwrap().path, EVIDENCE_FILE);
    }

    #[test]
    fn oversized_bundles_name_the_file_that_crossed_the_cap() {
        let mut builder = BundleBuilder::new();
        builder
            .add("a", vec![0; MAX_BUNDLE_BYTES as usize])
            .unwrap();
        let error = builder.add("b", vec![0]).unwrap_err();
        assert!(error.message.starts_with("capture size at b:"), "{error}");
    }
}
