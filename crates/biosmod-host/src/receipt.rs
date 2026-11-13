//! The `bme.evidence/1` record a diagnostic leaves behind.

use crate::clock::Timestamp;
use crate::identity::HostIdentity;
use biosmod_core::catalog::{EVIDENCE_SCHEMA, Evidence, EvidenceKind, HostObservation};
use biosmod_core::util::Digest256;
use std::collections::BTreeMap;

/// What a command wants said about its reading.
pub struct Receipt {
    pub command: &'static str,
    pub title: String,
    pub observations: Vec<String>,
    pub limits: String,
    /// SHA-256 of the artifacts the record describes, by name.
    pub digests: BTreeMap<String, Digest256>,
}

/// Lowercase letters and digits joined by single hyphens; `unknown` when none remain.
///
/// Example: `slug("E5-MR9A PRO")` is `"e5-mr9a-pro"`.
pub fn slug(text: &str) -> String {
    let words: Vec<String> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if words.is_empty() {
        "unknown".into()
    } else {
        words.join("-")
    }
}

/// Build the observation record for one diagnostic run.
///
/// The `board` is the slug of the DMI board vendor and name, and `firmware` the DMI
/// BIOS version: the diagnostics do not load a catalog, so neither is resolved
/// against one.
///
/// Example: a capture on the MR9A at boot `98d86da9-...` yields the id
/// `host-diag-acpi-capture-2026-11-12-98d86da9` and board `machinist-e5-mr9a-pro`.
pub fn observation_record(identity: &HostIdentity, at: Timestamp, receipt: Receipt) -> Evidence {
    let field = |name: &str| identity.dmi.get(name).map(String::as_str).unwrap_or("");
    let board = slug(&format!(
        "{} {}",
        field("board_vendor"),
        field("board_name")
    ));
    let firmware = identity
        .dmi
        .get("bios_version")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let boot_prefix: String = identity.boot_id.chars().take(8).collect();
    let mut limits = receipt.limits;
    limits.push_str(
        " Board and firmware come from DMI, not from a catalog, and the record is not validated against one.",
    );
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        id: format!(
            "host-{}-{}-{}",
            slug(receipt.command),
            at.date(),
            slug(&boot_prefix)
        ),
        kind: EvidenceKind::HardwareObservation,
        date: at.date(),
        title: receipt.title,
        board,
        firmware,
        configuration: None,
        patches: Vec::new(),
        image_sha256: None,
        built_with: Some(format!("bme {}", biosmod_core::VERSION)),
        observations: receipt.observations,
        limits,
        source: None,
        host: Some(HostObservation {
            command: receipt.command.into(),
            boot_id: identity.boot_id.clone(),
            kernel_release: identity.kernel_release.clone(),
            digests: receipt.digests,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakeSysfs;

    #[test]
    fn slug_collapses_separators_and_falls_back() {
        assert_eq!(slug("MACHINIST E5-MR9A PRO"), "machinist-e5-mr9a-pro");
        assert_eq!(slug(" -- "), "unknown");
    }

    #[test]
    fn the_record_carries_boot_kernel_digests_and_a_valid_date_and_id() {
        let identity = HostIdentity::read(&FakeSysfs::mr9a().files()).unwrap();
        let digest = Digest256::of(b"manifest");
        let record = observation_record(
            &identity,
            Timestamp {
                unix_seconds: 1_794_441_600,
            },
            Receipt {
                command: "diag acpi capture",
                title: "t".into(),
                observations: vec!["o".into()],
                limits: "Limit.".into(),
                digests: BTreeMap::from([("manifest.json".to_string(), digest)]),
            },
        );
        assert_eq!(record.id, "host-diag-acpi-capture-2026-11-12-98d86da9");
        assert_eq!(record.date, "2026-11-12");
        assert_eq!(record.board, "machinist-e5-mr9a-pro");
        assert_eq!(record.firmware, "5.11");
        let host = record.host.unwrap();
        assert_eq!(host.boot_id, FakeSysfs::BOOT_ID);
        assert_eq!(host.kernel_release, "7.0.0-42-generic");
        assert_eq!(host.digests["manifest.json"], digest);
    }
}
