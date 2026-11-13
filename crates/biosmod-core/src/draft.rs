//! Draft a board profile and firmware build from what an image says about itself.
//!
//! Unknown boards start here: build identity strings give the build an id and
//! a version, the module inventory records what a catalog build is later keyed
//! on, and SMBIOS identity (read by the caller on the machine that holds the
//! board) fills vendor and model only when it provably belongs to this image.
//! Every output is marked as an unreviewed draft.
//!
//! Example:
//! ```
//! use biosmod_core::draft::{identity_strings, firmware_id};
//! let image = b"\0\0X99H BIOS Date: 12/02/2022 Ver: X99HA00M\0\0";
//! let identity = identity_strings(image);
//! assert_eq!(firmware_id(identity.first().map(String::as_str), image), "x99ha00m-20221202");
//! ```

use crate::analysis::module_bytes;
use crate::catalog::{
    BOARD_SCHEMA, Board, Finding, FindingStatus, FirmwareBuild, LeafKind, Revision, RevisionStatus,
};
use crate::firmware::Image;
use crate::plan::document::Blob;
use crate::util::{Digest256, Guid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FIRMWARE_DRAFT_SCHEMA: &str = "bme.firmware-draft/1";

/// Marks every drafted document, so no reader mistakes it for reviewed data.
pub const DRAFT_NOTICE: &str = "DRAFT (unreviewed)";

/// Longest identity string kept; longer printable runs are data, not a version banner.
const MAX_IDENTITY: usize = 120;
/// Shortest printable run considered.
const MIN_IDENTITY: usize = 8;

/// One module leaf the catalog can key a build on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleDigest {
    pub ffs_guid: Guid,
    pub leaf: LeafKind,
    /// UI section name of the module, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_name: Option<String>,
    pub length: u64,
    pub sha256: Digest256,
}

/// The firmware build drafted from an image, with the facts it was drafted from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareDraft {
    pub schema: String,
    /// Always true: a person reviews the draft before it goes into a catalog.
    pub draft: bool,
    /// The build as a board profile lists it.
    pub build: FirmwareBuild,
    /// The image the draft describes.
    pub image: Blob,
    /// Printable build identity strings found in the image, banner first.
    pub identity: Vec<String>,
    /// The catalog build the image matched when it was scanned, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches_catalog_build: Option<String>,
    /// SMBIOS fields of the machine, kept only when they match this image.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub smbios: BTreeMap<String, String>,
    /// PE32 and ACPI table modules with their digests.
    pub modules: Vec<ModuleDigest>,
}

/// A date such as `12/02/2022` as `20221202`, if `text` holds one.
fn find_date(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(9)).find_map(|at| {
        let w = &bytes[at..at + 10];
        let digits = |range: std::ops::Range<usize>| w[range].iter().all(u8::is_ascii_digit);
        (digits(0..2) && w[2] == b'/' && digits(3..5) && w[5] == b'/' && digits(6..10)).then(|| {
            // The banner writes MM/DD/YYYY.
            format!(
                "{}{}{}",
                &text[at + 6..at + 10],
                &text[at..at + 2],
                &text[at + 3..at + 5]
            )
        })
    })
}

/// Printable ASCII banners that carry a `Ver:` marker, banners with a date first.
///
/// Example: `identity_strings(b"..X9R9P Ver:005 03/22/2023 19:30..")` yields the banner.
pub fn identity_strings(image: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut start = None;
    for (at, byte) in image.iter().copied().chain([0]).enumerate() {
        let printable = (0x20..=0x7E).contains(&byte);
        match (printable, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                start = None;
                let run = &image[from..at];
                if (MIN_IDENTITY..=MAX_IDENTITY).contains(&run.len()) {
                    let text = String::from_utf8_lossy(run).trim().to_string();
                    if text.contains("Ver:") && !found.contains(&text) {
                        found.push(text);
                    }
                }
            }
            _ => {}
        }
    }
    // Stable: banners that carry a date come first, offsets keep their order otherwise.
    found.sort_by_key(|text| find_date(text).is_none());
    found.truncate(4);
    found
}

fn slug(text: &str) -> String {
    let mapped: String = text
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_string()
}

/// A firmware build id for an image: version and date from its banner, else its digest.
///
/// `X99H BIOS Date: 12/02/2022 Ver: X99HA00M` gives `x99ha00m-20221202`; a bare numeric
/// version takes the word before `Ver:` as its prefix. Without a banner the id is
/// `fw-` and the first 12 digits of the image SHA-256.
///
/// Example: `firmware_id(None, &bytes)` is `fw-<digest prefix>`.
pub fn firmware_id(banner: Option<&str>, image: &[u8]) -> String {
    let derived = banner.and_then(|banner| {
        let (before, after) = banner.split_once("Ver:")?;
        let version = after.split_whitespace().next()?;
        let name = if version.chars().any(|c| c.is_ascii_alphabetic()) {
            slug(version)
        } else {
            let prefix = before.split_whitespace().last().unwrap_or("");
            slug(&format!("{prefix}-{version}"))
        };
        let id = match find_date(banner) {
            Some(date) => format!("{name}-{date}"),
            None => name,
        };
        (!id.is_empty() && id.len() <= 64).then_some(id)
    });
    derived.unwrap_or_else(|| format!("fw-{}", &Digest256::of(image).to_string()[..12]))
}

/// PE32 and DSDT leaves of an image with their lengths and digests, in GUID order.
///
/// Example: `module_inventory(&image).len()` counts the modules a patch could target.
pub fn module_inventory(image: &Image) -> Vec<ModuleDigest> {
    let mut modules = Vec::new();
    for (guid, leaves) in &image.leaves {
        for leaf in leaves {
            for kind in [LeafKind::Pe32, LeafKind::AcpiTable] {
                if let Some(bytes) = module_bytes(image, leaf, kind, 0) {
                    modules.push(ModuleDigest {
                        ffs_guid: *guid,
                        leaf: kind,
                        ui_name: image.ui_name(leaf.volume, leaf.file),
                        length: bytes.len() as u64,
                        sha256: Digest256::of(bytes),
                    });
                }
            }
        }
    }
    modules
}

/// Whether SMBIOS describes the firmware in `identity`: its BIOS date appears in a banner.
///
/// A host is not assumed to hold the board that produced a dump: a dump of another
/// build carries another date.
///
/// Example: `bios_date` `03/22/2023` matches the banner `X9R9P Ver:005 03/22/2023`.
pub fn smbios_matches(identity: &[String], smbios: &BTreeMap<String, String>) -> bool {
    smbios
        .get("bios_date")
        .is_some_and(|date| !date.is_empty() && identity.iter().any(|banner| banner.contains(date)))
}

/// What `draft` needs to know about the image and its surroundings.
#[derive(Debug, Clone)]
pub struct DraftRequest<'a> {
    pub image: &'a Image,
    /// Board id to use; `None` derives `draft-<firmware id>`.
    pub board_id: Option<&'a str>,
    /// SMBIOS identity of the running machine (empty off the board's machine).
    pub smbios: &'a BTreeMap<String, String>,
    /// The catalog build the scan matched, if any.
    pub matches_catalog_build: Option<&'a str>,
}

fn unreviewed(what: &str) -> String {
    format!("{DRAFT_NOTICE}: {what}")
}

/// Draft a board profile and firmware build for an image.
///
/// The board lists the build and nothing else; vendor, model and revision come
/// from SMBIOS only when [`smbios_matches`] holds, otherwise they read `Unknown`.
///
/// Example: `let (board, firmware) = draft(&request)?;`
pub fn draft(request: &DraftRequest) -> crate::Result<(Board, FirmwareDraft)> {
    let bytes = &request.image.bytes;
    let identity = identity_strings(bytes);
    let banner = identity.first().map(String::as_str);
    let firmware_id = firmware_id(banner, bytes);
    let board_id = match request.board_id {
        Some(id) => id.to_string(),
        None => crate::case::bounded_id("draft", &firmware_id)
            .chars()
            .take(64)
            .collect(),
    };
    crate::validation::identifier(&board_id, "board id")?;
    let blob = Blob::of(bytes);
    let smbios = if smbios_matches(&identity, request.smbios) {
        request.smbios.clone()
    } else {
        BTreeMap::new()
    };
    let from_smbios = |field: &str| smbios.get(field).cloned();
    let build = FirmwareBuild {
        id: firmware_id,
        title: match banner {
            Some(banner) => format!("{banner} (draft)"),
            None => format!(
                "Unidentified image {} (draft)",
                &blob.sha256.to_string()[..12]
            ),
        },
        version_string: banner.map(str::to_string),
        image_size: Some(blob.length),
        note: Some(unreviewed(
            "drafted by `bme case init` from the image; check the version string and size against the vendor release",
        )),
    };
    let board = Board {
        schema: BOARD_SCHEMA.into(),
        id: board_id,
        vendor: from_smbios("board_vendor").unwrap_or_else(|| "Unknown".into()),
        model: from_smbios("board_name").unwrap_or_else(|| "Unknown".into()),
        chipset: None,
        revision: Revision {
            label: from_smbios("board_version"),
            status: if smbios.is_empty() {
                RevisionStatus::Unknown
            } else {
                RevisionStatus::Unverified
            },
            note: Some(unreviewed(if smbios.is_empty() {
                "no SMBIOS identity matched the image; fill in vendor, model and revision from the physical board"
            } else {
                "vendor, model and revision come from the SMBIOS of the machine that ran `bme case init`; confirm them on the physical board"
            })),
        },
        description: Some(unreviewed(
            "board profile drafted by `bme case init`; it lists the build and no patches",
        )),
        firmware: vec![build.clone()],
        facts: vec![],
        patches: vec![],
        findings: vec![],
        evidence: vec![],
    };
    let firmware = FirmwareDraft {
        schema: FIRMWARE_DRAFT_SCHEMA.into(),
        draft: true,
        build,
        image: blob,
        identity,
        matches_catalog_build: request.matches_catalog_build.map(str::to_string),
        smbios,
        modules: module_inventory(request.image),
    };
    Ok((board, firmware))
}

/// Draft an open finding for a detector hit, to travel with the case.
///
/// The copy affects only `firmware`, drops the patches and detectors of the
/// catalog record, and lists `evidence_artifact` (an artifact id of the case) as
/// evidence. Its status is open: the catalog has no variant for this build.
///
/// Example: `let finding = draft_finding(&catalog_finding, "fw-1", "001-scan");`
pub fn draft_finding(source: &Finding, firmware: &str, evidence_artifact: &str) -> Finding {
    let mut finding = source.clone();
    finding.status = FindingStatus::Open;
    finding.patches.clear();
    finding.detectors.clear();
    finding.affects.builds = vec![firmware.to_string()];
    for reference in &mut finding.owner.references {
        reference.build = reference.build.take().filter(|b| b == firmware);
    }
    finding.evidence = vec![evidence_artifact.to_string()];
    finding.description = unreviewed(&format!(
        "a defect signature of this finding matched the image; the catalog has no verified variant for this build. {}",
        source.description
    ));
    finding
}
