//! Defect-class detectors: masked byte signatures that run on any build.
//!
//! A patch variant recognises a defect only in the exact build it was written
//! for. A [`Detector`] lives on a finding and describes the defective code
//! itself, with masks over addresses and displacements, so the same record
//! finds the defect in builds the catalog has never seen. Hits are reported
//! per module as [`DetectorState::LikelyPresent`]; they never make a patch
//! applicable.
//!
//! Example:
//! ```no_run
//! # use biosmod_core::{catalog::Catalog, detect, firmware::Image};
//! # fn demo(image: &Image, catalog: &Catalog) {
//! for report in detect::run_all(image, catalog) {
//!     println!("{} {}: {:?}", report.finding, report.detector, report.state);
//! }
//! # }
//! ```

use crate::analysis::module_bytes;
use crate::catalog::{Anchor, Catalog, Detector, Finding, LeafKind, ModuleKind, Pattern};
use crate::firmware::Image;
use crate::patch::find_matches;
use crate::util::Guid;
use serde::Serialize;

/// FFS file types (PI specification) that make up each [`ModuleKind`].
fn file_types(kind: ModuleKind) -> &'static [u8] {
    match kind {
        // PEI_CORE is 0x04; PEIM 0x06; COMBINED_PEIM_DRIVER 0x08.
        ModuleKind::Peim => &[0x04, 0x06, 0x08],
        // DRIVER 0x07; COMBINED_PEIM_DRIVER 0x08; COMBINED_SMM_DXE 0x0C; DXE_CORE 0x05.
        ModuleKind::Dxe => &[0x05, 0x07, 0x08, 0x0C],
        // SMM 0x0A; COMBINED_SMM_DXE 0x0C; SMM_CORE 0x0D.
        ModuleKind::Smm => &[0x0A, 0x0C, 0x0D],
    }
}

/// Outcome of one detector on one image, or on one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorState {
    /// The defect signature occurs as many times as the detector expects.
    LikelyPresent,
    /// The defect signature occurs, but not as often as the detector expects.
    UnexpectedCount,
    /// Only the corrected code pattern occurs.
    FixedPattern,
    /// A module that could hold the signature sits inside an encapsulation this engine cannot read.
    Unsupported,
    /// No signature occurs; not proof the defect is absent from code the pattern does not cover.
    Absent,
}

impl DetectorState {
    /// Short human label.
    ///
    /// Example: `DetectorState::LikelyPresent.label() == "likely present"`.
    pub fn label(self) -> &'static str {
        match self {
            DetectorState::LikelyPresent => "likely present",
            DetectorState::UnexpectedCount => "unexpected count",
            DetectorState::FixedPattern => "fixed pattern",
            DetectorState::Unsupported => "unsupported",
            DetectorState::Absent => "absent",
        }
    }
}

/// One signature match inside a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Site {
    /// Label of the signature that matched.
    pub signature: String,
    /// Offset of the match in the module (PE image or ACPI table) bytes.
    pub offset: usize,
}

/// What one module holds for a detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleHits {
    pub ffs_guid: Guid,
    /// UI section name of the module, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_name: Option<String>,
    pub state: DetectorState,
    /// Matches of the defect signatures, in offset order.
    pub defect: Vec<Site>,
    /// Matches of the corrected-code signatures, in offset order.
    pub fixed: Vec<Site>,
    /// True when a signature stopped listing sites at `max_per_module + 1`; the real count is higher.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// One detector's result on an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectorReport {
    pub finding: String,
    pub detector: String,
    pub title: String,
    pub state: DetectorState,
    /// Modules with at least one match; modules without any are not listed.
    pub modules: Vec<ModuleHits>,
    /// Modules inside unsupported encapsulations that the anchor could cover.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unsupported: Vec<Guid>,
}

/// The module bytes a detector's anchor selects, with the owning FFS file index.
struct Candidate<'a> {
    guid: Guid,
    ui_name: Option<String>,
    bytes: &'a [u8],
}

fn candidates<'a>(image: &'a Image, anchor: &Anchor) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for (guid, leaves) in &image.leaves {
        for leaf in leaves {
            let file = image.file(leaf);
            let (kind, wanted_guid) = match anchor {
                Anchor::Pe32 {
                    module_kind,
                    ffs_guid,
                } => (module_kind, ffs_guid),
                Anchor::Dsdt => (&None, &None),
            };
            if wanted_guid.is_some_and(|g| g != *guid)
                || kind.is_some_and(|k| !file_types(k).contains(&file.kind))
            {
                continue;
            }
            let leaf_kind = match anchor {
                Anchor::Pe32 { .. } => LeafKind::Pe32,
                Anchor::Dsdt => LeafKind::AcpiTable,
            };
            if let Some(bytes) = module_bytes(image, leaf, leaf_kind, 0) {
                out.push(Candidate {
                    guid: *guid,
                    ui_name: image.ui_name(leaf.volume, leaf.file),
                    bytes,
                });
            }
        }
    }
    out
}

/// FFS GUIDs of opaque (unreadable) files the anchor could have covered.
fn opaque_candidates(image: &Image, anchor: &Anchor) -> Vec<Guid> {
    let (kind, wanted_guid) = match anchor {
        Anchor::Pe32 {
            module_kind,
            ffs_guid,
        } => (module_kind, ffs_guid),
        // A DSDT can hide in any raw section; without reading it nothing is excluded.
        Anchor::Dsdt => (&None, &None),
    };
    let mut guids: Vec<Guid> = image
        .volumes
        .iter()
        .flat_map(|v| &v.files)
        .filter(|f| f.opaque)
        .filter(|f| wanted_guid.is_none_or(|g| g == f.guid))
        .filter(|f| kind.is_none_or(|k| file_types(k).contains(&f.kind)))
        .map(|f| f.guid)
        .collect();
    guids.sort();
    guids.dedup();
    guids
}

/// Sites of `pattern` in `data`, at most `cap`; the flag says the cap cut the list short.
fn sites(data: &[u8], signature: &str, pattern: &Pattern, cap: usize) -> (Vec<Site>, bool) {
    let mut found = find_matches(data, &pattern.bytes.0, &pattern.wild, cap + 1);
    let truncated = found.len() > cap;
    found.truncate(cap);
    let sites = found
        .into_iter()
        .map(|offset| Site {
            signature: signature.to_string(),
            offset,
        })
        .collect();
    (sites, truncated)
}

/// Run one detector of `finding` on `image`.
///
/// Example: `let report = detect::run(&image, &finding, &finding.detectors[0]);`
pub fn run(image: &Image, finding: &Finding, detector: &Detector) -> DetectorReport {
    let mut modules: Vec<ModuleHits> = Vec::new();
    for candidate in candidates(image, &detector.anchor) {
        let mut defect = Vec::new();
        let mut fixed = Vec::new();
        let mut truncated = false;
        // One site past the maximum is enough to know the count is out of range.
        let cap = detector.expect.max_per_module as usize + 1;
        for signature in &detector.signatures {
            let (hits, cut) = sites(candidate.bytes, &signature.label, &signature.defect, cap);
            defect.extend(hits);
            truncated |= cut;
            if let Some(pattern) = &signature.fixed {
                let (hits, cut) = sites(candidate.bytes, &signature.label, pattern, cap);
                fixed.extend(hits);
                truncated |= cut;
            }
        }
        if defect.is_empty() && fixed.is_empty() {
            continue;
        }
        defect.sort_by_key(|s| s.offset);
        fixed.sort_by_key(|s| s.offset);
        let count = defect.len() as u32;
        let state = if defect.is_empty() {
            DetectorState::FixedPattern
        } else if (detector.expect.min_per_module..=detector.expect.max_per_module).contains(&count)
        {
            DetectorState::LikelyPresent
        } else {
            DetectorState::UnexpectedCount
        };
        modules.push(ModuleHits {
            ffs_guid: candidate.guid,
            ui_name: candidate.ui_name,
            state,
            defect,
            fixed,
            truncated,
        });
    }
    let unsupported = opaque_candidates(image, &detector.anchor);
    let any = |state| modules.iter().any(|m| m.state == state);
    // A module with an out-of-range count needs review, so it outranks clean hits
    // elsewhere. "Only the corrected shape occurs" is a claim about every candidate,
    // so it cannot stand while some candidate could not be read.
    let state = if any(DetectorState::UnexpectedCount) {
        DetectorState::UnexpectedCount
    } else if any(DetectorState::LikelyPresent) {
        DetectorState::LikelyPresent
    } else if !modules.is_empty() && unsupported.is_empty() {
        DetectorState::FixedPattern
    } else if !unsupported.is_empty() {
        DetectorState::Unsupported
    } else {
        DetectorState::Absent
    };
    DetectorReport {
        finding: finding.id.clone(),
        detector: detector.id.clone(),
        title: detector.title.clone(),
        state,
        modules,
        unsupported,
    }
}

/// Run every detector in the catalog on `image`, in finding and detector order.
///
/// Example: `let reports = detect::run_all(&image, &catalog);`
pub fn run_all(image: &Image, catalog: &Catalog) -> Vec<DetectorReport> {
    catalog
        .findings
        .values()
        .flat_map(|finding| {
            finding
                .detectors
                .iter()
                .map(move |detector| run(image, finding, detector))
        })
        .collect()
}
