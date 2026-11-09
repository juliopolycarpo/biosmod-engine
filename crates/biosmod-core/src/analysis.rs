//! Locate catalog components in an image, detect the firmware build and report patch states.
//!
//! A component matches only when undoing the recognized fixes recovers the
//! exact recorded original (by SHA-256). Signature matches on other builds
//! are diagnostic only and never make a patch applicable.
//!
//! Example:
//! ```no_run
//! # use biosmod_core::{analysis, catalog::Catalog, firmware::Image};
//! # fn demo(catalog: &Catalog, image: &Image) {
//! let report = analysis::scan(image, catalog, None);
//! println!("{:?}", report.firmware);
//! # }
//! ```

use crate::catalog::{Catalog, Component, LeafKind, Patch, PatchClass, Tier, Variant};
use crate::error::{Code, Error, Result};
use crate::firmware::{Image, LeafRef, SECTION_PE32, SECTION_RAW, SECTION_TE};
use crate::patch::{self, HunkState};
use crate::util::{Digest256, Guid, le32};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The bytes a leaf holds for a component kind, or `None` when the kind differs.
pub fn module_bytes<'a>(
    image: &'a Image,
    leaf: &LeafRef,
    kind: LeafKind,
    table_offset: usize,
) -> Option<&'a [u8]> {
    let (section, stream) = image.section(leaf);
    let body = section.body(stream);
    match kind {
        LeafKind::Pe32 => {
            (section.kind == SECTION_PE32 || section.kind == SECTION_TE).then_some(body)
        }
        LeafKind::AcpiTable => {
            if section.kind != SECTION_RAW {
                return None;
            }
            let header_end = table_offset.checked_add(8);
            let length = if header_end.is_some_and(|end| body.len() >= end) {
                le32(body, table_offset + 4, "ACPI length").ok()? as usize
            } else {
                0
            };
            let start = table_offset.min(body.len());
            let table = &body[start..table_offset.saturating_add(length).min(body.len())];
            table.starts_with(b"DSDT").then_some(table)
        }
    }
}

/// Every patch id reachable from `ids` through `supersedes`, including `ids`.
pub fn included(catalog: &Catalog, ids: &[String]) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let mut pending: Vec<String> = ids.to_vec();
    while let Some(id) = pending.pop() {
        if result.insert(id.clone())
            && let Some(patch) = catalog.patches.get(&id)
        {
            pending.extend(patch.supersedes.iter().cloned());
        }
    }
    result
}

/// One application unit per correction: drop ids superseded by others, keeping order.
pub fn minimal(catalog: &Catalog, ids: &[String]) -> Vec<String> {
    let mut chosen: Vec<String> = Vec::new();
    for id in ids {
        if !chosen.contains(id) {
            chosen.push(id.clone());
        }
    }
    let mut covered = BTreeSet::new();
    for id in &chosen {
        let older = catalog
            .patches
            .get(id)
            .map(|p| p.supersedes.clone())
            .unwrap_or_default();
        covered.extend(included(catalog, &older));
    }
    chosen
        .into_iter()
        .filter(|id| !covered.contains(id))
        .collect()
}

/// Patches with a component at `(guid, kind)` for `firmware`, in id order.
pub fn related<'a>(
    catalog: &'a Catalog,
    firmware: &str,
    guid: Guid,
    kind: LeafKind,
) -> Vec<(&'a Patch, &'a Component)> {
    catalog
        .patches_for(firmware)
        .filter_map(|patch| {
            patch
                .components(firmware)
                .iter()
                .find(|c| c.ffs_guid == guid && c.leaf == kind)
                .map(|c| (patch, c))
        })
        .collect()
}

/// Describe another ACPI table offset that shares the component's FFS identity.
///
/// For example, offsets 0 and 8 on one GUID cannot yet be composed separately.
pub(crate) fn table_offset_conflict(
    catalog: &Catalog,
    firmware: &str,
    component: &Component,
) -> Option<String> {
    if component.leaf != LeafKind::AcpiTable {
        return None;
    }
    let other = catalog
        .patches_for(firmware)
        .flat_map(|patch| patch.components(firmware))
        .find(|other| {
            other.ffs_guid == component.ffs_guid
                && other.leaf == component.leaf
                && other.table_offset != component.table_offset
        })?;
    Some(format!(
        "{}: FFS {} has ACPI table offsets {:#x} and {:#x}; expected one table offset per FFS file",
        component.name, component.ffs_guid, component.table_offset, other.table_offset
    ))
}

/// A component found in an image and its relation to the recorded original.
#[derive(Debug, Clone)]
pub struct Match {
    pub leaf: LeafRef,
    pub current: Vec<u8>,
    pub original: Vec<u8>,
    /// Recognized fixes present, minimal (superseded ones removed).
    pub fixed: Vec<String>,
}

/// Locate a component and undo known fixes to recover the exact original.
pub fn match_component(
    image: &Image,
    catalog: &Catalog,
    firmware: &str,
    component: &Component,
) -> Option<Match> {
    if copies(image, component) > 1 {
        return None;
    }
    let related = related(catalog, firmware, component.ffs_guid, component.leaf);
    let (layered, base): (Vec<_>, Vec<_>) =
        related.iter().partition(|(_, c)| !c.layer_on.is_empty());
    for leaf in image.leaves.get(&component.ffs_guid)? {
        let Some(current) = module_bytes(image, leaf, component.leaf, component.table_offset)
        else {
            continue;
        };
        let Some((intermediate, layered_fixed)) = undo(catalog, current, &layered) else {
            continue;
        };
        if layered_fixed.iter().any(|id| {
            layered
                .iter()
                .any(|(p, c)| &p.id == id && c.input_sha256 != Some(Digest256::of(&intermediate)))
        }) {
            continue;
        }
        let Some((original, base_fixed)) = undo(catalog, &intermediate, &base) else {
            continue;
        };
        if Digest256::of(&original) == component.source_sha256 {
            let fixed = base_fixed.into_iter().chain(layered_fixed).collect();
            return Some(Match {
                leaf: leaf.clone(),
                current: current.to_vec(),
                original,
                fixed,
            });
        }
    }
    None
}

/// How many decodable copies of a component's module the image holds.
///
/// Only uniquely identified modules are matched or patched: with two copies
/// (for example a backup boot block) patching one would leave the defect in
/// the other while every check reads the patched copy.
///
/// Example: `assert_eq!(copies(&image, component), 1)` for the reference boards.
pub fn copies(image: &Image, component: &Component) -> usize {
    image.leaves.get(&component.ffs_guid).map_or(0, |leaves| {
        leaves
            .iter()
            .filter(|l| module_bytes(image, l, component.leaf, component.table_offset).is_some())
            .count()
    })
}

/// Reverse every related patch whose fixed bytes are present; `None` on inconsistency.
fn undo(
    catalog: &Catalog,
    data: &[u8],
    related: &[&(&Patch, &Component)],
) -> Option<(Vec<u8>, Vec<String>)> {
    let fixed: Vec<String> = related
        .iter()
        .filter(|(_, c)| patch::state(data, &c.hunks).ok() == Some(HunkState::Fixed))
        .map(|(p, _)| p.id.clone())
        .collect();
    let fixed = minimal(catalog, &fixed);
    let hunks = related
        .iter()
        .filter(|(p, _)| fixed.contains(&p.id))
        .flat_map(|(_, c)| &c.hunks);
    let original = patch::reverse(data, hunks).ok()?;
    Some((original, fixed))
}

/// Coverage of one firmware build's recorded originals in an image.
#[derive(Debug, Clone, Serialize)]
pub struct BuildScore {
    pub firmware: String,
    pub boards: Vec<String>,
    pub matched: usize,
    pub total: usize,
}

/// The detected firmware build, or why none was chosen.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub firmware: Option<String>,
    pub ambiguous: bool,
    pub scores: Vec<BuildScore>,
}

/// Score every firmware build by how many of its recorded originals the image contains.
pub fn detect(image: &Image, catalog: &Catalog) -> Detection {
    let mut scores = Vec::new();
    for (firmware, boards) in catalog.firmware_builds() {
        let mut keys: BTreeMap<(Guid, LeafKind), &Component> = BTreeMap::new();
        for patch in catalog.patches_for(firmware) {
            for component in patch.components(firmware) {
                keys.entry((component.ffs_guid, component.leaf))
                    .or_insert(component);
            }
        }
        let matched = keys
            .values()
            .filter(|c| match_component(image, catalog, firmware, c).is_some())
            .count();
        scores.push(BuildScore {
            firmware: firmware.to_string(),
            boards: boards.iter().map(|b| b.id.clone()).collect(),
            matched,
            total: keys.len(),
        });
    }
    let best = scores.iter().map(|s| s.matched).max().unwrap_or(0);
    let leaders: Vec<&BuildScore> = scores
        .iter()
        .filter(|s| s.matched == best && best > 0)
        .collect();
    Detection {
        firmware: (leaders.len() == 1).then(|| leaders[0].firmware.clone()),
        ambiguous: leaders.len() > 1,
        scores,
    }
}

/// A patch's state on an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Exact original present; the patch applies to this build.
    Present,
    /// Already applied.
    Fixed,
    /// Some components patched, some not.
    Partial,
    /// Signature of the defect found in a different build (diagnostic only).
    LikelyPresent,
    /// Signature of the fix found in a different build (diagnostic only).
    LikelyFixed,
    /// No match; not proof the defect is absent.
    NotDetected,
    NotApplicable,
    /// The module sits inside an encapsulation this engine cannot read.
    Unsupported,
}

impl State {
    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            State::Present => "DEFECT PRESENT",
            State::Fixed => "fixed",
            State::Partial => "PARTIAL",
            State::LikelyPresent => "likely present",
            State::LikelyFixed => "likely fixed",
            State::NotDetected => "not detected",
            State::NotApplicable => "n/a",
            State::Unsupported => "unsupported",
        }
    }
}

/// One patch's scan row.
#[derive(Debug, Clone, Serialize)]
pub struct PatchReport {
    pub id: String,
    pub version: String,
    pub title: String,
    pub class: PatchClass,
    pub tier: Tier,
    pub manual: bool,
    pub state: State,
    pub detail: String,
    /// Whether `plan` can select this patch on this exact image.
    pub plannable: bool,
    /// Why a present patch cannot be planned (manual packing, context, facts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requires_facts: Vec<String>,
    /// Hardware observations recorded for this patch version (scoped; see evidence).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// The whole scan result.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub firmware: Option<String>,
    pub boards: Vec<String>,
    pub detection: Detection,
    pub patches: Vec<PatchReport>,
    /// Plannable tier-recommended corrections.
    pub recommended: Vec<String>,
}

/// The state of one patch on an image for a known firmware build.
pub fn patch_state(
    image: &Image,
    catalog: &Catalog,
    firmware: &str,
    patch: &Patch,
) -> (State, String) {
    let variant = match patch.variants.get(firmware) {
        Some(Variant::Applicable(v)) => v,
        Some(Variant::NotApplicable(n)) => return (State::NotApplicable, n.reason.clone()),
        None => {
            return (
                State::NotApplicable,
                format!("no variant for firmware {firmware}"),
            );
        }
    };
    for component in &variant.components {
        if let Some(message) = table_offset_conflict(catalog, firmware, component) {
            return (State::Unsupported, message);
        }
    }
    let mut states = BTreeSet::new();
    let mut missing = Vec::new();
    let mut opaque = Vec::new();
    for component in &variant.components {
        let count = copies(image, component);
        if count > 1 {
            return (
                State::Unsupported,
                format!(
                    "{} occurs {count} times; only uniquely identified modules are patched",
                    component.name
                ),
            );
        }
        match match_component(image, catalog, firmware, component) {
            Some(m) => {
                let fixed = included(catalog, &m.fixed).contains(&patch.id);
                states.insert(if fixed { State::Fixed } else { State::Present });
            }
            None => {
                let hidden = count == 0;
                let in_opaque = image
                    .volumes
                    .iter()
                    .flat_map(|v| &v.files)
                    .any(|f| f.guid == component.ffs_guid && f.opaque);
                if hidden && in_opaque {
                    opaque.push(component.name.as_str());
                }
                missing.push(component.name.as_str());
            }
        }
    }
    if !opaque.is_empty() {
        return (
            State::Unsupported,
            format!(
                "modules inside unsupported encapsulation: {}",
                opaque.join(", ")
            ),
        );
    }
    if !missing.is_empty() {
        return (
            State::NotDetected,
            format!(
                "not the {firmware} original: {}",
                missing
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    match (
        states.contains(&State::Present),
        states.contains(&State::Fixed),
    ) {
        (true, false) => (
            State::Present,
            "defect present; patch applies to this exact build".into(),
        ),
        (false, true) => (State::Fixed, "already patched".into()),
        _ => (State::Partial, "some components patched, some not".into()),
    }
}

/// Look for a patch's defect by context signature, for builds without an exact record.
pub fn signature_scan(image: &Image, patch: &Patch, firmware: &str) -> (State, String) {
    let mut results = Vec::new();
    for component in patch.components(firmware) {
        let mut best = HunkState::Mismatch;
        for leaf in image.leaves.get(&component.ffs_guid).into_iter().flatten() {
            if let Some(current) = module_bytes(image, leaf, component.leaf, component.table_offset)
            {
                let (state, _) = patch::locate(current, &component.hunks);
                if state != HunkState::Mismatch {
                    best = state;
                    break;
                }
            }
        }
        results.push(best);
    }
    if !results.is_empty() && results.iter().all(|r| *r == HunkState::Original) {
        return (
            State::LikelyPresent,
            format!("code pattern of the {firmware} defect found; build differs"),
        );
    }
    if !results.is_empty() && results.iter().all(|r| *r == HunkState::Fixed) {
        return (State::LikelyFixed, "fixed code pattern found".into());
    }
    (
        State::NotDetected,
        "pattern not found (different code or no such module)".into(),
    )
}

/// Why a present patch cannot be planned on this image, ignoring user policy flags.
pub fn blocker(image: &Image, catalog: &Catalog, firmware: &str, patch: &Patch) -> Option<String> {
    if patch.packing == crate::catalog::Packing::Manual {
        return Some("manual packing: the module grows and must be relocated by hand".into());
    }
    let variant = patch.applicable(firmware)?;
    let clash: Vec<&str> = catalog
        .patches
        .values()
        .filter(|other| other.conflicts.contains(&patch.id) || patch.conflicts.contains(&other.id))
        .filter(|other| patch_state(image, catalog, firmware, other).0 == State::Fixed)
        .map(|other| other.id.as_str())
        .collect();
    if !clash.is_empty() {
        return Some(format!(
            "the image already contains the conflicting {}",
            clash.join(", ")
        ));
    }
    if let Err(error) = check_context(image, &variant.context) {
        return Some(error.message);
    }
    let missing: Vec<&String> = patch
        .requires
        .iter()
        .filter(|r| {
            catalog
                .patches
                .get(*r)
                .is_none_or(|p| patch_state(image, catalog, firmware, p).0 != State::Fixed)
        })
        .collect();
    if !missing.is_empty() {
        return Some(format!(
            "requires {} (select together or apply first)",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    None
}

/// Verify a variant's context modules have one of their reviewed hashes.
pub fn check_context(image: &Image, context: &[crate::catalog::ContextRequirement]) -> Result<()> {
    for need in context {
        let hits: Vec<&[u8]> = image
            .leaves
            .get(&need.ffs_guid)
            .into_iter()
            .flatten()
            .filter_map(|leaf| module_bytes(image, leaf, need.leaf, 0))
            .collect();
        if hits.len() != 1 || !need.sha256_any.contains(&Digest256::of(hits[0])) {
            return Err(Error::new(
                Code::PatchSourceMismatch,
                format!(
                    "context module {} ({}): expected one module with a reviewed hash | found {}",
                    need.name,
                    need.ffs_guid,
                    hits.len()
                ),
            ));
        }
    }
    Ok(())
}

/// Report every patch's state; fall back to signatures on unknown builds.
pub fn scan(image: &Image, catalog: &Catalog, firmware: Option<&str>) -> ScanReport {
    let detection = detect(image, catalog);
    let firmware = firmware
        .map(str::to_string)
        .or_else(|| detection.firmware.clone());
    let boards = firmware
        .as_deref()
        .map(|f| catalog.boards_for(f))
        .unwrap_or_default();
    let mut patches = Vec::new();
    for patch in catalog.patches.values() {
        let (state, detail) = match firmware.as_deref() {
            Some(fw) => {
                let (state, detail) = patch_state(image, catalog, fw, patch);
                if state == State::NotDetected {
                    signature_scan(image, patch, fw)
                } else {
                    (state, detail)
                }
            }
            None => unknown_build_state(image, patch),
        };
        let blocked = match (state, firmware.as_deref()) {
            (State::Present, Some(fw)) => blocker(image, catalog, fw, patch),
            _ => None,
        };
        let requires_facts = firmware
            .as_deref()
            .and_then(|f| patch.applicable(f))
            .map(|v| v.requires_facts.clone())
            .unwrap_or_default();
        patches.push(PatchReport {
            id: patch.id.clone(),
            version: patch.version.to_string(),
            title: patch.title.clone(),
            class: patch.class,
            tier: patch.tier,
            manual: patch.packing == crate::catalog::Packing::Manual,
            state,
            detail,
            plannable: state == State::Present && blocked.is_none(),
            blocked,
            requires_facts,
            evidence: catalog.evidence_for(patch).map(|e| e.id.clone()).collect(),
        });
    }
    let recommended = patches
        .iter()
        .filter(|p| {
            p.plannable
                && p.tier == Tier::Recommended
                && p.class == PatchClass::Correction
                && p.requires_facts.is_empty()
        })
        .map(|p| p.id.clone())
        .collect();
    ScanReport {
        firmware,
        boards,
        detection,
        patches,
        recommended,
    }
}

fn unknown_build_state(image: &Image, patch: &Patch) -> (State, String) {
    let mut first = None;
    for firmware in patch.variants.keys() {
        if patch.components(firmware).is_empty() {
            continue;
        }
        let hit = signature_scan(image, patch, firmware);
        if hit.0 != State::NotDetected {
            return hit;
        }
        first.get_or_insert(hit);
    }
    first.unwrap_or((State::NotApplicable, String::new()))
}
