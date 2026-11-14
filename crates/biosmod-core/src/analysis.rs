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

use crate::catalog::{
    Catalog, Component, Finding, FindingStatus, LeafKind, Patch, PatchClass, Priority, Tier,
    Variant,
};
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
                return None;
            };
            let end = table_offset.checked_add(length)?;
            if length < 36 || end > body.len() {
                return None;
            }
            let table = &body[table_offset..end];
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
///
/// This returns the first matching component per patch without distinguishing
/// table offsets. Use [`related_component`] for an exact component identity.
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

/// Patches targeting the same physical component, including its table offset.
///
/// Example: `related_component(&catalog, "build", &component)` excludes tables
/// at other offsets in the same RAW section.
pub fn related_component<'a>(
    catalog: &'a Catalog,
    firmware: &str,
    component: &Component,
) -> Vec<(&'a Patch, &'a Component)> {
    catalog
        .patches_for(firmware)
        .filter_map(|patch| {
            patch
                .components(firmware)
                .iter()
                .find(|other| {
                    other.ffs_guid == component.ffs_guid
                        && other.leaf == component.leaf
                        && other.table_offset == component.table_offset
                })
                .map(|other| (patch, other))
        })
        .collect()
}

/// Indexed ACPI table ranges for one firmware, including conflicting ranges.
pub(crate) struct TableOffsetIndex {
    ranges: BTreeMap<Guid, BTreeMap<usize, u128>>,
    conflicts: BTreeMap<(Guid, usize), usize>,
}

impl TableOffsetIndex {
    /// Collect the largest declared extent at each table offset and index overlaps.
    ///
    /// Example: ranges 0..64 and 68..132 are disjoint.
    pub(crate) fn new(catalog: &Catalog, firmware: &str) -> Self {
        let mut ranges: BTreeMap<Guid, BTreeMap<usize, u128>> = BTreeMap::new();
        for component in catalog
            .patches_for(firmware)
            .flat_map(|p| p.components(firmware))
        {
            if component.leaf != LeafKind::AcpiTable {
                continue;
            }
            let end = component.table_offset as u128
                + u128::from(component.source_size.max(component.result_size));
            let existing = ranges
                .entry(component.ffs_guid)
                .or_default()
                .entry(component.table_offset)
                .or_insert(end);
            *existing = (*existing).max(end);
        }
        let mut conflicts = BTreeMap::new();
        for (guid, tables) in &ranges {
            let mut furthest: Option<(usize, u128)> = None;
            for (&start, &end) in tables {
                if let Some((previous, previous_end)) = furthest {
                    if (start as u128) < previous_end {
                        conflicts.entry((*guid, previous)).or_insert(start);
                        conflicts.entry((*guid, start)).or_insert(previous);
                    }
                    if end > previous_end {
                        furthest = Some((start, end));
                    }
                } else {
                    furthest = Some((start, end));
                }
            }
        }
        Self { ranges, conflicts }
    }

    /// Describe an overlapping ACPI table identity, if any.
    ///
    /// Example: offsets 0 and 8 overlap when the first table is 64 bytes long.
    pub(crate) fn conflict(&self, component: &Component) -> Option<String> {
        if component.leaf != LeafKind::AcpiTable {
            return None;
        }
        let tables = self.ranges.get(&component.ffs_guid)?;
        let other = self
            .conflicts
            .get(&(component.ffs_guid, component.table_offset))
            .copied()
            .or_else(|| {
                let end = component.table_offset as u128
                    + u128::from(component.source_size.max(component.result_size));
                if tables
                    .get(&component.table_offset)
                    .is_some_and(|known_end| end <= *known_end)
                {
                    return None;
                }
                tables
                    .iter()
                    .filter(|(start, _)| **start != component.table_offset)
                    .find(|(start, other_end)| {
                        (**start as u128) < end && (component.table_offset as u128) < **other_end
                    })
                    .map(|(start, _)| *start)
            })?;
        Some(format!(
            "{}: FFS {} has overlapping ACPI table offsets {:#x} and {:#x}; expected disjoint table ranges",
            component.name, component.ffs_guid, component.table_offset, other
        ))
    }

    /// Return an error when the decoded table exceeds its indexed range.
    ///
    /// Example: a 68-byte table exceeds a recorded 64-byte extent.
    pub(crate) fn extent_error(&self, component: &Component, size: usize) -> Option<String> {
        if component.leaf != LeafKind::AcpiTable {
            return None;
        }
        let end = self
            .ranges
            .get(&component.ffs_guid)
            .and_then(|tables| tables.get(&component.table_offset))
            .copied()
            .unwrap_or_else(|| {
                component.table_offset as u128
                    + u128::from(component.source_size.max(component.result_size))
            });
        let actual_end = component.table_offset as u128 + size as u128;
        (actual_end > end).then(|| format!("{}: ACPI table at {:#x} has {size} bytes | expected at most {} bytes from the catalog", component.name, component.table_offset, end - component.table_offset as u128))
    }

    /// Tell whether an ACPI file has another cataloged table at a different offset.
    ///
    /// Example: offsets 0 and 68 require preserving both positions when rebuilding.
    pub(crate) fn has_other(&self, component: &Component) -> bool {
        self.ranges
            .get(&component.ffs_guid)
            .is_some_and(|tables| tables.len() > 1 || !tables.contains_key(&component.table_offset))
    }
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
    let related = related_component(catalog, firmware, component);
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
        if original.len() as u64 == component.source_size
            && Digest256::of(&original) == component.source_sha256
        {
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
        let mut keys: BTreeMap<(Guid, LeafKind, usize), &Component> = BTreeMap::new();
        for patch in catalog.patches_for(firmware) {
            for component in patch.components(firmware) {
                keys.entry((component.ffs_guid, component.leaf, component.table_offset))
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
    /// Hardware observations of this patch version on the scanned build; empty when the build
    /// is unknown.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// A finding that stays open for the scanned build.
#[derive(Debug, Clone, Serialize)]
pub struct FindingReport {
    pub id: String,
    pub title: String,
    pub priority: Priority,
    /// Finding and condition grades, as in the register's Confidence column.
    pub confidence: String,
}

/// The whole scan result.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub firmware: Option<String>,
    pub boards: Vec<String>,
    pub detection: Detection,
    pub patches: Vec<PatchReport>,
    /// Open findings recorded for the detected build, most urgent first.
    pub findings: Vec<FindingReport>,
    /// Defect-class detector results on this image, whatever the build.
    pub detectors: Vec<crate::detect::DetectorReport>,
    /// Plannable tier-recommended corrections.
    pub recommended: Vec<String>,
}

/// Reuse firmware-specific analysis while checking several patch states.
///
/// ```no_run
/// # use biosmod_core::{analysis::PatchStateContext, catalog::Catalog, firmware::Image};
/// # fn demo(image: &Image, catalog: &Catalog) {
/// let context = PatchStateContext::new(image, catalog, "build-id");
/// for patch in catalog.patches.values() {
///     let (state, detail) = context.patch_state(patch);
///     println!("{state:?}: {detail}");
/// }
/// # }
/// ```
pub struct PatchStateContext<'a> {
    image: &'a Image,
    catalog: &'a Catalog,
    firmware: &'a str,
    offsets: TableOffsetIndex,
}

impl<'a> PatchStateContext<'a> {
    /// Prepare state checks for an image, catalog, and firmware build.
    ///
    /// Example: `PatchStateContext::new(&image, &catalog, "build-id")`.
    pub fn new(image: &'a Image, catalog: &'a Catalog, firmware: &'a str) -> Self {
        Self {
            image,
            catalog,
            firmware,
            offsets: TableOffsetIndex::new(catalog, firmware),
        }
    }

    /// Return the state and explanation for a patch using the bound inputs.
    ///
    /// Example: `context.patch_state(&catalog.patches["PA"])`.
    pub fn patch_state(&self, patch: &Patch) -> (State, String) {
        patch_state_indexed(
            self.image,
            self.catalog,
            self.firmware,
            patch,
            &self.offsets,
        )
    }
}

/// The state of one patch on an image for a known firmware build.
pub fn patch_state(
    image: &Image,
    catalog: &Catalog,
    firmware: &str,
    patch: &Patch,
) -> (State, String) {
    patch_state_indexed(
        image,
        catalog,
        firmware,
        patch,
        &TableOffsetIndex::new(catalog, firmware),
    )
}

/// Evaluate a patch using an index shared by the surrounding scan or build.
///
/// Example: a scan constructs one index and uses it for every patch.
pub(crate) fn patch_state_indexed(
    image: &Image,
    catalog: &Catalog,
    firmware: &str,
    patch: &Patch,
    offsets: &TableOffsetIndex,
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
        if let Some(message) = offsets.conflict(component) {
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
                if let Some((encoding, place)) = image.decode_only_encapsulation(&m.leaf) {
                    return (
                        State::Unsupported,
                        format!(
                            "{} sits inside a decode-only {} section at {place}; rebuild supports LZMA only",
                            component.name,
                            encoding.label()
                        ),
                    );
                }
                if let Some(message) = offsets.extent_error(component, m.current.len()) {
                    return (State::Unsupported, message);
                }
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
                    opaque.push(format!(
                        "{} ({})",
                        component.name,
                        image.opaque_sections_of(component.ffs_guid).join("; ")
                    ));
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
    blocker_indexed(
        image,
        catalog,
        firmware,
        patch,
        &TableOffsetIndex::new(catalog, firmware),
    )
}

/// Find a planning blocker using the caller's firmware-specific offset index.
///
/// Example: a scan reuses its index while evaluating every present patch.
fn blocker_indexed(
    image: &Image,
    catalog: &Catalog,
    firmware: &str,
    patch: &Patch,
    offsets: &TableOffsetIndex,
) -> Option<String> {
    if patch.packing == crate::catalog::Packing::Manual {
        return Some("manual packing: the module grows and must be relocated by hand".into());
    }
    let variant = patch.applicable(firmware)?;
    let clash: Vec<&str> = catalog
        .patches
        .values()
        .filter(|other| other.conflicts.contains(&patch.id) || patch.conflicts.contains(&other.id))
        .filter(|other| {
            patch_state_indexed(image, catalog, firmware, other, offsets).0 == State::Fixed
        })
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
            catalog.patches.get(*r).is_none_or(|p| {
                patch_state_indexed(image, catalog, firmware, p, offsets).0 != State::Fixed
            })
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
    let offsets = firmware
        .as_deref()
        .map(|fw| TableOffsetIndex::new(catalog, fw));
    let mut patches = Vec::new();
    for patch in catalog.patches.values() {
        let (state, detail) = match firmware.as_deref() {
            Some(fw) => {
                let (state, detail) = patch_state_indexed(
                    image,
                    catalog,
                    fw,
                    patch,
                    offsets.as_ref().expect("firmware index"),
                );
                if state == State::NotDetected {
                    signature_scan(image, patch, fw)
                } else {
                    (state, detail)
                }
            }
            None => unknown_build_state(image, patch),
        };
        let blocked = match (state, firmware.as_deref()) {
            (State::Present, Some(fw)) => blocker_indexed(
                image,
                catalog,
                fw,
                patch,
                offsets.as_ref().expect("firmware index"),
            ),
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
            // Without a detected build the image has no board, so no record is its own.
            evidence: firmware
                .as_deref()
                .map(|fw| {
                    catalog
                        .evidence_for(patch, fw)
                        .map(|e| e.id.clone())
                        .collect()
                })
                .unwrap_or_default(),
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
    let findings = firmware
        .as_deref()
        .map(|fw| open_findings(catalog, fw))
        .unwrap_or_default();
    ScanReport {
        firmware,
        boards,
        detection,
        patches,
        findings,
        detectors: crate::detect::run_all(image, catalog),
        recommended,
    }
}

/// Findings still open for `firmware`, ordered by priority and then id.
///
/// Example: `let open = open_findings(&catalog, "build-id");`
pub fn open_findings(catalog: &Catalog, firmware: &str) -> Vec<FindingReport> {
    let mut open: Vec<&Finding> = catalog
        .findings_for(firmware)
        .filter(|f| f.status == FindingStatus::Open)
        .collect();
    open.sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
    open.into_iter()
        .map(|f| FindingReport {
            id: f.id.clone(),
            title: f.title.clone(),
            priority: f.priority,
            confidence: crate::register::confidence_cell(&f.confidence),
        })
        .collect()
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

#[cfg(test)]
mod table_offset_tests {
    use super::*;
    use crate::catalog::{MemorySource, Scope, Variant};
    use crate::synthetic::{self, Fixture};

    #[test]
    fn offset_index_ignores_other_firmware_and_non_acpi_components() {
        let fixture = Fixture::new(7);
        let mut catalog =
            Catalog::load(&MemorySource::new(fixture.catalog_files()), Scope::All).unwrap();
        let mut other = catalog.patches["TB"].clone();
        other.id = "ZZ".into();
        let Variant::Applicable(mut variant) = other.variants.remove(synthetic::FIRMWARE).unwrap()
        else {
            panic!("expected applicable variant")
        };
        variant.components[0].table_offset = 8;
        other
            .variants
            .insert("other-firmware".into(), Variant::Applicable(variant));
        catalog.patches.insert(other.id.clone(), other);
        let index = TableOffsetIndex::new(&catalog, synthetic::FIRMWARE);
        let component = &catalog.patches["TB"].components(synthetic::FIRMWARE)[0];
        assert_eq!(index.conflict(component), None);
        let mut absent = component.clone();
        absent.table_offset = 8;
        assert!(
            index
                .conflict(&absent)
                .unwrap()
                .contains("offsets 0x8 and 0x0")
        );
        absent.leaf = LeafKind::Pe32;
        assert_eq!(index.conflict(&absent), None);
        assert_eq!(
            TableOffsetIndex::new(&catalog, "unknown").conflict(component),
            None
        );
    }
}
