//! Resolve a selection, build a patched image in memory, and verify it.
//!
//! The build follows the reference packer: each touched component is rebuilt
//! from the recovered original plus the union of selected and already-present
//! fixes; LZMA sections are recompressed with their original properties; files
//! grow into free space only when nothing fixed-address moves. The output is
//! re-parsed, every kept patch must read `fixed`, and every byte outside the
//! change allowlist must be identical.
//!
//! Example:
//! ```no_run
//! # use biosmod_core::{plan::{build, Request}, catalog::Catalog, firmware::Image};
//! # fn demo(image: &Image, catalog: &Catalog) -> biosmod_core::Result<()> {
//! let request = Request { select: vec!["B02-B03".into()], ..Request::default() };
//! let built = build(image, catalog, &request)?;
//! # Ok(()) }
//! ```

use crate::analysis::{
    self, State, check_context, included, match_component, minimal, module_bytes, related,
};
use crate::catalog::{Catalog, Component, LeafKind, Packing, Patch, PatchClass, Tier};
use crate::error::{Code, Error, Result};
use crate::firmware::rebuild::{self, Replacement};
use crate::firmware::{Image, pe};
use crate::patch;
use crate::util::{Digest256, Guid, align};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// What to build.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Firmware build id; detected when `None`.
    pub firmware: Option<String>,
    /// Patch ids (unqualified, within the catalog).
    pub select: Vec<String>,
    /// Hardware facts the user asserts.
    pub facts: BTreeSet<String>,
    pub allow_hold: bool,
    pub allow_diagnostic: bool,
}

/// One rebuilt (or already correct) component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentChange {
    pub name: String,
    pub ffs_guid: Guid,
    pub leaf: LeafKind,
    /// Offset of the ACPI table inside its RAW section; 0 for PE32 modules.
    pub table_offset: usize,
    pub file_offset: usize,
    pub patches: Vec<String>,
    pub source_sha256: Digest256,
    pub result_sha256: Digest256,
    pub file_size_change: i64,
    pub rebuilt: bool,
}

/// A byte range `[start, end)` of the image.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// The in-memory build result.
#[derive(Debug, Clone)]
pub struct Built {
    pub firmware: String,
    /// Selected application units after supersession.
    pub selected: Vec<String>,
    /// Fixes already present and kept.
    pub carried: Vec<String>,
    pub image: Vec<u8>,
    pub components: Vec<ComponentChange>,
    pub notes: Vec<String>,
    /// Regions allowed to differ from the input.
    pub allowlist: Vec<Span>,
    /// Regions that actually differ.
    pub changed: Vec<Span>,
}

/// Validate a selection; return the minimal application units and notes.
pub fn resolve(
    catalog: &Catalog,
    firmware: &str,
    request: &Request,
) -> Result<(Vec<String>, Vec<String>)> {
    let unknown: Vec<&String> = request
        .select
        .iter()
        .filter(|id| !catalog.patches.contains_key(*id))
        .collect();
    if !unknown.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "patch ids {unknown:?}: expected ids from catalog {}",
                catalog.manifest.id
            ),
        ));
    }
    if request.select.is_empty() {
        return Err(Error::new(
            Code::SelectionInvalid,
            "selection: expected at least one patch id",
        ));
    }
    let chosen = minimal(catalog, &request.select);
    let mut notes = Vec::new();
    for older in &request.select {
        if !chosen.contains(older)
            && let Some(owner) = chosen
                .iter()
                .find(|id| included(catalog, &[(*id).clone()]).contains(older))
        {
            notes.push(format!("{older} dropped: {owner} already contains it"));
        }
    }
    for id in &chosen {
        let patch = &catalog.patches[id];
        let clash: Vec<&String> = chosen
            .iter()
            .filter(|o| patch.conflicts.contains(o))
            .collect();
        if !clash.is_empty() {
            return Err(Error::new(
                Code::PatchConflict,
                format!("{id} conflicts with {clash:?}: they edit the same bytes; choose one"),
            ));
        }
        if patch.tier == Tier::Hold && !request.allow_hold {
            return Err(Error::new(
                Code::SelectionInvalid,
                format!(
                    "{id} is on hold ({}); pass --allow-hold to include it",
                    short(&patch.limits)
                ),
            ));
        }
        if patch.class == PatchClass::Diagnostic && !request.allow_diagnostic {
            return Err(Error::new(
                Code::SelectionInvalid,
                format!(
                    "{id} is a diagnostic, not a correction; pass --allow-diagnostic to include it"
                ),
            ));
        }
        if patch.packing == Packing::Manual {
            return Err(Error::new(
                Code::PackingRefused,
                format!(
                    "{id} requires manual packing (the module grows and must be relocated by hand); see `bme guide manual`"
                ),
            ));
        }
        let Some(variant) = patch.applicable(firmware) else {
            let reason = match patch.variants.get(firmware) {
                Some(crate::catalog::Variant::NotApplicable(n)) => n.reason.clone(),
                _ => "no variant for this firmware".into(),
            };
            return Err(Error::new(
                Code::SelectionInvalid,
                format!("{id} does not apply to {firmware}: {reason}"),
            ));
        };
        let missing: Vec<&String> = variant
            .requires_facts
            .iter()
            .filter(|f| !request.facts.contains(*f))
            .collect();
        if !missing.is_empty() {
            return Err(Error::new(
                Code::AssertionRequired,
                format!(
                    "{id} requires hardware facts {missing:?}; confirm them on the physical board and pass --assert <fact>"
                ),
            ));
        }
    }
    Ok((chosen, notes))
}

fn short(text: &str) -> String {
    let cut: String = text.chars().take(80).collect();
    if cut.len() < text.len() {
        format!("{cut}...")
    } else {
        cut
    }
}

fn carried_fixes(
    catalog: &Catalog,
    present: &[String],
    wanted: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut keep = BTreeSet::new();
    for id in present {
        let superseded = wanted
            .iter()
            .any(|w| w != id && included(catalog, std::slice::from_ref(w)).contains(id));
        if superseded {
            continue;
        }
        let clash: Vec<&String> = wanted
            .iter()
            .filter(|w| {
                catalog.patches[*w].conflicts.contains(id)
                    || catalog.patches[id].conflicts.contains(w)
            })
            .collect();
        if !clash.is_empty() {
            return Err(Error::new(
                Code::PatchConflict,
                format!(
                    "image already contains {id}, which conflicts with {clash:?}; start from an unpatched dump"
                ),
            ));
        }
        keep.insert(id.clone());
    }
    Ok(keep)
}

/// Build the patched image for a request; nothing is written anywhere.
pub fn build(image: &Image, catalog: &Catalog, request: &Request) -> Result<Built> {
    let firmware = match &request.firmware {
        Some(f) => f.clone(),
        None => {
            let detection = analysis::detect(image, catalog);
            if detection.ambiguous {
                return Err(Error::new(
                    Code::TargetAmbiguous,
                    "firmware build: several builds match equally; pass --firmware",
                ));
            }
            detection.firmware.ok_or_else(|| {
                Error::new(Code::PatchSourceMismatch, "firmware build: no cataloged build's original modules were found; see `bme guide porting`")
            })?
        }
    };
    let (chosen, mut notes) = resolve(catalog, &firmware, request)?;
    let wanted: BTreeSet<String> = chosen.iter().cloned().collect();
    // Conflicts apply to the whole image, including modules we will not rebuild.
    let installed: Vec<String> = catalog
        .patches_for(&firmware)
        .filter(|patch| analysis::patch_state(image, catalog, &firmware, patch).0 == State::Fixed)
        .map(|patch| patch.id.clone())
        .collect();
    carried_fixes(catalog, &installed, &wanted)?;
    let covered = included(catalog, &chosen);
    for id in &chosen {
        for need in &catalog.patches[id].requires {
            let present = analysis::patch_state(image, catalog, &firmware, &catalog.patches[need])
                .0
                == State::Fixed;
            if !covered.contains(need) && !present {
                return Err(Error::new(
                    Code::SelectionInvalid,
                    format!(
                        "{id} requires {need}; select it too or start from an image that has it"
                    ),
                ));
            }
        }
    }
    let mut plan: Vec<(&Component, analysis::Match)> = Vec::new();
    for id in &chosen {
        let patch = &catalog.patches[id];
        for component in patch.components(&firmware) {
            if plan
                .iter()
                .any(|(c, _)| c.ffs_guid == component.ffs_guid && c.leaf == component.leaf)
            {
                continue;
            }
            let count = analysis::copies(image, component);
            if count > 1 {
                return Err(Error::new(
                    Code::TargetAmbiguous,
                    format!(
                        "{id}/{}: module {} occurs {count} times | expected exactly one",
                        component.name, component.ffs_guid
                    ),
                ));
            }
            let found = match_component(image, catalog, &firmware, component).ok_or_else(|| {
                let (state, detail) = analysis::patch_state(image, catalog, &firmware, patch);
                let code = if state == State::Unsupported { Code::FormatUnsupported } else { Code::PatchSourceMismatch };
                Error::new(code, format!("{id}/{}: module differs from the {firmware} original this patch was made for ({detail})", component.name))
            })?;
            plan.push((component, found));
        }
        check_context(
            image,
            &patch.applicable(&firmware).expect("resolved").context,
        )
        .map_err(|e| e.context(id))?;
    }
    let mut carried_all = BTreeSet::new();
    let mut by_volume: BTreeMap<usize, Vec<Replacement>> = BTreeMap::new();
    let mut components = Vec::new();
    for (component, found) in &plan {
        let related = related(catalog, &firmware, component.ffs_guid, component.leaf);
        let related_ids: BTreeSet<String> = related.iter().map(|(p, _)| p.id.clone()).collect();
        let carried = carried_fixes(catalog, &found.fixed, &wanted)?;
        carried_all.extend(carried.iter().cloned());
        let candidates: Vec<String> = carried
            .union(&wanted.intersection(&related_ids).cloned().collect())
            .cloned()
            .collect();
        let keep: Vec<String> = {
            let mut k = minimal(catalog, &candidates);
            k.sort();
            k
        };
        let result = compose(&firmware, component, &found.original, &keep, &related)?;
        check_structure(image, found, &related, &keep)?;
        let file = image.file(&found.leaf);
        let mut change = ComponentChange {
            name: component.name.clone(),
            ffs_guid: component.ffs_guid,
            leaf: component.leaf,
            table_offset: component.table_offset,
            file_offset: file.offset,
            patches: keep.clone(),
            source_sha256: component.source_sha256,
            result_sha256: Digest256::of(&result),
            file_size_change: 0,
            rebuilt: false,
        };
        if result == found.current {
            components.push(change);
            continue;
        }
        let mut body = result.clone();
        if component.leaf == LeafKind::AcpiTable {
            let container = image.leaf_body(&found.leaf);
            let at = component.table_offset;
            body = [
                &container[..at],
                &result[..],
                &container[at + found.current.len()..],
            ]
            .concat();
        }
        let data = rebuild::keep_extent(
            rebuild::rebuilt_file(image, &found.leaf, &body)?,
            file.extent(),
            file.header_size,
        )?;
        change.file_size_change = align(data.len(), 8) as i64 - file.extent() as i64;
        change.rebuilt = true;
        let slot = by_volume.entry(found.leaf.volume).or_default();
        if slot.iter().any(|(i, _)| *i == found.leaf.file) {
            return Err(Error::new(
                Code::FormatUnsupported,
                format!(
                    "{}: two selected components live in the same FFS file",
                    component.name
                ),
            ));
        }
        slot.push((found.leaf.file, data));
        components.push(change);
    }
    let mut out = image.bytes.clone();
    let mut allowlist = Vec::new();
    for (index, replaced) in &by_volume {
        let volume = &image.volumes[*index];
        let grows = replaced
            .iter()
            .any(|(i, d)| align(d.len(), 8) > volume.files[*i].extent());
        if grows {
            notes.extend(rebuild::reflow(image, &mut out, volume, replaced)?);
            allowlist.push(Span {
                start: volume.offset,
                end: volume.offset + volume.length,
            });
        } else {
            rebuild::write_in_place(&mut out, volume, replaced);
            allowlist.extend(replaced.iter().map(|(i, _)| {
                let file = &volume.files[*i];
                Span {
                    start: file.offset,
                    end: file.offset + file.extent(),
                }
            }));
        }
    }
    allowlist.sort();
    let carried: Vec<String> = carried_all.difference(&wanted).cloned().collect();
    let built = Built {
        firmware,
        selected: chosen,
        carried,
        changed: diff(&image.bytes, &out),
        image: out,
        components,
        notes,
        allowlist,
    };
    verify_built(image, catalog, built)
}

/// Apply the kept patches to the recovered original, base patches before layered ones.
fn compose(
    firmware: &str,
    component: &Component,
    original: &[u8],
    keep: &[String],
    related: &[(&Patch, &Component)],
) -> Result<Vec<u8>> {
    let lookup = |id: &String| related.iter().find(|(p, _)| &p.id == id).map(|(_, c)| *c);
    let (layered, base): (Vec<&String>, Vec<&String>) = keep
        .iter()
        .partition(|id| lookup(id).is_some_and(|c| !c.layer_on.is_empty()));
    let mut result = patch::apply(
        original,
        base.iter()
            .filter_map(|id| lookup(id))
            .flat_map(|c| &c.hunks),
    )
    .map_err(|e| e.context(format!("{} on {firmware}", component.name)))?;
    if !layered.is_empty() {
        for id in &layered {
            let layer = lookup(id).expect("partitioned");
            if Some(Digest256::of(&result)) != layer.input_sha256 {
                return Err(Error::new(
                    Code::PatchSourceMismatch,
                    format!(
                        "{id} is written against exactly {:?} on {}; the combined module differs (kept: {keep:?})",
                        layer.layer_on, component.name
                    ),
                ));
            }
        }
        result = patch::apply(
            &result,
            layered
                .iter()
                .filter_map(|id| lookup(id))
                .flat_map(|c| &c.hunks),
        )?;
    }
    let expect_single = |id: &String, c: &Component| {
        if Digest256::of(&result) != c.result_sha256 {
            return Err(Error::new(
                Code::OutputVerificationFailed,
                format!(
                    "{}: result hash differs from the published {id} result",
                    component.name
                ),
            ));
        }
        Ok(())
    };
    if keep.len() == 1 {
        expect_single(&keep[0], lookup(&keep[0]).expect("kept patch is related"))?;
    } else if let [only] = layered.as_slice() {
        let layer = lookup(only).expect("partitioned");
        let bases: BTreeSet<&String> = base.iter().copied().collect();
        if bases == layer.layer_on.iter().collect() {
            expect_single(only, layer)?;
        }
    }
    Ok(result)
}

/// Enforce per-component structural checks on the original and result.
fn check_structure(
    image: &Image,
    found: &analysis::Match,
    related: &[(&Patch, &Component)],
    keep: &[String],
) -> Result<()> {
    for (patch, component) in related.iter().filter(|(p, _)| keep.contains(&p.id)) {
        if component.checks.xip_image_base {
            let file = image.file(&found.leaf);
            let in_place = !found.leaf.compressed && found.leaf.path.len() == 1;
            let (section, _) = image.section(&found.leaf);
            let address = image.flash_base()
                + (file.offset + file.header_size + section.offset + section.header_size) as u64;
            let base = pe::image_base(&found.original)?;
            if !in_place || base != Some(address) {
                return Err(Error::new(
                    Code::PatchSourceMismatch,
                    format!(
                        "{}/{}: expected an uncompressed module linked at its flash address {address:#x} | image base {base:x?}",
                        patch.id, component.name
                    ),
                ));
            }
        }
        if component.checks.no_relocated_bytes {
            let covered = pe::relocation_offsets(&found.original)?;
            if let Some(h) = component
                .hunks
                .iter()
                .find(|h| touches_relocation(h, &covered))
            {
                return Err(Error::new(
                    Code::PatchSourceMismatch,
                    format!(
                        "{}/{}: hunk at {:#x} touches a PE base relocation",
                        patch.id, component.name, h.offset
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Whether a hunk's original or replacement bytes overlap a relocated byte.
///
/// Example: a hunk at 4 with 3 `before` bytes touches a relocation at offset 6.
fn touches_relocation(hunk: &crate::catalog::Hunk, covered: &BTreeSet<usize>) -> bool {
    let len = hunk.before.0.len().max(hunk.after.0.len());
    let end = hunk.offset.saturating_add(len);
    covered.range(hunk.offset..end).next().is_some()
}

/// Re-parse the output and confirm states and untouched bytes.
fn verify_built(input: &Image, catalog: &Catalog, mut built: Built) -> Result<Built> {
    let check = Image::parse(std::mem::take(&mut built.image)).map_err(|e| {
        Error::new(
            Code::OutputVerificationFailed,
            format!("re-parsed output: {}", e.message),
        )
    })?;
    for id in built.selected.iter().chain(&built.carried) {
        let (state, detail) =
            analysis::patch_state(&check, catalog, &built.firmware, &catalog.patches[id]);
        if state != State::Fixed {
            return Err(Error::new(
                Code::OutputVerificationFailed,
                format!("{id}: re-parsed output shows {state:?} ({detail}) | expected fixed"),
            ));
        }
    }
    outside_allowlist_unchanged(&input.bytes, &check.bytes, &built.allowlist)?;
    verify_components(&check, &built.components)?;
    built.image = check.bytes;
    Ok(built)
}

/// Confirm each rebuilt component is present in the re-parsed output with its composed hash.
///
/// Example: a plan whose ACPI table sits at offset 8 of its RAW section is found at
/// `table_offset: 8` and refused at 0.
fn verify_components(check: &Image, components: &[ComponentChange]) -> Result<()> {
    for change in components {
        let leaves = check
            .leaves
            .get(&change.ffs_guid)
            .cloned()
            .unwrap_or_default();
        let found = leaves
            .iter()
            .filter_map(|l| module_bytes(check, l, change.leaf, change.table_offset))
            .any(|bytes| Digest256::of(bytes) == change.result_sha256);
        if !found {
            return Err(Error::new(
                Code::OutputVerificationFailed,
                format!(
                    "{}: re-parsed {:?} module hash differs from the composed result {}",
                    change.name, change.leaf, change.result_sha256
                ),
            ));
        }
    }
    Ok(())
}

/// Fail when any byte outside `allowlist` differs, or the size changed.
pub fn outside_allowlist_unchanged(input: &[u8], output: &[u8], allowlist: &[Span]) -> Result<()> {
    if input.len() != output.len() {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            format!(
                "image size: expected {} | received {}",
                input.len(),
                output.len()
            ),
        ));
    }
    if let Some(bad) = allowlist
        .iter()
        .find(|s| s.start > s.end || s.end > input.len())
    {
        return Err(Error::new(
            Code::PlanInvalid,
            format!(
                "allowlist span {:#x}..{:#x} | expected start <= end <= image size {:#x}",
                bad.start,
                bad.end,
                input.len()
            ),
        ));
    }
    let mut cursor = 0;
    for span in allowlist.iter().chain(std::iter::once(&Span {
        start: input.len(),
        end: input.len(),
    })) {
        if span.start > cursor && input[cursor..span.start] != output[cursor..span.start] {
            let first = (cursor..span.start)
                .find(|i| input[*i] != output[*i])
                .unwrap_or(cursor);
            return Err(Error::new(
                Code::OutputVerificationFailed,
                format!("byte {first:#x} outside the change allowlist differs"),
            ));
        }
        cursor = cursor.max(span.end);
    }
    Ok(())
}

/// Ranges where two equal-length buffers differ, merged when closer than 16 bytes.
pub fn diff(a: &[u8], b: &[u8]) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x == y {
            continue;
        }
        match spans.last_mut() {
            Some(last) if i <= last.end + 16 => last.end = i + 1,
            _ => spans.push(Span {
                start: i,
                end: i + 1,
            }),
        }
    }
    spans
}

/// Count of differing bytes between equal-length buffers.
pub fn changed_bytes(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}

/// Versioned plan and output-manifest documents.
///
/// A plan is untrusted data: applying it re-resolves the selection from the
/// pinned catalog, rebuilds from scratch and only compares digests. Editing a
/// plan can change what is requested, never which checks run.
pub mod document {
    use super::{Built, ComponentChange, Request, Span};
    use crate::catalog::{Catalog, FileEntry};
    use crate::util::Digest256;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    pub const PLAN_SCHEMA: &str = "bme.plan/1";
    pub const MANIFEST_SCHEMA: &str = "bme.manifest/1";
    /// Printed in every manifest and verify report.
    pub const NOTICE: &str = "Offline structural verification only. It does not establish boot safety, hardware compatibility or signature/platform-enforcement acceptance.";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct Blob {
        pub sha256: Digest256,
        pub length: u64,
    }

    impl Blob {
        pub fn of(bytes: &[u8]) -> Blob {
            Blob {
                sha256: Digest256::of(bytes),
                length: bytes.len() as u64,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct EngineId {
        pub version: String,
        pub codec: String,
    }

    impl EngineId {
        pub fn current() -> EngineId {
            EngineId {
                version: crate::VERSION.into(),
                codec: crate::codec::identity(),
            }
        }
    }

    /// The catalog snapshot a plan was made against.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct SourcePin {
        pub alias: String,
        pub trust: String,
        pub location: String,
        /// Board profile path when the catalog was loaded as a board closure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        pub catalog_id: String,
        pub catalog_version: String,
        pub manifest_sha256: Digest256,
        pub files: Vec<FileEntry>,
    }

    impl SourcePin {
        /// Compare a freshly loaded catalog with this pin.
        pub fn matches(&self, catalog: &Catalog) -> bool {
            self.manifest_sha256 == catalog.manifest_sha256 && self.files == catalog.consumed
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct PlanDocument {
        pub schema: String,
        pub engine: EngineId,
        pub input: Blob,
        pub source: SourcePin,
        pub firmware: String,
        pub boards: Vec<String>,
        /// Selection as requested, qualified as `alias::id@version`.
        pub requested: Vec<String>,
        /// Application units after supersession.
        pub selected: Vec<String>,
        /// Fixes already present and preserved.
        pub carried: Vec<String>,
        pub facts: Vec<String>,
        pub allow_hold: bool,
        pub allow_diagnostic: bool,
        pub components: Vec<ComponentChange>,
        pub notes: Vec<String>,
        pub allowlist: Vec<Span>,
        pub changed: Vec<Span>,
        pub output: Blob,
        /// Evidence ids whose recorded image digest equals this output.
        pub identical_to_observed_images: Vec<String>,
    }

    impl PlanDocument {
        /// Describe a build.
        pub fn new(
            built: &Built,
            input: &[u8],
            source: SourcePin,
            boards: Vec<String>,
            requested: Vec<String>,
            request: &Request,
            catalog: &Catalog,
        ) -> PlanDocument {
            let output = Blob::of(&built.image);
            let observed = catalog
                .evidence
                .values()
                .filter(|e| e.image_sha256 == Some(output.sha256))
                .map(|e| e.id.clone())
                .collect();
            PlanDocument {
                schema: PLAN_SCHEMA.into(),
                engine: EngineId::current(),
                input: Blob::of(input),
                source,
                firmware: built.firmware.clone(),
                boards,
                requested,
                selected: built.selected.clone(),
                carried: built.carried.clone(),
                facts: request.facts.iter().cloned().collect(),
                allow_hold: request.allow_hold,
                allow_diagnostic: request.allow_diagnostic,
                components: built.components.clone(),
                notes: built.notes.clone(),
                allowlist: built.allowlist.clone(),
                changed: built.changed.clone(),
                output,
                identical_to_observed_images: observed,
            }
        }

        /// The build request this plan describes (ids unqualified).
        pub fn request(&self) -> Request {
            Request {
                firmware: Some(self.firmware.clone()),
                select: self.selected.clone(),
                facts: self.facts.iter().cloned().collect(),
                allow_hold: self.allow_hold,
                allow_diagnostic: self.allow_diagnostic,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct Verification {
        pub reparsed: bool,
        pub patches_fixed: Vec<String>,
        pub outside_allowlist_identical: bool,
        pub changed_bytes: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct OutputManifest {
        pub schema: String,
        pub output_file: String,
        pub plan: PlanDocument,
        pub verification: Verification,
        pub notice: String,
    }
}

#[cfg(test)]
mod relocation_tests {
    use super::*;
    use crate::catalog::{Hunk, HunkOp};
    use crate::util::HexBytes;

    fn hunk(offset: usize, before: &[u8], after: &[u8]) -> Hunk {
        Hunk {
            op: HunkOp::Replace,
            offset,
            before: HexBytes(before.to_vec()),
            after: HexBytes(after.to_vec()),
            context_before: HexBytes::default(),
            context_after: HexBytes::default(),
            findings: vec![],
            wild_before: vec![],
            wild_after: vec![],
        }
    }

    #[test]
    fn relocation_check_covers_the_longer_of_before_and_after() {
        let covered: BTreeSet<usize> = [6].into();
        assert!(touches_relocation(&hunk(4, &[1, 2, 3], &[9]), &covered));
        assert!(touches_relocation(&hunk(6, &[1], &[9, 9]), &covered));
        assert!(!touches_relocation(&hunk(0, &[1, 2], &[9, 9]), &covered));
    }
}

#[cfg(test)]
mod component_verification_tests {
    use super::*;
    use crate::synthetic::{TABLE_GUID, acpi, ffs, module, section, volume};

    fn image_with_table_at(prefix: usize) -> (Image, Vec<u8>) {
        let table = acpi(&module(3, 96));
        let body = [vec![0u8; prefix], table.clone()].concat();
        let file = ffs(TABLE_GUID, 0x02, &section(0x19, &body), 0);
        let mut bytes = vec![0xFF; 0x1000];
        bytes.extend(volume(&[file], 0x4000));
        (Image::parse(bytes).expect("synthetic image parses"), table)
    }

    fn change(table_offset: usize, result: &[u8]) -> ComponentChange {
        ComponentChange {
            name: "Table".into(),
            ffs_guid: TABLE_GUID,
            leaf: LeafKind::AcpiTable,
            table_offset,
            file_offset: 0,
            patches: vec![],
            source_sha256: Digest256::of(&[]),
            result_sha256: Digest256::of(result),
            file_size_change: 0,
            rebuilt: true,
        }
    }

    #[test]
    fn acpi_table_hash_mismatch_is_refused() {
        let (image, table) = image_with_table_at(0);
        let mut wrong = table.clone();
        wrong[40] ^= 0xFF;
        let err = verify_components(&image, &[change(0, &wrong)]).unwrap_err();
        assert_eq!(err.code, Code::OutputVerificationFailed);
        assert!(err.message.contains("hash differs"), "{err}");
    }

    #[test]
    fn acpi_table_is_found_at_its_recorded_offset() {
        let (image, table) = image_with_table_at(8);
        verify_components(&image, &[change(8, &table)]).expect("table at offset 8");
        let err = verify_components(&image, &[change(0, &table)]).unwrap_err();
        assert_eq!(err.code, Code::OutputVerificationFailed);
    }
}
