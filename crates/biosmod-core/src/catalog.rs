//! Catalog contract: manifest, board profiles, patch records, findings and evidence.
//!
//! A catalog is a directory whose `catalog.json` indexes every consumed file
//! by relative path, kind, length and SHA-256. Files live at fixed paths:
//! `boards/<id>.json`, `patches/<id>.json`, `findings/<id>.json`, `evidence/<id>.json`. Loading reads
//! through a [`FileSource`], so the core never touches the filesystem itself.
//!
//! Example:
//! ```no_run
//! # use biosmod_core::catalog::{Catalog, Scope, FileSource};
//! # fn demo(source: &dyn FileSource) -> biosmod_core::Result<()> {
//! let catalog = Catalog::load(source, Scope::All)?;
//! println!("{} patches", catalog.patches.len());
//! # Ok(()) }
//! ```

use crate::error::{Code, Error, Result};
use crate::json::parse_strict;
use crate::util::{Digest256, Guid, HexBytes};
use schemars::JsonSchema;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
pub(crate) mod fixtures;
pub mod merge;
pub mod records;
pub mod split;

pub use merge::{MergeInput, Merged, PinCheck, PinState, Shared, check_pins, merge_catalogs};
pub use records::Records;
pub use split::{Dropped, Split, split_board};

pub const CATALOG_SCHEMA: &str = "bme.catalog/1";
pub const BOARD_SCHEMA: &str = "bme.board/1";
pub const PATCH_SCHEMA: &str = "bme.patch/1";
pub const EVIDENCE_SCHEMA: &str = "bme.evidence/1";
pub const FINDING_SCHEMA: &str = "bme.finding/1";

/// Largest `catalog.json` accepted.
pub const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// Largest single indexed file accepted.
pub const MAX_FILE_BYTES: u64 = 8 << 20;
/// Largest total indexed size accepted.
pub const MAX_TOTAL_BYTES: u64 = 64 << 20;
/// Most indexed files accepted.
pub const MAX_FILES: usize = 4096;

/// Read access to catalog files by validated relative path.
pub trait FileSource {
    /// Read `path` (relative, `/`-separated, already validated), failing when it exceeds `limit` bytes.
    fn read(&self, path: &str, limit: u64) -> Result<Vec<u8>>;
}

/// The catalog index.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub id: String,
    #[schemars(with = "String")]
    pub version: Version,
    pub title: String,
    #[schemars(with = "String")]
    pub engine: VersionReq,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The catalogs a merge built this one from, in merge order. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<CatalogSource>,
    pub files: Vec<FileEntry>,
}

/// A source catalog of a merge, pinned by the digest of its `catalog.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogSource {
    /// The `id` in the source's `catalog.json`.
    pub id: String,
    #[schemars(with = "String")]
    pub version: Version,
    /// SHA-256 of the exact bytes of the source's `catalog.json`.
    pub manifest_sha256: Digest256,
}

/// One indexed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub kind: FileKind,
    pub length: u64,
    pub sha256: Digest256,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    Board,
    Patch,
    /// A defect or observation, with or without a patch.
    Finding,
    Evidence,
    /// Supporting material (assembly sources, notes); hashed, never interpreted.
    Provenance,
}

impl FileKind {
    /// Every kind, in directory-walk order.
    pub const ALL: [FileKind; 5] = [
        FileKind::Board,
        FileKind::Patch,
        FileKind::Finding,
        FileKind::Evidence,
        FileKind::Provenance,
    ];

    /// The directory holding files of this kind.
    pub fn directory(self) -> &'static str {
        match self {
            FileKind::Board => "boards",
            FileKind::Patch => "patches",
            FileKind::Finding => "findings",
            FileKind::Evidence => "evidence",
            FileKind::Provenance => "provenance",
        }
    }
}

/// A board/revision profile: the discovery and compatibility entry point.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Board {
    pub schema: String,
    pub id: String,
    pub vendor: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chipset: Option<String>,
    pub revision: Revision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub firmware: Vec<FirmwareBuild>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    pub patches: Vec<String>,
    /// Findings that concern this board, with or without a patch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// The physical revision a profile describes, and how it is known.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: RevisionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RevisionStatus {
    /// Read from the physical board by a contributor (see `note`/evidence).
    Observed,
    /// Taken from a listing, filename or vendor label only.
    Unverified,
    Unknown,
}

/// One firmware build a board ships; patch variants are keyed by its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirmwareBuild {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_string: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A hardware fact firmware cannot prove; users assert it with `--assert <id>`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub id: String,
    pub statement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PatchClass {
    Correction,
    Diagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Apply first (reference tier 1).
    Recommended,
    /// Reference tier 2.
    Optional,
    /// Unknown hardware effect; refused without `--allow-hold`.
    Hold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Packing {
    #[default]
    Automatic,
    /// Known not to fit automatically; planning refuses it.
    Manual,
}

/// Confidence grades, kept separate as the reference requires.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Confidence {
    pub findings: BTreeMap<String, String>,
    pub offline_fix: String,
    pub physical_fix: String,
}

/// Where a record came from.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub sha256: Digest256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A reusable patch with firmware-specific variants.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub schema: String,
    pub id: String,
    #[schemars(with = "String")]
    pub version: Version,
    pub title: String,
    pub class: PatchClass,
    pub tier: Tier,
    pub findings: Vec<String>,
    /// Findings this patch resolves; a subset of `findings`. Each named
    /// finding lists this patch in its own `patches`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<String>,
    pub confidence: Confidence,
    #[serde(default)]
    pub packing: Packing,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub supersedes: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    pub limits: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Keyed by firmware build id.
    pub variants: BTreeMap<String, Variant>,
}

impl Patch {
    /// Components of the variant for `firmware`; empty when not applicable.
    pub fn components(&self, firmware: &str) -> &[Component] {
        match self.variants.get(firmware) {
            Some(Variant::Applicable(v)) => &v.components,
            _ => &[],
        }
    }

    /// The applicable variant for `firmware`, if any.
    pub fn applicable(&self, firmware: &str) -> Option<&ApplicableVariant> {
        match self.variants.get(firmware) {
            Some(Variant::Applicable(v)) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Variant {
    Applicable(ApplicableVariant),
    NotApplicable(NotApplicable),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotApplicable {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplicableVariant {
    pub components: Vec<Component>,
    /// Board facts that must be asserted before planning.
    #[serde(default)]
    pub requires_facts: Vec<String>,
    /// Other modules whose exact content this variant's analysis depends on.
    #[serde(default)]
    pub context: Vec<ContextRequirement>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum LeafKind {
    /// The PE32 or TE image section.
    Pe32,
    /// A DSDT inside a RAW section.
    AcpiTable,
}

/// Extra structural checks a component requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    /// The module must be uncompressed and linked at the flash address it occupies.
    #[serde(default)]
    pub xip_image_base: bool,
    /// No changed byte may be covered by a PE base relocation.
    #[serde(default)]
    pub no_relocated_bytes: bool,
}

/// One module change for one firmware build.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub ffs_guid: Guid,
    pub leaf: LeafKind,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub table_offset: usize,
    pub source_sha256: Digest256,
    pub source_size: u64,
    pub result_sha256: Digest256,
    pub result_size: u64,
    /// Patches whose combined result these hunks are written against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layer_on: Vec<String>,
    /// Hash of the `layer_on` result; required with `layer_on`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_sha256: Option<Digest256>,
    #[serde(default, skip_serializing_if = "is_default_checks")]
    pub checks: Checks,
    pub hunks: Vec<Hunk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_failure_guard: Option<GuardRecipe>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_default_checks(checks: &Checks) -> bool {
    *checks == Checks::default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HunkOp {
    /// Replace `before` with `after` of the same length.
    Replace,
    /// Append `after` at the end of the module (`before` empty, `offset` = module size).
    Append,
}

/// A guarded byte change in component coordinates.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hunk {
    pub op: HunkOp,
    pub offset: usize,
    pub before: HexBytes,
    pub after: HexBytes,
    #[serde(default)]
    pub context_before: HexBytes,
    #[serde(default)]
    pub context_after: HexBytes,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub wild_before: Vec<usize>,
    #[serde(default)]
    pub wild_after: Vec<usize>,
}

/// Another module whose exact content a variant requires.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextRequirement {
    pub name: String,
    pub ffs_guid: Guid,
    pub leaf: LeafKind,
    pub sha256_any: Vec<Digest256>,
}

/// The reversible recipe for the reference memory-failure guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardRecipe {
    pub revision: u32,
    pub legacy_sha256: Digest256,
    pub legacy_size: usize,
    pub entry_offset: usize,
    pub displaced_prologue: HexBytes,
    pub guard_offset: usize,
    pub guard_size: usize,
    pub halt_fn: u64,
    pub legacy_headers: Vec<GuardHeader>,
    pub assembly_sha256: Digest256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardHeader {
    pub offset: usize,
    pub value: u32,
}

/// Audit priority of a finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Priority {
    P1,
    P2,
    P3,
}

impl Priority {
    /// The label used in documents and tables.
    ///
    /// Example: `Priority::P1.label() == "P1"`.
    pub fn label(self) -> &'static str {
        match self {
            Priority::P1 => "P1",
            Priority::P2 => "P2",
            Priority::P3 => "P3",
        }
    }
}

/// Where a finding stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    /// Not resolved; no patch in the catalog fixes it.
    Open,
    /// At least one patch lists it in `fixes`.
    FixedByPatch,
    /// Withdrawn or superseded by later analysis; kept for the record.
    Retired,
    /// Understood, and no change is justified.
    WontFix,
}

impl FindingStatus {
    /// The kebab-case name used in documents and CLI output.
    ///
    /// Example: `FindingStatus::FixedByPatch.label() == "fixed-by-patch"`.
    pub fn label(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::FixedByPatch => "fixed-by-patch",
            FindingStatus::Retired => "retired",
            FindingStatus::WontFix => "wont-fix",
        }
    }
}

/// One confidence grade (`C0` to `C3`) and the aspect it grades.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grade {
    pub grade: String,
    /// What the grade covers or qualifies, such as `code`, `cause` or `conditional`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Confidence in the finding and in the condition that triggers it, graded apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingConfidence {
    /// How well the code behavior or observation is established.
    pub finding: Grade,
    /// How well the condition or cause that makes it matter is established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Grade>,
}

/// The firmware builds a finding affects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Affects {
    /// Scope in words, such as `Both` or `PR9 only`.
    pub label: String,
    /// Firmware build ids; boards follow from the profiles that ship them.
    pub builds: Vec<String>,
}

/// A module that owns the defective code, named as the firmware names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleRef {
    /// UI section name of the FFS file.
    pub ui_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ffs_guid: Option<Guid>,
}

/// A function or offset inside an owning module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// UI name of the module the location is relative to.
    pub module: String,
    /// Function, RVA, file offset or range, as the analyst wrote it.
    pub location: String,
}

/// The code that owns a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    /// Owning module and routine in words.
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<ModuleRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<CodeReference>,
}

/// The kind of firmware module a detector searches, by FFS file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleKind {
    /// PEI core and PEIMs.
    Peim,
    /// DXE core and DXE drivers.
    Dxe,
    /// SMM drivers and the SMM core.
    Smm,
}

/// Where a detector looks: the module bytes its signatures run over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "in", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Anchor {
    /// The PE32 or TE image of every module, optionally limited to one kind or one FFS GUID.
    Pe32 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        module_kind: Option<ModuleKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ffs_guid: Option<Guid>,
    },
    /// The DSDT held in a RAW section of any file.
    Dsdt,
}

/// A byte pattern with wildcards for addresses and displacements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    pub bytes: HexBytes,
    /// Indices into `bytes` that match any value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wild: Vec<usize>,
}

/// One code shape of a defect, with the shape its correction leaves behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub label: String,
    /// The defective code.
    pub defect: Pattern,
    /// The corrected code, when the catalog has a patch that produces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<Pattern>,
}

/// How many defect sites one module is expected to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    #[serde(default = "one")]
    pub min_per_module: u32,
    #[serde(default = "one")]
    pub max_per_module: u32,
}

fn one() -> u32 {
    1
}

impl Default for Expect {
    fn default() -> Self {
        Expect {
            min_per_module: 1,
            max_per_module: 1,
        }
    }
}

/// A defect-class detector: signatures that find a finding's code in any build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Detector {
    pub id: String,
    pub title: String,
    pub anchor: Anchor,
    pub signatures: Vec<Signature>,
    #[serde(default)]
    pub expect: Expect,
}

/// A defect or observation found in firmware, independent of any patch.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub id: String,
    pub title: String,
    pub priority: Priority,
    pub status: FindingStatus,
    pub affects: Affects,
    pub owner: Owner,
    pub confidence: FindingConfidence,
    /// The defect and its status.
    pub description: String,
    /// What the analysis does not establish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_established: Option<String>,
    /// Remediation strategy, or why there is none, with the fix confidence.
    pub remediation: String,
    /// Evidence record ids that support or weaken the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Patches that fix it; the same patches list this id in `fixes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<String>,
    /// Signatures that find the defect in builds with no recorded variant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detectors: Vec<Detector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Observed on physical hardware; scoped to its board, configuration and image.
    HardwareObservation,
    /// Offline analysis or emulation.
    OfflineValidation,
}

/// A scoped observation about specific patch versions on specific hardware.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub id: String,
    pub kind: EvidenceKind,
    pub date: String,
    pub title: String,
    pub board: String,
    pub firmware: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    pub patches: Vec<EvidencePatch>,
    /// SHA-256 of the exact image tested, when one was flashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<Digest256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_with: Option<String>,
    pub observations: Vec<String>,
    pub limits: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// What the running machine reported, for records made by `bme diag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostObservation>,
    /// The harness, runtime and digests of an emulated run (`bme replay`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayRun>,
}

/// Where and how a `bme diag` command observed the running machine.
///
/// Example: `{"command": "diag acpi capture", "boot_id": "98d86da9-...",
/// "kernel_release": "7.0.0-42-generic", "digests": {"manifest.json": "ab..."}}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    /// The `bme` command that made the observation, such as `diag superio read`.
    pub command: String,
    /// `/proc/sys/kernel/random/boot_id`: ties the record to one boot.
    pub boot_id: String,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel_release: String,
    /// SHA-256 of each artifact the record describes, by name.
    pub digests: BTreeMap<String, Digest256>,
}

/// How an emulated run produced an evidence record: enough to repeat it and to notice that
/// an input or the runtime changed.
///
/// Example: a record from `bme replay script fan.py --module SioDxeInit.pe` lists `fan.py`
/// and `SioDxeInit.pe` under `inputs` and the Unicorn version under `runtime`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayRun {
    /// Harness script or scenario file name.
    pub harness: String,
    /// Scenario id when a `bme.scenario/1` document drove the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    /// Interpreter and package versions that ran it, by name.
    pub runtime: BTreeMap<String, String>,
    /// Every file the run read.
    pub inputs: Vec<ReplayInput>,
    /// SHA-256 of the JSON documents the run emitted, one per line.
    pub output_sha256: Digest256,
}

/// One input file of a replay: its role, name and digest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayInput {
    /// `harness`, `scenario` or `module`.
    pub role: String,
    pub name: String,
    pub sha256: Digest256,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidencePatch {
    pub id: String,
    #[schemars(with = "String")]
    pub version: Version,
}

/// Which part of a catalog to load.
#[derive(Debug, Clone)]
pub enum Scope {
    /// Every indexed file.
    All,
    /// One board profile and its dependency closure.
    Board(String),
}

/// A loaded, validated catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub manifest: Manifest,
    /// SHA-256 of the exact `catalog.json` bytes.
    pub manifest_sha256: Digest256,
    pub boards: BTreeMap<String, Board>,
    pub patches: BTreeMap<String, Patch>,
    pub findings: BTreeMap<String, Finding>,
    pub evidence: BTreeMap<String, Evidence>,
    /// Every file read, with its verified hash.
    pub consumed: Vec<FileEntry>,
    pub scope: Scope,
}

impl Catalog {
    /// Load and validate a catalog through `source`.
    pub fn load(source: &dyn FileSource, scope: Scope) -> Result<Catalog> {
        let bytes = source.read("catalog.json", MAX_MANIFEST_BYTES)?;
        let manifest_sha256 = Digest256::of(&bytes);
        let manifest: Manifest = parse_strict(&bytes, "catalog.json")?;
        crate::validation::manifest(&manifest)?;
        let index: BTreeMap<&str, &FileEntry> = manifest
            .files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect();
        let mut loader = Loader {
            source,
            index,
            consumed: Vec::new(),
        };
        let mut catalog = Catalog {
            manifest: manifest.clone(),
            manifest_sha256,
            boards: BTreeMap::new(),
            patches: BTreeMap::new(),
            findings: BTreeMap::new(),
            evidence: BTreeMap::new(),
            consumed: Vec::new(),
            scope: scope.clone(),
        };
        match &scope {
            Scope::All => {
                for entry in &manifest.files {
                    let bytes = loader.read(&entry.path)?;
                    catalog.insert(entry, &bytes)?;
                }
            }
            Scope::Board(path) => catalog.load_closure(&mut loader, path)?,
        }
        catalog.consumed = loader.consumed;
        crate::validation::catalog(&catalog)?;
        Ok(catalog)
    }

    fn insert(&mut self, entry: &FileEntry, bytes: &[u8]) -> Result<()> {
        let stem = entry
            .path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".json");
        let id = match entry.kind {
            FileKind::Board => {
                let board: Board = parse_strict(bytes, &entry.path)?;
                let id = board.id.clone();
                self.boards.insert(id.clone(), board);
                id
            }
            FileKind::Patch => {
                let patch: Patch = parse_strict(bytes, &entry.path)?;
                let id = patch.id.clone();
                self.patches.insert(id.clone(), patch);
                id
            }
            FileKind::Finding => {
                let finding: Finding = parse_strict(bytes, &entry.path)?;
                let id = finding.id.clone();
                self.findings.insert(id.clone(), finding);
                id
            }
            FileKind::Evidence => {
                let evidence: Evidence = parse_strict(bytes, &entry.path)?;
                let id = evidence.id.clone();
                self.evidence.insert(id.clone(), evidence);
                id
            }
            FileKind::Provenance => return Ok(()),
        };
        if id != stem {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{}: id {id:?} must match the file name {stem:?}",
                    entry.path
                ),
            ));
        }
        Ok(())
    }

    fn load_closure(&mut self, loader: &mut Loader<'_>, board_path: &str) -> Result<()> {
        let entry = loader.entry(board_path)?.clone();
        if entry.kind != FileKind::Board {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{board_path}: expected a board profile | indexed as {:?}",
                    entry.kind
                ),
            ));
        }
        let bytes = loader.read(board_path)?;
        self.insert(&entry, &bytes)?;
        let board = self.boards.values().next().expect("inserted").clone();
        let mut pending: Vec<String> = board.patches.clone();
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let path = format!("patches/{id}.json");
            let entry = loader
                .entry(&path)
                .map_err(|e| e.context(format!("board {} references patch {id}", board.id)))?
                .clone();
            let bytes = loader.read(&path)?;
            self.insert(&entry, &bytes)?;
            let patch = &self.patches[&id];
            pending.extend(
                patch
                    .requires
                    .iter()
                    .chain(&patch.supersedes)
                    .chain(&patch.conflicts)
                    .cloned(),
            );
        }
        // Findings come from the board and from the patches it loaded, so a
        // patch's `fixes` always resolves inside the closure.
        let mut finding_ids: BTreeSet<String> = board.findings.iter().cloned().collect();
        for patch in self.patches.values() {
            finding_ids.extend(patch.fixes.iter().cloned());
        }
        for id in &finding_ids {
            let path = format!("findings/{id}.json");
            let entry = loader
                .entry(&path)
                .map_err(|e| e.context(format!("board {} references finding {id}", board.id)))?
                .clone();
            let bytes = loader.read(&path)?;
            self.insert(&entry, &bytes)?;
        }
        let evidence_ids: BTreeSet<String> = board
            .evidence
            .iter()
            .cloned()
            .chain(self.findings.values().flat_map(|f| f.evidence.clone()))
            .collect();
        for id in &evidence_ids {
            let path = format!("evidence/{id}.json");
            let entry = loader
                .entry(&path)
                .map_err(|e| e.context(format!("board {} references evidence {id}", board.id)))?
                .clone();
            let bytes = loader.read(&path)?;
            self.insert(&entry, &bytes)?;
        }
        Ok(())
    }

    /// Ids of the boards that ship `firmware`, empty when no board declares it.
    ///
    /// Example: `let boards = catalog.boards_for("B05");`
    pub fn boards_for(&self, firmware: &str) -> Vec<String> {
        self.firmware_builds()
            .get(firmware)
            .map(|boards| boards.iter().map(|b| b.id.clone()).collect())
            .unwrap_or_default()
    }

    /// Firmware build ids declared by boards, with the boards that ship them.
    pub fn firmware_builds(&self) -> BTreeMap<&str, Vec<&Board>> {
        let mut builds: BTreeMap<&str, Vec<&Board>> = BTreeMap::new();
        for board in self.boards.values() {
            for build in &board.firmware {
                builds.entry(build.id.as_str()).or_default().push(board);
            }
        }
        builds
    }

    /// Patches that list `firmware` among their variants, in id order.
    pub fn patches_for(&self, firmware: &str) -> impl Iterator<Item = &Patch> {
        self.patches
            .values()
            .filter(move |p| p.variants.contains_key(firmware))
    }

    /// Findings that affect `firmware`, in id order.
    ///
    /// Example: `catalog.findings_for("build-id").filter(|f| f.status == FindingStatus::Open)`.
    pub fn findings_for(&self, firmware: &str) -> impl Iterator<Item = &Finding> {
        self.findings
            .values()
            .filter(move |f| f.affects.builds.iter().any(|b| b == firmware))
    }

    /// Hardware observations that include `patch` at its current version.
    pub fn evidence_for<'a>(&'a self, patch: &'a Patch) -> impl Iterator<Item = &'a Evidence> + 'a {
        self.evidence.values().filter(move |e| {
            e.patches
                .iter()
                .any(|p| p.id == patch.id && p.version == patch.version)
        })
    }
}

struct Loader<'a> {
    source: &'a dyn FileSource,
    index: BTreeMap<&'a str, &'a FileEntry>,
    consumed: Vec<FileEntry>,
}

impl Loader<'_> {
    fn entry(&self, path: &str) -> Result<&FileEntry> {
        self.index.get(path).copied().ok_or_else(|| {
            Error::new(
                Code::CatalogInvalid,
                format!("{path}: not indexed in catalog.json"),
            )
        })
    }

    fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let entry = self.entry(path)?.clone();
        let bytes = self.source.read(&entry.path, entry.length)?;
        if bytes.len() as u64 != entry.length {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{path}: expected length {} | received {}",
                    entry.length,
                    bytes.len()
                ),
            ));
        }
        let digest = Digest256::of(&bytes);
        if digest != entry.sha256 {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{path}: expected sha256 {} | received {digest}",
                    entry.sha256
                ),
            ));
        }
        if !self.consumed.iter().any(|c| c.path == entry.path) {
            self.consumed.push(entry);
        }
        Ok(bytes)
    }
}

/// Build a deterministic index for `files` given as `(path, bytes)`.
///
/// Paths must already use the fixed layout; kinds are derived from the
/// directory. Used by `bme catalog index` so contributors never hand-edit hashes.
pub fn index_files(files: &[(String, Vec<u8>)]) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        crate::validation::relative_path(path)?;
        let top = path.split('/').next();
        let Some(kind) = FileKind::ALL
            .into_iter()
            .find(|k| top == Some(k.directory()))
        else {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: expected boards/, patches/, findings/, evidence/ or provenance/"),
            ));
        };
        entries.push(FileEntry {
            path: path.clone(),
            kind,
            length: bytes.len() as u64,
            sha256: Digest256::of(bytes),
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// An in-memory [`FileSource`], used for the bundled catalog and tests.
#[derive(Debug, Clone, Default)]
pub struct MemorySource {
    files: BTreeMap<String, Vec<u8>>,
}

impl MemorySource {
    /// Create from `(path, bytes)` pairs.
    pub fn new(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> MemorySource {
        MemorySource {
            files: files.into_iter().collect(),
        }
    }

    /// Replace or add one file (tests use this to tamper with catalogs).
    pub fn put(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_string(), bytes);
    }
}

impl FileSource for MemorySource {
    fn read(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        let bytes = self.files.get(path).ok_or_else(|| {
            Error::new(
                Code::CatalogInvalid,
                format!("{path}: missing from catalog source"),
            )
        })?;
        if bytes.len() as u64 > limit {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{path}: {} bytes exceed the indexed length {limit}",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_RECORD: &str = r#"{"schema":"bme.evidence/1","id":"host-x","kind":"hardware-observation",
        "date":"2026-11-12","title":"t","board":"b","firmware":"f","patches":[],
        "observations":[],"limits":"l"HOST}"#;

    #[test]
    fn evidence_host_observation_round_trips_and_stays_optional() {
        let host = r#","host":{"command":"diag acpi capture","boot_id":"b0","kernel_release":"7.0",
            "digests":{"manifest.json":"0000000000000000000000000000000000000000000000000000000000000001"}}"#;
        let with: Evidence =
            parse_strict(HOST_RECORD.replace("HOST", host).as_bytes(), "host.json").unwrap();
        let observed = with.host.as_ref().expect("host observation");
        assert_eq!(observed.command, "diag acpi capture");
        assert_eq!(observed.digests["manifest.json"].0[31], 1);
        let again = serde_json::to_string(&with).unwrap();
        assert!(again.contains("\"host\""), "serialized: {again}");

        let without: Evidence =
            parse_strict(HOST_RECORD.replace("HOST", "").as_bytes(), "plain.json").unwrap();
        assert!(without.host.is_none());
    }
}
