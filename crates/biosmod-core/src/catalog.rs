//! Catalog contract: manifest, board profiles, patch records and evidence.
//!
//! A catalog is a directory whose `catalog.json` indexes every consumed file
//! by relative path, kind, length and SHA-256. Files live at fixed paths:
//! `boards/<id>.json`, `patches/<id>.json`, `evidence/<id>.json`. Loading reads
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

pub const CATALOG_SCHEMA: &str = "bme.catalog/1";
pub const BOARD_SCHEMA: &str = "bme.board/1";
pub const PATCH_SCHEMA: &str = "bme.patch/1";
pub const EVIDENCE_SCHEMA: &str = "bme.evidence/1";

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
    pub files: Vec<FileEntry>,
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
    Evidence,
    /// Supporting material (assembly sources, notes); hashed, never interpreted.
    Provenance,
}

impl FileKind {
    /// Every kind, in directory-walk order.
    pub const ALL: [FileKind; 4] = [
        FileKind::Board,
        FileKind::Patch,
        FileKind::Evidence,
        FileKind::Provenance,
    ];

    /// The directory holding files of this kind.
    pub fn directory(self) -> &'static str {
        match self {
            FileKind::Board => "boards",
            FileKind::Patch => "patches",
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
        for id in &board.evidence {
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
                format!("{path}: expected boards/, patches/, evidence/ or provenance/"),
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
