//! Import `x99-bios-fixes` schema-1 patch records into `bme.patch/1`.
//!
//! The conversion is mechanical and provenance-preserving: hunks, hashes,
//! signatures and limits are copied verbatim; reference board names are
//! mapped to firmware build ids; `hardware_tested` is dropped in favour of
//! scoped evidence records. Unknown legacy fields are rejected rather than
//! silently discarded.
//!
//! Example: `let patch = import(&bytes, "patches/B02-B03.json", &map, &origin)?;`

use crate::catalog::*;
use crate::error::{Code, Error, Result};
use crate::util::{Digest256, Guid, HexBytes};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the legacy records come from.
#[derive(Debug, Clone)]
pub struct Origin {
    pub repository: String,
    pub commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRecord {
    schema: u32,
    id: String,
    title: String,
    findings: Vec<String>,
    finding_confidence: BTreeMap<String, String>,
    local_fix_confidence: String,
    physical_fix_confidence: String,
    hardware_tested: bool,
    tier: serde_json::Value,
    #[serde(default)]
    packing: Option<String>,
    supersedes: Vec<String>,
    conflicts: Vec<String>,
    limits: String,
    boards: BTreeMap<String, LegacyBoard>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyBoard {
    applicable: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    components: Vec<LegacyComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyComponent {
    name: String,
    ffs_guid: Guid,
    leaf: LeafKind,
    #[serde(default)]
    table_offset: usize,
    source_sha256: Digest256,
    source_size: u64,
    result_sha256: Digest256,
    result_size: u64,
    hunks: Vec<LegacyHunk>,
    #[serde(default)]
    memory_failure_guard: Option<GuardRecipe>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyHunk {
    offset: usize,
    before: HexBytes,
    after: HexBytes,
    #[serde(default)]
    context_before: HexBytes,
    #[serde(default)]
    context_after: HexBytes,
    #[serde(default)]
    findings: Vec<String>,
    #[serde(default)]
    wild_before: Vec<usize>,
    #[serde(default)]
    wild_after: Vec<usize>,
}

/// Convert one legacy record. `boards` maps reference board names (e.g. `mr9a`) to firmware ids.
pub fn import(
    bytes: &[u8],
    path: &str,
    boards: &BTreeMap<String, String>,
    origin: &Origin,
) -> Result<Patch> {
    let record: LegacyRecord = crate::json::parse_strict(bytes, path)?;
    let at = format!("{path} ({})", record.id);
    if record.schema != 1 {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "{at}: expected legacy schema 1 | received {}",
                record.schema
            ),
        ));
    }
    if record.hardware_tested {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "{at}: hardware_tested=true needs a scoped evidence record; convert it by hand"
            ),
        ));
    }
    let tier = match &record.tier {
        serde_json::Value::Number(n) if n.as_u64() == Some(1) => Tier::Recommended,
        serde_json::Value::Number(n) if n.as_u64() == Some(2) => Tier::Optional,
        serde_json::Value::String(s) if s == "hold" => Tier::Hold,
        other => {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{at}: tier {other}: expected 1, 2 or \"hold\""),
            ));
        }
    };
    let packing = match record.packing.as_deref() {
        None | Some("automatic") => Packing::Automatic,
        Some("manual") => Packing::Manual,
        Some(other) => {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{at}: packing {other:?}: expected automatic or manual"),
            ));
        }
    };
    let mut variants = BTreeMap::new();
    for (board, entry) in record.boards {
        let firmware = boards
            .get(&board)
            .ok_or_else(|| Error::new(Code::Usage, format!("{at}: board {board:?} has no firmware mapping; pass --map {board}=<firmware-id>")))?;
        let variant = if entry.applicable {
            Variant::Applicable(ApplicableVariant {
                components: entry
                    .components
                    .into_iter()
                    .map(component)
                    .collect::<Result<_>>()
                    .map_err(|e| e.context(&at))?,
                requires_facts: vec![],
                context: vec![],
            })
        } else {
            Variant::NotApplicable(NotApplicable {
                reason: entry.reason.unwrap_or_default(),
            })
        };
        variants.insert(firmware.clone(), variant);
    }
    Ok(Patch {
        schema: PATCH_SCHEMA.into(),
        id: record.id,
        version: semver::Version::new(1, 0, 0),
        title: record.title,
        class: PatchClass::Correction,
        tier,
        findings: record.findings,
        fixes: Vec::new(),
        confidence: Confidence {
            findings: record.finding_confidence,
            offline_fix: record.local_fix_confidence,
            physical_fix: record.physical_fix_confidence,
        },
        packing,
        requires: vec![],
        supersedes: record.supersedes,
        conflicts: record.conflicts,
        limits: record.limits,
        provenance: Some(Provenance {
            repository: origin.repository.clone(),
            commit: origin.commit.clone(),
            path: path.to_string(),
            sha256: Digest256::of(bytes),
            note: Some(
                "converted by `bme catalog import-x99fix`; hunks and hashes copied verbatim".into(),
            ),
        }),
        variants,
    })
}

fn component(legacy: LegacyComponent) -> Result<Component> {
    let hunks = legacy
        .hunks
        .into_iter()
        .map(|h| {
            let op = if h.before.0.is_empty() { HunkOp::Append } else { HunkOp::Replace };
            if op == HunkOp::Replace && h.before.0.len() != h.after.0.len() {
                return Err(Error::new(
                    Code::FormatUnsupported,
                    format!("{}: hunk at {:#x} changes size mid-module; only same-size replace and append are supported", legacy.name, h.offset),
                ));
            }
            Ok(Hunk {
                op,
                offset: h.offset,
                before: h.before,
                after: h.after,
                context_before: h.context_before,
                context_after: h.context_after,
                findings: h.findings,
                wild_before: h.wild_before,
                wild_after: h.wild_after,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Component {
        name: legacy.name,
        ffs_guid: legacy.ffs_guid,
        leaf: legacy.leaf,
        table_offset: legacy.table_offset,
        source_sha256: legacy.source_sha256,
        source_size: legacy.source_size,
        result_sha256: legacy.result_sha256,
        result_size: legacy.result_size,
        layer_on: vec![],
        input_sha256: None,
        checks: Checks::default(),
        hunks,
        memory_failure_guard: legacy.memory_failure_guard,
    })
}
