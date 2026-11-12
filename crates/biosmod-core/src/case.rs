//! Investigation cases: the `bme.case/1` document, status checks and catalog export.
//!
//! A case is a directory that follows one investigation of one image. It lists
//! its inputs by digest, never copies them, and keeps every recorded command
//! result as an artifact with the exact command, engine version, catalog
//! snapshot and input digests that produced it. Everything here is pure: the
//! CLI hashes files and passes the observations in, and writes what comes out.
//!
//! Example:
//! ```
//! use biosmod_core::case::{Case, CASE_SCHEMA};
//! let case = Case {
//!     schema: CASE_SCHEMA.into(),
//!     id: "draft-board".into(),
//!     engine: "0.1.0".into(),
//!     created: "2026-11-12T10:00:00Z".into(),
//!     catalogs: vec![],
//!     inputs: vec![],
//!     artifacts: vec![],
//! };
//! assert_eq!(case.next_artifact_number(), 1);
//! ```

use crate::catalog::{
    BOARD_SCHEMA, Board, CATALOG_SCHEMA, Catalog, EVIDENCE_SCHEMA, Evidence, EvidenceKind, Finding,
    FindingStatus, Manifest, MemorySource, Scope, index_files,
};
use crate::draft::FirmwareDraft;
use crate::error::{Code, Error, Result};
use crate::json::pretty;
use crate::plan::document::Blob;
use crate::util::Digest256;
use crate::validation::identifier;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CASE_SCHEMA: &str = "bme.case/1";
/// Directory of a case that holds recorded artifacts.
pub const ARTIFACT_DIRECTORY: &str = "artifacts";

/// One identified input file: its name and content, never its location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    /// File name, such as `dump.bin`.
    pub name: String,
    pub sha256: Digest256,
    pub length: u64,
}

/// The catalog a result was computed against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshot {
    pub alias: String,
    pub id: String,
    pub version: String,
    /// SHA-256 of the exact `catalog.json` bytes.
    pub manifest_sha256: Digest256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// The `bme/1` JSON envelope a command printed.
    Output,
    /// A file the command wrote, copied into the case.
    File,
    /// A directory tree the command wrote, copied into the case; `files` lists it.
    Directory,
}

/// One file of a recorded directory artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    /// Path inside the directory, `/`-separated, such as `tables/DSDT.aml`.
    pub path: String,
    pub sha256: Digest256,
    pub length: u64,
}

/// The digest a directory artifact records: SHA-256 over its sorted file list.
///
/// Each file is one line, `<sha256> <length> <path>\n`, in path order, so the digest
/// covers names and bytes but not the order the files were listed in. `length` is the
/// sum of the file lengths.
///
/// Example: two files `a` and `b` give the same blob in either order.
/// ```
/// use biosmod_core::case::{ArtifactFile, tree_blob};
/// use biosmod_core::util::Digest256;
/// let file = |path: &str, byte: u8| ArtifactFile {
///     path: path.into(),
///     sha256: Digest256([byte; 32]),
///     length: 3,
/// };
/// let forward = tree_blob(&[file("a", 1), file("b", 2)]);
/// assert_eq!(forward, tree_blob(&[file("b", 2), file("a", 1)]));
/// assert_eq!(forward.length, 6);
/// ```
pub fn tree_blob(files: &[ArtifactFile]) -> Blob {
    let mut sorted: Vec<&ArtifactFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let listing: String = sorted
        .iter()
        .map(|f| format!("{} {} {}\n", f.sha256, f.length, f.path))
        .collect();
    Blob {
        sha256: Digest256::of(listing.as_bytes()),
        length: files.iter().map(|f| f.length).sum(),
    }
}

/// How one file of a directory artifact differs from its record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileStatus {
    pub path: String,
    /// `Missing` for a recorded file that is gone; `Changed` for other bytes or an unrecorded file.
    pub state: Verdict,
}

/// Compare a recorded directory with the files found in it; verified files are left out.
///
/// Example: a recorded file with other bytes is `Changed`, one that is gone is `Missing`,
/// and a file the record never listed is `Changed`.
/// ```
/// use biosmod_core::case::{ArtifactFile, Verdict, tree_changes};
/// use biosmod_core::util::Digest256;
/// let file = |path: &str, byte: u8| ArtifactFile {
///     path: path.into(),
///     sha256: Digest256([byte; 32]),
///     length: 3,
/// };
/// let changes = tree_changes(&[file("a", 1), file("b", 2)], &[file("a", 9), file("c", 3)]);
/// let states: Vec<_> = changes.iter().map(|c| (c.path.as_str(), c.state)).collect();
/// assert_eq!(
///     states,
///     [("a", Verdict::Changed), ("b", Verdict::Missing), ("c", Verdict::Changed)]
/// );
/// ```
pub fn tree_changes(recorded: &[ArtifactFile], found: &[ArtifactFile]) -> Vec<FileStatus> {
    let found: BTreeMap<&str, &ArtifactFile> = found.iter().map(|f| (f.path.as_str(), f)).collect();
    let mut changes: BTreeMap<String, Verdict> = BTreeMap::new();
    for file in recorded {
        match found.get(file.path.as_str()) {
            None => {
                changes.insert(file.path.clone(), Verdict::Missing);
            }
            Some(now) if now.sha256 != file.sha256 || now.length != file.length => {
                changes.insert(file.path.clone(), Verdict::Changed);
            }
            Some(_) => {}
        }
    }
    let listed: BTreeSet<&str> = recorded.iter().map(|f| f.path.as_str()).collect();
    for path in found.keys().filter(|p| !listed.contains(**p)) {
        changes.insert((*path).to_string(), Verdict::Changed);
    }
    changes
        .into_iter()
        .map(|(path, state)| FileStatus { path, state })
        .collect()
}

/// A recorded command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Unique within the case, such as `001-scan`.
    pub id: String,
    /// Path relative to the case directory, `/`-separated.
    pub path: String,
    pub kind: ArtifactKind,
    pub sha256: Digest256,
    pub length: u64,
    /// The `bme` arguments exactly as run, without the program name.
    pub command: Vec<String>,
    /// Engine version that produced it.
    pub bme_version: String,
    pub catalogs: Vec<CatalogSnapshot>,
    /// Existing files named by the command, by digest.
    pub inputs: Vec<CaseInput>,
    /// UTC time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub recorded: String,
    /// The files of a `directory` artifact, whose `sha256` is `tree_blob` of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ArtifactFile>,
}

/// The `bme.case/1` document (`case.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub schema: String,
    /// Draft board id the case works on.
    pub id: String,
    /// Engine version that created the case.
    pub engine: String,
    /// UTC time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub created: String,
    pub catalogs: Vec<CatalogSnapshot>,
    pub inputs: Vec<CaseInput>,
    pub artifacts: Vec<Artifact>,
}

impl Case {
    /// The number the next artifact takes: one above the highest `NNN-` prefix in use.
    ///
    /// Example: a case holding `001-scan` returns 2.
    pub fn next_artifact_number(&self) -> u32 {
        self.artifacts
            .iter()
            .filter_map(|a| a.id.split('-').next()?.parse::<u32>().ok())
            .max()
            .map_or(1, |n| n + 1)
    }

    /// Check the document's own consistency: schema, ids, unique artifacts and paths.
    ///
    /// Example: `case.check()?` fails with `FORMAT_INVALID` on a duplicate artifact id.
    pub fn check(&self) -> Result<()> {
        let invalid = |message: String| Error::new(Code::FormatInvalid, message);
        if self.schema != CASE_SCHEMA {
            return Err(invalid(format!(
                "case.json: expected schema {CASE_SCHEMA:?} | received {:?}",
                self.schema
            )));
        }
        identifier(&self.id, "case id").map_err(|e| invalid(e.message))?;
        let prefix = format!("{ARTIFACT_DIRECTORY}/");
        let mut seen = BTreeSet::new();
        for artifact in &self.artifacts {
            identifier(&artifact.id, "artifact id").map_err(|e| invalid(e.message))?;
            let name = artifact.path.strip_prefix(&prefix).unwrap_or("");
            if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
                return Err(invalid(format!(
                    "case.json artifact {}: path expected {prefix}<name> | received {:?}",
                    artifact.id, artifact.path
                )));
            }
            if !seen.insert(artifact.id.as_str()) {
                return Err(invalid(format!(
                    "case.json: duplicate artifact id {:?}",
                    artifact.id
                )));
            }
            if artifact.kind != ArtifactKind::Directory && !artifact.files.is_empty() {
                return Err(invalid(format!(
                    "case.json artifact {}: expected no files unless kind is directory | received {}",
                    artifact.id,
                    artifact.files.len()
                )));
            }
            let mut listed = BTreeSet::new();
            for file in &artifact.files {
                let safe = !file.path.is_empty()
                    && file.path.split('/').all(|part| {
                        !part.is_empty() && !part.starts_with('.') && !part.contains('\\')
                    });
                if !safe || !listed.insert(file.path.as_str()) {
                    return Err(invalid(format!(
                        "case.json artifact {}: file path expected unique relative `a/b` without dot-leading parts | received {:?}",
                        artifact.id, file.path
                    )));
                }
            }
            if artifact.kind == ArtifactKind::Directory {
                let blob = tree_blob(&artifact.files);
                if blob.sha256 != artifact.sha256 || blob.length != artifact.length {
                    return Err(invalid(format!(
                        "case.json artifact {}: expected sha256 {} over its files | received {}",
                        artifact.id, blob.sha256, artifact.sha256
                    )));
                }
            }
        }
        Ok(())
    }
}

/// What a check found for one input or artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// The bytes match the recorded digest.
    Verified,
    /// The file is there with a different digest.
    Changed,
    /// The file could not be found.
    Missing,
}

impl Verdict {
    /// The kebab-case name, e.g. `Verdict::Changed.label() == "changed"`.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Changed => "changed",
            Verdict::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputStatus {
    pub name: String,
    pub state: Verdict,
    pub expected: Blob,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<Blob>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactStatus {
    pub id: String,
    pub path: String,
    pub state: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<Blob>,
    /// Why the recorded result predates the current engine, catalog or inputs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<String>,
    /// For a directory artifact, the files that differ from the record.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileStatus>,
}

/// A finding the case holds, as `status` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingRef {
    pub id: String,
    pub status: FindingStatus,
}

/// The result of checking a case against the files at hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseStatus {
    /// Every input and artifact verified.
    pub clean: bool,
    pub inputs: Vec<InputStatus>,
    pub artifacts: Vec<ArtifactStatus>,
    pub findings: Vec<FindingRef>,
}

impl CaseStatus {
    /// The inputs and artifacts that are changed or missing, one line each.
    ///
    /// Example: after a byte flip, `status.drifted()` is `["input dump.bin: changed"]`.
    pub fn drifted(&self) -> Vec<String> {
        let inputs = self
            .inputs
            .iter()
            .filter(|i| i.state != Verdict::Verified)
            .map(|i| format!("input {}: {}", i.name, i.state.label()));
        let artifacts = self
            .artifacts
            .iter()
            .filter(|a| a.state != Verdict::Verified)
            .map(|a| format!("artifact {}: {}", a.path, a.state.label()));
        inputs.chain(artifacts).collect()
    }

    /// Artifacts produced by an older engine, catalog or input than the current ones.
    pub fn stale(&self) -> Vec<&ArtifactStatus> {
        self.artifacts
            .iter()
            .filter(|a| !a.stale.is_empty())
            .collect()
    }
}

/// The engine and catalogs a case is compared with when judging staleness.
#[derive(Debug, Clone, Copy)]
pub struct Current<'a> {
    pub bme_version: &'a str,
    pub catalogs: &'a [CatalogSnapshot],
}

fn verdict(expected: &Blob, found: Option<&Blob>) -> Verdict {
    match found {
        None => Verdict::Missing,
        Some(found) if found == expected => Verdict::Verified,
        Some(_) => Verdict::Changed,
    }
}

/// Reasons an artifact no longer reflects the current engine, catalog or inputs.
fn stale_reasons(artifact: &Artifact, case: &Case, current: &Current) -> Vec<String> {
    let mut reasons = Vec::new();
    if artifact.bme_version != current.bme_version {
        reasons.push(format!(
            "bme version expected {} | recorded {}",
            current.bme_version, artifact.bme_version
        ));
    }
    for recorded in &artifact.catalogs {
        let Some(now) = current.catalogs.iter().find(|c| c.alias == recorded.alias) else {
            continue;
        };
        if now.manifest_sha256 != recorded.manifest_sha256 {
            reasons.push(format!(
                "catalog {} expected {} ({}) | recorded {} ({})",
                recorded.alias,
                now.version,
                now.manifest_sha256,
                recorded.version,
                recorded.manifest_sha256
            ));
        }
    }
    for input in &artifact.inputs {
        if let Some(own) = case.inputs.iter().find(|i| i.name == input.name)
            && own.sha256 != input.sha256
        {
            reasons.push(format!(
                "input {} expected sha256 {} | recorded {}",
                input.name, own.sha256, input.sha256
            ));
        }
    }
    reasons
}

/// Compare a case with the digests of the files found for it.
///
/// `inputs` maps input names and `artifacts` maps artifact paths to what was
/// read, with `None` for a file that could not be found. A name absent from
/// either map counts as missing. Staleness never makes a case unclean.
///
/// Example: with every observation equal to its record, `status(..).clean` is true.
pub fn status(
    case: &Case,
    inputs: &BTreeMap<String, Option<Blob>>,
    artifacts: &BTreeMap<String, Option<Blob>>,
    current: &Current,
) -> CaseStatus {
    let inputs: Vec<InputStatus> = case
        .inputs
        .iter()
        .map(|input| {
            let expected = Blob {
                sha256: input.sha256,
                length: input.length,
            };
            let found = inputs.get(&input.name).cloned().flatten();
            InputStatus {
                name: input.name.clone(),
                state: verdict(&expected, found.as_ref()),
                expected,
                found,
            }
        })
        .collect();
    let artifacts: Vec<ArtifactStatus> = case
        .artifacts
        .iter()
        .map(|artifact| {
            let expected = Blob {
                sha256: artifact.sha256,
                length: artifact.length,
            };
            let found = artifacts.get(&artifact.path).cloned().flatten();
            ArtifactStatus {
                id: artifact.id.clone(),
                path: artifact.path.clone(),
                state: verdict(&expected, found.as_ref()),
                found,
                stale: stale_reasons(artifact, case, current),
                files: Vec::new(),
            }
        })
        .collect();
    let clean = inputs.iter().all(|i| i.state == Verdict::Verified)
        && artifacts.iter().all(|a| a.state == Verdict::Verified);
    CaseStatus {
        clean,
        inputs,
        artifacts,
        findings: Vec::new(),
    }
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Example: `utc_timestamp(0)` is `"1970-01-01T00:00:00Z"`.
pub fn utc_timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm, proleptic Gregorian).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Join `prefix` and `suffix` into an identifier of at most 64 characters, trimming the prefix.
///
/// Example: `bounded_id("board", "001-scan") == "board-001-scan"`.
pub fn bounded_id(prefix: &str, suffix: &str) -> String {
    let room = 64usize.saturating_sub(suffix.len() + 1);
    let prefix: String = prefix.chars().take(room).collect();
    format!("{}-{suffix}", prefix.trim_end_matches(['-', '.', '_']))
}

/// The catalog evidence id an artifact becomes on export.
///
/// Example: `evidence_id("draft-x", "001-scan") == "draft-x-001-scan"`.
pub fn evidence_id(case_id: &str, artifact_id: &str) -> String {
    bounded_id(case_id, artifact_id)
}

/// A command shown without directories, so published evidence names no local paths.
fn public_command(command: &[String]) -> String {
    command
        .iter()
        .map(|token| match token.rsplit(['/', '\\']).next() {
            Some(name) if token.contains(['/', '\\']) && !name.is_empty() => name.to_string(),
            _ => token.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Turn one artifact into an unreviewed evidence record for `board` and `firmware`.
///
/// Example: `evidence_record(&case, &case.artifacts[0], "draft-x", "fw-1")`.
pub fn evidence_record(case: &Case, artifact: &Artifact, board: &str, firmware: &str) -> Evidence {
    let image = case
        .inputs
        .iter()
        .find(|i| artifact.inputs.iter().any(|a| a.sha256 == i.sha256));
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        id: evidence_id(&case.id, &artifact.id),
        kind: EvidenceKind::OfflineValidation,
        date: artifact.recorded.chars().take(10).collect(),
        title: format!(
            "DRAFT: bme {} (unreviewed)",
            public_command(&artifact.command)
        ),
        board: board.into(),
        firmware: firmware.into(),
        configuration: None,
        patches: vec![],
        image_sha256: image.map(|i| i.sha256),
        built_with: Some(format!("bme {}", artifact.bme_version)),
        observations: vec![
            format!("command: bme {}", public_command(&artifact.command)),
            format!(
                "artifact {} sha256 {} ({} bytes), recorded {}",
                artifact.path, artifact.sha256, artifact.length, artifact.recorded
            ),
        ],
        limits: "Draft evidence from an unreviewed case. The artifact file is not part of this catalog; check it by its digest.".into(),
        source: Some("bme case export".into()),
        host: None,
    }
}

/// A finding from the case, rewritten so it stands alone in a submission.
///
/// Patches do not travel with a case, so the finding drops them and cannot stay
/// fixed-by-patch. It affects only the draft build, and `evidence` entries that
/// name artifact ids become evidence ids.
fn standalone_finding(mut finding: Finding, case: &Case, firmware: &str) -> Result<Finding> {
    finding.patches.clear();
    if finding.status == FindingStatus::FixedByPatch {
        finding.status = FindingStatus::Open;
    }
    finding.affects.builds = vec![firmware.into()];
    for reference in &mut finding.owner.references {
        reference.build = reference.build.take().filter(|b| b == firmware);
    }
    let mut evidence = Vec::new();
    for id in &finding.evidence {
        if !case.artifacts.iter().any(|a| &a.id == id) {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "finding {}: evidence {id:?} expected an artifact id of case {} ({})",
                    finding.id,
                    case.id,
                    case.artifacts
                        .iter()
                        .map(|a| a.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        evidence.push(evidence_id(&case.id, id));
    }
    finding.evidence = evidence;
    Ok(finding)
}

/// Assemble a catalog submission directory's files from a case.
///
/// Returns `(path, bytes)` pairs for `catalog.json`, `boards/`, `findings/`,
/// `evidence/` and `provenance/`, and proves they load as a valid catalog
/// before returning. Findings that list artifact ids as evidence get the
/// matching evidence ids.
///
/// Example: `let files = submission_files(&case, board, &firmware, findings)?;`
pub fn submission_files(
    case: &Case,
    mut board: Board,
    firmware: &FirmwareDraft,
    findings: Vec<Finding>,
) -> Result<Vec<(String, Vec<u8>)>> {
    if board.schema != BOARD_SCHEMA {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "drafts/board.json: expected schema {BOARD_SCHEMA:?} | received {:?}",
                board.schema
            ),
        ));
    }
    let evidence: Vec<Evidence> = case
        .artifacts
        .iter()
        .map(|a| evidence_record(case, a, &board.id, &firmware.build.id))
        .collect();
    let findings = findings
        .into_iter()
        .map(|f| standalone_finding(f, case, &firmware.build.id))
        .collect::<Result<Vec<_>>>()?;
    board.firmware = vec![firmware.build.clone()];
    board.patches.clear();
    board.findings = findings.iter().map(|f| f.id.clone()).collect();
    board.evidence = evidence.iter().map(|e| e.id.clone()).collect();
    let mut files: Vec<(String, Vec<u8>)> =
        vec![(format!("boards/{}.json", board.id), pretty(&board))];
    files.extend(
        findings
            .iter()
            .map(|f| (format!("findings/{}.json", f.id), pretty(f))),
    );
    files.extend(
        evidence
            .iter()
            .map(|e| (format!("evidence/{}.json", e.id), pretty(e))),
    );
    files.push((
        format!("provenance/{}-firmware-draft.json", board.id),
        pretty(firmware),
    ));
    let version = semver::Version::parse(crate::VERSION).expect("crate version is semver");
    let manifest = Manifest {
        schema: CATALOG_SCHEMA.into(),
        id: bounded_id("case", &board.id),
        version: semver::Version::parse("0.1.0-draft").expect("valid version"),
        title: format!("DRAFT case export for {} (unreviewed)", board.id),
        engine: semver::VersionReq::parse(&format!("^{}.{}", version.major, version.minor))
            .expect("valid requirement"),
        description: Some(
            "Draft submission exported by `bme case export`; board, build, findings and evidence are unreviewed.".into(),
        ),
        files: index_files(&files)?,
    };
    files.push(("catalog.json".into(), pretty(&manifest)));
    Catalog::load(&MemorySource::new(files.clone()), Scope::All)
        .map_err(|e| e.context(format!("case {}: exported catalog", case.id)))?;
    Ok(files)
}
