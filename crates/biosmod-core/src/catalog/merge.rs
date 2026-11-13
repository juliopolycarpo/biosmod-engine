//! Union catalogs that share records, and refuse when a shared record drifted.
//!
//! Records match by id within their kind. A record one catalog defines is carried
//! over unchanged. For a record several catalogs define, the fields that differ
//! per board are unioned and every other field must be equal. Each disagreement
//! becomes one line that names the record, the field, both values and both
//! catalog ids, and [`merge_catalogs`] reports all of them at once.

use super::{
    Board, CatalogSource, CodeReference, Evidence, Finding, FindingStatus, Patch, records::Records,
};
use crate::error::{Code, Error, Result};
use crate::util::Digest256;
use semver::{Version, VersionReq};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// One catalog to merge.
#[derive(Debug, Clone, Copy)]
pub struct MergeInput<'a> {
    /// The id in the catalog's `catalog.json`; named in disagreements.
    pub catalog_id: &'a str,
    /// The `version` in the catalog's `catalog.json`.
    pub version: &'a Version,
    /// SHA-256 of the exact bytes of the catalog's `catalog.json`.
    pub manifest_sha256: Digest256,
    /// The `sources` the catalog's `catalog.json` lists, empty unless it is itself a merge.
    pub sources: &'a [CatalogSource],
    /// The `engine` requirement in the catalog's `catalog.json`.
    pub engine: &'a VersionReq,
    pub records: &'a Records,
    /// Provenance files as `(path below the catalog root, bytes)`.
    pub provenance: &'a [(String, Vec<u8>)],
}

/// Whether a pinned source still has the `catalog.json` it was merged from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PinState {
    /// The source's current `catalog.json` has the pinned digest.
    Pinned,
    /// The source's current `catalog.json` has another digest.
    Moved,
}

impl PinState {
    pub fn label(self) -> &'static str {
        match self {
            PinState::Pinned => "pinned",
            PinState::Moved => "moved",
        }
    }
}

/// One entry of a catalog's `sources`, compared with the given source it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinCheck {
    /// Display name of the catalog that lists the entry.
    pub listed_by: String,
    /// Display name of the given source with the entry's id.
    pub source: String,
    /// The entry's `id` and `version`.
    pub id: String,
    pub version: Version,
    pub pinned: Digest256,
    pub current: Digest256,
    pub state: PinState,
}

/// Compare every `sources` entry of each input with the other inputs that have its id.
///
/// An entry gets one check per other input with the same id, in input order. A moved pin
/// does not stop a merge: the records can still agree.
///
/// Example: `check_pins(&inputs)` is empty when no input lists `sources`.
pub fn check_pins(inputs: &[MergeInput<'_>]) -> Vec<PinCheck> {
    let names = display_names(inputs);
    let mut checks = Vec::new();
    for (holder, input) in inputs.iter().enumerate() {
        for entry in input.sources {
            for (index, other) in inputs.iter().enumerate() {
                if index == holder || other.catalog_id != entry.id {
                    continue;
                }
                checks.push(PinCheck {
                    listed_by: names[holder].clone(),
                    source: names[index].clone(),
                    id: entry.id.clone(),
                    version: entry.version.clone(),
                    pinned: entry.manifest_sha256,
                    current: other.manifest_sha256,
                    state: if entry.manifest_sha256 == other.manifest_sha256 {
                        PinState::Pinned
                    } else {
                        PinState::Moved
                    },
                });
            }
        }
    }
    checks
}

/// The ids two or more catalogs define, per kind, in id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shared {
    pub boards: Vec<String>,
    pub patches: Vec<String>,
    pub findings: Vec<String>,
    pub evidence: Vec<String>,
    /// Provenance paths.
    pub provenance: Vec<String>,
}

/// The union of the catalogs.
#[derive(Debug, Clone)]
pub struct Merged {
    pub records: Records,
    pub provenance: Vec<(String, Vec<u8>)>,
    /// The `engine` requirement every catalog declares.
    pub engine: VersionReq,
    /// One pin per merged catalog, in input order, for the `sources` of the written `catalog.json`.
    pub sources: Vec<CatalogSource>,
    pub shared: Shared,
}

/// Union `inputs`, in the order given.
///
/// - Board: every field is equal except `patches`, `findings` and `evidence`, which are unioned.
/// - Patch: `variants` are unioned by build (one build in two catalogs must be equal);
///   `requires`, `supersedes` and `conflicts` must agree on every patch both catalogs define
///   and are then unioned; every other field is equal.
/// - Finding: `affects.builds`, `owner.references` and `evidence` are unioned; `patches` follows the
///   relation rule; `status` is equal, or `open` against `fixed-by-patch` (merged to `fixed-by-patch`);
///   every other field is equal.
/// - Evidence and provenance files with one id or path are identical.
/// - The `engine` requirements are equal.
/// - `sources` pins every input by id, version and `manifest_sha256`, in input order.
///
/// A disagreement names a catalog by its id, or `id (#N)` by position when another input has the same id.
///
/// Unions keep first-seen order, so `merge(A, B)` keeps A's order and appends B's new entries.
/// Fails with `USAGE` for no input, and with `CATALOG_INVALID` for disagreements; the message has one line per disagreement and
/// `details.disagreements` lists the same lines.
///
/// Example: `let merged = merge_catalogs(&[first, second])?;`
pub fn merge_catalogs(inputs: &[MergeInput<'_>]) -> Result<Merged> {
    if inputs.is_empty() {
        return Err(Error::new(
            Code::Usage,
            "catalogs: expected at least 1 catalog to merge | received none",
        ));
    }
    let mut report = Report::new(inputs);
    let engine = merge_engine(inputs, &mut report);
    let mut records = Records::default();
    let mut shared = Shared::default();
    for (id, entries) in gather(inputs, |r| &r.boards) {
        note_shared(&mut shared.boards, &id, &entries);
        records
            .boards
            .insert(id.clone(), merge_board(&id, &entries, &mut report));
    }
    for (id, entries) in gather(inputs, |r| &r.patches) {
        note_shared(&mut shared.patches, &id, &entries);
        records
            .patches
            .insert(id.clone(), merge_patch(&id, &entries, inputs, &mut report));
    }
    for (id, entries) in gather(inputs, |r| &r.findings) {
        note_shared(&mut shared.findings, &id, &entries);
        records.findings.insert(
            id.clone(),
            merge_finding(&id, &entries, inputs, &mut report),
        );
    }
    for (id, entries) in gather(inputs, |r| &r.evidence) {
        note_shared(&mut shared.evidence, &id, &entries);
        records
            .evidence
            .insert(id.clone(), merge_evidence(&id, &entries, &mut report));
    }
    let provenance = merge_provenance(inputs, &mut shared, &mut report);
    report.finish()?;
    Ok(Merged {
        records,
        provenance,
        engine: engine.expect("at least one input"),
        sources: inputs
            .iter()
            .map(|input| CatalogSource {
                id: input.catalog_id.to_string(),
                version: input.version.clone(),
                manifest_sha256: input.manifest_sha256,
            })
            .collect(),
        shared,
    })
}

/// How each input is named in a disagreement: its catalog id, or `id (#N)` with `N` the
/// 1-based position among the sources when another source has the same id.
///
/// Example: sources `dev`, `other`, `dev` are named `dev (#1)`, `other`, `dev (#3)`.
pub fn display_names(inputs: &[MergeInput<'_>]) -> Vec<String> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let repeated = inputs
                .iter()
                .filter(|other| other.catalog_id == input.catalog_id)
                .count()
                > 1;
            if repeated {
                format!("{} (#{})", input.catalog_id, index + 1)
            } else {
                input.catalog_id.to_string()
            }
        })
        .collect()
}

/// A record and the index of the input that holds it.
type Entries<'a, T> = Vec<(usize, &'a T)>;

/// Collect the records of one kind by id, each with the inputs that define it in input order.
fn gather<'a, T>(
    inputs: &[MergeInput<'a>],
    pick: impl Fn(&'a Records) -> &'a BTreeMap<String, T>,
) -> BTreeMap<String, Entries<'a, T>> {
    let mut by_id: BTreeMap<String, Entries<'a, T>> = BTreeMap::new();
    for (index, input) in inputs.iter().enumerate() {
        for (id, record) in pick(input.records) {
            by_id.entry(id.clone()).or_default().push((index, record));
        }
    }
    by_id
}

fn note_shared<T>(shared: &mut Vec<String>, id: &str, entries: &Entries<'_, T>) {
    if entries.len() > 1 {
        shared.push(id.to_string());
    }
}

/// The disagreement lines found so far.
#[derive(Debug, Default)]
struct Report {
    lines: Vec<String>,
    /// Display name of each input, by position.
    names: Vec<String>,
}

impl Report {
    fn new(inputs: &[MergeInput<'_>]) -> Report {
        Report {
            lines: Vec::new(),
            names: display_names(inputs),
        }
    }

    /// Record `record: field: expected ... | received <a> (<catalog>) and <b> (<catalog>)`.
    ///
    /// Each side is `(input index, value)`; the index selects the catalog's display name.
    fn disagree(
        &mut self,
        record: &str,
        field: &str,
        expected: &str,
        first: (usize, &str),
        other: (usize, &str),
    ) {
        self.lines.push(format!(
            "{record}: {field}: expected {expected} | received {} ({}) and {} ({})",
            first.1, self.names[first.0], other.1, self.names[other.0]
        ));
    }

    fn finish(self) -> Result<()> {
        if self.lines.is_empty() {
            return Ok(());
        }
        Err(Error::new(Code::CatalogInvalid, self.lines.join("\n"))
            .with_details(json!({"disagreements": self.lines})))
    }
}

const SAME_VALUE: &str = "the same value in every catalog";

fn to_value<T: Serialize>(record: &T) -> Value {
    serde_json::to_value(record).expect("catalog documents serialize")
}

/// Remove the field at dotted `path`, if present.
fn remove_path(value: &mut Value, path: &str) {
    match path.split_once('.') {
        Some((head, rest)) => {
            if let Some(child) = value.get_mut(head) {
                remove_path(child, rest);
            }
        }
        None => {
            if let Some(object) = value.as_object_mut() {
                object.remove(path);
            }
        }
    }
}

/// Differences between two values as `(dotted field, a, b)`; objects are compared key by key,
/// everything else as a whole. A missing key shows as `None`.
fn field_diffs(
    a: Option<&Value>,
    b: Option<&Value>,
    path: &str,
    out: &mut Vec<(String, Option<Value>, Option<Value>)>,
) {
    if let (Some(Value::Object(x)), Some(Value::Object(y))) = (a, b) {
        let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
        for key in keys {
            let next = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            field_diffs(x.get(key), y.get(key), &next, out);
        }
    } else if a != b {
        out.push((path.to_string(), a.cloned(), b.cloned()));
    }
}

fn show(value: &Option<Value>) -> String {
    value
        .as_ref()
        .map_or_else(|| "absent".into(), Value::to_string)
}

/// Compare every record against the first one, field by field, after removing the
/// dotted paths in `merged_apart` (those are unioned by the caller).
fn require_equal_fields<T: Serialize>(
    label: &str,
    entries: &Entries<'_, T>,
    merged_apart: &[&str],
    report: &mut Report,
) {
    let values: Vec<Value> = entries
        .iter()
        .map(|(_, record)| {
            let mut value = to_value(record);
            for path in merged_apart {
                remove_path(&mut value, path);
            }
            value
        })
        .collect();
    for (position, later) in values.iter().enumerate().skip(1) {
        let mut diffs = Vec::new();
        field_diffs(Some(&values[0]), Some(later), "", &mut diffs);
        for (field, first, other) in diffs {
            report.disagree(
                label,
                &field,
                SAME_VALUE,
                (entries[0].0, &show(&first)),
                (entries[position].0, &show(&other)),
            );
        }
    }
}

/// Append the items of `lists` that `seen` does not hold yet, keeping first-seen order.
fn union_in_order<'a, T: PartialEq + Clone + 'a>(lists: impl Iterator<Item = &'a [T]>) -> Vec<T> {
    let mut union: Vec<T> = Vec::new();
    for item in lists.flatten() {
        if !union.contains(item) {
            union.push(item.clone());
        }
    }
    union
}

/// Unions a patch relation list after checking the catalogs agree on it.
///
/// Two catalogs agree when, among the patches both define, one lists exactly the ids the other
/// lists. An id only one catalog defines is carried over: `split` cuts these lists to the
/// patches a board keeps.
fn merge_relation<T>(
    label: &str,
    field: &str,
    entries: &Entries<'_, T>,
    inputs: &[MergeInput<'_>],
    list: impl Fn(&T) -> &Vec<String>,
    report: &mut Report,
) -> Vec<String> {
    for (position, (first_index, first)) in entries.iter().enumerate() {
        for (other_index, other) in &entries[position + 1..] {
            let both_define = |id: &&String| {
                inputs[*first_index].records.patches.contains_key(*id)
                    && inputs[*other_index].records.patches.contains_key(*id)
            };
            let in_first: Vec<&String> = list(first).iter().filter(both_define).collect();
            let in_other: Vec<&String> = list(other).iter().filter(both_define).collect();
            let a: BTreeSet<&String> = in_first.iter().copied().collect();
            let b: BTreeSet<&String> = in_other.iter().copied().collect();
            if a != b {
                report.disagree(
                    label,
                    field,
                    "the same ids among the patches both catalogs define",
                    (*first_index, &json!(in_first).to_string()),
                    (*other_index, &json!(in_other).to_string()),
                );
            }
        }
    }
    union_in_order(entries.iter().map(|(_, record)| list(record).as_slice()))
}

/// Merge the board profiles of one id.
fn merge_board(id: &str, entries: &Entries<'_, Board>, report: &mut Report) -> Board {
    let label = format!("board {id}");
    require_equal_fields(
        &label,
        entries,
        &["patches", "findings", "evidence"],
        report,
    );
    let mut merged = entries[0].1.clone();
    merged.patches = union_in_order(entries.iter().map(|(_, b)| b.patches.as_slice()));
    merged.findings = union_in_order(entries.iter().map(|(_, b)| b.findings.as_slice()));
    merged.evidence = union_in_order(entries.iter().map(|(_, b)| b.evidence.as_slice()));
    merged
}

/// Merge the patch records of one id.
fn merge_patch(
    id: &str,
    entries: &Entries<'_, Patch>,
    inputs: &[MergeInput<'_>],
    report: &mut Report,
) -> Patch {
    let label = format!("patch {id}");
    require_equal_fields(
        &label,
        entries,
        &["variants", "requires", "supersedes", "conflicts"],
        report,
    );
    let mut merged = entries[0].1.clone();
    merged.requires = merge_relation(&label, "requires", entries, inputs, |p| &p.requires, report);
    merged.supersedes = merge_relation(
        &label,
        "supersedes",
        entries,
        inputs,
        |p| &p.supersedes,
        report,
    );
    merged.conflicts = merge_relation(
        &label,
        "conflicts",
        entries,
        inputs,
        |p| &p.conflicts,
        report,
    );
    // Each build keeps the first variant; later ones must equal it.
    let mut first_seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, patch) in entries {
        for (build, variant) in &patch.variants {
            match first_seen.get(build.as_str()) {
                None => {
                    first_seen.insert(build, *index);
                    merged.variants.insert(build.clone(), variant.clone());
                }
                Some(origin) => {
                    let first = to_value(&merged.variants[build]);
                    let mut diffs = Vec::new();
                    field_diffs(
                        Some(&first),
                        Some(&to_value(variant)),
                        &format!("variants.{build}"),
                        &mut diffs,
                    );
                    for (field, a, b) in diffs {
                        report.disagree(
                            &label,
                            &field,
                            SAME_VALUE,
                            (*origin, &show(&a)),
                            (*index, &show(&b)),
                        );
                    }
                }
            }
        }
    }
    merged
}

/// Merge the finding records of one id.
fn merge_finding(
    id: &str,
    entries: &Entries<'_, Finding>,
    inputs: &[MergeInput<'_>],
    report: &mut Report,
) -> Finding {
    let label = format!("finding {id}");
    require_equal_fields(
        &label,
        entries,
        &[
            "status",
            "affects.builds",
            "owner.references",
            "evidence",
            "patches",
        ],
        report,
    );
    let mut merged = entries[0].1.clone();
    merged.affects.builds =
        union_in_order(entries.iter().map(|(_, f)| f.affects.builds.as_slice()));
    merged.owner.references = merge_references(&label, entries, report);
    merged.evidence = union_in_order(entries.iter().map(|(_, f)| f.evidence.as_slice()));
    merged.patches = merge_relation(&label, "patches", entries, inputs, |f| &f.patches, report);
    merged.status = merge_status(&label, entries, report);
    merged
}

/// Unions `owner.references` after checking the catalogs agree on the ones they share.
///
/// A reference belongs to one firmware build, or to none. Two catalogs share the references
/// without a build, and those of every build both list in `affects.builds`; for each of these
/// groups the two lists must be equal. Without this check an edited `location` would not
/// compare equal to the original and the union would silently keep both.
fn merge_references(
    label: &str,
    entries: &Entries<'_, Finding>,
    report: &mut Report,
) -> Vec<CodeReference> {
    let of_build = |finding: &Finding, build: Option<&str>| -> Vec<CodeReference> {
        finding
            .owner
            .references
            .iter()
            .filter(|reference| reference.build.as_deref() == build)
            .cloned()
            .collect()
    };
    // `None` is the group without a build, which every catalog holds.
    let mut groups: Vec<Option<&str>> = vec![None];
    for (_, finding) in entries {
        for build in &finding.affects.builds {
            if !groups.contains(&Some(build.as_str())) {
                groups.push(Some(build.as_str()));
            }
        }
    }
    for group in groups {
        let holds = |finding: &Finding| {
            group.is_none_or(|build| finding.affects.builds.iter().any(|b| b == build))
        };
        // Compare every later holder against the first one, so one drift is reported once.
        let mut holders = entries.iter().filter(|(_, finding)| holds(finding));
        let Some((origin, first)) = holders.next() else {
            continue;
        };
        let expected = of_build(first, group);
        for (index, finding) in holders {
            let received = of_build(finding, group);
            if received != expected {
                let field = match group {
                    Some(build) => format!("owner.references of build {build}"),
                    None => "owner.references without a build".to_string(),
                };
                report.disagree(
                    label,
                    &field,
                    SAME_VALUE,
                    (*origin, &to_value(&expected).to_string()),
                    (*index, &to_value(&received).to_string()),
                );
            }
        }
    }
    union_in_order(entries.iter().map(|(_, f)| f.owner.references.as_slice()))
}

/// Equal statuses stay; `open` against `fixed-by-patch` becomes `fixed-by-patch`,
/// because a board whose build has no variant sees the finding as open.
fn merge_status(label: &str, entries: &Entries<'_, Finding>, report: &mut Report) -> FindingStatus {
    let first = entries[0].1.status;
    let Some((position, other)) = entries
        .iter()
        .enumerate()
        .find(|(_, (_, f))| f.status != first)
        .map(|(position, (_, f))| (position, f.status))
    else {
        return first;
    };
    let statuses: BTreeSet<&str> = entries.iter().map(|(_, f)| f.status.label()).collect();
    if statuses == BTreeSet::from(["fixed-by-patch", "open"]) {
        return FindingStatus::FixedByPatch;
    }
    report.disagree(
        label,
        "status",
        "the same value in every catalog, or open and fixed-by-patch",
        (entries[0].0, &format!("{:?}", first.label())),
        (entries[position].0, &format!("{:?}", other.label())),
    );
    first
}

/// Merge evidence records of one id: they must be identical.
fn merge_evidence(id: &str, entries: &Entries<'_, Evidence>, report: &mut Report) -> Evidence {
    require_equal_fields(&format!("evidence {id}"), entries, &[], report);
    entries[0].1.clone()
}

/// The `engine` requirement all catalogs declare; reports the first catalog that differs.
fn merge_engine(inputs: &[MergeInput<'_>], report: &mut Report) -> Option<VersionReq> {
    let first = inputs.first()?;
    for (index, other) in inputs.iter().enumerate().skip(1) {
        if other.engine != first.engine {
            report.disagree(
                "catalog.json",
                "engine",
                "the same requirement in every catalog",
                (0, &format!("{:?}", first.engine.to_string())),
                (index, &format!("{:?}", other.engine.to_string())),
            );
        }
    }
    Some(first.engine.clone())
}

/// Union provenance files by path; files with one path must be byte-identical.
fn merge_provenance(
    inputs: &[MergeInput<'_>],
    shared: &mut Shared,
    report: &mut Report,
) -> Vec<(String, Vec<u8>)> {
    let mut merged: Vec<(String, Vec<u8>)> = Vec::new();
    let mut origin: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, input) in inputs.iter().enumerate() {
        for (path, bytes) in input.provenance {
            let Some(&first) = origin.get(path.as_str()) else {
                origin.insert(path, index);
                merged.push((path.clone(), bytes.clone()));
                continue;
            };
            if !shared.provenance.contains(path) {
                shared.provenance.push(path.clone());
            }
            let kept = &merged.iter().find(|(p, _)| p == path).expect("seen").1;
            if kept != bytes {
                let describe = |bytes: &[u8]| {
                    format!("{} bytes, sha256 {}", bytes.len(), Digest256::of(bytes))
                };
                report.disagree(
                    &format!("provenance {path}"),
                    "content",
                    "the same bytes in every catalog",
                    (first, &describe(kept)),
                    (index, &describe(bytes)),
                );
            }
        }
    }
    shared.provenance.sort();
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Variant;
    use crate::catalog::fixtures::{board, evidence, finding, fixed_finding, patch};
    use crate::catalog::split::split_board;

    const A: &str = "build-a";
    const B: &str = "build-b";

    static ONE: Version = Version::new(1, 0, 0);

    /// A merge input at version 1.0.0 with no provenance and no sources; its manifest
    /// digest is the SHA-256 of its id.
    fn input<'a>(
        catalog_id: &'a str,
        engine: &'a VersionReq,
        records: &'a Records,
    ) -> MergeInput<'a> {
        MergeInput {
            catalog_id,
            version: &ONE,
            manifest_sha256: Digest256::of(catalog_id.as_bytes()),
            sources: &[],
            engine,
            records,
            provenance: &[],
        }
    }

    fn engine() -> VersionReq {
        VersionReq::parse("^0.1").unwrap()
    }

    /// Merge `(catalog id, records)` pairs with no provenance.
    fn merge(catalogs: &[(&str, &Records)]) -> Result<Merged> {
        let engine = engine();
        let inputs: Vec<MergeInput<'_>> = catalogs
            .iter()
            .map(|(catalog_id, records)| input(catalog_id, &engine, records))
            .collect();
        merge_catalogs(&inputs)
    }

    /// The bundled shape: two boards, one shared patch and finding, one patch per board.
    fn both_boards() -> Records {
        let mut r = Records::default();
        r.boards.insert(
            "board-a".into(),
            board(
                "board-a",
                &[A],
                &["S", "PA", "PB"],
                &["F-S", "F-A"],
                &["E-A"],
            ),
        );
        r.boards.insert(
            "board-b".into(),
            board(
                "board-b",
                &[B],
                &["S", "PB", "PA"],
                &["F-S", "F-B"],
                &["E-B"],
            ),
        );
        r.patches
            .insert("S".into(), patch("S", &[(A, true), (B, true)]));
        r.patches
            .insert("PA".into(), patch("PA", &[(A, true), (B, false)]));
        r.patches
            .insert("PB".into(), patch("PB", &[(A, false), (B, true)]));
        // Each patch names the finding it fixes, so a board that cannot run it keeps the verdict.
        for (patch, finding) in [("S", "F-S"), ("PA", "F-A"), ("PB", "F-B")] {
            r.patches.get_mut(patch).unwrap().findings = vec![finding.into()];
        }
        r.findings
            .insert("F-S".into(), fixed_finding("F-S", &[A, B], &["S"]));
        r.findings
            .insert("F-A".into(), fixed_finding("F-A", &[A], &["PA"]));
        r.findings
            .insert("F-B".into(), fixed_finding("F-B", &[B], &["PB"]));
        r.evidence
            .insert("E-A".into(), evidence("E-A", "board-a", A, &["S"]));
        r.evidence
            .insert("E-B".into(), evidence("E-B", "board-b", B, &["S"]));
        r
    }

    fn one(id: &str) -> Records {
        let mut r = Records::default();
        r.patches.insert(id.into(), patch(id, &[(A, true)]));
        r
    }

    fn json_of<T: Serialize>(map: &BTreeMap<String, T>) -> Value {
        to_value(map)
    }

    #[test]
    fn merging_the_board_splits_alone_restores_every_record() {
        let whole = both_boards();
        let a = split_board(&whole, "board-a").unwrap().records;
        let b = split_board(&whole, "board-b").unwrap().records;
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        assert_eq!(json_of(&merged.records.boards), json_of(&whole.boards));
        assert_eq!(json_of(&merged.records.patches), json_of(&whole.patches));
        assert_eq!(json_of(&merged.records.findings), json_of(&whole.findings));
        assert_eq!(json_of(&merged.records.evidence), json_of(&whole.evidence));
    }

    #[test]
    fn not_applicable_verdicts_come_back_in_the_merge_of_board_splits() {
        let whole = both_boards();
        let a = split_board(&whole, "board-a").unwrap().records;
        let b = split_board(&whole, "board-b").unwrap().records;
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        // PB does not apply to build-a, and the board-a split recorded that with F-B.
        assert_eq!(
            a.findings["F-B"].affects.builds,
            Vec::<String>::new(),
            "(F-B in the board-a split)"
        );
        let variants: Vec<(&str, bool)> = merged.records.patches["PB"]
            .variants
            .iter()
            .map(|(build, variant)| (build.as_str(), matches!(variant, Variant::Applicable(_))))
            .collect();
        assert_eq!(variants, [(A, false), (B, true)]);
        assert_eq!(merged.records.findings["F-B"].affects.builds, [B]);
        assert_eq!(merged.records.findings["F-B"].owner.references.len(), 1);
    }

    #[test]
    fn finding_fixed_for_one_board_and_open_for_the_other_merges_to_fixed() {
        let mut whole = both_boards();
        whole.patches.insert("PX".into(), patch("PX", &[(B, true)]));
        whole
            .findings
            .insert("F-X".into(), fixed_finding("F-X", &[A, B], &["PX"]));
        let a = split_board(&whole, "board-a").unwrap().records;
        let b = split_board(&whole, "board-b").unwrap().records;
        assert_eq!(
            a.findings["F-X"].status,
            FindingStatus::Open,
            "(split for board-a)"
        );
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        let finding = &merged.records.findings["F-X"];
        assert_eq!(finding.status, FindingStatus::FixedByPatch);
        assert_eq!(finding.patches, ["PX"]);
        assert_eq!(finding.affects.builds, [A, B]);
        assert_eq!(finding.owner.references.len(), 2);
    }

    #[test]
    fn a_record_one_catalog_defines_is_carried_over_unchanged() {
        let (x, y) = (one("PX"), one("PY"));
        let merged = merge(&[("x", &x), ("y", &y)]).unwrap();
        assert_eq!(
            to_value(&merged.records.patches["PX"]),
            to_value(&x.patches["PX"])
        );
        assert_eq!(
            to_value(&merged.records.patches["PY"]),
            to_value(&y.patches["PY"])
        );
        assert_eq!(merged.records.patches.len(), 2);
        assert_eq!(merged.shared, Shared::default());
    }

    #[test]
    fn shared_ids_are_listed_per_kind() {
        let whole = both_boards();
        let a = split_board(&whole, "board-a").unwrap().records;
        let b = split_board(&whole, "board-b").unwrap().records;
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        // Both splits keep every patch and the finding of each patch.
        assert_eq!(merged.shared.patches, ["PA", "PB", "S"]);
        assert_eq!(merged.shared.findings, ["F-A", "F-B", "F-S"]);
        assert!(merged.shared.boards.is_empty() && merged.shared.evidence.is_empty());
    }

    #[test]
    fn patch_title_drift_names_record_field_values_and_catalogs() {
        let mut a = one("B02-B03");
        let mut b = one("B02-B03");
        a.patches.get_mut("B02-B03").unwrap().title = "Separate DIMM counters".into();
        b.patches.get_mut("B02-B03").unwrap().title = "Split DIMM counters".into();
        let error = merge(&[("mr9a", &a), ("pr9", &b)]).unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert_eq!(
            error.message,
            "patch B02-B03: title: expected the same value in every catalog | received \"Separate DIMM counters\" (mr9a) and \"Split DIMM counters\" (pr9)"
        );
    }

    #[test]
    fn every_disagreement_is_reported_in_one_error() {
        let mut a = one("P");
        let mut b = one("P");
        a.patches.get_mut("P").unwrap().title = "one".into();
        b.patches.get_mut("P").unwrap().title = "two".into();
        b.patches.get_mut("P").unwrap().limits = "other".into();
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        let lines: Vec<&str> = error.message.lines().collect();
        assert_eq!(lines.len(), 2, "{}", error.message);
        assert!(lines[0].starts_with("patch P: limits:"), "{}", lines[0]);
        assert!(lines[1].starts_with("patch P: title:"), "{}", lines[1]);
        assert_eq!(
            error.details.unwrap()["disagreements"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn patch_fields_other_than_variants_and_relations_must_be_equal() {
        type Edit = fn(&mut Patch);
        let edits: [(&str, Edit); 9] = [
            ("version", |p| p.version = semver::Version::new(2, 0, 0)),
            ("class", |p| {
                p.class = crate::catalog::PatchClass::Diagnostic
            }),
            ("tier", |p| p.tier = crate::catalog::Tier::Hold),
            ("findings", |p| p.findings = vec!["F".into()]),
            ("limits", |p| p.limits = "changed".into()),
            ("packing", |p| p.packing = crate::catalog::Packing::Manual),
            ("confidence.offline_fix", |p| {
                p.confidence.offline_fix = "C2".into()
            }),
            ("fixes", |p| p.fixes = vec!["F".into()]),
            ("provenance", |p| {
                p.provenance = Some(crate::catalog::Provenance {
                    repository: "repo".into(),
                    commit: "abc".into(),
                    path: "patches/P.json".into(),
                    sha256: Digest256::of(b"x"),
                    note: None,
                })
            }),
        ];
        for (field, edit) in edits {
            let a = one("P");
            let mut b = one("P");
            edit(b.patches.get_mut("P").unwrap());
            let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
            assert!(
                error.message.starts_with(&format!(
                    "patch P: {field}: expected the same value in every catalog | received "
                )),
                "(patch field {field}): expected a disagreement | received {}",
                error.message
            );
        }
    }

    #[test]
    fn patch_variants_union_by_build() {
        let mut a = Records::default();
        a.patches.insert("P".into(), patch("P", &[(A, true)]));
        let mut b = Records::default();
        b.patches.insert("P".into(), patch("P", &[(B, false)]));
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        let builds: Vec<&str> = merged.records.patches["P"]
            .variants
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(builds, [A, B]);
    }

    #[test]
    fn one_build_with_different_variants_is_a_disagreement() {
        let mut a = Records::default();
        a.patches.insert("P".into(), patch("P", &[(A, true)]));
        let mut b = Records::default();
        b.patches.insert("P".into(), patch("P", &[(A, false)]));
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert!(
            error.message.contains("patch P: variants.build-a.status: expected the same value in every catalog | received \"applicable\" (a) and \"not-applicable\" (b)"),
            "{}",
            error.message
        );
    }

    #[test]
    fn relations_that_disagree_on_a_patch_both_define_fail() {
        let mut a = one("P");
        a.patches.insert("Q".into(), patch("Q", &[(A, true)]));
        let mut b = a.clone();
        a.patches.get_mut("P").unwrap().requires = vec!["Q".into()];
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert_eq!(
            error.message,
            "patch P: requires: expected the same ids among the patches both catalogs define | received [\"Q\"] (a) and [] (b)"
        );
        b.patches.get_mut("P").unwrap().conflicts = vec!["Q".into()];
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert!(
            error.message.contains("patch P: conflicts:"),
            "{}",
            error.message
        );
    }

    #[test]
    fn relations_agree_when_the_id_exists_in_only_one_catalog() {
        let mut a = one("P");
        a.patches.insert("Q".into(), patch("Q", &[(A, true)]));
        a.patches.get_mut("P").unwrap().requires = vec!["Q".into()];
        a.patches.get_mut("P").unwrap().supersedes = vec!["Q".into()];
        let b = one("P");
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        assert_eq!(merged.records.patches["P"].requires, ["Q"]);
        assert_eq!(merged.records.patches["P"].supersedes, ["Q"]);
    }

    #[test]
    fn relation_union_keeps_first_seen_order() {
        let mut a = one("P");
        let mut b = one("P");
        for id in ["Q1", "Q2", "Q3"] {
            a.patches.insert(id.into(), patch(id, &[(A, true)]));
        }
        // b defines only Q3, so it may omit Q1 and Q2 but lists Q3 first-seen later.
        b.patches.insert("Q3".into(), patch("Q3", &[(A, true)]));
        b.patches.insert("Q4".into(), patch("Q4", &[(A, true)]));
        a.patches.get_mut("P").unwrap().requires = vec!["Q2".into(), "Q1".into(), "Q3".into()];
        b.patches.get_mut("P").unwrap().requires = vec!["Q4".into(), "Q3".into()];
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        // Q4 is defined only by b; Q3 by both and listed by both.
        assert_eq!(
            merged.records.patches["P"].requires,
            ["Q2", "Q1", "Q3", "Q4"]
        );
        let reversed = merge(&[("b", &b), ("a", &a)]).unwrap();
        assert_eq!(
            reversed.records.patches["P"].requires,
            ["Q4", "Q3", "Q2", "Q1"]
        );
    }

    #[test]
    fn board_lists_union_and_every_other_field_must_be_equal() {
        let mut a = Records::default();
        a.boards
            .insert("bd".into(), board("bd", &[A], &["P1"], &["F1"], &["E1"]));
        let mut b = Records::default();
        b.boards
            .insert("bd".into(), board("bd", &[A], &["P2", "P1"], &[], &["E2"]));
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        let bd = &merged.records.boards["bd"];
        assert_eq!(
            (
                bd.patches.as_slice(),
                bd.findings.as_slice(),
                bd.evidence.as_slice()
            ),
            (
                &["P1".to_string(), "P2".into()][..],
                &["F1".to_string()][..],
                &["E1".to_string(), "E2".into()][..]
            )
        );

        b.boards.get_mut("bd").unwrap().model = "Y99".into();
        b.boards.get_mut("bd").unwrap().firmware[0].title = "other".into();
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert!(
            error.message.contains(
                "board bd: firmware: expected the same value in every catalog | received [{"
            ),
            "{}",
            error.message
        );
        assert!(error.message.contains("board bd: model: expected the same value in every catalog | received \"X99\" (a) and \"Y99\" (b)"), "{}", error.message);
    }

    #[test]
    fn every_other_board_field_must_be_equal() {
        type Edit = fn(&mut Board);
        let edits: [(&str, Edit); 6] = [
            ("vendor", |b| b.vendor = "Other".into()),
            ("chipset", |b| b.chipset = Some("C612".into())),
            ("revision.status", |b| {
                b.revision.status = crate::catalog::RevisionStatus::Unknown
            }),
            ("revision.label", |b| {
                b.revision.label = Some("rev 2".into())
            }),
            ("description", |b| b.description = Some("text".into())),
            ("facts", |b| {
                b.facts = vec![crate::catalog::Fact {
                    id: "f".into(),
                    statement: "s".into(),
                }]
            }),
        ];
        for (field, edit) in edits {
            let mut a = Records::default();
            a.boards
                .insert("bd".into(), board("bd", &[A], &[], &[], &[]));
            let mut b = a.clone();
            edit(b.boards.get_mut("bd").unwrap());
            let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
            assert!(
                error.message.starts_with(&format!(
                    "board bd: {field}: expected the same value in every catalog | received "
                )),
                "(board field {field}): expected a disagreement | received {}",
                error.message
            );
        }
    }

    #[test]
    fn a_shared_code_reference_that_drifted_is_a_disagreement() {
        // Both catalogs list build A, so its references must match; an edited location
        // must fail instead of surviving next to the original.
        let a = finding_set(finding("F", &[A, B]));
        let mut drifted = finding("F", &[A]);
        drifted.owner.references[0].location = "build-a+0x99".into();
        let error = merge(&[("a", &a), ("b", &finding_set(drifted))]).unwrap_err();
        assert!(
            error.message.contains(
                "finding F: owner.references of build build-a: expected the same value in every catalog | received [{\"build\":\"build-a\",\"location\":\"build-a+0x10\",\"module\":\"Mod\"}] (a) and [{\"build\":\"build-a\",\"location\":\"build-a+0x99\",\"module\":\"Mod\"}] (b)"
            ),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_code_reference_without_a_build_must_be_equal_in_every_catalog() {
        let buildless = |location: &str| {
            let mut finding = finding("F", &[A]);
            finding.owner.references.push(CodeReference {
                build: None,
                module: "Mod".into(),
                location: location.into(),
            });
            finding_set(finding)
        };
        let error = merge(&[("a", &buildless("entry")), ("b", &buildless("entry+4"))]).unwrap_err();
        assert!(
            error.message.contains(
                "finding F: owner.references without a build: expected the same value in every catalog | received"
            ),
            "{}",
            error.message
        );
        let merged = merge(&[("a", &buildless("entry")), ("b", &buildless("entry"))]).unwrap();
        assert_eq!(merged.records.findings["F"].owner.references.len(), 2);
    }

    #[test]
    fn code_references_of_a_build_only_one_catalog_lists_are_unioned() {
        let a = finding_set(finding("F", &[A]));
        let b = finding_set(finding("F", &[B]));
        let merged = merge(&[("a", &a), ("b", &b)]).unwrap();
        let builds: Vec<_> = merged.records.findings["F"]
            .owner
            .references
            .iter()
            .map(|reference| reference.build.as_deref())
            .collect();
        assert_eq!(builds, [Some(A), Some(B)]);
    }

    #[test]
    fn finding_fields_other_than_the_unioned_ones_must_be_equal() {
        type Edit = fn(&mut Finding);
        let edits: [(&str, Edit); 10] = [
            ("title", |f| f.title = "changed".into()),
            ("priority", |f| f.priority = crate::catalog::Priority::P1),
            ("affects.label", |f| f.affects.label = "PR9 only".into()),
            ("owner.description", |f| {
                f.owner.description = "changed".into()
            }),
            ("owner.modules", |f| {
                f.owner.modules = vec![crate::catalog::ModuleRef {
                    ui_name: "M".into(),
                    ffs_guid: None,
                }]
            }),
            ("confidence.finding.grade", |f| {
                f.confidence.finding.grade = "C2".into()
            }),
            ("description", |f| f.description = "changed".into()),
            ("not_established", |f| {
                f.not_established = Some("changed".into())
            }),
            ("remediation", |f| f.remediation = "changed".into()),
            ("detectors", |f| {
                f.detectors = vec![
                    serde_json::from_value(json!({
                        "id": "scan", "title": "scan", "anchor": {"in": "dsdt"},
                        "signatures": [{"label": "one", "defect": {"bytes": "00112233"}}],
                    }))
                    .unwrap(),
                ]
            }),
        ];
        for (field, edit) in edits {
            let a = finding_set(finding("F", &[A]));
            let mut changed = finding("F", &[A]);
            edit(&mut changed);
            let b = finding_set(changed);
            let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
            assert!(
                error.message.starts_with(&format!(
                    "finding F: {field}: expected the same value in every catalog | received "
                )),
                "(finding field {field}): expected a disagreement | received {}",
                error.message
            );
        }
    }

    fn finding_set(finding: Finding) -> Records {
        let mut r = Records::default();
        r.findings.insert(finding.id.clone(), finding);
        r
    }

    #[test]
    fn absent_optional_field_reads_as_absent_in_the_disagreement() {
        let a = finding_set(finding("F", &[A]));
        let mut changed = finding("F", &[A]);
        changed.not_established = Some("text".into());
        let error = merge(&[("a", &a), ("b", &finding_set(changed))]).unwrap_err();
        assert_eq!(
            error.message,
            "finding F: not_established: expected the same value in every catalog | received absent (a) and \"text\" (b)"
        );
    }

    #[test]
    fn finding_evidence_builds_and_references_union_without_duplicates() {
        let mut fa = finding("F", &[A]);
        fa.evidence = vec!["E1".into()];
        let mut fb = finding("F", &[A, B]);
        fb.evidence = vec!["E1".into(), "E2".into()];
        let merged = merge(&[("a", &finding_set(fa)), ("b", &finding_set(fb))]).unwrap();
        let f = &merged.records.findings["F"];
        assert_eq!(f.affects.builds, [A, B]);
        assert_eq!(f.evidence, ["E1", "E2"]);
        assert_eq!(
            f.owner.references.len(),
            2,
            "(identical reference deduplicated)"
        );
    }

    #[test]
    fn finding_patches_follow_the_relation_rule() {
        let mut a = both_boards();
        let mut b = both_boards();
        a.findings.get_mut("F-S").unwrap().patches = vec!["S".into()];
        b.findings.get_mut("F-S").unwrap().patches = vec!["S".into(), "PB".into()];
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert!(
            error.message.contains("finding F-S: patches: expected the same ids among the patches both catalogs define | received [\"S\"] (a) and [\"S\",\"PB\"] (b)"),
            "{}",
            error.message
        );
    }

    #[test]
    fn status_other_than_open_against_fixed_must_be_equal() {
        let mut retired = finding("F", &[A]);
        retired.status = FindingStatus::Retired;
        let error = merge(&[
            ("a", &finding_set(retired)),
            ("b", &finding_set(finding("F", &[A]))),
        ])
        .unwrap_err();
        assert_eq!(
            error.message,
            "finding F: status: expected the same value in every catalog, or open and fixed-by-patch | received \"retired\" (a) and \"open\" (b)"
        );
        let mut wont_fix = finding("F", &[A]);
        wont_fix.status = FindingStatus::WontFix;
        let fixed = fixed_finding("F", &[A], &["P"]);
        assert!(merge(&[("a", &finding_set(wont_fix)), ("b", &finding_set(fixed))]).is_err());
    }

    #[test]
    fn equal_statuses_are_kept_including_open_in_both() {
        let merged = merge(&[
            ("a", &finding_set(finding("F", &[A]))),
            ("b", &finding_set(finding("F", &[A]))),
        ])
        .unwrap();
        assert_eq!(merged.records.findings["F"].status, FindingStatus::Open);
    }

    #[test]
    fn evidence_with_one_id_must_be_identical() {
        let mut a = Records::default();
        a.evidence.insert("E".into(), evidence("E", "bd", A, &[]));
        let mut b = a.clone();
        b.evidence.get_mut("E").unwrap().limits = "other".into();
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        assert_eq!(
            error.message,
            "evidence E: limits: expected the same value in every catalog | received \"one boot\" (a) and \"other\" (b)"
        );
        assert!(merge(&[("a", &a), ("b", &a.clone())]).is_ok());
    }

    #[test]
    fn provenance_files_with_one_path_must_be_byte_identical() {
        let records = Records::default();
        let engine = engine();
        let same = vec![("provenance/P/x.asm".to_string(), b"mov".to_vec())];
        let other = vec![("provenance/P/x.asm".to_string(), b"nop".to_vec())];
        let extra = vec![("provenance/Q/y.asm".to_string(), b"ret".to_vec())];
        let input = |catalog_id, provenance| MergeInput {
            provenance,
            ..input(catalog_id, &engine, &records)
        };
        let merged =
            merge_catalogs(&[input("a", &same), input("b", &same), input("c", &extra)]).unwrap();
        let paths: Vec<&str> = merged.provenance.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["provenance/P/x.asm", "provenance/Q/y.asm"]);
        assert_eq!(merged.shared.provenance, ["provenance/P/x.asm"]);

        let error = merge_catalogs(&[input("a", &same), input("b", &other)]).unwrap_err();
        assert!(
            error.message.starts_with("provenance provenance/P/x.asm: content: expected the same bytes in every catalog | received 3 bytes, sha256 ")
                && error.message.contains(" (a) and 3 bytes, sha256 ")
                && error.message.ends_with(" (b)"),
            "{}",
            error.message
        );
    }

    #[test]
    fn engine_requirements_must_be_equal() {
        let records = Records::default();
        let (first, second) = (
            VersionReq::parse("^0.1").unwrap(),
            VersionReq::parse("^0.2").unwrap(),
        );
        let input = |catalog_id, engine| input(catalog_id, engine, &records);
        let error = merge_catalogs(&[input("a", &first), input("b", &second)]).unwrap_err();
        assert_eq!(
            error.message,
            "catalog.json: engine: expected the same requirement in every catalog | received \"^0.1\" (a) and \"^0.2\" (b)"
        );
        let merged = merge_catalogs(&[input("a", &first), input("b", &first)]).unwrap();
        assert_eq!(merged.engine, first);
    }

    #[test]
    fn sources_with_one_id_are_named_by_position_in_a_disagreement() {
        let mut first = one("P");
        let mut second = one("P");
        first.patches.get_mut("P").unwrap().title = "x".into();
        second.patches.get_mut("P").unwrap().title = "y".into();
        let other = Records::default();
        let error = merge(&[("dev", &first), ("other", &other), ("dev", &second)]).unwrap_err();
        assert_eq!(
            error.message,
            "patch P: title: expected the same value in every catalog | received \"x\" (dev (#1)) and \"y\" (dev (#3))"
        );
    }

    #[test]
    fn engine_disagreement_between_sources_with_one_id_names_both_by_position() {
        let records = Records::default();
        let (first, second) = (
            VersionReq::parse("^0.1").unwrap(),
            VersionReq::parse("^0.2").unwrap(),
        );
        let error = merge_catalogs(&[
            input("dev", &first, &records),
            input("dev", &second, &records),
        ])
        .unwrap_err();
        assert_eq!(
            error.message,
            "catalog.json: engine: expected the same requirement in every catalog | received \"^0.1\" (dev (#1)) and \"^0.2\" (dev (#2))"
        );
    }

    #[test]
    fn display_names_add_a_position_only_to_ids_that_repeat() {
        let (engine, records) = (engine(), Records::default());
        let inputs = [
            input("dev", &engine, &records),
            input("other", &engine, &records),
            input("dev", &engine, &records),
        ];
        assert_eq!(display_names(&inputs), ["dev (#1)", "other", "dev (#3)"]);
        assert_eq!(display_names(&inputs[..2]), ["dev", "other"]);
    }

    #[test]
    fn merged_sources_pin_every_input_in_order() {
        let (engine, records) = (engine(), Records::default());
        let version = Version::new(2, 3, 4);
        let first = MergeInput {
            version: &version,
            ..input("a", &engine, &records)
        };
        let merged = merge_catalogs(&[first, input("b", &engine, &records)]).unwrap();
        assert_eq!(
            merged.sources,
            [
                CatalogSource {
                    id: "a".into(),
                    version,
                    manifest_sha256: Digest256::of(b"a"),
                },
                CatalogSource {
                    id: "b".into(),
                    version: ONE.clone(),
                    manifest_sha256: Digest256::of(b"b"),
                },
            ]
        );
    }

    /// The pin of `id` as a catalog that merged it would record it.
    fn pin(id: &str, manifest: &[u8]) -> CatalogSource {
        CatalogSource {
            id: id.into(),
            version: ONE.clone(),
            manifest_sha256: Digest256::of(manifest),
        }
    }

    #[test]
    fn a_pin_is_current_when_the_source_manifest_has_the_pinned_digest() {
        let (engine, records) = (engine(), Records::default());
        // `input` digests the id as the manifest bytes, so "b" matches a pin made over b"b".
        let listed = [pin("b", b"b")];
        let merge_of = MergeInput {
            sources: &listed,
            ..input("merged", &engine, &records)
        };
        let checks = check_pins(&[merge_of, input("b", &engine, &records)]);
        assert_eq!(checks.len(), 1);
        let check = &checks[0];
        assert_eq!(
            (check.listed_by.as_str(), check.source.as_str(), check.state),
            ("merged", "b", PinState::Pinned)
        );
        assert_eq!(check.pinned, check.current);
    }

    #[test]
    fn a_pin_moved_when_the_source_manifest_changed_and_both_digests_are_kept() {
        let (engine, records) = (engine(), Records::default());
        let listed = [pin("b", b"older manifest")];
        let merge_of = MergeInput {
            sources: &listed,
            ..input("merged", &engine, &records)
        };
        let checks = check_pins(&[input("b", &engine, &records), merge_of]);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].state, PinState::Moved);
        assert_eq!(checks[0].pinned, Digest256::of(b"older manifest"));
        assert_eq!(checks[0].current, Digest256::of(b"b"));
    }

    #[test]
    fn a_pin_without_a_source_of_that_id_gives_no_check_and_a_missing_list_gives_none() {
        let (engine, records) = (engine(), Records::default());
        let listed = [pin("gone", b"x")];
        let merge_of = MergeInput {
            sources: &listed,
            ..input("merged", &engine, &records)
        };
        assert!(check_pins(&[merge_of, input("b", &engine, &records)]).is_empty());
        assert!(
            check_pins(&[input("a", &engine, &records), input("b", &engine, &records)]).is_empty()
        );
    }

    #[test]
    fn a_pin_is_checked_against_each_source_with_its_id_and_never_against_its_own_catalog() {
        let (engine, records) = (engine(), Records::default());
        let listed = [pin("dev", b"dev"), pin("merged", b"merged")];
        let merge_of = MergeInput {
            sources: &listed,
            ..input("merged", &engine, &records)
        };
        let checks = check_pins(&[
            input("dev", &engine, &records),
            merge_of,
            input("dev", &engine, &records),
        ]);
        let names: Vec<(&str, &str)> = checks
            .iter()
            .map(|c| (c.listed_by.as_str(), c.source.as_str()))
            .collect();
        assert_eq!(names, [("merged", "dev (#1)"), ("merged", "dev (#3)")]);
    }

    #[test]
    fn disagreements_come_in_kind_then_id_order_whatever_the_insertion_order() {
        let drift = |ids: &[&str]| {
            let mut records = Records::default();
            for id in ids {
                records
                    .patches
                    .insert((*id).into(), patch(id, &[(A, true)]));
                records.findings.insert((*id).into(), finding(id, &[A]));
            }
            records
        };
        let mut a = drift(&["P2", "P1"]);
        let mut b = drift(&["P1", "P2"]);
        for id in ["P2", "P1"] {
            a.patches.get_mut(id).unwrap().title = "x".into();
            b.patches.get_mut(id).unwrap().title = "y".into();
            a.findings.get_mut(id).unwrap().title = "x".into();
            b.findings.get_mut(id).unwrap().title = "y".into();
        }
        let error = merge(&[("a", &a), ("b", &b)]).unwrap_err();
        let heads: Vec<&str> = error
            .message
            .lines()
            .map(|line| line.split(": title:").next().unwrap())
            .collect();
        assert_eq!(heads, ["patch P1", "patch P2", "finding P1", "finding P2"]);
    }

    #[test]
    fn merging_no_catalog_is_a_usage_error() {
        let error = merge_catalogs(&[]).unwrap_err();
        assert_eq!(error.code, Code::Usage);
        assert_eq!(
            error.message,
            "catalogs: expected at least 1 catalog to merge | received none"
        );
    }

    #[test]
    fn remove_path_removes_a_nested_field_only() {
        let mut value = json!({"a": {"b": 1, "c": 2}, "d": 3});
        remove_path(&mut value, "a.b");
        remove_path(&mut value, "missing.x");
        assert_eq!(value, json!({"a": {"c": 2}, "d": 3}));
    }

    #[test]
    fn field_diffs_name_nested_fields_and_missing_keys() {
        let a = json!({"x": {"y": 1, "z": 2}, "only_a": true});
        let b = json!({"x": {"y": 1, "z": 3}});
        let mut diffs = Vec::new();
        field_diffs(Some(&a), Some(&b), "", &mut diffs);
        assert_eq!(
            diffs,
            [
                ("only_a".to_string(), Some(json!(true)), None),
                ("x.z".to_string(), Some(json!(2)), Some(json!(3))),
            ]
        );
    }

    #[test]
    fn union_in_order_deduplicates_across_lists() {
        let lists: [Vec<&str>; 3] = [vec!["b", "a"], vec!["a", "c"], vec!["b", "d"]];
        assert_eq!(
            union_in_order(lists.iter().map(Vec::as_slice)),
            ["b", "a", "c", "d"]
        );
    }
}
