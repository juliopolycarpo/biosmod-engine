//! Semantic validation that typed parsing cannot express.
//!
//! Strict serde models reject unknown fields and wrong types; these checks
//! cover identifiers, paths, references, cycles, symmetric conflicts, hunk
//! geometry and engine compatibility.

use crate::catalog::*;
use crate::error::{Code, Error, Result};
use crate::patch;
use std::collections::{BTreeMap, BTreeSet};

/// This engine's version, checked against `engine` requirements.
pub fn engine_version() -> semver::Version {
    semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver")
}

fn invalid(message: String) -> Error {
    Error::new(Code::CatalogInvalid, message)
}

/// Identifiers: 1-64 chars of `[A-Za-z0-9._-]`, starting alphanumeric.
pub fn identifier(id: &str, what: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} {id:?}: expected 1-64 characters [A-Za-z0-9._-] starting alphanumeric"
        )))
    }
}

/// Catalog-relative paths: `/`-separated, no empty, `.` or `..` components, safe characters only.
pub fn relative_path(path: &str) -> Result<()> {
    let ok = !path.is_empty()
        && path.len() <= 200
        && !path.starts_with('/')
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        });
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "path {path:?}: expected a relative path of [A-Za-z0-9._-] components"
        )))
    }
}

/// Validate the index itself.
pub fn manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != CATALOG_SCHEMA {
        return Err(invalid(format!(
            "catalog.json: expected schema {CATALOG_SCHEMA:?} | received {:?}",
            manifest.schema
        )));
    }
    identifier(&manifest.id, "catalog id")?;
    if !manifest.engine.matches(&engine_version()) {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "catalog {} requires engine {} | this is {}",
                manifest.id,
                manifest.engine,
                engine_version()
            ),
        ));
    }
    if manifest.files.len() > MAX_FILES {
        return Err(invalid(format!(
            "catalog.json: {} files exceed the limit of {MAX_FILES}",
            manifest.files.len()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for entry in &manifest.files {
        relative_path(&entry.path)?;
        let expected = entry.kind.directory();
        let (dir, name) = entry.path.split_once('/').unwrap_or(("", ""));
        if dir != expected
            || (entry.kind != FileKind::Provenance
                && (name.contains('/') || !name.ends_with(".json")))
        {
            return Err(invalid(format!(
                "{}: {:?} files must be {expected}/<id>.json",
                entry.path, entry.kind
            )));
        }
        if !seen.insert(entry.path.to_ascii_lowercase()) {
            return Err(invalid(format!(
                "{}: listed more than once (paths compare case-insensitively)",
                entry.path
            )));
        }
        if entry.length > MAX_FILE_BYTES {
            return Err(invalid(format!(
                "{}: length {} exceeds {MAX_FILE_BYTES}",
                entry.path, entry.length
            )));
        }
        total += entry.length;
    }
    if total > MAX_TOTAL_BYTES {
        return Err(invalid(format!(
            "catalog.json: indexed files total {total} bytes, above {MAX_TOTAL_BYTES}"
        )));
    }
    Ok(())
}

/// Validate cross-references and invariants of a loaded catalog.
pub fn catalog(catalog: &Catalog) -> Result<()> {
    let full = matches!(catalog.scope, Scope::All);
    let mut firmware: BTreeMap<&str, &str> = BTreeMap::new();
    for board in catalog.boards.values() {
        board_profile(board, catalog)?;
        for build in &board.firmware {
            if let Some(other) = firmware.insert(&build.id, &board.id) {
                return Err(invalid(format!(
                    "firmware {}: declared by both {other} and {}",
                    build.id, board.id
                )));
            }
        }
    }
    for patch in catalog.patches.values() {
        record(patch, catalog, &firmware, full)?;
        patch_fixes(patch, catalog)?;
    }
    for finding in catalog.findings.values() {
        finding_record(finding, catalog, &firmware, full)?;
    }
    acyclic(catalog, "requires", |p| &p.requires)?;
    acyclic(catalog, "supersedes", |p| &p.supersedes)?;
    for evidence in catalog.evidence.values() {
        evidence_record(evidence, catalog, &firmware)?;
    }
    Ok(())
}

fn board_profile(board: &Board, catalog: &Catalog) -> Result<()> {
    let at = format!("board {}", board.id);
    if board.schema != BOARD_SCHEMA {
        return Err(invalid(format!(
            "{at}: expected schema {BOARD_SCHEMA:?} | received {:?}",
            board.schema
        )));
    }
    identifier(&board.id, "board id")?;
    if board.firmware.is_empty() {
        return Err(invalid(format!(
            "{at}: expected at least one firmware build"
        )));
    }
    unique(
        board.firmware.iter().map(|b| b.id.as_str()),
        &format!("{at} firmware"),
    )?;
    unique(
        board.facts.iter().map(|f| f.id.as_str()),
        &format!("{at} facts"),
    )?;
    unique(
        board.patches.iter().map(String::as_str),
        &format!("{at} patches"),
    )?;
    for build in &board.firmware {
        identifier(&build.id, "firmware id")?;
    }
    for fact in &board.facts {
        identifier(&fact.id, "fact id")?;
    }
    for id in &board.patches {
        if !catalog.patches.contains_key(id) {
            return Err(invalid(format!("{at}: references unknown patch {id}")));
        }
    }
    for id in &board.evidence {
        if !catalog.evidence.contains_key(id) {
            return Err(invalid(format!("{at}: references unknown evidence {id}")));
        }
    }
    unique(
        board.findings.iter().map(String::as_str),
        &format!("{at} findings"),
    )?;
    for id in &board.findings {
        let Some(finding) = catalog.findings.get(id) else {
            return Err(invalid(format!("{at}: references unknown finding {id}")));
        };
        if !finding
            .affects
            .builds
            .iter()
            .any(|b| board.firmware.iter().any(|f| &f.id == b))
        {
            return Err(invalid(format!(
                "{at}: lists finding {id}, which affects none of its firmware builds"
            )));
        }
    }
    Ok(())
}

/// A confidence grade: `C0` (established) to `C3` (speculative).
fn grade(value: &Grade, what: &str) -> Result<()> {
    let ok = matches!(value.grade.as_bytes(), [b'C', b'0'..=b'3']);
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} grade: expected C0 | C1 | C2 | C3 | received {:?}",
            value.grade
        )))
    }
}

fn finding_record(
    finding: &Finding,
    catalog: &Catalog,
    firmware: &BTreeMap<&str, &str>,
    full: bool,
) -> Result<()> {
    let at = format!("finding {}", finding.id);
    if finding.schema != FINDING_SCHEMA {
        return Err(invalid(format!(
            "{at}: expected schema {FINDING_SCHEMA:?} | received {:?}",
            finding.schema
        )));
    }
    identifier(&finding.id, "finding id")?;
    for (text, name) in [
        (&finding.title, "title"),
        (&finding.description, "description"),
        (&finding.remediation, "remediation"),
        (&finding.owner.description, "owner description"),
        (&finding.affects.label, "affects label"),
    ] {
        if text.trim().is_empty() {
            return Err(invalid(format!("{at}: {name} must not be empty")));
        }
    }
    grade(
        &finding.confidence.finding,
        &format!("{at} finding confidence"),
    )?;
    if let Some(condition) = &finding.confidence.condition {
        grade(condition, &format!("{at} condition confidence"))?;
    }
    if finding.affects.builds.is_empty() {
        return Err(invalid(format!(
            "{at}: affects.builds expects at least one firmware build"
        )));
    }
    unique(
        finding.affects.builds.iter().map(String::as_str),
        &format!("{at} affects.builds"),
    )?;
    if full
        && let Some(build) = finding
            .affects
            .builds
            .iter()
            .find(|b| !firmware.contains_key(b.as_str()))
    {
        return Err(invalid(format!("{at}: affects unknown firmware {build}")));
    }
    for reference in &finding.owner.references {
        if let Some(build) = &reference.build
            && !finding.affects.builds.contains(build)
        {
            return Err(invalid(format!(
                "{at}: code reference {} names build {build}, which is not in affects.builds",
                reference.location
            )));
        }
    }
    unique(
        finding.evidence.iter().map(String::as_str),
        &format!("{at} evidence"),
    )?;
    for id in &finding.evidence {
        if !catalog.evidence.contains_key(id) {
            return Err(invalid(format!("{at}: references unknown evidence {id}")));
        }
    }
    unique(
        finding.patches.iter().map(String::as_str),
        &format!("{at} patches"),
    )?;
    if finding.status == FindingStatus::FixedByPatch && finding.patches.is_empty() {
        return Err(invalid(format!(
            "{at}: status fixed-by-patch expects at least one patch in patches | received none"
        )));
    }
    if finding.status != FindingStatus::FixedByPatch && !finding.patches.is_empty() {
        return Err(invalid(format!(
            "{at}: status expected fixed-by-patch while patches are listed | received {}",
            finding.status.label()
        )));
    }
    // A board-scoped load holds only that board's patches, so the finding to
    // patch direction is checked on full loads; `patch_fixes` covers the other
    // direction on every load.
    if full {
        for id in &finding.patches {
            let Some(patch) = catalog.patches.get(id) else {
                return Err(invalid(format!("{at}: references unknown patch {id}")));
            };
            if !patch.fixes.contains(&finding.id) {
                return Err(invalid(format!(
                    "{at}: lists patch {id}, but {id} does not list {} in fixes",
                    finding.id
                )));
            }
        }
    }
    unique(
        finding.detectors.iter().map(|d| d.id.as_str()),
        &format!("{at} detectors"),
    )?;
    for detector in &finding.detectors {
        detector_record(detector, &format!("{at} detector {}", detector.id))?;
    }
    Ok(())
}

/// Check one detector: identifier, signatures, wildcard indices and match counts.
fn detector_record(detector: &Detector, at: &str) -> Result<()> {
    identifier(&detector.id, &format!("{at} id"))?;
    if detector.title.trim().is_empty() {
        return Err(invalid(format!("{at}: title must not be empty")));
    }
    if detector.signatures.is_empty() {
        return Err(invalid(format!(
            "{at}: signatures expects at least one signature | received none"
        )));
    }
    let expect = detector.expect;
    if expect.max_per_module == 0 || expect.min_per_module > expect.max_per_module {
        return Err(invalid(format!(
            "{at}: expect expects 1 <= max_per_module and min_per_module <= max_per_module | received min {} max {}",
            expect.min_per_module, expect.max_per_module
        )));
    }
    unique(
        detector.signatures.iter().map(|s| s.label.as_str()),
        &format!("{at} signature labels"),
    )?;
    for signature in &detector.signatures {
        let at = format!("{at} signature {:?}", signature.label);
        identifier(&signature.label, &format!("{at} label"))?;
        pattern_record(&signature.defect, &format!("{at} defect"))?;
        if let Some(fixed) = &signature.fixed {
            pattern_record(fixed, &format!("{at} fixed"))?;
            if fixed.bytes.0 == signature.defect.bytes.0 && fixed.wild == signature.defect.wild {
                return Err(invalid(format!(
                    "{at}: fixed expects a pattern different from defect | received an identical pattern"
                )));
            }
        }
    }
    Ok(())
}

/// Fewest non-wildcard bytes a detector pattern may have.
const MIN_FIXED_BYTES: usize = 4;

/// A pattern needs bytes, and every wildcard index must fall inside them once.
///
/// Example: eight bytes with wildcards at 0 and 1 pass; four bytes with one wildcard fail.
fn pattern_record(pattern: &Pattern, at: &str) -> Result<()> {
    let length = pattern.bytes.0.len();
    if length == 0 {
        return Err(invalid(format!("{at}: bytes must not be empty")));
    }
    let mut seen = BTreeSet::new();
    for index in &pattern.wild {
        if *index >= length || !seen.insert(*index) {
            return Err(invalid(format!(
                "{at}: wild index expected unique and below {length} | received {index}"
            )));
        }
    }
    // Fewer fixed bytes match far too much code to name a defect.
    let fixed = length - seen.len();
    if fixed < MIN_FIXED_BYTES {
        return Err(invalid(format!(
            "{at}: expected at least {MIN_FIXED_BYTES} fixed (non-wild) bytes | received {fixed} of {length}"
        )));
    }
    Ok(())
}

/// Check a patch's `fixes` against its findings, the finding records and the grades it records.
fn patch_fixes(patch: &Patch, catalog: &Catalog) -> Result<()> {
    let at = format!("patch {}", patch.id);
    unique(
        patch.fixes.iter().map(String::as_str),
        &format!("{at} fixes"),
    )?;
    for id in &patch.fixes {
        if !patch.findings.contains(id) {
            return Err(invalid(format!(
                "{at}: fixes {id}, which is not in findings"
            )));
        }
        let Some(finding) = catalog.findings.get(id) else {
            return Err(invalid(format!("{at}: fixes unknown finding {id}")));
        };
        if !finding.patches.contains(&patch.id) {
            return Err(invalid(format!(
                "{at}: fixes {id}, but finding {id} does not list {} in patches",
                patch.id
            )));
        }
        if let Some(recorded) = patch.confidence.findings.get(id) {
            let leading = recorded.split_whitespace().next().unwrap_or("");
            if leading != finding.confidence.finding.grade {
                return Err(invalid(format!(
                    "{at}: confidence for {id} expected leading grade {} (as in the finding) | received {recorded:?}",
                    finding.confidence.finding.grade
                )));
            }
        }
    }
    Ok(())
}

fn unique<'a>(items: impl Iterator<Item = &'a str>, what: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(invalid(format!("{what}: duplicate {item:?}")));
        }
    }
    Ok(())
}

fn record(
    patch: &Patch,
    catalog: &Catalog,
    firmware: &BTreeMap<&str, &str>,
    full: bool,
) -> Result<()> {
    let at = format!("patch {}", patch.id);
    if patch.schema != PATCH_SCHEMA {
        return Err(invalid(format!(
            "{at}: expected schema {PATCH_SCHEMA:?} | received {:?}",
            patch.schema
        )));
    }
    identifier(&patch.id, "patch id")?;
    for (list, name) in [
        (&patch.requires, "requires"),
        (&patch.supersedes, "supersedes"),
        (&patch.conflicts, "conflicts"),
    ] {
        unique(list.iter().map(String::as_str), &format!("{at} {name}"))?;
        for other in list {
            if other == &patch.id {
                return Err(invalid(format!("{at}: {name} lists itself")));
            }
            let Some(target) = catalog.patches.get(other) else {
                return Err(invalid(format!(
                    "{at}: {name} references unknown patch {other}"
                )));
            };
            if name == "conflicts" && !target.conflicts.contains(&patch.id) {
                return Err(invalid(format!(
                    "{at}: conflicts with {other}, but {other} does not list {}",
                    patch.id
                )));
            }
        }
    }
    if let Some(both) = patch.requires.iter().find(|r| patch.conflicts.contains(r)) {
        return Err(invalid(format!(
            "{at}: both requires and conflicts with {both}"
        )));
    }
    if patch.variants.is_empty() {
        return Err(invalid(format!("{at}: expected at least one variant")));
    }
    for (build, variant) in &patch.variants {
        let board = firmware.get(build.as_str());
        if board.is_none() && full {
            return Err(invalid(format!(
                "{at}: variant for unknown firmware {build}"
            )));
        }
        let Variant::Applicable(variant) = variant else {
            continue;
        };
        let at = format!("{at} variant {build}");
        if variant.components.is_empty() {
            return Err(invalid(format!(
                "{at}: applicable variant has no components"
            )));
        }
        if let Some(board) = board.and_then(|b| catalog.boards.get(*b)) {
            for fact in &variant.requires_facts {
                if !board.facts.iter().any(|f| &f.id == fact) {
                    return Err(invalid(format!(
                        "{at}: requires fact {fact}, which board {} does not define",
                        board.id
                    )));
                }
            }
        }
        let mut keys = BTreeSet::new();
        let mut tables: BTreeMap<_, Vec<(usize, u128)>> = BTreeMap::new();
        for component in &variant.components {
            if !keys.insert((component.ffs_guid, component.leaf, component.table_offset)) {
                return Err(invalid(format!(
                    "{at}: component {} listed twice",
                    component.name
                )));
            }
            component_geometry(component, patch, &at)?;
            if component.leaf == LeafKind::AcpiTable {
                let end = component.table_offset as u128
                    + u128::from(component.source_size.max(component.result_size));
                tables
                    .entry(component.ffs_guid)
                    .or_default()
                    .push((component.table_offset, end));
            }
        }
        for (guid, ranges) in &mut tables {
            ranges.sort_unstable();
            let mut furthest: Option<(usize, u128)> = None;
            for &(start, end) in ranges.iter() {
                if let Some((previous, previous_end)) = furthest {
                    if (start as u128) < previous_end {
                        return Err(invalid(format!(
                            "{at}: FFS {guid} has overlapping ACPI table offsets {previous:#x} and {start:#x}"
                        )));
                    }
                    if end > previous_end {
                        furthest = Some((start, end));
                    }
                } else {
                    furthest = Some((start, end));
                }
            }
        }
    }
    Ok(())
}

fn component_geometry(component: &Component, patch: &Patch, at: &str) -> Result<()> {
    let at = format!("{at} component {}", component.name);
    if component.leaf == LeafKind::Pe32 && component.table_offset != 0 {
        return Err(invalid(format!(
            "{at}: table_offset applies only to acpi-table components"
        )));
    }
    if component.hunks.is_empty() {
        return Err(invalid(format!("{at}: expected at least one hunk")));
    }
    for name in &component.layer_on {
        if !patch.requires.contains(name) {
            return Err(invalid(format!(
                "{at}: layer_on {name} must also be listed in requires"
            )));
        }
    }
    if component.layer_on.is_empty() != component.input_sha256.is_none() {
        return Err(invalid(format!(
            "{at}: input_sha256 is required exactly when layer_on is set"
        )));
    }
    patch::ordered(&component.hunks).map_err(|e| invalid(format!("{at}: {}", e.message)))?;
    let base = usize::try_from(component.source_size).map_err(|_| {
        invalid(format!(
            "{at}: source_size {} exceeds the supported range",
            component.source_size
        ))
    })?;
    let result = usize::try_from(component.result_size).map_err(|_| {
        invalid(format!(
            "{at}: result_size {} exceeds the supported range",
            component.result_size
        ))
    })?;
    let mut appended = 0usize;
    for hunk in &component.hunks {
        let window = hunk.context_before.0.len()
            + hunk.before.0.len().max(hunk.after.0.len())
            + hunk.context_after.0.len();
        if let Some(bad) = hunk
            .wild_before
            .iter()
            .chain(&hunk.wild_after)
            .find(|w| **w >= window)
        {
            return Err(invalid(format!(
                "{at}: hunk at {:#x} wildcard {bad} outside its {window}-byte signature",
                hunk.offset
            )));
        }
        match hunk.op {
            HunkOp::Replace => {
                if hunk.before.0.is_empty() || hunk.before.0.len() != hunk.after.0.len() {
                    return Err(invalid(format!(
                        "{at}: replace hunk at {:#x} needs equal, non-empty before/after",
                        hunk.offset
                    )));
                }
                if hunk
                    .offset
                    .checked_add(hunk.before.0.len())
                    .is_none_or(|end| end > base)
                {
                    return Err(invalid(format!(
                        "{at}: hunk at {:#x} ends past the module size {base:#x}",
                        hunk.offset
                    )));
                }
            }
            HunkOp::Append => {
                if !hunk.before.0.is_empty() || hunk.after.0.is_empty() {
                    return Err(invalid(format!(
                        "{at}: append hunk at {:#x} needs empty before and non-empty after",
                        hunk.offset
                    )));
                }
                if component.layer_on.is_empty() && hunk.offset != base {
                    return Err(invalid(format!(
                        "{at}: append hunk offset {:#x} must equal source_size {base:#x}",
                        hunk.offset
                    )));
                }
                appended = appended.checked_add(hunk.after.0.len()).ok_or_else(|| {
                    invalid(format!(
                        "{at}: appended size {appended} plus {} exceeds the supported range",
                        hunk.after.0.len()
                    ))
                })?;
            }
        }
    }
    let expected = base.checked_add(appended).ok_or_else(|| {
        invalid(format!(
            "{at}: source_size {base} plus {appended} appended bytes exceeds the supported range"
        ))
    })?;
    if component.layer_on.is_empty() && result != expected {
        return Err(invalid(format!(
            "{at}: result_size {} must equal source_size {base} plus {appended} appended bytes",
            component.result_size
        )));
    }
    Ok(())
}

fn acyclic(catalog: &Catalog, name: &str, edges: impl Fn(&Patch) -> &Vec<String>) -> Result<()> {
    // Depth-first search with colors; reports the first cycle found.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    fn visit<'a>(
        id: &'a str,
        catalog: &'a Catalog,
        edges: &dyn Fn(&Patch) -> &Vec<String>,
        state: &mut BTreeMap<&'a str, u8>,
        name: &str,
    ) -> Result<()> {
        match state.get(id) {
            Some(1) => {
                return Err(invalid(format!(
                    "patch {id}: {name} relationship forms a cycle"
                )));
            }
            Some(_) => return Ok(()),
            None => {}
        }
        state.insert(id, 1);
        if let Some(patch) = catalog.patches.get(id) {
            for next in edges(patch) {
                visit(next, catalog, edges, state, name)?;
            }
        }
        state.insert(id, 2);
        Ok(())
    }
    for id in catalog.patches.keys() {
        visit(id, catalog, &edges, &mut state, name)?;
    }
    Ok(())
}

fn evidence_record(
    evidence: &Evidence,
    catalog: &Catalog,
    firmware: &BTreeMap<&str, &str>,
) -> Result<()> {
    let at = format!("evidence {}", evidence.id);
    if evidence.schema != EVIDENCE_SCHEMA {
        return Err(invalid(format!(
            "{at}: expected schema {EVIDENCE_SCHEMA:?} | received {:?}",
            evidence.schema
        )));
    }
    identifier(&evidence.id, "evidence id")?;
    let date_ok = evidence.date.len() == 10
        && evidence.date.bytes().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
    if !date_ok {
        return Err(invalid(format!(
            "{at}: date {:?}: expected YYYY-MM-DD",
            evidence.date
        )));
    }
    if let Some(board) = catalog.boards.get(&evidence.board) {
        if !board.firmware.iter().any(|f| f.id == evidence.firmware) {
            return Err(invalid(format!(
                "{at}: firmware {} is not a build of board {}",
                evidence.firmware, board.id
            )));
        }
    } else if matches!(catalog.scope, Scope::All)
        || !firmware.contains_key(evidence.firmware.as_str())
    {
        return Err(invalid(format!(
            "{at}: references unknown board {}",
            evidence.board
        )));
    }
    if let Some(run) = &evidence.replay {
        replay_run(&at, run)?;
    }
    for item in &evidence.patches {
        if let Some(patch) = catalog.patches.get(&item.id) {
            if patch.version < item.version {
                return Err(invalid(format!(
                    "{at}: patch {} version {} is newer than the catalog's {}",
                    item.id, item.version, patch.version
                )));
            }
        } else if matches!(catalog.scope, Scope::All) {
            return Err(invalid(format!(
                "{at}: references unknown patch {}",
                item.id
            )));
        }
    }
    Ok(())
}

/// The replay block of an evidence record: roles are known and something ran on something.
///
/// Example: an input with role `"sample"` fails with `expected harness | scenario | module`.
fn replay_run(at: &str, run: &ReplayRun) -> Result<()> {
    if run.harness.is_empty() {
        return Err(invalid(format!(
            "{at}: replay harness: expected a file name | received none"
        )));
    }
    if run.runtime.is_empty() {
        return Err(invalid(format!(
            "{at}: replay runtime: expected versions | received none"
        )));
    }
    if run.inputs.is_empty() {
        return Err(invalid(format!(
            "{at}: replay inputs: expected at least the harness | received none"
        )));
    }
    for input in &run.inputs {
        if !["harness", "scenario", "module"].contains(&input.role.as_str()) {
            return Err(invalid(format!(
                "{at}: replay input {}: role: expected harness | scenario | module | received {}",
                input.name, input.role
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Digest256;
    use std::collections::BTreeMap;

    fn run() -> ReplayRun {
        ReplayRun {
            harness: "fan.py".into(),
            scenario: None,
            runtime: BTreeMap::from([("unicorn".to_string(), "2.1.4".to_string())]),
            inputs: vec![ReplayInput {
                role: "harness".into(),
                name: "fan.py".into(),
                sha256: Digest256::of(b"fan"),
            }],
            output_sha256: Digest256::of(b""),
        }
    }

    #[test]
    fn a_complete_replay_block_is_accepted() {
        replay_run("evidence x", &run()).expect("complete block");
    }

    #[test]
    fn a_replay_block_without_inputs_names_the_gap() {
        let mut broken = run();
        broken.inputs.clear();
        let error = replay_run("evidence x", &broken).unwrap_err();
        assert!(
            error
                .message
                .contains("replay inputs: expected at least the harness | received none"),
            "{error}"
        );
    }

    #[test]
    fn a_replay_block_without_runtime_versions_names_the_gap() {
        let mut broken = run();
        broken.runtime.clear();
        let error = replay_run("evidence x", &broken).unwrap_err();
        assert!(
            error.message.contains("replay runtime: expected versions"),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_input_role_names_the_role() {
        let mut broken = run();
        broken.inputs[0].role = "sample".into();
        let error = replay_run("evidence x", &broken).unwrap_err();
        assert!(
            error
                .message
                .contains("role: expected harness | scenario | module | received sample"),
            "{error}"
        );
    }

    #[test]
    fn an_evidence_record_with_a_replay_block_round_trips_strictly() {
        let text = serde_json::json!({
            "schema": EVIDENCE_SCHEMA, "id": "replay-fan", "kind": "offline-validation",
            "date": "2026-11-12", "title": "t", "board": "unscoped", "firmware": "unscoped",
            "patches": [], "observations": [], "limits": "emulated",
            "replay": run(),
        });
        let parsed: Evidence = serde_json::from_value(text).expect("record parses");
        assert_eq!(parsed.replay.expect("replay block").harness, "fan.py");
        let extra = serde_json::json!({
            "schema": EVIDENCE_SCHEMA, "id": "x", "kind": "offline-validation", "date": "2026-11-12",
            "title": "t", "board": "b", "firmware": "f", "patches": [], "observations": [],
            "limits": "l", "replay": {"harness": "h", "mystery": 1},
        });
        assert!(serde_json::from_value::<Evidence>(extra).is_err());
    }

    #[test]
    fn paths_reject_escapes_and_hidden_components() {
        for bad in [
            "../x.json",
            "/abs.json",
            "a//b.json",
            "a/./b.json",
            ".hidden/x.json",
            "a\\b.json",
            "a/b c.json",
            "",
        ] {
            assert!(relative_path(bad).is_err(), "{bad} should be rejected");
        }
        assert!(relative_path("patches/B02-B03.json").is_ok());
    }

    #[test]
    fn identifiers_are_bounded() {
        assert!(identifier("machinist-mr9a-pro-q87-rev-1.2", "board id").is_ok());
        assert!(identifier("-x", "id").is_err());
        assert!(identifier(&"a".repeat(65), "id").is_err());
        assert!(identifier("a::b", "id").is_err());
    }
}
