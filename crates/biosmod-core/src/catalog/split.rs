//! Cut the records of one board out of a multi-board catalog.
//!
//! A single-board catalog cannot carry a foreign firmware build: validation
//! rejects a variant for an unknown build, a code reference whose build is not
//! in `affects.builds`, a finding that affects no build, and a board that lists
//! a finding affecting none of its builds. [`split_board`] reduces every record
//! to the board's builds and reports what it dropped.

use super::{Board, Finding, FindingStatus, Patch, Variant, records::Records};
use crate::error::{Code, Error, Result};
use std::collections::BTreeSet;

/// The ids of the records a split left out, in id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dropped {
    pub patches: Vec<String>,
    pub findings: Vec<String>,
    pub evidence: Vec<String>,
}

/// A single-board catalog and what was left out of it.
#[derive(Debug, Clone)]
pub struct Split {
    pub records: Records,
    pub dropped: Dropped,
}

fn invalid(message: String) -> Error {
    Error::new(Code::CatalogInvalid, message)
}

/// Reduce `source` to the board `board_id`.
///
/// - A patch stays when one of the board's builds has an `applicable` variant;
///   its variants are cut to those builds and `requires`, `supersedes` and
///   `conflicts` to the patches that stay.
/// - A finding stays when `affects.builds` meets the board's builds; foreign
///   builds and code references go, and a `fixed-by-patch` finding left with
///   no patch becomes `open`.
/// - Evidence stays when its `board` is `board_id`.
/// - The board's `patches`, `findings` and `evidence` lists keep their order.
///
/// Fails when the board is unknown, when a kept patch requires a dropped patch
/// or names a dropped finding, or when kept evidence names a dropped patch.
///
/// Example: `let split = split_board(&records, "acme-x99")?;`
pub fn split_board(source: &Records, board_id: &str) -> Result<Split> {
    let board = source.boards.get(board_id).ok_or_else(|| {
        let known: Vec<&str> = source.boards.keys().map(String::as_str).collect();
        Error::new(
            Code::TargetNotFound,
            format!(
                "board: expected one of {} | received {board_id}",
                known.join(", ")
            ),
        )
    })?;
    let builds: BTreeSet<&str> = board.firmware.iter().map(|b| b.id.as_str()).collect();

    let kept_patches: BTreeSet<&str> = source
        .patches
        .values()
        .filter(|patch| runs_on(patch, &builds))
        .map(|patch| patch.id.as_str())
        .collect();
    let kept_findings: BTreeSet<&str> = source
        .findings
        .values()
        .filter(|finding| affects_any(finding, &builds))
        .map(|finding| finding.id.as_str())
        .collect();
    let kept_evidence: BTreeSet<&str> = source
        .evidence
        .values()
        .filter(|evidence| evidence.board == board_id)
        .map(|evidence| evidence.id.as_str())
        .collect();

    let mut records = Records::default();
    for id in &kept_patches {
        let patch = reduce_patch(&source.patches[*id], board_id, &builds, &kept_patches)?;
        if let Some(finding) = patch
            .findings
            .iter()
            .find(|finding| !kept_findings.contains(finding.as_str()))
        {
            return Err(invalid(format!(
                "patch {id}: findings: expected only findings that affect board {board_id} | received {finding}, which affects none of its builds"
            )));
        }
        records.patches.insert(patch.id.clone(), patch);
    }
    for id in &kept_findings {
        let finding = reduce_finding(
            &source.findings[*id],
            &builds,
            &kept_patches,
            &kept_evidence,
        );
        records.findings.insert(finding.id.clone(), finding);
    }
    for id in &kept_evidence {
        let evidence = &source.evidence[*id];
        if let Some(patch) = evidence
            .patches
            .iter()
            .find(|patch| !kept_patches.contains(patch.id.as_str()))
        {
            return Err(invalid(format!(
                "evidence {id}: patches: expected only patches with an applicable variant for board {board_id} | received {}",
                patch.id
            )));
        }
        records
            .evidence
            .insert(evidence.id.clone(), evidence.clone());
    }
    records.boards.insert(
        board_id.to_string(),
        reduce_board(board, &kept_patches, &kept_findings, &kept_evidence),
    );

    let dropped = Dropped {
        patches: left_out(source.patches.keys(), &kept_patches),
        findings: left_out(source.findings.keys(), &kept_findings),
        evidence: left_out(source.evidence.keys(), &kept_evidence),
    };
    Ok(Split { records, dropped })
}

/// Whether `patch` has an `applicable` variant for one of `builds`.
///
/// Example: a patch with only a `not-applicable` variant for the board's build is false.
fn runs_on(patch: &Patch, builds: &BTreeSet<&str>) -> bool {
    patch.variants.iter().any(|(build, variant)| {
        builds.contains(build.as_str()) && matches!(variant, Variant::Applicable(_))
    })
}

/// Whether `finding` affects one of `builds`.
fn affects_any(finding: &Finding, builds: &BTreeSet<&str>) -> bool {
    finding
        .affects
        .builds
        .iter()
        .any(|build| builds.contains(build.as_str()))
}

/// Ids in `all` that are not in `kept`.
fn left_out<'a>(all: impl Iterator<Item = &'a String>, kept: &BTreeSet<&str>) -> Vec<String> {
    all.filter(|id| !kept.contains(id.as_str()))
        .cloned()
        .collect()
}

/// Keep the entries of `ids` that are in `kept`, in order.
fn retain_kept(ids: &[String], kept: &BTreeSet<&str>) -> Vec<String> {
    ids.iter()
        .filter(|id| kept.contains(id.as_str()))
        .cloned()
        .collect()
}

/// Cut a kept patch to the board's builds and to the patches that stay.
///
/// Fails when the patch `requires` a patch that stays out.
fn reduce_patch(
    patch: &Patch,
    board_id: &str,
    builds: &BTreeSet<&str>,
    kept: &BTreeSet<&str>,
) -> Result<Patch> {
    if let Some(missing) = patch.requires.iter().find(|id| !kept.contains(id.as_str())) {
        return Err(invalid(format!(
            "patch {}: requires: expected patches with an applicable variant for board {board_id} | received {missing}, which has none",
            patch.id
        )));
    }
    let mut reduced = patch.clone();
    reduced
        .variants
        .retain(|build, _| builds.contains(build.as_str()));
    reduced.requires = retain_kept(&patch.requires, kept);
    reduced.supersedes = retain_kept(&patch.supersedes, kept);
    reduced.conflicts = retain_kept(&patch.conflicts, kept);
    Ok(reduced)
}

/// Cut a kept finding to the board's builds, patches and evidence.
fn reduce_finding(
    finding: &Finding,
    builds: &BTreeSet<&str>,
    kept_patches: &BTreeSet<&str>,
    kept_evidence: &BTreeSet<&str>,
) -> Finding {
    let mut reduced = finding.clone();
    reduced
        .affects
        .builds
        .retain(|build| builds.contains(build.as_str()));
    reduced.owner.references.retain(|reference| {
        reference
            .build
            .as_deref()
            .is_none_or(|build| builds.contains(build))
    });
    reduced.patches = retain_kept(&finding.patches, kept_patches);
    reduced.evidence = retain_kept(&finding.evidence, kept_evidence);
    if reduced.status == FindingStatus::FixedByPatch && reduced.patches.is_empty() {
        reduced.status = FindingStatus::Open;
    }
    reduced
}

/// Cut the board's record lists to the records that stay, keeping their order.
fn reduce_board(
    board: &Board,
    kept_patches: &BTreeSet<&str>,
    kept_findings: &BTreeSet<&str>,
    kept_evidence: &BTreeSet<&str>,
) -> Board {
    let mut reduced = board.clone();
    reduced.patches = retain_kept(&board.patches, kept_patches);
    reduced.findings = retain_kept(&board.findings, kept_findings);
    reduced.evidence = retain_kept(&board.evidence, kept_evidence);
    reduced
}

/// Evidence kept for a board, used by tests to read the reduced list.
#[cfg(test)]
fn evidence_ids(records: &Records) -> Vec<&str> {
    records.evidence.values().map(|e| e.id.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixtures::{board, evidence, finding, fixed_finding, patch};

    const A: &str = "build-a";
    const B: &str = "build-b";

    /// Two boards, `board-a` (build-a) and `board-b` (build-b); `S` runs on both,
    /// `PA` only on A (with a not-applicable B variant), `PB` only on B.
    fn two_boards() -> Records {
        let mut r = Records::default();
        r.boards.insert(
            "board-a".into(),
            board(
                "board-a",
                &[A],
                &["S", "PA", "PB"],
                &["F-S", "F-A", "F-B"],
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

    #[test]
    fn unknown_board_names_the_id_and_the_known_ids() {
        let error = split_board(&two_boards(), "board-z").unwrap_err();
        assert_eq!(error.code, Code::TargetNotFound);
        assert_eq!(
            error.message,
            "board: expected one of board-a, board-b | received board-z"
        );
    }

    #[test]
    fn patch_without_an_applicable_variant_is_dropped_with_its_board_entry() {
        let split = split_board(&two_boards(), "board-a").unwrap();
        assert_eq!(split.dropped.patches, ["PB"]);
        let kept: Vec<&str> = split.records.patches.keys().map(String::as_str).collect();
        assert_eq!(kept, ["PA", "S"]);
        assert_eq!(split.records.boards["board-a"].patches, ["S", "PA"]);
    }

    #[test]
    fn variants_are_cut_to_the_board_builds() {
        let split = split_board(&two_boards(), "board-a").unwrap();
        for patch in split.records.patches.values() {
            let builds: Vec<&str> = patch.variants.keys().map(String::as_str).collect();
            assert_eq!(builds, [A], "(patch {} variants)", patch.id);
        }
    }

    #[test]
    fn requires_on_a_dropped_patch_fails_naming_both() {
        let mut records = two_boards();
        records.patches.get_mut("PA").unwrap().requires = vec!["PB".into()];
        let error = split_board(&records, "board-a").unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert_eq!(
            error.message,
            "patch PA: requires: expected patches with an applicable variant for board board-a | received PB, which has none"
        );
    }

    #[test]
    fn supersedes_and_conflicts_are_cut_to_kept_patches() {
        let mut records = two_boards();
        let pa = records.patches.get_mut("PA").unwrap();
        pa.supersedes = vec!["S".into(), "PB".into()];
        pa.conflicts = vec!["PB".into()];
        let split = split_board(&records, "board-a").unwrap();
        let pa = &split.records.patches["PA"];
        assert_eq!(pa.supersedes, ["S"]);
        assert!(pa.conflicts.is_empty());
    }

    #[test]
    fn requires_between_kept_patches_survive() {
        let mut records = two_boards();
        records.patches.get_mut("PA").unwrap().requires = vec!["S".into()];
        let split = split_board(&records, "board-a").unwrap();
        assert_eq!(split.records.patches["PA"].requires, ["S"]);
    }

    #[test]
    fn kept_patch_naming_a_dropped_finding_fails_naming_both() {
        let mut records = two_boards();
        records.patches.get_mut("S").unwrap().findings = vec!["F-B".into()];
        let error = split_board(&records, "board-a").unwrap_err();
        assert_eq!(
            error.message,
            "patch S: findings: expected only findings that affect board board-a | received F-B, which affects none of its builds"
        );
    }

    #[test]
    fn finding_for_another_build_is_dropped_and_shared_ones_are_cut() {
        let split = split_board(&two_boards(), "board-a").unwrap();
        assert_eq!(split.dropped.findings, ["F-B"]);
        let shared = &split.records.findings["F-S"];
        assert_eq!(shared.affects.builds, [A]);
        assert_eq!(shared.affects.label, "Both");
        let refs: Vec<_> = shared
            .owner
            .references
            .iter()
            .map(|r| r.build.as_deref())
            .collect();
        assert_eq!(refs, [Some(A)], "(foreign code reference dropped)");
    }

    #[test]
    fn code_reference_without_a_build_stays() {
        let mut records = two_boards();
        records
            .findings
            .get_mut("F-S")
            .unwrap()
            .owner
            .references
            .push(
                serde_json::from_value(serde_json::json!({"module": "Mod", "location": "any"}))
                    .unwrap(),
            );
        let split = split_board(&records, "board-a").unwrap();
        assert_eq!(split.records.findings["F-S"].owner.references.len(), 2);
    }

    #[test]
    fn fixed_finding_left_without_a_patch_becomes_open() {
        let mut records = two_boards();
        // F-X is fixed only by PB, which board-a drops; board-a still sees the defect.
        records
            .findings
            .insert("F-X".into(), fixed_finding("F-X", &[A, B], &["PB"]));
        let split = split_board(&records, "board-a").unwrap();
        let reduced = &split.records.findings["F-X"];
        assert_eq!(reduced.status, FindingStatus::Open);
        assert!(reduced.patches.is_empty());
        assert_eq!(
            split.records.findings["F-S"].status,
            FindingStatus::FixedByPatch
        );
        assert_eq!(split.records.findings["F-S"].patches, ["S"]);
    }

    #[test]
    fn finding_evidence_is_cut_to_kept_evidence() {
        let mut records = two_boards();
        records.findings.get_mut("F-S").unwrap().evidence = vec!["E-A".into(), "E-B".into()];
        let split = split_board(&records, "board-a").unwrap();
        assert_eq!(split.records.findings["F-S"].evidence, ["E-A"]);
    }

    #[test]
    fn evidence_of_another_board_is_dropped() {
        let split = split_board(&two_boards(), "board-a").unwrap();
        assert_eq!(evidence_ids(&split.records), ["E-A"]);
        assert_eq!(split.dropped.evidence, ["E-B"]);
        assert_eq!(split.records.boards["board-a"].evidence, ["E-A"]);
    }

    #[test]
    fn kept_evidence_naming_a_dropped_patch_fails() {
        let mut records = two_boards();
        records
            .evidence
            .insert("E-A".into(), evidence("E-A", "board-a", A, &["PB"]));
        let error = split_board(&records, "board-a").unwrap_err();
        assert_eq!(
            error.message,
            "evidence E-A: patches: expected only patches with an applicable variant for board board-a | received PB"
        );
    }

    #[test]
    fn board_lists_keep_their_order() {
        let split = split_board(&two_boards(), "board-b").unwrap();
        // board-b lists S, PB, PA; PA has only a not-applicable B variant.
        assert_eq!(split.records.boards["board-b"].patches, ["S", "PB"]);
        assert_eq!(split.records.boards["board-b"].findings, ["F-S", "F-B"]);
    }

    #[test]
    fn split_output_has_exactly_one_board() {
        let split = split_board(&two_boards(), "board-b").unwrap();
        let boards: Vec<&str> = split.records.boards.keys().map(String::as_str).collect();
        assert_eq!(boards, ["board-b"]);
    }

    #[test]
    fn runs_on_needs_an_applicable_variant_for_a_board_build() {
        let builds = BTreeSet::from([A]);
        assert!(runs_on(&patch("P", &[(A, true)]), &builds));
        assert!(!runs_on(&patch("P", &[(A, false), (B, true)]), &builds));
        assert!(!runs_on(&patch("P", &[(B, true)]), &builds));
    }

    #[test]
    fn affects_any_needs_one_shared_build() {
        let builds = BTreeSet::from([A]);
        assert!(affects_any(&finding("F", &[A, B]), &builds));
        assert!(!affects_any(&finding("F", &[B]), &builds));
    }

    #[test]
    fn retain_kept_and_left_out_split_ids_both_ways() {
        let kept = BTreeSet::from(["b", "d"]);
        let ids: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        assert_eq!(retain_kept(&ids, &kept), ["b", "d"]);
        assert_eq!(left_out(ids.iter(), &kept), ["a", "c"]);
    }
}
