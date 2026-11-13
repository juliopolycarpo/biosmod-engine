//! The typed documents of a catalog, without its index or file bytes.
//!
//! `split` and `merge` work on these: documents in, documents out, no I/O.

use super::{Board, Catalog, Evidence, Finding, Patch};
use std::collections::BTreeMap;

/// Boards, patches, findings and evidence by id.
#[derive(Debug, Clone, Default)]
pub struct Records {
    pub boards: BTreeMap<String, Board>,
    pub patches: BTreeMap<String, Patch>,
    pub findings: BTreeMap<String, Finding>,
    pub evidence: BTreeMap<String, Evidence>,
}

impl Records {
    /// Copy the documents of a loaded catalog.
    ///
    /// Example: `let records = Records::of(&catalog);`
    pub fn of(catalog: &Catalog) -> Records {
        Records {
            boards: catalog.boards.clone(),
            patches: catalog.patches.clone(),
            findings: catalog.findings.clone(),
            evidence: catalog.evidence.clone(),
        }
    }

    /// Whether a board, patch, finding or evidence record has this id.
    ///
    /// Example: with patch `A02`, `records.has_record("A02")` is true.
    pub fn has_record(&self, id: &str) -> bool {
        self.boards.contains_key(id)
            || self.patches.contains_key(id)
            || self.findings.contains_key(id)
            || self.evidence.contains_key(id)
    }

    /// Whether the provenance file at `path` belongs to one of these records.
    ///
    /// A provenance file belongs to the record named by the first path
    /// component below `provenance/`.
    ///
    /// Example: `provenance/A02/note.md` goes with the board, patch, finding or evidence `A02`.
    pub fn keeps_provenance(&self, path: &str) -> bool {
        provenance_owner(path).is_some_and(|id| self.has_record(id))
    }
}

/// The record id a provenance path names: its first component below `provenance/`.
///
/// A file directly in `provenance/` has no owner, because its first component is a file name.
///
/// Example: `provenance_owner("provenance/A02/x.asm") == Some("A02")`.
pub fn provenance_owner(path: &str) -> Option<&str> {
    let (owner, rest) = path.strip_prefix("provenance/")?.split_once('/')?;
    (!owner.is_empty() && !rest.is_empty()).then_some(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixtures;

    #[test]
    fn provenance_owner_is_the_first_directory_below_provenance() {
        assert_eq!(
            provenance_owner("provenance/MRC-BREADCRUMBS/mrc.asm"),
            Some("MRC-BREADCRUMBS")
        );
        assert_eq!(provenance_owner("provenance/A/b/c.txt"), Some("A"));
    }

    #[test]
    fn provenance_owner_is_absent_for_loose_files_and_other_directories() {
        for path in ["provenance/loose.txt", "patches/A.json", "provenance/", ""] {
            assert_eq!(provenance_owner(path), None, "{path:?}");
        }
    }

    #[test]
    fn keeps_provenance_matches_board_patch_finding_and_evidence_ids() {
        let mut records = Records::default();
        records
            .patches
            .insert("P1".into(), fixtures::patch("P1", &[("build-a", true)]));
        records
            .findings
            .insert("F1".into(), fixtures::finding("F1", &["build-a"]));
        records.boards.insert(
            "bd".into(),
            fixtures::board("bd", &["build-a"], &[], &[], &[]),
        );
        records
            .evidence
            .insert("E1".into(), fixtures::evidence("E1", "bd", "build-a", &[]));
        assert!(records.keeps_provenance("provenance/P1/a.asm"));
        assert!(records.keeps_provenance("provenance/bd/a.md"));
        assert!(records.keeps_provenance("provenance/E1/a.md"));
        assert!(records.keeps_provenance("provenance/F1/a.md"));
        assert!(!records.keeps_provenance("provenance/P2/a.asm"));
        assert!(!records.keeps_provenance("provenance/P1"));
    }
}
