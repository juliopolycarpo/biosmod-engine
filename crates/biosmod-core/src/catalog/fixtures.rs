//! Small synthetic documents for the `split` and `merge` tests.

use super::{Board, Evidence, Finding, Patch};
use serde_json::json;

/// A patch with one variant per `(build, applicable)` pair.
pub(crate) fn patch(id: &str, variants: &[(&str, bool)]) -> Patch {
    let variants: serde_json::Map<String, serde_json::Value> = variants
        .iter()
        .map(|(build, applicable)| {
            let variant = if *applicable {
                json!({"status": "applicable", "components": []})
            } else {
                json!({"status": "not-applicable", "reason": "other board"})
            };
            (build.to_string(), variant)
        })
        .collect();
    serde_json::from_value(json!({
        "schema": "bme.patch/1", "id": id, "version": "1.0.0", "title": format!("Patch {id}"),
        "class": "correction", "tier": "recommended", "findings": [],
        "confidence": {"findings": {}, "offline_fix": "C0", "physical_fix": "C3"},
        "limits": "none", "variants": variants,
    }))
    .expect("fixture patch parses")
}

/// An open finding that affects `builds`, with one code reference per build.
pub(crate) fn finding(id: &str, builds: &[&str]) -> Finding {
    let references: Vec<_> = builds
        .iter()
        .map(|b| json!({"build": b, "module": "Mod", "location": format!("{b}+0x10")}))
        .collect();
    serde_json::from_value(json!({
        "schema": "bme.finding/1", "id": id, "title": format!("Finding {id}"), "priority": "P2",
        "status": "open", "affects": {"label": "Both", "builds": builds},
        "owner": {"description": "owner", "references": references},
        "confidence": {"finding": {"grade": "C0"}},
        "description": "defect", "remediation": "none",
    }))
    .expect("fixture finding parses")
}

/// A finding fixed by `patches`: status `fixed-by-patch` and the patch ids listed.
pub(crate) fn fixed_finding(id: &str, builds: &[&str], patches: &[&str]) -> Finding {
    let mut finding = finding(id, builds);
    finding.status = super::FindingStatus::FixedByPatch;
    finding.patches = patches.iter().map(|p| p.to_string()).collect();
    finding
}

/// A board that ships `builds` and lists the given records.
pub(crate) fn board(
    id: &str,
    builds: &[&str],
    patches: &[&str],
    findings: &[&str],
    evidence: &[&str],
) -> Board {
    let firmware: Vec<_> = builds
        .iter()
        .map(|b| json!({"id": b, "title": format!("Build {b}")}))
        .collect();
    serde_json::from_value(json!({
        "schema": "bme.board/1", "id": id, "vendor": "Acme", "model": "X99",
        "revision": {"status": "observed"}, "firmware": firmware,
        "patches": patches, "findings": findings, "evidence": evidence,
    }))
    .expect("fixture board parses")
}

/// An observation on `board` that names `patches` at version 1.0.0.
pub(crate) fn evidence(id: &str, board: &str, firmware: &str, patches: &[&str]) -> Evidence {
    let patches: Vec<_> = patches
        .iter()
        .map(|p| json!({"id": p, "version": "1.0.0"}))
        .collect();
    serde_json::from_value(json!({
        "schema": "bme.evidence/1", "id": id, "kind": "hardware-observation",
        "date": "2026-11-13", "title": format!("Evidence {id}"), "board": board,
        "firmware": firmware, "patches": patches, "observations": [], "limits": "one boot",
    }))
    .expect("fixture evidence parses")
}
