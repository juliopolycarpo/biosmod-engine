//! Compare two parsed images module by module.
//!
//! Leaf sections of top-level FFS files are paired by file GUID and leaf kind.
//! When several leaves share a GUID and kind (one file with two PE32 sections,
//! or a GUID repeated across volumes), the n-th leaf of A in image order pairs
//! with the n-th leaf of B; extra leaves on either side are listed as present
//! in one image only. Each pair is classified as byte-identical, identical
//! after relocation normalization, or different.
//!
//! Rebased PE bytes exist for the report only ([`crate::firmware::pe::RebasedForReport`]
//! has no accessor outside the crate), so a comparison can never feed `patch` or `replace`.
//!
//! Example: `let report = compare::compare_images(&a, &b); println!("{}", report.summary.different);`

pub mod functions;

use crate::firmware::pe::{self, RebasedForReport};
use crate::firmware::{FILE_PAD, Image, SECTION_PE32, SECTION_TE, SECTION_UI};
use crate::util::{Guid, sha256_hex};
use serde::Serialize;
use std::collections::BTreeMap;

/// Differing runs closer than this many bytes are reported as one range.
pub const RANGE_MERGE_GAP: usize = 8;
/// Most changed ranges listed per pair; the count of changed bytes stays exact.
pub const MAX_RANGES: usize = 64;

/// How a pair relates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Same bytes.
    Identical,
    /// Same bytes once both PE/TE images are rebased to image base zero.
    IdenticalAfterNormalization,
    /// Different bytes, even after normalization when it applies.
    Different,
}

/// A half-open byte range `[start, end)` inside a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

/// What the changed ranges were measured on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    /// The leaf bytes as stored.
    Raw,
    /// The leaf bytes after both images were rebased to image base zero.
    Normalized,
}

/// A PE section (or the headers) that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionChange {
    pub name: String,
    pub status: SectionStatus,
    pub size_a: Option<usize>,
    pub size_b: Option<usize>,
}

/// How one section differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionStatus {
    Changed,
    OnlyInA,
    OnlyInB,
}

/// One leaf on one side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeafSide {
    pub size: usize,
    pub sha256: String,
    /// Section path inside the file (empty for a file without sections).
    pub path: Vec<usize>,
    /// Offset of the FFS file in its image.
    pub file_offset: usize,
}

/// What base removal did to a pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Normalization {
    pub image_base_a: u64,
    pub image_base_b: u64,
    pub relocations_a: usize,
    pub relocations_b: usize,
    /// SHA-256 of A's rebased bytes (report value; the bytes are never exposed).
    pub sha256_a: String,
    pub sha256_b: String,
}

/// A leaf present in both images.
#[derive(Debug, Clone, Serialize)]
pub struct Pair {
    pub guid: Guid,
    pub leaf: String,
    /// Position among leaves sharing this GUID and kind.
    pub ordinal: usize,
    pub name: Option<String>,
    pub a: LeafSide,
    pub b: LeafSide,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalization: Option<Normalization>,
    /// Why normalization did not apply to a PE-kind pair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalization_error: Option<String>,
    /// Number of differing bytes (plus the length difference).
    pub changed_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges_basis: Option<Basis>,
    pub changed_ranges: Vec<ByteRange>,
    pub ranges_truncated: bool,
    pub sections: Vec<SectionChange>,
}

/// A leaf present in one image only.
#[derive(Debug, Clone, Serialize)]
pub struct Lone {
    pub guid: Guid,
    pub leaf: String,
    pub ordinal: usize,
    pub name: Option<String>,
    #[serde(flatten)]
    pub side: LeafSide,
}

/// Counts over a comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub paired: usize,
    pub identical: usize,
    pub identical_after_normalization: usize,
    pub different: usize,
    pub only_in_a: usize,
    pub only_in_b: usize,
}

/// The full report.
#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub summary: Summary,
    pub pairs: Vec<Pair>,
    pub only_in_a: Vec<Lone>,
    pub only_in_b: Vec<Lone>,
}

/// One comparable leaf, borrowed from its image.
struct Item<'a> {
    guid: Guid,
    leaf: String,
    name: Option<String>,
    side: LeafSide,
    body: &'a [u8],
}

/// Name a section kind the way `extract --leaf` and the docs do.
///
/// Example: `assert_eq!(leaf_label(0x12), "pe32");`
pub fn leaf_label(kind: u8) -> String {
    match kind {
        SECTION_PE32 | SECTION_TE => "pe32".into(),
        0x11 => "pic".into(),
        0x13 => "dxe-depex".into(),
        0x14 => "version".into(),
        0x19 => "raw".into(),
        0x1B => "pei-depex".into(),
        0x1C => "mm-depex".into(),
        other => format!("section-{other:#04x}"),
    }
}

/// Every comparable leaf of an image in image order, with ordinals per (GUID, kind).
fn items(image: &Image) -> BTreeMap<(Guid, String), Vec<Item<'_>>> {
    let mut found: Vec<(usize, usize, Vec<usize>, Item<'_>)> = Vec::new();
    for (v, volume) in image.volumes.iter().enumerate() {
        for (f, file) in volume.files.iter().enumerate() {
            if file.kind == FILE_PAD || file.opaque {
                continue;
            }
            let name = image.ui_name(v, f);
            if file.sections.is_empty() {
                found.push((
                    v,
                    f,
                    Vec::new(),
                    Item {
                        guid: file.guid,
                        leaf: "file".into(),
                        name,
                        side: side(file.body(&image.bytes), &[], file.offset),
                        body: file.body(&image.bytes),
                    },
                ));
            }
        }
    }
    for (guid, leaves) in &image.leaves {
        for leaf in leaves {
            let (section, stream) = image.section(leaf);
            if section.kind == SECTION_UI {
                continue;
            }
            let body = section.body(stream);
            let file = image.file(leaf);
            found.push((
                leaf.volume,
                leaf.file,
                leaf.path.clone(),
                Item {
                    guid: *guid,
                    leaf: leaf_label(section.kind),
                    name: image.ui_name(leaf.volume, leaf.file),
                    side: side(body, &leaf.path, file.offset),
                    body,
                },
            ));
        }
    }
    found.sort_by(|x, y| (x.0, x.1, &x.2).cmp(&(y.0, y.1, &y.2)));
    let mut grouped: BTreeMap<(Guid, String), Vec<Item<'_>>> = BTreeMap::new();
    for (_, _, _, item) in found {
        grouped
            .entry((item.guid, item.leaf.clone()))
            .or_default()
            .push(item);
    }
    grouped
}

fn side(body: &[u8], path: &[usize], file_offset: usize) -> LeafSide {
    LeafSide {
        size: body.len(),
        sha256: sha256_hex(body),
        path: path.to_vec(),
        file_offset,
    }
}

/// Differing runs between two byte strings: exact count, merged ranges, and whether the list was cut.
///
/// A length difference counts as changed bytes and shows as a trailing range.
///
/// Example: `let (count, ranges, _) = changed_ranges(&[1, 2, 3], &[1, 9, 3]); assert_eq!((count, ranges[0].start), (1, 1));`
pub fn changed_ranges(a: &[u8], b: &[u8]) -> (usize, Vec<ByteRange>, bool) {
    let common = a.len().min(b.len());
    let mut ranges: Vec<ByteRange> = Vec::new();
    let mut count = 0;
    for index in (0..common).filter(|i| a[*i] != b[*i]) {
        count += 1;
        match ranges.last_mut() {
            Some(last) if index - last.end < RANGE_MERGE_GAP => last.end = index + 1,
            _ => ranges.push(ByteRange {
                start: index,
                end: index + 1,
            }),
        }
    }
    if a.len() != b.len() {
        count += a.len().abs_diff(b.len());
        ranges.push(ByteRange {
            start: common,
            end: a.len().max(b.len()),
        });
    }
    let truncated = ranges.len() > MAX_RANGES;
    ranges.truncate(MAX_RANGES);
    (count, ranges, truncated)
}

/// Section-level differences between two PE/TE byte strings of the same basis.
fn section_changes(a: &[u8], b: &[u8]) -> Vec<SectionChange> {
    let (Ok(spans_a), Ok(spans_b)) = (pe::section_spans(a), pe::section_spans(b)) else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    for span in &spans_a {
        let data_a = &a[span.start..span.end];
        match spans_b.iter().find(|other| other.name == span.name) {
            Some(other) => {
                let data_b = &b[other.start..other.end];
                if data_a != data_b {
                    changes.push(SectionChange {
                        name: span.name.clone(),
                        status: SectionStatus::Changed,
                        size_a: Some(data_a.len()),
                        size_b: Some(data_b.len()),
                    });
                }
            }
            None => changes.push(SectionChange {
                name: span.name.clone(),
                status: SectionStatus::OnlyInA,
                size_a: Some(data_a.len()),
                size_b: None,
            }),
        }
    }
    for span in &spans_b {
        if !spans_a.iter().any(|other| other.name == span.name) {
            changes.push(SectionChange {
                name: span.name.clone(),
                status: SectionStatus::OnlyInB,
                size_a: None,
                size_b: Some(span.end - span.start),
            });
        }
    }
    changes
}

/// Compare one pair of leaves.
fn compare_pair(ordinal: usize, a: Item<'_>, b: Item<'_>) -> Pair {
    let mut pair = Pair {
        guid: a.guid,
        leaf: a.leaf.clone(),
        ordinal,
        name: a.name.clone().or_else(|| b.name.clone()),
        a: a.side.clone(),
        b: b.side.clone(),
        verdict: Verdict::Identical,
        normalization: None,
        normalization_error: None,
        changed_bytes: 0,
        ranges_basis: None,
        changed_ranges: Vec::new(),
        ranges_truncated: false,
        sections: Vec::new(),
    };
    if a.body == b.body {
        return pair;
    }
    pair.verdict = Verdict::Different;
    let rebased: Option<(RebasedForReport, RebasedForReport)> = if a.leaf == "pe32" {
        match (pe::rebase_for_report(a.body), pe::rebase_for_report(b.body)) {
            (Ok(ra), Ok(rb)) => Some((ra, rb)),
            (Err(e), _) => {
                pair.normalization_error = Some(format!("A: {e}"));
                None
            }
            (_, Err(e)) => {
                pair.normalization_error = Some(format!("B: {e}"));
                None
            }
        }
    } else {
        None
    };
    let (basis, bytes_a, bytes_b) = match &rebased {
        Some((ra, rb)) => {
            pair.normalization = Some(Normalization {
                image_base_a: ra.image_base,
                image_base_b: rb.image_base,
                relocations_a: ra.relocations,
                relocations_b: rb.relocations,
                sha256_a: ra.sha256_hex(),
                sha256_b: rb.sha256_hex(),
            });
            if ra.report_bytes() == rb.report_bytes() {
                pair.verdict = Verdict::IdenticalAfterNormalization;
                return pair;
            }
            (Basis::Normalized, ra.report_bytes(), rb.report_bytes())
        }
        None => (Basis::Raw, a.body, b.body),
    };
    let (count, ranges, truncated) = changed_ranges(bytes_a, bytes_b);
    pair.changed_bytes = count;
    pair.changed_ranges = ranges;
    pair.ranges_truncated = truncated;
    pair.ranges_basis = Some(basis);
    if a.leaf == "pe32" {
        pair.sections = section_changes(bytes_a, bytes_b);
    }
    pair
}

fn lone(ordinal: usize, item: Item<'_>) -> Lone {
    Lone {
        guid: item.guid,
        leaf: item.leaf,
        ordinal,
        name: item.name,
        side: item.side,
    }
}

/// Compare two images leaf by leaf.
///
/// Example: `let report = compare_images(&a, &b); assert_eq!(report.summary.paired, report.pairs.len());`
pub fn compare_images(a: &Image, b: &Image) -> Comparison {
    let mut left = items(a);
    let mut right = items(b);
    let keys: std::collections::BTreeSet<(Guid, String)> =
        left.keys().chain(right.keys()).cloned().collect();
    let mut report = Comparison {
        summary: Summary::default(),
        pairs: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
    };
    for key in keys {
        let mut xs = left.remove(&key).unwrap_or_default().into_iter();
        let mut ys = right.remove(&key).unwrap_or_default().into_iter();
        let mut ordinal = 0;
        loop {
            match (xs.next(), ys.next()) {
                (Some(x), Some(y)) => report.pairs.push(compare_pair(ordinal, x, y)),
                (Some(x), None) => report.only_in_a.push(lone(ordinal, x)),
                (None, Some(y)) => report.only_in_b.push(lone(ordinal, y)),
                (None, None) => break,
            }
            ordinal += 1;
        }
    }
    let s = &mut report.summary;
    s.paired = report.pairs.len();
    for pair in &report.pairs {
        match pair.verdict {
            Verdict::Identical => s.identical += 1,
            Verdict::IdenticalAfterNormalization => s.identical_after_normalization += 1,
            Verdict::Different => s.different += 1,
        }
    }
    s.only_in_a = report.only_in_a.len();
    s.only_in_b = report.only_in_b.len();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::{SECTION_COMPRESSION, SECTION_RAW};
    use crate::synthetic::{PEIM_GUID, TABLE_GUID, ffs, image_of_files, relocatable_pe, section};

    const OTHER: Guid = Guid::constant("01010101-0202-0303-0404-050505050505");

    fn parse(files: Vec<Vec<u8>>) -> Image {
        Image::parse(image_of_files(&files)).expect("synthetic image parses")
    }

    fn peim(guid: Guid, pe: &[u8]) -> Vec<u8> {
        ffs(guid, 0x06, &section(0x10, pe), 0)
    }

    fn pair_of(report: &Comparison, guid: Guid) -> &Pair {
        report
            .pairs
            .iter()
            .find(|p| p.guid == guid)
            .unwrap_or_else(|| panic!("pair {guid}: expected present | received none"))
    }

    #[test]
    fn identical_bytes_are_identical() {
        let pe = relocatable_pe(0x1000_0000, b"same");
        let a = parse(vec![peim(PEIM_GUID, &pe)]);
        let b = parse(vec![peim(PEIM_GUID, &pe)]);
        let report = compare_images(&a, &b);
        assert_eq!(pair_of(&report, PEIM_GUID).verdict, Verdict::Identical);
        assert_eq!(report.summary.identical, 1);
    }

    #[test]
    fn rebased_copy_is_identical_after_normalization() {
        let a = parse(vec![peim(PEIM_GUID, &relocatable_pe(0x1000_0000, b"same"))]);
        let b = parse(vec![peim(PEIM_GUID, &relocatable_pe(0x2000_0000, b"same"))]);
        let report = compare_images(&a, &b);
        let pair = pair_of(&report, PEIM_GUID);
        assert_eq!(
            pair.verdict,
            Verdict::IdenticalAfterNormalization,
            "{pair:?}"
        );
        let note = pair.normalization.as_ref().expect("normalization recorded");
        assert_eq!(
            (note.image_base_a, note.image_base_b, note.relocations_a),
            (0x1000_0000, 0x2000_0000, 1)
        );
        assert_eq!(note.sha256_a, note.sha256_b);
    }

    #[test]
    fn code_change_stays_different_after_normalization() {
        let a = parse(vec![peim(PEIM_GUID, &relocatable_pe(0x1000_0000, b"aaaa"))]);
        let b = parse(vec![peim(PEIM_GUID, &relocatable_pe(0x2000_0000, b"abaa"))]);
        let report = compare_images(&a, &b);
        let pair = pair_of(&report, PEIM_GUID);
        assert_eq!(pair.verdict, Verdict::Different);
        assert_eq!(pair.ranges_basis, Some(Basis::Normalized));
        assert_eq!(pair.changed_bytes, 1);
        assert_eq!(
            pair.changed_ranges,
            vec![ByteRange {
                start: 0x221,
                end: 0x222
            }]
        );
        assert_eq!(
            pair.sections,
            vec![SectionChange {
                name: ".text".into(),
                status: SectionStatus::Changed,
                size_a: Some(0x200),
                size_b: Some(0x200),
            }]
        );
    }

    #[test]
    fn files_in_one_image_are_listed_once() {
        let pe = relocatable_pe(0x1000_0000, b"x");
        let a = parse(vec![peim(PEIM_GUID, &pe), peim(OTHER, &pe)]);
        let b = parse(vec![peim(PEIM_GUID, &pe)]);
        let report = compare_images(&a, &b);
        assert_eq!(report.only_in_a.len(), 1);
        assert_eq!(report.only_in_a[0].guid, OTHER);
        assert!(report.only_in_b.is_empty());
        let reverse = compare_images(&b, &a);
        assert_eq!(reverse.only_in_b[0].guid, OTHER);
    }

    #[test]
    fn duplicate_guid_pairs_by_image_order_and_lists_the_surplus() {
        let first = relocatable_pe(0x1000_0000, b"one");
        let second = relocatable_pe(0x1000_0000, b"two");
        let a = parse(vec![peim(PEIM_GUID, &first), peim(PEIM_GUID, &second)]);
        let b = parse(vec![peim(PEIM_GUID, &first)]);
        let report = compare_images(&a, &b);
        assert_eq!(report.pairs.len(), 1);
        assert_eq!(report.pairs[0].ordinal, 0);
        assert_eq!(report.pairs[0].verdict, Verdict::Identical);
        assert_eq!(report.only_in_a.len(), 1);
        assert_eq!(report.only_in_a[0].ordinal, 1);
    }

    #[test]
    fn non_pe_leaf_compares_raw_bytes() {
        let table = |tail: u8| ffs(TABLE_GUID, 0x02, &section(0x19, &[1, 2, tail, 4]), 0);
        let a = parse(vec![table(3)]);
        let b = parse(vec![table(9)]);
        let report = compare_images(&a, &b);
        let pair = pair_of(&report, TABLE_GUID);
        assert_eq!(pair.leaf, "raw");
        assert_eq!(pair.verdict, Verdict::Different);
        assert_eq!(pair.ranges_basis, Some(Basis::Raw));
        assert_eq!(pair.changed_ranges, vec![ByteRange { start: 2, end: 3 }]);
        assert!(pair.normalization.is_none() && pair.sections.is_empty());
    }

    #[test]
    fn malformed_pe_falls_back_to_raw_and_says_why() {
        let a = parse(vec![peim(PEIM_GUID, &[b'M', b'Z', 1, 2, 3, 4])]);
        let b = parse(vec![peim(PEIM_GUID, &[b'M', b'Z', 1, 2, 3, 5])]);
        let report = compare_images(&a, &b);
        let pair = pair_of(&report, PEIM_GUID);
        assert_eq!(pair.verdict, Verdict::Different);
        assert_eq!(pair.ranges_basis, Some(Basis::Raw));
        assert!(
            pair.normalization_error
                .as_deref()
                .unwrap_or("")
                .starts_with("A: "),
            "{pair:?}"
        );
    }

    #[test]
    fn changed_ranges_merge_close_runs_and_count_length_difference() {
        let a = [0u8; 40];
        let mut b = [0u8; 40];
        b[2] = 1;
        b[5] = 1;
        b[30] = 1;
        let (count, ranges, truncated) = changed_ranges(&a, &b);
        assert_eq!(count, 3);
        assert_eq!(
            ranges,
            vec![
                ByteRange { start: 2, end: 6 },
                ByteRange { start: 30, end: 31 }
            ]
        );
        assert!(!truncated);
        let (count, ranges, _) = changed_ranges(&a[..4], &b[..6]);
        assert_eq!(count, 3);
        assert_eq!(ranges.last(), Some(&ByteRange { start: 4, end: 6 }));
    }

    #[test]
    fn changed_ranges_cap_the_list_not_the_count() {
        let a = vec![0u8; 2000];
        let b: Vec<u8> = (0..2000).map(|i| u8::from(i % 20 == 0)).collect();
        let (count, ranges, truncated) = changed_ranges(&a, &b);
        assert_eq!(count, 100);
        assert_eq!(ranges.len(), MAX_RANGES);
        assert!(truncated);
    }

    #[test]
    fn leaf_labels_name_pe_kinds_together() {
        assert_eq!(leaf_label(SECTION_PE32), "pe32");
        assert_eq!(leaf_label(SECTION_TE), "pe32");
        assert_eq!(leaf_label(SECTION_RAW), "raw");
        assert_eq!(leaf_label(SECTION_COMPRESSION), "section-0x01");
    }
}
