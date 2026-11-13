//! Compare the ACPI tables of two inputs object by object.
//!
//! An input is a firmware image, a bare `.aml` table or the files of a live capture
//! (`tables_from_capture`). DSDT and SSDT tables
//! are found in an image by scanning every leaf for a table header whose
//! length fits and whose checksum sums to zero (a DSDT that opens a RAW leaf
//! is accepted without the checksum, as `extract --leaf acpi-table` does).
//! Tables pair by signature and OEM table ID; several tables with the same
//! pair match in image order. Within a pair, objects pair by full path and
//! each is reported as added, removed or changed. Methods are compared by body
//! hash, names and regions by the hash of their term.
//!
//! Example: `let report = compare_tables(&tables_from_input(a_bytes)?, &tables_from_input(b_bytes)?);`

use super::items;
use crate::aml::{self, AmlObject, ObjectKind, TableHeader};
use crate::error::{Code, Error, Result};
use crate::firmware::Image;
use crate::util::sha256_hex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Signatures whose AML this module walks.
const AML_SIGNATURES: [&[u8; 4]; 2] = [b"DSDT", b"SSDT"];

/// An ACPI table found in an input.
#[derive(Debug, Clone)]
pub struct FoundTable {
    pub header: TableHeader,
    /// Where it came from: `file` for a bare table, else leaf and offset.
    pub source: String,
    bytes: Vec<u8>,
}

impl FoundTable {
    /// Build a table from bytes whose header is valid; `source` names its origin.
    ///
    /// Example: `let table = FoundTable::new(dsdt_bytes, "A.aml".into())?;`
    pub fn new(bytes: Vec<u8>, source: String) -> Result<FoundTable> {
        let header = aml::parse_header(&bytes)?;
        let bytes = bytes[..header.length as usize].to_vec();
        Ok(FoundTable {
            header,
            source,
            bytes,
        })
    }

    /// The table bytes. A found table is a read-only copy: it is never written back to an image.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the whole table.
    pub fn sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }
}

/// Every DSDT and SSDT in an image, in leaf order.
///
/// Example: `let tables = tables_in_image(&image); println!("{} tables", tables.len());`
pub fn tables_in_image(image: &Image) -> Vec<FoundTable> {
    let mut found = Vec::new();
    for ((guid, leaf), group) in items(image) {
        for (ordinal, item) in group.iter().enumerate() {
            let body = item.body;
            let mut at = 0;
            while at + aml::HEADER_LEN <= body.len() {
                let candidate = &body[at..];
                if !AML_SIGNATURES.iter().any(|s| candidate.starts_with(*s)) {
                    at += 1;
                    continue;
                }
                let accepted = aml::parse_header(candidate)
                    .ok()
                    .filter(|h| h.checksum_ok || (at == 0 && leaf == "raw"));
                match accepted {
                    Some(header) => {
                        let length = header.length as usize;
                        found.push(FoundTable {
                            source: format!("{guid} {leaf}#{ordinal} offset {at:#x}"),
                            bytes: candidate[..length].to_vec(),
                            header,
                        });
                        at += length;
                    }
                    None => at += 1,
                }
            }
        }
    }
    found
}

/// The tables of one input: a bare table, or every DSDT and SSDT of a firmware image.
///
/// A bare table is recognized by its signature and a declared length equal to the file size.
/// Anything else must parse as an image; the error names both readings.
///
/// Example: `let tables = tables_from_input(std::fs::read("DSDT.aml")?)?;`
pub fn tables_from_input(bytes: Vec<u8>) -> Result<Vec<FoundTable>> {
    let bare = AML_SIGNATURES.iter().any(|s| bytes.starts_with(*s))
        && aml::parse_header(&bytes).is_ok_and(|h| h.length as usize == bytes.len());
    if bare {
        return Ok(vec![FoundTable::new(bytes, "file".into())?]);
    }
    let image = Image::parse(bytes).map_err(|e| {
        Error::new(
            Code::FormatUnsupported,
            format!(
                "input: expected a DSDT/SSDT table whose length equals the file size, or a firmware image | received neither ({e})"
            ),
        )
    })?;
    Ok(tables_in_image(&image))
}

/// What `tables_from_capture` found in a `bme diag acpi capture` directory.
#[derive(Debug, Clone)]
pub struct CaptureTables {
    /// Every DSDT and SSDT, in the order the files were given.
    pub tables: Vec<FoundTable>,
    /// Captured table files that are not DSDT or SSDT (FACP, BERT, ...), by relative path.
    pub skipped: Vec<String>,
}

/// The DSDT and SSDT tables of a live capture, from `(relative path, bytes)` of each file under
/// `acpi/tables/` (sysfs names such as `DSDT`, `dynamic/SSDT3`).
///
/// The sysfs name does not decide anything: a file is a table to compare when its bytes start
/// with `DSDT` or `SSDT` and the declared length fits. Other tables are listed as skipped, because
/// the walker only reads AML. A file that looks like AML but has a bad header is an error naming
/// its path. Tables pair with an image's by signature and OEM table ID in `compare_tables`.
///
/// Example: `let found = tables_from_capture(vec![("DSDT".into(), dsdt_bytes)])?; assert!(found.skipped.is_empty());`
pub fn tables_from_capture(files: Vec<(String, Vec<u8>)>) -> Result<CaptureTables> {
    let mut found = CaptureTables {
        tables: Vec::new(),
        skipped: Vec::new(),
    };
    for (path, bytes) in files {
        if !AML_SIGNATURES.iter().any(|s| bytes.starts_with(*s)) {
            found.skipped.push(path);
            continue;
        }
        let table = FoundTable::new(bytes, format!("capture {path}"))
            .map_err(|e| e.context(format!("capture file {path}")))?;
        found.tables.push(table);
    }
    Ok(found)
}

/// How an object differs between two builds of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeStatus {
    Added,
    Removed,
    Changed,
}

/// One differing object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectChange {
    pub path: String,
    pub status: ChangeStatus,
    /// Kind in B for added and changed objects, in A for removed ones.
    pub kind: ObjectKind,
    /// Kind in A when it differs from B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_a: Option<ObjectKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_a: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_b: Option<String>,
}

/// One side of a table pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableSide {
    pub length: u32,
    pub sha256: String,
    pub oem_id: String,
    pub oem_revision: u32,
    pub source: String,
    /// Objects the walker listed.
    pub objects: usize,
    /// Terms the walker could not read; the listing is incomplete there.
    pub warnings: Vec<String>,
}

/// Per-kind counts of a table pair's changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChangeCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

/// A table present in both inputs.
#[derive(Debug, Clone, Serialize)]
pub struct TablePair {
    pub signature: String,
    pub oem_table_id: String,
    pub ordinal: usize,
    /// Index of the table in A's list (for callers that need its bytes).
    #[serde(skip)]
    pub index_a: usize,
    /// Index of the table in B's list.
    #[serde(skip)]
    pub index_b: usize,
    pub a: TableSide,
    pub b: TableSide,
    /// Same bytes.
    pub identical: bool,
    pub methods: ChangeCounts,
    pub names: ChangeCounts,
    pub other: ChangeCounts,
    pub changes: Vec<ObjectChange>,
    /// Every object the walker listed in A, for callers that print the full namespace.
    #[serde(skip)]
    pub objects_a: Vec<AmlObject>,
    /// Every object the walker listed in B.
    #[serde(skip)]
    pub objects_b: Vec<AmlObject>,
}

/// A table present in one input only.
#[derive(Debug, Clone, Serialize)]
pub struct LoneTable {
    pub signature: String,
    pub oem_table_id: String,
    pub ordinal: usize,
    pub length: u32,
    pub sha256: String,
    pub source: String,
}

/// The report over two inputs.
#[derive(Debug, Clone, Serialize)]
pub struct AcpiComparison {
    pub pairs: Vec<TablePair>,
    pub only_in_a: Vec<LoneTable>,
    pub only_in_b: Vec<LoneTable>,
}

fn side(table: &FoundTable, space: &aml::Namespace) -> TableSide {
    TableSide {
        length: table.header.length,
        sha256: table.sha256(),
        oem_id: table.header.oem_id.clone(),
        oem_revision: table.header.oem_revision,
        source: table.source.clone(),
        objects: space.objects.len(),
        warnings: space.warnings.clone(),
    }
}

/// Objects by path in table order; repeated paths keep their order.
fn by_path(space: &aml::Namespace) -> BTreeMap<&str, Vec<&AmlObject>> {
    let mut map: BTreeMap<&str, Vec<&AmlObject>> = BTreeMap::new();
    for object in &space.objects {
        map.entry(object.path.as_str()).or_default().push(object);
    }
    map
}

/// Added, removed and changed objects between two walked tables.
///
/// Containers (scopes, devices, ...) are only reported as added or removed;
/// their contents show up as their own objects.
///
/// Example: `let changes = diff_namespaces(&walk_a, &walk_b);`
pub fn diff_namespaces(a: &aml::Namespace, b: &aml::Namespace) -> Vec<ObjectChange> {
    let (left, right) = (by_path(a), by_path(b));
    let paths: BTreeSet<&str> = left.keys().chain(right.keys()).copied().collect();
    let mut changes = Vec::new();
    for path in paths {
        let xs = left.get(path).map_or(&[][..], Vec::as_slice);
        let ys = right.get(path).map_or(&[][..], Vec::as_slice);
        for index in 0..xs.len().max(ys.len()) {
            match (xs.get(index), ys.get(index)) {
                (Some(x), None) => changes.push(ObjectChange {
                    path: path.to_string(),
                    status: ChangeStatus::Removed,
                    kind: x.kind,
                    kind_a: None,
                    sha256_a: x.sha256.clone(),
                    sha256_b: None,
                }),
                (None, Some(y)) => changes.push(ObjectChange {
                    path: path.to_string(),
                    status: ChangeStatus::Added,
                    kind: y.kind,
                    kind_a: None,
                    sha256_a: None,
                    sha256_b: y.sha256.clone(),
                }),
                (Some(x), Some(y)) => {
                    let kind_differs = x.kind != y.kind;
                    let hash_differs = x.sha256 != y.sha256;
                    if kind_differs || hash_differs {
                        changes.push(ObjectChange {
                            path: path.to_string(),
                            status: ChangeStatus::Changed,
                            kind: y.kind,
                            kind_a: kind_differs.then_some(x.kind),
                            sha256_a: x.sha256.clone(),
                            sha256_b: y.sha256.clone(),
                        });
                    }
                }
                (None, None) => unreachable!("index below the longer side"),
            }
        }
    }
    changes
}

fn count(changes: &[ObjectChange], wanted: impl Fn(ObjectKind) -> bool) -> ChangeCounts {
    let mut counts = ChangeCounts::default();
    for change in changes.iter().filter(|c| wanted(c.kind)) {
        match change.status {
            ChangeStatus::Added => counts.added += 1,
            ChangeStatus::Removed => counts.removed += 1,
            ChangeStatus::Changed => counts.changed += 1,
        }
    }
    counts
}

/// Compare the tables of two inputs.
///
/// Example: `let report = compare_tables(&a_tables, &b_tables); assert!(report.pairs.iter().all(|p| p.a.length > 0));`
pub fn compare_tables(a: &[FoundTable], b: &[FoundTable]) -> AcpiComparison {
    type Key = (String, String);
    let group = |tables: &[FoundTable]| {
        let mut map: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
        for (index, table) in tables.iter().enumerate() {
            map.entry((
                table.header.signature.clone(),
                table.header.oem_table_id.clone(),
            ))
            .or_default()
            .push(index);
        }
        map
    };
    let (left, right) = (group(a), group(b));
    let keys: BTreeSet<&Key> = left.keys().chain(right.keys()).collect();
    let mut report = AcpiComparison {
        pairs: Vec::new(),
        only_in_a: Vec::new(),
        only_in_b: Vec::new(),
    };
    let lone = |key: &Key, ordinal: usize, table: &FoundTable| LoneTable {
        signature: key.0.clone(),
        oem_table_id: key.1.clone(),
        ordinal,
        length: table.header.length,
        sha256: table.sha256(),
        source: table.source.clone(),
    };
    for key in keys {
        let xs = left.get(key).map_or(&[][..], Vec::as_slice);
        let ys = right.get(key).map_or(&[][..], Vec::as_slice);
        for ordinal in 0..xs.len().max(ys.len()) {
            match (xs.get(ordinal), ys.get(ordinal)) {
                (Some(&i), Some(&j)) => {
                    let (ta, tb) = (&a[i], &b[j]);
                    let space_a = aml::walk_table(ta.bytes()).unwrap_or_default();
                    let space_b = aml::walk_table(tb.bytes()).unwrap_or_default();
                    let changes = diff_namespaces(&space_a, &space_b);
                    report.pairs.push(TablePair {
                        signature: key.0.clone(),
                        oem_table_id: key.1.clone(),
                        ordinal,
                        index_a: i,
                        index_b: j,
                        a: side(ta, &space_a),
                        b: side(tb, &space_b),
                        identical: ta.bytes() == tb.bytes(),
                        methods: count(&changes, |k| k == ObjectKind::Method),
                        names: count(&changes, |k| k == ObjectKind::Name),
                        other: count(&changes, |k| {
                            !matches!(k, ObjectKind::Method | ObjectKind::Name)
                        }),
                        changes,
                        objects_a: space_a.objects,
                        objects_b: space_b.objects,
                    });
                }
                (Some(&i), None) => report.only_in_a.push(lone(key, ordinal, &a[i])),
                (None, Some(&j)) => report.only_in_b.push(lone(key, ordinal, &b[j])),
                (None, None) => unreachable!("ordinal below the longer side"),
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aml::fixture::*;
    use crate::synthetic::{ffs, image_of_files, section};

    fn found(signature: &str, id: &str, aml: &[u8]) -> FoundTable {
        FoundTable::new(table(signature, id, aml), "fixture".into()).unwrap()
    }

    fn dsdt(sios_body: &[u8], siow: bool) -> Vec<u8> {
        let mut children = vec![method("SIOS", 1, sios_body)];
        if siow {
            children.push(method("SIOW", 1, &[0xA4, 0x00]));
        }
        [
            scope("\\_SB_", &[device("PCI0", &[device("SIO1", &children)])]),
            name_package("\\_S3_", &[5, 0]),
        ]
        .concat()
    }

    fn status_of<'a>(pair: &'a TablePair, path: &str) -> Option<&'a ObjectChange> {
        pair.changes.iter().find(|c| c.path == path)
    }

    #[test]
    fn capture_files_keep_aml_tables_and_list_the_rest_as_skipped() {
        let dsdt_bytes = table("DSDT", "LIVE", &dsdt(&[0xA4, 0x01], false));
        let ssdt_bytes = table("SSDT", "DYN", &name_package("\\_S3_", &[5, 0]));
        let found = tables_from_capture(vec![
            ("DSDT".into(), dsdt_bytes.clone()),
            ("dynamic/SSDT3".into(), ssdt_bytes),
            ("data/BERT".into(), table("BERT", "LIVE", &[])),
        ])
        .unwrap();
        let sources: Vec<&str> = found.tables.iter().map(|t| t.source.as_str()).collect();
        assert_eq!(sources, ["capture DSDT", "capture dynamic/SSDT3"]);
        assert_eq!(found.tables[0].bytes(), &dsdt_bytes[..]);
        assert_eq!(found.skipped, ["data/BERT"]);
    }

    #[test]
    fn a_capture_file_with_a_truncated_aml_table_names_its_path() {
        let mut bytes = table("SSDT", "DYN", &name_package("\\_S3_", &[5, 0]));
        bytes.truncate(bytes.len() - 3);
        let error = tables_from_capture(vec![("dynamic/SSDT7".into(), bytes)]).unwrap_err();
        assert!(
            error.message.contains("capture file dynamic/SSDT7"),
            "(capture truncated SSDT): expected the file path in the message | received {}",
            error.message
        );
        assert_eq!(error.code, Code::FormatInvalid);
    }

    #[test]
    fn changed_added_and_removed_objects_are_reported_by_path() {
        let a = found("DSDT", "TEST", &dsdt(&[0xA4, 0x01], false));
        let b = found("DSDT", "TEST", &dsdt(&[0xA4, 0x02], true));
        let report = compare_tables(&[a], &[b]);
        assert_eq!(report.pairs.len(), 1);
        let pair = &report.pairs[0];
        assert!(!pair.identical);
        let sios = status_of(pair, "\\_SB_.PCI0.SIO1.SIOS").expect("SIOS changed");
        assert_eq!(
            (sios.status, sios.kind),
            (ChangeStatus::Changed, ObjectKind::Method)
        );
        let siow = status_of(pair, "\\_SB_.PCI0.SIO1.SIOW").expect("SIOW added");
        assert_eq!(siow.status, ChangeStatus::Added);
        assert!(
            status_of(pair, "\\_S3_").is_none(),
            "_S3_ is the same in both"
        );
        assert_eq!(
            pair.methods,
            ChangeCounts {
                added: 1,
                removed: 0,
                changed: 1
            }
        );
        assert_eq!(pair.a.objects + 1, pair.b.objects);
        let reverse = compare_tables(
            &[found("DSDT", "TEST", &dsdt(&[0xA4, 0x02], true))],
            &[found("DSDT", "TEST", &dsdt(&[0xA4, 0x01], false))],
        );
        assert_eq!(
            status_of(&reverse.pairs[0], "\\_SB_.PCI0.SIO1.SIOW")
                .unwrap()
                .status,
            ChangeStatus::Removed
        );
    }

    #[test]
    fn names_and_other_kinds_are_counted_apart_from_methods() {
        let a = found(
            "SSDT",
            "CpuPm",
            &[
                name_package("\\PSTA", &[1]),
                operation_region("\\SMI0", 0xB2, 2),
            ]
            .concat(),
        );
        let b = found(
            "SSDT",
            "CpuPm",
            &[
                name_package("\\PSTA", &[2]),
                operation_region("\\SMI0", 0xB4, 2),
            ]
            .concat(),
        );
        let pair = &compare_tables(&[a], &[b]).pairs[0];
        assert_eq!(pair.names.changed, 1);
        assert_eq!(pair.other.changed, 1);
        assert_eq!(pair.methods, ChangeCounts::default());
    }

    #[test]
    fn identical_tables_report_no_changes() {
        let aml = dsdt(&[0xA4, 0x01], true);
        let pair =
            &compare_tables(&[found("DSDT", "T", &aml)], &[found("DSDT", "T", &aml)]).pairs[0];
        assert!(pair.identical && pair.changes.is_empty());
    }

    #[test]
    fn tables_pair_by_signature_and_oem_table_id_with_surplus_listed() {
        let a = [
            found("DSDT", "MAIN", &[]),
            found("SSDT", "CpuPm", &[]),
            found("SSDT", "Cpu0Ist", &[]),
        ];
        let b = [
            found("SSDT", "CpuPm", &[]),
            found("DSDT", "MAIN", &[]),
            found("SSDT", "Other", &[]),
        ];
        let report = compare_tables(&a, &b);
        let keys: Vec<(&str, &str)> = report
            .pairs
            .iter()
            .map(|p| (p.signature.as_str(), p.oem_table_id.as_str()))
            .collect();
        assert_eq!(keys, vec![("DSDT", "MAIN"), ("SSDT", "CpuPm")]);
        assert_eq!(report.only_in_a[0].oem_table_id, "Cpu0Ist");
        assert_eq!(report.only_in_b[0].oem_table_id, "Other");
    }

    #[test]
    fn repeated_table_ids_pair_in_order() {
        let first = found("SSDT", "DUP", &name_byte("\\ONE_", 1));
        let second = found("SSDT", "DUP", &name_byte("\\TWO_", 2));
        let report = compare_tables(&[first.clone(), second], &[first]);
        assert_eq!((report.pairs.len(), report.only_in_a.len()), (1, 1));
        assert_eq!(report.only_in_a[0].ordinal, 1);
    }

    #[test]
    fn bare_table_and_image_inputs_are_recognized() {
        let aml = table("DSDT", "BARE", &dsdt(&[0xA4, 0x01], true));
        let bare = tables_from_input(aml.clone()).unwrap();
        assert_eq!((bare.len(), bare[0].source.as_str()), (1, "file"));
        let ssdt = table("SSDT", "EMBED", &name_byte("\\EMBD", 1));
        let files = [
            ffs(crate::synthetic::TABLE_GUID, 0x02, &section(0x19, &aml), 0),
            ffs(
                crate::synthetic::PEIM_GUID,
                0x06,
                &section(0x10, &[b"junk".as_slice(), &ssdt, b"tail"].concat()),
                0,
            ),
        ];
        let tables = tables_from_input(image_of_files(&files)).unwrap();
        let ids: Vec<&str> = tables
            .iter()
            .map(|t| t.header.oem_table_id.as_str())
            .collect();
        assert!(ids.contains(&"BARE") && ids.contains(&"EMBED"), "{ids:?}");
    }

    #[test]
    fn signature_inside_code_without_a_valid_checksum_is_ignored() {
        let mut fake = table("SSDT", "FAKE", &[]);
        fake[9] ^= 0xFF;
        let files = [ffs(
            crate::synthetic::PEIM_GUID,
            0x06,
            &section(0x10, &fake),
            0,
        )];
        assert!(
            tables_from_input(image_of_files(&files))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unrecognized_input_names_both_readings() {
        let error = tables_from_input(vec![0u8; 64]).expect_err("zeroes are neither");
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error.message.contains(
                "expected a DSDT/SSDT table whose length equals the file size, or a firmware image"
            ),
            "{error}"
        );
    }
}
