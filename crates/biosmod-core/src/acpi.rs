//! Inventory of the ACPI tables an image stores.
//!
//! A table counts when a PE32, TE or raw section body holds a header whose
//! signature is four printable ASCII characters, whose length fits inside the
//! section, whose revision is 1 to 0x20, whose OEM ID, OEM table ID and creator
//! ID are NUL-padded printable ASCII and whose bytes sum to zero modulo 256. The
//! text rule keeps PE code and data from matching by chance: without it, false
//! tables appear in the stock images. A real table with a binary creator ID would
//! be missed. The result is the stored set: firmware builds FADT, MADT and similar
//! tables at boot, so those rarely
//! carry a valid stored checksum and are missing here by design.
//!
//! Example:
//! ```no_run
//! # fn main() -> biosmod_core::Result<()> {
//! let image = biosmod_core::firmware::Image::parse(std::fs::read("bios.bin").unwrap())?;
//! for table in biosmod_core::acpi::inventory(&image).tables {
//!     println!("{} {} {} bytes", table.signature, table.oem_table_id, table.length);
//! }
//! # Ok(()) }
//! ```

use crate::error::{Code, Error, Result};
use crate::firmware::{Image, SECTION_PE32, SECTION_RAW, SECTION_TE, locate, walk};
use crate::util::{Digest256, Guid, le32, sum8};
use serde::Serialize;

/// Size of the common ACPI description header.
pub const HEADER_LEN: usize = 36;
/// Largest stored table length accepted as plausible.
const MAX_TABLE_LEN: usize = 16 << 20;
/// Highest header revision accepted as plausible (published tables use 1 to 6).
const MAX_REVISION: u8 = 0x20;

/// Printed with every inventory: what the list does and does not cover.
pub const STORED_SET_NOTICE: &str = "Stored set: tables found with a valid checksum inside firmware sections. It is not the set the firmware publishes at runtime; FADT, MADT and other tables built during boot are absent.";

/// Where one copy of a table sits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableLocation {
    /// GUID of the owning top-level FFS file.
    pub file_guid: Guid,
    pub file_name: Option<String>,
    /// Section indices from the file's section list down to the leaf section.
    pub section_path: Vec<usize>,
    /// `raw`, `pe32` or `te`.
    pub section_kind: &'static str,
    /// True when the path passes through an LZMA section.
    pub compressed: bool,
    /// Table offset within the section body.
    pub offset: usize,
}

/// One distinct table (by SHA-256) and every place it is stored.
#[derive(Debug, Clone, Serialize)]
pub struct StoredTable {
    pub signature: String,
    pub revision: u8,
    pub length: usize,
    pub oem_id: String,
    pub oem_table_id: String,
    pub oem_revision: u32,
    pub creator_id: String,
    pub creator_revision: u32,
    pub sha256: Digest256,
    pub locations: Vec<TableLocation>,
}

impl StoredTable {
    /// Describe `bytes`, a table already accepted by [`scan_body`], stored at `location`.
    fn describe(location: TableLocation, bytes: &[u8]) -> StoredTable {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        StoredTable {
            signature: id_text(&bytes[0..4]),
            revision: bytes[8],
            length: bytes.len(),
            oem_id: id_text(&bytes[10..16]),
            oem_table_id: id_text(&bytes[16..24]),
            oem_revision: word(24),
            creator_id: id_text(&bytes[28..32]),
            creator_revision: word(32),
            sha256: Digest256::of(bytes),
            locations: vec![location],
        }
    }
}

/// Result of [`inventory`].
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub notice: &'static str,
    pub tables: Vec<StoredTable>,
}

/// A checksum-valid table at `offset` in a scanned body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate<'a> {
    pub offset: usize,
    pub bytes: &'a [u8],
}

/// Find checksum-valid ACPI tables in one section body, in offset order and without overlap.
///
/// Example: `assert!(scan_body(&[0u8; 64]).is_empty());`
pub fn scan_body(body: &[u8]) -> Vec<Candidate<'_>> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + HEADER_LEN <= body.len() {
        match table_at(body, at) {
            Some(bytes) => {
                found.push(Candidate { offset: at, bytes });
                at += bytes.len();
            }
            None => at += 1,
        }
    }
    found
}

/// The table starting at `at`, if the header is plausible and the checksum holds.
fn table_at(body: &[u8], at: usize) -> Option<&[u8]> {
    let header = body.get(at..at + HEADER_LEN)?;
    if !header[..4].iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    let length = le32(header, 4, "ACPI length").ok()? as usize;
    if !(HEADER_LEN..=MAX_TABLE_LEN).contains(&length) || header[8] == 0 || header[8] > MAX_REVISION
    {
        return None;
    }
    // OEM ID, OEM table ID and creator ID are text padded with NULs; random bytes that
    // sum to zero rarely satisfy that, which keeps PE code and data from matching.
    let text_fields = [&header[10..16], &header[16..24], &header[28..32]];
    if !text_fields
        .iter()
        .all(|f| f.iter().all(|c| *c == 0 || (0x20..0x7F).contains(c)))
    {
        return None;
    }
    let table = body.get(at..at.checked_add(length)?)?;
    (sum8(table) == 0).then_some(table)
}

/// Render a fixed-width ID without trailing NUL or space padding; bytes outside printable ASCII become `?`.
///
/// Example: `assert_eq!(id_text(b"PmMgt\0\0\0"), "PmMgt");`
pub fn id_text(raw: &[u8]) -> String {
    let end = raw
        .iter()
        .rposition(|c| *c != 0 && *c != b' ')
        .map_or(0, |i| i + 1);
    raw[..end]
        .iter()
        .map(|c| {
            if (0x20..0x7F).contains(c) {
                *c as char
            } else {
                '?'
            }
        })
        .collect()
}

fn kind_name(kind: u8) -> Option<&'static str> {
    match kind {
        SECTION_RAW => Some("raw"),
        SECTION_PE32 => Some("pe32"),
        SECTION_TE => Some("te"),
        _ => None,
    }
}

/// Every checksum-valid table in `image`, deduplicated by SHA-256 in first-seen order.
///
/// Example: `let tables = inventory(&image).tables;`
pub fn inventory(image: &Image) -> Inventory {
    Inventory {
        notice: STORED_SET_NOTICE,
        tables: distinct_tables(image, None)
            .into_iter()
            .map(|t| t.0)
            .collect(),
    }
}

/// Distinct tables with their bytes; `only` restricts the scan to one FFS file.
fn distinct_tables(image: &Image, only: Option<Guid>) -> Vec<(StoredTable, Vec<u8>)> {
    let mut tables: Vec<(StoredTable, Vec<u8>)> = Vec::new();
    scan_image(image, only, &mut |location, bytes| {
        let sha256 = Digest256::of(bytes);
        match tables.iter_mut().find(|(t, _)| t.sha256 == sha256) {
            Some((table, _)) => table.locations.push(location),
            None => tables.push((StoredTable::describe(location, bytes), bytes.to_vec())),
        }
    });
    tables
}

/// Call `found` for every table copy in image order.
fn scan_image(image: &Image, only: Option<Guid>, found: &mut dyn FnMut(TableLocation, &[u8])) {
    for (v, volume) in image.volumes.iter().enumerate() {
        for (f, file) in volume.files.iter().enumerate() {
            if only.is_some_and(|guid| guid != file.guid) {
                continue;
            }
            let name = image.ui_name(v, f);
            let stream = file.body(&image.bytes);
            walk(
                &file.sections,
                &mut Vec::new(),
                false,
                &mut |path, section, compressed| {
                    let Some(section_kind) = kind_name(section.kind) else {
                        return;
                    };
                    let (leaf, container) = locate(&file.sections, stream, path);
                    for candidate in scan_body(leaf.body(container)) {
                        let location = TableLocation {
                            file_guid: file.guid,
                            file_name: name.clone(),
                            section_path: path.to_vec(),
                            section_kind,
                            compressed,
                            offset: candidate.offset,
                        };
                        found(location, candidate.bytes);
                    }
                },
            );
        }
    }
}

/// Fields that narrow a table choice inside one FFS file; unset fields match anything.
#[derive(Debug, Clone, Default)]
pub struct TableSelector {
    pub signature: Option<String>,
    pub oem_table_id: Option<String>,
    pub sha256: Option<Digest256>,
}

impl TableSelector {
    /// True when no field is set.
    pub fn is_empty(&self) -> bool {
        self.signature.is_none() && self.oem_table_id.is_none() && self.sha256.is_none()
    }

    /// True when every set field equals the table's (IDs compare without padding).
    ///
    /// Example: `TableSelector::default().matches(&table)` is always true.
    pub fn matches(&self, table: &StoredTable) -> bool {
        self.signature
            .as_ref()
            .is_none_or(|s| *s == table.signature)
            && self
                .oem_table_id
                .as_ref()
                .is_none_or(|s| id_text(s.as_bytes()) == table.oem_table_id)
            && self.sha256.is_none_or(|s| s == table.sha256)
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(s) = &self.signature {
            parts.push(format!("signature {s}"));
        }
        if let Some(s) = &self.oem_table_id {
            parts.push(format!("oem-table-id {s}"));
        }
        if let Some(s) = &self.sha256 {
            parts.push(format!("sha256 {s}"));
        }
        if parts.is_empty() {
            "any table".into()
        } else {
            parts.join(", ")
        }
    }
}

/// The table in file `guid` that `selector` picks, with its bytes.
///
/// Identical copies inside the file count as one table. Zero matches fail with
/// `TARGET_NOT_FOUND`; several distinct tables fail with `TARGET_AMBIGUOUS`
/// and name each candidate.
///
/// Example: `let (table, bytes) = select_table(&image, guid, &selector)?;`
pub fn select_table(
    image: &Image,
    guid: Guid,
    selector: &TableSelector,
) -> Result<(StoredTable, Vec<u8>)> {
    let all = distinct_tables(image, Some(guid));
    let total = all.len();
    let mut picked: Vec<_> = all
        .into_iter()
        .filter(|(t, _)| selector.matches(t))
        .collect();
    match picked.len() {
        1 => Ok(picked.remove(0)),
        0 => Err(Error::new(
            Code::TargetNotFound,
            format!(
                "GUID {guid}: expected a stored ACPI table matching {} | received none among {total} table(s) in the file",
                selector.describe()
            ),
        )),
        count => {
            let names: Vec<String> = picked
                .iter()
                .map(|(t, _)| format!("{} {:?} sha256 {}", t.signature, t.oem_table_id, t.sha256))
                .collect();
            Err(Error::new(
                Code::TargetAmbiguous,
                format!(
                    "GUID {guid}: expected one ACPI table matching {} | received {count}: {}; narrow with --oem-table-id or --sha256",
                    selector.describe(),
                    names.join(", ")
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::{AcpiInventoryFixture, acpi_table};

    #[test]
    fn scan_body_finds_valid_tables_and_skips_bad_checksums() {
        let good = acpi_table(*b"SSDT", "Alpha", 1, 40);
        let mut bad = acpi_table(*b"SSDT", "Decoy", 1, 40);
        bad[40] ^= 0x01;
        let mut body = vec![0xAA; 5];
        body.extend(&good);
        body.extend(&bad);
        let found = scan_body(&body);
        assert_eq!(
            found.iter().map(|c| c.offset).collect::<Vec<_>>(),
            vec![5],
            "(scan_body): expected only the checksum-valid table at offset 5"
        );
        assert_eq!(found[0].bytes, &good[..]);
    }

    #[test]
    fn scan_body_rejects_implausible_headers() {
        let mut nonprint = acpi_table(*b"SSDT", "Alpha", 1, 40);
        nonprint[0] = 0x01;
        let mut revision0 = acpi_table(*b"SSDT", "Alpha", 1, 40);
        revision0[8] = 0;
        let mut revision_high = acpi_table(*b"SSDT", "Alpha", 1, 40);
        revision_high[9] = revision_high[9].wrapping_sub(0x75 - 1);
        revision_high[8] = 0x75;
        let mut oversize = acpi_table(*b"SSDT", "Alpha", 1, 40);
        oversize.truncate(60);
        let mut binary_oem = acpi_table(*b"SSDT", "Alpha", 1, 40);
        binary_oem[10] = 0xC3;
        binary_oem[9] = binary_oem[9].wrapping_sub(0xC3 - b'S');
        for (name, body) in [
            ("binary OEM ID", binary_oem),
            ("non-printable signature", nonprint),
            ("revision 0", revision0),
            ("revision 0x75", revision_high),
            ("length past section end", oversize),
        ] {
            assert!(
                scan_body(&body).is_empty(),
                "({name}): expected no table | received one"
            );
        }
    }

    #[test]
    fn id_text_trims_padding_and_masks_binary() {
        assert_eq!(id_text(b"PmMgt\0\0\0"), "PmMgt");
        assert_eq!(id_text(b"A M I \0\0"), "A M I");
        assert_eq!(id_text(&[b'A', 0x01, 0]), "A?");
        assert_eq!(id_text(&[0; 8]), "");
    }

    #[test]
    fn inventory_lists_pe_and_raw_tables_and_dedupes_by_hash() {
        let fixture = AcpiInventoryFixture::new();
        let image = Image::parse(fixture.image.clone()).unwrap();
        let list = inventory(&image);
        let ids: Vec<(&str, &str)> = list
            .tables
            .iter()
            .map(|t| (t.signature.as_str(), t.oem_table_id.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec![("SSDT", "InPe"), ("SSDT", "InRaw")],
            "(inventory): expected the PE table and the raw table only, no decoy"
        );
        let in_raw = &list.tables[1];
        assert_eq!(in_raw.sha256, Digest256::of(&fixture.raw_table));
        assert_eq!(
            in_raw
                .locations
                .iter()
                .map(|l| l.file_guid)
                .collect::<Vec<_>>(),
            vec![fixture.raw_guid, fixture.mixed_guid],
            "(InRaw locations): expected both owning files, in image order"
        );
        assert_eq!(in_raw.locations[0].section_kind, "raw");
        assert_eq!(in_raw.locations[0].section_path, vec![0]);
        assert_eq!(in_raw.locations[0].offset, 0);
        let in_pe = &list.tables[0];
        assert_eq!(in_pe.locations.len(), 2, "the mixed file repeats it");
        assert_eq!(in_pe.locations[0].section_kind, "pe32");
        assert_eq!(in_pe.locations[0].offset, fixture.pe_offset);
        assert_eq!(in_pe.locations[0].file_name.as_deref(), Some("PeHost"));
        assert_eq!(in_pe.oem_id, "SYNTH");
        assert_eq!(in_pe.creator_id, "BME");
        assert!(list.notice.contains("not the set the firmware publishes"));
    }

    #[test]
    fn select_table_picks_by_field_and_reports_ambiguity() {
        let fixture = AcpiInventoryFixture::new();
        let image = Image::parse(fixture.image.clone()).unwrap();
        let guid = fixture.pe_guid;
        let by_id = TableSelector {
            oem_table_id: Some("InPe".into()),
            ..Default::default()
        };
        assert_eq!(
            select_table(&image, guid, &by_id).unwrap().1,
            fixture.pe_table
        );
        let missing = TableSelector {
            signature: Some("DSDT".into()),
            ..Default::default()
        };
        assert_eq!(
            select_table(&image, guid, &missing).unwrap_err().code,
            Code::TargetNotFound
        );
        // The raw file holds one valid table next to a bad-checksum decoy.
        let single = select_table(&image, fixture.raw_guid, &TableSelector::default());
        assert_eq!(single.unwrap().1, fixture.raw_table);
        let both = fixture.mixed_guid;
        assert_eq!(
            select_table(&image, both, &TableSelector::default())
                .unwrap_err()
                .code,
            Code::TargetAmbiguous
        );
    }
}
