//! AMI Aptio NVAR store walker.
//!
//! Record layout (little endian), as documented by UEFITool's `nvram.h`:
//!
//! ```text
//! 0  "NVAR"
//! 4  u16 size            whole record, header included
//! 6  u24 next            offset from this record's start to the next record of the
//!                        chain, 0xFFFFFF when this is the latest
//! 9  u8  attributes      see the FLAG_* constants
//! 10 [guid]              16 bytes with FLAG_GUID, else a u8 index into the GUID table
//! .. [name]              NUL-terminated ASCII (FLAG_ASCII_NAME) or UCS-2
//! .. data
//! .. [extended header]   FLAG_EXT_HEADER: u8 attributes, optional u8 checksum,
//!                        optional timestamp and hash, u16 header size (last two bytes)
//! ```
//!
//! Data-only records (FLAG_DATA_ONLY) carry neither GUID nor name; they are updates linked
//! from the variable's first record. The GUID table sits at the end of the store, index 0
//! at the very end, and grows towards the records.

use super::{
    AMI_DEFAULTS_GUID, DefaultsClass, Draft, EFI_AUTH_WRITE, EFI_BOOTSERVICE, EFI_NON_VOLATILE,
    EFI_RUNTIME, EFI_TIME_BASED, Issue, NvramReport, RecordState, Store, StoreKind, is_erased,
    ucs2_text,
};
use crate::util::Guid;
use std::collections::HashMap;

const SIGNATURE: &[u8; 4] = b"NVAR";
const HEADER: usize = 10;
const NEXT_NONE: u32 = 0x00FF_FFFF;

const FLAG_RUNTIME: u8 = 0x01;
const FLAG_ASCII_NAME: u8 = 0x02;
const FLAG_GUID: u8 = 0x04;
const FLAG_DATA_ONLY: u8 = 0x08;
const FLAG_EXT_HEADER: u8 = 0x10;
const FLAG_HW_ERROR: u8 = 0x20;
const FLAG_AUTH_WRITE: u8 = 0x40;
const FLAG_VALID: u8 = 0x80;

const EXT_CHECKSUM: u8 = 0x01;
const EXT_AUTH_WRITE: u8 = 0x10;
const EXT_TIME_BASED: u8 = 0x20;

/// True when `bytes` begins with an NVAR record.
pub(super) fn sniff(bytes: &[u8]) -> bool {
    bytes.starts_with(SIGNATURE)
}

/// Decode a top-level NVAR store whose first byte sits at image offset `base`.
pub(super) fn parse_store(
    bytes: &[u8],
    base: usize,
    file_guid: Option<Guid>,
    report: &mut NvramReport,
) {
    let label = format!("nvar@{base:#x}");
    parse_into(
        Source {
            bytes,
            base,
            label,
            kind: StoreKind::Nvar,
            defaults: None,
            file_guid,
        },
        report,
    );
}

struct Source<'a> {
    bytes: &'a [u8],
    base: usize,
    label: String,
    kind: StoreKind,
    defaults: Option<DefaultsClass>,
    file_guid: Option<Guid>,
}

/// One structurally valid record.
struct Entry {
    offset: usize,
    attributes: u8,
    /// Store offset of the next record in the chain.
    next: Option<usize>,
    body: Option<Body>,
}

/// The decoded interior of a record.
struct Body {
    name: String,
    guid: Guid,
    data: std::ops::Range<usize>,
    extended_attributes: Option<u8>,
    checksum: Option<u8>,
}

/// A defaults holder to parse after its parent store is recorded.
struct Nested {
    label: String,
    class: DefaultsClass,
    base: usize,
    data: Vec<u8>,
    file_guid: Option<Guid>,
}

fn parse_into(source: Source<'_>, report: &mut NvramReport) {
    let Source {
        bytes,
        base,
        label,
        kind,
        defaults,
        file_guid,
    } = source;
    let GuidTable {
        guids: table,
        overlap,
    } = guid_table(bytes);
    let limit = bytes.len() - 16 * table.len();
    let mut issues = Vec::new();
    if let Some(overlap) = overlap {
        issues.push(Issue {
            store: label.clone(),
            offset: base + overlap.records_end,
            message: format!(
                "GUID table: expected {} entries after the last record | received {}",
                overlap.needed, overlap.available
            ),
        });
    }
    let entries = walk(&bytes[..limit], &table, &label, base, &mut issues);
    let by_offset: HashMap<usize, usize> = entries
        .iter()
        .enumerate()
        .map(|(index, e)| (e.offset, index))
        .collect();
    let mut claimed = vec![false; entries.len()];
    let mut drafts: Vec<Draft> = Vec::new();
    let mut nested: Vec<Nested> = Vec::new();

    for (head_index, head) in entries.iter().enumerate() {
        if head.attributes & FLAG_DATA_ONLY != 0 {
            continue;
        }
        let Some(head_body) = &head.body else {
            continue;
        };
        let chain = follow_chain(
            head_index,
            &entries,
            &by_offset,
            &mut claimed,
            &label,
            base,
            &mut issues,
        );
        let head_valid = head.attributes & FLAG_VALID != 0;
        let (attributes, flags) = describe(head.attributes, head_body.extended_attributes);
        // The newest member that decoded and is not marked invalid is the live value; a
        // damaged or invalidated tail must not leave the variable without one.
        let active_position = chain.iter().rposition(|&i| {
            head_valid && entries[i].attributes & FLAG_VALID != 0 && entries[i].body.is_some()
        });
        for (position, &member_index) in chain.iter().enumerate() {
            let member = &entries[member_index];
            let Some(body) = &member.body else {
                continue;
            };
            let state = if !head_valid || member.attributes & FLAG_VALID == 0 {
                RecordState::Deleted
            } else if Some(position) == active_position {
                RecordState::Active
            } else {
                RecordState::Superseded
            };
            let data = bytes[body.data.clone()].to_vec();
            // Only a top-level store holds defaults; a holder inside one stays a plain record.
            if state == RecordState::Active
                && kind == StoreKind::Nvar
                && head_body.guid == AMI_DEFAULTS_GUID
                && sniff(&data)
                && let Some(class) = defaults_class(&head_body.name)
            {
                nested.push(Nested {
                    label: format!("{label}:{}", head_body.name),
                    class,
                    base: base + body.data.start,
                    data: data.clone(),
                    file_guid,
                });
            }
            drafts.push(Draft {
                store: label.clone(),
                name: head_body.name.clone(),
                guid: head_body.guid,
                state,
                offset: base + member.offset,
                attributes,
                flags: flags.clone(),
                extended_attributes: body.extended_attributes,
                checksum: body.checksum,
                chain_index: position,
                chain_len: chain.len(),
                defaults,
                data,
            });
        }
    }

    // Data-only records that no variable record reaches: their name is lost.
    for (index, entry) in entries.iter().enumerate() {
        if entry.attributes & FLAG_DATA_ONLY == 0 || claimed[index] {
            continue;
        }
        let Some(body) = &entry.body else { continue };
        let state = if entry.attributes & FLAG_VALID == 0 {
            RecordState::Deleted
        } else {
            RecordState::Orphan
        };
        drafts.push(Draft {
            store: label.clone(),
            name: String::new(),
            guid: Guid([0; 16]),
            state,
            offset: base + entry.offset,
            attributes: 0,
            flags: flag_names(entry.attributes),
            extended_attributes: body.extended_attributes,
            checksum: body.checksum,
            chain_index: 0,
            chain_len: 1,
            defaults,
            data: bytes[body.data.clone()].to_vec(),
        });
    }
    drafts.sort_by_key(|d| d.offset);

    report.stores.push(Store {
        label: label.clone(),
        kind,
        offset: base,
        length: bytes.len(),
        file_guid,
        defaults,
        guid_table_entries: table.len(),
        records: drafts.len(),
    });
    report
        .variables
        .extend(drafts.into_iter().map(Draft::finish));
    report.issues.extend(issues);

    for holder in nested {
        parse_into(
            Source {
                bytes: &holder.data,
                base: holder.base,
                label: holder.label,
                kind: StoreKind::NvarDefaults,
                defaults: Some(holder.class),
                file_guid: holder.file_guid,
            },
            report,
        );
    }
}

fn defaults_class(name: &str) -> Option<DefaultsClass> {
    match name {
        "StdDefaults" => Some(DefaultsClass::Standard),
        "MfgDefaults" => Some(DefaultsClass::Manufacturing),
        _ => None,
    }
}

/// The GUID table of a store and, when the records leave too little room for it, the gap.
struct GuidTable {
    guids: Vec<Guid>,
    overlap: Option<Overlap>,
}

/// Records that name more GUID indexes than fit between the last record and the store end.
struct Overlap {
    records_end: usize,
    needed: usize,
    available: usize,
}

/// GUIDs stored at the end of the store, index 0 last.
///
/// The table never reaches into the records: it holds at most the 16-byte slots after the
/// last structurally valid record, and ends earlier where an erased slot separates it from
/// them. Without that bound a store whose table directly follows the records (no erased
/// gap) would have its last records read as table entries.
fn guid_table(bytes: &[u8]) -> GuidTable {
    let Extent {
        end,
        guid_indexes_needed,
    } = records_extent(bytes);
    let available = (bytes.len() - end) / 16;
    let mut guids = Vec::new();
    let mut table_end = bytes.len();
    while guids.len() < available && !is_erased(&bytes[table_end - 16..table_end]) {
        guids.push(Guid::from_slice(&bytes[table_end - 16..table_end]));
        table_end -= 16;
    }
    let overlap = (guid_indexes_needed > available).then_some(Overlap {
        records_end: end,
        needed: guid_indexes_needed,
        available,
    });
    GuidTable { guids, overlap }
}

/// Where the records of a store end and how many GUID table entries they name.
struct Extent {
    /// Offset just past the last structurally valid record.
    end: usize,
    /// Highest GUID index named by a variable record, plus one.
    guid_indexes_needed: usize,
}

/// Walk the record framing of the whole store (no table needed) the way [`walk`] does:
/// skip erased runs and resynchronise on damage. The table bytes at the end do not frame as
/// records, so the walk runs out there and `end` marks the last record before them.
fn records_extent(bytes: &[u8]) -> Extent {
    let mut extent = Extent {
        end: 0,
        guid_indexes_needed: 0,
    };
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == 0xFF && is_erased(&bytes[offset..(offset + 4).min(bytes.len())]) {
            match bytes[offset..].iter().position(|b| *b != 0xFF) {
                Some(skip) => offset += skip,
                None => break,
            }
            continue;
        }
        let remaining = bytes.len() - offset;
        if !bytes[offset..].starts_with(SIGNATURE) {
            offset = resync(bytes, offset + 1);
            continue;
        }
        if remaining < HEADER {
            break;
        }
        let size = usize::from(u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]));
        if size < HEADER || size > remaining {
            offset = resync(bytes, offset + 4);
            continue;
        }
        let attributes = bytes[offset + 9];
        if attributes & (FLAG_DATA_ONLY | FLAG_GUID) == 0
            && let Some(index) = bytes[offset..offset + size].get(HEADER)
        {
            extent.guid_indexes_needed = extent.guid_indexes_needed.max(usize::from(*index) + 1);
        }
        offset += size;
        extent.end = offset;
    }
    extent
}

/// Split the records area into structurally valid entries; damaged parts become issues.
fn walk(
    area: &[u8],
    table: &[Guid],
    label: &str,
    base: usize,
    issues: &mut Vec<Issue>,
) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut issue = |offset: usize, message: String| {
        issues.push(Issue {
            store: label.to_owned(),
            offset: base + offset,
            message,
        });
    };
    while offset < area.len() {
        if area[offset] == 0xFF && is_erased(&area[offset..(offset + 4).min(area.len())]) {
            // Erased run: skip to the next programmed byte, if any.
            match area[offset..].iter().position(|b| *b != 0xFF) {
                Some(skip) => offset += skip,
                None => break,
            }
            continue;
        }
        let remaining = area.len() - offset;
        if !area[offset..].starts_with(SIGNATURE) {
            issue(
                offset,
                format!(
                    "record signature: expected \"NVAR\" | received {:02X?}",
                    &area[offset..offset + remaining.min(4)]
                ),
            );
            offset = resync(area, offset + 1);
            continue;
        }
        if remaining < HEADER {
            issue(
                offset,
                format!("record header: expected {HEADER} bytes | received {remaining}"),
            );
            break;
        }
        let size = usize::from(u16::from_le_bytes([area[offset + 4], area[offset + 5]]));
        if size < HEADER || size > remaining {
            issue(
                offset,
                format!("record size: expected {HEADER}..={remaining} | received {size}"),
            );
            offset = resync(area, offset + 4);
            continue;
        }
        let next = u32::from_le_bytes([area[offset + 6], area[offset + 7], area[offset + 8], 0]);
        let attributes = area[offset + 9];
        let record = &area[offset..offset + size];
        let body = match decode_body(record, attributes, table) {
            Ok(body) => Some(Body {
                data: body.data.start + offset..body.data.end + offset,
                ..body
            }),
            Err(message) => {
                issue(offset, message);
                None
            }
        };
        entries.push(Entry {
            offset,
            attributes,
            next: (next != NEXT_NONE).then(|| offset + next as usize),
            body,
        });
        offset += size;
    }
    entries
}

/// Offset of the next `NVAR` signature at or after `from`, or the end of `area`.
fn resync(area: &[u8], from: usize) -> usize {
    area.get(from..)
        .and_then(|rest| rest.windows(4).position(|w| w == SIGNATURE))
        .map_or(area.len(), |at| from + at)
}

/// Decode GUID, name, data range and extended header of one record.
/// Offsets in the result are relative to the record.
fn decode_body(record: &[u8], attributes: u8, table: &[Guid]) -> Result<Body, String> {
    let size = record.len();
    let mut position = HEADER;
    let mut name = String::new();
    let mut guid = Guid([0; 16]);
    if attributes & FLAG_DATA_ONLY == 0 {
        if attributes & FLAG_GUID != 0 {
            let raw = record.get(position..position + 16).ok_or_else(|| {
                format!(
                    "inline GUID: expected 16 bytes | received {}",
                    size - position
                )
            })?;
            guid = Guid::from_slice(raw);
            position += 16;
        } else {
            let index = usize::from(
                *record
                    .get(position)
                    .ok_or("GUID index: expected 1 byte | received none")?,
            );
            guid = *table.get(index).ok_or_else(|| {
                format!(
                    "GUID index: expected < {} (table entries) | received {index}",
                    table.len()
                )
            })?;
            position += 1;
        }
        if attributes & FLAG_ASCII_NAME != 0 {
            let length = record[position..]
                .iter()
                .position(|b| *b == 0)
                .ok_or("ASCII name: expected a NUL terminator inside the record | received none")?;
            name = String::from_utf8_lossy(&record[position..position + length]).into_owned();
            position += length + 1;
        } else {
            let length = record[position..]
                .as_chunks::<2>()
                .0
                .iter()
                .position(|c| *c == [0, 0])
                .ok_or("UCS-2 name: expected a NUL terminator inside the record | received none")?;
            name = ucs2_text(&record[position..position + 2 * length]);
            position += 2 * length + 2;
        }
    }
    let mut data_end = size;
    let mut extended_attributes = None;
    let mut checksum = None;
    if attributes & FLAG_EXT_HEADER != 0 {
        let tail = size
            .checked_sub(2)
            .filter(|at| *at >= position)
            .map(|at| usize::from(u16::from_le_bytes([record[at], record[at + 1]])))
            .ok_or("extended header size: expected 2 bytes after the name | received none")?;
        if tail < 3 || tail > size - position {
            return Err(format!(
                "extended header size: expected 3..={} | received {tail}",
                size - position
            ));
        }
        data_end = size - tail;
        let attrs = record[data_end];
        extended_attributes = Some(attrs);
        if attrs & EXT_CHECKSUM != 0 {
            checksum = record.get(data_end + 1).copied();
        }
    }
    Ok(Body {
        name,
        guid,
        data: position..data_end,
        extended_attributes,
        checksum,
    })
}

/// The records of one variable: the head, then each linked update.
fn follow_chain(
    head: usize,
    entries: &[Entry],
    by_offset: &HashMap<usize, usize>,
    claimed: &mut [bool],
    label: &str,
    base: usize,
    issues: &mut Vec<Issue>,
) -> Vec<usize> {
    let mut chain = vec![head];
    let mut current = head;
    while let Some(target) = entries[current].next {
        let problem = match by_offset.get(&target) {
            None => format!("next record: expected a record start | received {target:#x}"),
            Some(&index) if entries[index].attributes & FLAG_DATA_ONLY == 0 => {
                format!(
                    "next record at {target:#x}: expected a data-only record | received a variable record"
                )
            }
            // Every chain member after the head is claimed and the head is a variable record,
            // which the arm above rejects, so `claimed` alone detects every loop in O(1).
            Some(&index) if claimed[index] => {
                format!(
                    "next record at {target:#x}: expected an unvisited record | received a loop"
                )
            }
            Some(&index) => {
                claimed[index] = true;
                chain.push(index);
                current = index;
                continue;
            }
        };
        issues.push(Issue {
            store: label.to_owned(),
            offset: base + entries[current].offset,
            message: problem,
        });
        break;
    }
    chain
}

/// Derived EFI attributes and flag names for a variable record.
fn describe(attributes: u8, extended: Option<u8>) -> (u32, Vec<&'static str>) {
    let mut efi = EFI_NON_VOLATILE | EFI_BOOTSERVICE;
    if attributes & FLAG_RUNTIME != 0 {
        efi |= EFI_RUNTIME;
    }
    if attributes & FLAG_AUTH_WRITE != 0 || extended.is_some_and(|e| e & EXT_AUTH_WRITE != 0) {
        efi |= EFI_AUTH_WRITE;
    }
    if extended.is_some_and(|e| e & EXT_TIME_BASED != 0) {
        efi |= EFI_TIME_BASED;
    }
    let mut flags = flag_names(attributes);
    if let Some(extended) = extended {
        for (bit, name) in [
            (EXT_CHECKSUM, "ext_checksum"),
            (EXT_AUTH_WRITE, "ext_auth_write"),
            (EXT_TIME_BASED, "ext_time_based"),
        ] {
            if extended & bit != 0 {
                flags.push(name);
            }
        }
    }
    (efi, flags)
}

fn flag_names(attributes: u8) -> Vec<&'static str> {
    [
        (FLAG_RUNTIME, "runtime"),
        (FLAG_ASCII_NAME, "ascii_name"),
        (FLAG_GUID, "inline_guid"),
        (FLAG_DATA_ONLY, "data_only"),
        (FLAG_EXT_HEADER, "ext_header"),
        (FLAG_HW_ERROR, "hw_error_record"),
        (FLAG_AUTH_WRITE, "auth_write"),
        (FLAG_VALID, "valid"),
    ]
    .into_iter()
    .filter(|(bit, _)| attributes & bit != 0)
    .map(|(_, name)| name)
    .collect()
}
