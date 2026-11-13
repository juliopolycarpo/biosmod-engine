//! EDK II variable store (VSS/VSS2) walker.
//!
//! Store header, two spellings (UEFITool `nvram.h`, EDK II `VariableFormat.h`):
//!
//! ```text
//! GUID form (VSS2): GUID signature (16) | u32 size | u8 format 0x5A | u8 state 0xFE | u16 | u32   = 28 bytes
//! "$VSS" form:      "$VSS" (4)          | u32 size | u8 format 0x5A | u8 state 0xFE | u16 | u32   = 16 bytes
//! ```
//!
//! Variable header, 4-byte aligned, start marker `0x55AA`: plain (32 bytes: start id, state,
//! reserved, attributes, name size, data size, vendor GUID) or authenticated (60 bytes: the
//! attributes are followed by monotonic counter, 16-byte timestamp and public key index
//! before the sizes). The name is UCS-2 including its NUL, the data follows it.
//!
//! The state byte only ever clears bits: `0x3F` added, `0x3E` added and in deleted
//! transition, `0x3D` deleted, `0x7F` header valid only (never completed).

use super::{
    Draft, EFI_AUTH_WRITE, EFI_BOOTSERVICE, EFI_NON_VOLATILE, EFI_RUNTIME, EFI_TIME_BASED, Issue,
    NvramReport, RecordState, Store, StoreKind, ucs2_text,
};
use crate::util::{Guid, align};
use std::collections::HashMap;

const SIGNATURE_VSS: &[u8; 4] = b"$VSS";
/// `gEfiVariableGuid` (EDK II), VSS2 and FDC store signatures.
const PLAIN_STORE_GUIDS: [Guid; 2] = [
    Guid::constant("DDCF3616-3275-4164-98B6-FE85707FFE7D"),
    Guid::constant("DDCF3617-3275-4164-98B6-FE85707FFE7D"),
];
/// `gEfiAuthenticatedVariableGuid`: the store holds authenticated variable headers.
const AUTH_STORE_GUID: Guid = Guid::constant("AAF32C78-947B-439A-A180-2E144EC37792");

const START_ID: u16 = 0x55AA;
const FORMAT_FORMATTED: u8 = 0x5A;
const STATE_HEALTHY: u8 = 0xFE;
const PLAIN_HEADER: usize = 32;
const AUTH_HEADER: usize = 60;

/// True when `bytes` begins with a VSS or VSS2 store header.
pub(super) fn sniff(bytes: &[u8]) -> bool {
    bytes.starts_with(SIGNATURE_VSS)
        || (bytes.len() >= 28
            && (bytes[..16] == AUTH_STORE_GUID.0
                || PLAIN_STORE_GUIDS.iter().any(|g| bytes[..16] == g.0)))
}

/// What the state byte says about a record before duplicates are resolved.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Added,
    InTransition,
    Deleted,
    Incomplete,
}

struct Raw {
    offset: usize,
    phase: Phase,
    attributes: u32,
    name: String,
    guid: Guid,
    data: Vec<u8>,
}

/// Decode a VSS store whose first byte sits at image offset `base`.
pub(super) fn parse_store(
    bytes: &[u8],
    base: usize,
    file_guid: Option<Guid>,
    report: &mut NvramReport,
) {
    let label = format!("vss@{base:#x}");
    let mut issues = Vec::new();
    let mut issue = |offset: usize, message: String| {
        issues.push(Issue {
            store: label.clone(),
            offset: base + offset,
            message,
        });
    };
    let (store_header, guid_form) = if bytes.starts_with(SIGNATURE_VSS) {
        (16, false)
    } else {
        (28, true)
    };
    if bytes.len() < store_header {
        issue(
            0,
            format!(
                "store header: expected {store_header} bytes | received {}",
                bytes.len()
            ),
        );
        report.issues.extend(issues);
        return;
    }
    let declared = u32::from_le_bytes(
        bytes[4 + 12 * usize::from(guid_form)..][..4]
            .try_into()
            .unwrap(),
    ) as usize;
    let length = if (store_header..=bytes.len()).contains(&declared) {
        declared
    } else {
        issue(
            4 + 12 * usize::from(guid_form),
            format!(
                "store size: expected {store_header:#x}..={:#x} | received {declared:#x}",
                bytes.len()
            ),
        );
        bytes.len()
    };
    let area = &bytes[..length];
    let format = area[store_header - 8];
    let state = area[store_header - 7];
    if format != FORMAT_FORMATTED {
        issue(
            store_header - 8,
            format!("store format: expected {FORMAT_FORMATTED:#04x} | received {format:#04x}"),
        );
    }
    if state != STATE_HEALTHY {
        issue(
            store_header - 7,
            format!("store state: expected {STATE_HEALTHY:#04x} | received {state:#04x}"),
        );
    }
    let authenticated = if guid_form {
        area[..16] == AUTH_STORE_GUID.0
    } else {
        // "$VSS" does not say; take the header shape whose first record is plausible.
        !plausible_first(area, store_header, PLAIN_HEADER)
            && plausible_first(area, store_header, AUTH_HEADER)
    };
    let header_size = if authenticated {
        AUTH_HEADER
    } else {
        PLAIN_HEADER
    };

    let mut raws: Vec<Raw> = Vec::new();
    let mut offset = store_header;
    while offset + header_size <= area.len() {
        let start = u16::from_le_bytes([area[offset], area[offset + 1]]);
        if start == 0xFFFF {
            break;
        }
        if start != START_ID {
            issue(
                offset,
                format!("variable start marker: expected {START_ID:#06x} | received {start:#06x}"),
            );
            offset = resync(area, offset + 4, header_size);
            continue;
        }
        let field = |at: usize| u32::from_le_bytes(area[offset + at..][..4].try_into().unwrap());
        let (name_size, data_size, guid_at) = if authenticated {
            (field(36) as usize, field(40) as usize, 44)
        } else {
            (field(8) as usize, field(12) as usize, 16)
        };
        let room = area.len() - offset - header_size;
        if name_size < 2
            || !name_size.is_multiple_of(2)
            || name_size > room
            || data_size > room - name_size
        {
            issue(
                offset,
                format!(
                    "variable sizes: expected an even name size >= 2 and name + data <= {room:#x} | received name {name_size:#x}, data {data_size:#x}"
                ),
            );
            offset = resync(area, offset + 4, header_size);
            continue;
        }
        let name_at = offset + header_size;
        let data_at = name_at + name_size;
        raws.push(Raw {
            offset,
            phase: phase_of(area[offset + 2]),
            attributes: field(4),
            name: ucs2_text(&area[name_at..data_at]),
            guid: Guid::from_slice(&area[offset + guid_at..][..16]),
            data: area[data_at..data_at + data_size].to_vec(),
        });
        offset = align(data_at + data_size, 4);
    }

    let mut groups: HashMap<(String, Guid), Vec<usize>> = HashMap::new();
    for (index, raw) in raws.iter().enumerate() {
        groups
            .entry((raw.name.clone(), raw.guid))
            .or_default()
            .push(index);
    }
    let mut states = vec![RecordState::Deleted; raws.len()];
    let mut positions = vec![(0, 1); raws.len()];
    for members in groups.values() {
        // A completed update beats a record still in deleted transition (EDK II recovery).
        let winner = members
            .iter()
            .rev()
            .find(|i| raws[**i].phase == Phase::Added)
            .or_else(|| {
                members
                    .iter()
                    .rev()
                    .find(|i| raws[**i].phase == Phase::InTransition)
            })
            .copied();
        for (position, &index) in members.iter().enumerate() {
            positions[index] = (position, members.len());
            states[index] = match raws[index].phase {
                Phase::Deleted => RecordState::Deleted,
                Phase::Incomplete => RecordState::Incomplete,
                Phase::Added | Phase::InTransition if Some(index) == winner => RecordState::Active,
                Phase::Added | Phase::InTransition => RecordState::Superseded,
            };
        }
    }
    report.stores.push(Store {
        label: label.clone(),
        kind: StoreKind::Vss,
        offset: base,
        length,
        file_guid,
        defaults: None,
        guid_table_entries: 0,
        records: raws.len(),
    });
    for (index, raw) in raws.into_iter().enumerate() {
        report.variables.push(
            Draft {
                store: label.clone(),
                name: raw.name,
                guid: raw.guid,
                state: states[index],
                offset: base + raw.offset,
                attributes: raw.attributes,
                flags: flag_names(raw.attributes),
                extended_attributes: None,
                checksum: None,
                chain_index: positions[index].0,
                chain_len: positions[index].1,
                defaults: None,
                data: raw.data,
            }
            .finish(),
        );
    }
    report.issues.extend(issues);
}

fn phase_of(state: u8) -> Phase {
    if state & 0x02 == 0 {
        Phase::Deleted
    } else if state & 0xC0 != 0 {
        // 0x7F (header valid only) or an erased state byte: the record never completed.
        Phase::Incomplete
    } else if state & 0x01 == 0 {
        Phase::InTransition
    } else {
        Phase::Added
    }
}

/// True when the first variable header after the store header fits its store (or there is none).
fn plausible_first(area: &[u8], at: usize, header_size: usize) -> bool {
    let Some(header) = area.get(at..at + header_size) else {
        return true;
    };
    if u16::from_le_bytes([header[0], header[1]]) != START_ID {
        return true;
    }
    let (name_size, data_size) = if header_size == AUTH_HEADER {
        (36, 40)
    } else {
        (8, 12)
    };
    let name = u32::from_le_bytes(header[name_size..][..4].try_into().unwrap()) as usize;
    let data = u32::from_le_bytes(header[data_size..][..4].try_into().unwrap()) as usize;
    let room = area.len() - at - header_size;
    name >= 2 && name.is_multiple_of(2) && name <= room && data <= room - name
}

/// Next 4-aligned `0x55AA` marker at or after `from` with room for a header, else the end.
fn resync(area: &[u8], from: usize, header_size: usize) -> usize {
    let mut at = align(from, 4);
    while at + header_size <= area.len() {
        if u16::from_le_bytes([area[at], area[at + 1]]) == START_ID {
            return at;
        }
        at += 4;
    }
    area.len()
}

fn flag_names(attributes: u32) -> Vec<&'static str> {
    [
        (EFI_NON_VOLATILE, "non_volatile"),
        (EFI_BOOTSERVICE, "boot_service"),
        (EFI_RUNTIME, "runtime"),
        (0x08, "hw_error_record"),
        (EFI_AUTH_WRITE, "auth_write"),
        (EFI_TIME_BASED, "time_based_auth"),
        (0x40, "append_write"),
    ]
    .into_iter()
    .filter(|(bit, _)| attributes & bit != 0)
    .map(|(_, name)| name)
    .collect()
}
