//! SMBIOS structure table decoder (DMTF DSP0134) for the facts `bme diag smbios` reports.
//!
//! The input is the raw structure table as Linux exposes it in
//! `/sys/firmware/dmi/tables/DMI`: structures back to back, each a formatted area
//! (type, length, handle, fields) followed by a string set ended by a double NUL.
//! The decoder reads types 0 (BIOS), 1 (system), 2 (baseboard) and 17 (memory
//! device) and stops at type 127. Everything else is skipped by length.
//!
//! Rules:
//! - No I/O: callers pass bytes.
//! - Fields past a structure's declared length are `None`, never read: older
//!   firmware ships shorter structures.
//! - Serial numbers, UUIDs, asset tags and the SKU are not decoded. A report built
//!   from this module cannot leak them.
//! - Malformed input is `FORMAT_INVALID` naming the offset, never a panic or a
//!   silent partial result.

use crate::{Code, Error, Result};
use serde::Serialize;

/// BIOS Information (type 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BiosInformation {
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub release_date: Option<String>,
    /// Size of the BIOS ROM in KiB, from the 64 KiB-step field.
    pub rom_size_kib: Option<u64>,
}

/// System Information (type 1), without serial number, UUID or SKU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemInformation {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub version: Option<String>,
    pub family: Option<String>,
}

/// Baseboard Information (type 2), without serial number or asset tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseboardInformation {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// Memory Device (type 17): one DIMM slot, populated or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryDevice {
    pub handle: u16,
    /// Width in bits including check bits; `None` when unknown.
    pub total_width_bits: Option<u16>,
    /// Width in bits of the data path; `None` when unknown.
    pub data_width_bits: Option<u16>,
    /// `Some(0)` is an empty slot; `None` is unknown or not reported.
    pub size_kib: Option<u64>,
    pub form_factor: Option<String>,
    pub device_locator: Option<String>,
    pub bank_locator: Option<String>,
    pub memory_type: Option<String>,
    /// Rated speed in MT/s.
    pub speed_mts: Option<u32>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub rank: Option<u8>,
    /// Speed the module runs at, in MT/s.
    pub configured_speed_mts: Option<u32>,
}

/// What the table says about the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Smbios {
    pub bios: Option<BiosInformation>,
    pub system: Option<SystemInformation>,
    pub baseboard: Option<BaseboardInformation>,
    pub memory_devices: Vec<MemoryDevice>,
    /// Structures walked, including skipped types and the end marker.
    pub structures: usize,
}

/// One structure: its type, handle, formatted area and string set.
struct Structure<'a> {
    kind: u8,
    handle: u16,
    /// The whole formatted area, header included, so offsets match the specification.
    area: &'a [u8],
    strings: Vec<String>,
}

impl Structure<'_> {
    fn byte(&self, offset: usize) -> Option<u8> {
        self.area.get(offset).copied()
    }

    fn word(&self, offset: usize) -> Option<u16> {
        let bytes = self.area.get(offset..offset + 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn dword(&self, offset: usize) -> Option<u32> {
        let bytes = self.area.get(offset..offset + 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// The string a one-based index byte at `offset` selects; `None` for 0, an
    /// index with no string, an empty string or a field the structure lacks.
    fn string(&self, offset: usize) -> Option<String> {
        let index = usize::from(self.byte(offset)?);
        let text = self.strings.get(index.checked_sub(1)?)?;
        (!text.is_empty()).then(|| text.clone())
    }
}

/// Split the table into structures, stopping after type 127.
///
/// A table that ends on a structure boundary without type 127 is accepted; one that
/// ends inside a structure is not.
fn walk(table: &[u8]) -> Result<Vec<Structure<'_>>> {
    let mut structures = Vec::new();
    let mut offset = 0;
    while offset < table.len() {
        let invalid = |expected: &str, received: String| {
            Error::new(
                Code::FormatInvalid,
                format!(
                    "smbios structure at offset {offset:#x}: expected {expected} | received {received}"
                ),
            )
        };
        let header = table.get(offset..offset + 4).ok_or_else(|| {
            invalid(
                "a 4-byte header",
                format!("{} bytes left", table.len() - offset),
            )
        })?;
        let (kind, length, handle) = (
            header[0],
            usize::from(header[1]),
            u16::from_le_bytes([header[2], header[3]]),
        );
        if length < 4 {
            return Err(invalid(
                "a formatted length of at least 4",
                length.to_string(),
            ));
        }
        let area = table.get(offset..offset + length).ok_or_else(|| {
            invalid(
                &format!("{length} bytes of formatted area"),
                format!("{} bytes left", table.len() - offset),
            )
        })?;
        // The string set: NUL-terminated strings, ended by an empty one. With no
        // strings it is two NULs.
        let mut cursor = offset + length;
        let mut strings = Vec::new();
        loop {
            let rest = table.get(cursor..).unwrap_or_default();
            let end = rest.iter().position(|&b| b == 0).ok_or_else(|| {
                invalid(
                    "the string set ended by a double NUL",
                    format!("the table ended at offset {:#x}", table.len()),
                )
            })?;
            if end == 0 {
                cursor += 1;
                // A structure without strings has a second NUL right after the first.
                if strings.is_empty() {
                    if table.get(cursor) != Some(&0) {
                        return Err(invalid(
                            "a second NUL after a structure without strings",
                            table
                                .get(cursor)
                                .map_or("the end of the table".into(), |b| format!("{b:#04x}")),
                        ));
                    }
                    cursor += 1;
                }
                break;
            }
            strings.push(String::from_utf8_lossy(&rest[..end]).trim().to_string());
            cursor += end + 1;
        }
        structures.push(Structure {
            kind,
            handle,
            area,
            strings,
        });
        offset = cursor;
        if kind == 127 {
            break;
        }
    }
    Ok(structures)
}

fn memory_type_name(code: u8) -> Option<String> {
    let name = match code {
        0x01 => "Other",
        0x02 | 0x00 => return None,
        0x03 => "DRAM",
        0x0F => "SDRAM",
        0x12 => "DDR",
        0x13 => "DDR2",
        0x18 => "DDR3",
        0x1A => "DDR4",
        0x1B => "LPDDR",
        0x1C => "LPDDR2",
        0x1D => "LPDDR3",
        0x1E => "LPDDR4",
        0x1F => "Logical non-volatile device",
        0x20 => "HBM",
        0x21 => "HBM2",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        0x24 => "HBM3",
        other => return Some(format!("Unknown type {other:#04x}")),
    };
    Some(name.into())
}

fn form_factor_name(code: u8) -> Option<String> {
    let name = match code {
        0x00 | 0x02 => return None,
        0x01 => "Other",
        0x03 => "SIMM",
        0x09 => "DIMM",
        0x0A => "TSOP",
        0x0C => "RIMM",
        0x0D => "SODIMM",
        0x0F => "FB-DIMM",
        0x10 => "Die",
        other => return Some(format!("Unknown form factor {other:#04x}")),
    };
    Some(name.into())
}

/// Speed words: 0 is unknown, 0xFFFF defers to the 32-bit field at `extended`.
fn speed(structure: &Structure, offset: usize, extended: usize) -> Option<u32> {
    match structure.word(offset)? {
        0 => None,
        0xFFFF => structure.dword(extended).filter(|&mts| mts != 0),
        mts => Some(u32::from(mts)),
    }
}

/// The size field: 0 empty, 0xFFFF unknown, 0x7FFF defers to the extended size in MiB,
/// bit 15 means the value is in KiB.
fn size_kib(structure: &Structure) -> Option<u64> {
    match structure.word(0x0C)? {
        0xFFFF => None,
        0x7FFF => Some(u64::from(structure.dword(0x1C)? & 0x7FFF_FFFF) * 1024),
        raw if raw & 0x8000 != 0 => Some(u64::from(raw & 0x7FFF)),
        raw => Some(u64::from(raw) * 1024),
    }
}

fn width(structure: &Structure, offset: usize) -> Option<u16> {
    structure.word(offset).filter(|&bits| bits != 0xFFFF)
}

fn memory_device(structure: &Structure) -> MemoryDevice {
    MemoryDevice {
        handle: structure.handle,
        total_width_bits: width(structure, 0x08),
        data_width_bits: width(structure, 0x0A),
        size_kib: size_kib(structure),
        form_factor: structure.byte(0x0E).and_then(form_factor_name),
        device_locator: structure.string(0x10),
        bank_locator: structure.string(0x11),
        memory_type: structure.byte(0x12).and_then(memory_type_name),
        speed_mts: speed(structure, 0x15, 0x54),
        manufacturer: structure.string(0x17),
        part_number: structure.string(0x1A),
        rank: structure.byte(0x1B).map(|r| r & 0x0F).filter(|&r| r != 0),
        configured_speed_mts: speed(structure, 0x20, 0x58),
    }
}

/// Decode the structure table.
///
/// Intent: turn the bytes the kernel exposes into the identity and memory facts a
/// diagnostic reports, with an unknown field as `None`.
///
/// Example: `parse(&std::fs::read("/sys/firmware/dmi/tables/DMI")?)?.memory_devices[0].total_width_bits`
/// is `Some(72)` on a board whose first slot holds a 72-bit module.
pub fn parse(table: &[u8]) -> Result<Smbios> {
    let structures = walk(table)?;
    let mut smbios = Smbios {
        bios: None,
        system: None,
        baseboard: None,
        memory_devices: Vec::new(),
        structures: structures.len(),
    };
    for structure in &structures {
        match structure.kind {
            0 if smbios.bios.is_none() => {
                smbios.bios = Some(BiosInformation {
                    vendor: structure.string(0x04),
                    version: structure.string(0x05),
                    release_date: structure.string(0x08),
                    rom_size_kib: structure
                        .byte(0x09)
                        .filter(|&n| n != 0xFF)
                        .map(|n| (u64::from(n) + 1) * 64),
                });
            }
            1 if smbios.system.is_none() => {
                smbios.system = Some(SystemInformation {
                    manufacturer: structure.string(0x04),
                    product_name: structure.string(0x05),
                    version: structure.string(0x06),
                    family: structure.string(0x1A),
                });
            }
            2 if smbios.baseboard.is_none() => {
                smbios.baseboard = Some(BaseboardInformation {
                    manufacturer: structure.string(0x04),
                    product: structure.string(0x05),
                    version: structure.string(0x06),
                });
            }
            17 => smbios.memory_devices.push(memory_device(structure)),
            _ => {}
        }
    }
    Ok(smbios)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::{
        SMBIOS_SECRET, SmbiosSlot, smbios_fixture_structures, smbios_memory_device,
        smbios_structure, smbios_table,
    };

    fn only_slot(slot: &SmbiosSlot) -> MemoryDevice {
        let mut table = smbios_memory_device(slot);
        table.extend(smbios_structure(127, 0xFFFF, &[], &[]));
        parse(&table).unwrap().memory_devices.remove(0)
    }

    #[test]
    fn the_fixture_decodes_identity_and_both_slots() {
        let smbios = parse(&smbios_table()).unwrap();
        assert_eq!(smbios.structures, 7);
        let bios = smbios.bios.unwrap();
        assert_eq!(bios.vendor.as_deref(), Some("Synthetic Firmware Vendor"));
        assert_eq!(bios.version.as_deref(), Some("5.11"));
        assert_eq!(bios.release_date.as_deref(), Some("03/22/2023"));
        assert_eq!(bios.rom_size_kib, Some(8192));
        let system = smbios.system.unwrap();
        assert_eq!(system.manufacturer.as_deref(), Some("SYNTHETIC"));
        assert_eq!(system.product_name.as_deref(), Some("Synthetic System"));
        assert_eq!(system.version.as_deref(), Some("V1"));
        assert_eq!(system.family.as_deref(), Some("Synthetic Family"));
        let board = smbios.baseboard.unwrap();
        assert_eq!(board.product.as_deref(), Some("Synthetic Board"));
        assert_eq!(board.version.as_deref(), Some("V1.2"));
        assert_eq!(smbios.memory_devices.len(), 2);
        let empty = &smbios.memory_devices[1];
        assert_eq!(empty.size_kib, Some(0));
        assert_eq!(empty.total_width_bits, None);
        assert_eq!(empty.memory_type, None);
        assert_eq!(empty.device_locator.as_deref(), Some("DIMM_B1"));
        assert_eq!(empty.manufacturer, None);
    }

    #[test]
    fn a_72_bit_type_17_decodes_as_72_by_72() {
        // MR9A finding R01: the board reports total and data width 72/72.
        let device = parse(&smbios_table()).unwrap().memory_devices.remove(0);
        assert_eq!(device.total_width_bits, Some(72));
        assert_eq!(device.data_width_bits, Some(72));
        assert_eq!(device.size_kib, Some(8 * 1024 * 1024));
        assert_eq!(device.memory_type.as_deref(), Some("DDR4"));
        assert_eq!(device.form_factor.as_deref(), Some("DIMM"));
        assert_eq!(device.device_locator.as_deref(), Some("DIMM_A1"));
        assert_eq!(device.bank_locator.as_deref(), Some("BANK 0"));
        assert_eq!(device.speed_mts, Some(2666));
        assert_eq!(device.configured_speed_mts, Some(2133));
        assert_eq!(device.manufacturer.as_deref(), Some("Synthetic Memory"));
        assert_eq!(device.part_number.as_deref(), Some("SYN-DDR4-8G"));
        assert_eq!(device.rank, Some(1));
        assert_eq!(device.handle, 0x1100);
    }

    #[test]
    fn serials_uuids_and_asset_tags_never_reach_the_decoded_report() {
        let json = serde_json::to_string(&parse(&smbios_table()).unwrap()).unwrap();
        assert!(!json.contains(SMBIOS_SECRET), "{json}");
        assert!(
            !json.contains("1111"),
            "UUID bytes must not be decoded: {json}"
        );
        assert!(!json.contains("SKU-1"), "{json}");
    }

    #[test]
    fn size_words_cover_mib_kib_extended_unknown_and_empty() {
        let size = |size_word, extended_size_mib| {
            only_slot(&SmbiosSlot {
                size_word,
                extended_size_mib,
                ..SmbiosSlot::populated_72_bit()
            })
            .size_kib
        };
        assert_eq!(size(4096, 0), Some(4096 * 1024));
        assert_eq!(size(0x8000 | 512, 0), Some(512));
        assert_eq!(size(0x7FFF, 32768), Some(32768 * 1024));
        assert_eq!(size(0xFFFF, 0), None);
        assert_eq!(size(0, 0), Some(0));
    }

    #[test]
    fn speed_words_cover_unknown_and_extended() {
        let speeds = |speed, configured_speed| {
            let device = only_slot(&SmbiosSlot {
                speed,
                configured_speed,
                ..SmbiosSlot::populated_72_bit()
            });
            (device.speed_mts, device.configured_speed_mts)
        };
        assert_eq!(speeds(0, 0), (None, None));
        assert_eq!(speeds(3200, 2933), (Some(3200), Some(2933)));
        // 0xFFFF defers to the 32-bit fields, which the fixture leaves zero.
        assert_eq!(speeds(0xFFFF, 0xFFFF), (None, None));
    }

    #[test]
    fn unknown_type_and_form_factor_codes_are_named_not_dropped() {
        let device = only_slot(&SmbiosSlot {
            memory_type: 0x77,
            form_factor: 0x66,
            ..SmbiosSlot::populated_72_bit()
        });
        assert_eq!(device.memory_type.as_deref(), Some("Unknown type 0x77"));
        assert_eq!(
            device.form_factor.as_deref(),
            Some("Unknown form factor 0x66")
        );
        assert_eq!(memory_type_name(0x22).as_deref(), Some("DDR5"));
        assert_eq!(memory_type_name(0x18).as_deref(), Some("DDR3"));
        assert_eq!(form_factor_name(0x0D).as_deref(), Some("SODIMM"));
    }

    #[test]
    fn fields_past_a_short_structure_are_none_not_read() {
        // A pre-2.3 type 17 is 0x15 bytes long: no speed, manufacturer or part number.
        let mut body = vec![0u8; 0x15 - 4];
        body[0x08 - 4..0x0A - 4].copy_from_slice(&64u16.to_le_bytes());
        body[0x0A - 4..0x0C - 4].copy_from_slice(&64u16.to_le_bytes());
        body[0x10 - 4] = 1;
        let mut table = smbios_structure(17, 7, &body, &["DIMM0"]);
        table.extend(smbios_structure(127, 0xFFFF, &[], &[]));
        let device = parse(&table).unwrap().memory_devices.remove(0);
        assert_eq!(device.total_width_bits, Some(64));
        assert_eq!(device.device_locator.as_deref(), Some("DIMM0"));
        assert_eq!(device.speed_mts, None);
        assert_eq!(device.manufacturer, None);
        assert_eq!(device.part_number, None);
        assert_eq!(device.rank, None);
        assert_eq!(device.configured_speed_mts, None);
        assert_eq!(device.size_kib, Some(0));
    }

    #[test]
    fn string_indexes_without_a_string_are_none() {
        // The system structure names string 5 but carries one.
        let mut body = vec![0u8; 0x08 - 4];
        body[0x04 - 4] = 1;
        body[0x05 - 4] = 5;
        let mut table = smbios_structure(1, 1, &body, &["only"]);
        table.extend(smbios_structure(127, 0xFFFF, &[], &[]));
        let system = parse(&table).unwrap().system.unwrap();
        assert_eq!(system.manufacturer.as_deref(), Some("only"));
        assert_eq!(system.product_name, None);
        assert_eq!(system.family, None);
    }

    #[test]
    fn decoding_stops_at_type_127_and_ignores_what_follows() {
        let mut table = smbios_table();
        table.extend_from_slice(&[0xFF; 9]);
        assert_eq!(parse(&table).unwrap().structures, 7);
    }

    #[test]
    fn a_table_without_an_end_marker_is_accepted_on_a_structure_boundary() {
        let structures = smbios_fixture_structures();
        let table = structures[..6].concat();
        assert_eq!(parse(&table).unwrap().structures, 6);
        assert_eq!(parse(&[]).unwrap().structures, 0);
    }

    #[test]
    fn structures_without_strings_use_two_nuls_and_the_first_of_a_type_wins() {
        let mut table = smbios_structure(9, 9, &[0; 4], &[]);
        table.extend(smbios_structure(1, 1, &[1, 0, 0, 0], &["first"]));
        table.extend(smbios_structure(1, 2, &[1, 0, 0, 0], &["second"]));
        let smbios = parse(&table).unwrap();
        assert_eq!(smbios.structures, 3);
        assert_eq!(
            smbios.system.unwrap().manufacturer.as_deref(),
            Some("first")
        );
    }

    #[test]
    fn every_truncation_inside_a_structure_is_format_invalid_with_its_offset() {
        let structures = smbios_fixture_structures();
        let table = structures.concat();
        let mut boundaries = vec![0usize];
        for structure in &structures {
            boundaries.push(boundaries.last().unwrap() + structure.len());
        }
        for cut in 0..=table.len() {
            let result = parse(&table[..cut]);
            if boundaries.contains(&cut) {
                assert!(
                    result.is_ok(),
                    "(cut at {cut}): expected a clean boundary to parse"
                );
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code, Code::FormatInvalid, "cut at {cut}: {error}");
                assert!(
                    error.message.contains("smbios structure at offset 0x"),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn a_formatted_length_under_four_is_refused_naming_the_value() {
        let error = parse(&[1, 3, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error
                .message
                .contains("expected a formatted length of at least 4 | received 3"),
            "{error}"
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A cheap deterministic fuzz: every prefix of noise, at several seeds.
        for seed in 0u32..64 {
            let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
            let bytes: Vec<u8> = (0..300)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect();
            for end in 0..bytes.len() {
                let _ = parse(&bytes[..end]);
            }
        }
    }
}
