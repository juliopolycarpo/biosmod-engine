//! HII package lists and string packages (UEFI spec 2.x, section 33.3).
//!
//! A package list is `GUID, u32 total length`, then packages (`u24 length, u8 type`
//! headers) ending with an end package (type 0xDF). The scanner accepts a candidate
//! only when that chain closes exactly on the declared length, so an unrelated byte
//! pattern in a PE image is rejected silently.

use crate::error::{Code, Error, Result};
use crate::util::{Guid, le16, le32, slice};
use std::collections::BTreeMap;

pub const PACKAGE_FORMS: u8 = 0x02;
pub const PACKAGE_STRINGS: u8 = 0x04;
pub const PACKAGE_END: u8 = 0xDF;
const PACKAGE_LIST_HEADER: usize = 20;
const PACKAGE_HEADER: usize = 4;
const STRING_PACKAGE_FIXED: usize = 46;

/// One package inside a list: its type and the byte range of the whole package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPackage {
    pub kind: u8,
    /// Offset of the package header within the scanned bytes.
    pub offset: usize,
    /// Package length including its 4-byte header.
    pub length: usize,
}

/// A package list that passed chain validation.
#[derive(Debug, Clone)]
pub struct RawList {
    pub offset: usize,
    pub guid: Guid,
    pub length: usize,
    pub packages: Vec<RawPackage>,
}

fn package_type_plausible(kind: u8) -> bool {
    matches!(kind, 0x01..=0x0B | PACKAGE_END | 0xE0..=0xFF)
}

/// Walk the package chain of a candidate list at `offset`; `None` unless it closes on its length.
fn validate_chain(data: &[u8], offset: usize) -> Option<RawList> {
    let length = u32::from_le_bytes(data.get(offset + 16..offset + 20)?.try_into().ok()?) as usize;
    let end = offset.checked_add(length)?;
    if length < PACKAGE_LIST_HEADER + PACKAGE_HEADER || end > data.len() {
        return None;
    }
    let mut packages = Vec::new();
    let mut at = offset + PACKAGE_LIST_HEADER;
    loop {
        let header = u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?);
        let (size, kind) = ((header & 0x00FF_FFFF) as usize, (header >> 24) as u8);
        if size < PACKAGE_HEADER || at + size > end || !package_type_plausible(kind) {
            return None;
        }
        packages.push(RawPackage {
            kind,
            offset: at,
            length: size,
        });
        at += size;
        if kind == PACKAGE_END {
            return (at == end).then(|| RawList {
                offset,
                guid: Guid::from_slice(&data[offset..offset + 16]),
                length,
                packages,
            });
        }
    }
}

/// Every well-formed HII package list in `data`, in offset order, without nesting.
///
/// Example: `let lists = biosmod_core::ifr::hii::find_package_lists(&[0u8; 8]); assert!(lists.is_empty());`
pub fn find_package_lists(data: &[u8]) -> Vec<RawList> {
    let mut lists = Vec::new();
    let mut at = 0;
    while at + PACKAGE_LIST_HEADER + PACKAGE_HEADER <= data.len() {
        // Cheap filter first: the first package header's type byte.
        if package_type_plausible(data[at + PACKAGE_LIST_HEADER + 3])
            && let Some(list) = validate_chain(data, at)
        {
            at += list.length;
            lists.push(list);
            continue;
        }
        at += 1;
    }
    lists
}

/// A decoded string package: language and its string table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPackage {
    pub language: String,
    pub strings: BTreeMap<u16, String>,
}

fn bad(package: usize, at: usize, what: impl std::fmt::Display) -> Error {
    Error::new(
        Code::FormatInvalid,
        format!("ifr string package at {package:#x}: {what} at {at:#x}"),
    )
}

/// NUL-terminated UCS-2 string at `at`; returns the text and the offset after the NUL.
fn read_ucs2(data: &[u8], at: usize, end: usize, package: usize) -> Result<(String, usize)> {
    let mut units = Vec::new();
    let mut cursor = at;
    loop {
        if cursor + 2 > end {
            return Err(bad(package, at, "unterminated UCS-2 string"));
        }
        let unit = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;
        if unit == 0 {
            return Ok((String::from_utf16_lossy(&units), cursor));
        }
        units.push(unit);
    }
}

/// NUL-terminated 8-bit string at `at`; bytes map to Latin-1 code points (SCSU is not expanded).
fn read_narrow(data: &[u8], at: usize, end: usize, package: usize) -> Result<(String, usize)> {
    let Some(len) = data
        .get(at..end)
        .and_then(|rest| rest.iter().position(|b| *b == 0))
    else {
        return Err(bad(package, at, "unterminated 8-bit string"));
    };
    let text = data[at..at + len].iter().map(|b| char::from(*b)).collect();
    Ok((text, at + len + 1))
}

/// Parse the fixed header; returns the language tag and the block offset within the package.
fn parse_string_header(data: &[u8], offset: usize, length: usize) -> Result<(String, usize)> {
    let package = slice(data, offset, length, "string package")?;
    let header_size = le32(package, 4, "string package header size")? as usize;
    let info = le32(package, 8, "string package block offset")? as usize;
    if header_size <= STRING_PACKAGE_FIXED || header_size > length || info > length {
        return Err(bad(
            offset,
            offset + 4,
            format!(
                "header size {header_size:#x} / block offset {info:#x}: expected {STRING_PACKAGE_FIXED:#x} < header <= {length:#x}"
            ),
        ));
    }
    let language_bytes = &package[STRING_PACKAGE_FIXED..header_size];
    let language_len = language_bytes.iter().position(|b| *b == 0).ok_or_else(|| {
        bad(
            offset,
            offset + STRING_PACKAGE_FIXED,
            "unterminated language tag",
        )
    })?;
    let language = String::from_utf8_lossy(&language_bytes[..language_len]).into_owned();
    Ok((language, info))
}

/// The language tag of the string package at `offset`, without decoding its strings.
///
/// Example: `let tag = biosmod_core::ifr::hii::string_package_language(&bytes, offset, length)?;`
pub fn string_package_language(data: &[u8], offset: usize, length: usize) -> Result<String> {
    parse_string_header(data, offset, length).map(|(language, _)| language)
}

/// Decode the string package occupying `data[offset..offset + length]`.
///
/// Handles the string blocks defined by the UEFI spec (SCSU and UCS-2, with or without
/// font, plus duplicate, skip and extension blocks). Font and unknown blocks are
/// `FormatInvalid` errors naming the block offset.
pub fn decode_string_package(data: &[u8], offset: usize, length: usize) -> Result<StringPackage> {
    let (language, info) = parse_string_header(data, offset, length)?;
    let end = offset + length;
    let mut strings = BTreeMap::new();
    let mut next_id: u32 = 1;
    let mut at = offset + info;
    let store = |strings: &mut BTreeMap<u16, String>, id: u32, text: String, at: usize| {
        let id = u16::try_from(id)
            .map_err(|_| bad(offset, at, format!("string id {id:#x}: expected <= 0xffff")))?;
        strings.insert(id, text);
        Ok::<(), Error>(())
    };
    while at < end {
        let block = data[at];
        let block_at = at;
        at += 1;
        match block {
            0x00 => break,
            0x10 | 0x11 | 0x14 | 0x15 => {
                if matches!(block, 0x11 | 0x15) {
                    at += 1; // font id
                }
                let (text, after) = if block <= 0x11 {
                    read_narrow(data, at, end, offset)?
                } else {
                    read_ucs2(data, at, end, offset)?
                };
                store(&mut strings, next_id, text, block_at)?;
                next_id += 1;
                at = after;
            }
            0x12 | 0x13 | 0x16 | 0x17 => {
                if matches!(block, 0x13 | 0x17) {
                    at += 1;
                }
                if at + 2 > end {
                    return Err(bad(offset, block_at, "string count cut off"));
                }
                let count = le16(data, at, "string count")?;
                at += 2;
                for _ in 0..count {
                    let (text, after) = if block <= 0x13 {
                        read_narrow(data, at, end, offset)?
                    } else {
                        read_ucs2(data, at, end, offset)?
                    };
                    store(&mut strings, next_id, text, block_at)?;
                    next_id += 1;
                    at = after;
                }
            }
            0x20 => {
                if at + 2 > end {
                    return Err(bad(offset, block_at, "duplicate block cut off"));
                }
                let source = le16(data, at, "duplicate id")?;
                at += 2;
                let text = strings.get(&source).cloned().unwrap_or_default();
                store(&mut strings, next_id, text, block_at)?;
                next_id += 1;
            }
            0x21 | 0x22 => {
                let width = if block == 0x21 { 2 } else { 1 };
                if at + width > end {
                    return Err(bad(offset, block_at, "skip block cut off"));
                }
                let skip = if width == 2 {
                    u32::from(le16(data, at, "skip count")?)
                } else {
                    u32::from(data[at])
                };
                at += width;
                next_id += skip;
            }
            0x30..=0x32 => {
                // Extension blocks store their own total length after the two type bytes.
                let (header, size) = match block {
                    0x30 => (3, data.get(at + 1).map(|b| usize::from(*b))),
                    0x31 => (4, le16(data, at + 1, "length").ok().map(usize::from)),
                    _ => (6, le32(data, at + 1, "length").ok().map(|v| v as usize)),
                };
                let size = size
                    .filter(|size| *size >= header)
                    .ok_or_else(|| bad(offset, block_at, "extension block length invalid"))?;
                at = block_at + size;
                if at > end {
                    return Err(bad(
                        offset,
                        block_at,
                        "extension block overruns the package",
                    ));
                }
            }
            other => {
                return Err(bad(
                    offset,
                    block_at,
                    format!(
                        "string block type {other:#04x}: expected 0x00, 0x10-0x17, 0x20-0x22 or 0x30-0x32"
                    ),
                ));
            }
        }
    }
    Ok(StringPackage { language, strings })
}
