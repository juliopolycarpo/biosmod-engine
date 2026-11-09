//! Parse UEFI PI firmware volumes, FFS files and sections.
//!
//! Supported: FFSv2/FFSv3 volumes, ordinary and extended section headers,
//! LZMA and CRC32 GUID-defined sections and nested firmware-volume sections,
//! the subset exercised by the reference AMI Aptio images. Other
//! encapsulations (EFI/Tiano compression, unknown GUID-defined sections) are
//! kept as opaque leaves, flagged, and never rewritten.
//!
//! Example:
//! ```no_run
//! # fn main() -> biosmod_core::Result<()> {
//! let image = biosmod_core::firmware::Image::parse(std::fs::read("bios.bin").unwrap())?;
//! for volume in &image.volumes {
//!     println!("FV at {:#x} with {} files", volume.offset, volume.files.len());
//! }
//! # Ok(()) }
//! ```

pub mod pe;
pub mod rebuild;

use crate::codec;
use crate::error::{Code, Error, Result};
use crate::util::{Guid, align, le16, le24, le32, le64, sum8};
use std::collections::BTreeMap;

pub const FFS2_GUID: Guid = Guid::constant("8C8CE578-8A3D-4F1C-9935-896185C32DD3");
pub const FFS3_GUID: Guid = Guid::constant("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A");
pub const LZMA_GUID: Guid = Guid::constant("EE4E5898-3914-4259-9D6E-DC7BD79403CF");
pub const CRC32_GUID: Guid = Guid::constant("FC1BCDB0-7D31-49AA-936A-A4600D9DD083");
pub const VTF_GUID: Guid = Guid::constant("1BA0062E-C779-4582-8566-336AE8F78F09");

pub const SECTION_COMPRESSION: u8 = 0x01;
pub const SECTION_GUID_DEFINED: u8 = 0x02;
pub const SECTION_PE32: u8 = 0x10;
pub const SECTION_TE: u8 = 0x12;
pub const SECTION_UI: u8 = 0x15;
pub const SECTION_FV_IMAGE: u8 = 0x17;
pub const SECTION_RAW: u8 = 0x19;

pub const FILE_RAW: u8 = 0x01;
pub const FILE_PAD: u8 = 0xF0;
pub const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
pub const FFS_ATTRIB_DATA_ALIGNMENT_2: u8 = 0x02;
pub const FFS_ATTRIB_FIXED: u8 = 0x04;
pub const FFS_ATTRIB_CHECKSUM: u8 = 0x40;

/// Maximum combined nesting of sections and volumes.
pub const MAX_DEPTH: usize = 16;
/// Maximum bytes decoded from all LZMA sections of one image.
pub const MAX_TOTAL_DECODED: usize = 512 << 20;

/// A decoded encapsulation: its plain stream and the sections inside it.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub children: Vec<Section>,
}

/// One PI section at `offset` within its containing stream.
#[derive(Debug, Clone)]
pub struct Section {
    pub offset: usize,
    pub size: usize,
    pub kind: u8,
    pub header_size: usize,
    /// GUID of a GUID-defined section.
    pub guid: Option<Guid>,
    /// Payload start, relative to the section, for GUID-defined sections.
    pub data_offset: usize,
    /// Set for LZMA and CRC32 GUID-defined sections.
    pub decoded: Option<Decoded>,
    /// Set for firmware-volume image sections.
    pub volumes: Option<Vec<Volume>>,
    /// For CRC32 sections: whether the stored CRC matched.
    pub crc_valid: Option<bool>,
}

impl Section {
    /// Section bytes, given the stream that contains it.
    pub fn raw<'a>(&self, stream: &'a [u8]) -> &'a [u8] {
        &stream[self.offset..self.offset + self.size]
    }

    /// Bytes after the common header.
    pub fn body<'a>(&self, stream: &'a [u8]) -> &'a [u8] {
        &stream[self.offset + self.header_size..self.offset + self.size]
    }

    /// True when the reference packer treats this section as a leaf.
    pub fn is_leaf(&self) -> bool {
        self.decoded.is_none() && self.volumes.as_ref().is_none_or(|v| v.is_empty())
    }

    /// True for encapsulations this engine cannot see into.
    pub fn is_opaque(&self) -> bool {
        self.kind == SECTION_COMPRESSION
            || (self.kind == SECTION_GUID_DEFINED && self.decoded.is_none())
    }
}

/// One FFS file at `offset` within its volume's buffer.
#[derive(Debug, Clone)]
pub struct FfsFile {
    pub offset: usize,
    pub header_size: usize,
    pub size: usize,
    pub guid: Guid,
    pub kind: u8,
    pub attributes: u8,
    pub sections: Vec<Section>,
    /// True when any section in the tree is an opaque encapsulation.
    pub opaque: bool,
}

impl FfsFile {
    /// Size rounded up to the 8-byte file alignment.
    pub fn extent(&self) -> usize {
        align(self.size, 8)
    }

    /// Header bytes, given the containing buffer.
    pub fn header<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        &buffer[self.offset..self.offset + self.header_size]
    }

    /// Body bytes (the section stream), given the containing buffer.
    pub fn body<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        &buffer[self.offset + self.header_size..self.offset + self.size]
    }
}

/// One firmware volume at `offset` within its containing buffer.
#[derive(Debug, Clone)]
pub struct Volume {
    pub offset: usize,
    pub length: usize,
    pub header_size: usize,
    pub filesystem: Guid,
    pub files: Vec<FfsFile>,
    /// First byte after the last file (start of erased space).
    pub free_start: usize,
}

impl Volume {
    /// Bytes from the free-space start to the volume end.
    pub fn free_bytes(&self) -> usize {
        (self.offset + self.length).saturating_sub(self.free_start)
    }
}

/// Address of one leaf section: volume and file indices plus the section path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRef {
    pub volume: usize,
    pub file: usize,
    pub path: Vec<usize>,
    /// True when the path passes through an LZMA section.
    pub compressed: bool,
}

/// A parsed firmware image: a full SPI dump or a BIOS region.
#[derive(Debug, Clone)]
pub struct Image {
    pub bytes: Vec<u8>,
    pub volumes: Vec<Volume>,
    /// Leaf sections of top-level files, by file GUID, in image order.
    pub leaves: BTreeMap<Guid, Vec<LeafRef>>,
}

struct Budget {
    decoded: usize,
}

impl Image {
    /// Parse an image, validating every volume header and FFS checksum.
    pub fn parse(bytes: Vec<u8>) -> Result<Image> {
        let mut budget = Budget { decoded: 0 };
        let volumes = find_volumes(&bytes, false, 0, &mut budget)?;
        if volumes.is_empty() {
            return Err(Error::new(
                Code::FormatUnsupported,
                "image: expected at least one UEFI firmware volume (_FVH) | received none",
            ));
        }
        let mut leaves: BTreeMap<Guid, Vec<LeafRef>> = BTreeMap::new();
        for (v, volume) in volumes.iter().enumerate() {
            for (f, file) in volume.files.iter().enumerate() {
                walk(
                    &file.sections,
                    &mut Vec::new(),
                    false,
                    &mut |path, _, compressed| {
                        leaves.entry(file.guid).or_default().push(LeafRef {
                            volume: v,
                            file: f,
                            path: path.to_vec(),
                            compressed,
                        });
                    },
                );
            }
        }
        Ok(Image {
            bytes,
            volumes,
            leaves,
        })
    }

    /// The file holding a leaf.
    pub fn file(&self, leaf: &LeafRef) -> &FfsFile {
        &self.volumes[leaf.volume].files[leaf.file]
    }

    /// The leaf section and the stream that contains it.
    pub fn section(&self, leaf: &LeafRef) -> (&Section, &[u8]) {
        let file = self.file(leaf);
        locate(&file.sections, file.body(&self.bytes), &leaf.path)
    }

    /// The leaf section's body.
    pub fn leaf_body(&self, leaf: &LeafRef) -> &[u8] {
        let (section, stream) = self.section(leaf);
        section.body(stream)
    }

    /// Flash address of image offset 0, with the BIOS region mapped to end at 4 GiB.
    ///
    /// A full SPI dump maps its descriptor BIOS region below 4 GiB; a BIOS-only
    /// image ends at 4 GiB itself.
    ///
    /// Example: `let address = image.flash_base() + file.offset as u64;`
    pub fn flash_base(&self) -> u64 {
        let end = descriptor_regions(&self.bytes)
            .and_then(|regions| regions.into_iter().find(|r| r.name == "bios"))
            .map_or(self.bytes.len(), |bios| bios.end);
        (1u64 << 32).wrapping_sub(end as u64)
    }

    /// The UI name of a file, if it has a UI section.
    pub fn ui_name(&self, volume: usize, file: usize) -> Option<String> {
        let file = &self.volumes[volume].files[file];
        let mut name = None;
        let body = file.body(&self.bytes);
        visit(&file.sections, body, &mut |section, stream| {
            if name.is_none() && section.kind == SECTION_UI && section.is_leaf() {
                let units: Vec<u16> = section
                    .body(stream)
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|u| *u != 0)
                    .collect();
                name = Some(String::from_utf16_lossy(&units));
            }
        });
        name
    }
}

/// Resolve a section path within a section list.
pub fn locate<'a>(
    sections: &'a [Section],
    stream: &'a [u8],
    path: &[usize],
) -> (&'a Section, &'a [u8]) {
    let mut sections = sections;
    let mut stream = stream;
    for (depth, index) in path.iter().enumerate() {
        let section = &sections[*index];
        if depth + 1 == path.len() {
            return (section, stream);
        }
        let decoded = section
            .decoded
            .as_ref()
            .expect("leaf path passes through a decoded section");
        sections = &decoded.children;
        stream = &decoded.bytes;
    }
    unreachable!("empty leaf path")
}

/// Call `visit` for every leaf as `(path, section, compressed)`, like the reference walker.
pub fn walk(
    sections: &[Section],
    prefix: &mut Vec<usize>,
    compressed: bool,
    visit: &mut dyn FnMut(&[usize], &Section, bool),
) {
    for (index, section) in sections.iter().enumerate() {
        prefix.push(index);
        if let Some(decoded) = &section.decoded {
            let inner = compressed || section.guid == Some(LZMA_GUID);
            walk(&decoded.children, prefix, inner, visit);
        } else if section.is_leaf() {
            visit(prefix, section, compressed);
        }
        prefix.pop();
    }
}

fn visit(sections: &[Section], stream: &[u8], f: &mut dyn FnMut(&Section, &[u8])) {
    for section in sections {
        f(section, stream);
        if let Some(decoded) = &section.decoded {
            visit(&decoded.children, &decoded.bytes, f);
        }
    }
}

/// Wrapping sum of the 16-bit little-endian words in `data`.
///
/// Example: `assert_eq!(checksum16(&[1, 0, 2, 0]), 3);`
pub fn checksum16(data: &[u8]) -> u16 {
    data.as_chunks::<2>().0.iter().fold(0u16, |acc, w| {
        acc.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
    })
}

/// True when 16-bit little-endian words sum to zero, as the FV header requires.
pub fn checksum16_ok(data: &[u8]) -> bool {
    checksum16(data) == 0
}

fn find_volumes(
    buffer: &[u8],
    nested: bool,
    depth: usize,
    budget: &mut Budget,
) -> Result<Vec<Volume>> {
    let mut volumes = Vec::new();
    let mut cursor = 0usize;
    while let Some(hit) = find(buffer, b"_FVH", cursor) {
        let parsed = if hit >= 40 {
            parse_volume(buffer, hit - 40, depth, budget)?
        } else {
            None
        };
        let Some(volume) = parsed else {
            cursor = hit + 4;
            continue;
        };
        cursor = volume.offset + volume.length;
        let empty = volume.length == 0;
        volumes.push(volume);
        if nested && empty {
            break;
        }
    }
    Ok(volumes)
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn parse_volume(
    buffer: &[u8],
    offset: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<Option<Volume>> {
    if offset + 56 > buffer.len() || &buffer[offset + 40..offset + 44] != b"_FVH" {
        return Ok(None);
    }
    let length = le64(buffer, offset + 32, "FV length")?;
    let header_size = usize::from(le16(buffer, offset + 48, "FV header length")?);
    let Ok(length) = usize::try_from(length) else {
        return Ok(None);
    };
    if !(56 <= header_size && header_size <= length)
        || offset
            .checked_add(length)
            .is_none_or(|end| end > buffer.len())
    {
        return Ok(None);
    }
    if !checksum16_ok(&buffer[offset..offset + header_size]) {
        return Ok(None);
    }
    let filesystem = Guid::from_slice(&buffer[offset + 16..offset + 32]);
    if filesystem != FFS2_GUID && filesystem != FFS3_GUID {
        return Ok(Some(Volume {
            offset,
            length,
            header_size,
            filesystem,
            files: Vec::new(),
            free_start: offset + header_size,
        }));
    }
    if !offset.is_multiple_of(8) {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("FFS volume at {offset:#x}: expected an 8-byte aligned volume offset"),
        ));
    }
    if depth >= MAX_DEPTH {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("FV at {offset:#x}: nesting exceeds {MAX_DEPTH} levels"),
        ));
    }
    let ext_offset = usize::from(le16(buffer, offset + 52, "FV extended header offset")?);
    let mut start = offset + header_size;
    if ext_offset != 0 {
        let ext_size = le32(buffer, offset + ext_offset + 16, "FV extended header size")? as usize;
        let ext_end = (offset + ext_offset)
            .checked_add(ext_size)
            .filter(|end| *end <= offset + length);
        let Some(ext_end) = ext_end else {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "FV at {offset:#x}: extended header ({ext_offset:#x} + {ext_size:#x}) | expected within the volume length {length:#x}"
                ),
            ));
        };
        start = start.max(ext_end);
    }
    let (files, free_start) =
        parse_files(buffer, align(start, 8), offset + length, depth + 1, budget)?;
    Ok(Some(Volume {
        offset,
        length,
        header_size,
        filesystem,
        files,
        free_start,
    }))
}

fn parse_files(
    buffer: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Vec<FfsFile>, usize)> {
    let mut files = Vec::new();
    let mut cursor = start;
    while cursor + 24 <= end {
        let header = &buffer[cursor..cursor + 24];
        if header.iter().all(|b| *b == 0xFF) {
            break;
        }
        let attributes = header[19];
        let mut size = le24(header, 20, "FFS size")? as usize;
        let mut header_size = 24;
        if attributes & FFS_ATTRIB_LARGE_FILE != 0 {
            if cursor + 32 > end {
                return Err(Error::new(
                    Code::FormatInvalid,
                    format!("FFS file at {cursor:#x}: truncated extended header"),
                ));
            }
            size = usize::try_from(le64(buffer, cursor + 24, "FFS extended size")?)
                .unwrap_or(usize::MAX);
            header_size = 32;
        }
        if size < header_size || cursor.checked_add(size).is_none_or(|e| e > end) {
            return Err(Error::new(
                Code::FormatInvalid,
                format!("FFS file at {cursor:#x}: size {size:#x} exceeds volume end {end:#x}"),
            ));
        }
        let full_header = &buffer[cursor..cursor + header_size];
        // State and the data-checksum byte do not participate in the header sum.
        if sum8(full_header)
            .wrapping_sub(full_header[17])
            .wrapping_sub(full_header[23])
            != 0
        {
            return Err(Error::new(
                Code::FormatInvalid,
                format!("FFS file at {cursor:#x}: invalid header checksum"),
            ));
        }
        let body = &buffer[cursor + header_size..cursor + size];
        if attributes & FFS_ATTRIB_CHECKSUM != 0 {
            if sum8(body).wrapping_add(full_header[17]) != 0 {
                return Err(Error::new(
                    Code::FormatInvalid,
                    format!("FFS file at {cursor:#x}: invalid data checksum"),
                ));
            }
        } else if full_header[17] != 0xAA {
            return Err(Error::new(
                Code::FormatInvalid,
                format!("FFS file at {cursor:#x}: expected fixed data checksum 0xaa"),
            ));
        }
        let kind = header[18];
        let sections = if kind != FILE_PAD && kind != FILE_RAW {
            parse_stream(body, depth, budget)?
        } else {
            Vec::new()
        };
        let mut opaque = false;
        visit(&sections, body, &mut |s, _| opaque |= s.is_opaque());
        files.push(FfsFile {
            offset: cursor,
            header_size,
            size,
            guid: Guid::from_slice(header),
            kind,
            attributes,
            sections,
            opaque,
        });
        cursor = align(cursor + size, 8);
    }
    Ok((files, cursor))
}

/// Split a section stream, decoding LZMA, CRC32 and FV-image sections.
fn parse_stream(stream: &[u8], depth: usize, budget: &mut Budget) -> Result<Vec<Section>> {
    if depth > MAX_DEPTH {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("section nesting: expected at most {MAX_DEPTH} levels"),
        ));
    }
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= stream.len() {
        let rest = &stream[offset..];
        if rest.iter().all(|b| *b == 0) || rest.iter().all(|b| *b == 0xFF) {
            break;
        }
        let mut size = le24(stream, offset, "section size")? as usize;
        let mut header_size = 4;
        if size == 0xFF_FFFF {
            size = le32(stream, offset + 4, "extended section size")? as usize;
            header_size = 8;
        }
        if size < header_size || offset.checked_add(size).is_none_or(|e| e > stream.len()) {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "section at {offset:#x}: size {size:#x} exceeds stream {:#x}",
                    stream.len()
                ),
            ));
        }
        let mut section = Section {
            offset,
            size,
            kind: stream[offset + 3],
            header_size,
            guid: None,
            data_offset: 0,
            decoded: None,
            volumes: None,
            crc_valid: None,
        };
        decode_section(&mut section, stream, depth, budget)?;
        result.push(section);
        offset = align(offset + size, 4);
    }
    Ok(result)
}

fn decode_section(
    section: &mut Section,
    stream: &[u8],
    depth: usize,
    budget: &mut Budget,
) -> Result<()> {
    let raw = section.raw(stream);
    if section.kind == SECTION_FV_IMAGE {
        section.volumes = Some(find_volumes(
            &raw[section.header_size..],
            true,
            depth + 1,
            budget,
        )?);
        return Ok(());
    }
    if section.kind != SECTION_GUID_DEFINED {
        return Ok(());
    }
    let h = section.header_size;
    if raw.len() < h + 20 {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "GUID section at {:#x}: shorter than its 20-byte header",
                section.offset
            ),
        ));
    }
    let guid = Guid::from_slice(&raw[h..h + 16]);
    let data_offset = usize::from(le16(raw, h + 16, "GUID section data offset")?);
    section.guid = Some(guid);
    section.data_offset = data_offset;
    if guid != LZMA_GUID && guid != CRC32_GUID {
        return Ok(());
    }
    if data_offset < h + 20 || data_offset > raw.len() {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "GUID section at {:#x}: data offset {data_offset:#x} outside {:#x}..={:#x}",
                section.offset,
                h + 20,
                raw.len()
            ),
        ));
    }
    let payload = &raw[data_offset..];
    let decoded = if guid == LZMA_GUID {
        let plain = codec::decompress(payload)
            .map_err(|e| e.context(format!("LZMA section at {:#x}", section.offset)))?;
        budget.decoded = budget.decoded.saturating_add(plain.len());
        if budget.decoded > MAX_TOTAL_DECODED {
            return Err(Error::new(
                Code::FormatUnsupported,
                format!("image: decoded sections exceed {MAX_TOTAL_DECODED:#x} bytes"),
            ));
        }
        plain
    } else {
        if data_offset < h + 24 {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "CRC32 section at {:#x}: data offset {data_offset:#x} leaves no CRC32 field",
                    section.offset
                ),
            ));
        }
        let stored = le32(raw, h + 20, "CRC32")?;
        let actual = codec::crc32(payload);
        if stored != actual {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "CRC32 section at {:#x}: expected checksum {actual:#010x} | received {stored:#010x}",
                    section.offset
                ),
            ));
        }
        section.crc_valid = Some(true);
        payload.to_vec()
    };
    let children = parse_stream(&decoded, depth + 1, budget)?;
    section.decoded = Some(Decoded {
        bytes: decoded,
        children,
    });
    Ok(())
}

/// One Intel flash-descriptor region.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Region {
    pub name: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Regions from an Intel flash descriptor at the image start, if present.
pub fn descriptor_regions(image: &[u8]) -> Option<Vec<Region>> {
    if image.len() < 0x1000 || le32(image, 0x10, "descriptor signature").ok()? != 0x0FF0_A55A {
        return None;
    }
    let flmap0 = le32(image, 0x14, "FLMAP0").ok()?;
    let frba = (((flmap0 >> 16) & 0xFF) << 4) as usize;
    const NAMES: [&str; 5] = ["descriptor", "bios", "me", "gbe", "platform-data"];
    let mut regions = Vec::new();
    for (i, name) in NAMES.iter().enumerate() {
        let reg = le32(image, frba + i * 4, "FLREG").ok()?;
        let base = ((reg & 0x7FFF) as usize) << 12;
        let limit = (((reg >> 16) & 0x7FFF) as usize) << 12 | 0xFFF;
        if base <= limit && limit < image.len() {
            regions.push(Region {
                name,
                start: base,
                end: limit + 1,
            });
        }
    }
    Some(regions)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn checksum16_wraps_and_ignores_a_trailing_odd_byte() {
        assert_eq!(checksum16(&[1, 0, 2, 0]), 3);
        assert_eq!(checksum16(&[0xFF, 0xFF, 2, 0]), 1, "sum wraps at 16 bits");
        assert_eq!(checksum16(&[1, 0, 9]), 1, "odd trailing byte is ignored");
        assert!(checksum16_ok(&[1, 0, 0xFF, 0xFF]));
    }
}

#[cfg(test)]
mod unaligned_volume_regression {
    use super::*;
    use crate::synthetic::{DXE_GUID, ffs, section, volume};

    #[test]
    fn rejects_unaligned_volume_before_interpreting_file_offsets() {
        let file = ffs(DXE_GUID, 0x07, &section(SECTION_PE32, &[1; 20]), 0);
        let mut bytes = vec![0xff; 0x1001];
        bytes.extend(volume(&[file], 0x1000));
        let error = Image::parse(bytes).expect_err("unaligned volume must be refused");
        assert_eq!(error.code, Code::FormatUnsupported, "{error}");
        assert!(error.message.contains("0x1001"), "{error}");
        assert!(error.message.contains("8-byte aligned"), "{error}");
    }
}

#[cfg(test)]
mod crc_regression {
    use super::*;
    use crate::synthetic::{ffs, section, volume};

    fn image_with_crc(stored: u32, data_offset: u16) -> Vec<u8> {
        let payload = [4, 0, 0, SECTION_RAW];
        let mut body = Vec::new();
        body.extend_from_slice(&CRC32_GUID.0);
        body.extend_from_slice(&data_offset.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&stored.to_le_bytes());
        body.extend_from_slice(&payload);
        let file = ffs(
            CRC32_GUID,
            2,
            &section(SECTION_GUID_DEFINED, &body),
            FFS_ATTRIB_CHECKSUM,
        );
        volume(&[file], 0x1000)
    }

    #[test]
    fn rejects_invalid_crc32_section() {
        let payload = [4, 0, 0, SECTION_RAW];
        let actual = codec::crc32(&payload);
        let valid = Image::parse(image_with_crc(actual, 28)).expect("valid CRC and FFS checksums");
        assert_eq!(valid.volumes[0].files[0].sections[0].crc_valid, Some(true));
        let error = Image::parse(image_with_crc(0, 28)).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error.message.contains(&format!(
                "expected checksum {actual:#010x} | received 0x00000000"
            )),
            "{error}"
        );
    }

    #[test]
    fn rejects_crc32_section_without_checksum_field() {
        let error = Image::parse(image_with_crc(0, 24)).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error
                .message
                .contains("data offset 0x18 leaves no CRC32 field"),
            "{error}"
        );
    }
}
