//! Parse UEFI PI firmware volumes, FFS files and sections.
//!
//! Supported: FFSv2/FFSv3 volumes, ordinary and extended section headers,
//! nested firmware-volume sections and these encapsulations (see [`Encoding`]):
//! LZMA, CRC32, EFI 1.1 and Tiano compression sections, Brotli and LZMA F86
//! GUID-defined sections. Only LZMA and CRC32 content can be rebuilt; the
//! other encodings are decode-only. Remaining encapsulations (other
//! compression types, unknown GUID-defined sections) are kept as opaque
//! leaves, flagged, and never rewritten.
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
/// EDK II `BrotliCustomDecompress` GUID-defined section.
pub const BROTLI_GUID: Guid = Guid::constant("3D532050-5CDA-4FD0-879E-0F7F630D5AFB");
/// LZMA followed by the x86 BCJ filter (`LzmaF86Decompress`).
pub const LZMA_F86_GUID: Guid = Guid::constant("D42AE6BD-1352-4BFB-909A-CA72A6EAE889");
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
/// Maximum bytes decoded from all encapsulated sections of one image.
pub const MAX_TOTAL_DECODED: usize = 512 << 20;

/// How an encapsulating section stores its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// GUID-defined LZMA.
    Lzma,
    /// GUID-defined LZMA followed by the x86 BCJ filter.
    LzmaX86,
    /// GUID-defined CRC32 wrapper; the content is stored as is.
    Crc32,
    /// GUID-defined Brotli with the EDK II 16-byte header.
    Brotli,
    /// Compression section (type 01), EFI 1.1 bitstream.
    EfiCompression,
    /// Compression section (type 01), Tiano bitstream.
    TianoCompression,
}

impl Encoding {
    /// Short stable name, as reported in `bme inspect`.
    pub fn tag(self) -> &'static str {
        match self {
            Encoding::Lzma => "lzma",
            Encoding::LzmaX86 => "lzma-f86",
            Encoding::Crc32 => "crc32",
            Encoding::Brotli => "brotli",
            Encoding::EfiCompression => "efi",
            Encoding::TianoCompression => "tiano",
        }
    }

    /// Human-readable name used in error messages.
    pub fn label(self) -> &'static str {
        match self {
            Encoding::Lzma => "LZMA",
            Encoding::LzmaX86 => "LZMA F86",
            Encoding::Crc32 => "CRC32",
            Encoding::Brotli => "Brotli",
            Encoding::EfiCompression => "EFI 1.1 compression",
            Encoding::TianoCompression => "Tiano compression",
        }
    }

    /// True when the content is stored compressed (everything but CRC32).
    pub fn is_compressed(self) -> bool {
        self != Encoding::Crc32
    }

    /// True when rebuild can re-encode the content; the rest is decode-only.
    pub fn is_rebuildable(self) -> bool {
        matches!(self, Encoding::Lzma | Encoding::Crc32)
    }
}

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
    /// Payload start, relative to the section, for GUID-defined and compression sections.
    pub data_offset: usize,
    /// Set for every encapsulation this engine decodes.
    pub decoded: Option<Decoded>,
    /// How `decoded` is stored; `Some` exactly when `decoded` is.
    pub encoding: Option<Encoding>,
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
        self.decoded.is_none()
            && (self.kind == SECTION_COMPRESSION || self.kind == SECTION_GUID_DEFINED)
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

    /// Encodings of the encapsulating sections in the file's tree, once each, in first-seen order.
    ///
    /// Example: `let tags: Vec<_> = file.encodings().iter().map(|e| e.tag()).collect();`
    pub fn encodings(&self) -> Vec<Encoding> {
        let mut found = Vec::new();
        visit(&self.sections, &[], &mut |section, _| {
            if let Some(encoding) = section.encoding
                && !found.contains(&encoding)
            {
                found.push(encoding);
            }
        });
        found
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
    /// True when the path passes through a compressed section (any [`Encoding`] but CRC32).
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

/// Decoded bytes spent so far across one image.
struct Budget {
    decoded: usize,
}

impl Budget {
    /// Largest decoded size the next section may produce.
    fn section_limit(&self) -> usize {
        codec::MAX_DECODED.min(MAX_TOTAL_DECODED.saturating_sub(self.decoded))
    }

    /// Record `bytes` of decoded content, failing past the image-wide cap.
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.decoded = self.decoded.saturating_add(bytes);
        if self.decoded > MAX_TOTAL_DECODED {
            return Err(Error::new(
                Code::FormatUnsupported,
                format!("image: decoded sections exceed {MAX_TOTAL_DECODED:#x} bytes"),
            ));
        }
        Ok(())
    }
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

    /// The first decode-only encapsulation (and its section offset) a leaf sits inside.
    ///
    /// Rebuild refuses such leaves; callers can report that before planning.
    /// Example: `if let Some((encoding, offset)) = image.decode_only_encapsulation(&leaf) { /* refuse */ }`
    pub fn decode_only_encapsulation(&self, leaf: &LeafRef) -> Option<(Encoding, usize)> {
        let file = self.file(leaf);
        let mut sections = &file.sections[..];
        for index in &leaf.path[..leaf.path.len() - 1] {
            let section = &sections[*index];
            let encoding = section.encoding?;
            if !encoding.is_rebuildable() {
                return Some((encoding, section.offset));
            }
            sections = &section.decoded.as_ref()?.children;
        }
        None
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
        file_ui_name(file, &self.bytes)
    }
}

/// The UI name of `file`, given the buffer of the volume that holds it.
///
/// Works for files in nested volumes too, where `buffer` is the FV-image section body.
///
/// Example: `let name = file_ui_name(&volume.files[0], &image.bytes);`
pub fn file_ui_name(file: &FfsFile, buffer: &[u8]) -> Option<String> {
    let mut name = None;
    visit(&file.sections, file.body(buffer), &mut |section, stream| {
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
            let inner = compressed || section.encoding.is_some_and(Encoding::is_compressed);
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
        parse_files(buffer, offset, start, offset + length, depth + 1, budget)?;
    Ok(Some(Volume {
        offset,
        length,
        header_size,
        filesystem,
        files,
        free_start,
    }))
}

/// Parse files from `start`, aligning each to 8 bytes relative to the volume at `base`.
fn parse_files(
    buffer: &[u8],
    base: usize,
    start: usize,
    end: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Vec<FfsFile>, usize)> {
    let mut files = Vec::new();
    let mut cursor = base + align(start - base, 8);
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
        cursor = base + align(cursor + size - base, 8);
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
            encoding: None,
            volumes: None,
            crc_valid: None,
        };
        decode_section(&mut section, stream, depth, budget)?;
        result.push(section);
        offset = align(offset + size, 4);
    }
    Ok(result)
}

/// A decoded section payload and the encoding that produced it.
type Candidate = (Vec<u8>, Encoding);

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
    let candidates = match section.kind {
        SECTION_COMPRESSION => decode_compression_section(section, raw, budget)?,
        SECTION_GUID_DEFINED => decode_guid_defined_section(section, raw, budget)?,
        _ => Vec::new(),
    };
    // Usually one candidate. An EFI compression stream carries no checksum, so
    // a stream of one variant can decode to garbage as the other: take the first
    // candidate whose content parses as a section stream.
    let spent = budget.decoded;
    let mut first_error = None;
    for (bytes, encoding) in candidates {
        budget.decoded = spent;
        if encoding.is_compressed() {
            budget.charge(bytes.len())?;
        }
        match parse_stream(&bytes, depth + 1, budget) {
            Ok(children) => {
                section.encoding = Some(encoding);
                section.decoded = Some(Decoded { bytes, children });
                return Ok(());
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    budget.decoded = spent;
    first_error.map_or(Ok(()), Err)
}

/// Run `decode` with the largest size this image's budget still allows.
///
/// Failures name `label` and the section offset.
fn decode_within_budget(
    offset: usize,
    label: &str,
    budget: &Budget,
    decode: impl FnOnce(usize) -> Result<Vec<Candidate>>,
) -> Result<Vec<Candidate>> {
    let limit = budget.section_limit();
    decode(limit).map_err(|error| {
        let error = error.context(format!("{label} section at {offset:#x}"));
        if limit < codec::MAX_DECODED {
            error.context(format!(
                "image budget {MAX_TOTAL_DECODED:#x} bytes, {limit:#x} left"
            ))
        } else {
            error
        }
    })
}

/// Compression section (type 01): only compression type 1 (EFI 1.1 or Tiano) is decoded.
fn decode_compression_section(
    section: &mut Section,
    raw: &[u8],
    budget: &Budget,
) -> Result<Vec<Candidate>> {
    let h = section.header_size;
    if raw.len() < h + 5 {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "compression section at {:#x}: shorter than its {}-byte header",
                section.offset,
                h + 5
            ),
        ));
    }
    let declared = le32(raw, h, "compression section decoded length")? as usize;
    if raw[h + 4] != 1 {
        return Ok(Vec::new());
    }
    section.data_offset = h + 5;
    let payload = &raw[h + 5..];
    let offset = section.offset;
    let candidates = decode_within_budget(offset, "EFI compression", budget, |limit| {
        Ok(codec::efi_decompress_candidates(payload, limit)?
            .into_iter()
            .map(|(plain, variant)| {
                let encoding = match variant {
                    codec::tiano::Variant::Efi => Encoding::EfiCompression,
                    codec::tiano::Variant::Tiano => Encoding::TianoCompression,
                };
                (plain, encoding)
            })
            .collect())
    })?;
    // Every candidate has the length the stream header declares.
    let (plain, encoding) = &candidates[0];
    if plain.len() != declared {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "{} section at {offset:#x}: expected decoded length {declared:#x} from the section header | received {:#x}",
                encoding.label(),
                plain.len()
            ),
        ));
    }
    Ok(candidates)
}

/// GUID-defined section: LZMA, LZMA F86, Brotli and CRC32 are decoded.
fn decode_guid_defined_section(
    section: &mut Section,
    raw: &[u8],
    budget: &Budget,
) -> Result<Vec<Candidate>> {
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
    let encoding = match guid {
        LZMA_GUID => Encoding::Lzma,
        LZMA_F86_GUID => Encoding::LzmaX86,
        BROTLI_GUID => Encoding::Brotli,
        CRC32_GUID => Encoding::Crc32,
        _ => return Ok(Vec::new()),
    };
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
    if encoding == Encoding::Crc32 {
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
        return Ok(vec![(payload.to_vec(), encoding)]);
    }
    decode_within_budget(section.offset, encoding.label(), budget, |limit| {
        let plain = match encoding {
            Encoding::Lzma => codec::decompress_within(payload, limit)?,
            Encoding::LzmaX86 => codec::lzma_x86_decompress(payload, limit)?,
            _ => codec::brotli_decompress(payload, limit)?,
        };
        Ok(vec![(plain, encoding)])
    })
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
    fn unaligned_volume_aligns_file_offsets_relative_to_the_volume() {
        // 0x1c-byte files leave a 4-byte gap before the next volume-relative
        // 8-byte boundary, which absolute alignment at 0x1001 would miss.
        let first = ffs(DXE_GUID, 0x07, &section(SECTION_RAW, &[1]), 0);
        let second = ffs(DXE_GUID, 0x07, &section(SECTION_RAW, &[2]), 0);
        assert_eq!(first.len(), 0x1d);
        let mut bytes = vec![0xff; 0x1001];
        bytes.extend(volume(&[first, second], 0x1000));
        let image = Image::parse(bytes).expect("unaligned volume parses");
        let offsets: Vec<usize> = image.volumes[0].files.iter().map(|f| f.offset).collect();
        assert_eq!(
            offsets,
            [0x1001 + 0x48, 0x1001 + 0x68],
            "expected volume-relative 8-byte file offsets"
        );
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

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use crate::codec::tiano::tests::fixture_text;
    use crate::synthetic::{
        DXE_GUID, compression_section, ffs, guid_defined_section, lzma_f86_section, lzma_section,
        section, volume, x86_code,
    };

    const STREAM_EFI: &[u8] = include_bytes!("../../tests/fixtures/stream.efi");
    const STREAM_TIANO: &[u8] = include_bytes!("../../tests/fixtures/stream.tiano");
    const STREAM_BROTLI: &[u8] = include_bytes!("../../tests/fixtures/stream.br");

    /// The section stream the fixtures compress: one RAW section of fixture text.
    fn raw_stream() -> Vec<u8> {
        section(SECTION_RAW, &fixture_text(300, 1))
    }

    fn brotli_section(declared: u64, stream: &[u8]) -> Vec<u8> {
        let mut payload = declared.to_le_bytes().to_vec();
        payload.extend_from_slice(&0x1000u64.to_le_bytes());
        payload.extend_from_slice(stream);
        guid_defined_section(BROTLI_GUID, &payload)
    }

    fn parse_one(encapsulation: &[u8]) -> Result<Image> {
        Image::parse(volume(&[ffs(DXE_GUID, 0x07, encapsulation, 0)], 0x1000))
    }

    /// The decoded plain stream and leaf body of the only section of the only file.
    fn decoded_leaf(image: &Image) -> (Encoding, Vec<u8>) {
        let section = &image.volumes[0].files[0].sections[0];
        let leaf = &image.leaves[&DXE_GUID][0];
        assert!(leaf.compressed, "expected a compressed leaf path");
        assert!(!image.volumes[0].files[0].opaque, "expected a decoded file");
        (
            section.encoding.expect("section has an encoding"),
            image.leaf_body(leaf).to_vec(),
        )
    }

    #[test]
    fn efi_and_tiano_compression_sections_decode_and_record_the_variant() {
        for (stream, expected) in [
            (STREAM_EFI, Encoding::EfiCompression),
            (STREAM_TIANO, Encoding::TianoCompression),
        ] {
            let image = parse_one(&compression_section(1, 304, stream)).expect("parses");
            let (encoding, body) = decoded_leaf(&image);
            assert_eq!(encoding, expected);
            assert_eq!(body, fixture_text(300, 1));
            let section = &image.volumes[0].files[0].sections[0];
            assert_eq!(section.data_offset, 9, "payload follows the 5-byte header");
            assert!(!section.is_opaque());
        }
    }

    /// An EFI 1.1 stream (EDK II `EfiCompress`) of one RAW section holding 39 bytes of 0x01.
    ///
    /// Tiano decodes it without error to a different, invalid section stream.
    const AMBIGUOUS_EFI: &[u8] = include_bytes!("../../tests/fixtures/ambiguous.efi");

    #[test]
    fn a_variant_that_decodes_to_garbage_does_not_hide_the_valid_one() {
        let real = section(SECTION_RAW, &[1; 39]);
        let candidates = codec::efi_decompress_candidates(AMBIGUOUS_EFI, 1 << 20).unwrap();
        assert_eq!(
            candidates.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
            [codec::tiano::Variant::Tiano, codec::tiano::Variant::Efi],
            "expected both variants to decode this stream"
        );
        assert!(candidates[0].0 != real, "expected Tiano to decode garbage");
        assert!(
            candidates[1].0 == real,
            "expected EFI 1.1 to decode the real stream"
        );

        let image = parse_one(&compression_section(1, 43, AMBIGUOUS_EFI)).expect("parses");
        let section = &image.volumes[0].files[0].sections[0];
        assert_eq!(section.encoding, Some(Encoding::EfiCompression));
        assert_eq!(section.decoded.as_ref().unwrap().bytes, real);
        assert_eq!(image.leaf_body(&image.leaves[&DXE_GUID][0]), [1u8; 39]);
    }

    #[test]
    fn brotli_guid_section_decodes() {
        let image = parse_one(&brotli_section(304, STREAM_BROTLI)).expect("parses");
        let (encoding, body) = decoded_leaf(&image);
        assert_eq!(encoding, Encoding::Brotli);
        assert_eq!(body, fixture_text(300, 1));
    }

    #[test]
    fn lzma_f86_section_decodes_with_the_x86_filter_undone() {
        let code = x86_code(600);
        let image = parse_one(&lzma_f86_section(&section(SECTION_RAW, &code))).expect("parses");
        let (encoding, body) = decoded_leaf(&image);
        assert_eq!(encoding, Encoding::LzmaX86);
        assert!(body == code, "expected the BCJ filter to be undone");
    }

    #[test]
    fn encodings_nest_inside_lzma() {
        let inner = compression_section(1, 304, STREAM_TIANO);
        let image = parse_one(&lzma_section(&inner)).expect("parses");
        let leaf = &image.leaves[&DXE_GUID][0];
        assert_eq!(leaf.path, [0, 0, 0]);
        assert!(leaf.compressed);
        assert_eq!(image.leaf_body(leaf), fixture_text(300, 1));
        let outer = &image.volumes[0].files[0].sections[0];
        assert_eq!(outer.encoding, Some(Encoding::Lzma));
        let nested = &outer.decoded.as_ref().unwrap().children[0];
        assert_eq!(nested.encoding, Some(Encoding::TianoCompression));
    }

    #[test]
    fn other_compression_types_stay_opaque() {
        let image = parse_one(&compression_section(0, 4, &[1, 2, 3, 4])).expect("parses");
        let file = &image.volumes[0].files[0];
        assert!(file.opaque);
        assert!(file.sections[0].is_opaque());
        assert_eq!(file.sections[0].encoding, None);
    }

    #[test]
    fn unknown_guid_defined_sections_stay_opaque() {
        let unknown = Guid::constant("01234567-89AB-CDEF-0123-456789ABCDEF");
        let image = parse_one(&guid_defined_section(unknown, &[1, 2, 3, 4])).expect("parses");
        assert!(image.volumes[0].files[0].opaque);
    }

    #[test]
    fn declared_section_length_must_match_the_decoded_stream() {
        let error = parse_one(&compression_section(1, 303, STREAM_TIANO)).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error.message.contains(
                "Tiano compression section at 0x0: expected decoded length 0x12f from the section header | received 0x130"
            ),
            "{error}"
        );
    }

    #[test]
    fn corrupt_streams_fail_naming_the_encoding_and_offset() {
        let mut truncated = STREAM_TIANO.to_vec();
        truncated.truncate(60);
        let error = parse_one(&compression_section(1, 304, &truncated)).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
        assert!(
            error.message.starts_with("EFI compression section at 0x0"),
            "{error}"
        );

        let error = parse_one(&brotli_section(304, &STREAM_BROTLI[..40])).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
        assert!(
            error.message.starts_with("Brotli section at 0x0"),
            "{error}"
        );

        let error = parse_one(&guid_defined_section(LZMA_F86_GUID, &[0; 5])).unwrap_err();
        assert!(
            error.message.starts_with("LZMA F86 section at 0x0"),
            "{error}"
        );
    }

    #[test]
    fn expansion_bombs_fail_on_a_named_limit() {
        let mut efi = STREAM_TIANO.to_vec();
        efi[4..8].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        let error = parse_one(&compression_section(1, 0x4000_0000, &efi)).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error
                .message
                .contains("declares 0x40000000 decoded bytes | expected at most 0x4000000"),
            "{error}"
        );
        assert!(
            error.message.contains("EFI compression section at 0x0"),
            "{error}"
        );

        let error = parse_one(&brotli_section(1 << 40, STREAM_BROTLI)).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error.message.contains("expected at most 0x4000000"),
            "{error}"
        );
    }

    #[test]
    fn the_image_wide_budget_caps_what_later_sections_may_decode() {
        let mut budget = Budget {
            decoded: MAX_TOTAL_DECODED - 100,
        };
        assert_eq!(budget.section_limit(), 100);
        let stream = compression_section(1, 304, STREAM_TIANO);
        let error = parse_stream(&stream, 1, &mut budget).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error
                .message
                .contains("image budget 0x20000000 bytes, 0x64 left"),
            "{error}"
        );
        assert!(error.message.contains("expected at most 0x64"), "{error}");
    }

    #[test]
    fn budget_charge_fails_past_the_image_cap_and_saturates() {
        let mut budget = Budget { decoded: 0 };
        budget
            .charge(MAX_TOTAL_DECODED)
            .expect("exactly at the cap");
        assert_eq!(budget.section_limit(), 0);
        let error = budget.charge(1).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error
                .message
                .contains("image: decoded sections exceed 0x20000000 bytes"),
            "{error}"
        );
        budget.decoded = usize::MAX;
        assert_eq!(budget.section_limit(), 0);
    }

    #[test]
    fn rebuild_refuses_modules_inside_decode_only_encodings() {
        let cases = [
            (
                compression_section(1, 304, STREAM_TIANO),
                "Tiano compression",
            ),
            (
                compression_section(1, 304, STREAM_EFI),
                "EFI 1.1 compression",
            ),
            (brotli_section(304, STREAM_BROTLI), "Brotli"),
            (
                lzma_f86_section(&section(SECTION_RAW, &x86_code(600))),
                "LZMA F86",
            ),
        ];
        for (encapsulation, label) in cases {
            let image = parse_one(&encapsulation).expect("parses");
            let leaf = image.leaves[&DXE_GUID][0].clone();
            let error = rebuild::rebuilt_file(&image, &leaf, &[0u8; 8]).unwrap_err();
            assert_eq!(error.code, Code::FormatUnsupported, "{label}: {error}");
            assert!(
                error.message.contains(&format!(
                    "{label} section at 0x0: rebuild expected an LZMA or CRC32 encapsulation | received a decode-only {label} section"
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn decode_only_encapsulation_names_the_first_blocking_section() {
        let mut stream = lzma_section(&compression_section(1, 304, STREAM_TIANO));
        let image = parse_one(&stream).expect("parses");
        let leaf = &image.leaves[&DXE_GUID][0];
        assert_eq!(
            image.decode_only_encapsulation(leaf),
            Some((Encoding::TianoCompression, 0)),
            "LZMA is rebuildable, the Tiano section inside it is not"
        );
        stream = lzma_section(&raw_stream());
        let image = parse_one(&stream).expect("parses");
        assert_eq!(
            image.decode_only_encapsulation(&image.leaves[&DXE_GUID][0]),
            None
        );
        let plain = Image::parse(volume(&[ffs(DXE_GUID, 0x07, &raw_stream(), 0)], 0x1000)).unwrap();
        assert_eq!(
            plain.decode_only_encapsulation(&plain.leaves[&DXE_GUID][0]),
            None
        );
    }

    #[test]
    fn rebuild_still_reencodes_lzma() {
        let image = parse_one(&lzma_section(&raw_stream())).expect("parses");
        let leaf = image.leaves[&DXE_GUID][0].clone();
        let body = fixture_text(300, 2);
        let file = rebuild::rebuilt_file(&image, &leaf, &body).expect("LZMA rebuilds");
        let rebuilt = Image::parse(volume(&[file], 0x1000)).expect("rebuilt parses");
        assert_eq!(rebuilt.leaf_body(&rebuilt.leaves[&DXE_GUID][0]), body);
    }

    #[test]
    fn file_encodings_list_each_encapsulation_once_in_tree_order() {
        let inner = compression_section(1, 304, STREAM_TIANO);
        let mut stream = lzma_section(&inner);
        stream.resize(align(stream.len(), 4), 0);
        stream.extend(brotli_section(304, STREAM_BROTLI));
        let image = parse_one(&stream).expect("parses");
        assert_eq!(
            image.volumes[0].files[0].encodings(),
            [Encoding::Lzma, Encoding::TianoCompression, Encoding::Brotli]
        );
        let plain = Image::parse(volume(&[ffs(DXE_GUID, 0x07, &raw_stream(), 0)], 0x1000)).unwrap();
        assert!(plain.volumes[0].files[0].encodings().is_empty());
    }

    #[test]
    fn encoding_names_and_capabilities() {
        let all = [
            (Encoding::Lzma, "lzma", "LZMA", true, true),
            (Encoding::LzmaX86, "lzma-f86", "LZMA F86", true, false),
            (Encoding::Crc32, "crc32", "CRC32", false, true),
            (Encoding::Brotli, "brotli", "Brotli", true, false),
            (
                Encoding::EfiCompression,
                "efi",
                "EFI 1.1 compression",
                true,
                false,
            ),
            (
                Encoding::TianoCompression,
                "tiano",
                "Tiano compression",
                true,
                false,
            ),
        ];
        for (encoding, tag, label, compressed, rebuildable) in all {
            assert_eq!(encoding.tag(), tag);
            assert_eq!(encoding.label(), label);
            assert_eq!(encoding.is_compressed(), compressed, "{label}");
            assert_eq!(encoding.is_rebuildable(), rebuildable, "{label}");
        }
    }
}
