//! Rebuild FFS files around a changed leaf, and reflow a volume when a file grows.
//!
//! Same-size files stay in place. A grown file moves later files into the
//! volume's free space, but never a file that runs from a fixed flash address:
//! PEI-phase images, execute-in-place images, FIXED files, the volume top file
//! and PAD files that carry data. These rules and the byte layout follow the
//! reference packer exactly, so identical inputs produce identical images.

use super::{
    CRC32_GUID, FFS_ATTRIB_CHECKSUM, FFS_ATTRIB_DATA_ALIGNMENT_2, FFS_ATTRIB_FIXED,
    FFS_ATTRIB_LARGE_FILE, FILE_PAD, FfsFile, Image, LZMA_GUID, LeafRef, SECTION_PE32, SECTION_RAW,
    SECTION_TE, Section, VTF_GUID, Volume, pe, walk,
};
use crate::codec;
use crate::error::{Code, Error, Result};
use crate::util::{align, sum8};

const ALIGNMENTS: [usize; 8] = [1, 16, 128, 512, 1024, 4096, 32768, 65536];
/// SEC, PEI core, PEIM and combined PEIM/driver file types execute in place.
const XIP_FILE_TYPES: [u8; 4] = [0x03, 0x04, 0x06, 0x08];

/// Recompute FFS header and data checksums in place.
pub fn file_checksum(header: &mut [u8], body: &[u8]) {
    header[17] = if header[19] & FFS_ATTRIB_CHECKSUM != 0 {
        sum8(body).wrapping_neg()
    } else {
        0xAA
    };
    let state = header[23];
    header[16] = 0;
    header[23] = 0;
    header[16] = sum8(header).wrapping_sub(header[17]).wrapping_neg();
    header[23] = state;
}

/// Build an FFS file from an existing header's fields and a new body.
pub fn make_file(header: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut header = header.to_vec();
    let size = header.len() + body.len();
    if header.len() == 24 {
        if size >= 0xFF_FFFF {
            return Err(Error::new(
                Code::FormatUnsupported,
                format!("FFS size {size:#x}: expected below 0xFFFFFF without LARGE_FILE"),
            ));
        }
        header[20..23].copy_from_slice(&(size as u32).to_le_bytes()[..3]);
    } else {
        header[24..32].copy_from_slice(&(size as u64).to_le_bytes());
    }
    file_checksum(&mut header, body);
    header.extend_from_slice(body);
    Ok(header)
}

/// Rebuild a section's header around a new body, keeping its header form.
pub fn section_with_body(section: &Section, stream: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let size = section.header_size + body.len();
    let mut out = section.raw(stream)[..section.header_size].to_vec();
    if section.header_size == 8 {
        let size = u32::try_from(size).map_err(|_| {
            Error::new(
                Code::FormatUnsupported,
                format!("section size {size:#x}: exceeds 32 bits"),
            )
        })?;
        out[4..8].copy_from_slice(&size.to_le_bytes());
    } else if size >= 0xFF_FFFF {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("section size {size:#x}: needs an extended header"),
        ));
    } else {
        out[0..3].copy_from_slice(&(size as u32).to_le_bytes()[..3]);
    }
    out.extend_from_slice(body);
    Ok(out)
}

/// Padding after the last section, kept verbatim by the rebuild.
fn stream_tail<'a>(stream: &'a [u8], sections: &[Section]) -> &'a [u8] {
    let end = sections.last().map_or(0, |s| s.offset + s.size);
    let start = align(end, 4);
    if start < stream.len() {
        &stream[start..]
    } else {
        &[]
    }
}

/// A section stream with the leaf at `path` replaced by `body`.
fn rebuild_stream(
    sections: &[Section],
    stream: &[u8],
    path: &[usize],
    body: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(stream.len() + body.len());
    let count = sections.len();
    for (index, section) in sections.iter().enumerate() {
        if index != path[0] {
            out.extend_from_slice(section.raw(stream));
        } else if path.len() == 1 {
            out.extend(section_with_body(section, stream, body)?);
        } else {
            out.extend(rebuild_encapsulation(section, stream, &path[1..], body)?);
        }
        if index + 1 < count {
            out.resize(align(out.len(), 4), 0);
        }
    }
    out.extend_from_slice(stream_tail(stream, sections));
    Ok(out)
}

/// Rebuild one LZMA or CRC32 GUID-defined section around a changed child.
fn rebuild_encapsulation(
    section: &Section,
    stream: &[u8],
    path: &[usize],
    body: &[u8],
) -> Result<Vec<u8>> {
    let decoded = section
        .decoded
        .as_ref()
        .ok_or_else(|| Error::new(Code::Internal, "rebuild path enters an undecoded section"))?;
    let inner = rebuild_stream(&decoded.children, &decoded.bytes, path, body)?;
    let raw = section.raw(stream);
    let mut extra = raw[section.header_size..section.data_offset].to_vec();
    let payload = match section.guid {
        Some(guid) if guid == LZMA_GUID => {
            codec::compress_like(&inner, &raw[section.data_offset..])?
        }
        Some(guid) if guid == CRC32_GUID => {
            if extra.len() < 24 {
                return Err(Error::new(
                    Code::FormatUnsupported,
                    "CRC32 section: header has no CRC field",
                ));
            }
            extra[20..24].copy_from_slice(&codec::crc32(&inner).to_le_bytes());
            inner
        }
        other => {
            return Err(Error::new(
                Code::FormatUnsupported,
                format!("GUID section {other:?}: rebuilding is not supported"),
            ));
        }
    };
    extra.extend(payload);
    section_with_body(section, stream, &extra)
}

/// The FFS file holding `leaf`, with the leaf's body replaced.
pub fn rebuilt_file(image: &Image, leaf: &LeafRef, body: &[u8]) -> Result<Vec<u8>> {
    let file = image.file(leaf);
    let stream = rebuild_stream(&file.sections, file.body(&image.bytes), &leaf.path, body)?;
    make_file(file.header(&image.bytes), &stream)
}

/// Pad a shrunk file with a RAW section so later files keep their offsets.
pub fn keep_extent(data: Vec<u8>, extent: usize, header_size: usize) -> Result<Vec<u8>> {
    if align(data.len(), 8) >= extent {
        return Ok(data);
    }
    let mut body = data[header_size..].to_vec();
    body.resize(align(body.len(), 4), 0);
    let Some(filler) = extent.checked_sub(header_size + body.len()) else {
        return Ok(data);
    };
    if filler < 4 {
        return Ok(data);
    }
    if filler >= 0xFF_FFFF {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("filler section size {filler:#x}: expected below 0xFFFFFF"),
        ));
    }
    body.extend_from_slice(&(filler as u32).to_le_bytes()[..3]);
    body.push(SECTION_RAW);
    body.resize(body.len() + filler - 4, 0xFF);
    make_file(&data[..header_size], &body)
}

/// Section offsets along an uncompressed path inside a file.
fn section_offsets(file: &FfsFile, path: &[usize]) -> usize {
    let mut total = 0;
    let mut sections = &file.sections[..];
    for index in path {
        let section = &sections[*index];
        total += section.offset;
        match &section.decoded {
            Some(decoded) => {
                total += section.data_offset;
                sections = &decoded.children;
            }
            None => sections = &[],
        }
    }
    total
}

/// Why an uncompressed image in `file` runs from its flash address, if it does.
///
/// PEI-phase file types execute in place. Any other image counts as XIP only
/// when its image base equals the address it occupies in flash.
pub fn xip_reason(image: &Image, file: &FfsFile) -> Option<String> {
    let mut reason = None;
    let body = file.body(&image.bytes);
    walk(
        &file.sections,
        &mut Vec::new(),
        false,
        &mut |path, section, compressed| {
            if reason.is_some()
                || compressed
                || (section.kind != SECTION_PE32 && section.kind != SECTION_TE)
            {
                return;
            }
            if XIP_FILE_TYPES.contains(&file.kind) {
                reason = Some(format!(
                    "is a PEI-phase image (file type {:#x}) that executes in place",
                    file.kind
                ));
                return;
            }
            let address = image.flash_base()
                + (file.offset
                    + file.header_size
                    + section_offsets(file, path)
                    + section.header_size) as u64;
            let (leaf, stream) = super::locate(&file.sections, body, path);
            match pe::image_base(leaf.body(stream)) {
                Ok(Some(base)) if base == address => {
                    reason = Some(format!(
                        "executes in place at {address:#x} and would need relocation"
                    ))
                }
                Ok(_) => {}
                Err(error) => {
                    reason = Some(format!(
                        "has an unreadable image header ({})",
                        error.message
                    ))
                }
            }
        },
    );
    reason
}

/// Why a file must not move, or `None` when moving it is safe.
pub fn immovable(image: &Image, file: &FfsFile) -> Option<String> {
    if file.attributes & FFS_ATTRIB_FIXED != 0 {
        return Some("has the FIXED attribute".into());
    }
    if file.guid == VTF_GUID {
        return Some("is the volume top file".into());
    }
    if file.attributes & FFS_ATTRIB_DATA_ALIGNMENT_2 != 0 {
        return Some("uses FFSv3 extended data alignment".into());
    }
    if let Some(reason) = xip_reason(image, file) {
        return Some(reason);
    }
    if holds_uncompressed_volume(&file.sections) {
        return Some(
            "contains an uncompressed firmware volume whose code may execute in place".into(),
        );
    }
    if file.kind == FILE_PAD && !erased(file.body(&image.bytes)) {
        return Some("is a PAD file that carries data".into());
    }
    None
}

/// True when an FV image section with files sits outside any LZMA encapsulation.
///
/// Addresses inside such a volume are fixed by its position in flash, so the
/// containing file is treated as immovable (conservatively, whatever it holds).
fn holds_uncompressed_volume(sections: &[Section]) -> bool {
    sections.iter().any(|section| {
        if section
            .volumes
            .as_ref()
            .is_some_and(|v| v.iter().any(|v| !v.files.is_empty()))
        {
            return true;
        }
        let compressed = section.guid == Some(LZMA_GUID);
        !compressed
            && section
                .decoded
                .as_ref()
                .is_some_and(|d| holds_uncompressed_volume(&d.children))
    })
}

fn erased(body: &[u8]) -> bool {
    body.iter().all(|b| *b == 0xFF)
}

/// An erased PAD file of `size` bytes (a multiple of 8, at least 24).
fn pad_file(size: usize) -> Result<Vec<u8>> {
    if !(24..0xFF_FFFF).contains(&size) {
        return Err(Error::new(
            Code::PackingRefused,
            format!("PAD file size {size:#x}: expected 0x18..0xFFFFFE"),
        ));
    }
    let mut header = vec![0xFF; 16];
    header.extend_from_slice(&[0, 0xAA, FILE_PAD, 0]);
    header.extend_from_slice(&(size as u32).to_le_bytes()[..3]);
    header.push(0xF8);
    make_file(&header, &vec![0xFF; size - 24])
}

/// The file's declared data alignment in bytes.
fn data_alignment(file: &FfsFile) -> usize {
    ALIGNMENTS[usize::from((file.attributes >> 3) & 7)]
}

/// The first legal start at or after both `cursor` and the original offset.
///
/// The gap after `cursor` must be zero or hold a PAD file (24+ bytes), and the
/// file's data must meet its declared alignment. FFS alignment is relative to
/// the volume at `base`.
fn place(base: usize, cursor: usize, file: &FfsFile) -> usize {
    let alignment = data_alignment(file);
    let header = if file.attributes & FFS_ATTRIB_LARGE_FILE != 0 {
        32
    } else {
        24
    };
    let mut start = base + align(cursor.max(file.offset) - base, 8);
    while !(start - base + header).is_multiple_of(alignment)
        || (start > cursor && start - cursor < 24)
    {
        start += 8;
    }
    start
}

/// A file replacement inside one volume: file index and new file bytes.
pub type Replacement = (usize, Vec<u8>);

/// Rewrite a volume's files in order, moving later files when one grows.
///
/// Returns notes describing every moved file. Fails with `PackingRefused`
/// when a file that must stay in place would move or the volume overflows.
pub fn reflow(
    image: &Image,
    out: &mut [u8],
    volume: &Volume,
    replaced: &[Replacement],
) -> Result<Vec<String>> {
    let end = volume.offset + volume.length;
    let base = volume.offset;
    let mut buffer = out[base..end].to_vec();
    let mut notes = Vec::new();
    let mut cursor = volume.files.first().map_or(volume.free_start, |f| f.offset);
    buffer[cursor - base..].fill(0xFF);
    for (index, file) in volume.files.iter().enumerate() {
        let replacement = replaced
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, d)| d.as_slice());
        if file.kind == FILE_PAD && erased(file.body(&image.bytes)) && replacement.is_none() {
            continue;
        }
        let data = replacement.unwrap_or(&image.bytes[file.offset..file.offset + file.size]);
        let start = place(base, cursor, file);
        if start != file.offset {
            if let Some(reason) = immovable(image, file) {
                return Err(Error::new(
                    Code::PackingRefused,
                    format!(
                        "file {} at {:#x} {reason}; this change cannot be packed automatically here",
                        file.guid, file.offset
                    ),
                ));
            }
            notes.push(format!(
                "moved {} {:#x} -> {start:#x}",
                file.guid, file.offset
            ));
        }
        if start
            .checked_add(data.len())
            .is_none_or(|file_end| file_end > end)
        {
            return Err(Error::new(
                Code::PackingRefused,
                format!(
                    "volume at {:#x}: file at {start:#x} of size {:#x} needs more bytes than its free space (volume end {end:#x}); this change cannot be packed automatically here",
                    volume.offset,
                    data.len()
                ),
            ));
        }
        if start > cursor {
            buffer[cursor - base..start - base].copy_from_slice(&pad_file(start - cursor)?);
        }
        buffer[start - base..start - base + data.len()].copy_from_slice(data);
        cursor = base + align(start + data.len() - base, 8);
    }
    out[base..end].copy_from_slice(&buffer);
    Ok(notes)
}

/// Write same-extent replacements in place, padding each file's slot with 0xFF.
pub fn write_in_place(out: &mut [u8], volume: &Volume, replaced: &[Replacement]) {
    for (index, data) in replaced {
        let file = &volume.files[*index];
        let slot = &mut out[file.offset..file.offset + file.extent()];
        slot[..data.len()].copy_from_slice(data);
        slot[data.len()..].fill(0xFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64 KiB descriptor dump whose BIOS region ends at 0xd000, holding one
    /// uncompressed DXE driver linked at `base`.
    fn descriptor_image(base: u32) -> Image {
        use crate::synthetic::{DXE_GUID, ffs, section, volume};
        let mut pe = vec![0; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
        pe[0x74..0x78].copy_from_slice(&base.to_le_bytes());
        let file = ffs(DXE_GUID, 0x07, &section(SECTION_PE32, &pe), 0);
        let mut bytes = vec![0xff; 0x1000];
        bytes[0x10..0x14].copy_from_slice(&0x0ff0_a55au32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        for (index, region) in [
            0x0000_0000u32,
            0x000c_0001,
            0x000f_000d,
            0x0000_7fff,
            0x0000_7fff,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[0x40 + index * 4..0x44 + index * 4].copy_from_slice(&region.to_le_bytes());
        }
        bytes.extend(volume(&[file], 0xc000));
        bytes.resize(0x10000, 0xff);
        let regions = super::super::descriptor_regions(&bytes).expect("valid descriptor");
        assert!(regions.iter().any(|r| r.name == "bios" && r.end == 0xd000));
        Image::parse(bytes).expect("descriptor fixture parses")
    }

    #[test]
    fn descriptor_flash_base_maps_the_bios_region_end_to_4_gib() {
        let image = descriptor_image(0);
        assert_eq!(
            image.flash_base(),
            (1u64 << 32) - 0xd000,
            "expected the BIOS region end at 4 GiB, not the dump end"
        );
    }

    #[test]
    fn descriptor_layout_keeps_an_executable_linked_at_its_flash_address() {
        // The PE body starts at 0x1000 + 0x48 + 24 + 4 in the dump.
        let image = descriptor_image(((1u64 << 32) - 0xd000 + 0x1064) as u32);
        let reason = immovable(&image, &image.volumes[0].files[0])
            .expect("an executable linked at its flash address must stay in place");
        assert!(reason.contains("executes in place"), "{reason}");
    }

    #[test]
    fn descriptor_layout_moves_an_executable_linked_elsewhere() {
        let image = descriptor_image(0);
        let reason = immovable(&image, &image.volumes[0].files[0]);
        assert_eq!(reason, None, "expected a base-0 DXE driver to be movable");
    }

    #[test]
    fn reflow_aligns_file_data_relative_to_the_volume() {
        use crate::synthetic::{DXE_GUID, NEXT_GUID, ffs, section, volume};
        let grown = ffs(DXE_GUID, 0x07, &section(SECTION_RAW, &[1; 20]), 0);
        let aligned = ffs(NEXT_GUID, 0x07, &section(SECTION_RAW, &[2; 20]), 1 << 3);
        let mut bytes = vec![0xff; 8];
        bytes.extend(volume(&[grown, aligned], 0x1000));
        let image = Image::parse(bytes).expect("volume parses");
        let vol = &image.volumes[0];
        let mut out = image.bytes.clone();
        let notes = reflow(&image, &mut out, vol, &[]).expect("unchanged volume reflows");
        assert!(
            notes.is_empty(),
            "expected no moved files | received {notes:?}"
        );
        assert_eq!(out, image.bytes, "expected an unchanged volume");

        let bigger = ffs(DXE_GUID, 0x07, &section(SECTION_RAW, &[1; 60]), 0);
        reflow(&image, &mut out, vol, &[(0, bigger)]).expect("grown volume reflows");
        let rebuilt = Image::parse(out).expect("rebuilt volume parses");
        let moved = rebuilt.volumes[0]
            .files
            .iter()
            .find(|f| f.guid == NEXT_GUID)
            .expect("aligned file survives");
        let data = moved.offset - rebuilt.volumes[0].offset + moved.header_size;
        assert!(
            data.is_multiple_of(16),
            "expected volume-relative data offset aligned to 0x10 | received {data:#x}"
        );
    }

    #[test]
    fn reflow_refuses_alignment_past_volume_end() {
        let file = |offset, attributes| FfsFile {
            offset,
            header_size: 24,
            size: 24,
            guid: CRC32_GUID,
            kind: 2,
            attributes,
            sections: vec![],
            opaque: false,
        };
        let volume = Volume {
            offset: 0,
            length: 0x2000,
            header_size: 0,
            filesystem: CRC32_GUID,
            files: vec![file(0, 0), file(0xfe8, 5 << 3)],
            free_start: 0x1000,
        };
        let image = Image {
            bytes: vec![0xff; 0x2000],
            volumes: vec![],
            leaves: Default::default(),
        };
        let mut out = image.bytes.clone();
        let error = reflow(&image, &mut out, &volume, &[(0, vec![0; 0x1ff0])]).unwrap_err();
        assert_eq!(error.code, Code::PackingRefused);
        assert_eq!(out, image.bytes);
    }

    #[test]
    fn checksums_match_the_parser_rules() {
        let mut header = vec![0x11; 24];
        header[19] = FFS_ATTRIB_CHECKSUM;
        header[23] = 0xF8;
        let body = [1u8, 2, 3];
        file_checksum(&mut header, &body);
        assert_eq!(
            sum8(&header)
                .wrapping_sub(header[17])
                .wrapping_sub(header[23]),
            0
        );
        assert_eq!(sum8(&body).wrapping_add(header[17]), 0);
        assert_eq!(header[23], 0xF8);
    }

    #[test]
    fn pad_file_is_erased_and_sized() {
        let pad = pad_file(48).unwrap();
        assert_eq!(pad.len(), 48);
        assert_eq!(pad[18], FILE_PAD);
        assert!(pad[24..].iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn pad_file_rejects_sizes_its_24_bit_field_cannot_hold() {
        let error = pad_file(0x100_0000).unwrap_err();
        assert_eq!(error.code, Code::PackingRefused);
        assert!(error.message.contains("0x1000000"), "{error}");
        assert!(pad_file(16).is_err());
    }

    #[test]
    fn keep_extent_fills_a_shrunk_file_with_a_raw_section() {
        let header = vec![0u8; 24];
        let data = make_file(&header, &[0xAB; 12]).unwrap();
        let kept = keep_extent(data, 64, 24).unwrap();
        assert_eq!(kept.len(), 64);
        assert_eq!(kept[24 + 12 + 3], SECTION_RAW);
    }
}
