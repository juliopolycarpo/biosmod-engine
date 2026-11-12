//! Minimal checked PE/TE helpers: section table, image base and base-relocation coverage.
//!
//! Example: `let covered = relocation_offsets(&module)?;`

use crate::error::{Code, Error, Result};
use crate::util::{le16, le32, le64};
use std::collections::BTreeSet;

/// One section-table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSection {
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
}

fn header(pe: &[u8]) -> Result<usize> {
    let at = le32(pe, 0x3C, "PE e_lfanew")? as usize;
    if pe.get(at..at + 4) != Some(b"PE\0\0") {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("PE header at {at:#x}: expected 'PE\\0\\0'"),
        ));
    }
    Ok(at)
}

/// Whether the optional header is PE32+ (64-bit).
pub fn is_wide(pe: &[u8]) -> Result<bool> {
    Ok(le16(pe, header(pe)? + 24, "PE optional magic")? == 0x20B)
}

/// Section table rows.
pub fn sections(pe: &[u8]) -> Result<Vec<PeSection>> {
    let at = header(pe)?;
    let count = le16(pe, at + 6, "PE section count")? as usize;
    let optional = le16(pe, at + 20, "PE optional header size")? as usize;
    let table = at + 24 + optional;
    (0..count)
        .map(|i| {
            let row = table + i * 40;
            Ok(PeSection {
                virtual_size: le32(pe, row + 8, "PE section")?,
                rva: le32(pe, row + 12, "PE section")?,
                raw_size: le32(pe, row + 16, "PE section")?,
                raw_offset: le32(pe, row + 20, "PE section")?,
            })
        })
        .collect()
}

/// Map an RVA to a file offset, or `None` when no file data backs it.
pub fn rva_to_offset(pe: &[u8], rva: u32) -> Result<Option<usize>> {
    for s in sections(pe)? {
        let span = s.virtual_size.max(s.raw_size);
        if s.rva <= rva
            && u64::from(rva) < u64::from(s.rva) + u64::from(span)
            && rva - s.rva < s.raw_size
        {
            return Ok(Some(s.raw_offset as usize + (rva - s.rva) as usize));
        }
    }
    let size_of_headers = le32(pe, header(pe)? + 84, "PE SizeOfHeaders")?;
    Ok((rva < size_of_headers).then_some(rva as usize))
}

/// File offsets of every byte covered by a HIGHLOW or DIR64 base relocation.
pub fn relocation_offsets(pe: &[u8]) -> Result<BTreeSet<usize>> {
    if pe.starts_with(b"VZ") {
        return Err(Error::new(
            Code::FormatUnsupported,
            "TE image relocation coverage: expected a PE image; TE relocation checks are not supported",
        ));
    }
    let mut covered = BTreeSet::new();
    for (target, width) in relocation_fields(pe)? {
        covered.extend(target..target + width);
    }
    Ok(covered)
}

/// A base-relocated field: file offset and width (4 for HIGHLOW, 8 for DIR64).
pub type RelocatedField = (usize, usize);

/// Every HIGHLOW and DIR64 field a PE (`MZ`) or TE (`VZ`) image relocates, in table order.
///
/// Fields the section table does not back with file data are skipped.
///
/// Example: `for (offset, width) in relocation_fields(&module)? { /* module[offset..offset + width] */ }`
pub fn relocation_fields(image: &[u8]) -> Result<Vec<RelocatedField>> {
    let te = image.starts_with(b"VZ");
    let directory = if te {
        24
    } else {
        header(image)? + 24 + if is_wide(image)? { 112 } else { 96 } + 5 * 8
    };
    let map = |rva: u32| {
        if te {
            te_rva_to_offset(image, rva)
        } else {
            rva_to_offset(image, rva)
        }
    };
    let rva = le32(image, directory, "relocation directory")?;
    let size = le32(image, directory + 4, "relocation directory")? as usize;
    let mut fields = Vec::new();
    let Some(start) = (if size != 0 { map(rva)? } else { None }) else {
        return Ok(fields);
    };
    let end = start.saturating_add(size).min(image.len());
    let mut cursor = start;
    while cursor + 8 <= end {
        let page = le32(image, cursor, "relocation block")?;
        let block = le32(image, cursor + 4, "relocation block")? as usize;
        if block < 8 {
            break;
        }
        let entries = (cursor + 8..(cursor + block).min(end)).step_by(2);
        for entry_at in entries {
            let entry = le16(image, entry_at, "relocation entry")?;
            let width = match entry >> 12 {
                3 => 4,
                10 => 8,
                _ => continue,
            };
            if let Some(target) = map(page.wrapping_add(u32::from(entry & 0xFFF)))? {
                fields.push((target, width));
            }
        }
        cursor += block;
    }
    Ok(fields)
}

/// TE section rows (the PE 40-byte layout, after the 40-byte TE header).
fn te_sections(te: &[u8]) -> Result<Vec<PeSection>> {
    let count = usize::from(*te.get(4).ok_or_else(|| {
        Error::new(
            Code::FormatInvalid,
            "TE section count: expected 1 byte at offset 4 | received a shorter image",
        )
    })?);
    (0..count)
        .map(|i| {
            let row = 40 + i * 40;
            Ok(PeSection {
                virtual_size: le32(te, row + 8, "TE section")?,
                rva: le32(te, row + 12, "TE section")?,
                raw_size: le32(te, row + 16, "TE section")?,
                raw_offset: le32(te, row + 20, "TE section")?,
            })
        })
        .collect()
}

/// Map an RVA of a TE image to a file offset: section data moves down by the stripped header size.
fn te_rva_to_offset(te: &[u8], rva: u32) -> Result<Option<usize>> {
    let stripped = u64::from(le16(te, 6, "TE stripped size")?);
    for s in te_sections(te)? {
        let span = s.virtual_size.max(s.raw_size);
        if s.rva <= rva
            && u64::from(rva) < u64::from(s.rva) + u64::from(span)
            && rva - s.rva < s.raw_size
        {
            let offset = u64::from(s.raw_offset) + u64::from(rva - s.rva) + 40;
            return Ok(offset.checked_sub(stripped).map(|o| o as usize));
        }
    }
    Ok(None)
}

/// Image bytes rebased to image base zero, for comparison reports only.
///
/// The bytes are deliberately unreachable from outside the crate: there is no
/// accessor, conversion or `Deref`, so a rebased copy cannot be handed to
/// `patch`, `replace` or any writer. Callers read its length and digest, or
/// diff it through [`crate::compare`].
///
/// Example: `let rebased = rebase_for_report(&module)?; println!("{}", rebased.sha256_hex());`
pub struct RebasedForReport {
    bytes: Vec<u8>,
    /// The image base the relocations were removed against.
    pub image_base: u64,
    /// HIGHLOW and DIR64 fields rewritten.
    pub relocations: usize,
}

impl RebasedForReport {
    /// Length in bytes (equal to the source image).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the image is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// SHA-256 of the rebased bytes, lowercase hex.
    pub fn sha256_hex(&self) -> String {
        crate::util::sha256_hex(&self.bytes)
    }

    /// Crate-private view used by the comparison report.
    pub(crate) fn report_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Undo base relocations: subtract the image base from every relocated field and zero the base field.
///
/// Two builds of one module linked at different bases then compare equal when
/// only their relocated values differ. Reads PE32, PE32+ and TE images.
///
/// Example: `assert_eq!(rebase_for_report(&a)?.sha256_hex(), rebase_for_report(&b)?.sha256_hex());`
pub fn rebase_for_report(image: &[u8]) -> Result<RebasedForReport> {
    let te = image.starts_with(b"VZ");
    // (offset, width) of the image-base field inside the optional header.
    let (base_at, base_width) = if te {
        (16, 8)
    } else {
        let at = header(image)?;
        if is_wide(image)? {
            (at + 24 + 24, 8)
        } else {
            (at + 24 + 28, 4)
        }
    };
    let base = if base_width == 8 {
        le64(image, base_at, "image base")?
    } else {
        u64::from(le32(image, base_at, "image base")?)
    };
    let mut bytes = image.to_vec();
    let fields = relocation_fields(image)?;
    for &(offset, width) in &fields {
        let Some(field) = bytes.get_mut(offset..offset + width) else {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "relocated field {offset:#x}+{width}: expected inside image of {:#x} bytes",
                    image.len()
                ),
            ));
        };
        if width == 4 {
            let value = u32::from_le_bytes(field.try_into().expect("four bytes"));
            field.copy_from_slice(&value.wrapping_sub(base as u32).to_le_bytes());
        } else {
            let value = u64::from_le_bytes(field.try_into().expect("eight bytes"));
            field.copy_from_slice(&value.wrapping_sub(base).to_le_bytes());
        }
    }
    bytes[base_at..base_at + base_width].fill(0);
    Ok(RebasedForReport {
        bytes,
        image_base: base,
        relocations: fields.len(),
    })
}

/// A named byte range of a PE or TE file: the headers or one section's raw data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionSpan {
    pub name: String,
    pub start: usize,
    pub end: usize,
}

/// The headers and each section's raw file range, clipped to the image length.
///
/// Example: `let names: Vec<_> = section_spans(&module)?.into_iter().map(|s| s.name).collect();`
pub fn section_spans(image: &[u8]) -> Result<Vec<SectionSpan>> {
    let te = image.starts_with(b"VZ");
    let (rows, table, headers_end) = if te {
        (te_sections(image)?, 40, 0)
    } else {
        let at = header(image)?;
        let optional = le16(image, at + 20, "PE optional header size")? as usize;
        (
            sections(image)?,
            at + 24 + optional,
            le32(image, at + 24 + 60, "PE SizeOfHeaders")? as usize,
        )
    };
    let stripped = if te {
        usize::from(le16(image, 6, "TE stripped size")?)
    } else {
        0
    };
    let table_end = table + rows.len() * 40;
    let mut spans = vec![SectionSpan {
        name: "headers".into(),
        start: 0,
        end: headers_end.max(table_end).min(image.len()),
    }];
    for (index, row) in rows.iter().enumerate() {
        let name_bytes = &image[table + index * 40..table + index * 40 + 8];
        let name: String = name_bytes
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| char::from(*b))
            .collect();
        let start = (row.raw_offset as usize + if te { 40 } else { 0 })
            .saturating_sub(stripped)
            .min(image.len());
        let end = (start + row.raw_size as usize).min(image.len());
        spans.push(SectionSpan {
            name: if name.is_empty() {
                format!("#{index}")
            } else {
                name
            },
            start,
            end,
        });
    }
    Ok(spans)
}

/// The linked image base of a PE32/PE32+ or TE image, if the header is recognized.
pub fn image_base(body: &[u8]) -> Result<Option<u64>> {
    if body.starts_with(b"VZ") {
        let stripped = u64::from(le16(body, 6, "TE stripped size")?);
        return Ok(Some(
            le64(body, 16, "TE image base")?
                .wrapping_add(40)
                .wrapping_sub(stripped),
        ));
    }
    if !body.starts_with(b"MZ") {
        return Ok(None);
    }
    let at = header(body)?;
    if is_wide(body)? {
        Ok(Some(le64(body, at + 48, "PE image base")?))
    } else {
        Ok(Some(u64::from(le32(body, at + 52, "PE image base")?)))
    }
}

/// Positions of likely rel32 branch displacements (E8/E9/0F 8x).
///
/// A byte heuristic, not a disassembler: it can also mask data that looks
/// like a branch, which only makes signatures less specific.
pub fn branch_fields(code: &[u8]) -> BTreeSet<usize> {
    let mut wild = BTreeSet::new();
    for (index, value) in code.iter().enumerate() {
        if (*value == 0xE8 || *value == 0xE9) && index + 5 <= code.len() {
            wild.extend(index + 1..index + 5);
        } else if *value == 0x0F
            && index + 6 <= code.len()
            && (0x80..=0x8F).contains(&code[index + 1])
        {
            wild.extend(index + 2..index + 6);
        }
    }
    wild
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny PE32 with one section at RVA 0x200 and one HIGHLOW relocation at 0x210.
    pub(crate) fn tiny_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        let optional = 0x98;
        pe[optional..optional + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        pe[optional + 28..optional + 32].copy_from_slice(&0xFFF0_0000u32.to_le_bytes());
        pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let reloc_dir = optional + 96 + 40;
        pe[reloc_dir..reloc_dir + 4].copy_from_slice(&0x300u32.to_le_bytes());
        pe[reloc_dir + 4..reloc_dir + 8].copy_from_slice(&12u32.to_le_bytes());
        let table = optional + 0xE0;
        for (i, v) in [0x200u32, 0x200, 0x200, 0x200].iter().enumerate() {
            pe[table + 8 + i * 4..table + 12 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        pe[0x300..0x304].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x304..0x308].copy_from_slice(&12u32.to_le_bytes());
        pe[0x308..0x30A].copy_from_slice(&(0x3000u16 | 0x10).to_le_bytes());
        pe
    }

    #[test]
    fn relocation_coverage_and_image_base() {
        let pe = tiny_pe();
        assert_eq!(
            relocation_offsets(&pe)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![0x210, 0x211, 0x212, 0x213]
        );
        assert_eq!(image_base(&pe).unwrap(), Some(0xFFF0_0000));
        assert_eq!(rva_to_offset(&pe, 0x10).unwrap(), Some(0x10));
        assert_eq!(rva_to_offset(&pe, 0x900).unwrap(), None);
    }

    #[test]
    fn truncated_header_is_an_error() {
        let pe = tiny_pe();
        assert!(relocation_offsets(&pe[..0x90]).is_err());
        assert_eq!(image_base(b"ab").unwrap(), None);
    }

    #[test]
    fn te_relocation_coverage_is_explicitly_unsupported() {
        let mut te = vec![0; 128];
        te[..2].copy_from_slice(b"VZ");
        let error = relocation_offsets(&te).expect_err("TE relocations must not be guessed");
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(error.message.contains("TE"), "{error}");
        assert!(error.message.contains("relocation"), "{error}");
    }

    #[test]
    fn branch_heuristic_masks_displacements() {
        let wild = branch_fields(&[0x90, 0xE8, 1, 2, 3, 4, 0x0F, 0x84, 1, 2, 3, 4]);
        assert_eq!(
            wild.into_iter().collect::<Vec<_>>(),
            vec![2, 3, 4, 5, 8, 9, 10, 11]
        );
    }

    /// A TE image: 40-byte header, one `.text` section, one relocated HIGHLOW at section+0x10.
    fn tiny_te(base: u64) -> Vec<u8> {
        let mut te = vec![0u8; 0x50 + 0x100];
        te[0..2].copy_from_slice(b"VZ");
        te[4] = 1;
        te[6..8].copy_from_slice(&0x58u16.to_le_bytes());
        te[16..24].copy_from_slice(&base.to_le_bytes());
        te[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        te[28..32].copy_from_slice(&12u32.to_le_bytes());
        te[40..46].copy_from_slice(b".text\0");
        for (i, v) in [0x100u32, 0x80, 0x100, 0x80].iter().enumerate() {
            te[48 + i * 4..52 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        te[0x60..0x64].copy_from_slice(&(base as u32).wrapping_add(0x77).to_le_bytes());
        te[0xD0..0xD4].copy_from_slice(&0x80u32.to_le_bytes());
        te[0xD4..0xD8].copy_from_slice(&12u32.to_le_bytes());
        te[0xD8..0xDA].copy_from_slice(&(0x3000u16 | 0x10).to_le_bytes());
        te
    }

    #[test]
    fn rebase_subtracts_the_base_and_zeroes_the_base_field() {
        let pe = tiny_pe();
        let mut linked = pe.clone();
        linked[0x210..0x214].copy_from_slice(&0xFFF0_1234u32.to_le_bytes());
        let rebased = rebase_for_report(&linked).unwrap();
        assert_eq!(rebased.image_base, 0xFFF0_0000);
        assert_eq!(rebased.relocations, 1);
        let bytes = rebased.report_bytes();
        assert_eq!(&bytes[0x210..0x214], &0x1234u32.to_le_bytes());
        assert_eq!(&bytes[0x98 + 28..0x98 + 32], &[0; 4]);
        assert_eq!(rebased.len(), linked.len());
        assert_eq!(rebased.sha256_hex(), crate::util::sha256_hex(bytes));
    }

    #[test]
    fn rebase_reads_te_images() {
        let rebased = rebase_for_report(&tiny_te(0x1_0000_0000)).unwrap();
        assert_eq!(
            (rebased.image_base, rebased.relocations),
            (0x1_0000_0000, 1)
        );
        assert_eq!(&rebased.report_bytes()[0x60..0x64], &0x77u32.to_le_bytes());
        assert_eq!(&rebased.report_bytes()[16..24], &[0; 8]);
        assert_eq!(
            rebase_for_report(&tiny_te(0x1_0000_0000))
                .unwrap()
                .sha256_hex(),
            rebase_for_report(&tiny_te(0x2_0000_0000))
                .unwrap()
                .sha256_hex()
        );
    }

    #[test]
    fn rebase_rejects_a_truncated_image() {
        let error = rebase_for_report(&tiny_pe()[..0x90])
            .err()
            .expect("truncated PE must fail");
        assert_eq!(error.code, Code::FormatInvalid);
    }

    #[test]
    fn te_relocation_fields_are_found_at_shifted_offsets() {
        assert_eq!(
            relocation_fields(&tiny_te(0x1000)).unwrap(),
            vec![(0x60, 4)]
        );
    }

    #[test]
    fn section_spans_name_headers_and_sections() {
        let mut pe = tiny_pe();
        pe[0x98 + 0xE0..0x98 + 0xE6].copy_from_slice(b".text\0");
        let spans = section_spans(&pe).unwrap();
        let rows: Vec<_> = spans
            .iter()
            .map(|s| (s.name.as_str(), s.start, s.end))
            .collect();
        assert_eq!(rows, vec![("headers", 0, 0x200), (".text", 0x200, 0x400)]);
        let spans = section_spans(&tiny_te(0)).unwrap();
        let rows: Vec<_> = spans
            .iter()
            .map(|s| (s.name.as_str(), s.start, s.end))
            .collect();
        assert_eq!(rows, vec![("headers", 0, 0x50), (".text", 0x50, 0x150)]);
    }
}
