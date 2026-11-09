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
    let at = header(pe)?;
    let directory = at + 24 + if is_wide(pe)? { 112 } else { 96 } + 5 * 8;
    let rva = le32(pe, directory, "PE relocation directory")?;
    let size = le32(pe, directory + 4, "PE relocation directory")? as usize;
    let mut covered = BTreeSet::new();
    let Some(start) = (if size != 0 {
        rva_to_offset(pe, rva)?
    } else {
        None
    }) else {
        return Ok(covered);
    };
    let end = start.saturating_add(size).min(pe.len());
    let mut cursor = start;
    while cursor + 8 <= end {
        let page = le32(pe, cursor, "relocation block")?;
        let block = le32(pe, cursor + 4, "relocation block")? as usize;
        if block < 8 {
            break;
        }
        let entries = (cursor + 8..(cursor + block).min(end)).step_by(2);
        for entry_at in entries {
            let entry = le16(pe, entry_at, "relocation entry")?;
            let width = match entry >> 12 {
                3 => 4,
                10 => 8,
                _ => continue,
            };
            if let Some(target) = rva_to_offset(pe, page.wrapping_add(u32::from(entry & 0xFFF)))? {
                covered.extend(target..target + width);
            }
        }
        cursor += block;
    }
    Ok(covered)
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
}
