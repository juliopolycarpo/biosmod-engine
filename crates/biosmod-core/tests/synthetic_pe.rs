//! The synthetic PE builder produces images with the header fields a loader reads.
//!
//! `tools/tests/pe_builder.py` builds the same bytes for the Python replay tests; the pinned
//! digests keep the two builders in step.

use biosmod_core::synthetic::{PE_CODE_RVA, PE_IMAGE_BASE, pe};
use biosmod_core::util::sha256;

const CODE: [u8; 6] = [0xB8, 7, 0, 0, 0, 0xC3]; // mov eax, 7; ret

fn u16_at(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(image[at..at + 2].try_into().expect("two bytes"))
}

fn u32_at(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(image[at..at + 4].try_into().expect("four bytes"))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn pe32_plus_header_names_the_machine_entry_and_base() {
    let image = pe(true, &CODE, &[]);
    assert_eq!(&image[..2], b"MZ");
    let pe_at = u32_at(&image, 0x3C) as usize;
    assert_eq!(&image[pe_at..pe_at + 4], b"PE\0\0");
    assert_eq!(u16_at(&image, pe_at + 4), 0x8664, "machine");
    let optional = pe_at + 24;
    assert_eq!(u16_at(&image, optional), 0x20B, "optional header magic");
    assert_eq!(u32_at(&image, optional + 16), PE_CODE_RVA, "entry rva");
    let base = u64::from_le_bytes(image[optional + 24..optional + 32].try_into().unwrap());
    assert_eq!(base, PE_IMAGE_BASE, "image base");
    assert_eq!(
        &image[0x200..0x200 + CODE.len()],
        &CODE,
        "code at the first raw page"
    );
}

#[test]
fn pe32_header_names_the_machine_and_a_four_byte_base() {
    let image = pe(false, &CODE, &[]);
    let pe_at = u32_at(&image, 0x3C) as usize;
    assert_eq!(u16_at(&image, pe_at + 4), 0x014C, "machine");
    let optional = pe_at + 24;
    assert_eq!(u16_at(&image, optional), 0x10B, "optional header magic");
    assert_eq!(
        u32_at(&image, optional + 28),
        PE_IMAGE_BASE as u32,
        "image base"
    );
}

#[test]
fn relocations_land_in_a_second_section_and_the_base_relocation_directory() {
    let image = pe(true, &[0u8; 16], &[0x1008]);
    let pe_at = u32_at(&image, 0x3C) as usize;
    assert_eq!(u16_at(&image, pe_at + 6), 2, "section count");
    let directory = pe_at + 24 + 0x70 + 5 * 8;
    assert_eq!(u32_at(&image, directory), 0x2000, "base relocation rva");
    assert_eq!(
        u32_at(&image, directory + 4),
        12,
        "one padded block of 8 + 2 * 2 bytes"
    );
    // `.reloc` raw data follows the 0x200-byte `.text` page.
    let reloc = 0x400;
    assert_eq!(u32_at(&image, reloc), 0x1000, "page rva");
    assert_eq!(
        u16_at(&image, reloc + 8),
        (10 << 12) | 8,
        "DIR64 entry for offset 8"
    );
}

#[test]
fn pinned_digests_match_the_python_builder() {
    assert_eq!(
        hex(sha256(&pe(true, &CODE, &[]))),
        "ddbe3c834fcf497f566b37609f390b23cc07120f6913a01fc5d750e682e6951e"
    );
    assert_eq!(
        hex(sha256(&pe(false, &CODE, &[]))),
        "c9b2daea4a7d7b928da079663b81c08c11af2055433d315f9e28d67cd9109ae6"
    );
    assert_eq!(
        hex(sha256(&pe(true, &[0u8; 16], &[0x1008]))),
        "e40be8c13480b89ac2e1a7af6f67270ca5193fdf8345e889e5da82a6556fb5a1"
    );
}
