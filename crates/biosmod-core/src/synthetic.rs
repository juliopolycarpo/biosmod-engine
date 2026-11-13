//! Synthetic firmware and catalog fixtures containing no vendor code.
//!
//! The image follows the PI layout closely enough for the parser and packer:
//! a DXE volume (an LZMA-compressed driver, an empty PAD file, a follower file
//! and a DSDT) and a PEI volume (an execute-in-place PEIM). The catalog
//! exercises supersession, conflicts, holds, growth/reflow, ACPI tables,
//! layered diagnostics and hardware facts.
//!
//! Example: `let fixture = Fixture::new(0x07); let files = fixture.catalog_files();`

use crate::catalog::*;
use crate::codec;
use crate::firmware::rebuild::make_file;
use crate::firmware::{BROTLI_GUID, FFS2_GUID, LZMA_F86_GUID, LZMA_GUID};
pub use crate::json::pretty;
use crate::util::{Digest256, Guid, HexBytes, align, sha256};
use semver::Version;
use std::collections::BTreeMap;

pub const PEIM_GUID: Guid = Guid::constant("11111111-2222-3333-4444-555555555555");
pub const DXE_GUID: Guid = Guid::constant("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
pub const NEXT_GUID: Guid = Guid::constant("99999999-8888-7777-6666-555555555555");
pub const PAD_GUID: Guid = Guid::constant("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
pub const TABLE_GUID: Guid = Guid::constant("7E374E25-8E01-4FEE-87F2-390C23C606CD");
pub const BOARD: &str = "synthetic-board";
pub const FIRMWARE: &str = "synthetic-fw";
pub const FACT: &str = "synthetic-superio";

/// A section with a common four-byte header.
pub fn section(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = ((4 + body.len()) as u32).to_le_bytes()[..3].to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// A GUID-defined section with the 24-byte header (GUID, data offset 24, attributes 1).
pub fn guid_defined_section(guid: Guid, payload: &[u8]) -> Vec<u8> {
    let mut body = guid.0.to_vec();
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(payload);
    section(0x02, &body)
}

/// A compression section (type 01) holding `payload` of the given compression type.
///
/// `decoded_len` is the uncompressed length the section header declares.
pub fn compression_section(compression_type: u8, decoded_len: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = decoded_len.to_le_bytes().to_vec();
    body.push(compression_type);
    body.extend_from_slice(payload);
    section(0x01, &body)
}

/// Deterministic x86-looking code that exercises the BCJ filter's branches.
///
/// Four rotating patterns: a CALL with a small positive operand, a JMP with a
/// negative one (top byte 0xFF), three opcodes in a row (operands overlapping
/// the next opcode) and a CALL whose top byte is not a sign extension, which
/// the filter leaves alone.
pub fn x86_code(size: usize) -> Vec<u8> {
    let mut code = Vec::new();
    let mut index = 0u32;
    while code.len() < size {
        match index % 4 {
            0 => {
                code.extend_from_slice(&[0x55, 0xE8]);
                code.extend_from_slice(&(index.wrapping_mul(37) & 0xFFFF).to_le_bytes());
            }
            1 => {
                code.extend_from_slice(&[0x90, 0xE9]);
                code.extend_from_slice(&index.wrapping_mul(29).wrapping_neg().to_le_bytes());
            }
            2 => {
                code.extend_from_slice(&[0xE8, 0xE8, 0xE9]);
                code.extend_from_slice(&(index.wrapping_mul(11) & 0xFFFF).to_le_bytes());
            }
            _ => code.extend_from_slice(&[0xE8, 0, 0, 0, 0x40]),
        }
        code.push(0xC3);
        index += 1;
    }
    code.truncate(size);
    code
}

/// An LZMA F86 GUID-defined section: the x86 filter, then LZMA, around a section stream.
pub fn lzma_f86_section(stream: &[u8]) -> Vec<u8> {
    let mut filtered = stream.to_vec();
    codec::x86_convert(&mut filtered, true);
    guid_defined_section(LZMA_F86_GUID, &lzma_payload(&filtered))
}

/// A Brotli stream of one uncompressed meta-block (at most 64 KiB) plus the final empty one.
///
/// Lets tests build Brotli sections around any bytes without a compressor.
pub fn brotli_stored(data: &[u8]) -> Vec<u8> {
    assert!(
        (1..=1 << 16).contains(&data.len()),
        "stored Brotli block: expected 1..=65536 bytes | received {}",
        data.len()
    );
    // Bits, LSB first: WBITS=16 (0), ISLAST=0, MNIBBLES=4 (00), MLEN-1 (16), ISUNCOMPRESSED=1.
    let header = (((data.len() - 1) as u32) << 4) | (1 << 20);
    let mut stream = header.to_le_bytes()[..3].to_vec();
    stream.extend_from_slice(data);
    // ISLAST=1, ISLASTEMPTY=1.
    stream.push(0x03);
    stream
}

/// A Brotli GUID-defined section (EDK II layout) wrapping a section stream.
pub fn brotli_section(stream: &[u8]) -> Vec<u8> {
    let mut payload = (stream.len() as u64).to_le_bytes().to_vec();
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend(brotli_stored(stream));
    guid_defined_section(BROTLI_GUID, &payload)
}

fn lzma_payload(stream: &[u8]) -> Vec<u8> {
    let mut template = vec![0x5D, 0, 0, 1, 0];
    template.extend_from_slice(&[0xFF; 8]);
    codec::compress_like(stream, &template).expect("synthetic LZMA")
}

/// An LZMA GUID-defined section wrapping a section stream.
pub fn lzma_section(stream: &[u8]) -> Vec<u8> {
    guid_defined_section(LZMA_GUID, &lzma_payload(stream))
}

/// An FFS file with valid checksums.
pub fn ffs(guid: Guid, kind: u8, body: &[u8], attributes: u8) -> Vec<u8> {
    let mut header = guid.0.to_vec();
    header.extend_from_slice(&[0, 0, kind, attributes, 0, 0, 0, 0xF8]);
    make_file(&header, body).expect("synthetic file")
}

/// An FFSv2 volume holding `files` in order, erased to `length`.
pub fn volume(files: &[Vec<u8>], length: usize) -> Vec<u8> {
    let mut header = vec![0u8; 16];
    header.extend_from_slice(&FFS2_GUID.0);
    header.extend_from_slice(&(length as u64).to_le_bytes());
    header.extend_from_slice(b"_FVH");
    header.extend_from_slice(&0x0004_FEFFu32.to_le_bytes());
    header.extend_from_slice(&0x48u16.to_le_bytes());
    header.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
    for value in [(length / 0x1000) as u32, 0x1000, 0, 0] {
        header.extend_from_slice(&value.to_le_bytes());
    }
    let sum = crate::firmware::checksum16(&header);
    header[50..52].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
    let mut out = header;
    for file in files {
        out.resize(align(out.len(), 8), 0xFF);
        out.extend_from_slice(file);
    }
    out.resize(length, 0xFF);
    out
}

/// Deterministic non-PE bytes with no repeated windows.
pub fn module(seed: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((seed * 7 + i * 31 + (i >> 8) * 13) & 0xFF) as u8)
        .collect()
}

/// Deterministic incompressible bytes from a SHA-256 chain.
pub fn noise(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 32);
    let mut block = b"seed".to_vec();
    while out.len() < size {
        block = sha256(&block).to_vec();
        out.extend_from_slice(&block);
    }
    out.truncate(size);
    out
}

/// A fake DSDT with a correct length field.
pub fn acpi(body: &[u8]) -> Vec<u8> {
    let mut out = b"DSDT".to_vec();
    out.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(&[0; 28]);
    out.extend_from_slice(body);
    out
}

/// A checksum-valid ACPI table with a deterministic `payload_len`-byte payload.
///
/// OEM ID is `SYNTH`, creator is `BME`; `oem_table_id` is padded with NULs to 8 bytes.
///
/// Example: `let table = acpi_table(*b"SSDT", "InPe", 2, 40); assert_eq!(table.len(), 76);`
pub fn acpi_table(
    signature: [u8; 4],
    oem_table_id: &str,
    revision: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut out = signature.to_vec();
    out.extend_from_slice(&((36 + payload_len) as u32).to_le_bytes());
    out.extend_from_slice(&[revision, 0]);
    out.extend_from_slice(b"SYNTH\0");
    let mut id = oem_table_id.as_bytes().to_vec();
    id.resize(8, 0);
    out.extend_from_slice(&id);
    out.extend_from_slice(&7u32.to_le_bytes());
    out.extend_from_slice(b"BME\0");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend(module(signature[0] as usize, payload_len));
    let sum = out.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    out[9] = sum.wrapping_neg();
    out
}

/// Synthetic image whose files store ACPI tables in several places.
///
/// * `pe_guid` (UI name `PeHost`): a PE32 section with `pe_table` at `pe_offset`.
/// * `raw_guid`: a raw section with `raw_table`, then a raw section with a bad-checksum decoy.
/// * `mixed_guid`: one raw section holding `raw_table` and `pe_table` back to back.
///
/// Sections are 4-byte aligned, so each table length is a multiple of 4.
///
/// Example: `let fixture = AcpiInventoryFixture::new(); let image = fixture.image;`
#[derive(Debug, Clone)]
pub struct AcpiInventoryFixture {
    pub image: Vec<u8>,
    pub pe_table: Vec<u8>,
    pub raw_table: Vec<u8>,
    pub decoy: Vec<u8>,
    pub pe_offset: usize,
    pub pe_guid: Guid,
    pub raw_guid: Guid,
    pub mixed_guid: Guid,
}

impl AcpiInventoryFixture {
    /// Build the image and keep the expected table bytes next to it.
    ///
    /// Example: `let fixture = AcpiInventoryFixture::new(); assert!(fixture.pe_offset > 0);`
    pub fn new() -> AcpiInventoryFixture {
        let pe_guid = PEIM_GUID;
        let raw_guid = TABLE_GUID;
        let mixed_guid = NEXT_GUID;
        let pe_table = acpi_table(*b"SSDT", "InPe", 2, 60);
        let raw_table = acpi_table(*b"SSDT", "InRaw", 1, 88);
        let mut decoy = acpi_table(*b"SSDT", "Decoy", 1, 50);
        let last = decoy.len() - 1;
        decoy[last] ^= 0x01;
        let pe_offset = 0x24;
        let mut pe_body = module(5, pe_offset);
        pe_body.extend(&pe_table);
        pe_body.extend(module(6, 20));
        let ui: Vec<u8> = "PeHost\0"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let files = [
            ffs(
                pe_guid,
                0x07,
                &[section(0x10, &pe_body), section(0x15, &ui)].concat(),
                0,
            ),
            ffs(
                raw_guid,
                0x02,
                &[section(0x19, &raw_table), section(0x19, &decoy)].concat(),
                0,
            ),
            ffs(
                mixed_guid,
                0x02,
                &section(0x19, &[&raw_table[..], &pe_table[..]].concat()),
                0,
            ),
        ];
        let mut image = vec![0xFF; 0x1000];
        image.extend(volume(&files, 0x4000));
        AcpiInventoryFixture {
            image,
            pe_table,
            raw_table,
            decoy,
            pe_offset,
            pe_guid,
            raw_guid,
            mixed_guid,
        }
    }
}

impl Default for AcpiInventoryFixture {
    fn default() -> Self {
        AcpiInventoryFixture::new()
    }
}

/// Synthetic image whose only file wraps a firmware volume (FV-image section) holding
/// a file with one ACPI table in a raw section.
///
/// Example: `let fixture = NestedAcpiFixture::new(); assert_ne!(fixture.outer_guid, fixture.inner_guid);`
#[derive(Debug, Clone)]
pub struct NestedAcpiFixture {
    pub image: Vec<u8>,
    pub table: Vec<u8>,
    pub outer_guid: Guid,
    pub inner_guid: Guid,
}

impl NestedAcpiFixture {
    /// Build the image and keep the nested table bytes.
    ///
    /// Example: `let fixture = NestedAcpiFixture::new(); assert_eq!(fixture.table.len(), 76);`
    pub fn new() -> NestedAcpiFixture {
        let outer_guid = DXE_GUID;
        let inner_guid = PEIM_GUID;
        let table = acpi_table(*b"SSDT", "Nested", 1, 40);
        let inner = ffs(inner_guid, 0x07, &section(0x19, &table), 0);
        let inner_volume = volume(&[inner], 0x1000);
        let outer = ffs(outer_guid, 0x0B, &section(0x17, &inner_volume), 0);
        let mut image = vec![0xFF; 0x1000];
        image.extend(volume(&[outer], 0x4000));
        NestedAcpiFixture {
            image,
            table,
            outer_guid,
            inner_guid,
        }
    }
}

impl Default for NestedAcpiFixture {
    fn default() -> Self {
        NestedAcpiFixture::new()
    }
}

/// A 0x400-byte PE32 linked at `base` with one `.text` section (RVA and file offset 0x200).
///
/// A pointer to `base + 0x1234` at 0x210 carries the image's only HIGHLOW
/// relocation (table at 0x300) and `code` starts at 0x220, so two images that
/// differ only in `base` match after relocation normalization.
///
/// Example: `let pe = relocatable_pe(0x1000_0000, b"code");`
pub fn relocatable_pe(base: u32, code: &[u8]) -> Vec<u8> {
    assert!(
        code.len() <= 0xD0,
        "code: expected <= 0xD0 bytes | received {}",
        code.len()
    );
    let mut pe = vec![0u8; 0x400];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
    let optional = 0x98;
    pe[optional..optional + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
    pe[optional + 28..optional + 32].copy_from_slice(&base.to_le_bytes());
    pe[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
    let reloc_dir = optional + 96 + 40;
    pe[reloc_dir..reloc_dir + 4].copy_from_slice(&0x300u32.to_le_bytes());
    pe[reloc_dir + 4..reloc_dir + 8].copy_from_slice(&12u32.to_le_bytes());
    let table = optional + 0xE0;
    pe[table..table + 6].copy_from_slice(b".text\0");
    for (i, v) in [0x200u32, 0x200, 0x200, 0x200].iter().enumerate() {
        pe[table + 8 + i * 4..table + 12 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    pe[0x210..0x214].copy_from_slice(&base.wrapping_add(0x1234).to_le_bytes());
    pe[0x220..0x220 + code.len()].copy_from_slice(code);
    pe[0x300..0x304].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x304..0x308].copy_from_slice(&12u32.to_le_bytes());
    pe[0x308..0x30A].copy_from_slice(&(0x3000u16 | 0x10).to_le_bytes());
    pe
}

/// A BIOS-region image holding `files` in one FFS volume.
///
/// Example: `let image = Image::parse(image_of_files(&[ffs(PEIM_GUID, 0x06, &section(0x10, &pe), 0)]))?;`
pub fn image_of_files(files: &[Vec<u8>]) -> Vec<u8> {
    let mut image = vec![0xFF; 0x1000];
    image.extend(volume(files, 0x8000));
    image
}

/// A replace hunk with 16 bytes of context on each side.
pub fn hunk(data: &[u8], offset: usize, after: &[u8]) -> Hunk {
    let end = offset + after.len();
    Hunk {
        op: HunkOp::Replace,
        offset,
        before: HexBytes(data[offset..end].to_vec()),
        after: HexBytes(after.to_vec()),
        context_before: HexBytes(data[offset.saturating_sub(16)..offset].to_vec()),
        context_after: HexBytes(data[end..(end + 16).min(data.len())].to_vec()),
        findings: vec![],
        wild_before: vec![],
        wild_after: vec![],
    }
}

/// The synthetic image and its modules.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub peim: Vec<u8>,
    pub driver: Vec<u8>,
    pub table: Vec<u8>,
    pub image: Vec<u8>,
}

impl Fixture {
    /// Build the image; `follower_kind` 0x07 (DXE driver) can move, 0x06 (PEIM) cannot.
    pub fn new(follower_kind: u8) -> Fixture {
        Fixture::with_dxe_length(follower_kind, 0x4000)
    }

    /// Build with a custom DXE volume length (small values leave no free space).
    pub fn with_dxe_length(follower_kind: u8, dxe_length: usize) -> Fixture {
        Fixture::with_driver_encoding(follower_kind, dxe_length, lzma_section)
    }

    /// Build with the DXE driver's section stream wrapped by `encode`.
    ///
    /// Example: `Fixture::with_driver_encoding(0x07, 0x4000, brotli_section)` stores the
    /// driver in a decode-only Brotli section.
    pub fn with_driver_encoding(
        follower_kind: u8,
        dxe_length: usize,
        encode: fn(&[u8]) -> Vec<u8>,
    ) -> Fixture {
        let peim = module(1, 256);
        let driver = module(2, 512);
        let table = acpi(&module(3, 96));
        let pei = volume(&[ffs(PEIM_GUID, 0x06, &section(0x10, &peim), 0)], 0x4000);
        let dxe = volume(
            &[
                ffs(DXE_GUID, 0x07, &encode(&section(0x10, &driver)), 0),
                ffs(PAD_GUID, 0xF0, &[], 0),
                ffs(NEXT_GUID, follower_kind, &section(0x10, &module(4, 64)), 0),
                ffs(TABLE_GUID, 0x02, &section(0x19, &table), 0),
            ],
            dxe_length,
        );
        let mut image = vec![0xFF; 0x1000];
        image.extend(dxe);
        image.extend(pei);
        Fixture {
            peim,
            driver,
            table,
            image,
        }
    }

    fn component(
        name: &str,
        guid: Guid,
        leaf: LeafKind,
        source: &[u8],
        hunks: Vec<Hunk>,
    ) -> Component {
        let result = crate::patch::apply(source, &hunks).expect("synthetic hunks apply");
        Component {
            name: name.into(),
            ffs_guid: guid,
            leaf,
            table_offset: 0,
            source_sha256: Digest256::of(source),
            source_size: source.len() as u64,
            result_sha256: Digest256::of(&result),
            result_size: result.len() as u64,
            layer_on: vec![],
            input_sha256: None,
            checks: Checks::default(),
            hunks,
            memory_failure_guard: None,
        }
    }

    fn patch(id: &str, tier: Tier, components: Vec<Component>) -> Patch {
        let mut variants = BTreeMap::new();
        variants.insert(
            FIRMWARE.to_string(),
            Variant::Applicable(ApplicableVariant {
                components,
                requires_facts: vec![],
                context: vec![],
            }),
        );
        Patch {
            schema: PATCH_SCHEMA.into(),
            id: id.into(),
            version: Version::new(1, 0, 0),
            title: format!("synthetic {id}"),
            class: PatchClass::Correction,
            tier,
            findings: vec![id.into()],
            fixes: vec![],
            confidence: Confidence {
                findings: BTreeMap::new(),
                offline_fix: "synthetic".into(),
                physical_fix: "synthetic".into(),
            },
            packing: Packing::Automatic,
            requires: vec![],
            supersedes: vec![],
            conflicts: vec![],
            limits: "synthetic fixture".into(),
            provenance: None,
            variants,
        }
    }

    /// The patch records: PA/PB disjoint PEIM fixes, PS supersedes PA, DG grows the
    /// compressed driver, TB edits the DSDT, HD is held, CX conflicts with PB,
    /// LD is a diagnostic layered on PA, FR needs an asserted fact.
    pub fn patches(&self) -> Vec<Patch> {
        let peim = |hunks| Self::component("Peim", PEIM_GUID, LeafKind::Pe32, &self.peim, hunks);
        let pa = vec![hunk(&self.peim, 10, &[0x90, 0x90])];
        let mut ps_hunks = pa.clone();
        ps_hunks.push(hunk(&self.peim, 50, &[0x00, 0x01]));
        let mut grow = vec![hunk(&self.driver, 20, &[0x11])];
        let tail = noise(0x2400);
        grow.push(Hunk {
            op: HunkOp::Append,
            offset: self.driver.len(),
            after: HexBytes(tail),
            ..hunk(&self.driver, 0, &[])
        });
        grow[1].before = HexBytes::default();
        grow[1].context_before = HexBytes::default();
        grow[1].context_after = HexBytes::default();

        let mut ps = Self::patch("PS", Tier::Optional, vec![peim(ps_hunks)]);
        ps.supersedes = vec!["PA".into()];
        let mut pb = Self::patch(
            "PB",
            Tier::Recommended,
            vec![peim(vec![hunk(&self.peim, 100, &[0xCC])])],
        );
        pb.conflicts = vec!["CX".into()];
        let mut cx = Self::patch(
            "CX",
            Tier::Optional,
            vec![peim(vec![hunk(&self.peim, 150, &[0x02])])],
        );
        cx.conflicts = vec!["PB".into()];

        let pa_result = crate::patch::apply(&self.peim, &pa).expect("PA applies");
        let mut layered = Self::component("Peim", PEIM_GUID, LeafKind::Pe32, &self.peim, vec![]);
        layered.hunks = vec![hunk(&pa_result, 10, &[0x41, 0x41])];
        let layered_result = crate::patch::apply(&pa_result, &layered.hunks).expect("LD applies");
        layered.layer_on = vec!["PA".into()];
        layered.input_sha256 = Some(Digest256::of(&pa_result));
        layered.result_sha256 = Digest256::of(&layered_result);
        let mut ld = Self::patch("LD", Tier::Optional, vec![layered]);
        ld.class = PatchClass::Diagnostic;
        ld.requires = vec!["PA".into()];

        let mut fr = Self::patch(
            "FR",
            Tier::Optional,
            vec![peim(vec![hunk(&self.peim, 200, &[0x03])])],
        );
        if let Some(Variant::Applicable(v)) = fr.variants.get_mut(FIRMWARE) {
            v.requires_facts = vec![FACT.into()];
        }
        let mut fixes_pa = Self::patch("PA", Tier::Recommended, vec![peim(pa)]);
        fixes_pa.fixes = vec!["PA".into()];
        fixes_pa
            .confidence
            .findings
            .insert("PA".into(), "C0".into());
        vec![
            fixes_pa,
            pb,
            ps,
            Self::patch(
                "DG",
                Tier::Optional,
                vec![Self::component(
                    "Driver",
                    DXE_GUID,
                    LeafKind::Pe32,
                    &self.driver,
                    grow,
                )],
            ),
            Self::patch(
                "TB",
                Tier::Optional,
                vec![Self::component(
                    "Table",
                    TABLE_GUID,
                    LeafKind::AcpiTable,
                    &self.table,
                    vec![hunk(&self.table, 40, &[0x5A])],
                )],
            ),
            Self::patch(
                "HD",
                Tier::Hold,
                vec![peim(vec![hunk(&self.peim, 201, &[0x01])])],
            ),
            cx,
            ld,
            fr,
        ]
    }

    /// The findings: `PA` is fixed by patch PA, `OPEN1` has no patch.
    pub fn findings(&self) -> Vec<Finding> {
        let owner = Owner {
            description: "Synthetic Peim, first routine".into(),
            modules: vec![ModuleRef {
                ui_name: "Peim".into(),
                ffs_guid: Some(PEIM_GUID),
            }],
            references: vec![CodeReference {
                build: Some(FIRMWARE.into()),
                module: "Peim".into(),
                location: "offset 0x0A".into(),
            }],
        };
        let finding = |id: &str, status, patches: Vec<String>| Finding {
            schema: FINDING_SCHEMA.into(),
            id: id.into(),
            title: format!("synthetic finding {id}"),
            priority: Priority::P2,
            status,
            affects: Affects {
                label: "Synthetic".into(),
                builds: vec![FIRMWARE.into()],
            },
            owner: owner.clone(),
            confidence: FindingConfidence {
                finding: Grade {
                    grade: "C0".into(),
                    note: Some("code".into()),
                },
                condition: Some(Grade {
                    grade: "C3".into(),
                    note: Some("trigger".into()),
                }),
            },
            description: "Synthetic defect used by the test fixtures.".into(),
            not_established: Some("No hardware effect.".into()),
            remediation: "Synthetic fix, C1.".into(),
            evidence: vec![],
            patches,
            detectors: vec![],
        };
        let mut open = finding("OPEN1", FindingStatus::Open, vec![]);
        open.detectors = vec![self.detector()];
        vec![
            open,
            finding("PA", FindingStatus::FixedByPatch, vec!["PA".into()]),
        ]
    }

    /// Offset in `peim` where the detector's defect pattern sits; no patch touches it.
    pub const DETECTOR_SITE: usize = 120;

    /// A PEIM detector: eight bytes of `peim` with one wildcard, and the same bytes
    /// with the first one flipped as the corrected shape.
    pub fn detector(&self) -> Detector {
        let defect = self.peim[Self::DETECTOR_SITE..Self::DETECTOR_SITE + 8].to_vec();
        let mut fixed = defect.clone();
        fixed[0] ^= 0xFF;
        Detector {
            id: "peim-site".into(),
            title: "synthetic eight-byte site".into(),
            anchor: Anchor::Pe32 {
                module_kind: Some(ModuleKind::Peim),
                ffs_guid: None,
            },
            signatures: vec![Signature {
                label: "site".into(),
                defect: Pattern {
                    bytes: HexBytes(defect),
                    wild: vec![3],
                },
                fixed: Some(Pattern {
                    bytes: HexBytes(fixed),
                    wild: vec![3],
                }),
            }],
            expect: Expect::default(),
        }
    }

    /// The board profile.
    pub fn board(&self, patches: &[Patch]) -> Board {
        Board {
            schema: BOARD_SCHEMA.into(),
            id: BOARD.into(),
            vendor: "Synthetic".into(),
            model: "Fixture".into(),
            chipset: None,
            revision: Revision {
                label: None,
                status: RevisionStatus::Unknown,
                note: Some("synthetic fixture, no hardware".into()),
            },
            description: None,
            firmware: vec![FirmwareBuild {
                id: FIRMWARE.into(),
                title: "Synthetic firmware".into(),
                version_string: None,
                image_size: None,
                note: None,
            }],
            facts: vec![Fact {
                id: FACT.into(),
                statement: "The synthetic board has the synthetic Super I/O".into(),
            }],
            patches: patches.iter().map(|p| p.id.clone()).collect(),
            findings: self.findings().iter().map(|f| f.id.clone()).collect(),
            evidence: vec![],
        }
    }

    /// All catalog files including a generated `catalog.json`, as `(path, bytes)`.
    pub fn catalog_files(&self) -> Vec<(String, Vec<u8>)> {
        let patches = self.patches();
        let mut files: Vec<(String, Vec<u8>)> = patches
            .iter()
            .map(|p| (format!("patches/{}.json", p.id), pretty(p)))
            .collect();
        files.extend(
            self.findings()
                .iter()
                .map(|f| (format!("findings/{}.json", f.id), pretty(f))),
        );
        files.push((
            format!("boards/{BOARD}.json"),
            pretty(&self.board(&patches)),
        ));
        let manifest = Manifest {
            schema: CATALOG_SCHEMA.into(),
            id: "synthetic".into(),
            version: Version::new(1, 0, 0),
            title: "Synthetic test catalog".into(),
            engine: semver::VersionReq::parse(">=0.1.0").expect("valid requirement"),
            description: Some("Generated by biosmod-core; contains no vendor code.".into()),
            files: index_files(&files).expect("synthetic paths are valid"),
        };
        files.push(("catalog.json".into(), pretty(&manifest)));
        files
    }
}

/// FFS file GUID of the synthetic Setup module (`ifr_setup_image`).
pub const SETUP_GUID: Guid = Guid::constant("899407D7-99FE-43D8-9A21-79EC328CAC21");
/// Form set GUID of the synthetic Setup form.
pub const SETUP_FORMSET_GUID: Guid = Guid::constant("7B59104A-C00D-4158-87FF-F04D6396A915");
/// Variable store GUID of the synthetic `Setup` store.
pub const SETUP_VARSTORE_GUID: Guid = Guid::constant("EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9");

/// An HII package: `u24 length | u8 type` header plus `body`.
pub fn hii_package(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = ((4 + body.len()) as u32).to_le_bytes()[..3].to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// An HII package list: GUID, total length, `packages` and the end package.
pub fn hii_package_list(guid: Guid, packages: &[Vec<u8>]) -> Vec<u8> {
    let mut body: Vec<u8> = packages.concat();
    body.extend(hii_package(0xDF, &[]));
    let mut out = guid.0.to_vec();
    out.extend_from_slice(&((20 + body.len()) as u32).to_le_bytes());
    out.extend(body);
    out
}

/// A string package for `language` whose strings are numbered from 1 in UCS-2 blocks.
pub fn hii_string_package(language: &str, strings: &[&str]) -> Vec<u8> {
    let header_size = 46 + language.len() + 1;
    let mut blocks = Vec::new();
    for text in strings {
        blocks.push(0x14);
        for unit in text.encode_utf16() {
            blocks.extend_from_slice(&unit.to_le_bytes());
        }
        blocks.extend_from_slice(&[0, 0]);
    }
    blocks.push(0x00);
    let mut body = (header_size as u32).to_le_bytes().to_vec();
    body.extend_from_slice(&(header_size as u32).to_le_bytes());
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(language.as_bytes());
    body.push(0);
    body.extend(blocks);
    hii_package(0x04, &body)
}

/// An IFR opcode: opcode byte, length with the scope bit, then `payload`.
pub fn ifr_op(opcode: u8, scope: bool, payload: &[u8]) -> Vec<u8> {
    let length = (2 + payload.len()) as u8;
    let mut out = vec![opcode, length | if scope { 0x80 } else { 0 }];
    out.extend_from_slice(payload);
    out
}

/// The `End` opcode that closes a scope.
pub fn ifr_end() -> Vec<u8> {
    ifr_op(0x29, false, &[])
}

/// The 11 bytes that start every question after the opcode header.
fn ifr_question_header(prompt: u16, help: u16, id: u16, store: u16, offset: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [prompt, help, id, store, offset] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.push(0x10);
    out
}

/// A `OneOf` over a u16 value: question header, flags 0x11, then min, max and step.
pub fn ifr_one_of_u16(
    (prompt, help, id): (u16, u16, u16),
    store: u16,
    offset: u16,
    (min, max): (u16, u16),
) -> Vec<u8> {
    let mut payload = ifr_question_header(prompt, help, id, store, offset);
    payload.push(0x11);
    for value in [min, max, 0] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    ifr_op(0x05, true, &payload)
}

/// A `OneOfOption` with a u16 value; `flags` 0x10 is default, 0x20 manufacturing default.
pub fn ifr_option_u16(label: u16, flags: u8, value: u16) -> Vec<u8> {
    let mut payload = label.to_le_bytes().to_vec();
    payload.extend_from_slice(&[flags, 1]);
    payload.extend_from_slice(&value.to_le_bytes());
    ifr_op(0x09, false, &payload)
}

/// A `CheckBox` with a scope for its `Default` opcodes.
pub fn ifr_checkbox((prompt, help, id): (u16, u16, u16), store: u16, offset: u16) -> Vec<u8> {
    let mut payload = ifr_question_header(prompt, help, id, store, offset);
    payload.push(0);
    ifr_op(0x06, true, &payload)
}

/// A `Numeric` over a u8 value.
pub fn ifr_numeric_u8(
    (prompt, help, id): (u16, u16, u16),
    store: u16,
    offset: u16,
    (min, max, step): (u8, u8, u8),
) -> Vec<u8> {
    let mut payload = ifr_question_header(prompt, help, id, store, offset);
    payload.extend_from_slice(&[0x10, min, max, step]);
    ifr_op(0x07, true, &payload)
}

/// A `Default` opcode with a u8 value.
pub fn ifr_default_u8(default_id: u16, value: u8) -> Vec<u8> {
    let mut payload = default_id.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0, value]);
    ifr_op(0x5B, false, &payload)
}

/// A `Subtitle` statement (its scope is closed by the caller).
pub fn ifr_subtitle(prompt: u16) -> Vec<u8> {
    let mut payload = prompt.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0, 0, 0]);
    ifr_op(0x02, true, &payload)
}

/// An `EqIdVal` expression opcode.
pub fn ifr_eq_id_val(question: u16, value: u16) -> Vec<u8> {
    let mut payload = question.to_le_bytes().to_vec();
    payload.extend_from_slice(&value.to_le_bytes());
    ifr_op(0x12, false, &payload)
}

/// A form package holding one form set with the `Setup` variable store (id 1, 0x40 bytes),
/// the standard default store and the given forms.
pub fn ifr_form_package(forms: &[Vec<u8>]) -> Vec<u8> {
    let mut formset = SETUP_FORMSET_GUID.0.to_vec();
    formset.extend_from_slice(&[1, 0, 2, 0, 0]);
    let mut varstore = SETUP_VARSTORE_GUID.0.to_vec();
    varstore.extend_from_slice(&[1, 0, 0x40, 0]);
    varstore.extend_from_slice(b"Setup\0");
    let mut body = ifr_op(0x0E, true, &formset);
    body.extend(ifr_op(0x24, false, &varstore));
    body.extend(ifr_op(0x5C, false, &[0, 0, 0, 0]));
    for form in forms {
        body.extend_from_slice(form);
    }
    body.extend(ifr_end());
    hii_package(0x02, &body)
}

/// The strings that [`ifr_setup_form`] refers to, numbered from 1.
pub fn ifr_setup_strings() -> [&'static str; 12] {
    [
        "Setup",
        "Setup root",
        "Main",
        "ACPI Sleep State",
        "Highest sleep state",
        "Suspend Disabled",
        "S1 (CPU Stop Clock)",
        "S3 (Suspend to RAM)",
        "Enable Hibernation",
        "Allows S4",
        "Fan PWM",
        "Section",
    ]
}

/// One form with a suppressed `OneOf`, a grayed-out `CheckBox` and a `Numeric`.
///
/// The OneOf (question 0x19, `Setup` offset 0x0A, u16, options 0/1/2 with 2 the default)
/// sits in `SuppressIf ideqval 0x9 == 1`; the CheckBox (0x20, offset 0x0D) carries explicit
/// `Default` 1 values under `GrayOutIf ideqval 0x9 == 1`; the Numeric (0x21, offset 0x2C)
/// is unconditional.
pub fn ifr_setup_form() -> Vec<u8> {
    let mut form = ifr_op(0x01, true, &[0x10, 0x27, 3, 0]);
    form.extend(ifr_subtitle(12));
    form.extend(ifr_end());
    form.extend(ifr_op(0x0A, true, &[]));
    form.extend(ifr_eq_id_val(9, 1));
    form.extend(ifr_one_of_u16((4, 5, 0x19), 1, 0x0A, (0, 2)));
    form.extend(ifr_option_u16(6, 0x00, 0));
    form.extend(ifr_option_u16(7, 0x00, 1));
    form.extend(ifr_option_u16(8, 0x30, 2));
    form.extend(ifr_end());
    form.extend(ifr_end());
    form.extend(ifr_op(0x19, true, &[]));
    form.extend(ifr_eq_id_val(9, 1));
    form.extend(ifr_checkbox((9, 10, 0x20), 1, 0x0D));
    form.extend(ifr_default_u8(0, 1));
    form.extend(ifr_default_u8(1, 1));
    form.extend(ifr_end());
    form.extend(ifr_end());
    form.extend(ifr_numeric_u8((11, 0, 0x21), 1, 0x2C, (0, 255, 1)));
    form.extend(ifr_end());
    form.extend(ifr_end());
    form
}

/// A bare module: filler bytes around one package list with English and Portuguese strings.
pub fn ifr_setup_module() -> Vec<u8> {
    let english = hii_string_package("en-US", &ifr_setup_strings());
    let shouted = ifr_setup_strings().map(str::to_uppercase);
    let shouted: Vec<&str> = shouted.iter().map(String::as_str).collect();
    let portuguese = hii_string_package("pt-BR", &shouted);
    let list = hii_package_list(
        Guid::constant("11111111-0000-0000-0000-000000000001"),
        &[ifr_form_package(&[ifr_setup_form()]), english, portuguese],
    );
    let mut bytes = module(5, 96);
    bytes.extend(list);
    bytes.extend(module(6, 40));
    bytes
}

/// A firmware image whose file `SETUP_GUID` holds [`ifr_setup_module`] as a PE32 section.
pub fn ifr_setup_image() -> Vec<u8> {
    let setup = ffs(SETUP_GUID, 0x07, &section(0x10, &ifr_setup_module()), 0);
    let mut image = vec![0xFF; 0x1000];
    image.extend(volume(&[setup], 0x4000));
    image
}

/// One record of a synthetic NVAR store; see [`nvar_store`].
#[derive(Debug, Clone)]
pub enum NvarSpec<'a> {
    /// A variable record with an ASCII name and a GUID-table index.
    /// `link` is the index (in the spec list) of the data-only update that follows it.
    Variable {
        name: &'a str,
        guid_index: u8,
        runtime: bool,
        valid: bool,
        data: &'a [u8],
        link: Option<usize>,
    },
    /// A data-only update record.
    DataOnly {
        valid: bool,
        data: &'a [u8],
        link: Option<usize>,
    },
    /// Bytes placed verbatim (corrupt or unusual records).
    Raw(Vec<u8>),
}

/// A raw NVAR record: `NVAR`, size, next 0xFFFFFF, attributes, then `payload`.
pub fn nvar_record(attributes: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = b"NVAR".to_vec();
    out.extend_from_slice(&((10 + payload.len()) as u16).to_le_bytes());
    out.extend_from_slice(&[0xFF, 0xFF, 0xFF, attributes]);
    out.extend_from_slice(payload);
    out
}

/// An NVAR store of `length` bytes: the records of `specs`, erased space, and `guids` as the
/// table at the very end (index 0 last), the way an AMI NVRAM file body is laid out.
///
/// Links are written as offsets relative to the linking record.
///
/// Example: `let store = nvar_store(&[NvarSpec::Raw(nvar_record(0x82, b"\0A\0\x01"))], &[SETUP_VARSTORE_GUID], 0xFA0);`
pub fn nvar_store(specs: &[NvarSpec<'_>], guids: &[Guid], length: usize) -> Vec<u8> {
    let mut records: Vec<Vec<u8>> = Vec::new();
    for spec in specs {
        records.push(match spec {
            NvarSpec::Variable {
                name,
                guid_index,
                runtime,
                valid,
                data,
                ..
            } => {
                let mut payload = vec![*guid_index];
                payload.extend_from_slice(name.as_bytes());
                payload.push(0);
                payload.extend_from_slice(data);
                let flags = 0x02 | u8::from(*runtime) | if *valid { 0x80 } else { 0 };
                nvar_record(flags, &payload)
            }
            NvarSpec::DataOnly { valid, data, .. } => {
                nvar_record(0x08 | if *valid { 0x80 } else { 0 }, data)
            }
            NvarSpec::Raw(bytes) => bytes.clone(),
        });
    }
    let starts: Vec<usize> = records
        .iter()
        .scan(0usize, |at, record| {
            let start = *at;
            *at += record.len();
            Some(start)
        })
        .collect();
    for (index, spec) in specs.iter().enumerate() {
        let link = match spec {
            NvarSpec::Variable { link, .. } | NvarSpec::DataOnly { link, .. } => *link,
            NvarSpec::Raw(_) => None,
        };
        if let Some(target) = link {
            let relative = (starts[target] - starts[index]) as u32;
            records[index][6..9].copy_from_slice(&relative.to_le_bytes()[..3]);
        }
    }
    let mut out: Vec<u8> = records.concat();
    assert!(
        out.len() + 16 * guids.len() < length,
        "synthetic NVAR store: {} record bytes and {} GUIDs do not fit {length}",
        out.len(),
        guids.len()
    );
    out.resize(length, 0xFF);
    for (index, guid) in guids.iter().enumerate() {
        let end = length - 16 * index;
        out[end - 16..end].copy_from_slice(&guid.0);
    }
    out
}

/// A volume of 0x1000 bytes whose one raw file (`NVRAM_FILE_GUID`) holds `store`, which must be
/// 0xFA0 bytes so the GUID table ends exactly at the volume end, as in a real NVRAM volume.
pub fn nvram_volume(store: &[u8]) -> Vec<u8> {
    let file = ffs(crate::nvram::NVRAM_FILE_GUID, 0x01, store, 0);
    volume(&[file], 0x1000)
}

/// [`ifr_setup_image`] followed by one NVRAM volume per entry of `stores`.
pub fn nvram_image(stores: &[Vec<u8>]) -> Vec<u8> {
    let mut image = ifr_setup_image();
    for store in stores {
        image.extend(nvram_volume(store));
    }
    image
}

/// Variable header style of a synthetic VSS store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VssFlavor {
    /// EDK II `VARIABLE_STORE_HEADER` with the plain-variable GUID (28 bytes).
    Plain,
    /// EDK II header with the authenticated-variable GUID.
    Authenticated,
    /// `$VSS` header (16 bytes) with plain variable headers.
    Dollar,
}

/// One record of a synthetic VSS store; see [`vss_store`].
#[derive(Debug, Clone)]
pub enum VssSpec<'a> {
    Variable {
        name: &'a str,
        guid: Guid,
        attributes: u32,
        state: u8,
        data: &'a [u8],
    },
    /// Bytes placed verbatim at the next 4-byte boundary.
    Raw(Vec<u8>),
}

/// A VSS store of `length` bytes with variables laid out back to back.
///
/// `state` is the raw state byte: 0x3F added, 0x3E in deleted transition, 0x3D deleted,
/// 0x7F header only.
///
/// Example: `let store = vss_store(VssFlavor::Plain, &[], 0x400);`
pub fn vss_store(flavor: VssFlavor, specs: &[VssSpec<'_>], length: usize) -> Vec<u8> {
    let mut out = match flavor {
        VssFlavor::Plain => Guid::constant("DDCF3617-3275-4164-98B6-FE85707FFE7D")
            .0
            .to_vec(),
        VssFlavor::Authenticated => Guid::constant("AAF32C78-947B-439A-A180-2E144EC37792")
            .0
            .to_vec(),
        VssFlavor::Dollar => b"$VSS".to_vec(),
    };
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.extend_from_slice(&[0x5A, 0xFE, 0, 0, 0, 0, 0, 0]);
    for spec in specs {
        out.resize(align(out.len(), 4), 0xFF);
        match spec {
            VssSpec::Variable {
                name,
                guid,
                attributes,
                state,
                data,
            } => {
                let mut name_bytes: Vec<u8> =
                    name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                name_bytes.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&[0xAA, 0x55, *state, 0]);
                out.extend_from_slice(&attributes.to_le_bytes());
                if flavor == VssFlavor::Authenticated {
                    // Monotonic counter, timestamp, public key index.
                    out.extend_from_slice(&[0; 28]);
                }
                out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(&guid.0);
                out.extend(name_bytes);
                out.extend_from_slice(data);
            }
            VssSpec::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }
    assert!(
        out.len() <= length,
        "synthetic VSS store: {} bytes do not fit {length}",
        out.len()
    );
    out.resize(length, 0xFF);
    out
}

/// A 0x40-byte `Setup` payload (the size of the synthetic IFR `Setup` store) with the sleep
/// word at offset 0x0A set to `sleep`.
pub fn setup_payload(sleep: u16) -> Vec<u8> {
    let mut data = vec![0u8; 0x40];
    data[0x0A..0x0C].copy_from_slice(&sleep.to_le_bytes());
    data
}

/// A 0xFA0-byte NVAR store: a `StdDefaults` holder (sleep word 2, plus a `Setup` of another
/// GUID), a three-record `Setup` chain (sleep 0, 1, then 2), a deleted `Gone` variable and an
/// orphan update. GUID table: 0 defaults holder, 1 [`SETUP_VARSTORE_GUID`].
pub fn nvar_sample_store() -> Vec<u8> {
    let other = Guid::constant("80E1202E-2697-4264-9CC9-80762C3E5863");
    let variable = |name, guid_index, data, link| NvarSpec::Variable {
        name,
        guid_index,
        runtime: false,
        valid: true,
        data,
        link,
    };
    let update = |data, link| NvarSpec::DataOnly {
        valid: true,
        data,
        link,
    };
    let (v0, v1, v2) = (setup_payload(0), setup_payload(1), setup_payload(2));
    let nested = nvar_store(
        &[
            variable("Setup", 0, &v2, None),
            variable("Setup", 1, &[7; 6], None),
        ],
        &[SETUP_VARSTORE_GUID, other],
        0x300,
    );
    nvar_store(
        &[
            variable("StdDefaults", 0, &nested, None),
            variable("Setup", 1, &v0, Some(2)),
            update(&v1, Some(3)),
            update(&v2, None),
            NvarSpec::Variable {
                name: "Gone",
                guid_index: 1,
                runtime: true,
                valid: false,
                data: &[1, 2],
                link: None,
            },
            update(&[9, 9], None),
        ],
        &[crate::nvram::AMI_DEFAULTS_GUID, SETUP_VARSTORE_GUID],
        0xFA0,
    )
}

/// Like [`ifr_setup_image`], but the Setup module's questions are built so that the prompt
/// "Twin" names questions 0x30 (`Setup`+0x0A, default 0) and 0x31 (`Setup`+0x0C, none), "Dup"
/// names 0x32 and 0x33 (same storage and default) and "Plain" names 0x34, a numeric without
/// variable storage. One NVRAM volume per entry of `stores` follows the Setup volume.
pub fn ifr_twin_prompt_image(stores: &[Vec<u8>]) -> Vec<u8> {
    let mut form = ifr_op(0x01, true, &[0x10, 0x27, 3, 0]);
    form.extend(ifr_one_of_u16((1, 2, 0x30), 1, 0x0A, (0, 2)));
    form.extend(ifr_option_u16(3, 0x10, 0));
    form.extend(ifr_end());
    form.extend(ifr_one_of_u16((1, 2, 0x31), 1, 0x0C, (0, 2)));
    form.extend(ifr_end());
    form.extend(ifr_one_of_u16((4, 2, 0x32), 1, 0x0A, (0, 2)));
    form.extend(ifr_option_u16(3, 0x10, 0));
    form.extend(ifr_end());
    form.extend(ifr_one_of_u16((5, 2, 0x33), 1, 0x0A, (0, 2)));
    form.extend(ifr_option_u16(3, 0x10, 0));
    form.extend(ifr_end());
    form.extend(ifr_numeric_u8((6, 2, 0x34), 0, 0, (0, 1, 1)));
    form.extend(ifr_end());
    form.extend(ifr_end());
    let strings = hii_string_package("en-US", &["Twin", "Help", "Zero", "Dup", "Dup", "Plain"]);
    let list = hii_package_list(
        Guid::constant("11111111-0000-0000-0000-000000000001"),
        &[ifr_form_package(&[form]), strings],
    );
    let setup = ffs(
        SETUP_GUID,
        0x07,
        &section(0x10, &[module(5, 16), list].concat()),
        0,
    );
    let mut image = vec![0xFF; 0x1000];
    image.extend(volume(&[setup], 0x4000));
    for store in stores {
        image.extend(nvram_volume(store));
    }
    image
}

/// A string that must never reach a report: the fixture plants it in every serial,
/// UUID and asset tag field.
pub const SMBIOS_SECRET: &str = "SECRET-SERIAL";

/// One SMBIOS structure: the four-byte header (type, length, handle), the formatted
/// fields in `body` (everything after the header), then the string set.
///
/// Example: `smbios_structure(127, 0xFFFF, &[], &[])` is the end-of-table marker.
pub fn smbios_structure(kind: u8, handle: u16, body: &[u8], strings: &[&str]) -> Vec<u8> {
    let mut out = vec![kind, (4 + body.len()) as u8];
    out.extend_from_slice(&handle.to_le_bytes());
    out.extend_from_slice(body);
    for text in strings {
        out.extend_from_slice(text.as_bytes());
        out.push(0);
    }
    // Terminates the set; a structure without strings gets its two NULs here.
    out.push(0);
    if strings.is_empty() {
        out.push(0);
    }
    out
}

/// Place `bytes` in a structure body at the specification's `offset`, which counts
/// the four header bytes the body does not hold.
fn put_field(body: &mut [u8], offset: usize, bytes: &[u8]) {
    let start = offset - 4;
    body[start..start + bytes.len()].copy_from_slice(bytes);
}

/// A memory device slot for [`smbios_memory_device`].
#[derive(Debug, Clone)]
pub struct SmbiosSlot {
    pub handle: u16,
    pub total_width: u16,
    pub data_width: u16,
    /// The raw size word: MiB, or KiB with bit 15, or `0x7FFF` for the extended size.
    pub size_word: u16,
    pub extended_size_mib: u32,
    pub speed: u16,
    pub configured_speed: u16,
    pub memory_type: u8,
    pub form_factor: u8,
    pub rank: u8,
    pub locator: &'static str,
    pub bank: &'static str,
    pub manufacturer: &'static str,
    pub part_number: &'static str,
}

impl SmbiosSlot {
    /// An 8 GiB DDR4 DIMM whose total and data widths are both 72 bits, the shape the
    /// MR9A reports (finding R01).
    pub fn populated_72_bit() -> SmbiosSlot {
        SmbiosSlot {
            handle: 0x1100,
            total_width: 72,
            data_width: 72,
            size_word: 8192,
            extended_size_mib: 0,
            speed: 2666,
            configured_speed: 2133,
            memory_type: 0x1A,
            form_factor: 0x09,
            rank: 1,
            locator: "DIMM_A1",
            bank: "BANK 0",
            manufacturer: "Synthetic Memory",
            part_number: "SYN-DDR4-8G",
        }
    }

    /// An empty slot: size 0, unknown widths and type.
    pub fn empty(locator: &'static str) -> SmbiosSlot {
        SmbiosSlot {
            handle: 0x1101,
            total_width: 0xFFFF,
            data_width: 0xFFFF,
            size_word: 0,
            extended_size_mib: 0,
            speed: 0,
            configured_speed: 0,
            memory_type: 0x02,
            form_factor: 0x09,
            rank: 0,
            locator,
            bank: "BANK 1",
            manufacturer: "",
            part_number: "",
        }
    }
}

/// A type 17 structure with the SMBIOS 3.2 formatted length (0x28), a serial number
/// string and an asset tag string that the decoder must not report.
///
/// Example: `smbios_memory_device(&SmbiosSlot::populated_72_bit())`.
pub fn smbios_memory_device(slot: &SmbiosSlot) -> Vec<u8> {
    let mut strings: Vec<&str> = Vec::new();
    // One-based index of a string, or 0 for an empty one.
    let mut index = |text: &'static str| -> u8 {
        if text.is_empty() {
            return 0;
        }
        strings.push(text);
        strings.len() as u8
    };
    let locator = index(slot.locator);
    let bank = index(slot.bank);
    let manufacturer = index(slot.manufacturer);
    let serial = index(SMBIOS_SECRET);
    let asset = index(SMBIOS_SECRET);
    let part = index(slot.part_number);
    // Offsets below are the specification's, minus the four header bytes.
    let mut body = vec![0u8; 0x28 - 4];
    let mut put = |offset: usize, bytes: &[u8]| put_field(&mut body, offset, bytes);
    put(0x08, &slot.total_width.to_le_bytes());
    put(0x0A, &slot.data_width.to_le_bytes());
    put(0x0C, &slot.size_word.to_le_bytes());
    put(0x0E, &[slot.form_factor]);
    put(0x10, &[locator, bank, slot.memory_type]);
    put(0x15, &slot.speed.to_le_bytes());
    put(0x17, &[manufacturer, serial, asset, part, slot.rank]);
    put(0x1C, &slot.extended_size_mib.to_le_bytes());
    put(0x20, &slot.configured_speed.to_le_bytes());
    smbios_structure(17, slot.handle, &body, &strings)
}

/// The structures of the SMBIOS fixture, in table order: BIOS, system, baseboard, a
/// processor (a type the decoder skips), two memory slots and the end marker.
pub fn smbios_fixture_structures() -> Vec<Vec<u8>> {
    let mut bios = [0u8; 0x18 - 4];
    put_field(&mut bios, 0x04, &[1, 2]);
    put_field(&mut bios, 0x08, &[3, 0x7F]);
    let mut system = [0u8; 0x1B - 4];
    put_field(&mut system, 0x04, &[1, 2, 3, 4]);
    put_field(&mut system, 0x08, &[0x11; 16]);
    put_field(&mut system, 0x19, &[5, 6]);
    let mut baseboard = [0u8; 0x0F - 4];
    put_field(&mut baseboard, 0x04, &[1, 2, 3, 4, 5]);
    vec![
        smbios_structure(
            0,
            0,
            &bios,
            &["Synthetic Firmware Vendor", "5.11", "03/22/2023"],
        ),
        smbios_structure(
            1,
            1,
            &system,
            &[
                "SYNTHETIC",
                "Synthetic System",
                "V1",
                SMBIOS_SECRET,
                "SKU-1",
                "Synthetic Family",
            ],
        ),
        smbios_structure(
            2,
            2,
            &baseboard,
            &[
                "SYNTHETIC",
                "Synthetic Board",
                "V1.2",
                SMBIOS_SECRET,
                SMBIOS_SECRET,
            ],
        ),
        smbios_structure(4, 4, &[0u8; 0x30 - 4], &["Synthetic CPU"]),
        smbios_memory_device(&SmbiosSlot::populated_72_bit()),
        smbios_memory_device(&SmbiosSlot::empty("DIMM_B1")),
        smbios_structure(127, 0xFFFF, &[], &[]),
    ]
}

/// The SMBIOS fixture as the kernel exposes it: all structures back to back.
///
/// Example: `smbios::parse(&smbios_table())?.memory_devices.len()` is 2.
pub fn smbios_table() -> Vec<u8> {
    smbios_fixture_structures().concat()
}
