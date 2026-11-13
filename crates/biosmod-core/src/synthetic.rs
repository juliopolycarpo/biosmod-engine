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
use crate::firmware::{FFS2_GUID, LZMA_GUID};
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

/// An LZMA GUID-defined section wrapping a section stream.
pub fn lzma_section(stream: &[u8]) -> Vec<u8> {
    let mut template = vec![0x5D, 0, 0, 1, 0];
    template.extend_from_slice(&[0xFF; 8]);
    let packed = codec::compress_like(stream, &template).expect("synthetic LZMA");
    let mut body = LZMA_GUID.0.to_vec();
    body.extend_from_slice(&24u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend(packed);
    section(0x02, &body)
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
        let peim = module(1, 256);
        let driver = module(2, 512);
        let table = acpi(&module(3, 96));
        let pei = volume(&[ffs(PEIM_GUID, 0x06, &section(0x10, &peim), 0)], 0x4000);
        let dxe = volume(
            &[
                ffs(DXE_GUID, 0x07, &lzma_section(&section(0x10, &driver)), 0),
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
        vec![
            Self::patch("PA", Tier::Recommended, vec![peim(pa)]),
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
