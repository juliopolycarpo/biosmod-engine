//! Read-only parser for firmware variable stores (NVRAM).
//!
//! Supported layouts:
//!
//! * AMI Aptio NVAR stores: a raw FFS file (usually GUID [`NVRAM_FILE_GUID`]) whose body
//!   is a run of `NVAR` records, a free area and, at the very end of the file, a GUID table
//!   that grows backwards. Records chain through `next` to their data-only updates; the
//!   last record of a chain is the current value. `StdDefaults` and `MfgDefaults` records
//!   (variable GUID [`AMI_DEFAULTS_GUID`]) hold a nested NVAR store of default values with
//!   its own GUID table.
//! * EDK II variable stores (VSS/VSS2): a `VARIABLE_STORE_HEADER` (GUID signature) or a
//!   `$VSS` header, followed by `0x55AA` variable headers, plain or authenticated.
//!
//! [`scan_image`] finds stores structurally, from parsed FFS files and volume bodies
//! (never by searching for signatures), and lists every record with its state. A record
//! that cannot be decoded becomes an [`Issue`] with its offset and the walk goes on at the
//! next plausible record, so one damaged record never hides the rest. [`check_sizes`]
//! compares stored sizes with the IFR variable stores, and [`read_field`] resolves a Setup
//! question to the bytes it occupies in every stored copy.
//!
//! Offsets are image offsets (bytes from the start of the dump).
//!
//! Example:
//! ```
//! let report = biosmod_core::nvram::scan_bytes(&[0xFF; 64]);
//! assert!(report.variables.is_empty());
//! ```

mod field;
mod nvar;
#[cfg(test)]
mod tests;
mod vss;

pub use field::{Field, FieldValue, read_field};

use crate::firmware::Image;
use crate::ifr::{ModuleIfr, VarStoreKind};
use crate::util::{Guid, sha256_hex};
use serde::Serialize;

/// File GUID of the AMI NVRAM volume file.
pub const NVRAM_FILE_GUID: Guid = Guid::constant("CEF5B9A3-476D-497F-9FDC-E98143E0422C");
/// Variable GUID of the `StdDefaults` and `MfgDefaults` holder records.
pub const AMI_DEFAULTS_GUID: Guid = Guid::constant("4599D26F-1A11-49B8-B91F-858745CFF824");

/// Which parser produced a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    /// AMI NVAR store.
    Nvar,
    /// NVAR store nested in a `StdDefaults` or `MfgDefaults` record.
    NvarDefaults,
    /// EDK II VSS/VSS2 store.
    Vss,
}

/// The default class of a defaults store (matches IFR default ids 0 and 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultsClass {
    Standard,
    Manufacturing,
}

impl DefaultsClass {
    /// The IFR default id: 0 standard, 1 manufacturing.
    ///
    /// Example: `assert_eq!(DefaultsClass::Manufacturing.default_id(), 1);`
    pub fn default_id(self) -> u16 {
        match self {
            DefaultsClass::Standard => 0,
            DefaultsClass::Manufacturing => 1,
        }
    }
}

/// What a record means for the variable it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// The current value.
    Active,
    /// An older value of a variable that has a newer record (history).
    Superseded,
    /// Marked deleted (NVAR valid bit clear, VSS `DELETED` state).
    Deleted,
    /// A VSS record whose header or data was never completed.
    Incomplete,
    /// A data-only NVAR record that no variable record links to.
    Orphan,
}

/// One variable store found in the image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Store {
    /// Stable name used by `--store`: `nvar@0x840000`, `nvar@0x840000:StdDefaults`, `vss@0x…`.
    pub label: String,
    pub kind: StoreKind,
    /// Offset of the store's first byte.
    pub offset: usize,
    pub length: usize,
    /// GUID of the FFS file that holds the store, when it sits in one.
    pub file_guid: Option<Guid>,
    pub defaults: Option<DefaultsClass>,
    /// Entries of the NVAR GUID table (0 for VSS).
    pub guid_table_entries: usize,
    /// Records decoded, in every state.
    pub records: usize,
}

/// One variable record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Variable {
    /// [`Store::label`] of the store that holds the record.
    pub store: String,
    /// Empty for an [`RecordState::Orphan`] record.
    pub name: String,
    pub guid: Guid,
    pub state: RecordState,
    /// Offset of the record header.
    pub offset: usize,
    /// Data bytes (without header, name and extended header).
    pub size: usize,
    /// EFI variable attribute bits. NVAR stores no EFI attributes: they are derived
    /// (non-volatile and boot-service always, runtime from the NVAR runtime flag, the
    /// authentication bits from the NVAR flags).
    pub attributes: u32,
    /// Names of the store-native flags (NVAR attribute byte or EFI attribute bits).
    pub flags: Vec<&'static str>,
    /// NVAR extended-header attribute byte, when the record has one.
    pub extended_attributes: Option<u8>,
    /// NVAR extended-header checksum byte as stored (not verified), when present.
    pub checksum: Option<u8>,
    /// Position in the record chain (0 is the variable record, later ones are updates).
    pub chain_index: usize,
    pub chain_len: usize,
    pub defaults: Option<DefaultsClass>,
    pub sha256: String,
    /// Size of the matching IFR `VarStore`, set by [`check_sizes`].
    pub expected_size: Option<usize>,
    /// True when `expected_size` is set and differs from `size`.
    pub size_mismatch: bool,
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// A record or structure that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub store: String,
    pub offset: usize,
    /// Names the invalid value within the expected shape.
    pub message: String,
}

/// Everything found in one image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NvramReport {
    pub stores: Vec<Store>,
    pub variables: Vec<Variable>,
    pub issues: Vec<Issue>,
}

/// Find and decode the variable stores of a parsed image.
///
/// Looks at every top-level FFS file whose body starts with an NVAR record or a VSS store
/// header, at files with [`NVRAM_FILE_GUID`] (an erased one is an empty store), and at the
/// body of file-less volumes for an EDK II store that follows the volume header directly.
///
/// Example: `let report = biosmod_core::nvram::scan_image(&image);`
pub fn scan_image(image: &Image) -> NvramReport {
    let mut report = NvramReport::default();
    for volume in &image.volumes {
        let volume_end = (volume.offset + volume.length).min(image.bytes.len());
        let body_start = volume.offset + volume.header_size;
        if volume.files.is_empty()
            && let Some(body) = image.bytes.get(body_start..volume_end)
            && vss::sniff(body)
        {
            vss::parse_store(body, body_start, None, &mut report);
        }
        for file in &volume.files {
            let body = file.body(&image.bytes);
            let base = file.offset + file.header_size;
            if nvar::sniff(body) || (file.guid == NVRAM_FILE_GUID && is_erased(body)) {
                nvar::parse_store(body, base, Some(file.guid), &mut report);
            } else if vss::sniff(body) {
                vss::parse_store(body, base, Some(file.guid), &mut report);
            } else if file.guid == NVRAM_FILE_GUID {
                report.issues.push(Issue {
                    store: format!("file {}", file.guid),
                    offset: base,
                    message: format!(
                        "NVRAM file body: expected an NVAR or VSS store | received {:02X?}",
                        &body[..body.len().min(4)]
                    ),
                });
            }
        }
    }
    report
}

/// Decode `bytes` as one bare store (NVAR or VSS), for inputs that are not firmware images.
///
/// Example: `let report = biosmod_core::nvram::scan_bytes(&store_bytes);`
pub fn scan_bytes(bytes: &[u8]) -> NvramReport {
    let mut report = NvramReport::default();
    if nvar::sniff(bytes) {
        nvar::parse_store(bytes, 0, None, &mut report);
    } else if vss::sniff(bytes) {
        vss::parse_store(bytes, 0, None, &mut report);
    }
    report
}

/// Compare each record's size with the IFR variable store of the same name and GUID.
///
/// Sets [`Variable::expected_size`] and [`Variable::size_mismatch`]. Only buffer variable
/// stores count, and orphan records (no name) are skipped. A name can be declared by several
/// form sets; the size matches when any declaration agrees. Many stores legitimately differ
/// (`PlatformLang` is declared with 2 bytes and stored as a string), so a mismatch is a
/// per-record fact, not an error.
///
/// Example: `nvram::check_sizes(&mut report, &ifr::decode_image(&image, None, None)?.modules);`
pub fn check_sizes(report: &mut NvramReport, modules: &[ModuleIfr]) {
    let mut declared: Vec<(&str, Guid, usize)> = Vec::new();
    for list in modules.iter().flat_map(|m| &m.module.package_lists) {
        for store in list.form_sets.iter().flat_map(|set| &set.varstores) {
            if store.kind == VarStoreKind::Buffer {
                declared.push((&store.name, store.guid, usize::from(store.size)));
            }
        }
    }
    for variable in &mut report.variables {
        if variable.state == RecordState::Orphan {
            continue;
        }
        let sizes: Vec<usize> = declared
            .iter()
            .filter(|(name, guid, _)| *name == variable.name && *guid == variable.guid)
            .map(|(_, _, size)| *size)
            .collect();
        variable.expected_size = sizes.first().copied();
        variable.size_mismatch = !sizes.is_empty() && !sizes.contains(&variable.size);
    }
}

/// True for an all-0xFF (erased) slice.
pub(crate) fn is_erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0xFF)
}

/// A record before its size and digest are computed; shared by both parsers.
pub(crate) struct Draft {
    pub store: String,
    pub name: String,
    pub guid: Guid,
    pub state: RecordState,
    pub offset: usize,
    pub attributes: u32,
    pub flags: Vec<&'static str>,
    pub extended_attributes: Option<u8>,
    pub checksum: Option<u8>,
    pub chain_index: usize,
    pub chain_len: usize,
    pub defaults: Option<DefaultsClass>,
    pub data: Vec<u8>,
}

impl Draft {
    pub(crate) fn finish(self) -> Variable {
        Variable {
            sha256: sha256_hex(&self.data),
            size: self.data.len(),
            store: self.store,
            name: self.name,
            guid: self.guid,
            state: self.state,
            offset: self.offset,
            attributes: self.attributes,
            flags: self.flags,
            extended_attributes: self.extended_attributes,
            checksum: self.checksum,
            chain_index: self.chain_index,
            chain_len: self.chain_len,
            defaults: self.defaults,
            expected_size: None,
            size_mismatch: false,
            data: self.data,
        }
    }
}

/// EFI variable attribute bits.
pub(crate) const EFI_NON_VOLATILE: u32 = 0x01;
pub(crate) const EFI_BOOTSERVICE: u32 = 0x02;
pub(crate) const EFI_RUNTIME: u32 = 0x04;
pub(crate) const EFI_AUTH_WRITE: u32 = 0x10;
pub(crate) const EFI_TIME_BASED: u32 = 0x20;

/// UCS-2 text up to (not including) the first NUL.
pub(crate) fn ucs2_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
