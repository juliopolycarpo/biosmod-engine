//! Read-only decoder for UEFI IFR (HII form packages) embedded in a Setup module.
//!
//! AMI Aptio keeps the Setup menu as an HII package list inside a PE image: form
//! packages (IFR opcodes) plus string packages. [`decode_module`] finds every package
//! list in the bytes of a PE, TE or raw section and returns the form sets with their
//! questions: prompt and help text, question id, backing variable store, offset and
//! width, range, options, explicit defaults and the enclosing `SuppressIf`,
//! `GrayOutIf` and `DisableIf` conditions rendered as text. [`decode_image`] does the
//! same for every PE32/TE leaf of a parsed firmware image.
//!
//! Offsets named `opcode_offset` and `offset` count bytes from the start of the
//! decoded module, not from the flash image.
//!
//! Example:
//! ```
//! use biosmod_core::ifr;
//! let module = ifr::decode_module(&[0u8; 64], None).unwrap();
//! assert!(module.package_lists.is_empty());
//! ```

mod decode;
mod expr;
pub mod hii;
#[cfg(test)]
mod tests;

use crate::error::Result;
use crate::firmware::{Image, SECTION_PE32, SECTION_TE};
use crate::util::Guid;
use serde::Serialize;

/// Language chosen when the caller names none.
pub const DEFAULT_LANGUAGE: &str = "en-US";

/// All HII package lists found in one module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IfrModule {
    pub package_lists: Vec<PackageList>,
}

/// One HII package list with its decoded form sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageList {
    /// Offset of the list header within the module.
    pub offset: usize,
    pub guid: Guid,
    /// Language whose strings were used; `None` when the list has no string package.
    pub language: Option<String>,
    /// Every language the list carries a string package for.
    pub languages: Vec<String>,
    pub form_sets: Vec<FormSet>,
}

/// A form set: the Setup "application" with its variable stores and forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormSet {
    pub opcode_offset: usize,
    pub guid: Guid,
    pub title: String,
    pub help: String,
    pub class_guids: Vec<Guid>,
    pub varstores: Vec<VarStore>,
    pub default_stores: Vec<DefaultStore>,
    pub forms: Vec<Form>,
}

/// Storage flavor of a variable store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VarStoreKind {
    /// `VarStore`: a named buffer of `size` bytes.
    Buffer,
    /// `VarStoreEfi`: an EFI variable accessed by name.
    Efi,
    /// `VarStoreNameValue`: name/value pairs.
    NameValue,
}

/// A variable store declared by a form set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VarStore {
    pub opcode_offset: usize,
    pub id: u16,
    pub kind: VarStoreKind,
    pub guid: Guid,
    pub name: String,
    pub size: u16,
}

/// Names a default class (0 standard, 1 manufacturing, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultStore {
    pub id: u16,
    pub name: String,
}

/// A form: one Setup page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Form {
    pub opcode_offset: usize,
    pub id: u16,
    pub title: String,
    pub statements: Vec<Statement>,
}

/// Statement flavors the decoder reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    OneOf,
    CheckBox,
    Numeric,
    String,
    OrderedList,
    Password,
    Date,
    Time,
    Action,
    Ref,
    Text,
    Subtitle,
}

impl StatementKind {
    /// True for kinds that carry a question id and can be set by the user.
    pub fn is_question(self) -> bool {
        !matches!(self, StatementKind::Text | StatementKind::Subtitle)
    }
}

/// The variable store a question reads and writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VarStoreRef {
    pub id: u16,
    pub name: String,
    pub guid: Guid,
}

/// One selectable value of a `OneOf` or `OrderedList` question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Choice {
    pub opcode_offset: usize,
    pub value: u64,
    pub label: String,
    /// Option flag 0x10 (standard default).
    pub standard_default: bool,
    /// Option flag 0x20 (manufacturing default).
    pub manufacturing_default: bool,
}

/// An explicit `Default` opcode inside a question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExplicitDefault {
    pub opcode_offset: usize,
    /// 0 is the standard default, 1 manufacturing; see [`FormSet::default_stores`].
    pub default_id: u16,
    /// `None` when the value is not a plain number (for example an expression).
    pub value: Option<u64>,
}

/// Which condition opcode encloses a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionKind {
    SuppressIf,
    GrayOutIf,
    DisableIf,
}

/// An enclosing condition with its expression rendered as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Condition {
    pub opcode_offset: usize,
    pub kind: ConditionKind,
    pub expression: String,
}

/// A question, or a layout statement (subtitle, text) that has no question id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Statement {
    pub opcode_offset: usize,
    pub kind: StatementKind,
    pub prompt: String,
    pub help: String,
    pub question_id: Option<u16>,
    /// Question flags byte (0x10 is the callback bit).
    pub question_flags: u8,
    /// Kind-specific flags byte (numeric size and display, checkbox defaults).
    pub flags: u8,
    pub varstore_id: u16,
    /// Resolved store; `None` for statements without storage or an undeclared id.
    pub varstore: Option<VarStoreRef>,
    /// Byte offset inside the store (`VarOffset`); `None` without storage.
    pub var_offset: Option<u16>,
    /// Storage width in bytes (numeric size, 1 for a checkbox, 2 per character for strings).
    pub width: Option<u16>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub step: Option<u64>,
    /// Destination form of a `Ref`.
    pub target_form: Option<u16>,
    pub options: Vec<Choice>,
    pub defaults: Vec<ExplicitDefault>,
    pub conditions: Vec<Condition>,
}

impl Statement {
    /// The default for `default_id` (0 standard, 1 manufacturing).
    ///
    /// Order: an explicit `Default` opcode, then an option flagged as default, then the
    /// checkbox default flags. Returns `None` when the statement states none.
    ///
    /// Example: `if let Some(value) = statement.default_value(0) { println!("{value}") }`
    pub fn default_value(&self, default_id: u16) -> Option<u64> {
        if let Some(explicit) = self
            .defaults
            .iter()
            .find(|d| d.default_id == default_id && d.value.is_some())
        {
            return explicit.value;
        }
        if let Some(option) = self.options.iter().find(|o| {
            if default_id == 1 {
                o.manufacturing_default
            } else {
                o.standard_default
            }
        }) {
            return Some(option.value);
        }
        (self.kind == StatementKind::CheckBox && default_id < 2)
            .then(|| u64::from(self.flags >> default_id & 1))
    }

    /// Where the question lives: store, byte offset and width. `None` without storage.
    ///
    /// Example: `if let Some((store, offset, width)) = statement.storage() { println!("{}+{offset:#x}/{width}", store.name) }`
    pub fn storage(&self) -> Option<(&VarStoreRef, u16, u16)> {
        Some((self.varstore.as_ref()?, self.var_offset?, self.width?))
    }
}

impl IfrModule {
    /// Every statement of every form, with its form set and form.
    pub fn statements(&self) -> impl Iterator<Item = (&FormSet, &Form, &Statement)> {
        self.package_lists
            .iter()
            .flat_map(|list| &list.form_sets)
            .flat_map(|set| set.forms.iter().map(move |form| (set, form)))
            .flat_map(|(set, form)| form.statements.iter().map(move |s| (set, form, s)))
    }

    /// Every question whose prompt equals `prompt` (case-insensitive, trimmed).
    ///
    /// Prompts are not unique ("Access Level" repeats under different conditions), so
    /// callers get all matches and decide.
    ///
    /// Example: `let hits = module.find_questions("ACPI Sleep State");`
    pub fn find_questions(&self, prompt: &str) -> Vec<(&FormSet, &Form, &Statement)> {
        let wanted = prompt.trim().to_lowercase();
        self.statements()
            .filter(|(_, _, s)| s.kind.is_question() && s.prompt.trim().to_lowercase() == wanted)
            .collect()
    }
}

/// Decode every HII package list found in `module`.
///
/// `language` picks the string package (for example `"en-US"`); `None` prefers
/// [`DEFAULT_LANGUAGE`] and otherwise takes the first language present. Bytes that
/// do not hold a well-formed package list are ignored; a list that is well formed but
/// whose packages are malformed fails with `FormatInvalid` naming offset and opcode.
///
/// Example: `let module = biosmod_core::ifr::decode_module(&[0u8; 64], Some("en-US")).unwrap();`
pub fn decode_module(module: &[u8], language: Option<&str>) -> Result<IfrModule> {
    decode::decode_module(module, language)
}

/// The IFR of one module. `guid` and `name` identify the FFS file when the module was
/// taken from a firmware image, and are `None` for a bare PE or section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleIfr {
    pub guid: Option<Guid>,
    pub name: Option<String>,
    #[serde(flatten)]
    pub module: IfrModule,
}

/// A module of an image whose IFR could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleDiagnostic {
    pub guid: Guid,
    pub name: Option<String>,
    pub code: crate::error::Code,
    pub message: String,
}

/// Result of decoding an image: the modules that decoded and those that did not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImageIfr {
    pub modules: Vec<ModuleIfr>,
    pub diagnostics: Vec<ModuleDiagnostic>,
}

/// Decode the IFR of every PE32/TE leaf in `image`, or only of the file `guid`.
///
/// Modules without any package list are left out. Without `guid`, a module whose
/// packages are malformed is reported in [`ImageIfr::diagnostics`] and the other modules
/// still decode. With `guid` set the file must exist (`TargetNotFound`) and its decode
/// errors are returned, naming the file GUID.
///
/// Example: `let found = biosmod_core::ifr::decode_image(&image, None, None)?;`
pub fn decode_image(image: &Image, guid: Option<Guid>, language: Option<&str>) -> Result<ImageIfr> {
    use crate::error::{Code, Error};
    if let Some(wanted) = guid
        && !image.leaves.contains_key(&wanted)
    {
        return Err(Error::new(
            Code::TargetNotFound,
            format!("GUID {wanted}: expected a file in the image | received none"),
        ));
    }
    let mut found = ImageIfr::default();
    for (file_guid, leaves) in &image.leaves {
        if guid.is_some_and(|wanted| wanted != *file_guid) {
            continue;
        }
        for leaf in leaves {
            let (section, stream) = image.section(leaf);
            if section.kind != SECTION_PE32 && section.kind != SECTION_TE {
                continue;
            }
            let name = image.ui_name(leaf.volume, leaf.file);
            match decode_module(section.body(stream), language) {
                Ok(module) if module.package_lists.is_empty() => {}
                Ok(module) => found.modules.push(ModuleIfr {
                    guid: Some(*file_guid),
                    name,
                    module,
                }),
                Err(error) if guid.is_some() => {
                    return Err(error.context(format!("file {file_guid}")));
                }
                Err(error) => found.diagnostics.push(ModuleDiagnostic {
                    guid: *file_guid,
                    name,
                    code: error.code,
                    message: error.message,
                }),
            }
        }
    }
    if found.modules.is_empty()
        && let Some(wanted) = guid
    {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "GUID {wanted}: expected a PE32 or TE module holding an HII form package | received none"
            ),
        ));
    }
    Ok(found)
}
