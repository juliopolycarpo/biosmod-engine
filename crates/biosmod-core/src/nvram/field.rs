//! Resolve a Setup question to its stored bytes: "stored versus default".

use super::{DefaultsClass, NvramReport, RecordState};
use crate::error::{Code, Error, Result};
use crate::ifr::ModuleIfr;
use crate::util::Guid;
use serde::Serialize;

/// The question after resolution: where it lives and what the form says it defaults to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Field {
    pub prompt: String,
    /// Every question id that names this field (one field can be offered by several
    /// questions that differ only in their conditions).
    pub question_ids: Vec<u16>,
    pub varstore_name: String,
    pub varstore_guid: Guid,
    /// Size the IFR declares for the variable store.
    pub varstore_size: u16,
    pub offset: u16,
    pub width: u16,
    /// Default of the form (explicit `Default`, flagged option or checkbox flag), id 0.
    pub standard_default: Option<u64>,
    /// Default id 1.
    pub manufacturing_default: Option<u64>,
    /// One entry per stored record of the variable, in image order.
    pub values: Vec<FieldValue>,
}

/// The field's bytes in one stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldValue {
    pub store: String,
    pub state: RecordState,
    /// Set for records of a `StdDefaults` / `MfgDefaults` store.
    pub defaults: Option<DefaultsClass>,
    /// Offset of the record.
    pub record_offset: usize,
    /// Data size of the record.
    pub record_size: usize,
    /// Little-endian value when the width is at most 8 bytes and the record covers it.
    pub value: Option<u64>,
    /// The raw bytes as hex; `None` when the record is shorter than `offset + width`.
    pub bytes: Option<String>,
    /// Whether `value` equals the form default for the record's class (standard for
    /// everything but a manufacturing defaults store); `None` when either side is unknown.
    pub equals_default: Option<bool>,
    /// True when the record size differs from the IFR variable store size.
    pub size_mismatch: bool,
}

/// Read `prompt` from every stored copy of its variable.
///
/// `prompt` is matched like [`crate::ifr::IfrModule::find_questions`] across all `modules`;
/// `question_id` narrows the match. Questions that share storage and defaults count as one
/// field; otherwise the prompt is ambiguous and the error lists each question id with its
/// form set. Only active records are returned unless `all_records` is set, which adds
/// superseded and deleted ones.
///
/// Example: `let field = nvram::read_field(&report, &modules, "ACPI Sleep State", None, false)?;`
pub fn read_field(
    report: &NvramReport,
    modules: &[ModuleIfr],
    prompt: &str,
    question_id: Option<u16>,
    all_records: bool,
) -> Result<Field> {
    struct Candidate<'a> {
        id: Option<u16>,
        set: String,
        statement: &'a crate::ifr::Statement,
    }
    let mut candidates: Vec<Candidate<'_>> = Vec::new();
    for module in modules {
        for (set, _form, statement) in module.module.find_questions(prompt) {
            if question_id.is_some_and(|wanted| statement.question_id != Some(wanted)) {
                continue;
            }
            candidates.push(Candidate {
                id: statement.question_id,
                set: format!("{} {:?}", set.guid, set.title),
                statement,
            });
        }
    }
    if candidates.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "question prompt {prompt:?}: expected a Setup question{} | received none",
                question_id.map_or_else(String::new, |id| format!(" with id {id:#06x}"))
            ),
        ));
    }
    let storage_of = |c: &Candidate<'_>| {
        c.statement.storage().map(|(store, offset, width)| {
            (
                store.name.clone(),
                store.guid,
                offset,
                width,
                c.statement.default_value(0),
                c.statement.default_value(1),
            )
        })
    };
    let Some(first) = candidates.iter().find_map(storage_of) else {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "question {prompt:?} (ids {}): expected backing variable storage | received none",
                ids(&candidates.iter().map(|c| c.id).collect::<Vec<_>>())
            ),
        ));
    };
    if candidates
        .iter()
        .any(|c| storage_of(c).is_none_or(|s| s != first))
    {
        let listing: Vec<String> = candidates
            .iter()
            .map(|c| {
                format!(
                    "{} in {}",
                    c.id.map_or("?".to_owned(), |id| format!("{id:#06x}")),
                    c.set
                )
            })
            .collect();
        return Err(Error::new(
            Code::TargetAmbiguous,
            format!(
                "question {prompt:?}: expected one question | received {} ({}); pick one with --question-id",
                candidates.len(),
                listing.join(", ")
            ),
        ));
    }
    let (name, guid, offset, width, standard_default, manufacturing_default) = first;
    let statement = candidates[0].statement;
    let declared = super::declared_sizes(&super::declared_buffer_stores(modules), &name, guid);
    let varstore_size = declared.first().copied().map_or(0, |size| size as u16);
    let mut question_ids: Vec<u16> = candidates.iter().filter_map(|c| c.id).collect();
    question_ids.sort_unstable();
    question_ids.dedup();

    let start = usize::from(offset);
    let end = start + usize::from(width);
    let values = report
        .variables
        .iter()
        .filter(|v| v.name == name && v.guid == guid)
        .filter(|v| {
            v.state == RecordState::Active
                || (all_records
                    && matches!(v.state, RecordState::Superseded | RecordState::Deleted))
        })
        .map(|v| {
            let bytes = v.data.get(start..end);
            let value = bytes.filter(|b| b.len() <= 8).map(|b| {
                b.iter()
                    .rev()
                    .fold(0u64, |acc, byte| acc << 8 | u64::from(*byte))
            });
            let wanted = if v.defaults == Some(DefaultsClass::Manufacturing) {
                manufacturing_default
            } else {
                standard_default
            };
            FieldValue {
                store: v.store.clone(),
                state: v.state,
                defaults: v.defaults,
                record_offset: v.offset,
                record_size: v.size,
                value,
                bytes: bytes.map(crate::util::hex),
                equals_default: value.zip(wanted).map(|(stored, default)| stored == default),
                size_mismatch: super::size_disagrees(&declared, v.size),
            }
        })
        .collect();
    Ok(Field {
        prompt: statement.prompt.clone(),
        question_ids,
        varstore_name: name,
        varstore_guid: guid,
        varstore_size,
        offset,
        width,
        standard_default,
        manufacturing_default,
        values,
    })
}

fn ids(ids: &[Option<u16>]) -> String {
    ids.iter()
        .map(|id| id.map_or("?".to_owned(), |id| format!("{id:#06x}")))
        .collect::<Vec<_>>()
        .join(", ")
}
