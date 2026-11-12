//! IFR opcode walker: scopes, form sets, variable stores and statements.
//!
//! Every opcode is `opcode u8, (length:7 | scope:1) u8, payload`. The scope bit opens a
//! scope that a later `End` (0x29) closes, expression opcodes included. Unknown opcodes
//! are skipped by their length; only structural faults (short length, overrun, `End`
//! without a scope, unclosed scopes, excessive depth) are `FormatInvalid`.

use super::expr::{ExpressionBuilder, is_expression_opcode};
use super::hii::{self, PACKAGE_FORMS, PACKAGE_STRINGS, RawList};
use super::*;
use crate::error::{Code, Error, Result};
use crate::util::{Guid, le16};
use std::collections::BTreeMap;

/// Deepest scope nesting accepted. Real Setup forms stay below ten.
pub const MAX_SCOPE_DEPTH: usize = 64;

const OP_FORM: u8 = 0x01;
const OP_SUBTITLE: u8 = 0x02;
const OP_TEXT: u8 = 0x03;
const OP_ONE_OF: u8 = 0x05;
const OP_CHECKBOX: u8 = 0x06;
const OP_NUMERIC: u8 = 0x07;
const OP_PASSWORD: u8 = 0x08;
const OP_ONE_OF_OPTION: u8 = 0x09;
const OP_SUPPRESS_IF: u8 = 0x0A;
const OP_ACTION: u8 = 0x0C;
const OP_FORM_SET: u8 = 0x0E;
const OP_REF: u8 = 0x0F;
const OP_GRAY_OUT_IF: u8 = 0x19;
const OP_DATE: u8 = 0x1A;
const OP_TIME: u8 = 0x1B;
const OP_STRING: u8 = 0x1C;
const OP_DISABLE_IF: u8 = 0x1E;
const OP_ORDERED_LIST: u8 = 0x23;
const OP_VARSTORE: u8 = 0x24;
const OP_VARSTORE_NAME_VALUE: u8 = 0x25;
const OP_VARSTORE_EFI: u8 = 0x26;
const OP_END: u8 = 0x29;
const OP_DEFAULT: u8 = 0x5B;
const OP_DEFAULT_STORE: u8 = 0x5C;

/// Opcode names for error messages and diagnostics.
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_FORM => "Form",
        OP_SUBTITLE => "Subtitle",
        OP_TEXT => "Text",
        0x04 => "Image",
        OP_ONE_OF => "OneOf",
        OP_CHECKBOX => "CheckBox",
        OP_NUMERIC => "Numeric",
        OP_PASSWORD => "Password",
        OP_ONE_OF_OPTION => "OneOfOption",
        OP_SUPPRESS_IF => "SuppressIf",
        0x0B => "Locked",
        OP_ACTION => "Action",
        0x0D => "ResetButton",
        OP_FORM_SET => "FormSet",
        OP_REF => "Ref",
        0x10 => "NoSubmitIf",
        0x11 => "InconsistentIf",
        0x12 => "EqIdVal",
        0x13 => "EqIdId",
        0x14 => "EqIdValList",
        0x15 => "And",
        0x16 => "Or",
        0x17 => "Not",
        0x18 => "Rule",
        OP_GRAY_OUT_IF => "GrayOutIf",
        OP_DATE => "Date",
        OP_TIME => "Time",
        OP_STRING => "String",
        0x1D => "Refresh",
        OP_DISABLE_IF => "DisableIf",
        0x1F => "Animation",
        0x20 => "ToLower",
        0x21 => "ToUpper",
        0x22 => "Map",
        OP_ORDERED_LIST => "OrderedList",
        OP_VARSTORE => "VarStore",
        OP_VARSTORE_NAME_VALUE => "VarStoreNameValue",
        OP_VARSTORE_EFI => "VarStoreEfi",
        0x27 => "VarStoreDevice",
        0x28 => "Version",
        OP_END => "End",
        0x2A => "Match",
        0x2F => "Equal",
        0x46 => "True",
        0x47 => "False",
        0x5A => "Value",
        OP_DEFAULT => "Default",
        OP_DEFAULT_STORE => "DefaultStore",
        0x5D => "FormMap",
        0x5F => "Guid",
        0x60 => "Security",
        0x61 => "ModalTags",
        0x62 => "RefreshId",
        0x63 => "WarningIf",
        _ if is_expression_opcode(opcode) => "Expression",
        _ => "Unknown",
    }
}

/// Byte width of an IFR value type (`EFI_IFR_TYPE_*`), when fixed.
fn value_width(kind: u8) -> Option<usize> {
    match kind {
        0 | 4 => Some(1),
        1 | 7 | 10 => Some(2),
        2 | 6 => Some(4),
        3 => Some(8),
        5 => Some(3),
        _ => None,
    }
}

/// Little-endian value of up to eight bytes.
fn le_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .enumerate()
        .fold(0, |acc, (i, b)| acc | u64::from(*b) << (8 * i))
}

struct PendingCondition {
    kind: ConditionKind,
    /// `Some` while the expression opcodes are still arriving.
    builder: Option<ExpressionBuilder>,
    expression: String,
}

enum FrameKind {
    FormSet,
    Form,
    /// A statement; `option_width` is the value width of its first option.
    Statement {
        form: usize,
        index: usize,
        option_width: Option<u16>,
    },
    Condition(PendingCondition),
    Expression,
    Other,
}

struct Frame {
    opcode: u8,
    offset: usize,
    kind: FrameKind,
}

struct Walker<'a> {
    data: &'a [u8],
    /// Offset of the package being walked, for messages.
    package: usize,
    strings: &'a BTreeMap<u16, String>,
    sets: Vec<FormSet>,
    stack: Vec<Frame>,
}

impl Walker<'_> {
    fn fail(&self, opcode: u8, at: usize, what: impl std::fmt::Display) -> Error {
        Error::new(
            Code::FormatInvalid,
            format!(
                "ifr form package at {:#x}: opcode {} ({opcode:#04x}) at {at:#x}: {what}",
                self.package,
                opcode_name(opcode)
            ),
        )
    }

    fn text(&self, id: u16) -> String {
        self.strings.get(&id).cloned().unwrap_or_default()
    }

    /// Close the expression of a condition that is still collecting opcodes.
    fn finish_collecting(&mut self) {
        if let Some(Frame {
            kind: FrameKind::Condition(pending),
            ..
        }) = self.stack.last_mut()
            && let Some(builder) = pending.builder.take()
        {
            pending.expression = builder.finish();
        }
    }

    fn collecting_builder(&mut self) -> Option<&mut ExpressionBuilder> {
        let frame = self
            .stack
            .iter_mut()
            .rev()
            .find(|f| !matches!(f.kind, FrameKind::Expression))?;
        match &mut frame.kind {
            FrameKind::Condition(pending) => pending.builder.as_mut(),
            _ => None,
        }
    }

    fn push_frame(&mut self, opcode: u8, offset: usize, kind: FrameKind) -> Result<()> {
        if self.stack.len() >= MAX_SCOPE_DEPTH {
            return Err(self.fail(
                opcode,
                offset,
                format!(
                    "scope depth: expected <= {MAX_SCOPE_DEPTH} | received {}",
                    self.stack.len() + 1
                ),
            ));
        }
        self.stack.push(Frame {
            opcode,
            offset,
            kind,
        });
        Ok(())
    }

    /// The form a new statement belongs to: the last form, which must still be open.
    fn current_form(&mut self, opcode: u8, at: usize) -> Result<(usize, &mut Form)> {
        let open = self.stack.iter().any(|f| matches!(f.kind, FrameKind::Form));
        if !open || self.sets.last().is_none_or(|set| set.forms.is_empty()) {
            return Err(self.fail(opcode, at, "statement outside a form"));
        }
        if let Some(set) = self.sets.last_mut() {
            let index = set.forms.len() - 1;
            if let Some(form) = set.forms.last_mut() {
                return Ok((index, form));
            }
        }
        Err(Error::new(Code::Internal, "ifr: open form missing"))
    }

    /// The statement at `(form, index)` of the form set being walked.
    fn statement_mut(&mut self, form: usize, index: usize) -> Option<&mut Statement> {
        self.sets
            .last_mut()?
            .forms
            .get_mut(form)?
            .statements
            .get_mut(index)
    }

    /// Address `(form, statement)` of the innermost open statement frame.
    fn open_statement(&self) -> Option<(usize, usize)> {
        self.stack.iter().rev().find_map(|f| match f.kind {
            FrameKind::Statement { form, index, .. } => Some((form, index)),
            _ => None,
        })
    }

    fn conditions(&self) -> Vec<Condition> {
        self.stack
            .iter()
            .filter_map(|f| match &f.kind {
                FrameKind::Condition(p) => Some(Condition {
                    opcode_offset: f.offset,
                    kind: p.kind,
                    expression: p.expression.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    fn walk(&mut self, start: usize, end: usize) -> Result<()> {
        let mut at = start;
        while at < end {
            if at + 2 > end {
                return Err(self.fail(
                    self.data[at],
                    at,
                    format!("opcode header: expected 2 bytes | received {}", end - at),
                ));
            }
            let opcode = self.data[at];
            let length = usize::from(self.data[at + 1] & 0x7F);
            let scope = self.data[at + 1] & 0x80 != 0;
            if length < 2 {
                return Err(self.fail(
                    opcode,
                    at,
                    format!("length: expected >= 2 | received {length}"),
                ));
            }
            if at + length > end {
                return Err(self.fail(
                    opcode,
                    at,
                    format!(
                        "length {length:#x}: expected <= {:#x} bytes left in the package",
                        end - at
                    ),
                ));
            }
            let payload = &self.data[at + 2..at + length];
            self.opcode(opcode, at, scope, payload)?;
            at += length;
        }
        if let Some(open) = self.stack.last() {
            return Err(self.fail(
                open.opcode,
                open.offset,
                format!("scope opened here: expected End before the package ends at {end:#x}"),
            ));
        }
        Ok(())
    }

    fn need(&self, opcode: u8, at: usize, payload: &[u8], bytes: usize) -> Result<()> {
        if payload.len() < bytes {
            return Err(self.fail(
                opcode,
                at,
                format!(
                    "payload: expected >= {bytes} bytes | received {}",
                    payload.len()
                ),
            ));
        }
        Ok(())
    }

    fn opcode(&mut self, opcode: u8, at: usize, scope: bool, payload: &[u8]) -> Result<()> {
        if opcode != OP_END && !is_expression_opcode(opcode) {
            self.finish_collecting();
        }
        if opcode == OP_END {
            self.finish_collecting();
            let Some(frame) = self.stack.pop() else {
                return Err(self.fail(opcode, at, "End without an open scope"));
            };
            match frame.kind {
                FrameKind::FormSet => self.resolve_varstores(),
                FrameKind::Statement {
                    form,
                    index,
                    option_width,
                } => self.close_statement(form, index, option_width),
                _ => {}
            }
            return Ok(());
        }
        if is_expression_opcode(opcode) {
            let strings = self.strings;
            let collecting = if let Some(builder) = self.collecting_builder() {
                builder.push(opcode, payload, &|id| {
                    strings.get(&id).cloned().unwrap_or_default()
                });
                true
            } else {
                false
            };
            if scope {
                let kind = if collecting {
                    FrameKind::Expression
                } else {
                    FrameKind::Other
                };
                self.push_frame(opcode, at, kind)?;
            }
            return Ok(());
        }
        let mut kind = FrameKind::Other;
        match opcode {
            OP_FORM_SET => {
                if !self.stack.is_empty() {
                    return Err(self.fail(opcode, at, "FormSet inside another scope"));
                }
                self.need(opcode, at, payload, 21)?;
                let class_count = usize::from(payload[20] & 3).min((payload.len() - 21) / 16);
                self.sets.push(FormSet {
                    opcode_offset: at,
                    guid: Guid::from_slice(payload),
                    title: self.text(le16(payload, 16, "")?),
                    help: self.text(le16(payload, 18, "")?),
                    class_guids: (0..class_count)
                        .map(|i| Guid::from_slice(&payload[21 + i * 16..]))
                        .collect(),
                    varstores: vec![],
                    default_stores: vec![],
                    forms: vec![],
                });
                kind = FrameKind::FormSet;
            }
            OP_FORM => {
                // Forms are direct children of the form set; a nested one would
                // detach open statements from the form they were declared in.
                if !matches!(
                    self.stack.as_slice(),
                    [Frame {
                        kind: FrameKind::FormSet,
                        ..
                    }]
                ) {
                    return Err(self.fail(opcode, at, "Form inside another scope"));
                }
                self.need(opcode, at, payload, 4)?;
                let form = Form {
                    opcode_offset: at,
                    id: le16(payload, 0, "")?,
                    title: self.text(le16(payload, 2, "")?),
                    statements: vec![],
                };
                let Some(set) = self.sets.last_mut() else {
                    return Err(self.fail(opcode, at, "Form outside a FormSet"));
                };
                set.forms.push(form);
                kind = FrameKind::Form;
            }
            OP_VARSTORE | OP_VARSTORE_NAME_VALUE | OP_VARSTORE_EFI => {
                self.declare_varstore(opcode, at, payload)?;
            }
            OP_DEFAULT_STORE => {
                self.need(opcode, at, payload, 4)?;
                let store = DefaultStore {
                    name: self.text(le16(payload, 0, "")?),
                    id: le16(payload, 2, "")?,
                };
                match self.sets.last_mut() {
                    Some(set) => set.default_stores.push(store),
                    None => return Err(self.fail(opcode, at, "DefaultStore outside a FormSet")),
                }
            }
            OP_SUPPRESS_IF | OP_GRAY_OUT_IF | OP_DISABLE_IF => {
                kind = FrameKind::Condition(PendingCondition {
                    kind: match opcode {
                        OP_SUPPRESS_IF => ConditionKind::SuppressIf,
                        OP_GRAY_OUT_IF => ConditionKind::GrayOutIf,
                        _ => ConditionKind::DisableIf,
                    },
                    builder: Some(ExpressionBuilder::default()),
                    expression: String::new(),
                });
            }
            OP_SUBTITLE | OP_TEXT | OP_ONE_OF | OP_CHECKBOX | OP_NUMERIC | OP_PASSWORD
            | OP_ACTION | OP_REF | OP_DATE | OP_TIME | OP_STRING | OP_ORDERED_LIST => {
                let (form, index) = self.statement(opcode, at, payload)?;
                kind = FrameKind::Statement {
                    form,
                    index,
                    option_width: None,
                };
            }
            OP_ONE_OF_OPTION => self.option(opcode, at, payload)?,
            OP_DEFAULT => {
                self.need(opcode, at, payload, 3)?;
                // Only plain numbers: date, time, string and other types have no scalar value.
                let value = value_width(payload[2])
                    .filter(|_| payload[2] <= 4)
                    .filter(|width| payload.len() >= 3 + width)
                    .map(|width| le_value(&payload[3..3 + width]));
                let default = ExplicitDefault {
                    opcode_offset: at,
                    default_id: le16(payload, 0, "")?,
                    value,
                };
                let Some((form, index)) = self.open_statement() else {
                    return Err(self.fail(opcode, at, "Default outside a question"));
                };
                match self.statement_mut(form, index) {
                    Some(statement) => statement.defaults.push(default),
                    None => return Err(self.fail(opcode, at, "Default outside a question")),
                }
            }
            _ => {}
        }
        if scope {
            self.push_frame(opcode, at, kind)?;
        } else if matches!(kind, FrameKind::FormSet | FrameKind::Form) {
            // A form or form set without a scope has no body to close.
            return Err(self.fail(opcode, at, "scope bit: expected set"));
        }
        Ok(())
    }

    fn declare_varstore(&mut self, opcode: u8, at: usize, payload: &[u8]) -> Result<()> {
        let store = match opcode {
            OP_VARSTORE => {
                self.need(opcode, at, payload, 21)?;
                VarStore {
                    opcode_offset: at,
                    id: le16(payload, 16, "")?,
                    kind: VarStoreKind::Buffer,
                    guid: Guid::from_slice(payload),
                    size: le16(payload, 18, "")?,
                    name: ascii_name(&payload[20..]),
                }
            }
            OP_VARSTORE_NAME_VALUE => {
                self.need(opcode, at, payload, 18)?;
                VarStore {
                    opcode_offset: at,
                    id: le16(payload, 0, "")?,
                    kind: VarStoreKind::NameValue,
                    guid: Guid::from_slice(&payload[2..]),
                    size: 0,
                    name: String::new(),
                }
            }
            _ => {
                self.need(opcode, at, payload, 22)?;
                let named = payload.len() >= 24;
                VarStore {
                    opcode_offset: at,
                    id: le16(payload, 0, "")?,
                    kind: VarStoreKind::Efi,
                    guid: Guid::from_slice(&payload[2..]),
                    size: if named { le16(payload, 22, "")? } else { 0 },
                    name: if named {
                        ascii_name(&payload[24..])
                    } else {
                        String::new()
                    },
                }
            }
        };
        match self.sets.last_mut() {
            Some(set) => set.varstores.push(store),
            None => return Err(self.fail(opcode, at, "variable store outside a FormSet")),
        }
        Ok(())
    }

    /// Build a statement from its opcode and return its index in the current form.
    fn statement(&mut self, opcode: u8, at: usize, payload: &[u8]) -> Result<(usize, usize)> {
        let kind = match opcode {
            OP_SUBTITLE => StatementKind::Subtitle,
            OP_TEXT => StatementKind::Text,
            OP_ONE_OF => StatementKind::OneOf,
            OP_CHECKBOX => StatementKind::CheckBox,
            OP_NUMERIC => StatementKind::Numeric,
            OP_PASSWORD => StatementKind::Password,
            OP_ACTION => StatementKind::Action,
            OP_REF => StatementKind::Ref,
            OP_DATE => StatementKind::Date,
            OP_TIME => StatementKind::Time,
            OP_STRING => StatementKind::String,
            _ => StatementKind::OrderedList,
        };
        self.need(opcode, at, payload, 4)?;
        let mut statement = Statement {
            opcode_offset: at,
            kind,
            prompt: self.text(le16(payload, 0, "")?),
            help: self.text(le16(payload, 2, "")?),
            question_id: None,
            question_flags: 0,
            flags: 0,
            varstore_id: 0,
            varstore: None,
            var_offset: None,
            width: None,
            min: None,
            max: None,
            step: None,
            target_form: None,
            options: vec![],
            defaults: vec![],
            conditions: self.conditions(),
        };
        if kind.is_question() {
            self.need(opcode, at, payload, 11)?;
            statement.question_id = Some(le16(payload, 4, "")?);
            statement.varstore_id = le16(payload, 6, "")?;
            statement.question_flags = payload[10];
            if statement.varstore_id != 0 {
                statement.var_offset = Some(le16(payload, 8, "")?);
            }
            self.question_body(opcode, at, payload, &mut statement)?;
        }
        let (form_index, form) = self.current_form(opcode, at)?;
        form.statements.push(statement);
        Ok((form_index, form.statements.len() - 1))
    }

    /// Kind-specific fields that follow the 11-byte question header.
    fn question_body(
        &self,
        opcode: u8,
        at: usize,
        payload: &[u8],
        statement: &mut Statement,
    ) -> Result<()> {
        let kind = statement.kind;
        match kind {
            StatementKind::OneOf | StatementKind::Numeric => {
                self.need(opcode, at, payload, 12)?;
                let flags = payload[11];
                let size = 1usize << (flags & 3);
                self.need(opcode, at, payload, 12 + 3 * size)?;
                statement.flags = flags;
                statement.width = Some(size as u16);
                statement.min = Some(le_value(&payload[12..12 + size]));
                statement.max = Some(le_value(&payload[12 + size..12 + 2 * size]));
                statement.step = Some(le_value(&payload[12 + 2 * size..12 + 3 * size]));
            }
            StatementKind::CheckBox => {
                self.need(opcode, at, payload, 12)?;
                statement.flags = payload[11];
                statement.width = Some(1);
            }
            StatementKind::String => {
                self.need(opcode, at, payload, 14)?;
                statement.min = Some(u64::from(payload[11]));
                statement.max = Some(u64::from(payload[12]));
                statement.flags = payload[13];
                statement.width = Some(u16::from(payload[12]) * 2);
            }
            StatementKind::Password => {
                self.need(opcode, at, payload, 15)?;
                let (min, max) = (le16(payload, 11, "")?, le16(payload, 13, "")?);
                statement.min = Some(u64::from(min));
                statement.max = Some(u64::from(max));
                statement.width = max.checked_mul(2);
            }
            StatementKind::OrderedList => {
                self.need(opcode, at, payload, 13)?;
                statement.max = Some(u64::from(payload[11]));
                statement.flags = payload[12];
            }
            StatementKind::Date | StatementKind::Time => {
                self.need(opcode, at, payload, 12)?;
                statement.flags = payload[11];
            }
            StatementKind::Ref => {
                if payload.len() >= 13 {
                    statement.target_form = Some(le16(payload, 11, "")?);
                }
            }
            StatementKind::Action | StatementKind::Text | StatementKind::Subtitle => {}
        }
        Ok(())
    }

    fn option(&mut self, opcode: u8, at: usize, payload: &[u8]) -> Result<()> {
        self.need(opcode, at, payload, 4)?;
        let value_type = payload[3];
        let width = value_width(value_type);
        let value = match width {
            Some(width) => {
                self.need(opcode, at, payload, 4 + width)?;
                le_value(&payload[4..4 + width])
            }
            None => 0,
        };
        let choice = Choice {
            opcode_offset: at,
            value,
            label: self.text(le16(payload, 0, "")?),
            standard_default: payload[2] & 0x10 != 0,
            manufacturing_default: payload[2] & 0x20 != 0,
        };
        let Some((form, index)) = self.open_statement() else {
            return Err(self.fail(opcode, at, "option outside a question"));
        };
        match self.statement_mut(form, index) {
            Some(statement) => statement.options.push(choice),
            None => return Err(self.fail(opcode, at, "option outside a question")),
        }
        for frame in self.stack.iter_mut().rev() {
            if let FrameKind::Statement {
                form: open_form,
                index: open,
                option_width,
            } = &mut frame.kind
                && (*open_form, *open) == (form, index)
            {
                option_width.get_or_insert(width.unwrap_or(0) as u16);
                break;
            }
        }
        Ok(())
    }

    /// An ordered list stores one value per container; width follows its first option.
    fn close_statement(&mut self, form: usize, index: usize, option_width: Option<u16>) {
        let Some(statement) = self.statement_mut(form, index) else {
            return;
        };
        if statement.kind == StatementKind::OrderedList
            && let (Some(containers), Some(width)) = (statement.max, option_width)
            && width > 0
        {
            statement.width = u16::try_from(containers * u64::from(width)).ok();
        }
    }

    fn resolve_varstores(&mut self) {
        let Some(set) = self.sets.last_mut() else {
            return;
        };
        let stores = set.varstores.clone();
        for statement in set.forms.iter_mut().flat_map(|f| &mut f.statements) {
            if statement.varstore_id != 0 {
                statement.varstore =
                    stores
                        .iter()
                        .find(|s| s.id == statement.varstore_id)
                        .map(|s| VarStoreRef {
                            id: s.id,
                            name: s.name.clone(),
                            guid: s.guid,
                        });
            }
        }
    }
}

fn ascii_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes[..end].iter().map(|b| char::from(*b)).collect()
}

/// True when a form package at `offset` starts with a scoped FormSet opcode.
fn starts_with_form_set(data: &[u8], offset: usize, length: usize) -> bool {
    length >= 6 && data[offset + 4] == OP_FORM_SET && data[offset + 5] & 0x80 != 0
}

fn decode_list(data: &[u8], raw: &RawList, language: Option<&str>) -> Result<Option<PackageList>> {
    let forms: Vec<_> = raw
        .packages
        .iter()
        .filter(|p| p.kind == PACKAGE_FORMS && starts_with_form_set(data, p.offset, p.length))
        .collect();
    if forms.is_empty() {
        return Ok(None);
    }
    let mut languages = Vec::new();
    let mut tagged = Vec::new();
    for package in raw.packages.iter().filter(|p| p.kind == PACKAGE_STRINGS) {
        let tag = hii::string_package_language(data, package.offset, package.length)?;
        languages.push(tag.clone());
        tagged.push((tag, package));
    }
    let wanted = language.unwrap_or(DEFAULT_LANGUAGE);
    let chosen = tagged
        .iter()
        .find(|(tag, _)| tag.eq_ignore_ascii_case(wanted))
        .or_else(|| {
            tagged
                .iter()
                .find(|(tag, _)| tag.eq_ignore_ascii_case(DEFAULT_LANGUAGE))
        })
        .or(tagged.first());
    let (language, strings) = match chosen {
        Some((tag, package)) => (
            Some(tag.clone()),
            hii::decode_string_package(data, package.offset, package.length)?.strings,
        ),
        None => (None, BTreeMap::new()),
    };
    let mut form_sets = Vec::new();
    for package in forms {
        let mut walker = Walker {
            data,
            package: package.offset,
            strings: &strings,
            sets: vec![],
            stack: vec![],
        };
        walker.walk(package.offset + 4, package.offset + package.length)?;
        form_sets.append(&mut walker.sets);
    }
    Ok(Some(PackageList {
        offset: raw.offset,
        guid: raw.guid,
        language,
        languages,
        form_sets,
    }))
}

pub fn decode_module(module: &[u8], language: Option<&str>) -> Result<IfrModule> {
    let mut package_lists = Vec::new();
    for raw in hii::find_package_lists(module) {
        if let Some(list) = decode_list(module, &raw, language)? {
            package_lists.push(list);
        }
    }
    Ok(IfrModule { package_lists })
}
