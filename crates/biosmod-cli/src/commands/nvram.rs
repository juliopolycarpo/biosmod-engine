//! `bme nvram`: list the variable stores of a firmware image and read Setup fields from them.

use super::{MAX_IMAGE_BYTES, describe_diagnostic, read_bounded};
use crate::NvramArgs;
use crate::config::write_new;
use crate::output::{Reply, display_path, table};
use biosmod_core::firmware::Image;
use biosmod_core::ifr::{self, ModuleDiagnostic};
use biosmod_core::nvram::{self, DefaultsClass, Field, NvramReport, RecordState, Variable};
use biosmod_core::util::{Guid, sha256_hex};
use biosmod_core::{Code, Error, Result};
use serde_json::json;
use std::fmt::Write as _;

/// Scan the input, then either list records, dump one, or read a field.
pub fn run(args: &NvramArgs) -> Result<Reply> {
    let bytes = read_bounded(&args.input, MAX_IMAGE_BYTES)?;
    let sha256 = sha256_hex(&bytes);
    let guid: Option<Guid> = args.guid.as_deref().map(str::parse).transpose()?;
    let question_id = args
        .question_id
        .as_deref()
        .map(parse_question_id)
        .transpose()?;
    let (mut report, modules, diagnostics, ifr_error) = match Image::parse(bytes.clone()) {
        Ok(image) => {
            let report = nvram::scan_image(&image);
            // Form sizes are context, not a requirement: a listing survives undecodable forms.
            match ifr::decode_image(&image, None, None) {
                Ok(decoded) => (report, decoded.modules, decoded.diagnostics, None),
                Err(error) if args.field.is_none() => {
                    (report, Vec::new(), Vec::new(), Some(error.to_string()))
                }
                Err(error) => return Err(error.context("Setup forms")),
            }
        }
        Err(error) if error.code == Code::FormatUnsupported => {
            (nvram::scan_bytes(&bytes), Vec::new(), Vec::new(), None)
        }
        Err(error) => return Err(error.context(args.input.display())),
    };
    if report.stores.is_empty() && report.issues.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "{}: expected an NVAR or VSS variable store | received none",
                args.input.display()
            ),
        ));
    }
    nvram::check_sizes(&mut report, &modules);
    if let Some(wanted) = &args.store {
        let wanted = wanted.to_lowercase();
        report
            .variables
            .retain(|v| v.store.to_lowercase().contains(&wanted));
        report
            .stores
            .retain(|s| s.label.to_lowercase().contains(&wanted));
        if report.stores.is_empty() {
            return Err(Error::new(
                Code::TargetNotFound,
                format!("--store {wanted:?}: expected a part of a store label | received no match"),
            ));
        }
    }
    if let Some(prompt) = &args.field {
        if modules.is_empty() {
            return Err(Error::new(
                Code::Usage,
                format!(
                    "{}: --field needs a firmware image whose Setup module carries HII forms | received none",
                    args.input.display()
                ),
            ));
        }
        let field = nvram::read_field(&report, &modules, prompt, question_id, args.all_records)?;
        let mut text = field_text(&field);
        // A module that failed to decode may have held the question; say so next to the answer.
        for diagnostic in &diagnostics {
            let _ = writeln!(text, "warning: {}", describe_diagnostic(diagnostic));
        }
        return Ok(Reply::new(
            json!({
                "input": args.input.to_string_lossy(),
                "sha256": sha256,
                "field": field,
                "ifr_diagnostics": diagnostics,
            }),
            text,
        ));
    }

    let selected: Vec<&Variable> = report
        .variables
        .iter()
        .filter(|v| args.all_records || v.state == RecordState::Active)
        .filter(|v| args.name.as_ref().is_none_or(|n| &v.name == n))
        .filter(|v| guid.is_none_or(|g| v.guid == g))
        .collect();
    if args.dump {
        return dump(args, &selected);
    }
    let hidden = report
        .variables
        .iter()
        .filter(|v| !args.all_records && v.state != RecordState::Active)
        .count();
    let text = list_text(
        &report,
        &selected,
        hidden,
        &diagnostics,
        ifr_error.as_deref(),
    );
    let counts: Vec<(String, usize)> = [
        RecordState::Active,
        RecordState::Superseded,
        RecordState::Deleted,
        RecordState::Incomplete,
        RecordState::Orphan,
    ]
    .iter()
    .map(|state| {
        (
            state_name(*state).to_owned(),
            report
                .variables
                .iter()
                .filter(|v| v.state == *state)
                .count(),
        )
    })
    .collect();
    Ok(Reply::new(
        json!({
            "input": args.input.to_string_lossy(),
            "sha256": sha256,
            "stores": report.stores,
            "variables": selected,
            "records_by_state": counts.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
            "issues": report.issues,
            "ifr_diagnostics": diagnostics,
            "ifr_error": ifr_error,
        }),
        text,
    ))
}

/// Decimal or `0x` hexadecimal question id.
fn parse_question_id(text: &str) -> Result<u16> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| {
        Error::new(
            Code::Usage,
            format!(
                "--question-id: expected a number 0..=65535 (decimal or 0x hex) | received {text:?}"
            ),
        )
    })
}

/// Write the data of exactly one record.
fn dump(args: &NvramArgs, selected: &[&Variable]) -> Result<Reply> {
    let output = args
        .output
        .as_ref()
        .expect("clap requires --output with --dump");
    let record = match selected {
        [] => {
            return Err(Error::new(
                Code::TargetNotFound,
                "--dump: expected one matching record | received none; narrow with --name, --guid, --store, --all-records",
            ));
        }
        [one] => *one,
        many => {
            let listing: Vec<String> = many
                .iter()
                .map(|v| {
                    format!(
                        "{} {} {} at {:#x}",
                        v.store,
                        state_name(v.state),
                        v.name,
                        v.offset
                    )
                })
                .collect();
            return Err(Error::new(
                Code::TargetAmbiguous,
                format!(
                    "--dump: expected one matching record | received {} ({}); narrow with --name, --guid, --store",
                    many.len(),
                    listing.join("; ")
                ),
            ));
        }
    };
    write_new(output, &record.data)?;
    let text = format!(
        "Wrote {}: {} bytes of {} ({}, {}), sha256 {}\n",
        output.display(),
        record.size,
        record.name,
        record.store,
        state_name(record.state),
        record.sha256
    );
    Ok(Reply::new(
        json!({"output": display_path(output), "length": record.size, "sha256": record.sha256, "variable": record}),
        text,
    ))
}

fn state_name(state: RecordState) -> &'static str {
    match state {
        RecordState::Active => "active",
        RecordState::Superseded => "superseded",
        RecordState::Deleted => "deleted",
        RecordState::Incomplete => "incomplete",
        RecordState::Orphan => "orphan",
    }
}

fn class_name(class: Option<DefaultsClass>) -> &'static str {
    match class {
        Some(DefaultsClass::Standard) => "standard",
        Some(DefaultsClass::Manufacturing) => "manufacturing",
        None => "-",
    }
}

fn list_text(
    report: &NvramReport,
    selected: &[&Variable],
    hidden: usize,
    diagnostics: &[ModuleDiagnostic],
    ifr_error: Option<&str>,
) -> String {
    let mut text = String::new();
    for store in &report.stores {
        let _ = writeln!(
            text,
            "store {} at {:#x}, {:#x} bytes, {} records{}",
            store.label,
            store.offset,
            store.length,
            store.records,
            store
                .defaults
                .map(|c| format!(", {} defaults", class_name(Some(c))))
                .unwrap_or_default()
        );
    }
    let mut rows = vec![
        [
            "STORE", "STATE", "NAME", "GUID", "SIZE", "OFFSET", "FLAGS", "SHA256",
        ]
        .map(String::from)
        .to_vec(),
    ];
    for v in selected {
        let size = match (v.size_mismatch, v.expected_size) {
            (true, Some(expected)) => {
                format!("{:#x} (IFR {expected:#x}: MISMATCH)", v.size)
            }
            _ => format!("{:#x}", v.size),
        };
        rows.push(vec![
            v.store.clone(),
            state_name(v.state).to_owned(),
            if v.name.is_empty() {
                "-".into()
            } else {
                v.name.clone()
            },
            if v.name.is_empty() {
                "-".into()
            } else {
                v.guid.to_string()
            },
            size,
            format!("{:#x}", v.offset),
            v.flags.join(","),
            v.sha256[..16].to_owned(),
        ]);
    }
    text.push_str(&table(&rows));
    if hidden > 0 {
        let _ = writeln!(
            text,
            "{hidden} superseded, deleted, incomplete or orphan records hidden; pass --all-records"
        );
    }
    for issue in &report.issues {
        let _ = writeln!(
            text,
            "issue {} at {:#x}: {}",
            issue.store, issue.offset, issue.message
        );
    }
    for diagnostic in diagnostics {
        let _ = writeln!(
            text,
            "warning: size check skipped for a module: {}",
            describe_diagnostic(diagnostic)
        );
    }
    if let Some(error) = ifr_error {
        let _ = writeln!(
            text,
            "note: Setup forms not decoded, size check skipped: {error}"
        );
    }
    text
}

fn field_text(field: &Field) -> String {
    let ids: Vec<String> = field
        .question_ids
        .iter()
        .map(|id| format!("{id:#06x}"))
        .collect();
    let show = |value: Option<u64>| value.map_or("none".to_owned(), |v| format!("{v:#x}"));
    let mut text = format!(
        "{:?} (question {}): {} {} +{:#x}, {} byte(s); IFR variable store {:#x} bytes\nIFR default: standard {}, manufacturing {}\n",
        field.prompt,
        ids.join("/"),
        field.varstore_name,
        field.varstore_guid,
        field.offset,
        field.width,
        field.varstore_size,
        show(field.standard_default),
        show(field.manufacturing_default),
    );
    let mut rows = vec![
        [
            "STORE",
            "STATE",
            "DEFAULTS",
            "RECORD",
            "SIZE",
            "STORED",
            "VS DEFAULT",
        ]
        .map(String::from)
        .to_vec(),
    ];
    for v in &field.values {
        rows.push(vec![
            v.store.clone(),
            state_name(v.state).to_owned(),
            class_name(v.defaults).to_owned(),
            format!("{:#x}", v.record_offset),
            if v.size_mismatch {
                format!(
                    "{:#x} (IFR {:#x}: MISMATCH)",
                    v.record_size, field.varstore_size
                )
            } else {
                format!("{:#x}", v.record_size)
            },
            match (&v.value, &v.bytes) {
                (Some(value), _) => format!("{value:#x}"),
                (None, Some(bytes)) => bytes.clone(),
                (None, None) => "outside record".to_owned(),
            },
            match v.equals_default {
                Some(true) => "equal",
                Some(false) => "DIFFERS",
                None => "-",
            }
            .to_owned(),
        ]);
    }
    if field.values.is_empty() {
        text.push_str("no stored record of this variable (use --all-records for history)\n");
    } else {
        text.push_str(&table(&rows));
    }
    text
}
