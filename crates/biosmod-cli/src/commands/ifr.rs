//! `bme ifr`: decode the Setup forms (UEFI IFR) of a firmware image or a single PE.

use super::{MAX_IMAGE_BYTES, read_bounded};
use crate::IfrArgs;
use crate::output::{Reply, table};
use biosmod_core::firmware::Image;
use biosmod_core::ifr::{self, ConditionKind, ModuleIfr, Statement, StatementKind};
use biosmod_core::util::{Guid, sha256_hex};
use biosmod_core::{Code, Error, Result};
use serde_json::json;
use std::fmt::Write as _;

/// Decode the file named by `args`: a full image (every PE with IFR, or `--guid`) or a bare module.
pub fn run(args: &IfrArgs) -> Result<Reply> {
    let bytes = read_bounded(&args.input, MAX_IMAGE_BYTES)?;
    let guid: Option<Guid> = args.guid.as_deref().map(str::parse).transpose()?;
    let language = args.language.as_deref();
    let sha256 = sha256_hex(&bytes);
    let (source, modules) = match Image::parse(bytes.clone()) {
        Ok(image) => ("image", ifr::decode_image(&image, guid, language)?),
        Err(error) if error.code == Code::FormatUnsupported && guid.is_some() => {
            return Err(Error::new(
                Code::Usage,
                format!(
                    "{}: --guid needs a firmware image | received a bare module",
                    args.input.display()
                ),
            ));
        }
        // Not a firmware image: treat the bytes as one PE, TE or raw section.
        Err(error) if error.code == Code::FormatUnsupported => (
            "module",
            vec![ModuleIfr {
                guid: None,
                name: None,
                module: ifr::decode_module(&bytes, language)?,
            }],
        ),
        Err(error) => return Err(error.context(args.input.display())),
    };
    let modules: Vec<ModuleIfr> = modules
        .into_iter()
        .filter(|m| !m.module.package_lists.is_empty())
        .collect();
    if modules.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "{}: expected a module holding an HII form package | received none",
                args.input.display()
            ),
        ));
    }
    let text = render(&modules);
    Ok(Reply::new(
        json!({"input": args.input.to_string_lossy(), "sha256": sha256, "source": source, "modules": modules}),
        text,
    ))
}

fn condition_tag(kind: ConditionKind) -> &'static str {
    match kind {
        ConditionKind::SuppressIf => "suppress",
        ConditionKind::GrayOutIf => "grayout",
        ConditionKind::DisableIf => "disable",
    }
}

fn kind_name(kind: StatementKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// One table row for a question: id, kind, prompt, storage, range, default, options, conditions.
fn row(statement: &Statement) -> Vec<String> {
    let storage = statement
        .storage()
        .map(|(store, offset, width)| format!("{}+{offset:#x}/{width}", store.name))
        .unwrap_or_default();
    let range = match (statement.min, statement.max) {
        (Some(min), Some(max)) if statement.kind != StatementKind::OrderedList => {
            format!("{min:#x}..{max:#x}")
        }
        _ => String::new(),
    };
    let default = statement
        .default_value(0)
        .map(|v| format!("default {v}"))
        .unwrap_or_default();
    let options: Vec<String> = statement
        .options
        .iter()
        .map(|o| {
            let flags = match (o.standard_default, o.manufacturing_default) {
                (true, true) => " (default, mfg)",
                (true, false) => " (default)",
                (false, true) => " (mfg)",
                _ => "",
            };
            format!("{}={:?}{flags}", o.value, o.label)
        })
        .collect();
    let conditions: Vec<String> = statement
        .conditions
        .iter()
        .map(|c| format!("{}: {}", condition_tag(c.kind), c.expression))
        .collect();
    vec![
        statement
            .question_id
            .map(|id| format!("{id:#06x}"))
            .unwrap_or_default(),
        kind_name(statement.kind),
        format!("{:?}", statement.prompt),
        storage,
        range,
        default,
        options.join("; "),
        conditions.join(" && "),
    ]
}

/// Compact text: one table per form listing its questions.
fn render(modules: &[ModuleIfr]) -> String {
    let mut text = String::new();
    for module in modules {
        for list in &module.module.package_lists {
            let origin = match (&module.guid, &module.name) {
                (Some(guid), Some(name)) => format!("{guid} {name} "),
                (Some(guid), None) => format!("{guid} "),
                _ => String::new(),
            };
            let _ = writeln!(
                text,
                "{origin}package list {} at {:#x}, language {}",
                list.guid,
                list.offset,
                list.language.as_deref().unwrap_or("none")
            );
            for set in &list.form_sets {
                let _ = writeln!(text, " FormSet {} {:?}", set.guid, set.title);
                for form in &set.forms {
                    let rows: Vec<Vec<String>> = form
                        .statements
                        .iter()
                        .filter(|s| s.kind.is_question())
                        .map(row)
                        .collect();
                    let _ = writeln!(
                        text,
                        "  Form {:#06x} {:?} ({} questions)",
                        form.id,
                        form.title,
                        rows.len()
                    );
                    for line in table(&rows).lines() {
                        let _ = writeln!(text, "    {line}");
                    }
                }
            }
        }
    }
    text
}
