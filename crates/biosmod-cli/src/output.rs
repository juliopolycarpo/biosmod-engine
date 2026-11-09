//! The machine protocol envelope and human output.
//!
//! With `--json`, stdout carries exactly one JSON document per invocation,
//! for successes and failures alike. Diagnostics always go to stderr.

use biosmod_core::{Code, Error};
use serde::Serialize;
use serde_json::{Value, json};

/// Protocol identifier, versioned independently of catalog schemas.
pub const PROTOCOL: &str = "bme/1";
pub const PRODUCT: &str = "biosmod-engine";

/// Process exit codes.
pub mod exit {
    pub const OK: i32 = 0;
    pub const FAILED: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const INCOMPLETE: i32 = 3;
}

/// A successful command result: structured data plus its human rendering.
#[derive(Debug)]
pub struct Reply {
    pub data: Value,
    pub text: String,
}

impl Reply {
    /// Build a reply from serializable data and human text.
    pub fn new(data: impl Serialize, text: impl Into<String>) -> Reply {
        Reply {
            data: serde_json::to_value(data).expect("reply data serializes"),
            text: text.into(),
        }
    }
}

/// Output settings shared by every command.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub json: bool,
    pub quiet: bool,
}

impl Out {
    /// A progress or warning line on stderr (suppressed by `--quiet`).
    pub fn note(&self, message: impl AsRef<str>) {
        if !self.quiet {
            eprintln!("bme: {}", message.as_ref());
        }
    }

    /// Print a success and return its exit code.
    pub fn success(&self, command: &str, reply: Reply) -> i32 {
        if self.json {
            println!(
                "{}",
                envelope(command, json!({"ok": true, "data": reply.data}))
            );
        } else if !reply.text.is_empty() {
            print!("{}", reply.text);
            if !reply.text.ends_with('\n') {
                println!();
            }
        }
        exit::OK
    }

    /// Print a failure and return its exit code.
    pub fn failure(&self, command: &str, error: &Error) -> i32 {
        if self.json {
            let mut body = json!({"code": error.code, "message": error.message});
            if let Some(details) = &error.details {
                body["details"] = details.clone();
            }
            println!("{}", envelope(command, json!({"ok": false, "error": body})));
        } else {
            eprintln!("bme: {}", error);
        }
        code_for(error.code)
    }
}

fn envelope(command: &str, body: Value) -> String {
    let mut doc = json!({"protocol": PROTOCOL, "product": PRODUCT, "version": biosmod_core::VERSION, "command": command});
    if let (Value::Object(target), Value::Object(extra)) = (&mut doc, body) {
        target.extend(extra);
    }
    serde_json::to_string_pretty(&doc).expect("envelope serializes")
}

/// Exit code for an error code.
pub fn code_for(code: Code) -> i32 {
    match code {
        Code::Usage => exit::USAGE,
        Code::PublishIncomplete => exit::INCOMPLETE,
        _ => exit::FAILED,
    }
}

/// Render rows as aligned columns.
pub fn table(rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = (0..rows.first().map_or(0, Vec::len))
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                if i + 1 == row.len() {
                    cell.clone()
                } else {
                    format!("{cell:<w$}", w = widths[i])
                }
            })
            .collect();
        out += line.join("  ").trim_end();
        out.push('\n');
    }
    out
}
