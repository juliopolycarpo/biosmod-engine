//! The machine protocol envelope and human output.
//!
//! With `--json`, stdout carries exactly one JSON document per invocation,
//! for successes and failures alike. Diagnostics always go to stderr.

use biosmod_core::{Code, Error};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::path::Path;

/// Return a displayable path for a JSON reply.
///
/// Example: `display_path(Path::new("out.bin"))` yields `"out.bin"`.
pub fn display_path(path: &Path) -> Cow<'_, str> {
    path.to_string_lossy()
}

/// Serialize a path using the same display format as JSON reply fields.
///
/// Example: annotate a `PathBuf` field with `#[serde(serialize_with = "serialize_display_path")]`.
pub fn serialize_display_path<S: Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&display_path(path))
}

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
            println!("{}", failure_document(command, error));
        } else {
            eprintln!("bme: {}", error);
        }
        code_for(error.code)
    }
}

/// The exact text `--json` prints for a failure: one `bme/1` document with the error.
///
/// Example: `failure_document("scan", &error)` has `"ok": false` and the error code.
pub fn failure_document(command: &str, error: &Error) -> String {
    let mut body = json!({"code": error.code, "message": error.message});
    if let Some(details) = &error.details {
        body["details"] = details.clone();
    }
    envelope(command, json!({"ok": false, "error": body}))
}

/// The exact text `--json` prints for a success: one `bme/1` document.
///
/// Example: `success_document("scan", &reply)` is what `bme scan --json` writes.
pub fn success_document(command: &str, reply: &Reply) -> String {
    envelope(command, json!({"ok": true, "data": reply.data}))
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

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn display_path_preserves_utf8() {
        assert_eq!(display_path(Path::new("folder/out.bin")), "folder/out.bin");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn display_path_replaces_invalid_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"out-\xff.bin"));
        assert_eq!(display_path(path), "out-\u{fffd}.bin");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_document_carries_the_code_message_and_details() {
        let error = Error::new(Code::CaseDrift, "case x: input dump.bin: changed")
            .with_details(json!({"clean": false}));
        let document: Value =
            serde_json::from_str(&failure_document("case status", &error)).unwrap();
        assert_eq!(document["ok"], false, "{document}");
        assert_eq!(document["command"], "case status");
        assert_eq!(document["error"]["code"], "CASE_DRIFT");
        assert_eq!(
            document["error"]["message"],
            "case x: input dump.bin: changed"
        );
        assert_eq!(document["error"]["details"]["clean"], false);
        let plain = failure_document("scan", &Error::new(Code::Io, "x: unreadable"));
        assert!(!plain.contains("details"), "{plain}");
    }

    #[test]
    fn success_document_wraps_the_data_in_the_protocol_envelope() {
        let reply = Reply::new(json!({"n": 1}), "text");
        let document: Value = serde_json::from_str(&success_document("scan", &reply)).unwrap();
        assert_eq!(document["ok"], true, "{document}");
        assert_eq!(document["protocol"], PROTOCOL);
        assert_eq!(document["data"]["n"], 1);
    }
}
