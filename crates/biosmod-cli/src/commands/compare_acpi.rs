//! `compare --acpi`: per-object ACPI table comparison, with optional `iasl` method diffs.

use super::{MAX_IMAGE_BYTES, read_bounded};
use crate::CompareArgs;
use crate::output::{Reply, display_path};
use crate::toolchain::{Invocation, Runner};
use biosmod_core::aml::ObjectKind;
use biosmod_core::compare::acpi::{
    AcpiComparison, ChangeStatus, FoundTable, TablePair, compare_tables, tables_from_input,
};
use biosmod_core::compare::asl::{extract_methods, iasl_path, unified_diff};
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use serde_json::json;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

/// How long one `iasl` run may take.
const IASL_TIMEOUT: Duration = Duration::from_secs(120);

/// One written method diff.
#[derive(Debug, Serialize)]
pub struct MethodDiff {
    pub table: String,
    pub path: String,
    pub status: ChangeStatus,
    pub file: String,
}

/// What `--disassemble` produced.
#[derive(Debug, Default, Serialize)]
pub struct Disassembly {
    pub written: Vec<MethodDiff>,
    /// Changed methods `iasl` output did not contain, with the reason.
    pub skipped: Vec<String>,
}

/// Run `compare --acpi`; `runner` runs `iasl` when `--disassemble` is given.
///
/// Example: `compare_acpi(&args, &System)?` prints the per-table method changes.
pub fn compare_acpi(args: &CompareArgs, runner: &dyn Runner) -> Result<Reply> {
    let load = |path: &Path| -> Result<Vec<FoundTable>> {
        let bytes = read_bounded(path, MAX_IMAGE_BYTES)?;
        tables_from_input(bytes).map_err(|e| e.context(path.display()))
    };
    let (a, b) = (load(&args.a)?, load(&args.b)?);
    let report = compare_tables(&a, &b);
    let disassembly = match &args.disassemble {
        Some(dir) => Some(disassemble_changed_methods(runner, &report, &a, &b, dir)?),
        None => None,
    };
    let mut text = render(&report, disassembly.as_ref());
    let mut pairs = serde_json::to_value(&report.pairs).expect("pairs serialize");
    if args.objects {
        for (row, pair) in pairs
            .as_array_mut()
            .expect("pairs array")
            .iter_mut()
            .zip(&report.pairs)
        {
            row["objects_a"] = json!(pair.objects_a);
            row["objects_b"] = json!(pair.objects_b);
            let _ = writeln!(text, "Objects of {} (B):", tag(pair));
            for object in &pair.objects_b {
                let _ = writeln!(
                    text,
                    "  {:?} {} {}",
                    object.kind,
                    object.path,
                    object.sha256.as_deref().unwrap_or("-")
                );
            }
        }
    }
    let data = json!({
        "a": {"path": display_path(&args.a), "tables": a.len()},
        "b": {"path": display_path(&args.b), "tables": b.len()},
        "pairs": pairs,
        "only_in_a": report.only_in_a,
        "only_in_b": report.only_in_b,
        "disassembly": disassembly,
    });
    Ok(Reply::new(data, text))
}

fn tag(pair: &TablePair) -> String {
    format!("{} {}", pair.signature, pair.oem_table_id)
}

fn counts(label: &str, c: &biosmod_core::compare::acpi::ChangeCounts) -> String {
    format!("{label} +{} -{} ~{}", c.added, c.removed, c.changed)
}

fn render(report: &AcpiComparison, disassembly: Option<&Disassembly>) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "{} tables paired, {} only in A, {} only in B",
        report.pairs.len(),
        report.only_in_a.len(),
        report.only_in_b.len()
    );
    for pair in &report.pairs {
        let _ = writeln!(
            text,
            "{}{}: {} -> {} bytes{}; {}; {}; {}",
            tag(pair),
            if pair.ordinal > 0 {
                format!(" #{}", pair.ordinal)
            } else {
                String::new()
            },
            pair.a.length,
            pair.b.length,
            if pair.identical { " (identical)" } else { "" },
            counts("methods", &pair.methods),
            counts("names", &pair.names),
            counts("other", &pair.other),
        );
        for change in &pair.changes {
            let _ = writeln!(
                text,
                "  {:?} {:?} {}",
                change.status, change.kind, change.path
            );
        }
        for (side, table) in [("A", &pair.a), ("B", &pair.b)] {
            for warning in &table.warnings {
                let _ = writeln!(text, "  warning ({side}): {warning}");
            }
        }
    }
    for (title, rows) in [
        ("Only in A", &report.only_in_a),
        ("Only in B", &report.only_in_b),
    ] {
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(text, "{title}:");
        for lone in rows {
            let _ = writeln!(
                text,
                "  {} {} ({} bytes, {})",
                lone.signature, lone.oem_table_id, lone.length, lone.source
            );
        }
    }
    if let Some(d) = disassembly {
        let _ = writeln!(text, "Wrote {} method diffs", d.written.len());
        for diff in &d.written {
            let _ = writeln!(text, "  {}", diff.file);
        }
        for skipped in &d.skipped {
            let _ = writeln!(text, "  skipped: {skipped}");
        }
    }
    text
}

/// Characters of a path that are safe in a file name.
fn file_stem(text: &str) -> String {
    text.trim_start_matches('\\')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Disassemble each table pair that has changed methods with `iasl -d` and write a unified
/// ASL diff per changed, added or removed method under `dir/<SIG>-<OEM table ID>/`.
///
/// Example: `disassemble_changed_methods(&System, &report, &a, &b, Path::new("asl-diffs"))?`
pub fn disassemble_changed_methods(
    runner: &dyn Runner,
    report: &AcpiComparison,
    a: &[FoundTable],
    b: &[FoundTable],
    dir: &Path,
) -> Result<Disassembly> {
    let io =
        |path: &Path, e: std::io::Error| Error::new(Code::Io, format!("{}: {e}", path.display()));
    let mut done = Disassembly::default();
    let work = tempfile::tempdir().map_err(|e| io(Path::new("temporary directory"), e))?;
    for pair in report
        .pairs
        .iter()
        .filter(|p| p.methods != Default::default())
    {
        let mut methods = Vec::new();
        for (side, table) in [("a", &a[pair.index_a]), ("b", &b[pair.index_b])] {
            let aml = work.path().join(format!("{side}-{}.aml", pair.index_a));
            std::fs::write(&aml, table.bytes()).map_err(|e| io(&aml, e))?;
            let finished = runner
                .run(
                    &Invocation::new("iasl")
                        .arg("-d")
                        .arg(&aml)
                        .timeout(IASL_TIMEOUT),
                )
                .map_err(|e| {
                    Error::new(
                        Code::ToolUnavailable,
                        format!("iasl: expected a runnable iasl on PATH (see `bme tools status`) | received {e}"),
                    )
                })?;
            let dsl = aml.with_extension("dsl");
            let text = std::fs::read_to_string(&dsl).map_err(|_| {
                Error::new(
                    Code::ToolFailed,
                    format!(
                        "iasl -d {}: expected {} | received {} ({})",
                        aml.display(),
                        dsl.display(),
                        finished.describe(),
                        finished.tail(300)
                    ),
                )
            })?;
            methods.push(extract_methods(&text));
        }
        let (methods_a, methods_b) = (&methods[0], &methods[1]);
        let table_dir = dir.join(format!(
            "{}-{}{}",
            file_stem(&pair.signature),
            file_stem(&pair.oem_table_id),
            if pair.ordinal > 0 {
                format!("-{}", pair.ordinal)
            } else {
                String::new()
            }
        ));
        for change in pair.changes.iter().filter(|c| c.kind == ObjectKind::Method) {
            let key = iasl_path(&change.path);
            let (old, new) = (methods_a.get(&key), methods_b.get(&key));
            let missing = match change.status {
                ChangeStatus::Added => new.is_none(),
                ChangeStatus::Removed => old.is_none(),
                ChangeStatus::Changed => old.is_none() || new.is_none(),
            };
            if missing {
                done.skipped.push(format!(
                    "{} {}: expected the method in the iasl listing | received none",
                    tag(pair),
                    change.path
                ));
                continue;
            }
            let diff = unified_diff(
                old.map_or("", String::as_str),
                new.map_or("", String::as_str),
                &format!("A {}", change.path),
                &format!("B {}", change.path),
            );
            let file = table_dir.join(format!("{}.diff", file_stem(&key)));
            if file.exists() {
                return Err(Error::new(
                    Code::OutputExists,
                    format!(
                        "{}: expected a new file | received an existing one",
                        file.display()
                    ),
                ));
            }
            std::fs::create_dir_all(&table_dir).map_err(|e| io(&table_dir, e))?;
            crate::config::write_new(&file, diff.as_bytes())?;
            done.written.push(MethodDiff {
                table: tag(pair),
                path: change.path.clone(),
                status: change.status,
                file: display_path(&file).into_owned(),
            });
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::Finished;
    use biosmod_core::aml::fixture::{device, method, scope, table};
    use std::cell::RefCell;

    /// Named fake of `iasl -d`: writes a canned listing next to the `.aml` it is given.
    struct FakeIasl {
        listing_a: &'static str,
        listing_b: &'static str,
        calls: RefCell<Vec<String>>,
    }

    impl Runner for FakeIasl {
        fn run(&self, invocation: &Invocation) -> Result<Finished> {
            let aml = std::path::PathBuf::from(&invocation.args[1]);
            self.calls.borrow_mut().push(format!(
                "{} {}",
                invocation.program.display(),
                invocation.args[0].to_string_lossy()
            ));
            let listing = if aml.file_name().unwrap().to_string_lossy().starts_with('a') {
                self.listing_a
            } else {
                self.listing_b
            };
            std::fs::write(aml.with_extension("dsl"), listing).unwrap();
            Ok(Finished {
                status: Some(0),
                ..Finished::default()
            })
        }
    }

    /// Named fake for a system without `iasl`.
    struct MissingIasl;

    impl Runner for MissingIasl {
        fn run(&self, invocation: &Invocation) -> Result<Finished> {
            Err(Error::new(
                Code::ToolUnavailable,
                format!(
                    "{}: No such file or directory",
                    invocation.program.display()
                ),
            ))
        }
    }

    const LISTING_A: &str = "Scope (\\_SB)\n{\n    Device (SIO1)\n    {\n        Method (SIOS, 1, NotSerialized)\n        {\n            Return (One)\n        }\n    }\n}\n";
    const LISTING_B: &str = "Scope (\\_SB)\n{\n    Device (SIO1)\n    {\n        Method (SIOS, 1, NotSerialized)\n        {\n            Return (Zero)\n        }\n    }\n}\n";

    fn tables() -> (Vec<FoundTable>, Vec<FoundTable>) {
        let build = |body: &[u8]| {
            let aml = scope("\\_SB_", &[device("SIO1", &[method("SIOS", 1, body)])]);
            vec![FoundTable::new(table("DSDT", "TEST", &aml), "fixture".into()).unwrap()]
        };
        (build(&[0xA4, 0x01]), build(&[0xA4, 0x00]))
    }

    #[test]
    fn writes_one_unified_diff_per_changed_method() {
        let (a, b) = tables();
        let report = compare_tables(&a, &b);
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeIasl {
            listing_a: LISTING_A,
            listing_b: LISTING_B,
            calls: RefCell::new(Vec::new()),
        };
        let done =
            disassemble_changed_methods(&fake, &report, &a, &b, &dir.path().join("out")).unwrap();
        assert_eq!(done.written.len(), 1, "{done:?}");
        assert_eq!(done.written[0].path, "\\_SB_.SIO1.SIOS");
        let diff = std::fs::read_to_string(&done.written[0].file).unwrap();
        assert!(
            diff.contains("-            Return (One)")
                && diff.contains("+            Return (Zero)"),
            "{diff}"
        );
        assert!(
            done.written[0]
                .file
                .ends_with("DSDT-TEST/_SB.SIO1.SIOS.diff"),
            "{}",
            done.written[0].file
        );
        assert_eq!(fake.calls.borrow().len(), 2);
        assert!(fake.calls.borrow().iter().all(|c| c == "iasl -d"));
    }

    #[test]
    fn identical_tables_never_call_iasl() {
        let (a, _) = tables();
        let report = compare_tables(&a, &a);
        let fake = FakeIasl {
            listing_a: "",
            listing_b: "",
            calls: RefCell::new(Vec::new()),
        };
        let dir = tempfile::tempdir().unwrap();
        let done = disassemble_changed_methods(&fake, &report, &a, &a, dir.path()).unwrap();
        assert!(done.written.is_empty() && fake.calls.borrow().is_empty());
    }

    #[test]
    fn method_missing_from_the_listing_is_skipped_with_its_path() {
        let (a, b) = tables();
        let report = compare_tables(&a, &b);
        let fake = FakeIasl {
            listing_a: "Scope (\\_SB)\n{\n}\n",
            listing_b: "Scope (\\_SB)\n{\n}\n",
            calls: RefCell::new(Vec::new()),
        };
        let dir = tempfile::tempdir().unwrap();
        let done = disassemble_changed_methods(&fake, &report, &a, &b, dir.path()).unwrap();
        assert!(done.written.is_empty());
        assert!(
            done.skipped[0].contains("\\_SB_.SIO1.SIOS: expected the method in the iasl listing"),
            "{done:?}"
        );
    }

    #[test]
    fn missing_iasl_is_tool_unavailable_and_names_tools_status() {
        let (a, b) = tables();
        let report = compare_tables(&a, &b);
        let dir = tempfile::tempdir().unwrap();
        let error = disassemble_changed_methods(&MissingIasl, &report, &a, &b, dir.path())
            .expect_err("no iasl");
        assert_eq!(error.code, Code::ToolUnavailable);
        assert!(error.message.contains("bme tools status"), "{error}");
    }

    #[test]
    fn existing_diff_file_is_never_overwritten() {
        let (a, b) = tables();
        let report = compare_tables(&a, &b);
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeIasl {
            listing_a: LISTING_A,
            listing_b: LISTING_B,
            calls: RefCell::new(Vec::new()),
        };
        disassemble_changed_methods(&fake, &report, &a, &b, dir.path()).unwrap();
        let error = disassemble_changed_methods(&fake, &report, &a, &b, dir.path())
            .expect_err("second run collides");
        assert_eq!(error.code, Code::OutputExists);
    }

    #[test]
    fn file_stem_keeps_only_safe_characters() {
        assert_eq!(file_stem("\\_SB.PCI0.SIOS"), "_SB.PCI0.SIOS");
        assert_eq!(file_stem("Cpu0 Ist/x"), "Cpu0_Ist_x");
    }

    #[test]
    fn text_lists_changes_and_counts() {
        let (a, b) = tables();
        let report = compare_tables(&a, &b);
        let text = render(&report, None);
        assert!(text.contains("1 tables paired"), "{text}");
        assert!(text.contains("methods +0 -0 ~1"), "{text}");
        assert!(text.contains("Changed Method \\_SB_.SIO1.SIOS"), "{text}");
    }
}
