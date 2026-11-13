//! `compare`: read-only comparison of two images, or of two `tools analyze` exports with `--functions`.

use super::{read_bounded, read_image};
use crate::CompareArgs;
use crate::output::{Reply, display_path};
use biosmod_core::Result;
use biosmod_core::compare::functions::{self, FunctionComparison, FunctionVerdict};
use biosmod_core::compare::{self, Basis, Comparison, Pair, Verdict};
use biosmod_core::util::sha256_hex;
use serde_json::json;
use std::fmt::Write as _;

/// Changed ranges printed per pair in text mode (JSON carries the full capped list).
const TEXT_RANGES: usize = 6;

/// Largest `tools analyze` JSON export accepted.
const MAX_EXPORT_BYTES: u64 = 256 << 20;

pub fn compare(args: &CompareArgs) -> Result<Reply> {
    if args.functions {
        return compare_function_exports(args);
    }
    let a = read_image(&args.a)?;
    let b = read_image(&args.b)?;
    let report = compare::compare_images(&a, &b);
    let text = render(
        &report,
        &args.a.display().to_string(),
        &args.b.display().to_string(),
        &sha256_hex(&a.bytes),
        &sha256_hex(&b.bytes),
    );
    let data = json!({
        "a": {"path": display_path(&args.a), "length": a.bytes.len(), "sha256": sha256_hex(&a.bytes)},
        "b": {"path": display_path(&args.b), "length": b.bytes.len(), "sha256": sha256_hex(&b.bytes)},
        "summary": report.summary,
        "pairs": report.pairs,
        "only_in_a": report.only_in_a,
        "only_in_b": report.only_in_b,
    });
    Ok(Reply::new(data, text))
}

/// Compare two `tools analyze` exports function by function.
fn compare_function_exports(args: &CompareArgs) -> Result<Reply> {
    let load = |path: &std::path::Path| -> Result<functions::FunctionExport> {
        let bytes = read_bounded(path, MAX_EXPORT_BYTES)?;
        functions::parse_export(&bytes, &path.display().to_string())
    };
    let report = functions::compare_functions(&load(&args.a)?, &load(&args.b)?);
    let text = render_functions(&report);
    let data = json!({
        "a": {"path": display_path(&args.a), "program": report.program_a},
        "b": {"path": display_path(&args.b), "program": report.program_b},
        "summary": report.summary,
        "pairs": report.pairs,
        "unmatched_a": report.unmatched_a,
        "unmatched_b": report.unmatched_b,
    });
    Ok(Reply::new(data, text))
}

fn render_functions(report: &FunctionComparison) -> String {
    let s = &report.summary;
    let mut text = format!(
        "A {} ({} functions), B {} ({} functions)\n{} identical, {} normalized-identical, {} changed ({} candidates to review); {} unmatched in A, {} in B\n",
        report.program_a,
        s.functions_a,
        report.program_b,
        s.functions_b,
        s.identical,
        s.normalized_identical,
        s.changed,
        s.candidates,
        s.unmatched_a,
        s.unmatched_b
    );
    for pair in report
        .pairs
        .iter()
        .filter(|p| p.verdict != FunctionVerdict::Identical)
    {
        let _ = writeln!(
            text,
            "  {:?} {} {:#x} -> {} {:#x}{}",
            pair.verdict,
            pair.name_a,
            pair.rva_a,
            pair.name_b,
            pair.rva_b,
            if pair.candidate { " [candidate]" } else { "" }
        );
        for range in &pair.changed_ranges {
            let span = |r: &functions::InstructionRange| match (r.rva_start, r.rva_end) {
                (Some(start), Some(end)) => format!("{start:#x}-{end:#x} ({} insns)", r.count),
                _ => format!("end ({} insns)", r.count),
            };
            let _ = writeln!(text, "      A {} | B {}", span(&range.a), span(&range.b));
        }
    }
    for (title, rows) in [
        ("Unmatched in A", &report.unmatched_a),
        ("Unmatched in B", &report.unmatched_b),
    ] {
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(text, "{title}:");
        for f in rows {
            let _ = writeln!(text, "  {} {:#x} ({} insns)", f.name, f.rva, f.instructions);
        }
    }
    text
}

fn label(
    name: &Option<String>,
    guid: impl std::fmt::Display,
    leaf: &str,
    ordinal: usize,
) -> String {
    let suffix = if ordinal > 0 {
        format!("#{ordinal}")
    } else {
        String::new()
    };
    match name {
        Some(name) => format!("{name} {guid} {leaf}{suffix}"),
        None => format!("{guid} {leaf}{suffix}"),
    }
}

fn pair_text(pair: &Pair) -> String {
    let mut line = format!(
        "  {}: {} -> {} bytes, {} changed",
        label(&pair.name, pair.guid, &pair.leaf, pair.ordinal),
        pair.a.size,
        pair.b.size,
        pair.changed_bytes
    );
    if pair.ranges_basis == Some(Basis::Normalized) {
        line += " after normalization";
    }
    if let Some(error) = &pair.normalization_error {
        let _ = write!(line, " (not normalized: {error})");
    }
    line.push('\n');
    if !pair.sections.is_empty() {
        let names: Vec<String> = pair
            .sections
            .iter()
            .map(|s| format!("{} ({:?})", s.name, s.status))
            .collect();
        let _ = writeln!(line, "      sections: {}", names.join(", "));
    }
    if !pair.changed_ranges.is_empty() {
        let shown: Vec<String> = pair
            .changed_ranges
            .iter()
            .take(TEXT_RANGES)
            .map(|r| format!("{:#x}-{:#x}", r.start, r.end))
            .collect();
        let more = pair.changed_ranges.len().saturating_sub(TEXT_RANGES);
        let _ = writeln!(
            line,
            "      ranges: {}{}",
            shown.join(" "),
            if more > 0 || pair.ranges_truncated {
                " ..."
            } else {
                ""
            }
        );
    }
    line
}

fn render(report: &Comparison, a: &str, b: &str, sha_a: &str, sha_b: &str) -> String {
    let s = &report.summary;
    let mut text = format!("A {a} (sha256 {sha_a})\nB {b} (sha256 {sha_b})\n");
    let _ = writeln!(
        text,
        "{} paired: {} identical, {} identical after relocation normalization, {} different; {} only in A, {} only in B",
        s.paired,
        s.identical,
        s.identical_after_normalization,
        s.different,
        s.only_in_a,
        s.only_in_b
    );
    let section = |text: &mut String, title: &str, verdict: Verdict| {
        let rows: Vec<&Pair> = report
            .pairs
            .iter()
            .filter(|p| p.verdict == verdict)
            .collect();
        if rows.is_empty() {
            return;
        }
        let _ = writeln!(text, "{title}:");
        for pair in rows {
            if verdict == Verdict::Different {
                text.push_str(&pair_text(pair));
            } else {
                let _ = writeln!(
                    text,
                    "  {}",
                    label(&pair.name, pair.guid, &pair.leaf, pair.ordinal)
                );
            }
        }
    };
    section(
        &mut text,
        "Identical after relocation normalization",
        Verdict::IdenticalAfterNormalization,
    );
    section(&mut text, "Different", Verdict::Different);
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
                "  {} ({} bytes)",
                label(&lone.name, lone.guid, &lone.leaf, lone.ordinal),
                lone.side.size
            );
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use biosmod_core::firmware::Image;
    use biosmod_core::synthetic::{PEIM_GUID, ffs, image_of_files, relocatable_pe, section};

    fn report_for(code_a: &[u8], code_b: &[u8]) -> Comparison {
        let parse = |base, code: &[u8]| {
            let files = [ffs(
                PEIM_GUID,
                0x06,
                &section(0x10, &relocatable_pe(base, code)),
                0,
            )];
            Image::parse(image_of_files(&files)).unwrap()
        };
        compare::compare_images(&parse(0x1000_0000, code_a), &parse(0x2000_0000, code_b))
    }

    #[test]
    fn text_names_normalized_pairs_and_differences() {
        let same = render(&report_for(b"x", b"x"), "a.bin", "b.bin", "aa", "bb");
        assert!(
            same.contains("1 identical after relocation normalization"),
            "{same}"
        );
        assert!(
            same.contains("Identical after relocation normalization:\n  "),
            "{same}"
        );
        let different = render(&report_for(b"x", b"y"), "a.bin", "b.bin", "aa", "bb");
        assert!(
            different.contains("1 changed after normalization"),
            "{different}"
        );
        assert!(
            different.contains("sections: .text (Changed)"),
            "{different}"
        );
        assert!(different.contains("ranges: 0x220-0x221"), "{different}");
    }

    #[test]
    fn label_marks_only_repeated_ordinals() {
        assert_eq!(label(&None, "G", "pe32", 0), "G pe32");
        assert_eq!(label(&Some("N".into()), "G", "raw", 2), "N G raw#2");
    }
}
