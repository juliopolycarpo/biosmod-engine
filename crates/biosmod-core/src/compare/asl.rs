//! Per-method ASL text helpers for `iasl` disassembly: method extraction and unified diffs.
//!
//! The core never runs `iasl`; it takes the text a caller produced. Method
//! paths here follow `iasl`'s spelling (trailing `_` padding removed:
//! `\_SB.PCI0`), so [`iasl_path`] converts the raw paths of [`crate::aml`].
//!
//! Example: `let methods = extract_methods(&dsl); let sios = methods.get(&iasl_path("\\_SB_.SIOS"));`

use std::collections::BTreeMap;

/// Largest `a * b` cell count of the diff table; larger inputs become one replaced block.
const MAX_DIFF_CELLS: usize = 4_000_000;

/// Convert a raw AML path to `iasl`'s spelling by dropping each segment's trailing `_` padding.
///
/// Example: `assert_eq!(iasl_path("\\_SB_.PCI0.SIOS"), "\\_SB.PCI0.SIOS");`
pub fn iasl_path(path: &str) -> String {
    let (prefix, rest) = match path.strip_prefix('\\') {
        Some(rest) => ("\\", rest),
        None => ("", path),
    };
    let segments: Vec<&str> = rest
        .split('.')
        .map(|s| {
            let trimmed = s.trim_end_matches('_');
            if trimmed.is_empty() { s } else { trimmed }
        })
        .collect();
    format!("{prefix}{}", segments.join("."))
}

/// A name as written in ASL resolved against the enclosing scope's segments.
fn resolve(scope: &[String], written: &str) -> Vec<String> {
    let (mut base, rest): (Vec<String>, &str) = if let Some(rest) = written.strip_prefix('\\') {
        (Vec::new(), rest)
    } else {
        let parents = written.chars().take_while(|c| *c == '^').count();
        (
            scope[..scope.len().saturating_sub(parents)].to_vec(),
            &written[parents..],
        )
    };
    base.extend(
        rest.split('.')
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    base
}

/// Keywords whose first argument names a namespace object with a body.
const BLOCK_KEYWORDS: [&str; 6] = [
    "Scope",
    "Device",
    "Method",
    "Processor",
    "PowerResource",
    "ThermalZone",
];

struct Frame {
    segments: Vec<String>,
    method_start: Option<usize>,
    depth_before: usize,
}

/// Text of every `Method` in an `iasl` disassembly, keyed by its full `iasl`-style path.
///
/// Braces inside strings and `//` comments are ignored. A method defined twice
/// keeps the last definition.
///
/// Example: `let methods = extract_methods("Scope (\\_SB)\n{\n Method (FOO_, 0)\n {\n }\n}\n");`
pub fn extract_methods(dsl: &str) -> BTreeMap<String, String> {
    let lines: Vec<&str> = dsl.lines().collect();
    let mut methods = BTreeMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut pending: Option<(Vec<String>, Option<usize>)> = None;
    let mut depth = 0usize;
    for (number, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if let Some(keyword) = BLOCK_KEYWORDS
            .iter()
            .find(|k| trimmed.starts_with(&format!("{k} (")))
        {
            let args = &trimmed[keyword.len() + 2..];
            let written = args.split([',', ')']).next().unwrap_or_default().trim();
            let scope = stack.last().map_or(&[][..], |f| f.segments.as_slice());
            pending = Some((
                resolve(scope, written),
                (*keyword == "Method").then_some(number),
            ));
        }
        let mut in_string = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' => in_string = !in_string,
                '/' if !in_string && chars.peek() == Some(&'/') => break,
                '{' if !in_string => {
                    if let Some((segments, method_start)) = pending.take() {
                        stack.push(Frame {
                            segments,
                            method_start,
                            depth_before: depth,
                        });
                    }
                    depth += 1;
                }
                '}' if !in_string => {
                    depth = depth.saturating_sub(1);
                    if let Some(frame) = stack.pop_if(|f| f.depth_before == depth)
                        && let Some(start) = frame.method_start
                    {
                        let path = format!("\\{}", frame.segments.join("."));
                        methods.insert(path, lines[start..=number].join("\n"));
                    }
                }
                _ => {}
            }
        }
    }
    methods
}

/// A unified diff (3 lines of context) of two texts, or an empty string when they match.
///
/// Example: `let diff = unified_diff("a\nb\n", "a\nc\n", "A", "B");`
pub fn unified_diff(a: &str, b: &str, label_a: &str, label_b: &str) -> String {
    let (x, y): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let prefix = x.iter().zip(&y).take_while(|(p, q)| p == q).count();
    let suffix = x[prefix..]
        .iter()
        .rev()
        .zip(y[prefix..].iter().rev())
        .take_while(|(p, q)| p == q)
        .count();
    let (mx, my) = (&x[prefix..x.len() - suffix], &y[prefix..y.len() - suffix]);
    if mx.is_empty() && my.is_empty() {
        return String::new();
    }
    // Edit script over the whole files: ' ' keep, '-' delete, '+' insert.
    let mut script: Vec<(char, &str)> = x[..prefix].iter().map(|l| (' ', *l)).collect();
    if mx.len().saturating_mul(my.len()) > MAX_DIFF_CELLS {
        script.extend(mx.iter().map(|l| ('-', *l)));
        script.extend(my.iter().map(|l| ('+', *l)));
    } else {
        let mut table = vec![vec![0u32; my.len() + 1]; mx.len() + 1];
        for i in (0..mx.len()).rev() {
            for j in (0..my.len()).rev() {
                table[i][j] = if mx[i] == my[j] {
                    table[i + 1][j + 1] + 1
                } else {
                    table[i + 1][j].max(table[i][j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < mx.len() || j < my.len() {
            if i < mx.len() && j < my.len() && mx[i] == my[j] {
                script.push((' ', mx[i]));
                i += 1;
                j += 1;
            } else if j >= my.len() || (i < mx.len() && table[i + 1][j] >= table[i][j + 1]) {
                script.push(('-', mx[i]));
                i += 1;
            } else {
                script.push(('+', my[j]));
                j += 1;
            }
        }
    }
    script.extend(x[x.len() - suffix..].iter().map(|l| (' ', *l)));
    render_hunks(&script, label_a, label_b)
}

/// Group an edit script into unified-diff hunks with 3 lines of context.
fn render_hunks(script: &[(char, &str)], label_a: &str, label_b: &str) -> String {
    const CONTEXT: usize = 3;
    let changed: Vec<usize> = script
        .iter()
        .enumerate()
        .filter(|(_, (op, _))| *op != ' ')
        .map(|(i, _)| i)
        .collect();
    let mut out = format!("--- {label_a}\n+++ {label_b}\n");
    let mut index = 0;
    while index < changed.len() {
        let first = changed[index];
        let mut last = first;
        while index + 1 < changed.len() && changed[index + 1] - last <= 2 * CONTEXT + 1 {
            index += 1;
            last = changed[index];
        }
        index += 1;
        let (start, end) = (
            first.saturating_sub(CONTEXT),
            (last + CONTEXT + 1).min(script.len()),
        );
        let before = |upto: usize| script[..upto].iter().filter(|(op, _)| *op != '+').count();
        let after = |upto: usize| script[..upto].iter().filter(|(op, _)| *op != '-').count();
        let (old_len, new_len) = (before(end) - before(start), after(end) - after(start));
        // An empty side starts at the line before the hunk, as `diff -u` writes it.
        let first_line = |done: usize, len: usize| if len == 0 { done } else { done + 1 };
        out += &format!(
            "@@ -{},{} +{},{} @@\n",
            first_line(before(start), old_len),
            old_len,
            first_line(after(start), new_len),
            new_len
        );
        for (op, line) in &script[start..end] {
            out.push(*op);
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DSL: &str = "\
DefinitionBlock (\"\", \"DSDT\", 2, \"OEM\", \"TABLE\", 0x1)
{
    Scope (\\_SB)
    {
        Device (PCI0)
        {
            Method (_INI, 0, NotSerialized)  // _INI: Initialize
            {
                Debug = \"a { brace\"
            }

            Device (LPCB)
            {
                Method (SIOS, 1, NotSerialized)
                {
                    If ((Arg0 == 0x05))
                    {
                        ENFG (0x0A)
                    }
                }
            }
        }
    }

    Method (\\_PTS, 1, NotSerialized)  // _PTS: Prepare To Sleep
    {
        SIOS (Arg0)
    }
}
";

    #[test]
    fn extracts_methods_under_their_full_paths() {
        let methods = extract_methods(DSL);
        let paths: Vec<&str> = methods.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            vec!["\\_PTS", "\\_SB.PCI0.LPCB.SIOS", "\\_SB.PCI0._INI"]
        );
        let sios = &methods["\\_SB.PCI0.LPCB.SIOS"];
        assert!(
            sios.starts_with("                Method (SIOS, 1"),
            "{sios}"
        );
        assert!(
            sios.trim_end().ends_with('}') && sios.contains("ENFG (0x0A)"),
            "{sios}"
        );
        assert!(
            !methods["\\_SB.PCI0._INI"].contains("SIOS"),
            "a quoted brace must not end the method early"
        );
    }

    #[test]
    fn brace_on_the_keyword_line_is_handled() {
        let methods = extract_methods("Scope (\\X) {\n Method (ABCD, 0) { Return (1) }\n}\n");
        assert_eq!(methods.keys().collect::<Vec<_>>(), vec!["\\X.ABCD"]);
    }

    #[test]
    fn iasl_path_drops_padding_per_segment() {
        assert_eq!(iasl_path("\\_SB_.PCI0.SIOS"), "\\_SB.PCI0.SIOS");
        assert_eq!(iasl_path("\\_S3_"), "\\_S3");
        assert_eq!(iasl_path("\\____"), "\\____");
    }

    #[test]
    fn unified_diff_shows_context_and_changes() {
        let a = "1\n2\n3\n4\n5\n6\n7\n8\n";
        let b = "1\n2\n3\n4\nfive\n6\n7\n8\n";
        assert_eq!(
            unified_diff(a, b, "A", "B"),
            "--- A\n+++ B\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
        );
        assert_eq!(unified_diff(a, a, "A", "B"), "");
    }

    #[test]
    fn distant_changes_make_separate_hunks() {
        let a: String = (1..=30).map(|n| format!("{n}\n")).collect();
        let b = a
            .replace("\n2\n", "\ntwo\n")
            .replace("\n29\n", "\ntwenty-nine\n");
        let diff = unified_diff(&a, &b, "A", "B");
        assert_eq!(diff.matches("@@").count(), 4, "{diff}");
    }

    #[test]
    fn pure_insertion_and_deletion_are_diffs() {
        assert_eq!(
            unified_diff("", "x\n", "A", "B"),
            "--- A\n+++ B\n@@ -0,0 +1,1 @@\n+x\n"
        );
        assert!(unified_diff("x\n", "", "A", "B").contains("-x"));
    }
}
