//! Findings as an audit register: one Markdown table row per finding.
//!
//! The register that audits keep by hand has six columns. A `bme.finding/1`
//! document carries every one of them as a field, and [`render`] and [`parse`]
//! convert between the two without losing a column, so a catalog can be read
//! as a register and a register can be checked against its documents.
//!
//! | Column | Field |
//! |---|---|
//! | ID | `id` |
//! | Priority | `priority` |
//! | Confidence | `confidence.finding`, then `confidence.condition` |
//! | Board / owning code | `affects.label`, then `owner.description` |
//! | Finding and status | `description`, then `not_established` |
//! | Patch strategy / fix confidence | `remediation` |
//!
//! Example:
//! ```
//! # use biosmod_core::{catalog::Finding, register};
//! # fn demo(findings: &[&Finding]) {
//! let table = register::render(findings);
//! assert!(table.starts_with("| ID | Priority |"));
//! # }
//! ```

use crate::catalog::{Affects, Finding, FindingConfidence, Grade, Owner, Priority};
use crate::error::{Code, Error, Result};

/// The six register columns, in order.
pub const COLUMNS: [&str; 6] = [
    "ID",
    "Priority",
    "Confidence",
    "Board / owning code",
    "Finding and status",
    "Patch strategy / fix confidence",
];

/// Marks where the description ends and the unestablished part begins.
const NOT_ESTABLISHED: &str = " Not established: ";

/// The register fields recovered from one table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub priority: Priority,
    pub confidence: FindingConfidence,
    pub affects_label: String,
    pub owner_description: String,
    pub description: String,
    pub not_established: Option<String>,
    pub remediation: String,
}

/// The register fields a finding document holds.
///
/// Example: `register::row(&finding).id == finding.id`.
pub fn row(finding: &Finding) -> Row {
    Row {
        id: finding.id.clone(),
        priority: finding.priority,
        confidence: finding.confidence.clone(),
        affects_label: finding.affects.label.clone(),
        owner_description: finding.owner.description.clone(),
        description: finding.description.clone(),
        not_established: finding.not_established.clone(),
        remediation: finding.remediation.clone(),
    }
}

/// The confidence cell: `C0 config; C3 cause`.
///
/// Example: a finding graded `C0` with a `C3` condition renders `C0; C3`.
pub fn confidence_cell(confidence: &FindingConfidence) -> String {
    let grade = |g: &Grade| match &g.note {
        Some(note) => format!("{} {note}", g.grade),
        None => g.grade.clone(),
    };
    match &confidence.condition {
        Some(condition) => format!("{}; {}", grade(&confidence.finding), grade(condition)),
        None => grade(&confidence.finding),
    }
}

fn parse_grade(text: &str) -> Grade {
    match text.split_once(' ') {
        Some((grade, note)) => Grade {
            grade: grade.to_string(),
            note: Some(note.to_string()),
        },
        None => Grade {
            grade: text.to_string(),
            note: None,
        },
    }
}

/// Parse a confidence cell produced by [`confidence_cell`].
///
/// Example: `parse_confidence_cell("C0 code; C3 cause").condition.is_some()`.
pub fn parse_confidence_cell(cell: &str) -> FindingConfidence {
    match cell.split_once("; ") {
        Some((finding, condition)) => FindingConfidence {
            finding: parse_grade(finding),
            condition: Some(parse_grade(condition)),
        },
        None => FindingConfidence {
            finding: parse_grade(cell),
            condition: None,
        },
    }
}

fn escape(cell: &str) -> String {
    cell.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', " ")
}

/// The six cells of a finding's row, unescaped.
pub fn cells(finding: &Finding) -> [String; 6] {
    let Finding {
        id,
        priority,
        confidence,
        affects: Affects { label, .. },
        owner: Owner { description, .. },
        ..
    } = finding;
    let defect = match &finding.not_established {
        Some(text) => format!("{}{NOT_ESTABLISHED}{text}", finding.description),
        None => finding.description.clone(),
    };
    [
        id.clone(),
        priority.label().to_string(),
        confidence_cell(confidence),
        format!("{label}; {description}"),
        defect,
        finding.remediation.clone(),
    ]
}

/// Render findings as the register table, in the order given.
///
/// Example: `register::render(&[&finding])` returns the header, a rule and one row.
pub fn render(findings: &[&Finding]) -> String {
    let mut out = format!("| {} |\n|{}\n", COLUMNS.join(" | "), "---|".repeat(6));
    for finding in findings {
        let row: Vec<String> = cells(finding).iter().map(|c| escape(c)).collect();
        out += &format!("| {} |\n", row.join(" | "));
    }
    out
}

/// Split one table line into unescaped cells.
fn split_cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = vec![String::new()];
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    cells.last_mut().expect("cell").push(next);
                }
            }
            '|' => cells.push(String::new()),
            _ => cells.last_mut().expect("cell").push(c),
        }
    }
    cells.into_iter().map(|c| c.trim().to_string()).collect()
}

fn invalid(message: String) -> Error {
    Error::new(Code::FormatInvalid, message)
}

/// Read a register table back into its fields.
///
/// Fails when the header is not the six [`COLUMNS`], a row has a different
/// cell count, or a priority is not `P1` to `P3`.
///
/// Example: `register::parse(&register::render(&[&finding]))?[0].id`.
pub fn parse(table: &str) -> Result<Vec<Row>> {
    let mut lines = table.lines().filter(|l| !l.trim().is_empty());
    let header = lines
        .next()
        .map(split_cells)
        .ok_or_else(|| invalid("register: expected a header row | received none".into()))?;
    if header != COLUMNS {
        return Err(invalid(format!(
            "register header: expected {COLUMNS:?} | received {header:?}"
        )));
    }
    lines.next();
    let mut rows = Vec::new();
    for line in lines {
        let cells = split_cells(line);
        let [id, priority, confidence, owner, defect, remediation]: [String; 6] =
            cells.try_into().map_err(|c: Vec<String>| {
                invalid(format!(
                    "register row {line:?}: expected 6 cells | received {}",
                    c.len()
                ))
            })?;
        let priority = match priority.as_str() {
            "P1" => Priority::P1,
            "P2" => Priority::P2,
            "P3" => Priority::P3,
            other => {
                return Err(invalid(format!(
                    "register row {id}: priority expected P1 | P2 | P3 | received {other:?}"
                )));
            }
        };
        let (affects_label, owner_description) = owner
            .split_once("; ")
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .ok_or_else(|| {
                invalid(format!(
                    "register row {id}: board cell expected `<scope>; <owner>` | received {owner:?}"
                ))
            })?;
        let (description, not_established) = match defect.split_once(NOT_ESTABLISHED) {
            Some((d, n)) => (d.to_string(), Some(n.to_string())),
            None => (defect, None),
        };
        rows.push(Row {
            id,
            priority,
            confidence: parse_confidence_cell(&confidence),
            affects_label,
            owner_description,
            description,
            not_established,
            remediation,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::Fixture;

    #[test]
    fn rendered_register_has_the_six_columns_and_parses_back_to_the_documents() {
        let fixture = Fixture::new(7);
        let findings = fixture.findings();
        let refs: Vec<&Finding> = findings.iter().collect();
        let table = render(&refs);
        assert_eq!(
            table.lines().next().unwrap(),
            "| ID | Priority | Confidence | Board / owning code | Finding and status | Patch strategy / fix confidence |"
        );
        let rows = parse(&table).unwrap();
        let expected: Vec<Row> = findings.iter().map(row).collect();
        assert_eq!(rows, expected);
    }

    #[test]
    fn pipes_and_missing_optional_fields_survive_the_round_trip() {
        let fixture = Fixture::new(7);
        let mut finding = fixture.findings().remove(0);
        finding.description = "reads a | b and c\\d".into();
        finding.not_established = None;
        finding.confidence.condition = None;
        let rows = parse(&render(&[&finding])).unwrap();
        assert_eq!(rows, vec![row(&finding)]);
    }

    #[test]
    fn confidence_cell_round_trips_with_and_without_notes() {
        for cell in ["C1", "C0 conditional", "C0 code; C3 condition", "C0; C2"] {
            assert_eq!(confidence_cell(&parse_confidence_cell(cell)), cell);
        }
    }

    #[test]
    fn parse_names_the_wrong_header_and_the_bad_priority() {
        let header = parse("| ID | Title |\n|---|---|\n").unwrap_err();
        assert!(header.message.contains("register header"), "{header}");
        let fixture = Fixture::new(7);
        let table = render(&[&fixture.findings()[0]]).replace("| P2 |", "| P9 |");
        let priority = parse(&table).unwrap_err();
        assert!(priority.message.contains("\"P9\""), "{priority}");
        let short = parse(&format!("{}| a | b |\n", render(&[]))).unwrap_err();
        assert!(short.message.contains("expected 6 cells"), "{short}");
    }
}
