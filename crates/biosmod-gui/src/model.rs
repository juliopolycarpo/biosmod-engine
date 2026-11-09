//! Presentation of engine-owned facts; no firmware interpretation or selection solver.

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Patch {
    pub id: String,
    pub version: String,
    pub title: String,
    pub class: String,
    pub tier: String,
    pub state: String,
    pub plannable: bool,
    pub manual: bool,
    pub detail: String,
    #[serde(default)]
    pub blocked: Option<String>,
    #[serde(default)]
    pub requires_facts: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(skip)]
    pub selected: bool,
}

impl Patch {
    /// Restrict desktop selection to independently plannable ordinary corrections.
    /// Example: a `present`, plannable correction without hardware facts is selectable.
    pub fn selectable(&self) -> bool {
        self.state == "present"
            && self.class == "correction"
            && self.plannable
            && !self.manual
            && matches!(self.tier.as_str(), "recommended" | "optional")
            && self.requires_facts.is_empty()
    }

    /// Preserve the source and version in selection identities.
    /// Example: `patch.qualified("lab")` returns `lab::PA@1.0.0`.
    pub fn qualified(&self, alias: &str) -> String {
        format!("{alias}::{}@{}", self.id, self.version)
    }

    /// List why the desktop cannot select this row, without the engine's own detail line.
    /// Example: a diagnostic returns the CLI-only selection notice; a selectable row returns none.
    pub fn limits(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(blocked) = &self.blocked {
            lines.push(blocked.clone());
        }
        if !self.requires_facts.is_empty() {
            lines.push(format!(
                "Requires physical observations: {}. Review with the CLI.",
                self.requires_facts.join(", ")
            ));
        }
        if !self.selectable() {
            lines.push("Desktop selection requires a present, independently plannable correction without hold or hardware gates. Joint prerequisites require the CLI.".into());
        }
        lines
    }

    /// Explain engine blockers and the desktop's supported selection scope.
    /// Example: a diagnostic remains visible with a CLI-only explanation.
    pub fn explanation(&self) -> String {
        let mut lines = vec![self.detail.clone()];
        lines.extend(self.limits());
        lines.join("\n")
    }

    /// Name the scan state for people instead of echoing the protocol token.
    /// Example: `likely-present` reads `Likely present`; an unknown state is shown unchanged.
    pub fn state_label(&self) -> String {
        match self.state.as_str() {
            "present" => "Defect present",
            "fixed" => "Fixed",
            "partial" => "Partially patched",
            "likely-present" => "Likely present",
            "likely-fixed" => "Likely fixed",
            "not-detected" => "Not detected",
            "not-applicable" => "Not applicable",
            "unsupported" => "Unsupported",
            other => other,
        }
        .into()
    }

    /// Choose how prominently the state is shown.
    /// Example: `present` asks for attention, `fixed` reads as good news, unknown states stay quiet.
    pub fn state_tone(&self) -> StateTone {
        match self.state.as_str() {
            "present" | "partial" => StateTone::Attention,
            "fixed" => StateTone::Good,
            _ => StateTone::Quiet,
        }
    }
}

/// How prominently a scan state is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTone {
    Attention,
    Good,
    Quiet,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scan {
    pub input: Value,
    pub sources: Vec<SourceReport>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct SourceReport {
    pub alias: String,
    pub trust: String,
    pub catalog: String,
    pub catalog_version: String,
    pub report: Report,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Report {
    pub firmware: Option<String>,
    pub boards: Vec<String>,
    pub patches: Vec<Patch>,
}

/// Render the complete document below a concise, human-readable plan summary.
/// Example: `plan_summary(&document)` includes `table_offset` without merging components.
pub fn plan_summary(plan: &Value) -> String {
    let mut text = format!(
        "Firmware: {}\nSource: {} · {} {} · {}\n\nRequested: {}\nSelected: {}\nAlready carried: {}\n\nInput SHA-256: {}\nOutput SHA-256: {}\nEngine: {} · {}\n\n",
        string(plan, "firmware"),
        plan["source"]["alias"].as_str().unwrap_or("?"),
        plan["source"]["catalog_id"].as_str().unwrap_or("?"),
        plan["source"]["catalog_version"].as_str().unwrap_or("?"),
        plan["source"]["trust"].as_str().unwrap_or("?"),
        joined(&plan["requested"]),
        joined(&plan["selected"]),
        joined(&plan["carried"]),
        plan["input"]["sha256"].as_str().unwrap_or("?"),
        plan["output"]["sha256"].as_str().unwrap_or("?"),
        plan["engine"]["version"].as_str().unwrap_or("?"),
        plan["engine"]["codec"].as_str().unwrap_or("?")
    );
    if let Some(components) = plan["components"].as_array() {
        for c in components {
            text.push_str(&format!(
                "{} · {} · table offset {} · file offset {}\n  {}\n",
                string(c, "name"),
                string(c, "ffs_guid"),
                c["table_offset"],
                c["file_offset"],
                joined(&c["patches"])
            ));
        }
    }
    text.push_str(&format!("\nHardware assertions: {}\nAllow hold: {} · Allow diagnostic: {}\n{}\n\nComplete plan and source snapshot\n{}",
        joined(&plan["facts"]), plan["allow_hold"], plan["allow_diagnostic"], joined(&plan["notes"]), pretty(plan)));
    text
}

/// Format a protocol value for copyable details. Example: `pretty(&json!({"ok": true}))`.
pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// Present each reported verification check with its actual result and limitations.
/// Example: a skipped reproduction check remains visibly incomplete.
pub fn verification_summary(report: &Value) -> String {
    let mut lines = vec!["Independent offline checks".to_owned(), String::new()];
    if let Some(checks) = report["checks"].as_array() {
        for check in checks {
            let name = check["check"].as_str().unwrap_or("unknown check");
            let label = match name {
                "input-digest" => "Original image digest",
                "output-digest" => "Output digest",
                "structure" => "Firmware structure",
                "unchanged-outside-allowlist" => "Bytes outside the allowed changes",
                "changed-regions" => "Changed regions",
                "patch-states" => "Selected patch states",
                "reproduced-from-catalog" => "Independent reproduction from the catalog",
                _ => name,
            };
            lines.push(format!(
                "{}  {label}",
                if check["ok"] == true {
                    "PASS"
                } else {
                    "INCOMPLETE"
                }
            ));
        }
    }
    if let Some(skipped) = report["skipped"].as_array() {
        for check in skipped {
            lines.push(format!(
                "SKIPPED  {}\n{}",
                string(check, "check"),
                string(check, "reason")
            ));
        }
    }
    lines.push(format!("\n{}", string(report, "notice")));
    lines.join("\n")
}

fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or("unknown")
}
fn joined(value: &Value) -> String {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "None".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn verification_summary_preserves_passes_skips_and_notice() {
        let report = json!({"checks":[{"check":"input-digest","ok":true},{"check":"new-check","ok":false}],"skipped":[{"check":"reproduction","reason":"catalog unavailable"}],"notice":"Offline checks only"});
        let text = verification_summary(&report);
        assert!(text.contains("PASS  Original image digest"));
        assert!(text.contains("INCOMPLETE  new-check"));
        assert!(text.contains("SKIPPED  reproduction\ncatalog unavailable"));
        assert!(text.contains("Offline checks only"));
    }
    fn correction() -> Patch {
        serde_json::from_value(json!({"id":"PA", "version":"1.0.0", "title":"Correction", "class":"correction", "tier":"recommended", "state":"present", "plannable":true, "manual":false,"detail":"exact match"})).unwrap()
    }
    #[test]
    fn conservative_selection_and_qualified_identity() {
        let p = correction();
        assert!(p.selectable());
        assert_eq!(p.qualified("lab"), "lab::PA@1.0.0");
        for state in [
            "fixed",
            "partial",
            "likely-present",
            "likely-fixed",
            "not-detected",
            "not-applicable",
            "unsupported",
            "new-state",
        ] {
            let mut p = p.clone();
            p.state = state.into();
            assert!(!p.selectable(), "state {state}: expected read-only");
        }
        let mut gated = p.clone();
        gated.requires_facts.push("physical-board".into());
        assert!(!gated.selectable());
        assert!(gated.explanation().contains("physical-board"));
        for tier in ["hold", "future-tier"] {
            let mut p = p.clone();
            p.tier = tier.into();
            assert!(!p.selectable());
        }
        let mut p = p;
        p.plannable = false;
        p.blocked = Some("needs prerequisite".into());
        assert!(!p.selectable());
        assert!(p.explanation().contains("needs prerequisite"));
    }
    #[test]
    fn limits_exclude_the_engine_detail_and_explanation_keeps_it_first() {
        let selectable = correction();
        assert!(selectable.limits().is_empty());
        assert_eq!(selectable.explanation(), "exact match");
        let mut blocked = selectable;
        blocked.plannable = false;
        blocked.blocked = Some("needs prerequisite".into());
        let limits = blocked.limits();
        assert_eq!(limits[0], "needs prerequisite");
        assert!(
            limits.len() == 2,
            "limits: expected blocker + selection notice | received {limits:?}"
        );
        assert!(
            blocked
                .explanation()
                .starts_with("exact match\nneeds prerequisite")
        );
    }
    #[test]
    fn state_labels_and_tones_cover_every_engine_state() {
        let expected = [
            ("present", "Defect present", StateTone::Attention),
            ("partial", "Partially patched", StateTone::Attention),
            ("fixed", "Fixed", StateTone::Good),
            ("likely-present", "Likely present", StateTone::Quiet),
            ("likely-fixed", "Likely fixed", StateTone::Quiet),
            ("not-detected", "Not detected", StateTone::Quiet),
            ("not-applicable", "Not applicable", StateTone::Quiet),
            ("unsupported", "Unsupported", StateTone::Quiet),
            ("new-state", "new-state", StateTone::Quiet),
        ];
        for (state, label, tone) in expected {
            let mut p = correction();
            p.state = state.into();
            assert_eq!(p.state_label(), label, "state {state}: label");
            assert_eq!(p.state_tone(), tone, "state {state}: tone");
        }
    }
    #[test]
    fn summary_keeps_component_identity_policy_and_snapshot() {
        let plan = json!({"firmware":"synthetic", "components":[{"name":"ACPI", "ffs_guid":"guid", "table_offset":128, "file_offset":4096, "patches":["A"]}], "facts":["board-rev"], "allow_hold":true, "allow_diagnostic":false, "source":{"manifest_sha256":"pinned"}});
        let text = plan_summary(&plan);
        assert!(text.contains("table offset 128"));
        assert!(text.contains("board-rev"));
        assert!(text.contains("pinned"));
        assert!(text.contains("Allow hold: true"));
        assert_eq!(joined(&Value::Null), "None");
        assert!(pretty(&plan).contains("synthetic"));
    }
}
