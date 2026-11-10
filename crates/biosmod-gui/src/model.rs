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
        for tier in ["hold", "future-tier"] {
            let mut p = p.clone();
            p.tier = tier.into();
            assert!(!p.selectable());
        }
        let mut p = p;
        p.plannable = false;
        p.blocked = Some("needs prerequisite".into());
        assert!(!p.selectable());
    }
    #[test]
    fn state_tones_cover_every_engine_state() {
        for (state, tone) in [
            ("present", StateTone::Attention),
            ("partial", StateTone::Attention),
            ("fixed", StateTone::Good),
            ("likely-present", StateTone::Quiet),
            ("likely-fixed", StateTone::Quiet),
            ("not-detected", StateTone::Quiet),
            ("not-applicable", StateTone::Quiet),
            ("unsupported", StateTone::Quiet),
            ("new-state", StateTone::Quiet),
        ] {
            let mut p = correction();
            p.state = state.into();
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
