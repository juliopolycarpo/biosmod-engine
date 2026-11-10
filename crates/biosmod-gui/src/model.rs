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
    pub snapshot_sha256: String,
    pub report: Report,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Report {
    pub firmware: Option<String>,
    pub boards: Vec<String>,
    pub recommended: Vec<String>,
    pub patches: Vec<Patch>,
}

/// Format a protocol value for copyable details. Example: `pretty(&json!({"ok": true}))`.
pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
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
    fn pretty_prints_protocol_values() {
        assert!(pretty(&json!({"firmware": "synthetic"})).contains("\"firmware\": \"synthetic\""));
    }
}
