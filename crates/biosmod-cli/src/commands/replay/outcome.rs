//! Turn the documents of a scenario run into a pass/fail verdict per expectation.
//!
//! The runtime emits one document per expectation and a closing summary. bme does not take the
//! runtime's word for the count: a missing, repeated or out-of-range expectation is a failed
//! tool, not a passing scenario.

use biosmod_core::scenario::Scenario;
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use serde_json::Value;

/// One expectation after the run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub index: usize,
    pub kind: String,
    pub passed: bool,
    pub expected: Value,
    pub received: Value,
}

/// Where a run stopped, as the runtime's summary reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The scenario could not be applied to this module (bad option, symbol, binding, image).
    Setup,
    /// The firmware faulted, touched an unmodeled device or service, or ran out of budget.
    Call,
    /// An expectation could not be read back from the finished call.
    Evaluate,
}

/// Why a run did not finish cleanly.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunError {
    pub phase: Phase,
    /// What raised, e.g. `fault` or `ValueError`.
    pub kind: String,
    pub message: String,
}

/// What a scenario run decided.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub verdicts: Vec<Verdict>,
    /// Why the run did not finish, when it did not.
    pub error: Option<RunError>,
    pub passed: bool,
}

impl Outcome {
    /// `ok` or `FAIL` lines, one per expectation, then the error when there is one.
    pub fn lines(&self) -> String {
        let mut text = String::new();
        for verdict in &self.verdicts {
            text.push_str(&format!(
                "{} expectation {} ({}): expected {} | received {}\n",
                if verdict.passed { "ok  " } else { "FAIL" },
                verdict.index,
                verdict.kind,
                verdict.expected,
                verdict.received
            ));
        }
        if let Some(error) = &self.error {
            text.push_str(&format!("FAIL {}: {}\n", error.phase.name(), error.message));
        }
        text
    }

    /// The error code of a run that did not pass.
    ///
    /// A call that faulted or touched something unmodeled is a finding about the firmware
    /// (`REPLAY_FAILED`, like a missed expectation). A scenario that cannot be applied to the
    /// module is the scenario's fault (`SCENARIO_INVALID`). A result the runtime could not read
    /// back is the runtime's (`TOOL_FAILED`).
    pub fn code(&self) -> Code {
        match self.error.as_ref().map(|e| e.phase) {
            Some(Phase::Setup) => Code::ScenarioInvalid,
            Some(Phase::Evaluate) => Code::ToolFailed,
            Some(Phase::Call) | None => Code::ReplayFailed,
        }
    }

    /// The failed expectations on one line, for an error message.
    ///
    /// Example: `expectation 1 (return): expected 7 | received 9`.
    pub fn failures(&self) -> String {
        self.verdicts
            .iter()
            .filter(|v| !v.passed)
            .map(|v| {
                format!(
                    "expectation {} ({}): expected {} | received {}",
                    v.index, v.kind, v.expected, v.received
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// `3 of 6 expectations passed`, with the error when the call did not finish.
    pub fn summary(&self) -> String {
        let passed = self.verdicts.iter().filter(|v| v.passed).count();
        let mut text = format!("{passed} of {} expectations passed", self.verdicts.len());
        if let Some(error) = &self.error {
            text.push_str(&format!(
                "; {} failed: {}",
                error.phase.name(),
                error.message
            ));
        }
        text
    }
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Setup => "setup",
            Phase::Call => "call",
            Phase::Evaluate => "evaluate",
        }
    }
}

/// Read the summary's `error` object.
fn run_error(summary: &Value) -> Result<Option<RunError>> {
    let Some(error) = summary.get("error") else {
        return Ok(None);
    };
    let text = |name: &str| {
        error.get(name).and_then(Value::as_str).ok_or_else(|| {
            bad(format!(
                "summary error {name}: expected a string | received {summary}"
            ))
        })
    };
    let phase = match text("phase")? {
        "setup" => Phase::Setup,
        "call" => Phase::Call,
        "evaluate" => Phase::Evaluate,
        other => {
            return Err(bad(format!(
                "summary error phase: expected setup | call | evaluate | received {other:?}"
            )));
        }
    };
    Ok(Some(RunError {
        phase,
        kind: text("type")?.to_string(),
        message: text("message")?.to_string(),
    }))
}

fn bad(message: String) -> Error {
    Error::new(Code::ToolFailed, message)
}

/// Read the verdicts out of the emitted `documents`.
///
/// Example: for a scenario with two expectations, two `{"expectation": i, ...}` documents and a
/// `{"summary": true, "passed": true}` document pass; a third expectation document fails with
/// `expectation documents: expected 2 | received 3`.
pub fn outcome(scenario: &Scenario, documents: &[Value]) -> Result<Outcome> {
    let mut verdicts = Vec::new();
    let mut summary = None;
    for document in documents {
        if document.get("summary").is_some() {
            if summary.replace(document).is_some() {
                return Err(bad(
                    "summary documents: expected 1 | received more than one".into(),
                ));
            }
        } else if document.get("expectation").is_some() {
            verdicts.push(verdict(document)?);
        }
    }
    if verdicts.len() != scenario.expect.len() {
        return Err(bad(format!(
            "expectation documents: expected {} | received {}",
            scenario.expect.len(),
            verdicts.len()
        )));
    }
    for (position, verdict) in verdicts.iter().enumerate() {
        if verdict.index != position {
            return Err(bad(format!(
                "expectation document {position}: expected index {position} | received {}",
                verdict.index
            )));
        }
    }
    let summary =
        summary.ok_or_else(|| bad("summary document: expected 1 | received none".into()))?;
    let reported = summary
        .get("passed")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            bad(format!(
                "summary passed: expected a boolean | received {summary}"
            ))
        })?;
    Ok(Outcome {
        passed: reported && verdicts.iter().all(|v| v.passed),
        error: run_error(summary)?,
        verdicts,
    })
}

fn verdict(document: &Value) -> Result<Verdict> {
    let field = |name: &str| {
        document.get(name).ok_or_else(|| {
            bad(format!(
                "expectation document: expected {name} | received {document}"
            ))
        })
    };
    Ok(Verdict {
        index: field("expectation")?.as_u64().ok_or_else(|| {
            bad(format!(
                "expectation index: expected an integer | received {document}"
            ))
        })? as usize,
        kind: field("kind")?.as_str().unwrap_or_default().to_string(),
        passed: field("passed")?.as_bool().ok_or_else(|| {
            bad(format!(
                "expectation passed: expected a boolean | received {document}"
            ))
        })?,
        expected: field("expected")?.clone(),
        received: field("received")?.clone(),
    })
}

#[cfg(test)]
mod tests;
