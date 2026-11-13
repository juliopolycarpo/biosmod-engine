//! Turn the documents of a scenario run into a pass/fail verdict per expectation.
//!
//! The runtime emits one document per expectation and a closing summary. bme does not take the
//! runtime's word for any of it. It derives what each expectation wants from the scenario it
//! validated, checks the runtime evaluated that expectation, and decides pass or fail itself
//! from the `received` value. A missing, repeated or reordered expectation, a different
//! `expected`, or a `passed` that contradicts `received` is a failed tool, not a verdict.

use biosmod_core::scenario::{Expectation, Scenario};
use biosmod_core::util::hex;
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

/// The `kind` an expectation spells in the document.
fn kind_of(expectation: &Expectation) -> &'static str {
    match expectation {
        Expectation::Return { .. } => "return",
        Expectation::Register { .. } => "register",
        Expectation::Port { .. } => "port",
        Expectation::Variable { .. } => "variable",
        Expectation::ServiceCalls { .. } => "service-calls",
    }
}

/// What an expectation wants, as the runtime reports values: an unsigned number, or the
/// lowercase hex of a variable's bytes.
fn expected_of(expectation: &Expectation) -> Value {
    match expectation {
        Expectation::Return { equals }
        | Expectation::Register { equals, .. }
        | Expectation::Port { equals, .. } => Value::from(equals.0),
        Expectation::Variable { equals, .. } => Value::from(hex(&equals.0)),
        Expectation::ServiceCalls { count, .. } => Value::from(count.0),
    }
}

/// The runtime's `received`, in the shape `expected_of` uses: null (nothing was read), an
/// unsigned number, or a lowercase hex string for a variable.
fn received_of(expectation: &Expectation, index: usize, document: &Value) -> Result<Value> {
    let received = &document["received"];
    let ok = match (expectation, received) {
        (_, Value::Null) => true,
        (Expectation::Variable { .. }, Value::String(_)) => true,
        (Expectation::Variable { .. }, _) => false,
        (_, number) => number.is_u64(),
    };
    if !ok {
        return Err(bad(format!(
            "expectation {index} received: expected null | {} | received {received}",
            if matches!(expectation, Expectation::Variable { .. }) {
                "a hex string"
            } else {
                "an unsigned integer"
            }
        )));
    }
    Ok(match received {
        Value::String(text) => Value::from(text.to_ascii_lowercase()),
        other => other.clone(),
    })
}

/// Read the verdicts out of the emitted `documents`.
///
/// Example: for a scenario with two expectations, two `{"expectation": i, ...}` documents and a
/// `{"summary": true, "passed": true}` document pass; a third expectation document fails with
/// `expectation documents: expected 2 | received 3`. A document whose `passed` is true while
/// `received` differs from the scenario's value fails with
/// `expectation 0 passed: expected false (from received 9) | received true`.
pub fn outcome(scenario: &Scenario, documents: &[Value]) -> Result<Outcome> {
    let mut raw = Vec::new();
    let mut summary = None;
    for document in documents {
        if document.get("summary").is_some() {
            if summary.replace(document).is_some() {
                return Err(bad(
                    "summary documents: expected 1 | received more than one".into(),
                ));
            }
        } else if document.get("expectation").is_some() {
            raw.push(document);
        }
    }
    if raw.len() != scenario.expect.len() {
        return Err(bad(format!(
            "expectation documents: expected {} | received {}",
            scenario.expect.len(),
            raw.len()
        )));
    }
    let summary =
        summary.ok_or_else(|| bad("summary document: expected 1 | received none".into()))?;
    // The runtime's overall verdict can only veto: a scenario passes when bme's own recount
    // passes and the runtime does not say otherwise.
    let reported = summary
        .get("passed")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            bad(format!(
                "summary passed: expected a boolean | received {summary}"
            ))
        })?;
    let error = run_error(summary)?;
    let mut verdicts = Vec::new();
    for (position, (document, spec)) in raw.iter().zip(&scenario.expect).enumerate() {
        verdicts.push(verdict(position, document, spec, error.is_some())?);
    }
    Ok(Outcome {
        passed: reported && error.is_none() && verdicts.iter().all(|v| v.passed),
        error,
        verdicts,
    })
}

/// Check one expectation document against the expectation it claims to evaluate.
fn verdict(
    position: usize,
    document: &Value,
    spec: &Expectation,
    run_failed: bool,
) -> Result<Verdict> {
    let field = |name: &str| {
        document.get(name).ok_or_else(|| {
            bad(format!(
                "expectation document {position}: expected {name} | received {document}"
            ))
        })
    };
    let index = field("expectation")?.as_u64().ok_or_else(|| {
        bad(format!(
            "expectation index: expected an integer | received {document}"
        ))
    })?;
    if index != position as u64 {
        return Err(bad(format!(
            "expectation document {position}: expected index {position} | received {index}"
        )));
    }
    let kind = kind_of(spec);
    let reported_kind = field("kind")?.as_str().unwrap_or_default();
    if reported_kind != kind {
        return Err(bad(format!(
            "expectation {position} kind: expected {kind} | received {reported_kind:?}"
        )));
    }
    let expected = expected_of(spec);
    let reported_expected = field("expected")?;
    // A run that stopped before evaluating reports no expected value.
    let evaluated = !(run_failed && reported_expected.is_null());
    if evaluated && *reported_expected != expected {
        return Err(bad(format!(
            "expectation {position} expected: expected {expected} (from the scenario) | received {reported_expected}"
        )));
    }
    let reported_passed = field("passed")?.as_bool().ok_or_else(|| {
        bad(format!(
            "expectation passed: expected a boolean | received {document}"
        ))
    })?;
    field("received")?;
    let received = received_of(spec, position, document)?;
    let passed = !received.is_null() && received == expected;
    if reported_passed != passed {
        return Err(bad(format!(
            "expectation {position} passed: expected {passed} (from received {received}) | received {reported_passed}"
        )));
    }
    Ok(Verdict {
        index: position,
        kind: kind.to_string(),
        passed,
        expected,
        received,
    })
}

#[cfg(test)]
mod tests;
