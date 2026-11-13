use super::*;
use serde_json::json;

fn scenario(expectations: usize) -> Scenario {
    let expect: Vec<Value> = (0..expectations)
        .map(|_| json!({"kind": "return", "equals": 7}))
        .collect();
    let document = json!({
        "schema": "bme.scenario/1",
        "id": "synthetic",
        "description": "d",
        "module": {"sha256": "0".repeat(64), "bitness": 64},
        "entry": {"rva": "0x1000"},
        "budget": 10,
        "expect": expect,
    });
    serde_json::from_value(document).expect("scenario")
}

fn expectation(index: usize, passed: bool) -> Value {
    json!({"expectation": index, "kind": "return", "passed": passed, "expected": 7, "received": if passed { 7 } else { 9 }})
}

fn summary(passed: bool) -> Value {
    json!({"summary": true, "passed": passed})
}

#[test]
fn every_expectation_passing_passes_the_scenario() {
    let docs = [expectation(0, true), expectation(1, true), summary(true)];
    let outcome = outcome(&scenario(2), &docs).expect("outcome");
    assert!(outcome.passed);
    assert_eq!(outcome.summary(), "2 of 2 expectations passed");
}

#[test]
fn one_failed_expectation_fails_the_scenario_and_names_both_values() {
    let docs = [expectation(0, true), expectation(1, false), summary(false)];
    let outcome = outcome(&scenario(2), &docs).expect("outcome");
    assert!(!outcome.passed);
    assert!(
        outcome
            .lines()
            .contains("FAIL expectation 1 (return): expected 7 | received 9")
    );
}

#[test]
fn failures_lists_only_the_failed_expectations() {
    let docs = [expectation(0, true), expectation(1, false), summary(false)];
    let failed = outcome(&scenario(2), &docs).unwrap();
    assert_eq!(
        failed.failures(),
        "expectation 1 (return): expected 7 | received 9"
    );
    let docs = [expectation(0, true), summary(true)];
    assert_eq!(outcome(&scenario(1), &docs).unwrap().failures(), "");
}

#[test]
fn a_summary_that_says_failed_fails_even_when_every_expectation_passed() {
    let docs = [expectation(0, true), summary(false)];
    assert!(!outcome(&scenario(1), &docs).unwrap().passed);
}

fn failing_summary(phase: &str, kind: &str, message: &str) -> Value {
    json!({"summary": true, "passed": false, "error": {"phase": phase, "type": kind, "message": message}})
}

#[test]
fn a_call_error_is_reported_with_the_verdicts() {
    let docs = [
        expectation(0, false),
        failing_summary(
            "call",
            "fault",
            "fault read-unmapped at 0x0 (rip 0x10001000)",
        ),
    ];
    let outcome = outcome(&scenario(1), &docs).unwrap();
    assert!(outcome.lines().contains("FAIL call: fault read-unmapped"));
    assert!(
        outcome
            .summary()
            .ends_with("call failed: fault read-unmapped at 0x0 (rip 0x10001000)")
    );
}

#[test]
fn the_phase_of_the_error_picks_the_code() {
    for (phase, code) in [
        ("setup", Code::ScenarioInvalid),
        ("call", Code::ReplayFailed),
        ("evaluate", Code::ToolFailed),
    ] {
        let docs = [
            expectation(0, false),
            failing_summary(phase, "ValueError", "boom"),
        ];
        let outcome = outcome(&scenario(1), &docs).unwrap();
        assert_eq!(
            outcome.code(),
            code,
            "(phase {phase}): expected {code} | received {}",
            outcome.code()
        );
    }
    let docs = [expectation(0, false), summary(false)];
    assert_eq!(
        outcome(&scenario(1), &docs).unwrap().code(),
        Code::ReplayFailed
    );
}

#[test]
fn an_error_without_a_known_phase_is_a_tool_failure() {
    let docs = [expectation(0, false), failing_summary("teardown", "X", "m")];
    let error = outcome(&scenario(1), &docs).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error.message.contains(
            "summary error phase: expected setup | call | evaluate | received \"teardown\""
        ),
        "{}",
        error.message
    );
    let docs = [
        expectation(0, false),
        json!({"summary": true, "passed": false, "error": "text"}),
    ];
    let error = outcome(&scenario(1), &docs).unwrap_err();
    assert!(
        error
            .message
            .contains("summary error phase: expected a string"),
        "{}",
        error.message
    );
}

#[test]
fn a_missing_expectation_document_is_a_tool_failure() {
    let error = outcome(&scenario(2), &[expectation(0, true), summary(true)]).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error
            .message
            .contains("expectation documents: expected 2 | received 1")
    );
}

#[test]
fn an_out_of_order_expectation_is_a_tool_failure() {
    let docs = [expectation(1, true), summary(true)];
    let error = outcome(&scenario(1), &docs).unwrap_err();
    assert!(
        error.message.contains("expected index 0 | received 1"),
        "{}",
        error.message
    );
}

#[test]
fn a_missing_summary_is_a_tool_failure() {
    let error = outcome(&scenario(1), &[expectation(0, true)]).unwrap_err();
    assert!(
        error
            .message
            .contains("summary document: expected 1 | received none")
    );
}

#[test]
fn two_summaries_are_a_tool_failure() {
    let docs = [expectation(0, true), summary(true), summary(true)];
    let error = outcome(&scenario(1), &docs).unwrap_err();
    assert!(
        error
            .message
            .contains("summary documents: expected 1 | received more than one")
    );
}

#[test]
fn a_summary_without_a_boolean_verdict_is_a_tool_failure() {
    let docs = [expectation(0, true), json!({"summary": true})];
    let error = outcome(&scenario(1), &docs).unwrap_err();
    assert!(error.message.contains("summary passed: expected a boolean"));
}
