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

#[test]
fn a_passed_that_contradicts_received_is_a_tool_failure() {
    let lying =
        json!({"expectation": 0, "kind": "return", "passed": true, "expected": 7, "received": 9});
    let error = outcome(&scenario(1), &[lying, summary(true)]).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error
            .message
            .contains("expectation 0 passed: expected false (from received 9) | received true"),
        "{}",
        error.message
    );
    let hiding =
        json!({"expectation": 0, "kind": "return", "passed": false, "expected": 7, "received": 7});
    let error = outcome(&scenario(1), &[hiding, summary(false)]).unwrap_err();
    assert!(
        error
            .message
            .contains("expected true (from received 7) | received false"),
        "{}",
        error.message
    );
}

#[test]
fn an_expected_that_differs_from_the_scenario_is_a_tool_failure() {
    let other =
        json!({"expectation": 0, "kind": "return", "passed": true, "expected": 8, "received": 8});
    let error = outcome(&scenario(1), &[other, summary(true)]).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error
            .message
            .contains("expectation 0 expected: expected 7 (from the scenario) | received 8"),
        "{}",
        error.message
    );
}

#[test]
fn a_kind_that_differs_from_the_scenario_is_a_tool_failure() {
    let port =
        json!({"expectation": 0, "kind": "port", "passed": true, "expected": 7, "received": 7});
    let error = outcome(&scenario(1), &[port, summary(true)]).unwrap_err();
    assert!(
        error
            .message
            .contains("expectation 0 kind: expected return | received \"port\""),
        "{}",
        error.message
    );
}

#[test]
fn a_null_expected_is_accepted_only_when_the_run_failed() {
    let skipped = json!({"expectation": 0, "kind": "return", "passed": false, "expected": null, "received": null});
    let failed = failing_summary("call", "fault", "fault");
    let decided = outcome(&scenario(1), &[skipped.clone(), failed]).unwrap();
    assert_eq!(
        decided.verdicts[0].expected,
        json!(7),
        "(expected): the scenario's value, not the runtime's null"
    );
    let error = outcome(&scenario(1), &[skipped, summary(false)]).unwrap_err();
    assert!(
        error.message.contains("expectation 0 expected"),
        "{}",
        error.message
    );
}

#[test]
fn a_summary_that_says_passed_with_an_error_still_fails() {
    let docs = [
        expectation(0, true),
        json!({"summary": true, "passed": true, "error": {"phase": "evaluate", "type": "X", "message": "m"}}),
    ];
    let decided = outcome(&scenario(1), &docs).unwrap();
    assert!(
        !decided.passed,
        "(passed): expected false with an error | received true"
    );
    assert!(
        decided.verdicts[0].passed,
        "(expectation 0): it was read back and matched"
    );
}

#[test]
fn a_summary_that_says_passed_cannot_save_a_failed_expectation() {
    let docs = [expectation(0, false), summary(true)];
    assert!(!outcome(&scenario(1), &docs).unwrap().passed);
}

#[test]
fn a_received_of_the_wrong_shape_is_a_tool_failure() {
    let text = json!({"expectation": 0, "kind": "return", "passed": false, "expected": 7, "received": "seven"});
    let error = outcome(&scenario(1), &[text, summary(false)]).unwrap_err();
    assert!(
        error.message.contains(
            "expectation 0 received: expected null | an unsigned integer | received \"seven\""
        ),
        "{}",
        error.message
    );
}

#[test]
fn a_variable_expectation_compares_lowercase_hex_and_reports_the_scenarios_bytes() {
    let document = json!({
        "schema": "bme.scenario/1", "id": "v", "description": "d",
        "module": {"sha256": "0".repeat(64), "bitness": 64},
        "entry": {"rva": "0x1000"}, "budget": 10,
        "expect": [{"kind": "variable", "name": "N", "guid": "4E82091E-32A1-4689-8A00-CDE41ED63CDD", "equals": "0A0b"}],
    });
    let scenario: Scenario = serde_json::from_value(document).unwrap();
    let ran = json!({"expectation": 0, "kind": "variable", "passed": true, "expected": "0a0b", "received": "0A0B"});
    let decided = outcome(&scenario, &[ran, summary(true)]).unwrap();
    assert!(decided.passed);
    assert_eq!(decided.verdicts[0].received, json!("0a0b"));
}
