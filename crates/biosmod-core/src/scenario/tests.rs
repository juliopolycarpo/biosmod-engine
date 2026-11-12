use super::*;
use serde_json::json;

const DIGEST: &str = "8e8827a64c9ef65d42d0ffe21a82e51062ba2c4b40b125ad525a21c229732d04";

fn document() -> Value {
    json!({
        "schema": SCENARIO_SCHEMA,
        "id": "fan-zero-policy",
        "description": "a scenario",
        "module": {"sha256": DIGEST, "bitness": 64},
        "entry": {"rva": "0x1658"},
        "services": {"kind": "dxe", "bind": [{"rva": "0x2468", "to": "runtime-services"}]},
        "hardware": [{
            "name": "hwm",
            "kind": "indexed-registers",
            "options": {"index_port": "0xa25", "data_port": "0xa26", "banks": 16}
        }],
        "variables": [{
            "name": "NCT5532D_SMF",
            "guid": "4E82091E-32A1-4689-8A00-CDE41ED63CDD",
            "data": "0102"
        }],
        "budget": 30000,
        "expect": [
            {"kind": "register", "device": "hwm", "bank": 2, "index": "0x27", "equals": 0},
            {"kind": "service-calls", "service": "GetVariable", "count": 1}
        ]
    })
}

fn parse_value(value: &Value) -> Result<Scenario> {
    parse(&serde_json::to_vec(value).unwrap(), "scenario.json")
}

fn rejected(value: Value) -> String {
    parse_value(&value).unwrap_err().message
}

#[test]
fn a_complete_scenario_is_accepted() {
    let scenario = parse_value(&document()).expect("complete scenario");
    assert_eq!(scenario.entry.rva, Word(0x1658));
    assert_eq!(scenario.expect.len(), 2);
}

#[test]
fn numbers_accept_integers_and_hex_strings() {
    let mut value = document();
    value["entry"]["rva"] = json!(5720);
    assert_eq!(parse_value(&value).unwrap().entry.rva, Word(0x1658));
}

#[test]
fn a_malformed_number_names_the_value() {
    let mut value = document();
    value["entry"]["rva"] = json!("1658");
    assert!(rejected(value).contains("number \"1658\": expected 0x followed by hex digits"));
}

#[test]
fn operands_take_numbers_and_known_symbols() {
    let mut value = document();
    value["entry"]["args"] = json!([0, "0x10", "system-table"]);
    let args = parse_value(&value).unwrap().entry.args;
    assert_eq!(args[2], Operand::Symbol("system-table".into()));
    assert_eq!(args[1], Operand::Value(Word(16)));
}

#[test]
fn an_unknown_field_is_rejected() {
    let mut value = document();
    value["entry"]["extra"] = json!(1);
    assert!(rejected(value).contains("extra"));
}

#[test]
fn every_rejection_carries_the_scenario_invalid_code() {
    let mut unknown_field = document();
    unknown_field["colour"] = json!("red");
    let mut bad_id = document();
    bad_id["id"] = json!("not valid!");
    let mut bad_bitness = document();
    bad_bitness["module"]["bitness"] = json!(16);
    let mut bad_symbol = document();
    bad_symbol["services"]["bind"][0]["to"] = json!("nowhere");
    let duplicate_key = br#"{"schema":"bme.scenario/1","schema":"bme.scenario/1"}"#.to_vec();
    let mut cases = vec![
        ("unknown field", serde_json::to_vec(&unknown_field).unwrap()),
        ("identifier", serde_json::to_vec(&bad_id).unwrap()),
        ("validate()", serde_json::to_vec(&bad_bitness).unwrap()),
        ("symbol", serde_json::to_vec(&bad_symbol).unwrap()),
        ("duplicate key", duplicate_key),
    ];
    cases.push(("not JSON", b"nope".to_vec()));
    for (what, bytes) in cases {
        let error = parse(&bytes, "scenario.json").unwrap_err();
        assert_eq!(
            error.code,
            Code::ScenarioInvalid,
            "({what}): expected SCENARIO_INVALID | received {} ({})",
            error.code,
            error.message
        );
    }
}

#[test]
fn a_service_name_must_belong_to_the_services_kind() {
    let mut misspelt = document();
    misspelt["expect"][1]["service"] = json!("GetVariabel");
    let message = rejected(misspelt);
    assert!(
        message.contains("GetVariabel")
            && message.contains("Dxe")
            && message.contains("GetVariable"),
        "(misspelt service): expected the name, the kind and the valid names | received {message}"
    );
    let mut wrong_kind = document();
    wrong_kind["services"]["kind"] = json!("pei");
    wrong_kind["services"]["bind"] = json!([]);
    let message = rejected(wrong_kind);
    assert!(
        message.contains("GetVariable") && message.contains("Pei"),
        "(DXE service under pei): expected the name and the kind | received {message}"
    );
}

#[test]
fn every_services_kind_lists_names_and_the_slots_the_runtime_uses_are_among_them() {
    for kind in [ServicesKind::Dxe, ServicesKind::Smm, ServicesKind::Pei] {
        assert!(
            !service_names(kind).is_empty(),
            "(service names of {kind:?})"
        );
    }
    assert!(service_names(ServicesKind::Dxe).contains(&"GetVariable".to_string()));
    assert!(service_names(ServicesKind::Smm).contains(&"SmmAllocatePool".to_string()));
    assert!(service_names(ServicesKind::Pei).contains(&"LocatePpi".to_string()));
}

#[test]
fn an_unknown_field_inside_an_expectation_is_rejected() {
    let mut value = document();
    value["expect"][1]["counts"] = json!(2);
    assert!(rejected(value).contains("counts"));
}

#[test]
fn an_unknown_expectation_kind_is_rejected() {
    let mut value = document();
    value["expect"][1] = json!({"kind": "checksum", "equals": 1});
    assert!(rejected(value).contains("checksum"));
}

#[test]
fn a_duplicate_key_is_rejected() {
    let text = r#"{"schema":"bme.scenario/1","schema":"bme.scenario/1"}"#;
    assert!(parse(text.as_bytes(), "s.json").is_err());
}

#[test]
fn a_wrong_schema_names_both() {
    let mut value = document();
    value["schema"] = json!("bme.scenario/2");
    assert!(rejected(value).contains("schema: expected bme.scenario/1 | received bme.scenario/2"));
}

#[test]
fn bitness_must_be_32_or_64() {
    let mut value = document();
    value["module"]["bitness"] = json!(16);
    assert!(rejected(value).contains("module bitness: expected 32 | 64 | received 16"));
}

#[test]
fn a_digest_must_be_lowercase_hex() {
    let mut value = document();
    value["module"]["sha256"] = json!("ABC");
    assert!(rejected(value).contains("expected 64 lowercase hex digits"));
}

#[test]
fn an_empty_expectation_list_is_rejected() {
    let mut value = document();
    value["expect"] = json!([]);
    assert!(rejected(value).contains("expect: expected at least one expectation | received none"));
}

#[test]
fn a_zero_budget_is_rejected() {
    let mut value = document();
    value["budget"] = json!(0);
    assert!(rejected(value).contains("budget: expected at least 1 instruction | received 0"));
}

#[test]
fn a_symbol_the_services_do_not_provide_is_rejected() {
    let mut value = document();
    value["entry"]["args"] = json!(["smm-table"]);
    assert!(rejected(value).contains("entry argument 0: expected a symbol from"));
}

#[test]
fn a_binding_to_a_missing_symbol_is_rejected() {
    let mut value = document();
    value["services"]["bind"][0]["to"] = json!("pei-services");
    assert!(rejected(value).contains("binding at 0x2468"));
}

#[test]
fn an_expectation_on_an_undeclared_device_is_rejected() {
    let mut value = document();
    value["expect"][0]["device"] = json!("sio");
    let message = rejected(value);
    assert!(message.contains("expectation 0"), "{message}");
    assert!(
        message.contains(
            "device \"sio\": expected a declared indexed-registers device | received none"
        )
    );
}

#[test]
fn an_expectation_on_a_device_of_another_kind_is_rejected() {
    let mut value = document();
    value["expect"][0] = json!({"kind": "port", "device": "hwm", "port": "0xa25", "equals": 0});
    assert!(
        rejected(value)
            .contains("device \"hwm\": expected kind port-registers | received indexed-registers")
    );
}

#[test]
fn service_calls_need_a_services_block() {
    let mut value = document();
    value.as_object_mut().unwrap().remove("services");
    assert!(rejected(value).contains("service \"GetVariable\": expected a services block"));
}

#[test]
fn a_variable_expectation_needs_no_declared_variable() {
    let mut value = document();
    value["expect"][0] = json!({
        "kind": "variable",
        "name": "Created",
        "guid": "4E82091E-32A1-4689-8A00-CDE41ED63CDD",
        "equals": "00"
    });
    parse_value(&value).expect("a module may create the variable itself");
}

#[test]
fn an_unknown_device_kind_is_rejected() {
    let mut value = document();
    value["hardware"][0]["kind"] = json!("flash");
    assert!(rejected(value).contains("unknown variant `flash`"));
}

#[test]
fn a_duplicate_device_name_is_rejected() {
    let mut value = document();
    let first = value["hardware"][0].clone();
    value["hardware"].as_array_mut().unwrap().push(first);
    assert!(
        rejected(value).contains("hardware \"hwm\": expected a unique name | received a duplicate")
    );
}

#[test]
fn mmio_devices_need_a_window_and_port_devices_must_not_have_one() {
    let mut value = document();
    value["hardware"][0]["base"] = json!("0xfed1c000");
    assert!(rejected(value).contains("unknown field `base`"));
    let mut value = document();
    value["hardware"][0]["kind"] = json!("mmio-registers");
    let message = rejected(value);
    assert!(
        message.contains("missing field `base`") || message.contains("unknown field"),
        "{message}"
    );
}

fn device(options: Value) -> Value {
    json!({"name": "hwm", "kind": "indexed-registers", "options": options})
}

fn with_device(device: Value) -> Value {
    let mut value = document();
    value["hardware"] = json!([device]);
    value
}

#[test]
fn an_unknown_option_names_itself() {
    let message = rejected(with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "bankz": 16}),
    )));
    assert!(message.contains("unknown field `bankz`"), "{message}");
}

#[test]
fn an_option_that_is_not_a_number_is_rejected() {
    let message = rejected(with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "seed": "soon"}),
    )));
    assert!(message.contains("number \"soon\""), "{message}");
}

#[test]
fn a_missing_required_option_is_named() {
    let message = rejected(with_device(device(json!({"index_port": "0xa25"}))));
    assert!(message.contains("missing field `data_port`"), "{message}");
}

#[test]
fn an_expectation_bank_must_be_below_the_declared_banks() {
    let mut value = with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "banks": 2}),
    ));
    value["expect"][0]["bank"] = json!(2);
    let message = rejected(value);
    assert!(
        message.contains("bank: expected below banks (2) | received 2"),
        "{message}"
    );
}

#[test]
fn a_register_bank_or_index_outside_the_model_is_rejected() {
    let message = rejected(with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "banks": 2, "registers": {"2": {"0x10": 1}}}),
    )));
    assert!(
        message.contains("register bank: expected below banks (2) | received 2"),
        "{message}"
    );
    let message = rejected(with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "registers": {"0": {"0x100": 1}}}),
    )));
    assert!(
        message.contains("register index: expected at most 0xff | received 0x100"),
        "{message}"
    );
}

#[test]
fn a_register_key_that_is_not_a_number_is_rejected() {
    let message = rejected(with_device(device(
        json!({"index_port": "0xa25", "data_port": "0xa26", "registers": {"zero": {}}}),
    )));
    assert!(message.contains("register bank \"zero\""), "{message}");
}

#[test]
fn two_devices_cannot_claim_the_same_port() {
    let mut value = document();
    value["hardware"] = json!([
        device(json!({"index_port": "0xa25", "data_port": "0xa26"})),
        {"name": "other", "kind": "port-registers", "options": {"values": {"0xa26": 0}}}
    ]);
    let message = rejected(value);
    assert!(
        message.contains("0xa26") && message.contains("claims"),
        "{message}"
    );
}

#[test]
fn an_mmio_value_outside_its_window_and_overlapping_windows_are_rejected() {
    let window = |name: &str, base: &str, offset: &str| {
        json!({"name": name, "kind": "mmio-registers", "base": base, "size": "0x1000",
               "options": {"values": {offset: 0}}})
    };
    let mut value = document();
    value["hardware"] = json!([window("a", "0xfed1c000", "0x1000")]);
    let message = rejected(value);
    assert!(message.contains("offset 0x1000"), "{message}");
    let mut value = document();
    value["hardware"] = json!([
        window("a", "0xfed1c000", "0x0"),
        window("b", "0xfed1c800", "0x0")
    ]);
    let message = rejected(value);
    assert!(message.contains("overlap"), "{message}");
}

#[test]
fn a_port_expectation_needs_a_port_the_device_lists() {
    let mut value = document();
    value["hardware"] = json!([
        {"name": "pm", "kind": "port-registers", "options": {"values": {"0x404": 1}}}
    ]);
    value["expect"][0] = json!({"kind": "port", "device": "pm", "port": "0x405", "equals": 0});
    let message = rejected(value);
    assert!(message.contains("port 0x405"), "{message}");
}

#[test]
fn an_invalid_identifier_is_rejected() {
    let mut value = document();
    value["id"] = json!("not valid");
    assert!(rejected(value).contains("scenario id"));
}
