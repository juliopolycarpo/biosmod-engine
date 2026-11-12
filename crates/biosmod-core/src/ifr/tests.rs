//! Tests on vendor-free IFR built by `synthetic`.

use super::decode::MAX_SCOPE_DEPTH;
use super::*;
use crate::error::Code;
use crate::firmware::Image;
use crate::synthetic::*;

fn setup() -> IfrModule {
    decode_module(&ifr_setup_module(), None).expect("synthetic setup decodes")
}

/// A package list whose only form package has `body` (which must open a FormSet itself).
fn list_with_body(body: &[u8]) -> Vec<u8> {
    hii_package_list(
        Guid::constant("22222222-0000-0000-0000-000000000002"),
        &[hii_package(0x02, body)],
    )
}

fn formset_open() -> Vec<u8> {
    let mut payload = SETUP_FORMSET_GUID.0.to_vec();
    payload.extend_from_slice(&[0, 0, 0, 0, 0]);
    ifr_op(0x0E, true, &payload)
}

fn decode_error(bytes: &[u8]) -> String {
    let error = decode_module(bytes, None).expect_err("malformed IFR must fail");
    assert_eq!(error.code, Code::FormatInvalid, "{error}");
    error.message
}

#[test]
fn decodes_form_set_forms_and_varstore() {
    let module = setup();
    assert_eq!(module.package_lists.len(), 1);
    let list = &module.package_lists[0];
    assert_eq!(list.language.as_deref(), Some("en-US"));
    assert_eq!(list.languages, ["en-US", "pt-BR"]);
    let set = &list.form_sets[0];
    assert_eq!(set.guid, SETUP_FORMSET_GUID);
    assert_eq!(set.title, "Setup");
    assert_eq!(set.varstores.len(), 1);
    assert_eq!(set.varstores[0].name, "Setup");
    assert_eq!(set.varstores[0].guid, SETUP_VARSTORE_GUID);
    assert_eq!(set.varstores[0].size, 0x40);
    assert_eq!(set.forms.len(), 1);
    assert_eq!(
        (set.forms[0].id, set.forms[0].title.as_str()),
        (0x2710, "Main")
    );
}

#[test]
fn one_of_reports_storage_options_and_suppress_condition() {
    let module = setup();
    let hits = module.find_questions("acpi sleep state");
    assert_eq!(hits.len(), 1);
    let sleep = hits[0].2;
    assert_eq!(sleep.kind, StatementKind::OneOf);
    assert_eq!(sleep.question_id, Some(0x19));
    let (store, offset, width) = sleep.storage().expect("sleep state has storage");
    assert_eq!(
        (store.name.as_str(), store.guid, offset, width),
        ("Setup", SETUP_VARSTORE_GUID, 0x0A, 2)
    );
    assert_eq!((sleep.min, sleep.max), (Some(0), Some(2)));
    let values: Vec<(u64, &str, bool, bool)> = sleep
        .options
        .iter()
        .map(|o| {
            (
                o.value,
                o.label.as_str(),
                o.standard_default,
                o.manufacturing_default,
            )
        })
        .collect();
    assert_eq!(
        values,
        [
            (0, "Suspend Disabled", false, false),
            (1, "S1 (CPU Stop Clock)", false, false),
            (2, "S3 (Suspend to RAM)", true, true),
        ]
    );
    assert_eq!(sleep.default_value(0), Some(2));
    assert_eq!(sleep.default_value(1), Some(2));
    assert_eq!(sleep.conditions.len(), 1);
    assert_eq!(sleep.conditions[0].kind, ConditionKind::SuppressIf);
    assert_eq!(sleep.conditions[0].expression, "ideqval 0x9 == 1");
}

#[test]
fn checkbox_keeps_explicit_defaults_and_grayout_condition() {
    let module = setup();
    let hibernate = module.find_questions("Enable Hibernation")[0].2;
    assert_eq!(hibernate.kind, StatementKind::CheckBox);
    assert_eq!(hibernate.storage().map(|(_, o, w)| (o, w)), Some((0x0D, 1)));
    let ids: Vec<(u16, Option<u64>)> = hibernate
        .defaults
        .iter()
        .map(|d| (d.default_id, d.value))
        .collect();
    assert_eq!(ids, [(0, Some(1)), (1, Some(1))]);
    assert_eq!(hibernate.default_value(0), Some(1));
    assert_eq!(hibernate.conditions[0].kind, ConditionKind::GrayOutIf);
}

#[test]
fn numeric_reads_range_at_its_width_and_has_no_conditions() {
    let module = setup();
    let fan = module.find_questions("Fan PWM")[0].2;
    assert_eq!(fan.kind, StatementKind::Numeric);
    assert_eq!(
        (fan.min, fan.max, fan.step, fan.width),
        (Some(0), Some(255), Some(1), Some(1))
    );
    assert!(fan.conditions.is_empty(), "{:?}", fan.conditions);
    assert_eq!(fan.default_value(0), None);
}

#[test]
fn subtitles_are_statements_without_question_ids() {
    let module = setup();
    let subtitle = module
        .statements()
        .find(|(_, _, s)| s.kind == StatementKind::Subtitle)
        .expect("subtitle")
        .2;
    assert_eq!(subtitle.prompt, "Section");
    assert_eq!(subtitle.question_id, None);
    assert!(module.find_questions("Section").is_empty());
}

#[test]
fn checkbox_flags_supply_defaults_when_no_default_opcode_exists() {
    let mut module = setup();
    let list = &mut module.package_lists[0];
    let statement = list.form_sets[0].forms[0]
        .statements
        .iter_mut()
        .find(|s| s.kind == StatementKind::CheckBox)
        .unwrap();
    statement.defaults.clear();
    statement.flags = 0b01;
    assert_eq!(statement.default_value(0), Some(1));
    assert_eq!(statement.default_value(1), Some(0));
}

#[test]
fn language_selection_uses_requested_then_english_then_first() {
    let bytes = ifr_setup_module();
    let portuguese = decode_module(&bytes, Some("pt-BR")).unwrap();
    let list = &portuguese.package_lists[0];
    assert_eq!(list.language.as_deref(), Some("pt-BR"));
    assert_eq!(list.form_sets[0].title, "SETUP");
    let fallback = decode_module(&bytes, Some("xx-YY")).unwrap();
    assert_eq!(fallback.package_lists[0].language.as_deref(), Some("en-US"));
}

#[test]
fn list_without_string_package_decodes_with_empty_text() {
    let mut body = formset_open();
    body.extend(ifr_end());
    let module = decode_module(&list_with_body(&body), None).unwrap();
    let list = &module.package_lists[0];
    assert_eq!(list.language, None);
    assert_eq!(list.form_sets[0].title, "");
}

#[test]
fn random_bytes_and_formless_lists_are_ignored() {
    assert!(
        decode_module(&module(9, 4096), None)
            .unwrap()
            .package_lists
            .is_empty()
    );
    let strings_only = hii_package_list(
        Guid::constant("33333333-0000-0000-0000-000000000003"),
        &[hii_string_package("en-US", &["x"])],
    );
    assert!(
        decode_module(&strings_only, None)
            .unwrap()
            .package_lists
            .is_empty()
    );
}

#[test]
fn end_without_scope_names_offset_and_opcode() {
    let message = decode_error(&list_with_body(
        &[formset_open(), ifr_end(), ifr_end()].concat(),
    ));
    assert!(message.contains("opcode End (0x29)"), "{message}");
    assert!(message.contains("End without an open scope"), "{message}");
    assert!(message.contains("ifr form package at 0x14"), "{message}");
    // Package header at 0x14, FormSet at 0x18 (0x17 bytes), End at 0x2f, second End at 0x31.
    assert!(message.contains("End (0x29) at 0x31"), "{message}");
}

#[test]
fn unclosed_scope_names_the_opening_opcode() {
    let message = decode_error(&list_with_body(&formset_open()));
    assert!(
        message.contains("opcode FormSet (0x0e) at 0x18"),
        "{message}"
    );
    assert!(message.contains("expected End"), "{message}");
}

#[test]
fn short_and_overlong_opcode_lengths_are_rejected() {
    let short = list_with_body(&[formset_open(), vec![0x46, 0x01]].concat());
    let message = decode_error(&short);
    assert!(message.contains("opcode True (0x46)"), "{message}");
    assert!(
        message.contains("length: expected >= 2 | received 1"),
        "{message}"
    );
    let long = list_with_body(&[formset_open(), vec![0x46, 0x40]].concat());
    let message = decode_error(&long);
    assert!(message.contains("length 0x40"), "{message}");
}

#[test]
fn truncated_payload_names_the_expected_size() {
    let body = [formset_open(), ifr_op(0x24, false, &[0; 4]), ifr_end()].concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("opcode VarStore (0x24)"), "{message}");
    assert!(
        message.contains("expected >= 21 bytes | received 4"),
        "{message}"
    );
}

#[test]
fn scope_depth_is_bounded() {
    let mut body = formset_open();
    for _ in 0..MAX_SCOPE_DEPTH {
        body.extend(ifr_op(0x0A, true, &[]));
    }
    let message = decode_error(&list_with_body(&body));
    assert!(
        message.contains(&format!("expected <= {MAX_SCOPE_DEPTH}")),
        "{message}"
    );
    assert!(message.contains("opcode SuppressIf (0x0a)"), "{message}");
}

#[test]
fn question_outside_a_form_is_rejected() {
    let body = [
        formset_open(),
        ifr_checkbox((1, 2, 3), 0, 0),
        ifr_end(),
        ifr_end(),
    ]
    .concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("opcode CheckBox (0x06)"), "{message}");
    assert!(message.contains("statement outside a form"), "{message}");
}

#[test]
fn option_outside_a_question_is_rejected() {
    let body = [formset_open(), ifr_option_u16(1, 0, 0), ifr_end()].concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("opcode OneOfOption (0x09)"), "{message}");
}

#[test]
fn expression_scopes_do_not_close_the_condition() {
    // AMI writes `Uint64 1 {scope} Uint64 0 Equal End` inside SuppressIf.
    let one = 1u64.to_le_bytes();
    let zero = 0u64.to_le_bytes();
    let mut form = ifr_op(0x01, true, &[1, 0, 0, 0]);
    form.extend(ifr_op(0x0A, true, &[]));
    form.extend(ifr_op(0x45, true, &one));
    form.extend(ifr_op(0x45, false, &zero));
    form.extend(ifr_op(0x2F, false, &[]));
    form.extend(ifr_end());
    form.extend(ifr_numeric_u8((0, 0, 7), 0, 0, (0, 9, 1)));
    form.extend(ifr_end());
    form.extend(ifr_end());
    form.extend(ifr_end());
    let body = [formset_open(), form, ifr_end()].concat();
    let module = decode_module(&list_with_body(&body), None).unwrap();
    let statement = &module.package_lists[0].form_sets[0].forms[0].statements[0];
    assert_eq!(statement.conditions.len(), 1);
    assert_eq!(statement.conditions[0].expression, "1 == 0");
    assert_eq!(statement.varstore, None);
    assert_eq!(statement.storage(), None);
}

#[test]
fn string_package_blocks_skip_duplicate_and_reject_unknown_types() {
    let mut package = hii_string_package("en-US", &["first"]);
    // Replace the END block with: SKIP1 2, UCS-2 "after", DUPLICATE of id 1, END.
    package.pop();
    package.extend_from_slice(&[0x22, 2, 0x14]);
    for unit in "after".encode_utf16() {
        package.extend_from_slice(&unit.to_le_bytes());
    }
    package.extend_from_slice(&[0, 0, 0x20, 1, 0, 0x00]);
    let length = package.len();
    package[..3].copy_from_slice(&(length as u32).to_le_bytes()[..3]);
    let decoded = hii::decode_string_package(&package, 0, length).unwrap();
    assert_eq!(decoded.language, "en-US");
    assert_eq!(decoded.strings[&1], "first");
    assert_eq!(decoded.strings[&4], "after");
    assert_eq!(decoded.strings[&5], "first");
    assert!(!decoded.strings.contains_key(&2));

    let mut bad = hii_string_package("en-US", &[]);
    bad.insert(bad.len() - 1, 0x40);
    let length = bad.len();
    bad[..3].copy_from_slice(&(length as u32).to_le_bytes()[..3]);
    let error = hii::decode_string_package(&bad, 0, length).unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid);
    assert!(error.message.contains("block type 0x40"), "{error}");
    assert!(
        error.message.contains("ifr string package at 0x0"),
        "{error}"
    );
}

#[test]
fn string_package_header_bounds_are_checked() {
    let mut package = hii_string_package("en-US", &["x"]);
    package[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
    let length = package.len();
    let error = hii::decode_string_package(&package, 0, length).unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid);
    assert!(error.message.contains("header size 0xffff"), "{error}");
    assert!(hii::string_package_language(&package, 0, length).is_err());
}

#[test]
fn package_list_scan_requires_the_chain_to_close_on_the_declared_length() {
    let good = ifr_setup_module();
    assert_eq!(hii::find_package_lists(&good).len(), 1);
    let mut longer = good.clone();
    let list = hii::find_package_lists(&good)[0].clone();
    longer[list.offset + 16..list.offset + 20]
        .copy_from_slice(&((list.length + 1) as u32).to_le_bytes());
    assert!(hii::find_package_lists(&longer).is_empty());
}

#[test]
fn decode_image_walks_pe_leaves_and_filters_by_guid() {
    let image = Image::parse(ifr_setup_image()).expect("synthetic image parses");
    let all = decode_image(&image, None, None).unwrap().modules;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].guid, Some(SETUP_GUID));
    let one = decode_image(&image, Some(SETUP_GUID), Some("pt-BR"))
        .unwrap()
        .modules;
    assert_eq!(
        one[0].module.package_lists[0].language.as_deref(),
        Some("pt-BR")
    );

    let missing = Guid::constant("00000000-0000-0000-0000-00000000000A");
    let error = decode_image(&image, Some(missing), None).unwrap_err();
    assert_eq!(error.code, Code::TargetNotFound);
    assert!(error.message.contains("0000000A"), "{error}");

    let plain = Fixture::new(0x07);
    let plain = Image::parse(plain.image).unwrap();
    assert_eq!(
        decode_image(&plain, None, None).unwrap(),
        ImageIfr::default()
    );
    let error = decode_image(&plain, Some(crate::synthetic::PEIM_GUID), None).unwrap_err();
    assert_eq!(error.code, Code::TargetNotFound);
}

#[test]
fn form_nested_in_a_question_scope_is_rejected_not_indexed_out_of_bounds() {
    // FormSet { Form { OneOf { Form { OneOfOption } } } }: the inner Form used to
    // detach the open OneOf from its form and the option indexed past the new form.
    let body = [
        formset_open(),
        ifr_op(0x01, true, &[1, 0, 0, 0]),
        ifr_one_of_u16((0, 0, 7), 0, 0, (0, 1)),
        ifr_op(0x01, true, &[2, 0, 0, 0]),
        ifr_option_u16(0, 0, 0),
    ]
    .concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("opcode Form (0x01)"), "{message}");
    assert!(message.contains("Form inside another scope"), "{message}");
}

/// AMI Platform layout: FormSet { SuppressIf { Form { .. } Form { .. } } Form { .. } }.
fn formset_with_conditioned_forms() -> Vec<u8> {
    [
        formset_open(),
        ifr_op(0x0A, true, &[]),
        ifr_eq_id_val(9, 1),
        ifr_op(0x01, true, &[1, 0, 0, 0]),
        ifr_subtitle(0),
        ifr_end(),
        ifr_end(),
        ifr_op(0x01, true, &[2, 0, 0, 0]),
        ifr_subtitle(0),
        ifr_end(),
        ifr_end(),
        ifr_end(),
        ifr_op(0x01, true, &[3, 0, 0, 0]),
        ifr_subtitle(0),
        ifr_end(),
        ifr_end(),
        ifr_end(),
    ]
    .concat()
}

#[test]
fn form_inside_a_condition_scope_is_decoded_and_records_the_condition() {
    let module = decode_module(&list_with_body(&formset_with_conditioned_forms()), None)
        .expect("forms under a FormSet-level SuppressIf decode");
    let forms = &module.package_lists[0].form_sets[0].forms;
    assert_eq!(forms.iter().map(|f| f.id).collect::<Vec<_>>(), [1, 2, 3]);
    for wrapped in &forms[..2] {
        assert_eq!(wrapped.conditions.len(), 1, "form {}", wrapped.id);
        assert_eq!(wrapped.conditions[0].kind, ConditionKind::SuppressIf);
        assert!(wrapped.conditions[0].expression.contains("== 1"));
        // Statements keep binding to their own form and inherit its condition.
        assert_eq!(wrapped.statements.len(), 1);
        assert_eq!(wrapped.statements[0].conditions.len(), 1);
    }
    assert!(forms[2].conditions.is_empty());
    assert_eq!(forms[2].statements.len(), 1);
    assert!(forms[2].statements[0].conditions.is_empty());
}

#[test]
fn form_inside_a_form_under_a_condition_is_rejected() {
    let body = [
        formset_open(),
        ifr_op(0x0A, true, &[]),
        ifr_op(0x01, true, &[1, 0, 0, 0]),
        ifr_op(0x01, true, &[2, 0, 0, 0]),
    ]
    .concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("Form inside another scope"), "{message}");
}

#[test]
fn statement_after_its_form_closed_is_rejected() {
    let body = [
        formset_open(),
        ifr_op(0x01, true, &[1, 0, 0, 0]),
        ifr_end(),
        ifr_checkbox((0, 0, 3), 0, 0),
        ifr_end(),
        ifr_end(),
    ]
    .concat();
    let message = decode_error(&list_with_body(&body));
    assert!(message.contains("statement outside a form"), "{message}");
}

mod random_streams {
    use super::*;
    use proptest::prelude::*;

    /// Opcodes worth hitting often: scopes, statements, options, expressions, stores.
    const INTERESTING: [u8; 30] = [
        0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0E, 0x0F, 0x12, 0x14, 0x15,
        0x17, 0x19, 0x1A, 0x1B, 0x1C, 0x1E, 0x23, 0x24, 0x25, 0x26, 0x29, 0x29, 0x45, 0x5B, 0x5C,
    ];

    fn opcode_strategy() -> impl Strategy<Value = Vec<u8>> {
        let opcode = prop_oneof![
            4 => proptest::sample::select(INTERESTING.to_vec()),
            1 => any::<u8>(),
        ];
        (
            opcode,
            any::<bool>(),
            proptest::collection::vec(any::<u8>(), 0..40),
        )
            .prop_map(|(opcode, scope, payload)| ifr_op(opcode, scope, &payload))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        /// Random opcode streams under a form set either decode or fail with FormatInvalid.
        #[test]
        fn opcode_streams_never_panic(ops in proptest::collection::vec(opcode_strategy(), 0..60)) {
            let body = [formset_open(), ops.concat(), ifr_end()].concat();
            if let Err(error) = decode_module(&list_with_body(&body), None) {
                prop_assert_eq!(error.code, Code::FormatInvalid, "{}", error);
            }
        }

        /// Raw bytes in the form package body, behind a valid FormSet header.
        #[test]
        fn raw_bodies_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
            let body = [formset_open(), raw].concat();
            if let Err(error) = decode_module(&list_with_body(&body), None) {
                prop_assert_eq!(error.code, Code::FormatInvalid, "{}", error);
            }
        }

        /// Raw bytes as string package blocks.
        #[test]
        fn string_blocks_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..200)) {
            let mut package = hii_string_package("en-US", &[]);
            package.pop();
            package.extend(raw);
            let length = package.len();
            package[..3].copy_from_slice(&(length as u32).to_le_bytes()[..3]);
            if let Err(error) = hii::decode_string_package(&package, 0, length) {
                prop_assert_eq!(error.code, Code::FormatInvalid, "{}", error);
            }
        }
    }
}

/// An image with the good Setup module and a second PE whose form package is malformed.
fn image_with_one_broken_module() -> (Image, Guid) {
    let broken_guid = Guid::constant("00000000-0000-0000-0000-0000000000B1");
    let broken = list_with_body(&[formset_open(), ifr_end(), ifr_end()].concat());
    let files = [
        ffs(SETUP_GUID, 0x07, &section(0x10, &ifr_setup_module()), 0),
        ffs(broken_guid, 0x07, &section(0x10, &broken), 0),
    ];
    let mut bytes = vec![0xFF; 0x1000];
    bytes.extend(volume(&files, 0x4000));
    (
        Image::parse(bytes).expect("synthetic image parses"),
        broken_guid,
    )
}

#[test]
fn image_decode_keeps_good_modules_and_reports_the_broken_one() {
    let (image, broken_guid) = image_with_one_broken_module();
    let found = decode_image(&image, None, None).expect("one bad module must not abort the image");
    assert_eq!(found.modules.len(), 1);
    assert_eq!(found.modules[0].guid, Some(SETUP_GUID));
    assert_eq!(found.diagnostics.len(), 1);
    let diagnostic = &found.diagnostics[0];
    assert_eq!(diagnostic.guid, broken_guid);
    assert_eq!(diagnostic.code, Code::FormatInvalid);
    assert!(
        diagnostic.message.contains("opcode End (0x29) at 0x31"),
        "{}",
        diagnostic.message
    );
}

#[test]
fn image_decode_fails_hard_when_guid_targets_the_broken_module() {
    let (image, broken_guid) = image_with_one_broken_module();
    let error = decode_image(&image, Some(broken_guid), None).unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid);
    assert!(error.message.contains("0000B1"), "{error}");
    assert!(error.message.contains("opcode End (0x29)"), "{error}");
}
