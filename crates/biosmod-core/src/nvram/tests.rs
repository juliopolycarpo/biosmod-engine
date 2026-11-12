use super::*;
use crate::error::Code;
use crate::firmware::Image;
use crate::ifr;
use crate::synthetic::{
    NvarSpec, SETUP_VARSTORE_GUID, VssFlavor, VssSpec, ifr_twin_prompt_image, nvar_record,
    nvar_sample_store, nvar_store, nvram_image, nvram_volume, setup_payload, vss_store,
};

/// Large enough for the records of every fixture, small enough to be one 0x1000 volume.
const STORE_LENGTH: usize = 0xFA0;
const OTHER_GUID: Guid = Guid::constant("80E1202E-2697-4264-9CC9-80762C3E5863");

fn variable<'a>(
    name: &'a str,
    guid_index: u8,
    data: &'a [u8],
    link: Option<usize>,
) -> NvarSpec<'a> {
    NvarSpec::Variable {
        name,
        guid_index,
        runtime: false,
        valid: true,
        data,
        link,
    }
}

fn update(data: &[u8], link: Option<usize>) -> NvarSpec<'_> {
    NvarSpec::DataOnly {
        valid: true,
        data,
        link,
    }
}

fn records<'a>(report: &'a NvramReport, name: &str) -> Vec<&'a Variable> {
    report.variables.iter().filter(|v| v.name == name).collect()
}

fn states(report: &NvramReport, store: &str, name: &str) -> Vec<RecordState> {
    report
        .variables
        .iter()
        .filter(|v| v.store == store && v.name == name)
        .map(|v| v.state)
        .collect()
}

#[test]
fn nvar_chain_marks_the_last_record_active_and_older_ones_superseded() {
    let report = scan_bytes(&nvar_sample_store());
    let setup = records(&report, "Setup");
    let main: Vec<&&Variable> = setup.iter().filter(|v| v.store == "nvar@0x0").collect();
    assert_eq!(
        main.iter().map(|v| v.state).collect::<Vec<_>>(),
        [
            RecordState::Superseded,
            RecordState::Superseded,
            RecordState::Active
        ],
        "(Setup chain states): expected superseded, superseded, active | received {main:?}"
    );
    assert_eq!(
        main.iter()
            .map(|v| (v.chain_index, v.chain_len))
            .collect::<Vec<_>>(),
        [(0, 3), (1, 3), (2, 3)]
    );
    assert_eq!(main[2].data, setup_payload(2), "(active Setup data)");
    assert_eq!(
        main[2].guid, SETUP_VARSTORE_GUID,
        "(data-only record inherits the GUID)"
    );
    assert!(main.iter().all(|v| v.size == 0x40), "(Setup size)");
    assert!(main[0].offset < main[1].offset && main[1].offset < main[2].offset);
}

#[test]
fn nvar_clear_valid_bit_means_deleted_and_unlinked_updates_are_orphans() {
    let report = scan_bytes(&nvar_sample_store());
    assert_eq!(
        states(&report, "nvar@0x0", "Gone"),
        [RecordState::Deleted],
        "(Gone state)"
    );
    let orphans: Vec<&Variable> = report
        .variables
        .iter()
        .filter(|v| v.state == RecordState::Orphan)
        .collect();
    assert_eq!(orphans.len(), 1, "(orphan count): {orphans:?}");
    assert_eq!(orphans[0].data, [9, 9]);
    assert!(orphans[0].name.is_empty());
    assert!(report.issues.is_empty(), "(issues): {:?}", report.issues);
}

#[test]
fn nvar_deleted_head_deletes_the_whole_chain() {
    let store = nvar_store(
        &[
            NvarSpec::Variable {
                name: "Setup",
                guid_index: 0,
                runtime: false,
                valid: false,
                data: &[1],
                link: Some(1),
            },
            update(&[2], None),
        ],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert_eq!(
        report.variables.iter().map(|v| v.state).collect::<Vec<_>>(),
        [RecordState::Deleted, RecordState::Deleted]
    );
}

#[test]
fn nvar_defaults_holder_yields_a_nested_store_with_its_own_guid_table() {
    let report = scan_bytes(&nvar_sample_store());
    let labels: Vec<&str> = report.stores.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["nvar@0x0", "nvar@0x0:StdDefaults"]);
    let nested = &report.stores[1];
    assert_eq!(nested.kind, StoreKind::NvarDefaults);
    assert_eq!(nested.defaults, Some(DefaultsClass::Standard));
    assert_eq!(nested.guid_table_entries, 2);
    let defaults: Vec<&Variable> = report
        .variables
        .iter()
        .filter(|v| v.store == "nvar@0x0:StdDefaults")
        .collect();
    assert_eq!(defaults.len(), 2);
    // Same name, different GUIDs: both survive and keep their own GUID.
    assert_eq!(defaults[0].guid, SETUP_VARSTORE_GUID);
    assert_eq!(defaults[1].guid, OTHER_GUID);
    assert_eq!(defaults[0].defaults, Some(DefaultsClass::Standard));
    // The nested record offset points into the holder's data inside the parent store.
    let holder = &report.variables[0];
    assert_eq!(holder.name, "StdDefaults");
    assert_eq!(holder.guid, AMI_DEFAULTS_GUID);
    assert!(defaults[0].offset > holder.offset && defaults[0].offset < holder.offset + holder.size);
}

#[test]
fn nvar_manufacturing_holder_is_a_manufacturing_store() {
    let nested = nvar_store(
        &[variable("Setup", 0, &setup_payload(1), None)],
        &[SETUP_VARSTORE_GUID],
        0x200,
    );
    let store = nvar_store(
        &[variable("MfgDefaults", 0, &nested, None)],
        &[AMI_DEFAULTS_GUID],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert_eq!(
        report.stores[1].defaults,
        Some(DefaultsClass::Manufacturing)
    );
    assert_eq!(DefaultsClass::Manufacturing.default_id(), 1);
    assert_eq!(DefaultsClass::Standard.default_id(), 0);
}

#[test]
fn nvar_inline_guid_ucs2_name_and_extended_header_are_decoded() {
    // attributes: valid | ext header | inline GUID, no ASCII flag (UCS-2 name).
    let mut payload = SETUP_VARSTORE_GUID.0.to_vec();
    payload.extend("Wide".encode_utf16().flat_map(u16::to_le_bytes));
    payload.extend_from_slice(&[0, 0]);
    payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    // Extended header: attributes (checksum | auth write), checksum byte, size (4).
    payload.extend_from_slice(&[0x11, 0x5A, 4, 0]);
    let store = nvar_store(
        &[NvarSpec::Raw(nvar_record(0x80 | 0x10 | 0x04, &payload))],
        &[],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert!(report.issues.is_empty(), "(issues): {:?}", report.issues);
    let wide = &report.variables[0];
    assert_eq!(wide.name, "Wide", "(UCS-2 name)");
    assert_eq!(wide.guid, SETUP_VARSTORE_GUID, "(inline GUID)");
    assert_eq!(
        wide.data,
        [0xAA, 0xBB, 0xCC],
        "(data without extended header)"
    );
    assert_eq!(wide.extended_attributes, Some(0x11));
    assert_eq!(wide.checksum, Some(0x5A));
    assert_eq!(
        wide.attributes & EFI_AUTH_WRITE,
        EFI_AUTH_WRITE,
        "(auth write bit)"
    );
    assert!(wide.flags.contains(&"ext_header") && wide.flags.contains(&"ext_auth_write"));
}

#[test]
fn nvar_extended_header_larger_than_the_record_is_an_issue() {
    let mut payload = vec![0x00, b'A', 0, 1];
    payload.extend_from_slice(&[0x01, 0x00, 0x40, 0]);
    let store = nvar_store(
        &[NvarSpec::Raw(nvar_record(0x80 | 0x02 | 0x10, &payload))],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert!(report.variables.is_empty());
    assert_eq!(report.issues.len(), 1, "(issues): {:?}", report.issues);
    assert!(
        report.issues[0]
            .message
            .starts_with("extended header size: expected 3..="),
        "(message): {}",
        report.issues[0].message
    );
}

#[test]
fn nvar_corrupt_records_are_reported_with_offsets_and_the_walk_continues() {
    let mut oversized = nvar_record(0x82, &[0; 8]);
    oversized[4..6].copy_from_slice(&0x7FFFu16.to_le_bytes());
    let mut dangling = nvar_record(0x82, b"\0Dangling\0\x01");
    dangling[6..9].copy_from_slice(&0x0001_2345u32.to_le_bytes()[..3]);
    let specs = [
        variable("Before", 0, &[1], None),
        NvarSpec::Raw(oversized),
        variable("Between", 0, &[2], None),
        NvarSpec::Raw(vec![0x12; 7]),
        variable("BadIndex", 9, &[3], None),
        NvarSpec::Raw(dangling),
        variable("After", 0, &[4], None),
    ];
    let store = nvar_store(&specs, &[SETUP_VARSTORE_GUID], STORE_LENGTH);
    let report = scan_bytes(&store);
    let names: Vec<&str> = report.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(
        names,
        ["Before", "Between", "Dangling", "After"],
        "(variables surviving corruption)"
    );
    let messages: Vec<String> = report
        .issues
        .iter()
        .map(|i| format!("{:#x}: {}", i.offset, i.message))
        .collect();
    let at = |name: &str| records(&report, name)[0].offset;
    assert!(
        messages[0].starts_with(&format!(
            "{:#x}: record size: expected 10..=",
            // Before: 10 header + 1 index + "Before\0" + 1 data byte.
            at("Before") + 10 + 1 + 7 + 1
        )),
        "(oversized record): {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("record signature: expected \"NVAR\" | received [12, 12, 12, 12]")),
        "(garbage record): {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("GUID index: expected < 1 (table entries) | received 9")),
        "(bad GUID index): {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("next record: expected a record start | received 0x")),
        "(dangling link): {messages:?}"
    );
}

#[test]
fn nvar_link_loops_are_cut_and_reported() {
    let store = nvar_store(
        &[variable("Loop", 0, &[1], Some(1)), update(&[2], Some(1))],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert_eq!(report.variables.len(), 2);
    assert_eq!(report.issues.len(), 1, "(issues): {:?}", report.issues);
    assert!(
        report.issues[0]
            .message
            .contains("expected an unvisited record | received a loop")
    );
}

#[test]
fn nvar_link_to_a_variable_record_is_not_followed() {
    let store = nvar_store(
        &[
            variable("First", 0, &[1], Some(1)),
            variable("Second", 0, &[2], None),
        ],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let report = scan_bytes(&store);
    assert!(
        report.issues[0]
            .message
            .contains("expected a data-only record | received a variable record"),
        "(message): {:?}",
        report.issues
    );
    assert_eq!(states(&report, "nvar@0x0", "Second"), [RecordState::Active]);
}

#[test]
fn nvar_erased_and_full_garbage_stores_do_not_panic() {
    assert!(
        scan_bytes(&[0xFF; 64]).stores.is_empty(),
        "(erased input is no store)"
    );
    let report = scan_bytes(b"NVAR\x05");
    assert_eq!(report.variables.len(), 0);
    assert!(
        report.issues[0]
            .message
            .starts_with("record header: expected 10 bytes | received 5"),
        "(truncated header): {:?}",
        report.issues
    );
}

#[test]
fn scan_image_reports_absolute_offsets_of_each_store() {
    let image = nvram_image(&[nvar_sample_store(), nvar_sample_store()]);
    let parsed = Image::parse(image.clone()).unwrap();
    let report = scan_image(&parsed);
    let bases: Vec<usize> = report.stores.iter().map(|s| s.offset).collect();
    // ifr_setup_image is 0x1000 + 0x4000 bytes; each NVRAM volume adds 0x1000. The store
    // starts after the volume header (0x48) and the file header (0x18).
    assert_eq!(bases, [0x5060, 0x5077, 0x6060, 0x6077]);
    assert_eq!(report.stores[0].label, "nvar@0x5060");
    assert_eq!(report.stores[0].file_guid, Some(NVRAM_FILE_GUID));
    let setup = records(&report, "Setup")
        .into_iter()
        .find(|v| v.store == "nvar@0x5060" && v.state == RecordState::Active)
        .unwrap();
    assert_eq!(
        &image[setup.offset..setup.offset + 4],
        b"NVAR",
        "(image bytes at the record offset)"
    );
    assert_eq!(setup.sha256, crate::util::sha256_hex(&setup_payload(2)));
}

#[test]
fn scan_image_treats_an_erased_nvram_file_as_an_empty_store_and_flags_garbage() {
    let erased = nvram_image(&[vec![0xFF; STORE_LENGTH]]);
    let report = scan_image(&Image::parse(erased).unwrap());
    assert_eq!(report.stores.len(), 1, "(erased store): {report:?}");
    assert_eq!(report.stores[0].records, 0);
    assert!(report.issues.is_empty());

    let garbage = nvram_image(&[vec![0x11; STORE_LENGTH]]);
    let report = scan_image(&Image::parse(garbage).unwrap());
    assert!(report.stores.is_empty());
    assert!(
        report.issues[0].message.starts_with(
            "NVRAM file body: expected an NVAR or VSS store | received [11, 11, 11, 11]"
        ),
        "(garbage body): {:?}",
        report.issues
    );
}

#[test]
fn scan_image_finds_a_vss_store_in_a_raw_file_without_the_nvram_guid() {
    let store = vss_store(VssFlavor::Plain, &[], 0xF00);
    let file = crate::synthetic::ffs(
        Guid::constant("11111111-2222-3333-4444-000000000001"),
        0x01,
        &store,
        0,
    );
    let mut image = vec![0xFF; 0x1000];
    image.extend(crate::synthetic::volume(&[file], 0x1000));
    let report = scan_image(&Image::parse(image).unwrap());
    assert_eq!(report.stores.len(), 1);
    assert_eq!(report.stores[0].kind, StoreKind::Vss);
    assert_eq!(report.stores[0].label, "vss@0x1060");
}

fn vss_var<'a>(name: &'a str, state: u8, data: &'a [u8]) -> VssSpec<'a> {
    VssSpec::Variable {
        name,
        guid: SETUP_VARSTORE_GUID,
        attributes: 0x07,
        state,
        data,
    }
}

#[test]
fn vss_states_added_transition_deleted_and_header_only() {
    let specs = [
        vss_var("Old", 0x3E, &[1]),
        vss_var("Old", 0x3F, &[2]),
        vss_var("Lonely", 0x3E, &[3]),
        vss_var("Gone", 0x3D, &[4]),
        vss_var("Half", 0x7F, &[5]),
        vss_var("Plain", 0x3F, &[6, 7]),
    ];
    let report = scan_bytes(&vss_store(VssFlavor::Plain, &specs, 0x400));
    assert!(report.issues.is_empty(), "(issues): {:?}", report.issues);
    let state = |name: &str| states(&report, "vss@0x0", name);
    assert_eq!(
        state("Old"),
        [RecordState::Superseded, RecordState::Active],
        "(completed update beats the transition record)"
    );
    assert_eq!(
        state("Lonely"),
        [RecordState::Active],
        "(transition without a successor)"
    );
    assert_eq!(state("Gone"), [RecordState::Deleted]);
    assert_eq!(state("Half"), [RecordState::Incomplete]);
    assert_eq!(state("Plain"), [RecordState::Active]);
    let plain = records(&report, "Plain")[0];
    assert_eq!(plain.data, [6, 7]);
    assert_eq!(plain.guid, SETUP_VARSTORE_GUID);
    assert_eq!(plain.attributes, 0x07);
    assert_eq!(plain.flags, ["non_volatile", "boot_service", "runtime"]);
    assert_eq!(
        (report.stores[0].kind, report.stores[0].records),
        (StoreKind::Vss, 6)
    );
}

#[test]
fn vss_authenticated_and_dollar_stores_decode_their_header_shapes() {
    for flavor in [VssFlavor::Authenticated, VssFlavor::Dollar] {
        let specs = [
            vss_var("First", 0x3F, &[1, 2, 3]),
            vss_var("Second", 0x3F, &[4]),
        ];
        let report = scan_bytes(&vss_store(flavor, &specs, 0x400));
        assert!(
            report.issues.is_empty(),
            "({flavor:?} issues): {:?}",
            report.issues
        );
        let names: Vec<(&str, &[u8])> = report
            .variables
            .iter()
            .map(|v| (v.name.as_str(), v.data.as_slice()))
            .collect();
        assert_eq!(
            names,
            [("First", &[1u8, 2, 3][..]), ("Second", &[4u8][..])],
            "({flavor:?} variables)"
        );
    }
}

#[test]
fn vss_corrupt_records_are_reported_and_the_walk_resumes_at_the_next_marker() {
    let mut bad_sizes = vec![0xAA, 0x55, 0x3F, 0, 7, 0, 0, 0];
    bad_sizes.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    bad_sizes.extend_from_slice(&[0; 20]);
    let specs = [
        vss_var("Before", 0x3F, &[1]),
        VssSpec::Raw(bad_sizes),
        vss_var("Middle", 0x3F, &[2]),
        VssSpec::Raw(vec![0x12, 0x34, 0x56, 0x78]),
        vss_var("After", 0x3F, &[3]),
    ];
    let report = scan_bytes(&vss_store(VssFlavor::Plain, &specs, 0x400));
    let names: Vec<&str> = report.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(
        names,
        ["Before", "Middle", "After"],
        "(variables surviving corruption)"
    );
    assert!(
        report.issues.iter().any(|i| i
            .message
            .starts_with("variable sizes: expected an even name size")),
        "(sizes): {:?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message == "variable start marker: expected 0x55aa | received 0x3412"),
        "(marker): {:?}",
        report.issues
    );
}

#[test]
fn vss_store_header_problems_are_issues_not_failures() {
    let mut store = vss_store(VssFlavor::Plain, &[vss_var("A", 0x3F, &[1])], 0x400);
    store[20] = 0x00; // format
    store[21] = 0xFF; // state
    store[16..20].copy_from_slice(&0x9999_9999u32.to_le_bytes()); // size
    let report = scan_bytes(&store);
    assert_eq!(report.variables.len(), 1);
    let messages: Vec<&str> = report.issues.iter().map(|i| i.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("store size: expected 0x1c..=0x400 | received 0x99999999")),
        "{messages:?}"
    );
    assert!(
        messages.contains(&"store format: expected 0x5a | received 0x00"),
        "{messages:?}"
    );
    assert!(
        messages.contains(&"store state: expected 0xfe | received 0xff"),
        "{messages:?}"
    );
    let short = scan_bytes(b"$VSS\x01");
    assert!(
        short.issues[0]
            .message
            .starts_with("store header: expected 16 bytes | received 5")
    );
}

#[test]
fn sniffing_and_helpers_recognize_their_inputs() {
    assert!(nvar::sniff(b"NVAR...."));
    assert!(!nvar::sniff(b"NVA"));
    assert!(vss::sniff(b"$VSS\0\0\0\0"));
    assert!(vss::sniff(&vss_store(VssFlavor::Authenticated, &[], 0x100)));
    assert!(!vss::sniff(&[0u8; 64]));
    assert!(is_erased(&[0xFF; 8]) && !is_erased(&[0xFF, 0xFE]));
    assert_eq!(ucs2_text(&[b'H', 0, b'i', 0, 0, 0, b'x', 0]), "Hi");
    assert_eq!(nvram_volume(&vec![0xFF; STORE_LENGTH]).len(), 0x1000);
}

#[test]
fn read_field_lists_stored_values_against_the_ifr_default() {
    let image = Image::parse(nvram_image(&[nvar_sample_store()])).unwrap();
    let report = scan_image(&image);
    let modules = ifr::decode_image(&image, None, None).unwrap().modules;
    let field = read_field(&report, &modules, "acpi sleep state", None, false).unwrap();
    assert_eq!(field.question_ids, [0x19]);
    assert_eq!(
        (field.varstore_name.as_str(), field.offset, field.width),
        ("Setup", 0x0A, 2)
    );
    assert_eq!(field.varstore_guid, SETUP_VARSTORE_GUID);
    assert_eq!(field.varstore_size, 0x40);
    assert_eq!(field.standard_default, Some(2));
    type Row<'a> = (
        &'a str,
        RecordState,
        Option<DefaultsClass>,
        Option<u64>,
        Option<bool>,
    );
    let rows: Vec<Row<'_>> = field
        .values
        .iter()
        .map(|v| {
            (
                v.store.as_str(),
                v.state,
                v.defaults,
                v.value,
                v.equals_default,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "nvar@0x5060",
                RecordState::Active,
                None,
                Some(2),
                Some(true)
            ),
            (
                "nvar@0x5060:StdDefaults",
                RecordState::Active,
                Some(DefaultsClass::Standard),
                Some(2),
                Some(true)
            ),
        ],
        "(active records of Setup EC87D643; the 80E1202E Setup is a different variable)"
    );
    assert!(field.values.iter().all(|v| !v.size_mismatch));

    let history = read_field(&report, &modules, "ACPI Sleep State", None, true).unwrap();
    let values: Vec<Option<u64>> = history.values.iter().map(|v| v.value).collect();
    assert_eq!(
        values,
        [Some(0), Some(1), Some(2), Some(2)],
        "(superseded then active, in image order)"
    );
    assert_eq!(history.values[0].equals_default, Some(false));
    assert_eq!(history.values[0].bytes.as_deref(), Some("0000"));
}

#[test]
fn read_field_flags_short_records_and_missing_questions() {
    let short = nvar_store(
        &[variable("Setup", 0, &[0u8; 8], None)],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let image = Image::parse(nvram_image(&[short])).unwrap();
    let report = scan_image(&image);
    let modules = ifr::decode_image(&image, None, None).unwrap().modules;
    let field = read_field(&report, &modules, "Highest sleep state", None, false);
    assert_eq!(
        field.unwrap_err().code,
        Code::TargetNotFound,
        "(prompt is not a question text)"
    );
    let field = read_field(&report, &modules, "ACPI Sleep State", None, false).unwrap();
    assert_eq!(field.values.len(), 1);
    assert_eq!(
        (
            field.values[0].value,
            field.values[0].bytes.clone(),
            field.values[0].equals_default
        ),
        (None, None, None),
        "(offset 0xA..0xC lies beyond the 8 stored bytes)"
    );
    assert!(
        field.values[0].size_mismatch,
        "(8 bytes stored, 0x40 declared)"
    );

    let missing = read_field(&report, &modules, "No Such Prompt", None, false).unwrap_err();
    assert_eq!(missing.code, Code::TargetNotFound);
    assert!(
        missing.message.contains(
            "question prompt \"No Such Prompt\": expected a Setup question | received none"
        ),
        "(message): {}",
        missing.message
    );
    let by_id = read_field(&report, &modules, "ACPI Sleep State", Some(0x99), false).unwrap_err();
    assert!(
        by_id.message.contains("with id 0x0099"),
        "(message): {}",
        by_id.message
    );
}

#[test]
fn read_field_reports_ambiguity_with_question_ids_and_honors_question_id() {
    let image = Image::parse(ifr_twin_prompt_image(&[nvar_sample_store()])).unwrap();
    let report = scan_image(&image);
    let modules = ifr::decode_image(&image, None, None).unwrap().modules;
    let ambiguous = read_field(&report, &modules, "Twin", None, false).unwrap_err();
    assert_eq!(ambiguous.code, Code::TargetAmbiguous);
    assert!(
        ambiguous.message.contains("0x0030") && ambiguous.message.contains("0x0031"),
        "(ids listed): {}",
        ambiguous.message
    );
    assert!(
        ambiguous.message.contains("--question-id"),
        "(hint): {}",
        ambiguous.message
    );
    let picked = read_field(&report, &modules, "Twin", Some(0x31), false).unwrap();
    assert_eq!(
        (picked.offset, picked.question_ids.clone()),
        (0x0C, vec![0x31])
    );
    assert_eq!(picked.standard_default, None, "(no default stated)");
    assert!(picked.values.iter().all(|v| v.equals_default.is_none()));
}

#[test]
fn read_field_collapses_questions_that_share_storage_and_default() {
    let image = Image::parse(ifr_twin_prompt_image(&[nvar_sample_store()])).unwrap();
    let report = scan_image(&image);
    let modules = ifr::decode_image(&image, None, None).unwrap().modules;
    // Questions 0x32 and 0x33 differ in prompt, so make them the same by asking for both prompts.
    let one = read_field(&report, &modules, "Dup", None, false).unwrap();
    assert_eq!(one.question_ids, [0x32, 0x33], "(one field, two questions)");
}

#[test]
fn read_field_needs_variable_storage() {
    let image = Image::parse(ifr_twin_prompt_image(&[nvar_sample_store()])).unwrap();
    let report = scan_image(&image);
    let modules = ifr::decode_image(&image, None, None).unwrap().modules;
    let error = read_field(&report, &modules, "Plain", None, false);
    // Question 0x34 is a numeric whose store id 0 names no variable store.
    let error = error.unwrap_err();
    assert_eq!(error.code, Code::TargetNotFound);
    assert!(
        error.message.contains("expected backing variable storage"),
        "(message): {}",
        error.message
    );
}

#[test]
fn check_sizes_marks_records_that_differ_from_the_ifr_variable_store() {
    let wrong = nvar_store(
        &[
            variable("Setup", 0, &[0u8; 0x30], None),
            variable("Other", 0, &[1], None),
        ],
        &[SETUP_VARSTORE_GUID],
        STORE_LENGTH,
    );
    let image = Image::parse(nvram_image(&[nvar_sample_store(), wrong])).unwrap();
    let mut report = scan_image(&image);
    check_sizes(
        &mut report,
        &ifr::decode_image(&image, None, None).unwrap().modules,
    );
    let view: Vec<(&str, usize, Option<usize>, bool)> = report
        .variables
        .iter()
        .filter(|v| v.name == "Setup" || v.name == "Other")
        .filter(|v| v.guid == SETUP_VARSTORE_GUID)
        .map(|v| (v.store.as_str(), v.size, v.expected_size, v.size_mismatch))
        .collect();
    assert!(
        view.contains(&("nvar@0x5060", 0x40, Some(0x40), false)),
        "(match): {view:?}"
    );
    assert!(
        view.contains(&("nvar@0x6060", 0x30, Some(0x40), true)),
        "(mismatch): {view:?}"
    );
    assert!(
        view.contains(&("nvar@0x6060", 1, None, false)),
        "(no IFR store, no verdict): {view:?}"
    );
    let orphan = report
        .variables
        .iter()
        .find(|v| v.state == RecordState::Orphan)
        .unwrap();
    assert_eq!(
        orphan.expected_size, None,
        "(orphans have no name to check)"
    );
}
