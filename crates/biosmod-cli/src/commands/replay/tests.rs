//! Evidence building, output writing and the date helper for `bme replay`.

use super::*;
use biosmod_core::validation::identifier;

fn versions() -> Versions {
    Versions {
        python: "3.14.4".into(),
        packages: BTreeMap::from([
            ("unicorn".to_string(), Some("2.1.4".to_string())),
            ("capstone".to_string(), None),
        ]),
    }
}

fn spec<'a>(versions: &'a Versions, raw: &'a str) -> RecordSpec<'a> {
    RecordSpec {
        harness: "Fan Zero.py",
        harness_role: "harness",
        harness_sha256: Digest256::of(b"harness"),
        scenario: None,
        modules: vec![("SioDxeInit.pe".into(), Digest256::of(b"module"))],
        versions,
        raw_output: raw,
        documents: 2,
        observations: vec!["12 of 12 cases passed".into()],
        board: UNSCOPED,
        firmware: UNSCOPED,
        date: "2026-11-12".into(),
    }
}

#[test]
fn the_record_lists_the_harness_then_the_modules_and_the_output_digest() {
    let versions = versions();
    let record = evidence(spec(&versions, "{\"a\":1}\n"));
    let replay = record.replay.expect("replay block");
    let inputs: Vec<(&str, &str)> = replay
        .inputs
        .iter()
        .map(|i| (i.role.as_str(), i.name.as_str()))
        .collect();
    assert_eq!(
        inputs,
        [("harness", "Fan Zero.py"), ("module", "SioDxeInit.pe")]
    );
    assert_eq!(replay.output_sha256, Digest256::of(b"{\"a\":1}\n"));
    assert_eq!(record.kind, EvidenceKind::OfflineValidation);
    assert_eq!(
        record.observations,
        [
            "Fan Zero.py emitted 2 JSON documents",
            "12 of 12 cases passed"
        ]
    );
}

#[test]
fn runtime_lists_python_and_only_the_packages_that_have_a_version() {
    let versions = versions();
    let replay = evidence(spec(&versions, "")).replay.unwrap();
    assert_eq!(
        replay.runtime,
        BTreeMap::from([
            ("python".to_string(), "3.14.4".to_string()),
            ("unicorn".to_string(), "2.1.4".to_string()),
        ])
    );
}

#[test]
fn the_id_is_a_valid_identifier_built_from_the_file_stem_and_output_digest() {
    let versions = versions();
    let record = evidence(spec(&versions, "x"));
    identifier(&record.id, "evidence id").unwrap();
    let digest = Digest256::of(b"x").to_string();
    assert_eq!(record.id, format!("replay-fan-zero-{}", &digest[..8]));
}

#[test]
fn a_scenario_names_the_record_and_the_replay_block() {
    let versions = versions();
    let mut input = spec(&versions, "");
    input.scenario = Some("zero-policy-case-1.json");
    input.harness_role = "scenario";
    let record = evidence(input);
    assert!(
        record.title.contains("zero-policy-case-1.json"),
        "{}",
        record.title
    );
    assert_eq!(
        record.replay.unwrap().scenario.as_deref(),
        Some("zero-policy-case-1.json")
    );
    assert!(
        record.id.starts_with("replay-zero-policy-case-1-"),
        "{}",
        record.id
    );
}

#[test]
fn one_document_is_singular_in_the_observation() {
    let versions = versions();
    let mut input = spec(&versions, "");
    input.documents = 1;
    assert_eq!(
        evidence(input).observations[0],
        "Fan Zero.py emitted 1 JSON document"
    );
}

#[test]
fn slug_keeps_lowercase_alphanumerics_and_collapses_the_rest() {
    assert_eq!(slug("Fan_Zero  Policy"), "fan-zero-policy");
    assert_eq!(slug("--x--"), "x");
    assert_eq!(slug("???"), "run");
    assert_eq!(slug(&"a".repeat(80)).len(), 40);
}

#[test]
fn civil_date_matches_known_days() {
    for (seconds, date) in [
        (0, "1970-01-01"),
        (86_399, "1970-01-01"),
        (86_400, "1970-01-02"),
        (951_782_400, "2000-02-29"),
        (1_700_000_000, "2023-11-14"),
        (4_102_444_800, "2100-01-01"),
    ] {
        assert_eq!(civil_date(seconds), date, "(unix time {seconds})");
    }
}

#[test]
fn outputs_land_in_a_new_directory_and_a_second_write_is_refused() {
    let versions = versions();
    let record = evidence(spec(&versions, "{}\n"));
    let dir = tempfile::tempdir().unwrap().keep().join("out");
    let written = write_outputs(&dir, "{}\n", &record).unwrap();
    assert_eq!(written, [dir.join(EVIDENCE_FILE), dir.join(RESULT_FILE)]);
    assert_eq!(fs::read_to_string(dir.join(RESULT_FILE)).unwrap(), "{}\n");
    let parsed: Evidence =
        serde_json::from_slice(&fs::read(dir.join(EVIDENCE_FILE)).unwrap()).unwrap();
    assert_eq!(parsed.id, record.id);
    let error = write_outputs(&dir, "{}\n", &record).unwrap_err();
    assert_eq!(error.code, Code::OutputExists, "{error}");
    assert!(error.message.contains("evidence.json"), "{error}");
    fs::remove_dir_all(dir.parent().unwrap()).unwrap();
}

#[test]
fn an_empty_existing_directory_is_free() {
    let dir = tempfile::tempdir().unwrap();
    check_output_free(dir.path()).unwrap();
}
