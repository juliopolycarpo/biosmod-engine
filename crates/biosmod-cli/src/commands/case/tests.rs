use super::*;
use crate::config::{Config, Paths};
use biosmod_core::catalog::{Catalog, Scope};
use biosmod_core::synthetic::{BANNER, Fixture, PEIM_GUID};

/// A clock that always reads the same instant.
struct FixedClock(u64);

impl Clock for FixedClock {
    fn unix_seconds(&self) -> u64 {
        self.0
    }
}

/// 2026-11-12T12:00:00Z
const NOON: u64 = 1_794_484_800;

/// A host whose SMBIOS is whatever the test says.
struct FakeHostIdentity(BTreeMap<String, String>);

impl FakeHostIdentity {
    fn with(fields: &[(&str, &str)]) -> FakeHostIdentity {
        FakeHostIdentity(
            fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    /// A machine whose BIOS date is the date in the synthetic banner.
    fn on_the_board() -> FakeHostIdentity {
        FakeHostIdentity::with(&[
            ("board_vendor", "ACME"),
            ("board_name", "X1"),
            ("board_version", "V2"),
            ("bios_date", "11/12/2026"),
        ])
    }
}

impl HostIdentity for FakeHostIdentity {
    fn smbios(&self) -> BTreeMap<String, String> {
        self.0.clone()
    }
}

/// A temporary directory with the synthetic image (banner included) and its catalog.
struct Workspace {
    dir: tempfile::TempDir,
    ctx: Ctx,
}

impl Workspace {
    fn new() -> Workspace {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture::new(0x07).with_banner(BANNER);
        fs::write(dir.path().join("dump.bin"), &fixture.image).unwrap();
        for (path, bytes) in fixture.catalog_files() {
            let target = dir.path().join("catalog").join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
        let ctx = Ctx {
            out: Out {
                json: true,
                quiet: true,
            },
            offline: true,
            paths: Paths {
                config: dir.path().join("config"),
                cache: dir.path().join("cache"),
                data: dir.path().join("data"),
            },
            config: Config::default(),
        };
        Workspace { dir, ctx }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn source(&self) -> SourceArgs {
        SourceArgs {
            catalogs: vec![self.path("catalog").to_string_lossy().into_owned()],
            allow_unsigned_local: true,
            firmware: None,
        }
    }

    fn init_with(&self, host: &FakeHostIdentity, board_id: Option<&str>) -> Result<Reply> {
        let environment = Environment {
            clock: &FixedClock(NOON),
            host,
        };
        init(
            &self.ctx,
            &CaseInitArgs {
                dump: self.path("dump.bin"),
                output: self.path("case"),
                board_id: board_id.map(str::to_string),
                source: self.source(),
            },
            &environment,
        )
    }

    fn init(&self) -> Reply {
        self.init_with(&FakeHostIdentity::with(&[]), None).unwrap()
    }

    fn record(&self, argv: &[&str], artifacts: &[&str]) -> Result<Reply> {
        let environment = Environment {
            clock: &FixedClock(NOON + 60),
            host: &FakeHostIdentity::with(&[]),
        };
        record(
            &self.ctx,
            &CaseRecordArgs {
                dir: self.path("case"),
                artifacts: artifacts.iter().map(PathBuf::from).collect(),
                argv: argv.iter().map(|word| word.to_string()).collect(),
            },
            &environment,
        )
    }

    fn status_with(&self, inputs: &[String]) -> Result<Reply> {
        case_status(
            &self.ctx,
            &CaseStatusArgs {
                dir: self.path("case"),
                inputs: inputs.to_vec(),
                catalogs: vec![],
                allow_unsigned_local: false,
            },
        )
    }

    fn status(&self) -> Result<Reply> {
        self.status_with(&[self.path("dump.bin").to_string_lossy().into_owned()])
    }

    fn export(&self, name: &str) -> Result<Reply> {
        export(&CaseExportArgs {
            dir: self.path("case"),
            output: self.path(name),
        })
    }

    fn case(&self) -> Case {
        load_case(&self.path("case")).unwrap()
    }
}

fn flip_first_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes[0] ^= 0xFF;
    fs::write(path, bytes).unwrap();
}

#[test]
fn init_writes_the_case_drafts_and_findings() {
    let workspace = Workspace::new();
    let reply = workspace
        .init_with(&FakeHostIdentity::on_the_board(), None)
        .unwrap();
    let case = workspace.case();
    let dump = fs::read(workspace.path("dump.bin")).unwrap();
    assert_eq!(case.created, "2026-11-12T12:00:00Z");
    assert_eq!(case.inputs[0].name, "dump.bin");
    assert_eq!(case.inputs[0].sha256, Digest256::of(&dump));
    assert_eq!(case.inputs[0].length, dump.len() as u64);
    assert_eq!(case.catalogs[0].alias, "local");
    let scan = fs::read(workspace.path("case/artifacts/001-scan.json")).unwrap();
    assert_eq!(case.artifacts[0].sha256, Digest256::of(&scan));
    assert_eq!(case.artifacts[0].command[..2], ["scan", "dump.bin"]);
    let board: Board = read_document(&workspace.path("case"), BOARD_DRAFT).unwrap();
    assert_eq!(board.id, "draft-syn1a00-20261112");
    assert_eq!(
        (board.vendor.as_str(), board.model.as_str()),
        ("ACME", "X1")
    );
    let firmware: FirmwareDraft = read_document(&workspace.path("case"), FIRMWARE_DRAFT).unwrap();
    assert_eq!(
        firmware.matches_catalog_build.as_deref(),
        Some("synthetic-fw")
    );
    assert!(!firmware.modules.is_empty());
    assert_eq!(reply.data["findings"], json!(["OPEN1"]));
    assert_eq!(reply.data["smbios_recorded"], true);
    let findings = case_findings(&workspace.path("case")).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].affects.builds, [firmware.build.id]);
    assert!(
        !workspace.path("case/dump.bin").exists(),
        "(case): expected the input never copied into the case"
    );
}

#[test]
fn init_keeps_smbios_out_when_the_host_bios_date_is_not_in_the_image() {
    let workspace = Workspace::new();
    let host = FakeHostIdentity::with(&[("board_vendor", "ACME"), ("bios_date", "03/22/2023")]);
    let reply = workspace.init_with(&host, None).unwrap();
    assert_eq!(reply.data["smbios_recorded"], false);
    let board: Board = read_document(&workspace.path("case"), BOARD_DRAFT).unwrap();
    assert_eq!(board.vendor, "Unknown");
}

#[test]
fn init_refuses_an_existing_output_and_leaves_it_alone() {
    let workspace = Workspace::new();
    fs::create_dir(workspace.path("case")).unwrap();
    fs::write(workspace.path("case/keep.txt"), b"mine").unwrap();
    let error = workspace
        .init_with(&FakeHostIdentity::with(&[]), None)
        .unwrap_err();
    assert_eq!(error.code, Code::OutputExists, "{error}");
    assert_eq!(fs::read(workspace.path("case/keep.txt")).unwrap(), b"mine");
}

#[test]
fn init_with_an_invalid_board_id_creates_nothing() {
    let workspace = Workspace::new();
    let error = workspace
        .init_with(&FakeHostIdentity::with(&[]), Some("bad id"))
        .unwrap_err();
    assert_eq!(error.code, Code::CatalogInvalid, "{error}");
    assert!(error.message.contains("\"bad id\""), "{error}");
    assert!(!workspace.path("case").exists());
}

#[test]
fn record_stores_the_output_the_files_and_their_provenance() {
    let workspace = Workspace::new();
    workspace.init();
    let dump = workspace.path("dump.bin");
    let module = workspace.path("module.bin");
    let argv = [
        "extract",
        dump.to_str().unwrap(),
        "--guid",
        &PEIM_GUID.to_string(),
        "-o",
        module.to_str().unwrap(),
    ];
    let reply = workspace.record(&argv, &[]).unwrap();
    assert_eq!(reply.data["command"], "extract");
    let case = workspace.case();
    assert_eq!(case.artifacts.len(), 3);
    let (output, file) = (&case.artifacts[1], &case.artifacts[2]);
    assert_eq!(
        (output.id.as_str(), output.kind),
        ("002-extract", ArtifactKind::Output)
    );
    assert_eq!(
        (file.id.as_str(), file.kind),
        ("003-module.bin", ArtifactKind::File)
    );
    assert_eq!(output.command, argv);
    assert_eq!(output.bme_version, biosmod_core::VERSION);
    assert_eq!(output.recorded, "2026-11-12T12:01:00Z");
    assert_eq!(output.inputs.len(), 1);
    assert_eq!(output.inputs[0].name, "dump.bin");
    assert_eq!(output.inputs[0].sha256, case.inputs[0].sha256);
    let stored = fs::read(workspace.path("case/artifacts/003-module.bin")).unwrap();
    assert_eq!(stored, fs::read(&module).unwrap());
    assert_eq!(file.sha256, Digest256::of(&stored));
    let envelope: Value = serde_json::from_slice(
        &fs::read(workspace.path("case/artifacts/002-extract.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        (envelope["ok"].as_bool(), envelope["command"].as_str()),
        (Some(true), Some("extract"))
    );
    assert!(
        workspace.status().is_ok(),
        "(case): expected clean after record"
    );
}

#[test]
fn record_notes_declared_outputs_the_command_did_not_create() {
    let workspace = Workspace::new();
    workspace.init();
    let dump = workspace.path("dump.bin");
    let absent = workspace.path("absent.bin");
    let reply = workspace
        .record(
            &["inspect", dump.to_str().unwrap()],
            &[absent.to_str().unwrap()],
        )
        .unwrap();
    assert_eq!(reply.data["not_created"], json!([absent.to_str().unwrap()]));
    assert_eq!(workspace.case().artifacts.len(), 2);
}

#[test]
fn record_refuses_nested_cases_existing_outputs_and_bad_arguments() {
    let workspace = Workspace::new();
    workspace.init();
    let nested = workspace.record(&["case", "status", "x"], &[]).unwrap_err();
    assert_eq!(nested.code, Code::Usage, "{nested}");
    assert!(nested.message.contains("other than `case`"), "{nested}");
    let existing = workspace.path("dump.bin");
    let overwrite = workspace
        .record(&["extract", "x", "-o", existing.to_str().unwrap()], &[])
        .unwrap_err();
    assert_eq!(overwrite.code, Code::Usage, "{overwrite}");
    assert!(overwrite.message.contains("dump.bin"), "{overwrite}");
    let unknown = workspace.record(&["no-such-command"], &[]).unwrap_err();
    assert_eq!(unknown.code, Code::Usage, "{unknown}");
    assert!(unknown.message.contains("no-such-command"), "{unknown}");
    assert_eq!(
        workspace.case().artifacts.len(),
        1,
        "(case): expected nothing recorded"
    );
}

#[test]
fn record_does_not_store_a_failed_command() {
    let workspace = Workspace::new();
    workspace.init();
    let missing = workspace.path("missing.bin");
    let error = workspace
        .record(&["inspect", missing.to_str().unwrap()], &[])
        .unwrap_err();
    assert_eq!(error.code, Code::Io, "{error}");
    assert_eq!(workspace.case().artifacts.len(), 1);
}

#[test]
fn record_refuses_an_existing_directory_as_an_output() {
    let workspace = Workspace::new();
    workspace.init();
    let dump = workspace.path("dump.bin");
    let directory = workspace.path("made-by-command");
    fs::create_dir(&directory).unwrap();
    let error = workspace
        .record(
            &["inspect", dump.to_str().unwrap()],
            &[directory.to_str().unwrap()],
        )
        .unwrap_err();
    assert_eq!(error.code, Code::Usage, "{error}");
}

#[test]
fn declared_outputs_reads_every_spelling_once() {
    let argv: Vec<String> = [
        "patch",
        "a.bin",
        "-o",
        "x.bin",
        "--output",
        "y.bin",
        "--output=z.bin",
        "-o",
        "x.bin",
    ]
    .map(String::from)
    .to_vec();
    assert_eq!(
        declared_outputs(&argv, &[PathBuf::from("w.bin")]),
        ["x.bin", "y.bin", "z.bin", "w.bin"].map(PathBuf::from)
    );
    assert!(declared_outputs(&["scan".to_string(), "-o".to_string()], &[]).is_empty());
}

#[test]
fn argument_inputs_digest_existing_files_only() {
    let workspace = Workspace::new();
    let dump = workspace.path("dump.bin");
    let flag = format!("--module={}", dump.display());
    let argv = vec![
        "verify".to_string(),
        dump.to_string_lossy().into_owned(),
        flag,
        "no-such-file.bin".to_string(),
        String::new(),
    ];
    let inputs = argument_inputs(&argv);
    assert_eq!(
        inputs.len(),
        1,
        "(inputs): expected one deduplicated file | {inputs:?}"
    );
    assert_eq!(inputs[0].name, "dump.bin");
    assert_eq!(inputs[0].sha256, Digest256::of(&fs::read(&dump).unwrap()));
}

#[test]
fn artifact_file_names_are_safe() {
    assert_eq!(artifact_file_name("m od/../x.bin"), "m-od-..-x.bin");
    assert_eq!(artifact_file_name("..hidden"), "hidden");
    assert_eq!(artifact_file_name("..."), "file");
    assert_eq!(artifact_file_name(&"a".repeat(80)).len(), 48);
}

#[test]
fn hash_file_streams_regular_files_and_refuses_directories() {
    let workspace = Workspace::new();
    let blob = hash_file(&workspace.path("dump.bin")).unwrap();
    let bytes = fs::read(workspace.path("dump.bin")).unwrap();
    assert_eq!(
        (blob.sha256, blob.length),
        (Digest256::of(&bytes), bytes.len() as u64)
    );
    let error = hash_file(workspace.dir.path()).unwrap_err();
    assert_eq!(error.code, Code::Io, "{error}");
    assert!(error.message.contains("expected a regular file"), "{error}");
}

#[test]
fn status_is_clean_on_a_fresh_case() {
    let workspace = Workspace::new();
    workspace.init();
    let reply = workspace.status().unwrap();
    assert_eq!(reply.data["clean"], true);
    assert_eq!(reply.data["findings"][0]["id"], "OPEN1");
    assert!(reply.text.ends_with("clean\n"), "{}", reply.text);
}

#[test]
fn status_reports_a_flipped_artifact_byte_as_changed() {
    let workspace = Workspace::new();
    workspace.init();
    flip_first_byte(&workspace.path("case/artifacts/001-scan.json"));
    let error = workspace.status().unwrap_err();
    assert_eq!(error.code, Code::CaseDrift, "{error}");
    assert!(
        error
            .message
            .contains("artifact artifacts/001-scan.json: changed"),
        "{error}"
    );
    let details = error.details.unwrap();
    assert_eq!(details["artifacts"][0]["state"], "changed");
    assert_eq!(details["clean"], false);
}

#[test]
fn status_reports_a_deleted_artifact_as_missing() {
    let workspace = Workspace::new();
    workspace.init();
    fs::remove_file(workspace.path("case/artifacts/001-scan.json")).unwrap();
    let error = workspace.status().unwrap_err();
    assert_eq!(error.code, Code::CaseDrift);
    assert!(error.message.contains("001-scan.json: missing"), "{error}");
}

#[test]
fn status_reports_a_changed_input() {
    let workspace = Workspace::new();
    workspace.init();
    flip_first_byte(&workspace.path("dump.bin"));
    let error = workspace.status().unwrap_err();
    assert_eq!(error.code, Code::CaseDrift);
    assert!(error.message.contains("input dump.bin: changed"), "{error}");
}

#[test]
fn status_reports_an_unlocated_input_as_missing_with_a_hint() {
    let workspace = Workspace::new();
    workspace.init();
    let elsewhere = workspace.path("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let error = workspace
        .status_with(&[format!("dump.bin={}", elsewhere.join("dump.bin").display())])
        .unwrap_err();
    assert_eq!(error.code, Code::CaseDrift);
    assert!(
        error.message.contains("input dump.bin: missing") && error.message.contains("--input"),
        "{error}"
    );
}

#[test]
fn status_maps_inputs_by_directory_renamed_file_and_explicit_name() {
    let workspace = Workspace::new();
    workspace.init();
    let other = workspace.path("other-machine");
    fs::create_dir(&other).unwrap();
    fs::copy(workspace.path("dump.bin"), other.join("renamed.rom")).unwrap();
    fs::remove_file(workspace.path("dump.bin")).unwrap();
    let by_digest = other.join("renamed.rom").to_string_lossy().into_owned();
    assert!(
        workspace
            .status_with(std::slice::from_ref(&by_digest))
            .is_ok()
    );
    let by_name = format!("dump.bin={by_digest}");
    assert!(workspace.status_with(&[by_name]).is_ok());
    fs::rename(other.join("renamed.rom"), other.join("dump.bin")).unwrap();
    let by_directory = other.to_string_lossy().into_owned();
    assert!(workspace.status_with(&[by_directory]).is_ok());
}

#[test]
fn status_finds_an_input_beside_the_case_directory_without_a_mapping() {
    let workspace = Workspace::new();
    workspace.init();
    assert!(workspace.status_with(&[]).is_ok());
}

#[test]
fn status_rejects_an_input_that_matches_nothing_in_the_case() {
    let workspace = Workspace::new();
    workspace.init();
    let stranger = workspace.path("stranger.bin");
    fs::write(&stranger, b"unrelated").unwrap();
    let error = workspace
        .status_with(&[stranger.to_string_lossy().into_owned()])
        .unwrap_err();
    assert_eq!(error.code, Code::Usage, "{error}");
    assert!(error.message.contains("dump.bin"), "{error}");
    let nothing = workspace.status_with(&["no-such-path".into()]).unwrap_err();
    assert_eq!(nothing.code, Code::Usage, "{nothing}");
}

#[test]
fn status_marks_results_from_another_engine_stale_without_failing() {
    let workspace = Workspace::new();
    workspace.init();
    let mut case = workspace.case();
    case.artifacts[0].bme_version = "0.0.1".into();
    fs::write(workspace.path("case/case.json"), pretty(&case)).unwrap();
    let reply = workspace.status().unwrap();
    let reasons = &reply.data["artifacts"][0]["stale"];
    assert!(
        reasons[0].as_str().unwrap().contains("recorded 0.0.1"),
        "{reasons}"
    );
    assert!(reply.text.contains("stale:"), "{}", reply.text);
}

#[test]
fn status_judges_catalog_staleness_against_the_catalog_it_is_given() {
    let workspace = Workspace::new();
    workspace.init();
    let manifest = workspace.path("catalog/catalog.json");
    let mut doc: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    doc["version"] = json!("1.0.1");
    fs::write(&manifest, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    let reply = case_status(
        &workspace.ctx,
        &CaseStatusArgs {
            dir: workspace.path("case"),
            inputs: vec![workspace.path("dump.bin").to_string_lossy().into_owned()],
            catalogs: workspace.source().catalogs,
            allow_unsigned_local: true,
        },
    )
    .unwrap();
    let reason = reply.data["artifacts"][0]["stale"][0].as_str().unwrap();
    assert!(
        reason.starts_with("catalog local expected 1.0.1"),
        "{reason}"
    );
}

#[test]
fn status_rejects_a_directory_that_is_not_a_case() {
    let workspace = Workspace::new();
    let error = workspace.status().unwrap_err();
    assert_eq!(error.code, Code::Io, "{error}");
    assert!(
        error.message.contains("expected a case directory"),
        "{error}"
    );
    fs::create_dir(workspace.path("case")).unwrap();
    fs::write(
        workspace.path("case/case.json"),
        b"{\"schema\":\"bme.case/9\"}",
    )
    .unwrap();
    let invalid = workspace.status().unwrap_err();
    assert_eq!(invalid.code, Code::FormatInvalid, "{invalid}");
}

#[test]
fn export_produces_a_catalog_that_validates() {
    let workspace = Workspace::new();
    workspace.init();
    let dump = workspace.path("dump.bin");
    workspace
        .record(&["inspect", dump.to_str().unwrap()], &[])
        .unwrap();
    let reply = workspace.export("submission").unwrap();
    assert_eq!(reply.data["evidence"], 2);
    let root = workspace.path("submission");
    let catalog =
        Catalog::load(&crate::sources::DirSource::new(&root).unwrap(), Scope::All).unwrap();
    assert_eq!(catalog.boards.len(), 1);
    assert_eq!(catalog.findings.keys().collect::<Vec<_>>(), ["OPEN1"]);
    assert_eq!(catalog.evidence.len(), 2);
    assert!(
        root.join("provenance")
            .read_dir()
            .unwrap()
            .flatten()
            .any(|e| e
                .file_name()
                .to_string_lossy()
                .ends_with("-firmware-draft.json"))
    );
}

#[test]
fn export_refuses_changed_artifacts_and_existing_outputs() {
    let workspace = Workspace::new();
    workspace.init();
    fs::create_dir(workspace.path("taken")).unwrap();
    let exists = workspace.export("taken").unwrap_err();
    assert_eq!(exists.code, Code::OutputExists, "{exists}");
    flip_first_byte(&workspace.path("case/artifacts/001-scan.json"));
    let changed = workspace.export("submission").unwrap_err();
    assert_eq!(changed.code, Code::CaseDrift, "{changed}");
    assert!(
        changed.message.contains("001-scan.json: changed"),
        "{changed}"
    );
    assert!(!workspace.path("submission").exists());
}

#[test]
fn export_uses_findings_the_investigator_added_to_the_case() {
    let workspace = Workspace::new();
    workspace.init();
    let mut finding = case_findings(&workspace.path("case")).unwrap().remove(0);
    finding.id = "X01".into();
    finding.title = "added by hand".into();
    finding.evidence = vec!["001-scan".into()];
    fs::write(workspace.path("case/findings/X01.json"), pretty(&finding)).unwrap();
    let reply = workspace.export("submission").unwrap();
    assert_eq!(reply.data["findings"], json!(["OPEN1", "X01"]));
    let renamed = workspace.path("case/findings/Y01.json");
    fs::copy(workspace.path("case/findings/X01.json"), &renamed).unwrap();
    let error = workspace.export("second").unwrap_err();
    assert_eq!(error.code, Code::FormatInvalid, "{error}");
    assert!(error.message.contains("Y01.json"), "{error}");
}

#[test]
fn smbios_comes_from_dmi_files_under_the_host_root() {
    let root = tempfile::tempdir().unwrap();
    let dmi = root.path().join("sys/class/dmi/id");
    fs::create_dir_all(&dmi).unwrap();
    fs::write(dmi.join("board_name"), "E5-MR9A PRO\n").unwrap();
    fs::write(dmi.join("bios_date"), "03/22/2023\n").unwrap();
    let host = Host {
        root: root.path().to_path_buf(),
        os: "linux",
        euid: None,
    };
    let smbios = host.smbios();
    assert_eq!(smbios["board_name"], "E5-MR9A PRO");
    assert_eq!(smbios["bios_date"], "03/22/2023");
    assert!(!smbios.contains_key("board_vendor"));
}

#[test]
fn clocks_report_seconds_since_the_epoch() {
    assert_eq!(FixedClock(NOON).unix_seconds(), NOON);
    assert!(
        SystemClock.unix_seconds() > 1_700_000_000,
        "(system clock): expected seconds after 2023-11"
    );
}

#[test]
fn source_arguments_rebuild_the_scan_flags() {
    let args = SourceArgs {
        catalogs: vec!["a".into(), "b".into()],
        allow_unsigned_local: true,
        firmware: Some("fw".into()),
    };
    assert_eq!(
        source_arguments(&args),
        [
            "--catalog",
            "a",
            "--catalog",
            "b",
            "--allow-unsigned-local",
            "--firmware",
            "fw"
        ]
    );
}
