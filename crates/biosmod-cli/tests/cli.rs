//! End-to-end tests of the `bme` binary on synthetic firmware (no vendor code).

mod common;

use common::{Sandbox, s};
use serde_json::Value;
use std::fs;

fn envelope_validator() -> jsonschema::Validator {
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/envelope.schema.json")).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn assert_envelope(doc: &Value) {
    let validator = envelope_validator();
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "(envelope): expected bme/1 shape | errors: {errors:?}\n{doc}"
    );
}

#[test]
fn json_envelope_on_success_failure_and_usage_errors() {
    let sandbox = Sandbox::new();
    let version = sandbox.run(["version", "--json"]);
    assert_eq!(version.code, 0);
    assert_envelope(&version.json());
    assert!(
        version.json()["data"]["codec"]
            .as_str()
            .unwrap()
            .starts_with("liblzma ")
    );

    let missing = sandbox.run(["scan", "/nonexistent/dump.bin", "--json"]);
    assert_eq!((missing.code, missing.error_code().as_str()), (1, "IO"));
    assert_envelope(&missing.json());

    let usage = sandbox.run(["patch", "--json", "--bogus"]);
    assert_eq!(usage.code, 2, "{}", usage.stdout);
    assert_eq!(usage.error_code(), "USAGE");
    assert_envelope(&usage.json());

    let capabilities = sandbox.run(["capabilities", "--json"]).json();
    let codes: Vec<&str> = capabilities["data"]["error_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"PLAN_INPUT_CHANGED") && codes.contains(&"PUBLISH_INCOMPLETE"),
        "{codes:?}"
    );
}

#[test]
fn plan_patch_verify_round_trip() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let untrusted = sandbox.run(["scan", s(&image), "--catalog", s(&catalog), "--json"]);
    assert_eq!(untrusted.error_code(), "SOURCE_UNTRUSTED");

    let scan = sandbox
        .run([
            "scan",
            s(&image),
            "--catalog",
            s(&catalog),
            "--allow-unsigned-local",
            "--json",
        ])
        .json();
    let report = &scan["data"]["sources"][0]["report"];
    assert_eq!(report["firmware"], "synthetic-fw");
    let pa = report["patches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "PA")
        .unwrap();
    assert_eq!(
        (pa["state"].as_str(), pa["plannable"].as_bool()),
        (Some("present"), Some(true))
    );

    let plan = sandbox.path("plan.json");
    let made = sandbox.run([
        "plan",
        s(&image),
        "--select",
        "PA",
        "TB",
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "-o",
        s(&plan),
        "--json",
    ]);
    assert_eq!(made.code, 0, "{}", made.stdout);
    let out = sandbox.path("out.bin");
    let patched = sandbox.run([
        "patch",
        s(&image),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!(patched.code, 0, "{}", patched.stdout);
    let expected = made.json()["data"]["plan"]["output"]["sha256"].clone();
    assert_eq!(
        patched.json()["data"]["manifest"]["plan"]["output"]["sha256"],
        expected
    );
    assert_eq!(
        Value::String(biosmod_core::util::sha256_hex(&fs::read(&out).unwrap())),
        expected
    );

    let verified = sandbox
        .run(["verify", s(&image), s(&out), "--plan", s(&plan), "--json"])
        .json();
    assert_eq!(verified["data"]["complete"], true, "{verified}");

    // The output and manifest are never replaced.
    let again = sandbox.run([
        "patch",
        s(&image),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!(again.error_code(), "OUTPUT_EXISTS");
    let into_input = sandbox.run([
        "patch",
        s(&image),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&image),
        "--json",
    ]);
    assert_eq!(into_input.error_code(), "OUTPUT_EXISTS");
}

#[test]
fn unavailable_pinned_catalog_is_incomplete_verification_not_success() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox.path("review.json");
    let output = sandbox.path("output.bin");
    let made = sandbox.run([
        "plan",
        s(&image),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--select",
        "PA",
        "-o",
        s(&plan),
        "--json",
    ]);
    assert_eq!(made.code, 0, "{}", made.stdout);
    let built = sandbox.run([
        "patch",
        s(&image),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&output),
        "--json",
    ]);
    assert_eq!(built.code, 0, "{}", built.stdout);
    fs::rename(&catalog, sandbox.path("unavailable-catalog")).unwrap();
    let verified = sandbox.run([
        "verify",
        s(&image),
        s(&output),
        "--plan",
        s(&plan),
        "--json",
        "--offline",
    ]);
    assert_eq!(
        verified.code, 1,
        "verification with unavailable catalog: expected exit 1, received {}: {}",
        verified.code, verified.stdout
    );
    assert_eq!(verified.error_code(), "VERIFICATION_INCOMPLETE");
    let envelope = verified.json();
    assert_envelope(&envelope);
    let details = &envelope["error"]["details"];
    assert_eq!(details["complete"], false);
    assert_eq!(details["checks"].as_array().unwrap().len(), 5);
    assert_eq!(
        details["skipped"][0]["check"],
        "patch-states and reproduction"
    );
    assert!(details["notice"].as_str().unwrap().contains("Offline"));
    assert!(
        output.exists(),
        "incomplete verification must preserve the output"
    );
}

// Linux permits raw-byte filenames; the macOS CI filesystem rejects them.
#[cfg(target_os = "linux")]
#[test]
fn json_publication_supports_non_utf8_output_paths_without_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox.path("review.json");
    let output = sandbox
        .dir
        .path()
        .join(std::ffi::OsString::from_vec(b"patched-\xff.bin".to_vec()));
    let made = sandbox.run([
        "plan",
        s(&image),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--select",
        "PA",
        "-o",
        s(&plan),
        "--json",
    ]);
    assert_eq!(made.code, 0, "{}", made.stdout);
    let built = sandbox.run(vec![
        std::ffi::OsString::from("patch"),
        image.clone().into_os_string(),
        "--plan".into(),
        plan.clone().into_os_string(),
        "--allow-unsigned-local".into(),
        "-o".into(),
        output.clone().into_os_string(),
        "--json".into(),
    ]);
    assert_eq!(
        built.code, 0,
        "JSON publication: expected exit 0 after publishing to an OS path | stdout {} stderr {}",
        built.stdout, built.stderr
    );
    assert!(output.is_file());
    assert_envelope(&built.json());
    let verified = sandbox.run(vec![
        std::ffi::OsString::from("verify"),
        image.into_os_string(),
        output.into_os_string(),
        "--plan".into(),
        plan.into_os_string(),
        "--json".into(),
    ]);
    assert_eq!(verified.code, 0, "{}", verified.stdout);
    assert_eq!(verified.json()["data"]["complete"], true);
}

#[cfg(unix)]
#[test]
fn firmware_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let sandbox = Sandbox::new();
    let fifo = sandbox.path("firmware.pipe");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a valid, terminated path in this test's private directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bme"))
        .args(["inspect", s(&fifo), "--json"])
        .env("BME_CONFIG_HOME", sandbox.path("config"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let exited = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    assert!(
        exited,
        "firmware FIFO: expected immediate regular-file refusal, received a blocked read"
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["error"]["code"], "IO");
    assert!(
        document["error"]["message"]
            .as_str()
            .unwrap()
            .contains("regular file")
    );
}

#[test]
fn plans_are_revalidated_not_trusted() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox.path("plan.json");
    let args = ["--catalog", s(&catalog), "--allow-unsigned-local"];
    let made = sandbox.run(
        [
            &["plan", s(&image), "--select", "PA", "-o", s(&plan)][..],
            &args[..],
        ]
        .concat(),
    );
    assert_eq!(made.code, 0, "{}", made.stderr);
    let original: Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
    let patch_with = |doc: &Value, name: &str| {
        let edited = sandbox.path(name);
        fs::write(&edited, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
        sandbox.run([
            "patch",
            s(&image),
            "--plan",
            s(&edited),
            "--allow-unsigned-local",
            "-o",
            s(&sandbox.path(&format!("{name}.bin"))),
            "--json",
        ])
    };

    let mut forged = original.clone();
    forged["output"]["sha256"] = Value::String("0".repeat(64));
    assert_eq!(
        patch_with(&forged, "forged.json").error_code(),
        "OUTPUT_VERIFICATION_FAILED"
    );

    let mut widened = original.clone();
    widened["allowlist"] = serde_json::json!([{"start": 0, "end": 1 << 20}]);
    assert_eq!(
        patch_with(&widened, "widened.json").error_code(),
        "OUTPUT_VERIFICATION_FAILED"
    );

    let mut requested = original.clone();
    requested["requested"] = serde_json::json!(["local::PA@9.9.9"]);
    assert_eq!(
        patch_with(&requested, "requested.json").error_code(),
        "PLAN_INVALID"
    );

    let mut boards = original.clone();
    boards["boards"] = serde_json::json!(["some-other-board"]);
    assert_eq!(
        patch_with(&boards, "boards.json").error_code(),
        "OUTPUT_VERIFICATION_FAILED"
    );

    let mut unknown = original.clone();
    unknown["skip_checks"] = Value::Bool(true);
    assert_eq!(
        patch_with(&unknown, "unknown.json").error_code(),
        "PLAN_INVALID"
    );

    // A changed input is detected before anything is built.
    let other = sandbox.path("other.bin");
    let mut bytes = fs::read(&image).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&other, bytes).unwrap();
    let run = sandbox.run([
        "patch",
        s(&other),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&sandbox.path("o.bin")),
        "--json",
    ]);
    assert_eq!(run.error_code(), "PLAN_INPUT_CHANGED");

    // So is a catalog edited after planning.
    let record = catalog.join("patches/PA.json");
    let mut text = fs::read_to_string(&record).unwrap();
    text.push('\n');
    fs::write(&record, text).unwrap();
    let run = sandbox.run([
        "patch",
        s(&image),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&sandbox.path("p.bin")),
        "--json",
    ]);
    assert_eq!(run.error_code(), "PLAN_INPUT_CHANGED", "{}", run.stdout);
    assert!(!sandbox.path("p.bin").exists() && !sandbox.path("p.bin.manifest.json").exists());
}

#[test]
fn selection_rules_need_explicit_flags() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let try_select = |ids: &[&str], extra: &[&str]| {
        let out = sandbox.path(&format!("{}.bin", ids.join("-")));
        let mut args = vec![
            "patch",
            s(&image),
            "--catalog",
            s(&catalog),
            "--allow-unsigned-local",
            "-o",
            s(&out),
            "--json",
            "--select",
        ];
        args.extend_from_slice(ids);
        args.extend_from_slice(extra);
        sandbox.run(args)
    };
    assert_eq!(try_select(&["HD"], &[]).error_code(), "SELECTION_INVALID");
    assert_eq!(
        try_select(&["LD"], &["--allow-hold"]).error_code(),
        "SELECTION_INVALID"
    );
    assert_eq!(try_select(&["FR"], &[]).error_code(), "ASSERTION_REQUIRED");
    assert_eq!(
        try_select(&["FR"], &["--assert", "synthetic-superio"]).code,
        0
    );
    assert_eq!(
        try_select(&["PB", "CX"], &[]).error_code(),
        "PATCH_CONFLICT"
    );
    assert_eq!(try_select(&["NOPE"], &[]).error_code(), "TARGET_NOT_FOUND");
    assert_eq!(try_select(&["PA", "LD"], &["--allow-diagnostic"]).code, 0);
}

#[test]
fn extract_replace_and_inspect() {
    let sandbox = Sandbox::new();
    let (image, _) = sandbox.synthetic();
    let inspect = sandbox
        .run(["inspect", s(&image), "--files", "--json"])
        .json();
    assert!(!inspect["data"]["volumes"].as_array().unwrap().is_empty());
    let module = sandbox.path("peim.pe");
    let guid = biosmod_core::synthetic::PEIM_GUID.to_string();
    let extracted = sandbox.run([
        "extract",
        s(&image),
        "--guid",
        &guid,
        "-o",
        s(&module),
        "--json",
    ]);
    assert_eq!(extracted.code, 0, "{}", extracted.stdout);
    let mut bytes = fs::read(&module).unwrap();
    bytes[0x40] ^= 0x01;
    let edited = sandbox.path("edited.pe");
    fs::write(&edited, &bytes).unwrap();
    let out = sandbox.path("replaced.bin");
    let replaced = sandbox.run([
        "replace",
        s(&image),
        "--guid",
        &guid,
        "--input",
        s(&edited),
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!(replaced.code, 0, "{}", replaced.stdout);
    assert_eq!(replaced.json()["data"]["module_bytes_changed"], 1);
    let back = sandbox.path("back.pe");
    sandbox.run(["extract", s(&out), "--guid", &guid, "-o", s(&back)]);
    assert_eq!(fs::read(&back).unwrap(), bytes);
}

#[test]
fn local_sources_and_breadcrumbs() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let added = sandbox.run([
        "catalog",
        "add",
        "lab",
        s(&catalog),
        "--allow-unsigned-local",
        "--json",
    ]);
    assert_eq!(added.code, 0, "{}", added.stdout);
    let listed = sandbox.run(["catalog", "list", "--json"]).json();
    assert_eq!(listed["data"]["sources"].as_array().unwrap().len(), 2);
    let scan = sandbox
        .run(["scan", s(&image), "--catalog", "lab", "--json"])
        .json();
    assert_eq!(scan["data"]["sources"][0]["trust"], "unsigned-local");
    let qualified = sandbox.run([
        "plan",
        s(&image),
        "--select",
        "lab::PA@1.0.0",
        "-o",
        s(&sandbox.path("q.json")),
        "--json",
    ]);
    assert_eq!(qualified.code, 0, "{}", qualified.stdout);
    let wrong = sandbox.run([
        "plan",
        s(&image),
        "--select",
        "lab::PA@9.9.9",
        "-o",
        s(&sandbox.path("w.json")),
        "--json",
    ]);
    assert_eq!(wrong.error_code(), "TARGET_NOT_FOUND");

    let decoded = sandbox.run([
        "diag",
        "breadcrumbs",
        "decode",
        "a1",
        "00",
        "00",
        "00",
        "bf",
        "ff",
        "ff",
        "ff",
        "ff",
        "00",
    ]);
    assert_eq!(
        decoded.stdout,
        "stored MRC pass: BF/00 location 0000, pass ended: true\nfailed MRC passes since arming: 0\n"
    );
}

#[test]
fn committed_schemas_match_the_types_and_the_official_catalog() {
    let sandbox = Sandbox::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut stale = Vec::new();
    for (name, _) in biosmod_core::schema::NAMES {
        let generated = biosmod_core::schema::generate(name).unwrap();
        let file = root.join(format!("schemas/{name}.schema.json"));
        let text = serde_json::to_string_pretty(&generated).unwrap() + "\n";
        if std::env::var_os("BME_UPDATE_SCHEMAS").is_some() {
            fs::write(&file, &text).unwrap();
        }
        if fs::read_to_string(&file).ok().as_deref() != Some(text.as_str()) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "(schemas/): expected generated output | stale: {stale:?}; run BME_UPDATE_SCHEMAS=1 cargo test"
    );

    let catalog = root.join("catalog");
    let index = sandbox.run(["catalog", "index", s(&catalog), "--check", "--json"]);
    assert_eq!(index.code, 0, "{}", index.stdout);
    for (dir, name) in [
        ("boards", "board"),
        ("patches", "patch"),
        ("evidence", "evidence"),
    ] {
        let validator =
            jsonschema::validator_for(&biosmod_core::schema::generate(name).unwrap()).unwrap();
        for entry in fs::read_dir(catalog.join(dir)).unwrap().flatten() {
            let doc: Value = serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
            let errors: Vec<String> = validator
                .iter_errors(&doc)
                .map(|e| format!("{e} at {}", e.instance_path()))
                .collect();
            assert!(
                errors.is_empty(),
                "({}): expected {name} schema | errors: {errors:?}",
                entry.path().display()
            );
        }
    }
    let shown = sandbox.run(["catalog", "show", "--json"]).json();
    assert_eq!(shown["data"]["sources"][0]["manifest"]["id"], "official");
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_paths_in_json_replies() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox
        .dir
        .path()
        .join(OsString::from_vec(b"plan-\xff.json".to_vec()));
    let extracted = sandbox
        .dir
        .path()
        .join(OsString::from_vec(b"module-\xff.pe".to_vec()));
    let synthetic = sandbox
        .dir
        .path()
        .join(OsString::from_vec(b"fixture-\xff".to_vec()));
    let guid = biosmod_core::synthetic::PEIM_GUID.to_string();
    let cases: Vec<(Vec<OsString>, &str, &std::path::Path)> = vec![
        (
            vec![
                "plan".into(),
                image.clone().into_os_string(),
                "--catalog".into(),
                catalog.into_os_string(),
                "--allow-unsigned-local".into(),
                "--select".into(),
                "PA".into(),
                "-o".into(),
                plan.clone().into_os_string(),
                "--json".into(),
            ],
            "plan_file",
            &plan,
        ),
        (
            vec![
                "extract".into(),
                image.into_os_string(),
                "--guid".into(),
                guid.into(),
                "-o".into(),
                extracted.clone().into_os_string(),
                "--json".into(),
            ],
            "output",
            &extracted,
        ),
        (
            vec![
                "dev".into(),
                "synthetic".into(),
                "-o".into(),
                synthetic.clone().into_os_string(),
                "--json".into(),
            ],
            "image",
            &synthetic,
        ),
    ];
    let mut failures = Vec::new();
    for (args, field, path) in cases {
        let run = sandbox.run(args);
        if run.code != 0 {
            failures.push(format!(
                "{field} {}: expected exit 0 | received {} stderr {}",
                path.display(),
                run.code,
                run.stderr
            ));
            continue;
        }
        let value = run.json();
        let expected = if field == "image" {
            path.join("synthetic.bin").to_string_lossy().into_owned()
        } else {
            path.to_string_lossy().into_owned()
        };
        assert_eq!(
            value["data"][field], expected,
            "({field}): expected display path"
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(target_os = "linux")]
#[test]
fn tools_paths_and_doctor_accept_non_utf8_directories() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let sandbox = Sandbox::new();
    let path = sandbox
        .dir
        .path()
        .join(OsString::from_vec(b"data-\xff".to_vec()));
    for command in ["paths", "doctor"] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_bme"))
            .args(["tools", command, "--json"])
            .env("BME_CONFIG_HOME", sandbox.path("config"))
            .env("BME_CACHE_HOME", sandbox.path("cache"))
            .env("BME_DATA_HOME", &path)
            .env_remove("GHIDRA_INSTALL_DIR")
            .output()
            .unwrap();
        let document: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
            panic!(
                "tools {command}: expected JSON | stderr {}",
                String::from_utf8_lossy(&result.stderr)
            )
        });
        let home = if command == "paths" {
            &document["data"]["ghidra_home"]
        } else {
            &document["error"]["details"]["ghidra_home"]
        };
        assert!(
            home["path"]
                .as_str()
                .unwrap()
                .starts_with(path.to_string_lossy().as_ref())
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn catalog_import_reports_non_utf8_output_path() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let sandbox = Sandbox::new();
    let input = sandbox.path("records");
    fs::create_dir(&input).unwrap();
    let record = serde_json::json!({"schema": 1, "id": "valid", "title": "test", "findings": [], "finding_confidence": {}, "local_fix_confidence": "", "physical_fix_confidence": "", "hardware_tested": false, "tier": 1, "supersedes": [], "conflicts": [], "limits": "", "boards": {}});
    fs::write(input.join("record.json"), record.to_string()).unwrap();
    let output = sandbox
        .dir
        .path()
        .join(OsString::from_vec(b"output-\xff".to_vec()));
    let run = sandbox.run(vec![
        "catalog".into(),
        "import-x99fix".into(),
        input.into_os_string(),
        "--map".into(),
        "board=firmware".into(),
        "--commit".into(),
        "a".repeat(40).into(),
        "-o".into(),
        output.clone().into_os_string(),
        "--json".into(),
    ]);
    assert_eq!(
        run.code,
        0,
        "catalog import {}: expected exit 0 | stdout {} stderr {}",
        output.display(),
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.json()["data"]["output"],
        output.to_string_lossy().as_ref()
    );
    assert!(output.join("valid.json").exists());
}
