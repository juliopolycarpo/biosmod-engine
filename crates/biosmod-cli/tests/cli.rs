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
    let fingerprint = version.json()["data"]["build_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        fingerprint.len(),
        64,
        "build fingerprint: expected 64 lowercase hexadecimal digits | received {fingerprint:?}"
    );
    assert!(
        fingerprint
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "build fingerprint: expected lowercase hexadecimal | received {fingerprint:?}"
    );
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
    let checks = verified["data"]["checks"].as_array().unwrap();
    let states = checks
        .iter()
        .find(|check| check["check"] == "patch-states")
        .unwrap();
    assert_eq!(
        states["patches"],
        serde_json::json!([
            {"id": "PA", "state": "fixed"}, {"id": "TB", "state": "fixed"}
        ])
    );
    let capabilities = sandbox.run(["capabilities", "--json"]).json();
    let required = capabilities["data"]["verification_required_checks"]
        .as_array()
        .unwrap();
    let actual = verified["data"]["checks"].as_array().unwrap();
    assert_eq!(
        required.len(),
        actual.len(),
        "required checks: expected {required:?} | received {actual:?}"
    );
    for name in required {
        let count = actual
            .iter()
            .filter(|check| check["check"] == *name && check["ok"] == true)
            .count();
        assert_eq!(
            count, 1,
            "verification check {name}: expected one passing result | received {count}"
        );
    }

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

#[test]
fn verification_reports_selected_and_carried_patch_states() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let first_plan = sandbox.path("first-plan.json");
    let first_output = sandbox.path("first-output.bin");
    let second_plan = sandbox.path("second-plan.json");
    let second_output = sandbox.path("second-output.bin");
    for (input, selected, plan, output) in [
        (&image, "PA", &first_plan, &first_output),
        (&first_output, "PB", &second_plan, &second_output),
    ] {
        let made = sandbox.run([
            "plan",
            s(input),
            "--catalog",
            s(&catalog),
            "--allow-unsigned-local",
            "--select",
            selected,
            "-o",
            s(plan),
            "--json",
        ]);
        assert_eq!(
            made.code, 0,
            "plan {selected}: {} {}",
            made.stdout, made.stderr
        );
        let built = sandbox.run([
            "patch",
            s(input),
            "--plan",
            s(plan),
            "--allow-unsigned-local",
            "-o",
            s(output),
            "--json",
        ]);
        assert_eq!(
            built.code, 0,
            "patch {selected}: {} {}",
            built.stdout, built.stderr
        );
    }
    let verified = sandbox.run([
        "verify",
        s(&first_output),
        s(&second_output),
        "--plan",
        s(&second_plan),
        "--json",
    ]);
    assert_eq!(
        verified.code, 0,
        "verify: {} {}",
        verified.stdout, verified.stderr
    );
    let document = verified.json();
    let states = document["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["check"] == "patch-states")
        .unwrap();
    assert_eq!(
        states["patches"],
        serde_json::json!([
            {"id": "PB", "state": "fixed"}, {"id": "PA", "state": "fixed"}
        ])
    );
}

#[test]
fn changed_or_missing_engine_build_fingerprint_requires_a_new_plan() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox.path("build-id-plan.json");
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
    assert_eq!(made.code, 0, "plan: {} {}", made.stdout, made.stderr);
    let original: Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
    let version = sandbox.run(["version", "--json"]).json();
    assert_eq!(
        original["engine"]["build_fingerprint"], version["data"]["build_fingerprint"],
        "plan and version must report the same build fingerprint"
    );
    let mut mismatched = original.clone();
    mismatched["engine"]["build_fingerprint"] = Value::String("0".repeat(64));
    let mut legacy = original.clone();
    legacy["engine"]
        .as_object_mut()
        .unwrap()
        .remove("build_fingerprint");
    for (name, document) in [("mismatch", mismatched), ("legacy", legacy)] {
        let path = sandbox.path(&format!("{name}.json"));
        let output = sandbox.path(&format!("{name}.bin"));
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let run = sandbox.run([
            "patch",
            s(&image),
            "--plan",
            s(&path),
            "--allow-unsigned-local",
            "-o",
            s(&output),
            "--json",
        ]);
        assert_eq!(run.error_code(), "PLAN_INVALID", "{name}: {}", run.stdout);
        let result = run.json();
        let message = result["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("build fingerprint") && message.contains("regenerate the plan"),
            "{name}: expected build fingerprint regeneration diagnostic | received {message}"
        );
        if name == "mismatch" {
            assert!(message.contains(&"0".repeat(64)), "{message}");
            assert!(
                message.contains(original["engine"]["build_fingerprint"].as_str().unwrap()),
                "{message}"
            );
        }
        assert!(!output.exists());
    }
    for field in ["version", "codec"] {
        let mut changed = original.clone();
        changed["engine"][field] = Value::String("unexpected-engine-value".into());
        let path = sandbox.path(&format!("{field}.json"));
        let output = sandbox.path(&format!("{field}.bin"));
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        let run = sandbox.run([
            "patch",
            s(&image),
            "--plan",
            s(&path),
            "--allow-unsigned-local",
            "-o",
            s(&output),
            "--json",
        ]);
        assert_eq!(run.error_code(), "PLAN_INVALID");
        let doc = run.json();
        let message = doc["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("unexpected-engine-value") && message.contains("regenerate the plan"),
            "{field}: {message}"
        );
        assert!(!output.exists());
    }
}

#[test]
fn verification_refuses_manifest_from_another_engine_build() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let plan = sandbox.path("identity-plan.json");
    let output = sandbox.path("identity-output.bin");
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
    assert_eq!(made.code, 0, "{} {}", made.stdout, made.stderr);
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
    assert_eq!(built.code, 0, "{} {}", built.stdout, built.stderr);
    let manifest_path = sandbox.path("identity-output.bin.manifest.json");
    let original: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    for missing in [false, true] {
        let mut manifest = original.clone();
        if missing {
            manifest["plan"]["engine"]
                .as_object_mut()
                .unwrap()
                .remove("build_fingerprint");
        } else {
            manifest["plan"]["engine"]["build_fingerprint"] = Value::String("f".repeat(64));
        }
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let run = sandbox.run(["verify", s(&image), s(&output), "--json"]);
        assert_eq!(run.error_code(), "PLAN_INVALID", "{}", run.stdout);
        let document = run.json();
        let message = document["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("build fingerprint") && message.contains("regenerate the plan"),
            "{message}"
        );
        assert!(
            message.contains(if missing { "<missing>" } else { "ffffffff" }),
            "{message}"
        );
    }
}

#[test]
fn verify_independently_checks_two_tables_in_one_file() {
    use biosmod_core::catalog::{Patch, Variant};
    use biosmod_core::firmware::{Image, rebuild};
    use biosmod_core::synthetic;
    use biosmod_core::util::Digest256;
    let sandbox = Sandbox::new();
    let (image_path, catalog) = sandbox.synthetic();
    let image = Image::parse(fs::read(&image_path).unwrap()).unwrap();
    let leaf = image.leaves[&synthetic::TABLE_GUID][0].clone();
    let make_table = |seed| {
        let mut table = synthetic::acpi(&synthetic::module(seed, 28));
        table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
        table
    };
    let first = make_table(12);
    let second = make_table(13);
    let mut body = first.clone();
    body.extend_from_slice(&[0x5a; 4]);
    body.extend_from_slice(&second);
    let file = rebuild::rebuilt_file(&image, &leaf, &body).unwrap();
    let mut bytes = image.bytes.clone();
    rebuild::write_in_place(
        &mut bytes,
        &image.volumes[leaf.volume],
        &[(leaf.file, file)],
    );
    fs::write(&image_path, bytes).unwrap();
    let record = catalog.join("patches/TB.json");
    let mut patch: Patch = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    let Variant::Applicable(variant) = patch.variants.get_mut(synthetic::FIRMWARE).unwrap() else {
        panic!("applicable variant")
    };
    let template = variant.components[0].clone();
    let component = |table: &[u8], offset, replacement: u8| {
        let mut item = template.clone();
        item.name = format!("DSDT-{offset}");
        item.table_offset = offset;
        let checksum = table[9].wrapping_sub(replacement.wrapping_sub(table[40]));
        item.hunks = vec![
            synthetic::hunk(table, 9, &[checksum]),
            synthetic::hunk(table, 40, &[replacement]),
        ];
        let result = biosmod_core::patch::apply(table, &item.hunks).unwrap();
        item.source_sha256 = Digest256::of(table);
        item.source_size = table.len() as u64;
        item.result_sha256 = Digest256::of(&result);
        item.result_size = result.len() as u64;
        item
    };
    variant.components = vec![component(&first, 0, 0x91), component(&second, 68, 0x92)];
    fs::write(&record, biosmod_core::json::pretty(&patch)).unwrap();
    let indexed = sandbox.run(["catalog", "index", s(&catalog), "--json"]);
    assert_eq!(
        indexed.code, 0,
        "index: {} {}",
        indexed.stdout, indexed.stderr
    );
    let plan = sandbox.path("tables-plan.json");
    let output = sandbox.path("tables-output.bin");
    let made = sandbox.run([
        "plan",
        s(&image_path),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "--select",
        "TB",
        "-o",
        s(&plan),
        "--json",
    ]);
    assert_eq!(made.code, 0, "plan: {} {}", made.stdout, made.stderr);
    assert_eq!(
        made.json()["data"]["plan"]["components"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let patched = sandbox.run([
        "patch",
        s(&image_path),
        "--plan",
        s(&plan),
        "--allow-unsigned-local",
        "-o",
        s(&output),
        "--json",
    ]);
    assert_eq!(
        patched.code, 0,
        "patch: {} {}",
        patched.stdout, patched.stderr
    );
    let verified = sandbox.run([
        "verify",
        s(&image_path),
        s(&output),
        "--plan",
        s(&plan),
        "--json",
    ]);
    assert_eq!(
        verified.code, 0,
        "verify: {} {}",
        verified.stdout, verified.stderr
    );
    let doc = verified.json();
    assert_eq!(doc["data"]["complete"], true);
    let checks = doc["data"]["checks"].as_array().unwrap();
    assert!(
        checks
            .iter()
            .any(|check| check["check"] == "patch-states" && check["ok"] == true)
    );
    assert!(
        checks
            .iter()
            .any(|check| check["check"] == "reproduced-from-catalog" && check["ok"] == true)
    );
}

#[test]
fn ifr_decodes_a_bare_module_as_text_and_json() {
    use biosmod_core::synthetic::{SETUP_VARSTORE_GUID, ifr_setup_module};
    let sandbox = Sandbox::new();
    let module = sandbox.path("setup.pe");
    fs::write(&module, ifr_setup_module()).unwrap();

    let text = sandbox.run(["ifr", s(&module)]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    for expected in [
        "FormSet 7B59104A-C00D-4158-87FF-F04D6396A915 \"Setup\"",
        "Form 0x2710 \"Main\" (3 questions)",
        "0x0019  one_of",
        "\"ACPI Sleep State\"",
        "Setup+0xa/2",
        "0x0..0x2",
        "2=\"S3 (Suspend to RAM)\" (default, mfg)",
        "suppress: ideqval 0x9 == 1",
        "grayout: ideqval 0x9 == 1",
    ] {
        assert!(
            text.stdout.contains(expected),
            "(ifr text): expected {expected:?} in\n{}",
            text.stdout
        );
    }

    let json = sandbox.run(["ifr", s(&module), "--json"]);
    let doc = json.json();
    assert_envelope(&doc);
    assert_eq!(doc["command"], "ifr");
    assert_eq!(doc["data"]["source"], "module");
    let list = &doc["data"]["modules"][0]["package_lists"][0];
    assert_eq!(list["language"], "en-US");
    let sleep = &list["form_sets"][0]["forms"][0]["statements"][1];
    assert_eq!(sleep["prompt"], "ACPI Sleep State");
    assert_eq!(sleep["varstore"]["guid"], SETUP_VARSTORE_GUID.to_string());
    assert_eq!(sleep["var_offset"], 0x0A);
    assert_eq!(sleep["width"], 2);
    assert_eq!(sleep["conditions"][0]["expression"], "ideqval 0x9 == 1");

    let portuguese = sandbox
        .run(["ifr", s(&module), "--language", "pt-BR", "--json"])
        .json();
    assert_eq!(
        portuguese["data"]["modules"][0]["package_lists"][0]["form_sets"][0]["title"],
        "SETUP"
    );
}

#[test]
fn ifr_scans_an_image_and_honors_guid() {
    use biosmod_core::synthetic::{SETUP_GUID, ifr_setup_image};
    let sandbox = Sandbox::new();
    let rom = sandbox.path("rom.bin");
    fs::write(&rom, ifr_setup_image()).unwrap();

    let all = sandbox.run(["ifr", s(&rom), "--json"]).json();
    assert_eq!(all["data"]["source"], "image");
    assert_eq!(all["data"]["modules"][0]["guid"], SETUP_GUID.to_string());
    let one = sandbox
        .run(["ifr", s(&rom), "--guid", &SETUP_GUID.to_string(), "--json"])
        .json();
    assert_eq!(one["data"]["modules"], all["data"]["modules"]);

    let absent = sandbox.run([
        "ifr",
        s(&rom),
        "--guid",
        "00000000-0000-0000-0000-00000000000A",
        "--json",
    ]);
    assert_eq!(absent.error_code(), "TARGET_NOT_FOUND");
}

#[test]
fn ifr_reports_inputs_without_forms_and_misused_guid() {
    use biosmod_core::synthetic::SETUP_GUID;
    let sandbox = Sandbox::new();
    let (image, _) = sandbox.synthetic();
    let none = sandbox.run(["ifr", s(&image), "--json"]);
    assert_eq!(none.error_code(), "TARGET_NOT_FOUND");

    let junk = sandbox.path("junk.bin");
    fs::write(&junk, vec![0x5A; 512]).unwrap();
    assert_eq!(
        sandbox.run(["ifr", s(&junk), "--json"]).error_code(),
        "TARGET_NOT_FOUND"
    );
    let guided = sandbox.run(["ifr", s(&junk), "--guid", &SETUP_GUID.to_string(), "--json"]);
    assert_eq!(guided.error_code(), "USAGE");
    assert!(
        guided.stdout.contains("--guid needs a firmware image"),
        "{}",
        guided.stdout
    );
}

#[test]
fn ifr_names_offset_and_opcode_of_malformed_forms() {
    use biosmod_core::synthetic::*;
    let sandbox = Sandbox::new();
    // FormSet scope closed twice: the second End at 0x31 has nothing to close.
    let mut payload = SETUP_FORMSET_GUID.0.to_vec();
    payload.extend_from_slice(&[0, 0, 0, 0, 0]);
    let body = [ifr_op(0x0E, true, &payload), ifr_end(), ifr_end()].concat();
    let list = hii_package_list(SETUP_GUID, &[hii_package(0x02, &body)]);
    let module = sandbox.path("broken.pe");
    fs::write(&module, list).unwrap();
    let run = sandbox.run(["ifr", s(&module), "--json"]);
    assert_eq!(run.error_code(), "FORMAT_INVALID");
    assert!(
        run.stdout.contains("opcode End (0x29) at 0x31"),
        "(ifr error): expected the opcode and offset | received {}",
        run.stdout
    );
}

#[test]
fn capabilities_list_the_ifr_command() {
    let doc = Sandbox::new().run(["capabilities", "--json"]).json();
    let names: Vec<&str> = doc["data"]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"ifr"),
        "(capabilities commands): expected ifr in {names:?}"
    );
}

/// Image holding the good Setup module and a PE with a malformed form package.
fn ifr_image_with_broken_module(include_setup: bool) -> Vec<u8> {
    use biosmod_core::synthetic::*;
    let mut payload = SETUP_FORMSET_GUID.0.to_vec();
    payload.extend_from_slice(&[0, 0, 0, 0, 0]);
    let body = [ifr_op(0x0E, true, &payload), ifr_end(), ifr_end()].concat();
    let broken = hii_package_list(SETUP_GUID, &[hii_package(0x02, &body)]);
    let mut files = vec![ffs(
        biosmod_core::util::Guid::constant("00000000-0000-0000-0000-0000000000B1"),
        0x07,
        &section(0x10, &broken),
        0,
    )];
    if include_setup {
        files.insert(
            0,
            ffs(SETUP_GUID, 0x07, &section(0x10, &ifr_setup_module()), 0),
        );
    }
    let mut image = vec![0xFF; 0x1000];
    image.extend(volume(&files, 0x4000));
    image
}

#[test]
fn ifr_image_reports_a_broken_module_without_dropping_the_others() {
    let sandbox = Sandbox::new();
    let rom = sandbox.path("mixed.bin");
    fs::write(&rom, ifr_image_with_broken_module(true)).unwrap();

    let text = sandbox.run(["ifr", s(&rom)]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(
        text.stdout.contains("\"ACPI Sleep State\""),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout
            .contains("warning: file 00000000-0000-0000-0000-0000000000B1: "),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("opcode End (0x29) at 0x31"),
        "{}",
        text.stdout
    );

    let doc = sandbox.run(["ifr", s(&rom), "--json"]).json();
    assert_envelope(&doc);
    assert_eq!(doc["data"]["modules"].as_array().unwrap().len(), 1);
    let diagnostic = &doc["data"]["diagnostics"][0];
    assert_eq!(diagnostic["guid"], "00000000-0000-0000-0000-0000000000B1");
    assert_eq!(diagnostic["code"], "FORMAT_INVALID");

    let targeted = sandbox.run([
        "ifr",
        s(&rom),
        "--guid",
        "00000000-0000-0000-0000-0000000000B1",
        "--json",
    ]);
    assert_eq!(targeted.error_code(), "FORMAT_INVALID");
}

#[test]
fn ifr_image_where_every_module_is_broken_fails_with_the_diagnostics() {
    let sandbox = Sandbox::new();
    let rom = sandbox.path("broken.bin");
    fs::write(&rom, ifr_image_with_broken_module(false)).unwrap();
    let run = sandbox.run(["ifr", s(&rom), "--json"]);
    assert_eq!(run.error_code(), "FORMAT_INVALID");
    assert!(
        run.stdout.contains("no module decoded") && run.stdout.contains("0000B1"),
        "{}",
        run.stdout
    );
}

/// An image with the synthetic Setup module and the sample NVAR store; the NVAR store starts
/// at 0x5060 (see `nvram::tests`).
fn nvram_sandbox_image(sandbox: &Sandbox, stores: &[Vec<u8>]) -> std::path::PathBuf {
    use biosmod_core::synthetic::nvram_image;
    let rom = sandbox.path("nvram.bin");
    fs::write(&rom, nvram_image(stores)).unwrap();
    rom
}

fn variable_rows(doc: &serde_json::Value) -> Vec<(String, String, String)> {
    doc["data"]["variables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["store"].as_str().unwrap().to_owned(),
                v["state"].as_str().unwrap().to_owned(),
                v["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn nvram_lists_active_records_and_history_on_request() {
    use biosmod_core::synthetic::nvar_sample_store;
    let sandbox = Sandbox::new();
    let rom = nvram_sandbox_image(&sandbox, &[nvar_sample_store()]);

    let doc = sandbox.run(["nvram", s(&rom), "--json"]).json();
    assert_envelope(&doc);
    assert_eq!(doc["command"], "nvram");
    let rows = variable_rows(&doc);
    assert!(
        rows.iter().all(|(_, state, _)| state == "active"),
        "(default listing): expected active records only | received {rows:?}"
    );
    let names: Vec<&str> = rows.iter().map(|(_, _, name)| name.as_str()).collect();
    assert_eq!(
        names,
        ["StdDefaults", "Setup", "Setup", "Setup"],
        "(active names)"
    );
    assert_eq!(doc["data"]["records_by_state"]["superseded"], 2);
    assert_eq!(doc["data"]["records_by_state"]["deleted"], 1);
    assert_eq!(doc["data"]["records_by_state"]["orphan"], 1);
    assert_eq!(doc["data"]["stores"][0]["label"], "nvar@0x5060");
    assert_eq!(doc["data"]["stores"][1]["defaults"], "standard");

    let all = sandbox
        .run(["nvram", s(&rom), "--all-records", "--json"])
        .json();
    let states: Vec<String> = variable_rows(&all).into_iter().map(|(_, s, _)| s).collect();
    for expected in ["active", "superseded", "deleted", "orphan"] {
        assert!(
            states.iter().any(|s| s == expected),
            "(--all-records): expected a {expected} record in {states:?}"
        );
    }

    let text = sandbox.run(["nvram", s(&rom)]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    for expected in [
        "store nvar@0x5060 at 0x5060, 0xfa0 bytes",
        "store nvar@0x5060:StdDefaults",
        "EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9",
        "4 superseded, deleted, incomplete or orphan records hidden; pass --all-records",
    ] {
        assert!(
            text.stdout.contains(expected),
            "(nvram text): expected {expected:?} in\n{}",
            text.stdout
        );
    }
}

#[test]
fn nvram_filters_by_name_guid_and_store() {
    use biosmod_core::synthetic::{SETUP_VARSTORE_GUID, nvar_sample_store};
    let sandbox = Sandbox::new();
    let rom = nvram_sandbox_image(&sandbox, &[nvar_sample_store()]);

    let by_name = sandbox
        .run([
            "nvram",
            s(&rom),
            "--name",
            "Setup",
            "--all-records",
            "--json",
        ])
        .json();
    assert_eq!(
        variable_rows(&by_name).len(),
        5,
        "(Setup records in every state and store)"
    );

    let defaults = sandbox
        .run(["nvram", s(&rom), "--store", "stddefaults", "--json"])
        .json();
    assert!(
        variable_rows(&defaults)
            .iter()
            .all(|(store, _, _)| store.ends_with(":StdDefaults"))
    );
    assert_eq!(defaults["data"]["stores"].as_array().unwrap().len(), 1);

    let by_guid = sandbox
        .run([
            "nvram",
            s(&rom),
            "--store",
            "StdDefaults",
            "--guid",
            &SETUP_VARSTORE_GUID.to_string(),
            "--json",
        ])
        .json();
    assert_eq!(
        variable_rows(&by_guid).len(),
        1,
        "(one Setup of EC87D643 in the defaults)"
    );

    let missing = sandbox.run(["nvram", s(&rom), "--store", "vss", "--json"]);
    assert_eq!(missing.error_code(), "TARGET_NOT_FOUND");
}

#[test]
fn nvram_flags_a_size_that_differs_from_the_ifr_variable_store() {
    use biosmod_core::synthetic::{NvarSpec, SETUP_VARSTORE_GUID, nvar_store};
    let sandbox = Sandbox::new();
    let short = nvar_store(
        &[NvarSpec::Variable {
            name: "Setup",
            guid_index: 0,
            runtime: false,
            valid: true,
            data: &[0; 0x30],
            link: None,
        }],
        &[SETUP_VARSTORE_GUID],
        0xFA0,
    );
    let rom = nvram_sandbox_image(&sandbox, &[short]);
    let text = sandbox.run(["nvram", s(&rom)]);
    assert!(
        text.stdout.contains("0x30 (IFR 0x40: MISMATCH)"),
        "(size check text): expected the stored and declared sizes in\n{}",
        text.stdout
    );
    let doc = sandbox.run(["nvram", s(&rom), "--json"]).json();
    let setup = &doc["data"]["variables"][0];
    assert_eq!(
        (
            setup["size"].clone(),
            setup["expected_size"].clone(),
            setup["size_mismatch"].clone()
        ),
        (0x30.into(), 0x40.into(), true.into())
    );
}

#[test]
fn nvram_field_prints_stored_values_next_to_the_ifr_default() {
    use biosmod_core::synthetic::nvar_sample_store;
    let sandbox = Sandbox::new();
    let rom = nvram_sandbox_image(&sandbox, &[nvar_sample_store()]);
    let text = sandbox.run(["nvram", s(&rom), "--field", "acpi sleep state"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    for expected in [
        "\"ACPI Sleep State\" (question 0x0019): Setup EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9 +0xa, 2 byte(s)",
        "IFR default: standard 0x2, manufacturing 0x2",
        "nvar@0x5060:StdDefaults  active  standard",
    ] {
        assert!(
            text.stdout.contains(expected),
            "(field text): expected {expected:?} in\n{}",
            text.stdout
        );
    }

    let history = sandbox
        .run([
            "nvram",
            s(&rom),
            "--field",
            "ACPI Sleep State",
            "--all-records",
            "--json",
        ])
        .json();
    assert_envelope(&history);
    let values: Vec<(String, u64, bool)> = history["data"]["field"]["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["state"].as_str().unwrap().to_owned(),
                v["value"].as_u64().unwrap(),
                v["equals_default"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        values,
        [
            ("superseded".to_owned(), 0, false),
            ("superseded".to_owned(), 1, false),
            ("active".to_owned(), 2, true),
            ("active".to_owned(), 2, true),
        ],
        "(sleep word history, then the active and default records)"
    );
}

#[test]
fn nvram_field_refuses_ambiguous_prompts_until_a_question_id_picks_one() {
    use biosmod_core::synthetic::{ifr_twin_prompt_image, nvar_sample_store};
    let sandbox = Sandbox::new();
    let rom = sandbox.path("twin.bin");
    fs::write(&rom, ifr_twin_prompt_image(&[nvar_sample_store()])).unwrap();

    let ambiguous = sandbox.run(["nvram", s(&rom), "--field", "Twin", "--json"]);
    assert_eq!(ambiguous.error_code(), "TARGET_AMBIGUOUS");
    assert!(
        ambiguous.stdout.contains("0x0030") && ambiguous.stdout.contains("0x0031"),
        "(ambiguous prompt): expected both question ids in {}",
        ambiguous.stdout
    );
    for id in ["0x31", "49"] {
        let picked = sandbox
            .run([
                "nvram",
                s(&rom),
                "--field",
                "Twin",
                "--question-id",
                id,
                "--json",
            ])
            .json();
        assert_eq!(
            picked["data"]["field"]["offset"], 0x0C,
            "(--question-id {id})"
        );
    }
    let bad = sandbox.run([
        "nvram",
        s(&rom),
        "--field",
        "Twin",
        "--question-id",
        "zz",
        "--json",
    ]);
    assert_eq!(bad.error_code(), "USAGE");
    let unknown = sandbox.run(["nvram", s(&rom), "--field", "No Such Prompt", "--json"]);
    assert_eq!(unknown.error_code(), "TARGET_NOT_FOUND");
}

#[test]
fn nvram_dump_writes_exactly_one_record_and_never_overwrites() {
    use biosmod_core::synthetic::{nvar_sample_store, setup_payload};
    let sandbox = Sandbox::new();
    let rom = nvram_sandbox_image(&sandbox, &[nvar_sample_store()]);
    let out = sandbox.path("setup.bin");
    let ambiguous = sandbox.run([
        "nvram",
        s(&rom),
        "--name",
        "Setup",
        "--dump",
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!(ambiguous.error_code(), "TARGET_AMBIGUOUS");
    assert!(!out.exists(), "(ambiguous dump): expected no output file");

    let run = sandbox
        .run([
            "nvram",
            s(&rom),
            "--name",
            "Setup",
            "--store",
            "stddefaults",
            "--guid",
            "EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9",
            "--dump",
            "-o",
            s(&out),
            "--json",
        ])
        .json();
    assert_envelope(&run);
    assert_eq!(fs::read(&out).unwrap(), setup_payload(2));
    assert_eq!(run["data"]["length"], 0x40);
    assert_eq!(
        run["data"]["sha256"],
        biosmod_core::util::sha256_hex(&setup_payload(2))
    );
    let again = sandbox.run([
        "nvram",
        s(&rom),
        "--name",
        "Setup",
        "--store",
        "stddefaults",
        "--guid",
        "EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9",
        "--dump",
        "-o",
        s(&out),
        "--json",
    ]);
    assert_eq!(
        again.error_code(),
        "IO",
        "(existing output): {}",
        again.stdout
    );
    let none = sandbox.run([
        "nvram",
        s(&rom),
        "--name",
        "Nope",
        "--dump",
        "-o",
        s(&sandbox.path("x.bin")),
        "--json",
    ]);
    assert_eq!(none.error_code(), "TARGET_NOT_FOUND");
}

#[test]
fn nvram_reports_corrupt_records_with_their_offsets() {
    use biosmod_core::synthetic::{NvarSpec, SETUP_VARSTORE_GUID, nvar_record, nvar_store};
    let sandbox = Sandbox::new();
    let mut oversized = nvar_record(0x82, &[0; 8]);
    oversized[4..6].copy_from_slice(&0x7FFFu16.to_le_bytes());
    let variable = |name| NvarSpec::Variable {
        name,
        guid_index: 0,
        runtime: false,
        valid: true,
        data: &[1],
        link: None,
    };
    let store = nvar_store(
        &[
            variable("Before"),
            NvarSpec::Raw(oversized),
            variable("After"),
        ],
        &[SETUP_VARSTORE_GUID],
        0xFA0,
    );
    let rom = nvram_sandbox_image(&sandbox, &[store]);
    let doc = sandbox.run(["nvram", s(&rom), "--json"]).json();
    let names: Vec<String> = variable_rows(&doc).into_iter().map(|(_, _, n)| n).collect();
    assert_eq!(names, ["Before", "After"], "(records around the damage)");
    let issue = &doc["data"]["issues"][0];
    // Store at 0x5060; "Before" is 19 bytes.
    assert_eq!(issue["offset"], 0x5060 + 19, "(issue offset)");
    assert!(
        issue["message"]
            .as_str()
            .unwrap()
            .starts_with("record size: expected 10..="),
        "(issue message): {issue}"
    );
    let text = sandbox.run(["nvram", s(&rom)]);
    assert!(
        text.stdout
            .contains("issue nvar@0x5060 at 0x5073: record size: expected 10..="),
        "(issue text): {}",
        text.stdout
    );
}

#[test]
fn nvram_reads_a_bare_vss_store_and_rejects_files_without_one() {
    use biosmod_core::synthetic::{VssFlavor, VssSpec, vss_store};
    let sandbox = Sandbox::new();
    let store = vss_store(
        VssFlavor::Plain,
        &[
            VssSpec::Variable {
                name: "Boot0000",
                guid: biosmod_core::util::Guid::constant("8BE4DF61-93CA-11D2-AA0D-00E098032B8C"),
                attributes: 7,
                state: 0x3F,
                data: &[1, 2, 3],
            },
            VssSpec::Variable {
                name: "Boot0000",
                guid: biosmod_core::util::Guid::constant("8BE4DF61-93CA-11D2-AA0D-00E098032B8C"),
                attributes: 7,
                state: 0x3D,
                data: &[9],
            },
        ],
        0x400,
    );
    let path = sandbox.path("vss.bin");
    fs::write(&path, &store).unwrap();
    let doc = sandbox
        .run(["nvram", s(&path), "--all-records", "--json"])
        .json();
    assert_envelope(&doc);
    let rows = variable_rows(&doc);
    assert_eq!(
        rows,
        [
            (
                "vss@0x0".to_owned(),
                "active".to_owned(),
                "Boot0000".to_owned()
            ),
            (
                "vss@0x0".to_owned(),
                "deleted".to_owned(),
                "Boot0000".to_owned()
            ),
        ]
    );
    assert_eq!(
        doc["data"]["variables"][0]["flags"],
        serde_json::json!(["non_volatile", "boot_service", "runtime"])
    );

    let field = sandbox.run(["nvram", s(&path), "--field", "Anything", "--json"]);
    assert_eq!(field.error_code(), "USAGE");

    let junk = sandbox.path("junk.bin");
    fs::write(&junk, vec![0x5A; 512]).unwrap();
    assert_eq!(
        sandbox.run(["nvram", s(&junk), "--json"]).error_code(),
        "TARGET_NOT_FOUND"
    );
    let (image, _) = sandbox.synthetic();
    assert_eq!(
        sandbox.run(["nvram", s(&image), "--json"]).error_code(),
        "TARGET_NOT_FOUND"
    );
}

#[test]
fn capabilities_and_guides_list_the_nvram_command() {
    let sandbox = Sandbox::new();
    let doc = sandbox.run(["capabilities", "--json"]).json();
    let names: Vec<&str> = doc["data"]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"nvram"),
        "(capabilities commands): expected nvram in {names:?}"
    );
    assert!(doc["data"]["formats"]["variable_stores"].is_array());
    let guide = sandbox.run(["guide", "nvram"]);
    assert_eq!(guide.code, 0, "{}", guide.stderr);
    assert!(
        guide.stdout.contains("bme nvram"),
        "(guide nvram): {}",
        guide.stdout
    );
}

#[test]
fn nvram_surfaces_the_ifr_diagnostics_of_a_module_that_failed_to_decode() {
    use biosmod_core::synthetic::{nvar_sample_store, nvram_volume};
    let sandbox = Sandbox::new();
    let rom = sandbox.path("nvram-broken-ifr.bin");
    let mut image = ifr_image_with_broken_module(true);
    image.extend(nvram_volume(&nvar_sample_store()));
    fs::write(&rom, image).unwrap();

    let listing = sandbox.run(["nvram", s(&rom), "--json"]);
    assert_eq!(listing.code, 0, "{}", listing.stdout);
    let diagnostics = &listing.json()["data"]["ifr_diagnostics"];
    assert!(
        diagnostics[0]["guid"]
            .as_str()
            .is_some_and(|g| g.ends_with("0000000000B1")),
        "(nvram ifr_diagnostics): expected the 0000B1 module | received {diagnostics}"
    );

    let field = sandbox.run(["nvram", s(&rom), "--field", "ACPI Sleep State"]);
    assert_eq!(field.code, 0, "{}", field.stdout);
    assert!(
        field
            .stdout
            .contains("warning: file 00000000-0000-0000-0000-0000000000B1"),
        "(nvram --field): expected the module warning | received {}",
        field.stdout
    );
}

/// Write the ACPI inventory fixture and return its path.
fn acpi_fixture(
    sandbox: &Sandbox,
) -> (
    std::path::PathBuf,
    biosmod_core::synthetic::AcpiInventoryFixture,
) {
    let fixture = biosmod_core::synthetic::AcpiInventoryFixture::new();
    let path = sandbox.path("acpi.bin");
    fs::write(&path, &fixture.image).unwrap();
    (path, fixture)
}

#[test]
fn inspect_acpi_lists_stored_tables_and_states_the_scope() {
    let sandbox = Sandbox::new();
    let (image, fixture) = acpi_fixture(&sandbox);
    let doc = sandbox
        .run(["inspect", s(&image), "--acpi", "--json"])
        .json();
    let acpi = &doc["data"]["acpi"];
    assert!(
        acpi["notice"]
            .as_str()
            .unwrap()
            .contains("not the set the firmware publishes"),
        "(acpi.notice): expected the stored-set statement | received {acpi}"
    );
    let tables = acpi["tables"].as_array().unwrap();
    let ids: Vec<&str> = tables
        .iter()
        .map(|t| t["oem_table_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["InPe", "InRaw"],
        "(oem table ids): decoy must not be listed"
    );
    assert_eq!(tables[0]["locations"][0]["file_name"], "PeHost");
    assert_eq!(tables[0]["locations"][0]["section_kind"], "pe32");
    assert_eq!(tables[0]["locations"][0]["offset"], fixture.pe_offset);
    assert_eq!(tables[1]["length"], fixture.raw_table.len());
    let text = sandbox.run(["inspect", s(&image), "--acpi"]).stdout;
    assert!(text.contains("ACPI tables: 2 distinct"), "{text}");
    assert!(text.contains("InRaw"), "{text}");
    let plain = sandbox.run(["inspect", s(&image), "--json"]).json();
    assert!(
        plain["data"].get("acpi").is_none(),
        "(inspect without --acpi): expected no acpi key | received {plain}"
    );
}

#[test]
fn extract_picks_stored_acpi_tables_by_signature_id_or_hash() {
    let sandbox = Sandbox::new();
    let (image, fixture) = acpi_fixture(&sandbox);
    let pe_guid = fixture.pe_guid.to_string();
    let try_extract = |name: &str, guid: &str, extra: &[&str]| {
        let out = sandbox.path(name);
        let mut args = vec![
            "extract",
            s(&image),
            "--guid",
            guid,
            "--leaf",
            "acpi-table",
            "-o",
            s(&out),
            "--json",
        ];
        args.extend(extra);
        (sandbox.run(args), out)
    };
    // A table inside a PE section, picked by signature and OEM table ID.
    let (run, out) = try_extract(
        "pe.aml",
        &pe_guid,
        &["--signature", "SSDT", "--oem-table-id", "InPe"],
    );
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(fs::read(out).unwrap(), fixture.pe_table);
    // The mixed file holds two tables: a bare signature is ambiguous, a hash is not.
    let mixed = fixture.mixed_guid.to_string();
    let (run, _) = try_extract("amb.aml", &mixed, &["--signature", "SSDT"]);
    assert_eq!(run.error_code(), "TARGET_AMBIGUOUS");
    let digest = biosmod_core::util::sha256_hex(&fixture.raw_table);
    let (run, out) = try_extract("raw.aml", &mixed, &["--sha256", &digest]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert_eq!(fs::read(out).unwrap(), fixture.raw_table);
    let (run, _) = try_extract("none.aml", &pe_guid, &["--oem-table-id", "Nope"]);
    assert_eq!(run.error_code(), "TARGET_NOT_FOUND");
    // The decoy sits in a valid raw section but fails its checksum.
    let decoy_digest = biosmod_core::util::sha256_hex(&fixture.decoy);
    let raw_guid = fixture.raw_guid.to_string();
    let (run, _) = try_extract("decoy.aml", &raw_guid, &["--sha256", &decoy_digest]);
    assert_eq!(run.error_code(), "TARGET_NOT_FOUND");
}

#[test]
fn extract_table_selectors_require_the_acpi_leaf() {
    let sandbox = Sandbox::new();
    let (image, fixture) = acpi_fixture(&sandbox);
    let guid = fixture.pe_guid.to_string();
    let run = sandbox.run([
        "extract",
        s(&image),
        "--guid",
        &guid,
        "--signature",
        "SSDT",
        "-o",
        s(&sandbox.path("x")),
        "--json",
    ]);
    assert_eq!(run.error_code(), "SELECTION_INVALID");
    let bad_hash = sandbox.run([
        "extract",
        s(&image),
        "--guid",
        &guid,
        "--leaf",
        "acpi-table",
        "--sha256",
        "XYZ",
        "-o",
        s(&sandbox.path("y")),
        "--json",
    ]);
    assert_ne!(bad_hash.code, 0, "(--sha256 XYZ): expected a rejection");
}
