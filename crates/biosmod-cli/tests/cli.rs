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
