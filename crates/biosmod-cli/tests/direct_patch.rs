mod common;

use biosmod_core::util::sha256_hex;
use common::{Sandbox, s};
use serde_json::Value;
use std::fs;

#[test]
fn direct_preview_export_replay_and_verify_share_the_exact_build() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let local = ["--catalog", s(&catalog), "--allow-unsigned-local", "--json"];
    let scan = sandbox
        .run(["scan", s(&image)].into_iter().chain(local))
        .json();
    let snapshot = &scan["data"]["sources"][0]["snapshot_sha256"];
    let input_digest = scan["data"]["input"]["sha256"].as_str().unwrap();
    let guards = [
        "--expect-input-sha256",
        input_digest,
        "--expect-source-sha256",
        snapshot.as_str().unwrap(),
    ];
    let direct = |args: &[&str]| {
        sandbox
            .run(args.iter().copied().chain(local).chain(guards))
            .json()
    };
    let before = fs::read_dir(image.parent().unwrap()).unwrap().count();
    let preview = direct(&["patch", s(&image), "local::PA@1.0.0", "--dry-run"]);
    assert_eq!(preview["data"]["dry_run"], true, "{preview}");
    assert_eq!(preview["data"]["source_snapshot_sha256"], *snapshot);
    for absent in ["output", "manifest_file", "proposed_output"] {
        assert!(preview["data"].get(absent).is_none(), "{preview}");
    }
    let proposed = direct(&["patch", s(&image), "PA", "--dry-run", "-o", s(&image)]);
    assert_eq!(proposed["data"]["proposed_output"], s(&image), "{proposed}");
    assert_eq!(
        fs::read_dir(image.parent().unwrap()).unwrap().count(),
        before
    );
    let recipe = sandbox.path("recipe.json");
    let export = direct(&["export", s(&image), "PA", "-o", s(&recipe)]);
    assert_eq!(export["data"]["patch_file"], s(&recipe), "{export}");
    assert_eq!(export["data"]["source_snapshot_sha256"], *snapshot);
    assert_eq!(export["data"]["plan"], preview["data"]["plan"]);
    let build = direct(&["patch", s(&image), "PA"]);
    let output = image.with_file_name("synthetic.patched.bin");
    let manifest = image.with_file_name("synthetic.patched.bin.manifest.json");
    assert_eq!(build["data"]["output"], s(&output), "{build}");
    assert_eq!(build["data"]["manifest"]["plan"], preview["data"]["plan"]);
    assert_eq!(build["data"]["source_snapshot_sha256"], *snapshot);
    let manifest_sha256 = sha256_hex(&fs::read(manifest).unwrap());
    assert_eq!(build["data"]["manifest_sha256"], manifest_sha256);
    let replayed = sandbox.path("replayed.rom");
    for mode in ["--dry-run", "--quiet"] {
        let replay = sandbox
            .run([
                "patch",
                s(&image),
                "--from",
                s(&recipe),
                "--allow-unsigned-local",
                "-o",
                s(&replayed),
                mode,
                "--json",
            ])
            .json();
        assert_eq!(replay["ok"], true, "{replay}");
        assert_eq!(replay["data"]["source_snapshot_sha256"], *snapshot);
        if mode == "--dry-run" {
            assert_eq!(replay["data"]["plan"], preview["data"]["plan"]);
            assert!(!replayed.exists());
        }
    }
    assert_eq!(fs::read(&output).unwrap(), fs::read(&replayed).unwrap());
    let verified = sandbox
        .run([
            "verify",
            s(&image),
            s(&output),
            "--from",
            s(&recipe),
            "--json",
        ])
        .json();
    assert_eq!(verified["data"]["complete"], true, "{verified}");
    assert_eq!(verified["data"]["manifest_sha256"], manifest_sha256);
    let collision = sandbox.run(
        ["patch", s(&image), "--select", "PA"]
            .into_iter()
            .chain(local),
    );
    assert_eq!(collision.error_code(), "OUTPUT_EXISTS");
    assert_eq!(sha256_hex(&fs::read(image).unwrap()), input_digest);
}

#[test]
fn recommended_and_legacy_selectors_keep_their_contracts() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let local = ["--catalog", s(&catalog), "--allow-unsigned-local", "--json"];
    let run = |args: &[&str]| sandbox.run(args.iter().copied().chain(local));
    let new = run(&["patch", s(&image), "--recommended", "--dry-run"]).json();
    let legacy = run(&["patch", s(&image), "--select", "recommended", "--dry-run"]).json();
    assert_eq!(new["ok"], true, "{new}");
    assert_eq!(new["data"], legacy["data"]);
    for flags in [vec![], vec!["--recommended"]] {
        let recipe = sandbox.path(&format!("recipe-{}.json", flags.len()));
        let args = ["export", s(&image), "-o", s(&recipe)]
            .into_iter()
            .chain(flags)
            .collect::<Vec<_>>();
        let export = run(&args).json();
        assert_eq!(export["data"]["plan"], new["data"]["plan"], "{export}");
    }

    for selectors in [
        vec![],
        vec!["recommended"],
        vec!["PA", "--recommended"],
        vec!["PA", "--select", "TB"],
        vec!["--recommended", "--select", "TB"],
        vec!["PA", "--from", "missing.json"],
        vec!["--from", "missing.json", "--assert", "fact"],
    ] {
        let result = sandbox.run(["patch", s(&image), "--json"].into_iter().chain(selectors));
        assert_eq!(result.error_code(), "USAGE", "{}", result.stdout);
    }
    assert_eq!(
        sandbox.run(["capabilities", "--json"]).json()["data"]["direct_patch_workflow"],
        1
    );
}

#[test]
fn scan_follow_up_round_trips_rom_and_catalog_paths() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    for (original, name) in [(image, "input 'rom'.bin"), (catalog, "local $catalog")] {
        fs::rename(original, sandbox.path(name)).unwrap();
    }
    let image = sandbox.path("input 'rom'.bin");
    let catalog = sandbox.path("local $catalog");
    let scan = sandbox.run([
        "scan",
        s(&image),
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
    ]);
    assert_eq!(scan.code, 0, "{}", scan.stderr);
    let follow_up = scan
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("Next: "))
        .expect("scan: expected a recommended follow-up command");
    let mut shell = if cfg!(windows) {
        let mut shell = std::process::Command::new("powershell.exe");
        shell.args([
            "-NoProfile", "-NonInteractive", "-Command",
            &format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8; function bme {{ foreach ($arg in $args) {{ [Console]::Write($arg + [char]0) }} }}; {follow_up}"),
        ]);
        shell
    } else {
        let mut shell = std::process::Command::new("sh");
        shell.args([
            "-c",
            &format!("bme() {{ printf '%s\\0' \"$@\"; }}\n{follow_up}"),
        ]);
        shell
    };
    let parsed = shell.output().unwrap();
    assert!(
        parsed.status.success(),
        "{follow_up}: {}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    let arguments = String::from_utf8(parsed.stdout).unwrap();
    let arguments = arguments
        .trim_end_matches('\0')
        .split('\0')
        .collect::<Vec<_>>();
    assert_eq!(
        arguments,
        [
            "patch",
            s(&image),
            "--recommended",
            "--catalog",
            s(&catalog),
            "--allow-unsigned-local"
        ],
        "follow-up command: {follow_up}"
    );
    let patch = sandbox.run(arguments.into_iter().chain(["--dry-run"]));
    assert_eq!(patch.code, 0, "{}", patch.stderr);
}

#[test]
fn guarded_operations_refuse_snapshot_drift_before_publishing() {
    let sandbox = Sandbox::new();
    let (image, catalog) = sandbox.synthetic();
    let local = ["--catalog", s(&catalog), "--allow-unsigned-local", "--json"];
    let scan = sandbox
        .run(["scan", s(&image)].into_iter().chain(local))
        .json();
    let input = scan["data"]["input"]["sha256"].as_str().unwrap();
    let source = scan["data"]["sources"][0]["snapshot_sha256"]
        .as_str()
        .unwrap();
    let output = sandbox.path("new-artifact");
    let wrong = "0".repeat(64);
    for (command, flag, kind, actual) in [
        ("patch", "--expect-source-sha256", "source", source),
        ("export", "--expect-input-sha256", "input", input),
    ] {
        let refused = sandbox.run(
            [command, s(&image), "PA", flag, &wrong, "-o", s(&output)]
                .into_iter()
                .chain(local),
        );
        assert_eq!(refused.error_code(), "PLAN_INPUT_CHANGED");
        let details = &refused.json()["error"]["details"];
        assert_eq!(details["kind"], kind, "{details}");
        assert_eq!(details["expected_sha256"], wrong);
        assert_eq!(details["actual_sha256"], actual);
        assert!(!output.exists());
    }

    let catalog_manifest = catalog.join("catalog.json");
    let mut catalog_bytes = fs::read(&catalog_manifest).unwrap();
    catalog_bytes.push(b'\n');
    fs::write(catalog_manifest, catalog_bytes).unwrap();
    let updated = sandbox
        .run(["scan", s(&image)].into_iter().chain(local))
        .json();
    let updated_snapshot = &updated["data"]["sources"][0]["snapshot_sha256"];
    assert_ne!(
        updated_snapshot, source,
        "expected scan to detect the catalog update"
    );
    let refused = sandbox.run(
        [
            "patch",
            s(&image),
            "PA",
            "--expect-source-sha256",
            source,
            "-o",
            s(&output),
        ]
        .into_iter()
        .chain(local),
    );
    assert_eq!(refused.error_code(), "PLAN_INPUT_CHANGED");
    assert_eq!(
        refused.json()["error"]["details"]["actual_sha256"],
        *updated_snapshot
    );
    assert!(!output.exists());

    fs::write(&image, b"changed and no longer a firmware image").unwrap();
    let refused = sandbox.run(
        [
            "patch",
            s(&image),
            "PA",
            "--dry-run",
            "--expect-input-sha256",
            input,
        ]
        .into_iter()
        .chain(local),
    );
    assert_eq!(refused.error_code(), "PLAN_INPUT_CHANGED");
    assert_ne!(
        refused.json()["error"]["details"]["actual_sha256"],
        Value::Null
    );
}

#[test]
fn a_finding_id_suggests_its_application_unit_without_selecting_it() {
    let sandbox = Sandbox::new();
    let (image, _) = sandbox.synthetic();
    for id in ["B01", "official::B01"] {
        let refused = sandbox.run(["patch", s(&image), id, "--json"]);
        assert_eq!(refused.error_code(), "TARGET_NOT_FOUND");
        let response = refused.json();
        let message = response["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("B01") && message.contains("official::B01-B06"),
            "{message}"
        );
        assert!(!image.with_file_name("synthetic.patched.bin").exists());
    }
}

#[test]
fn recommended_build_without_an_extension_and_empty_recommendation() {
    let sandbox = Sandbox::new();
    let (original, catalog) = sandbox.synthetic();
    let image = sandbox.path("rom");
    fs::rename(original, &image).unwrap();
    let local = ["--catalog", s(&catalog), "--allow-unsigned-local", "--json"];
    let patch = sandbox.run(
        ["patch", s(&image), "--recommended"]
            .into_iter()
            .chain(local),
    );
    let output = sandbox.path("rom.patched");
    assert_eq!(
        patch.json()["data"]["output"],
        s(&output),
        "{}",
        patch.stdout
    );
    assert!(output.is_file());
    let recipe = sandbox.path("empty.json");
    let refused = sandbox.run(
        ["export", s(&output), "-o", s(&recipe)]
            .into_iter()
            .chain(local),
    );
    assert_eq!(refused.error_code(), "SELECTION_INVALID");
    assert!(
        refused
            .stdout
            .contains("no applicable recommended correction")
    );
    assert!(!recipe.exists());
}
