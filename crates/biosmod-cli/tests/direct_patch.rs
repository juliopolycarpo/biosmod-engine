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
