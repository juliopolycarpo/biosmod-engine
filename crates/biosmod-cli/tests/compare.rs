//! `bme compare` on vendor-free synthetic images.

mod common;

use biosmod_core::synthetic::{PEIM_GUID, ffs, image_of_files, relocatable_pe, section};
use common::{Sandbox, s};
use std::fs;

/// Write an image holding one PEIM linked at `base` with `code`; return its path.
fn write_image(sandbox: &Sandbox, name: &str, base: u32, code: &[u8]) -> std::path::PathBuf {
    let files = [ffs(
        PEIM_GUID,
        0x06,
        &section(0x10, &relocatable_pe(base, code)),
        0,
    )];
    let path = sandbox.path(name);
    fs::write(&path, image_of_files(&files)).unwrap();
    path
}

#[test]
fn rebased_module_reports_identical_after_normalization() {
    let sandbox = Sandbox::new();
    let a = write_image(&sandbox, "a.bin", 0x1000_0000, b"same");
    let b = write_image(&sandbox, "b.bin", 0x2000_0000, b"same");
    let run = sandbox.run(["compare", s(&a), s(&b), "--json"]);
    assert_eq!(run.code, 0, "{}", run.stdout);
    let doc = run.json();
    assert_eq!(doc["command"], "compare");
    assert_eq!(doc["data"]["summary"]["identical_after_normalization"], 1);
    assert_eq!(
        doc["data"]["pairs"][0]["verdict"],
        "identical-after-normalization"
    );
}

#[test]
fn changed_code_reports_ranges_and_sections() {
    let sandbox = Sandbox::new();
    let a = write_image(&sandbox, "a.bin", 0x1000_0000, b"aaaa");
    let b = write_image(&sandbox, "b.bin", 0x2000_0000, b"abaa");
    let pair = sandbox.run(["compare", s(&a), s(&b), "--json"]).json()["data"]["pairs"][0].clone();
    assert_eq!(pair["verdict"], "different", "{pair}");
    assert_eq!(pair["ranges_basis"], "normalized");
    assert_eq!(pair["changed_ranges"][0]["start"], 0x221);
    assert_eq!(pair["sections"][0]["name"], ".text");
    let text = sandbox.run(["compare", s(&a), s(&b)]);
    assert!(text.stdout.contains("1 different"), "{}", text.stdout);
    assert!(
        text.stdout.contains("ranges: 0x221-0x222"),
        "{}",
        text.stdout
    );
}

#[test]
fn unreadable_input_is_an_error_naming_the_path() {
    let sandbox = Sandbox::new();
    let a = write_image(&sandbox, "a.bin", 0x1000_0000, b"x");
    let missing = sandbox.path("missing.bin");
    let run = sandbox.run(["compare", s(&a), s(&missing), "--json"]);
    assert_ne!(run.code, 0);
    assert!(run.stdout.contains("missing.bin"), "{}", run.stdout);
}

#[test]
fn compare_never_writes_files() {
    let sandbox = Sandbox::new();
    let a = write_image(&sandbox, "a.bin", 0x1000_0000, b"x");
    let b = write_image(&sandbox, "b.bin", 0x2000_0000, b"y");
    sandbox.run(["compare", s(&a), s(&b)]);
    let mut names: Vec<String> = fs::read_dir(sandbox.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".bin") || n.contains("manifest"))
        .collect();
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin"]);
}

/// A hand-written `tools analyze` export: named fake of Ghidra's `ExportFirmware` output.
mod export_fake {
    use serde_json::{Value, json};

    pub fn ins(rva: u64, bytes: &str, text: &str) -> Value {
        json!({"rva": format!("{rva:#x}"), "bytes": bytes, "mnemonic": text.split(' ').next().unwrap(), "text": text})
    }

    pub fn function(name: &str, rva: u64, instructions: Vec<Value>) -> Value {
        json!({"name": name, "rva": format!("{rva:#x}"), "calls": [], "instructions": instructions})
    }

    pub fn export(program: &str, functions: Vec<Value>) -> String {
        json!({"program": program, "image_base": "0x00400000", "functions": functions}).to_string()
    }
}

#[test]
fn functions_mode_reports_identical_changed_and_unmatched() {
    use export_fake::{export, function, ins};
    let sandbox = Sandbox::new();
    let same = |rva| {
        function(
            "same",
            rva,
            vec![ins(rva, "55", "PUSH EBP"), ins(rva + 1, "c3", "RET")],
        )
    };
    let body = |imm: &str, bytes: &str| {
        vec![
            ins(0x40, "55", "PUSH EBP"),
            ins(0x41, bytes, &format!("MOV EAX,{imm}")),
            ins(0x46, "c3", "RET"),
        ]
    };
    let a = sandbox.path("a.json");
    let b = sandbox.path("b.json");
    fs::write(
        &a,
        export(
            "Mod",
            vec![
                same(0x10),
                function("edit", 0x40, body("0x1", "b801000000")),
                function("gone", 0x80, vec![ins(0x80, "f4", "HLT")]),
            ],
        ),
    )
    .unwrap();
    fs::write(
        &b,
        export(
            "Mod",
            vec![
                same(0x10),
                function("edit", 0x40, body("0x2", "b802000000")),
            ],
        ),
    )
    .unwrap();
    let doc = sandbox
        .run(["compare", "--functions", s(&a), s(&b), "--json"])
        .json();
    let data = &doc["data"];
    assert_eq!(data["summary"]["identical"], 1, "{doc}");
    assert_eq!(data["summary"]["changed"], 1, "{doc}");
    assert_eq!(data["summary"]["unmatched_a"], 1, "{doc}");
    let changed = data["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["verdict"] == "changed")
        .unwrap();
    assert_eq!(changed["changed_ranges"][0]["a"]["rva_start"], "0x41");
    assert_eq!(
        changed["candidate"], true,
        "an unanchored entry point pairs as a candidate: {changed}"
    );
    let text = sandbox.run(["compare", "--functions", s(&a), s(&b)]).stdout;
    assert!(text.contains("1 changed"), "{text}");
    assert!(text.contains("gone 0x80"), "{text}");
}

#[test]
fn functions_mode_rejects_an_export_without_instructions() {
    let sandbox = Sandbox::new();
    let old = sandbox.path("old.json");
    fs::write(
        &old,
        r#"{"program":"m","functions":[{"name":"f","rva":"0x10"}]}"#,
    )
    .unwrap();
    let run = sandbox.run(["compare", "--functions", s(&old), s(&old), "--json"]);
    assert_eq!(run.error_code(), "FORMAT_INVALID");
    assert!(
        run.stdout.contains("old.json function f at 0x10"),
        "{}",
        run.stdout
    );
}
