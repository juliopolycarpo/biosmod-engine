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
