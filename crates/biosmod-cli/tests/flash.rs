//! The `flash` commands end to end against `FakeFlashromProgram`, a script standing
//! in for flashrom. No test reaches a real programmer or chip.

#![cfg(target_os = "linux")]

mod common;

use biosmod_core::util::sha256_hex;
use common::{Run, Sandbox, s};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// A flashrom stand-in whose chip is the file named by `FAKE_FLASH_CHIP`.
const FAKE_FLASHROM_PROGRAM: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
    echo "flashrom v1.6.0 on Linux 7.0.0 (x86_64)"
    exit 0
fi
operation=""
file=""
while [ $# -gt 0 ]; do
    case "$1" in
        -p|-c|-l|-i) shift ;;
        -r|-w) operation="$1"; file="$2"; shift ;;
    esac
    shift
done
echo 'Found Winbond flash chip "W25Q128.V" (16384 kB, SPI) on ch341a_spi.'
case "$operation" in
    -r) cp "$FAKE_FLASH_CHIP" "$file" ;;
    -w) cp "$file" "$FAKE_FLASH_CHIP" && echo "Verifying flash... VERIFIED." ;;
    *) echo "No operations were specified." ;;
esac
"#;

struct Bench {
    sandbox: Sandbox,
    flashrom: PathBuf,
    chip: PathBuf,
}

impl Bench {
    /// A sandbox whose chip holds the synthetic image.
    fn new() -> (Bench, PathBuf, PathBuf) {
        let sandbox = Sandbox::new();
        let (image, catalog) = sandbox.synthetic();
        let flashrom = sandbox.path("fake-flashrom");
        fs::write(&flashrom, FAKE_FLASHROM_PROGRAM).unwrap();
        fs::set_permissions(&flashrom, fs::Permissions::from_mode(0o755)).unwrap();
        let chip = sandbox.path("chip.bin");
        fs::copy(&image, &chip).unwrap();
        (
            Bench {
                sandbox,
                flashrom,
                chip,
            },
            image,
            catalog,
        )
    }

    fn flash(&self, args: &[&str]) -> Run {
        self.sandbox.run_with_env(
            ["flash"].iter().chain(args).chain(&["--json"]),
            &[
                ("BME_FLASHROM", &self.flashrom),
                ("FAKE_FLASH_CHIP", &self.chip),
            ],
        )
    }
}

#[test]
fn backup_patch_and_flash_round_trip() {
    let (bench, image, catalog) = Bench::new();
    let doctor = bench.flash(&["doctor", "-p", "ch341a_spi"]).json();
    assert_eq!(doctor["command"], "flash doctor", "{doctor}");
    assert_eq!(doctor["data"]["flashrom"]["version"], "1.6.0", "{doctor}");

    let probe = bench.flash(&["probe", "-p", "ch341a_spi"]).json();
    assert_eq!(probe["command"], "flash probe", "{probe}");
    assert_eq!(probe["data"]["chips"][0]["name"], "W25Q128.V", "{probe}");

    let dump = bench.sandbox.path("dump.bin");
    let backup = bench
        .flash(&["backup", "-p", "ch341a_spi", "-o", s(&dump)])
        .json();
    assert_eq!(backup["command"], "flash backup", "{backup}");
    assert_eq!(fs::read(&dump).unwrap(), fs::read(&image).unwrap());
    assert_eq!(
        backup["data"]["sha256"],
        sha256_hex(&fs::read(&dump).unwrap())
    );

    let patched = bench.sandbox.path("patched.bin");
    let build = bench.sandbox.run([
        "patch",
        s(&dump),
        "PA",
        "--catalog",
        s(&catalog),
        "--allow-unsigned-local",
        "-o",
        s(&patched),
    ]);
    assert_eq!(build.code, 0, "{}", build.stderr);
    let digest = sha256_hex(&fs::read(&patched).unwrap());

    let write = |extra: &[&str]| {
        let base = [
            "write",
            s(&patched),
            "--backup",
            s(&dump),
            "-p",
            "ch341a_spi",
            "--whole-chip",
        ];
        bench.flash(&[&base[..], extra].concat())
    };
    let unconfirmed = write(&[]);
    assert_eq!(
        (unconfirmed.code, unconfirmed.error_code().as_str()),
        (1, "FLASH_REFUSED"),
        "{}",
        unconfirmed.stdout
    );
    let preview = write(&["--dry-run"]).json();
    assert_eq!(preview["command"], "flash write", "{preview}");
    assert_eq!(preview["data"]["confirm"], digest, "{preview}");
    assert_eq!(
        fs::read(&bench.chip).unwrap(),
        fs::read(&dump).unwrap(),
        "(chip after dry run): expected the original contents"
    );
    let written = write(&["--confirm", &digest]).json();
    assert_eq!(written["data"]["verified"], true, "{written}");
    assert_eq!(
        fs::read(&bench.chip).unwrap(),
        fs::read(&patched).unwrap(),
        "(chip after write): expected the patched image"
    );

    // The old dump no longer describes the chip, so it cannot guard another write.
    let stale = write(&["--confirm", &digest]);
    assert_eq!(stale.error_code(), "FLASH_REFUSED", "{}", stale.stdout);
    assert!(
        stale.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("the backup does not hold what the chip holds now"),
        "{}",
        stale.stdout
    );
}

#[test]
fn flash_arguments_are_validated_before_flashrom_runs() {
    let (bench, image, _) = Bench::new();
    let option_like = bench.flash(&["probe", "--programmer=--help"]);
    assert_eq!(
        (option_like.code, option_like.error_code().as_str()),
        (2, "USAGE"),
        "{}",
        option_like.stdout
    );
    let both = bench.flash(&[
        "write",
        s(&image),
        "--backup",
        s(&image),
        "--dry-run",
        "--confirm",
        &"0".repeat(64),
    ]);
    assert_eq!(both.error_code(), "USAGE", "{}", both.stdout);
    let capabilities = bench.sandbox.run(["capabilities", "--json"]).json();
    assert_eq!(capabilities["data"]["flash_workflow"], 1);
    let codes = capabilities["data"]["error_codes"].to_string();
    assert!(
        codes.contains("FLASH_REFUSED") && codes.contains("FLASH_FAILED"),
        "{codes}"
    );
}
