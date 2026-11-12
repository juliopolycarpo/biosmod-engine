//! The committed scenario files parse, validate and name the module by digest only.

use biosmod_core::scenario::{self, Expectation};
use std::path::{Path, PathBuf};

const SIO_DXE_INIT_SHA256: &str =
    "8e8827a64c9ef65d42d0ffe21a82e51062ba2c4b40b125ad525a21c229732d04";

fn zero_policy_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/replay/scenarios/smartfan-zero-policy")
}

fn files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(zero_policy_dir())
        .expect("scenario directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

#[test]
fn the_zero_policy_check_ships_twelve_scenarios() {
    let found = files().len();
    assert_eq!(
        found, 12,
        "(zero-policy scenarios): expected 12 | received {found}"
    );
}

#[test]
fn every_zero_policy_scenario_validates_against_the_sio_module_digest() {
    for path in files() {
        let bytes = std::fs::read(&path).expect("scenario file");
        let scenario =
            scenario::parse(&bytes, &path.display().to_string()).expect("valid scenario");
        assert_eq!(
            scenario.module.sha256.to_string(),
            SIO_DXE_INIT_SHA256,
            "({}): expected the SioDxeInit digest | received {}",
            path.display(),
            scenario.module.sha256
        );
        let expect_pwm = scenario
            .expect
            .iter()
            .any(|e| matches!(e, Expectation::Register { index, .. } if index.0 == 0x27));
        assert!(
            expect_pwm,
            "({}): expected an expectation on PWM1 register 0x27 | received none",
            path.display()
        );
    }
}
