//! The flash chip session against the real CLI and a flashrom stand-in.
//! No test reaches a real programmer, chip or polkit.

#![cfg(target_os = "linux")]

mod common;

use biosmod_gui::controller::{Action, FlashReport, Outcome, PreparationError, Session, Status};
use biosmod_gui::engine::Engine;
use std::path::PathBuf;

struct FlashBench {
    directory: tempfile::TempDir,
    image: PathBuf,
    chip: PathBuf,
    engine: Engine,
}

impl FlashBench {
    /// A chip holding the synthetic image, reachable through the stand-in flashrom.
    fn new() -> Self {
        let binary = common::test_engine();
        let directory = tempfile::Builder::new()
            .prefix("bme-gui-flash-")
            .tempdir()
            .unwrap();
        let root = directory.path();
        let image = common::setup_fixture(&binary, root);
        let chip = root.join("chip.bin");
        std::fs::copy(&image, &chip).unwrap();
        let engine = Engine::new(&binary, root)
            .unwrap()
            .with_env("BME_CONFIG_HOME", root.join("config"))
            .with_env("BME_CACHE_HOME", root.join("cache"))
            .with_env("BME_DATA_HOME", root.join("data"))
            .with_env("BME_FLASHROM", common::fake_flashrom_program(root))
            .with_env("FAKE_FLASH_CHIP", &chip);
        Self {
            directory,
            image,
            chip,
            engine,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn run(&self, session: &mut Session, action: Action) {
        let job = session
            .prepare(action)
            .unwrap_or_else(|error| panic!("{action:?}: expected preparation | received {error}"));
        assert!(
            session.finish(job.run(&self.engine)),
            "{action:?}: expected current result"
        );
    }
}

#[test]
fn session_diagnoses_backs_up_checks_and_flashes_the_chip() {
    let bench = FlashBench::new();
    let mut session = Session::new().unwrap();
    bench.run(&mut session, Action::Connect);
    assert!(
        session.flash.supported,
        "(connect): expected the built CLI to advertise flash_workflow"
    );
    session.edit_flash(|flash| {
        flash.programmer = "ch341a_spi".into();
        flash.elevate = false;
        flash.whole_chip = true;
    });

    bench.run(&mut session, Action::FlashDoctor);
    assert_eq!(
        session.status_kind,
        Status::FlashDiagnosed,
        "{}",
        session.status
    );
    let Some(FlashReport::Doctor(doctor)) = session.flash.report.as_deref() else {
        panic!(
            "(doctor): expected a diagnosis | received {:?}",
            session.flash.report
        );
    };
    assert_eq!(doctor["flashrom"]["version"], "1.6.0");

    bench.run(&mut session, Action::FlashProbe);
    assert_eq!(
        session.status_kind,
        Status::FlashProbed,
        "{}",
        session.status
    );

    let dump = bench.path("dump.bin");
    session.edit_flash(|flash| flash.backup = Some(dump.clone()));
    bench.run(&mut session, Action::FlashBackup);
    assert_eq!(
        session.status_kind,
        Status::FlashBackedUp,
        "{}",
        session.status
    );
    assert_eq!(
        std::fs::read(&dump).unwrap(),
        std::fs::read(&bench.image).unwrap()
    );
    // A second backup to the same path is refused instead of replacing the first.
    bench.run(&mut session, Action::FlashBackup);
    assert_eq!(session.outcome, Outcome::Failed);
    assert!(
        session.status.contains("OUTPUT_EXISTS"),
        "{}",
        session.status
    );

    // Build the image to flash from the backup, as the workflow page does.
    session.change_image(Some(dump.clone()));
    session.source = "lab".into();
    bench.run(&mut session, Action::Scan);
    session.select_recommended();
    let patched = bench.path("patched.bin");
    session.set_output(Some(patched.clone()));
    bench.run(&mut session, Action::Build);
    assert_eq!(session.status_kind, Status::Published, "{}", session.status);

    session.edit_flash(|flash| flash.image = Some(patched.clone()));
    assert_eq!(
        session.prepare(Action::FlashWrite).err(),
        Some(PreparationError::FlashCheck)
    );
    bench.run(&mut session, Action::FlashCheck);
    assert_eq!(
        session.status_kind,
        Status::FlashChecked,
        "{}",
        session.status
    );
    assert_eq!(
        std::fs::read(&bench.chip).unwrap(),
        std::fs::read(&dump).unwrap(),
        "(chip after check): expected the original contents"
    );
    assert!(!session.can_flash_write());
    session.edit_flash(|flash| flash.acknowledged = true);
    assert!(session.can_flash_write());

    bench.run(&mut session, Action::FlashWrite);
    assert_eq!(session.outcome, Outcome::ChipWritten, "{}", session.status);
    assert_eq!(
        std::fs::read(&bench.chip).unwrap(),
        std::fs::read(&patched).unwrap(),
        "(chip after write): expected the patched image"
    );
    assert!(matches!(
        session.flash.report.as_deref(),
        Some(FlashReport::Written(data)) if data["verified"] == true
    ));

    // The dump no longer matches the chip: checking the same inputs again is refused.
    bench.run(&mut session, Action::FlashCheck);
    assert_eq!(session.outcome, Outcome::Failed);
    assert!(
        session.status.contains("FLASH_REFUSED") && session.status.contains("take a new one"),
        "{}",
        session.status
    );
    assert!(!session.flash_checked());
}
