use super::*;
use crate::config::{Config, Paths};
use crate::output::Out;
use crate::{DirectSelection, SelectArgs, SourceArgs};
use biosmod_core::synthetic::{BANNER, Fixture};
use std::fs;

/// What another program does to the ROM while the patch is being built.
#[derive(Clone, Copy)]
enum Edit {
    Nothing,
    FlipByte(usize),
    TruncateTo(usize),
    GrowBy(usize),
}

/// A named fake for the moment between building the output and checking the input again.
struct EditsRomAfterPlan {
    rom: PathBuf,
    edit: Edit,
}

impl BuildInterlude for EditsRomAfterPlan {
    fn after_plan(&self) {
        let mut bytes = fs::read(&self.rom).unwrap();
        match self.edit {
            Edit::Nothing => {}
            Edit::FlipByte(at) => bytes[at] ^= 0xFF,
            Edit::TruncateTo(length) => bytes.truncate(length),
            Edit::GrowBy(extra) => bytes.resize(bytes.len() + extra, 0xAB),
        }
        fs::write(&self.rom, bytes).unwrap();
    }
}

/// A temporary directory with the synthetic image (banner included) and its catalog.
struct Workspace {
    dir: tempfile::TempDir,
    ctx: Ctx,
    rom_length: usize,
}

impl Workspace {
    fn new() -> Workspace {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture::new(0x07).with_banner(BANNER);
        fs::write(dir.path().join("dump.bin"), &fixture.image).unwrap();
        for (path, bytes) in fixture.catalog_files() {
            let target = dir.path().join("catalog").join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
        let ctx = Ctx {
            out: Out {
                json: true,
                quiet: true,
            },
            offline: true,
            paths: Paths {
                config: dir.path().join("config"),
                cache: dir.path().join("cache"),
                data: dir.path().join("data"),
            },
            config: Config::default(),
        };
        Workspace {
            dir,
            ctx,
            rom_length: fixture.image.len(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// `bme patch dump.bin PA -o out.bin` against the local catalog.
    fn patch_with(&self, edit: Edit) -> Result<Reply> {
        let args = PatchArgs {
            rom: self.path("dump.bin"),
            plan: None,
            selection: DirectSelection {
                ids: vec![],
                recommended: false,
                legacy: SelectArgs {
                    select: vec!["PA".into()],
                    facts: vec![],
                    allow_hold: false,
                    allow_diagnostic: false,
                },
            },
            source: SourceArgs {
                catalogs: vec![self.path("catalog").to_string_lossy().into_owned()],
                allow_unsigned_local: true,
                firmware: None,
            },
            expectations: Default::default(),
            dry_run: false,
            output: Some(self.path("out.bin")),
        };
        let interlude = EditsRomAfterPlan {
            rom: self.path("dump.bin"),
            edit,
        };
        patch_with(&self.ctx, &args, &interlude)
    }

    fn assert_nothing_published(&self) {
        let output = self.path("out.bin");
        assert!(
            !output.exists(),
            "(output file): expected none written | received {}",
            output.display()
        );
        let manifest = manifest_path(&output);
        assert!(
            !manifest.exists(),
            "(manifest file): expected none written | received {}",
            manifest.display()
        );
    }
}

/// Run the patch while the ROM is edited, and return the refusal.
fn refused_after(edit: Edit) -> (Workspace, Error) {
    let workspace = Workspace::new();
    let error = match workspace.patch_with(edit) {
        Ok(_) => panic!("(patch result): expected PLAN_INPUT_CHANGED | received a written output"),
        Err(error) => error,
    };
    (workspace, error)
}

#[test]
fn an_untouched_rom_publishes_the_output_and_manifest() {
    let workspace = Workspace::new();
    workspace
        .patch_with(Edit::Nothing)
        .expect("an unchanged ROM patches");
    assert!(
        workspace.path("out.bin").exists(),
        "fixture: output written"
    );
    assert!(manifest_path(&workspace.path("out.bin")).exists());
}

#[test]
fn an_edited_byte_is_named_by_offset_and_nothing_is_written() {
    let at = 0x1234;
    let (workspace, error) = refused_after(Edit::FlipByte(at));
    let original = Fixture::new(0x07).with_banner(BANNER).image[at];
    assert_eq!(error.code, Code::PlanInputChanged, "{error}");
    let detail = format!(
        "expected {original:#04x} | received {:#04x} at offset {at:#x}",
        original ^ 0xFF
    );
    assert!(
        error.message.contains(&detail),
        "{error} | expected {detail}"
    );
    workspace.assert_nothing_published();
}

#[test]
fn a_truncated_rom_reports_both_lengths_and_nothing_is_written() {
    let (workspace, error) = refused_after(Edit::TruncateTo(0x2000));
    assert_eq!(error.code, Code::PlanInputChanged, "{error}");
    let detail = format!(
        "expected {} bytes | received {} bytes",
        workspace.rom_length, 0x2000
    );
    assert!(
        error.message.contains(&detail),
        "{error} | expected {detail}"
    );
    workspace.assert_nothing_published();
}

#[test]
fn a_grown_rom_reports_the_extra_byte_and_nothing_is_written() {
    let (workspace, error) = refused_after(Edit::GrowBy(16));
    assert_eq!(error.code, Code::PlanInputChanged, "{error}");
    let detail = format!(
        "expected {} bytes | received at least {} bytes",
        workspace.rom_length,
        workspace.rom_length + 1
    );
    assert!(
        error.message.contains(&detail),
        "{error} | expected {detail}"
    );
    workspace.assert_nothing_published();
}
