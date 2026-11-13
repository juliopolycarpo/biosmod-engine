//! Status tests. Programs are answered by `FakeInstalledTools`; nothing real runs.

use super::*;
use crate::config::{Config, Paths};
use crate::output::Out;
use crate::toolchain::{Finished, Profile};
use crate::transport::Offline;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const UBUNTU: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
const FEDORA: &str = "ID=fedora\n";
const ARCH: &str = "ID=arch\n";
const MINT: &str = "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";

/// Answers `--version` style calls by program file name and records the full command lines
/// and their timeouts.
struct FakeInstalledTools {
    answers: BTreeMap<&'static str, &'static str>,
    calls: RefCell<Vec<String>>,
    timeouts: RefCell<Vec<Duration>>,
}

impl FakeInstalledTools {
    fn complete() -> FakeInstalledTools {
        FakeInstalledTools {
            answers: BTreeMap::from([
                ("java", "openjdk version \"21.0.5\" 2026-10-21"),
                ("javac", "javac 21.0.5"),
                ("git", "git version 2.53.0"),
                ("nasm", "NASM version 2.16.01 compiled on Jan  1 2026"),
                (
                    "iasl",
                    "Intel ACPI Component Architecture\nASL+ Optimizing Compiler/Disassembler version 20250404",
                ),
                ("flashrom", "flashrom v1.6.0 on Linux 7.0 (x86_64)"),
            ]),
            calls: RefCell::new(Vec::new()),
            timeouts: RefCell::new(Vec::new()),
        }
    }

    fn without(mut self, program: &'static str) -> FakeInstalledTools {
        self.answers.remove(program);
        self
    }

    fn answering(mut self, program: &'static str, text: &'static str) -> FakeInstalledTools {
        self.answers.insert(program, text);
        self
    }
}

impl Runner for FakeInstalledTools {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let name = invocation
            .program
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        self.calls.borrow_mut().push(format!(
            "{} {}",
            invocation.program.display(),
            invocation.words().join(" ")
        ));
        self.timeouts.borrow_mut().push(invocation.timeout);
        match self.answers.get(name.as_str()) {
            Some(text) => Ok(Finished {
                status: Some(0),
                stdout: if name == "java" || name == "javac" {
                    String::new()
                } else {
                    (*text).into()
                },
                stderr: if name == "java" || name == "javac" {
                    (*text).into()
                } else {
                    String::new()
                },
                ..Finished::default()
            }),
            None => Err(Error::new(
                Code::ToolUnavailable,
                format!("{name}: not found"),
            )),
        }
    }
}

/// A Ghidra directory with a headless script, version file and extension data.
fn ghidra_directory(root: &Path, version: &str) -> PathBuf {
    let home = root.join("ghidra");
    fs::create_dir_all(home.join("support")).unwrap();
    fs::write(home.join("support/analyzeHeadless"), "#!/bin/sh\n").unwrap();
    fs::create_dir_all(home.join("Ghidra")).unwrap();
    fs::write(
        home.join("Ghidra/application.properties"),
        format!("application.version={version}\n"),
    )
    .unwrap();
    let extension = home.join("Ghidra/Extensions/ghidra-firmware-utils");
    fs::create_dir_all(extension.join("data")).unwrap();
    fs::write(
        extension.join("extension.properties"),
        format!("version={version}\n"),
    )
    .unwrap();
    home
}

struct Scene {
    root: tempfile::TempDir,
    runner: FakeInstalledTools,
    variables: BTreeMap<&'static str, OsString>,
    configured_flashrom: Option<PathBuf>,
    os_release: &'static str,
    linux: bool,
}

impl Scene {
    fn new(runner: FakeInstalledTools) -> Scene {
        Scene {
            root: tempfile::tempdir().unwrap(),
            runner,
            variables: BTreeMap::new(),
            configured_flashrom: None,
            os_release: UBUNTU,
            linux: true,
        }
    }

    fn rows(&self, ghidra: &GhidraHome) -> Vec<ToolRow> {
        let env = Env {
            runner: &self.runner,
            transport: &Offline,
            offline: false,
            data: self.root.path().join("data"),
            cache: self.root.path().join("cache"),
            profile: Profile::pinned(),
        };
        let get = |key: &str| self.variables.get(key).cloned();
        status(&Probe {
            env: &env,
            ghidra,
            get: &get,
            flashrom: self.configured_flashrom.as_deref(),
            sbin: &[],
            os_release: Some(self.os_release),
            linux: self.linux,
        })
    }
}

fn row<'a>(rows: &'a [ToolRow], id: &str) -> &'a ToolRow {
    rows.iter().find(|r| r.id == id).unwrap_or_else(|| {
        panic!(
            "(tools status): expected row {id} | received {:?}",
            rows.iter().map(|r| r.id).collect::<Vec<_>>()
        )
    })
}

fn pinned_ghidra(scene: &Scene) -> GhidraHome {
    GhidraHome {
        path: ghidra_directory(scene.root.path(), "12.2"),
        origin: "managed",
    }
}

#[test]
fn package_commands_follow_the_distribution_family() {
    let command = |text, package| package_command(text, package);
    assert_eq!(
        command(UBUNTU, Package::Flashrom).as_deref(),
        Some("sudo apt install flashrom")
    );
    assert_eq!(
        command(MINT, Package::Git).as_deref(),
        Some("sudo apt install git")
    );
    assert_eq!(
        command(UBUNTU, Package::Jdk(21)).as_deref(),
        Some("sudo apt install openjdk-21-jdk")
    );
    assert_eq!(
        command(FEDORA, Package::Jdk(21)).as_deref(),
        Some("sudo dnf install java-21-openjdk-devel")
    );
    assert_eq!(
        command(ARCH, Package::Flashrom).as_deref(),
        Some("sudo pacman -S flashrom")
    );
    assert_eq!(command("ID=plan9\n", Package::Git), None);
}

#[test]
fn every_package_has_a_command_on_every_known_family() {
    let packages = [
        Package::Flashrom,
        Package::Nasm,
        Package::Iasl,
        Package::Git,
        Package::Jdk(21),
    ];
    let expected = [
        (
            UBUNTU,
            [
                "sudo apt install flashrom",
                "sudo apt install nasm",
                "sudo apt install acpica-tools",
                "sudo apt install git",
                "sudo apt install openjdk-21-jdk",
            ],
        ),
        (
            FEDORA,
            [
                "sudo dnf install flashrom",
                "sudo dnf install nasm",
                "sudo dnf install acpica-tools",
                "sudo dnf install git",
                "sudo dnf install java-21-openjdk-devel",
            ],
        ),
        (
            ARCH,
            [
                "sudo pacman -S flashrom",
                "sudo pacman -S nasm",
                "sudo pacman -S acpica",
                "sudo pacman -S git",
                "sudo pacman -S jdk21-openjdk",
            ],
        ),
    ];
    for (release, commands) in expected {
        let received: Vec<String> = packages
            .iter()
            .map(|package| package_command(release, *package).unwrap())
            .collect();
        assert_eq!(
            received, commands,
            "(package commands for {release:?}): expected one command per package"
        );
    }
}

#[test]
fn a_complete_installation_is_ready_with_versions_and_locations() {
    let mut scene = Scene::new(FakeInstalledTools::complete());
    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    let rows = scene.rows(&pinned_ghidra(&scene));
    for row in &rows {
        assert_eq!(
            row.health,
            Health::Ready,
            "(tools status) {}: {}",
            row.id,
            row.detail
        );
    }
    assert_eq!(row(&rows, "ghidra").version.as_deref(), Some("12.2"));
    assert_eq!(row(&rows, "git").version.as_deref(), Some("2.53.0"));
    assert_eq!(row(&rows, "flashrom").version.as_deref(), Some("1.6.0"));
    assert!(render(&rows).ends_with("Every tool is ready.\n"));
}

#[test]
fn a_missing_flashrom_offers_the_distribution_command_and_a_custom_location() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let flashrom = row(&rows, "flashrom");
    assert_eq!(flashrom.health, Health::Missing);
    assert_eq!(flashrom.origin, "none");
    assert_eq!(
        flashrom.install.command.as_deref(),
        Some("sudo apt install flashrom")
    );
    assert!(!flashrom.install.automatic, "bme never runs sudo itself");
    assert!(flashrom.custom_location);
    let text = render(&rows);
    assert!(
        text.contains("install:  sudo apt install flashrom"),
        "{text}"
    );
    assert!(text.contains("bme tools set flashrom <path>"), "{text}");
}

#[test]
fn a_missing_ghidra_marks_the_extension_missing_and_points_to_setup() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let absent = GhidraHome {
        path: scene.root.path().join("no-ghidra"),
        origin: "managed",
    };
    let rows = scene.rows(&absent);
    assert_eq!(row(&rows, "ghidra").health, Health::Missing);
    assert_eq!(row(&rows, "firmware-utils").health, Health::Missing);
    assert_eq!(row(&rows, "firmware-utils").detail, "needs Ghidra first");
    assert_eq!(
        row(&rows, "ghidra").install.command.as_deref(),
        Some("bme tools setup ghidra")
    );
    assert_eq!(row(&rows, "ghidra").install.method, "bme");
}

#[test]
fn another_ghidra_release_needs_attention_not_a_failure() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let other = GhidraHome {
        path: ghidra_directory(scene.root.path(), "11.0"),
        origin: "config",
    };
    let rows = scene.rows(&other);
    let ghidra = row(&rows, "ghidra");
    assert_eq!(ghidra.health, Health::Attention);
    assert_eq!(ghidra.version.as_deref(), Some("11.0"));
    assert_eq!(ghidra.origin, "config");
    assert!(
        ghidra.detail.contains("expected 12.2 | received 11.0"),
        "{}",
        ghidra.detail
    );
}

#[test]
fn flashrom_location_prefers_the_environment_then_the_configuration_then_path() {
    let mut scene = Scene::new(FakeInstalledTools::complete());
    let ghidra = pinned_ghidra(&scene);
    let bin = scene.root.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("flashrom"), "").unwrap();
    scene.variables.insert("PATH", bin.clone().into_os_string());
    let rows = scene.rows(&ghidra);
    assert_eq!(row(&rows, "flashrom").origin, "PATH");

    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    let rows = scene.rows(&ghidra);
    assert_eq!(row(&rows, "flashrom").origin, "config");
    assert_eq!(
        row(&rows, "flashrom").path.as_deref(),
        Some("/opt/fr/flashrom")
    );

    scene
        .variables
        .insert("BME_FLASHROM", "/env/flashrom".into());
    let rows = scene.rows(&ghidra);
    assert_eq!(row(&rows, "flashrom").origin, "BME_FLASHROM");
    assert_eq!(
        row(&rows, "flashrom").path.as_deref(),
        Some("/env/flashrom")
    );
}

#[test]
fn a_program_without_the_flashrom_banner_needs_attention() {
    let mut scene = Scene::new(FakeInstalledTools::complete().answering("flashrom", "hello"));
    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let flashrom = row(&rows, "flashrom");
    assert_eq!(flashrom.health, Health::Attention);
    assert!(
        flashrom
            .detail
            .contains("expected a `flashrom v<version>` banner | received hello"),
        "{}",
        flashrom.detail
    );
}

#[test]
fn missing_java_and_git_get_install_commands_for_this_distribution() {
    let mut scene = Scene::new(
        FakeInstalledTools::complete()
            .without("java")
            .without("javac")
            .without("git"),
    );
    scene.os_release = FEDORA;
    let rows = scene.rows(&pinned_ghidra(&scene));
    assert_eq!(row(&rows, "java").health, Health::Missing);
    assert_eq!(
        row(&rows, "jdk").install.command.as_deref(),
        Some("sudo dnf install java-21-openjdk-devel")
    );
    assert_eq!(
        row(&rows, "git").install.command.as_deref(),
        Some("sudo dnf install git")
    );
}

#[test]
fn an_unknown_distribution_gets_a_generic_hint() {
    let mut scene = Scene::new(FakeInstalledTools::complete().without("git"));
    scene.os_release = "ID=plan9\n";
    let rows = scene.rows(&pinned_ghidra(&scene));
    assert_eq!(row(&rows, "git").install.command, None);
    assert!(render(&rows).contains("install:  use your package manager"));
}

/// A context over a temporary configuration directory.
fn context(root: &Path) -> Ctx {
    let paths = Paths {
        config: root.join("config"),
        cache: root.join("cache"),
        data: root.join("data"),
    };
    Ctx {
        out: Out {
            json: true,
            quiet: true,
        },
        offline: false,
        paths,
        config: Config::default(),
    }
}

fn executable(path: &Path) {
    fs::write(path, "#!/bin/sh\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn set_saves_a_validated_flashrom_and_unset_removes_it() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(root.path());
    let program = root.path().join("flashrom");
    executable(&program);
    let reply = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Flashrom,
        &program,
    )
    .unwrap();
    assert_eq!(reply.data["version"], "1.6.0");
    let saved = Config::load(&ctx.paths).unwrap();
    assert_eq!(saved.tools.flashrom.as_deref(), Some(program.as_path()));

    let ctx = Ctx {
        config: saved,
        ..ctx
    };
    let reply = unset(&ctx, Locatable::Flashrom).unwrap();
    assert_eq!(reply.data["previous"], program.to_string_lossy().as_ref());
    assert_eq!(Config::load(&ctx.paths).unwrap().tools.flashrom, None);
    let ctx = Ctx {
        config: Config::load(&ctx.paths).unwrap(),
        ..ctx
    };
    let again = unset(&ctx, Locatable::Flashrom).unwrap();
    assert_eq!(again.text, "flashrom had no saved location\n");
}

#[test]
fn set_rejects_a_flashrom_path_that_is_not_a_file() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(root.path());
    let missing = root.path().join("absent");
    let error = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Flashrom,
        &missing,
    )
    .unwrap_err();
    assert_eq!(error.code, Code::Usage);
    assert!(
        error
            .message
            .contains("expected an executable file | received none"),
        "{}",
        error.message
    );
    assert!(
        !ctx.paths.config_file().exists(),
        "a rejected value must not be saved"
    );
}

#[test]
fn set_rejects_a_program_that_is_not_flashrom() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(root.path());
    let program = root.path().join("flashrom");
    executable(&program);
    let impostor = FakeInstalledTools::complete().answering("flashrom", "bash 5.2");
    let error = set(&ctx, &impostor, Locatable::Flashrom, &program).unwrap_err();
    assert!(
        error
            .message
            .contains("expected a `flashrom v<version>` banner | received bash 5.2"),
        "{}",
        error.message
    );
    assert!(!ctx.paths.config_file().exists());
}

#[test]
fn set_ghidra_needs_the_headless_script() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(root.path());
    let empty = root.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    let error = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Ghidra,
        &empty,
    )
    .unwrap_err();
    assert!(
        error
            .message
            .contains("expected an installation containing support/analyzeHeadless"),
        "{}",
        error.message
    );
    let home = ghidra_directory(root.path(), "12.2");
    let reply = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Ghidra,
        &home,
    )
    .unwrap();
    assert_eq!(reply.data["version"], "12.2");
    assert_eq!(
        Config::load(&ctx.paths)
            .unwrap()
            .tools
            .ghidra_home
            .as_deref(),
        Some(home.as_path())
    );
}

#[test]
fn a_saved_ghidra_location_blocks_the_managed_install_and_says_how_to_unblock_it() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let missing = GhidraHome {
        path: scene.root.path().join("not-installed"),
        origin: "config",
    };
    let rows = scene.rows(&missing);
    let install = &row(&rows, "ghidra").install;
    assert!(
        !install.automatic && install.command.is_none(),
        "(ghidra install, origin config): expected no automatic install | received {install:?}"
    );
    assert!(
        install
            .blocked
            .as_deref()
            .is_some_and(|reason| reason.contains("bme tools unset ghidra")),
        "(ghidra install, origin config): expected the unset command | received {:?}",
        install.blocked
    );
    let environment = GhidraHome {
        path: scene.root.path().join("not-installed"),
        origin: "GHIDRA_INSTALL_DIR",
    };
    let rows = scene.rows(&environment);
    assert!(
        row(&rows, "ghidra")
            .install
            .blocked
            .as_deref()
            .is_some_and(|reason| reason.starts_with("GHIDRA_INSTALL_DIR points elsewhere")),
        "(ghidra install, origin environment): expected the variable named | received {:?}",
        row(&rows, "ghidra").install
    );
}

#[test]
fn setup_waits_for_java_and_git_because_it_checks_them_first() {
    let scene = Scene::new(
        FakeInstalledTools::complete()
            .without("git")
            .without("javac"),
    );
    let managed = GhidraHome {
        path: scene.root.path().join("not-installed"),
        origin: "managed",
    };
    let rows = scene.rows(&managed);
    let install = &row(&rows, "ghidra").install;
    assert!(!install.automatic, "{install:?}");
    let reason = install.blocked.as_deref().unwrap_or_default();
    assert!(
        reason.contains("Git") && reason.contains("Java JDK"),
        "(ghidra install): expected the missing prerequisites named | received {reason:?}"
    );
    let ready = Scene::new(FakeInstalledTools::complete());
    let rows = ready.rows(&GhidraHome {
        path: ready.root.path().join("not-installed"),
        origin: "managed",
    });
    let install = &row(&rows, "ghidra").install;
    assert_eq!(
        (install.automatic, install.blocked.as_deref()),
        (true, None),
        "(ghidra install, prerequisites ready)"
    );
}

#[test]
fn an_unreadable_java_runtime_does_not_block_setup_that_checks_only_the_jdk_and_git() {
    let scene = Scene::new(FakeInstalledTools::complete().answering("java", "unrecognized"));
    let rows = scene.rows(&GhidraHome {
        path: scene.root.path().join("not-installed"),
        origin: "managed",
    });
    assert_ne!(row(&rows, "java").health, Health::Ready, "(java row)");
    let install = &row(&rows, "ghidra").install;
    assert_eq!(
        install.blocked.as_deref(),
        None,
        "(ghidra install, java runtime unreadable, javac 21 and git ready): expected not blocked"
    );
}

#[test]
fn outside_linux_the_ghidra_row_offers_no_setup_command_that_would_refuse() {
    let mut scene = Scene::new(FakeInstalledTools::complete());
    scene.linux = false;
    let rows = scene.rows(&GhidraHome {
        path: scene.root.path().join("not-installed"),
        origin: "managed",
    });
    let install = &row(&rows, "ghidra").install;
    assert_eq!(
        (install.automatic, install.command.as_deref()),
        (false, None),
        "(ghidra install, not Linux): expected no automatic install and no setup command"
    );
    let text = render(&rows);
    assert!(
        !text.contains("bme tools setup ghidra") && text.contains("Linux only"),
        "(tools status text, not Linux): expected a by-hand hint | received {text}"
    );
}

#[test]
fn outside_linux_no_blocked_reason_points_to_a_setup_that_would_refuse() {
    let mut scene = Scene::new(FakeInstalledTools::complete().without("javac"));
    scene.linux = false;
    let home = pinned_ghidra(&scene);
    fs::remove_dir_all(home.path.join("Ghidra/Extensions/ghidra-firmware-utils")).unwrap();
    let rows = scene.rows(&home);
    for id in ["ghidra", "firmware-utils"] {
        let install = &row(&rows, id).install;
        assert_eq!(
            (install.command.as_deref(), install.blocked.as_deref()),
            (None, None),
            "({id} install, not Linux, JDK missing, unmarked Ghidra): expected no command or reason"
        );
    }
    let text = render(&rows);
    assert!(
        !text.contains("bme tools setup ghidra"),
        "(tools status text, not Linux): expected no setup command | received {text}"
    );
}

#[test]
fn every_status_probe_together_fits_inside_the_gui_engine_timeout() {
    // The GUI runs `tools status` after each tool change with its default 120 s engine timeout.
    const GUI_ENGINE_TIMEOUT: Duration = Duration::from_secs(120);
    let mut scene = Scene::new(FakeInstalledTools::complete());
    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    scene.rows(&pinned_ghidra(&scene));
    let timeouts = scene.runner.timeouts.borrow();
    let worst: Duration = timeouts.iter().sum();
    assert!(
        worst < GUI_ENGINE_TIMEOUT,
        "(tools status, {} probes): expected a worst case under {GUI_ENGINE_TIMEOUT:?} | received {worst:?} from {timeouts:?}",
        timeouts.len()
    );
}

/// Record `dir` as installed by the pinned profile, as setup does.
fn mark_installed(dir: &Path) {
    fs::write(
        dir.join(crate::toolchain::MARKER),
        serde_json::to_vec(&Profile::pinned()).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_managed_directory_setup_did_not_install_blocks_setup_with_the_force_command() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let leftover = scene.root.path().join("data/tools/ghidra_12.2_PUBLIC");
    fs::create_dir_all(leftover.join("Ghidra")).unwrap();
    let rows = scene.rows(&GhidraHome {
        path: leftover.clone(),
        origin: "managed",
    });
    let install = &row(&rows, "ghidra").install;
    assert_eq!(
        (install.automatic, install.command.as_deref()),
        (false, None),
        "(ghidra install, unmarked managed directory): expected no install button or command"
    );
    let reason = install.blocked.as_deref().unwrap_or_default();
    assert!(
        reason.contains(&leftover.display().to_string())
            && reason.contains("bme tools setup ghidra --force"),
        "(ghidra install, unmarked managed directory): expected the directory and the --force command | received {reason:?}"
    );
}

#[test]
fn a_managed_ghidra_without_its_extension_can_still_be_set_up() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let home = pinned_ghidra(&scene);
    mark_installed(&home.path);
    fs::remove_dir_all(home.path.join("Ghidra/Extensions/ghidra-firmware-utils")).unwrap();
    let rows = scene.rows(&home);
    let install = &row(&rows, "firmware-utils").install;
    assert_eq!(
        (install.automatic, install.blocked.as_deref()),
        (true, None),
        "(firmware-utils install, marked Ghidra, no extension directory)"
    );
    let extension = home.path.join("Ghidra/Extensions/ghidra-firmware-utils");
    fs::create_dir_all(&extension).unwrap();
    let rows = scene.rows(&home);
    let reason = row(&rows, "firmware-utils").install.blocked.clone();
    assert!(
        reason
            .as_deref()
            .is_some_and(|text| text.contains(&extension.display().to_string())),
        "(firmware-utils install, unmarked extension directory): expected it named | received {reason:?}"
    );
}

#[test]
fn a_missing_nasm_is_optional_and_does_not_make_the_report_not_ready() {
    let mut scene = Scene::new(FakeInstalledTools::complete().without("nasm"));
    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let nasm = row(&rows, "nasm");
    assert_eq!(nasm.health, Health::Missing);
    assert!(nasm.optional && !nasm.custom_location, "{nasm:?}");
    assert_eq!(
        nasm.install.command.as_deref(),
        Some("sudo apt install nasm")
    );
    let text = render(&rows);
    assert!(
        text.contains("Every required tool is ready. Optional:")
            && text.contains("nasm (optional)"),
        "(tools status): expected nasm listed as optional | received {text}"
    );
}

#[test]
fn nasm_reports_its_version_when_installed() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let rows = scene.rows(&pinned_ghidra(&scene));
    assert_eq!(row(&rows, "nasm").version.as_deref(), Some("2.16.01"));
    assert_eq!(row(&rows, "nasm").health, Health::Ready);
}

fn with_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn a_group_writable_saved_flashrom_needs_attention_with_the_chmod_fix() {
    let mut scene = Scene::new(FakeInstalledTools::complete());
    let program = scene.root.path().join("self-built").join("flashrom");
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    executable(&program);
    with_mode(&program, 0o775);
    scene.configured_flashrom = Some(program.clone());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let flashrom = row(&rows, "flashrom");
    assert_eq!(
        flashrom.health,
        Health::Attention,
        "(flashrom saved with mode 775): expected attention | received {}",
        flashrom.detail
    );
    assert!(
        flashrom.detail.contains("mode 775")
            && flashrom
                .detail
                .contains(&format!("chmod go-w {}", program.display())),
        "(flashrom detail): expected the mode and the chmod fix | received {}",
        flashrom.detail
    );

    with_mode(&program, 0o755);
    let rows = scene.rows(&pinned_ghidra(&scene));
    assert_eq!(row(&rows, "flashrom").health, Health::Ready);
}

#[test]
fn set_warns_that_root_will_refuse_a_group_writable_flashrom() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(root.path());
    let program = root.path().join("flashrom");
    executable(&program);
    with_mode(&program, 0o775);
    let reply = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Flashrom,
        &program,
    )
    .unwrap();
    let refusal = reply.data["root_refusal"].as_str().unwrap_or_default();
    assert!(
        refusal.contains("mode 775") && refusal.contains("chmod go-w"),
        "(tools set flashrom, mode 775): expected a root refusal with the fix | received {}",
        reply.data
    );
    with_mode(&program, 0o755);
    let reply = set(
        &ctx,
        &FakeInstalledTools::complete(),
        Locatable::Flashrom,
        &program,
    )
    .unwrap();
    assert!(reply.data["root_refusal"].is_null(), "{}", reply.data);
}

#[test]
fn a_retained_setup_backup_blocks_the_managed_install_and_names_the_backup() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let home = pinned_ghidra(&scene);
    mark_installed(&home.path);
    fs::remove_dir_all(home.path.join("Ghidra/Extensions/ghidra-firmware-utils")).unwrap();
    // What a cancelled `tools setup ghidra` leaves next to the managed directory.
    let backup = scene.root.path().join(".bme-backup-ghidra");
    fs::create_dir_all(&backup).unwrap();
    let rows = scene.rows(&home);
    let install = &row(&rows, "firmware-utils").install;
    let reason = install.blocked.as_deref().unwrap_or_default();
    assert!(
        !install.automatic && reason.contains(&backup.display().to_string()),
        "(firmware-utils install, retained backup): expected no install button and the backup named | received automatic {} and blocked {reason:?}",
        install.automatic
    );

    fs::remove_dir_all(&backup).unwrap();
    let gradle = scene.root.path().join("cache").join(format!(
        ".bme-backup-gradle-{}",
        Profile::pinned().gradle_version
    ));
    fs::create_dir_all(&gradle).unwrap();
    let rows = scene.rows(&home);
    let reason = row(&rows, "firmware-utils").install.blocked.clone();
    assert!(
        reason
            .as_deref()
            .is_some_and(|text| text.contains(&gradle.display().to_string())),
        "(firmware-utils install, retained Gradle backup): expected the backup named | received {reason:?}"
    );
}

/// `path` written relative to the current directory, as a user might export `BME_FLASHROM`.
fn relative_to_current_directory(path: &Path) -> PathBuf {
    let current = std::env::current_dir().unwrap();
    let up: PathBuf = current.components().skip(1).map(|_| "..").collect();
    up.join(path.strip_prefix("/").unwrap())
}

#[test]
fn a_relative_flashrom_override_is_judged_by_the_file_root_would_run() {
    let mut scene = Scene::new(FakeInstalledTools::complete());
    let program = scene.root.path().join("flashrom");
    executable(&program);
    with_mode(&program, 0o755);
    let relative = relative_to_current_directory(&program);
    scene
        .variables
        .insert(FLASHROM_OVERRIDE, relative.clone().into_os_string());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let flashrom = row(&rows, "flashrom");
    assert_eq!(
        flashrom.health,
        Health::Ready,
        "(flashrom from relative BME_FLASHROM {}, mode 755): expected ready, because flash repeats it as an absolute path | received {}",
        relative.display(),
        flashrom.detail
    );
}

#[test]
fn a_root_refusal_suggests_chmod_only_for_a_loose_mode() {
    let root = tempfile::tempdir().unwrap();
    let reason = root_refusal(root.path()).unwrap_or_default();
    assert!(
        !reason.is_empty() && !reason.contains("chmod"),
        "(root refusal, directory): expected a refusal without the chmod fix | received {reason:?}"
    );
}

#[test]
fn a_missing_iasl_is_optional_and_names_its_package() {
    let mut scene = Scene::new(FakeInstalledTools::complete().without("iasl"));
    scene.configured_flashrom = Some("/opt/fr/flashrom".into());
    let rows = scene.rows(&pinned_ghidra(&scene));
    let iasl = row(&rows, "iasl");
    assert_eq!(iasl.health, Health::Missing);
    assert!(iasl.optional && !iasl.custom_location, "{iasl:?}");
    assert_eq!(
        iasl.install.command.as_deref(),
        Some("sudo apt install acpica-tools")
    );
    let text = render(&rows);
    assert!(
        text.contains("Every required tool is ready. Optional:")
            && text.contains("iasl (optional)"),
        "(tools status): expected iasl listed as optional | received {text}"
    );
}

#[test]
fn iasl_reports_its_version_when_installed() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let rows = scene.rows(&pinned_ghidra(&scene));
    assert_eq!(row(&rows, "iasl").version.as_deref(), Some("20250404"));
    assert_eq!(row(&rows, "iasl").health, Health::Ready);
}

#[test]
fn status_reports_exactly_the_rows_of_the_id_constant_in_order() {
    let scene = Scene::new(FakeInstalledTools::complete());
    let ghidra = pinned_ghidra(&scene);
    let rows = scene.rows(&ghidra);
    let ids: Vec<&str> = rows.iter().map(|row| row.id).collect();
    assert_eq!(
        ids, TOOL_IDS,
        "(tools status ids): expected the TOOL_IDS order | received {ids:?}"
    );
}
