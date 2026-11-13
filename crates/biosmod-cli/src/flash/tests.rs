//! Flash command tests. No test starts flashrom or reads hardware: chip access goes
//! through `FakeFlashChip` and system facts come from a `FakeSysfs` directory tree.

use super::flashrom::{
    FlashromOrigin, layout_text, parse_chips, parse_version, validate_chip, validate_programmer,
};
use super::host::{board_matches, describe_chip};
use super::*;
use crate::toolchain::{Finished, Invocation, Runner};
use biosmod_core::synthetic::Fixture;
use biosmod_host::testkit::FakeSysfs;
use std::cell::{Cell, RefCell};

const PAGE: usize = 0x1000;

/// A SPI flash chip behind a pretend flashrom: serves reads, applies writes, records calls.
struct FakeFlashChip {
    contents: RefCell<Vec<u8>>,
    calls: RefCell<Vec<String>>,
    /// Lines printed when a chip is detected.
    found: String,
    /// Fail every chip access with this output, like a missing programmer.
    refusal: Option<&'static str>,
    /// Flip one byte in the read with this 1-based number, like a loose clip.
    noisy_read: Cell<Option<usize>>,
    reads: Cell<usize>,
    /// Exit non-zero from the write after changing nothing.
    failing_write: Cell<bool>,
    /// Report success for the write but store a wrong byte.
    lossy_write: Cell<bool>,
    /// Replace the layout file with a directory after writing to inject an I/O failure.
    blocked_read_back_layout: Cell<bool>,
}

impl FakeFlashChip {
    fn holding(contents: &[u8]) -> FakeFlashChip {
        FakeFlashChip {
            contents: RefCell::new(contents.to_vec()),
            calls: RefCell::new(Vec::new()),
            found: format!(
                "Found Winbond flash chip \"W25Q128.V\" ({} kB, SPI) on ch341a_spi.\n",
                contents.len() / 1024
            ),
            refusal: None,
            noisy_read: Cell::new(None),
            reads: Cell::new(0),
            failing_write: Cell::new(false),
            lossy_write: Cell::new(false),
            blocked_read_back_layout: Cell::new(false),
        }
    }

    fn writes(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.contains(" -w "))
            .count()
    }
}

/// The byte ranges a `-l layout -i name` selection covers; the whole chip without one.
fn selected_ranges(words: &[String], length: usize) -> Vec<(usize, usize)> {
    let Some(layout) = words.iter().position(|word| word == "-l") else {
        return vec![(0, length)];
    };
    let text = fs::read_to_string(&words[layout + 1]).unwrap();
    let included: Vec<&String> = words
        .iter()
        .enumerate()
        .filter(|(index, _)| *index > 0 && words[index - 1] == "-i")
        .map(|(_, word)| word)
        .collect();
    text.lines()
        .filter_map(|line| {
            let (range, name) = line.split_once(' ')?;
            let (start, end) = range.split_once(':')?;
            included.iter().any(|wanted| *wanted == name).then(|| {
                (
                    usize::from_str_radix(start, 16).unwrap(),
                    usize::from_str_radix(end, 16).unwrap() + 1,
                )
            })
        })
        .collect()
}

impl Runner for FakeFlashChip {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let words = invocation.words();
        self.calls
            .borrow_mut()
            .push(format!("flashrom {}", words.join(" ")));
        let finish = |status: i32, stdout: String| {
            Ok(Finished {
                status: Some(status),
                stdout,
                ..Finished::default()
            })
        };
        if words == ["--version"] {
            return finish(0, "flashrom v1.6.0 on Linux 7.0.0 (x86_64)\n".into());
        }
        if let Some(refusal) = self.refusal {
            return finish(1, refusal.to_string());
        }
        let file_after = |flag: &str| {
            words
                .iter()
                .position(|word| word == flag)
                .map(|at| PathBuf::from(&words[at + 1]))
        };
        let mut contents = self.contents.borrow_mut();
        let ranges = selected_ranges(&words, contents.len());
        if let Some(file) = file_after("-r") {
            self.reads.set(self.reads.get() + 1);
            // Real flashrom leaves unread bytes unspecified; zero makes that visible.
            let mut dump = vec![0u8; contents.len()];
            for (start, end) in &ranges {
                dump[*start..*end].copy_from_slice(&contents[*start..*end]);
            }
            if self.noisy_read.get() == Some(self.reads.get()) {
                let at = ranges[ranges.len() - 1].0 + 5;
                dump[at] ^= 0x01;
            }
            fs::write(file, dump).unwrap();
            return finish(0, format!("{}Reading flash... done.\n", self.found));
        }
        if let Some(file) = file_after("-w") {
            if self.failing_write.get() {
                return finish(
                    3,
                    format!(
                        "{}Erase/write done from 0 to 0\nFAILED at 0x00003000!\n",
                        self.found
                    ),
                );
            }
            let image = fs::read(file).unwrap();
            for (start, end) in &ranges {
                contents[*start..*end].copy_from_slice(&image[*start..*end]);
            }
            if self.lossy_write.get() {
                let at = ranges[0].0 + 9;
                contents[at] ^= 0x80;
            }
            if self.blocked_read_back_layout.get() {
                let layout = file_after("-l").expect("(fault injection): expected a region layout");
                fs::remove_file(&layout).unwrap();
                fs::create_dir(&layout).unwrap();
            }
            return finish(0, format!("{}Verifying flash... VERIFIED.\n", self.found));
        }
        finish(0, format!("{}No operations were specified.\n", self.found))
    }
}

/// The flash diagnosis view of a [`FakeSysfs`] tree.
trait HostOf {
    fn host(&self, euid: u32) -> Host;
}

impl HostOf for FakeSysfs {
    fn host(&self, euid: u32) -> Host {
        Host {
            root: self.root().to_path_buf(),
            os: "linux",
            euid: Some(euid),
        }
    }
}

fn no_variables(_: &str) -> Option<OsString> {
    None
}

fn env<'a>(chip: &'a FakeFlashChip, host: Host) -> Env<'a> {
    Env {
        runner: chip,
        host,
        flashrom: Some(PathBuf::from("/usr/sbin/flashrom")),
        flashrom_flag: None,
        out: Out {
            json: true,
            quiet: true,
        },
        variable: &no_variables,
        boards: Vec::new(),
    }
}

fn root_env(chip: &FakeFlashChip) -> Env<'_> {
    env(
        chip,
        Host {
            root: PathBuf::from("/nonexistent/bme-test-sysfs"),
            os: "linux",
            euid: Some(0),
        },
    )
}

fn target_args(programmer: &str) -> FlashTargetArgs {
    FlashTargetArgs {
        programmer: programmer.into(),
        chip: None,
        flashrom: None,
    }
}

/// A full dump: descriptor page, two ME pages, then a synthetic BIOS region.
fn dump_with_descriptor(follower_kind: u8) -> Vec<u8> {
    let mut bios = Fixture::new(follower_kind).image;
    bios.resize(bios.len().next_multiple_of(PAGE), 0xFF);
    let pages = 3 + bios.len() / PAGE;
    let mut dump = vec![0xFFu8; PAGE];
    dump[0x10..0x14].copy_from_slice(&0x0FF0_A55Au32.to_le_bytes());
    // FLMAP0: the region table starts at 0x40.
    dump[0x14..0x18].copy_from_slice(&(0x04u32 << 16).to_le_bytes());
    let region = |base: u32, limit: u32| ((limit << 16) | base).to_le_bytes();
    dump[0x40..0x44].copy_from_slice(&region(0, 0));
    dump[0x44..0x48].copy_from_slice(&region(3, pages as u32 - 1));
    dump[0x48..0x4C].copy_from_slice(&region(1, 2));
    // Unused regions have a base above their limit.
    dump[0x4C..0x50].copy_from_slice(&region(0x7FFF, 0));
    dump[0x50..0x54].copy_from_slice(&region(0x7FFF, 0));
    dump.extend(std::iter::repeat_n(0x5A, 2 * PAGE));
    dump.extend(bios);
    dump
}

struct Files {
    directory: tempfile::TempDir,
}

impl Files {
    fn new() -> Files {
        Files {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.directory.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
}

fn write_args(image: &Path, backup: &Path, confirm: Option<&str>) -> FlashWriteArgs {
    FlashWriteArgs {
        image: image.to_path_buf(),
        backup: backup.to_path_buf(),
        target: target_args("ch341a_spi"),
        regions: Vec::new(),
        whole_chip: false,
        dry_run: confirm.is_none(),
        confirm: confirm.map(|digest| digest.parse().unwrap()),
    }
}

#[test]
fn found_lines_become_chips() {
    let output = "flashrom v1.6.0 on Linux\nFound Winbond flash chip \"W25Q128.V\" (16384 kB, SPI) on ch341a_spi.\nFound Winbond flash chip \"W25Q128.V\" (16384 kB, SPI) on ch341a_spi.\nFound Macronix flash chip \"MX25L12835F/MX25L12845E\" (16384 kB, SPI) mapped at physical address 0xff000000.\nFound chipset \"Intel Q87\".\nFound Odd flash chip \"X\" (many kB, SPI)\n";
    let chips = parse_chips(output);
    assert_eq!(
        chips.iter().map(describe_chip).collect::<Vec<_>>(),
        [
            "Winbond W25Q128.V, 16777216 bytes, SPI",
            "Macronix MX25L12835F/MX25L12845E, 16777216 bytes, SPI"
        ]
    );
    assert!(parse_chips("No EEPROM/flash device found.").is_empty());
}

#[test]
fn banner_version_is_extracted() {
    assert_eq!(
        parse_version("flashrom v1.6.0 on Linux 7.0.0-42-generic (x86_64)\n").as_deref(),
        Some("1.6.0")
    );
    assert_eq!(
        parse_version("flashrom 1.4.0-devel (git:v1.4.0) on Linux").as_deref(),
        Some("1.4.0-devel")
    );
    assert_eq!(parse_version("flashrom is free software"), None);
}

#[test]
fn layout_lines_use_inclusive_ends() {
    let regions = firmware::descriptor_regions(&dump_with_descriptor(0x07)).unwrap();
    let text = layout_text(&regions);
    assert!(
        text.starts_with("00000000:00000fff descriptor\n00003000:"),
        "(layout): expected descriptor then bios lines | received {text}"
    );
    assert!(text.contains("00001000:00002fff me\n"), "{text}");
}

#[test]
fn programmer_and_chip_names_cannot_smuggle_options() {
    for accepted in [
        "internal",
        "ch341a_spi",
        "linux_mtd:dev=0",
        "ft2232_spi:type=2232H,port=A",
        "internal:laptop=force_I_want_a_brick",
    ] {
        validate_programmer(accepted).unwrap();
    }
    for rejected in [
        "",
        "-p",
        "--help",
        "ch341a spi",
        "internal;reboot",
        "9bad",
        ":dev=0",
    ] {
        let error = validate_programmer(rejected).unwrap_err();
        assert_eq!(error.code, Code::Usage, "{rejected:?}: {error}");
        assert!(error.message.contains(&format!("{rejected:?}")), "{error}");
    }
    validate_chip("MX25L6436E/MX25L6445E/MX25L6465E").unwrap();
    for rejected in ["", "-c", "W25Q128;x"] {
        assert_eq!(validate_chip(rejected).unwrap_err().code, Code::Usage);
    }
}

#[test]
fn command_lines_name_programmer_chip_and_regions() {
    let target = Target {
        flashrom: "/usr/sbin/flashrom".into(),
        programmer: "ch341a_spi".into(),
        chip: Some("W25Q128.V".into()),
    };
    let regions = ["descriptor", "bios"];
    let selection = Selection {
        layout: Path::new("/tmp/layout.txt"),
        regions: &regions,
    };
    assert_eq!(
        target
            .invocation(Some(selection), Operation::Read(Path::new("/tmp/d.bin")))
            .words(),
        [
            "-p",
            "ch341a_spi",
            "-c",
            "W25Q128.V",
            "-l",
            "/tmp/layout.txt",
            "-i",
            "descriptor",
            "-i",
            "bios",
            "-r",
            "/tmp/d.bin"
        ]
    );
    let selected_write = target
        .invocation(Some(selection), Operation::Write(Path::new("/tmp/i.bin")))
        .words();
    assert!(
        selected_write.iter().any(|word| word == "--noverify-all")
            && !selected_write.iter().any(|word| word == "--noverify"),
        "(region write): expected --noverify-all with selected-region verification | received {selected_write:?}"
    );
    assert_eq!(
        target
            .invocation(None, Operation::Write(Path::new("/tmp/i.bin")))
            .words(),
        ["-p", "ch341a_spi", "-c", "W25Q128.V", "-w", "/tmp/i.bin"]
    );
    assert_eq!(
        target.invocation(None, Operation::Version).words(),
        ["--version"]
    );
    assert_eq!(
        target.invocation(None, Operation::Probe).words(),
        ["-p", "ch341a_spi", "-c", "W25Q128.V"]
    );
}

#[test]
fn flashrom_is_found_by_override_then_config_then_path() {
    let directory = tempfile::tempdir().unwrap();
    let name = format!("flashrom{}", std::env::consts::EXE_SUFFIX);
    fs::write(directory.path().join(&name), "").unwrap();
    let path = directory.path().as_os_str().to_os_string();
    let configured = Path::new("/opt/configured/flashrom");
    let on_path = |key: &str| (key == "PATH").then(|| path.clone());
    assert_eq!(
        resolve_flashrom(&on_path, None),
        Some((directory.path().join(&name), FlashromOrigin::Path)),
        "PATH lookup"
    );
    assert_eq!(
        resolve_flashrom(&on_path, Some(configured)),
        Some((configured.to_path_buf(), FlashromOrigin::Config)),
        "configuration beats PATH"
    );
    let overridden = |key: &str| match key {
        "BME_FLASHROM" => Some("/opt/flashrom".into()),
        _ => Some(path.clone()),
    };
    assert_eq!(
        resolve_flashrom(&overridden, Some(configured)),
        Some((PathBuf::from("/opt/flashrom"), FlashromOrigin::Environment)),
        "BME_FLASHROM beats configuration"
    );
}

#[test]
fn doctor_identifies_the_board_and_passes_an_open_system() {
    let sysfs = FakeSysfs::mr9a()
        .file("sys/class/mtd/mtd0/name", "BIOS\n")
        .file("sys/class/mtd/mtd0/size", "16777216\n")
        .file("sys/class/mtd/mtd0/type", "nor\n")
        .directory("sys/class/mtd/mtd0ro")
        .file("sys/bus/usb/devices/1-4/idVendor", "1a86\n")
        .file("sys/bus/usb/devices/1-4/idProduct", "5512\n");
    let chip = FakeFlashChip::holding(&[0; 16]);
    let mut env = env(&chip, sysfs.host(0));
    env.boards = bundled_boards();
    let reply = doctor(&env, "ch341a_spi").unwrap();
    assert_eq!(reply.data["ready"], true, "{}", reply.text);
    assert_eq!(reply.data["system"]["board_name"], "E5-MR9A PRO");
    assert_eq!(
        reply.data["catalog_boards"][0]["id"], "machinist-mr9a-pro-q87-rev-1.2",
        "(catalog boards): expected the MR9A profile | received {}",
        reply.data["catalog_boards"]
    );
    assert_eq!(reply.data["catalog_boards"][0]["revision_matches"], true);
    assert_eq!(reply.data["flashrom"]["version"], "1.6.0");
    let state = |name: &str| {
        reply.data["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["check"] == name)
            .unwrap_or_else(|| {
                panic!(
                    "(checks): expected {name} | received {}",
                    reply.data["checks"]
                )
            })
            .clone()
    };
    assert_eq!(state("privileges")["state"], "pass");
    assert_eq!(state("usb-programmer")["state"], "pass");
    assert!(
        state("usb-programmer")["detail"]
            .as_str()
            .unwrap()
            .contains("--programmer ch341a_spi")
    );
    assert_eq!(
        state("mtd")["detail"],
        "mtd0 \"BIOS\" 16777216 bytes (nor): --programmer linux_mtd:dev=0"
    );
    assert_eq!(
        chip.calls.borrow().as_slice(),
        ["flashrom --version"],
        "(doctor): expected no programmer access"
    );
}

#[test]
fn doctor_fails_internal_access_under_lockdown_and_without_flashrom() {
    let sysfs = FakeSysfs::new()
        .file(
            "sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        )
        .file(
            "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            [6, 0, 0, 0, 1],
        );
    let chip = FakeFlashChip::holding(&[0; 16]);
    let mut env = env(&chip, sysfs.host(1000));
    env.flashrom = None;
    let reply = doctor(&env, "internal").unwrap();
    assert_eq!(reply.data["ready"], false);
    let states: Vec<(String, String)> = reply.data["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| {
            (
                check["check"].as_str().unwrap().to_string(),
                check["state"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for expected in [
        ("flashrom", "fail"),
        ("privileges", "warn"),
        ("kernel-lockdown", "fail"),
        ("secure-boot", "warn"),
    ] {
        assert!(
            states.contains(&(expected.0.into(), expected.1.into())),
            "(checks): expected {expected:?} | received {states:?}"
        );
    }
    assert!(reply.text.contains("Fix the FAIL lines"), "{}", reply.text);
    // The same lockdown does not stop an external programmer.
    let external = env.host.checks("ch341a_spi", None);
    let lockdown = external
        .iter()
        .find(|c| c.check == "kernel-lockdown")
        .unwrap();
    assert_eq!(lockdown.state, State::Info);
}

#[test]
fn doctor_reads_bios_write_protection_bits() {
    let config = |value: u8| {
        let mut bytes = vec![0u8; 256];
        bytes[0xDC] = value;
        bytes
    };
    for (value, state, wording) in [
        (0x00, State::Pass, "SMM_BWP=0"),
        (0x02, State::Warn, "veto"),
        (0x2A, State::Warn, "only be written from SMM"),
    ] {
        let sysfs = FakeSysfs::mr9a()
            .file("sys/bus/pci/devices/0000:00:1f.0/vendor", "0x8086\n")
            .file("sys/bus/pci/devices/0000:00:1f.0/config", config(value));
        let checks = sysfs.host(0).checks("internal", None);
        let check = checks
            .iter()
            .find(|c| c.check == "bios-write-protection")
            .unwrap();
        assert_eq!(
            check.state, state,
            "BIOS_CNTL {value:#04x}: {}",
            check.detail
        );
        assert!(check.detail.contains(wording), "{}", check.detail);
    }
    // An unprivileged read stops after the first 64 bytes.
    let sysfs = FakeSysfs::mr9a()
        .file("sys/bus/pci/devices/0000:00:1f.0/vendor", "0x8086\n")
        .file("sys/bus/pci/devices/0000:00:1f.0/config", [0u8; 64])
        .directory("sys/module/spi_intel");
    let checks = sysfs.host(1000).checks("internal", None);
    let detail = |name: &str| &checks.iter().find(|c| c.check == name).unwrap().detail;
    assert!(detail("bios-write-protection").contains("only readable as root"));
    assert!(detail("internal-access").contains("iomem=relaxed"));
}

#[test]
fn board_match_needs_vendor_and_model() {
    let dmi = FakeSysfs::mr9a().host(0).dmi();
    assert!(board_matches(&dmi, "Machinist", "E5-MR9A PRO"));
    assert!(!board_matches(&dmi, "Machinist", "PR9"));
    assert!(!board_matches(&dmi, "Other", "E5-MR9A PRO"));
}

#[test]
fn probe_reports_chips_and_explains_a_silent_programmer() {
    let chip = FakeFlashChip::holding(&[0; 2048]);
    let reply = probe(&root_env(&chip), &target_args("ch341a_spi")).unwrap();
    assert_eq!(reply.data["chips"][0]["name"], "W25Q128.V");
    assert_eq!(reply.data["chips"][0]["size_bytes"], 2048);
    assert_eq!(reply.data["ambiguous"], false);
    assert_eq!(chip.calls.borrow().as_slice(), ["flashrom -p ch341a_spi"]);

    let mut silent = FakeFlashChip::holding(&[0; 2048]);
    silent.refusal = Some("No EEPROM/flash device found.\n");
    let error = probe(&root_env(&silent), &target_args("ch341a_spi")).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed, "{error}");
    assert!(
        error
            .message
            .contains("expected exit status 0 | received exit status 1")
            && error.message.contains("clip orientation"),
        "{error}"
    );

    let mut denied = FakeFlashChip::holding(&[0; 2048]);
    denied.refusal = Some(
        "Make sure you are running flashrom with root privileges.\nError: Programmer initialization failed.\n",
    );
    let unprivileged = env(&denied, FakeSysfs::new().host(1000));
    let error = probe(&unprivileged, &target_args("internal")).unwrap_err();
    assert!(error.message.contains("run with sudo"), "{error}");

    let mut missing = root_env(&chip);
    missing.flashrom = None;
    let error = probe(&missing, &target_args("internal")).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable, "{error}");
}

#[test]
fn chip_commands_are_refused_outside_linux() {
    let chip = FakeFlashChip::holding(&[0; 16]);
    let mut env = root_env(&chip);
    env.host.os = "macos";
    let error = dispatch(&env, FlashCommand::Probe(target_args("internal"))).unwrap_err();
    assert_eq!(error.code, Code::PlatformUnsupported, "{error}");
    assert!(
        error.message.contains("expected linux | received macos"),
        "{error}"
    );
    assert!(chip.calls.borrow().is_empty());
    let reply = dispatch(
        &env,
        FlashCommand::Doctor {
            programmer: "internal".into(),
            flashrom: None,
        },
    )
    .unwrap();
    assert_eq!(reply.data["ready"], false);
}

#[test]
fn backup_publishes_two_identical_reads() {
    let dump = dump_with_descriptor(0x07);
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let output = files.path("dump.bin");
    let reply = backup(&root_env(&chip), &target_args("ch341a_spi"), &[], &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), dump);
    assert_eq!(reply.data["sha256"], sha256_hex(&dump));
    assert_eq!(reply.data["reads"], 2);
    assert_eq!(reply.data["partial"], false);
    assert_eq!(reply.data["chip"]["name"], "W25Q128.V");
    assert!(reply.data["firmware_volumes"].as_u64().unwrap() > 0);
    assert_eq!(reply.data["layout"][1]["name"], "bios");
    assert_eq!(chip.reads.get(), 2);

    let error = backup(&root_env(&chip), &target_args("ch341a_spi"), &[], &output).unwrap_err();
    assert_eq!(error.code, Code::OutputExists, "{error}");
    assert_eq!(
        chip.reads.get(),
        2,
        "(existing output): expected refusal before any chip read"
    );
}

#[test]
fn backup_refuses_unstable_and_blank_reads() {
    let dump = dump_with_descriptor(0x07);
    let files = Files::new();
    let chip = FakeFlashChip::holding(&dump);
    chip.noisy_read.set(Some(2));
    let output = files.path("noisy.bin");
    let error = backup(&root_env(&chip), &target_args("ch341a_spi"), &[], &output).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(
        error
            .message
            .contains("expected two identical reads | received a difference at 0x5"),
        "{error}"
    );
    assert!(!output.exists());

    let blank = FakeFlashChip::holding(&vec![0xFF; 4 * PAGE]);
    let output = files.path("blank.bin");
    let error = backup(&root_env(&blank), &target_args("ch341a_spi"), &[], &output).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(error.message.contains("received only 0xff"), "{error}");
    assert!(!output.exists());
}

#[test]
fn backup_of_selected_regions_reads_around_the_rest() {
    let dump = dump_with_descriptor(0x07);
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let output = files.path("bios-only.bin");
    let reply = backup(
        &root_env(&chip),
        &target_args("internal"),
        &["bios".into()],
        &output,
    )
    .unwrap();
    let saved = fs::read(&output).unwrap();
    assert_eq!(saved[..PAGE], dump[..PAGE], "descriptor is always kept");
    assert_eq!(saved[3 * PAGE..], dump[3 * PAGE..], "bios region");
    assert!(
        saved[PAGE..3 * PAGE].iter().all(|byte| *byte == 0xFF),
        "(me region): expected erased filler for unread bytes"
    );
    assert_eq!(reply.data["partial"], true);
    assert_eq!(reply.data["regions_read"], json!(["descriptor", "bios"]));
    assert!(
        chip.calls.borrow().iter().all(|call| call.contains(" -l ")),
        "(calls): expected every read to use a layout | received {:?}",
        chip.calls.borrow()
    );

    let error = backup(
        &root_env(&chip),
        &target_args("internal"),
        &["ec".into()],
        &files.path("ec.bin"),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::Usage, "{error}");
    assert!(
        error
            .message
            .contains("region \"ec\": expected one of descriptor, bios, me"),
        "{error}"
    );

    let bare = FakeFlashChip::holding(&Fixture::new(0x07).image);
    let error = backup(
        &root_env(&bare),
        &target_args("internal"),
        &["bios".into()],
        &files.path("bare.bin"),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
}

#[test]
fn dry_run_checks_the_chip_and_writes_nothing() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let (image, saved) = (
        files.put("patched.bin", &patched),
        files.put("dump.bin", &dump),
    );
    let reply = write(&root_env(&chip), &write_args(&image, &saved, None)).unwrap();
    assert_eq!(reply.data["dry_run"], true);
    assert_eq!(reply.data["written"], false);
    assert_eq!(reply.data["confirm"], sha256_hex(&patched));
    assert_eq!(reply.data["regions"][0]["name"], "bios");
    assert!(reply.data["regions"][0]["changed_bytes"].as_u64().unwrap() > 0);
    assert_eq!(chip.writes(), 0);
    assert_eq!(*chip.contents.borrow(), dump);
    assert!(
        chip.calls.borrow()[0].contains("-i descriptor -i bios -r"),
        "(pre-read): expected descriptor and bios | received {:?}",
        chip.calls.borrow()
    );
}

#[test]
fn confirmed_write_changes_only_the_bios_region_and_reads_back() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let (image, saved) = (
        files.put("patched.bin", &patched),
        files.put("dump.bin", &dump),
    );
    let digest = sha256_hex(&patched);
    let reply = write(&root_env(&chip), &write_args(&image, &saved, Some(&digest))).unwrap();
    assert_eq!(
        (&reply.data["written"], &reply.data["verified"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(*chip.contents.borrow(), patched);
    let calls = chip.calls.borrow();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(
        calls[1].contains("-i bios --noverify-all -w") && !calls[1].contains("descriptor"),
        "(write): expected only the bios region | received {}",
        calls[1]
    );
    assert!(calls[2].contains("-i bios -r"), "{}", calls[2]);
}

#[test]
fn write_requires_the_image_digest_before_touching_the_chip() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let (image, saved) = (
        files.put("patched.bin", &patched),
        files.put("dump.bin", &dump),
    );
    let wrong = sha256_hex(&dump);
    for confirm in [None, Some(wrong.as_str())] {
        let mut args = write_args(&image, &saved, confirm);
        args.dry_run = false;
        let error = write(&root_env(&chip), &args).unwrap_err();
        assert_eq!(error.code, Code::FlashRefused, "{error}");
        assert!(
            error.message.contains(&format!(
                "--confirm: expected the image SHA-256 {} | received {}",
                sha256_hex(&patched),
                confirm.unwrap_or("none")
            )),
            "{error}"
        );
    }
    assert!(chip.calls.borrow().is_empty(), "{:?}", chip.calls.borrow());
}

#[test]
fn write_refuses_a_backup_that_is_not_the_chip() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let mut stale = dump.clone();
    stale[3 * PAGE + 0x40] ^= 0xFF;
    let chip = FakeFlashChip::holding(&stale);
    let files = Files::new();
    let (image, saved) = (
        files.put("patched.bin", &patched),
        files.put("dump.bin", &dump),
    );
    let digest = sha256_hex(&patched);
    let error = write(&root_env(&chip), &write_args(&image, &saved, Some(&digest))).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(
        error
            .message
            .contains("chip at 0x3040 (bios): expected the backup byte"),
        "{error}"
    );
    assert_eq!(chip.writes(), 0);
    assert_eq!(*chip.contents.borrow(), stale);
}

#[test]
fn write_refuses_images_that_change_unwritten_regions_or_do_not_parse() {
    let dump = dump_with_descriptor(0x07);
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let saved = files.put("dump.bin", &dump);

    let mut touched_me = dump_with_descriptor(0x06);
    touched_me[PAGE + 7] = 0x00;
    let image = files.put("me.bin", &touched_me);
    let error = write(&root_env(&chip), &write_args(&image, &saved, None)).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(
        error.message.contains("image at 0x1007 (me): expected the backup byte 0x5a outside the written regions | received 0x00"),
        "{error}"
    );
    // Naming the region makes the same image acceptable.
    let mut args = write_args(&image, &saved, None);
    args.regions = vec!["bios".into(), "me".into()];
    let reply = write(&root_env(&chip), &args).unwrap();
    assert_eq!(reply.data["regions"][1]["name"], "me");
    assert_eq!(reply.data["regions"][1]["changed_bytes"], 1);

    let garbage = files.put("garbage.bin", &vec![0x11; dump.len()]);
    let error = write(&root_env(&chip), &write_args(&garbage, &saved, None)).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(
        error
            .message
            .contains("expected a firmware image that parses"),
        "{error}"
    );

    let short = files.put("short.bin", &dump[..dump.len() - PAGE]);
    let error = write(&root_env(&chip), &write_args(&short, &saved, None)).unwrap_err();
    assert!(
        error.message.contains(&format!(
            "image size: expected {} bytes like the backup | received {}",
            dump.len(),
            dump.len() - PAGE
        )),
        "{error}"
    );
    assert_eq!(chip.writes(), 0);
}

#[test]
fn chips_without_a_descriptor_need_whole_chip() {
    let (old, new) = (Fixture::new(0x07).image, Fixture::new(0x06).image);
    let chip = FakeFlashChip::holding(&old);
    let files = Files::new();
    let (image, saved) = (files.put("new.bin", &new), files.put("old.bin", &old));
    let digest = sha256_hex(&new);
    let error = write(&root_env(&chip), &write_args(&image, &saved, Some(&digest))).unwrap_err();
    assert_eq!(error.code, Code::FlashRefused, "{error}");
    assert!(error.message.contains("pass --whole-chip"), "{error}");

    let mut args = write_args(&image, &saved, Some(&digest));
    args.whole_chip = true;
    let reply = write(&root_env(&chip), &args).unwrap();
    assert_eq!(reply.data["whole_chip"], true);
    assert_eq!(reply.data["regions"][0]["name"], "chip");
    assert_eq!(*chip.contents.borrow(), new);
    assert!(
        chip.calls
            .borrow()
            .iter()
            .all(|call| !call.contains(" -l ")),
        "{:?}",
        chip.calls.borrow()
    );
}

#[test]
fn failed_and_unverified_writes_report_flash_failed_with_recovery() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let files = Files::new();
    let (image, saved) = (
        files.put("patched.bin", &patched),
        files.put("dump.bin", &dump),
    );
    let digest = sha256_hex(&patched);

    let failing = FakeFlashChip::holding(&dump);
    failing.failing_write.set(true);
    let error = write(
        &root_env(&failing),
        &write_args(&image, &saved, Some(&digest)),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::FlashFailed, "{error}");
    assert!(
        error
            .message
            .contains("received exit status 3: FAILED at 0x00003000!")
            && error.message.contains("write the backup back"),
        "{error}"
    );
    assert_eq!(error.details.unwrap()["step"], "write");

    let lossy = FakeFlashChip::holding(&dump);
    lossy.lossy_write.set(true);
    let error = write(
        &root_env(&lossy),
        &write_args(&image, &saved, Some(&digest)),
    )
    .unwrap_err();
    assert_eq!(error.code, Code::FlashFailed, "{error}");
    assert!(
        error
            .message
            .contains("read-back after writing: chip at 0x3009 (bios): expected the image byte"),
        "{error}"
    );
}

#[test]
fn layout_io_failure_after_writing_reports_flash_failed_with_recovery() {
    let (dump, patched) = (dump_with_descriptor(0x07), dump_with_descriptor(0x06));
    let chip = FakeFlashChip::holding(&dump);
    chip.blocked_read_back_layout.set(true);
    let files = Files::new();
    let image = files.put("patched.bin", &patched);
    let saved = files.put("dump.bin", &dump);
    let digest = sha256_hex(&patched);

    let error = write(&root_env(&chip), &write_args(&image, &saved, Some(&digest))).unwrap_err();
    assert_eq!(
        *chip.contents.borrow(),
        patched,
        "(chip): expected the completed write before layout failure"
    );
    assert_eq!(chip.writes(), 1);
    assert_eq!(
        error.code,
        Code::FlashFailed,
        "(post-write layout failure): expected FLASH_FAILED | received {error}"
    );
    assert!(
        error.message.contains("read-back layout after writing")
            && error.message.contains("write the backup back"),
        "{error}"
    );
    assert_eq!(error.details.unwrap()["step"], "read-back layout");
}

#[test]
fn invoking_user_comes_from_pkexec_or_sudo() {
    let pkexec = |key: &str| (key == "PKEXEC_UID").then(|| OsString::from("1000"));
    assert_eq!(invoking_user(&pkexec), Some((1000, None)));
    let sudo = |key: &str| match key {
        "SUDO_UID" => Some(OsString::from("1001")),
        "SUDO_GID" => Some(OsString::from("1002")),
        _ => None,
    };
    assert_eq!(invoking_user(&sudo), Some((1001, Some(1002))));
    assert_eq!(invoking_user(&no_variables), None);
    let garbage = |key: &str| (key == "SUDO_UID").then(|| OsString::from("root"));
    assert_eq!(invoking_user(&garbage), None);
}

#[test]
fn unprivileged_backups_keep_their_owner() {
    let dump = dump_with_descriptor(0x07);
    let chip = FakeFlashChip::holding(&dump);
    let files = Files::new();
    let sudo = |key: &str| (key == "SUDO_UID").then(|| OsString::from("4242"));
    let mut env = env(&chip, FakeSysfs::new().host(1000));
    env.variable = &sudo;
    let reply = backup(
        &env,
        &target_args("ch341a_spi"),
        &[],
        &files.path("dump.bin"),
    )
    .unwrap();
    assert_eq!(
        reply.data["owner_uid"],
        Value::Null,
        "(owner): expected no ownership change without root"
    );
}

fn executable_file(directory: &Path, name: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join(name);
    std::fs::write(&path, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn root_runs_only_an_absolute_regular_file_nobody_else_can_write() {
    let directory = tempfile::tempdir().unwrap();
    let good = executable_file(directory.path(), "flashrom", 0o755);
    super::flashrom::validate_privileged_flashrom(&good).unwrap();

    let writable = executable_file(directory.path(), "loose", 0o757);
    let error = super::flashrom::validate_privileged_flashrom(&writable).unwrap_err();
    assert!(
        error.message.contains("mode 757") && error.message.contains("loose"),
        "(root flashrom): expected the mode and path of a world-writable file | received {}",
        error.message
    );
    let error =
        super::flashrom::validate_privileged_flashrom(Path::new("relative/flashrom")).unwrap_err();
    assert!(error.message.contains("not absolute"), "{}", error.message);
    let error = super::flashrom::validate_privileged_flashrom(directory.path()).unwrap_err();
    assert!(
        error.message.contains("not a regular file"),
        "{}",
        error.message
    );
}

#[test]
fn shell_words_quote_only_what_the_shell_would_split() {
    use super::flashrom::shell_word;
    assert_eq!(
        shell_word(Path::new("/opt/fr/flashrom")),
        "/opt/fr/flashrom"
    );
    assert_eq!(
        shell_word(Path::new("/opt/my tools/fr")),
        "'/opt/my tools/fr'"
    );
    assert_eq!(shell_word(Path::new("/o'k/fr")), "'/o'\\''k/fr'");
}

#[test]
fn a_relative_flashrom_is_repeated_as_an_absolute_path_for_root() {
    let from_environment = |key: &str| (key == "BME_FLASHROM").then(|| "bin/flashrom".into());
    let (path, flag) = choose_flashrom(false, None, &from_environment, None).unwrap();
    assert_eq!(path, Some(PathBuf::from("bin/flashrom")));
    let flag = flag.expect("(BME_FLASHROM): expected a repeated flag | received none");
    assert!(
        flag.is_absolute() && flag.ends_with("bin/flashrom"),
        "(BME_FLASHROM bin/flashrom): expected an absolute flag that root accepts | received {}",
        flag.display()
    );
    let typed = PathBuf::from("bin/flashrom");
    let (_, flag) = choose_flashrom(false, Some(&typed), &no_variables, None).unwrap();
    assert!(
        flag.as_deref().is_some_and(Path::is_absolute),
        "(--flashrom bin/flashrom): expected an absolute flag | received {flag:?}"
    );
}

#[test]
fn saved_and_typed_flashrom_paths_are_both_repeated_for_root() {
    let directory = tempfile::tempdir().unwrap();
    let saved = executable_file(directory.path(), "saved-flashrom", 0o755);
    let typed = executable_file(directory.path(), "typed-flashrom", 0o755);

    let (path, flag) = choose_flashrom(false, None, &no_variables, Some(&saved)).unwrap();
    assert_eq!(
        (path, flag),
        (Some(saved.clone()), Some(saved.clone())),
        "(saved flashrom): expected the saved path and a flag that repeats it"
    );
    let (path, flag) = choose_flashrom(false, Some(&typed), &no_variables, Some(&saved)).unwrap();
    assert_eq!((path, flag), (Some(typed.clone()), Some(typed.clone())));
    let (path, flag) = choose_flashrom(false, None, &no_variables, None).unwrap();
    assert_eq!(
        flag, None,
        "(path lookup): expected no flag for a PATH result, path {path:?}"
    );
}

#[test]
fn root_refuses_a_loose_flashrom_before_running_anything() {
    let directory = tempfile::tempdir().unwrap();
    let loose = executable_file(directory.path(), "flashrom", 0o777);
    let error = choose_flashrom(true, Some(&loose), &no_variables, None).unwrap_err();
    assert!(error.message.contains("mode 777"), "{}", error.message);
    let from_environment = {
        let value = loose.clone().into_os_string();
        move |key: &str| (key == "BME_FLASHROM").then(|| value.clone())
    };
    let error = choose_flashrom(true, None, &from_environment, None).unwrap_err();
    assert!(error.message.contains("mode 777"), "{}", error.message);
}

#[test]
fn the_probe_next_step_repeats_the_saved_flashrom() {
    let chip = FakeFlashChip::holding(&[0; 2048]);
    let mut env = root_env(&chip);
    env.flashrom_flag = Some(PathBuf::from("/opt/my tools/flashrom"));
    let reply = probe(&env, &target_args("ch341a_spi")).unwrap();
    assert!(
        reply.text.contains(
            "Next: sudo bme flash backup --programmer ch341a_spi --flashrom '/opt/my tools/flashrom' -o dump.bin"
        ),
        "(flash probe): expected the next step to repeat the saved flashrom | received {}",
        reply.text
    );
    env.flashrom_flag = None;
    let reply = probe(&env, &target_args("ch341a_spi")).unwrap();
    assert!(
        reply
            .text
            .contains("backup --programmer ch341a_spi -o dump.bin"),
        "(flash probe): expected no flag without a saved flashrom | received {}",
        reply.text
    );
}

#[test]
fn the_doctor_next_step_repeats_the_flashrom_path_for_a_root_rerun() {
    let sysfs = FakeSysfs::mr9a()
        .file("sys/class/mtd/mtd0/name", "BIOS\n")
        .file("sys/class/mtd/mtd0/size", "16777216\n")
        .file("sys/class/mtd/mtd0/type", "nor\n")
        .directory("sys/class/mtd/mtd0ro")
        .file("sys/bus/usb/devices/1-4/idVendor", "1a86\n")
        .file("sys/bus/usb/devices/1-4/idProduct", "5512\n");
    let chip = FakeFlashChip::holding(&[0; 16]);
    let mut env = env(&chip, sysfs.host(0));
    env.flashrom_flag = Some(PathBuf::from("/opt/my tools/flashrom"));
    let reply = doctor(&env, "ch341a_spi").unwrap();
    assert!(
        reply.text.contains(
            "Next: sudo bme flash probe --flashrom '/opt/my tools/flashrom', then sudo bme flash backup --flashrom '/opt/my tools/flashrom' -o dump.bin"
        ),
        "(flash doctor): expected the next step to repeat the flashrom path | received {}",
        reply.text
    );
}

/// A configuration file that does not parse, as `Config::load` reports it.
fn broken_configuration() -> Result<Config> {
    Err(Error::new(
        Code::Usage,
        "config.toml: expected `=` at line 3",
    ))
}

#[test]
fn a_broken_configuration_stops_a_flash_command_that_would_read_tools_flashrom() {
    let result = configured_flashrom(false, None, &no_variables, broken_configuration);
    let error = result.expect_err(
        "(flash, broken config.toml, no override): expected an error | received a PATH fallback",
    );
    assert!(
        error
            .message
            .contains("config.toml: expected `=` at line 3")
            && error.message.contains("--flashrom"),
        "(flash, broken config.toml): expected the load error and the --flashrom way out | received {}",
        error.message
    );
}

#[test]
fn a_broken_configuration_is_not_read_when_an_override_or_root_chooses_flashrom() {
    let typed = PathBuf::from("/opt/fr/flashrom");
    let from_environment = |key: &str| (key == "BME_FLASHROM").then(|| "/opt/env/flashrom".into());
    let unread = || -> Result<Config> { panic!("(flash): expected config.toml left unread") };
    for (case, root, flag, variable) in [
        (
            "--flashrom",
            false,
            Some(&typed),
            &no_variables as &dyn Fn(&str) -> Option<OsString>,
        ),
        ("BME_FLASHROM", false, None, &from_environment),
        ("root", true, None, &no_variables),
    ] {
        let configured = configured_flashrom(root, flag, variable, unread);
        assert!(
            matches!(configured, Ok(None)),
            "(flash, {case}): expected no configured flashrom | received {configured:?}"
        );
    }
}

#[test]
fn the_doctor_warns_when_root_would_refuse_the_saved_flashrom() {
    let sysfs = FakeSysfs::mr9a();
    let directory = tempfile::tempdir().unwrap();
    let program = executable_file(directory.path(), "flashrom", 0o775);
    let chip = FakeFlashChip::holding(&[0; 16]);
    let mut env = env(&chip, sysfs.host(1000));
    env.flashrom = Some(program.clone());
    env.flashrom_flag = Some(program.clone());
    let reply = doctor(&env, "internal").unwrap();
    let warning = reply.data["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["check"] == "flashrom-root")
        .cloned();
    assert!(
        warning
            .as_ref()
            .is_some_and(|check| check["state"] == "warn"
                && check["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("mode 775")),
        "(flash doctor, saved flashrom mode 775): expected a flashrom-root warning naming the mode | received {}",
        reply.data["checks"]
    );
}

#[test]
fn a_flash_command_without_a_home_directory_reads_no_configuration() {
    let configuration = user_configuration(&|_| None);
    assert!(
        configuration
            .as_ref()
            .is_ok_and(|config| config.tools.flashrom.is_none()),
        "(flash, no HOME or XDG variables): expected the default configuration | received {:?}",
        configuration.err()
    );
}
