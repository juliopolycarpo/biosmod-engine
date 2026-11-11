//! `bme flash`: diagnose the system, find the chip, back it up and write an image.
//!
//! flashrom does every chip access. This module decides when a write is allowed:
//! the image must parse, the backup must equal what the chip holds right now, the
//! image may differ from the backup only inside the regions being written, and the
//! caller must repeat the image digest. The chip is read back after the write.

mod flashrom;
mod host;
#[cfg(all(test, unix))]
mod tests;

pub use flashrom::{
    Chip, FLASHROM_OVERRIDE, Operation, SBIN_DIRECTORIES, Selection, Target, parse_version,
    resolve_flashrom, resolve_flashrom_in,
};
pub use host::{Flashrom, Host, State};

use crate::commands::{MAX_IMAGE_BYTES, read_bounded};
use crate::config::{Config, io_error};
use crate::output::{Out, Reply, display_path, table};
use crate::publish::{check_outputs, publish_file};
use crate::toolchain::{Finished, Runner};
use crate::{FlashCommand, FlashTargetArgs, FlashWriteArgs};
use biosmod_core::catalog::Board;
use biosmod_core::firmware::{self, Image, Region};
use biosmod_core::util::sha256_hex;
use biosmod_core::{Code, Error, Result};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Characters of flashrom output kept in replies and errors.
const LOG_TAIL: usize = 4000;

/// The name of the only region of a chip without a flash descriptor.
const WHOLE_CHIP: &str = "chip";

/// Everything a flash command touches outside its arguments.
pub struct Env<'a> {
    pub runner: &'a dyn Runner,
    pub host: Host,
    pub flashrom: Option<PathBuf>,
    pub out: Out,
    /// Process environment lookup (who invoked sudo or pkexec).
    pub variable: &'a dyn Fn(&str) -> Option<OsString>,
    /// Board profiles to compare with the running motherboard.
    pub boards: Vec<Board>,
}

/// Run one `flash` subcommand against the real system.
///
/// flashrom is chosen by `--flashrom`, then `BME_FLASHROM`, then `tools.flashrom` from the
/// configuration, then `PATH`. Root (sudo, pkexec) never reads configuration, because the home
/// directory is root's: pass `--flashrom` or `BME_FLASHROM` there.
pub fn run(out: Out, command: FlashCommand) -> Result<Reply> {
    let variable = |key: &str| std::env::var_os(key);
    let host = Host::current();
    let configured = if host.euid == Some(0) {
        None
    } else {
        configured_flashrom(&out)
    };
    let flashrom = command
        .flashrom_override()
        .cloned()
        .or_else(|| resolve_flashrom(&variable, configured.as_deref()).map(|(path, _)| path));
    let env = Env {
        runner: &crate::toolchain::System,
        host,
        flashrom,
        out,
        variable: &variable,
        boards: bundled_boards(),
    };
    dispatch(&env, command)
}

/// `tools.flashrom` from the per-user configuration; a broken file only costs a warning here.
fn configured_flashrom(out: &Out) -> Option<PathBuf> {
    let loaded = crate::config::Paths::from_env().and_then(|paths| Config::load(&paths));
    match loaded {
        Ok(config) => config.tools.flashrom,
        Err(error) => {
            out.note(format!("ignoring tools.flashrom: {error}"));
            None
        }
    }
}

/// Route a parsed subcommand; chip access is refused outside Linux.
pub fn dispatch(env: &Env, command: FlashCommand) -> Result<Reply> {
    match command {
        FlashCommand::Doctor { programmer, .. } => doctor(env, &programmer),
        FlashCommand::Probe(target) => {
            require_linux(env, "flash probe")?;
            probe(env, &target)
        }
        FlashCommand::Backup {
            target,
            regions,
            output,
        } => {
            require_linux(env, "flash backup")?;
            backup(env, &target, &regions, &output)
        }
        FlashCommand::Write(args) => {
            require_linux(env, "flash write")?;
            write(env, &args)
        }
    }
}

fn require_linux(env: &Env, command: &str) -> Result<()> {
    if env.host.os == "linux" {
        return Ok(());
    }
    Err(Error::new(
        Code::PlatformUnsupported,
        format!(
            "{command}: expected linux | received {}; write the image with an external programmer (`bme guide flashing`)",
            env.host.os
        ),
    ))
}

/// Board profiles of the bundled official catalog; an unreadable catalog yields none.
fn bundled_boards() -> Vec<Board> {
    use biosmod_core::catalog::{Catalog, Scope};
    Catalog::load(&crate::sources::builtin_source(), Scope::All)
        .map(|catalog| catalog.boards.into_values().collect())
        .unwrap_or_default()
}

fn target(env: &Env, args: &FlashTargetArgs) -> Result<Target> {
    flashrom::validate_programmer(&args.programmer)?;
    if let Some(chip) = &args.chip {
        flashrom::validate_chip(chip)?;
    }
    let flashrom = env.flashrom.clone().ok_or_else(|| {
        Error::new(
            Code::ToolUnavailable,
            format!(
                "flashrom: expected an executable in PATH or the sbin directories | received none; install flashrom (`bme tools status`), set {}, or run `bme tools set flashrom <path>`",
                flashrom::FLASHROM_OVERRIDE
            ),
        )
    })?;
    Ok(Target {
        flashrom,
        programmer: args.programmer.clone(),
        chip: args.chip.clone(),
    })
}

fn installed_flashrom(env: &Env) -> Option<Flashrom> {
    let path = env.flashrom.clone()?;
    let target = Target {
        flashrom: path.clone(),
        programmer: String::new(),
        chip: None,
    };
    let version = env
        .runner
        .run(&target.invocation(None, Operation::Version))
        .ok()
        .and_then(|finished| flashrom::parse_version(&finished.output()));
    Some(Flashrom { path, version })
}

/// `flash doctor`: read-only diagnosis; never starts a programmer.
///
/// Example: `bme flash doctor --programmer ch341a_spi` lists what blocks a CH341A read.
pub fn doctor(env: &Env, programmer: &str) -> Result<Reply> {
    flashrom::validate_programmer(programmer)?;
    let installed = installed_flashrom(env);
    let checks = env.host.checks(programmer, installed.as_ref());
    let dmi = env.host.dmi();
    let boards: Vec<Value> = env
        .boards
        .iter()
        .filter(|board| host::board_matches(&dmi, &board.vendor, &board.model))
        .map(|board| {
            let revision_matches = board.revision.label.as_deref().map(|label| {
                dmi.get("board_version")
                    .is_some_and(|version| version.eq_ignore_ascii_case(label))
            });
            json!({
                "id": board.id,
                "vendor": board.vendor,
                "model": board.model,
                "revision": board.revision.label,
                "revision_matches": revision_matches,
            })
        })
        .collect();
    let ready = !checks.iter().any(|check| check.state == State::Fail);
    let mut text = String::from("System\n");
    for (field, value) in &dmi {
        let _ = writeln!(text, "  {field:<14} {value}");
    }
    if dmi.is_empty() {
        text += "  no DMI identity available\n";
    }
    for board in &boards {
        let _ = writeln!(
            text,
            "  catalog board  {} (revision {}{})",
            board["id"].as_str().unwrap_or_default(),
            board["revision"].as_str().unwrap_or("unknown"),
            match board["revision_matches"].as_bool() {
                Some(true) => ", matches",
                Some(false) => ", differs from this board",
                None => "",
            }
        );
    }
    let _ = writeln!(text, "\nChecks for programmer {programmer}");
    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|check| {
            vec![
                format!("  {}", state_word(check.state)),
                check.check.to_string(),
                check.detail.clone(),
            ]
        })
        .collect();
    text += &table(&rows);
    text += if ready {
        "\nNext: sudo bme flash probe, then sudo bme flash backup -o dump.bin\n"
    } else {
        "\nFix the FAIL lines before reading or writing the chip.\n"
    };
    Ok(Reply::new(
        json!({
            "platform": env.host.os,
            "programmer": programmer,
            "system": dmi,
            "catalog_boards": boards,
            "flashrom": installed,
            "checks": checks,
            "ready": ready,
        }),
        text,
    ))
}

fn state_word(state: State) -> &'static str {
    match state {
        State::Pass => "PASS",
        State::Warn => "WARN",
        State::Fail => "FAIL",
        State::Info => "INFO",
    }
}

/// The last characters of a flashrom run, for replies and errors.
fn log_tail(finished: &Finished) -> String {
    finished.tail(LOG_TAIL)
}

/// Explain a failed flashrom process, naming the usual cause when it is visible.
fn flashrom_failure(env: &Env, target: &Target, step: &str, finished: &Finished) -> Error {
    let output = finished.output();
    let lowered = output.to_lowercase();
    let hint = if env.host.euid != Some(0)
        && (lowered.contains("root privileges") || lowered.contains("permission"))
    {
        "; run with sudo, or let the desktop app ask for administrator rights"
    } else if lowered.contains("no eeprom/flash device found") {
        "; no chip answered: check the programmer name, the clip orientation and that the board is unplugged"
    } else if lowered.contains("multiple flash chip definitions") {
        "; several definitions match: choose one with --chip (see `bme flash probe`)"
    } else if lowered.contains("/dev/mem") {
        "; the kernel refused /dev/mem: see `bme flash doctor` (iomem=relaxed or a linux_mtd programmer)"
    } else {
        ""
    };
    let last = output
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output");
    Error::new(
        Code::ToolFailed,
        format!(
            "flashrom -p {} ({step}): expected exit status 0 | received {}: {last}{hint}",
            target.programmer,
            finished.describe()
        ),
    )
    .with_details(json!({"step": step, "log": log_tail(finished)}))
}

/// `flash probe`: detect the chip without reading it.
///
/// Example: `sudo bme flash probe --programmer ch341a_spi` names the chip under the clip.
pub fn probe(env: &Env, args: &FlashTargetArgs) -> Result<Reply> {
    let target = target(env, args)?;
    env.out
        .note(format!("probing through {}", target.programmer));
    let finished = env.runner.run(&target.invocation(None, Operation::Probe))?;
    let chips = flashrom::parse_chips(&finished.output());
    if chips.is_empty() {
        return Err(flashrom_failure(env, &target, "probe", &finished));
    }
    let ambiguous = chips.len() > 1;
    let mut text: String = chips
        .iter()
        .map(|chip| format!("Found {}\n", host::describe_chip(chip)))
        .collect();
    text += &if ambiguous {
        format!(
            "Several definitions match. Read the marking on the chip and pass one, e.g. --chip {:?}\n",
            chips[0].name
        )
    } else {
        format!(
            "Next: sudo bme flash backup --programmer {} -o dump.bin\n",
            target.programmer
        )
    };
    Ok(Reply::new(
        json!({
            "programmer": target.programmer,
            "chips": chips,
            "ambiguous": ambiguous,
            "log": log_tail(&finished),
        }),
        text,
    ))
}

/// One chip read into memory, with the definition flashrom used.
struct ChipRead {
    bytes: Vec<u8>,
    chip: Option<Chip>,
}

/// Read the chip (or the selected regions) into `file` and load it.
fn read_chip(
    env: &Env,
    target: &Target,
    selection: Option<Selection>,
    file: &Path,
    step: &str,
) -> Result<ChipRead> {
    env.out.note(format!("reading the chip ({step})"));
    let finished = env
        .runner
        .run(&target.invocation(selection, Operation::Read(file)))?;
    if !finished.success() {
        return Err(flashrom_failure(env, target, step, &finished));
    }
    let bytes = read_bounded(file, MAX_IMAGE_BYTES).map_err(|error| {
        Error::new(
            Code::ToolFailed,
            format!(
                "flashrom -p {} ({step}): expected a chip dump | received {}",
                target.programmer, error.message
            ),
        )
    })?;
    if bytes.is_empty() {
        return Err(Error::new(
            Code::ToolFailed,
            format!(
                "flashrom -p {} ({step}): expected a chip dump | received 0 bytes",
                target.programmer
            ),
        ));
    }
    Ok(ChipRead {
        bytes,
        chip: flashrom::parse_chips(&finished.output()).into_iter().next(),
    })
}

/// The first offset in `ranges` where two equally long buffers differ.
fn first_difference<'a>(a: &[u8], b: &[u8], ranges: &'a [Region]) -> Option<(&'a Region, usize)> {
    ranges.iter().find_map(|range| {
        a[range.start..range.end]
            .iter()
            .zip(&b[range.start..range.end])
            .position(|(x, y)| x != y)
            .map(|at| (range, range.start + at))
    })
}

fn whole(length: usize) -> Region {
    Region {
        name: WHOLE_CHIP,
        start: 0,
        end: length,
    }
}

/// Resolve `--region` names against a descriptor, rejecting unknown ones.
fn select_regions(available: &[Region], names: &[String]) -> Result<Vec<Region>> {
    let mut selected: Vec<Region> = Vec::new();
    for name in names {
        let region = available
            .iter()
            .find(|region| region.name == name)
            .ok_or_else(|| {
                Error::new(
                    Code::Usage,
                    format!(
                        "region {name:?}: expected one of {} | not in this flash descriptor",
                        available
                            .iter()
                            .map(|region| region.name)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            })?;
        if !selected.contains(region) {
            selected.push(region.clone());
        }
    }
    Ok(selected)
}

/// A layout file plus the region names to pass with `-i`.
struct Layout {
    file: PathBuf,
    names: Vec<&'static str>,
}

impl Layout {
    /// Write `regions` as a flashrom layout in `directory` and select `chosen`.
    fn create(directory: &Path, regions: &[Region], chosen: &[Region]) -> Result<Layout> {
        let file = directory.join("layout.txt");
        fs::write(&file, flashrom::layout_text(regions)).map_err(|e| io_error(&file, e))?;
        Ok(Layout {
            file,
            names: chosen.iter().map(|region| region.name).collect(),
        })
    }

    fn selection(&self) -> Selection<'_> {
        Selection {
            layout: &self.file,
            regions: &self.names,
        }
    }
}

fn work_directory() -> Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("bme-flash-")
        .tempdir()
        .map_err(|e| io_error(&std::env::temp_dir(), e))
}

/// Refuse a dump whose compared bytes are all erased or all zero: no chip answered.
fn refuse_blank(bytes: &[u8], ranges: &[Region]) -> Result<()> {
    for filler in [0xFFu8, 0x00] {
        if ranges
            .iter()
            .all(|range| bytes[range.start..range.end].iter().all(|b| *b == filler))
        {
            return Err(Error::new(
                Code::FlashRefused,
                format!(
                    "chip read: expected firmware bytes | received only {filler:#04x}; the chip is blank or the programmer is not connected"
                ),
            ));
        }
    }
    Ok(())
}

/// The user who ran sudo or pkexec, so root-created backups can be handed back.
///
/// Example: with `SUDO_UID=1000` and `SUDO_GID=1000` this is `Some((1000, Some(1000)))`.
pub fn invoking_user(variable: &dyn Fn(&str) -> Option<OsString>) -> Option<(u32, Option<u32>)> {
    let number = |key: &str| variable(key)?.to_str()?.parse::<u32>().ok();
    if let Some(uid) = number("PKEXEC_UID") {
        return Some((uid, None));
    }
    number("SUDO_UID").map(|uid| (uid, number("SUDO_GID")))
}

/// Give a file root just created to the user who asked for it.
fn hand_back(env: &Env, path: &Path) -> Option<u32> {
    if env.host.euid != Some(0) {
        return None;
    }
    let (uid, gid) = invoking_user(env.variable).filter(|(uid, _)| *uid != 0)?;
    #[cfg(unix)]
    if let Err(error) = std::os::unix::fs::chown(path, Some(uid), gid) {
        env.out.note(format!(
            "{}: still owned by root ({error}); fix with chown",
            path.display()
        ));
        return None;
    }
    #[cfg(not(unix))]
    let _ = (path, gid);
    Some(uid)
}

/// `flash backup`: read the chip twice, require identical reads, publish a new file.
///
/// Example: `sudo bme flash backup --programmer ch341a_spi -o dump.bin`.
pub fn backup(
    env: &Env,
    args: &FlashTargetArgs,
    regions: &[String],
    output: &Path,
) -> Result<Reply> {
    let target = target(env, args)?;
    check_outputs(&[output], &[])?;
    let work = work_directory()?;
    // A locked Intel ME region makes a full internal read fail; `--region` reads around it.
    let partial = if regions.is_empty() {
        None
    } else {
        let descriptor = Region {
            name: "descriptor",
            start: 0,
            end: 0x1000,
        };
        let only_descriptor = Layout::create(
            work.path(),
            std::slice::from_ref(&descriptor),
            std::slice::from_ref(&descriptor),
        )?;
        let read = read_chip(
            env,
            &target,
            Some(only_descriptor.selection()),
            &work.path().join("descriptor.bin"),
            "flash descriptor",
        )?;
        let available = firmware::descriptor_regions(&read.bytes).ok_or_else(|| {
            Error::new(
                Code::FlashRefused,
                "chip descriptor: expected an Intel flash descriptor for --region | received none; omit --region to read the whole chip",
            )
        })?;
        let mut chosen = select_regions(&available, regions)?;
        if !chosen.iter().any(|region| region.name == "descriptor") {
            chosen.insert(
                0,
                select_regions(&available, &["descriptor".into()])?.remove(0),
            );
        }
        Some((Layout::create(work.path(), &available, &chosen)?, chosen))
    };
    let selection = partial.as_ref().map(|(layout, _)| layout.selection());
    let first = read_chip(
        env,
        &target,
        selection,
        &work.path().join("read1.bin"),
        "read 1 of 2",
    )?;
    let second = read_chip(
        env,
        &target,
        selection,
        &work.path().join("read2.bin"),
        "read 2 of 2",
    )?;
    let ranges = match &partial {
        Some((_, chosen)) => chosen.clone(),
        None => vec![whole(first.bytes.len())],
    };
    if first.bytes.len() != second.bytes.len() {
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "chip reads: expected equal sizes | received {} and {} bytes",
                first.bytes.len(),
                second.bytes.len()
            ),
        ));
    }
    if let Some((range, at)) = first_difference(&first.bytes, &second.bytes, &ranges) {
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "chip reads: expected two identical reads | received a difference at {at:#x} ({}); reseat the clip or check the wiring, then retry",
                range.name
            ),
        ));
    }
    refuse_blank(&first.bytes, &ranges)?;
    let mut dump = first.bytes;
    if partial.is_some() {
        // Bytes flashrom did not read are whatever its buffer held; make them erased flash.
        let mut kept = vec![0xFFu8; dump.len()];
        for range in &ranges {
            kept[range.start..range.end].copy_from_slice(&dump[range.start..range.end]);
        }
        dump = kept;
    }
    let digest = sha256_hex(&dump);
    publish_file(output, &dump)?;
    let owner = hand_back(env, output);
    let layout = firmware::descriptor_regions(&dump);
    let parsed = Image::parse(dump.clone());
    let mut text = format!(
        "Backup {} ({} bytes, sha256 {digest})\nTwo reads matched.\n",
        output.display(),
        dump.len()
    );
    if partial.is_some() {
        let _ = writeln!(
            text,
            "Only these regions were read: {}. It can restore those regions, not the whole chip.",
            ranges.iter().map(|r| r.name).collect::<Vec<_>>().join(", ")
        );
    }
    match &parsed {
        Ok(image) => {
            let _ = writeln!(
                text,
                "Firmware volumes: {}. Keep this file; it is the only way back.\nNext: bme scan {}",
                image.volumes.len(),
                output.display()
            );
        }
        Err(error) => {
            let _ = writeln!(
                text,
                "Not recognized as UEFI firmware ({}). Keep it anyway.",
                error.message
            );
        }
    }
    Ok(Reply::new(
        json!({
            "programmer": target.programmer,
            "chip": first.chip,
            "output": display_path(output),
            "size": dump.len(),
            "sha256": digest,
            "reads": 2,
            "partial": partial.is_some(),
            "regions_read": ranges.iter().map(|r| r.name).collect::<Vec<_>>(),
            "layout": layout,
            "firmware_volumes": parsed.as_ref().ok().map(|image| image.volumes.len()),
            "firmware_note": parsed.as_ref().err().map(|error| error.message.clone()),
            "owner_uid": owner,
        }),
        text,
    ))
}

/// What a write will touch, decided from the image and the backup alone.
struct WritePlan {
    whole_chip: bool,
    /// Regions to write.
    write: Vec<Region>,
    /// Regions compared with the backup before, and with the image after, the write.
    read: Vec<Region>,
    /// Every descriptor region, when the backup has a descriptor.
    layout: Option<Vec<Region>>,
}

fn plan_write(args: &FlashWriteArgs, image: &[u8], backup: &[u8]) -> Result<WritePlan> {
    if image.len() != backup.len() {
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "image size: expected {} bytes like the backup | received {}",
                backup.len(),
                image.len()
            ),
        ));
    }
    Image::parse(image.to_vec()).map_err(|error| {
        Error::new(
            Code::FlashRefused,
            format!(
                "{}: expected a firmware image that parses | {}",
                args.image.display(),
                error.message
            ),
        )
    })?;
    let layout = firmware::descriptor_regions(backup);
    let plan = if args.whole_chip {
        let chip = whole(image.len());
        WritePlan {
            whole_chip: true,
            write: vec![chip.clone()],
            read: vec![chip],
            layout: None,
        }
    } else {
        let available = layout.clone().ok_or_else(|| {
            Error::new(
                Code::FlashRefused,
                format!(
                    "{}: expected an Intel flash descriptor to write single regions | received none; pass --whole-chip to write everything",
                    args.backup.display()
                ),
            )
        })?;
        let names = if args.regions.is_empty() {
            vec!["bios".to_string()]
        } else {
            args.regions.clone()
        };
        let write = select_regions(&available, &names)?;
        let mut read = write.clone();
        if !read.iter().any(|region| region.name == "descriptor") {
            read.insert(
                0,
                select_regions(&available, &["descriptor".into()])?.remove(0),
            );
        }
        WritePlan {
            whole_chip: false,
            write,
            read,
            layout: Some(available),
        }
    };
    // Anything the image changes outside the written regions would silently not be flashed.
    let mut covered = vec![false; image.len()];
    for region in &plan.write {
        covered[region.start..region.end].fill(true);
    }
    if let Some(at) = (0..image.len()).find(|&at| !covered[at] && image[at] != backup[at]) {
        let region = layout
            .iter()
            .flatten()
            .find(|region| (region.start..region.end).contains(&at))
            .map_or("outside every region", |region| region.name);
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "image at {at:#x} ({region}): expected the backup byte {:#04x} outside the written regions | received {:#04x}; build the image from this backup, or add --region {region} or --whole-chip",
                backup[at], image[at]
            ),
        ));
    }
    Ok(plan)
}

/// Where the regions to read live for flashrom: a layout selection, or the whole chip.
fn plan_layout(directory: &Path, plan: &WritePlan, chosen: &[Region]) -> Result<Option<Layout>> {
    plan.layout
        .as_ref()
        .map(|regions| Layout::create(directory, regions, chosen))
        .transpose()
}

/// `flash write`: guarded write of an image, then an independent read-back.
///
/// Example: `sudo bme flash write patched.bin --backup dump.bin --dry-run`, then repeat
/// with `--confirm <image sha256>` in place of `--dry-run`.
pub fn write(env: &Env, args: &FlashWriteArgs) -> Result<Reply> {
    let target = target(env, &args.target)?;
    let image = read_bounded(&args.image, MAX_IMAGE_BYTES)?;
    let backup = read_bounded(&args.backup, MAX_IMAGE_BYTES)?;
    let plan = plan_write(args, &image, &backup)?;
    let image_digest = sha256_hex(&image);
    if !args.dry_run {
        let confirmed = args.confirm.as_ref().map(ToString::to_string);
        if confirmed.as_deref() != Some(image_digest.as_str()) {
            return Err(Error::new(
                Code::FlashRefused,
                format!(
                    "--confirm: expected the image SHA-256 {image_digest} | received {}; run with --dry-run first and review what it will write",
                    confirmed.as_deref().unwrap_or("none")
                ),
            ));
        }
    }
    let work = work_directory()?;
    let read_layout = plan_layout(work.path(), &plan, &plan.read)?;
    let before = read_chip(
        env,
        &target,
        read_layout.as_ref().map(Layout::selection),
        &work.path().join("before.bin"),
        "comparing the chip with the backup",
    )?;
    if before.bytes.len() != backup.len() {
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "chip size: expected {} bytes like the backup | received {}; this backup is from another chip",
                backup.len(),
                before.bytes.len()
            ),
        ));
    }
    if let Some((range, at)) = first_difference(&before.bytes, &backup, &plan.read) {
        return Err(Error::new(
            Code::FlashRefused,
            format!(
                "chip at {at:#x} ({}): expected the backup byte {:#04x} | received {:#04x}; the backup does not hold what the chip holds now, take a new one with `bme flash backup`",
                range.name, backup[at], before.bytes[at]
            ),
        ));
    }
    let regions: Vec<Value> = plan
        .write
        .iter()
        .map(|region| {
            let changed = image[region.start..region.end]
                .iter()
                .zip(&backup[region.start..region.end])
                .filter(|(new, old)| new != old)
                .count();
            json!({"name": region.name, "start": region.start, "end": region.end, "changed_bytes": changed})
        })
        .collect();
    let mut data = json!({
        "dry_run": args.dry_run,
        "programmer": target.programmer,
        "chip": before.chip,
        "image": display_path(&args.image),
        "image_sha256": image_digest,
        "backup": display_path(&args.backup),
        "backup_sha256": sha256_hex(&backup),
        "size": image.len(),
        "whole_chip": plan.whole_chip,
        "regions": regions,
        "written": false,
        "verified": false,
    });
    let mut text = format!(
        "Image {} (sha256 {image_digest})\nBackup {} matches the chip.\n",
        args.image.display(),
        args.backup.display()
    );
    for region in &regions {
        let _ = writeln!(
            text,
            "  {:<14} {:#09x}-{:#09x}  {} bytes change",
            region["name"].as_str().unwrap_or_default(),
            region["start"].as_u64().unwrap_or_default(),
            region["end"].as_u64().unwrap_or_default().saturating_sub(1),
            region["changed_bytes"]
        );
    }
    if args.dry_run {
        data["confirm"] = json!(image_digest);
        let _ = writeln!(
            text,
            "Dry run: nothing was written.\nTo write, repeat without --dry-run and add --confirm {image_digest}\nOnly continue if you can recover a board that no longer starts (`bme guide recovery`)."
        );
        return Ok(Reply::new(data, text));
    }
    // flashrom reads a private copy, so the checked bytes are the written bytes.
    let staged = work.path().join("image.bin");
    fs::write(&staged, &image).map_err(|e| io_error(&staged, e))?;
    let write_layout = plan_layout(work.path(), &plan, &plan.write)?;
    env.out.note(
        "writing the chip: do not power off, unplug the programmer or interrupt this process",
    );
    let finished = env.runner.run(&target.invocation(
        write_layout.as_ref().map(Layout::selection),
        Operation::Write(&staged),
    ))?;
    let recovery = format!(
        "the chip may hold a partial image; do not power the board off if it is still running, and write the backup back: bme flash write {} --backup <a fresh dump of the chip> (see `bme guide recovery`)",
        args.backup.display()
    );
    if !finished.success() {
        let failure = flashrom_failure(env, &target, "write", &finished);
        return Err(Error::new(
            Code::FlashFailed,
            format!("{}; {recovery}", failure.message),
        )
        .with_details(json!({"step": "write", "log": log_tail(&finished)})));
    }
    let read_back_layout = plan_layout(work.path(), &plan, &plan.write).map_err(|error| {
        Error::new(
            Code::FlashFailed,
            format!(
                "read-back layout after writing: {}; {recovery}",
                error.message
            ),
        )
        .with_details(json!({"step": "read-back layout"}))
    })?;
    let after = read_chip(
        env,
        &target,
        read_back_layout.as_ref().map(Layout::selection),
        &work.path().join("after.bin"),
        "reading back what was written",
    )
    .map_err(|error| {
        Error::new(
            Code::FlashFailed,
            format!("read-back after writing: {}; {recovery}", error.message),
        )
    })?;
    let mismatch = if after.bytes.len() == image.len() {
        first_difference(&after.bytes, &image, &plan.write).map(|(range, at)| {
            format!(
                "chip at {at:#x} ({}): expected the image byte {:#04x} | received {:#04x}",
                range.name, image[at], after.bytes[at]
            )
        })
    } else {
        Some(format!(
            "chip size: expected {} bytes | received {}",
            image.len(),
            after.bytes.len()
        ))
    };
    if let Some(mismatch) = mismatch {
        return Err(Error::new(
            Code::FlashFailed,
            format!("read-back after writing: {mismatch}; {recovery}"),
        )
        .with_details(json!({"step": "read-back", "log": log_tail(&finished)})));
    }
    data["written"] = json!(true);
    data["verified"] = json!(true);
    data["log"] = json!(log_tail(&finished));
    text += "Written and read back: the chip holds the image.\nPower-cycle the board to start the new firmware. Keep the backup.\n";
    Ok(Reply::new(data, text))
}
