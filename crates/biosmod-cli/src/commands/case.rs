//! `case` subcommands: start an investigation, record command results, check them, export a draft.
//!
//! A case directory holds `case.json` (the `bme.case/1` document), `artifacts/`
//! (recorded results), `drafts/` (the unreviewed board profile and firmware
//! build) and `findings/` (finding documents the investigation produces).
//! Input dumps are listed by digest and never copied.

use super::{Ctx, firmware, load_sources, read_image};
use crate::config::{io_error, write_atomic, write_new};
use crate::flash::host::Host;
use crate::output::{Out, Reply, display_path, success_document};
use crate::publish::{check_outputs, create_new_directory, remove_failed_directory};
use crate::sources::Loaded;
use crate::{
    CaseCommand, CaseExportArgs, CaseInitArgs, CaseRecordArgs, CaseStatusArgs, Cli, Command,
    FlashCommand, ScanArgs, SourceArgs,
};
use biosmod_core::case::{
    ARTIFACT_DIRECTORY, Artifact, ArtifactFile, ArtifactKind, CASE_SCHEMA, Case, CaseInput,
    CaseStatus, CatalogSnapshot, Current, FindingRef, Verdict, public_command, public_value,
    status, submission_files, tree_blob, tree_changes, utc_timestamp,
};
use biosmod_core::catalog::{Board, Finding};
use biosmod_core::draft::{DraftRequest, FirmwareDraft, draft, draft_finding};
use biosmod_core::json::{parse_strict, pretty};
use biosmod_core::plan::document::Blob;
use biosmod_core::util::Digest256;
use biosmod_core::{Code, Error, Result};
use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const CASE_FILE: &str = "case.json";
const BOARD_DRAFT: &str = "drafts/board.json";
const FIRMWARE_DRAFT: &str = "drafts/firmware.json";
const FINDINGS_DIRECTORY: &str = "findings";
/// Largest case document or draft read.
const DOCUMENT_LIMIT: u64 = 16 << 20;
/// The artifact id the scan made by `case init` takes.
const SCAN_ARTIFACT: &str = "001-scan";

/// The time source; tests substitute [`FixedClock`].
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

/// Where SMBIOS identity comes from; tests substitute [`FakeHostIdentity`].
pub trait HostIdentity {
    /// DMI fields of the running machine, such as `board_name` and `bios_date`.
    fn smbios(&self) -> BTreeMap<String, String>;
}

impl HostIdentity for Host {
    fn smbios(&self) -> BTreeMap<String, String> {
        self.dmi()
            .into_iter()
            .map(|(field, value)| (field.to_string(), value))
            .collect()
    }
}

/// What `case` reads from its surroundings.
pub struct Environment<'a> {
    pub clock: &'a dyn Clock,
    pub host: &'a dyn HostIdentity,
}

pub fn run(ctx: &Ctx, command: CaseCommand) -> Result<Reply> {
    let host = Host::current();
    let environment = Environment {
        clock: &SystemClock,
        host: &host,
    };
    match command {
        CaseCommand::Init(args) => init(ctx, &args, &environment),
        CaseCommand::Record(args) => record(ctx, &args, &environment),
        CaseCommand::Status(args) => case_status(ctx, &args),
        CaseCommand::Export(args) => export(&args),
    }
}

/// Digest a regular file without reading it into memory.
///
/// Example: `hash_file(Path::new("dump.bin"))?.length` is the file size.
fn hash_file(path: &Path) -> Result<Blob> {
    let metadata = fs::metadata(path).map_err(|e| io_error(path, e))?;
    if !metadata.is_file() {
        return Err(Error::new(
            Code::Io,
            format!("{}: expected a regular file", path.display()),
        ));
    }
    let mut file = fs::File::open(path).map_err(|e| io_error(path, e))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 << 10];
    let mut length = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|e| io_error(path, e))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length += count as u64;
    }
    Ok(Blob {
        sha256: Digest256(hasher.finalize().into()),
        length,
    })
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::new(
                Code::Usage,
                format!("{}: expected a file path with a UTF-8 name", path.display()),
            )
        })
}

/// Read a case document that must be a regular file, never through a symbolic link.
///
/// The path is checked without following links, then opened with `O_NOFOLLOW` where the
/// platform has it, so a link swapped in between the two still fails.
///
/// Example: `read_regular(&dir.join("case.json"), DOCUMENT_LIMIT)?` fails on a link to a file.
fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    refuse_link(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| io_error(path, e))?;
    let metadata = file.metadata().map_err(|e| io_error(path, e))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "{}: expected a regular file of at most {limit} bytes | received {} bytes",
                path.display(),
                metadata.len()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
    Ok(bytes)
}

/// Fail when `path` is a symbolic link; a missing path is not an error here.
///
/// Example: `refuse_link(&dir.join("artifacts"))?` fails when `artifacts` links elsewhere.
fn refuse_link(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::new(
            Code::FormatInvalid,
            format!(
                "{}: expected a plain file or directory inside the case | received a symbolic link",
                path.display()
            ),
        )),
        _ => Ok(()),
    }
}

/// Check the case's own layout: `case.json` and the three working directories are the real
/// thing, so no read or write below follows a link out of the case.
fn check_layout(dir: &Path) -> Result<()> {
    for name in [CASE_FILE, ARTIFACT_DIRECTORY, "drafts", FINDINGS_DIRECTORY] {
        refuse_link(&dir.join(name))?;
    }
    Ok(())
}

fn load_case(dir: &Path) -> Result<Case> {
    let path = dir.join(CASE_FILE);
    check_layout(dir)?;
    let bytes = read_regular(&path, DOCUMENT_LIMIT)
        .map_err(|e| e.context(format!("{}: expected a case directory", dir.display())))?;
    let case: Case =
        parse_strict(&bytes, CASE_FILE).map_err(|e| Error::new(Code::FormatInvalid, e.message))?;
    case.check()?;
    Ok(case)
}

fn read_document<T: serde::de::DeserializeOwned>(dir: &Path, relative: &str) -> Result<T> {
    let path = dir.join(relative);
    let bytes = read_regular(&path, DOCUMENT_LIMIT)?;
    parse_strict(&bytes, relative).map_err(|e| Error::new(Code::FormatInvalid, e.message))
}

/// The finding documents in `findings/`, in id order. Each file is named for its id.
fn case_findings(dir: &Path) -> Result<Vec<Finding>> {
    let directory = dir.join(FINDINGS_DIRECTORY);
    let mut paths: Vec<PathBuf> = match fs::read_dir(&directory) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "json"))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(io_error(&directory, error)),
    };
    paths.sort();
    let mut findings = Vec::new();
    for path in paths {
        let name = file_name(&path)?;
        let finding: Finding = read_document(dir, &format!("{FINDINGS_DIRECTORY}/{name}"))?;
        if format!("{}.json", finding.id) != name {
            return Err(Error::new(
                Code::FormatInvalid,
                format!(
                    "{FINDINGS_DIRECTORY}/{name}: file name expected {}.json | received id {:?}",
                    finding.id, finding.id
                ),
            ));
        }
        findings.push(finding);
    }
    Ok(findings)
}

fn snapshots(loaded: &[Loaded]) -> Vec<CatalogSnapshot> {
    loaded
        .iter()
        .map(|source| CatalogSnapshot {
            alias: source.alias.clone(),
            id: source.catalog.manifest.id.clone(),
            version: source.catalog.manifest.version.to_string(),
            manifest_sha256: source.catalog.manifest_sha256,
        })
        .collect()
}

/// The `scan` arguments equivalent to `args`, without the dump path.
fn source_arguments(args: &SourceArgs) -> Vec<String> {
    let mut words = Vec::new();
    for catalog in &args.catalogs {
        words.extend(["--catalog".to_string(), catalog.clone()]);
    }
    if args.allow_unsigned_local {
        words.push("--allow-unsigned-local".into());
    }
    if let Some(firmware) = &args.firmware {
        words.extend(["--firmware".to_string(), firmware.clone()]);
    }
    words
}

/// The `--json` document of a result as a case stores it: one line-terminated `bme/1`
/// envelope with every absolute path in its strings reduced to a base name.
///
/// Example: a scan of `/home/me/dump.bin` stores `"dump.bin"` where the path was.
fn public_document(command: &str, reply: &Reply) -> Vec<u8> {
    let document: Value = serde_json::from_str(&success_document(command, reply))
        .expect("a success document is JSON");
    let mut bytes = serde_json::to_vec_pretty(&public_value(&document)).expect("JSON serializes");
    bytes.push(b'\n');
    bytes
}

/// Write `(relative path, bytes)` pairs under `root`, creating directories.
fn write_tree(root: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    for (relative, bytes) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        write_new(&path, bytes)?;
    }
    Ok(())
}

/// Create `directory` and fill it, removing it again when filling fails.
fn publish_tree(directory: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    create_new_directory(directory)?;
    write_tree(directory, files).map_err(|cause| remove_failed_directory(directory, cause))
}

// ---- init ----------------------------------------------------------------------------------

/// Detector hits of one scan source: the build it matched and the catalog findings that hit.
fn scan_summary<'a>(data: &Value, loaded: &'a [Loaded]) -> (Option<String>, Vec<&'a Finding>) {
    let mut matched = None;
    let mut hits: Vec<&Finding> = Vec::new();
    for (index, source) in data["sources"].as_array().into_iter().flatten().enumerate() {
        let report = &source["report"];
        if matched.is_none() {
            matched = report["firmware"].as_str().map(str::to_string);
        }
        for detector in report["detectors"].as_array().into_iter().flatten() {
            if detector["state"] != "likely-present" {
                continue;
            }
            let Some(finding) = detector["finding"]
                .as_str()
                .and_then(|id| loaded.get(index)?.catalog.findings.get(id))
            else {
                continue;
            };
            if !hits.iter().any(|known| known.id == finding.id) {
                hits.push(finding);
            }
        }
    }
    (matched, hits)
}

fn init(ctx: &Ctx, args: &CaseInitArgs, environment: &Environment) -> Result<Reply> {
    check_outputs(&[&args.output], &[&args.dump])?;
    let name = file_name(&args.dump)?;
    let image = read_image(&args.dump)?;
    let input = CaseInput {
        name: name.clone(),
        sha256: Digest256::of(&image.bytes),
        length: image.bytes.len() as u64,
    };
    let loaded = load_sources(ctx, &args.source, &[])?;
    let scan = firmware::scan(
        ctx,
        &ScanArgs {
            rom: args.dump.clone(),
            source: args.source.clone(),
        },
    )?;
    let (matched, hits) = scan_summary(&scan.data, &loaded);
    let smbios = environment.host.smbios();
    let (board, firmware_draft) = draft(&DraftRequest {
        image: &image,
        board_id: args.board_id.as_deref(),
        smbios: &smbios,
        matches_catalog_build: matched.as_deref(),
    })?;
    let findings: Vec<Finding> = hits
        .iter()
        .map(|source| draft_finding(source, &firmware_draft.build.id, SCAN_ARTIFACT))
        .collect();
    let recorded = utc_timestamp(environment.clock.unix_seconds());
    let mut command = vec!["scan".to_string(), name];
    command.extend(source_arguments(&args.source));
    let scan_bytes = public_document("scan", &scan);
    let blob = Blob::of(&scan_bytes);
    let case = Case {
        schema: CASE_SCHEMA.into(),
        id: board.id.clone(),
        engine: biosmod_core::VERSION.into(),
        created: recorded.clone(),
        catalogs: snapshots(&loaded),
        inputs: vec![input.clone()],
        artifacts: vec![Artifact {
            id: SCAN_ARTIFACT.into(),
            path: format!("{ARTIFACT_DIRECTORY}/{SCAN_ARTIFACT}.json"),
            kind: ArtifactKind::Output,
            sha256: blob.sha256,
            length: blob.length,
            command: public_command(&command),
            bme_version: biosmod_core::VERSION.into(),
            catalogs: snapshots(&loaded),
            inputs: vec![input.clone()],
            recorded,
            files: vec![],
        }],
    };
    case.check()?;
    // The drafts must already export as a valid catalog, so a case is never born unusable.
    submission_files(&case, board.clone(), &firmware_draft, findings.clone())?;
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (CASE_FILE.into(), pretty(&case)),
        (case.artifacts[0].path.clone(), scan_bytes),
        (BOARD_DRAFT.into(), pretty(&board)),
        (FIRMWARE_DRAFT.into(), pretty(&firmware_draft)),
    ];
    files.extend(
        findings
            .iter()
            .map(|f| (format!("{FINDINGS_DIRECTORY}/{}.json", f.id), pretty(f))),
    );
    publish_tree(&args.output, &files)?;
    let finding_ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    let mut text = format!(
        "Created case {} (draft board {}, draft firmware {})\n",
        display_path(&args.output),
        board.id,
        firmware_draft.build.id
    );
    let _ = writeln!(
        text,
        "  input     {} sha256 {} ({} bytes)",
        input.name, input.sha256, input.length
    );
    let _ = writeln!(
        text,
        "  scan      {}: {}",
        case.artifacts[0].path,
        match &matched {
            Some(build) => format!("matches catalog build {build}"),
            None => "no catalog build matched".into(),
        }
    );
    if finding_ids.is_empty() {
        text.push_str("  detectors no defect signature matched\n");
    } else {
        let _ = writeln!(
            text,
            "  detectors likely present: {} (drafted under {FINDINGS_DIRECTORY}/)",
            finding_ids.join(", ")
        );
    }
    let _ = writeln!(
        text,
        "  smbios    {}",
        if firmware_draft.smbios.is_empty() {
            "not recorded (this machine's BIOS date is not in the image)"
        } else {
            "recorded from this machine"
        }
    );
    let _ = writeln!(
        text,
        "Drafts are unreviewed. Next: bme case export {} -o <directory>",
        display_path(&args.output)
    );
    Ok(Reply::new(
        json!({
            "directory": display_path(&args.output),
            "case": case,
            "board": board.id,
            "firmware": firmware_draft.build.id,
            "matches_catalog_build": matched,
            "smbios_recorded": !firmware_draft.smbios.is_empty(),
            "findings": finding_ids,
            "modules": firmware_draft.modules.len(),
        }),
        text,
    ))
}

// ---- record --------------------------------------------------------------------------------

/// Output paths a command line declares: `-o X`, `--output X`, `--output=X`, plus `extra`.
///
/// Example: `["extract", "a.bin", "-o", "m.bin"]` declares `m.bin`.
fn declared_outputs(argv: &[String], extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut outputs: Vec<PathBuf> = Vec::new();
    let mut words = argv.iter();
    while let Some(word) = words.next() {
        let value = match word.as_str() {
            "-o" | "--output" => words.next().map(String::as_str),
            other => other.strip_prefix("--output="),
        };
        if let Some(value) = value {
            outputs.push(PathBuf::from(value));
        }
    }
    outputs.extend(extra.iter().cloned());
    let mut seen = BTreeSet::new();
    outputs.retain(|path| seen.insert(path.clone()));
    outputs
}

/// Existing regular files a command line names, by digest.
///
/// Both `path` and `--flag=path` words count. Example: `["scan", "dump.bin"]`
/// yields `dump.bin` with its digest when that file exists.
fn argument_inputs(argv: &[String]) -> Vec<CaseInput> {
    let mut inputs: Vec<CaseInput> = Vec::new();
    for word in argv {
        let candidate = match word.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => value,
            _ => word.as_str(),
        };
        if candidate.is_empty() {
            continue;
        }
        let path = Path::new(candidate);
        let (Some(name), Ok(blob)) = (path.file_name().and_then(|n| n.to_str()), hash_file(path))
        else {
            continue;
        };
        let input = CaseInput {
            name: name.to_string(),
            sha256: blob.sha256,
            length: blob.length,
        };
        if !inputs.contains(&input) {
            inputs.push(input);
        }
    }
    inputs
}

/// A file name safe inside `artifacts/`: `[A-Za-z0-9._-]`, not starting with a dot.
fn artifact_file_name(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = safe.trim_start_matches('.');
    if trimmed.is_empty() {
        "file".into()
    } else {
        trimmed.chars().take(48).collect()
    }
}

fn parse_inner(argv: &[String]) -> Result<Cli> {
    let mut words = vec!["bme".to_string()];
    words.extend(argv.iter().cloned());
    if !argv.iter().any(|word| word == "--json") {
        words.push("--json".into());
    }
    Cli::try_parse_from(&words).map_err(|error| {
        let text = error.to_string();
        let first = text
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start_matches("error: ");
        Error::new(
            Code::Usage,
            format!("case record -- {}: {first}", argv.join(" ")),
        )
    })
}

fn record(ctx: &Ctx, args: &CaseRecordArgs, environment: &Environment) -> Result<Reply> {
    let mut case = load_case(&args.dir)?;
    let outputs = declared_outputs(&args.argv, &args.artifacts);
    if let Some(existing) = outputs
        .iter()
        .find(|path| fs::symlink_metadata(path).is_ok())
    {
        return Err(Error::new(
            Code::Usage,
            format!(
                "{}: expected a path the command creates | received an existing file",
                existing.display()
            ),
        ));
    }
    let inputs = argument_inputs(&args.argv);
    let cli = parse_inner(&args.argv)?;
    if matches!(cli.command, Command::Case(_)) {
        return Err(Error::new(
            Code::Usage,
            "case record: expected a bme command other than `case`",
        ));
    }
    // A recording keeps whatever the command produced, so refuse the ones that would put
    // a whole chip dump (serial numbers, MAC addresses) into a case or change the chip.
    if let Command::Flash(FlashCommand::Backup { .. } | FlashCommand::Write(_)) = &cli.command {
        let refused = args
            .argv
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        return Err(Error::new(
            Code::Usage,
            format!(
                "case record -- {refused}: expected a command that neither copies the chip nor writes it | received `{refused}`; run it outside the case"
            ),
        ));
    }
    let command_name = crate::command_name(&cli.command);
    let quiet = ctx.out.quiet || cli.quiet;
    let reply = super::run(
        cli.command,
        Out { json: true, quiet },
        ctx.offline || cli.offline,
    )?;
    let catalogs = snapshots(&load_sources(
        ctx,
        &SourceArgs {
            catalogs: vec![],
            allow_unsigned_local: false,
            firmware: None,
        },
        &[],
    )?);
    let recorded = utc_timestamp(environment.clock.unix_seconds());
    let first = case.next_artifact_number();
    let describe = |id: String, path: String, kind, blob: Blob| Artifact {
        id,
        path,
        kind,
        sha256: blob.sha256,
        length: blob.length,
        command: public_command(&args.argv),
        bme_version: biosmod_core::VERSION.into(),
        catalogs: catalogs.clone(),
        inputs: inputs.clone(),
        recorded: recorded.clone(),
        files: Vec::new(),
    };
    let mut artifacts = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    // Gather what to store before writing anything, so a bad output never leaves half a record.
    let mut copies: Vec<(PathBuf, String, bool)> = Vec::new();
    for path in &outputs {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() || metadata.is_dir() => {
                let id = format!(
                    "{:03}-{}",
                    first + 1 + copies.len() as u32,
                    artifact_file_name(&file_name(path)?)
                );
                if metadata.is_dir() {
                    // Validate the whole tree now; nothing has been written to the case yet.
                    tree_files(path, true)?;
                }
                copies.push((path.clone(), id, metadata.is_dir()));
            }
            Ok(_) => {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "{}: expected a file or directory | received a symbolic link or special file",
                        path.display()
                    ),
                ));
            }
            Err(_) => skipped.push(display_path(path).into_owned()),
        }
    }
    let slug = command_name.replace(' ', "-");
    let output_id = format!("{first:03}-{slug}");
    let document = public_document(command_name, &reply);
    let output_path = format!("{ARTIFACT_DIRECTORY}/{output_id}.json");
    write_new(&args.dir.join(&output_path), &document)?;
    artifacts.push(describe(
        output_id,
        output_path,
        ArtifactKind::Output,
        Blob::of(&document),
    ));
    for (source, id, is_directory) in copies {
        let path = format!("{ARTIFACT_DIRECTORY}/{id}");
        let target = args.dir.join(&path);
        if target.exists() {
            return Err(Error::new(
                Code::OutputExists,
                format!("{}: already exists", target.display()),
            ));
        }
        if is_directory {
            copy_tree(&source, &target)?;
            // Describe what was stored, not what the command left behind.
            let files = tree_files(&target, true)?;
            let mut artifact = describe(id, path, ArtifactKind::Directory, tree_blob(&files));
            artifact.files = files;
            artifacts.push(artifact);
        } else {
            fs::copy(&source, &target).map_err(|e| io_error(&source, e))?;
            artifacts.push(describe(id, path, ArtifactKind::File, hash_file(&target)?));
        }
    }
    for note in &skipped {
        ctx.out.note(format!(
            "{note}: not created by the command; nothing recorded for it"
        ));
    }
    case.artifacts.extend(artifacts.iter().cloned());
    case.check()?;
    write_atomic(&args.dir.join(CASE_FILE), &pretty(&case))?;
    let mut text = reply.text.clone();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for artifact in &artifacts {
        let _ = writeln!(
            text,
            "Recorded {} (sha256 {}, {} bytes)",
            artifact.path, artifact.sha256, artifact.length
        );
    }
    Ok(Reply::new(
        json!({"command": command_name, "artifacts": artifacts, "not_created": skipped}),
        text,
    ))
}

// ---- status --------------------------------------------------------------------------------

/// Match `--input` words to the case's inputs and find the rest beside the working directory
/// and the case directory. Returns the path found for each input name, if any.
fn locate_inputs(
    case: &Case,
    mappings: &[String],
    case_directory: &Path,
    working_directory: &Path,
) -> Result<BTreeMap<String, Option<PathBuf>>> {
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let names: Vec<&str> = case.inputs.iter().map(|i| i.name.as_str()).collect();
    for mapping in mappings {
        if let Some((name, path)) = mapping.split_once('=')
            && names.contains(&name)
        {
            found.insert(name.to_string(), PathBuf::from(path));
            continue;
        }
        let path = Path::new(mapping);
        if path.is_dir() {
            for input in &case.inputs {
                let candidate = path.join(&input.name);
                if candidate.is_file() {
                    found.entry(input.name.clone()).or_insert(candidate);
                }
            }
        } else if path.is_file() {
            let blob = hash_file(path)?;
            let by_name = path.file_name().and_then(|n| n.to_str());
            let input = case
                .inputs
                .iter()
                .find(|i| Some(i.name.as_str()) == by_name)
                .or_else(|| case.inputs.iter().find(|i| i.sha256 == blob.sha256));
            let Some(input) = input else {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "--input {mapping}: expected a file named one of [{}] or with a recorded sha256 | received sha256 {}",
                        names.join(", "),
                        blob.sha256
                    ),
                ));
            };
            found.insert(input.name.clone(), path.to_path_buf());
        } else {
            return Err(Error::new(
                Code::Usage,
                format!("--input {mapping}: expected an existing file, directory or NAME=PATH"),
            ));
        }
    }
    let search = [
        Some(working_directory),
        case_directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty()),
    ];
    Ok(case
        .inputs
        .iter()
        .map(|input| {
            let path = found.remove(&input.name).or_else(|| {
                search
                    .iter()
                    .flatten()
                    .map(|directory| directory.join(&input.name))
                    .find(|candidate| candidate.is_file())
            });
            (input.name.clone(), path)
        })
        .collect())
}

/// Digests of the artifacts as stored, `None` for a missing or wrong-typed path.
///
/// A directory artifact digests as `tree_blob` of the files found in it.
fn observe_artifacts(case: &Case, directory: &Path) -> BTreeMap<String, Option<Blob>> {
    case.artifacts
        .iter()
        .map(|artifact| {
            let path = directory.join(&artifact.path);
            let blob = if artifact.kind == ArtifactKind::Directory {
                observe_tree(&path).map(|files| tree_blob(&files))
            } else {
                let regular = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
                regular.then(|| hash_file(&path).ok()).flatten()
            };
            (artifact.path.clone(), blob)
        })
        .collect()
}

/// The files found in a stored directory artifact, `None` when it is not a directory.
fn observe_tree(path: &Path) -> Option<Vec<ArtifactFile>> {
    let is_directory = fs::symlink_metadata(path).is_ok_and(|m| m.is_dir());
    is_directory.then(|| tree_files(path, false).ok()).flatten()
}

/// Every file under `root`, sorted by `/`-separated relative path, with its digest.
///
/// A `strict` walk (recording) fails on symbolic links, special files and names outside
/// `[A-Za-z0-9._-]`, so a case never holds something it cannot verify. A lenient walk
/// (checking) lists such entries with an all-zero digest so they show up as drift.
///
/// Example: a directory holding `tables/DSDT.aml` yields one entry, `tables/DSDT.aml`.
fn tree_files(root: &Path, strict: bool) -> Result<Vec<ArtifactFile>> {
    let mut files = Vec::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|e| io_error(&directory, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_error(&directory, e))?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = format!("{prefix}{name}");
            let metadata = fs::symlink_metadata(&path).map_err(|e| io_error(&path, e))?;
            let safe = !name.starts_with('.')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
            if strict && !safe {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "{}: expected file names of [A-Za-z0-9._-] not starting with a dot | received {name:?}",
                        path.display()
                    ),
                ));
            }
            if metadata.is_dir() && safe {
                pending.push((path, format!("{relative}/")));
            } else if metadata.is_file() && safe {
                let blob = hash_file(&path)?;
                files.push(ArtifactFile {
                    path: relative,
                    sha256: blob.sha256,
                    length: blob.length,
                });
            } else if strict {
                return Err(Error::new(
                    Code::Usage,
                    format!(
                        "{}: expected a regular file or directory | received a symbolic link or special file",
                        path.display()
                    ),
                ));
            } else {
                files.push(ArtifactFile {
                    path: relative,
                    sha256: Digest256([0; 32]),
                    length: 0,
                });
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Copy a directory tree that `tree_files(source, true)` accepted.
///
/// Example: `copy_tree(Path::new("capture"), Path::new("case/artifacts/002-capture"))`.
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target).map_err(|e| io_error(target, e))?;
    for file in tree_files(source, true)? {
        let from = source.join(&file.path);
        let to = target.join(&file.path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        fs::copy(&from, &to).map_err(|e| io_error(&from, e))?;
    }
    Ok(())
}

fn status_text(case: &Case, report: &CaseStatus) -> String {
    let mut text = format!("Case {} (created {})\n", case.id, case.created);
    for input in &report.inputs {
        let _ = writeln!(
            text,
            "  input     {:<28} {}",
            input.name,
            input.state.label()
        );
    }
    for artifact in &report.artifacts {
        let _ = writeln!(
            text,
            "  artifact  {:<28} {}",
            artifact.path,
            artifact.state.label()
        );
        for file in &artifact.files {
            let _ = writeln!(
                text,
                "            file {:<23} {}",
                file.path,
                file.state.label()
            );
        }
        for reason in &artifact.stale {
            let _ = writeln!(text, "            stale: {reason}");
        }
    }
    for finding in &report.findings {
        let _ = writeln!(
            text,
            "  finding   {:<28} {}",
            finding.id,
            finding.status.label()
        );
    }
    let stale = report.stale().len();
    let _ = writeln!(
        text,
        "{}",
        match (report.clean, stale) {
            (true, 0) => "clean".to_string(),
            (true, n) =>
                format!("clean, {n} stale result(s): record them again with `bme case record`"),
            (false, _) => "changed or missing files".to_string(),
        }
    );
    text
}

fn case_status(ctx: &Ctx, args: &CaseStatusArgs) -> Result<Reply> {
    let case = load_case(&args.dir)?;
    let working = std::env::current_dir().map_err(|e| io_error(Path::new("."), e))?;
    let located = locate_inputs(&case, &args.inputs, &args.dir, &working)?;
    let inputs: BTreeMap<String, Option<Blob>> = located
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                path.as_ref().and_then(|path| hash_file(path).ok()),
            )
        })
        .collect();
    let artifacts = observe_artifacts(&case, &args.dir);
    let loaded = load_sources(
        ctx,
        &SourceArgs {
            catalogs: args.catalogs.clone(),
            allow_unsigned_local: args.allow_unsigned_local,
            firmware: None,
        },
        &[],
    )?;
    let current = snapshots(&loaded);
    let mut report = status(
        &case,
        &inputs,
        &artifacts,
        &Current {
            bme_version: biosmod_core::VERSION,
            catalogs: &current,
        },
    );
    for (artifact, recorded) in report.artifacts.iter_mut().zip(&case.artifacts) {
        if artifact.state != Verdict::Verified && recorded.kind == ArtifactKind::Directory {
            let found = observe_tree(&args.dir.join(&recorded.path)).unwrap_or_default();
            artifact.files = tree_changes(&recorded.files, &found);
        }
    }
    report.findings = case_findings(&args.dir)?
        .into_iter()
        .map(|f| FindingRef {
            id: f.id,
            status: f.status,
        })
        .collect();
    let text = status_text(&case, &report);
    if report.clean {
        return Ok(Reply::new(report, text));
    }
    let hints = if report.inputs.iter().any(|i| i.state == Verdict::Missing) {
        " (point --input at the dump files)"
    } else {
        ""
    };
    Err(Error::new(
        Code::CaseDrift,
        format!("case {}: {}{hints}", case.id, report.drifted().join("; ")),
    )
    .with_details(serde_json::to_value(&report).expect("status serializes")))
}

// ---- export --------------------------------------------------------------------------------

fn export(args: &CaseExportArgs) -> Result<Reply> {
    check_outputs(&[&args.output], &[&args.dir])?;
    let case = load_case(&args.dir)?;
    // Evidence is only as good as its artifacts: refuse to export ones that changed.
    let inputs: BTreeMap<String, Option<Blob>> = case
        .inputs
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                Some(Blob {
                    sha256: i.sha256,
                    length: i.length,
                }),
            )
        })
        .collect();
    let report = status(
        &case,
        &inputs,
        &observe_artifacts(&case, &args.dir),
        &Current {
            bme_version: biosmod_core::VERSION,
            catalogs: &[],
        },
    );
    if !report.clean {
        return Err(Error::new(
            Code::CaseDrift,
            format!(
                "case {}: expected recorded artifacts to match their digests | {}",
                case.id,
                report.drifted().join("; ")
            ),
        )
        .with_details(serde_json::to_value(&report).expect("status serializes")));
    }
    let board: Board = read_document(&args.dir, BOARD_DRAFT)?;
    let firmware: FirmwareDraft = read_document(&args.dir, FIRMWARE_DRAFT)?;
    let findings = case_findings(&args.dir)?;
    let files = submission_files(&case, board.clone(), &firmware, findings.clone())?;
    publish_tree(&args.output, &files)?;
    let paths: Vec<&str> = files.iter().map(|(path, _)| path.as_str()).collect();
    let output = display_path(&args.output);
    let text = format!(
        "Exported {} files to {output} (draft board {}, firmware {}, {} findings, {} evidence records)\nThe submission is unreviewed; check vendor, model and revision, then run `bme catalog validate {output}`.\n",
        files.len(),
        board.id,
        firmware.build.id,
        findings.len(),
        case.artifacts.len(),
    );
    Ok(Reply::new(
        json!({
            "directory": output,
            "files": paths,
            "board": board.id,
            "firmware": firmware.build.id,
            "findings": findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            "evidence": case.artifacts.len(),
        }),
        text,
    ))
}

#[cfg(test)]
mod tests;
