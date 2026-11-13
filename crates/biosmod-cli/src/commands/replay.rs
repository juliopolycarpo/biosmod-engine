//! `bme replay`: run emulated firmware checks and record them as evidence.

mod outcome;

use super::{Ctx, MAX_IMAGE_BYTES, read_bounded};
use crate::config::{io_error, write_new};
use crate::output::Reply;
use crate::toolchain::{self, ScenarioRun, ScriptOutput, ScriptRun, Versions};
use crate::{ReplayRunArgs, ReplayScriptArgs};
use biosmod_core::catalog::{EVIDENCE_SCHEMA, Evidence, EvidenceKind, ReplayInput, ReplayRun};
use biosmod_core::scenario;
use biosmod_core::util::Digest256;
use biosmod_core::{Code, Error, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest scenario file accepted.
const MAX_SCENARIO_BYTES: u64 = 1 << 20;
/// Largest harness script accepted.
const MAX_HARNESS_BYTES: u64 = 4 << 20;
/// Evidence file written into `--output`.
pub const EVIDENCE_FILE: &str = "evidence.json";
/// The emitted documents, one per line, written into `--output`.
pub const RESULT_FILE: &str = "result.jsonl";
/// Board and firmware placeholder for a record that is not tied to a catalog entry.
pub const UNSCOPED: &str = "unscoped";
/// What every replay record says about its own reach.
const LIMITS: &str = "Emulated in Unicorn against simulated hardware models; not observed on physical hardware. The digests identify the inputs and the emitted documents, and say nothing about firmware the modules were not extracted from.";

/// What an evidence record needs from one run.
pub struct RecordSpec<'a> {
    /// File name of the harness or scenario.
    pub harness: &'a str,
    pub harness_role: &'a str,
    pub harness_sha256: Digest256,
    /// Scenario id, when a scenario drove the run.
    pub scenario: Option<&'a str>,
    /// Module name and digest, in command-line order.
    pub modules: Vec<(String, Digest256)>,
    pub versions: &'a Versions,
    pub raw_output: &'a str,
    pub documents: usize,
    pub observations: Vec<String>,
    pub board: &'a str,
    pub firmware: &'a str,
    pub date: String,
}

/// Build the evidence record of a run.
///
/// Example: a harness `fan.py` with module `SioDxeInit.pe` yields kind `offline-validation`
/// and id `replay-fan-<first 8 hex of the output digest>`.
pub fn evidence(spec: RecordSpec) -> Evidence {
    let output_sha256 = Digest256::of(spec.raw_output.as_bytes());
    let mut inputs = vec![ReplayInput {
        role: spec.harness_role.into(),
        name: spec.harness.into(),
        sha256: spec.harness_sha256,
    }];
    inputs.extend(spec.modules.iter().map(|(name, sha256)| ReplayInput {
        role: "module".into(),
        name: name.clone(),
        sha256: *sha256,
    }));
    // The embedded package decides what the emulation does, so its digest is part of the record.
    let mut runtime = BTreeMap::from([
        ("python".to_string(), spec.versions.python.clone()),
        ("bme".to_string(), biosmod_core::VERSION.to_string()),
        ("bme_replay".to_string(), toolchain::replay_package_digest()),
    ]);
    for (name, version) in &spec.versions.packages {
        if let Some(version) = version {
            runtime.insert(name.clone(), version.clone());
        }
    }
    let stem = Path::new(spec.scenario.unwrap_or(spec.harness))
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut observations = vec![format!(
        "{} emitted {} JSON document{}",
        spec.harness,
        spec.documents,
        if spec.documents == 1 { "" } else { "s" }
    )];
    observations.extend(spec.observations);
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        id: format!("replay-{}-{}", slug(&stem), &output_sha256.to_string()[..8]),
        kind: EvidenceKind::OfflineValidation,
        date: spec.date,
        title: format!(
            "Emulated replay of {}",
            spec.scenario.unwrap_or(spec.harness)
        ),
        board: spec.board.into(),
        firmware: spec.firmware.into(),
        configuration: None,
        patches: Vec::new(),
        image_sha256: None,
        built_with: None,
        observations,
        limits: LIMITS.into(),
        source: None,
        host: None,
        replay: Some(ReplayRun {
            harness: spec.harness.into(),
            scenario: spec.scenario.map(str::to_string),
            runtime,
            inputs,
            output_sha256,
        }),
    }
}

/// Lowercase `[a-z0-9-]` form of a file stem, at most 40 characters.
///
/// Example: `slug("Fan_Zero Policy")` is `fan-zero-policy`; an empty result becomes `run`.
pub fn slug(stem: &str) -> String {
    let mut out = String::new();
    for c in stem.chars().flat_map(char::to_lowercase) {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c != '-' || !(out.is_empty() || out.ends_with('-')) {
            out.push(c);
        }
    }
    let out: String = out.trim_end_matches('-').chars().take(40).collect();
    if out.is_empty() { "run".into() } else { out }
}

/// Civil date (`YYYY-MM-DD`, UTC) of a Unix time.
///
/// Example: `civil_date(951_782_400)` is `2000-02-29`.
pub fn civil_date(seconds: u64) -> String {
    // Howard Hinnant's days-from-civil inverse, valid for the whole proleptic Gregorian range.
    let days = (seconds / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Today's UTC date.
pub fn today() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    civil_date(seconds)
}

/// File name of a path, for records.
fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Refuse early when the output directory already holds results.
///
/// Example: a directory with `evidence.json` fails with `OutputExists` before anything runs.
pub fn check_output_free(dir: &Path) -> Result<()> {
    for name in [EVIDENCE_FILE, RESULT_FILE] {
        let path = dir.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(Error::new(
                Code::OutputExists,
                format!(
                    "{}: expected a new file | received an existing one",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Write the emitted documents and the evidence record into `dir`; returns the two paths.
pub fn write_outputs(dir: &Path, raw: &str, evidence: &Evidence) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
    check_output_free(dir)?;
    let result = dir.join(RESULT_FILE);
    let record = dir.join(EVIDENCE_FILE);
    write_new(&result, raw.as_bytes())?;
    write_new(&record, &biosmod_core::json::pretty(evidence))?;
    Ok(vec![record, result])
}

/// `bme replay script`: run a harness and record the run.
pub fn script(ctx: &Ctx, args: &ReplayScriptArgs) -> Result<Reply> {
    if let Some(dir) = &args.output
        && dir.is_dir()
    {
        check_output_free(dir)?;
    }
    let harness = read_bounded(&args.harness, MAX_HARNESS_BYTES)?;
    let mut modules = Vec::new();
    for path in &args.modules {
        let bytes = read_bounded(path, MAX_IMAGE_BYTES)?;
        modules.push((file_name(path), Digest256::of(&bytes)));
    }
    ctx.out.note(format!("running {}", args.harness.display()));
    let run = ScriptRun {
        harness: &args.harness,
        modules: &args.modules,
        args: &args.args,
        timeout: Duration::from_secs(args.timeout),
    };
    let output = toolchain::run_replay_script(ctx, &run)?;
    finish(
        args.output.as_deref(),
        RecordInputs {
            harness_name: file_name(&args.harness),
            harness_role: "harness",
            harness_sha256: Digest256::of(&harness),
            scenario: None,
            modules,
            board: &args.board,
            firmware: &args.firmware,
        },
        &output,
        Vec::new(),
    )
}

/// `bme replay run`: replay a scenario, report each expectation and record the run.
///
/// The record is written whether the scenario passes or not; a failed scenario then ends the
/// command with `REPLAY_FAILED` (or `SCENARIO_INVALID` when the scenario could not be applied to
/// the module, `TOOL_FAILED` when the runtime could not read a result back) and the verdicts in
/// `details`.
pub fn run(ctx: &Ctx, args: &ReplayRunArgs) -> Result<Reply> {
    if let Some(dir) = &args.output
        && dir.is_dir()
    {
        check_output_free(dir)?;
    }
    let scenario_bytes = read_bounded(&args.scenario, MAX_SCENARIO_BYTES)?;
    let scenario = scenario::parse(&scenario_bytes, &args.scenario.display().to_string())?;
    let module = read_bounded(&args.module, MAX_IMAGE_BYTES)?;
    let digest = Digest256::of(&module);
    if digest != scenario.module.sha256 {
        return Err(Error::new(
            Code::PatchSourceMismatch,
            format!(
                "{}: expected module sha256 {} | received {digest}",
                args.module.display(),
                scenario.module.sha256
            ),
        ));
    }
    ctx.out.note(format!(
        "replaying {} on {}",
        scenario.id,
        args.module.display()
    ));
    let output = toolchain::run_replay_scenario(
        ctx,
        &ScenarioRun {
            scenario: &scenario,
            label: &args.scenario,
            module: &args.module,
            timeout: Duration::from_secs(args.timeout),
        },
    )?;
    let outcome = outcome::outcome(&scenario, &output.documents)?;
    let mut reply = finish(
        args.output.as_deref(),
        RecordInputs {
            harness_name: file_name(&args.scenario),
            harness_role: "scenario",
            harness_sha256: Digest256::of(&scenario_bytes),
            scenario: Some(scenario.id.clone()),
            modules: vec![(file_name(&args.module), digest)],
            board: &args.board,
            firmware: &args.firmware,
        },
        &output,
        vec![format!("{}: {}", scenario.id, outcome.summary())],
    )?;
    reply.data["passed"] = json!(outcome.passed);
    reply.data["expectations"] = json!(outcome.verdicts);
    reply.text = format!(
        "{}: {}\n{}{}",
        scenario.id,
        if outcome.passed { "passed" } else { "FAILED" },
        outcome.lines(),
        reply.text
    );
    if outcome.passed {
        return Ok(reply);
    }
    Err(Error::new(
        outcome.code(),
        format!(
            "scenario {}: expected every expectation to pass | received {}{}",
            scenario.id,
            outcome.summary(),
            match outcome.failures().as_str() {
                "" => String::new(),
                failures => format!(" ({failures})"),
            }
        ),
    )
    .with_details(reply.data))
}

/// The identity of what ran, shared by `script` and `run`.
pub struct RecordInputs<'a> {
    pub harness_name: String,
    pub harness_role: &'static str,
    pub harness_sha256: Digest256,
    pub scenario: Option<String>,
    pub modules: Vec<(String, Digest256)>,
    pub board: &'a str,
    pub firmware: &'a str,
}

/// Build the record, write it when `--output` was given, and shape the reply.
pub fn finish(
    output_dir: Option<&Path>,
    inputs: RecordInputs,
    output: &ScriptOutput,
    observations: Vec<String>,
) -> Result<Reply> {
    let record = evidence(RecordSpec {
        harness: &inputs.harness_name,
        harness_role: inputs.harness_role,
        harness_sha256: inputs.harness_sha256,
        scenario: inputs.scenario.as_deref(),
        modules: inputs.modules,
        versions: &output.versions,
        raw_output: &output.raw,
        documents: output.documents.len(),
        observations,
        board: inputs.board,
        firmware: inputs.firmware,
        date: today(),
    });
    let written = match output_dir {
        Some(dir) => write_outputs(dir, &output.raw, &record)?,
        None => Vec::new(),
    };
    let mut text = format!(
        "{} emitted {} document{}\nruntime: {}\n",
        inputs.harness_name,
        output.documents.len(),
        if output.documents.len() == 1 { "" } else { "s" },
        output.versions.summary()
    );
    for path in &written {
        text.push_str(&format!("wrote {}\n", path.display()));
    }
    if written.is_empty() {
        text.push_str("no --output given: the evidence record is in the --json reply only\n");
    }
    Ok(Reply::new(
        json!({
            "documents": output.documents,
            "evidence": record,
            "written": written.iter().map(|p| crate::output::display_path(p)).collect::<Vec<_>>(),
        }),
        text,
    ))
}

#[cfg(all(test, unix))]
mod tests;
