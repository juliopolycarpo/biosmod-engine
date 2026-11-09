//! Firmware commands: inspect, scan, plan, patch, verify, extract, replace, derive.

use super::{Ctx, Token, load_sources, parse_token, read_bounded, read_image};
use crate::output::{Reply, table};
use crate::publish::{self, Filesystem, check_outputs, manifest_path};
use crate::sources::{self, LoadPolicy, Loaded};
use crate::{
    DeriveArgs, ExtractArgs, InspectArgs, PatchArgs, PlanArgs, ReplaceArgs, ScanArgs, SelectArgs,
    VerifyArgs,
};
use biosmod_core::analysis::{self, ScanReport, State, module_bytes};
use biosmod_core::catalog::{LeafKind, Scope};
use biosmod_core::firmware::{self, Image, rebuild};
use biosmod_core::plan::document::{
    Blob, MANIFEST_SCHEMA, NOTICE, OutputManifest, PLAN_SCHEMA, PlanDocument, SourcePin,
    Verification,
};
use biosmod_core::plan::{self, Request, Span, changed_bytes, diff, outside_allowlist_unchanged};
use biosmod_core::util::{Digest256, Guid, align, sha256_hex};
use biosmod_core::{Code, Error, Result, json, patch as hunks};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const PLAN_LIMIT: u64 = 16 << 20;

pub fn inspect(args: &InspectArgs) -> Result<Reply> {
    let image = read_image(&args.rom)?;
    let regions = firmware::descriptor_regions(&image.bytes);
    let mut volumes = Vec::new();
    let mut text = format!(
        "Image {} ({} bytes, sha256 {})\n",
        args.rom.display(),
        image.bytes.len(),
        sha256_hex(&image.bytes)
    );
    if let Some(regions) = &regions {
        text += "Intel flash descriptor regions:\n";
        for r in regions {
            let _ = writeln!(text, "  {:<14} {:#09x}-{:#09x}", r.name, r.start, r.end - 1);
        }
    }
    for (v, volume) in image.volumes.iter().enumerate() {
        let files: Vec<serde_json::Value> = volume
            .files
            .iter()
            .enumerate()
            .map(|(f, file)| {
                let compressed = image.leaves.get(&file.guid).is_some_and(|l| l.iter().any(|leaf| leaf.volume == v && leaf.file == f && leaf.compressed));
                json!({
                    "offset": file.offset, "guid": file.guid, "type": file.kind, "attributes": file.attributes,
                    "size": file.size, "name": image.ui_name(v, f), "compressed": compressed, "opaque": file.opaque,
                })
            })
            .collect();
        let _ = writeln!(
            text,
            "FV {:#09x} length {:#x} free {:#x} files {}{}",
            volume.offset,
            volume.length,
            volume.free_bytes(),
            volume.files.len(),
            if volume.filesystem == firmware::FFS2_GUID || volume.filesystem == firmware::FFS3_GUID
            {
                ""
            } else {
                " (non-FFS, opaque)"
            }
        );
        if args.files {
            for (file, row) in volume.files.iter().zip(&files) {
                let flags = [
                    (row["compressed"] == true, " lzma"),
                    (file.opaque, " opaque"),
                ]
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, s)| *s)
                .collect::<String>();
                let _ = writeln!(
                    text,
                    "  {:#09x} {} type {:#04x} size {:#8x} {}{flags}",
                    file.offset,
                    file.guid,
                    file.kind,
                    file.size,
                    row["name"].as_str().unwrap_or("")
                );
            }
        }
        volumes.push(json!({
            "offset": volume.offset, "length": volume.length, "header_size": volume.header_size,
            "filesystem": volume.filesystem, "free": volume.free_bytes(), "files": files,
        }));
    }
    let data = json!({
        "path": args.rom.to_string_lossy(), "length": image.bytes.len(), "sha256": sha256_hex(&image.bytes),
        "flash_base": image.flash_base(), "descriptor_regions": regions, "volumes": volumes,
    });
    Ok(Reply::new(data, text))
}

/// A patch id with the flags its selection needs, e.g. `H01 (--allow-hold --assert superio-nct5532d)`.
fn gated(patch: &analysis::PatchReport) -> String {
    let mut flags = Vec::new();
    if patch.tier == biosmod_core::catalog::Tier::Hold {
        flags.push("--allow-hold".to_string());
    }
    if patch.class == biosmod_core::catalog::PatchClass::Diagnostic {
        flags.push("--allow-diagnostic".to_string());
    }
    flags.extend(patch.requires_facts.iter().map(|f| format!("--assert {f}")));
    if flags.is_empty() {
        patch.id.clone()
    } else {
        format!("{} ({})", patch.id, flags.join(" "))
    }
}

fn scan_text(loaded: &Loaded, report: &ScanReport, rom: &Path) -> String {
    let mut text = String::new();
    let source = format!(
        "{} ({:?}, catalog {} {})",
        loaded.alias, loaded.trust, loaded.catalog.manifest.id, loaded.catalog.manifest.version
    );
    match &report.firmware {
        Some(fw) => {
            let score = report.detection.scores.iter().find(|s| &s.firmware == fw);
            let coverage = score
                .map(|s| format!(", {}/{} recorded modules match", s.matched, s.total))
                .unwrap_or_default();
            let _ = writeln!(
                text,
                "Source: {source}\nFirmware: {fw} (board profile {}){coverage}",
                report.boards.join(", ")
            );
        }
        None if report.detection.ambiguous => {
            let _ = writeln!(
                text,
                "Source: {source}\nFirmware: ambiguous, several builds match equally; pass --firmware"
            );
        }
        None => {
            let _ = writeln!(
                text,
                "Source: {source}\nFirmware: unknown (signature scan only)"
            );
        }
    }
    let mut rows = vec![vec![
        "ID".to_string(),
        "STATE".into(),
        "TIER".into(),
        "TITLE".into(),
    ]];
    for p in &report.patches {
        let tier = if p.manual {
            "manual".to_string()
        } else {
            format!("{:?}", p.tier).to_lowercase()
        };
        let class = if p.class == biosmod_core::catalog::PatchClass::Diagnostic {
            " [diagnostic]"
        } else {
            ""
        };
        rows.push(vec![
            p.id.clone(),
            p.state.label().into(),
            tier,
            format!("{}{class}", p.title),
        ]);
    }
    for line in table(&rows).lines() {
        let _ = writeln!(text, "  {line}");
    }
    for p in &report.patches {
        if !matches!(
            p.state,
            State::Present | State::Fixed | State::NotApplicable
        ) {
            let _ = writeln!(text, "  {}: {}", p.id, p.detail);
        }
        if let Some(blocked) = &p.blocked {
            let _ = writeln!(text, "  {}: not plannable: {blocked}", p.id);
        }
    }
    let plannable: Vec<String> = report
        .patches
        .iter()
        .filter(|p| p.plannable)
        .map(gated)
        .collect();
    let _ = writeln!(
        text,
        "Plannable on this exact build: {}",
        if plannable.is_empty() {
            "none".into()
        } else {
            plannable.join(", ")
        }
    );
    if !report.recommended.is_empty() {
        let _ = writeln!(
            text,
            "Recommended: {}\nNext: bme plan {} --select recommended -o plan.json",
            report.recommended.join(" "),
            rom.display()
        );
    }
    text
}

pub fn scan(ctx: &Ctx, args: &ScanArgs) -> Result<Reply> {
    let image = read_image(&args.rom)?;
    let loaded = load_sources(ctx, &args.source, &[])?;
    let mut reports = Vec::new();
    let mut text = String::new();
    for source in &loaded {
        let report = analysis::scan(&image, &source.catalog, args.source.firmware.as_deref());
        text += &scan_text(source, &report, &args.rom);
        reports.push(json!({"alias": source.alias, "trust": source.trust, "catalog": source.catalog.manifest.id, "catalog_version": source.catalog.manifest.version.to_string(), "report": report}));
    }
    Ok(Reply::new(
        json!({"input": Blob::of(&image.bytes), "sources": reports}),
        text,
    ))
}

/// The resolved inputs of one build.
struct Prepared<'a> {
    source: &'a Loaded,
    request: Request,
    requested: Vec<String>,
}

/// Resolve selection tokens against the loaded sources; all must come from one source.
fn prepare<'a>(
    image: &Image,
    loaded: &'a [Loaded],
    select: &SelectArgs,
    firmware: Option<&str>,
) -> Result<Prepared<'a>> {
    if select.select.is_empty() {
        return Err(Error::new(
            Code::Usage,
            "expected --select <ids> (or --plan for patch)",
        ));
    }
    let mut chosen: Option<usize> = None;
    let mut ids = Vec::new();
    let mut requested = Vec::new();
    for text in &select.select {
        let token = if text == "recommended" {
            Token {
                alias: None,
                id: text.clone(),
                version: None,
            }
        } else {
            parse_token(text)?
        };
        let index = pick_source(loaded, &token, chosen)?;
        if chosen.is_some_and(|c| c != index) {
            return Err(Error::new(
                Code::SelectionInvalid,
                format!(
                    "selection {text:?}: patches from different sources cannot be combined in one plan"
                ),
            ));
        }
        chosen = Some(index);
        let catalog = &loaded[index].catalog;
        if token.id == "recommended" {
            let report = analysis::scan(image, catalog, firmware);
            if report.recommended.is_empty() {
                return Err(Error::new(
                    Code::SelectionInvalid,
                    "recommended: no plannable tier-1 correction on this image",
                ));
            }
            ids.extend(report.recommended.iter().cloned());
            continue;
        }
        let patch = catalog.patches.get(&token.id).ok_or_else(|| {
            Error::new(
                Code::TargetNotFound,
                format!("patch {}: not in source {}", token.id, loaded[index].alias),
            )
        })?;
        if let Some(v) = &token.version
            && *v != patch.version
        {
            return Err(Error::new(
                Code::TargetNotFound,
                format!(
                    "{text}: source {} has version {}",
                    loaded[index].alias, patch.version
                ),
            ));
        }
        ids.push(token.id.clone());
    }
    let index = chosen.expect("non-empty selection");
    for id in &ids {
        let patch = &loaded[index].catalog.patches[id];
        requested.push(format!("{}::{}@{}", loaded[index].alias, id, patch.version));
    }
    let request = Request {
        firmware: firmware.map(str::to_string),
        select: ids,
        facts: select.facts.iter().cloned().collect(),
        allow_hold: select.allow_hold,
        allow_diagnostic: select.allow_diagnostic,
    };
    Ok(Prepared {
        source: &loaded[index],
        request,
        requested,
    })
}

fn pick_source(loaded: &[Loaded], token: &Token, chosen: Option<usize>) -> Result<usize> {
    if let Some(alias) = &token.alias {
        return loaded
            .iter()
            .position(|l| &l.alias == alias)
            .ok_or_else(|| {
                Error::new(Code::TargetNotFound, format!("source {alias}: not loaded"))
            });
    }
    if token.id == "recommended" {
        return Ok(chosen.unwrap_or(0));
    }
    let hits: Vec<usize> = (0..loaded.len())
        .filter(|i| loaded[*i].catalog.patches.contains_key(&token.id))
        .collect();
    match hits.as_slice() {
        [] => Err(Error::new(
            Code::TargetNotFound,
            format!(
                "patch {}: not in {}",
                token.id,
                loaded
                    .iter()
                    .map(|l| l.alias.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
        [one] => Ok(*one),
        _ => Err(Error::new(
            Code::TargetAmbiguous,
            format!(
                "patch {}: defined by {}; qualify it as ALIAS::{}",
                token.id,
                hits.iter()
                    .map(|i| loaded[*i].alias.as_str())
                    .collect::<Vec<_>>()
                    .join(" and "),
                token.id
            ),
        )),
    }
}

fn pin(source: &Loaded) -> SourcePin {
    let catalog = &source.catalog;
    SourcePin {
        alias: source.alias.clone(),
        trust: source.trust.as_str().to_string(),
        location: source.location.clone(),
        scope: match &catalog.scope {
            Scope::Board(path) => Some(path.clone()),
            Scope::All => None,
        },
        catalog_id: catalog.manifest.id.clone(),
        catalog_version: catalog.manifest.version.to_string(),
        manifest_sha256: catalog.manifest_sha256,
        files: catalog.consumed.clone(),
    }
}

fn make_plan(
    ctx: &Ctx,
    rom: &Path,
    select: &SelectArgs,
    source: &crate::SourceArgs,
) -> Result<(PlanDocument, Vec<u8>)> {
    let image = read_image(rom)?;
    let loaded = load_sources(ctx, source, &select.select)?;
    let prepared = prepare(&image, &loaded, select, source.firmware.as_deref())?;
    let built = plan::build(&image, &prepared.source.catalog, &prepared.request)?;
    let catalog = &prepared.source.catalog;
    let document = PlanDocument::new(
        &built,
        &image.bytes,
        pin(prepared.source),
        catalog.boards_for(&built.firmware),
        prepared.requested,
        &prepared.request,
        catalog,
    );
    Ok((document, built.image))
}

fn plan_text(plan: &PlanDocument) -> String {
    let mut text = format!(
        "Firmware {} (source {}::{} {}, {})\nSelected: {}\n",
        plan.firmware,
        plan.source.alias,
        plan.source.catalog_id,
        plan.source.catalog_version,
        plan.source.trust,
        plan.selected.join(" ")
    );
    if !plan.carried.is_empty() {
        let _ = writeln!(text, "Already present and kept: {}", plan.carried.join(" "));
    }
    for c in &plan.components {
        let state = if c.rebuilt {
            format!("rebuilt, file size change {:+}", c.file_size_change)
        } else {
            "unchanged".into()
        };
        let _ = writeln!(
            text,
            "  {:<20} {} at {:#x}: {} ({state})",
            c.name,
            c.ffs_guid,
            c.file_offset,
            c.patches.join("+")
        );
    }
    let moved = plan
        .notes
        .iter()
        .filter(|n| n.starts_with("moved "))
        .count();
    for note in plan.notes.iter().filter(|n| !n.starts_with("moved ")) {
        let _ = writeln!(text, "  note: {note}");
    }
    if moved > 0 {
        let _ = writeln!(
            text,
            "  note: {moved} files move into free space (listed in the plan)"
        );
    }
    let changed: usize = plan.changed.iter().map(|s| s.end - s.start).sum();
    let _ = writeln!(
        text,
        "Changed regions: {} spanning {changed} bytes; output sha256 {}",
        plan.changed.len(),
        plan.output.sha256
    );
    if !plan.identical_to_observed_images.is_empty() {
        let _ = writeln!(
            text,
            "Output is byte-identical to images recorded in evidence: {}",
            plan.identical_to_observed_images.join(", ")
        );
    }
    text
}

pub fn plan(ctx: &Ctx, args: &PlanArgs) -> Result<Reply> {
    check_outputs(&[&args.output], &[&args.rom])?;
    let (document, _) = make_plan(ctx, &args.rom, &args.select, &args.source)?;
    let bytes = biosmod_core::json::pretty(&document);
    crate::config::write_new(&args.output, &bytes)?;
    let text = plan_text(&document)
        + &format!(
            "Wrote plan {}\nNext: bme patch {} --plan {} -o <new-file>\n",
            args.output.display(),
            args.rom.display(),
            args.output.display()
        );
    Ok(Reply::new(
        json!({"plan_file": args.output, "plan": document}),
        text,
    ))
}

/// Load the plan's pinned source offline and confirm it is unchanged.
fn pinned_source(ctx: &Ctx, plan: &PlanDocument, allow_unsigned_local: bool) -> Result<Loaded> {
    let selector = if plan.source.alias == "local" {
        match &plan.source.scope {
            Some(scope) => format!("{}/{scope}", plan.source.location),
            None => plan.source.location.clone(),
        }
    } else {
        plan.source.alias.clone()
    };
    let loaded = sources::load(
        &selector,
        &ctx.config,
        &ctx.paths,
        LoadPolicy {
            allow_unsigned_local,
        },
    )
    .map_err(|e| {
        Error::new(
            if e.code == Code::SourceUntrusted {
                e.code
            } else {
                Code::PlanInputChanged
            },
            format!("plan source {}: {}", plan.source.alias, e.message),
        )
    })?;
    if !plan.source.matches(&loaded.catalog) || loaded.trust.as_str() != plan.source.trust {
        return Err(Error::new(
            Code::PlanInputChanged,
            format!(
                "source {}: catalog snapshot or trust changed since planning; regenerate the plan",
                plan.source.alias
            ),
        ));
    }
    Ok(loaded)
}

fn read_plan(path: &Path) -> Result<PlanDocument> {
    let bytes = read_bounded(path, PLAN_LIMIT)?;
    let plan: PlanDocument = json::parse_strict(&bytes, &path.display().to_string())
        .map_err(|e| Error::new(Code::PlanInvalid, e.message))?;
    if plan.schema != PLAN_SCHEMA {
        return Err(Error::new(
            Code::PlanInvalid,
            format!(
                "{}: expected schema {PLAN_SCHEMA} | received {}",
                path.display(),
                plan.schema
            ),
        ));
    }
    let engine = biosmod_core::plan::document::EngineId::current();
    if plan.engine != engine {
        return Err(Error::new(
            Code::PlanInvalid,
            format!(
                "{}: made by engine {} with {} | this is {} with {}; regenerate the plan",
                path.display(),
                plan.engine.version,
                plan.engine.codec,
                engine.version,
                engine.codec
            ),
        ));
    }
    Ok(plan)
}

/// Rebuild a plan from scratch and confirm every pinned digest.
fn rebuild_from_plan(
    ctx: &Ctx,
    rom: &Path,
    plan: &PlanDocument,
    allow_unsigned_local: bool,
) -> Result<Vec<u8>> {
    let input = read_bounded(rom, super::MAX_IMAGE_BYTES)?;
    if Blob::of(&input) != plan.input {
        return Err(Error::new(
            Code::PlanInputChanged,
            format!(
                "{}: sha256 {} differs from the planned input {}",
                rom.display(),
                Digest256::of(&input),
                plan.input.sha256
            ),
        ));
    }
    let loaded = pinned_source(ctx, plan, allow_unsigned_local)?;
    let image = Image::parse(input)?;
    let request = requested_ids(plan, &loaded)?;
    let built = plan::build(&image, &loaded.catalog, &request)?;
    // Every field is recomputed from the pinned catalog, so editing any of them is detected.
    let rebuilt = PlanDocument::new(
        &built,
        &image.bytes,
        pin(&loaded),
        loaded.catalog.boards_for(&built.firmware),
        plan.requested.clone(),
        &request,
        &loaded.catalog,
    );
    if rebuilt != *plan {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            format!(
                "rebuild does not reproduce the plan (output sha256 {} | planned {})",
                rebuilt.output.sha256, plan.output.sha256
            ),
        ));
    }
    Ok(built.image)
}

/// The build request named by a plan's `requested` list, checked against the pinned source.
///
/// Example: `official::B05@1.0.0` must name source `official` and its current version of B05.
fn requested_ids(plan: &PlanDocument, loaded: &Loaded) -> Result<Request> {
    let mut select = Vec::new();
    for text in &plan.requested {
        let token = parse_token(text).map_err(|e| Error::new(Code::PlanInvalid, e.message))?;
        let version = loaded.catalog.patches.get(&token.id).map(|p| &p.version);
        let qualified = token.alias.as_deref() == Some(loaded.alias.as_str())
            && token.version.is_some()
            && token.version.as_ref() == version;
        if !qualified {
            return Err(Error::new(
                Code::PlanInvalid,
                format!(
                    "requested {text:?} | expected {}::<id>@<version> from the pinned catalog",
                    loaded.alias
                ),
            ));
        }
        select.push(token.id);
    }
    Ok(Request {
        select,
        ..plan.request()
    })
}

pub fn patch(ctx: &Ctx, args: &PatchArgs) -> Result<Reply> {
    let manifest_file = manifest_path(&args.output);
    check_outputs(&[&args.output, &manifest_file], &[&args.rom])?;
    let (plan, output) = match &args.plan {
        Some(path) => {
            let plan = read_plan(path)?;
            let output =
                rebuild_from_plan(ctx, &args.rom, &plan, args.source.allow_unsigned_local)?;
            (plan, output)
        }
        None => {
            let (plan, output) = make_plan(ctx, &args.rom, &args.select, &args.source)?;
            (plan, output)
        }
    };
    let input = read_bounded(&args.rom, super::MAX_IMAGE_BYTES)?;
    if Blob::of(&input) != plan.input {
        return Err(Error::new(
            Code::PlanInputChanged,
            format!(
                "{}: changed while building; nothing was written",
                args.rom.display()
            ),
        ));
    }
    let verification = Verification {
        reparsed: true,
        patches_fixed: plan.selected.iter().chain(&plan.carried).cloned().collect(),
        outside_allowlist_identical: true,
        changed_bytes: changed_bytes(&input, &output),
    };
    let manifest = OutputManifest {
        schema: MANIFEST_SCHEMA.into(),
        output_file: args
            .output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        plan,
        verification,
        notice: NOTICE.into(),
    };
    let bytes = biosmod_core::json::pretty(&manifest);
    publish::publish(&Filesystem, &args.output, &output, &bytes)?;
    let mut text = plan_text(&manifest.plan);
    let _ = writeln!(
        text,
        "Wrote {} and {}\n{NOTICE}\nRead `bme guide flashing` before writing anything to a chip.",
        args.output.display(),
        manifest_file.display()
    );
    Ok(Reply::new(
        json!({"output": args.output.to_string_lossy(), "manifest_file": manifest_file.to_string_lossy(), "manifest": manifest}),
        text,
    ))
}

pub fn verify(ctx: &Ctx, args: &VerifyArgs) -> Result<Reply> {
    let manifest_file = args
        .manifest
        .clone()
        .unwrap_or_else(|| manifest_path(&args.output));
    let bytes = read_bounded(&manifest_file, PLAN_LIMIT)?;
    let manifest: OutputManifest = json::parse_strict(&bytes, &manifest_file.display().to_string())
        .map_err(|e| Error::new(Code::PlanInvalid, e.message))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(Error::new(
            Code::PlanInvalid,
            format!(
                "{}: expected schema {MANIFEST_SCHEMA}",
                manifest_file.display()
            ),
        ));
    }
    if let Some(path) = &args.plan
        && read_plan(path)? != manifest.plan
    {
        return Err(Error::new(
            Code::PlanInputChanged,
            format!("{}: the manifest embeds a different plan", path.display()),
        ));
    }
    let plan = &manifest.plan;
    let input = read_bounded(&args.input, super::MAX_IMAGE_BYTES)?;
    let output = read_bounded(&args.output, super::MAX_IMAGE_BYTES)?;
    if Blob::of(&input) != plan.input {
        return Err(Error::new(
            Code::PlanInputChanged,
            format!(
                "{}: is not the planned input ({})",
                args.input.display(),
                plan.input.sha256
            ),
        ));
    }
    if Blob::of(&output) != plan.output {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            format!(
                "{}: sha256 {} | manifest records {}",
                args.output.display(),
                Digest256::of(&output),
                plan.output.sha256
            ),
        ));
    }
    let structure = Image::parse(output).map_err(|e| {
        Error::new(
            Code::OutputVerificationFailed,
            format!("output structure: {}", e.message),
        )
    })?;
    let output = &structure.bytes;
    outside_allowlist_unchanged(&input, output, &plan.allowlist)?;
    let changed = diff(&input, output);
    if changed != plan.changed {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            "changed regions differ from the plan",
        ));
    }
    let mut checks = vec![
        json!({"check": "input-digest", "ok": true}),
        json!({"check": "output-digest", "ok": true}),
        json!({"check": "structure", "ok": true, "volumes": structure.volumes.len()}),
        json!({"check": "unchanged-outside-allowlist", "ok": true, "allowlist": plan.allowlist}),
        json!({"check": "changed-regions", "ok": true, "regions": changed.len(), "bytes": changed_bytes(&input, output)}),
    ];
    let mut skipped = Vec::new();
    match pinned_source(ctx, plan, true) {
        Ok(loaded) => {
            let mut states = Vec::new();
            for id in plan.selected.iter().chain(&plan.carried) {
                let patch = loaded.catalog.patches.get(id).ok_or_else(|| {
                    Error::new(
                        Code::PlanInputChanged,
                        format!("patch {id}: missing from source"),
                    )
                })?;
                let (state, detail) =
                    analysis::patch_state(&structure, &loaded.catalog, &plan.firmware, patch);
                if state != State::Fixed {
                    return Err(Error::new(
                        Code::OutputVerificationFailed,
                        format!("{id}: output shows {state:?} ({detail}) | expected fixed"),
                    ));
                }
                states.push(json!({"id": id, "state": state}));
            }
            checks.push(json!({"check": "patch-states", "ok": true, "patches": states}));
            let image = Image::parse(input)?;
            let built = plan::build(&image, &loaded.catalog, &plan.request())?;
            if built.image != *output {
                return Err(Error::new(
                    Code::OutputVerificationFailed,
                    "independent rebuild from the pinned catalog differs from the output",
                ));
            }
            checks.push(json!({"check": "reproduced-from-catalog", "ok": true}));
        }
        Err(error) => {
            skipped.push(json!({"check": "patch-states and reproduction", "reason": error.message}))
        }
    }
    let mut text = String::new();
    for c in &checks {
        let _ = writeln!(text, "  ok    {}", c["check"].as_str().unwrap_or(""));
    }
    for s in &skipped {
        let _ = writeln!(
            text,
            "  skip  {}: {}",
            s["check"].as_str().unwrap_or(""),
            s["reason"].as_str().unwrap_or("")
        );
    }
    if !plan.identical_to_observed_images.is_empty() {
        let _ = writeln!(
            text,
            "Output is byte-identical to images recorded in evidence: {} (see `bme catalog show`)",
            plan.identical_to_observed_images.join(", ")
        );
    }
    let _ = writeln!(text, "{NOTICE}");
    let complete = skipped.is_empty();
    let report = json!({"complete": complete, "checks": checks, "skipped": skipped, "identical_to_observed_images": plan.identical_to_observed_images, "notice": NOTICE});
    if !complete {
        return Err(Error::new(
            Code::VerificationIncomplete,
            format!("verification: expected all required checks to complete\n{text}"),
        )
        .with_details(report));
    }
    Ok(Reply::new(report, text))
}

/// The single leaf of `kind` in the file with `guid`.
fn find_leaf(image: &Image, guid: Guid, kind: LeafKind) -> Result<(firmware::LeafRef, Vec<u8>)> {
    let hits: Vec<(firmware::LeafRef, Vec<u8>)> = image
        .leaves
        .get(&guid)
        .into_iter()
        .flatten()
        .filter_map(|leaf| module_bytes(image, leaf, kind, 0).map(|b| (leaf.clone(), b.to_vec())))
        .collect();
    if hits.len() != 1 {
        let opaque = image
            .volumes
            .iter()
            .flat_map(|v| &v.files)
            .any(|f| f.guid == guid && f.opaque);
        let code = if hits.len() > 1 {
            Code::TargetAmbiguous
        } else if opaque {
            Code::FormatUnsupported
        } else {
            Code::TargetNotFound
        };
        return Err(Error::new(
            code,
            format!(
                "GUID {guid}: expected one {kind:?} leaf | received {}",
                hits.len()
            ),
        ));
    }
    Ok(hits.into_iter().next().expect("one hit"))
}

pub fn extract(args: &ExtractArgs) -> Result<Reply> {
    check_outputs(&[&args.output], &[&args.rom])?;
    let image = read_image(&args.rom)?;
    let guid: Guid = args.guid.parse()?;
    let (leaf, data) = find_leaf(&image, guid, args.leaf.into())?;
    crate::config::write_new(&args.output, &data)?;
    let digest = sha256_hex(&data);
    let text = format!(
        "Wrote {}: {} bytes, sha256 {digest}\n",
        args.output.display(),
        data.len()
    );
    Ok(Reply::new(
        json!({"output": args.output, "length": data.len(), "sha256": digest, "compressed": leaf.compressed, "file_offset": image.file(&leaf).offset}),
        text,
    ))
}

pub fn replace(args: &ReplaceArgs) -> Result<Reply> {
    let manifest_file = manifest_path(&args.output);
    check_outputs(&[&args.output, &manifest_file], &[&args.rom, &args.input])?;
    let image = read_image(&args.rom)?;
    let guid: Guid = args.guid.parse()?;
    let kind: LeafKind = args.leaf.into();
    let (leaf, old) = find_leaf(&image, guid, kind)?;
    let new = read_bounded(&args.input, super::MAX_IMAGE_BYTES)?;
    if new.len() != old.len() && !args.allow_resize {
        return Err(Error::new(
            Code::SelectionInvalid,
            format!(
                "module size: expected {} | received {}; pass --allow-resize",
                old.len(),
                new.len()
            ),
        ));
    }
    let body = if kind == LeafKind::AcpiTable {
        [&new[..], &image.leaf_body(&leaf)[old.len()..]].concat()
    } else {
        new.clone()
    };
    let file = image.file(&leaf);
    let data = rebuild::rebuilt_file(&image, &leaf, &body)?;
    if data.len() > file.extent() && !args.allow_resize {
        return Err(Error::new(
            Code::PackingRefused,
            "rebuilt file is larger than the original slot; pass --allow-resize",
        ));
    }
    let data = rebuild::keep_extent(data, file.extent(), file.header_size)?;
    let volume = &image.volumes[leaf.volume];
    let mut out = image.bytes.clone();
    let mut notes = Vec::new();
    let allowlist = if align(data.len(), 8) > file.extent() {
        notes = rebuild::reflow(&image, &mut out, volume, &[(leaf.file, data)])?;
        Span {
            start: volume.offset,
            end: volume.offset + volume.length,
        }
    } else {
        rebuild::write_in_place(&mut out, volume, &[(leaf.file, data)]);
        Span {
            start: file.offset,
            end: file.offset + file.extent(),
        }
    };
    let check = Image::parse(out).map_err(|e| {
        Error::new(
            Code::OutputVerificationFailed,
            format!("re-parsed output: {}", e.message),
        )
    })?;
    if find_leaf(&check, guid, kind)?.1 != new {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            "re-parsed module differs from the input module",
        ));
    }
    let out = check.bytes;
    outside_allowlist_unchanged(&image.bytes, &out, &[allowlist])?;
    let changed_module =
        old.iter().zip(&new).filter(|(a, b)| a != b).count() + old.len().abs_diff(new.len());
    let record = json!({
        "schema": "bme.replace/1", "input": Blob::of(&image.bytes), "output": Blob::of(&out), "guid": guid, "leaf": kind,
        "module_before": Blob::of(&old), "module_after": Blob::of(&new), "module_bytes_changed": changed_module,
        "allowlist": [allowlist], "notes": notes, "notice": NOTICE,
    });
    publish::publish(
        &Filesystem,
        &args.output,
        &out,
        &biosmod_core::json::pretty(&record),
    )?;
    let text = format!(
        "Wrote {} and {}: module bytes changed {changed_module}, image sha256 {}\n{NOTICE}\n",
        args.output.display(),
        manifest_file.display(),
        sha256_hex(&out)
    );
    Ok(Reply::new(record, text))
}

pub fn derive(ctx: &Ctx, args: &DeriveArgs) -> Result<Reply> {
    let loaded = load_sources(ctx, &args.source, std::slice::from_ref(&args.patch))?;
    let token = parse_token(&args.patch)?;
    let index = pick_source(&loaded, &token, None)?;
    let catalog = &loaded[index].catalog;
    let patch = catalog.patches.get(&token.id).ok_or_else(|| {
        Error::new(
            Code::TargetNotFound,
            format!("patch {}: not in catalog", token.id),
        )
    })?;
    let component = patch
        .components(&args.from_firmware)
        .iter()
        .find(|c| c.name == args.component)
        .ok_or_else(|| {
            Error::new(
                Code::TargetNotFound,
                format!(
                    "{}: no component {} for firmware {}",
                    patch.id, args.component, args.from_firmware
                ),
            )
        })?;
    let module = read_bounded(&args.module, super::MAX_IMAGE_BYTES)?;
    let rebased = hunks::rebase(&module, &component.hunks).map_err(|e| {
        Error::new(
            e.code,
            format!(
                "{}/{}: {} in {}; port by hand (`bme guide porting`)",
                patch.id,
                component.name,
                e.message,
                args.module.display()
            ),
        )
    })?;
    let mut draft = component.clone();
    draft.hunks = rebased.hunks;
    let result = hunks::apply(&module, &draft.hunks)?;
    draft.source_sha256 = Digest256::of(&module);
    draft.source_size = module.len() as u64;
    draft.result_sha256 = Digest256::of(&result);
    draft.result_size = result.len() as u64;
    let mut value = serde_json::to_value(&draft).expect("component serializes");
    value["draft"] = json!(
        "UNREVIEWED: offsets moved by signature; disassemble every hunk and recompute absolute addresses before use"
    );
    value["review_offsets"] = json!(rebased.review);
    let data = json!({"status": "applicable", "components": [value]});
    let unique: BTreeSet<usize> = draft.hunks.iter().map(|h| h.offset).collect();
    let text = serde_json::to_string_pretty(&data).expect("serializes")
        + &format!(
            "\n# {} hunks located; {} need their replacement bytes reviewed (review_offsets). Catalog validation rejects this draft until \"draft\" and \"review_offsets\" are removed.\n",
            unique.len(),
            rebased.review.len()
        );
    Ok(Reply::new(data, text))
}
