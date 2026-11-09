//! `catalog` subcommands.

use super::{Ctx, load_sources};
use crate::CatalogCommand;
use crate::config::{SourceKind, io_error, write_atomic, write_new};
use crate::output::{Reply, table};
use crate::sources::{self, DirSource, LoadPolicy, Store};
use crate::transport::{Https, Offline, Transport};
use biosmod_core::catalog::{CATALOG_SCHEMA, Catalog, FileKind, Manifest, Scope, index_files};
use biosmod_core::json::pretty;
use biosmod_core::legacy::{self, Origin};
use biosmod_core::{Code, Error, Result, json};
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(ctx: &mut Ctx, command: CatalogCommand) -> Result<Reply> {
    match command {
        CatalogCommand::Validate { path } => validate(&path),
        CatalogCommand::Index { path, check } => index(&path, check),
        CatalogCommand::Add {
            alias,
            location,
            trust_key,
            allow_unsigned_local,
        } => {
            let source = sources::add(
                &mut ctx.config,
                &alias,
                &location,
                trust_key.as_deref(),
                allow_unsigned_local,
            )?;
            if source.kind == SourceKind::Local {
                sources::load(&alias, &ctx.config, &ctx.paths, LoadPolicy::default())
                    .map_err(|e| e.context(format!("source {alias} not added")))?;
            }
            ctx.config.save(&ctx.paths)?;
            let next = if source.kind == SourceKind::Remote {
                format!("\nNext: bme catalog update {alias}")
            } else {
                String::new()
            };
            Ok(Reply::new(
                json!({"alias": alias, "source": source}),
                format!(
                    "Registered {alias} ({:?}) at {}{next}\n",
                    source.kind, source.location
                ),
            ))
        }
        CatalogCommand::List => Ok(list(ctx)),
        CatalogCommand::Remove { alias, purge } => {
            if ctx.config.sources.remove(&alias).is_none() {
                return Err(Error::new(
                    Code::TargetNotFound,
                    format!("source {alias}: not registered"),
                ));
            }
            ctx.config.save(&ctx.paths)?;
            let cache = ctx.paths.cache.join("sources").join(&alias);
            if purge && cache.exists() {
                fs::remove_dir_all(&cache).map_err(|e| io_error(&cache, e))?;
            }
            Ok(Reply::new(
                json!({"alias": alias, "purged": purge}),
                format!("Removed {alias}\n"),
            ))
        }
        CatalogCommand::Update { alias } => {
            let transport: Box<dyn Transport> = if ctx.offline {
                Box::new(Offline)
            } else {
                Box::new(Https::catalogs())
            };
            let updated = sources::update(&alias, &ctx.config, &ctx.paths, transport.as_ref())?;
            let verb = if updated.changed {
                "Activated"
            } else {
                "Already current:"
            };
            let text = format!(
                "{verb} {} {} ({} files, manifest {})\n",
                updated.catalog_id, updated.version, updated.files, updated.manifest_sha256
            );
            Ok(Reply::new(updated, text))
        }
        CatalogCommand::Show { source } => show(ctx, &source),
        CatalogCommand::ImportX99fix {
            dir,
            maps,
            commit,
            repository,
            output,
        } => import(&dir, &maps, &commit, &repository, &output),
    }
}

fn root_and_scope(path: &Path) -> Result<(PathBuf, Scope)> {
    let real = fs::canonicalize(path).map_err(|e| io_error(path, e))?;
    if real.is_dir() {
        return Ok((real, Scope::All));
    }
    let parent = real.parent().and_then(Path::parent).ok_or_else(|| {
        Error::new(
            Code::Usage,
            format!(
                "{}: expected a catalog directory or boards/<id>.json",
                path.display()
            ),
        )
    })?;
    let relative = real
        .strip_prefix(parent)
        .expect("ancestor")
        .to_string_lossy()
        .replace('\\', "/");
    Ok((parent.to_path_buf(), Scope::Board(relative)))
}

fn summary(catalog: &Catalog) -> serde_json::Value {
    json!({
        "id": catalog.manifest.id, "version": catalog.manifest.version.to_string(), "manifest_sha256": catalog.manifest_sha256,
        "boards": catalog.boards.keys().collect::<Vec<_>>(), "patches": catalog.patches.len(), "evidence": catalog.evidence.len(),
        "files": catalog.consumed.len(),
    })
}

fn validate(path: &Path) -> Result<Reply> {
    let (root, scope) = root_and_scope(path)?;
    let catalog = Catalog::load(&DirSource::new(&root)?, scope)?;
    let text = format!(
        "valid: {} {} ({} boards, {} patches, {} evidence records, {} files verified)\n",
        catalog.manifest.id,
        catalog.manifest.version,
        catalog.boards.len(),
        catalog.patches.len(),
        catalog.evidence.len(),
        catalog.consumed.len()
    );
    Ok(Reply::new(summary(&catalog), text))
}

/// Collect `(relative path, bytes)` for every file under the four content directories.
pub fn collect(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    let mut pending: Vec<PathBuf> = FileKind::ALL
        .iter()
        .map(|k| root.join(k.directory()))
        .filter(|d| d.is_dir())
        .collect();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| io_error(&dir, e))? {
            let entry = entry.map_err(|e| io_error(&dir, e))?;
            let kind = entry.file_type().map_err(|e| io_error(&entry.path(), e))?;
            if kind.is_symlink() {
                return Err(Error::new(
                    Code::CatalogInvalid,
                    format!(
                        "{}: symlinks are not allowed in catalogs",
                        entry.path().display()
                    ),
                ));
            }
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((
                relative,
                fs::read(entry.path()).map_err(|e| io_error(&entry.path(), e))?,
            ));
        }
    }
    Ok(files)
}

fn index(path: &Path, check: bool) -> Result<Reply> {
    let manifest_file = path.join("catalog.json");
    let bytes = fs::read(&manifest_file).map_err(|e| {
        io_error(&manifest_file, e).context(format!("create it first with schema {CATALOG_SCHEMA:?}, id, version, title, engine and an empty files list"))
    })?;
    let mut manifest: Manifest = json::parse_strict(&bytes, "catalog.json")?;
    manifest.files = index_files(&collect(path)?)?;
    let next = pretty(&manifest);
    if check {
        if next != bytes {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{}: index is stale; run `bme catalog index {}`",
                    manifest_file.display(),
                    path.display()
                ),
            ));
        }
        return Ok(Reply::new(
            json!({"current": true, "files": manifest.files.len()}),
            "index is current\n",
        ));
    }
    if next != bytes {
        write_atomic(&manifest_file, &next)?;
    }
    // The new index must describe a valid catalog.
    let catalog = Catalog::load(&DirSource::new(path)?, Scope::All)?;
    Ok(Reply::new(
        summary(&catalog),
        format!("indexed {} files; catalog is valid\n", manifest.files.len()),
    ))
}

fn list(ctx: &Ctx) -> Reply {
    let mut rows = vec![vec![
        "ALIAS".to_string(),
        "KIND".into(),
        "TRUST".into(),
        "SNAPSHOT".into(),
        "LOCATION".into(),
    ]];
    let mut data = vec![
        json!({"alias": sources::OFFICIAL, "kind": "builtin", "trust": "builtin", "location": "compiled into bme"}),
    ];
    rows.push(vec![
        sources::OFFICIAL.into(),
        "builtin".into(),
        "builtin".into(),
        "-".into(),
        "compiled into bme".into(),
    ]);
    for (alias, source) in &ctx.config.sources {
        let state = Store::new(&ctx.paths, alias).state().ok().flatten();
        let snapshot = state
            .as_ref()
            .and_then(|s| {
                s.accepted
                    .iter()
                    .find(|a| a.manifest_sha256 == s.current)
                    .map(|a| a.version.to_string())
            })
            .unwrap_or_else(|| "-".into());
        let trust = if source.trust_key.is_some() {
            "signed"
        } else {
            "unsigned-local"
        };
        rows.push(vec![
            alias.clone(),
            format!("{:?}", source.kind).to_lowercase(),
            trust.into(),
            snapshot.clone(),
            source.location.clone(),
        ]);
        data.push(json!({"alias": alias, "kind": source.kind, "trust": trust, "location": source.location, "snapshot": state}));
    }
    Reply::new(json!({"sources": data}), table(&rows))
}

fn show(ctx: &Ctx, args: &crate::SourceArgs) -> Result<Reply> {
    let mut text = String::new();
    let mut data = Vec::new();
    for loaded in load_sources(ctx, args, &[])? {
        let catalog = &loaded.catalog;
        let _ = writeln!(
            text,
            "{} ({:?}): {} {} - {}",
            loaded.alias,
            loaded.trust,
            catalog.manifest.id,
            catalog.manifest.version,
            catalog.manifest.title
        );
        for board in catalog.boards.values() {
            let revision = board
                .revision
                .label
                .as_deref()
                .unwrap_or("revision unknown");
            let _ = writeln!(
                text,
                "  board {} ({} {}, {revision}, {:?})",
                board.id, board.vendor, board.model, board.revision.status
            );
            for build in &board.firmware {
                let count = catalog.patches_for(&build.id).count();
                let _ = writeln!(
                    text,
                    "    firmware {}: {} ({count} patches)",
                    build.id, build.title
                );
            }
            for fact in &board.facts {
                let _ = writeln!(text, "    fact {}: {}", fact.id, fact.statement);
            }
        }
        for evidence in catalog.evidence.values() {
            let image = evidence
                .image_sha256
                .map(|d| format!(", image {d}"))
                .unwrap_or_default();
            let _ = writeln!(
                text,
                "  evidence {} ({}, {:?}{image}): {}",
                evidence.id, evidence.date, evidence.kind, evidence.title
            );
        }
        data.push(json!({
            "alias": loaded.alias, "trust": loaded.trust, "manifest": catalog.manifest, "manifest_sha256": catalog.manifest_sha256,
            "boards": catalog.boards, "patches": catalog.patches.values().map(|p| json!({"id": p.id, "version": p.version.to_string(), "title": p.title, "class": p.class, "tier": p.tier})).collect::<Vec<_>>(),
            "evidence": catalog.evidence,
        }));
    }
    Ok(Reply::new(json!({"sources": data}), text))
}

fn import(
    dir: &Path,
    maps: &[String],
    commit: &str,
    repository: &str,
    output: &Path,
) -> Result<Reply> {
    let mut boards = BTreeMap::new();
    for map in maps {
        let (board, firmware) = map.split_once('=').ok_or_else(|| {
            Error::new(
                Code::Usage,
                format!("--map {map:?}: expected BOARD=FIRMWARE-ID"),
            )
        })?;
        boards.insert(board.to_string(), firmware.to_string());
    }
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::new(
            Code::Usage,
            format!("--commit {commit:?}: expected a full 40-character commit hash"),
        ));
    }
    let origin = Origin {
        repository: repository.into(),
        commit: commit.to_lowercase(),
    };
    let mut sources: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| io_error(dir, e))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    sources.sort();
    if sources.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!("{}: no *.json records", dir.display()),
        ));
    }
    let mut converted = Vec::new();
    for path in &sources {
        let bytes = fs::read(path).map_err(|e| io_error(path, e))?;
        let name = format!(
            "patches/{}",
            path.file_name().expect("file").to_string_lossy()
        );
        let patch = legacy::import(&bytes, &name, &boards, &origin)?;
        biosmod_core::validation::identifier(&patch.id, "patch id")?;
        converted.push((format!("{}.json", patch.id), pretty(&patch), patch.id));
    }
    fs::create_dir_all(output).map_err(|e| io_error(output, e))?;
    for (file, _, _) in &converted {
        if output.join(file).exists() {
            return Err(Error::new(
                Code::OutputExists,
                format!(
                    "{}: already exists; nothing was written",
                    output.join(file).display()
                ),
            ));
        }
    }
    for (file, bytes, _) in &converted {
        write_new(&output.join(file), bytes)?;
    }
    let ids: Vec<&str> = converted.iter().map(|(_, _, id)| id.as_str()).collect();
    let text = format!(
        "converted {} records into {}: {}\nNext: add board profiles, then bme catalog index <catalog-dir>\n",
        ids.len(),
        output.display(),
        ids.join(" ")
    );
    Ok(Reply::new(json!({"output": output, "patches": ids}), text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_rejects_ids_that_escape_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("output");
        fs::create_dir(&input).unwrap();
        for id in ["../escaped", "/absolute", "C:\\escaped", "dir\\escaped"] {
            let record = json!({"schema": 1, "id": id, "title": "test", "findings": [], "finding_confidence": {}, "local_fix_confidence": "", "physical_fix_confidence": "", "hardware_tested": false, "tier": 1, "supersedes": [], "conflicts": [], "limits": "", "boards": {}});
            fs::write(input.join("record.json"), record.to_string()).unwrap();
            let err = import(&input, &[], &"a".repeat(40), "repo", &output).unwrap_err();
            assert_eq!(err.code, Code::CatalogInvalid);
            assert!(err.message.contains(&format!("{id:?}")), "{err}");
            assert!(
                !output.exists(),
                "invalid ID {id:?} created the output directory"
            );
        }
        assert!(!dir.path().join("escaped.json").exists());
    }
}
