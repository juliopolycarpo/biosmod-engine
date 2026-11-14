//! `catalog split` and `catalog merge`: share records between board catalogs.
//!
//! The reductions and the union live in `biosmod_core::catalog`; this module reads
//! the source catalogs, checks the result loads as a valid catalog and writes it.
//! Nothing here applies a catalog to firmware, so reading a directory needs no
//! trust flag, like `bme catalog validate <path>`.

use super::catalog_init::{
    INITIAL_VERSION, ManifestHeader, SCAFFOLD_FILES, bundled_title, check_repository,
    checked_title, manifest_bytes_from, write_repository,
};
use crate::checkout::head_commit;
use crate::output::{Reply, display_path};
use crate::publish::{check_outputs, publish_directory};
use crate::sources::{DirSource, OFFICIAL, builtin_source};
use biosmod_core::catalog::{
    Catalog, CatalogSource, FileKind, FileSource, MemorySource, MergeInput, PinCheck, PinState,
    Records, Scope, Shared, check_pins, merge_catalogs, split_board,
};
use biosmod_core::json::pretty;
use biosmod_core::util::Digest256;
use biosmod_core::{Code, Error, Result};
use semver::{Version, VersionReq};
use serde::Serialize;
use serde_json::json;
use std::path::Path;

/// A catalog read for splitting or merging.
#[derive(Debug)]
struct Origin {
    /// The id in its `catalog.json`.
    id: String,
    version: Version,
    /// SHA-256 of the exact `catalog.json` bytes.
    manifest_sha256: Digest256,
    /// The `repository` in its `catalog.json`.
    repository: Option<String>,
    /// The commit checked out in its directory; `None` for `official` and for a directory
    /// that is not a git checkout.
    commit: Option<String>,
    engine: VersionReq,
    /// The pins its `catalog.json` lists, empty unless it was written by a merge.
    sources: Vec<CatalogSource>,
    records: Records,
    /// Provenance files as `(path, bytes)`, in index order.
    provenance: Vec<(String, Vec<u8>)>,
}

/// Read `source`: the word `official` for the bundled catalog, otherwise a catalog directory.
///
/// The commit is read from the directory's `.git` after the catalog loads, so a directory
/// that is not a catalog fails first.
///
/// Example: `read_origin("official")?.records.boards.len() == 2` for the bundled catalog.
fn read_origin(source: &str) -> Result<Origin> {
    if source == OFFICIAL {
        read_files(&builtin_source())
    } else {
        let path = Path::new(source);
        let mut origin = read_files(&DirSource::new(path)?)?;
        origin.commit = head_commit(path);
        Ok(origin)
    }
}

/// Load and validate every indexed file of the catalog behind `files`.
fn read_files(files: &dyn FileSource) -> Result<Origin> {
    let catalog = Catalog::load(files, Scope::All)?;
    let mut provenance = Vec::new();
    for entry in catalog
        .manifest
        .files
        .iter()
        .filter(|entry| entry.kind == FileKind::Provenance)
    {
        let bytes = files.read(&entry.path, entry.length)?;
        if Digest256::of(&bytes) != entry.sha256 {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{}: expected sha256 {} | received {}",
                    entry.path,
                    entry.sha256,
                    Digest256::of(&bytes)
                ),
            ));
        }
        provenance.push((entry.path.clone(), bytes));
    }
    Ok(Origin {
        id: catalog.manifest.id.clone(),
        version: catalog.manifest.version.clone(),
        manifest_sha256: catalog.manifest_sha256,
        repository: catalog.manifest.repository.clone(),
        commit: None,
        engine: catalog.manifest.engine.clone(),
        sources: catalog.manifest.sources.clone(),
        records: Records::of(&catalog),
        provenance,
    })
}

/// The record documents as `(path, canonical JSON)`: boards, patches, findings, evidence.
///
/// Example: patch `A02` becomes `patches/A02.json`.
fn record_files(records: &Records) -> Vec<(String, Vec<u8>)> {
    fn files<T: Serialize>(
        directory: &str,
        documents: &std::collections::BTreeMap<String, T>,
    ) -> Vec<(String, Vec<u8>)> {
        documents
            .iter()
            .map(|(id, document)| (format!("{directory}/{id}.json"), pretty(document)))
            .collect()
    }
    let mut all = files(FileKind::Board.directory(), &records.boards);
    all.extend(files(FileKind::Patch.directory(), &records.patches));
    all.extend(files(FileKind::Finding.directory(), &records.findings));
    all.extend(files(FileKind::Evidence.directory(), &records.evidence));
    all
}

/// Load `files` plus `manifest` as a catalog in memory, so a result that would not
/// pass `bme catalog validate` never reaches the disk.
///
/// Example: `check_loads(&files, manifest)?` fails when two boards declare one build.
fn check_loads(files: &[(String, Vec<u8>)], manifest: Vec<u8>) -> Result<Catalog> {
    let mut all = files.to_vec();
    all.push(("catalog.json".to_string(), manifest));
    Catalog::load(&MemorySource::new(all), Scope::All)
}

fn paths(items: &[(String, Vec<u8>)]) -> Vec<&str> {
    items.iter().map(|(path, _)| path.as_str()).collect()
}

/// `none` or the ids separated by spaces.
fn listed(ids: &[impl AsRef<str>]) -> String {
    if ids.is_empty() {
        "none".to_string()
    } else {
        ids.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ")
    }
}

/// `catalog split`: write the device repository of one board.
pub fn split(
    source: &str,
    board: &str,
    dir: &Path,
    id: &str,
    title: Option<&str>,
    url: Option<&str>,
) -> Result<Reply> {
    let title = checked_title(id, title)?;
    check_repository(url)?;
    check_outputs(&[dir], &[])?;
    let origin = read_origin(source)?;
    let split = split_board(&origin.records, board)?;
    let (kept, dropped): (Vec<_>, Vec<_>) = origin
        .provenance
        .into_iter()
        .partition(|(path, _)| split.records.keeps_provenance(path));
    let mut records = record_files(&split.records);
    records.extend(kept);
    // The split keeps the source's engine requirement, so merging it back never disagrees on it.
    let manifest = manifest_bytes_from(
        ManifestHeader {
            id,
            title,
            version: INITIAL_VERSION,
            engine: origin.engine.clone(),
            description: None,
            repository: url,
            sources: Vec::new(),
        },
        &records,
    )?;
    check_loads(&records, manifest)?;
    let kept_provenance: Vec<String> = paths(&records)
        .into_iter()
        .filter(|path| path.starts_with("provenance/"))
        .map(String::from)
        .collect();
    let dropped_provenance: Vec<String> = dropped.into_iter().map(|(path, _)| path).collect();
    let repository = write_repository(dir, id, Some(title), url, origin.engine.clone(), records)?;

    let shown = &repository.directory;
    let kept_ids = |ids: Vec<&String>| ids.into_iter().cloned().collect::<Vec<String>>();
    let kept_patches = kept_ids(split.records.patches.keys().collect());
    let kept_findings = kept_ids(split.records.findings.keys().collect());
    let kept_evidence = kept_ids(split.records.evidence.keys().collect());
    let text = format!(
        "Split board {board} of {source_id} {source_version} into {shown}\n\
         \x20 catalog   {id} {INITIAL_VERSION}\n\
         \x20 kept      {} patches, {} findings, {} evidence records, {} provenance files\n\
         \x20 dropped   patches: {}\n\
         \x20 dropped   findings: {}\n\
         \x20 dropped   evidence: {}\n\
         \x20 dropped   provenance files: {}\n\
         Next:\n\
         \x20 bme catalog validate {shown}\n\
         \x20 bme catalog index {shown} --check\n",
        kept_patches.len(),
        kept_findings.len(),
        kept_evidence.len(),
        kept_provenance.len(),
        listed(&split.dropped.patches),
        listed(&split.dropped.findings),
        listed(&split.dropped.evidence),
        listed(&dropped_provenance),
        source_id = origin.id,
        source_version = origin.version,
    );
    let mut data = json!({
            "directory": shown,
            "id": id,
            "title": repository.title,
            "version": INITIAL_VERSION.to_string(),
            "board": board,
            "source": {"catalog": origin.id, "version": origin.version.to_string()},
            "files": SCAFFOLD_FILES,
            "kept": {
                "patches": kept_patches,
                "findings": kept_findings,
                "evidence": kept_evidence,
                "provenance": kept_provenance,
            },
            "dropped": {
                "patches": split.dropped.patches,
                "findings": split.dropped.findings,
                "evidence": split.dropped.evidence,
                "provenance": dropped_provenance,
            },
    });
    if let Some(url) = url {
        data["repository"] = json!(url);
    }
    Ok(Reply::new(data, text))
}

/// What `catalog merge` writes: nothing (`check`) or a catalog directory.
pub enum MergeOutput<'a> {
    Check,
    Write {
        dir: &'a Path,
        /// `None` writes the catalog bundled with `bme`, whose id is the reserved `official`.
        id: Option<&'a str>,
        title: Option<&'a str>,
        version: Option<&'a str>,
        description: Option<&'a str>,
    },
}

/// `catalog merge`: union the catalogs, then report agreement or write the result.
pub fn merge(sources: &[String], output: MergeOutput<'_>) -> Result<Reply> {
    if sources.len() < 2 {
        return Err(Error::new(
            Code::Usage,
            format!(
                "sources: expected at least 2 catalogs | received {}",
                sources.len()
            ),
        ));
    }
    // Validate the output request before reading any source.
    let target = match &output {
        MergeOutput::Check => None,
        MergeOutput::Write {
            dir,
            id,
            title,
            version,
            description,
        } => {
            let (id, title) = match id {
                Some(id) => (*id, checked_title(id, *title)?),
                None => (OFFICIAL, bundled_title(*title)?),
            };
            if description.is_some_and(|text| text.trim().is_empty()) {
                return Err(Error::new(
                    Code::Usage,
                    "description: expected non-empty text | received an empty value",
                ));
            }
            let version = match version {
                Some(text) => Version::parse(text).map_err(|e| {
                    Error::new(
                        Code::Usage,
                        format!("version: expected a semantic version | received {text:?} ({e})"),
                    )
                })?,
                None => INITIAL_VERSION,
            };
            check_outputs(&[dir], &[])?;
            Some((*dir, id, title, version, *description))
        }
    };
    let origins = sources
        .iter()
        .map(|source| read_origin(source).map_err(|e| e.context(format!("catalog {source}"))))
        .collect::<Result<Vec<_>>>()?;
    let inputs: Vec<MergeInput<'_>> = origins
        .iter()
        .map(|origin| MergeInput {
            catalog_id: &origin.id,
            version: &origin.version,
            manifest_sha256: origin.manifest_sha256,
            repository: origin.repository.as_deref(),
            commit: origin.commit.as_deref(),
            sources: &origin.sources,
            engine: &origin.engine,
            records: &origin.records,
            provenance: &origin.provenance,
        })
        .collect();
    let merged = merge_catalogs(&inputs)?;
    let mut files = record_files(&merged.records);
    files.extend(merged.provenance.iter().cloned());

    let (id, title, version, description) = match &target {
        Some((_, id, title, version, description)) => (*id, *title, version.clone(), *description),
        None => ("merge-check", "merge check", INITIAL_VERSION, None),
    };
    let manifest = manifest_bytes_from(
        ManifestHeader {
            id,
            title,
            version: version.clone(),
            engine: merged.engine.clone(),
            description,
            repository: None,
            sources: merged.sources.clone(),
        },
        &files,
    )?;
    let catalog = check_loads(&files, manifest.clone())?;
    let counts = json!({
        "boards": catalog.boards.len(),
        "patches": catalog.patches.len(),
        "findings": catalog.findings.len(),
        "evidence": catalog.evidence.len(),
        "provenance": merged.provenance.len(),
    });
    let ids: Vec<&str> = origins.iter().map(|origin| origin.id.as_str()).collect();
    let shared = shared_json(&merged.shared);
    let summary = format!(
        "{} boards, {} patches, {} findings, {} evidence records, {} provenance files",
        catalog.boards.len(),
        catalog.patches.len(),
        catalog.findings.len(),
        catalog.evidence.len(),
        merged.provenance.len()
    );
    let shared_text = format!(
        "{} boards, {} patches, {} findings, {} evidence records, {} provenance files",
        merged.shared.boards.len(),
        merged.shared.patches.len(),
        merged.shared.findings.len(),
        merged.shared.evidence.len(),
        merged.shared.provenance.len()
    );
    let Some((dir, id, title, version, _)) = target else {
        let pins = check_pins(&inputs);
        return Ok(Reply::new(
            json!({
                "agree": true, "catalogs": ids, "merged": counts, "shared": shared, "pins": pins,
            }),
            format!(
                "The catalogs agree: {}\n\x20 merged   {summary}\n\x20 shared   {shared_text}\n{}",
                ids.join(", "),
                pin_lines(&pins)
            ),
        ));
    };
    let mut written = files;
    written.push(("catalog.json".to_string(), manifest));
    let written_files: Vec<(&str, &[u8])> = written
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    publish_directory(dir, &written_files)?;
    let shown = display_path(dir);
    Ok(Reply::new(
        json!({
            "directory": shown, "id": id, "title": title, "version": version.to_string(),
            "catalogs": ids, "merged": counts, "shared": shared, "sources": merged.sources,
            "description": description,
        }),
        format!(
            "Merged {} into {shown}\n\x20 catalog   {id} {version}\n\x20 merged    {summary}\n\x20 shared    {shared_text}\nNext:\n\x20 bme catalog validate {shown}\n",
            ids.join(", ")
        ),
    ))
}

/// One line per pin check, or nothing: which catalog lists the source, and whether its
/// current `catalog.json` still has the pinned digest.
///
/// The source is named as it was given, so two sources with one id read `dev (#1)` and
/// `dev (#2)` and the moved one can be told apart.
///
/// A pin that records a commit shows its first 12 characters when the source moved, so the
/// line says which commit the digest was taken at.
///
/// Example: `  pin      rebuilt lists pr9-b85 0.1.0: pinned`.
fn pin_lines(pins: &[PinCheck]) -> String {
    pins.iter()
        .map(|pin| {
            let state = match pin.state {
                PinState::Pinned => pin.state.label().to_string(),
                PinState::Moved => {
                    let at = pin
                        .commit
                        .as_deref()
                        .map(|commit| format!(" at commit {}", commit.get(..12).unwrap_or(commit)))
                        .unwrap_or_default();
                    format!(
                        "{} (pinned {}{at}, current {})",
                        pin.state.label(),
                        pin.pinned,
                        pin.current
                    )
                }
            };
            format!(
                "  pin      {} lists {} {}: {state}\n",
                pin.listed_by, pin.source, pin.version
            )
        })
        .collect()
}

fn shared_json(shared: &Shared) -> serde_json::Value {
    json!({
        "boards": shared.boards,
        "patches": shared.patches,
        "findings": shared.findings,
        "evidence": shared.evidence,
        "provenance": shared.provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::catalog_init::{engine_requirement, manifest_bytes};
    use crate::sources::builtin_source;
    use biosmod_core::validation::engine_version;

    fn official() -> Origin {
        read_files(&builtin_source()).unwrap()
    }

    #[test]
    fn read_files_loads_records_and_provenance_of_the_bundled_catalog() {
        let origin = official();
        assert_eq!(origin.id, OFFICIAL);
        assert_eq!(origin.records.boards.len(), 2);
        let paths: Vec<&str> = origin.provenance.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["provenance/MRC-BREADCRUMBS/mrc-breadcrumbs.asm"]);
        assert!(!origin.provenance[0].1.is_empty());
    }

    #[test]
    fn read_origin_names_a_missing_directory() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("absent");
        let error = read_origin(missing.to_str().unwrap()).unwrap_err();
        assert_eq!(error.code, Code::Io, "{error}");
        assert!(error.message.contains("absent"), "{error}");
    }

    #[test]
    fn record_files_use_one_canonical_document_per_id() {
        let origin = official();
        let files = record_files(&origin.records);
        assert_eq!(files.len(), 2 + 19 + 40 + 10);
        let paths = paths(&files);
        assert!(paths.contains(&"patches/B02-B03.json"));
        assert!(paths.contains(&"boards/machinist-pr9-b85.json"));
        let (_, bytes) = files
            .iter()
            .find(|(p, _)| p == "findings/B09.json")
            .unwrap();
        assert!(
            bytes.ends_with(b"}\n"),
            "(findings/B09.json): expected a final newline"
        );
    }

    #[test]
    fn check_loads_accepts_a_valid_catalog_and_rejects_one_that_would_not_validate() {
        let origin = official();
        let files = record_files(&origin.records);
        let engine = engine_requirement(&engine_version());
        let manifest =
            manifest_bytes("copy", "Copy", INITIAL_VERSION, engine.clone(), &files).unwrap();
        check_loads(&files, manifest).unwrap();

        // A second board that ships a build the first already ships is not a valid catalog.
        let mut records = origin.records.clone();
        let mut twin = records.boards.values().next().unwrap().clone();
        twin.id = "twin-board".into();
        records.boards.insert(twin.id.clone(), twin);
        let files = record_files(&records);
        let manifest = manifest_bytes("copy", "Copy", INITIAL_VERSION, engine, &files).unwrap();
        let error = check_loads(&files, manifest).unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert!(
            error.message.contains("declared by both"),
            "(twin board): expected a duplicate firmware build | received {error}"
        );
    }

    #[test]
    fn listed_shows_none_for_an_empty_list() {
        let none: [&str; 0] = [];
        assert_eq!(listed(&none), "none");
        assert_eq!(listed(&["A".to_string(), "B".to_string()]), "A B");
    }

    /// A pin check of `id`, with the digests of `pinned` and `current` and an optional commit.
    fn pin_check(state: PinState, commit: Option<&str>) -> PinCheck {
        PinCheck {
            listed_by: "merged".into(),
            source: "pr9".into(),
            id: "pr9".into(),
            version: Version::new(0, 1, 0),
            pinned: Digest256::of(b"old"),
            current: Digest256::of(b"new"),
            commit: commit.map(str::to_string),
            state,
        }
    }

    #[test]
    fn a_moved_pin_line_names_the_first_12_characters_of_its_commit() {
        let commit = "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b";
        let line = pin_lines(&[pin_check(PinState::Moved, Some(commit))]);
        assert_eq!(
            line,
            format!(
                "  pin      merged lists pr9 0.1.0: moved (pinned {} at commit 1a2b3c4d5e6f, current {})\n",
                Digest256::of(b"old"),
                Digest256::of(b"new")
            )
        );
        let without = pin_lines(&[pin_check(PinState::Moved, None)]);
        assert!(!without.contains("commit"), "{without}");
    }

    #[test]
    fn a_pinned_line_stays_short_even_when_the_entry_has_a_commit() {
        let line = pin_lines(&[pin_check(PinState::Pinned, Some(&"a".repeat(40)))]);
        assert_eq!(line, "  pin      merged lists pr9 0.1.0: pinned\n");
    }

    #[test]
    fn read_origin_records_the_commit_of_a_checkout_and_none_for_official_or_a_plain_directory() {
        assert_eq!(read_origin(OFFICIAL).unwrap().commit, None);
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        crate::commands::catalog_init::init(&dir, "acme", None, Some("https://example.org/acme"))
            .unwrap();
        let plain = read_origin(dir.to_str().unwrap()).unwrap();
        assert_eq!(plain.commit, None);
        assert_eq!(
            plain.repository.as_deref(),
            Some("https://example.org/acme")
        );

        let commit = "ab".repeat(20);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/HEAD"), format!("{commit}\n")).unwrap();
        assert_eq!(
            read_origin(dir.to_str().unwrap())
                .unwrap()
                .commit
                .as_deref(),
            Some(commit.as_str())
        );
    }

    #[test]
    fn merge_needs_two_sources_before_reading_any() {
        let error = merge(&["does-not-exist".to_string()], MergeOutput::Check).unwrap_err();
        assert_eq!(error.code, Code::Usage);
        assert_eq!(
            error.message,
            "sources: expected at least 2 catalogs | received 1"
        );
    }
}
