//! Catalog sources: the bundled official catalog, local directories and signed
//! HTTPS distributions cached as validated, content-addressed snapshots.
//!
//! Firmware commands never touch the network: remote sources are read from
//! their last validated snapshot, and a missing snapshot is an explicit
//! `SOURCE_UNAVAILABLE` failure. Only `bme catalog update` downloads.

use crate::config::{Config, Paths, SourceConfig, SourceKind, io_error, write_atomic};
use crate::transport::{Transport, origin};
use biosmod_core::catalog::{
    Catalog, FileSource, MAX_MANIFEST_BYTES, Manifest, MemorySource, Scope,
};
use biosmod_core::util::Digest256;
use biosmod_core::{Code, Error, Result, json, validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

/// The reserved alias of the bundled catalog.
pub const OFFICIAL: &str = "official";
const SIGNATURE_LIMIT: u64 = 8 << 10;

/// How a loaded catalog is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    /// Compiled into this executable.
    Builtin,
    /// Minisign signature verified against a locally configured key.
    Signed,
    /// Unsigned local directory accepted by explicit user policy.
    UnsignedLocal,
}

/// A loaded source.
#[derive(Debug)]
pub struct Loaded {
    pub alias: String,
    pub trust: Trust,
    pub location: String,
    pub catalog: Catalog,
}

/// The bundled official catalog files.
pub fn builtin_source() -> MemorySource {
    MemorySource::new(
        embedded::FILES
            .iter()
            .map(|(p, b)| (p.to_string(), b.to_vec())),
    )
}

/// A [`FileSource`] confined to one directory: no escapes, no symlinks out, regular files only.
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    pub fn new(root: &Path) -> Result<DirSource> {
        let root = fs::canonicalize(root).map_err(|e| io_error(root, e))?;
        Ok(DirSource { root })
    }
}

impl FileSource for DirSource {
    fn read(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        let path_ok = path == "catalog.json"
            || path == "catalog.json.minisig"
            || validation::relative_path(path).is_ok();
        if !path_ok {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: unsafe catalog path"),
            ));
        }
        let joined = self.root.join(path);
        let real = fs::canonicalize(&joined)
            .map_err(|e| Error::new(Code::CatalogInvalid, format!("{path}: {e}")))?;
        if !real.starts_with(&self.root) {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: resolves outside the catalog directory"),
            ));
        }
        let meta = fs::metadata(&real).map_err(|e| io_error(&real, e))?;
        if !meta.is_file() {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: expected a regular file"),
            ));
        }
        if meta.len() > limit {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: {} bytes exceed the limit of {limit}", meta.len()),
            ));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        fs::File::open(&real)
            .and_then(|f| f.take(limit + 1).read_to_end(&mut bytes))
            .map_err(|e| io_error(&real, e))?;
        if bytes.len() as u64 > limit {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("{path}: grew beyond the limit of {limit} while reading"),
            ));
        }
        Ok(bytes)
    }
}

/// Parse a minisign public key from a file path or a base64 string.
pub fn parse_key(text: &str) -> Result<minisign_verify::PublicKey> {
    let path = Path::new(text);
    if path.is_file() {
        let content = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
        return minisign_verify::PublicKey::decode(content.trim())
            .or_else(|_| minisign_verify::PublicKey::from_base64(content.trim()))
            .map_err(|e| Error::new(Code::Usage, format!("{text}: minisign public key: {e}")));
    }
    minisign_verify::PublicKey::from_base64(text.trim()).map_err(|e| {
        Error::new(
            Code::Usage,
            format!("trust key: expected a minisign public key file or base64 | {e}"),
        )
    })
}

/// The base64 line of a key, for storing in configuration.
pub fn key_line(text: &str) -> Result<String> {
    parse_key(text)?;
    let path = Path::new(text);
    if path.is_file() {
        let content = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
        let line = content
            .lines()
            .map(str::trim)
            .rfind(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .unwrap_or_default();
        return Ok(line.to_string());
    }
    Ok(text.trim().to_string())
}

/// Verify a minisign signature over the exact manifest bytes.
pub fn verify_signature(key: &str, manifest: &[u8], signature: &[u8]) -> Result<()> {
    let key = parse_key(key)?;
    let text = std::str::from_utf8(signature)
        .map_err(|_| Error::new(Code::SourceUntrusted, "signature: expected minisign text"))?;
    let signature = minisign_verify::Signature::decode(text)
        .map_err(|e| Error::new(Code::SourceUntrusted, format!("signature: {e}")))?;
    key.verify(manifest, &signature, false).map_err(|e| {
        Error::new(
            Code::SourceUntrusted,
            format!("catalog.json signature: {e}"),
        )
    })
}

fn check_alias(alias: &str) -> Result<()> {
    validation::identifier(alias, "source alias")
        .map_err(|e| Error::new(Code::Usage, e.message))?;
    // `local` names unregistered directory catalogs inside plans.
    if alias == OFFICIAL || alias == "builtin" || alias == "local" {
        return Err(Error::new(
            Code::Usage,
            format!("source alias {alias:?} is reserved"),
        ));
    }
    Ok(())
}

/// Options that affect how a selector is loaded.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadPolicy {
    /// Accept a direct, unregistered local path.
    pub allow_unsigned_local: bool,
}

/// Load a source by alias or by path (a catalog directory or a board profile file).
pub fn load(selector: &str, config: &Config, paths: &Paths, policy: LoadPolicy) -> Result<Loaded> {
    if selector == OFFICIAL {
        let catalog = Catalog::load(&builtin_source(), Scope::All)
            .map_err(|e| e.context("bundled official catalog"))?;
        return Ok(Loaded {
            alias: OFFICIAL.into(),
            trust: Trust::Builtin,
            location: "builtin".into(),
            catalog,
        });
    }
    if let Some(source) = config.sources.get(selector) {
        return load_registered(selector, source, paths);
    }
    let path = Path::new(selector);
    if !path.exists() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "catalog {selector:?}: not a registered alias or an existing path (see `bme catalog list`)"
            ),
        ));
    }
    if !policy.allow_unsigned_local {
        return Err(Error::new(
            Code::SourceUntrusted,
            format!(
                "{selector}: unregistered local catalog; pass --allow-unsigned-local to use it"
            ),
        ));
    }
    let (root, scope) = locate_root(path)?;
    let catalog = Catalog::load(&DirSource::new(&root)?, scope)?;
    Ok(Loaded {
        alias: "local".into(),
        trust: Trust::UnsignedLocal,
        location: root.display().to_string(),
        catalog,
    })
}

/// For a board file, walk up (at most three levels) to the directory holding `catalog.json`.
fn locate_root(path: &Path) -> Result<(PathBuf, Scope)> {
    let real = fs::canonicalize(path).map_err(|e| io_error(path, e))?;
    if real.is_dir() {
        return Ok((real, Scope::All));
    }
    let mut dir = real.parent();
    for _ in 0..3 {
        let Some(candidate) = dir else { break };
        if candidate.join("catalog.json").is_file() {
            let relative = real
                .strip_prefix(candidate)
                .expect("ancestor")
                .to_string_lossy()
                .replace('\\', "/");
            return Ok((candidate.to_path_buf(), Scope::Board(relative)));
        }
        dir = candidate.parent();
    }
    Err(Error::new(
        Code::CatalogInvalid,
        format!(
            "{}: no catalog.json in its parent directories; run `bme catalog index` first",
            path.display()
        ),
    ))
}

fn load_registered(alias: &str, source: &SourceConfig, paths: &Paths) -> Result<Loaded> {
    match source.kind {
        SourceKind::Local => {
            let dir = DirSource::new(Path::new(&source.location))?;
            let trust = match &source.trust_key {
                Some(key) => {
                    let manifest = dir.read("catalog.json", MAX_MANIFEST_BYTES)?;
                    let signature = dir.read("catalog.json.minisig", SIGNATURE_LIMIT)?;
                    verify_signature(key, &manifest, &signature)?;
                    let catalog = Catalog::load(&Verified::new(&dir, manifest), Scope::All)
                        .map_err(|e| e.context(format!("source {alias}")))?;
                    reject_reserved_id(alias, &catalog.manifest)?;
                    return Ok(Loaded {
                        alias: alias.into(),
                        trust: Trust::Signed,
                        location: source.location.clone(),
                        catalog,
                    });
                }
                None if source.allow_unsigned => Trust::UnsignedLocal,
                None => {
                    return Err(Error::new(
                        Code::SourceUntrusted,
                        format!("source {alias}: unsigned and not allowed by policy"),
                    ));
                }
            };
            let catalog = Catalog::load(&dir, Scope::All)
                .map_err(|e| e.context(format!("source {alias}")))?;
            reject_reserved_id(alias, &catalog.manifest)?;
            Ok(Loaded {
                alias: alias.into(),
                trust,
                location: source.location.clone(),
                catalog,
            })
        }
        SourceKind::Remote => {
            let store = Store::new(paths, alias);
            let state = store.state()?.ok_or_else(|| {
                Error::new(Code::SourceUnavailable, format!("source {alias}: no validated snapshot; run `bme catalog update {alias}` while online"))
            })?;
            let dir = store.snapshot(&state.current);
            let source_dir = DirSource::new(&dir).map_err(|e| {
                Error::new(
                    Code::SourceUnavailable,
                    format!("source {alias}: snapshot missing ({})", e.message),
                )
            })?;
            let manifest = source_dir.read("catalog.json", MAX_MANIFEST_BYTES)?;
            if Digest256::of(&manifest) != state.current {
                return Err(Error::new(
                    Code::SourceUntrusted,
                    format!("source {alias}: cached snapshot does not match its recorded digest"),
                ));
            }
            let key = source.trust_key.as_deref().ok_or_else(|| {
                Error::new(
                    Code::SourceUntrusted,
                    format!("source {alias}: no trust key configured"),
                )
            })?;
            verify_signature(
                key,
                &manifest,
                &source_dir.read("catalog.json.minisig", SIGNATURE_LIMIT)?,
            )?;
            let catalog = Catalog::load(&Verified::new(&source_dir, manifest), Scope::All)
                .map_err(|e| e.context(format!("source {alias} snapshot")))?;
            Ok(Loaded {
                alias: alias.into(),
                trust: Trust::Signed,
                location: source.location.clone(),
                catalog,
            })
        }
    }
}

/// Serves an already verified `catalog.json` from memory and everything else from `inner`.
///
/// The loader then checks every indexed file against the exact manifest bytes
/// whose signature (or digest) was verified, not against a second read.
pub struct Verified<'a> {
    inner: &'a DirSource,
    manifest: Vec<u8>,
}

impl<'a> Verified<'a> {
    pub fn new(inner: &'a DirSource, manifest: Vec<u8>) -> Verified<'a> {
        Verified { inner, manifest }
    }
}

impl FileSource for Verified<'_> {
    fn read(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        if path != "catalog.json" {
            return self.inner.read(path, limit);
        }
        if self.manifest.len() as u64 > limit {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "catalog.json: {} bytes exceed the limit of {limit}",
                    self.manifest.len()
                ),
            ));
        }
        Ok(self.manifest.clone())
    }
}

fn reject_reserved_id(alias: &str, manifest: &Manifest) -> Result<()> {
    if manifest.id == OFFICIAL {
        return Err(Error::new(
            Code::SourceUntrusted,
            format!("source {alias}: catalog id \"official\" is reserved for the bundled catalog"),
        ));
    }
    Ok(())
}

/// Register a source. Registration grants no trust to keys inside the catalog.
pub fn add(
    config: &mut Config,
    alias: &str,
    location: &str,
    trust_key: Option<&str>,
    allow_unsigned: bool,
) -> Result<SourceConfig> {
    check_alias(alias)?;
    if config.sources.contains_key(alias) {
        return Err(Error::new(
            Code::Usage,
            format!("source {alias}: already registered; remove it first"),
        ));
    }
    let key = trust_key.map(key_line).transpose()?;
    let source = if location.starts_with("https://") || location.contains("://") {
        origin(location)?;
        if key.is_none() {
            return Err(Error::new(
                Code::SourceUntrusted,
                "remote sources require --trust-key (minisign public key)",
            ));
        }
        SourceConfig {
            kind: SourceKind::Remote,
            location: location.into(),
            trust_key: key,
            allow_unsigned: false,
        }
    } else {
        let dir = fs::canonicalize(location).map_err(|e| io_error(Path::new(location), e))?;
        if !dir.join("catalog.json").is_file() {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "{}: expected a catalog directory with catalog.json",
                    dir.display()
                ),
            ));
        }
        if key.is_none() && !allow_unsigned {
            return Err(Error::new(
                Code::SourceUntrusted,
                "local source without --trust-key: pass --allow-unsigned-local to accept it unsigned",
            ));
        }
        SourceConfig {
            kind: SourceKind::Local,
            location: dir.display().to_string(),
            trust_key: key,
            allow_unsigned,
        }
    };
    config.sources.insert(alias.into(), source.clone());
    Ok(source)
}

/// Accepted snapshot history for one remote source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub catalog_id: String,
    pub current: Digest256,
    pub accepted: Vec<Accepted>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub version: semver::Version,
    pub manifest_sha256: Digest256,
}

/// The on-disk cache for one source: `sources/<alias>/{state.json,snapshots/<digest>/}`.
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(paths: &Paths, alias: &str) -> Store {
        Store {
            root: paths.cache.join("sources").join(alias),
        }
    }

    pub fn snapshot(&self, digest: &Digest256) -> PathBuf {
        self.root.join("snapshots").join(digest.to_string())
    }

    pub fn state(&self) -> Result<Option<State>> {
        let file = self.root.join("state.json");
        match fs::read(&file) {
            Ok(bytes) => json::parse_strict(&bytes, &file.display().to_string()).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&file, e)),
        }
    }

    fn save_state(&self, state: &State) -> Result<()> {
        write_atomic(
            &self.root.join("state.json"),
            &serde_json::to_vec_pretty(state).expect("state serializes"),
        )
    }

    /// Remove staging directories left by interrupted updates.
    fn clean_staging(&self) {
        let Ok(entries) = fs::read_dir(self.root.join("snapshots")) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".staging-") {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// Outcome of an update.
#[derive(Debug, Clone, Serialize)]
pub struct Updated {
    pub alias: String,
    pub catalog_id: String,
    pub version: String,
    pub manifest_sha256: Digest256,
    pub changed: bool,
    pub files: usize,
}

/// Download, verify and atomically activate a new snapshot; keep the previous one on any failure.
pub fn update(
    alias: &str,
    config: &Config,
    paths: &Paths,
    transport: &dyn Transport,
) -> Result<Updated> {
    let source = config.sources.get(alias).ok_or_else(|| {
        Error::new(
            Code::TargetNotFound,
            format!("source {alias}: not registered"),
        )
    })?;
    if source.kind != SourceKind::Remote {
        return Err(Error::new(
            Code::Usage,
            format!("source {alias}: local sources are read in place; nothing to update"),
        ));
    }
    let key = source.trust_key.as_deref().ok_or_else(|| {
        Error::new(
            Code::SourceUntrusted,
            format!("source {alias}: no trust key"),
        )
    })?;
    let url = source.location.as_str();
    origin(url)?;
    let reject = |e: Error| {
        if e.code == Code::SourceUnavailable {
            e
        } else {
            Error::new(Code::SourceUpdateRejected, e.message)
                .with_details(serde_json::json!({"cause": e.code}))
        }
    };
    let manifest_bytes = transport.get(url, MAX_MANIFEST_BYTES)?;
    let signature = transport.get(&format!("{url}.minisig"), SIGNATURE_LIMIT)?;
    verify_signature(key, &manifest_bytes, &signature).map_err(reject)?;
    let manifest: Manifest =
        json::parse_strict(&manifest_bytes, "remote catalog.json").map_err(reject)?;
    validation::manifest(&manifest).map_err(reject)?;
    reject_reserved_id(alias, &manifest).map_err(reject)?;
    let digest = Digest256::of(&manifest_bytes);
    let store = Store::new(paths, alias);
    let state = store.state()?;
    if let Some(state) = &state {
        check_history(state, &manifest, digest).map_err(reject)?;
        if state.current == digest && store.snapshot(&digest).is_dir() {
            return Ok(Updated {
                alias: alias.into(),
                catalog_id: manifest.id,
                version: manifest.version.to_string(),
                manifest_sha256: digest,
                changed: false,
                files: manifest.files.len(),
            });
        }
    }
    store.clean_staging();
    let snapshots = store.root.join("snapshots");
    fs::create_dir_all(&snapshots).map_err(|e| io_error(&snapshots, e))?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&snapshots)
        .map_err(|e| io_error(&snapshots, e))?;
    let base = &url[..url.rfind('/').map_or(url.len(), |i| i + 1)];
    let write = |path: &str, bytes: &[u8]| -> Result<()> {
        let target = staging.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
        }
        fs::write(&target, bytes).map_err(|e| io_error(&target, e))
    };
    write("catalog.json", &manifest_bytes)?;
    write("catalog.json.minisig", &signature)?;
    for entry in &manifest.files {
        let bytes = transport.get(&format!("{base}{}", entry.path), entry.length)?;
        if bytes.len() as u64 != entry.length || Digest256::of(&bytes) != entry.sha256 {
            return Err(Error::new(
                Code::SourceUpdateRejected,
                format!(
                    "{}: length or sha256 differs from the signed index",
                    entry.path
                ),
            ));
        }
        write(&entry.path, &bytes)?;
    }
    let catalog = Catalog::load(&DirSource::new(staging.path())?, Scope::All).map_err(reject)?;
    let target = store.snapshot(&digest);
    if target.is_dir() {
        // Same content was accepted before; the staged copy is redundant.
        drop(staging);
    } else {
        let staged = staging.keep();
        fs::rename(&staged, &target).map_err(|e| io_error(&target, e))?;
    }
    let mut next = state.unwrap_or(State {
        catalog_id: manifest.id.clone(),
        current: digest,
        accepted: Vec::new(),
    });
    next.current = digest;
    if !next.accepted.iter().any(|a| a.manifest_sha256 == digest) {
        next.accepted.push(Accepted {
            version: manifest.version.clone(),
            manifest_sha256: digest,
        });
    }
    store.save_state(&next)?;
    Ok(Updated {
        alias: alias.into(),
        catalog_id: catalog.manifest.id,
        version: manifest.version.to_string(),
        manifest_sha256: digest,
        changed: true,
        files: manifest.files.len(),
    })
}

/// Reject identity changes, rollbacks and same-version content changes.
fn check_history(state: &State, manifest: &Manifest, digest: Digest256) -> Result<()> {
    if manifest.id != state.catalog_id {
        return Err(Error::new(
            Code::SourceUpdateRejected,
            format!(
                "catalog id changed from {} to {}; re-register the source if intended",
                state.catalog_id, manifest.id
            ),
        ));
    }
    if let Some(same) = state
        .accepted
        .iter()
        .find(|a| a.version == manifest.version && a.manifest_sha256 != digest)
    {
        return Err(Error::new(
            Code::SourceUpdateRejected,
            format!(
                "version {} was accepted with different content ({})",
                same.version, same.manifest_sha256
            ),
        ));
    }
    if let Some(newest) = state.accepted.iter().map(|a| &a.version).max()
        && manifest.version < *newest
    {
        return Err(Error::new(
            Code::SourceUpdateRejected,
            format!(
                "version {} is older than the accepted {newest} (rollback refused)",
                manifest.version
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
