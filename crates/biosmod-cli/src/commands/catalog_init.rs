//! `catalog init`: scaffold a device repository.
//!
//! A device repository is a catalog directory for one board or board family plus
//! investigation notes. The command only writes files; it never runs git. Its
//! `.gitignore` keeps vendor firmware bytes and machine identifiers out of the
//! history (see `templates/catalog-init/README.md` for the rules it gives users).
//!
//! `catalog split` writes the same repository with records in it, through
//! [`write_repository`].

use crate::config::io_error;
use crate::output::{Reply, display_path};
use crate::publish::{publish_directory, remove_failed_directory};
use crate::sources::OFFICIAL;
use biosmod_core::catalog::{CATALOG_SCHEMA, CatalogSource, Manifest, index_files};
use biosmod_core::json::pretty;
use biosmod_core::validation::{engine_version, identifier, repository_url};
use biosmod_core::{Code, Error, Result};
use semver::{Version, VersionReq};
use serde_json::json;
use std::fs;
use std::path::Path;

const README_TEMPLATE: &str = include_str!("../../templates/catalog-init/README.md");
const GITIGNORE: &str = include_str!("../../templates/catalog-init/gitignore");
const GITATTRIBUTES: &str = include_str!("../../templates/catalog-init/gitattributes");

/// Directories created empty. `catalog.json` indexes the files of all of them
/// except `notes` and `work`.
const DIRECTORIES: [&str; 7] = [
    "boards",
    "evidence",
    "findings",
    "notes",
    "patches",
    "provenance",
    "work",
];

/// The files every device repository starts with, in write order; the records
/// come after them and `catalog.json` last.
pub const SCAFFOLD_FILES: [&str; 4] = ["README.md", ".gitignore", ".gitattributes", "catalog.json"];

/// Version of a fresh catalog.
pub const INITIAL_VERSION: Version = Version::new(0, 1, 0);

/// A device repository that was written.
#[derive(Debug)]
pub struct Repository {
    /// The directory as shown to the user.
    pub directory: String,
    pub title: String,
}

/// Scaffold the device repository at `dir`. `url` is the `repository` of its `catalog.json`.
pub fn init(dir: &Path, id: &str, title: Option<&str>, url: Option<&str>) -> Result<Reply> {
    let repository = write_repository(
        dir,
        id,
        title,
        url,
        engine_requirement(&engine_version()),
        Vec::new(),
    )?;
    let shown = &repository.directory;
    let text = format!(
        "Created device repository {id} {INITIAL_VERSION} in {shown}\n\
         \x20 files        {}\n\
         \x20 directories  {}\n\
         Git tracks these files and what you add to the directories. work/ and any other top-level path stay local.\n\
         Git records no empty directory: each one reaches a clone with its first file.\n\
         bme did not run git; run `git init` in {shown} when you want a history.\n\
         Next:\n\
         \x20 cp /path/to/dump.bin {shown}/work/\n\
         \x20 bme case init {shown}/work/dump.bin -o {shown}/work/case\n\
         \x20 bme catalog index {shown}\n\
         \x20 bme catalog validate {shown}\n",
        SCAFFOLD_FILES.join(" "),
        DIRECTORIES.map(|d| format!("{d}/")).join(" "),
    );
    let mut data = json!({
        "directory": shown,
        "id": id,
        "title": repository.title,
        "version": INITIAL_VERSION.to_string(),
        "files": SCAFFOLD_FILES,
        "directories": DIRECTORIES,
    });
    if let Some(url) = url {
        data["repository"] = json!(url);
    }
    Ok(Reply::new(data, text))
}

/// Write the scaffold at `dir` with `records` (`(relative path, bytes)` below
/// `boards/`, `findings/`, `patches/`, `evidence/` or `provenance/`) indexed in
/// its `catalog.json` at [`INITIAL_VERSION`] with the `engine` requirement and the
/// `repository` URL `url`.
///
/// Checks the id, title and URL first, refuses an existing `dir` and removes the new
/// directory if a write fails.
///
/// Example: `write_repository(Path::new("acme"), "acme-x99", None, None, engine, Vec::new())?`.
pub fn write_repository(
    dir: &Path,
    id: &str,
    title: Option<&str>,
    url: Option<&str>,
    engine: VersionReq,
    records: Vec<(String, Vec<u8>)>,
) -> Result<Repository> {
    let title = checked_title(id, title)?;
    check_repository(url)?;
    let files = scaffold(id, title, url, engine, records)?;
    let files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    // Refuses an existing `dir` and removes the new one if a write fails.
    publish_directory(dir, &files)?;
    // Records already created the directories they sit in.
    let missing: Vec<&str> = DIRECTORIES
        .into_iter()
        .filter(|name| !dir.join(name).exists())
        .collect();
    create_directories(dir, &missing)?;
    Ok(Repository {
        directory: display_path(dir).into_owned(),
        title: title.to_string(),
    })
}

/// Check a catalog id and title and return the title, which defaults to the id.
///
/// Example: `checked_title("acme-x99", None)? == "acme-x99"`.
pub fn checked_title<'a>(id: &'a str, title: Option<&'a str>) -> Result<&'a str> {
    check_catalog_id(id)?;
    let title = title.unwrap_or(id);
    check_title(title)?;
    Ok(title)
}

/// Reject a `repository` URL that is not an `https` URL with a host.
///
/// Example: `check_repository(Some("https://example.org/acme"))` passes; `check_repository(Some("git@host:acme"))` fails.
pub fn check_repository(url: Option<&str>) -> Result<()> {
    url.map_or(Ok(()), |url| repository_url(url, "catalog repository"))
}

/// The title of the catalog bundled with `bme`. Its id is the reserved `official`, which
/// only `catalog merge --bundled` may write.
///
/// Example: `bundled_title(None)? == "official"`.
pub fn bundled_title(title: Option<&str>) -> Result<&str> {
    let title = title.unwrap_or(OFFICIAL);
    check_title(title)?;
    Ok(title)
}

/// Reject ids a catalog cannot carry: the identifier rule, and the id of the bundled catalog.
///
/// Example: `check_catalog_id("official")` fails; `check_catalog_id("acme-x99")` passes.
fn check_catalog_id(id: &str) -> Result<()> {
    identifier(id, "catalog id")?;
    if id == OFFICIAL {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "catalog id: expected an id other than the reserved {OFFICIAL:?} | received: {id}"
            ),
        ));
    }
    Ok(())
}

/// Reject a title that is empty or breaks the README heading it becomes.
///
/// Example: `check_title("Acme X99")` passes; `check_title("two\nlines")` fails.
fn check_title(title: &str) -> Result<()> {
    if title.trim().is_empty() || title.chars().any(char::is_control) {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "title: expected one non-empty line without control characters | received: {title:?}"
            ),
        ));
    }
    Ok(())
}

/// The engine requirement a catalog written by this build declares: the same
/// major and minor, like the bundled catalog's `^0.1`.
///
/// Example: for engine `0.1.7` it is `^0.1`.
pub fn engine_requirement(engine: &Version) -> VersionReq {
    VersionReq::parse(&format!("^{}.{}", engine.major, engine.minor))
        .expect("a caret requirement of two numbers parses")
}

/// The header fields of a `catalog.json`; [`manifest_bytes_from`] adds the file index.
pub struct ManifestHeader<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub version: Version,
    pub engine: VersionReq,
    pub description: Option<&'a str>,
    /// The `https` URL of the repository that holds the catalog.
    pub repository: Option<&'a str>,
    /// The pins a merge built the catalog from, in merge order.
    pub sources: Vec<CatalogSource>,
}

/// The `catalog.json` that indexes `records`, byte-identical to what `bme catalog index` writes.
///
/// Example: with no records it is the empty catalog `catalog init` writes.
#[cfg(test)]
pub fn manifest_bytes(
    id: &str,
    title: &str,
    version: Version,
    engine: VersionReq,
    records: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    manifest_bytes_from(
        ManifestHeader {
            id,
            title,
            version,
            engine,
            description: None,
            repository: None,
            sources: Vec::new(),
        },
        records,
    )
}

/// [`manifest_bytes`] with a `description`, a `repository` and the `sources` of a merge.
///
/// Example: `header.sources` holds one pin per merged catalog, in merge order.
pub fn manifest_bytes_from(
    header: ManifestHeader<'_>,
    records: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    Ok(pretty(&Manifest {
        schema: CATALOG_SCHEMA.to_string(),
        id: header.id.to_string(),
        version: header.version,
        title: header.title.to_string(),
        engine: header.engine,
        description: header.description.map(str::to_string),
        repository: header.repository.map(str::to_string),
        sources: header.sources,
        files: index_files(records)?,
    }))
}

/// The README with `{id}` and `{title}` filled in. The id goes first so a title
/// that contains `{id}` stays literal.
///
/// Example: `render_readme("x99", "X99 board")` starts with `# X99 board`.
fn render_readme(id: &str, title: &str) -> String {
    README_TEMPLATE
        .replace("{id}", id)
        .replace("{title}", title)
}

/// Every file of the repository: scaffold files, `records`, then `catalog.json`.
fn scaffold(
    id: &str,
    title: &str,
    url: Option<&str>,
    engine: VersionReq,
    mut records: Vec<(String, Vec<u8>)>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let manifest = manifest_bytes_from(
        ManifestHeader {
            id,
            title,
            version: INITIAL_VERSION,
            engine,
            description: None,
            repository: url,
            sources: Vec::new(),
        },
        &records,
    )?;
    let mut files = vec![
        (
            "README.md".to_string(),
            render_readme(id, title).into_bytes(),
        ),
        (".gitignore".to_string(), GITIGNORE.as_bytes().to_vec()),
        (
            ".gitattributes".to_string(),
            GITATTRIBUTES.as_bytes().to_vec(),
        ),
    ];
    files.append(&mut records);
    files.push(("catalog.json".to_string(), manifest));
    Ok(files)
}

/// Create each empty directory below `root`. If one fails, remove `root` again so
/// nothing half-built stays behind.
///
/// Example: `create_directories(Path::new("repo"), &["boards", "work"])?`.
fn create_directories(root: &Path, names: &[&str]) -> Result<()> {
    names
        .iter()
        .try_for_each(|name| {
            let path = root.join(name);
            fs::create_dir(&path).map_err(|e| io_error(&path, e))
        })
        .map_err(|cause| remove_failed_directory(root, cause))
}

#[cfg(test)]
mod tests {
    use super::*;
    use biosmod_core::catalog::{Catalog, FileKind, Scope};
    use biosmod_core::json::parse_strict;

    use crate::sources::DirSource;

    #[test]
    fn catalog_id_accepts_the_identifier_rule() {
        check_catalog_id("acme-x99_rev1.2").unwrap();
    }

    #[test]
    fn catalog_id_rejects_the_bundled_catalog_id_naming_the_value() {
        let error = check_catalog_id("official").unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert_eq!(
            error.message,
            "catalog id: expected an id other than the reserved \"official\" | received: official"
        );
    }

    #[test]
    fn catalog_id_rejects_values_outside_the_identifier_rule() {
        for id in ["", "-leading", "has space", "../escape", &"a".repeat(65)] {
            let error = check_catalog_id(id).unwrap_err();
            assert_eq!(error.code, Code::CatalogInvalid, "{id:?}");
            assert!(
                error.message.starts_with("catalog id ")
                    && error.message.contains("expected 1-64 characters"),
                "(catalog id {id:?}): expected the identifier rule | received: {error}"
            );
        }
    }

    #[test]
    fn title_accepts_one_line_of_text() {
        check_title("Acme X99-A (rev 1.0), Ünïcode ok").unwrap();
    }

    #[test]
    fn title_rejects_empty_blank_and_multiline_values() {
        for title in ["", "   ", "two\nlines", "tab\there", "nul\0"] {
            let error = check_title(title).unwrap_err();
            assert_eq!(error.code, Code::CatalogInvalid, "{title:?}");
            assert!(
                error.message.contains(&format!("received: {title:?}")),
                "(title): expected the value in the message | received: {error}"
            );
        }
    }

    #[test]
    fn engine_requirement_keeps_major_and_minor() {
        assert_eq!(
            engine_requirement(&Version::new(0, 1, 7)).to_string(),
            "^0.1"
        );
        assert_eq!(
            engine_requirement(&Version::new(1, 4, 2)).to_string(),
            "^1.4"
        );
    }

    #[test]
    fn engine_requirement_matches_this_engine() {
        let engine = engine_version();
        assert!(
            engine_requirement(&engine).matches(&engine),
            "(engine requirement): expected a match for {engine}"
        );
    }

    #[test]
    fn readme_substitutes_id_and_title_once() {
        let readme = render_readme("acme-x99", "Acme {id} board");
        assert!(readme.starts_with("# Acme {id} board\n"), "{readme}");
        assert!(readme.contains("bme catalog add acme-x99 "), "{readme}");
        assert!(
            !readme.contains("{title}"),
            "(README): expected every {{title}} replaced"
        );
    }

    #[test]
    fn empty_manifest_declares_the_given_catalog() {
        let bytes = manifest_bytes(
            "acme-x99",
            "Acme X99",
            INITIAL_VERSION,
            engine_requirement(&engine_version()),
            &[],
        )
        .unwrap();
        let manifest: Manifest = parse_strict(&bytes, "catalog.json").unwrap();
        assert_eq!(manifest.schema, CATALOG_SCHEMA);
        assert_eq!(manifest.id, "acme-x99");
        assert_eq!(manifest.title, "Acme X99");
        assert_eq!(manifest.version, Version::new(0, 1, 0));
        assert!(manifest.files.is_empty());
        assert!(manifest.engine.matches(&engine_version()));
        assert_eq!(
            pretty(&manifest),
            bytes,
            "(catalog.json): expected canonical bytes"
        );
    }

    #[test]
    fn scaffold_puts_catalog_json_last_and_records_between() {
        let record = ("patches/P.json".to_string(), b"{}".to_vec());
        let files = scaffold(
            "acme-x99",
            "Acme X99",
            None,
            engine_requirement(&engine_version()),
            vec![record],
        )
        .unwrap();
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "README.md",
                ".gitignore",
                ".gitattributes",
                "patches/P.json",
                "catalog.json"
            ]
        );
        assert_eq!(SCAFFOLD_FILES[3], "catalog.json");
    }

    #[test]
    fn manifest_bytes_index_the_records_and_stay_canonical() {
        let records = vec![("patches/P.json".to_string(), b"{}\n".to_vec())];
        let bytes = manifest_bytes(
            "acme",
            "Acme",
            Version::new(1, 2, 3),
            VersionReq::parse("^0.1").unwrap(),
            &records,
        )
        .unwrap();
        let manifest: Manifest = parse_strict(&bytes, "catalog.json").unwrap();
        assert_eq!(manifest.version, Version::new(1, 2, 3));
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "patches/P.json");
        assert_eq!(pretty(&manifest), bytes);
    }

    #[test]
    fn manifest_bytes_from_writes_the_description_repository_and_sources_and_round_trips() {
        let source = CatalogSource {
            id: "pr9-b85".into(),
            version: Version::new(0, 1, 0),
            manifest_sha256: biosmod_core::util::Digest256::of(b"catalog.json"),
            repository: Some("https://example.org/pr9-b85".into()),
            commit: Some("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b".into()),
        };
        let bytes = manifest_bytes_from(
            ManifestHeader {
                id: "both",
                title: "Both",
                version: INITIAL_VERSION,
                engine: engine_requirement(&engine_version()),
                description: Some("Two boards"),
                repository: Some("https://example.org/both"),
                sources: vec![source.clone()],
            },
            &[],
        )
        .unwrap();
        let manifest: Manifest = parse_strict(&bytes, "catalog.json").unwrap();
        assert_eq!(manifest.description.as_deref(), Some("Two boards"));
        assert_eq!(
            manifest.repository.as_deref(),
            Some("https://example.org/both")
        );
        assert_eq!(manifest.sources, [source]);
        assert_eq!(pretty(&manifest), bytes);
    }

    #[test]
    fn check_repository_accepts_none_and_an_https_url_and_names_a_refused_value() {
        check_repository(None).unwrap();
        check_repository(Some("https://example.org/acme/x99")).unwrap();
        let error = check_repository(Some("git@github.com:acme/x99.git")).unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert_eq!(
            error.message,
            "catalog repository: expected an https URL | received \"git@github.com:acme/x99.git\""
        );
    }

    #[test]
    fn write_repository_writes_the_repository_url_and_refuses_a_bad_one_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        write_repository(
            &dir,
            "acme-x99",
            None,
            Some("https://example.org/acme/x99"),
            engine_requirement(&engine_version()),
            Vec::new(),
        )
        .unwrap();
        let manifest: Manifest =
            parse_strict(&fs::read(dir.join("catalog.json")).unwrap(), "catalog.json").unwrap();
        assert_eq!(
            manifest.repository.as_deref(),
            Some("https://example.org/acme/x99")
        );

        let refused = parent.path().join("refused");
        let error = write_repository(
            &refused,
            "acme-x99",
            None,
            Some("http://example.org/acme"),
            engine_requirement(&engine_version()),
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "catalog repository: expected an https URL | received \"http://example.org/acme\""
        );
        assert!(
            !refused.exists(),
            "(refused repository): expected nothing written"
        );
    }

    #[test]
    fn manifest_bytes_leave_out_sources_description_and_repository_when_empty() {
        let bytes = manifest_bytes(
            "acme",
            "Acme",
            INITIAL_VERSION,
            engine_requirement(&engine_version()),
            &[],
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("sources")
                && !text.contains("description")
                && !text.contains("repository"),
            "(catalog.json): expected none of the keys | received {text}"
        );
    }

    #[test]
    fn manifest_bytes_reject_a_record_outside_the_layout() {
        let records = vec![("notes/x.md".to_string(), Vec::new())];
        let error = manifest_bytes(
            "acme",
            "Acme",
            INITIAL_VERSION,
            engine_requirement(&engine_version()),
            &records,
        )
        .unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid, "{error}");
    }

    #[test]
    fn write_repository_keeps_records_and_creates_only_the_missing_directories() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        let records = vec![("patches/P.json".to_string(), b"{}\n".to_vec())];
        write_repository(
            &dir,
            "acme-x99",
            None,
            None,
            engine_requirement(&engine_version()),
            records,
        )
        .unwrap();
        assert_eq!(fs::read(dir.join("patches/P.json")).unwrap(), b"{}\n");
        for name in DIRECTORIES {
            assert!(dir.join(name).is_dir(), "{name}");
        }
        let manifest: Manifest =
            parse_strict(&fs::read(dir.join("catalog.json")).unwrap(), "catalog.json").unwrap();
        assert_eq!(manifest.files.len(), 1);
    }

    #[test]
    fn bundled_title_defaults_to_the_reserved_id_and_checks_the_title() {
        assert_eq!(bundled_title(None).unwrap(), "official");
        assert_eq!(
            bundled_title(Some("Official catalog")).unwrap(),
            "Official catalog"
        );
        let error = bundled_title(Some("two\nlines")).unwrap_err();
        assert!(
            error.message.contains("title: expected one non-empty line"),
            "{}",
            error.message
        );
    }

    #[test]
    fn checked_title_defaults_to_the_id_and_checks_both() {
        assert_eq!(checked_title("acme", None).unwrap(), "acme");
        assert_eq!(checked_title("acme", Some("Acme X99")).unwrap(), "Acme X99");
        assert!(checked_title("official", None).is_err());
        assert!(checked_title("acme", Some("two\nlines")).is_err());
    }

    #[test]
    fn templates_use_line_feeds_only() {
        for (name, text) in [
            ("README.md", README_TEMPLATE),
            (".gitignore", GITIGNORE),
            (".gitattributes", GITATTRIBUTES),
        ] {
            assert!(
                !text.contains('\r') && text.ends_with('\n'),
                "({name}): expected LF line endings and a final newline"
            );
        }
    }

    #[test]
    fn gitignore_allowlists_every_catalog_directory_and_not_work() {
        let lines: Vec<&str> = GITIGNORE.lines().collect();
        assert!(
            lines.contains(&"/*"),
            "(.gitignore): expected the top-level deny `/*`"
        );
        for kind in FileKind::ALL {
            let allow = format!("!/{}/", kind.directory());
            assert!(
                lines.contains(&allow.as_str()),
                "(.gitignore): expected {allow} | received {lines:?}"
            );
        }
        assert!(lines.contains(&"!/notes/") && lines.contains(&"!/catalog.json"));
        assert!(
            !lines.iter().any(|line| line.starts_with("!/work")),
            "(.gitignore): expected work/ to stay ignored"
        );
    }

    #[test]
    fn directories_cover_every_indexed_kind() {
        for kind in FileKind::ALL {
            assert!(
                DIRECTORIES.contains(&kind.directory()),
                "(directories): expected {} | received {DIRECTORIES:?}",
                kind.directory()
            );
        }
    }

    #[test]
    fn init_writes_a_catalog_that_loads_and_reports_what_it_wrote() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        let reply = init(&dir, "acme-x99", Some("Acme X99"), None).unwrap();
        assert_eq!(reply.data["id"], "acme-x99");
        assert_eq!(reply.data["version"], "0.1.0");
        assert_eq!(reply.data["directory"], dir.to_string_lossy().as_ref());
        for name in DIRECTORIES {
            assert!(
                dir.join(name).read_dir().unwrap().next().is_none(),
                "{name}"
            );
        }
        let catalog = Catalog::load(&DirSource::new(&dir).unwrap(), Scope::All).unwrap();
        assert_eq!(catalog.manifest.title, "Acme X99");
        assert!(catalog.consumed.is_empty());
    }

    #[test]
    fn init_defaults_the_title_to_the_id() {
        let parent = tempfile::tempdir().unwrap();
        let reply = init(&parent.path().join("repo"), "acme-x99", None, None).unwrap();
        assert_eq!(reply.data["title"], "acme-x99");
    }

    #[test]
    fn init_refuses_an_existing_directory_and_leaves_it_alone() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"mine").unwrap();
        let error = init(&dir, "acme-x99", None, None).unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"mine");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn init_validates_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        assert_eq!(
            init(&dir, "official", None, None).unwrap_err().code,
            Code::CatalogInvalid
        );
        let error = init(&dir, "acme-x99", Some(""), None).unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert!(error.message.starts_with("title: expected"), "{error}");
        assert!(
            !dir.exists(),
            "(init): expected nothing written on invalid input"
        );
    }

    #[test]
    fn init_writes_the_repository_and_refuses_a_bad_url_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        let reply = init(&dir, "acme-x99", None, Some("https://example.org/acme")).unwrap();
        assert_eq!(reply.data["repository"], "https://example.org/acme");
        let catalog = Catalog::load(&DirSource::new(&dir).unwrap(), Scope::All).unwrap();
        assert_eq!(
            catalog.manifest.repository.as_deref(),
            Some("https://example.org/acme")
        );

        let refused = parent.path().join("refused");
        let error = init(&refused, "acme-x99", None, Some("example.org/acme")).unwrap_err();
        assert_eq!(
            error.message,
            "catalog repository: expected an https URL | received \"example.org/acme\""
        );
        assert!(!refused.exists(), "(init): expected nothing written");
    }

    #[test]
    fn create_directories_removes_the_root_when_one_fails() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("repo");
        fs::create_dir(&root).unwrap();
        // `missing/inner` cannot be created because `missing` does not exist.
        let error = create_directories(&root, &["boards", "missing/inner"]).unwrap_err();
        assert_eq!(error.code, Code::Io, "{error}");
        assert!(
            !root.exists(),
            "(create_directories): expected the root removed"
        );
    }
}
