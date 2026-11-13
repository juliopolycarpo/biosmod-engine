//! `catalog init`: scaffold a device repository.
//!
//! A device repository is a catalog directory for one board or board family plus
//! investigation notes. The command only writes files; it never runs git. Its
//! `.gitignore` keeps vendor firmware bytes and machine identifiers out of the
//! history (see `templates/catalog-init/README.md` for the rules it gives users).

use crate::config::io_error;
use crate::output::{Reply, display_path};
use crate::publish::{publish_directory, remove_failed_directory};
use crate::sources::OFFICIAL;
use biosmod_core::catalog::{CATALOG_SCHEMA, Manifest};
use biosmod_core::json::pretty;
use biosmod_core::validation::{engine_version, identifier};
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

/// Version of a fresh catalog.
const INITIAL_VERSION: Version = Version::new(0, 1, 0);

/// What `catalog init` writes, before any of it touches the disk.
struct Scaffold {
    /// Relative path and bytes; `catalog.json` is last because it marks completeness.
    files: Vec<(&'static str, Vec<u8>)>,
}

/// Scaffold the device repository at `dir`.
pub fn init(dir: &Path, id: &str, title: Option<&str>) -> Result<Reply> {
    check_catalog_id(id)?;
    let title = title.unwrap_or(id);
    check_title(title)?;
    let scaffold = scaffold(id, title);
    let files: Vec<(&str, &[u8])> = scaffold
        .files
        .iter()
        .map(|(path, bytes)| (*path, bytes.as_slice()))
        .collect();
    // Refuses an existing `dir` and removes the new one if a write fails.
    publish_directory(dir, &files)?;
    create_directories(dir, &DIRECTORIES)?;

    let shown = display_path(dir);
    let written: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
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
        written.join(" "),
        DIRECTORIES.map(|d| format!("{d}/")).join(" "),
    );
    Ok(Reply::new(
        json!({
            "directory": shown,
            "id": id,
            "title": title,
            "version": INITIAL_VERSION.to_string(),
            "files": written,
            "directories": DIRECTORIES,
        }),
        text,
    ))
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
fn engine_requirement(engine: &Version) -> VersionReq {
    VersionReq::parse(&format!("^{}.{}", engine.major, engine.minor))
        .expect("a caret requirement of two numbers parses")
}

/// The empty `catalog.json`, byte-identical to what `bme catalog index` writes for it.
fn empty_manifest(id: &str, title: &str) -> Vec<u8> {
    pretty(&Manifest {
        schema: CATALOG_SCHEMA.to_string(),
        id: id.to_string(),
        version: INITIAL_VERSION,
        title: title.to_string(),
        engine: engine_requirement(&engine_version()),
        description: None,
        files: Vec::new(),
    })
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

fn scaffold(id: &str, title: &str) -> Scaffold {
    Scaffold {
        files: vec![
            ("README.md", render_readme(id, title).into_bytes()),
            (".gitignore", GITIGNORE.as_bytes().to_vec()),
            (".gitattributes", GITATTRIBUTES.as_bytes().to_vec()),
            ("catalog.json", empty_manifest(id, title)),
        ],
    }
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
        let bytes = empty_manifest("acme-x99", "Acme X99");
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
    fn scaffold_puts_catalog_json_last() {
        let scaffold = scaffold("acme-x99", "Acme X99");
        let names: Vec<&str> = scaffold.files.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            ["README.md", ".gitignore", ".gitattributes", "catalog.json"]
        );
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
        let reply = init(&dir, "acme-x99", Some("Acme X99")).unwrap();
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
        let reply = init(&parent.path().join("repo"), "acme-x99", None).unwrap();
        assert_eq!(reply.data["title"], "acme-x99");
    }

    #[test]
    fn init_refuses_an_existing_directory_and_leaves_it_alone() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"mine").unwrap();
        let error = init(&dir, "acme-x99", None).unwrap_err();
        assert_eq!(error.code, Code::OutputExists, "{error}");
        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"mine");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn init_validates_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("repo");
        assert_eq!(
            init(&dir, "official", None).unwrap_err().code,
            Code::CatalogInvalid
        );
        let error = init(&dir, "acme-x99", Some("")).unwrap_err();
        assert_eq!(error.code, Code::CatalogInvalid);
        assert!(error.message.starts_with("title: expected"), "{error}");
        assert!(
            !dir.exists(),
            "(init): expected nothing written on invalid input"
        );
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
