//! Read the commit a git checkout has at its HEAD, from its files alone.
//!
//! `catalog merge` records the commit of each source directory. It reads `.git`
//! instead of running git, so it needs no git binary and executes nothing from
//! the directory. Anything unreadable or malformed means "no commit": a catalog
//! directory that is not a checkout is normal, and a bad file under `.git` must
//! never fail a merge.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// Largest `HEAD`, loose ref, `.git` or `commondir` file read.
const SMALL_FILE_LIMIT: u64 = 4096;
/// Most of `packed-refs` read: a line scan, so this bounds memory and time.
const PACKED_REFS_LIMIT: u64 = 32 << 20;
/// Most symbolic refs followed before giving up.
const MAX_REF_DEPTH: usize = 5;

/// The commit checked out in `dir`, as 40 (SHA-1) or 64 (SHA-256) lowercase hex characters.
///
/// `dir/.git` is a directory, or a file `gitdir: <path>` as in a worktree or submodule.
/// HEAD is a hash (detached) or `ref: refs/...`, resolved through the loose ref file
/// and then `packed-refs`. A worktree takes shared refs from its `commondir`.
///
/// This is the checkout's HEAD, not proof that the tree is clean: uncommitted
/// changes are covered by the digest of `catalog.json`, not by the commit.
///
/// Example: a directory with `.git/HEAD` holding 40 hex digits returns them; a plain
/// directory returns `None`.
pub fn head_commit(dir: &Path) -> Option<String> {
    let git_dir = git_dir(dir)?;
    let head = read_text(&git_dir.join("HEAD"))?;
    let head = head.trim();
    match head.strip_prefix("ref:") {
        Some(reference) => {
            let mut homes = vec![git_dir.clone()];
            if let Some(common) = common_dir(&git_dir) {
                homes.push(common);
            }
            resolve_ref(&homes, reference.trim(), MAX_REF_DEPTH)
        }
        None => object_id(head),
    }
}

/// The git directory of `dir`: `.git` itself, or the target of a `gitdir:` file.
fn git_dir(dir: &Path) -> Option<PathBuf> {
    let dot_git = dir.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let text = read_text(&dot_git)?;
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    if target.is_empty() {
        return None;
    }
    Some(dir.join(target)).filter(|path| path.is_dir())
}

/// The directory a linked worktree shares refs with, from its `commondir` file.
fn common_dir(git_dir: &Path) -> Option<PathBuf> {
    let text = read_text(&git_dir.join("commondir"))?;
    let target = text.trim();
    if target.is_empty() {
        return None;
    }
    Some(git_dir.join(target)).filter(|path| path.is_dir())
}

/// Resolve `reference` against each of `homes` in order: loose file first, then `packed-refs`.
fn resolve_ref(homes: &[PathBuf], reference: &str, depth: usize) -> Option<String> {
    if depth == 0 || !is_safe_ref(reference) {
        return None;
    }
    for home in homes {
        if let Some(text) = read_text(&home.join(reference)) {
            let text = text.trim();
            return match text.strip_prefix("ref:") {
                Some(next) => resolve_ref(homes, next.trim(), depth - 1),
                None => object_id(text),
            };
        }
    }
    homes
        .iter()
        .find_map(|home| packed_ref(&home.join("packed-refs"), reference))
}

/// A ref name that stays below the git directory: `refs/` and plain components.
fn is_safe_ref(reference: &str) -> bool {
    reference.starts_with("refs/")
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !reference.contains(['\\', '\0'])
}

/// The hash of `reference` in a `packed-refs` file: lines of `<hash> <ref>`, with
/// `#` headers and `^` peeled lines skipped.
fn packed_ref(path: &Path, reference: &str) -> Option<String> {
    let file = open_regular(path)?;
    for line in BufReader::new(file.take(PACKED_REFS_LIMIT)).lines() {
        let line = line.ok()?;
        if line.starts_with(['#', '^']) {
            continue;
        }
        if let Some((hash, name)) = line.split_once(' ')
            && name == reference
        {
            return object_id(hash);
        }
    }
    None
}

/// `text` when it is 40 or 64 lowercase hex characters.
fn object_id(text: &str) -> Option<String> {
    let ok = matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'));
    ok.then(|| text.to_string())
}

/// Open `path` only when it is a regular file.
///
/// A source directory can come from an untrusted archive. Opening a named pipe there
/// blocks until someone writes to it, and a link to a device such as `/dev/zero` never
/// ends, so anything that is not a regular file reads as absent.
fn open_regular(path: &Path) -> Option<File> {
    // `metadata` follows symbolic links: git itself links refs, and the target's type decides.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    File::open(path).ok()
}

/// The UTF-8 text of a small file, `None` when it is missing, unreadable, longer
/// than [`SMALL_FILE_LIMIT`] or not text.
fn read_text(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(SMALL_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > SMALL_FILE_LIMIT {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SHA1: &str = "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b";
    const OTHER: &str = "ffeeddccbbaaffeeddccbbaaffeeddccbbaaffee";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Write `text` at `path`, creating its parent directories.
    fn put(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// A checkout directory whose `.git/HEAD` holds `head`.
    fn checkout(head: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        put(&dir.path().join(".git/HEAD"), head);
        dir
    }

    #[test]
    fn a_detached_head_is_the_commit() {
        let dir = checkout(&format!("{SHA1}\n"));
        assert_eq!(head_commit(dir.path()).as_deref(), Some(SHA1));
    }

    #[test]
    fn a_sha256_repository_commit_is_accepted() {
        let dir = checkout(&format!("{SHA256}\n"));
        assert_eq!(head_commit(dir.path()).as_deref(), Some(SHA256));
    }

    #[test]
    fn a_branch_resolves_through_its_loose_ref() {
        let dir = checkout("ref: refs/heads/main\n");
        put(
            &dir.path().join(".git/refs/heads/main"),
            &format!("{SHA1}\n"),
        );
        put(
            &dir.path().join(".git/packed-refs"),
            &format!("{OTHER} refs/heads/main\n"),
        );
        assert_eq!(
            head_commit(dir.path()).as_deref(),
            Some(SHA1),
            "(loose ref): expected it to win over packed-refs"
        );
    }

    #[test]
    fn a_branch_resolves_through_packed_refs_when_it_has_no_loose_ref() {
        let dir = checkout("ref: refs/heads/release/1.0\n");
        put(
            &dir.path().join(".git/packed-refs"),
            &format!(
                "# pack-refs with: peeled fully-peeled sorted \n{OTHER} refs/heads/main\n^{OTHER}\n{SHA1} refs/heads/release/1.0\n{OTHER} refs/tags/v1\n"
            ),
        );
        assert_eq!(head_commit(dir.path()).as_deref(), Some(SHA1));
    }

    #[test]
    fn a_symbolic_loose_ref_is_followed_a_few_times_and_a_loop_gives_none() {
        let dir = checkout("ref: refs/heads/alias\n");
        put(
            &dir.path().join(".git/refs/heads/alias"),
            "ref: refs/heads/main\n",
        );
        put(
            &dir.path().join(".git/refs/heads/main"),
            &format!("{SHA1}\n"),
        );
        assert_eq!(head_commit(dir.path()).as_deref(), Some(SHA1));

        let looped = checkout("ref: refs/heads/a\n");
        put(
            &looped.path().join(".git/refs/heads/a"),
            "ref: refs/heads/b\n",
        );
        put(
            &looped.path().join(".git/refs/heads/b"),
            "ref: refs/heads/a\n",
        );
        assert_eq!(head_commit(looped.path()), None);
    }

    #[test]
    fn a_dot_git_file_points_at_the_git_directory_relative_or_absolute() {
        let dir = tempfile::tempdir().unwrap();
        put(&dir.path().join("modules/sub/HEAD"), &format!("{SHA1}\n"));
        put(&dir.path().join("sub/.git"), "gitdir: ../modules/sub\n");
        assert_eq!(head_commit(&dir.path().join("sub")).as_deref(), Some(SHA1));

        let absolute = dir.path().join("elsewhere");
        put(&absolute.join("HEAD"), &format!("{OTHER}\n"));
        put(
            &dir.path().join("other/.git"),
            &format!("gitdir: {}\n", absolute.display()),
        );
        assert_eq!(
            head_commit(&dir.path().join("other")).as_deref(),
            Some(OTHER)
        );
    }

    #[test]
    fn a_linked_worktree_reads_its_head_and_takes_refs_from_the_common_directory() {
        let dir = tempfile::tempdir().unwrap();
        let common = dir.path().join("main/.git");
        put(&common.join("HEAD"), "ref: refs/heads/main\n");
        put(&common.join("refs/heads/main"), &format!("{OTHER}\n"));
        put(&common.join("refs/heads/feature"), &format!("{SHA1}\n"));
        let admin = common.join("worktrees/wt");
        put(&admin.join("HEAD"), "ref: refs/heads/feature\n");
        put(&admin.join("commondir"), "../..\n");
        let tree = dir.path().join("wt");
        put(
            &tree.join(".git"),
            &format!("gitdir: {}\n", admin.display()),
        );
        assert_eq!(head_commit(&tree).as_deref(), Some(SHA1));

        // A branch only packed in the common directory resolves there too.
        put(&admin.join("HEAD"), "ref: refs/heads/packed\n");
        put(
            &common.join("packed-refs"),
            &format!("{OTHER} refs/heads/packed\n"),
        );
        assert_eq!(head_commit(&tree).as_deref(), Some(OTHER));
    }

    #[test]
    fn a_directory_that_is_not_a_checkout_has_no_commit() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(head_commit(dir.path()), None);
        assert_eq!(head_commit(&dir.path().join("absent")), None);

        // A `.git` directory with no HEAD, and a `.git` file naming a missing directory.
        fs::create_dir(dir.path().join(".git")).unwrap();
        assert_eq!(head_commit(dir.path()), None);
        let linked = tempfile::tempdir().unwrap();
        put(&linked.path().join(".git"), "gitdir: nowhere\n");
        assert_eq!(head_commit(linked.path()), None);
    }

    #[test]
    fn a_malformed_head_or_ref_gives_no_commit_and_no_error() {
        let upper = SHA1.to_uppercase();
        for head in [
            "",
            "\n",
            "not a hash",
            &SHA1[..39],
            &format!("{SHA1}0"),
            &upper,
            "ref:",
            "ref: heads/main",
            "ref: refs/../../etc/passwd",
            "ref: refs//main",
            "ref: refs/heads/missing",
        ] {
            let dir = checkout(head);
            assert_eq!(head_commit(dir.path()), None, "(HEAD {head:?})");
        }
        // Non-UTF-8 bytes and a truncated hash in the ref file.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/HEAD"), [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(head_commit(dir.path()), None);
        let short = checkout("ref: refs/heads/main\n");
        put(&short.path().join(".git/refs/heads/main"), "1a2b\n");
        assert_eq!(head_commit(short.path()), None);
    }

    #[test]
    fn a_packed_ref_with_a_malformed_hash_gives_no_commit() {
        let dir = checkout("ref: refs/heads/main\n");
        put(
            &dir.path().join(".git/packed-refs"),
            "XYZ refs/heads/main\n",
        );
        assert_eq!(head_commit(dir.path()), None);
    }

    /// Make `path` a named pipe, the file type whose `open` blocks without a writer.
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path that outlives the call.
        let status = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
        assert_eq!(
            status,
            0,
            "(mkfifo {}): expected 0 | received {status}",
            path.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_in_place_of_a_git_file_gives_no_commit_without_blocking() {
        // HEAD itself is a pipe.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        make_fifo(&dir.path().join(".git/HEAD"));
        assert_eq!(head_commit(dir.path()), None);

        // The loose ref and packed-refs are pipes.
        let dir = checkout("ref: refs/heads/main\n");
        fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
        make_fifo(&dir.path().join(".git/refs/heads/main"));
        make_fifo(&dir.path().join(".git/packed-refs"));
        assert_eq!(head_commit(dir.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_device_in_place_of_head_gives_no_commit() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(".git/HEAD")).unwrap();
        assert_eq!(head_commit(dir.path()), None);
    }

    #[test]
    fn a_head_file_over_the_size_limit_gives_no_commit() {
        let dir = checkout(&format!("{SHA1}{}", " ".repeat(5000)));
        assert_eq!(head_commit(dir.path()), None);
    }

    #[test]
    fn is_safe_ref_keeps_refs_below_the_git_directory() {
        assert!(is_safe_ref("refs/heads/feat/x"));
        for bad in [
            "HEAD",
            "refs",
            "/refs/heads/x",
            "refs/heads/../x",
            "refs/heads//x",
            "refs/./x",
            "refs/heads/x/",
            "refs\\heads",
        ] {
            assert!(!is_safe_ref(bad), "{bad:?}");
        }
    }
}
