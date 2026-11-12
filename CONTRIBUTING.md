# Contributing

English | [Brazilian Portuguese](CONTRIBUTING.pt-BR.md)

## Code

Install [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/)
(CI uses 0.9.150). Nextest runs each test in its own process and schedules tests
across binaries in parallel. Run doctests separately with `cargo test --doc`.

```sh
cargo fmt --all --check
cargo clippy -p biosmod-core -p biosmod-host -p biosmod-cli --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-core -p biosmod-host -p biosmod-cli
cargo test --locked --doc -p biosmod-core -p biosmod-host -p biosmod-cli
cargo build -p biosmod-cli
cargo clippy -p biosmod-gui --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-gui
cargo test --locked --doc -p biosmod-gui
```

Use `--profile ci` for the CI timeout and failure-reporting settings. Native GUI
runs under X11 or Wayland use `--test-threads 1` so windows do not compete for
focus; headless tests use nextest's default parallelism. Build the CLI before
running GUI integration tests because they launch `target/debug/bme`.

To check the native file-picker portal on a running desktop, use `cargo test -p biosmod-gui --test native_dialog -- --ignored --nocapture`. It opens the Portuguese plan picker for two seconds; the test process then exits and closes the dialog. Run it with each display backend.

Core and CLI retain Rust 1.88 and Linux, Windows and macOS coverage. The Linux GUI requires Rust 1.92 and its native windowing and graphics libraries. CI checks it separately on Ubuntu 24.04, with X11 and Wayland software-renderer smoke tests. Check both desktop sessions, keyboard navigation, scaling and file dialogs when changing the interface; headless tests alone do not qualify desktop integration.

- The core never does I/O; the CLI never interprets firmware on its own (see [docs/architecture.md](docs/architecture.md)).
- Every new function gets a test. Bug fixes start with a test that fails for the reported reason.
- External I/O in tests goes through named fakes (`FakeTransport`, `FakeTools`, `FakeCmos`, `FakeFlashChip`, `FakeSysfs`, `FakeKernelLog`, `FakePrivilege`, `FixedClock`, `RecordingPorts`), never the network or real hardware.
- Errors name the invalid value and the expected shape: `module size: expected 604832 | received 604800`.
- Required CI must not depend on vendor ROMs or large downloads. Tests that need real dumps read them from `BME_ROM_*` variables and report when they are skipped.
- Commits follow Conventional Commits, one concern each, with a body.

After changing a document type, regenerate the committed schemas: `BME_UPDATE_SCHEMAS=1 cargo nextest run --locked --test cli`.

## Translations

English is the canonical source. When changing an English document, review its Brazilian Portuguese counterpart and manually update the source SHA-256 in `docs/i18n-manifest.json` only after review. The hash records the reviewed source revision; it does not prove translation quality. New Markdown files under `docs/` require a counterpart and manifest entry. Preserve commands, flags, JSON examples and CLI output in English. Run `python3 tools/check-doc-translations.py` and `python3 -m unittest discover -s tools/tests` to check coverage, freshness and local links.

For interface messages, install the matching extractor with `cargo install slint-tr-extractor --version 1.18.1 --locked`, then run `python3 tools/update-gui-translations.py` to update catalogs or add `--check` to verify them. Review changed translations and preserve identifiers and technical details.

Use consistent terms: firmware and patch remain unchanged; translate catalog as catálogo, manifest as manifesto, and offline verification as verificação offline. The CLI and its protocol remain English.

## CI caches

Each job caches Cargo downloads and compiled dependency crates with
`Swatinem/rust-cache`. PRs can restore caches from `main`; successful PR jobs
also save caches for subsequent runs of the same PR. GitHub isolates PR caches
from `main` and other PRs.

Caches are separated by job, runner OS/architecture, compiler, and build
environment (including `RUSTFLAGS`). Cargo manifests, lockfiles, toolchain files,
and Cargo configuration contribute to automatic invalidation. After a dependency
change, the action can restore an older cache and Cargo rebuilds dependencies as
needed. MSRV and GUI jobs set `RUSTUP_TOOLCHAIN` before cache lookup so metadata
and builds use the same compiler.

Workspace crates and incremental build state are excluded by the action's
default cleanup. Debug and release dependency artifacts are cached, but each
profile still needs an initial build. Cache misses and GitHub eviction are
expected; every job must also work with an empty cache. Rust toolchain downloads
and the GUI job's system packages are installed separately on each runner.

## Board profiles and patch records

A record is accepted when someone else can check it from the files alone.

1. Add or update `catalog/boards/<id>.json`. Say how the revision is known (`observed` from the board, `unverified` from a listing, or `unknown`). Board ids are lowercase.
2. Add the variant under the firmware build id in `catalog/patches/<id>.json`. Hunks need the exact original bytes, 16 bytes of context on each side, and source and result hashes. Ported variants start from `bme derive` and must be reviewed hunk by hunk (`bme guide porting`).
3. Put assembly sources or notes needed to review the change in `catalog/provenance/`.
4. Run `bme catalog index catalog` and `bme catalog validate catalog`.
5. In the PR, state what the finding is, how it was shown (executed, analyzed, plausible), what the fix does not cover and how you checked the result.

Hardware observations go in `catalog/evidence/` with the exact `image_sha256` that was flashed, the patch versions, the configuration and the limits. One observation never upgrades a record's general confidence. Never include vendor images or extracted modules.

## Security

Report vulnerabilities in parsing, catalog trust or tool installation privately through GitHub security advisories, not in public issues.
