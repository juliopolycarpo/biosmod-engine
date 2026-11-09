# Contributing

## Code

Install [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/)
(CI uses 0.9.150). Nextest runs each test in its own process and schedules tests
across binaries in parallel. Run doctests separately with `cargo test --doc`.

```sh
cargo fmt --all --check
cargo clippy -p biosmod-core -p biosmod-cli --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-core -p biosmod-cli
cargo test --locked --doc -p biosmod-core -p biosmod-cli
cargo build -p biosmod-cli
cargo clippy -p biosmod-gui --all-targets -- -D warnings
cargo nextest run --locked -p biosmod-gui
cargo test --locked --doc -p biosmod-gui
```

Use `--profile ci` for the CI timeout and failure-reporting settings. Native GUI
runs under X11 or Wayland use `--test-threads 1` so windows do not compete for
focus; headless tests use nextest's default parallelism. Build the CLI before
running GUI integration tests because they launch `target/debug/bme`.

Core and CLI retain Rust 1.88 and Linux, Windows and macOS coverage. The Linux GUI requires Rust 1.92 and its native windowing and graphics libraries. CI checks it separately on Ubuntu 24.04, with X11 and Wayland software-renderer smoke tests. Check both desktop sessions, keyboard navigation, scaling and file dialogs when changing the interface; headless tests alone do not qualify desktop integration.

- The core never does I/O; the CLI never interprets firmware on its own (see [docs/architecture.md](docs/architecture.md)).
- Every new function gets a test. Bug fixes start with a test that fails for the reported reason.
- External I/O in tests goes through named fakes (`FakeTransport`, `FakeTools`, `FakeCmos`), never the network or real hardware.
- Errors name the invalid value and the expected shape: `module size: expected 604832 | received 604800`.
- Required CI must not depend on vendor ROMs or large downloads. Tests that need real dumps read them from `BME_ROM_*` variables and report when they are skipped.
- Commits follow Conventional Commits, one concern each, with a body.

After changing a document type, regenerate the committed schemas: `BME_UPDATE_SCHEMAS=1 cargo nextest run --locked --test cli`.

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
