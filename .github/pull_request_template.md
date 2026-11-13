## Summary

<!-- What changes and why. Link the issue. -->

## Validation

<!-- Commands run and their results. Say which real-ROM checks ran and which were skipped. -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy -p biosmod-core -p biosmod-host -p biosmod-cli --all-targets -- -D warnings`
- [ ] `cargo nextest run --locked -p biosmod-core -p biosmod-host -p biosmod-cli`
- [ ] `cargo test --locked --doc -p biosmod-core -p biosmod-host -p biosmod-cli`
- [ ] `cargo clippy -p biosmod-gui --all-targets -- -D warnings` (GUI changes)
- [ ] `cargo nextest run --locked -p biosmod-gui` (GUI changes)

<!-- For GUI changes, name the desktop sessions, renderers, dialogs, accessibility and scaling checks actually run. -->

## Catalog changes

<!-- Delete if none. Records changed, evidence added, how hunks were reviewed. -->

## Limits

<!-- What this does not establish. Offline verification is not hardware validation. -->
