## What and why

<!-- What does this change do, and why? Link any related issue. -->

## Checklist

- [ ] Clean-room: no code copied from `mtr`/`WinMTR` or other GPL sources
- [ ] `cargo build --workspace --locked` is clean (on Windows)
- [ ] `cargo test --workspace --locked` passes
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` is clean
- [ ] `unsafe` stays confined to `hopscout-net` behind a safe API
- [ ] `CHANGELOG.md` updated under "Unreleased" (for user-facing changes)
