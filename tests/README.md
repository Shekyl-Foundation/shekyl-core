# tests/

The Rust workspace holds the unit, integration, property and known-answer
tests: run them from `rust/` with
`cargo test --workspace --exclude shekyl-randomx-differential` (see
`CLAUDE.md`, "Build & test"). This directory holds what is not a cargo
test:

- `build-target-refusal/` — `run.sh` asserts that the depends system
  refuses the Android host triples and classifies a Linux triple as Linux.
- `stressnet/` — the sustained-load testnet's configuration, load
  generator and monitor (see its `README.md`).
