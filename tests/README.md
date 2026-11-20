# tests/

The Rust workspace holds the unit, integration, property and known-answer
tests: run them from `rust/` with
`cargo test --workspace --exclude shekyl-randomx-differential` (see
`CLAUDE.md`, "Build & test"). This directory holds what is not a cargo
test:

- `cmake-gate-test/` — `run.sh` configures the tree with a fake 32-bit
  toolchain and with an Android target and asserts that the top-level
  `CMakeLists.txt` refuses both before any probe runs
  (`.github/workflows/cmake-gate-test.yml`).
- `build-target-refusal/` — `run.sh` asserts that the depends system
  refuses the Android host triples and classifies a Linux triple as Linux.
- `stressnet/` — the sustained-load testnet's configuration, load
  generator and monitor (see its `README.md`).
