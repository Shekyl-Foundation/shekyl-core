# Follow-ups

Observations and improvement ideas that surfaced during Phase 6 execution.
Each item is out of scope for the current PR but worth tracking for future work.

---

- **`dalek-ff-group` version isolation enforced via CI gate.**
  The Rust workspace carries two versions: 0.5.x (used directly by Shekyl
  crates) and 0.4.x (pulled transitively by `ciphersuite` internals). A CI
  grep gate in `.github/workflows/build.yml` asserts that `shekyl-ffi`'s
  normal dependency tree never pulls in 0.4. Direct `dalek_ff_group` usage
  must always resolve to 0.5; the 0.4 version stays hidden behind
  `Ciphersuite` trait abstractions (`<Ed25519 as Ciphersuite>::G`, etc.).
  Never reach into `ciphersuite`'s internals. If upstream `ciphersuite`
  upgrades to `dalek-ff-group` 0.5, remove the gate.

- **`signing_round_trip.rs` tests Rust proof API, not raw FFI.**
  The re-added `rust/shekyl-ffi/tests/signing_round_trip.rs` calls
  `shekyl_fcmp::proof::{prove, verify}` (Rust-level) rather than the C FFI
  `shekyl_sign_fcmp_transaction`. This validates the cryptographic round-trip
  but does not exercise the FFI boundary serialization for signing. A future
  Gate 4 FFI test should call `shekyl_sign_fcmp_transaction` end-to-end once
  the test infrastructure supports constructing a full `FcmpSignRequest` JSON
  blob.

- **`shekyl-daemon-rpc/src/main.rs` uses `eprintln!` intentionally.**
  The standalone binary is a stub that exits with an error. No logging
  framework is initialized at that point. When standalone mode is
  implemented, replace with `tracing::error!` and proper logger init.

- **`shekyl-economics-sim` uses `eprintln!` for CLI progress.**
  This is a batch CLI tool that writes JSON to stdout and progress to stderr.
  `eprintln!` is idiomatic for this pattern. No change needed unless the sim
  gains a long-running mode where structured logging is warranted.

- **`wallet/api/wallet.cpp` Phase 0 deletion candidate.**
  The `wallet/api/` directory wraps `wallet2` for GUI consumption. With the
  Tauri GUI wallet (`shekyl-gui-wallet`) using Rust wallet crates directly,
  this C++ API layer is dead weight. Deletion is "genuinely free" — no
  downstream consumers remain — and should be a separate commit.

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  The `gen_tx_src` function constructs fake outputs for ring-style source
  entries. This is legacy test infrastructure that works but is conceptually
  dead for Shekyl (no rings). A future cleanup should replace `gen_tx_src`
  with a direct FCMP++-style source entry constructor.
