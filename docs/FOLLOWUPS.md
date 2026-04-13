# Follow-ups

Observations and improvement ideas that surfaced during Phase 6 execution.
Each item is out of scope for the current PR but worth tracking for future work.

---

- **`dalek-ff-group` version isolation enforced via CI gate.**
  The Rust workspace carries two versions: 0.5.x (used directly by Shekyl
  crates) and 0.4.x (pulled transitively by vendored serai/`ciphersuite`
  internals). A CI grep gate in `.github/workflows/build.yml` checks all
  Shekyl crates (`shekyl-ffi`, `shekyl-fcmp`, `shekyl-crypto-pq`,
  `shekyl-proofs`, `shekyl-tx-builder`, `shekyl-scanner`, `shekyl-wallet-rpc`,
  `shekyl-daemon-rpc`) and asserts that none of their normal dependency
  trees pull in 0.4. Direct `dalek_ff_group` usage in source is printed for
  visibility but does not fail (legitimate 0.5 usage is expected). The 0.4
  version must stay hidden behind `Ciphersuite` trait abstractions
  (`<Ed25519 as Ciphersuite>::G`, etc.). Never reach into `ciphersuite`'s
  internals. If upstream `ciphersuite` upgrades to `dalek-ff-group` 0.5,
  remove the gate.

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

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  The `gen_tx_src` function constructs fake outputs for ring-style source
  entries. This is legacy test infrastructure that works but is conceptually
  dead for Shekyl (no rings). A future cleanup should replace `gen_tx_src`
  with a direct FCMP++-style source entry constructor.

---

## Completed audit trail

- **Branch layer depth formula correction (April 12, 2026).**
  `shekyl-tx-builder` validation rule corrected from `c1 + c2 == depth`
  to `c1 + c2 + 1 == depth` (commit 03d233652). Discovered by the FFI
  signing round-trip test (Phase 6). Autopsy: old tests used depth=2
  with c1=1, c2=1 -- structurally wrong for a depth-2 tree but happened
  to satisfy the wrong formula. Two errors cancelled: wrong fixture +
  wrong rule = passing test that tests nothing. Depth=1 was never tested
  before Phase 6.

  Verifier-side check: not needed -- `shekyl-fcmp::proof::verify` uses
  proof-structure-implicit depth enforcement (branch data embedded in
  proof blob; verifier replays transcript using `tree_depth` as layer
  count). Both prover and verifier reject depth=0.

  Hardening applied:
  - `MAX_TREE_DEPTH=24` constant added to `shekyl-fcmp::lib` (single
    source of truth), enforced in both `shekyl-tx-builder::validate_inputs`
    and `shekyl-fcmp::proof::verify`.
  - C1/C2 alternation constraint now enforced in `validate_inputs`
    (previously only total count was checked). The `error.rs` doc was
    corrected -- it previously stated `c2 == c1 or c2 == c1 + 1` but
    the protocol requires `c1 == c2 or c1 == c2 + 1` (C1 at even
    indices, C2 at odd).
  - Parametric depth sweep test covers `1..=MAX_TREE_DEPTH` plus
    rejection at `MAX_TREE_DEPTH + 1`.
  - All test fixtures in `shekyl-tx-builder/src/tests.rs` corrected to
    be spec-derived (c1/c2 split computed from depth per the tower
    alternation rule, not pasted from observed behavior).
  - Testing rule added to `.cursor/rules/40-testing.mdc`: fixtures must
    be spec-derived, not behavior-derived.
