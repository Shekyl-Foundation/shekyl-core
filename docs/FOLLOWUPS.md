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

- **~~`signing_round_trip.rs` tests Rust proof API, not raw FFI.~~** RESOLVED.
  The test now calls `shekyl_sign_fcmp_transaction` and `shekyl_fcmp_verify`
  through C-ABI FFI, exercising the full FFI boundary serialization for
  signing. See `rust/shekyl-ffi/tests/signing_round_trip.rs`.

- **`shekyl-daemon-rpc/src/main.rs` uses `eprintln!` intentionally.**
  The standalone binary is a stub that exits with an error. No logging
  framework is initialized at that point. When standalone mode is
  implemented, replace with `tracing::error!` and proper logger init.

- **`shekyl-economics-sim` uses `eprintln!` for CLI progress.**
  This is a batch CLI tool that writes JSON to stdout and progress to stderr.
  `eprintln!` is idiomatic for this pattern. No change needed unless the sim
  gains a long-running mode where structured logging is warranted.

- **~~1 unit test skipped: requires FCMP++ non-coinbase transaction construction.~~** RESOLVED.
  `JsonSerialization.BulletproofPlusTransaction` restored using
  `make_v3_transaction_stub()` which builds a structurally valid v3
  transaction for JSON serialization round-trip testing. The old ring-style
  `make_transaction` was replaced.

- **Genesis TX blobs use zero-filled `enc_amounts`/`outPk`.**
  The regenerated v3 genesis blobs carry all-zero encrypted amounts and
  Pedersen commitments. This is structurally valid for parsing/hashing but
  means the genesis coinbase outputs are not cryptographically real. Before
  mainnet launch, regenerate using `build_genesis_coinbase_from_destinations`
  with proper PQC-enabled miner addresses to produce real commitments and
  KEM ciphertexts.

- **`shekyl-cli` offline signing uses hex blobs on the command line.**
  A future improvement should support QR-code-sized chunked transfer for
  air-gapped signing (e.g. `--qr` flag that splits into scannable chunks).
  Currently, unsigned/signed transaction sets are passed as hex strings
  which can be very long for multi-output transactions.

- **`shekyl-cli` key image export uses JSON-RPC format, not C++ binary.**
  The current implementation exports key images via the `export_key_images`
  JSON-RPC method and writes JSON. For byte-identical interop with the C++
  binary format (`"Shekyl key image export\003"` magic + view-key encrypted),
  add FFI functions `wallet2_ffi_export_key_images_to_file` and
  `wallet2_ffi_import_key_images_from_file` that call the underlying C++
  file-based export/import. This preserves interop with hardware-wallet and
  cold-spend workflows built on the binary format.

- **`rpassword` transitive dependency audit.** Pin `rpassword = "7"` and
  periodically audit for `windows-sys` bumps. Terminal echo restoration on
  panic has had CVEs in CLI password tooling. Run `cargo audit` in CI
  (already configured) with `rpassword` in scope.

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  The `gen_tx_src` function constructs fake outputs for ring-style source
  entries. This is legacy test infrastructure that works but is conceptually
  dead for Shekyl (no rings). A future cleanup should replace `gen_tx_src`
  with a direct FCMP++-style source entry constructor.

- **~~Fuzz harness for `derive_output_secrets`.~~** RESOLVED.
  Added `fuzz_derive_output_secrets` target in
  `rust/shekyl-crypto-pq/fuzz/fuzz_targets/`. Asserts determinism,
  non-zero ho/y for all non-empty combined_ss inputs, and no panics on
  truncated/oversized inputs.

- **~~Witness header round-trip test.~~** RESOLVED.
  Added `witness_header_build_then_parse_roundtrip` test in
  `rust/shekyl-ffi/src/lib.rs` with locked vectors in
  `docs/test_vectors/WITNESS_HEADER.json`. Verifies all 8 header fields
  survive the build → blob → parse cycle byte-for-byte.

- **~~y=0 consensus check for two-component output keys.~~** RESOLVED (infeasible).
  A consensus-level rejection of `y=0` outputs is not implementable: the
  verifier sees only `O` on the chain and `y` is a secret derived from
  the KEM shared secret. Testing whether `O` lies in the G-only subgroup
  (i.e., `O = x*G` for some `x` with zero T-component) requires knowing
  the discrete log relationship between G and T, which is unknown by
  design. Defense is structural: (1) `derive_output_secrets` hard-asserts
  `y != 0` (probability 2^-252 from honest HKDF), (2) `construct_output`
  is the sole construction path, (3) `fuzz_derive_output_secrets` covers
  the derivation with arbitrary inputs.

- **~~scheme_id binding (`expected_scheme_id` unused).~~** RESOLVED (by design).
  Deferred to PQC multisig PR; see `PQC_MULTISIG.md`.
  The `verify_transaction_pqc_auth` two-argument overload accepting
  `expected_scheme_id` is never called with a value because FCMP++ hides
  which output is being spent — the verifier cannot look up the creating
  transaction's committed scheme. Scheme downgrade protection is provided
  by the `h_pqc` curve tree leaf commitment: the FCMP++ proof binds the
  spending key's `H(hybrid_public_key)` to the leaf committed at output
  creation. A downgrade requires a Blake2b-512 collision between
  structurally different key encodings (single-signer 1996 bytes vs.
  multisig 2+N*1996 bytes), which is computationally infeasible.
  See `PQC_MULTISIG.md` Attack 1 for the corrected analysis. The
  `expected_scheme_id` parameter may be removed as dead code in V3.1.
  **Decision on removal deferred to multisig PR.**

- **~~`on_get_curve_tree_path` RPC reads current tree state, not reference-block state.~~** RESOLVED.
  Fixed by computing `ref_leaf_count` at `reference_height` (subtracting
  leaves drained after reference block via `get_pending_tree_drain_entries`),
  capping all leaf/layer reads to `ref_leaf_count`, and applying
  boundary-chunk hash trimming via `shekyl_curve_tree_hash_trim_{selene,helios}`
  for sibling chunks that grew since the reference block.

- **~~`docs/AUDIT_SCOPE.md` not yet created.~~** RESOLVED.
  `docs/AUDIT_SCOPE.md` created (April 12, 2026). Defines scope for the
  4-scalar leaf circuit security audit. Referenced by `RELEASE_CHECKLIST.md`
  and `FCMP_PLUS_PLUS.md`.

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
