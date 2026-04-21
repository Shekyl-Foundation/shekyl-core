# Follow-ups

Open work items and tracked decisions that did not fit the PR in which they
were discovered. Per `.cursor/rules/15-deletion-and-debt.mdc`, every item has a
target version; items without one get one within 30 days or get closed as
"won't fix." Resolved items are removed — git history is the archive. A short
audit trail is retained at the bottom for items whose resolution is worth
citing in a review.

---

## V3.1 — audit response and stressnet gates

- **PQC Multisig V3.1: external adversarial review (Phase 5).**
  Round 4 wargame against the V3.1 multisig implementation per
  `PQC_MULTISIG_V3_1_ANALYSIS.md` §5.4. Review targets:
  - Attacks on Solution C mechanism (grinding on `tx_secret_key_hash`)
  - Attacks on §2.7 invariant enforcement
  - Unknown-version silent-skip exploits
  - Relay directory signing process attacks
  - DKG ceremony failure modes

  Status: code complete, awaiting human coordination to schedule the review.

- **PQC Multisig V3.1: cryptographer review (Phase 6).**
  Four targeted reviews per `PQC_MULTISIG_V3_1_ANALYSIS.md` §7:
  1. KDF domain separation soundness
  2. HKDF-derived Ed25519 scalar for FCMP++ prover (bit-clamping question)
  3. FCMP++ proof binding to Y_prover
  4. Rotation-rule grinding cost analysis

  Status: outreach should begin immediately; does not block other work.
  Findings are folded in via targeted `fix/ms31-crypto-review-*` branches.

- **PQC Multisig V3.1: headless co-signer service.**
  Build a `shekyl-cosigner-headless` reference implementation (CLI, no
  GUI) to validate the "co-signer service" model where one of N
  participants is a dedicated automated signing service. Validates:
  - Policy-based auto-signing (amount limits, allowlists, time delays)
  - HSM key storage integration (PKCS#11 or similar)
  - Subscription/billing hooks (out of protocol scope but must not conflict)
  - Headless heartbeat and CounterProof handling

  The protocol already supports this model (a service is just another
  participant), but practical validation is needed.

- **PQC Multisig V3.1: wire `shekyl_pqc_verify_with_group_id` into
  consensus verifier.** (Audit response.)
  The FFI export `shekyl_pqc_verify_with_group_id` exists and accepts an
  `expected_group_id` parameter, but the daemon's C++ verifier
  (`tx_pqc_verify.cpp`) still calls `shekyl_pqc_verify` for `scheme_id == 2`
  without passing a group ID. This means defense-in-depth group binding
  (`PQC_MULTISIG.md` §16.3) is implemented in the Rust library but not
  enforced at the consensus verification layer. Wiring it in requires the
  C++ verifier to extract `group_id` from the multisig key blob and pass it
  through — a small change but consensus-touching, requires its own review
  cycle.

- **Historical tree path assembly uses current LMDB state.**
  `assemble_tree_path_for_output` (in both `chaingen.cpp` and
  `core_rpc_server.cpp`) reads sibling hashes from the current LMDB tree
  state even when the reference block predates the chain tip. When
  `ref_leaf_count < current_leaf_count`, the sibling structure differs
  between historical and current state, and the assembled witness hashes
  to a root that matches neither the historical nor the current tree
  root. The current tests pass because they use
  `ref_leaf_count == current_leaf_count` (reference block always at the
  tip). This will fail for any real wallet that uses a historical
  reference block (allowed by `FCMP_REFERENCE_BLOCK_MAX_AGE = 100`).
  Stressnet (Phase 7.7) with realistic reorg and varied reference-block
  usage will exercise this. Approach: reconstruct historical tree state
  on demand using per-block root snapshots already stored by
  `store_curve_tree_root_at_height`.

- **Audit FCMP++ integration for paired computations.**
  Five integration bugs were found during the first CI green effort, all
  sharing the shape "two functions answer the same question differently."
  A deliberate sweep of remaining paired computations would surface
  similar latent bugs. Key surfaces to audit: any function that computes
  leaf count, layer count, or tree depth independently of another that
  answers the same question. Document the canonical answer and delete
  the duplicate, or add cross-check assertions.

- **Regression test: `compute_leaf_count_at_height` vs LMDB drain.**
  Add a test that, for a chain with outputs at varied maturity heights,
  asserts
  `compute_leaf_count_at_height(H) == count_of(drain_pending_tree_leaves(H))`
  for every height. This is the invariant the off-by-one bug violated
  and is the highest-value regression gate for this class of bug.

- **Expose FCMP++ verification cache stats via daemon RPC (stressnet F14).**
  Add `verification_cache_hits` and `verification_cache_misses` fields to
  `get_info` (or a new `get_cache_stats` JSON-RPC method). Currently the
  verification cache hit/miss counters (`fcmp_verified`,
  `fcmp_verification_hash`) are internal to `tx_pool.cpp` with no RPC
  exposure. The stressnet wallet exerciser (`shekyl-dev/stressnet/`) uses
  block validation p95 as an indirect proxy until this endpoint exists.

---

## V3.1.x — dependency migrations

- **rand 0.9 migration and curve25519-dalek 5 cascade.**
  Seven Dependabot alerts on `shekyl-core` cite
  [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  ("Rand is unsound with a custom logger using rand::rng()"), vulnerable
  range `>= 0.7.0, < 0.9.3`. We currently pin `rand = "0.8"` in five
  workspace crates and `rand 0.8.5` is transitively selected in the
  `rust/Cargo.lock` and `rust/shekyl-crypto-pq/fuzz/Cargo.lock` lockfiles.
  CVSS for all seven is 0 (Dependabot severity label "low"). These alerts
  have been dismissed on GitHub with reason "risk tolerated" and a link
  to this follow-up.

  ### Affected manifests (all seven alerts)

  - `rust/Cargo.lock` (alert #3)
  - `rust/shekyl-crypto-pq/fuzz/Cargo.lock` (alert #4)
  - `rust/shekyl-crypto-pq/Cargo.toml` (alert #5)
  - `rust/shekyl-chacha/Cargo.toml` (alert #6)
  - `rust/shekyl-fcmp/Cargo.toml` (alert #7)
  - `rust/shekyl-proofs/Cargo.toml` (alert #8)
  - `rust/shekyl-tx-builder/Cargo.toml` (alert #9)

  ### Not exploitable today

  The `rand::rng()` function named in the advisory is the 0.9+
  thread-local RNG API and does not exist in rand 0.8. Shekyl's crypto
  paths obtain randomness two ways:

  - `rand::rngs::OsRng` passed directly to dalek's `Scalar::random` and
    to `SigningKey::generate` (see `rust/shekyl-crypto-pq/src/montgomery.rs`,
    `kem.rs`, `signature.rs`, `multisig.rs`).
  - `rand_chacha::ChaCha20Rng::from_seed([...])` for deterministic key
    derivation (see `rust/shekyl-crypto-pq/src/derivation.rs`).

  Neither codepath calls `rand::rng()` and the Shekyl daemon does not
  install a custom `log::Log` implementation, so the logging-induced
  soundness bug described in the advisory has no path to the RNG state
  in any Shekyl binary.

  ### Why we can't just bump rand to 0.9

  rand 0.9 moved `RngCore` / `CryptoRng` trait definitions and renamed
  several methods (`gen` → `random`, `gen_range` → `random_range`,
  `thread_rng` → `rng`). The rest of the crypto ecosystem we depend on
  is still pinned to the rand 0.8 `rand_core` trait set:

  - `curve25519-dalek = "4"` (and its `Scalar::random` wiring)
  - `ed25519-dalek = "2.2.0"` with the `rand_core` feature
  - `rand_chacha = "0.3"`
  - `fips204 = "0.4.6"`, `fips203 = "=0.4.3"` (NIST PQC implementations)

  Attempting to bump rand to 0.9 in isolation fails to compile because
  `Scalar::random(&mut rand::rngs::OsRng)` expects the 0.8 trait set. A
  real migration cascades into bumping curve25519-dalek to 5.x (plus its
  downstream consumers) and re-auditing every crypto call site.

  Per `.cursor/rules/20-rust-vs-cpp-policy.mdc`, a migration of this
  size is a planning activity — its own design document, 4–6 review
  rounds, its own test gates, its own PR. Folding it into any other
  change produces an unreviewable diff.

  ### Gate

  Do not start this migration until:

  1. `curve25519-dalek 5.x` has at least one stable release with a
     reviewable changelog against 4.x.
  2. `ed25519-dalek`, `rand_chacha`, and the `fips204`/`fips203` crates
     have released versions that advertise rand 0.9 compatibility.
  3. We have a test plan that confirms every `OsRng` / `from_seed`
     call site produces byte-identical output against pre-migration
     test vectors (HKDF vectors, signing round-trip vectors, FCMP++
     blinding-factor vectors).

  ### Scope when picked up

  - Bump rand, rand_chacha, and rand_core in all five workspace crates.
  - Update `Scalar::random`, `SigningKey::generate`, and
    `ChaCha20Rng::from_seed` call sites to the new trait API.
  - Re-run the full test-vector regeneration path and confirm no drift.
  - Dedicated PR; the "rand migration" lands on `dev` behind no feature
    flag, but must not be bundled with any other security or feature
    change.

  ### Residual: digest_auth transitive

  Even after our workspace crates migrate, `digest_auth v0.3.1` (a
  transitive dependency of `shekyl-simple-request-rpc` via the
  `shekyl-oxide` vendor tree) selects rand 0.8.5 for cnonce generation.
  It has no newer crates.io release. Alerts #3 and #4 (the two
  `Cargo.lock` alerts) will reappear until `digest_auth` is either:

  - upstream-patched and a new version published,
  - replaced with a different HTTP-digest library (evaluate
    `http-auth`, `reqwest-middleware` auth patterns), or
  - vendored and patched in-tree under `shekyl-oxide/`.

  Track that replacement as a sub-task of this item, not as a separate
  follow-up; both will land together. Target version: **V3.1.x**,
  specific minor decided when the curve25519-dalek 5.x release window
  becomes visible.

---

## V3.2 — Rust cutover and cleanup

- **`shekyl-cli` offline signing uses hex blobs on the command line.**
  A future improvement should support QR-code-sized chunked transfer
  for air-gapped signing (e.g. `--qr` flag that splits into scannable
  chunks). Currently, unsigned/signed transaction sets are passed as
  hex strings which can be very long for multi-output transactions.
  Target: V3.2 (coordinates with the broader wallet RPC Rust cutover).

- **`shekyl-cli` key image export uses JSON-RPC format, not C++ binary.**
  The current implementation exports key images via the
  `export_key_images` JSON-RPC method and writes JSON. For byte-identical
  interop with the C++ binary format
  (`"Shekyl key image export\003"` magic + view-key encrypted), add FFI
  functions `wallet2_ffi_export_key_images_to_file` and
  `wallet2_ffi_import_key_images_from_file` that call the underlying C++
  file-based export/import. This preserves interop with hardware-wallet
  and cold-spend workflows built on the binary format.
  Target: V3.2.

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  The `gen_tx_src` function constructs fake outputs for ring-style
  source entries. This is legacy test infrastructure that works but is
  conceptually dead for Shekyl (no rings). Replace `gen_tx_src` with a
  direct FCMP++-style source entry constructor.
  Target: V3.2 (lands with the `transfer_details` Rust migration).

- **`removed_flags` shim sunset.**
  `src/common/removed_flags.{h,cpp}` is a transitional utility
  introduced in V3.1 to give operators a friendly migration message
  when they pass `--detach`, `--pidfile`, or the Windows `--*-service`
  flags that the daemonizer removal retired. The flag list is
  maintained there as a single source of truth — `CHANGELOG.md` entries
  reference the file rather than duplicating the list. The file is
  deleted in V3.2 alongside the `shekyl-wallet-rpc` Rust cutover (which
  removes one of the two call sites); `shekyld`'s call site is deleted
  in the same V3.2 cleanup pass. Greppable as `TODO(v3.2)` in the file
  header.

---

## TBD — vendor- or standardization-dependent

- **PQC Multisig V3.1: hardware wallet integration.**
  Current hardware wallets (Coldcard, Trezor, Ledger, Jade) cannot
  support V3.1 multisig signing. Constraints:
  1. **ML-DSA-65 computation cost.** Signing takes ~100ms on modern
     desktop CPUs. On Cortex-M class MCUs (ARM Cortex-M4 @ 120MHz),
     ML-DSA-65 signing is estimated at 1–5 seconds. ML-KEM-768
     decapsulation is faster (~50ms on Cortex-M4) but still significant.
     Coldcard Mk4 (STM32H753, 480MHz Cortex-M7) may be the first viable
     target.
  2. **Screen constraints.** Hardware wallet displays are typically
     128×64 pixels. The signing payload (§10.4 of `PQC_MULTISIG.md`)
     should be representable as: "Sign intent {hash_prefix} sending
     {amount} SKL to {address_prefix}, fee {fee}". The intent_hash is
     32 bytes; showing a 4-byte prefix is sufficient for verification.
  3. **Signing payload self-containment.** The §10.4 canonical signing
     payload is already self-contained — no network calls are needed
     during signing. A hardware wallet can verify the payload offline
     given only the persisted output state. This is by design and must
     not change.
  4. **Vendor outreach.** Recommend the Foundation contact Coinkite
     (Coldcard) and Blockstream (Jade) during V3.1 launch. Both have
     shown interest in post-quantum cryptography. Trezor and Ledger
     have larger teams but longer decision cycles.
  5. **Protocol impact:** none. V3.1 is designed so hardware wallet
     integration requires no protocol changes. The signing payload and
     hybrid signature format are stable.

  Status: documentation complete. Code work deferred to V3.2 at
  earliest; actual vendor integration timeline is vendor-controlled.

---

## Long-lived utilities (no target version required)

These items document intentional decisions rather than pending work. They
stay here as a reference; closing them is equivalent to deleting this
reference.

- **`dalek-ff-group` version isolation enforced via CI gate.**
  The Rust workspace carries two versions: 0.5.x (used directly by
  Shekyl crates) and 0.4.x (pulled transitively by vendored
  serai/`ciphersuite` internals). A CI grep gate in
  `.github/workflows/build.yml` checks all Shekyl crates
  (`shekyl-ffi`, `shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-proofs`,
  `shekyl-tx-builder`, `shekyl-scanner`, `shekyl-wallet-rpc`,
  `shekyl-daemon-rpc`) and asserts that none of their normal dependency
  trees pull in 0.4. Direct `dalek_ff_group` usage in source is printed
  for visibility but does not fail (legitimate 0.5 usage is expected).
  The 0.4 version must stay hidden behind `Ciphersuite` trait
  abstractions (`<Ed25519 as Ciphersuite>::G`, etc.). Never reach into
  `ciphersuite`'s internals. If upstream `ciphersuite` upgrades to
  `dalek-ff-group` 0.5, remove the gate.

- **`shekyl-daemon-rpc/src/main.rs` uses `eprintln!` intentionally.**
  The standalone binary is a stub that exits with an error. No logging
  framework is initialized at that point. When standalone mode is
  implemented, replace with `tracing::error!` and proper logger init.
  This note is informational — there is no open action until standalone
  mode is specified.

- **`shekyl-economics-sim` uses `eprintln!` for CLI progress.**
  This is a batch CLI tool that writes JSON to stdout and progress to
  stderr. `eprintln!` is idiomatic for this pattern. No change planned;
  revisit only if the sim gains a long-running mode where structured
  logging is warranted.

---

## Recently resolved (audit trail)

Retained for citation in review; each links to the canonical record.

- **Branch layer depth formula correction (April 12, 2026).** Commit
  `03d233652`. `shekyl-tx-builder` validation rule corrected from
  `c1 + c2 == depth` to `c1 + c2 + 1 == depth`, discovered by the FFI
  signing round-trip test (Phase 6). Two errors cancelled: wrong
  fixture + wrong rule = passing test that tests nothing. Hardening
  applied: `MAX_TREE_DEPTH=24` constant (single source of truth),
  C1/C2 alternation constraint enforced, parametric depth sweep test,
  spec-derived fixture rule added to `.cursor/rules/40-testing.mdc`.

- **FFI depth-to-layers convention fix (April 15, 2026).**
  `shekyl_fcmp_prove`/`_verify` were performing an internal
  `layers = tree_depth + 1` conversion that was opaque to C++ callers
  and led to double-conversion bugs. Fix: removed the internal
  conversion; FFI accepts `layers` directly; C++ callers convert
  explicitly. `shekyl_sign_fcmp_transaction` still accepts LMDB depth
  and converts internally.

- **`core_tests` FCMP++ proof verification failures.** Root cause:
  `test_generator::construct_block` set `blk.curve_tree_root` to a
  fixed placeholder, not the real Merkle root from the DB. FAKECHAIN
  skipped the root check, so block headers were stored with placeholder
  roots. The prover assembled witness paths from the real LMDB tree,
  producing inconsistent proofs. Fix: added per-height curve tree root
  storage (`m_curve_tree_roots` LMDB table) that records the real root
  at every block height. Both the prover (`apply_fcmp_pipeline`) and
  verifier (`check_tx_inputs`) read the root from this table instead of
  block headers. Also aligned `compute_leaf_count_at_height` with
  production `collect_outputs` logic.

- **MSVC CI covers the daemon target.** The `build-windows-msvc` job
  builds `--target daemon wallet`. Any new daemon code must compile
  under MSVC. If a future change introduces MSVC-only errors,
  shekyl-core CI will catch it before the GUI wallet release workflow
  does.

- **PQC Multisig V3.1: FFI returns typed error codes.** All three
  verification FFI functions (`shekyl_pqc_verify`,
  `shekyl_pqc_verify_with_group_id`, `shekyl_fcmp_verify`) now return
  `u8` error codes: 0 = success, nonzero = typed error discriminant.
  The debug-only `shekyl_pqc_verify_debug` was deleted. C++ callers
  log error codes in all build modes. Per
  `.cursor/rules/30-ffi-discipline.mdc`.

- **PQC Multisig V3.1: ephemeral seed stack copies hardened.** `ed_seed`
  and `ml_seed` in `multisig_receiving.rs` are now
  `Zeroizing<[u8; 32]>`, ensuring automatic zeroization on drop. Closes
  the theoretical side-channel surface identified during the V3.1 audit
  response review.

- **Genesis TX blobs now use real commitments and KEM ciphertexts.**
  The genesis pipeline consumes Bech32m addresses, derives X25519 from
  the Ed25519 view key via Edwards→Montgomery mapping, assembles the
  full 1216-byte `m_pqc_public_key`
  (`X25519_pub || ML-KEM_ek`), and routes through
  `build_genesis_coinbase_from_destinations`. See
  `scripts/verify_genesis.py` in `shekyl-dev` for reproducibility
  verification.

- **scheme_id binding confirmed active.** `expected_scheme_id` IS used:
  `blockchain.cpp` calls `verify_transaction_pqc_auth(tx, expected_scheme)`
  where `expected_scheme` is derived from `tx.pqc_auths[0].scheme_id`.
  This enforces cross-input scheme consistency — all inputs in a
  transaction must use the same scheme_id. Scheme downgrade protection
  across outputs is still provided by the `h_pqc` curve tree leaf
  commitment as described in `PQC_MULTISIG.md` Attack 1.

- **`on_get_curve_tree_path` RPC correctly reads reference-block state.**
  Fixed by computing `ref_leaf_count` at `reference_height` (subtracting
  leaves drained after reference block via
  `get_pending_tree_drain_entries`), capping all leaf/layer reads to
  `ref_leaf_count`, and applying boundary-chunk hash trimming via
  `shekyl_curve_tree_hash_trim_{selene,helios}` for sibling chunks that
  grew since the reference block.
