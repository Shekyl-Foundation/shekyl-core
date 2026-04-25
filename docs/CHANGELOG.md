# Shekyl Changelog

## [Unreleased]

### Changed

- **`shekyl-wallet-file::WalletFileHandle` → `WalletFile`** (PR 0.2 of
  the [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)).
  Mechanical rename across all call sites in `shekyl-wallet-file`,
  `shekyl-wallet-prefs`, `shekyl-ffi`, and the C FFI doc-comment in
  `src/shekyl/shekyl_ffi.h`. No ABI change (the C-ABI symbols use the
  `shekyl_wallet_*` prefix, not the Rust type name). Frees the
  `Wallet` identifier for the Phase 1 `shekyl-wallet-core::Wallet`
  orchestrator and aligns the file-orchestrator type name with what it
  actually is — envelope, atomic IO, advisory locking, payload
  framing. Rationale and decision archive in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  ("Wallet stack greenfield Rust rewrite", 2026-04-25).

### Added

- **Mid-rewire benchmark warning window (commit 2k.c of the
  wallet-state-promotion plan,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.3.1).**
  Closes the structural-noise loophole that the 2k.a / 2k.b
  dual-stack rewire would otherwise punch through the
  `ci/benchmarks` gate. New sentinel file
  [`docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active`](benchmarks/MID_REWIRE_WARNING_WINDOW.active)
  toggles warning-only mode — when present, the `fail job on
  threshold trip` step in
  [`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml)
  downgrades the would-be `::error::` annotation to a
  `::warning::` and exits 0, preserving the upstream
  `compare` / PR comment / `profile-on-fail` observability
  chain without blocking merges. Policy paragraph in
  `MID_REWIRE_HARDENING.md` §3.3.1 pins *why* the window is
  needed (pre-rewire baseline vs. post-rewire gate calibration
  vs. structurally-slower-during-dual-stack middle state),
  *how* the sentinel beats workflow-level flags / Actions
  secrets / branch-name matching on grep discoverability and
  git-authored toggle trail, and *when* it must close (2m-cache
  commit, with a mandatory post-rotation of `bench-baseline`).
  The sentinel path is included in the workflow's `paths:`
  filters for both `pull_request` and `push` triggers, so
  opening and closing the window self-triggers the gate.
  Reviewers still see every delta and every samply profile
  during the window; what they lose is the automated merge
  block, which would otherwise fire on structural noise the
  rewire *is* expected to produce.

- **2k.b — refuse legacy `store_keys` writes on SHKW1 wallets
  (commit 2k.b of the wallet-state-promotion plan,
  [`.cursor/plans/wallet-state-promotion_ab273bfe.plan.md`](../.cursor/plans/wallet-state-promotion_ab273bfe.plan.md)
  §2k.b).** Installs the keys-layer fault line in
  `wallet2::store_to` so SHKW1-backed wallets cannot silently
  corrupt their on-disk file by falling back to the legacy
  `store_keys` JSON path. The two triggers that would otherwise
  reach the legacy save branch — save-as (`path` differs from
  the current `m_wallet_file`) and password change
  (`force_rewrite_keys=true`, as routed from
  `wallet2::change_password`) — now throw a typed
  [`tools::error::wallet_shkw1_operation_unsupported`](../src/wallet/wallet_errors.h)
  before any wallet-state mutation (no `trim_hashchain` cache
  touch, no `prepare_file_names` path rewrite, no cache
  serialization). Both flows require FFI that doesn't exist
  yet (`shekyl_wallet_save_as`, `shekyl_wallet_rotate_password`)
  and land in 2l alongside the cache-side rewire. The common
  `store()` → `store_to("", "")` path (same file, no forced
  keys rewrite) is *not* refused — it never touches the keys
  file, and its cache save still works through the legacy
  `shekyl_encrypt_wallet_cache` path until 2l. Callers audited:
  `wallet2::change_password` (exposed via `wallet2_ffi.cpp`
  and `wallet_rpc_server.cpp`) and direct `store_to(path, pw)`
  invocations in `tests/wallet_bench/` and
  `tests/unit_tests/wallet_storage.cpp` — all refused for
  SHKW1-backed wallets during the 2k.a → 2l window, revalidated
  in the rewrite-testing phase. `wallet_errors.h` hierarchy
  extended with the new `wallet_logic_error` subclass carrying
  both the operation name and the keys file path for UX
  rendering. Verified locally: full shekyl-core C++ rebuild
  clean across `wallet`, `daemon`, `shekyl-wallet-rpc`,
  `unit_tests`, `core_tests`, `functional_tests`; no new
  lints introduced.

- **2k.a — rewire `wallet2` load/verify/rewrite onto the SHKW1
  handle (commit 2k.a of the wallet-state-promotion plan,
  [`.cursor/plans/wallet-state-promotion_ab273bfe.plan.md`](../.cursor/plans/wallet-state-promotion_ab273bfe.plan.md)
  §2k.a).** The keys-side half of the wallet2 → Rust rewire.
  `wallet2::load_keys` now magic-sniffs via
  `shekyl_wallet_keys_inspect`; on an SHKW1 match it routes
  through `shekyl_wallet_open`, gates **before** any secret
  material leaves Rust on capability
  (`tools::error::wallet_keys_unsupported_capability`) and
  derivation network
  (`tools::error::wallet_keys_wrong_network`), then extracts
  only the 64-byte master seed into a scrubbing file-local
  `TransitionalRederivationInputs` RAII wrapper
  (`epee::mlocked<tools::scrubbed_arr<uint8_t, 64>>`).
  `m_account.load_from_shkw1` rebuilds every derived field
  (classical SK/PK, view SK/PK, ML-KEM decap key, account
  address) from the seed; `m_account.forget_master_seed`
  immediately scrubs the C++ copy (Option β — the
  `ShekylWallet` handle is the single in-memory source of
  truth for the master seed post-load). An AAD-bound
  address-match sanity check against
  `ShekylWalletMetadata::expected_classical_address` catches
  corruption, HKDF policy drift, and handle-repoint bugs
  via a distinct
  `tools::error::wallet_keys_aad_address_mismatch`; `init_type`
  and `set_createtime` land atomically with the handle-stash
  on `m_shekyl_wallet`. `wallet2::load_keys_buf` refuses SHKW1
  inputs with `error::wallet_internal_error` — the envelope
  requires the file-lock path and cannot be driven through a
  raw buffer. Both `verify_password` overloads route SHKW1
  verification through `shekyl_wallet_keys_open` with a sizing
  probe for the capability payload; the instance overload runs
  the same address-match sanity check against the opened
  handle's metadata so a future migration tool that repoints
  `m_keys_file` without re-opening the handle surfaces as a
  typed error rather than silently returning keys from the
  wrong handle. The static overload logs an L1 warning if a
  caller passes `no_spend_key=false` (no in-tree caller does
  today; the log guarantees any future regression trips test
  output). `wallet2::rewrite` becomes a logged L1 no-op for
  SHKW1 wallets — settings writes land in 2k.b's `store_to`
  rewire. `wallet2::deinit` resets `m_shekyl_wallet` *before*
  `m_account.deinit()` so the Rust handle's final state write
  runs while C++ secrets are still live, and the C++ wipe
  happens after the handle drops. Three new typed refusals
  in
  [`src/wallet/wallet_errors.h`](../src/wallet/wallet_errors.h)
  discriminate structural failure modes (wrong network vs.
  AAD-bound cryptographic inconsistency vs. unsupported
  capability) so CLI, wallet RPC, and tests can render
  targeted messages without parsing log strings. Security
  invariants: the 64-byte master seed lives in C++ only for
  the duration of `load_from_shkw1`, under `mlock`; the
  address-match check fires before any scalar is materialized
  in C++; `xor_with_key_stream` / `rederive_from_master_seed`
  / `decrypt` are all length-gated, so the post-scrub empty
  vector state is a no-op everywhere it's read. Verified
  locally: full shekyl-core C++ rebuild clean across `wallet`,
  `daemon`, `shekyl-wallet-rpc`, `unit_tests`, `core_tests`,
  `functional_tests`; `cargo check -p shekyl-wallet-file -p
  shekyl-ffi` clean. Test regeneration / wallet2 fixture
  migration deferred to the rewrite-testing phase per the
  user-approved scope split.

- **Region-2 parser fuzz harnesses (commit 8 of the mid-rewire
  hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.8).**
  Closes the gap the adversarial corpus (commit 7) structurally
  cannot cover: the corpus pins *specific* typed refusals against
  *specific* malformations it was written to check, which says
  nothing about byte patterns nobody thought to enumerate. New
  [`rust/shekyl-wallet-state/tests/fuzz_region2.rs`](../rust/shekyl-wallet-state/tests/fuzz_region2.rs)
  is a stable-Rust proptest harness that drives randomized input
  into `WalletLedger::from_postcard_bytes` — the canonical region-2
  decoder used by the wallet-file orchestrator — and asserts the
  single load-bearing property: **the parser never panics and
  always terminates with a typed result** (either `Ok`, or one of
  the four enumerated `WalletLedgerError` variants). Five
  strategies at 128 cases each cover every relevant mutation
  shape: point mutation of a valid empty bundle, truncation,
  random byte insertion, random byte deletion, and entirely-random
  bytes up to 4 KiB. The error-classification match in
  `assert_typed_or_ok` is deliberately exhaustive with distinct
  classification tags per arm, so adding a new `WalletLedgerError`
  variant without updating the harness is a compile-time error —
  the harness stays in lockstep with the error taxonomy
  mechanically rather than culturally. Total wall-clock is ≈0.06 s
  per run (three orders of magnitude under the plan's 30 s-per-PR
  exit criterion); cases = 640 total (128 × 5), comfortably inside
  the plan's ~500-iteration budget. Companion local-only
  coverage-guided harness at
  [`rust/shekyl-wallet-state/fuzz/`](../rust/shekyl-wallet-state/fuzz/):
  a minimal `fuzz_target!` wrapping
  `let _ = WalletLedger::from_postcard_bytes(data)`, excluded from
  the workspace via new `exclude = ["shekyl-wallet-state/fuzz"]`
  in [`rust/Cargo.toml`](../rust/Cargo.toml) so stable CI never
  tries to resolve `libfuzzer-sys`. Runnable locally with
  `cargo +nightly fuzz run region2_parser`; its README documents
  the two-condition graduation plan (nightly stabilisation OR
  mainnet-freeze proximity) and why nightly is not in CI today.
  The harness is kept trivial by design so that it cannot itself
  panic and mask a parser regression. Verified locally: 96
  existing `shekyl-wallet-state` unit tests remain green; 5-test
  proptest harness passes in 0.06 s; `cargo check --workspace
  --tests` on stable ignores the fuzz crate entirely; clippy is
  clean with `-D warnings`; fmt is clean.

- **Adversarial wallet-file corpus (commit 7 of the mid-rewire
  hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.7).**
  Locks in the "every layer refuses with a typed error, not a panic
  or a silent fallback" posture at the integration boundary. New
  [`rust/shekyl-wallet-file/tests/adversarial_corpus.rs`](../rust/shekyl-wallet-file/tests/adversarial_corpus.rs)
  drives 16 programmatic attack shapes through
  `WalletFile::open` and asserts the exact `WalletFileError`
  variant each one must surface: envelope header attacks on
  `.wallet.keys` (wrong magic → `UnknownMagic`, truncated header
  → `FileTooShort`, `file_version = 0xFF` → `FormatVersionTooNew`,
  region-1 ciphertext bit flip → `InvalidPasswordOrCorrupt`);
  envelope header attacks on `.wallet` (wrong magic, future
  `state_version`, region-2 ciphertext bit flip →
  `StateSeedBlockMismatch` as currently mapped, cross-wallet
  companion swap → `StateSeedBlockMismatch`); SWSP frame attacks
  (`BadMagic`, `UnsupportedPayloadVersion`, `BodyLenMismatch`);
  `WalletLedger` body attacks (bundle `format_version` bump →
  `UnsupportedFormatVersion`, per-block `block_version` bump →
  `UnsupportedBlockVersion`, truncated postcard → `Postcard`);
  the cross-block invariant gate from commit 6
  (`INV_TX_KEYS_NO_ORPHANS` → `InvariantFailed`); and a wiring
  assertion that capability-shape mismatches (plan rows B / C) flow
  through the existing envelope-level
  `CapContentLenMismatch { mode, len }` variant unchanged — the
  plan's proposed new `CapabilityPayloadMismatch` was dropped on
  review because `validate_cap_content` in
  `shekyl-crypto-pq::wallet_envelope` already enforces the entire
  intended `(mode, cap_content_len)` shape, and adding a second
  variant with identical semantics would duplicate the gate. The
  corpus is programmatic rather than binary-pinned: each test
  builds a real wallet pair via `WalletFile::create(...)`,
  then performs narrow byte surgery (on ciphertext-protected
  regions via the public
  `shekyl_crypto_pq::wallet_envelope::seal_state_file` helper) so
  it stays green across future format-field renames and AEAD
  parameter changes. New
  [`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) §2.5
  writes up the capability decode posture the corpus enforces —
  mode first, then `cap_content_len`, then per-capability
  interpretation, each step refusing rather than tolerating — so
  reviewers encountering a "why no new variant?" test can follow
  the trail. New
  [`rust/shekyl-wallet-file/tests/fixtures/adversarial/`](../rust/shekyl-wallet-file/tests/fixtures/adversarial/)
  holds a README + one `.md` per attack row documenting the
  construction and the rationale behind each typed refusal
  (including the deliberate
  `region-2-bit-flip → StateSeedBlockMismatch` collapse rather than
  `InvalidPasswordOrCorrupt`, which the envelope cannot
  distinguish from a seed-block-tag mismatch without running the
  full region-2 verification twice). Verified locally: all 16
  corpus tests pass; the rest of the `shekyl-wallet-file` suite
  remains green; clippy clean with `-D warnings`; fmt clean.

- **`WalletLedger::check_invariants()` aggregator-level gate (commit 6
  of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.6).**
  Closes the gap that neither single-block schemas (commit 4) nor the
  zeroizing-field grep (commit 5) structurally cover: a `.wallet`
  bundle whose every block decoded cleanly and whose every field is
  correctly wrapped can still be *semantically* impossible (a scanner
  tip below a recorded transfer; a key image shared between two
  transfers; an orphan per-tx secret whose transaction has been
  garbage-collected from every live reference). New
  [`rust/shekyl-wallet-state/src/invariants.rs`](../rust/shekyl-wallet-state/src/invariants.rs)
  owns the closed set of five cross-block invariants with stable
  machine-readable names: `tip-height-not-below-transfer`,
  `tx-keys-no-orphans`, `subaddress-registry-dense`,
  `reorg-trail-monotonic`, `spent-state-consistent`. Each check is
  O(n) in the number of transfers or map keys with a single
  `HashSet<[u8; 32]>` allocation, well under 100 µs for a 10 k-transfer
  bundle. New
  [`WalletLedgerError::InvariantFailed { invariant, detail }`](../rust/shekyl-wallet-state/src/error.rs)
  variant carries the stable name plus a pointed diagnostic ("missing
  minor index 3 in [1, 4]" rather than "file is corrupt"), which flows
  through `shekyl-wallet-file`'s `WalletFileError::Ledger` by existing
  `#[from]`. Two call sites wire the checks in: `WalletLedger::from_postcard_bytes`
  runs them after the per-block version gates pass (typed refusal on
  load), and `WalletLedger::preflight_save` runs them ahead of every
  `save_state` in `shekyl-wallet-file/src/handle.rs` — `debug_assert!`
  in debug so a runtime-induced invariant break aborts tests loudly,
  typed `Err` in release so a user save never panics mid-write. Two
  invariants (subaddress density, key-image uniqueness) replace the
  plan's §3.6 `spent_images` and `transfer_index` proposals with shapes
  that match the actual blocks (`BookkeepingBlock::subaddress_registry`
  and `TransferDetails::key_image` — there is no separate spent-image
  set and no transfer-index join); the plan explicitly sanctions such
  adjustment on landing, and the machine-readable names are chosen to
  outlive any future shape refactor. Verified locally: 16 unit tests
  (one positive + at least one negative per invariant, plus alternate
  reference paths for I-2 proving a pool- or pending-referenced tx
  passes) all pass; the pre-existing 96-test `shekyl-wallet-state`
  suite and 51-test `shekyl-wallet-file` suite remain green; clippy
  clean with `-D warnings`; fmt clean.
- **Zeroizing-field grep + allowlist CI guard (commit 5 of the
  mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.5).**
  Closes the gap that the wire-schema snapshot from commit 4
  structurally cannot cover: `Zeroizing<[u8; 32]>` and `[u8; 32]`
  produce byte-identical postcard output, so unwrapping a zeroize
  wrapper leaves the snapshot green while silently breaking the
  runtime secret-wipe contract. New
  [`scripts/ci/check_zeroize.sh`](../scripts/ci/check_zeroize.sh)
  walks `rust/shekyl-wallet-state/src/**/*.rs` and emits every
  `[u8; N]` or `Vec<u8>` field declaration: production code only
  (`#[cfg(test)]` modules and everything past the first
  `#[cfg(test)]` in a file are elided), with paren-depth tracking
  across multi-line `fn` signatures so `pub fn new(x: [u8; 32], …)`
  parameters are not mistaken for struct fields, and with standard
  filters on `//`, `///`, `use`, `type`, `impl`, `let`, `for`,
  `match`, `->` , and `assert` lines. Every hit must either carry a
  `Zeroizing<...>` / `SecretKey<...>` wrapper on the same line
  (auto-pass, no allowlist entry needed) or be enumerated verbatim —
  `<relative-path>|<normalized decl>` — in
  [`rust/shekyl-wallet-state/.zeroize-allowlist`](../rust/shekyl-wallet-state/.zeroize-allowlist).
  The allowlist is bi-directional: a new unwrapped field with no
  entry fails with `FATAL: unwrapped byte-shaped field(s) without
  allowlist entry`, and an allowlist line whose field no longer
  exists fails with `FATAL: stale allowlist entry — field no longer
  exists`, so the file cannot rot with ghost entries that would
  silently re-admit a future field of the same spelling. Initial
  allowlist encodes 27 deliberate public-bytes entries across six
  files (`bookkeeping_block`, `ledger_block`, `payment_id`,
  `runtime_state`, `sync_state_block`, `transfer`, `tx_meta_block`),
  grouped by category with per-entry comments: (a) public chain
  hashes (tip/reorg/creation-anchor/pending-tx/reference-block),
  (b) public key-image markers on `TransferDetails`, (c) 32-byte
  map keys keying per-tx metadata (tx hashes are public lookup
  handles; values that carry secrets, like `TxSecretKey`, are wrapped
  on their own line), (d) the clear `PaymentId([u8; 8])` handle
  (obfuscation is applied by the tx-builder, not the storage type),
  (e) FCMP++ `path_blob: Vec<u8>` (public-input proof bytes; leaks
  anonymity-set choice but not spender secrets), (f) mirror-struct
  schema fields on `TransferDetailsSchema` / `TxSecretKeySchema` that
  exist only to drive the `postcard_schema::Schema` derive and never
  allocate at runtime, (g) `runtime_state.rs` in-memory indexes
  that are rebuilt from `LedgerBlock` on every load and never
  persisted. New
  [`.github/workflows/zeroize-check.yml`](../.github/workflows/zeroize-check.yml)
  runs the script on PRs into `dev` that touch the wallet-state
  source tree, the allowlist, the script itself, or this workflow.
  Policy captured in
  [`.cursor/rules/42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc)'s
  enforcement section (§3.4 schema snapshot + §3.5 zeroize grep
  together form the mechanical half of the wire-format and
  secret-wipe discipline). Verified locally: script exits 0 on
  the current tree ("33 candidate field(s) scanned, all wrapped or
  allowlisted"); the three failure modes — adding an unwrapped
  `scratch_field: [u8; 32]`, adding a stale allowlist entry,
  unwrapping an `Option<Zeroizing<[u8; 32]>>` to `Option<[u8; 32]>`
  — each produce the expected pinpoint error.
- **Wire-schema snapshot + paired `block_version` CI guard (commit 4 of
  the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.4).**
  Converts the `block_version` discipline from cultural invariant
  (previously policed only by reviewer attention and the prose rule in
  `.cursor/rules/42-serialization-policy.mdc`) into a mechanical check
  that fires on every PR. Adds a `postcard-schema = "0.2"` dependency
  to `shekyl-wallet-state` (pinned at the same major as the on-disk
  `postcard = "1"` wire-format crate, stable schema representation),
  derives `postcard_schema::Schema` on every persisted block
  (`WalletLedger`, `LedgerBlock`, `BookkeepingBlock`, `TxMetaBlock`,
  `SyncStateBlock`, plus the nested `BlockchainTip`, `ReorgBlocks`,
  `FcmpPrecomputedPath`, `SubaddressLabels`, `AddressBookEntry`,
  `AccountTags`, `TxSecretKeys`, `ScannedPoolTx`, `SubaddressIndex`,
  `PaymentId` types), and hand-rolls `Schema` for the two leaf types
  whose fields use `#[serde(with = "…")]` helpers the derive macro
  cannot introspect (`TransferDetails`, `TxSecretKey`). The hand-rolled
  impls use the mirror-struct pattern: a compile-only
  `TransferDetailsSchema` / `TxSecretKeySchema` that mirrors the wire
  layout with `Vec<u8>` for byte sequences, then lifts
  `NamedType.ty` out of its derived `Schema` impl under the
  domain-facing type name. This is wire-identical to the original types
  (both produce length-prefixed byte sequences under postcard) but
  participates in `postcard-schema`'s `NamedType` tree, which is the
  load-bearing part of the check.
  [`rust/shekyl-wallet-state/src/schema_snapshot.rs`](../rust/shekyl-wallet-state/src/schema_snapshot.rs)
  is a new test module that renders each block's `NamedType` tree as
  pretty JSON (via `OwnedNamedType` — `NamedType` holds `&'static`
  references that `serde_json` cannot roundtrip through) and
  diff-compares against a committed `.snap` file under
  [`rust/shekyl-wallet-state/schemas/`](../rust/shekyl-wallet-state/schemas/).
  Seven tests: one per block (5) plus a self-parseability roundtrip
  guard and a canonicality check on the schemas-dir path. Running
  `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-wallet-state schema_snapshot`
  regenerates; running without the env var asserts. Mismatches print a
  line-oriented unified diff, name the file that moved, and spell out
  the three-step fix (bump the constant, regenerate, review).
  [`.github/workflows/schema-snapshot.yml`](../.github/workflows/schema-snapshot.yml)
  wires two jobs. The first runs
  `cargo test -p shekyl-wallet-state schema_snapshot --no-fail-fast`
  against the PR head. The second diffs the PR against the `dev`
  merge-base and, for every `.snap` that changed, insists that both
  (a) the paired source file was touched, and (b) the `pub const` line
  that declares the matching version constant appears on either side of
  the file's unified diff. Pairing is canonical in both the workflow
  (`PAIRS` array) and the `schema_snapshot.rs` module docs:
  `wallet_ledger.snap ↔ WALLET_LEDGER_FORMAT_VERSION`,
  `ledger_block.snap ↔ LEDGER_BLOCK_VERSION`,
  `bookkeeping_block.snap ↔ BOOKKEEPING_BLOCK_VERSION`,
  `tx_meta_block.snap ↔ TX_META_BLOCK_VERSION`,
  `sync_state_block.snap ↔ SYNC_STATE_BLOCK_VERSION`. Workflow paths
  filter is scoped to the wallet-state crate plus the workflow file
  itself, so unrelated PRs skip the job entirely. Design choices
  surfaced in §3.4: (a) the snapshot is schema JSON, not postcard
  bytes — a hex diff is opaque to a reviewer, whereas a `NamedType`
  diff names every field and spells out its `DataModelType`; (b) the
  schema-stability contract leans on `postcard-schema`'s SemVer
  (pinned `0.2`), because the `NamedType` representation is part of
  the crate's public API; (c) the mirror-struct pattern is preferred
  over upstream-patching `postcard_schema` to understand
  `#[serde(with)]` because it is local, reviewable, and does not couple
  us to an upstream release cadence. Exit criteria met: five snapshot
  files exist, the assert-test passes on a clean checkout, a deliberate
  field rename produced a unified diff pointing at the exact node
  (verified locally against a scratch `#[serde(rename = "restore_height")]`
  on `SyncStateBlock::restore_from_height`), and the workflow's
  grep-logic dry-run correctly accepts a `pub const … = N → N+1` diff
  and rejects source-file edits that leave the declaration line
  untouched.
- **CI benchmark gate — iai-callgrind per-PR + rolling baseline on
  `bench-baseline` (commit 3 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.3).**
  New `ci/benchmarks` workflow
  ([`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml))
  running on PRs into `dev` (the gate) and pushes to `dev` (the
  rolling-baseline updater). On a PR: `ubuntu-latest` runs the
  full five-bench iai-callgrind harness via
  `scripts/bench/capture_rust_baseline.sh` (~8-10 min, cached
  cargo registry + target dir), diffs the resulting
  `shekyl_rust_v0.json` against the tip of the orphan
  `bench-baseline` branch's `baseline.json` via
  [`scripts/bench/compare.py`](../scripts/bench/compare.py), and
  upserts a Markdown PR comment via
  [`scripts/bench/post_comment.py`](../scripts/bench/post_comment.py).
  Threshold table enforced mechanically: `crypto_bench_*` ±5% warn
  / ±15% fail (bidirectional — speed-ups are suspicious on
  constant-time paths too), `hot_path_bench_*` +5% warn / +15%
  fail (slowdown-only), missing-bench-in-PR = fail. On any fail a
  second job re-runs the criterion sibling of the tripped bench
  under `samply record` and uploads a `profile.json` artifact for
  flamegraph review. Bootstrap: the first PR before the
  `bench-baseline` branch exists gets a `bootstrap-pending`
  comment and the gate passes; the first subsequent push to `dev`
  creates the branch with a bot-authored orphan commit. Design
  choices documented in §3.3 "Implementation notes": (a) Tier 1
  only — criterion wall-clock numbers are rendered in the comment
  as an informational table but do not trip the gate (the Tier 2
  upgrade to dedicated-runner wall-clock is tracked in §6.1);
  (b) C++ Google Benchmark is **not** wired in this commit
  because only `BM_balance_compute` ships live on the C++ side and
  it is wall-clock (same Tier-2 bucket as criterion); (c) the gate
  diffs against `bench-baseline/baseline.json` directly rather
  than re-running the bench on the baseline commit, because
  iai-callgrind instruction counts are machine-independent for
  deterministic code (Valgrind VEX IR, not native cycles) — saves
  ~8 min of CI per PR and the rolling baseline is always at most
  one dev-merge cycle stale. The compare report schema
  (`shekyl_rust_v0_compare_v1`) is its own versioned envelope so a
  future schema bump on the capture side does not silently drift
  the comparator. Companion documentation:
  [`docs/benchmarks/README.md`](benchmarks/README.md) gains a
  full "CI integration" section with per-PR flow, threshold
  routing, rolling-baseline semantics, and a "When a gate trips"
  triage runbook. Permissions are scoped per-job (read-only at
  top level; `pull-requests: write` only on the comment-posting
  job; `contents: write` only on the baseline-updater job), using
  the default `GITHUB_TOKEN` — no PAT, no self-hosted runner, no
  secret provisioning required.
- **Provisional laptop-captured `shekyl_rust_v0` baseline
  (follow-up to hardening-pass commit 2).** The harness commit's
  CHANGELOG entry deferred the frozen `shekyl_rust_v0.json` +
  `shekyl_rust_v0.iai.snapshot` to a reference-machine capture. To
  unblock commit 3 (CI threshold gate), those two files are landed
  here as a **laptop capture** on the commit author's host; the
  envelope records the exact CPU model, kernel, and toolchain
  (`captured_on.*` fields) so the "provisional" status is
  self-documenting. The iai-callgrind instruction-count columns are
  stable across back-to-back runs on that host (the §3.2 determinism
  criterion is met), so the baseline is a valid slowdown detector
  for same-host re-captures; the criterion wall-clock columns are
  soft numbers that CPU frequency scaling and background load will
  drift, and the reference-machine re-capture will overwrite them.
  Schema is stable across the swap (`shekyl_rust_v0`), so commit 3's
  comparison script does not need to branch. The capture-script
  probe for `iai-callgrind-runner` is also fixed in the same
  landing: the tool's `--version` flag exits 1 outside the
  cargo-bench handshake protocol, so the envelope's
  `iai_callgrind_runner_version` field was previously `"unknown"`;
  it now resolves via `cargo install --list` with a fallback through
  the runner's own error banner.
  [`docs/benchmarks/README.md`](benchmarks/README.md) gains a
  "Provisional laptop baseline" subsection naming the policy
  relaxation and the exit condition for it.
- **Rust wallet-state benchmark harness — criterion + iai-callgrind
  (commit 2 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.2).**
  Five hot paths from the §3.1 list, each shipped with a
  `criterion` binary (wall-clock, Tier-2 metric) and an
  `iai-callgrind` sibling (deterministic instruction-count + cache-
  miss metrics, Tier-1 metric that CI will gate on in commit 3):
  `shekyl-wallet-state::{ledger, balance}`,
  `shekyl-wallet-file::open`, `shekyl-scanner::scan_block`,
  `shekyl-tx-builder::transfer_e2e`. Naming convention enforced:
  `crypto_bench_*` (bidirectional ±5% warn / ±15% fail) for
  anything touching curve25519, ML-DSA-65, Argon2id, or ChaCha20-
  Poly1305; `hot_path_bench_*` (slowdown-only) for postcard serde,
  balance compute, and scanner bookkeeping. All ten harnesses
  compile under `cargo check --benches`, run locally under
  `cargo bench -p <crate> --bench <name>`, and — on a host with
  `valgrind` + `iai-callgrind-runner` on `PATH` — produce
  byte-identical instruction counts across back-to-back runs
  (§3.2 exit criterion). One deliberate deviation from production
  code is documented: the `transfer_e2e_iai` bench bypasses
  `HybridEd25519MlDsa::sign` and inlines the two sign steps with
  `fips204::ml_dsa_65::try_sign_with_seed` +
  `try_keygen_with_rng(seeded)` because the production wrapper's
  `OsRng` draws inside ML-DSA-65 keygen + rejection-sampling loop
  produced ~16% instruction-count variance on the sign call and
  ~66% variance once keygen was accounted for, both violating the
  determinism criterion. The FIPS-204 deterministic variant
  exercises the identical signing primitives (same NTT, same
  rejection predicates, same packing); the criterion sibling
  preserves the randomized production path so the human-facing
  wall-clock number is honest. Known gap: the full
  `sign_transaction` call including the FCMP++ membership proof is
  **not** benched, because a deterministic curve-tree path fixture
  keyed to a synthetic tree root is its own scope of work; the
  manifest §6.1 tracks this and names the un-gap conditions for a
  future `shekyl_rust_v1` schema bump. Companion artifacts:
  [`docs/benchmarks/shekyl_rust_v0.manifest.md`](benchmarks/shekyl_rust_v0.manifest.md)
  (per-bench operation lists, fixture shapes, six documented known
  gaps, apples-to-oranges notes against the C++ baseline),
  [`scripts/bench/capture_rust_baseline.sh`](../scripts/bench/capture_rust_baseline.sh)
  (reference-machine capture wrapper — sibling of
  `capture_cpp_baseline.sh` from commit 1 — emits a schema-versioned
  `shekyl_rust_v0.json` envelope with toolchain + host CPU +
  git-rev metadata alongside a raw `shekyl_rust_v0.iai.snapshot`
  text artifact),
  [`docs/benchmarks/README.md`](benchmarks/README.md) updated with
  a "Capturing the Rust baseline" section and the shipped
  file-layout listing. Workspace impact is dev-dep-only:
  `criterion` + `iai-callgrind` land as `[dev-dependencies]` on
  the four crates that own a bench (`shekyl-wallet-state`,
  `shekyl-wallet-file`, `shekyl-scanner`, `shekyl-tx-builder`);
  the `shekyl-scanner` bench gains a self-referential
  `shekyl-scanner = { path = ".", features = ["test-utils"] }`
  dev-dep so `WalletOutput::new_for_test` +
  `RecoveredWalletOutput::new_for_test` are available in the
  bench without exposing them to downstream consumers. The frozen
  `shekyl_rust_v0.json` is captured on a reference machine by the
  commit author and landed as a follow-up — this commit ships the
  harness, not the numbers, because the reference machine is part
  of the measurement (same discipline as commit 1).
- **Wallet2 C++ baseline benchmark harness
  (`tests/wallet_bench/`, commit 1 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.1).**
  Google Benchmark v1.9.1 harness fetched via `FetchContent`,
  opt-in behind `-DBUILD_SHEKYL_WALLET_BENCH=ON` (OFF by default so
  normal contributors do not pay the cold-build cost). Of the five
  hot paths identified in §3.1, **one ships live on this tree**
  (`BM_balance_compute`, N ∈ {100, 1000, 10000}, O(n) `balance()`
  iteration over a seeded synthetic transfer set) and **two are
  scaffolded-but-gated** with `state.SkipWithError(...)`
  (`BM_open_cold`, `BM_cache_roundtrip`): those two depend on
  `wallet2::generate` → `store_to` → `load` round-tripping, which
  is broken on this tree and reproduced by the already-failing unit
  test `wallet_storage.store_to_mem2file`. Root-causing the
  wallet2 regression is the work scope of hardening-pass commits
  `2l` / `2m-keys` / `2m-cache`; patching it here would violate the
  "clear separations" invariant. Un-skipping is a one-line change
  in each bench function when those commits land. Fixtures use a
  pinned seed (`0xBEEFF00DCAFEBABE`) so two runs produce
  byte-identical inputs; the bench defines its own
  `wallet_accessor_test` in `tests/wallet_bench/bench_fixtures.h`
  (matching the existing friend declaration in `src/wallet/wallet2.h`,
  disjoint from the same-named class in `tests/core_tests/wallet_tools.h`
  — the two headers are never included in the same TU) with a minimal
  surface: `m_transfers` get, `get_cache_file_data`, `load_wallet_cache`. Two of the Five (`scan_block_K`,
  `transfer_e2e_1in_2out`) ship only in the Rust harness from
  commit 3.2: wallet2's scanner and FCMP++ proof paths are
  daemon-coupled and have no hermetic provisioning path; the
  architecturally honest move is to acknowledge the gap in
  `docs/MID_REWIRE_HARDENING.md` §3.1 and §4.3 rather than
  reimplement daemon-side synthetic-tree logic in code that is
  deleted in 2m-cache.
  Companion artifacts:
  [`docs/benchmarks/wallet2_baseline_v0.manifest.md`](benchmarks/wallet2_baseline_v0.manifest.md)
  (prose manifest: every operation in each live bench's hot loop,
  every I/O boundary, apples-to-oranges notes against Rust, and the
  un-skip criteria for the two gated paths),
  [`docs/benchmarks/README.md`](benchmarks/README.md) (capture
  procedure + baseline-update policy),
  [`scripts/bench/capture_cpp_baseline.sh`](../scripts/bench/capture_cpp_baseline.sh)
  (reference-machine capture wrapper emitting a schema-versioned
  JSON envelope with toolchain + host CPU + git-rev metadata),
  [`tests/wallet_bench/README.md`](../tests/wallet_bench/README.md)
  (local build + run instructions + known gaps). The frozen
  `wallet2_baseline_v0.json` is captured on a reference machine by
  the commit author and landed as a follow-up — this commit ships
  the harness, not the numbers, because the reference machine is
  part of the measurement.
- **Boost `program_options` link-time dep on `libcommon`
  (`src/common/CMakeLists.txt`).** `removed_flags.cpp` calls
  `boost::program_options::error_with_option_name::get_option_name()`,
  which inlines `get_canonical_option_name` and therefore requires
  the `libboost_program_options` symbol to resolve at link time
  (`libcommon.so` is linked with `-Wl,--no-undefined`). The dep was
  missing since `removed_flags` landed and only surfaced during a
  clean rebuild triggered by the benchmark harness above. Fix is a
  one-line `PRIVATE ${Boost_PROGRAM_OPTIONS_LIBRARY}` in
  `src/common/CMakeLists.txt`. No behavior change outside CMake.

### Documentation

- **Mid-rewire hardening plan (`docs/MID_REWIRE_HARDENING.md`)
  amended in §3.1 and §4.3.** §3.1 updated to reflect the
  architecturally honest scope for the C++ baseline capture: path
  relocated to `tests/wallet_bench/` (repo convention for
  benchmarks; `src/` is product code), coverage reduced to three
  of the Five with explicit per-benchmark C++/Rust availability
  table and the daemon-coupling rationale spelled out for the two
  Rust-only paths (`scan_block_K`, `transfer_e2e_1in_2out`). §4.3
  gained a "Benchmarks Rust-only by necessity" subsection
  capturing the asymmetry so the bench-comparison script (§3.3)
  and the PR-comment format can handle it deterministically rather
  than treating missing C++ numbers as a regression. The
  acknowledgment is explicit: two paths have no pre-deletion C++
  baseline and will never have one; regression detection across
  the rewire for those paths relies on the Rust rolling baseline
  plus human order-of-magnitude sanity, not on a pre-deletion
  comparator.

- **Mid-rewire hardening plan (`docs/MID_REWIRE_HARDENING.md`).**
  New design spec pinning the eight-commit instrumentation pass
  that lands between the Rust-side wallet-file FFI (commits
  `2a`…`2k.4`, merged) and the C++ consumer rewire (commits
  `2k.5a` onward, deferred). Covers: Google Benchmark C++ baseline
  capture against the existing `wallet2.cpp` hot paths;
  criterion + iai-callgrind Rust benchmark harness mirroring the
  same five paths; GitHub Actions CI integration with
  bidirectional thresholds for `crypto_bench_*` (any drift is
  suspicious — constant-time property defense) and slowdown-only
  thresholds for `hot_path_bench_*`; rolling baseline on a
  dedicated `bench-baseline` branch; `postcard-schema` snapshot
  files with CI-enforced `block_version` bump on every drift;
  ripgrep + allowlist secret-wipe discipline for
  `shekyl-wallet-state` blocks; `WalletLedger::check_invariants()`
  with five cross-block tripwires and a new
  `WalletFileError::InvariantFailed { invariant, detail }` variant;
  adversarial wallet-file corpus covering the three capability-
  mode attack shapes (tamper-in-place, declared-FULL-with-VIEW_ONLY-
  shape, declared-VIEW_ONLY-with-trailing-bytes); proptest fuzz
  harness on stable plus checked-in (non-CI) `cargo-fuzz` targets.
  Also captures the dual-path output-equivalence requirement for
  `2k.5b`…`2l` as a structural commit-message template line, not a
  reviewer convention. No code or CI changes in this commit — spec
  only; the eight follow-up commits each cite a section.

## [3.1.0-alpha.5] - 2026-04-22

### Security

- **Retired 32-bit build targets (`v3.1.0-alpha.5`, Chore #3). Shekyl is
  now 64-bit only, on security grounds — not on maintenance grounds.**
  Shekyl's Post-Quantum primitives — `fips203` (ML-KEM-768) and
  `fips204` (ML-DSA-65), consumed on the hot path by `shekyl-crypto-pq`
  and `shekyl-tx-builder` — state their constant-time guarantees
  against native 64-bit arithmetic. On 32-bit targets the compiler
  lowers `u64` operations through compiler-emitted libgcc helpers
  (`__muldi3`, `__udivdi3`, `__ashldi3`) with no constant-time
  guarantee, plus variable-latency `u64` multiply on common 32-bit ARM
  cores (Cortex-A series). That is a CT violation introduced by the
  code generator, not the source — exactly the class source-level CT
  audits cannot catch. **KyberSlash (Bernstein et al., 2024)**
  demonstrates remote-timing key recovery against ostensibly
  constant-time Kyber implementations broken by non-CT division; the
  Cortex-M4 Kyber timing-attack line (2022–2024) is supporting
  context. **The X25519+ML-KEM hybrid does not save us**: "hybrid is
  secure if either half is secure" protects against algorithmic
  breaks, not side-channel breaks — if ML-KEM leaks its secret via
  timing on 32-bit, X25519 is offline-attackable against captured
  ciphertexts with unlimited attacker time. **FCMP++ proof generation
  has not been audited for constant-time properties on 32-bit
  targets, and Shekyl will not take responsibility for that audit
  across all 32-bit toolchains we would otherwise ship** (policy
  framing, not speculation). `MDB_VL32` (LMDB's 32-bit paged-mmap
  mode) and the `src/crypto/slow-hash.c` 32-bit software fallback are
  untested consensus-adjacent storage and PoW paths respectively.

  **32-bit Shekyl wallet users were at meaningfully elevated risk of
  key extraction compared to 64-bit users; supporting the platform
  was a tacit lie about the security posture of users on it.** This
  is the correction.

  **Node-only operation is also retired.** A future contributor will
  argue "I just want to run a 32-bit pruned node on a Pi, I'm not
  doing wallet operations, the CT argument doesn't apply." That is
  partially true — node code does not touch secret PQC keys. But
  `MDB_VL32` paging against a multi-GB chain makes sync time measured
  in weeks (not a supported posture), and shipping a 32-bit daemon
  binary creates a reasonable user expectation that wallet operation
  is supported, which it is not. The operational complexity of
  splitting "32-bit daemon supported, 32-bit wallet refused"
  outweighs any benefit.

  **Four independent tripwires (defense-in-depth):**

  1. **Tripwire D — `CMakeLists.txt`.** C++-side configure gate:
     `message(FATAL_ERROR …)` on `NOT CMAKE_SIZEOF_VOID_P EQUAL 8`,
     placed before any `find_package` / `include` /
     `add_subdirectory` so configure fails early with the CT
     argument in the message. Exercised on every PR to `dev` by
     `.github/workflows/cmake-gate-test.yml` + `tests/cmake-gate-test/`,
     which drives CMake with a fake 32-bit toolchain and asserts
     non-zero exit, gate message + KyberSlash citation in stderr,
     and no `find_package` chatter (so a PR that moves the gate
     below a probe also fails the test).
  2. **Tripwire A — `rust/shekyl-crypto-pq/src/lib.rs`.** Primary
     `compile_error!` on `not(target_pointer_width = "64")`, since
     this crate is the ML-KEM-768 / ML-DSA-65 consumer. The gate
     that fires in practice on a 32-bit Rust build.
  3. **Tripwire B — `rust/shekyl-ffi/src/lib.rs`.**
     Structural-not-observable: duplicated by design to preserve
     the refusal at the FFI seam under a future refactor that
     might split this crate from `shekyl-crypto-pq`. **Do not
     delete this gate on the grounds that it "never fires" — its
     value is structural, not observable**; see the comment block
     on the tripwire and `docs/audit_trail/RESOLVED_260419.md`
     §"Chore #3".
  4. **Tripwire C — `rust/shekyl-tx-builder/src/lib.rs`.** Direct
     `fips204` (ML-DSA-65) consumer on the transaction-signing hot
     path; independent of Tripwire A so a future refactor that
     narrows the dependency shape cannot silently drop the
     refusal.

  **Deleted, not `#if 1`-ed out.** Every 32-bit-conditional block
  removed in this chore was deleted outright. Dead
  `#if ARCH_WIDTH == 64` / `#ifdef __i386__` / `#ifdef __arm__`
  scaffolding invites future contributors to assume a meaningful
  32-bit alternative exists somewhere and reason about it; the
  whole point of the retirement is to foreclose that reasoning.

  **What went away.** Build system:
  `cmake/32-bit-toolchain.cmake`; the six 32-bit `Makefile` targets
  that actually existed on `dev` (`release-static-win32`,
  `debug-static-win32`, `release-static-linux-i686`,
  `release-static-linux-armv6`, `release-static-linux-armv7`,
  `release-static-android-armv7`); `BUILD_64` / `DEFAULT_BUILD_64` /
  `ARCH_WIDTH` / `ARM_TEST` / `ARM6` / `ARM7` machinery and the
  Clang+32 `libatomic` workaround in the root `CMakeLists.txt`; the
  `-D BUILD_64=ON` argument on all remaining 64-bit `Makefile`
  targets; `ARCH_WIDTH != 32` conditional in
  `src/blockchain_utilities/blockchain_import.cpp` (body retained,
  guard deleted); `-D MDB_VL32` in
  `external/db_drivers/liblmdb/CMakeLists.txt` (vendored `mdb.c`
  `MDB_VL32` code paths are now unreachable in Shekyl builds and
  deliberately left unpatched in-tree — see
  `docs/VENDORED_DEPENDENCIES.md` §"`MDB_VL32` — 32-bit retirement
  note" for the future-update drill); `contrib/depends/` toolchain
  template `i686` / `armv7` / `BUILD_64` / `LINUX_32` branches,
  package recipes for `boost` / `openssl` / `android_ndk` / the
  arch-asymmetric `_cflags_mingw32+="-D_WIN32_WINNT=0x600"` line in
  `unbound.mk`, `README.md` host list, `.gitignore` `i686*` / `arm*`
  entries, `packages.md` example; `cmake/BuildRust.cmake` all
  non-64-bit `CMAKE_SYSTEM_PROCESSOR` branches; gitian configs
  (`gitian-linux.yml`, `gitian-android.yml`, `gitian-win.yml`)
  32-bit hosts and MinGW alternatives.

  C/C++ conditionals: `src/common/compat/glibc_compat.cpp`
  `__wrap___divmoddi4` block and `__i386__`/`__arm__` glob symver
  arms (plus the corresponding `-Wl,--wrap=__divmoddi4` linker flag
  in the root `CMakeLists.txt`); `src/crypto/slow-hash.c` outer
  guard narrowed from `__arm__ || __aarch64__` to `__aarch64__` and
  the 32-bit fallback `cn_slow_hash_{allocate,free}_state` stubs
  removed; `src/crypto/CryptonightR_JIT.{c,h}`,
  `src/crypto/CryptonightR_template.h` x86 gates narrowed from
  `__i386 || __x86_64__` to `__x86_64__`;
  `src/cryptonote_basic/miner.cpp` FreeBSD APM gates narrowed from
  `__amd64__ || __i386__ || __x86_64__` to
  `__amd64__ || __x86_64__`;
  `src/blockchain_db/lmdb/db_lmdb.h` `__arm__` `DEFAULT_MAPSIZE`
  branch removed; `src/blockchain_db/lmdb/db_lmdb.cpp`
  `MISALIGNED_OK` gate narrowed to `__x86_64` only.
  **Disambiguation:** `tests/hash/main.cpp:192,206`
  `<emmintrin.h>` SSE-intrinsic gates are x86_64 arch gates, not
  32-bit gates, and are **not** deleted — an earlier draft of
  `STRUCTURAL_TODO.md` lumped them with the 32-bit retirement
  imprecisely.

  Rust: three `compile_error!` tripwires (A/B/C, above);
  `rust/shekyl-oxide/crypto/helioselene/benches/helioselene.rs`
  `target_arch = "x86"` branches collapsed to `x86_64` only.

  CI: `.github/workflows/depends.yml` ARM v7 stub replaced with a
  pointer to this chore; new `.github/workflows/cmake-gate-test.yml`
  + `tests/cmake-gate-test/` enforcing Tripwire D placement.

  Docs: `README.md`, `docs/INSTALLATION_GUIDE.md`,
  `docs/RELEASING.md`, and `docs/COMPILING_DEBUGGING_TESTING.md`
  are now 64-bit-only; `docs/VENDORED_DEPENDENCIES.md` carries the
  `MDB_VL32` future-update note; `docs/STRUCTURAL_TODO.md` §"32-bit
  targets cannot safely run Shekyl" is the canonical reviewer-facing
  copy; `docs/audit_trail/RESOLVED_260419.md` §"Chore #3
  (v3.1.0-alpha.5) — 32-bit target retirement: security closure"
  carries the closure narrative.

  **Supported architectures going forward:** `x86_64`, `aarch64`
  (Linux and Apple Silicon), `riscv64` (Gitian). `armhf`, `armv7`,
  `armv6`, `i686`, `i386` are out of scope — not deferred, not
  "maybe later," out of scope. Users on 32-bit hardware must not
  run Shekyl wallets; node operation on 32-bit hardware is not
  supported either. Operators on ARM32 / i686 hardware should plan
  a migration to 64-bit before upgrading past `v3.1.0-alpha.5`.

  *Maintenance benefits are real but secondary:* every 32-bit
  carve-out in `STRUCTURAL_TODO.md` §"bit-width carve-out without
  coverage" is eliminated in one chore, closing the dead-scaffolding
  pattern that motivated the §.

### Changed

- **Shekyl Foundation institutional release-signing key adopted.**
  `v3.1.0-alpha.5` is the first release signed by the Shekyl Foundation
  institutional signing key (subkey fingerprint `3778 B4C8 63C6 1512
  B5FC 2203 6914 D748 23DD A8DC`, long ID `6914D74823DDA8DC`; primary
  fingerprint `F5F7 5A47 70C9 4FE1 D5A5 AE59 844E 424F 9866 4F44`,
  long ID `844E424F98664F44`). The primary certification key is held
  offline; the signing subkey is hardware-backed (OpenPGP applet) with
  a two-year expiry (2028-04-18) enforcing a rotation cadence.

  Previous alphas (`v3.1.0-alpha.3`, `v3.1.0-alpha.4`) were signed with
  Rick Dawson's personal maintainer key and remain verifiable against
  that key — prior signatures are not invalidated. Going forward,
  maintainer keys remain a valid *additive* fallback for release-tag
  signing when the institutional key is unavailable (documented
  exception, not default path); they continue to be the right tool for
  commit signing, where authorship-attribution is the question.

  `docs/SIGNING.md` is rewritten as the canonical, self-contained
  reference: both key blocks inline (no loose `.asc` files), an
  explicit step-by-step release-tag signing ceremony with pre-flight
  checks, expected-output annotations, a failure-mode table, and a
  separate downstream-verification path. `docs/RELEASING.md` §3
  (tag creation) now points at the SIGNING.md ceremony and captures
  the minimum command sequence (`gpg --card-status` → `git tag -u
  6914D74823DDA8DC -a -s …` → `git verify-tag` before push) as a
  summary, not a replacement. Resolves the `docs/SIGNING.md`
  §"Future: Foundation institutional signing key" deferral that had
  been carried forward from V3.1 on the premise that institutional
  signing required ceremony (offline primary, hardware-backed subkey,
  bounded expiry) before it added value over a plain personal-key
  setup; those prerequisites are now in place.

- **Logging output format (breaking change, all binaries).**
  Chore #2 of the `easylogging++` retirement completes the
  migration started in V3.1 alpha.4: `shekyld`, `shekyl-wallet-rpc`,
  `shekyl-cli`, and every other in-tree binary now emit through the
  same Rust `tracing-subscriber` stack. The default formatter is
  `tracing_subscriber::fmt::layer`, and its line shape is *not*
  byte-compatible with the vendored `easylogging++` layout it
  replaces:

  ```
  # Before (easylogging++ default format string):
  2026-04-19 14:23:11.042    INFO    global   src/daemon/main.cpp:322    Shekyl 'Codename' (v3.1.0-alpha.3-release)

  # After (tracing-subscriber fmt::layer default):
  2026-04-19T14:23:11.042123Z  INFO global: Shekyl 'Codename' (v3.1.0-alpha.3-release)
  ```

  Timestamps are RFC 3339 UTC (not local time with microseconds),
  level tokens are full words (`ERROR` / `WARN` / `INFO` /
  `DEBUG` / `TRACE`, not the `E` / `W` / `I` / `D` / `V` single
  letters), the target appears as a structured `target:` field, and
  source location (`file:line`) is elided by default.
  Log-scraping tooling that parsed the prior format byte-for-byte
  must be updated; `docs/USER_GUIDE.md` §"Logging" documents the
  new shape for operators.

- **`MONERO_LOGS` → `SHEKYL_LOG` (env-var rename).** Every in-tree
  consumer of `MONERO_LOGS` now reads `SHEKYL_LOG` instead. This
  closes the C++-side half of the per-`.cursor/rules/93-legacy-
  symbol-migration.mdc` rename — Chore #1 (V3.1 alpha.4) already
  migrated the Rust binaries. `SHEKYL_LOG` accepts the same
  `tracing-subscriber`-compatible directive grammar as Chore #1
  (bare levels, per-target overrides, module-qualified targets)
  *plus* the legacy easylogging++ category grammar
  (`net.p2p:DEBUG,wallet.wallet2:INFO`, numeric `0..=4` presets,
  `+`/`-` modifiers) routed through the Rust-side translator. The
  legacy grammar is preserved on purpose: the ~1,345 `MINFO` /
  `MDEBUG` / etc. call sites in `src/` and `contrib/` ship
  category strings in that grammar, and operator runbooks doing
  `SHEKYL_LOG='*:DEBUG,net.p2p:TRACE'` must keep working with no
  downstream edits.

  **Operator action required before upgrading past V3.x alpha.0:**
  scripts, systemd units, Docker/Podman compose files, or launch
  plists that set `MONERO_LOGS=...` will silently become no-ops.
  Add a `SHEKYL_LOG=...` line alongside each `MONERO_LOGS=...`
  line before cutting over (both can coexist on pre-Chore-#2
  builds so the rollover is safe).

- **Log target separator normalized to `::`.** Targets that used to
  render in the easylogging++ output as `net.p2p` / `daemon.rpc`
  now appear as `net::p2p` / `daemon::rpc` in every
  `tracing-subscriber`-rendered line. The FFI boundary
  (`shekyl_log_emit` / `shekyl_log_level_enabled` in
  `rust/shekyl-logging/src/ffi.rs`) rewrites dot-separated category
  names into Rust-idiomatic module-path form before handing the
  event to the dispatcher, matching the form the legacy-grammar
  translator emits into EnvFilter directives
  (`net::p2p=trace`). Without this, every category-scoped emit
  from the C++ shim (`MCINFO("net.p2p", …)`,
  `MCLOG(level, "daemon.rpc", …)`, …) would silently fall through
  to the bare default clause because EnvFilter compares target
  strings byte-for-byte. Operator-supplied `SHEKYL_LOG` directives
  continue to accept both spellings — the legacy-grammar translator
  rewrites `.` to `::` on the way in, so
  `SHEKYL_LOG='*:WARNING,net.p2p:TRACE'` and
  `SHEKYL_LOG='warn,net::p2p=trace'` behave identically. Only the
  rendered output changes. Log-scraping pipelines that grep for
  `target=net\.p2p` need to grep for `target=net::p2p` (or, per
  the format-break entry above, `net::p2p:` at the front of the
  fields block) instead.

- **`shekyld` default log sink moved to `~/.shekyl/logs/`.**
  Under `chore/cxx-logging-consolidation`, the daemon's default
  `--log-file` path changed from `<data_dir>/shekyld.log` (next to
  the blockchain database) to `~/.shekyl/logs/shekyld.log`,
  resolved through the Rust FFI's `shekyl_log_default_path`.
  Testnet/stagenet/regtest runs use the suffixed base names
  `shekyld-testnet.log` / `shekyld-stagenet.log` /
  `shekyld-regtest.log` so the three networks can run
  side-by-side without clobbering each other's log. Rotation
  defaults to ~100 MB × 50 archives, and the live file plus
  every rotated archive are forced to POSIX mode `0600` on Unix
  — operator-tunable permissions are not a supported knob.
  Operators who want to keep the legacy next-to-data-dir layout
  can pass `--log-file` explicitly; the override path is
  unchanged.

- **CMake Python discovery modernized (Chore #3 follow-up).**
  `include(FindPythonInterp)` at the top of `CMakeLists.txt` is
  replaced with `find_package(Python3 COMPONENTS Interpreter REQUIRED)`
  as a single, early, authoritative discovery pass; two downstream
  shadowing call sites (`find_package(Python3 ...)` before the
  economics-params generator and `find_package(PythonInterp)` before
  the tests subdir) are deleted. The legacy `PYTHON_EXECUTABLE` and
  `PYTHONINTERP_FOUND` variables are aliased post-discovery so
  consumers under `tests/difficulty/CMakeLists.txt`,
  `tests/block_weight/CMakeLists.txt`, and the `cmake/CheckTrezor.cmake`
  fallback arm continue to work without a cascading migration. The
  `cmake_policy(SET CMP0148 OLD)` migration-debt carve-out that
  preserved the deprecated module on CMake ≥ 3.27 is removed in the
  same commit — there is no legacy module left to un-deprecate.
  Resolves the Copilot review comment on PR #15; addresses
  `docs/CHANGELOG.md` V3.1.0-alpha.3 entry's own callout of the
  same migration debt.

### Removed

- **`MONERO_LOG_FORMAT` env var (no replacement).** The custom
  format string that `MONERO_LOG_FORMAT` used to seed on the
  easylogging++ tree is no longer a tunable. Formatting is owned
  by the Rust subscriber's layer stack (`fmt::layer`,
  optionally stacked with `tracing-subscriber` feature flags at
  build time), not by an operator env var. There is no V3.x
  alpha.0 replacement and no intent to re-add one — if you have
  a log-format requirement that RFC 3339 UTC does not satisfy,
  file an issue rather than patching the format string.

- **Vendored `external/easylogging++/` tree.** Deleted in
  `ded9875b6`. All call sites that reached `el::Logger` /
  `el::Configurations` / `el::base::Writer` etc. directly have
  been rewritten to route through the `shekyl_log_emit` /
  `shekyl_log_level_enabled` FFI in `src/shekyl/shekyl_log.h`.
  The `el::` namespace survives only as a thin typedef-only
  compatibility shim in `contrib/epee/include/misc_log_ex.h`
  (`el::Level`, `el::Color`, `el::base::DispatchAction`) so the
  existing `MINFO` / `MDEBUG` / `MWARNING` / `MCINFO` macros
  expand without touching the ~1,345 call sites. Closes the
  `STRUCTURAL_TODO.md` §"Replace easylogging++ with a maintained
  logger" item (both chores); swept narrative in
  `docs/audit_trail/RESOLVED_260419.md`.

- **`src/rpc/rpc_version_str.{h,cpp}` and its unit test
  (`tests/unit_tests/rpc_version_str.cpp`), inherited from Monero.** The
  daemon constructs its own version string deterministically in
  `cmake/GitVersion.cmake` from the annotated tag on HEAD, then emits
  `SHEKYL_VERSION_FULL` over RPC as an opaque value. The validator
  regex was a Monero-era sanity check that parsed that string back
  against a hardcoded pattern — "protecting" consumers from a failure
  mode that the CMake construction logic already makes impossible.

  Exposed on the `v3.1.0-alpha.3` tag-push CI run
  ([#394](https://github.com/Shekyl-Foundation/shekyl-core/actions/runs/24637252528),
  `test-ubuntu` matrix): on a tagged build, `SHEKYL_VERSION_FULL`
  resolves to `3.1.0-alpha.3-release`, and the regex (adapted from
  Monero but never taught SemVer 2.0.0 §9 dotted pre-release
  identifiers) rejects the dot in `-alpha.3`. Every tagged release
  using `-alpha.N` / `-beta.N` / `-rc.N` numbering would trip the same
  assertion — so every tagged release with this file in tree is
  inherently broken, which is enough of a tell that the file is wrong
  to have on disk.

  Per `.cursor/rules/60-no-monero-legacy.mdc` "ask why is this here?"
  — this is an inherited assertion against a Shekyl-owned invariant.
  The invariant is enforced by `cmake/GitVersion.cmake`; the daemon
  should not re-parse its own output to re-check it. `rpc_command_executor.cpp`
  keeps the empty-string guard (`if (res.version.empty())`) so the CLI
  still reports "version not available" when the RPC response lacks a
  version, but no longer attempts to format-validate the string it
  receives.

### Fixed

- **Tagged-release `ci/gh-actions/cli` jobs on `test-ubuntu` matrix.**
  Follows from the `rpc_version_str` removal above. `v3.1.0-alpha.3`
  shipped with the daemon, wallet, and source archive built cleanly,
  but its tag-push CI ran red on this single unit test; `v3.1.0-alpha.4`
  will be the first alpha whose tag-push CI is green end-to-end.

- **Tripwire D processor regex broadened; gate-test probe assertion
  tightened (Chore #3 fixup).** The `CMAKE_SYSTEM_PROCESSOR` arm of
  the 64-bit-only gate in `CMakeLists.txt` previously used
  `armv[67]l?`, which only matches `armv[67]` and `armv[67]l` exactly —
  real toolchains also emit `armv7-a`, `armv7a`, `armv7ve`, `armv7hf`,
  `armv6kz`, `armv5te`, etc., which are all 32-bit ARM profiles.
  Broadened to `armv[567].*` so the "defense-in-depth" half of the
  predicate (which fires when `CMAKE_SIZEOF_VOID_P` is misreported as 8
  on a 32-bit target) actually covers those variants. 64-bit names
  (`aarch64`, `arm64`, `armv8*` in AArch64 mode) remain outside the
  pattern by construction. Companion tightening in
  `tests/cmake-gate-test/run.sh`: the probe-chatter assertion now
  also catches `-- Performing Test ...` (from `CheckCCompilerFlag` /
  `CheckCXXCompilerFlag` / `CheckLinkerFlag`), matching the set of
  modules actually relocated below the gate; `-- Detecting C/CXX
  compiler ABI info` is deliberately NOT caught because those lines
  come from `project()` itself, which runs before the gate by
  construction (the gate's `CMAKE_SIZEOF_VOID_P` predicate is
  populated by `project()`'s own compiler probe). Resolves the
  second Copilot review on PR #15.

- **`contrib/depends` Win64 unbound build restored (Chore #3 fixup).**
  The `$(package)_cflags_mingw32+=-D_WIN32_WINNT=0x600` line in
  `contrib/depends/packages/unbound.mk` was deleted in the Chore #3
  build-system commit under the mistaken framing of "arch-asymmetric
  32-bit MinGW carve-out." The `_mingw32` suffix in `contrib/depends`
  is the OS segment of the host triple, not an architecture gate: it
  matches every `*-w64-mingw32` host including `x86_64-w64-mingw32`.
  Unbound 1.19.1's `util/netevent.c` uses `WSAPoll` / `POLLOUT` /
  `POLLERR` / `POLLHUP` unconditionally and requires
  `_WIN32_WINNT >= 0x0600` to be defined before `<winsock2.h>` is
  included; the vendored `x86_64-w64-mingw32` toolchain does not
  default this the way MSYS2 pacman toolchains do, so the deletion
  broke the `depends.yml` Win64 lane (the `build.yml` MSYS2 and MSVC
  lanes use different toolchain pathways and stayed green). Line
  restored with the scope unchanged — only one MinGW host remains
  after Chore #3, and the flag belongs on it.

### Known regressions

- **`MLOG_SET_THREAD_NAME(label)` no longer reaches the log stream.**
  The macro still compiles and still evaluates its argument (so
  `-Wunused-value` stays quiet at the call sites), but the label
  (`[SRV_MAIN]` from `abstract_tcp_server2.inl`, `[miner N]` from
  `miner.cpp`, `DLN` from `download.cpp`) does not appear in emitted
  events. easylogging++ used this hook to stamp a semantic label
  into every subsequent log line; the Rust `tracing-subscriber`
  formatter reads the OS-level thread name instead (via the
  platform `pthread_getname_np` / `GetThreadDescription` path), and
  those names are not being populated in Chore #2. Restoring
  semantic thread labels — either by teaching the C++ shim to call
  `pthread_setname_np` + Windows equivalents, or by routing the
  label through the Rust subscriber as a `span` field — is tracked
  as a V3.2 follow-up in `docs/FOLLOWUPS.md`. The impact is
  diagnostic only: thread-scoped log lines now show a generic
  thread ID instead of the human-readable label the prior format
  carried.

## [3.1.0-alpha.3] - 2026-04-19

### Added

- **Release signing policy and maintainer keys (`docs/SIGNING.md`).**
  New document establishing that every release tag from `v3.1.0-alpha.3`
  onward is a signed annotated tag created with `git tag -a -s`. It
  records the initial maintainer signing key (Rick Dawson, ed25519
  `FEFEC7EF9952D40C`, ASCII-armored public key embedded in the doc so
  downstream verifiers can import it from the repo without trusting a
  keyserver lookup), and documents verification with `git verify-tag`,
  the reproducible-build cross-check that tag verification does not
  subsume, procedures for adding new maintainer keys, rotation,
  retirement, revocation, key hygiene expectations (passphrase,
  offline revocation certificate, hardware token or encrypted
  storage, GitHub registration), and the rationale for GPG over SSH
  signing or Sigstore at this stage. Earlier alpha tags
  (`v3.1.0-alpha.1`, `v3.1.0-alpha.2`) predate this policy and are
  not signed; their authenticity is established by branch topology
  and reproducible Guix builds.

### Changed

- **Branch policy mandates signed annotated release tags and
  non-fast-forward merges from `dev` to `main`.**
  `.cursor/rules/06-branching.mdc` was updated to require that `main`
  advance only via a merge commit (`git merge --no-ff dev`, GitHub
  "Create a merge commit") with a signed annotated tag placed on the
  resulting merge commit. Fast-forward, rebase-and-merge,
  squash-and-merge, and force-push to `main` are now explicitly
  forbidden. The rule cross-links to `docs/SIGNING.md` at both the
  Hard rule 1 mention and the Release flow step 4 mention so a
  maintainer reading the policy lands on the signing doc. A new
  "Rationale (why merge commit, not fast-forward)" section was added
  to capture the reasoning so the decision is not re-litigated each
  cycle.

- **`docs/FOLLOWUPS.md` tracks Shekyl Foundation institutional
  signing key as V3.1.x+ item.** Records the V3.1 decision: release
  signing uses maintainer keys, not an institutional Foundation key,
  until the Foundation has multi-maintainer operational structure
  (two or more active release maintainers). Cross-referenced from
  `docs/SIGNING.md` §"Future: Foundation institutional signing key".

### Security

- **Bump `cryptography` from `44.0.2` to `46.0.6`** in
  `tools/reference/requirements.txt` to clear two Dependabot advisories
  indexed 2026-04-13:
  - [GHSA-r6ph-v2qm-q3c2](https://github.com/advisories/GHSA-r6ph-v2qm-q3c2)
    (high): missing subgroup validation for SECT curves could allow a
    small-subgroup attack during ECDH.
  - [GHSA-m959-cc7f-wv43](https://github.com/advisories/GHSA-m959-cc7f-wv43)
    (low): incomplete DNS name constraint enforcement on peer names.

  **Not exploitable against Shekyl users.** `cryptography` is pulled in
  only by `tools/reference/derive_output_secrets.py`, a developer-only
  HKDF test-vector generator that never ships in any binary and is not
  on a consensus path at runtime. Inspection shows the
  `cryptography.hazmat.primitives.{hashes,kdf.hkdf}` imports in that
  script are unused — all HKDF logic is hand-rolled with stdlib
  `hmac`/`hashlib` — so the bump cannot change its output. Verified by
  regenerating `docs/test_vectors/PQC_OUTPUT_SECRETS.json` under the
  new version in a clean venv; SHA-256 matches byte-for-byte
  (`1159cb6de2ce3fa4af5d7a8f88eac71ed35c8f00ebf297a4d9259439b6477163`).

- **Accept seven `rand 0.8.5` Dependabot alerts as risk-tolerated.**
  [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  ("Rand is unsound with a custom logger using rand::rng()") indexes
  against the five workspace crates that pin `rand = "0.8"` plus two
  `Cargo.lock` files. CVSS is 0 on all seven; the actual exploit
  requires calling `rand::rng()` (a 0.9+ thread-local RNG API that
  does not exist in 0.8) while a custom `log::Log` implementation is
  installed. Shekyl uses `rand::rngs::OsRng` directly and
  `rand_chacha::ChaCha20Rng::from_seed` for deterministic derivation,
  and the daemon installs no custom `log::Log`, so no Shekyl code
  path reaches the vulnerable code. Migrating to `rand = "0.9"`
  cascades into bumping `curve25519-dalek` 4 → 5 plus several other
  crypto crates; per `.cursor/rules/20-rust-vs-cpp-policy.mdc` that
  is a planning activity with its own design doc and review cycle,
  tracked in `docs/FOLLOWUPS.md` §"rand 0.9 migration and
  curve25519-dalek 5 cascade" with target V3.1.x. Alerts #3 through
  #9 dismissed on GitHub with reason "risk tolerated" and a link to
  the follow-up.

### Changed

- **`wallet2_ffi` no longer carries wallet-directory state.** Removed
  `wallet2_ffi_set_wallet_dir` and the `wallet_dir` field on
  `wallet2_handle`. The four wallet-file FFI entry points
  (`wallet2_ffi_create_wallet`, `wallet2_ffi_open_wallet`,
  `wallet2_ffi_restore_deterministic_wallet`,
  `wallet2_ffi_generate_from_keys`) now take a full `wallet_path`
  parameter in place of the bare `filename` that was joined with
  `wallet_dir` using a hardcoded `"/"` separator. Path construction was
  inherited Monero `wallet_rpc_server` scaffolding and produced
  mixed-separator paths on Windows (`C:\Users\x\...\...//My Wallet.keys`).
  Callers now join paths in Rust via `PathBuf::join`, which is
  platform-correct on every target. The legacy C++
  `wallet_rpc_server.cpp` keeps its own `wallet_dir` state and is
  unaffected — it does not go through the FFI. The `shekyl-cli`
  `WalletContext` now holds the directory and joins filenames before
  each call; the `shekyl-wallet-rpc` Rust shim keeps
  `ServerConfig.wallet_dir` for the V3.2 cutover when its handlers
  will own wallet-file creation. `validate_filename` was narrowed and
  renamed to `validate_wallet_path` (empty-path check only) —
  path-component validation is the caller's responsibility now that
  the caller also owns the directory.

- **Nightly `proptest-exhaustive` job tuned and extended to `dev`.** Dropped
  `PROPTEST_CASES` from `1_000_000` to `200_000` — the old value could not
  finish inside the 30-minute runner cap on `ubuntu-latest` (ML-KEM-768
  keygen per case dominates wall time, the run was being cancelled not
  failed). Raised `timeout-minutes` to `180` so the job has real headroom,
  and added a branch matrix `[main, dev]` with per-branch cache keys so
  nightly coverage tracks both active histories instead of only the default
  branch. Actual elapsed time is surfaced via the job's `::notice::`
  annotation so the 200k / 180m bracket can be tightened once we have real
  data. See `.github/workflows/nightly.yml`.

## [3.1.0-alpha.2] - 2026-04-17

> Retroactive CHANGELOG entry. The v3.1.0-alpha.2 tag was created without
> promoting `[Unreleased]` first; the bullets below were subsequently
> split out from `[Unreleased]` during the alpha.3 release cycle. The
> split is based on the commit range `v3.1.0-alpha.1..v3.1.0-alpha.2`;
> content is verbatim from the original `[Unreleased]` copy and has
> not been edited retrospectively.

### Removed

- **Daemonizer layer.** Deleted `src/daemonizer/` (POSIX `fork()` detach,
  Windows Service Control Manager registration, console-control glue)
  and the four thin wrapper classes in `src/daemon/` (`t_core`,
  `t_protocol`, `t_p2p`, `t_rpc`) plus the executor shim. Background
  execution is now delegated to systemd (Linux), launchd (macOS), Task
  Scheduler (Windows), or the Tauri sidecar (GUI wallet); in-process
  forking and Windows service registration were untested code paths
  touching privilege boundaries and file-descriptor lifetimes, so their
  removal is a security improvement in addition to an audit-surface
  reduction. The removal also breaks the circular include chain where
  `daemon/command_line_args.h` transitively pulled `windows.h` into
  most of the codebase. Closes FOLLOWUPS.md §"windows-daemonizer-cleanup"
  and STRUCTURAL_TODO.md §"Daemonizer removal".
- **Daemonizer CLI flags:** `--detach`, `--pidfile`, `--install-service`,
  `--uninstall-service`, `--start-service`, `--stop-service`,
  `--run-as-service`. Both `shekyld` and `shekyl-wallet-rpc` accept
  these only long enough to print a migration message pointing at
  platform service managers (see `src/common/removed_flags.{h,cpp}`,
  marked `TODO(v3.2)` for deletion alongside the `shekyl-wallet-rpc`
  Rust cutover). `--non-interactive` is preserved in both binaries.

### Changed

- **Daemon orchestration class renamed.** `daemonize::t_daemon` is now
  `daemonize::Daemon` in `shekyld`, and `shekyl-wallet-rpc`'s unrelated
  inline class is now `WalletRpcDaemon`. The two binaries no longer
  share a type name, clarifying audit scope and the V3.2 Rust cutover
  plan.
- **Default data directory resolution moved to `src/common/`.** The
  admin-vs-user `CSIDL_*` branching formerly in `daemonizer` now lives
  in `common/daemon_default_data_dir.{h,cpp}`, preserving the exact
  path `shekyld` resolved before V3.1. Pinned by a new
  `daemon_default_data_dir` unit test so a future refactor cannot
  silently point operators at an empty data directory.
- MSVC CI job now builds `--target daemon wallet` instead of just
  `--target wallet`, matching what the GUI wallet release workflow
  actually compiles. Future MSVC regressions in daemon code will be
  caught in shekyl-core CI rather than surfacing in the GUI wallet
  release after an hour of compilation.

### Fixed

- Fixed probabilistic flake in
  `shekyl-crypto-pq::multisig_receiving::tests::scan_wrong_participant_ciphertext_fails`.
  The view tag hint is a single byte by design (fast scanner pre-filter),
  so a wrong-ciphertext decapsulation had ~1/256 chance of producing a
  hint that collided with the published one, causing the test's
  rejection assertion to fail. Test now retries keypair generation
  (bounded to 64 attempts) until the wrong-ciphertext hint actually
  differs, so the rejection path is exercised deterministically. No
  protocol or code change; scan semantics are unchanged.
- Made all `src/daemon/` headers self-contained for MSVC portability:
  `protocol.h` (6 missing includes), `p2p.h` (2), `daemon.h` (2),
  `rpc.h` (2). These headers relied on include ordering from their
  callers, which GCC/Clang tolerated but MSVC rejects.
- Fixed `#ifdef` inside `MERROR()` macro argument in `core_rpc_server.cpp`
  (undefined behavior, C2059 on MSVC). Replaced with literal function name.
- Explicitly captured `handshake` in lambda in
  `abstract_tcp_server2.inl` (C3493 on MSVC).
- Explicitly captured `credits_per_hash_threshold` in lambda in
  `core_rpc_server.cpp` (C3493 on MSVC).
- SFINAE-constrained `network_address` template constructor in
  `net_utils_base.h` to prevent MSVC eager instantiation (C2039).

## [3.1.0-alpha.1] - 2026-04-15

First public alpha release. First green CI in repository history.

This release establishes the Shekyl versioning scheme: software versions
follow SemVer independently per repo; the protocol version is a separate
integer (`protocol_version = 3`). See `docs/VERSIONING.md` for the full
scheme. The version jump from prior tags (v3.0.x-RC series) to 3.1.0
reflects the addition of FROST-style multisig to the feature set.

### Highlights

- **FCMP++ end-to-end test suite passing.** The full prove-sign-verify
  pipeline works across C++ and Rust via FFI, validated by 10-iteration
  randomized round-trip tests and C++ unit tests on Ubuntu 22.04/24.04,
  Arch Linux, macOS, and Windows.

- **Five FCMP++ integration bugs fixed.** Root causes documented in
  `docs/FOLLOWUPS.md` audit trail: FFI depth/layers off-by-one, branch
  extraction loop bound, missing point-to-scalar conversion, leaf count
  off-by-one, key image y-normalization breaking batch verification.
  Additionally, a sixth bug (FFI depth-to-layers convention ambiguity)
  was found and fixed during CI stabilization.

- **V3.1 multisig protocol specified and implemented.** FROST-style
  coordinator-less multisig with hybrid PQC signing, specified in
  `docs/PQC_MULTISIG.md` and wire format in
  `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`. 93 unit tests, 19 integration
  tests, 11 fuzz harnesses.

- **Versioning scheme established.** `docs/VERSIONING.md` defines SemVer
  for software versions and a separate integer protocol version.
  `SHEKYL_PROTOCOL_VERSION` constant added to `cryptonote_config.h`,
  exposed via `--version` output and `/get_info` RPC.

## Unreleased

### ✨ Added

- **PQC Multisig V3.1: equal-participants protocol implementation.**
  Full implementation of the coordinator-less multisig protocol as
  specified in `PQC_MULTISIG.md`. Key components:
  - `MultisigKeyContainer` v1.1 with `spend_auth_version` field and
    `multisig_group_id` v1.1 (includes version byte)
  - `rotating_prover_index`: cryptographic hash-based prover assignment
  - 8 HKDF-derived key/nonce labels for domain-separated derivation
  - `construct_multisig_output_for_sender`, `scan_for_multisig_output`,
    `validate_multisig_output_i7` for output lifecycle
  - `GriefingTracker`: per-output cost bounding for invalid outputs
  - `shekyl1m` Bech32m address format with file-based handling and
    3-representation fingerprint
  - `SpendIntent`: 14-check validation pipeline (structural, temporal,
    chain state, balance)
  - `ProverOutput`, `SignatureShare`, `ProverReceipt`: prover and
    signing flow types with equivocation detection
  - Honest-signer invariants I1–I7 enforcement
  - `MultisigEnvelope` with 11 message types and AEAD encryption
    (ChaCha20-Poly1305 with HKDF-derived keys)
  - Per-intent state machine (8 states: Proposed → Broadcast + terminal)
  - `HeartbeatTracker`: liveness, censorship, and sync anomaly detection
  - `CounterProof`: 8-rule chain evidence verification for counter recovery
  - C++ `tx_extra` tags 0x08, 0x09, 0x0A for multisig metadata
  - FFI: `shekyl_pqc_verify_with_group_id` for defense-in-depth
  - Consensus: scheme_id consistency enforcement across transaction inputs

- **PQC Multisig V3.1: GUI components (shekyl-gui-wallet).**
  7 React components for the multisig UX:
  - `FingerprintBadge`: grouped hex fingerprint with copy and metadata
  - `ProverView`: per-participant prover assignment breakdown
  - `LossAcknowledgment`: mandatory 1/N loss checkbox
  - `AddressProvenance`: fingerprint history with change detection
  - `RelayConfig`: multi-relay management with operator diversity
  - `ViolationAlert`: I1–I7 violation display with auto-abort
  - `SigningDashboard`: real-time intent state with sign/veto actions

- **PQC Multisig V3.1: test infrastructure.**
  - 93 unit tests across all V3.1 modules
  - 19 integration tests (functional, adversarial, determinism)
  - 4 cross-platform determinism canaries with pinned byte prefixes
  - 11 fuzz harnesses (wallet-core) covering serialization, encryption,
    state machine, validation, and verification
  - Criterion benchmarks for intent_hash, encryption, serialization,
    fingerprint computation, and assembly consensus

- **`docs/MULTISIG_OPERATIONS.md`**: end-user operations guide covering
  group setup, receiving, spending, recovery, relay configuration, and
  security considerations.

- **`docs/AUDIT_SCOPE.md`**: expanded to include V3.1 multisig attack
  surface (KDF, prover assignment, invariants, AEAD, CounterProof,
  griefing defense).

- **`docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`**: standalone portable wire
  format spec for the V3.1 multisig protocol. Covers MultisigEnvelope
  binary layout, SpendIntent canonical serialization, 11 message type
  discriminants, AEAD parameters (ChaCha20-Poly1305 with HKDF-SHA256),
  DecryptedPayload encoding, chain state fingerprint computation,
  file transport conventions, and conformance requirements. Enables
  third-party wallet implementations without reading the full spec.

- **GroupDescriptor**: canonical JSON backup file format for multisig
  groups. One file contains everything needed to restore a group from
  seeds (group_id, threshold, pubkeys, relays, fingerprint). Rust type
  in `shekyl-wallet-core`, Tauri export/import commands, and GUI
  component in `shekyl-gui-wallet`.

- **Failure-mode UX**: Multisig page restructured with 6 failure-mode
  alert banners (unresponsive co-signer, counter divergence, relay
  disconnect, fingerprint change, stuck intent, CounterProof failure).
  All Phase 3 components (SigningDashboard, ViolationAlert, ProverView,
  FingerprintBadge, LossAcknowledgment, AddressProvenance, RelayConfig)
  wired into the Multisig page.

- **File-based transport**: promoted from placeholder to first-class GUI
  option with Tauri file I/O commands and functional import/sign/export
  workflow. Equal prominence with relay transport.

- **Fee impact analysis**: added to MULTISIG_OPERATIONS.md with tx size
  comparison, per-input/per-output overhead, Bitcoin comparison, and
  economic viability analysis for small transactions.

- **Address format discipline**: cursor rule
  `65-address-format-discipline.mdc` codifying that `shekyl1m` is the
  sole multisig HRP for V3.x, with version bytes as the extension
  mechanism.

### 📚 Documentation

- **`docs/MULTISIG_OPERATIONS.md`**: expanded from 222-line protocol
  reference to ~500-line comprehensive operations guide with decision
  framework, 3 operational playbooks, 6 failure recovery guides,
  threat model worksheet, and honest limitations section.

- **`docs/FOLLOWUPS.md`**: added hardware wallet constraints (ML-DSA-65
  computation cost on Cortex-M, screen constraints, vendor outreach)
  and headless co-signer service reference implementation, both
  targeting V3.2.

- **GUI wallet cursor rules**: added `81-no-protocol-knowledge.mdc`
  (users never see FCMP++, KEM, HKDF in the UI) and
  `82-failure-mode-ux.mdc` (every feature must enumerate failure modes
  before implementation, failure states get dedicated UI).

### 🔒 Security

- **Zeroize ephemeral multisig signing seeds.** `ed_seed` and `ml_seed`
  stack copies in `construct_multisig_output_for_sender` are now wrapped
  in `Zeroizing<[u8; 32]>`, ensuring automatic zeroing on drop. Closes
  a theoretical side-channel surface from FOLLOWUPS.md V3.1 audit response.

- **`PersistedMultisigOutput` Debug redaction.** The `Debug` derive on
  `PersistedMultisigOutput` was replaced with a manual implementation that
  redacts `my_shared_secret` (64-byte KEM-derived material). Prevents
  accidental secret exposure through `dbg!` or structured logging.

- **`validate_balance` checked arithmetic.** `SpendIntent::validate_balance`
  now uses `checked_add` for input sums, output sums, and fee addition.
  Previously used wrapping `sum()` — crafted u64 values could wrap both
  sides to the same value and pass the equality check.

- **HKDF derivations return `Result`.** `derive_multisig_kem_seed` and
  `derive_participant_kem_randomness` now return `Result<..., CryptoError>`
  instead of panicking via `.expect()` on the transaction construction path.

- **`eprintln!` removed from `shekyl_fcmp_verify` FFI.** Two diagnostic
  `eprintln!` calls in the FCMP verification FFI path have been removed.
  The C++ caller already logs verification failures; the Rust-side stderr
  output was redundant and failed the CI lint.

### 🐛 Fixed

- **FCMP++ FFI: move depth-to-layers conversion to C++ callers.**
  `shekyl_fcmp_prove` and `shekyl_fcmp_verify` previously converted
  LMDB depth to upstream `layers` internally (`layers = depth + 1`).
  This created an ambiguous contract where the same `tree_depth`
  parameter meant different things in different FFI functions. Now both
  functions accept the upstream `layers` count directly; C++ callers
  (`blockchain.cpp`, `rctSigs.cpp`) perform `depth + 1` before calling.
  `shekyl_sign_fcmp_transaction` still accepts LMDB depth and converts
  internally (wallet callers pass LMDB depth). Added diagnostic tracing
  to `proof::verify` for `FcmpPlusPlus::read` and key image
  decompression failures. Fixed `validate.rs` c1/c2 alternation comment
  (the formula was correct but had been transiently swapped during
  refactoring). Tests simplified to single-layer Selene root (layers=1)
  to match the Rust unit test convention.

- **CI: fix `cargo audit` failure from RUSTSEC-2026-0098/0099.** Bumped
  `rustls-webpki` 0.103.10 -> 0.103.12 and `rand` 0.9.2 -> 0.9.4 in
  `Cargo.lock`. Added `rust/audit.toml` to acknowledge `rand` 0.8.5
  (RUSTSEC-2026-0097, not applicable: Shekyl uses `OsRng`, not
  `rand::rng()` with a custom logger).

- **Remove dead `verify_transaction_pqc_auth` one-arg overload.** The
  no-argument overload in `tx_pqc_verify.cpp` had zero callers — the
  sole production caller (`blockchain.cpp`) uses the two-arg form with
  `expected_scheme_id`. Replaced with a default parameter. Per
  `15-deletion-and-debt.mdc`: dead code goes.

- **Fix stale `shekyl_ffi.h` `shekyl_pqc_verify_debug` comment.** The
  error code documentation (0-4) did not match the Rust `PqcVerifyError`
  enum (0-11). Updated to reflect the actual `repr(u8)` discriminants.

- **Reconcile FOLLOWUPS.md and STRUCTURAL_TODO.md.** Marked 5 items in
  STRUCTURAL_TODO as resolved (code already fixed). Corrected the
  `expected_scheme_id` FOLLOWUPS entry (parameter is actively used by
  `blockchain.cpp`, contrary to the prior note). Marked `rpassword` audit
  as covered by CI.

### 🔄 Changed

- **FFI: verification functions return typed `u8` error codes instead of
  `bool`.** `shekyl_pqc_verify`, `shekyl_pqc_verify_with_group_id`, and
  `shekyl_fcmp_verify` now return 0 on success and a nonzero error
  discriminant on failure. PQC verify uses `PqcVerifyError` codes 1-11;
  FCMP verify uses `VerifyError` codes 1-7. Error codes are available in
  all build modes, eliminating the debug-only double-call pattern. C++
  callers (`tx_pqc_verify.cpp`, `blockchain.cpp`) updated to log error
  codes unconditionally. Per `30-ffi-discipline.mdc`.

- **Clippy lint rename: `unchecked_duration_subtraction` →
  `unchecked_time_subtraction`.** Updated in workspace `Cargo.toml` to
  track the upstream rename.

### 🗑️ Removed

- **`shekyl_pqc_verify_debug` deleted.** Now that production
  `shekyl_pqc_verify` returns typed error codes, the debug-only variant
  is redundant. All call sites and the `#ifndef NDEBUG` C header guard
  removed.

### 🐛 Fixed (continued)

- **All Rust clippy warnings resolved in `shekyl-crypto-pq`.** Fixed 1
  error (`missing_fields_in_debug` in `PersistedMultisigOutput`) and 13
  warnings: `op_ref` (11 sites in `kem.rs`, `montgomery.rs`, `output.rs`),
  `needless_range_loop` and `unnecessary_map_or` (in
  `multisig_receiving.rs`), `uninlined_format_args` (in `output.rs`
  tests). Also ran `cargo fmt` across workspace.

- **FCMP++ proof verification: five integration bugs fixed, first green CI.**
  The FCMP++ core tests (`gen_fcmp_tx_valid`, `gen_fcmp_tx_double_spend`,
  `gen_fcmp_tx_reference_block_too_old`, `gen_fcmp_tx_reference_block_too_recent`,
  `gen_fcmp_tx_timestamp_unlock_rejected`) have never passed since integration.
  Root causes identified and fixed:
  1. **FFI depth/layers off-by-one.** LMDB stores 0-indexed `tree_depth`;
     the upstream library expects 1-indexed `layers` count.
     Fix: `layers = tree_depth + 1` at the FFI boundary.
  2. **C++ branch extraction loop was `< depth` instead of `<= depth`.**
     Both `genRctFcmpPlusPlus` and `assemble_tree_path_for_output` skipped
     the root layer's branch data. Fix: `layer <= tree_depth` in both.
  3. **Point-to-scalar conversion missing in witness construction.**
     Raw LMDB point hashes were passed as branch siblings without converting
     to cycle scalars. Fix: `selene_to_helios_scalar` / `helios_to_selene_scalar`
     applied during `genRctFcmpPlusPlus` branch assembly.
  4. **`compute_leaf_count_at_height` off-by-one.** Maturity comparison used
     `<= target_height + 1` while LMDB's `drain_pending_tree_leaves` uses
     `<= current_height`. Fix: removed the `+ 1` to match LMDB semantics.
  5. **`key_image_y_normalize` broke Ed25519 batch verification.** The
     normalization (clearing byte 31 sign bit) modified the key image away
     from the true `x * Hp(O)` used by the Rust prover. Fix: deleted
     `key_image_y_normalize` entirely — FCMP++ key images are not
     y-normalized.
  6. **PQC signing payload computed before all public keys were derived.**
     `get_transaction_signed_payload` hashes all inputs' `hybrid_public_key`
     values, but the single-loop approach signed early inputs before later
     keys existed. Fix: two-phase PQC signing (derive all keys, then sign
     all inputs).
  All 5 FCMP++ core tests, 4 staking tests, 28 FCMP unit tests, and 45
  Rust `shekyl-fcmp` tests now pass. This is the first green CI in the
  repository's history.

- **Consensus-critical: curve tree leaf ordering bug (DB v6 → v7).**
  `pending_tree_leaves` used `MDB_DUPSORT` on 128-byte leaf data, causing
  outputs with the same maturity height to drain into the curve tree in
  byte-sorted order rather than `global_output_index` order. This broke the
  implicit `global_output_index == tree_leaf_index` assumption that every
  caller of `get_curve_tree_leaf()` relied on. Replaced with 16-byte
  composite keys `BE(maturity) || BE(output_index)` enforcing canonical
  drain order. Same restructuring applied to `pending_tree_drain`. Added
  explicit bidirectional mapping tables (`output_to_leaf`, `leaf_to_output`)
  and a `block_pending_additions` journal for robust `pop_block` reversal.
  DB schema bumped to v7 (incompatible with v6 — requires resync).

- **`get_curve_tree_leaf()` parameter was silently misnamed.**
  The function accepted `global_output_index` in its signature but actually
  looked up by tree position. Renamed to `get_curve_tree_leaf_by_tree_position()`
  and added `get_curve_tree_leaf_by_output_index()` (double lookup via mapping
  table). All callers updated — compile errors catch any missed sites.

- **`check_stake_claim_input` now recomputes and verifies the stored leaf.**
  Previously the stake claim gate only checked bounds
  (`staked_output_index < leaf_count`). Now the stored leaf is retrieved via
  the output→leaf mapping and bytewise-compared to a leaf recomputed from
  the output's `(output_key, commitment, h_pqc)`. This binds the claim to
  the actual output data in the tree.

### ✨ Added

- **`src/blockchain_db/shekyl_types.h`**: Strongly-typed identifiers
  (`TreePosition`, `OutputIndex`, `MaturityHeight`, `BlockHeight`) and
  LMDB key/value encoders (`PendingLeafKey`, `DrainKey`, `DrainValue`,
  `BlockPendingKey`, `BlockPendingValue`) for curve-tree state. Designed
  for 1:1 translation to Rust newtypes and heed `BytesEncode`/`BytesDecode`.

- **4 new regression tests** in `deferred_insertion.cpp`:
  same-maturity drain order by output_index, block_pending_additions
  journal round-trip, output↔leaf mapping round-trip, pop_block
  journal-driven reversal simulation.

### 📋 Protocol

- **X25519 public key derived from Ed25519 view key.**
  The X25519 public key used in the hybrid KEM classical component is the
  Edwards→Montgomery image of the Ed25519 view public key:
  `x25519_pub = (1 + y) / (1 - y) mod p`. It is not carried in the address
  or generated independently. The Bech32m address PQC segments carry ML-KEM
  material exclusively. See `POST_QUANTUM_CRYPTOGRAPHY.md` §X25519 Binding
  to View Key.

- **Unclamped Montgomery DH (not RFC 7748 X25519).**
  The classical KEM component performs `Scalar * MontgomeryPoint` with the
  Ed25519 view scalar as the private input. RFC 7748 scalar clamping is not
  applied because the view scalar is already reduced mod `ℓ`; clamping
  would mutate it and desynchronize sender/receiver derivation. See
  `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics.

- **Low-order Montgomery point rejection (validation rule).**
  Recipients MUST reject low-order Montgomery points on `kem_ct_x25519`
  before performing DH: `if (8 * point).is_identity() → reject`. This
  replaces RFC 7748 clamping's cofactor-clearing role. Sender-side check
  on the derived recipient X25519 pub is defense-in-depth. See
  `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics.

- **`m_pqc_public_key` layout invariant: 1216 bytes.**
  `X25519_pub[0..32] || ML-KEM-768_ek[32..1216]` where `X25519_pub` is
  derived (never transmitted). Canonical assemblers:
  `get_account_address_from_str`, `generate_pqc_key_material`. Runtime
  checks enforce exact size at every split site.

- **Wallet key consistency invariant.**
  `m_pqc_secret_key[0..32] == m_view_secret_key`. Wallet refuses to open
  on mismatch.

- **X25519 derivation test vectors published.**
  `docs/test_vectors/PQC_TEST_VECTOR_005_X25519_DERIVATION.json` pins the
  Ed25519→X25519 derivation, unclamped DH shared secrets, low-order
  rejection inputs, and Edwards rejection inputs for third-party
  implementers.

### ✨ Added

- **`montgomery.rs`**: Edwards→Montgomery conversion, unclamped scalar
  interpretation, low-order point detection. (`shekyl-crypto-pq`)
- **`shekyl_view_pub_to_x25519_pub` FFI export** for C++ callers.
  (`shekyl-ffi`)
- **Genesis reproducibility artifacts**: `verify_genesis.py` script and
  `GENESIS_BUILD_INFO.txt`. (`shekyl-dev/tools/genesis_builder/`)

### 🔄 Changed

- **`genesis_builder` print_usage updated to Bech32m.**
  Usage example now shows `<bech32m>` addresses instead of `<base58>`.

### 🐛 Fixed

- **Fixed `core_tests` FCMP++ proof verification failures.**
  `gen_fcmp_tx_valid`, `gen_fcmp_tx_double_spend`, and `gen_staking_lifecycle`
  all failed with "FCMP++ proof verification failed" because test-chain block
  headers carried a placeholder `curve_tree_root` (`selene_hash_init`) while
  witness paths were assembled from the real LMDB tree. Added per-height curve
  tree root storage (`m_curve_tree_roots` LMDB table) so both the prover and
  verifier read the correct historical root for any reference block height.
  Also aligned `compute_leaf_count_at_height` in `chaingen.cpp` with production
  `collect_outputs` logic (output-type filtering and `outPk` bounds checks).

- **Reverted `vcpkg.json` manifest that broke MSVC CI.**
  Commit `397817b` introduced a `vcpkg.json` with `"builtin-baseline": null`,
  which caused the MSVC CI job to fail (vcpkg auto-detected the manifest and
  rejected the null baseline). The CI workflow already manages vcpkg
  dependencies via explicit CLI invocation. Deleted the manifest to restore
  the working state.

- **Restored and upgraded `JsonSerialization.FcmpPlusPlusTransaction` test.**
  Replaced ring-style `make_transaction` with `make_fcmp_transaction()` that
  constructs a real v3 FCMP++ transaction via the full Rust FFI signing
  pipeline: KEM keypair generation, output construction, scan-and-recover,
  curve tree leaf/root building, FCMP++ proof signing and verification, and
  PQC auth signing. The test now exercises real cryptographic operations
  (not stubs) before round-tripping through JSON serialization. Deprecated
  `wallet_tools::gen_tx_src` with migration note pointing to the FCMP++
  pipeline in `chaingen.cpp`.

- **Fixed `rctSig` JSON serializer missing `message` and `referenceBlock`.**
  The JSON round-trip for `rct::rctSig` did not serialize the `message` field
  (tx prefix hash) or the `referenceBlock` field (for `RCTTypeFcmpPlusPlusPqc`).
  Both are part of the binary wire format in `rctTypes.h` but were silently
  lost during JSON serialization. Added `message` to all rctSig JSON output
  and `referenceBlock` for FCMP++ transactions. Discovered by the
  `FcmpPlusPlusTransaction` JSON round-trip test.

- **`on_get_curve_tree_path` RPC consistency fix.** The RPC handler read
  `leaf_count` from tip state but returned a `reference_block` several blocks
  behind tip. If the tree grew in between, the returned leaf data and layer
  hashes did not match the reference block's `curve_tree_root`. Fixed by
  computing `ref_leaf_count` at `reference_height` via drain journal, capping
  all reads to that count, and applying boundary-chunk hash trimming for
  sibling chunks that changed since the reference block. Mirrors the fix
  already applied to the test harness in `chaingen.cpp`.

- **MSVC portability batch.** Expanded `src/common/compat.h` with centralized
  platform-conditional includes for `unistd.h`/`io.h`, `dlfcn.h`, and
  `sys/mman.h`. Added `AND NOT MSVC` guards to `monero_enable_coverage`
  (GCC-only `--coverage` flags) and `enable_stack_trace` (GNU `ld`
  `-Wl,--wrap=__cxa_throw`). Fixed `bootstrap_file.cpp` `long` types to
  `std::streamoff`/`uint64_t` for LLP64 correctness. Fixed unsigned negation
  in `wallet2.cpp:772` (`std::advance(left, -N)` where N is `size_t`) with
  `static_cast<ptrdiff_t>`. Created root `vcpkg.json` manifest for
  deterministic dependency management.

- **FCMP++ test harness: tree state mismatch.** `assemble_tree_path_for_output`
  and `construct_fcmp_tx` in `tests/core_tests/chaingen.cpp` read the current
  (tip) curve tree state but the verifier checks against the reference block's
  historical tree root. Fixed by computing `ref_leaf_count` at the reference
  block height and capping all leaf/layer reads to that count, with boundary
  chunk hash trimming via `shekyl_curve_tree_hash_trim_selene` for siblings
  that changed since the reference block. Also fixed a layer offset bug where
  sibling hashes were read from `layer` instead of `layer - 1`.

- **FCMP++ test harness: staking tests missing FCMP++ pipeline.**
  `gen_staking_lifecycle` and `gen_stake_all_tiers` used `construct_staked_tx`
  which produced stub RCT signatures without FCMP++ proofs or PQC auth.
  Rewritten to use callback-based testing (like `gen_fcmp_tx_valid`) with a
  new `construct_fcmp_staked_tx` that routes through the full FCMP++ proving
  and PQC signing pipeline via `apply_fcmp_pipeline`.

### 🔄 Changed

- **Unified constant-time comparison for all 32-byte crypto types.**
  `public_key`, `key_image`, and `hash` now use `crypto_verify_32` via
  `CRYPTO_MAKE_HASHABLE_CONSTANT_TIME` instead of `memcmp`-based
  `CRYPTO_MAKE_HASHABLE`. Eliminates the footgun of a developer choosing
  the non-constant-time macro for a new secret-bearing 32-byte type.

- **Added `ct_signatures` type alias.** `using ct_signatures = rct::rctSig;`
  added in `cryptonote_basic.h` as the starting point for migrating away
  from the Monero-era `rct_signatures` name. Full caller migration and
  `rct::` namespace rename deferred to V4.

- **Documented alternative tokens decision.** Keeping `/FIiso646.h`
  workaround for MSVC; mechanical replacement of `not`/`and`/`or` is
  high-effort, low-value. Recorded in STRUCTURAL_TODO.md.

- **Workspace-wide clippy cleanup.** Resolved all `cargo clippy --all-targets
  --no-deps -- -D warnings` errors across the Rust workspace (14 crates,
  52 files). Key changes: replaced `as u128` casts with `u128::from()`,
  added `#[allow]` for intentional truncation in economics/FFI code,
  marked FFI `extern "C"` functions `unsafe` with `# Safety` docs,
  replaced redundant closures with method references, used `let...else`,
  switched `from_slice` to `GenericArray::from()` in chacha20poly1305,
  changed `&Vec<T>` to `&[T]` in public APIs. No behavioral changes.

### ✨ Added

- **Fuzz target for `derive_output_secrets`.** New `fuzz_derive_output_secrets`
  cargo-fuzz harness in `rust/shekyl-crypto-pq/fuzz/`. Exercises arbitrary
  `combined_ss` inputs (up to 1200 bytes) and output indices; asserts
  determinism, non-zero ho/y scalars, and absence of panics on
  truncated/oversized input. Closes FOLLOWUPS.md fuzz-derivation item.

- **Witness header round-trip test.** New `witness_header_build_then_parse_roundtrip`
  test in `rust/shekyl-ffi/` with locked vectors in
  `docs/test_vectors/WITNESS_HEADER.json`. Proves `shekyl_fcmp_build_witness_header`
  (writer) and `parse_prove_witness` (reader) agree byte-for-byte on all 8
  header fields `[O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]`.
  Closes FOLLOWUPS.md witness-roundtrip item.

### 📚 Documentation

- **y=0 consensus check resolved as infeasible.** Documented that a
  consensus-level rejection of outputs with `y=0` T-component cannot be
  implemented: the verifier does not know `y` (it is a KEM-derived secret)
  and testing whether `O` lies in the G-only subgroup requires knowing the
  DL between G and T. Defense is structural via `derive_output_secrets`
  hard-assert and fuzz coverage. Closes FOLLOWUPS.md y=0-consensus item.

- **scheme_id binding analysis corrected in `PQC_MULTISIG.md`.** The
  `expected_scheme_id` parameter in `verify_transaction_pqc_auth` is unused
  because FCMP++ hides which output is being spent. Scheme downgrade
  protection is provided by the `h_pqc` curve tree leaf commitment —
  the FCMP++ proof binds `H(hybrid_public_key)` to the leaf, making a
  downgrade require a Blake2b-512 collision. Updated Attack 1 mitigation
  description and `POST_QUANTUM_CRYPTOGRAPHY.md` accordingly.

- **FOLLOWUPS.md and STRUCTURAL_TODO.md audit and cleanup.**
  Marked 5 stale items as resolved (2 in FOLLOWUPS, 3 in STRUCTURAL_TODO):
  `signing_round_trip.rs` now exercises FFI, `AUDIT_SCOPE.md` exists,
  C++20-isms audit complete, easylogging++ MSVC fully fixed, `wallet2.h:2324`
  bool/char pattern removed by wallet refactoring. Updated 2 stale references:
  `simplewallet.cpp` deleted (removed from `long` type sites and `memcmp`
  resolution list), `wallet2.cpp:782` shifted to line 772. Updated test
  `memcmp` count from 84 to ~90. Annotated `expected_scheme_id` removal as
  deferred to PQC multisig PR.

### 📚 Documentation

- **Cross-repo documentation audit.** Comprehensive review across all five
  Shekyl repos fixing stale references, Monero-era branding, completed-but-
  unchecked items, and broken cross-references. Key changes:
  - `README.md`: Removed Monero CI badges (Coverity, OSS Fuzz, Coveralls),
    stale distribution packages (`apt install monero`, etc.), Raspberry Pi
    Jessie instructions, 2022-era pruning sizes, `monerod.conf` references.
    Fixed research section cross-references to shekyl-dev repo.
  - `proxies.md`: Renamed "Monero ecosystem" to "Shekyl ecosystem".
  - `DOCUMENTATION_TODOS_AND_PQC.md`: Fixed FCMP++ "Phase 8" references
    (doc exists), CryptoNight reference (Shekyl uses RandomX from genesis),
    `CURVE_TREE_OPERATIONS.md` reference (covered in `FCMP_PLUS_PLUS.md`),
    v2.0 tx references (should be v3).
  - `INSTALLATION_GUIDE.md`: `FCMP_PLUS_PLUS.md` exists, not "planned."
  - `V4_DESIGN_NOTES.md`: Checked boxes for items done in V3.
  - `RELEASE_CHECKLIST.md`: Marked wallet/exchange/pool entries as
    placeholders for Shekyl-specific partners.
  - `FOLLOWUPS.md`: Added items for fuzz harness on `derive_output_secrets`,
    witness header round-trip test, y=0 consensus check, and
    `AUDIT_SCOPE.md` creation.
  - KEM plan: Updated 18 todo items from `pending` to `completed` matching
    actual codebase state.

### 🗑️ Removed

- **`tests/unit_tests/address_from_url.cpp` deleted.** The test referenced
  `MONERO_DONATION_ADDR` (removed constant) and tested Monero OpenAlias DNS
  resolution against `donate.getmonero.org`. Both the constant and the DNS
  endpoint are irrelevant to Shekyl; the test broke the macOS CI build.

- **`simplewallet` (shekyl-wallet-cli) deleted.** The 9,126-line C++ interactive
  wallet REPL has been removed. Its replacement, `shekyl-cli` (Rust), was
  already at full parity for all actively-used commands. Removed
  `src/simplewallet/` directory, CMake target, CI artifact references, and
  Windows installer entries. The `translations/` directory retains
  simplewallet-era `.ts` strings as dead entries within shared i18n files.

- **`wallet/api/` C++ wrapper layer deleted.** The 3,909-line Monero-era C++
  wrapper (`wallet2_api.h` and 10 implementation files) had no production
  consumer -- the GUI uses `wallet2_ffi` via `shekyl-wallet-rpc` (Rust). Removed
  `src/wallet/api/` directory, `tests/libwallet_api_tests/`, and the
  `add_subdirectory(api)` entry from `src/wallet/CMakeLists.txt`. Cleaned up
  stale `#include "wallet/api/*.h"` references in `object_sizes.cpp` and
  `address_from_url.cpp`.

### 🐛 Fixed

- **19 `core_tests` failures and SEGFAULT from v3 transaction incompatibility.**
  The test framework's `construct_miner_tx_manually` was hardcoded to produce v2
  transactions without PQC output construction, causing 16 block validation tests
  to fail during generation and a SEGFAULT in `tx_validation` tests. Rewrote the
  function to perform genuine v3 output construction via `shekyl_construct_output`
  FFI. Added `append_v3_output_to_miner_tx` helper for tests that add outputs to
  coinbase. Fixed `fill_tx_sources` to populate `ho`/`v3_ho_valid` on source
  entries via `try_v3_scan_output`. Removed stale classical key derivation from
  view tag tests. Fixed serialization consistency in tests that modify
  `vout`/`vin` without updating `rct_signatures` fields.

- **Non-exhaustive `TxBuilderError` match in FFI error-code mapping.**
  Commit `aff9f777` added `TreeDepthTooLarge(u8)` to `TxBuilderError` but did
  not add the corresponding arm to `tx_builder_error_code()` in `shekyl-ffi`,
  breaking CI compilation on all platforms. Added `TreeDepthTooLarge(_) => -27`.

## [core-v3.1.0] - 2026-04-13

### 🔄 Changed

- **Dev merged into main.** 128 commits from `dev` promoted to `main`
  including: FCMP++ curve-tree integration, hybrid PQC KEM scanning,
  shekyl-cli full parity, shekyl-address Bech32m encoding, native Rust
  transaction signing, staking enhancements, wallet/api removal, and
  ZeroMQ cleanup. Tagged as `core-v3.1.0` for GUI wallet CI pinning.

### ✨ Added

- **`shekyl-cli` full parity with simplewallet (40 of 81 commands).** The
  `rust/shekyl-cli/` crate now covers all actively-used simplewallet
  functionality. Key additions since the initial scaffold:
  - **Security-hardened UX**: `display.rs` for secret display with TTY
    checks, multiplexer warnings, best-effort scrollback clear, and honest
    residual-scrollback warning. `errors.rs` for JSON-RPC error sanitization
    (strips paths/hex; `--debug` routes raw errors to stderr or 0600 log
    file, never stdout). Context-specific `confirm_dangerous()` tokens for
    destructive operations (sweep amount, address prefix, acknowledgment
    phrase).
  - **Stateless account model**: `ReplSession` holds session-default
    account on REPL stack; `ResolvedCommand` enum resolves `--account N` at
    parse time. No wallet-level current-account state.
    `--subaddr-index`/`--subaddr-indices` for subaddress selection.
  - **Independent daemon client**: `daemon.rs` using ureq (rustls backend,
    pinned) for `chain_health`. SOCKS stream isolation via distinct auth
    username. `--daemon-ca-cert` and `--proxy` CLI flags. Differentiated
    error reporting (5 failure modes).
  - **Staking**: `stake`, `unstake`, `claim`, `staking_info`, `chain_health`.
  - **Keys**: `viewkey`, `spendkey` with terminal safety; `export_key_images`
    (0600 permissions, `--since-height`, `--all`); `import_key_images` with
    format validation.
  - **Proofs**: `get_tx_key`, `check_tx_key`, `get_tx_proof`,
    `check_tx_proof`, `get_reserve_proof`, `check_reserve_proof`.
  - **Wallet ops**: `password` (old-first with fast-fail validation),
    `rescan` (`confirm_dangerous`), `sweep_all` (privacy warning),
    `show_transfer`.
  - **Offline signing**: `describe_transfer`, `sign_transfer`,
    `submit_transfer`; `--do-not-relay` on `transfer`.
  - **Signing**: `sign`, `verify` (domain separation documented),
    `version`, `wallet_info` (no filename).
  - **Input validation**: `validate.rs` with hex, txid, address, and
    input-length validators.
  - **Fuzz tests**: `proptest` dev-dependency with 14 property tests for
    amount parsing, hex validation, address validation, and argument
    parsing.
  - **Parity matrix**: `docs/CLI_PARITY_MATRIX.md` maps all 81
    simplewallet commands to shekyl-cli equivalents or explicit out-of-scope
    with reasons. Phase 3 deletion gate defined.
  - **Categorized help** with per-command usage docs and domain-separation
    note on sign/verify.

- **CI gate: `dalek-ff-group` version isolation.** Added a workflow step that
  asserts `shekyl-ffi`'s normal dependency tree never pulls in
  `dalek-ff-group` v0.4. The 0.4 version is allowed transitively inside
  `ciphersuite` internals but must never be used directly by Shekyl code.

- **CI lint: no debug macros in production Rust.** Added a workflow step that
  rejects `eprintln!`, `dbg!`, and `println!` in production Rust code
  (excluding test modules, build scripts, binary entry points, and the
  economics simulator). Prevents accidental debug logging from reaching
  production builds.

- **CI lint: BOOST_FOREACH guard.** Added a workflow step that fails if any
  `BOOST_FOREACH` usage is reintroduced via upstream cherry-picks. All 31
  prior instances were replaced with range-based for loops.

### 🔄 Changed

- **CI lint: exclude `shekyl-cli` from debug-macro ban.** The interactive
  CLI REPL legitimately uses `println!`/`eprintln!` for terminal output.
  The lint now skips `rust/shekyl-cli/` to avoid false positives on
  binary crate I/O.

### 🐛 Fixed

- **[CONSENSUS] Genesis TX blobs upgraded to v3 wire format.** The hardcoded
  `GENESIS_TX` hex in `cryptonote_config.h` (mainnet, testnet, stagenet)
  was still in the legacy v2 format, missing the `enc_amounts` and `outPk`
  arrays required by the current `serialize_rctsig_base`. Updated all three
  blobs to v3 (`tx.version = 3`) with zero-filled `enc_amounts`/`outPk`
  for `RCTTypeNull` coinbase. This was the root cause of `core_tests`
  SEGFAULT, `block_weight` failure, and wallet init failures in CI.

- **JSON serialization now includes `enc_amounts`/`commitments` for
  `RCTTypeNull` coinbase.** The `toJsonValue`/`fromJsonValue` for
  `rct::rctSig` previously skipped these fields for `RCTTypeNull`, but the
  binary wire format serializes them for all RCT types since the v3 format
  change. This caused JSON round-trip failures for coinbase transactions.

- **`HTTP_Client_Auth.MD5_auth` test used hardcoded empty cnonce.** The test
  computed the expected MD5 digest with `cnonce=""` while the production
  `http_auth.cpp` generates a random cnonce. Fixed to extract the actual
  cnonce from the parsed auth response.

### 🗑️ Deprecated

- **`test::make_transaction` ring-style helper.** The helper constructs
  Monero-era ring-signature source entries incompatible with v3/FCMP++
  transaction construction. `BulletproofPlusTransaction` is `GTEST_SKIP`'d
  pending FCMP++ test infrastructure.

- **[CONSENSUS-ADJACENT] Branch layer depth validation off-by-one in
  `shekyl-tx-builder`.** The rule `c1 + c2 == depth` was corrected to
  `c1 + c2 + 1 == depth` (layer 0 is the leaf hash and has no branch
  entry). The previous rule incorrectly rejected valid witnesses at
  depth=1 and accepted structurally wrong branch counts at all other
  depths. Discovered by the FFI signing round-trip test introduced in
  this release. Verifier side verified: uses proof-structure-implicit
  depth enforcement (no explicit c1/c2 check needed). Additionally,
  validation now enforces the spec-correct C1/C2 alternation split
  (`c1 == c2` or `c1 == c2 + 1`), the error.rs doc was corrected
  (previously stated the relationship backwards), and `MAX_TREE_DEPTH=24`
  was added as a named constant in `shekyl-fcmp` with enforcement in both
  prover and verifier. See FOLLOWUPS.md for the full audit trail.

### ✅ Testing

- **FFI signing round-trip test rewritten to use `shekyl_sign_fcmp_transaction`.**
  `rust/shekyl-ffi/tests/signing_round_trip.rs` now exercises the full C-ABI
  FFI boundary: KEM keypair generation, output construction, output scanning,
  curve tree leaf/root computation, JSON serialization of `FcmpSignInput` +
  `OutputInfo`, signing via `shekyl_sign_fcmp_transaction`, and verification
  via `shekyl_fcmp_verify`. Runs 10 iterations with different random seeds.
  Previously called `proof::prove` directly, bypassing FFI JSON parsing, key
  derivation, and buffer management.

### 📚 Documentation

- **FFI header upgraded to `///` doc comments (Phase 6 completion).** Converted all
  `//` function and struct documentation comments in `src/shekyl/shekyl_ffi.h` to
  `///` Doxygen-style. Covers all ~70 FFI exports: output construction/scanning,
  key image computation, FCMP++ prove/verify, wallet proofs, cache encryption,
  KEM operations, Bech32m encoding, curve tree hashing, seed derivation, and
  daemon RPC. Rewrote the `SHEKYL_PROVE_WITNESS_HEADER_BYTES` comment from
  `DEPRECATED`/`TODO` language to document its role as test infrastructure for
  `genRctFcmpPlusPlus` in `core_tests`.

### 🔄 Changed

- **`simplewallet` marked deprecated.** Added a yellow deprecation banner to
  `simplewallet.cpp` startup: "shekyl-wallet-cli is deprecated and will be
  removed. Use shekyl-cli instead." No new features will be added; the binary
  will be deleted once `shekyl-cli` reaches parity.

- **Axum RPC binds to standard port.** When `--no-rust-rpc` is not set, the
  Axum daemon RPC server now binds to the standard RPC port (11029/12029/13029)
  and the epee HTTP listener is skipped. Falls back to epee on Axum startup
  failure. Previously Axum bound to `epee_port + 10000`.

- **Production `eprintln!` removed from Rust FFI.** Replaced 6 `eprintln!`
  calls in `shekyl-ffi/src/lib.rs` error handlers with silent error
  suppression (the C++ caller checks the bool return). Converted 1
  `eprintln!` in `shekyl-daemon-rpc/src/ffi_exports.rs` to `tracing::error!`.

- **Test code migrated to remove all calls to deleted crypto/device functions.**
  Updated 14 test files across `tests/crypto/`, `tests/unit_tests/`,
  `tests/core_tests/`, `tests/performance_tests/`, `tests/trezor/`, and
  `tests/benchmark.cpp` to remove references to `derive_public_key`,
  `derive_secret_key`, `derivation_to_scalar`, `derive_subaddress_public_key`,
  `derive_view_tag`, `is_out_to_acc`, `lookup_acc_outs`, `ecdhDecode`,
  `ecdhHash`, `genCommitmentMask`, `generate_key_image_helper`, and
  `generate_output_ephemeral_keys`. Where inline key derivation was needed
  (block/miner-tx construction tests), local helpers using Ed25519 primitives
  (`hash_to_scalar`, `ge_scalarmult_base`, `sc_add`) replace the deleted
  functions. Legacy output scanning in `chaingen.cpp` and `chain_switch_1.cpp`
  falls through to the v3 scan path. All `additional_tx_keys` parameters
  removed from `construct_tx_and_get_tx_key` call sites. Benchmark harnesses
  for `derive_subaddress_public_key` and per-tx scanning removed.

### 🗑️ Removed

- **Complete ZMQ removal.** Deleted the entire ZeroMQ subsystem: ZMQ pub/sub
  (`zmq_pub.cpp`), ZMQ RPC server (`zmq_server.cpp`, `daemon_handler.cpp`,
  `daemon_messages.cpp`), low-level ZMQ helpers (`net/zmq.cpp`), message schema
  (`message.cpp`, `daemon_rpc_version.h`, `rpc/fwd.h`), and the `rpc_pub`,
  `daemon_rpc_server`, `daemon_messages` CMake targets. Removed `libzmq`
  build dependency from root CMakeLists, `contrib/depends`, and all link
  targets. Deleted 3 test files (`zmq_rpc.cpp`, `txpool.py`,
  `python-rpc/framework/zmq.py`) and the `zeromq.mk` depends recipe with its
  patches. Removed `--zmq-rpc-bind-ip`, `--zmq-rpc-bind-port`, `--zmq-pub`,
  `--no-zmq` CLI arguments. ZMQ was a duplicate, unauthenticated RPC surface
  inherited from an abandoned Monero "migrate RPC to ZMQ" effort. It had zero
  first-party consumers, leaked `do_not_relay` transactions, and its tests had
  been broken for 82+ consecutive CI runs, polluting the test signal during
  the FCMP++ migration. Ports 11025/12025/13025 are now reserved.
  Re-audit follow-up: removed stale `#include "rpc/daemon_messages.h"` and
  two ZMQ-schema-dependent tests (`DaemonInfo`, `HandlerFromJson`) from
  `json_serialization.cpp`, and fixed daemon link order (`rpc` after
  `${SHEKYL_DAEMON_RPC_LINK_LIBS}`) to resolve circular FFI back-references
  previously satisfied transitively through `daemon_rpc_server`.

- **`wallet/api/` C++ wrapper layer deleted (~3,900 lines).** The
  `src/wallet/api/` directory (22 files) wrapped `wallet2` for GUI consumption.
  With the Tauri GUI using `wallet2_ffi` via Rust, no production consumer
  remained. Removed the directory, `add_subdirectory(api)` from wallet
  CMakeLists, `wallet/api` includes and sizeof reporters from
  `object_sizes.cpp`, broken includes in `subaddress.cpp` and trezor tests,
  `wallet_api` link target from trezor CMakeLists, and CI `--target wallet_api`
  build steps.

- **`libwallet_api_tests/` test suite deleted (~1,300 lines).** Removed the
  `tests/libwallet_api_tests/` directory and its CMake entry. Cleaned up the
  Makefile's `libwallet_api_tests` ctest exclusions (originally disabled for
  Issue #895, now fully removed). Also removed the `wallet_api_tests` class
  and implementation from trezor tests.

- **`load_deprecated_formats` / `is_deprecated` dead code excised (Phase 6
  completion).** Removed the `is_deprecated()` method, `is_old_file_format`
  member, `m_load_deprecated_formats` member and its getter/setter from
  `wallet2.h`. Deleted the `is_deprecated()` definition, JSON save/load of
  `load_deprecated_formats`, the non-JSON wallet keys file fallback (now a hard
  error), and the boost `portable_binary_iarchive` version `\003`/`\004`
  branches in `parse_unsigned_tx_from_str` and `parse_tx_from_str` from
  `wallet2.cpp`. Removed the `set_load_deprecated_formats` command, its
  `CHECK_SIMPLE_VARIABLE` entry, settings display line, and the `is_deprecated()`
  upgrade flow from `simplewallet.cpp`/`.h`. Shekyl is v3-from-genesis; there are
  no legacy non-JSON wallet files or boost-serialized transaction blobs to load.

- **`additional_tx_keys` / `additional_tx_pub_keys` infrastructure fully
  removed.** Deleted member variables, struct fields, serialization entries, and
  function parameters referencing additional transaction keys from `wallet2.h`,
  `wallet2.cpp`, `cryptonote_tx_utils.h/.cpp`, `cryptonote_format_utils.h`,
  `device.hpp`, `device_default.hpp/.cpp`, and `device_ledger.hpp/.cpp`. In
  `wallet2.cpp`, removed all `additional_tx_pub_keys` / `additional_tx_keys`
  local variables, derivation computation loops, `m_additional_tx_keys` map
  operations, `etd.m_additional_tx_keys` export/import paths, and updated
  function definitions (`get_tx_key_cached`, `get_tx_key`, `set_tx_key`,
  `check_tx_key`, `get_tx_proof`) to match the simplified header signatures. The
  `conceal_derivation` device method implementations were updated to match
  the simplified signatures (no additional keys/derivations parameters). The
  `ABPkeys` struct no longer carries `additional_key`. Cleaned up all remaining
  call sites across `wallet2_ffi.cpp`, `wallet/api/wallet.cpp`,
  `simplewallet.cpp`, `wallet_rpc_server.cpp`, and `trezor/protocol.cpp` —
  removing additional-key parsing loops, serialization, and pass-through
  parameters. `get_additional_tx_pub_keys_from_extra` is now an inline stub
  returning an empty vector. In V3, per-output KEM ciphertexts replace
  additional tx keys; there is only one tx pubkey per transaction.

- **`derive_public_key`, `derive_secret_key`, and `derivation_to_scalar` removed
  from the device interface chain.** Deleted the pure virtual declarations from
  `device.hpp` and all override implementations from `device_default` and
  `device_ledger`. Also deleted `derive_public_key` and `derive_secret_key` from
  `crypto.cpp`/`crypto.h` (kept `derivation_to_scalar` in crypto, still needed by
  `derive_subaddress_public_key`). Removed associated performance test files.
  These Keccak-based one-component key derivation helpers are superseded by the
  V3 HKDF two-component output key derivation in `cryptonote_tx_utils`.

- **`out_can_be_to_acc`, `is_out_to_acc_precomp`, and `derive_view_tag` dead
  code removed.** Deleted the Keccak-based `out_can_be_to_acc` and
  `is_out_to_acc_precomp` functions from `cryptonote_format_utils`, the
  `derive_view_tag` function from `crypto`, and the `derive_view_tag` virtual
  method from the device interface chain (`device.hpp`, `device_default`,
  `device_ledger`). Removed associated performance tests. These functions were
  superseded by the X25519/HKDF view-tag derivation path in the V3 transaction
  format.

- **`ecdhHash` and `genCommitmentMask` dead code removed.** Deleted the
  `ecdhHash` and `genCommitmentMask` function definitions from `rctOps.cpp`,
  their declarations from `rctOps.h`, the `genCommitmentMask` virtual method
  from the device interface chain (`device.hpp`, `device_default`,
  `device_ledger`), and the `ecdhDecode` unit test that depended on them.
  These Keccak-based helpers were superseded by HKDF-derived amount encryption
  in V3.

- **Ring signature / decoy infrastructure removed from wallet2.** Removed
  `fake_outs_count` parameters from `create_transactions_2`,
  `create_transactions_all`, `create_transactions_single`, and
  `create_transactions_from`. Removed `transfer_selected_rct`'s
  `fake_outputs_count` and `outs` parameters. Deleted `get_output_relatedness`,
  `outs_unique`, `m_print_ring_members`, and `m_rings` bookkeeping. FCMP++
  eliminates ring signatures, making decoy selection and output relatedness
  scoring dead code.

### 🔒 Security

- **`m_combined_shared_secret` changed to `scrubbed_arr<uint8_t, 64>` (Phase 6,
  Gate 3).** Replaced `std::vector<uint8_t>` with `tools::scrubbed_arr<uint8_t, 64>`
  in both `transfer_details` and `exported_transfer_details`. This ensures
  zero-on-drop semantics consistent with `m_y` and `m_mask`. A boolean
  `m_combined_shared_secret_set` flag replaces size-based emptiness checks. All
  serialization (epee and Boost) updated with safe vector round-trip conversion.

- **WalletState invariant enforcement (Phase 6, Gate 5b).** Added
  `check_invariants()` to `WalletState` verifying 8 structural properties
  (balance consistency, spendable/spent partition, key image correspondence, etc.).
  `debug_assert!` fires after every mutation in debug builds. Property test (Gate 5c)
  exercises random operation sequences against invariant checks.

### ✨ Added

- **PQC output round-trip property tests (Phase 6, Gate 1).** `prop_round_trip.rs`
  exercises `construct_output` → `scan_output_recover` → `derive_proof_secrets` →
  `compute_key_image` with random keys and amounts via `proptest`. Asserts
  determinism (same inputs → identical outputs) and non-zero secrets (`ho`, `y`,
  `z`, `k_amount`, `key_image`). Includes boundary cases for `amount=0` and
  `amount=u64::MAX`. Runs with `--release` in CI.

- **Wallet cache AEAD tests (Phase 6, Gate 2).** `cache_crypto.rs` covers
  encrypt/decrypt round-trip, version mismatch detection (returns -1 before AEAD
  decryption attempt), wrong-key auth failure, empty ciphertext, and truncated
  ciphertext. Sub-case A2 proves version check ordering by corrupting ciphertext
  and asserting version mismatch fires first.

- **100-iteration signing round-trip stress test (Phase 6, Gate 4).**
  `test_gate4_signing_round_trip_100` in `proof_round_trip.rs` runs full outbound
  prove+verify cycle 100 times with unique randomness per iteration.

- **`unmark_spent` unit tests (Phase 6, Gate 5a).** Five tests covering: reversal
  to spendable pool, unknown key image noop, idempotent on already-unspent, partial
  set behavior, and invariant preservation after unmark.

- **Random-sequence invariant property test (Phase 6, Gate 5c).** `proptest` drives
  random sequences of `AddOutputs`, `MarkSpent`, `UnmarkSpent`, `Freeze`, `Thaw`,
  and `Reorg` operations, asserting `check_invariants()` after each step.

- **Sync bookkeeping tests (Phase 6, Gate 7).** Mock-block-driven tests for
  `WalletState` mutations: progress monotonicity, spend detection, reorg state
  restoration, empty block height advancement, and spend/unmark round-trip.
  Explicitly documented as bookkeeping-only (not integration against a real daemon).

- **CI grep gates (Phase 6).** Seven blocking grep gates in `build.yml`:
  `shekyl_y` absence, `derivation_to_y_scalar` absence, legacy RCT type absence,
  v1/v2 tx version branch absence, `HASH_KEY_TXPROOF` absence,
  `combined_shared_secret` confinement to wallet boundary,
  `ecdhEncode`/`ecdhDecode` confinement to Ledger gate. All run without
  `continue-on-error`.

- **FFI header documentation (Phase 6).** `shekyl_ffi.h` now has Doxygen-style
  file-level documentation covering the memory model, secret handling conventions,
  and error reporting contract.

### 🗑️ Removed

- **`derivation_to_y_scalar` deleted (Phase 6).** Removed the function body from
  `crypto.cpp`, declarations from `crypto.h`, and all call sites in
  `derive_public_key` and `derive_subaddress_public_key`. The `"shekyl_y"` salt
  no longer appears in the binary.

- **Test stubs 9-10 deleted (Phase 6).** Removed `#[ignore]` placeholder tests
  `test_09_watch_only_outbound_proof_error` and
  `test_10_restored_wallet_outbound_proof_error` from `proof_round_trip.rs`.
  Future implementations tracked in `WALLET_STATE_MIGRATION.md`.

- **Dead v1/v2 transaction branches in consensus (Phase 5).**
  `check_tx_outputs` now rejects `tx.version < 3` instead of `< 2`.
  Removed redundant `if (tx.version >= 2)` zero-amount guard (now
  unconditional). Tightened coinbase version check from `>= 2` to `>= 3`.
  Removed dead `tx.version < 3` early return in `check_commitment_mask_valid`.
  Commitment mask checks are now unconditional (version is always >= 3).

- **Dead legacy code excision (Phase 6 completion).**
  Deleted `decodeRctSimple` and its overload from `rctSigs.cpp/.h`.
  Deleted `tools::decodeRct` wrapper and all callers in `wallet2.cpp`.
  Deleted `generate_output_ephemeral_keys`
  declaration from `cryptonote_tx_utils.h`. Deleted `tx_proof.cpp` unit test
  (referenced removed `crypto::generate_tx_proof_v1`). Deleted
  `is_out_to_acc.h` performance test and its registrations.

- **`generate_key_image_helper` / `generate_key_image_helper_precomp` fully
  removed.** Migrated remaining production callers in `wallet2.cpp`
  (`export_key_images`, two `import_outputs` overloads) to the v3 HKDF path
  via `shekyl_derive_proof_secrets` FFI. Replaced dead `else` branch in
  `cryptonote_tx_utils.cpp::construct_tx_with_tx_key` with a hard error.
  Replaced `scan_output`'s `generate_key_image_helper_precomp` call with a
  v3-only assertion (function is dead for v3 scanning). Deleted both function
  definitions from `cryptonote_format_utils.cpp/.h`, the `compute_key_image`
  virtual method from `device.hpp` and its Trezor override in
  `device_trezor.hpp/.cpp`. Updated test callers in `chaingen.cpp` and
  `tx_validation.cpp` to use v3 `sc_add(ho, b)` derivation.

### 🔒 Security (Phase 5 Audit Notes)

- **Consensus hardening: commitment mask validation verified (Phase 5).**
  Audited `check_commitment_mask_valid` in `blockchain.cpp`: confirms
  rejection of identity commitment (mask=0, amount=0), generator-point
  commitment (mask=1, amount=0), and coinbase `zeroCommit(amount)` form
  (mask=1, any amount). Called unconditionally for both miner transactions
  and regular transactions.

- **y=0 defense-in-depth verified (Phase 5).** Confirmed construction-time
  `assert!(y != [0u8; 32])` and `assert!(ho != [0u8; 32])` in
  `derive_output_secrets` (Rust, release-mode assert). Both sender
  (`construct_output`) and receiver (`scan_output_recover`) hit the same
  assert. Documented in `POST_QUANTUM_CRYPTOGRAPHY.md` with full defense
  stack analysis.

### ✨ Added

- **GUI wallet native-sign activation (Phase 4a).** Added `native-sign`
  feature to the GUI wallet's `shekyl-wallet-rpc` dependency. The transfer
  path is now: C++ prepare → Rust sign → C++ finalize.

- **Scanner keys FFI export (Phase 4b).** Added `wallet2_ffi_get_scanner_keys`
  to the wallet2 FFI layer, returning all keys needed by the Rust scanner
  (spend/view secrets, X25519 SK, ML-KEM DK) as JSON. Added `get_scanner_keys`
  wrapper method to `Wallet2`.

- **Hybrid PQC KEM scanner (Phase 3a).** `shekyl-scanner` now scans blocks
  using the V3 two-component key derivation: X25519 + ML-KEM-768 hybrid
  KEM. The `InternalScanner::scan_transaction` pipeline parses
  `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (0x06), applies X25519 view-tag
  pre-filtering (~99.6% rejection), and calls `scan_output_recover` for
  full KEM decapsulation, HKDF secret derivation, amount decryption, and
  B' recovery. Key images are computed natively in Rust via
  `hash_to_point` + `compute_output_key_image`. Legacy ECDH scan path
  removed.

- **`RecoveredWalletOutput` struct.** New scan result type carrying all
  KEM-derived secrets (`ho`, `y`, `z`, `k_amount`, `combined_shared_secret`),
  the computed `key_image`, and decrypted `amount` alongside the base
  `WalletOutput`. Implements `ZeroizeOnDrop` — secrets are wiped when the
  struct leaves scope.

- **`TransferDetails` PQC fields and `eligible_height`.** Extended with
  `ho`, `y`, `z`, `k_amount`, `combined_shared_secret` (all `Zeroizing`)
  and `eligible_height: u64` (`block_height + SPENDABLE_AGE`). Outputs
  below `eligible_height` are immature (no curve-tree path) and cannot be
  spent. `is_spendable()` enforces this gate.

- **`WalletState` KEM-aware processing.** `process_scanned_outputs` now
  populates all PQC fields from `RecoveredWalletOutput`, sets key images at
  scan time, and performs duplicate output key detection (burning bug).
  `spendable_outputs` filters on `eligible_height`.

- **`unmark_spent` for rollback.** `WalletState::unmark_spent` reverses
  spent marks on outputs whose signing round succeeded but whose finalize
  step failed (daemon rejection, relay timeout). Prevents phantom-spent
  balance loss.

- **Background sync loop (Phase 3b).** `shekyl-scanner::sync::run_sync_loop`
  polls the daemon RPC for new blocks, feeds them through the hybrid KEM
  scanner, detects spent outputs via key-image matching against block inputs,
  and emits `SyncProgress` events after each block. Cancellation-safe via
  `tokio_util::CancellationToken`. Configurable flush interval: every 100
  blocks on desktop, every block on mobile (OS can kill without warning).

- **`BalanceSummary` uses `eligible_height`.** Timelock categorization now
  reads `td.eligible_height` directly instead of recomputing from
  `block_height + DEFAULT_LOCK_WINDOW`.

- **`ViewPair` extended with KEM keys.** Added `x25519_sk` and `ml_kem_dk`
  fields to `ViewPair` for hybrid KEM decapsulation. The scanner requires
  both the X25519 secret and ML-KEM decapsulation key.

### 🐛 Fixed

- **Stale `fake_outs_count` arguments in wallet transaction creation.**
  Removed vestigial `0` (decoy count) from 9 call sites across
  `wallet2_ffi.cpp`, `wallet_rpc_server.cpp`, and `wallet/api/wallet.cpp`
  that no longer match `create_transactions_2`, `create_transactions_all`,
  and `create_transactions_single` signatures after ring removal.

- **Test compilation: `wallet_tools.cpp` and `transactions_flow_test.cpp`.**
  Replaced removed `td.is_rct()` calls with `true` (all Shekyl outputs are
  RCT), changed `tools::wallet2::get_outs_entry` to the local typedef from
  `chaingen.h`, and removed stale `mix_in_factor` argument in the functional
  test.

- **PQC doc label error.** Fixed incorrect HKDF label reference in
  `POST_QUANTUM_CRYPTOGRAPHY.md`: the output-key check uses `ho` with label
  `shekyl-output-x`, not `shekyl-pqc-output` (which is the ML-DSA seed
  label).

- **Test compilation: `json_serialization.cpp` aggregate init.**
  Replaced brace-enclosed initializer list for `tx_source_entry` with explicit
  member assignment. The struct is no longer an aggregate (user-declared
  destructor for `ho` wiping) and the old initializer also referenced a removed
  `real_out_additional_tx_keys` field.

- **Multi-output scan bug.** Removed erroneous `break` in
  `InternalScanner::scan_transaction` that exited the output iteration loop
  after finding the first matching output. Transactions with multiple wallet
  outputs (e.g., payment + change) now detect all of them.

- **Reorg handling in `handle_reorg`.** Rewrote `WalletState::handle_reorg`
  to use `(height, hash)` pairs instead of treating height as a direct vector
  index. Correctly handles non-genesis-aligned and sparse sync histories.
  `synced_height` is now derived from the last remaining block entry.

- **Reorg detection in sync loop.** `run_sync_loop` now compares each incoming
  block's `header.previous` hash against the wallet's stored hash for the
  prior height. On mismatch, walks backwards to find the fork point and calls
  `handle_reorg` before resuming.

- **Block fetch retry with backoff.** Per-block `get_scannable_block_by_number`
  calls now retry up to 5 times with exponential backoff (500ms initial,
  capped at 30s) instead of immediately aborting the sync loop on transient
  failures.

- **Secure memory wiping.** `TransferDetails` now implements both `Zeroize`
  (covering all fields including `key`, `commitment`, and `fcmp_precomputed_path`)
  and `Drop` (calls `zeroize()` on drop). `WalletState` implements `Drop` to
  wipe all transfers, key images, pub keys, and block hashes. Removed unsafe
  `#[derive(Clone, Debug)]` from `TransferDetails`; `Debug` is now manual and
  redacts secret fields.

- **Misleading payment ID comment.** Corrected comment in `scan.rs` that
  incorrectly described ECDH-based XOR decryption for payment IDs; V3
  transactions do not use encrypted payment IDs.

- **Always-true pattern in sync loop.** Removed `if let Some(tx_hashes) =
  Some(&scannable.block.transactions)` which was a no-op guard. Block
  transactions are now iterated directly.

### 🔄 Changed

- **`EncryptedAmount` wire format fix.** The Rust `EncryptedAmount` struct
  (in `shekyl-oxide::fcmp`) now correctly includes both `amount: [u8; 8]`
  and `amount_tag: u8`, matching the C++ 9-byte wire format. Previously
  only the 8-byte amount was read, causing silent data misalignment.

- **`Scanner::new` signature.** Now requires the wallet's `spend_secret`
  (`Zeroizing<[u8; 32]>`) for native key image computation at scan time.
  Both `Scanner::new` and `GuaranteedScanner::new` updated.

- **Deterministic KEM encapsulation from `tx_key_secret`.** `construct_output`
  now derives X25519 ephemeral keys and ML-KEM ciphertexts deterministically
  via HKDF-SHA-512 (`derive_kem_seed`), eliminating the need to cache
  per-output shared secrets. The sender can re-derive `combined_ss` at proof
  time from `tx_key_secret` and public data.

- **Proof pipeline helpers in `shekyl-crypto-pq`.** Seven new functions:
  `rederive_combined_ss`, `derive_proof_secrets`, `derive_output_key`,
  `recover_recipient_spend_pubkey`, `decrypt_amount`,
  `compute_output_key_image`, and `compute_output_key_image_from_ho`. These
  support the V3 tx_proof / reserve_proof / key-image protocols. The narrow
  `ProofSecrets(ho, y, z, k_amount)` projection ensures `combined_ss` never
  crosses the FFI boundary.

- **`ProofSecrets` widened to include `z`.** The Pedersen commitment mask is
  now part of the proof secrets projection, enabling direct `C = z*G +
  amount*H` verification in TX proofs. `derive_proof_secrets` passes `z`
  through instead of discarding it.

- **`shekyl-proofs` crate: full Phase 1a implementation.** Three modules:
  - `dleq.rs`: Two-base Schnorr DLEQ proof with domain separator
    `shekyl-reserve-proof-dleq-v1` and full base binding in the challenge
    hash (`G`, `Hp(O)`, `R1`, `R2`, `P`, `I`, `msg`). 6 unit tests.
  - `tx_proof.rs`: Outbound (101+128N bytes) and inbound (69+128N bytes)
    proof generation and verification. Domain-separated Schnorr signatures
    (`shekyl-outbound-tx-proof-v1`, `shekyl-inbound-tx-proof-v1`). Per-output
    `ho`, `y`, `z`, `k_amount` with algebraic output key and commitment checks.
  - `reserve_proof.rs`: Reserve proof (69+192N bytes) with per-output DLEQ
    key image binding. `enc_amount` sourced from blockchain, not from proof.
  - Version assertion (v1) before any cryptographic work. 4-byte output_count
    (u32 LE) supporting up to 2³²−1 outputs per proof.
  - 10-point round-trip test skeleton (exit criterion for Phase 5, `#[ignore]`).

- **FCMP_PLUS_PLUS.md section 21: Wallet Proof Structure.** Genesis-native
  proof design rationale. Documents the Schnorr/KEM decomposition, reserve
  proof DLEQ requirement, HKDF binding argument for z-omission in reserve
  proofs, and the `enc_amount`-from-chain invariant.

- **Phase 1b FFI exports (PR-wallet).** New exports in `shekyl_ffi.h`:
  - `shekyl_scan_and_recover`: Merged scan + key image in one call. All
    secret outputs write directly into `transfer_details` fields (no
    intermediate scratch buffers). `persist_combined_ss` flag controls
    whether `combined_ss` is returned or wiped internally (hot vs cold).
  - `shekyl_compute_output_key_image` / `_from_ho`: Key image computation
    for the 2 remaining sites (stake claim, tx_source_entry).
  - `shekyl_sign_fcmp_transaction`: Collapsed signing. C++ passes wallet
    master spend key `b` + per-input `{combined_ss, output_index, ...}`.
    Rust derives `x = ho + b` and `y` internally via HKDF. C++ never
    touches `x`.
  - `shekyl_derive_proof_secrets`: Helper writing `ho`, `y`, `z`,
    `k_amount` directly to caller-provided destination addresses.
  - `shekyl_encrypt_wallet_cache` / `shekyl_decrypt_wallet_cache`: AEAD
    encryption with AAD binding on `cache_format_version`. Distinct error
    codes for version mismatch (-1), auth failure (-2), and format error (-3).
  - 6 proof FFI exports: `shekyl_generate_tx_proof_outbound`,
    `shekyl_verify_tx_proof_outbound`, `shekyl_generate_tx_proof_inbound`,
    `shekyl_verify_tx_proof_inbound`, `shekyl_generate_reserve_proof`,
    `shekyl_verify_reserve_proof`. Signatures stabilized; wiring to
    `shekyl-proofs` internals deferred to Phase 2e.

- **`shekyl-chacha` AEAD extension.** Added `chacha20poly1305` (v0.10)
  support: `encrypt_with_aad` and `decrypt_with_aad` wrapping
  XChaCha20-Poly1305. No hand-rolled AEAD — nonce handling, constant-time
  tag comparison, and AD framing delegated to audited crate. 6 new tests.

- **`RecoveredOutput` now includes `combined_ss`.** The scan result carries
  the 64-byte combined shared secret so the merged scan FFI can optionally
  persist it without re-doing KEM decapsulation. Wiped by `ZeroizeOnDrop`.

- **ML-KEM shared secret `Zeroizing` wrap (W5 fix).** All 4 production
  sites where `ml_ss.into_bytes()` produces a bare stack-local now wrap
  the result in `Zeroizing<[u8; 32]>`, ensuring the ML-KEM shared secret
  bytes are zeroed on scope exit. Closes the W5 correlation leak.

- **Fixed stale `shekyl_construct_output` C header.** Added missing
  `tx_key_secret` parameter to match the Rust implementation.

- **KEM derivation KAT vectors.** `docs/test_vectors/KEM_DERIVE_V1_KAT.json`
  with 8 pinned vectors for `derive_kem_seed`. Serves as tripwire against
  silent behavior changes from `fips203` or `curve25519-dalek` upgrades.

- **`fips203` exact version pin.** Pinned to `=0.4.3` with audit comment
  explaining the `DummyRng::fill_bytes = unimplemented!()` risk.

- **Fuzz target for `derive_output_key`.** Exercises `derive_output_key` and
  `recover_recipient_spend_pubkey` round-trip with fuzzer-supplied inputs.

- **Ledger V3 hard gate.** `device_ledger.cpp` now has a `#error` that fires
  when `WITH_DEVICE_LEDGER` is defined, preventing silently broken builds.
  The Ledger APDU protocol has not been updated for V3 two-component keys.

- **Fuzz target for malformed KEM ciphertexts on scan.** New
  `fuzz_scan_malformed_ct` exercises corrupted, truncated, and random ML-KEM
  ciphertexts through `scan_output_recover` with a valid wallet KEM secret.
  Validates ML-KEM implicit rejection + downstream algebraic checks fail
  closed without panics or timing leaks.

### 📚 Documentation

- **Security properties of the derivation** section in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`. Documents the y==0 defense-in-depth
  stack (construction assert + probabilistic impossibility + fuzz coverage),
  explains why a wire-level y==0 check is impossible, documents malformed
  KEM ciphertext handling through ML-KEM implicit rejection, view-tag
  pre-filter behavior on adversarial match grinding, and the wallet cache
  version gate requirement for PR-wallet.

- **Tightened malformed KEM ciphertext framing.** Reframed `amount_tag` as
  a ~99.6% cheap pre-filter (performance optimization), not a security gate.
  Commitment algebraic check `C == z*G + amount*H` is the soundness barrier.
  Documented structural independence of the two algebraic checks (different
  HKDF labels, different scalar families).

- **Wallet cache version gate hardened.** Added mandatory AAD binding
  (include `cache_format_version` in XChaCha20-Poly1305 AAD to prevent
  version-confusion attacks) and hard no-migration policy (delete and resync
  from seed, never in-place migration).

### 🗑️ Removed

- **`ecdhTuple` / `ecdhEncode` / `ecdhDecode` removal.** Deleted the
  Monero-era ECDH amount-masking struct and encode/decode functions from
  `rctTypes.h`, `rctOps.h/.cpp`, `device.hpp`, `device_default.hpp/.cpp`,
  `device_ledger.hpp/.cpp`, and the Trezor protocol files. The
  `enc_amount_to_ecdh_compat` shim is deleted.

- **`check_tx_key_helper` / `is_out_to_acc` deletion.** Both overloads of
  `wallet2::check_tx_key_helper` and `wallet2::is_out_to_acc` removed.
  These used `derive_public_key` (Keccak Category 1) and the old ecdhDecode
  path. Replaced by KEM-based proof FFI round-trip in `check_tx_key`.

- **`crypto::generate_tx_proof` / `generate_tx_proof_v1` / `check_tx_proof`
  deletion.** Monero-era DH-based Schnorr proof functions removed from
  `crypto.cpp`, `crypto.h`, `device_default.cpp`, `device_ledger.cpp`,
  `device.hpp`, and derived device headers. `HASH_KEY_TXPROOF_V2` removed
  from `cryptonote_config.h`.

- **`ecdh.rs` module stub cleanup.** Removed orphaned `mod ecdh` declaration
  and associated test functions from `shekyl-tx-builder` (module file was
  previously deleted, declaration left behind).

- **V3-from-genesis Boost serialization purge (`wallet2.h`).** Deleted all
  `if (ver < N)` migration branches from Boost `serialize` functions for
  `transfer_details`, `unconfirmed_transfer_details`, `confirmed_transfer_details`,
  `payment_details`, `address_book_row`, `unsigned_tx_set`, `signed_tx_set`,
  `tx_construction_data`, and `pending_tx`. Deleted the `initialize_transfer_details`
  helper (both saving and loading overloads). Reset all `BOOST_CLASS_VERSION`
  macros to 1 (genesis version). Added `assert(ver == 1)` guards. Epee cache
  envelope `if (version < N)` branches also removed, replaced with
  `assert(version == 2)`. Staking fields (`m_staked`, `m_stake_tier`,
  `m_stake_lock_until`, `m_last_claimed_height`) and new Phase 2b field
  (`m_k_amount`) added to the `transfer_details` Boost serializer. Legacy
  `m_rct` field no longer serialized (previously removed from struct).

### 🔄 Changed

- **Phase 2e: Proof functions collapsed to Rust FFI (PR-wallet).** All six
  wallet proof functions (`get_tx_proof`, `check_tx_proof`, `get_reserve_proof`,
  `check_reserve_proof`) now delegate to the `shekyl-proofs` Rust crate via
  the FFI bridge. `check_tx_key` also uses the FFI round-trip (generate outbound
  proof + verify with on-chain data). The intermediate C++ helpers
  `check_tx_key_helper` (both overloads) and `is_out_to_acc` have been deleted.
  New `gather_on_chain_proof_data` helper extracts output keys, commitments,
  encrypted amounts, and KEM ciphertexts from transactions for proof
  verification. Reserve proof wire format now includes output locators
  (txid + index_in_tx) as a header so the verifier can independently fetch
  on-chain data from the daemon.

- **Phase 2f: Category 1 Keccak deletions (PR-wallet).** Deleted Monero-era
  DH-based proof functions from the crypto layer: `crypto::generate_tx_proof`,
  `crypto::generate_tx_proof_v1`, `crypto::check_tx_proof`, along with their
  device implementations (device_default, device_ledger) and virtual interface
  declarations. Removed `HASH_KEY_TXPROOF_V2` from `cryptonote_config.h`.
  Removed orphaned `ecdh.rs` module declaration and tests from
  `shekyl-tx-builder`. Remaining Category 1 functions (`derive_public_key`,
  `derivation_to_scalar`, `derive_subaddress_public_key`, `decodeRctSimple`)
  still have live callers in scan/sign paths and are deferred to Phase 3
  migration. `ecdhHash` and `genCommitmentMask` have been removed.

- **Phase 2d: Collapsed signing via `shekyl_sign_fcmp_transaction` (PR-wallet).**
  The CLI wallet's `transfer_selected_rct` now calls the Rust collapsed
  signing FFI instead of C++ `genRctFcmpPlusPlus`. C++ builds JSON arrays
  of `FcmpSignInput` (per-input `combined_ss`, `output_index`, tree layers)
  and `OutputInfo` (per-output `commitment_mask`, `enc_amount`), then
  unpacks the returned `SignedProofs` (BP+ blob, FCMP++ proof, pseudo-outs,
  commitments, enc_amounts) into `tx.rct_signatures`. Rust owns all
  witness assembly — C++ never touches the ephemeral spend secret `x`.
  `genRctFcmpPlusPlus` is deprecated (retained only for `chaingen.cpp`
  test infrastructure).

- **Rust `sign_transaction` updated for v3 HKDF semantics (PR-wallet).**
  `OutputInfo` now carries `commitment_mask: [u8; 32]` and `enc_amount:
  [u8; 9]` (pre-derived by `construct_output`), replacing the old
  `amount_key` field. `SignedProofs.enc_amounts` widened from 8 to 9 bytes.
  The signing pipeline uses pre-derived HKDF masks for BP+ instead of
  generating random ones, and uses pre-encrypted amounts instead of
  Keccak-based ECDH encoding.

- **`wallet2_ffi.cpp` `enc_amounts` field name fix.** The native-sign
  finalize path now reads `enc_amounts` from Rust `SignedProofs` JSON
  (was incorrectly reading `ecdh_amounts`).

- **`enc_amounts` field comment updated in `rctTypes.h`.** Clarifies that
  byte [8] is the HKDF-derived `amount_tag` AAD, documents the Rust scanner
  validation behavior (reject on mismatch), and removes the stale
  `RESERVED_AMOUNT_TAG_PLACEHOLDER` reference.

- **Comprehensive CLI User Guide (`docs/USER_GUIDE.md`).** Covers all shipped
  executables, daemon operation (flags, config file, console commands), wallet
  CLI (create, restore, send, receive, proofs), staking (tiers, unstake,
  claim, accrual rules), mining, PQC multisig (file-based workflow, size
  table), anonymity networks (Tor/I2P), wallet RPC, blockchain utilities,
  security/backup, and troubleshooting. Mirrors the GUI wallet guide structure
  for easy cross-referencing.

- **C++/Rust cross-validation test for `total_weighted_stake`.** New test in
  `staking.cpp` constructs the same staker set via both the C++ 128-bit cache
  accumulation and the Rust FFI, then asserts byte-equality of the results.
  Prevents spec/impl drift regression.

- **`u128` saturation test.** Demonstrates that the u128 weighted stake does NOT
  saturate where u64 would (100M stakers at 100 SKL, tier 2), and verifies
  reward computation remains correct with the large denominator.

- **LMDB write atomicity audit.** Comprehensive audit of all `BlockchainLMDB`
  write paths (block connect, block pop, txpool, alt blocks, staking, FCMP++
  curve tree). Documented in `docs/LMDB_WRITE_ATOMICITY_AUDIT.md`. Found and
  fixed a missing `lock.commit()` in `get_relayable_transactions` (Dandelion++
  timestamp rollback bug) and added a defensive `db_wtxn_guard` around the
  staker accrual reversal in `pop_block_from_blockchain`.

- **LMDB schema reference (`docs/LMDB_SCHEMA.md`).** Complete documentation of
  all 28 sub-databases: LMDB names, open flags, custom comparators, key/value
  byte layouts with struct field offsets, read/write access patterns, and hard
  fork version introduction. Standalone audit value and prerequisite for the
  eventual heed migration.

- **Vendored dependency tracking (`docs/VENDORED_DEPENDENCIES.md`).** Documents
  the vendored LMDB version (0.9.70, based on OpenLDAP `mdb.master` branch),
  applied upstream patches (ITS#9385, ITS#9496, ITS#9500, etc.), CVE review
  (CVE-2026-22185 does not affect us), and the `mdb.master` vs `mdb.master3`
  branch distinction relevant to future heed migration.

- **V4 design notes (`docs/V4_DESIGN_NOTES.md`).** Records the heed LMDB
  migration deferral with detailed reasoning (shared-write risk, schema drift,
  map resize race conditions) and the recommended approach for V4 (single
  Rust-owned Env, no split write ownership, full BlockchainLMDB unit cutover).

- **Additional C++ conservation-invariant tests.** Six new tests in
  `tests/unit_tests/staking.cpp`: weighted denominator >= raw sum invariant,
  tier-0 weight equality, higher-tier strict inequality, zero-staker burn path,
  single-staker full capture, dust staker conservation, multi-block claim range
  conservation, and MAX_CLAIM_RANGE boundary validation.

- **`shekyl-wallet-core` crate.** New Rust crate providing transaction builder
  plans for stake, unstake, and claim operations. Includes `ClaimTxBuilder` for
  constructing claim transaction plans with automatic MAX_CLAIM_RANGE splitting,
  and `ClaimAndUnstakePlan` for the two-step drain-then-unstake workflow.

- **Coin selection module (`shekyl-scanner/coin_select.rs`).** Min-relatedness
  output selection algorithm that prefers combining outputs with fewer shared
  metadata fingerprints (tx hash, block height, subaddress, tier) for improved
  on-chain privacy. Supports dust separation and configurable selection criteria.

- **Output freezing and coin control.** `WalletState` now supports freeze/thaw
  of individual outputs by index or key image, with frozen outputs excluded from
  spendable candidate lists. New `spendable_outputs()` method with optional
  account, subaddress, and minimum amount filters.

- **Staker pool tracking in Rust (`shekyl-scanner/staker_pool.rs`).** Wallet-side
  `StakerPoolState` mirrors per-block accrual records from the daemon, enabling
  local reward estimation without RPC round-trips. Supports reorg handling and
  conservation invariant checking.

- **Claim watermark tracking.** `TransferDetails` now carries `last_claimed_height`
  for monotonic claim watermark management. `WalletState` exposes
  `update_claim_watermark()`, `claimable_outputs()`, and
  `claimable_rewards_summary()` methods. New `ClaimableInfo` struct provides
  per-output claim state including accrual frozen status.

- **New RPC methods.** `get_claimable_stakes`, `get_unstakeable_outputs`,
  `freeze`, and `thaw` added to the Rust scanner-backed RPC handler. All four
  are routed through the Rust scanner when `rust-scanner` feature is active.

- **GUI wallet staking bridge.** `wallet_bridge.rs` extended with
  `get_scanner_claimable_stakes`, `get_scanner_unstakeable_outputs`,
  `scanner_freeze`, and `scanner_thaw` for Tauri frontend integration.

- **Staking transaction types in `shekyl-oxide`.** `Input::StakeClaim` variant
  (binary tag 0x03) and `Output::staking: Option<StakingMeta>` (binary tag 0x04)
  added with full binary serialization/deserialization. `StakingMeta` carries
  the `lock_tier` field (`lock_until` is computed dynamically).

- **Property-based staking tests.** 11 new property tests in `shekyl-staking`:
  conservation across uniform/mixed/stress scenarios, proportionality, floor
  division safety, weight function validation, multi-block accumulation bounds,
  and adversarial edge cases.

- **`shekyl-chacha` crate.** New Rust crate providing XChaCha20 (192-bit nonce)
  stream cipher for wallet and cache file encryption. Wraps the NCC-audited
  RustCrypto `chacha20` crate. Exported via FFI as `xchacha20()`, replacing
  the C implementation in `chacha.c`.

- **KEM-derived output secrets (`OutputSecrets`).** New Rust infrastructure in
  `shekyl-crypto-pq/src/derivation.rs` derives per-output secrets (`ho`, `y`,
  `z`, `k_amount`, `view_tag_combined`, `amount_tag`, `ml_dsa_seed`) from the
  combined X25519 + ML-KEM shared secret via HKDF-SHA-512 with distinct info
  labels. Includes `derive_view_tag_x25519` for fast wallet scan pre-filtering
  without ML-KEM decapsulation. FFI exports: `shekyl_derive_output_secrets`,
  `shekyl_derive_view_tag_x25519`.

- **Cross-language HKDF test vectors.** Python reference implementation
  (`tools/reference/derive_output_secrets.py`) generates locked JSON test
  vectors (`docs/test_vectors/PQC_OUTPUT_SECRETS.json`). Rust unit tests
  validate byte-for-byte against these vectors.

- **Witness header constant.** `SHEKYL_PROVE_WITNESS_HEADER_BYTES = 256`
  defined in both `shekyl_ffi.h` and `shekyl-ffi/src/lib.rs`, replacing all
  magic literal 256 values.

- **Consensus `mask=1` placeholder.** `check_commitment_mask_valid()` wired
  into `check_tx_outputs` for all v3 transactions. Returns accept-all now;
  PR-construct will flip to reject `zeroCommit` form for non-coinbase.

- **HKDF label registry.** `docs/POST_QUANTUM_CRYPTOGRAPHY.md` now documents
  all HKDF salt/info pairs for the per-output derivation stream and the
  separate X25519-only view tag derivation.

- **Unified Rust output construction (`construct_output`).** New
  `shekyl-crypto-pq/src/output.rs` implements `construct_output` (KEM
  encapsulation + HKDF → two-component key `O = ho*G + B + y*T`, Pedersen
  commitment `C = z*G + amount*H`, encrypted amount, view tag, PQC leaf
  hash) and `scan_output_recover` (KEM decapsulation + HKDF → recovered
  spend key `B' = O - ho*G - y*T` for subaddress lookup, plus all per-output
  secrets). FFI exports: `shekyl_construct_output`, `shekyl_scan_output_recover`.

- **PQC signing in Rust (`sign_pqc_auth`).** ML-DSA-65 keypair is derived,
  used, and wiped entirely within Rust. The secret key never crosses the
  FFI boundary. FFI export: `shekyl_sign_pqc_auth`.

- **FCMP++ witness header assembly in Rust.** The 256-byte witness header
  (`[O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]`) is now assembled
  via `shekyl_fcmp_build_witness_header` with a typed `ProveInputFields`
  struct, replacing 8 raw `memcpy` calls in C++.

- **`construct_miner_tx` and `construct_tx_with_tx_key` rewired to Rust.**
  Both v3 output construction paths now call `shekyl_construct_output` per
  output in a unified loop. KEM ciphertexts and PQC leaf hashes are written
  to `tx_extra`. The legacy `derivation_to_y_scalar` path is retired on all
  construction paths.

- **Wallet scanner uses `scan_output_recover`.** `wallet2::process_new_transaction`
  has a v3-specific scanning path that calls `shekyl_scan_output_recover`
  for KEM decapsulation, HKDF derivation, amount recovery, and subaddress
  lookup. Key images are computed as `(ho + b_spend) * Hp(O)`.

- **X25519-derived view tag.** Per-output view tags are now derived from the
  X25519 shared secret only (no ML-KEM needed), enabling fast wallet scan
  pre-filtering. Written during construction, checked first during scanning.

- **`additional_tx_keys` removed for v3.** `need_additional_txkeys` is false
  for `tx.version >= 3`. The `additional_tx_public_keys` field is no longer
  populated or consumed in v3 construction or scanning.

- **Real Pedersen commitments for coinbase (`RCTTypeNull`).** `outPk` and
  `enc_amounts` are now serialized for `RCTTypeNull` transactions.
  `blockchain_db.cpp` uses the on-chain `outPk[i].mask` for v3+ coinbase
  instead of computing `zeroCommit(amount)`.

- **`check_commitment_mask_valid` enforced.** Rejects trivial commitment
  masks (`z = 0` or `z = 1`) for all non-coinbase v3 outputs. Called from
  both `check_tx_outputs` and `prevalidate_miner_transaction`.

- **PQC salt consolidation.** All per-output PQC key derivation now uses the
  unified `OutputSecrets.ml_dsa_seed` from salt B
  (`shekyl-output-derive-v1`). The legacy `HKDF_SALT_PQC_DERIVE` salt A is
  deleted. **Testnet reset required** — invalidates all existing `h_pqc`.

- **Chaingen test infrastructure updated for v3.** `init_output_indices`,
  `fill_tx_sources`, `init_spent_output_indices`, and `construct_fcmp_tx`
  now use `shekyl_scan_output_recover` for HKDF-based output ownership
  detection, mask recovery, and key image computation.

- **`genRctFcmpPlusPlus` uses HKDF commitment masks.** The function now accepts
  pre-computed HKDF `z` scalars (`commitment_masks`) and pre-computed encrypted
  amounts (`enc_amounts_precomputed`) instead of re-deriving them internally via
  Keccak. This fixes a critical mismatch where BP+ proofs used Keccak-derived
  masks while `scan_output` expected HKDF-derived values. The old `amount_keys`
  parameter is removed. **Testnet reset required** — on-chain commitments and
  encrypted amounts are now HKDF-derived, incompatible with prior Keccak format.

- **Stake claim outputs use `shekyl_construct_output`.** The wallet's
  `create_stake_claim_tx` now constructs outputs via the unified Rust HKDF path,
  producing correct output keys, view tags, KEM ciphertexts, leaf hashes, and
  `enc_amounts` with `amount_tag`. BP+ blinding factors remain constrained by
  the `zeroCommit` pseudo-out balance equation (sum to N).

- **Chaingen PQC signing via `shekyl_sign_pqc_auth`.** Core test
  `construct_fcmp_tx` now uses the high-level FFI that derives, signs, and wipes
  the ML-DSA secret key entirely inside Rust. The raw `shekyl_pqc_sign` call
  (which accepted the secret key as a C++ byte pointer) is replaced.

- **`zeroCommit` dead code removed from DB layer.** `blockchain_db.cpp` and
  `db_lmdb.cpp` no longer fall back to `zeroCommit(amount)` for output
  commitments. All outputs (including coinbase) use on-chain `outPk[i].mask`.
  The `pre_rct_outkey` branch in LMDB now throws for `amount != 0` (Shekyl
  has no pre-RCT outputs).

- **RCTTypeNull round-trip serialization test.** New test in
  `tests/unit_tests/serialization.cpp` verifies that `RCTTypeNull` transactions
  with populated `outPk` and `enc_amounts` (8-byte amount + 1-byte `amount_tag`)
  survive binary serialize/deserialize round-trip.

- **libFuzzer harness for `construct_output`.** New fuzz target
  `fuzz_construct_output` in `rust/shekyl-crypto-pq/fuzz/` exercises
  `construct_output` + `scan_output` round-trip with arbitrary spend keys,
  amounts, corrupted `enc_amount`, and wrong `amount_tag`.

- **libFuzzer harness for malformed KEM keys.** New fuzz target
  `fuzz_construct_output_malformed_kem` feeds arbitrary bytes as X25519
  and ML-KEM-768 encapsulation keys to `construct_output`. Exercises
  wrong-length, oversized, and garbage KEM public key inputs to ensure
  the function returns `Err`, never panics.

- **PQC leaf hash known-answer test.** New JSON fixture
  `docs/test_vectors/PQC_LEAF_HASH_KAT.json` (8 vectors) pins the output of
  `derive_pqc_leaf_hash(combined_ss, output_index)`. Rust KAT test validates
  byte-for-byte against the fixture.

- **Coinbase `check_commitment_mask_valid` hardened.** For `RCTTypeNull` (coinbase)
  outputs, the consensus check now rejects commitments that equal
  `zeroCommit(public_amount)` (i.e. `C = G + amount*H`), preventing miners
  from constructing trivial-mask coinbases that leak amount to observers.
  Non-coinbase defense-in-depth checks (identity and G) are retained.

- **Dead Keccak y-scalar fallback removed from wallet scanner.** The
  `else if (tx.vout[o].amount == 0)` and `else if (miner_tx)` branches that
  fell back to `derivation_to_y_scalar` are removed. Shekyl is v3 from genesis;
  all matched outputs must succeed the HKDF scan path. A hard
  `wallet_internal_error` is thrown if `v3_hkdf_scanned` is false, preventing
  silent domain fallback that would produce unspendable outputs.

- **Legacy coinbase construction path removed.** `construct_miner_tx` now
  asserts PQC key presence with a clear error message (`CHECK_AND_ASSERT_MES`)
  before entering the output construction loop, instead of falling back to
  legacy Keccak `derive_public_key` / `derive_view_tag` which would produce
  an invalid (unscannable, missing `outPk`/`enc_amounts`) coinbase. All Shekyl
  addresses carry PQC keys from genesis.

- **Genesis coinbase builder uses `shekyl_construct_output`.**
  `build_genesis_coinbase_from_destinations` now constructs outputs via the
  Rust HKDF path, producing correct HKDF-derived output keys, view tags,
  commitments, encrypted amounts with `amount_tag`, KEM ciphertexts, and
  PQC leaf hashes. The legacy Keccak derivation path is removed.

- **Legacy `additional_tx_public_keys` dead code removed.** The
  `need_additional_txkeys` logic, `additional_tx_public_keys` vector, and
  pre-v3 output derivation loop in `construct_tx_with_tx_key` are deleted.
  V3 replaces per-output additional tx keys with KEM ciphertext (tag 0x06).

### 🔄 Changed

- **`transfer_details::m_mask` type changed.** `rct::key` → `crypto::secret_key`
  for automatic zeroization on drop. All RCT call sites use explicit
  `rct::sk2rct()` / `rct::rct2sk()` conversion. Binary-compatible (same
  32-byte layout).

- **`ecdhInfo` replaced by `enc_amounts`.** The per-output encrypted amount
  format changes from `ecdhTuple` (64 bytes: 32 mask + 32 amount) to
  `std::array<uint8_t, 9>` (8 bytes XOR-encrypted amount + 1 byte amount
  tag). Affects `rctSigBase`, all serialization paths (binary, boost, JSON),
  and transaction construction (`genRctFcmpPlusPlus`, `fill_construct_tx_rct_stub`,
  wallet claim construction).

- **`ecdhEncode` removed.** The ECDH encoding function is deleted from
  `rctOps`, `device.hpp`, and `device_default`. Transaction construction now
  writes `enc_amounts` directly via Rust HKDF-based output construction.
  `ecdhDecode` is retained as a scanner shim until the wallet migrates to
  Rust `scan_output`. `ecdhHash` and `genCommitmentMask` have been fully
  removed from `rctOps`, the device interface chain, and tests.

- **FROST SAL deferred to V4.** Per-output HKDF-derived `y` is incompatible
  with DKG group-shared `y`. FROST SAL section in `docs/PQC_MULTISIG.md`
  marked as deferred with V4 resolution path (Carrot-style address scheme).

### 🐛 Fixed

- **`sc_check()` signed left-shift undefined behavior.** `signum(...) << k` on
  `int64_t` in `crypto-ops.c` is UB when the result is negative. Introduced
  `signed_lshift()` helper that uses multiplication on non-GCC compilers.
  Ported from monero@c5be4dd.

- **`wallet2::verify_password()` logic inversion.** Background wallet detection
  used `HasParseError() && IsObject()` instead of `!HasParseError() && IsObject()`,
  causing background wallets to fail password verification. Added the missing `!`.
  Ported from monero@b19cd82.

- **HTTP digest auth missing client nonce (`cnonce`).** The epee HTTP client sent
  an empty `cnonce` with `qop=auth`, weakening the digest exchange against replay
  attacks. Now generates a random 16-byte cnonce via `RAND_bytes` and includes it
  in the response hash and Authorization header. Ported from monero@3d6b9fb.

- **Critical: SAL `y` / commitment mask `z` conflation in FCMP++ prover.**
  `wallet2.cpp` passed `td.m_mask` (Pedersen commitment mask) as `spend_key_y`
  to the FCMP++ prover, but SAL requires `y` such that `O = xG + yT`. Since
  legacy outputs had `y = 0` and `z != 0`, `OpenedInputTuple::open` always
  failed. Fixed by migrating to two-component output keys (`O = xG + yT`)
  where `y = Hs_y(derivation || i)`, and passing `z` as a separate
  `commitment_mask` field. Affects every spend on the chain — this was the
  root cause of all FCMP++ proof generation failures.

- **Coinbase commitment mask in test harness.** `fill_tx_sources` in
  `chaingen.cpp` set `ts.mask = rct::zero()` for coinbase, but
  `zeroCommit(amount) = G + amount*H` has mask = scalar 1. Fixed to
  `rct::identity()`.

- **Critical: u64 saturation in `total_weighted_stake` (Bug 7).** The in-memory
  cache and LMDB `staker_accrual_record` used `uint64_t` for the tier-weighted
  stake denominator. With 12-decimal atomic units and tier multipliers > 1.0,
  this saturates at ~18.4M SHEKYL of weighted stake — well below moderate
  adoption. Reward computation collapses to a meaningless ceiling once saturated.
  Fixed by widening to u128 end-to-end: in-memory cache uses lo/hi u64 pairs
  with proper carry arithmetic, LMDB record gains `total_weighted_stake_hi`
  field (32→40 bytes), FFI `shekyl_calc_per_block_staker_reward` accepts lo/hi
  parameters, and Rust `AccrualRecord`/`StakeRegistry::total_weighted_stake()`
  return u128.

- **Critical: back-dating exploit on first claim (Bug 3).** `check_stake_claim_input`
  only enforced `from_height == watermark` when watermark > 0. For the first
  claim (no watermark), `from_height` was unconstrained. An attacker could stake
  at block N, then submit a claim with `from_height = 0`, walking 10,000
  historical blocks and collecting rewards against denominators that never
  included the attacker's output. Fixed by looking up the staked output's
  creation height and requiring `from_height >= creation_height` when no
  watermark exists.

- **Critical: inter-tx pool sufficiency race within a block (Bug 4).** The per-tx
  pool balance check in `check_tx_inputs` reads the pre-block pool balance, so
  five claim txs each claiming 1000 against a pool of 3000 all individually pass.
  The silent-skip path in `add_transaction_data` then lets over-claimed txs
  through without decrementing the pool. Fixed with two changes: a block-level
  aggregate pool check in `handle_block_to_main_chain` that sums all claim
  amounts across ALL txs and rejects the block if the total exceeds the pool,
  plus converting the silent-skip path in `add_transaction_data` to a hard throw
  (dead code if validation is correct, fatal if not).

- **Reorg watermark restoration loses data (Bug 5).** `remove_transaction` used
  `from_height == 0` as the signal for "first claim, remove watermark." But
  `from_height` for a first claim is typically the creation height (non-zero).
  Fixed by looking up the staked output's creation height to distinguish first
  claims from subsequent claims.

- **Reorg pool reversal direction wrong for no-staker blocks (Bug 6).**
  `pop_block_from_blockchain` unconditionally subtracted accrued inflow from
  `pool_balance`, but for no-staker blocks the inflow was burned (not added to
  pool). Popping such a block caused a spurious pool underflow. Fixed by reading
  the accrual record's `total_weighted_stake`: if zero, subtract from
  `total_burned` instead of `pool_balance`.

- **Empty-staker-set accrual audit trail.** The `actually_destroyed` field in
  the persisted accrual record did not reflect the no-staker burn because the
  record was written before the burn decision. Fixed by moving `add_staker_accrual`
  to after the no-staker burn path, so the record captures the full
  `actually_destroyed` value.

- **Dandelion++ relay timestamp rollback.** `get_relayable_transactions` in
  `tx_pool.cpp` was missing `lock.commit()`, causing all stem/forward timestamp
  updates to be silently rolled back by the `LockedTXN` destructor. Transactions
  in Dandelion++ stem/forward states could be re-relayed with stale timing data,
  degrading transaction-origin privacy. Fixed by adding the missing commit.

- **Staker accrual reversal without write transaction guard.** The staker pool
  balance and burn total reversal in `pop_block_from_blockchain` relied on the
  caller's batch context for a write transaction but had no defensive guard.
  While all current production callers maintain a batch, a future caller without
  one would crash or produce undefined behavior. Fixed by wrapping the reversal
  block in `db_wtxn_guard`.

- **Critical: weighted denominator bug in staker reward accrual.** The per-block
  `total_weighted_stake` was computed from raw staked amounts instead of
  tier-weighted amounts, causing proportional over-distribution (up to +100% when
  all stakers use the Long tier). Fixed by introducing separate caches for raw
  and tier-weighted stake amounts in `blockchain.h`/`blockchain.cpp`.

- **Claim timing: lock conflated with claimability.** `check_stake_claim_input`
  incorrectly rejected claims when `lock_until > current_height`, making rewards
  unclaimable during the lock period. Fixed by removing the lock-based rejection
  and adding `to_height <= min(current_height, lock_until)` enforcement. Wallet
  filters updated to include both locked and matured-but-unspent outputs.

- **Zero-staker blocks: unclaimed pool accumulation.** When no stakers existed,
  staker emission and fee pool amounts accumulated in `staker_pool_balance`
  indefinitely. Fixed to burn these amounts when `total_weighted_stake == 0`.

- **Staked outputs incorrectly spendable.** `is_spendable()` allowed spending
  staked outputs after maturity. Fixed: staked outputs are never directly
  spendable -- they must go through the unstake path.

- **Claim watermark not persisted.** Added `m_last_claimed_height` to
  `transfer_details` (C++ wallet) and `TransferDetails` (Rust scanner) with
  serialization. FFI layer now calls `stage_claim_watermarks()` after
  broadcasting claim transactions.

- **Critical: stake tx only mineable in exact creation block (Bug 13).**
  `handle_block_to_main_chain` validated staked outputs with strict equality
  `staked.lock_until == blockchain_height + lock_blocks`. Since the wallet
  signed `lock_until = current_height + lock_blocks`, any mempool latency made
  every honest stake tx permanently unminable. Fixed by removing `lock_until`
  from the on-chain `txout_to_staked_key` struct entirely. The effective lock
  expiry is now computed dynamically as `creation_height + tier_lock_blocks` at
  every check site. Removes ~8 bytes per staked output and eliminates the
  signing-time/mining-time mismatch bug class.

- **High: mempool admits unminable stake txs (Bug 12).** Pool admission
  checked tier validity and non-zero `lock_until` but not the strict equality
  that block validation enforced. Honest and malicious stake txs passed
  admission but were rejected at block-add time, causing miners to waste work
  on blocks that would be rejected. Resolved by the Bug 13 fix: with no
  on-chain `lock_until`, the entire validation path is removed.

- **Medium: off-by-one at upper lock boundary (Bug 11).** The accrual scan
  excluded an output at block `lock_until` (`<= eval_height`), but claim
  validation accepted `to_height <= lock_until`. A staker could claim a
  one-block reward at `lock_until` against a denominator that didn't include
  their weight. Fixed by changing the accrual scan to `effective_lock_until <
  eval_height` (inclusive upper bound) and scheduling unlock subtraction at
  `effective_lock_until + 1`. `lock_blocks = N` now means exactly N blocks of
  accrual.

- **Medium: unstake forfeits unclaimed rewards (Bug 8).**
  `create_unstake_transaction` jumped straight to `create_transactions_from`
  without checking for unclaimed reward backlog. A user who staked for the
  long tier and never claimed would silently forfeit all accrued rewards.
  Fixed: the wallet now refuses to unstake if any target output has
  `m_last_claimed_height < min(current_height, effective_lock_until)` and
  instructs the user to claim first.

- **Minor: local claim watermark advanced on broadcast, not confirmation.**
  `update_claim_watermarks` (now `stage_claim_watermarks`) committed the
  watermark immediately after broadcast. If the tx was dropped or never
  confirmed, the local watermark diverged from consensus. Fixed with an
  in-flight tracking system: claims are staged in `m_pending_claim_watermarks`
  at broadcast, committed by `confirm_claim_watermarks` when the tx appears in
  a confirmed block during scan, and expired by
  `expire_pending_claim_watermarks` after 100 unconfirmed blocks.

### 🔄 Changed

- **Wallet encryption upgraded from ChaCha20 (64-bit nonce) to XChaCha20 (192-bit
  nonce).** The 24-byte nonce eliminates collision risk for randomly-generated
  nonces. Implementation moved from C (`chacha.c`) to Rust (`shekyl-chacha`
  crate) using the NCC-audited RustCrypto `chacha20` crate. `CHACHA_IV_SIZE`
  increased from 8 to 24 bytes. Wallet keys files and cache files now use
  XChaCha20 exclusively.

- **Two-component output keys (`O = xG + yT`).** All output public keys now
  include a domain-separated `y` component along generator `T`, satisfying the
  FCMP++ SAL proof's `OpenedInputTuple::open` constraint. Previously, outputs
  were single-component (`O = xG + 0·T`) and the wallet incorrectly passed
  the Pedersen commitment mask `z` as the SAL `y`, causing proof generation to
  fail. The y-scalar uses the `"shekyl_y"` domain separator in `crypto.cpp`.
  The commitment mask `z` is now passed separately in the 256-byte witness
  header at offset 192. `transfer_details` stores `m_y` (boost serial v14).
  Two regression tests in `proof.rs` verify that the old bug (y=mask) fails
  and the correct path (y=real) succeeds.

- **`MAX_TX_EXTRA_SIZE` (24576 bytes).** The previous Monero-era cap (1060) was
  too small for FCMP++ `tx_extra` payloads (hybrid KEM ciphertexts ~1120 B per
  output, PQC leaf hashes, pubkey/nonce). Construction of v3 spends failed once
  PQC fields were appended; the pool and `construct_tx` checks now allow the
  larger bound.
- **`construct_tx` RCT/PQC stubs.** v3 spends require `|pqc_auths| == |vin|`
  for binary serialization, and `RCTTypeFcmpPlusPlusPqc` needs BP+, ECDH, and
  pseudo-out vectors sized to inputs/outputs. `construct_tx` now assigns stub
  `pqc_authentication` entries and calls `rct::fill_construct_tx_rct_stub()`
  (dummy Bulletproofs+, ECDH encoding, Pedersen pseudo-outs) so
  `get_transaction_hash` and JSON/blob round-trips succeed before the wallet
  replaces the RCT payload with `genRctFcmpPlusPlus()`.

### 🗑️ Removed

- **`shekyl_fcmp_derive_pqc_keypair` FFI function.** Deleted the Rust FFI
  function and its C declaration. This function returned the ML-DSA secret key
  to C++, violating the security invariant that PQC secrets stay in Rust.
  Replaced by `shekyl_derive_pqc_leaf_hash` (returns only h_pqc) and
  `shekyl_derive_pqc_public_key` (returns only the public key).

- **`derive_pqc_keypair`, `derive_hybrid_pqc_keypair`, `DerivedPqcKeypair`,
  `DOMAIN_PQC_OUTPUT` from `shekyl-crypto-pq`.** These legacy derivation
  functions used the old salt A (`shekyl-pqc-derive-v1`) and returned secret
  key material. All callers now use `derive_output_secrets` (salt B) +
  `keygen_from_seed` or the higher-level `sign_pqc_auth_for_output`.

- **`derived_pqc_secret_keys`, `derived_pqc_public_keys`, `claim_signing_sks`
  vectors in `wallet2.cpp`.** These C++ vectors held PQC secret keys in wallet
  memory. All 4 call sites migrated to `shekyl_derive_pqc_leaf_hash` +
  `shekyl_sign_pqc_auth`, which derive and zeroize internally in Rust.

- **`pqc_secret_keys` from `native_sign_state` (`wallet2.h`).** The deferred
  native-signing path no longer stores PQC secret keys. The Rust tx-builder
  receives `combined_ss` + `output_index` and derives keys internally.

- **`SpendInput::pqc_secret_key` from `shekyl-tx-builder`.** Replaced with
  `combined_ss: Vec<u8>` (64 bytes) and `output_index: u64`. The Rust
  `sign_pqc_auths` function now calls `sign_pqc_auth_for_output` internally.

- **4 legacy Monero fixture tests in `serialization.cpp`.** Removed
  `portability_wallet`, `portability_outputs`, `portability_unsigned_tx`,
  `portability_signed_tx`. These tested Monero-era wallet/tx formats that
  Shekyl does not support (no backward compatibility).

- **10 Monero-specific long-term block weight tests.** Removed all tests from
  `long_term_block_weight.cpp` (`empty_short` through `cache_matches_true_value`).
  Monero-specific weight baselines do not apply to Shekyl economics.

- **`chacha.c` (C ChaCha implementation).** Replaced by the Rust `shekyl-chacha`
  crate via FFI. The C implementation had a strict aliasing violation in its
  `U8TO32_LITTLE`/`U32TO8_LITTLE` macros (pointer cast to `uint32_t*`).

- **ChaCha8 dead code.** All `crypto::chacha8()` call sites in `wallet2.cpp`
  were Monero backward-compatibility fallbacks for reading pre-2018 wallet
  files. Shekyl has no legacy wallets; these paths were unreachable.

### 🔒 Security

- **ML-DSA secret keys never cross the FFI boundary.** All wallet PQC signing
  paths now use `shekyl_sign_pqc_auth` (Rust FFI) or `sign_pqc_auth_for_output`
  (Rust tx-builder), which derive the keypair from `combined_ss` + `output_index`,
  sign, and zeroize the secret key — all within Rust. No ML-DSA secret key bytes
  exist in C++ memory at any point. This eliminates the largest PQC secret key
  exposure surface (~4064 bytes per input) from the wallet process.

- **XChaCha20 192-bit nonces for wallet encryption.** Upgraded from the DJB
  ChaCha20 64-bit nonce to XChaCha20 192-bit nonce, eliminating nonce collision
  risk for randomly-generated nonces. The previous 64-bit nonce was safe for
  Shekyl's usage pattern but the larger nonce provides a wider safety margin.

- **Secure memory hardening (project-wide).** Systematic implementation of the
  `secure-memory.mdc` rule across Rust and C++ codebases:
  - `shekyl_buffer_free` now uses `zeroize` crate instead of `std::ptr::write_bytes`,
    preventing the compiler from optimizing away the secret-wiping write.
  - `native_sign_state::clear()` in `wallet2.h` now `memwipe`s all secret fields
    (`spend_key_x`, `spend_key_y`, `h_pqc`, `amount_key`, `pqc_secret_keys`) before
    clearing vectors.
  - Added `prctl(PR_SET_DUMPABLE, 0)` to daemon (`main.cpp`), simplewallet, and
    `wallet2_ffi_create()` to prevent core dumps containing key material on Linux.
  - Passwords, seeds, spend keys, and view keys in `wallet2_ffi.cpp` JSON-RPC dispatch
    now use `memwipe` scope guards to wipe temporary `std::string` buffers after use.
  - New `shekyl_madvise_dontdump` FFI function (`MADV_DONTDUMP` on Linux, no-op elsewhere)
    declared in `shekyl_secure_mem.h`.
  - PQC long-lived secret keys (`m_pqc_secret_key`) are now `mlock`ed and
    `madvise(MADV_DONTDUMP)`ed after generation and decryption, and `memwipe`d +
    `munlock`ed on `forget_spend_key()`.

- **Dev branch audit: Tier 1-6 security and code hardening.** Comprehensive
  re-audit of the dev branch with 22 findings addressed:
  - **PQC secret key lifecycle (Tier 1).** Added `~account_keys()` destructor
    that wipes all secret keys (classical + PQC) and munlocks PQC material.
    Fixed `create_from_keys` and `set_null` to wipe+unlock PQC secrets before
    clearing. Prevents secrets from lingering in freed heap memory.
  - **Debug trait on secret key types (Tier 1).** Removed `#[derive(Debug)]`
    from `HybridSecretKey`, `HybridKemSecretKey`, and `SharedSecret`. All now
    implement manual `Debug` printing `[REDACTED]` to prevent log leakage.
  - **Proof generation panic removal (Tier 1).** Replaced 12
    `ScalarDecomposition::new(...).unwrap()` calls in `proof.rs` with
    `?`-propagated `ProveError::ScalarDecompositionFailed`. Zero-scalar blinding
    factors now return a clean error instead of panicking the wallet.
  - **RELEASE-BLOCKER resolution (Tier 1).** Evaluated and downgraded all 6
    RELEASE-BLOCKER comments in shekyl-oxide to TODO with documented
    justifications. None were correctness or security blockers.
  - **FROST multisig feature-gated (Tier 1).** All FROST SAL and DKG FFI
    functions gated behind `#[cfg(feature = "multisig")]`. Production builds
    exclude multisig code unless the feature is enabled. C++ `#ifdef
    SHEKYL_MULTISIG` blocks have been removed from `shekyl_ffi.h`,
    `wallet2.h/cpp`, and `wallet2_ffi.cpp` — FROST multisig is now
    consumed exclusively through the Rust wallet crates.
  - **CString unwrap removal (Tier 2).** Replaced all `CString::new().unwrap()`
    in `shekyl-wallet-rpc` with `to_cstring()` helper returning `WalletError`.
    Fixed `Mutex::lock().unwrap()` in server.rs to return JSON-RPC error on
    lock poisoning.
  - **Sign function zeroization (Tier 2).** `HybridEd25519MlDsa::sign()` now
    wraps temporary secret arrays in `Zeroizing<[u8; N]>` for automatic cleanup.
  - **hex_to_key temp buffer wiped (Tier 2).** Added `memwipe` scope guard
    to `hex_to_key` in `wallet2_ffi.cpp`.
  - **PQC verify debug gated (Tier 2).** `shekyl_pqc_verify_debug` now only
    compiled with `debug_assertions` or `debug-verify` feature to prevent use
    as a signature oracle in production.
  - **Free-string wipe (Tier 2).** `wallet2_ffi_free_string` now wipes the
    buffer before freeing, protecting against secret-bearing JSON residue.
  - **Buffer free contract documented (Tier 2).** `shekyl_buffer_free` len
    safety contract documented in both Rust doc-comment and C header.
  - **Claim builder silent wrong index (Tier 2).** `position(...).unwrap_or(0)`
    replaced with explicit `TransferNotFound` error in `claim_builder.rs`.
  - **deny(unsafe_code) added (Tier 3).** Added to 5 pure-Rust crates:
    `shekyl-consensus`, `shekyl-economics`, `shekyl-staking`,
    `shekyl-crypto-hash`, `shekyl-crypto-pq`.
  - **Workspace lints inherited (Tier 3).** `[lints] workspace = true` added
    to 11 Shekyl-first crates for consistent Clippy enforcement.
  - **Legacy naming cleanup (Tier 4).** Renamed `MONERO_DEFAULT_LOG_CATEGORY`
    to `SHEKYL_DEFAULT_LOG_CATEGORY` across 128 files.
  - **FCMP++ edge-case tests (Tier 5).** Added 9 parametrized tests covering
    boundary input counts, missing tree paths, empty proof data, count
    mismatches, zero tree depth, and wrong signable_tx_hash.
  - **CI improvements (Tier 6).** Added `.env` to `.gitignore`, created
    explicit CodeQL workflow targeting both `dev` and `main` branches,
    added `permissions: contents: read` to `build.yml`.

- **Base58 overflow and non-canonical encoding fix (monero-oxide fork).**
  `shekyl-base58::decode()` now uses `checked_add` to prevent integer overflow
  during character accumulation, and rejects non-canonical encodings where
  unused high bytes of the decoded sum are non-zero. Defense-in-depth measure;
  Shekyl production addresses use Bech32m.

- **Cargo profile hardening (both Rust workspaces).** All profiles (dev,
  release, test, bench) now enforce `overflow-checks = true` in both the
  monero-oxide fork `Cargo.toml` and the Shekyl `rust/Cargo.toml`. Dev and
  release profiles additionally set `panic = "abort"`.

- **HKDF domain-separated salts for PQC key derivation.** All HKDF-SHA-512
  calls in `shekyl-crypto-pq` now use explicit fixed salts (`shekyl-pqc-derive-v1`,
  `shekyl-master-derive-v1`) instead of `None`. Strengthens domain separation
  and prevents cross-protocol seed reuse if the same combined shared secret
  appears in other contexts.

- **`FrostSalSession` secret deduplication.** Removed the redundant `x`
  (spend secret scalar) from `FrostSalSession` struct fields. Previously the
  secret was stored both in the struct and inside `SalAlgorithm`, with only
  the struct copy explicitly zeroized on drop. Now the secret lives solely
  inside the algorithm, eliminating the unprotected duplicate.

- **Levin double-compression guard.** `try_compress_message` now checks
  `LEVIN_PACKET_COMPRESSED` in the input header before compressing. Prevents
  double-compression of already-compressed messages in future refactors.

- **Divisor degree underflow assertions.** `Divisor::div` now asserts that
  `self.a.degree >= rhs.degree` and `self.b.degree >= rhs.degree` before
  `usize` subtraction, converting silent wraparound into a clear panic with
  diagnostic context.

- **Interpolator allocation bounds fix.** `Interpolator::interpolate` now
  allocates the output coefficient vector using the domain size
  (`self.lagrange_polys.len()`) instead of `evals.len()`, preventing trailing
  zeros from inflating the vector when callers provide excess evaluations.

- **`member_of_list` witness construction hardened.** Replaced
  `next_eval.unwrap()` with `carry_eval.zip(next_eval)` in the FCMP++ circuit
  gadget, eliminating a potential panic if evaluation invariants change.

### ✨ Added

- **`shekyl-tx-builder` crate.** New Rust crate (`rust/shekyl-tx-builder/`)
  consolidating Bulletproofs+ range proofs, FCMP++ full-chain membership proof
  construction, ECDH amount encoding, and PQC (ML-DSA-65) signing into a single
  native Rust call path. Replaces the prior C++ → Rust → C++ → Rust FFI
  round-trip for proof generation. Includes 19 unit tests covering validation
  edge cases (0 inputs, overflow amounts, empty trees, wrong-length PQC keys)
  and ECDH encoding round-trips. All secret key material is wrapped in
  `zeroize::Zeroizing` and wiped on drop.

- **`shekyl_sign_transaction` FFI export.** New C ABI function in `shekyl-ffi`
  wrapping `shekyl-tx-builder::sign_transaction()`. Accepts JSON-serialized
  inputs/outputs, returns a `ShekylSignResult` with either JSON proofs or a
  structured error code and message. Declared in `shekyl_ffi.h`.

- **Wallet RPC `native-sign` feature.** `shekyl-wallet-rpc` gains an optional
  `native-sign` Cargo feature that enables `transfer_native()` — a pure-Rust
  transfer path using `shekyl-tx-builder` directly, eliminating C++ proof FFI
  round-trips. The split pipeline uses `wallet2_ffi_prepare_transfer` (C++ →
  JSON) → `shekyl-tx-builder::sign_transaction` (pure Rust) →
  `wallet2_ffi_finalize_transfer` (JSON → C++).

- **`wallet2_ffi_prepare_transfer` / `wallet2_ffi_finalize_transfer` implemented.**
  Full C++ implementation of the split transfer pipeline. `prepare_transfer`
  activates native-sign mode in `transfer_selected_rct` (skipping C++ proof
  generation), gathers per-input signing data (secret keys, tree paths parsed
  into c1/c2 branch layers, leaf chunks, PQC key material), per-output data
  (dest keys, amount keys), tree context (reference block, curve tree root,
  depth), and serializes everything as hex-encoded JSON matching the Rust
  `SpendInput`/`OutputInfo`/`TreeContext` types. `finalize_transfer` receives
  the Rust-generated `SignedProofs` JSON, manually reconstructs the BP+ struct
  from the Rust blob (handling the V-field format difference), inserts all
  proofs into `tx.rct_signatures`, performs PQC signing using stored secret
  keys, and commits/broadcasts the transaction. Fee estimation uses
  `shekyl_fcmp_proof_len()` to pad the stub FCMP++ proof to the correct
  estimated size.

- **Native-sign mode in `wallet2::transfer_selected_rct`.** New
  `m_native_sign_mode` flag and `native_sign_state` struct on `wallet2`.
  When enabled, `transfer_selected_rct` skips `genRctFcmpPlusPlus` and PQC
  signing, instead storing all signing data for the Rust path. Tree path
  blobs are parsed into structured c1/c2 branch layers. Padded stub proofs
  provide accurate fee estimation.

- **Hex serde for `shekyl-tx-builder` types.** All `[u8; 32]`, `Vec<u8>`,
  and `Vec<[u8; 32]>` fields on `SpendInput`, `OutputInfo`, `TreeContext`,
  `SignedProofs`, `LeafEntry`, and `PqcAuth` now serialize/deserialize as hex
  strings via custom serde modules. This enables clean JSON interop with the
  C++ FFI layer which produces hex-encoded cryptographic keys and blobs.

- **Secure memory Cursor rule.** Added `.cursor/rules/secure-memory.mdc`
  codifying project-wide conventions for cryptographic secret zeroization in
  both Rust (`Zeroizing<T>`, `ZeroizeOnDrop`) and C++ (`memwipe`, scope guards,
  `wipeable_string`), FFI boundary ownership, and OS-level protections (`mlock`,
  `prctl(PR_SET_DUMPABLE, 0)`, `MADV_DONTDUMP`).

- **Vendored monero-oxide protocol crates.** Completed the vendored crate set
  in `rust/shekyl-oxide/`: added `shekyl-primitives` (Keccak-256, Pedersen
  commitments), `shekyl-bulletproofs` (BP+ range proofs), the root `shekyl-oxide`
  crate (transaction/block types, FCMP module), `shekyl-rpc` (daemon RPC trait,
  `ScannableBlock`), and `shekyl-simple-request-rpc` (HTTP transport). Resolved
  the `shekyl-address` naming collision by removing the oxide base58 address
  dependency from the vendored RPC crate (Shekyl uses Bech32m exclusively).
  Added crypto-heavy crate optimizations to `[profile.dev.package]` and
  workspace-level clippy lints for the oxide crates.

- **`shekyl-scanner` crate.** New Rust crate (`rust/shekyl-scanner/`) providing
  a native transaction scanner with Shekyl-specific extensions. Ported the core
  scanning pipeline from monero-oxide (SharedKeyDerivations, Extra parsing,
  ViewPair, per-block/per-tx/per-output ECDH scan loop) and extended it with:
  - PQC KEM ciphertext parsing (tx_extra tag 0x06) and leaf hash parsing (0x07)
  - Staking output detection and balance categorization (matured/locked tiers)
  - `TransferDetails` struct with FCMP++ path precompute, combined PQC shared
    secret, and spend tracking fields
  - `WalletState` for in-memory transfer management with key image dedup, spend
    detection, and reorg handling
  - `BalanceSummary` with staking-aware breakdown (total, unlocked, timelocked,
    staked matured/locked, frozen)

- **Split RPC routing (`rust-scanner` feature).** `shekyl-wallet-rpc` now
  supports a `rust-scanner` feature flag that routes scanner-backed read-only
  methods (get_balance, get_transfers, incoming_transfers, get_height,
  get_staked_outputs, get_staked_balance) to native Rust handlers via
  `shekyl-scanner`, while all mutation methods continue through the C++ FFI.
  Added `ScannerState`, `dispatch_with_scanner()`, and typed scanner handlers.

- **GUI wallet scanner integration.** Updated `wallet_bridge.rs` in
  `shekyl-gui-wallet` to include a `ScannerState` alongside the FFI `Wallet2`
  handle. Added `get_scanner_balance()`, `get_scanner_staked_outputs()`, and
  `get_scanner_height()` bridge methods for future scanner-backed queries.

- **`shekyl-encoding` crate.** New standalone Rust crate (`rust/shekyl-encoding/`)
  for general-purpose Bech32m blob encoding and decoding with arbitrary HRPs.
  Defines HRP constants for wallet proofs (`shekylspendproof`, `shekyltxproof`,
  `shekylreserveproof`, `shekylsig`, `shekylmultisig`, `shekylsigner`).

- **`shekyl-address` crate.** New standalone Rust crate (`rust/shekyl-address/`)
  for network-aware segmented Bech32m address encoding. Defines `Network` enum
  (Mainnet, Testnet, Stagenet) with HRP lookup tables for classical (`shekyl`,
  `tshekyl`, `sshekyl`) and PQC (`skpq`/`skpq2`, `tskpq`/`tskpq2`,
  `sskpq`/`sskpq2`) segments. `ShekylAddress` supports `encode()`, `decode()`,
  and `decode_for_network()`.

- **Generic Bech32m blob FFI.** `shekyl_encode_blob()` and `shekyl_decode_blob()`
  FFI functions allow C++ to encode/decode arbitrary binary data with
  purpose-specific HRPs, replacing all direct Base58 calls in wallet proofs.

- **Network-aware address FFI.** `shekyl_address_encode()` and
  `shekyl_address_decode()` now accept/return a `network` parameter (0=mainnet,
  1=testnet, 2=stagenet) for HRP-based network discrimination.

- **Shekyl-first development rule.** Added `.cursor/rules/shekyl-first-development.mdc`
  codifying that Shekyl core is the authoritative codebase and the monero-oxide
  fork is a disposable downstream consumer.

- **FROST SAL threshold signing for FCMP++ multisig.** New `frost_sal`
  module in `shekyl-fcmp` wraps upstream `SalAlgorithm<Ed25519T>` for
  threshold Spend-Auth-and-Linkability proofs. `FrostSalSession` manages
  per-input FROST state; `prove_with_sal()` constructs FCMP++ proofs from
  pre-aggregated SAL pairs. FFI functions (`shekyl_frost_sal_session_new`,
  `_get_rerand`, `_aggregate_and_prove`, `_session_free`) expose the session
  lifecycle to C++. The `multisig` feature flag enables FROST dependencies
  (`modular-frost`, `transcript`, `rand_chacha`).

- **FROST DKG key management.** New `frost_dkg` module in `shekyl-fcmp`
  provides `SerializedThresholdKeys` for `ThresholdKeys<Ed25519T>`
  serialization/deserialization, group key extraction, and parameter
  validation. FFI functions (`shekyl_frost_keys_import`, `_export`,
  `_group_key`, `_validate`, `_free`) manage threshold keys from C++.

- **Variable-length FCMP++ witness wire format.** `shekyl_fcmp_prove` FFI
  now accepts a single `witness_ptr`/`witness_len` blob containing per-input
  fixed headers, leaf chunk Ed25519 output data, and Helios/Selene branch
  layers. `genRctFcmpPlusPlus` in `rctSigs.cpp` serializes the full witness.

- **Daemon RPC `chunk_outputs_blob`.** `get_curve_tree_path` response now
  includes per-chunk compressed Ed25519 output data (O, I=Hp(O), C,
  H(pqc_pk)) enabling the wallet to pass full output points to the prover.

- **C++ wallet FROST multisig integration (removed).** Previously added
  C++ FROST integration in `wallet2.cpp` (`prepare_multisig_fcmp_proof`,
  `export_multisig_signing_request`, `import_multisig_signatures`, threshold
  key import/export). This C++ code has been replaced by the Rust-native
  wallet crates and all `#ifdef SHEKYL_MULTISIG` blocks have been removed
  from `wallet2.h/cpp`, `wallet2_ffi.cpp`, and `shekyl_ffi.h`.

- **`FrostSigningCoordinator` for multi-input nonce aggregation.** New
  coordinator in `shekyl-fcmp/src/frost_sal.rs` manages per-input preprocess
  collection, nonce sum computation, share collection, and final aggregation
  into `SpendAuthAndLinkability` pairs for `prove_with_sal()`.

- **Full FROST DKG ceremony via `MultisigDkgSession`.** New wallet-level
  wrapper in `shekyl-wallet-core/src/multisig/dkg.rs` drives the `dkg-pedpop`
  `KeyGenMachine` state machine through all three rounds with type-safe
  transitions: `generate_coefficients` → `generate_secret_shares` →
  `calculate_share` → `complete`. DKG messages are exchanged as byte buffers
  (file-based, air-gap compatible).

- **`MultisigSigningSession` for wallet-level FROST orchestration.** New
  session in `shekyl-wallet-core/src/multisig/signing.rs` wraps per-input
  `FrostSalSession` instances and a `FrostSigningCoordinator`, providing
  hex-encoded preprocess/share exchange for transport-agnostic signing.

- **`MultisigGroup` with PQC keypair management.** New type in
  `shekyl-wallet-core/src/multisig/group.rs` stores threshold keys,
  group metadata, and PQC hybrid keypairs with automatic zeroization
  on drop. Supports serialization/deserialization for wallet storage.

- **FROST multisig RPC endpoints.** 9 new JSON-RPC methods in
  `shekyl-wallet-rpc/src/multisig_handlers.rs` for FROST signing
  coordination: `multisig_register_group`, `multisig_list_groups`,
  `multisig_create_signing`, `multisig_sign_preprocess`,
  `multisig_sign_add_preprocess`, `multisig_sign_nonce_sums`,
  `multisig_sign_own`, `multisig_sign_add_shares`,
  `multisig_sign_aggregate`. All byte fields hex-encoded. DKG is
  intentionally excluded from RPC (file-based only).

- **`SalLegacyAlgorithm` and `legacy_multisig` removed from shekyl-oxide.**
  Deleted the legacy Monero multisig SAL algorithm and test module from the
  vendored `shekyl-oxide/fcmp/fcmp++` crate. Only the modern `SalAlgorithm`
  (used by `FrostSalSession`) is retained.

- **16+ new Rust tests for FROST.** 4 `frost_sal` unit tests (session
  creation, pseudo-out distinctness, identity rejection, field roundtrip),
  6 `FrostSigningCoordinator` tests (wrong preprocess count, shares before
  nonces, duplicate shares, nonce sums timing, point addition, bytes
  roundtrip), 2 `FrostSalSession` negative tests, 4 `frost_dkg` unit tests
  (serialization roundtrip, group key extraction, parameter validation,
  byte-level roundtrip), 8 FFI lifecycle tests (null safety, invalid data
  rejection, session handle management), 5 `shekyl-wallet-core` multisig
  tests (DKG 2-of-3 and 3-of-5 roundtrips, DKG state machine errors,
  group serialization, threshold keys roundtrip).

- **FCMP++ prove/verify round-trip test.** `prove_verify_roundtrip()` in
  `rust/shekyl-fcmp/src/proof.rs` exercises the full stack: random key
  generation, single-leaf tree root computation, `prove()`, `verify()`, and
  negative tests (tampered key image, wrong tree root).

### 🐛 Fixed

- **Suppressed vendored crate warnings.** Fixed `dead_code` warning for
  `InconsistentWitness` variant in `generalized-bulletproofs` (only constructed
  under `debug_assertions`) with `#[cfg_attr(not(debug_assertions), allow(dead_code))]`.
  Fixed deprecated `GenericArray::as_slice()` in `helioselene` ciphersuite by
  replacing with `as_ref()`.

- **Stake-claim vs `verRctSemanticsSimple` conflict.** Stake-claim transactions
  use `RCTTypeFcmpPlusPlusPqc` but have no FCMP++ membership proof (they prove
  ownership via PQC auth on public amounts). `ver_non_input_consensus` now
  excludes stake-claim-only transactions from the RCT semantics batch that
  rejects empty `fcmp_pp_proof`.

- **`genRctFcmpPlusPlus` hard-fail on proof failure.** Previously logged and
  returned an `rctSig` with an empty proof when `shekyl_fcmp_prove` failed; now
  throws `CHECK_AND_ASSERT_THROW_MES` so the wallet catches the error
  immediately rather than producing an invalid transaction.

- **PQC leaf scalar now uses proper Selene field reduction.** `PqcLeafScalar::from_pqc_public_key`
  and `hash_pqc_public_key` previously truncated Blake2b-512 to 32 bytes and
  cleared bit 255, which could produce non-canonical values exceeding the
  Selene base field modulus. Now uses `HelioseleneField::wide_reduce` on the
  full 64-byte hash for unbiased, canonical field elements.

- **Deterministic PQC keygen stability.** Replaced `rand::rngs::StdRng` with
  `rand_chacha::ChaCha20Rng` for ML-DSA-65 keypair derivation. `StdRng`'s
  underlying algorithm is not a stability guarantee across `rand` versions,
  which could break wallet-restore-from-seed.

- **Bech32m variant enforcement.** `decode_blob` now strictly enforces the
  Bech32m checksum variant instead of accepting both Bech32 and Bech32m.
  Removed unused `EncodingError::EmptyData` variant.

### 🔒 Security

- **FrostSalSession spend secret zeroized on drop.** The FROST SAL session's
  spend secret scalar is zeroized when the session is dropped, per the
  project-wide secure memory rule. After the `FrostSalSession` secret
  deduplication (see Changed), the secret lives solely inside the
  `SalAlgorithm` and is zeroized through its `Drop` impl.

- **RELEASE-BLOCKER resolved in circuit gadgets.** The `incomplete_add_pub`
  function in the FCMP++ circuit already receives parameters typed as `OnCurve`,
  which guarantees the on-curve constraint. Replaced the
  `RELEASE-BLOCKER(shekyl)` comment with documentation explaining why no
  additional constraint is needed.

- **Pruning watermark hardening.** `BlockchainLMDB::prune_tx_data()` now
  fails the current batch on missing transaction rows (`TX_DNE`) instead of
  logging and continuing, so `tx_prune_next_block` cannot advance on partial
  pruning.

- **FCMP++ compile-path compatibility fixes.** Updated wallet/core-test FCMP++
  construction callsites for the current `genRctFcmpPlusPlus` leaf-chunk API,
  and added explicit cached-chunk to `rct::fcmp_chunk_entry` conversion in
  wallet construction to keep GCC 14 builds green.

- **CI portability and fuzz gate hardening.** Replaced GNU-only `xargs -r`
  usage in Cargo absolute-path guard with a portable shell loop, and added a
  required fuzz-harness inventory smoke gate in Rust CI.

- **Stale fuzz targets updated.** `fuzz_fcmp_proof_deserialize` and
  `fuzz_tx_deserialize_fcmp_type7` now pass the required `signable_tx_hash`
  7th argument to `verify()`. `fuzz_block_header_tree_root` rewritten for the
  current `ProveInput` struct and 4-arg `prove()` signature.

- **`prune_tx_data` miner output lookup.** When storing output-pruning metadata,
  RCT coinbase outputs are keyed under amount `0` in LMDB (same as
  `add_transaction`); pruning now uses that amount for `get_output_key` instead
  of the plaintext `vout.amount`, avoiding `OUTPUT_DNE` during prune for
  miner transactions.

### 🗑️ Removed

- **RingCT-era dead code excision (C++ wallet).** Comprehensive removal of
  ring-signature infrastructure that is structurally unreachable on an FCMP++
  chain. Deleted: `gamma_picker` class and `GAMMA_SHAPE`/`GAMMA_SCALE`
  constants, `transfer_selected` (non-RCT overload), `wallet2::get_outs`
  decoy-fetching overloads (~700 lines), `tx_add_fake_output`,
  `select_available_mixable_outputs`, `select_available_outputs_from_histogram`,
  `get_spend_proof`/`check_spend_proof` (ring-sig-dependent proofs),
  `get_min_ring_size`/`get_max_ring_size`, `m_confirm_non_default_ring_size`
  preference, the entire `ringdb.h`/`ringdb.cpp` subsystem (LMDB ring
  database), ring commands in simplewallet, spend proof RPC endpoints and FFI
  dispatch, `boroSig` struct from `rctTypes.h`, unreachable
  `hf_version < HF_VERSION_FCMP_PLUS_PLUS_PQC` branch in
  `cryptonote_tx_utils.cpp`, `blockchain_blackball` utility, and
  `output_selection.cpp` unit test. Removed LMDB link dependency from wallet
  CMake target.

- **Decoy and ring_size removal from Rust RPC.** Removed `ring_size: u32`
  parameter from `shekyl-wallet-rpc` transfer API (`types.rs`, `wallet.rs`,
  `ffi.rs`), from the C++ FFI boundary (`wallet2_ffi.h`/`.cpp`), and from the
  C++ wallet RPC `estimate_tx_size_and_weight` command definition. Deleted
  `Decoys` struct, `MAX_RING_SIZE` constant, `DecoyRpc` trait and blanket
  implementation, `OutputInformation` struct, `rpc_point` helper, and
  `test_decoy_rpc` test from `shekyl-oxide`. Removed
  `/get_output_distribution.bin` route from `shekyl-daemon-rpc`.

- **Bulletproof v1 ("Original") deletion.** Deleted the entire `original/`
  module tree and its tests from `shekyl-bulletproofs`. Removed
  `Bulletproof::Original` enum variant, v1 `prove()`/`read()` functions,
  v1 match arms in `verify`/`batch_verify`/`write_core`, and the standalone
  `BulletproofsBatchVerifier` struct. Cleaned up dead `inner_product` and
  `mul_vec` methods that were only used by v1 code.

- **Light wallet support removed.** Deleted all `m_light_wallet` state,
  `set_light_wallet`, `light_wallet_login`, `light_wallet_get_outs`,
  `import_outputs`, `get_unspent_outs`, `submit_raw_tx`, and all
  `if (m_light_wallet)` branches from `wallet2.cpp`/`.h`. Deleted
  `wallet_light_rpc.h` entirely. Removed light wallet API from
  `wallet2_api.h`/`wallet.h`/`wallet.cpp`. Fundamentally incompatible with
  FCMP++ privacy model (sends view keys to remote server).

### 🔄 Changed

- **MLSAG naming debt resolved.** Renamed `get_pre_mlsag_hash` to
  `get_tx_prehash`, `mlsag_prehash`/`mlsag_prepare`/`mlsag_hash`/`mlsag_sign`
  to `tx_prehash`/`tx_prepare`/`tx_hash`/`tx_sign` across the device interface
  hierarchy (`device.hpp`, `device_default.hpp`/`.cpp`, `device_ledger.hpp`/`.cpp`),
  `rctSigs.cpp`/`.h`, and `protocol.cpp`. Renamed Ledger `INS_MLSAG` constant
  to `INS_TX_SIGN`. These functions are live code repurposed for FCMP++
  transaction hashing; the names now reflect their actual role.

- **Base58 encoding removed entirely.** Deleted `src/common/base58.{h,cpp}`,
  `tests/unit_tests/base58.cpp`, `tests/fuzz/base58.cpp`, and all CMake
  references. Removed `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX`,
  `CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX`, and
  `CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX` constants from all network
  namespaces and `config_t`. No code path accepts or produces Base58 strings.

- **Legacy address structs removed.** `integrated_address`,
  `legacy_account_public_address`, and `legacy_integrated_address` structs
  removed from `cryptonote_basic_impl.cpp`. Subaddress and integrated address
  logic removed from address encoding/decoding chokepoints.

### 🔄 Changed

- **Rust naming convention cleanup.** Fixed phantom FFI function reference in
  `shekyl_pqc_verify` doc comment (referenced non-existent
  `shekyl_pqc_verify_multisig_with_group_id`, now points to
  `shekyl_pqc_multisig_group_id`). Renamed Windows `SystemInfo.dw_page_size`
  to `page_size` (drop Hungarian notation). Renamed `shekyl-wallet-rpc-rs`
  binary to `shekyl-wallet-rpc` (drop `-rs` suffix per Rust API Guidelines).

- **Address encoding migrated to Bech32m.** `get_account_address_as_str()` and
  `get_account_address_from_str()` now call Rust FFI (`shekyl_address_encode`,
  `shekyl_address_decode`) for network-aware Bech32m encoding. The `subaddress`
  parameter is retained for API compatibility but ignored. `address_parse_info`
  fields `is_subaddress` and `has_payment_id` are always false.

- **Wallet proofs use Bech32m blob encoding.** Spend proofs, tx proofs (in/out),
  reserve proofs, message signatures, multisig signatures, and signer keys are
  now encoded with purpose-specific HRPs via `shekyl_encode_blob` /
  `shekyl_decode_blob` FFI. Version headers (`SpendProofV1`, `InProofV2`, etc.)
  removed; the HRP now serves as the type discriminator.

- **`shekyl-crypto-pq` re-exports `shekyl-address`.** The `address` module in
  `shekyl-crypto-pq` is now a re-export of the standalone `shekyl-address` crate.
  The old `shekyl-crypto-pq/src/address.rs` has been deleted.

- **Tx-data prune watermark.** `prune_tx_data` now stores `tx_prune_next_block`
  (exclusive next height) instead of ambiguous `last_pruned_tx_data_height`
  values; legacy keys migrate on read/write. LMDB unit tests live in
  `tests/unit_tests/tx_data_pruning_lmdb.cpp` (minimal block builder only; does
  not link `tests/core_tests/chaingen.cpp` into `unit_tests`, avoiding duplicate
  object code and macOS linker unwind/diagnostic issues in CI).

- **FCMP++ Rust dependency source moved in-repo.** `shekyl-fcmp` now consumes
  vendored `shekyl-oxide` crates via path dependencies under
  `rust/shekyl-oxide/` instead of git dependencies plus local absolute-path
  `[patch]` overrides. This removes host-specific Cargo path failures in CI and
  keeps builds fully repo-local.

- **Upstream sync and portability guardrails.** Added vendored snapshot metadata
  at `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`, a divergence workflow
  (`.github/workflows/shekyl-oxide-divergence.yml`), and build workflow checks
  that fail on absolute local paths in Cargo manifests/config.

### ✨ Added

- **`--prune-blockchain` transaction-data pruning.** LMDB v6 adds `txs_pqc_auths`
  (split from `txs_pruned` at `pqc_auths_offset`), implements `prune_tx_data`
  (batch 256 blocks, output metadata, watermark, TOCTOU height check), default
  depth `CRYPTONOTE_TX_PRUNE_DEPTH` (5000), `pop_block` guard when verification
  data is gone, continuous pruning via `update_blockchain_pruning`, RPC
  `get_transactions.pruned` and `get_info.tx_prune_height`.

- **Staking FFI and config-driven tier parameters.** `shekyl-staking` now
  generates tier lock durations, yield multipliers, and max stake-claim range
  from `config/economics_params.json` at build time (aligned with
  `shekyl-economics`). New FFI: `shekyl_calc_per_block_staker_reward` (128-bit
  division with optional overflow flag), `shekyl_stake_tier_count`,
  `shekyl_stake_tier_name`, `shekyl_stake_max_claim_range`. C++ uses these in
  `blockchain.cpp`, `core_rpc_server.cpp`, and `simplewallet` instead of
  duplicating tier strings or inline `mul128`/`div128_64` reward math.

- **FCMP++ transaction construction helper (`construct_fcmp_tx`).** New chaingen
  helper in `tests/core_tests/chaingen.cpp` that builds fully valid FCMP++
  transactions during core test replay: tree path assembly from the live LMDB
  curve tree, `genRctFcmpPlusPlus` proof generation, KEM decapsulation for
  per-input PQC keypair derivation, and PQC auth signing. This unblocks 30+
  disabled core tests that relied on the old `construct_tx_rct` stub.

- **FCMP++ core test generators (Phase 7).** Five new tests in
  `tests/core_tests/fcmp_tests.cpp`:
  - `gen_fcmp_tx_valid`: end-to-end FCMP++ transaction construction and pool
    acceptance during replay
  - `gen_fcmp_tx_double_spend`: second FCMP++ spend of the same output rejected
  - `gen_fcmp_tx_reference_block_too_old`: stale referenceBlock rejected
  - `gen_fcmp_tx_reference_block_too_recent`: too-recent referenceBlock rejected
  - `gen_fcmp_tx_timestamp_unlock_rejected`: timestamp-based `unlock_time` rejected

- **Verification caching unit tests.** Six new GTest cases in
  `tests/unit_tests/fcmp.cpp` validating `compute_fcmp_verification_hash`
  determinism, sensitivity to proof/referenceBlock/key-image changes, null return
  for non-FCMP++ types, and multi-input handling.

- **Deferred insertion boundary tests.** New `tests/unit_tests/deferred_insertion.cpp`
  with tests for: outputs not drainable before maturity, coinbase maturity window
  (60 blocks), regular tx maturity window (10 blocks), drain journal atomicity
  round-trip, and insertion ordering determinism across two DB instances.

- **Pending tree add/pop stress test.** New `tests/unit_tests/pending_tree_fuzz.cpp`
  with randomized stress test (100 random leaves, multi-height draining),
  add/remove round-trip, drain journal CRUD, and leaf removal correctness.

- **`fuzz_tx_deserialize_fcmp_type7` Rust fuzz target.** New cargo-fuzz target in
  `rust/shekyl-fcmp/fuzz/` that exercises FCMP++ proof verification with
  transaction-structured random inputs: pseudoOuts, proof blobs, PQC hashes,
  corrupted type bytes, empty proofs, and mismatched input counts.

- **Comprehensive staking test suite.** New test coverage across C++ and Rust:
  - `tests/unit_tests/staking.cpp`: 20+ GTest unit tests covering
    `txin_stake_claim` and `txout_to_staked_key` serialization round-trips,
    reward integer math (including `mul128`/`div128_64` vs `double` divergence
    at large values), helper function coverage (`get_inputs_money_amount`,
    `check_inputs_overflow`, `check_inputs_types_supported`,
    `get_output_staking_info`, `set_staked_tx_out`), stake weight/tier FFI
    validation, and variant type handling.
  - `tests/core_tests/staking.cpp` + `staking.h`: 18 chaingen core tests
    covering staking lifecycle (stake output creation), invalid claim
    rejection (inverted range, oversized range, future height, wrong
    watermark, wrong amount, non-staked output, output not in tree), lock
    period enforcement (invalid tier), rollback
    correctness (pool balance, watermark), txpool handling, sorted-input
    enforcement, and multi-tier staking.
  - `rust/shekyl-staking/src/tiers.rs`: 10 edge-case tests including
    exhaustive invalid tier ID rejection, ordering invariants for yield
    multiplier and lock blocks, contiguous ID verification, and positive
    parameter assertions.
  - `rust/shekyl-staking/fuzz/fuzz_targets/fuzz_claim_reward.rs`: cargo-fuzz
    target that generates random accrual records and verifies reward
    computation invariants (no overflow, reward <= pool, weight monotonicity,
    cumulative bounds).

### 🔄 Changed

- **Universal deferred curve-tree insertion (Decision 15).** All outputs
  (coinbase, regular, staked) now enter the `pending_tree_leaves` table at
  creation and drain into the curve tree only after their type-specific
  maturity height (coinbase: +60, regular: +10, staked: max(effective_lock_until, +10)).
  The `pending_staked_*` identifiers were renamed to `pending_tree_*` across
  all database interfaces. The drain journal (`pending_tree_drain`) now stores
  full 136-byte entries (maturity_height + leaf_data) for exact `pop_block`
  reversal instead of just a drain count. `pop_block` restores drained leaves
  to pending and removes the popped block's own pending entries.

- **FCMP_REFERENCE_BLOCK_MIN_AGE reduced to 5 (Decision 14).** With maturity
  enforced by deferred tree insertion, MIN_AGE now serves only as a reorg
  safety margin (5 blocks ≈ 10 minutes). The old static_asserts tying
  MIN_AGE to unlock windows have been removed.

- **Timestamp-based `unlock_time` rejected (Decision 13).** Transactions
  with `unlock_time >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500M) are now
  rejected in `check_tx_outputs`. Only height-based lock times are accepted.

- **`prune_tx_data` status clarification.** The output-metadata pruning loop
  in `db_lmdb.cpp` is a plumbing-only stub (`TODO(phase6f)`). The
  `store_output_metadata`, `get_output_metadata`, and `is_output_pruned`
  interfaces are live, but the block-iteration pruning loop does not execute.

### 🗑️ Removed

- **Vestigial hard fork constants.** Removed `HF_VERSION_CLSAG` and
  `HF_VERSION_MIN_V2_COINBASE_TX` from `cryptonote_config.h`. All test
  references replaced with literal `1`.

- **Legacy tests incompatible with FCMP++ consensus.** Disabled 30+ core
  and unit tests that relied on Monero-era transaction construction
  (`RCTTypeBulletproofPlus`, CLSAG ring signatures, v1/v2 transactions):
  - `tests/core_tests/chaingen_main.cpp`: Disabled `gen_simple_chain_001`,
    `gen_simple_chain_split_1`, `gen_chain_switch_1`, `gen_ring_signature_1`,
    `gen_ring_signature_2`, all `txpool_*` tests, all `gen_double_spend_*`
    tests, `gen_block_reward`, all `gen_bpp_*` Bulletproofs+ tests, and
    several `gen_tx_*` tests whose setup required valid user transactions.
    These tests construct transactions via `MAKE_TX`/`construct_tx_rct`
    which produce `RCTTypeFcmpPlusPlusPqc` stubs with empty `pqc_auths`,
    rejected by `check_tx_inputs` even in FAKECHAIN mode.
  - `tests/unit_tests/bulletproofs.cpp`: All three weight tests
    (`weight_equal`, `weight_more`, `weight_pruned`) prefixed with
    `DISABLED_` and hex blobs removed. Shekyl's `rctSigBase` serialization
    rejects any type other than `RCTTypeFcmpPlusPlusPqc` (type 7), so old
    `RCTTypeBulletproofPlus` (type 6) blobs fail to deserialize.
  - Re-enabling requires a chaingen FCMP++ transaction generator that
    produces valid PQC auth signatures and curve-tree membership proofs.

### 🔄 Changed

- **Upstream monero-oxide dependencies renamed to shekyl-oxide.** Updated
  `shekyl-fcmp/Cargo.toml` and all Rust source files to use the renamed
  packages from the monero-oxide fork (`monero-fcmp-plus-plus` →
  `shekyl-fcmp-plus-plus`, `monero-generators` → `shekyl-generators`).
  `Cargo.lock` advanced from pin `92af05e` to `416d8d1` which includes the
  complete `monero-oxide/` → `shekyl-oxide/` directory and package rename.

- **`shekyl-fcmp` crate cleanup.** Removed unused `sha2` and `shekyl-crypto-pq`
  dependencies from `rust/shekyl-fcmp/Cargo.toml`. Renamed the misleading
  `ProveError::InputCountMismatch` variant to `ProveError::PqcHashMismatch`
  with a clear `input_index` field indicating which input has a mismatched
  leaf `h_pqc` vs `pqc_auth` commitment.

### 🐛 Fixed

- **Private member access in pending tree unit tests.** Fixed 18 compile
  errors in `pending_tree_fuzz.cpp` and 4 in `deferred_insertion.cpp` on
  macOS CI where calls to `add_pending_tree_leaf`, `drain_pending_tree_leaves`,
  `add_pending_tree_drain_entry`, `get_pending_tree_drain_entries`,
  `remove_pending_tree_drain_entries`, and `remove_pending_tree_leaf` were
  calling private overrides on `BlockchainLMDB`. Changed all test methods
  to use `BlockchainDB&` references, accessing the public base class interface.

- **CI compile errors across all platforms.** Fixed compilation failures in
  the new staking and FCMP++ test suites:
  - `tests/core_tests/staking.cpp`: Added missing `fill_tx_sources`
    declaration to `chaingen.h` and moved `Blockchain::check_stake_claim_input`
    from the private section to the public API so core tests can call it
    without `IN_UNIT_TESTS`.
  - `tests/unit_tests/fcmp.cpp`: Fixed serialization calls to use
    `do_serialize(ar, v)` instead of non-existent `v.serialize(ar)` member;
    replaced `binary_archive<false>(istringstream&)` with the correct
    `binary_archive<false>(span<const uint8_t>)` constructor; fixed
    `shekyl_pqc_verify` call to include the required `scheme_id` first
    argument and corrected parameter order.
  - `tests/unit_tests/staking.cpp`: Same `binary_archive<false>` constructor
    fix — replaced `istringstream` with `epee::span<const uint8_t>` in all
    four serialization round-trip tests.
  - macOS CI: Added `zstd` to Homebrew dependencies and fixed CMake to use
    `PkgConfig::ZSTD` imported target instead of bare library name, resolving
    `ld: library 'zstd' not found` on macOS Homebrew where the library lives
    in a non-standard path (`/opt/homebrew/lib`).

- **RPC estimate_claim_reward floating-point precision bug.** The
  `on_estimate_claim_reward` RPC handler used `double`-precision arithmetic
  for reward estimation, which diverges from the consensus `mul128`/`div128_64`
  path when `total_weighted_stake > 2^53`. Fixed to use identical 128-bit
  integer math, ensuring wallet reward estimates always match consensus.

### 🐛 Fixed

- **FCMP++ wallet precompute metadata and input consistency checks.**
  `transfer_selected_rct` and multisig proof prep now read tree depth from
  RPC metadata (`tree_depth`) instead of `path_blob[0]`, enforce that all
  selected inputs share the same reference block/depth snapshot, and reject
  empty precomputed paths. This fixes silent spend-construction failures.

- **Stake-claim input routing in consensus verification.**
  `Blockchain::check_tx_inputs` now routes pure `txin_stake_claim`
  transactions through the claim-specific input checks before generic FCMP++
  `txin_to_key` validation, preventing incorrect rejection of valid
  stake-claim transactions that use `RCTTypeFcmpPlusPlusPqc`.

- **Stake-claim reward math overflow defense.** Added a defensive `q_hi != 0`
  check after `div128_64` in claim reward computation, rejecting impossible
  overflow states instead of silently truncating.

- **Claim transaction PQC signing correctness/performance.** Removed wallet
  master-key fallback for claim input signing and now require per-output
  shared-secret rederivation for all claim inputs. Claim signing keypairs are
  derived once per input and reused for both `pqc_auths` public key and
  signature generation.

- **Curve-tree path RPC returns spendable reference block.**
  `get_curve_tree_path` now returns a `reference_block` at least
  `FCMP_REFERENCE_BLOCK_MIN_AGE + 1` behind tip, avoiding immediate mempool
  rejection of freshly built transactions that used a too-recent tip anchor.

- **PQC derivation index correctness and duplicate derivation overhead.**
  Spend-path and multisig PQC key derivation now use
  `m_internal_output_index` (matching KEM encapsulation/decapsulation) and
  derive each per-input keypair once per transaction, reusing it for both
  `H(pqc_pk)` and signing.

- **Staked-output FCMP++ path precompute filtering.**
  Wallet precompute/incremental updates now skip still-locked staked outputs
  (`m_stake_lock_until > current_height`) to avoid daemon path lookup errors.

- **Stake-claim rollback completeness.** `BlockchainDB::remove_transaction`
  now fully reverses `txin_stake_claim` state on reorg: watermark is restored
  to its pre-claim value (or removed for first-time claims) and the claimed
  amount is credited back into the staker reward pool. Previously only the
  spent key was removed, leaving claim-progress accounting permanently
  advanced after a reorg.

- **Txpool key-image handling for stake claims.** All six txpool functions
  that walk transaction inputs (`insert_key_images`,
  `remove_transaction_keyimages`, `have_tx_keyimges_as_spent`,
  `have_key_images`, `append_key_images`, `mark_double_spend`) now handle
  `txin_stake_claim` inputs alongside `txin_to_key`. Previously they used
  `CHECKED_GET_SPECIFIC_VARIANT(..., txin_to_key, ...)` which caused
  immediate false-return on any stake-claim input, breaking mempool
  bookkeeping for claim transactions.

- **`remove_transaction_keyimages` no longer returns early on error.**
  The function now continues removing remaining key images instead of
  aborting at the first mismatch, eliminating the partial-cleanup semantics
  noted by the long-standing FIXME.

- **Core helper support for `txin_stake_claim`.** `get_inputs_money_amount`
  and `check_inputs_overflow` now handle both `txin_to_key` and
  `txin_stake_claim` input variants instead of failing on the latter. These
  are called unconditionally for all transactions (via `check_money_overflow`),
  so the old hard-cast to `txin_to_key` would reject any transaction
  containing a stake claim.

### 🔒 Security

- **FFI buffer zeroization before free.** `shekyl_buffer_free` now wipes
  buffer contents prior to deallocation, reducing secret-key residue risk in
  allocator-managed memory.

- **Wallet KEM key management fix.** `generate_pqc_key_material()` now
  generates `HybridX25519MlKem` KEM keypairs via `shekyl_kem_keypair_generate()`
  instead of `HybridEd25519MlDsa` signing keypairs. The wallet-level PQC
  keys (`m_pqc_public_key` / `m_pqc_secret_key`) are encapsulation/decapsulation
  keys; per-output ML-DSA-65 signing keys are always derived from the KEM
  shared secret at spend time.

- **Full hybrid ciphertext storage in tx_extra tag 0x06.** All KEM
  encapsulation sites (coinbase, claim, regular transfers) now store the
  complete 1120-byte hybrid ciphertext (`x25519_ephemeral_pk[32] || ml_kem_ct[1088]`)
  instead of only the ML-KEM portion. This enables correct hybrid
  decapsulation during wallet scanning and seed restore.

### ✨ Added

- **FCMP++ wallet transaction construction (Phase 5).** `transfer_selected_rct`
  now builds transactions using full-chain membership proofs instead of ring
  signatures:
  - Inputs contain only the real output (no decoy selection).
  - `genRctFcmpPlusPlus` generates the combined Bulletproofs+ and FCMP++
    membership proof.
  - Per-input PQC auth signatures use ML-DSA-65 keypairs derived from the
    KEM shared secret and output index.
  - `construct_tx_with_tx_key` adds KEM encapsulation (tag 0x06) and
    `H(pqc_pk)` leaf hashes (tag 0x07) for each output, and skips
    wallet-level PQC signing.

- **KEM decapsulation during wallet scanning.** `process_new_transaction`
  now extracts hybrid KEM ciphertexts from `tx_extra` tag 0x06, calls
  `shekyl_kem_decapsulate` with the wallet's KEM secret keys, and stores
  the resulting 64-byte combined shared secret in `transfer_details::m_combined_shared_secret`.
  This enables per-output PQC key derivation at spend time.

- **FCMP++ fee estimation.** `estimate_rct_tx_size` now accounts for the
  FCMP++ membership proof size (`shekyl_fcmp_proof_len`), per-input PQC
  auth envelopes (~5400 bytes each), and per-output KEM ciphertexts and
  leaf hashes.

- **GUI wallet QR code.** Receive page now renders a real QR code encoding
  the full FCMP++ Bech32m address via `qrcode.react`.

- **GUI wallet fee preview.** Send page shows an estimated transaction fee
  before submission, debounced as the user types.

### 🗑️ Removed

- **CLSAG device interface methods.** Removed `clsag_prepare`, `clsag_hash`,
  and `clsag_sign` virtual methods from `device.hpp` and all implementations
  (`device_default.cpp`, `device_ledger.cpp`). Shekyl never supported CLSAG;
  the device interface now only exposes FCMP++ methods.

- **`get_outs` / `get_outs.bin` RPC endpoints.** Removed the ring member
  fetching endpoints from the C++ daemon (`core_rpc_server`), the FFI dispatch
  tables (`core_rpc_ffi.cpp`), and the Rust daemon RPC (`shekyl-daemon-rpc`).
  FCMP++ uses full-chain membership proofs; there is no decoy selection.

- **Dead hard fork constants.** Removed `HF_VERSION_MIN_MIXIN_4/6/10/15`,
  `HF_VERSION_SAME_MIXIN`, `HF_VERSION_ENFORCE_MIN_AGE`,
  `HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY`,
  `HF_VERSION_REJECT_SIGS_IN_COINBASE`, `HF_VERSION_ENFORCE_RCT`,
  `HF_VERSION_DETERMINISTIC_UNLOCK_TIME` from `cryptonote_config.h`. These
  were defined but never referenced in production code. `HF_VERSION_CLSAG`
  and `HF_VERSION_MIN_V2_COINBASE_TX` are retained for test compilation
  until Phase 7 rewrites the legacy tests.

### ✨ Added

- **Zstd compression for Levin P2P relay (Phase 6e).** P2P payloads above
  256 bytes are transparently compressed with zstd (level 1) before relay.
  A new `LEVIN_PACKET_COMPRESSED` flag (0x10) in the Levin header marks
  compressed frames. Peers negotiate compression via
  `P2P_SUPPORT_FLAG_ZSTD_COMPRESSION` (0x02) in the handshake support flags.
  Reduces relay bandwidth by ~10-20% for FCMP++ transactions, especially
  important for Tor/I2P connections. Compression is optional at compile time
  (requires libzstd); decompression always succeeds if the flag is set.

### 📚 Documentation

- **Updated `DAEMON_RPC_RUST.md`.** Fixed stale references to `get_outs.bin`
  and `get_curve_tree_root`; corrected endpoint counts and cutover test steps.

### 🐛 Fixed

- **`rct::key` missing `operator!=`.** Added `operator!=` to the `key`
  struct in `rctTypes.h`. The operator was present for cross-type
  comparisons (`rct::key` vs `crypto::public_key`) but not for
  `rct::key` vs `rct::key`, causing compilation failures on all
  platforms when comparing pseudo-outs to expected zero-commitments in
  the stake claim verification path.

- **MSVC `binary_archive` constructor mismatch.** Fixed `wallet2.cpp`
  to use `epee::strspan<std::uint8_t>` instead of `std::istringstream`
  for constructing `binary_archive<false>`, which MSVC could not resolve.

- **Memory leak on exception in PQC auth signing.** Added RAII scope
  guard for `ShekylPqcKeypair` buffers in `transfer_selected_rct`
  Phase C, ensuring Rust-allocated key material is freed even if
  `THROW_WALLET_EXCEPTION_IF` throws mid-loop.

- **Secret key material not wiped on KEM decapsulation failure.** The
  stack buffer in `process_new_transaction` KEM decapsulation is now
  wiped unconditionally (success or failure), preventing partial key
  material from lingering on the stack.

- **Shadowed `tx_extra_fields` variable in KEM decapsulation.** Removed
  redundant inner `tx_extra_fields` reference that shadowed the outer
  one in `process_new_transaction`, using the already-resolved outer
  reference instead.

### 🔄 Changed

- **Decoy selection functions are dead code.** `get_outs`,
  `tx_add_fake_output`, and `light_wallet_get_outs` in `wallet2.cpp` are
  no longer called from the active transfer path. They remain in the
  codebase for reference and will be removed in a follow-up cleanup.

- **Claim transaction indistinguishability (Phase 4 — CRITICAL).** Rewrote
  `wallet2::create_claim_transaction()` to produce privacy-preserving claim
  transactions that blend into the anonymity set:
  - Uses `RCTTypeFcmpPlusPlusPqc` with Bulletproofs+ range proofs instead
    of `RCTTypeNull` with plaintext amounts.
  - Adds a dummy change output (amount = 0) to match the standard 2-output
    transaction structure, preventing structural fingerprinting.
  - Performs hybrid KEM derivation (X25519 + ML-KEM-768) via
    `shekyl_fcmp_derive_pqc_keypair()` for per-output PQC keys instead of
    reusing the wallet master PQC key.
  - Embeds ML-KEM ciphertexts in `tx_extra` under tag `0x06` and
    `H(pqc_pk)` leaf hashes under new tag `0x07`.
  - Signs with per-output KEM-derived PQC keys, not the wallet-level key.
  - Sets deterministic pseudo-outs (`zeroCommit(claim_amount)`) for each
    stake claim input to satisfy the Bulletproofs+ balance check.

- **Consensus rejects `RCTTypeNull` for non-coinbase v3 transactions.**
  `check_tx_inputs` now enforces that only coinbase (`txin_gen`) may use
  `RCTTypeNull`. All other v3 transactions (including stake claims) must
  use `RCTTypeFcmpPlusPlusPqc` with confidential amounts. Claim
  transactions are validated within the FCMP++ handler with their own
  sub-path that verifies pseudo-out determinism, PQC ownership, and pool
  balance while skipping the membership proof (which is not applicable to
  `txin_stake_claim` inputs).

### ✨ Added

- **`TX_EXTRA_TAG_PQC_LEAF_HASHES` (`0x07`).** New `tx_extra` field
  (`tx_extra_pqc_leaf_hashes`) stores per-output `H(pqc_pk)` values —
  the 32-byte Blake2b-512 hashes of each output's derived ML-DSA-65
  public key. Used by curve tree insertion to commit the correct PQC
  ownership hash to each leaf instead of a zero placeholder.

- **Curve tree leaves use actual `H(pqc_pk)` from `tx_extra`.** The
  `collect_outputs` / `make_leaf` path in `blockchain_db.cpp` now extracts
  `H(pqc_pk)` values from the `0x07` tag, replacing the zero placeholder
  that was previously committed to the 4th leaf scalar. This enables the
  PQC ownership cross-check for stake claim verification.

- **Coinbase transactions emit `H(pqc_pk)` leaf hashes.** `construct_miner_tx`
  now derives per-output PQC keypairs via KEM shared secrets and includes
  their `H(pqc_pk)` values in the `0x07` `tx_extra` field alongside the
  existing KEM ciphertexts in `0x06`.

### 🔒 Security

- **Integer-only stake reward computation.** Replaced floating-point
  arithmetic (`(double)total_reward * weight / total_weighted_stake`) with
  128-bit integer math (`mul128`/`div128_64`) in `check_stake_claim_input`
  to eliminate rounding errors that could cause determinism mismatches
  across platforms.

- **Batch pool balance validation for stake claims.** Moved the staker
  pool balance check from per-claim (`check_stake_claim_input`) to a
  batch check in `check_tx_inputs` that sums all claim amounts first.
  Prevents multiple claims in the same block from independently passing
  the balance check and overdrawing the pool.

- **PQC ownership cross-check on stake claims.** Each `txin_stake_claim`
  now verifies that the `H(pqc_pk)` stored in the curve tree leaf (bytes
  96–128) matches `shekyl_fcmp_pqc_leaf_hash(pqc_auths[i].hybrid_public_key)`,
  preventing reward claims for outputs the claimer does not own the PQC
  key for.

### 🐛 Fixed

- **Stake claim key image cleanup on reorg.** `remove_transaction` in
  `blockchain_db.cpp` now handles `txin_stake_claim` key images in
  addition to `txin_to_key`, preventing stale key images from persisting
  after block pops.

### 🔄 Changed

- **Sorted input enforcement extended to stake claims.** The
  sorted-inputs check in `check_tx_inputs` now covers both `txin_to_key`
  and `txin_stake_claim` key images, ensuring consistent ordering rules
  across all input types.

- **Third-party headers treated as SYSTEM includes.** `external/`, `external/rapidjson`,
  `external/easylogging++`, and `external/supercop` are now `-isystem` in CMake,
  suppressing `-Wsuggest-override` and other warnings from third-party code while
  keeping strict warnings for first-party code.

### 🗑️ Removed

- **Dead `check_ring_signature` function.** Removed unused ring signature
  verification from `blockchain.cpp` and its declaration from
  `blockchain.h`. Shekyl uses FCMP++ from genesis; ring signatures are
  never validated.

- **Dead `expand_transaction_2` function.** Removed the no-op transaction
  expansion function from `blockchain.cpp` and its declaration from
  `blockchain.h`. FCMP++ does not use mixRing expansion.

- **Dropped `serde_json` dev-dependency from `shekyl-fcmp`.** Replaced the JSON
  round-trip test with a byte-level serialization check, reducing the dev-dep
  surface.

### 📚 Documentation

- Synced `docs/FCMP_PLUS_PLUS.md` curve-tree text with consensus: outputs are
  indexed at creation; maturity is enforced via `referenceBlock` and other
  rules, not by delaying leaf insertion.
- Clarified `docs/POST_QUANTUM_CRYPTOGRAPHY.md` to use `pqc_auths` (per-input)
  terminology consistently.
- Documented mempool FCMP verification-cache id: `compute_fcmp_verification_hash`
  binds proof + `referenceBlock` + key images (comment in `blockchain.cpp`).
- Noted the monero-oxide commit pin in `rust/shekyl-fcmp/Cargo.toml` comments
  (lockfile remains authoritative).
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` with integer arithmetic, batch
  pool check, PQC cross-check, and sorted input consensus rules.

### ✨ Added

- **Block-inclusion FCMP++ cache fast path.** When a transaction was previously
  verified in the mempool and arrives in a block, `check_tx_inputs` skips the
  expensive `shekyl_fcmp_verify` FFI call (~35ms/input) while still running all
  structural checks (referenceBlock, depth, key images, PQC auth).

- **`construct_leaf` now accepts PQC key hash parameter.** The Rust FFI
  function `shekyl_construct_curve_tree_leaf` takes a 4th `h_pqc_ptr` argument
  (32 bytes) to set the 4th leaf scalar.  Callers pass zero bytes until
  per-output PQC commitments are wired in Phase 3.

- **Deferred staked leaf insertion infrastructure.**
  Added `pending_staked_leaves` (LMDB DUPSORT/DUPFIXED table keyed by
  `lock_until_height` with 128-byte leaf values) and `pending_staked_drain`
  (block_height → drain count) tables to the blockchain database layer.
  Five new methods on `BlockchainDB`: `add_pending_staked_leaf`,
  `drain_pending_staked_leaves`, `set_pending_staked_drain_count`,
  `get_pending_staked_drain_count`, and `remove_pending_staked_drain_count`.
  This enables staked outputs whose `effective_lock_until > block_height` to be parked
  in a pending table and batch-inserted into the curve tree when they mature.

- **Comprehensive FCMP++ test suite and fuzz targets (Phase 7).**
  Added 6 `cargo-fuzz` targets across `rust/shekyl-fcmp/fuzz/` (proof
  deserialization, curve tree leaf hashing, block header tree root mismatch)
  and `rust/shekyl-crypto-pq/fuzz/` (Bech32m address decoding, KEM
  decapsulation with corrupted ciphertexts). Extended Rust unit tests in
  `proof.rs`, `tree.rs`, `leaf.rs`, `kem.rs`, `address.rs`, and
  `derivation.rs` covering prove/verify round-trips, hash grow/trim inverse
  properties, boundary values, and cross-crate consistency. Extended C++ unit
  tests in `tests/unit_tests/fcmp.cpp` with RCTTypeFcmpPlusPlusPqc
  serialization round-trip, key image y-normalization, referenceBlock
  staleness constants, and empty proof rejection. Added PQC rederivation
  criterion benchmark (`rust/shekyl-crypto-pq/benches/pqc_rederivation.rs`)
  targeting < 100ms per output for the full ML-KEM-768 decapsulation +
  HKDF-SHA-512 + ML-DSA-65 keygen pipeline.

- **Stressnet tooling for FCMP++ pre-audit gate (Phase 7.7).**
  Added `tests/stressnet/` with configuration, load generator, and monitoring
  scripts for a 4-week sustained-load testnet. The stressnet exercises curve
  tree growth, verification caching, wallet restore correctness, pruned vs.
  full node storage, staking lifecycle, and block validation latency under
  near-block-weight-limit load. Includes `config.yaml` with load profiles,
  `load_generator.py` for synthetic transaction submission, and `monitor.py`
  for real-time metric collection, consensus checking, and daily report
  generation.

- **Security audit scope document (Phase 9).**
  Added `docs/AUDIT_SCOPE.md` defining the scope for a third-party security
  review of the 4-scalar leaf circuit modification. Covers soundness,
  zero-knowledge, and completeness verification for the `H(pqc_pk)` extension,
  Shekyl fork modifications to monero-fcmp-plus-plus, PQC commitment binding,
  and the FFI verification boundary. Includes materials list, auditor guidance
  questions, success criteria, and timeline.

- **Mainnet gate: stressnet and audit prerequisites in release checklist.**
  Updated `docs/RELEASE_CHECKLIST.md` with "Stressnet stable for 4 consecutive
  weeks" and "4-scalar leaf circuit audit completed" as hard prerequisites
  for mainnet launch.

### 🔄 Changed

- **Renamed `src/ringct/` to `src/fcmp/` for naming consistency.**
  Shekyl does not use ring signatures; the directory now reflects the actual
  FCMP++ confidential transaction system.  CMake targets renamed from
  `ringct`/`ringct_basic` to `fcmp`/`fcmp_basic`.  All `#include "ringct/..."`
  paths updated across 44 source and test files.  Log categories, user-facing
  strings ("RingCT" → "FCMP"), JSON keys, and documentation updated.
  The `rct::` namespace is preserved for now as a separate future rename.

- **Unified coinbase transaction version to v3.**
  `construct_miner_tx` and `build_genesis_coinbase_from_destinations` now emit
  `tx.version = 3`, matching regular FCMP++ transactions.  All `miner_tx &&
  tx.version == 2` checks have been widened to `>= 2` across `blockchain_db`,
  `blockchain`, `wallet2`, and test infrastructure.  The `pqc_auths`
  serialization gate (`!txin_gen`) already excluded coinbase, so v3 coinbase
  serializes identically to v2 minus the version byte.

### 🐛 Fixed

- **Fixed wallet API compilation errors after ring-signature removal.**
  `wallet/api/wallet.cpp` still referenced the undefined `fake_outs_count`
  variable and called `estimate_fee` with the old 12-argument signature.
  Replaced `fake_outs_count` with `0` (FCMP++ has no decoys) and updated
  `estimateTransactionFee` to use the simplified 8-argument `estimate_fee`
  signature with hardcoded `use_per_byte_fee=true`, `use_rct=true`,
  `use_view_tags=true`.

- **Fixed CI build failure from removed legacy RCT types in test files.**
  Stripped all references to removed `rct::Bulletproof`, `rct::RCTConfig`,
  `rct::RangeProofType`, `rct::RCTTypeBulletproofPlus`, `rct::clsag`,
  `rct::proveRctCLSAGSimple`/`verRctCLSAGSimple`, and `rct::genRctSimple`
  from: `chaingen.h`/`.cpp`, `bulletproof_plus.cpp`/`.h`, `chain_switch_1.cpp`,
  `wallet_tools.h`/`.cpp`, `bulletproofs.cpp` (unit), `ringct.cpp` (unit),
  `serialization.cpp` (unit), `ver_rct_non_semantics_simple_cached.cpp`,
  `json_serialization.cpp`, `fuzz/bulletproof.cpp`, and all performance test
  headers.  Removed legacy-only test cases; updated shared test helpers to drop
  `RangeProofType`/`bp_version` parameters.

### 🗑️ Removed

- **Dead verification cache code (`verRctNonSemanticsSimple`, `ver_rct_non_semantics_simple_cached`).**
  Removed the stub `verRctNonSemanticsSimple` from `rctSigs.cpp/.h` (returned `true`
  unconditionally), the `ver_rct_non_semantics_simple_cached` wrapper and its
  `ver_rct_non_sem` helper from `tx_verification_utils.cpp/.h`, the unused
  `rct_ver_cache_t` type alias and `m_rct_ver_cache` member from `Blockchain`,
  and the dead `RCT_CACHE_TYPE` constant from `check_tx_inputs`.  Real FCMP++
  verification lives in `check_tx_inputs` (blockchain.cpp) and the mempool
  uses `compute_fcmp_verification_hash` for caching.

### 🔒 Security

- **CRITICAL: PQC signed payload now binds to prunable FCMP++ data (Phase 4c).**
  `get_transaction_signed_payload` now includes `H(serialize(RctSigPrunable))`
  in the signed payload, binding PQC signatures to the FCMP++ proof, pseudoOuts,
  curve_trees_tree_depth, and Bulletproofs+.  Without this, an attacker could
  substitute different prunable data without invalidating PQC signatures,
  breaking the dual-layer security model.

- **CRITICAL: Wired stake claim validation in `check_tx_inputs` (Phase 4e audit fix).**
  The non-FAKECHAIN gate in `check_tx_inputs` rejected all `RCTTypeNull`
  transactions, which includes pure stake-claim txs.  The gate now allows
  `RCTTypeNull` transactions through when all inputs are `txin_stake_claim`.
  Additionally, the `RCTTypeNull` switch case now calls `check_stake_claim_input`
  for each claim input and checks key image double-spend — previously it
  `break`ed without any validation.

- **HIGH: Bound all inputs' H(pqc_pk) hashes into PQC signed payload.**
  `get_transaction_signed_payload` now appends `H(pqc_pk_0) || ... || H(pqc_pk_{N-1})`
  after the per-input header blob, preventing key-substitution attacks where an
  attacker replaces one input's PQC key without invalidating other signatures.

- **MEDIUM: Stake claim curve tree leaf verification (Phase 4e).**
  `check_stake_claim_input` now verifies the staked output's leaf is present
  in the curve tree by checking `staked_output_index < get_curve_tree_leaf_count()`
  and reading the leaf with `get_curve_tree_leaf()`.  Previously, only the
  lock period check was performed, which didn't guarantee the leaf had been
  inserted into the tree.

- **MEDIUM: PQC `auth_version` and `flags` consensus enforcement.**
  `verify_transaction_pqc_auth` now rejects `auth_version != 1` and
  `flags != 0`, enforcing spec steps 6a/6c. Previously these fields were
  serialized and signed over but never validated.

- **LOW: Single-signer `hybrid_public_key` size enforcement.**
  `verify_transaction_pqc_auth` now verifies single-signer key blobs are
  exactly `HYBRID_SINGLE_KEY_LEN` (1996 bytes). Previously only multisig
  keys had size bounds checks; single-signer keys relied solely on the FFI
  call to reject malformed keys.

- **LOW: Added deserialization size bounds for `pqc_authentication` blobs.**
  `hybrid_public_key` and `hybrid_signature` vectors are now rejected during
  deserialization if they exceed `PQC_MAX_PUBLIC_KEY_BLOB` or
  `PQC_MAX_SIGNATURE_BLOB`, preventing memory-exhaustion attacks via
  oversized PQC fields.

### 🐛 Fixed

- **HIGH: Fixed `pop_block()` off-by-one for staked-output curve tree removal.**
  The height used for staked-output eligibility checking was captured *after*
  `remove_block()`, using the post-pop height instead of the removed block's
  height.  This caused a mismatch with `add_block()`'s logic: outputs added at
  the exact lock boundary were inserted during add but not removed during pop,
  leaving orphaned leaves in the curve tree.

- **HIGH: Fixed `pseudoOuts` serialization mismatch in generic `rctSigBase`.**
  The generic `BEGIN_SERIALIZE_OBJECT()` path in `rctSigBase` unconditionally
  included `pseudoOuts`, even for `RCTTypeFcmpPlusPlusPqc` where pseudo-outs
  live in the prunable section.  Now gated with
  `if (type != RCTTypeFcmpPlusPlusPqc)` to match the custom serializer.

- **MEDIUM: `get_curve_tree_path` RPC now fails on missing layer hashes.**
  Previously, a failed `get_curve_tree_layer_hash()` silently inserted zeros
  into the proof path, potentially generating invalid proofs from inconsistent
  DB state.  Now returns `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`.



- **CRITICAL: Fixed incorrect existing_child in internal layer hash propagation**
  (`grow_curve_tree`).  When updating an existing child chunk's hash, the
  parent's Pedersen commitment was computed with `existing_child = 0` instead of
  the previous cycle-scalar.  This produced wrong chunk hashes for any block
  that updated (rather than created) a child chunk.  The fix tracks both old and
  new hashes through `updated_chunk_t` and passes the previous cycle-scalar to
  `hash_grow`.

- **CRITICAL: Replaced O(N) `trim_curve_tree` with incremental `hash_trim`.**
  Reorgs previously read all remaining leaves, cleared the tree, and rebuilt
  from scratch — a liveness risk at scale.  The new implementation uses
  `hash_trim_selene`/`hash_trim_helios` FFI to surgically update only the
  affected chunks, then propagates the old→new deltas up through internal layers.
  Complexity is now O(removed × log N).

- **CRITICAL: Enforced output maturity via `FCMP_REFERENCE_BLOCK_MIN_AGE`.**
  Outputs enter the curve tree at creation time (maximising the anonymity set).
  Maturity is enforced at spending time by requiring the reference block to be
  at least `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) blocks behind the tip.
  Added `static_assert`s in `cryptonote_config.h` to prevent regression.

- **HIGH: Validated meta reads in `save_curve_tree_checkpoint`.**  The function
  now checks that root, depth, and leaf_count were all successfully read from
  meta before storing a checkpoint.  If any value is missing or leaf_count is 0,
  the checkpoint is skipped with a log warning instead of storing a corrupt
  zero-valued checkpoint.

### 🔄 Changed

- **Consensus: `curve_trees_tree_depth` validation now accepts `<= current`.**
  The referenceBlock's tree may have fewer layers than the current tip (depth
  is monotonically non-decreasing).  The strict `!=` check was replaced with a
  range check `(0, current_depth]`, and the FCMP++ proof verifier provides the
  authoritative depth validation.

- **Consensus: Removed ring-based validation path from `check_tx_inputs`.**
  Shekyl starts at genesis with FCMP++; the legacy ring-signature per-input
  validation is unreachable dead code.  The `else` branch now immediately
  rejects non-FCMP++ transactions with a clear error message.

- **Coinbase KEM: Added warning when miner address lacks PQC public key.**
  If a miner's address has no PQC key at the FCMP++ hard fork, a warning is
  logged noting that the output will have `H(pqc_pk) = 0` in the curve tree —
  a distinguishable pattern.

- **RPC: Replaced hardcoded chunk widths with FFI calls.**
  `get_curve_tree_path` now calls `shekyl_curve_tree_selene_chunk_width()` and
  `shekyl_curve_tree_helios_chunk_width()` instead of using static constants.

- **RPC: Added `reference_height` and `leaf_count` to `get_curve_tree_path`
  response.**  Wallets can now verify response freshness and detect stale paths
  without parsing the reference block hash.

- **RPC: Added `MAX_OUTPUTS_PER_RPC_REQUEST` (64) rate limit** to
  `get_curve_tree_path` to prevent abuse from unbounded requests.

### ✨ Added

- **RPC: `get_curve_tree_info` endpoint** returns root hash, depth, leaf count,
  and chain height for the current curve tree state.

- **RPC: `get_curve_tree_checkpoint` endpoint** retrieves a stored checkpoint
  (root, depth, leaf_count) at a given block height, needed for fast-sync.

### 📚 Documentation

- Documented `verRctNonSemanticsSimple` stub status: the FCMP++ membership
  proof is verified in the main consensus path (`check_tx_inputs`), not in the
  verification-caching path.  Added TODO for Phase 5 unification.
- ~~Documented coinbase `tx.version = 2` rationale~~ — superseded: coinbase
  is now version 3, unified with regular transactions.
- Documented LMDB post-delete cursor contract (`MDB_GET_CURRENT` after
  `mdb_cursor_del` returns the next item) in pruning and GC loops.
- Added `ct_layer_chunk_key` bit-layout comment explaining the 8-bit layer /
  56-bit chunk index encoding for LMDB integer keys.
- Documented `construct_leaf` zero 4th scalar (H(pqc_pk)) and the tree rebuild
  requirement when PQC per-output keys are activated.
- Documented depth tracking semantics (root layer index, not layer count) and
  root detection invariant in `grow_curve_tree`.
- Added TODO for async/batched checkpoint+pruning in `add_block`.
- Documented `get_curve_tree_root` empty-tree return semantics (returns
  `hash_init`, callers should check `leaf_count`).

### 🗑️ Removed

- **Legacy RCT and mixin references stripped from wallet layer.** Completed
  the wallet-side refactor removing all references to legacy ring sizes,
  `adjust_mixin`, `default_mixin`, `m_default_mixin`, `RCTConfig`, and
  mixin-count parameters:
  - `wallet2.h`: Removed `estimate_fee` mixin/bulletproof/clsag params,
    `adjust_mixin()`, `default_mixin()` getter/setter, `m_default_mixin`
    member, `rct_config` from `pending_tx` and `transfer_selected_rct`.
  - `wallet2.cpp`: Removed mixin from `estimate_rct_tx_size`,
    `estimate_tx_size`, `estimate_tx_weight`, `estimate_fee` signatures
    and all call sites. Removed `adjust_mixin()` definition, JSON
    serialization of `default_mixin`, constructor initialization. Removed
    `const bool clsag/bulletproof/bulletproof_plus = true` patterns.
  - `wallet_errors.h`: Removed `mixin_count` field from
    `not_enough_outs_to_mix` error struct.
  - `wallet2_ffi.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet_rpc_server.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet2_api.h`, `wallet.h`, `wallet.cpp`: Removed `mixin_count`
    parameter from `createTransaction` and `createTransactionMultDest`.
  - `unsigned_transaction.cpp`: Simplified `mixin()` and `minMixinCount()`
    to always return 0 (FCMP++ has no explicit mixin).
  - `simplewallet.cpp`: Removed ring-size parsing, `adjust_mixin` calls,
    and `default_mixin` display. All fake_outs_count set to 0.
- **Legacy RCT references stripped from all src/ files.** Removed all
  remaining references to CLSAG, legacy RCT types, `RCTConfig`, `mixRing`,
  and `low_mixin` from device drivers, Trezor protocol, RPC handlers,
  blockchain verification, transaction utilities, wallet, and serialization:
  - `device_ledger.cpp`: Removed `INS_CLSAG` define, legacy type branches
    in `mlsag_prehash`, replaced `clsag_prepare`/`clsag_hash`/`clsag_sign`
    with FCMP++ TODO stubs.
  - `protocol.cpp`/`protocol.hpp` (Trezor): Removed `rct::Bulletproof`
    variant, `is_simple()`/`is_req_bulletproof()`/`is_bulletproof()`/
    `is_clsag()` helpers, `mixRing` resize, CLSAG deserialization in
    `step_final_ack`. Added `is_fcmp_pp()` helper.
  - `core_rpc_server.cpp`/`core_rpc_server_commands_defs.h`: Removed
    `low_mixin` field and its assignment from send_raw_tx response.
  - `daemon_handler.cpp`: Removed `m_low_mixin` error branch.
  - `verification_context.h`: Removed `m_low_mixin` from
    `tx_verification_context`.
  - `blockchain.cpp`: Replaced legacy mixin-checking branch with a reject
    gate for non-FCMP++ transactions (Shekyl only supports FCMP++).
  - `cryptonote_tx_utils.h`/`.cpp`: Removed `rct::RCTConfig` parameter
    from `construct_tx_with_tx_key` and `construct_tx_and_get_tx_key`.
    Replaced `genRctSimple` call with FCMP++ proof generation stub.
    Removed `mixRing` construction.
  - `cryptonote_format_utils.cpp`: Removed `is_rct_bulletproof`/
    `is_rct_clsag` calls, simplified BP+ weight calculations.
  - `cryptonote_boost_serialization.h`: Removed serialization functions
    for `rct::rangeSig`, `rct::Bulletproof`, `rct::mgSig`, `rct::clsag`,
    `rct::RCTConfig`, `rct::boroSig`. Simplified `rctSigBase` and
    `rctSigPrunable` serialization to only handle FCMP++.
  - `tx_verification_utils.h`/`.cpp`: Removed `mix_ring` parameter from
    `ver_rct_non_semantics_simple_cached`. Removed `expand_tx_and_ver_rct_non_sem`,
    `calc_tx_mixring_hash`, and `is_canonical_bulletproof_layout`.
  - `json_object.h`/`.cpp`: Removed JSON serialization for `rct::rangeSig`,
    `rct::Bulletproof`, `rct::boroSig`, `rct::mgSig`, `rct::clsag`.
    Removed legacy prunable fields from `rctSig` JSON output.
  - `wallet2.h`: Removed `rct_config` field from `tx_construction_data`
    serialization and the version-gated `RangeProofPaddedBulletproof`
    defaults in Boost serialization.
  - `wallet2.cpp`: Fixed `construct_tx_and_get_tx_key` call site that
    still passed `{}` where the removed `rct_config` parameter was.
  - `bulletproofs.h`/`.cc`: Gutted non-plus Bulletproof PROVE/VERIFY
    functions — the `rct::Bulletproof` struct was already removed from
    `rctTypes.h`, making these 1000+ lines of dead code.
- **Legacy RCT types stripped from core.** Removed `RCTTypeFull` (1),
  `RCTTypeSimple` (2), `RCTTypeBulletproof` (3), `RCTTypeBulletproof2` (4),
  `RCTTypeCLSAG` (5), and `RCTTypeBulletproofPlus` (6) from the enum.
  Only `RCTTypeNull` (0) and `RCTTypeFcmpPlusPlusPqc` (7) remain.
- Deleted structs: `mgSig`, `clsag`, `rangeSig`, `Bulletproof` (non-plus),
  `RangeProofType` enum, and `RCTConfig`.
- Removed `mixRing` member from `rctSigBase` and `mixin` parameter from
  `serialize_rctsig_prunable`.
- Removed from `rctSigPrunable`: `rangeSigs`, `bulletproofs` (non-plus),
  `MGs`, `CLSAGs` vectors and their serialization blocks.
- Removed functions: `CLSAG_Gen`, `proveRctCLSAGSimple`,
  `verRctCLSAGSimple`, `genRctSimple` (both overloads),
  `populateFromBlockchainSimple`, `getKeyFromBlockchain`,
  `is_rct_simple`, `is_rct_bulletproof`, `is_rct_borromean`, `is_rct_clsag`,
  `proveRangeBulletproof`, `verBulletproof`, `make_dummy_bulletproof`,
  `make_dummy_clsag`.
- Removed `HASH_KEY_CLSAG_ROUND`, `HASH_KEY_CLSAG_AGG_0`,
  `HASH_KEY_CLSAG_AGG_1`, and `HASH_KEY_TXHASH_AND_MIXRING` from
  `cryptonote_config.h`.
- Removed VARIANT_TAG entries for `mgSig`, `rangeSig`, `Bulletproof`,
  and `clsag`.
- Simplified `get_pre_mlsag_hash` to only handle `RCTTypeFcmpPlusPlusPqc`.
- Simplified `verRctSemanticsSimple` and `verRctNonSemanticsSimple` to
  only accept FCMP++ transactions (no CLSAG/ring verification path).

### 🔄 Changed

- **FCMP++ Phase 3: Per-input PQC authorization vector.** Replaced
  `std::optional<pqc_authentication> pqc_auth` with
  `std::vector<pqc_authentication> pqc_auths` on `cryptonote::transaction`
  (one `pqc_authentication` per input). Updated binary, Boost, and JSON
  serialization, transaction hash (`cn_fast_hash` of serialized
  `pqc_auths`), per-input PQC verification, and wallet/RPC signing paths.

### ✨ Added

- **FCMP++ (Full-Chain Membership Proofs): complete implementation across
  Phases 1–6.**
  Shekyl replaces ring signatures (CLSAG) with FCMP++ from genesis. Every
  spend proves membership in the entire UTXO set via a Helios/Selene curve
  tree, giving every transaction full-chain anonymity instead of 16-decoy
  ring ambiguity. Combined with hybrid post-quantum spend authorization
  (Ed25519 + ML-DSA-65), this makes Shekyl the first cryptocurrency to offer
  full-UTXO-set anonymity with quantum-resistant ownership.

  Key components delivered:
  - **Rust foundation (Phase 1):** `shekyl-fcmp` crate wrapping upstream
    `monero-fcmp-plus-plus` with 4-scalar leaf type `{O.x, I.x, C.x,
    H(pqc_pk)}`. Hybrid X25519 + ML-KEM-768 KEM with HKDF-SHA-512.
    Bech32m segmented address encoding. Per-output PQC key derivation.
    15 FFI exports. Security audit (zero vulnerabilities, zero unsafe in
    first-party code). Reproducible builds with pinned Cargo.lock.
  - **Transaction format (Phase 3):** `RCTTypeFcmpPlusPlusPqc = 7` with
    `referenceBlock`, `curve_trees_tree_depth`, and `fcmp_pp_proof` fields.
    `curve_tree_root` commitment in every block header.
  - **Consensus verification (Phase 4):** 7-step verification order in
    `check_tx_inputs` — referenceBlock age, tree depth, key image
    y-normalization, FCMP++ proof via Rust FFI, PQC signature verification,
    BP+ range proofs. Mempool verification caching (`fcmp_verification_hash`
    in `txpool_tx_meta_t`). Staked output curve-tree leaves.
  - **Curve tree database (Phase 2):** Full `get_curve_tree_path` RPC
    implementation assembling real Merkle paths (leaf scalars + per-layer
    sibling hashes with position encoding). Selective pruning of
    intermediate tree layers between checkpoints, wired into `add_block`
    after `save_curve_tree_checkpoint`. Old checkpoint garbage collection.
  - **Wallet integration (Phase 5):** `genRctFcmpPlusPlus()` proof
    construction. `get_curve_tree_path` RPC. Tree-path precomputation
    and incremental update in wallet refresh loop. PQC key rederivation from
    stored shared secret. Restore-from-seed PQC rederivation.
  - **Infrastructure (Phase 6):** Hardware device FCMP++ stubs. CI pipeline
    for Rust workspace build, FCMP crate, determinism check, Bech32m tests.
    `output_pruning_metadata_t` and `m_output_metadata` LMDB table for
    transaction pruning. LMDB curve tree schema (leaves, layers, meta,
    checkpoints). Checkpoint every 10,000 blocks for fast-sync resumption.

  See `docs/FCMP_PLUS_PLUS.md` for the full specification.

- **FCMP++ Phase 3: KEM ciphertext `tx_extra` and coinbase self-encapsulation.**
  - `tx_extra_pqc_kem_ciphertext` with tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
    (`0x06`): payload `blob` is the concatenation of N ML-KEM-768 ciphertexts
    (1088 bytes each), one per output in order.
  - **Coinbase:** When the miner address has a PQC key and the hard-fork
    version is at least `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `construct_miner_tx`
    performs KEM self-encapsulation to the miner’s own address per coinbase
    output (same tag and derivation semantics as normal transfers), then
    wipes the shared secret after use.

- **FCMP++ Phase 5e: Wallet precomputation of curve tree paths.**
  - Added `fcmp_precomputed_path` struct to `wallet2.h` caching per-output
    tree path, root hash at precompute time, and precompute height.
  - Added `m_fcmp_precomputed_paths` runtime cache (not serialized) and
    `m_fcmp_last_precompute_height` watermark to `wallet2`.
  - `precompute_fcmp_paths()` fetches tree paths for all unspent outputs
    via the `get_curve_tree_path` daemon RPC endpoint.
  - `update_fcmp_paths_incremental(new_height)` extends existing paths
    and adds newly discovered outputs, pruning paths for spent outputs.
  - Incremental path update is hooked into the wallet refresh loop,
    triggering after sync catches up if blocks were fetched.
  - Progress callbacks (`on_fcmp_path_precompute_progress`) fire during
    both initial and incremental precomputation.
- **FCMP++ Phase 5.5: Wallet sync and restore-from-seed PQC support.**
  - `transfer_details::m_combined_shared_secret` (64 bytes) stores the
    hybrid KEM shared secret needed to rederive per-output PQC keys.
  - `rederive_pqc_keys_for_output(td)` calls `shekyl_fcmp_derive_pqc_keypair`
    via FFI to validate keypair derivation from stored shared secret.
  - `rederive_all_pqc_keys()` iterates all transfers with stored shared
    secrets and rederives PQC keys, with progress callback
    `on_pqc_rederivation_progress`.
  - Restore-from-seed triggers full PQC key rederivation on first refresh
    after sync completes.

### 🐛 Fixed

- **Curve tree pop_block over-trim:** `pop_block` previously counted all
  `tx.vout` entries when computing how many leaves to trim, but `add_block`
  skips outputs that fail type checks (unknown target types), locked staked
  outputs, and outputs whose FFI leaf construction fails. The trim count now
  mirrors the same filtering logic used in the grow path, preventing tree
  desynchronization during reorgs.
- **Curve tree pruning correctness:** `prune_curve_tree_intermediate_layers`
  was deleting all intermediate layer entries instead of selectively pruning
  only chunks fully below the previous checkpoint boundary. Fixed to compute
  the chunk boundary from the previous checkpoint's `leaf_count` and only
  remove sealed entries. Also added garbage collection of stale checkpoint
  records (only the two most recent are kept).
- **LMDB output metadata: removed undefined behavior in cursor macros.**
  - `store_output_metadata` now uses `mdb_put` directly with `m_write_txn`
    instead of the `CURSOR()` macro which required `m_cursors` to be in
    scope.
  - `get_output_metadata` and `prune_tx_data` now use `m_txn` (from
    `TXN_PREFIX_RDONLY`) instead of `txn_ptr` (from `TXN_PREFIX`).
  - Removed unused `m_txc_output_metadata` cursor field and
    `m_cur_output_metadata` macro from `db_lmdb.h`.
- **Wallet FCMP++ path precomputation: fixed undefined behavior.**
  - Replaced `reinterpret_cast<std::string&>` on `std::vector<uint8_t>` with
    a proper intermediate `std::string` copy in both `precompute_fcmp_paths`
    and `update_fcmp_paths_incremental`.

- **FCMP++ Phase 6c: CI pipeline updates.**
  - Added x86_64 architecture verification step to the `rust-audit-and-test`
    CI job in `.github/workflows/build.yml`.
  - Added explicit `cargo build --locked -p shekyl-fcmp` step to verify the
    FCMP++ crate builds as part of the Rust workspace.
  - Added dedicated Bech32m address encoding test step that runs
    `shekyl-crypto-pq` address tests with visible CI output.
  - The monero-oxide git dependency is cached via `~/.cargo/git` in the
    existing Cargo cache key (`rust-${{ hashFiles('rust/Cargo.lock') }}`).
  - Determinism check (build twice, diff `libshekyl_ffi.a` hashes) and
    `cargo audit` remain in place.
- **FCMP++ Phase 6f: Transaction pruning mode (skeleton).**
  - Added `output_pruning_metadata_t` packed struct to `blockchain_db.h`
    storing per-output scan data (pubkey, commitment, unlock_time, height,
    pruned flag) for wallet scanning after transaction pruning.
  - Added abstract interface in `BlockchainDB`: `store_output_metadata()`,
    `get_output_metadata()`, `is_output_pruned()`, `prune_tx_data()`.
  - Added `m_output_metadata` LMDB table (keyed by `global_output_index`)
    in `db_lmdb.h` and `db_lmdb.cpp` with cursor, rflag, and DBI member.
  - LMDB implementation: `store_output_metadata` and `get_output_metadata`
    are fully wired; `is_output_pruned` delegates to `get_output_metadata`;
    `prune_tx_data` validates depth against `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`
    and reads/writes a `last_pruned_tx_data_height` watermark in the
    properties table to skip already-processed blocks on subsequent runs.
    The block-iteration pruning loop is documented as a TODO skeleton.
  - `--prune-blockchain` CLI flag now also triggers `prune_tx_data()` in
    `cryptonote_core.cpp`, running output-metadata pruning alongside
    Monero's existing stripe-based pruning.
  - Test DB (`testdb.h`) updated with no-op stubs for all four new methods.
- **FCMP++ Phase 4b: Mempool verification caching.**
  - Added `fcmp_verification_hash` (32-byte `crypto::hash`) and
    `fcmp_verified` (1-bit flag) to `txpool_tx_meta_t` in
    `src/blockchain_db/blockchain_db.h`, carved from the existing
    76-byte padding (now 44 bytes).  Struct stays 192 bytes.
  - New `Blockchain::compute_fcmp_verification_hash()` computes a
    deterministic cache key from `hash(proof || referenceBlock || key_images)`.
  - `tx_memory_pool::add_tx` stores the cache hash on successful FCMP++
    verification.
  - `tx_memory_pool::is_transaction_ready_to_go` checks the cached hash
    via `is_fcmp_verification_cached()` and seeds `m_input_cache` to
    skip re-running `shekyl_fcmp_verify()` for previously-verified
    mempool transactions.
  - Added `static_assert` guards at the `memcmp` site on
    `txpool_tx_meta_t` (tx_pool.cpp line 1656) enforcing
    trivially-copyable layout and 192-byte struct size.
  - All padding and new fields are zero-initialized at every meta
    construction site.
- **FCMP++ Phase 4e: Staking consensus rules for FCMP++.**
  - `collect_outputs` in `blockchain_db.cpp::add_block` now handles
    `txout_to_staked_key` outputs using the same 4-scalar leaf format
    `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Deferred insertion: staked outputs only enter the curve tree when
    `block_height >= effective_lock_until`.  Outputs still within their lock
    period are stored in the `pending_staked_leaves` DB table and
    inserted into the curve tree when they mature (see deferred
    staked leaf insertion entry below).
  - `check_stake_claim_input` validates claims against the staked output's
    `effective_lock_until` (`creation_height + tier_lock_blocks`) and enforces
    `to_height <= min(current_height, effective_lock_until)`.
- **FCMP++ Phase 5: Wallet transaction construction skeleton.**
  - Added `rct::genRctFcmpPlusPlus()` in `src/fcmp/rctSigs.cpp` — builds
    an FCMP++ `rctSig` with `RCTTypeFcmpPlusPlusPqc`, Bulletproofs+ range
    proofs, balanced pseudo-outputs, and invokes `shekyl_fcmp_prove()` via
    FFI to generate the membership proof.
  - Declared the new function in `src/fcmp/rctSigs.h`.
  - Added `COMMAND_RPC_GET_CURVE_TREE_PATH` RPC command in
    `src/rpc/core_rpc_server_commands_defs.h` — accepts output indices and
    returns Merkle paths from the curve tree (stub handler for now).
  - Wired `get_curve_tree_path` JSON-RPC endpoint in
    `src/rpc/core_rpc_server.h` and `src/rpc/core_rpc_server.cpp`.
  - Added TODO scaffolding in `src/wallet/wallet2.cpp` at the decoy
    selection (`get_outs`), transaction construction
    (`construct_tx_and_get_tx_key`), and fee estimation
    (`estimate_tx_weight`) sites, documenting how FCMP++ replaces ring
    signatures in the wallet transfer flow.
- **FCMP++ Phase 6a: Hardware device stubs.**
  - Added `fcmp_prepare`, `fcmp_proof_start`, and `fcmp_proof_add_input`
    virtual methods to `hw::device` (base class) with default `return false`
    implementations for unsupported devices.
  - Software device (`device_default`) returns `true` (scaffolding for Rust
    FFI delegation).
  - Ledger device (`device_ledger`) logs an informative error and returns
    `false`, guiding users to software wallets until Ledger firmware gains
    FCMP++ support.
  - Trezor inherits the base-class defaults (unsupported) without code changes.
  - Updated `RELEASE_CHECKLIST.md` to document hardware wallet readiness status.
- **FCMP++ Phase 4a: Verification in `check_tx_inputs`.**
  - Added `RCTTypeFcmpPlusPlusPqc` verification path in
    `Blockchain::check_tx_inputs` (`src/cryptonote_core/blockchain.cpp`).
  - `referenceBlock` age validation: confirmed within
    `[tip - MAX_AGE, tip - MIN_AGE]` using DB block lookup.
  - `curve_trees_tree_depth` validated against the current tree state.
  - Key offsets verified empty for all FCMP++ inputs.
  - Key image y-normalization enforced (sign bit of byte 31 cleared).
  - Input count bounded by `FCMP_MAX_INPUTS_PER_TX`.
  - `shekyl_fcmp_verify()` FFI call wired up with key images, pseudo
    outputs, and proof blob.
  - Per-input `pqc_auths` verification left as documented TODO pending
    the per-input auth field migration.
- **FCMP++ Phase 4a-pre: PQC auth binding specification.**
  - New `docs/FCMP_PLUS_PLUS.md` formally documents the dual-layer
    binding model, per-input signed payload layout, and 7-step consensus
    verification order for `RCTTypeFcmpPlusPlusPqc` transactions.
- **FCMP++ Phase 3.5: Curve tree root in block header (consensus-critical).**
  - Added `curve_tree_root` (`crypto::hash`) field to `block_header` in
    `src/cryptonote_basic/cryptonote_basic.h`, initialized to `null_hash`.
  - Field is always serialized (genesis-native, no version gating) in both
    the binary archive (`BEGIN_SERIALIZE`) and Boost serialization.
  - Block template creation (`Blockchain::create_block_template`) snapshots
    the current DB curve tree root into the header.
  - Block validation (`Blockchain::handle_block_to_main_chain`) verifies
    `curve_tree_root` matches the locally-computed tree root after
    `add_block` grows the tree; rejects the block on mismatch.
  - RPC `block_header_response` now includes `curve_tree_root` hex string.
  - Test generator (`chaingen.cpp`) sets `curve_tree_root` to `null_hash`
    in `construct_block` and `construct_block_manually`.
- **FCMP++ Phase 3: Transaction format for FCMP++ PQC.**
  - Added `RCTTypeFcmpPlusPlusPqc = 7` to the RCT type enum in
    `src/fcmp/rctTypes.h` — Shekyl's only non-coinbase transaction type.
  - Added `referenceBlock` (block hash anchoring the curve tree snapshot)
    to `rctSigBase`, serialized only for the new type.
  - Added `curve_trees_tree_depth` and `fcmp_pp_proof` (opaque FCMP++ proof
    blob) to `rctSigPrunable`, replacing CLSAG ring signatures for the new type.
  - Added `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (0x06) to `tx_extra.h` for
    per-output ML-KEM-768 ciphertexts.
  - Added `key_image_y_normalize()` to `crypto.h`/`crypto.cpp` — clears the
    sign bit of a key image's y-coordinate as required by FCMP++.
  - Added `is_rct_fcmp_pp_pqc()` helper to `rctTypes.h`/`rctTypes.cpp`.
  - Updated serialization helpers (`serialize_rctsig_base`,
    `serialize_rctsig_prunable`) and type classifier functions
    (`is_rct_simple`, `is_rct_bulletproof_plus`) to handle the new type.
- **FCMP++ Phase 2e: Curve tree checkpoint strategy.**
  - New `BlockchainDB` virtual methods: `save_curve_tree_checkpoint`,
    `get_curve_tree_checkpoint`, `get_latest_curve_tree_checkpoint_height`,
    `prune_curve_tree_intermediate_layers`.
  - LMDB implementation with `curve_tree_checkpoints` table (MDB_INTEGERKEY),
    storing root[32] + depth[1] + leaf_count[8] per checkpoint.
  - Automatic checkpoint every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (10 000)
    blocks during `add_block`, enabling fast-sync resumption.
  - Configurable interval via `cryptonote_config.h` constant.
- **FCMP++ Phase 2f: Curve tree pruning strategy.**
  - `prune_curve_tree_intermediate_layers` removes recomputable internal hash
    layers between checkpoints, preserving leaves and the root layer to reduce
    storage overhead.
- **FCMP++ Phase 1: Rust foundation crates.**
  - New `rust/shekyl-fcmp/` crate wrapping upstream `monero-fcmp-plus-plus`
    (from `Shekyl-Foundation/monero-oxide` fork, `fcmp++` branch) with
    4-scalar curve tree leaf type `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Implemented `HybridX25519MlKem` (X25519 + ML-KEM-768 FIPS 203) in
    `shekyl-crypto-pq/src/kem.rs` with HKDF-SHA-512 shared-secret
    combination and master-seed key derivation.
  - Implemented Bech32m segmented address encoding
    (`shekyl1<classical>/skpq1<pqc_a>/skpq21<pqc_b>`) in
    `shekyl-crypto-pq/src/address.rs`, keeping each segment within
    Bech32m's proven checksum range.
  - Implemented per-output PQC keypair derivation (HKDF-Expand → ML-DSA-65
    deterministic keygen) in `shekyl-crypto-pq/src/derivation.rs`.
  - Added 15 new FFI exports to `shekyl-ffi` for FCMP++ proofs, KEM
    operations, address encoding, and seed derivation.
  - Added FCMP++ consensus constants to `cryptonote_config.h`:
    `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `FCMP_REFERENCE_BLOCK_MAX_AGE` (100),
    `FCMP_REFERENCE_BLOCK_MIN_AGE` (2), `FCMP_MAX_INPUTS_PER_TX` (8).
  - Updated `BuildRust.cmake` with `--locked` flag for reproducible builds.
- **FCMP++ Phase 1a.1: Security review of forked monero-oxide crates.**
  - `cargo audit`: 226 crate dependencies scanned, zero vulnerabilities found.
  - `unsafe` block audit: zero `unsafe` in first-party monero-oxide workspace
    code (helioselene, ec-divisors, generalized-bulletproofs, fcmps,
    monero-oxide). Only 4 `unsafe` blocks exist in helioselene benchmarks
    (`_rdtsc()` for cycle counting, not in library code). `dalek-ff-group`
    (crates.io dependency) also has zero `unsafe` blocks.
  - Veridise audit status: FCMPs circuit audited by Veridise (June 2025);
    Generalized Bulletproofs security proofs by Cypher Stack; Divisor proofs
    reviewed by both Veridise and Cypher Stack. Pinned commit `92af05e0` is
    post-audit. Helioselene and ec-divisors are not yet independently audited.
    Multi-phase integration audit (seraphis-migration/monero#294) is in
    planning.
- **FCMP++ Phase 1a.2: Rust reproducible builds.**
  - `Cargo.lock` pins all git dependencies to exact commit hash `92af05e0`.
  - Double-build determinism verified: `libshekyl_ffi.a` hash identical across
    consecutive builds on x86_64.
  - Added CI job `rust-audit-and-test` to `.github/workflows/build.yml` with
    cargo audit, workspace tests, and determinism check (build twice, diff).
  - Documented x86_64-only build requirement and Guix integration status in
    `docs/COMPILING_DEBUGGING_TESTING.md`.

### 🔄 Changed

- **P2P reorg functional test uses deadline-based polling.** Replaced three
  fixed-sleep polling sites in `test_p2p_reorg()` (`time.sleep(10)` x2,
  `loops = 100` counter) with 240 s deadline + 0.25 s interval polling,
  matching the pattern already used in `test_p2p_tx_propagation()`.
  Adapted from upstream Monero #9795.

### ✨ Added

- **Extra compiler warnings and hardening flags.** Added `-Wredundant-decls`,
  `-Wdate-time`, `-Wimplicit-fallthrough`, `-Wunreachable-code` (common);
  `-Woverloaded-virtual`, `-Wsuggest-override` (C++ only); `-Wgnu`,
  `-Wshadow-field`, `-Wthread-safety`, `-Wloop-analysis`,
  `-Wconditional-uninitialized`, `-Wdocumentation`, `-Wself-assign` (Clang);
  `-Wduplicated-branches` (GCC). Added security protections:
  `-fno-extended-identifiers`, `-fstack-reuse=none`, and ARM64 branch
  protection (`-mbranch-protection=bti` on macOS, `standard` elsewhere).
  Adapted from upstream Monero #9858.
- **Linker dead-code stripping.** Added `-ffunction-sections -fdata-sections`
  to compile flags and `-Wl,--gc-sections` (Linux) / `-Wl,-dead_strip`
  (macOS) to linker flags, enabling the linker to strip unreferenced
  functions and data. Inspired by upstream Monero #9898 author's findings
  (~14 MiB reduction in Docker images).

### 📚 Documentation

- **Upstream Monero PR triage.** Replaced the stale "To be done (and merged)"
  section in `COMPILING_DEBUGGING_TESTING.md` with a structured triage table
  covering applied PRs (#6937, #9762, #9795, #9858, #9898) and tracked-for-
  future-work PRs (#10157, #10084, #9801) with STRUCTURAL_TODO.md cross-refs.
- **FCMP++ documentation rework (Phase 0.5a).** Reworked all core documentation
  to reflect FCMP++ as the membership proof system from genesis. Replaced CLSAG
  and ring signature references with FCMP++ full-chain membership proof language.
  Updated PQC spec for per-input pqc_auths, per-output KEM derivation, Bech32m
  addresses, and curve tower architecture. Retired V4 lattice ring signature
  roadmap. Updated V3_ROLLOUT.md size estimates for ~23 KB typical transactions.
  Added FCMP++ items to RELEASE_CHECKLIST.md.

### 🐛 Fixed

- **Re-enabled `gen_block_reward` core test with Shekyl economics.**
  Rewrote `check_block_rewards()` in `block_reward.cpp` to verify miner
  outputs against Shekyl's four-component economics formula (release
  multiplier + emission split + fee burn) instead of legacy Monero fixed
  expectations. Updated `construct_miner_tx_by_weight` to pass explicit
  economics parameters. Fixed `construct_block` and
  `construct_block_manually` in `chaingen.cpp` to pass
  `circulating_supply=already_generated_coins` to `construct_miner_tx`,
  preventing parameter mismatch between test generator and validator.
  80 core_tests now pass (was 79).

- **MSVC C4334: 23 `1 << n` sites widened to `1ULL << n` in consensus
  code.** Fixed potential undefined behavior (signed 32-bit overflow if
  shift amount ever reaches 32) in `cryptonote_format_utils.cpp` (3),
  `bulletproofs.cc` (6), `bulletproofs_plus.cc` (6), `rctTypes.cpp` (5),
  `rctSigs.cpp` (2), and `multiexp.cc` (2).

- **MSVC C4333 right-shift warning in UTF-8 helpers.** Changed `wint_t cp` to
  `uint32_t cp` in `src/common/util.cpp` `get_string_prefix_by_width()`, and
  added an explicit `static_cast<uint32_t>` on the transform result in
  `src/common/utf8.h` `utf8canonical()`. On MSVC, `wint_t` is 16-bit
  `unsigned short`, so `cp >> 18` shifted by more than the type's width.

- **Remaining HF17 references corrected to HF1.** Fixed stale Monero-era
  `HF17` / `HF_VERSION_SHEKYL_NG = 17` references in `POST_QUANTUM_CRYPTOGRAPHY.md`
  (scheme registry, rollout notes, V4 roadmap), `PQC_MULTISIG.md` (V3 heading,
  V4 scheme table, activation target), `V3_ROLLOUT.md` (title, consensus gate,
  node checklist), and `STAKER_REWARD_DISBURSEMENT.md`. Also corrected `HF18`
  references to `HF2` in multisig V4 rollout tables. The source code constant
  `HF_VERSION_SHEKYL_NG` was already correctly defined as `1` in
  `cryptonote_config.h`; only documentation was affected.

- **CMake Boost detection on CMake 3.30+**: The built-in `FindBoost.cmake`
  module was removed in CMake 3.30. Restructured Boost detection to try
  CONFIG mode first (finding `BoostConfig.cmake` installed by b2), falling
  back to MODULE on older CMake. Fixes `contrib/depends` builds on Ubuntu
  24.04 runners with CMake ≥ 3.30.

### 🗑️ Removed

- **Classical multisig wallet RPC commands.** Removed all 9 Monero-inherited
  multisig RPC endpoints (`is_multisig`, `prepare_multisig`, `make_multisig`,
  `export_multisig_info`, `import_multisig_info`, `finalize_multisig`,
  `exchange_multisig_keys`, `sign_multisig`, `submit_multisig`) from the
  wallet RPC server. Removed `multisig_txset` fields from transfer and sweep
  response structs. Removed the `CHECK_MULTISIG_ENABLED` macro and
  `multisig/multisig.h` dependency. Classical secret-splitting multisig is
  replaced by PQC-only authorization (`scheme_id = 2`); see
  `docs/PQC_MULTISIG.md`.
- **Classical multisig simplewallet CLI commands.** Removed all multisig and
  MMS (Multisig Messaging System) commands from `simplewallet`: `prepare_multisig`,
  `make_multisig`, `exchange_multisig_keys`, `export_multisig_info`,
  `import_multisig_info`, `sign_multisig`, `submit_multisig`,
  `export_raw_multisig_tx`, and all `mms` subcommands. Removed
  `--generate-from-multisig-keys` and `--restore-multisig-wallet` CLI flags.
  Removed `enable-multisig-experimental` wallet setting. Removed
  `wallet/message_store.h` dependency. The `transfer_main`/`called_by_mms`
  indirection was collapsed into a single `transfer` method.
- **Classical multisig test and device_trezor remnants.** Removed stale
  multisig references from test infrastructure: `m_multisig*` wallet resets
  in `wallet_tools.cpp`, `multisig_sigs.clear()` in Trezor tests,
  `multisig_txset` assertion in `cold_signing.py`, and deleted
  `tests/functional_tests/multisig.py`. Removed `multisig` from the
  functional test default list. Cleaned up device_trezor protocol:
  removed `translate_klrki`, `MoneroMultisigKLRki` alias, `m_multisig`
  member, and multisig cout decryption in `Signer::step_final_ack`.
  Removed `mms_error`, `no_connection_to_bitmessage`, and
  `bitmessage_api_error` error classes from `wallet_errors.h`.
- **Classical multisig wallet API layer.** Removed all classical multisig
  code from the public wallet API: `MultisigState` struct, virtual multisig
  declarations (`multisig`, `getMultisigInfo`, `makeMultisig`,
  `exchangeMultisigKeys`, `exportMultisigImages`, `importMultisigImages`,
  `hasMultisigPartialKeyImages`, `restoreMultisigTransaction`,
  `publicMultisigSignerKey`, `signMultisigParticipant`,
  `multisigSignData`, `signMultisigTx`). Removed multisig helper functions
  and multisig threshold check from PendingTransaction commit path.
  Removed multisig guard from the background-sync validation macro.
- **Classical multisig wallet core (`wallet2.cpp`).** Removed all classical
  multisig code from the wallet core: `#include "multisig/..."` headers,
  `MULTISIG_UNSIGNED_TX_PREFIX`/`MULTISIG_EXPORT_FILE_MAGIC`/`MULTISIG_SIGNATURE_MAGIC`
  constants, `m_multisig`/`m_multisig_threshold`/`m_multisig_rounds_passed`/
  `m_enable_multisig`/`m_message_store`/`m_mms_file` member initializations,
  `num_priv_multisig_keys_post_setup`, `get_multisig_seed`, multisig restore
  path in `generate()`, `make_multisig`, `exchange_multisig_keys`,
  `get_multisig_first_kex_msg`, `multisig()`, `has_multisig_partial_key_images`,
  `frozen(multisig_tx_set)`, all `save/parse/load/sign_multisig_tx` overloads,
  the multisig transaction builder path in `transfer_selected_rct`,
  `export_multisig`, `import_multisig`, `update_multisig_rescan_info`,
  `get_multisig_signer_public_key`, `get_multisig_signing_public_key`,
  `get_multisig_k`, `get_multisig_kLRki`, `get_multisig_composite_kLRki`,
  `get_multisig_composite_key_image`, `get_multisig_wallet_state`,
  `sign_multisig_participant`, JSON serialization/deserialization of multisig
  fields, MMS file handling, and all scattered `m_multisig` guard branches.
- **Classical multisig `m_key_image_partial` remnants.** Removed the
  `m_key_image_partial` bitfield from `exported_transfer_details` and all
  code references in `wallet2.cpp` and `simplewallet.cpp`. Since classical
  multisig was removed, partial key images can never exist; all guard
  conditions (`!known || partial`, `known && !partial`, standalone partial
  checks) were simplified to reference only `m_key_image_known`. Removed
  the dead `old_mms_file` cleanup block from `wallet2::store_to`.

### ✨ Added

- **Daemon RPC migrated to Rust/Axum (Phase 1).** The daemon HTTP RPC transport
  is now served by the `shekyl-daemon-rpc` Rust crate using Axum, replacing
  `epee::http_server_impl_base`. All 90 endpoints (33 JSON REST, 9 binary,
  48 JSON-RPC 2.0) are routed through Axum with PQC-ready 10 MiB body limits,
  CORS, and restricted-mode enforcement. The C++ `core_rpc_server` handler
  logic is unchanged and accessed via a `core_rpc_ffi` C ABI facade. Enabled
  by default; `--no-rust-rpc` falls back to the legacy epee HTTP server.
  JSON REST endpoints accept both GET and POST (matching epee). Binary
  endpoints return 400 on parse failure (matching epee's MAP_URI_AUTO_BIN2).
  Validated on live testnet: 23/25 pass, 2 expected diffs
  (`rpc_connections_count`), 2 binary skips (empty-POST → 400 on both).
  Validation harness at `tests/rpc_comparison/compare_rpc.sh`;
  test data in `shekyl-dev/data/rpc_comparison/`.
- **PQC multisig core (scheme_id=2).** Implemented M-of-N hybrid Ed25519 +
  ML-DSA-65 multisig in Rust. Includes `MultisigKeyContainer`,
  `MultisigSigContainer`, `multisig_group_id`, and a 10-check adversarial
  verification pipeline. Maximum 7 participants (consensus constant). Domain
  separator: `shekyl-multisig-group-v1`.
- **PQC multisig FFI bridge.** Extended `shekyl_pqc_verify` to accept
  `scheme_id` and dispatch between single-signer (1) and multisig (2) paths.
  Added `shekyl_pqc_verify_debug` for diagnostic error codes and
  `shekyl_pqc_multisig_group_id` for group identity computation.
- **Scheme downgrade protection.** New `tx_extra_pqc_ownership` tag (0x05)
  records the expected PQC scheme and group ID for each output, preventing
  attackers from spending multisig-protected outputs with single-signer
  transactions.
- **Wallet multisig coordination.** New wallet2 methods for PQC multisig:
  `create_pqc_multisig_group`, `export_multisig_signing_request`,
  `sign_multisig_partial`, `import_multisig_signatures`. File-based JSON
  signing protocol. Wallet serialization version bumped to 32.
- **Cargo-fuzz harnesses.** 4 fuzz targets for multisig deserialization and
  verification (`fuzz_multisig_key_blob`, `fuzz_multisig_sig_blob`,
  `fuzz_multisig_verify`, `fuzz_group_id`), each validated at 10M iterations
  with zero panics.
- **PQC multisig subset-signing test.** Added `valid_subset_signing_3_of_5`
  test to `shekyl-crypto-pq` verifying that any valid 3-of-5 signer subset
  produces a valid multisig through the full 10-check verification pipeline.
- **PQC multisig test vectors.** Published
  `docs/PQC_TEST_VECTOR_002_MULTISIG.json` with canonical encoding sizes,
  wire-format sizes, verification pipeline checks, the 10-check pipeline,
  size regression data, and adversarial test cases for `scheme_id = 2`.
- **MSVC wallet-core build path**: `BuildRust.cmake` now selects the
  `x86_64-pc-windows-msvc` Rust target when CMake is driven by MSVC,
  enabling the Tauri GUI wallet to link against shekyl-core on Windows.
  The existing MinGW cross-compilation path for headless binaries is
  unchanged.
- **CI: Windows MSVC wallet-core job** (`build-windows-msvc`): New CI
  lane builds the wallet-core static libraries with Visual Studio / MSVC
  via vcpkg, validating the MSVC portability patches on every push.
- **Unified Gitian release pipeline.** The `gitian` workflow is now the sole
  release pipeline, replacing the separate `release-tagged` workflow. Gitian
  builds produce reproducible binaries; a new `package-and-publish` job
  creates `.deb`/`.rpm` packages, a Windows NSIS installer, source archive,
  and `SHA256SUMS`, then publishes the GitHub Release. Eliminates duplicate
  cross-compilation and host-toolchain issues.
- **Source archive in GitHub Releases.** The packaging job produces
  `shekyl-vX.Y.Z-source.tar.gz` containing the full source tree with all
  submodules, attached to each release alongside the binaries.

### 🔄 Changed

- **`shekyl_pqc_verify` FFI signature change.** Now requires `scheme_id` as
  first parameter for scheme dispatch.
- **`depends.yml` demoted to PR-only.** The cross-compilation CI workflow now
  runs only on pull requests (and manual dispatch), not on every push. Saves
  significant CI minutes; Gitian catches cross-platform issues at release time.
- **`release-tagged.yml` disabled.** The Gitian pipeline now handles all
  release artifacts. The old workflow is preserved as `.disabled` for one
  release cycle.
- **Gitian reproducible builds: migrated from Ubuntu 18.04 (Bionic) to 22.04
  (Jammy).** All five build descriptors (`gitian-linux.yml`, `gitian-win.yml`,
  `gitian-osx.yml`, `gitian-android.yml`, `gitian-freebsd.yml`),
  `gitian-build.py`, and `dockrun.sh` now target Jammy. Drops GCC 7 and
  Python 2 dependencies in favour of the distro-default GCC 11 and Python 3.
  Upgrades FreeBSD cross-compiler from Clang 8 to Clang 14. Removes
  Bionic-specific workarounds (i686 asm symlink hack, glibc `math-finite.h`
  hack). Adds `linux-libc-dev:i386` for native i686 headers. C++17 is now
  fully supported by the Gitian toolchain.

### 🐛 Fixed

- **Comprehensive compiler warning cleanup across all CI platforms.** Eliminated
  ~30 unique warnings inherited from Monero across Linux, macOS, Windows, and
  Arch Linux CI builds:
  - Removed dead code: `add_public_key` (format_utils), `keys_intersect`
    (wallet2), unused `addressof` template specialization (crypto test),
    unused `max_block_height` variable (protocol_handler).
  - Fixed `oaes_lib.c`: replaced deprecated `ftime()` with `gettimeofday()`,
    corrected transposed `calloc` argument order (5 call sites).
  - Fixed `rx-slow-hash.c`: added `(void)` to K&R-style function definitions.
  - Suppressed GCC false positive `-Wstringop-overflow` in `tree-hash.c`.
  - Replaced deprecated `strand::wrap()` with `boost::asio::bind_executor()`
    in `levin_notify.cpp`.
  - Suppressed GCC `-Wuninitialized` for safe circular-reference constructors
    in `cryptonote_core.cpp` and `long_term_block_weight.cpp`.
  - Added default member initializers to `BulletproofPlus` (rctTypes.h),
    `transfer_details` and `payment_details` (wallet2.h) to silence
    `-Wmaybe-uninitialized`.
  - Fixed Windows: removed unused variables in `windows_service.cpp`,
    eliminated `-Wcast-function-type` in `util.cpp` via `void*` intermediate
    cast, fixed `-Wtype-limits` in `utf8.h` by using `uint32_t` instead of
    `wint_t` for code points.
  - Suppressed intentional uninitialized read in `memwipe.cpp` test.
  - Set `MACOSX_DEPLOYMENT_TARGET` for native Darwin Cargo builds in
    `BuildRust.cmake` to eliminate 672 linker warnings from `ring` crate.
- **CI link errors: separated `shekyl-daemon-rpc` from `shekyl-ffi`.** The daemon
  RPC Axum crate was bundled into `libshekyl_ffi.a`, causing `undefined reference
  to core_rpc_ffi_*` on non-daemon targets (gen-ssl-cert, wallet-crypto-bench,
  etc.) across all 5 CI platforms. Moved FFI exports (`shekyl_daemon_rpc_start`,
  `shekyl_daemon_rpc_stop`) into a new `ffi_exports.rs` within the daemon-rpc
  crate, which now produces its own `libshekyl_daemon_rpc.a` staticlib. Only the
  daemon target links both libraries. `BuildRust.cmake` updated with a second
  cargo build step and `SHEKYL_DAEMON_RPC_LINK_LIBS`.
- **Wallet: `--daemon-port` help text referenced Monero port 18081.** Updated to
  Shekyl's default RPC port 11029.
- **Wallet: `account_public_address` equality after PQC.** Destination and
  change-address checks used `memcmp` on the whole struct; `m_pqc_public_key`
  is a `std::vector`, so equality was wrong when keys matched but allocations
  differed. All such sites now use `operator==` / `!=`. Added a
  `static_assert` that the type is not trivially copyable to discourage raw
  `memcmp` regressions.
- **Wallet / Ledger: constant-time comparison for 32-byte secrets.**
  `wallet2::is_deterministic` and Ledger HMAC secret lookup now use
  `crypto_verify_32` instead of `memcmp`.
- **MSVC: add `<io.h>` and POSIX guards in `util.cpp`.** Added `<io.h>`
  for `_open_osfhandle`/`_close`, expanded MinGW conditionals to cover
  MSVC for `setenv`→`putenv`, `mode_t`/`umask`, and `closefrom`→no-op.
- **MSVC: replace `__thread` with `thread_local` in `perf_timer.cpp` and
  `threadpool.cpp`.** GCC's `__thread` is not supported by MSVC.
- **MSVC: rename `xor` parameter in `slow-hash.c` to `xor_pad`.** MSVC
  treats `xor` as a reserved keyword in C mode. Both the x86/SSE and
  ARM/NEON variants of `aes_pseudo_round_xor()` were affected.
- **MSVC: fix iterator-to-pointer cast in `http_auth.cpp`.** MSVC
  `boost::as_literal()` iterator is a class, not a raw pointer. Used
  `&*data.begin()` to obtain the address.
- **MSVC: guard `unbound.h` include and usage in `util.cpp`.** The
  include and `unbound_built_with_threads()` function/call were not
  wrapped in `HAVE_DNS_UNBOUND`, causing a missing-header error.
- **MSVC: guard `unistd.h` in easylogging++.** The third-party logging
  library unconditionally included `<unistd.h>` which does not exist on
  MSVC.
- **MSVC: add `<io.h>` include for `_isatty` in `mlog.cpp`.** The WIN32
  code path uses `_isatty`/`_fileno` which require `<io.h>` on MSVC.
- **MSVC: fix `boost::iterator_range` conversion in `http_auth.cpp`.**
  Boost 1.90 `as_literal()` returns an iterator type that does not
  implicitly convert to `iterator_range<const char*>` on MSVC. Changed to
  `auto` deduction.
- **MSVC: add `<cwctype>` include for `std::towlower` in
  `language_base.h`.** MSVC does not transitively include wide-character
  utilities through other Boost headers.
- **MSVC: fix rvalue binding in portable_storage serialization.** Changed
  `array_entry_t::insert_first_val` and `insert_next_value` from strict
  rvalue-reference parameters (`t_entry_type&&`) to pass-by-value, allowing
  lvalue forwarding from `portable_storage::insert_first_value` /
  `insert_next_value` to work correctly under MSVC template deduction.
- **MSVC: force-include `<iso646.h>` for C++ alternative tokens.** The
  codebase uses `not`, `and`, `or` extensively (hundreds of sites). MSVC
  does not recognise these as keywords by default. Added `/FIiso646.h` to
  the MSVC compile definitions so they are defined in every translation
  unit.
- **MSVC: enable conformant preprocessor (`/Zc:preprocessor`).** MSVC's
  traditional preprocessor breaks nested `__VA_ARGS__` forwarding in the
  `THROW_ON_RPC_RESPONSE_ERROR` macro chain, causing `throw_wallet_ex`
  template deduction failures. Added `/Zc:preprocessor` to MSVC compile
  flags and removed the obsolete Boost.Preprocessor-based `throw_wallet_ex`
  fallback in favour of the standard variadic template version.
- **Gitian: enable `universe` repository and remove apt proxy in Docker base
  image.** The `ubuntu:jammy` Docker image only enables `main restricted` by
  default; `gitian-build.py` now patches the base image after `make-base-vm`
  to add `universe` and remove the `apt-cacher-ng` proxy configuration
  (`/etc/apt/apt.conf.d/50cacher`). The proxy routes all apt traffic through
  `172.17.0.1:3142` which is unreliable on ephemeral CI runners, causing
  persistent 503 failures during package installation. Uses `docker build`
  (not run+commit) to preserve the image's CMD/USER metadata.
- **Gitian Linux: fix i386-dependent package installation.** The i386
  architecture is now enabled in the Docker base image (via `gitian-build.py`'s
  `docker build` step) along with passwordless `sudo` for the `ubuntu` user,
  allowing `linux-libc-dev:i386`, `gcc-multilib`, and `g++-multilib` to be
  installed normally via the descriptor's `packages:` section.
- **Gitian macOS: add `libtinfo5` and `python-is-python3`, remove `python`
  from `FAKETIME_PROGS`.** The pre-built Clang 9 cross-compiler requires
  `libtinfo.so.5`. The `python` faketime wrapper broke CMake's
  `FindPythonInterp` version detection in the `native_libtapi` build (empty
  `PYTHON_VERSION_STRING`); removing `python` from the faketime wrappers
  fixes this while preserving timestamp reproducibility for `ar`, `ranlib`,
  `date`, `dmg`, and `genisoimage`.
- **Gitian Android: add `python-is-python3`.** Android NDK r17b scripts use
  `#!/usr/bin/env python` which does not exist on Jammy without this package.
- **Gitian macOS: fix Rust `ring` crate cross-compilation.** `BuildRust.cmake`
  incorrectly overrode the macOS cross-compiler with the Linux system `clang`
  when cross-compiling for Darwin, causing the `ring` crate to include
  Linux-only `cet.h`. Now only uses system clang on native macOS builds.
- **Gitian Windows: drop i686 (32-bit) target.** The i686-pc-windows-gnu Rust
  target has an unresolved `GetHostNameW@8` symbol against MinGW's `ws2_32`.
  Since the release workflow only targets x86_64, the 32-bit Gitian build is
  removed.
- **macOS cross-build: exclude `-fcf-protection=full`.** Intel CET is x86
  Linux only; the flag defines `__CET__` which triggers `#include <cet.h>` in
  the `ring` crate's assembly, but `cet.h` does not exist in the macOS SDK.
  Now excluded for all Apple targets.
- **macOS aarch64 cross-build: set `MACOSX_DEPLOYMENT_TARGET=10.16`.**
  Clang 9 (depends cross-compiler) does not recognise macOS version 11.0+.
  Apple aliases 10.16 == 11.0; the `cc-rs` crate respects this env var, fixing
  the `ring` build for `aarch64-apple-darwin`.
- **Gitian Docker base image: install `sudo` before creating sudoers entry.**
  The `/etc/sudoers.d/` directory does not exist in the minimal Ubuntu image
  until the `sudo` package is installed.

### 🔄 Changed

- **Replace all `BOOST_FOREACH` / `BOOST_REVERSE_FOREACH` with range-for
  loops.** 31+ call sites across test and utility code replaced with standard
  C++11 range-based for. Adds `/DNOMINMAX` to MSVC definitions to prevent
  Windows `min`/`max` macro collisions.
- **Replace hardcoded `-fPIC` with `POSITION_INDEPENDENT_CODE`.** The CMake
  property works across all compilers (GCC, Clang, MSVC). Applied to
  `liblmdb` and `easylogging++` CMakeLists.
- **Guard/remove unguarded `#include <unistd.h>`.** POSIX header guarded
  behind `#ifndef _WIN32` in `blockchain_import.cpp`; unused include removed
  from `crypto.cpp`.
- **Replace C++20 designated initializers with C++17-compatible member
  assignment.** Rewrote 10 call sites in `cryptonote_core.cpp`,
  `blockchain.cpp`, `levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, and
  `wallet2.cpp`. GCC/Clang accepted these as extensions; MSVC rejects them.
- **Replace all `__thread` with `thread_local`.** Covers `easylogging++.cc`,
  `perf_timer.cpp`, and `threadpool.cpp`. The `__thread` qualifier is
  GCC/Clang-specific; `thread_local` (C++11) is
  portable across GCC, Clang, and MSVC.
- **Centralize `ssize_t` typedef in `src/common/compat.h`.** Replaces
  duplicate `#if defined(_MSC_VER)` guards in `util.h` and `download.h`
  with a single include.

### 🗑️ Removed

- **Classical multisig code removed from wallet2.h.** Removed all classical
  Monero-style multisig types (`multisig_info`, `multisig_sig`,
  `multisig_kLR_bundle`, `multisig_tx_set`), public/private multisig API
  methods, multisig private members, MMS (message store) integration, and
  associated Boost serialization functions. The `src/multisig/` directory and
  `src/wallet/message_store.h` are deleted; `wallet2.h` no longer depends on
  those headers. All multisig uses PQC-only authorization (`scheme_id = 2`)
  via the `pqc_auth` layer.
- **Gitian Android build.** Removed from the Gitian matrix since there is no
  Android wallet. The Android NDK r17b is also incompatible with Ubuntu Jammy.
- **Gitian Linux: drop i686-linux-gnu (32-bit x86) target.** Eliminates the
  need for `linux-libc-dev:i386`, `gcc-multilib`, `g++-multilib`, `sudo`,
  and the `dpkg --add-architecture i386` workaround. Simplifies the Docker
  base image patching to only enable the `universe` repository.

### 📚 Documentation

- **`docs/RELEASING.md`: document all release artifacts.** Updated the
  artifact table to list all 13 files produced per release (was 6),
  including cross-platform tarballs, aarch64 `.deb`/`.rpm`, and source
  archive. Updated "Future Platforms" to reflect that macOS tarballs are
  now shipping and `.dmg`/AppImage remain planned.

## [3.0.3-RC1] - 2026-03-31

### Known Limitations

- **Multisig not yet implemented.** Multisig wallets are restricted to v2
  transactions (no PQC authentication). PQC-enabled multisig is planned for
  a future release. See `docs/PQC_MULTISIG.md` for the design.

### ✨ Added

- **Rust wallet RPC server (`shekyl-wallet-rpc`)**: New Rust crate that
  replaces the C++ `wallet_rpc_server` with an axum-based JSON-RPC server.
  Calls the existing C++ `wallet2` library through a new C FFI facade
  (`wallet2_ffi.cpp/.h`). Supports all 98 RPC methods with full parity.
  Can run as a standalone binary (`shekyl-wallet-rpc`) or be embedded
  as a library in the Tauri GUI wallet. See `docs/WALLET_RPC_RUST.md`.

- **C++ wallet2 FFI facade (`wallet2_ffi.cpp/.h`)**: Opaque-handle C API
  over `wallet2` with JSON serialization at the boundary. Includes a
  generic `wallet2_ffi_json_rpc()` dispatcher that routes all RPC methods
  to the underlying wallet2 implementation. Covers lifecycle, queries,
  transfers, sweeps, proofs, accounts, address book, import/export,
  multisig, staking, mining, background sync, and daemon management.

- **GUI wallet direct FFI integration**: The Tauri GUI wallet now calls
  wallet2 directly through the Rust FFI bridge (`wallet_bridge.rs`)
  instead of spawning a child `shekyl-wallet-rpc` process and
  communicating via HTTP. Eliminates process management, port allocation,
  and HTTP overhead. Removed `wallet_process.rs` and `wallet_rpc.rs`.

### v3-First Core Test Adaptation

- **Enforced min_tx_version=3 for non-coinbase transactions**: All user
  transactions in the test suite now construct v3 with PQC authentication
  (hybrid Ed25519 + ML-DSA-65). Coinbase transactions remain v2.
- **Adapted chaingen framework for RCT-from-genesis**: Transaction
  construction helpers (`construct_tx_to_key`, `construct_tx_rct`) thread
  `hf_version=1` and `use_view_tags=true`. Coinbase outputs are indexed
  under `amount=0` for correct RCT spending. Fixed difficulty is injected
  for FAKECHAIN replay. Mixin checks are relaxed for FAKECHAIN.
- **Added RCT-aware balance verification**: Pool transaction balance checks
  in `gen_chain_switch_1` now decrypt ecdhInfo amounts using the recipient's
  view key instead of relying on the plaintext `o.amount` field (always 0
  for RCT outputs).
- **Recalibrated economic constants for Shekyl**: Test constants
  (`TESTS_DEFAULT_FEE`, `FIRST_BLOCK_REWARD`, `MK_COINS`) match Shekyl's
  `COIN = 10^9`, `EMISSION_SPEED_FACTOR = 21`, and staker/burn splits.
  `construct_miner_tx_manually` in block validation tests uses Shekyl's
  reward distribution.
- **Fixed Bulletproofs+ test suite**: Dynamically discover miner output
  amounts, set HF to 1 for all block construction, correctly flag coinbase
  outputs as RCT. All 15 BP+ tests pass.
- **Fixed txpool tests**: Adjusted key image count assertions for
  multi-input RCT transactions and corrected unlock_time handling.
- **Fixed double-spend tests**: Modified output selection to pick the
  largest decomposed output, avoiding underflow on fee subtraction.
- **Disabled legacy-incompatible tests**: `gen_block_invalid_binary_format`
  (hours-long), `gen_block_invalid_nonce`, `gen_block_late_v1_coinbase_tx`,
  `gen_uint_overflow_1`, `gen_block_reward`,
  `gen_bpp_tx_invalid_before_fork`, `gen_bpp_tx_invalid_clsag_type`,
  `gen_ring_signature_big`. These rely on pre-RCT economics, legacy
  fork transitions, or are prohibitively slow.
- **All 79 core_tests pass with 0 failures.**

### Test suite cleanup for Shekyl HF1

- **Removed 96 dead Borromean ringct tests**: All tests in
  `tests/unit_tests/ringct.cpp` that exercised legacy Borromean range
  proofs were removed. Shekyl HF1 rejects Borromean proofs at the
  `genRctSimple` level. Retained 9 non-Borromean tests (CLSAG, HPow2,
  d2h, d2b, key_ostream, zeroCommit, H, mul8).
- **Updated transaction construction helpers to Bulletproofs+**: The
  `test::make_transaction` helper (used by JSON serialization and ZMQ
  tests) now constructs transactions with
  `{ RangeProofPaddedBulletproof, 4 }` (BP+/CLSAG) instead of the
  removed Borromean or unsupported BP v2 configs. Removed the obsolete
  `bulletproof` parameter. Consolidated three JSON serialization tests
  (RegularTransaction, RingctTransaction, BulletproofTransaction) into
  one `BulletproofPlusTransaction` test. Fixes all 8 zmq_pub/zmq_server
  test failures.
- **Updated serialization round-trip test to BP+**: Changed
  `Serialization.serializes_ringct_types` from `bp_version 2` (throws
  "Unsupported BP version") to `bp_version 4` (Bulletproofs+). Updated
  assertions from MGs to CLSAGs and from `bulletproofs` to
  `bulletproofs_plus`.
- **Removed legacy Monero-era core/perf test executions**: Stopped running
  deprecated Borromean/pre-RCT/fork-transition test generators in
  `core_tests` and removed Borromean/MLSAG/range-proof performance test
  invocations and defaults, so CI validates HF1-era behavior only.
- **Hardened block-weight test contract for HF1 semantics**: `block_weight`
  comparison now enforces deterministic `H/BW/LTBW` parity and EMBW floor
  invariants instead of byte-identical legacy model output, preventing
  false failures from non-consensus median implementation details.
- **Fixed block_reward test expected values**: Updated emission curve
  expectations to match Shekyl's `EMISSION_SPEED_FACTOR = 21` (120s
  blocks) and per-block tail floor of
  `FINAL_SUBSIDY_PER_MINUTE * target_minutes`.
- **Rewrote mining_parity release multiplier test**: Replaced legacy
  pre-Shekyl-NG equality assertion (which tested a non-existent version
  0) with a test that verifies the release multiplier correctly scales
  rewards above and below the tx volume baseline.
- **Fixed Ubuntu 24.04 CI test runner**: Replaced `pip install` with
  `apt install python3-*` packages to comply with PEP 668
  (externally-managed-environment).

### 🐛 Fixed

- **macOS cross-compilation (depends CI)**: Fixed multiple build failures
  for Cross-Mac x86_64 and Cross-Mac aarch64 targets:
  - Raised macOS minimum deployment target from 10.8 (Mountain Lion, 2012)
    to 10.15 (Catalina, 2019) to enable `std::filesystem` support in the
    cross-compiled libc++.
  - Fixed Boost discovery in depends builds by setting `Boost_NO_BOOST_CMAKE`
    and forcing MODULE mode, preventing `BoostConfig.cmake` variant-check
    failures on cross-compiled Darwin libraries.
  - Made `boost_locale` a conditional dependency (Windows only), since it
    is only used within `#ifdef WIN32` blocks and was unavailable for
    Darwin cross-builds.
  - Added per-target `CC_<triple>/AR_<triple>/CFLAGS_<triple>` environment
    variables in `BuildRust.cmake` so the `ring` crate can locate the
    cross-compiler for C/assembly code.
  - Used system clang (instead of the depends-bundled Clang 9) for Rust
    crate C compilation on Darwin, since `ring` 0.17 requires clang
    features unavailable in Clang 9 (macOS 11 version strings,
    `-fno-semantic-interposition`).
  - Guarded `-fno-semantic-interposition` behind `check_c_compiler_flag()`
    so it is only added when the compiler supports it (Clang 9 does not).
  - Fixed OSX SDK cache key in `depends.yml` to include the SDK version
    and skip the cache step for non-macOS builds.

- **FreeBSD cross-compilation (depends CI)**: Fixed multiple build failures
  for the x86_64 FreeBSD target:
  - Switched Boost's b2 toolset from `gcc` to `clang` for FreeBSD, fixing
    C++ standard library header resolution (`<cstddef>` not found).
  - Embedded `-stdlib=libc++` in the FreeBSD clang++ wrapper script so all
    depends packages automatically use the correct C++ standard library,
    regardless of whether their own `$(package)_cxxflags` overrides the
    host flags (previously broke zeromq, sodium, and other packages).
  - Fixed compiler wrapper argument quoting: replaced the broken
    `echo "...$$$$""@"` pattern with `printf '..."$$$$@"'` so `"$@"`
    passes through correctly to the generated wrapper, preventing argument
    mangling for flags containing quotes (e.g. `-DPACKAGE_VERSION="1.0.20"`).
  - Added `-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION` to both
    Boost's FreeBSD cxxflags and the CMake toolchain, restoring
    `std::unary_function` compatibility needed by Boost 1.74's
    `container_hash/hash.hpp` under FreeBSD's strict C++17 libc++.
  - Removed the unsupported `no-devcrypto` option from OpenSSL's FreeBSD
    configure flags (the devcrypto engine was removed in OpenSSL 3.0).
  - Added `threadapi=pthread runtime-link=shared` to Boost's FreeBSD
    config options for correct threading and linking behavior.

- **Linux static release build (libudev linking)**: Added `libudev-dev` to
  the `release-tagged.yml` CI package list. Static `libusb-1.0.a` and
  `libhidapi-libusb.a` depend on `libudev` for USB hotplug support;
  without the dev package installed, `find_library(udev)` failed and the
  final link produced undefined `udev_*` references, preventing the
  "Publish GitHub Release" step from running.
- **Win64 build failure (ICU generator expression)**: Replaced broken CMake
  generator expressions `$<$<BOOL:${WIN32}>:${ICU_LIBRARIES}>` with
  `if(WIN32)` blocks in `simplewallet`, `wallet_api`, and
  `libwallet_api_tests` CMakeLists. Generator expressions cannot contain
  semicolon-separated lists; the old pattern passed literal fragments like
  `$<1:icuio` to the linker on MinGW cross-compilation.
- **Linux static build (libunbound linking)**: Fixed `FindUnbound.cmake`
  scoping bug where `list(APPEND UNBOUND_LIBRARIES ...)` created a local
  variable shadowing the `find_library` cache entry. The transitive static
  deps (libevent, libnettle, libhogweed, libgmp) were silently dropped,
  causing undefined reference errors in `release-static-linux-x86_64`
  builds.
- **JSON serialization of v3 (PQC) transactions**: Added missing
  `pqc_auth` field to the RapidJSON `toJsonValue`/`fromJsonValue`
  roundtrip for `cryptonote::transaction`. V3 transactions created
  under `HF_VERSION_SHEKYL_NG` include a `pqc_authentication`
  envelope; without JSON support the field was silently dropped,
  causing `get_transaction_hash` to fail with "Inconsistent
  transaction prefix, unprunable and blob sizes" after a JSON
  roundtrip. Fixes the `JsonSerialization.BulletproofPlusTransaction`
  unit test failure.

### GUI Wallet

- New project: Shekyl GUI Wallet (`shekyl-gui-wallet`) at
  [Shekyl-Foundation/shekyl-gui-wallet](https://github.com/Shekyl-Foundation/shekyl-gui-wallet).
  Built with Tauri 2 (Rust backend) + Vite + React 19 + TypeScript + Tailwind CSS 4.
  Initial scaffold includes 6 pages (Dashboard, Send, Receive, Staking,
  Transactions, Settings), stub Tauri commands, Shekyl gold/purple design system,
  and verified production builds for Linux (.deb, .rpm, .AppImage).
  Phase 2 will add the C++ FFI bridge to `wallet2_api.h` for real wallet operations.
- Added testing infrastructure: Vitest + React Testing Library for frontend
  (20 tests across 6 suites), cargo test for Rust backend (10 tests), with
  Tauri IPC mocking for isolated component testing.
- Added CI/CD via GitHub Actions: `ci.yml` runs ESLint, TypeScript type-check,
  Vitest, Rustfmt, Clippy, and cargo test on every PR; `release.yml` builds
  multi-platform binaries (Linux x64, Windows x64, macOS ARM64 + Intel) via
  `tauri-action` and creates draft GitHub releases.

### Consensus timing alignment (HF1)

- Fixed remaining runtime paths that still derived timing from legacy `DIFFICULTY_TARGET_V1` (`60s`) so active Shekyl HF1 behavior consistently uses `DIFFICULTY_TARGET_V2` (`120s`) for difficulty target selection, block reward minute-scaling, unlock-time leeway checks, sync ETA reporting, and wallet lock-time display.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to mark the 120s block-time drift item as resolved (`code_fix_required` completed).

### 📚 Documentation

- Updated `docs/V3_ROLLOUT.md` to reflect HF1 (genesis) activation instead
  of the stale HF17 references. Added v3-first test strategy section.
- Updated `docs/POST_QUANTUM_CRYPTOGRAPHY.md` scheme_id status table and
  deferred-items section from HF17 to HF1.
- Updated `docs/PQC_MULTISIG.md` V3 signature list heading from HF17 to HF1.
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` to reference HF1 activation.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` HF naming drift label
  from `doc_correction` to resolved.
- Added `core_tests` section to `docs/COMPILING_DEBUGGING_TESTING.md`
  documenting the v3-from-genesis test approach and how to run/filter tests.

### Genesis initialization compatibility

- Regenerated `GENESIS_TX` for mainnet, testnet, and stagenet to modern coinbase format (`tx.version = 2`) with tagged outputs.
- Removed all legacy genesis compatibility exceptions and enforced strict coinbase version checks (`tx.version > 1`) across all network types, including `FAKECHAIN`.
- Fixed genesis reward validation to accept the hardcoded `GENESIS_TX` amount at `height == 0` while leaving post-genesis reward accounting unchanged.
- Fixed startup edge case where long-term weight median calculations could evaluate with zero historical blocks during genesis initialization (`count == 0`), causing daemon boot failure on empty data dirs.
- Updated genesis-construction helper (`build_genesis_coinbase_from_destinations`) to emit `tx.version = 2` with view-tagged outputs for current HF1 expectations.
- Added canonical root build command `make genesis-builder` (using the main release build dir with `GENESIS_TOOL_SRC_DIR`) to avoid split/ambiguous genesis-builder binaries across multiple build trees.

### Testnet economy readiness checks

- Added `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to track design-vs-code status for economy testnet rehearsal with explicit drift tags (`doc_correction`, `code_fix_required`, `needs_decision`).
- Added `scripts/check_testnet_genesis_consensus.py` to verify multi-node testnet tuple consistency (`height 0 block hash`, `miner tx hash`, `tx hex`) and optional economy field presence in `get_info`.
- Added Rust parity/invariant tests:
  - `shekyl-economics-sim`: validates `SimParams::default()` against `config/economics_params.json`.
  - `shekyl-economics`: added release monotonicity, burn bounds, and emission-share monotonicity tests.
  - `shekyl-ffi`: added direct FFI-vs-Rust consistency tests for burn pct and emission share.
- Added functional RPC test `tests/functional_tests/economy_info.py` and included it in `functional_tests_rpc.py` default test list to assert required economy fields are exposed by `get_info`.
- Corrected documentation errors without changing design intent:
  - Clarified `DESIGN_CONCEPTS.md` Section 2 as historical baseline.
  - Removed duplicate heading in `GENESIS_TRANSPARENCY.md`.
  - Linked `RELEASE_CHECKLIST.md` testnet section to the rehearsal runbook/checklist and deterministic tuple check command.

### BREAKING: Second-pass rebrand (wallet, URI, serialization)

- **URI scheme**: Wallet URI generation and parsing now use `shekyl:` only.
  The legacy `monero:` scheme is no longer accepted. QR codes and payment
  links generated by previous builds will fail to parse. Regenerate all
  payment URIs before upgrading wallets.
- **Wallet/export/cache magic strings**: All file-format magic prefixes have
  been rewritten from `Monero` to `Shekyl`:
  - `UNSIGNED_TX_PREFIX` → `"Shekyl unsigned tx set\005"`
  - `SIGNED_TX_PREFIX` → `"Shekyl signed tx set\005"`
  - `MULTISIG_UNSIGNED_TX_PREFIX` → `"Shekyl multisig unsigned tx set\001"`
  - `KEY_IMAGE_EXPORT_FILE_MAGIC` → `"Shekyl key image export\003"`
  - `MULTISIG_EXPORT_FILE_MAGIC` → `"Shekyl multisig export\001"`
  - `OUTPUT_EXPORT_FILE_MAGIC` → `"Shekyl output export\004"`
  - `ASCII_OUTPUT_MAGIC` → `"ShekylAsciiDataV1"`
  - Wallet cache magic → `"shekyl wallet cache"`
  Old wallet caches, exported key images, multisig exports, signed/unsigned
  tx sets, and output exports are **incompatible** and must be re-exported
  after upgrading.
- **Message signing domain**: `HASH_KEY_MESSAGE_SIGNING` changed from
  `"MoneroMessageSignature"` to `"ShekylMessageSignature"`. Messages signed
  with the old domain separator will fail verification.
- **i18n domain**: Translation catalogue domain changed from `"monero"` to
  `"shekyl"`.
- **Daemon stdout redirect**: Daemonized output file changed from
  `bitmonero.daemon.stdout.stderr` to `shekyl.daemon.stdout.stderr`.
- **Log file names**: All blockchain utility log files renamed from
  `monero-blockchain-*` to `shekyl-blockchain-*`.
- **DNS seed/checkpoint domains**: Replaced `moneroseeds.*` and
  `moneropulse.*` lookups with 5-domain consensus set: `shekyl.org`,
  `shekyl.net`, `shekyl.com`, `shekyl.biz`, `shekyl.io`. Majority
  threshold is 3 of 5. See `shekyl-dev/docs/DNS_CONFIG.md` for the full
  infrastructure reference.
- **Update check**: Software name comparison for macOS `.dmg` extension
  switched from `monero-gui` to `shekyl-gui`.
- **Hardware wallet**: Ledger app error message now references "Shekyl Ledger
  App" instead of "Monero Ledger App". Trezor protobuf namespaces are
  unchanged (third-party protocol dependency).
- **Intentionally preserved**: Trezor/Ledger protobuf includes and protocol
  namespaces (`hw.trezor.messages.monero.*`), Esperanto mnemonic word
  `"monero"` (means "money"), academic paper citations, copyright headers,
  `MONERO_DEFAULT_LOG_CATEGORY` build-internal macros, and `MakeCryptoOps.py`
  build artifacts.

#### Operator migration checklist

1. Delete old wallet cache files (`.keys` files are unaffected).
2. Re-export any key-image, multisig, or output export files.
3. Re-export and re-sign any unsigned/signed transaction sets.
4. Regenerate all `monero:` QR codes/payment URIs as `shekyl:` URIs.
5. Update any scripts or integrations that parse URI scheme or file magic.
6. Verify message signatures were not created with the old signing domain.
7. Update log rotation configs if they reference `monero-blockchain-*` paths.
8. Update DNS infrastructure to serve records under all 5 TLDs (`.org`,
   `.net`, `.com`, `.biz`, `.io`). See `shekyl-dev/docs/DNS_CONFIG.md`.

### Dead Monero legacy code removal

- **Dead HF branch cleanup**: Collapsed all always-true / always-false hard fork
  version branches across `blockchain.cpp` (~25 sites), `wallet2.cpp` (~22 sites),
  `cryptonote_basic_impl.cpp` (2 sites), and `cryptonote_core.cpp` (2 sites).
  Since all `HF_VERSION_*` constants are 1, every `hf_version >= HF_VERSION_*`
  was always true and every `hf_version < HF_VERSION_*` was always false.
  Collapsed fee algorithms, ring size ladders, tx version ladders, difficulty
  target selection, sync block size selection, BP/CLSAG/BP+ gating, dynamic
  fee scaling, long-term block weight calculations, and `use_fork_rules()` call
  sites. Removed ~500-800 lines of dead conditional logic.

- **Dropped v1 transaction support entirely**:
  - **Consensus**: `check_tx_outputs` now rejects `tx.version == 1` outright.
    `check_tx_inputs` sets `min_tx_version = 2` unconditionally; unmixable
    output counting and ring-size exemptions removed. v1 ring signature
    verification code and threaded v1 signature checking removed from
    `check_tx_inputs`. `expand_transaction_2` only handles CLSAG and
    BulletproofPlus; old RCTTypeFull/Simple/Bulletproof/Bulletproof2 branches
    removed.
  - **RingCT** (`rctSigs.cpp`/`.h`): Removed ~770 lines of dead crypto code:
    `genBorromean`, `verifyBorromean`, `MLSAG_Gen`, `MLSAG_Ver`, `proveRange`,
    `verRange`, `proveRctMG`, `proveRctMGSimple`, `verRctMG`, `verRctMGSimple`,
    `populateFromBlockchain`, `genRct` (both overloads), `verRct`, `decodeRct`
    (both overloads). `genRctSimple`, `verRctSemanticsSimple`,
    `verRctNonSemanticsSimple`, and `decodeRctSimple` only accept
    `RCTTypeCLSAG` and `RCTTypeBulletproofPlus`. Header reduced from 144 to
    87 lines.
  - **Transaction construction** (`cryptonote_tx_utils.cpp`): Removed v1
    ring signature generation block and non-simple RCT construction
    (`genRct`). All transactions now use `genRctSimple` (CLSAG path).
  - **Tx verification utils**: Removed `RCTTypeSimple`, `RCTTypeFull`,
    `RCTTypeBulletproof`, `RCTTypeBulletproof2` from batch semantics
    verification.
  - **Test fixups**: Updated all test files under `tests/` to match the
    removed RCT primitives. Stubbed performance benchmarks for MLSAG
    (`rct_mlsag.h`, `sig_mlsag.h`) and Borromean range proofs
    (`range_proof.h`). Replaced `verRct` with `verRctNonSemanticsSimple`
    in `check_tx_signature.h`. Removed `decodeRct` else-branches from
    `rct.cpp`, `rct2.cpp`, `bulletproofs.cpp`, `bulletproof_plus.cpp`.
    In `unit_tests/ringct.cpp`: removed Borromean, MLSAG, and
    RCTTypeFull-only tests; rewrote `make_sample_rct_sig` to use
    `genRctSimple`; replaced all `verRct` calls with `verRctSimple`.

- **Wallet v1 cleanup**: Removed unmixable sweep functions, v1 fee/amount
  paths, v1 coinbase optimization, dead non-RCT creation branches, and
  replaced `RangeProofBorromean` defaults with `RangeProofPaddedBulletproof`.
  `sweep_dust` RPC returns error; `createSweepUnmixableTransaction` API
  returns empty result with error status.

- **Trezor Shekyl rebrand**: Renamed all include guard macros from
  `MONERO_*_H` to `SHEKYL_*_H` in 8 `device_trezor/` headers. Updated
  derivation path comment and HTTP Origin URL. Protobuf message types and
  wire protocol identifiers intentionally preserved (must match Trezor
  firmware definitions).

### Epee Phase 1: Rust replacement for security-critical primitives

- **SSL certificate generation migrated to Rust (`rcgen`)**: Replaced the
  deprecated OpenSSL RSA/EC_KEY certificate generation in `net_ssl.cpp` with
  Rust's `rcgen` crate (ECDSA P-256) via FFI. Eliminates all `RSA_new`,
  `RSA_generate_key_ex`, `EC_KEY_new`, `EC_KEY_generate_key`, and other
  OpenSSL 3.0-deprecated API calls. The `create_rsa_ssl_certificate` and
  `create_ec_ssl_certificate` functions are replaced by a single
  `create_ssl_certificate` that delegates to `shekyl_generate_ssl_certificate`
  in the Rust FFI, returning PEM-encoded key+cert for loading into OpenSSL's
  SSL_CTX via non-deprecated BIO APIs.
- **Post-quantum hybrid key exchange enabled**: TLS context configuration now
  prefers `X25519MLKEM768` (FIPS 203 ML-KEM-768 hybrid) key exchange groups,
  falling back to classical `X25519:P-256:P-384` when the OpenSSL build lacks
  PQ support. Also added explicit TLS 1.3 ciphersuite configuration. Removed
  deprecated `SSL_CTX_set_ecdh_auto` call.
- **Secure memory wiping migrated to Rust (`zeroize`)**: Replaced the
  platform-specific `memwipe.c` implementation (memset_s / explicit_bzero /
  compiler-barrier fallback) with a single call to the Rust `zeroize` crate
  via `shekyl_memwipe` FFI. The `zeroize` crate uses `write_volatile` which
  is guaranteed not to be optimized away, replacing the fragile compiler
  barrier tricks.
- **Memory locking migrated to Rust (`libc`)**: Replaced the GNUC-only
  `mlock`/`munlock`/`sysconf` calls in `mlocker.cpp` with Rust FFI functions
  (`shekyl_mlock`, `shekyl_munlock`, `shekyl_page_size`) backed by the `libc`
  crate. Adds Windows `VirtualLock`/`VirtualUnlock` support that was
  previously missing (`#warning Missing implementation`). The `mlocked<T>` and
  `scrubbed<T>` C++ template wrappers are preserved unchanged.
- **New Rust FFI dependencies**: Added `rcgen = "0.14"`, `zeroize = "1"`,
  `libc = "0.2"` to `shekyl-ffi/Cargo.toml`.
- **C-compatible FFI header**: Added `src/shekyl/shekyl_secure_mem.h` with
  C-linkage declarations for the secure memory primitives, usable from both
  C (`memwipe.c`) and C++ (`mlocker.cpp`) translation units.
- **CMake wiring**: `epee` library now links `${SHEKYL_FFI_LINK_LIBS}` and
  includes `${CMAKE_SOURCE_DIR}/src` for the FFI headers.

### Build fixes

- **Boost CONFIG-mode compatibility shim**: When Boost is found via cmake
  CONFIG mode (Boost 1.85+), old-style `${Boost_XXX_LIBRARY}` variables may
  resolve to versioned `.so` paths that don't exist on rolling-release distros
  (e.g. Arch Linux with Boost 1.90). Added a shim in the root `CMakeLists.txt`
  that remaps all `Boost_*_LIBRARY` variables to `Boost::*` imported targets
  when CONFIG mode is active. Fixes linker failures on Arch.
- **Removed duplicate `parse_amount` test**: Two identical
  `TEST_pos(18446744073709551615, ...)` entries in
  `tests/unit_tests/parse_amount.cpp` caused a redefinition error on macOS
  Clang. Removed the duplicate.
- **Boost CONFIG-mode validation**: Added a cmake-configure-time check that
  verifies Boost imported-target `IMPORTED_LOCATION` files exist on disk.
  Gives a clear `FATAL_ERROR` with remediation steps instead of a cryptic
  linker failure minutes into the build.
- **Arch Linux CI**: Added `boost-libs` to the Arch pacman install to
  provide shared `.so` files alongside the `boost` headers/cmake-config
  package.
- **Ubuntu 24.04 test matrix**: Added Ubuntu 24.04 to the `test-ubuntu`
  CI matrix (previously only 22.04 was tested).

### Depends system updates

- **FreeBSD sysroot updated to 14.4-RELEASE**: The cross-compilation
  sysroot was stuck at FreeBSD 11.3 (EOL Sept 2021), whose `base.txz`
  had been removed from FreeBSD mirrors (404). Updated to 14.4-RELEASE
  (March 2026), updated SHA256 hash, and fixed clang wrapper scripts
  from clang-8 to clang-14 to match `hosts/freebsd.mk`. Added
  `-stdlib=libc++` to CXXFLAGS and LDFLAGS since FreeBSD uses libc++
  and the Ubuntu host's clang-14 defaults to libstdc++. Also added
  `libc++-14-dev` and `libc++abi-14-dev` to CI packages for the FreeBSD
  cross-build so the host compiler can find libc++ headers when
  `-stdlib=libc++` is specified.
- **Boost: skip CONFIG mode for depends builds**: The depends-built Boost
  1.74.0 installs CMake config files whose variant detection fails for
  darwin cross-builds (`boost_locale` reports "No suitable build variant").
  `find_package(Boost ... CONFIG)` is now skipped when `DEPENDS` is true
  (set by the depends toolchain), falling back to the more robust MODULE
  mode (`FindBoost.cmake`).
- **OpenSSL: disabled `devcrypto` engine for FreeBSD**: Added
  `no-devcrypto` to FreeBSD OpenSSL configure options. The `/dev/crypto`
  engine requires the `crypto/cryptodev.h` kernel header which is not
  available in a cross-compilation sysroot.
- **libsodium updated to 1.0.20**: The 1.0.18 tarball was removed from
  `download.libsodium.org` (404). Updated to 1.0.20 with new SHA256 hash.
  Removed the 1.0.18-specific patches (`fix-whitespace.patch`,
  `disable-glibc-getrandom-getentropy.patch`) which no longer apply.

### Warning cleanup and dead code removal

- **Removed dead fork helpers**: Deleted unused `get_bulletproof_fork()`,
  `get_bulletproof_plus_fork()`, and `get_clsag_fork()` from `wallet2.cpp`.
  These Monero-era version ladders had no call sites; Shekyl activates all
  features from HF1.
- **Removed dead variable**: Deleted unused `bool refreshed` in
  `wallet2::refresh()`.
- **Removed legacy `result_type` typedefs**: Deleted `using result_type = void`
  from `add_input` and `add_output` visitor structs in `json_object.cpp`. These
  were required by `boost::static_visitor` but are unused by `std::visit`.
- **Fixed uninitialized-variable warning**: Zero-initialized `local_blocks_to_unlock`
  and `local_time_to_unlock` in `wallet2::unlocked_balance_all()`.
- **Fixed aliasing cast in wallet serialization**: Replaced C-style cast of
  `m_account_tags` from `pair<serializable_map, vector>` to `pair<map, vector>&`
  with direct `.parent()` accessor, eliminating formal undefined behavior.
- **Suppressed epee warnings**: Added targeted `#pragma GCC diagnostic` guards
  for `-Wclass-memaccess` (memcpy into `mlocked<scrubbed<>>` in
  `keyvalue_serialization_overloads.h`) and `-Wstring-compare` (type_info
  comparisons in `portable_storage.h`).
- **Renamed test target**: `monero-wallet-crypto-bench` renamed to
  `shekyl-wallet-crypto-bench`.
- **Trezor Protobuf fixes**: Added `std::string()` wrapping for
  `GetDescriptor()->name()` calls in `messages_map.cpp/.hpp` to handle
  Protobuf 22+ returning `absl::string_view`/`std::string_view`. Added
  missing `<cstdint>` include to `exceptions.hpp`.

### Rust crypto infrastructure

- **New `shekyl-crypto-hash` crate**: Implements `cn_fast_hash` (Keccak-256
  with original padding, not SHA3) and `tree_hash` (Merkle tree) in Rust
  using `tiny-keccak`. Both functions produce byte-identical output to the
  C implementations in `src/crypto/hash.c` and `src/crypto/tree-hash.c`.
- **FFI exports**: `shekyl_cn_fast_hash` and `shekyl_tree_hash` exposed
  through `shekyl-ffi` with C-ABI declarations in `shekyl_ffi.h`. The C++
  side can now call Rust hashing alongside or instead of the C path.
- **Rust-preferred development rule**: Added `.cursor/rules/rust-preferred.mdc`
  establishing policy for gradual C++ to Rust migration: new modules in Rust,
  crypto primitives via RustCrypto crates, computational extraction to Rust
  behind FFI when modifying existing C++ modules.

### Hardfork reboot and testnet wallet readiness

- **Hardfork schedule rebooted**: All `HF_VERSION_*` constants collapsed to 1.
  The chain starts with all features active from genesis -- no legacy migration
  gates. Hardfork tables reduced to single-entry `{ 1, 1, 0, timestamp }` for
  all three networks (mainnet, testnet, stagenet).
- Removed all raw numeric HF version gates (`hf_version <= 3`, `>= 7`, `< 8`,
  `> 8`, etc.) from consensus and transaction construction code, replacing them
  with named `HF_VERSION_*` constants. Legacy Monero-era transition logic
  (borromean proofs, bulletproofs v1, grandfathered txs) removed.
- Coinbase transactions always v2 RCT with single output, zero dust threshold.
- **Staked outputs excluded from spendable balance**: `is_transfer_unlocked()`
  now returns false for staked outputs, preventing them from being selected
  during normal transfers. `balance_per_subaddress` and
  `unlocked_balance_per_subaddress` skip staked outputs.
- **Unstake transaction fixed**: `create_unstake_transaction` now passes matured
  staked output indices directly to `create_transactions_from`, properly using
  the actual staked UTXOs as transaction inputs with standard ring signatures.
- **Claim reward validation fixed**: `check_stake_claim_input` now looks up the
  real staked output from the blockchain DB to get the actual amount and tier,
  replacing the hardcoded `shekyl_stake_weight(0, 0)` placeholder.
- **New daemon RPC `estimate_claim_reward`**: computes per-output reward
  server-side using the accrual database, returning reward amount, tier, and
  staked amount. Wallet `estimate_claimable_reward` now calls this RPC instead
  of returning a hardcoded zero.
- **CLI improvements**: `balance` command now shows staked balance alongside
  liquid and unlocked balances. New `staking_info` command shows wallet staking
  overview (locked/matured output counts with tier and remaining lock blocks).
  `stake`, `unstake`, and `claim_rewards` commands now include daemon
  connectivity guards.
- **Wallet RPC fixes**: `unstake` response changed from single `tx_hash` to
  `tx_hash_list` array to support multi-transaction unstaking. `stake` request
  now accepts `account_index` parameter. New `get_staked_balance` RPC returns
  staked balance with locked/matured output counts.

### Post-quantum cryptography

- **Phase 4 wallet/core PQC wiring completed**: all v3 transaction construction
  paths now include hybrid Ed25519 + ML-DSA-65 signing via `pqc_auth`. Fixed
  `create_claim_transaction` (staking reward claims) which previously built v3
  transactions without PQC authentication, causing consensus rejection.
- PQC verification enforced in both mempool acceptance and block validation for
  all non-coinbase v3 transactions.
- Multisig wallets intentionally restricted to v2 transactions (no PQC); the
  PQC secret key is cleared on multisig creation with a documented design note.
- Aligned `POST_QUANTUM_CRYPTOGRAPHY.md` field naming: `hybrid_ownership_material`
  renamed to `hybrid_public_key` to match the canonical code implementation.
- Added three negative PQC test vectors (`docs/PQC_TEST_VECTOR_002–004`) covering
  tampered ownership material, wrong scheme_id, and oversized/truncated signature
  blobs. Each vector is generated and verified by integration tests in
  `rust/shekyl-crypto-pq/tests/negative_vectors.rs`.
- Reconciled `POST_QUANTUM_CRYPTOGRAPHY.md` Open Items: resolved Rust crate
  selection, `RctSigningBody` layout, ownership binding, and max tx size;
  only `scheme_id` registry extension remains open.
- Added tentative V4 PQC Privacy Roadmap to `POST_QUANTUM_CRYPTOGRAPHY.md`
  with four phases (V4-A Research, V4-B Prototype, V4-C Testnet,
  V4-D Activation) and explicit KEM composition decision milestone
  (`X25519 + ML-KEM-768` via `HKDF-SHA-512`).
- Added payload limit guidance section to `V3_ROLLOUT.md` with recommended
  minimum mempool/ZMQ/relay buffer sizes for post-PQC transactions.

### Economics and simulation

- Added `rust/shekyl-economics-sim` workspace crate: reproducible 8-scenario
  simulation harness driven from `config/economics_params.json`. Scenarios
  cover baseline, boom-bust, sustained growth, stuffing attack, stake
  concentration, mass unstaking, chain bootstrap, and late-chain tail state.
  Results archived in `docs/economics_sim_results.json`.
- Provisionally locked `tx_baseline` (50) and `FINAL_SUBSIDY_PER_MINUTE`
  (300,000,000) in `DESIGN_CONCEPTS.md` after simulation validation; pending
  final testnet confirmation.
- Wired live chain-health RPC fields in `get_info`: `release_multiplier` now
  computed from rolling `tx_volume_avg`, `burn_pct` from current chain state,
  `total_burned` persisted in LMDB and accumulated per block.
- Wired `total_staked` in `get_staking_info` via new
  `Blockchain::get_total_staked()` accessor backed by existing stake cache.
- Added `total_burned` LMDB persistence: `set_total_burned`/`get_total_burned`
  on `BlockchainDB`, with rollback support via extended `staker_accrual_record`
  (`actually_destroyed` field).

### Privacy and anonymity networks

- Updated `ANONYMITY_NETWORKS.md` with measured v3 payload impact analysis
  (cell/fragment counts for Tor and I2P), known leak vectors vs mitigations
  matrix, and recommended pre-mainnet testing checklist.
- Extended `LEVIN_PROTOCOL.md` wire inventory with per-command PQC size
  impact, anonymity sensitivity ratings, and a summary table covering all
  P2P and Cryptonote protocol commands.
- Added privacy considerations section to `STAKER_REWARD_DISBURSEMENT.md`
  covering claim timing, amount correlation, and staked output visibility.
- Added reward-driven privacy/mixing research appendix to
  `DESIGN_CONCEPTS.md` evaluating random maturation delay, claim batching,
  and reward output shaping with adversarial analysis and go/no-go criteria.

### C++17 and Boost migration

- **C++17 standard bump**: `CMAKE_CXX_STANDARD` changed from 14 to 17 in both
  the main `CMakeLists.txt` and the macOS cross-compilation toolchain
  (`contrib/depends/toolchain.cmake.in`). This unblocks `std::filesystem`,
  `std::optional`, and other modern C++ features. Upstream Monero cherry-picks
  that required C++14-to-C++17 back-ports now compile without shims.
- **`boost::optional` → `std::optional` (complete)**:
  Migrated ~486 use sites across ~93 files in `src/`, `contrib/epee/`, and
  `tests/`. Replaced `boost::optional<T>` with `std::optional<T>`,
  `boost::none` with `std::nullopt`, `boost::make_optional` with
  `std::make_optional`, and `.get()` accessor calls with `*` / `->`.
  Added a `std::optional` Boost.Serialization adapter in
  `cryptonote_boost_serialization.h` so PQC auth fields serialize correctly.
  Replaced `BOOST_STATIC_ASSERT`/`boost::is_base_of` with
  `static_assert`/`std::is_base_of` in Trezor `messages_map.hpp`.
- **`boost::filesystem` → `std::filesystem` (wallet/RPC layer)**:
  Migrated `wallet_manager.cpp`, `wallet_rpc_server.cpp`,
  `core_rpc_server.cpp`, and `wallet_args.cpp` from `boost::filesystem` to
  `std::filesystem`. Combined with the earlier utility-file migration, this
  covers all filesystem usage outside of `net_ssl.cpp` (epee, deferred due to
  permissions API coupling).
- **`boost::format` removal (wallet/RPC layer)**:
  Replaced all `boost::format` calls in `wallet2.cpp` (4), `wallet_rpc_server.cpp`
  (8), and `wallet_args.cpp` (1) with stream output or string concatenation.
  `simplewallet.cpp` (106 uses, i18n-sensitive) remains deferred.
- **`boost::chrono`/`boost::this_thread` in daemonizer**: Replaced with
  `std::chrono`/`std::this_thread` in `windows_service.cpp` (PR #9544 equivalent).
- **Medium-effort Boost removals (completed earlier)**:
  - `boost::algorithm::string` (trim, to_lower, iequals, join) replaced with
    `tools::string_util` helpers in `src/common/string_util.h`.
  - `boost::format` replaced with `snprintf`, stream output, or string
    concatenation in `util.cpp`, `message_store.cpp`, `gen_ssl_cert.cpp`,
    `gen_multisig.cpp`.
  - `boost::regex` replaced with `std::regex` in `simplewallet.cpp` and
    `wallet_manager.cpp`.
  - `boost::mutex`, `boost::lock_guard`, `boost::unique_lock`, and
    `boost::condition_variable` replaced with `std::mutex`, `std::lock_guard`,
    `std::unique_lock`, and `std::condition_variable` in `util.h`, `util.cpp`,
    `threadpool.h`, `threadpool.cpp`, and `rpc_payment.h`/`rpc_payment.cpp`.
  - `boost::thread::hardware_concurrency()` replaced with
    `std::thread::hardware_concurrency()`.
- **Filesystem migration (utility files, completed earlier)**:
  - `boost::filesystem` replaced with `std::filesystem` in
    `blockchain_export.cpp`, `blockchain_import.cpp`, `cn_deserialize.cpp`,
    `util.cpp`, `bootstrap_file.h`/`.cpp`, and `blocksdat_file.h`/`.cpp`.
  - Eliminated `BOOST_VERSION` preprocessor conditional in `copy_file()`.
- **Upstream Monero cherry-pick verification**: Confirmed PRs #9628 (ASIO
  `io_service` → `io_context`), #6690 (serialization overhaul), and #9544
  (daemonizer chrono/thread) are already absorbed in our tree.
- **`boost::variant` → `std::variant` (complete)**:
  Full migration from `boost::variant` to C++17 `std::variant` across the
  entire codebase (~100+ replacements in ~40 files):
  - **Serialization layer rewrite** (`serialization/variant.h`): Replaced
    Boost.MPL type-list iteration with C++17 `if constexpr` recursion for
    deserialization and `std::visit` lambda for serialization. Removed all
    `boost::mpl`, `boost::static_visitor`, and `boost::apply_visitor` usage.
  - **Archive headers**: Replaced `boost::mpl::bool_<B>` with
    `std::bool_constant<B>` in `binary_archive.h`, `json_archive.h`, and
    `serialization.h`. Replaced `boost::true_type`/`false_type` and
    `boost::is_integral` with `std` equivalents.
  - **Core typedefs**: Changed `txin_v`, `txout_target_v`, `tx_extra_field`,
    `transfer_view::block`, and Trezor `rsig_v` from `boost::variant` to
    `std::variant`.
  - **Boost.Serialization shim**: Added a local ~45-line `std::variant`
    serialization adapter in `cryptonote_boost_serialization.h` (save/load
    with index + payload, wire-compatible with old `boost::variant` format).
    Removed dependency on `<boost/serialization/variant.hpp>`.
  - **Mechanical replacements** across all `src/` and `tests/` files:
    `boost::get<T>(v)` → `std::get<T>(v)`,
    `boost::get<T>(&v)` → `std::get_if<T>(&v)`,
    `v.type() == typeid(T)` → `std::holds_alternative<T>(v)`,
    `v.which()` → `v.index()`,
    `boost::apply_visitor(vis, v)` → `std::visit(vis, v)`.
  - **P2P layer**: Updated `net_peerlist_boost_serialization.h` to use
    `std::false_type`/`std::true_type` instead of `boost::mpl` equivalents.
  - `tests/unit_tests/net.cpp` retains `boost::get<N>` for `boost::tuple`
    access via `boost::combine` (not variant-related).
- **Remaining deferred Boost areas**: ASIO deep plumbing,
  multi-index containers, Spirit parser, multiprecision, `net_ssl.cpp` filesystem,
  `simplewallet.cpp` format strings, `boost::thread::attributes` (stack size).
  Tagged with `TODO(shekyl-v4)` in source. See `DOCUMENTATION_TODOS_AND_PQC.md`
  section 1.11 for the full backlog.

### CI/CD and build system

- **Boost minimum bumped to 1.74**: `BOOST_MIN_VER` in `CMakeLists.txt` raised
  from 1.62 to 1.74. The `contrib/depends` system now pins Boost 1.74.0
  (previously 1.69.0) and builds with `-std=c++17`. Removed legacy Boost 1.64
  patches (`fix_aroptions.patch`, `fix_arm_arch.patch`) that do not apply to 1.74.
- **CI containers updated to Ubuntu 22.04 minimum**: Dropped Debian 11 and
  Ubuntu 20.04 build jobs from `build.yml`, `depends.yml`, and
  `release-tagged.yml`. Ubuntu 22.04 is now the lowest-common-denominator Linux
  build environment (ships Boost 1.74+ and GCC 11+). Added Ubuntu 24.04 build
  matrix entry.
- Migrated version identifiers from legacy `MONERO_*` symbols to canonical
  `SHEKYL_*` names (`SHEKYL_VERSION`, `SHEKYL_VERSION_TAG`,
  `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_FULL`, `SHEKYL_VERSION_IS_RELEASE`)
  in `src/version.h` and `src/version.cpp.in`. The old `MONERO_*` names are
  retained as preprocessor aliases so existing call sites and future Monero
  upstream cherry-picks continue to compile unchanged. The aliases will be
  removed in a single cleanup after v4 RingPQC stabilises.
- Fixed Gitian deterministic build pipeline: replaced all hardcoded Monero
  repository URLs and internal package names with Shekyl equivalents across
  `gitian-build.py`, all 5 gitian descriptor YAMLs, `dockrun.sh`, and the
  `gitian.yml` GitHub Actions workflow. The workflow now passes `--url` to
  ensure the correct repository is cloned. Added checkout error handling with
  an actionable message when a tag/branch is missing.
- Tag-driven versioning: `GitVersion.cmake` now extracts the version string
  from git tags (e.g. `v3.0.2-RC1` → `3.0.2-RC1`). The hardcoded version in
  `version.cpp.in` is replaced with the CMake-substituted `@SHEKYL_VERSION@`;
  a default (`3.1.0`) is used for development builds not on a tag.
  `Version.cmake` centralises the fallback default in `SHEKYL_VERSION_DEFAULT`.
- Updated RPC version string validator (`rpc_version_str.cpp`) from Monero's
  four-number format to Shekyl's three-number semver with optional pre-release
  suffix (e.g. `3.0.2-RC1-release`).
- Updated gitian descriptor names from Monero's `0.18` to Shekyl `3` series.
- Added `release/tagged` GitHub Actions workflow: builds static Linux x86_64
  binaries, cross-compiles Windows x64 via MinGW, and produces `.tar.gz`,
  `.deb`, `.rpm`, `.zip`, and NSIS `.exe` installer artifacts on every `v*` tag.
- Added `BuildRust.cmake` cross-compilation support: detects `CMAKE_SYSTEM_NAME`
  and `CMAKE_SYSTEM_PROCESSOR` to derive Rust target triples for Windows, macOS,
  Android, FreeBSD, and Linux cross-targets (ARM, aarch64, i686, RISC-V);
  automatically configures the MinGW linker for Windows cross-compilation.
- Added Rust toolchain installation to all CI workflows (`build.yml`,
  `depends.yml`, `release-tagged.yml`) and all 5 Gitian deterministic build
  descriptors with appropriate cross-compilation targets; required for
  `libshekyl_ffi.a` linking.
- Fixed Gitian `gitian-build.py` to fetch tags explicitly (`--tags`) during
  repository setup, preventing checkout failures for tag-based builds.
- Enhanced `gitian-build.py` error handling: robust `lsb_release` detection,
  auto-correction of stale clone origins when `--url` changes, and detailed
  diagnostics on checkout failure (lists available remote tags and suggests
  the push command).
- Added `workflow_dispatch` trigger to `gitian.yml` with configurable `tag` and
  `repo_url` inputs, allowing manual re-runs and testing against forks without
  retagging.
- Fixed Doxygen project name from `Monero` to `Shekyl` in `cmake/Doxyfile.in`.
- Replaced bundled Google Test 1.7.0 (2013) with CMake `FetchContent` for
  GoogleTest v1.16.0. Fixes `GTEST_SKIP` compilation errors on all platforms
  without a system gtest. Removes 34k lines of vendored source.
- Upgraded all GitHub Actions workflows to Node.js 24: bumped `actions/checkout`
  to v5, `actions/cache` to v5, `actions/upload-artifact` to v6, and
  `actions/download-artifact` to v7 to resolve the Node.js 20 deprecation
  warnings.
- Trimmed `depends.yml` cross-compilation matrix: dropped i686 Win and i686
  Linux (32-bit targets are dead); deferred RISCV 64-bit and ARM v7 until
  user demand materialises. Active matrix is now ARM v8, Win64, x86_64 Linux,
  Cross-Mac x86_64, Cross-Mac aarch64, and x86_64 FreeBSD (6 targets, down
  from 10). Added Cross-Mac aarch64 to the artifact upload filter.
- Added Linux packaging files: `contrib/packaging/linux/shekyld.service`
  (systemd unit) and `contrib/packaging/windows/shekyl.nsi` (NSIS installer).

### Upstream Monero sync (March 2026)

Cherry-picked 62 upstream Monero commits (from `monero-project/monero` master)
across five risk-phased integration rounds. Key improvements absorbed:

- **Wallet**: Fee priority refactoring (`fee_priority` enum + utility functions),
  improved subaddress lookahead logic, `set_subaddress_lookahead` RPC endpoint
  (no longer requires password), incoming transfers without daemon connection,
  HTTP body size limit, fast refresh checkpoint fix, ring index sanity checks,
  `find_and_save_rings()` deprecation, pool spend identification during scan.
- **Daemon/RPC**: Dynamic `print_connections` column width, ZMQ IPv6 support,
  dynamic base fee estimates via ZMQ, `getblocks.bin` start height validation,
  CryptoNight v1 error reporting, batch key image existence check, blockchain
  prune DB version handling, removed `COMMAND_RPC_SUBMIT_RAW_TX` (light wallet
  deprecated).
- **P2P/Network**: Removed `state_idle` connection state, fixed inverted peerlist
  ternary, removed `#pragma pack` from protocol defs, connection patches for
  reliability, dynamic block sync span limits.
- **Crypto/Serialization**: Fixed invalid `constexpr` on hash functions, added
  `hash_combine.h`, aligned container pod-as-blob serialization, fixed
  `apply_permutation()` for `std::vector<bool>`.
- **Build system**: Removed iwyu/MSVC/obsolete CMake targets, added
  `MANUAL_SUBMODULES` cache option, Trezor protobuf 30 compatibility, fixed
  `FetchContent`/`ExternalProject` cmake usage.
- **Tests**: New unit tests for format utils, threadpool, varint, logging,
  serialization static asserts, cold signing functional test fixes.
- **Misc**: Boost ASIO 1.87+ compatibility, fixed Trezor temporary binding,
  fixed multisig key exchange intermediate message update, `constexpr`
  `cn_variant1_check`, extra nonce length fix, removed redundant BP consensus rule.

Skipped commits (deferred to future integration): input verification caching
(conflicts with `txin_stake_claim`/PQC), `wallet_keys_unlocker` refactoring,
`get_txids_loose` DB API (missing prerequisite), complex subaddress lookahead
fixes, and several CMake/depends version bumps that conflict with Shekyl's
build system divergences.

Cherry-picked code was initially adapted to C++14 compatibility; with the
subsequent C++17 standard bump, many of those back-ports are now unnecessary
and can use native `std::optional`, `std::string_view`, etc.

### Documentation

- Added `docs/EXECUTABLES.md`: comprehensive reference for all 17 build
  artifacts covering usage, CLI options, interactive commands, and examples
  for `shekyld`, `shekyl-wallet-cli`, `shekyl-wallet-rpc`, blockchain
  utilities, and debug tools.

### Operations

- Added `utils/systemd/shekyld.service` for Shekyl-native daemon service
  deployment (`/usr/local/bin/shekyld` + `/etc/shekyl/shekyld.conf`).
- Updated `docs/INSTALLATION_GUIDE.md` related-doc references to include seed
  operations documentation in the companion `shekyl-dev` docs set.
- Added `docs/BLOCKCHAIN_NETWORKS.md` with a deep-dive comparison of network
  models across Bitcoin, Ethereum, Monero, Solana, Polkadot, and Avalanche,
  and mapped those patterns to Shekyl's mainnet/testnet/stagenet/fakechain
  usage guidance.
- Migrated Shekyl stagenet defaults from legacy Monero ports to
  `13021` (P2P), `13029` (RPC), and `13025` (ZMQ), and aligned test/docs
  references so `--testnet` workflows use `12029` while scripts support
  overrideable network/daemon variables.
- Updated libwallet API helper scripts to call `shekyl-wallet-cli` (not
  `monero-wallet-cli`) so test tooling matches Shekyl binary names.

### Staking (end-to-end claim-based system)

- Added `txout_to_staked_key` output target type for locking coins at a chosen
  tier (short/medium/long). Outputs carry `lock_tier` field enforced at the
  consensus layer. (Note: `lock_until` was originally stored on-chain but was
  removed in a subsequent fix — see Bug 13 under Unreleased.)
- Added `txin_stake_claim` input type for claiming accrued staking rewards.
  Claims specify a height range and are validated against deterministic per-block
  accrual records.
- Extended LMDB schema with `staker_accrual` and `staker_claims` tables plus a
  `staker_pool_balance` property for on-chain reward pool accounting.
- Per-block accrual logic computes staker emission share and fee pool allocation
  at block insertion time, with full reversal on reorg (block pop).
- Consensus validation: lock period enforcement on staked outputs, claim amount
  verification against accrual records, watermark-based anti-double-claim,
  maximum claim range (10,000 blocks), pool balance sufficiency checks.
- Pure claim transactions (`txin_stake_claim`-only inputs) use `RCTTypeNull`
  signatures, cleanly separated from ring-signature transaction validation.
- Extended `tx_destination_entry` with `is_staking` and `stake_tier`
  fields. `construct_tx_with_tx_key` emits `txout_to_staked_key` outputs
  when `is_staking` is set.
- Extended `transfer_details` with `m_staked`, `m_stake_tier`, and
  `m_stake_lock_until` for wallet-side staking metadata tracking.
  (`m_stake_lock_until` is computed locally from `creation_height + tier_lock_blocks`.)
- Implemented wallet2 methods: `create_staking_transaction`,
  `create_unstake_transaction`, `create_claim_transaction`,
  `get_matured_staked_outputs`, `get_locked_staked_outputs`,
  `get_claimable_staked_outputs`, `get_staked_balance`,
  `estimate_claimable_reward`.
- Added simplewallet commands: `stake <tier> <amount>`, `unstake`,
  `claim_rewards`.
- Added wallet RPC endpoints: `stake`, `unstake`, `get_staked_outputs`,
  `claim_rewards`.
- Added daemon RPC endpoint: `get_staking_info` returning current staking
  metrics (height, stake ratio, pool balance, emission share, tier lock blocks).
- Wired `stake_ratio` and `staker_pool_balance` in `/get_info` to live
  blockchain state.
- No minimum stake amount enforced (matches design doc).
- Fixed compilation errors from `txin_stake_claim` missing in exhaustive
  `boost::static_visitor` patterns: added `operator()` overloads to the
  double-spend visitor (`blockchain.cpp`) and the JSON serialization visitor
  (`json_object.cpp`), added JSON deserialization branch for `"stake_claim"`
  inputs, added `toJsonValue`/`fromJsonValue` declarations and implementations
  for `txin_stake_claim`, and added Boost.Serialization `serialize()` free
  function for wallet binary archive support (`cryptonote_boost_serialization.h`).

### Consensus and mining economics

- Wired Four-Component economics to live chain-state inputs for miner reward
  paths:
  - block template construction now passes rolling `tx_volume_avg`,
    `circulating_supply`, and `stake_ratio` to `construct_miner_tx`
  - miner transaction validation now uses the release-multiplier reward path
    and non-placeholder fee-burn inputs
  - tx pool block template estimation now uses the same rolling
    `tx_volume_avg` reward path for consistency
- Added `Blockchain::get_tx_volume_avg(height)` and
  `Blockchain::get_stake_ratio(height)` (stubbed to `0` until staking state is
  consensus-tracked).

### Modular PoW

- Added pluggable PoW schema abstractions:
  - `IPowSchema` interface
  - `RandomX` and `Cryptonight` schema implementations
  - PoW registry-based selection preserving existing behavior by block version
- Refactored `get_block_longhash` to route through the PoW schema registry while
  keeping existing RandomX seed handling and the historical block 202612
  workaround.
- Updated miner thread preparation to call schema-level
  `prepare_miner_thread(...)` (RandomX prepares thread context; Cryptonight is
  a no-op).
