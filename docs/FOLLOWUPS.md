# Follow-ups

Open residue only. Per `.cursor/rules/95-documentation-lifecycle.mdc` and
`.cursor/rules/15-deletion-and-debt.mdc`, every item is a one-liner with a
`Target:` of **pre-genesis**, **post-genesis**, or **V4**. Essays live in the
owning plan doc. Resolved items are removed — git history is the archive.

Acceptances that are not work items: [`audit_trail/FOLLOWUPS_ACCEPTANCES.md`](audit_trail/FOLLOWUPS_ACCEPTANCES.md).

There is no V3.1 / V3.2 / V3.x release train.

## Pre-genesis

Default. Lands before genesis if it should exist at launch.

- **Delete `fill_construct_tx_rct_stub`** — the remaining half of the CT-naming [`CT_SURFACE_NAMING_PIN.md`](design/CT_SURFACE_NAMING_PIN.md)
  - Target: pre-genesis

- **The C++ transaction builder is test-only and nothing tracked that.** [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  - Target: pre-genesis

- **`src/device/device_ledger.*` may be the next `device_cold.hpp`** [`CMakeLists.txt`](../CMakeLists.txt)
  - Target: pre-genesis

- **`get_archival_emission_claim_source` walks the entire serve-credit table per unauthenticated RPC** (PR-P4; fix is consensus+LMDB aggregate, not wallet-side).
  - Target: pre-genesis

- **`shekyl-ffi` has 105 undocumented items, so `missing_docs` cannot gate detached-doc drift.**
  - Target: pre-genesis

- **Staking has no REACHABLE exit: Unbond assembles (PR-P4) but has no RPC/CLI; Rebond/HoldingsUpdate still refuse.** [`ARCHIVAL_BOND_GATE4.md`](design/ARCHIVAL_BOND_GATE4.md)
  - Target: pre-genesis

- **Assembled `Unbond` bytes are never submitted through the native C++ consensus path (the daemon walk); blocked on the Unbond submit fact set.** [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md)
  - Target: pre-genesis

- **Release-asset manifest signing owed before the first non-RC release
  - Target: pre-genesis

- **F-7 structural gate for the test-only PQC FFI exports (added
  - Target: pre-genesis

- **GENESIS ADDRESS FORMAT: PQ signing anchor decision (address v2) — [`design/WALLET_MESSAGE_SIGNING.md`](./design/WALLET_MESSAGE_SIGNING.md)
  - Target: pre-genesis

- **FFI *signature* drift has no remedy, unlike FFI *constant* drift [`audit_trail/2026-05-ffi-constant-drift-audit.md`](./audit_trail/2026-05-ffi-constant-drift-audit.md)
  - Target: pre-genesis

- **TJ-1 (was CRITICAL) — leaf-index beacon MITIGATED 2026-08-24 (`PC-D3`); still closes by TJ-B deleting the vin-carried opening.** [`ARCHIVAL_RESPONSE_FORMAT.md`](design/ARCHIVAL_RESPONSE_FORMAT.md)
  - Target: pre-genesis

- **TJ-2 — `CHALLENGE_RESPONSE_BLOCKS` is PINNED (2026-08-15); the freeze item
  - Target: pre-genesis

- **TJ-3/TJ-4 (HIGH, `(m, n)` re-pin inputs)** (added 2026-07-29, §10.3–§10.4).
  - Target: pre-genesis

- **TJ-7 (HIGH, sweep input) — sybil-per-shard has NO uniqueness constraint,
  - Target: pre-genesis

- **TJ-8 (briefing constraint on the Round-2 re-pin) — do NOT credit the
  - Target: pre-genesis

- **TJ-5 (MEDIUM, fix-in-place)** (added 2026-07-29, §10.5–§10.6).
  - Target: pre-genesis

- **TJ price premise — NOT codeable, tracked here with its falsifiers as
  - Target: pre-genesis

- **Superseded-section cross-reference sweep (docs hygiene, split out by the
  - Target: pre-genesis

- **Live-pin index, independent of doc status (process-structural — added
  - Target: pre-genesis

- **Daemon chain store (`DRS-*`) — gap-close pass landed in design.** SoT: [`docs/design/DAEMON_REDB_STORE.md`](./design/DAEMON_REDB_STORE.md)
  - Target: pre-genesis

- **DRS-P0 multi-PR — blocks DRS-0.** **P0a** schema+CI; **P0b**
  - Target: pre-genesis

- **DRS-BENCH — resource/privacy/IBD/pop suite (not throughput).** File
  - Target: pre-genesis

- **DRS-D3c — cross-store leaf/position KAT.** Daemon vs wallet LeafStore:
  - Target: pre-genesis

- **`BlockchainLMDB::reset()` drops an INCOMPLETE table set — stale Shekyl
  - Target: pre-genesis

- **Round-2 stressnet re-pin of the failure-window `m`/`n` — must be JOINT with
  - Target: pre-genesis

- **`prev_block` block templates deleted (RESERVED at the RPC) — reopen has a
  - Target: pre-genesis

- **`sweep_all` — deleted in WI-RPC-2b, no Shekyl-native surface; decide
  - Target: pre-genesis

- **Drain/claim dispatch driver — terminal-reject prune + byte-identical resubmit remain (confirmation-observe landed 2026-08-27, #572).**
  - Target: pre-genesis

- **Q11 zero-fee-input emission claim has no settlement evidence** (destitute mint-pays-fee; named blocker: accrual has no claim-match set).
  - Target: pre-genesis

- **Enumerate the greenfield pending set: items whose only callers are tests** (`cargo clippy -p <crate>` vs `--all-targets`).
  - Target: pre-genesis

- **GF-7 `stake_in` change-co-presence residual — shipped with a warning,
  - Target: pre-genesis

- **Workspace-wide `deny_unknown_fields` on the remaining wallet-RPC params
  - Target: pre-genesis

- **Wallet thin-market entry disclosure — the §13.2 re-disposition's
  - Target: pre-genesis

- **Solo address registry: decide (a registration tx type is genesis-only)**
  - Target: pre-genesis

- **Unbond verify: record-floor belt (the `RebondRecordFloorBroken` twin)**
  - Target: pre-genesis

- **RPC transport posture — RULED 2026-08-21; RT-W1 landed; RT-W2/W5/W7 authorized**
  - Target: pre-genesis

- **Daemon Axum: onion-as-remote-RPC docs + operator story** (added
  - Target: pre-genesis

- **Daemon Axum: connection caps + live `rpc_connections_count`** (added
  - Target: pre-genesis

- **Rust wallet stack: no Windows support (blocks Windows wallet [`WINDOWS_WALLET_SUPPORT.md`](design/WINDOWS_WALLET_SUPPORT.md)
  - Target: pre-genesis

- **Hardware-device C++ surface: B2 LANDED 2026-08-18 — deleted**
  - Target: pre-genesis

- **Daemon RPC: restricted-method dual-list single-source** (added
  - Target: pre-genesis

- **Phase 4b: `rescan_blockchain` needs an Engine rescan API** —
  - Target: pre-genesis

- **Phase 4c: no way to abandon an unconfirmed submitted transaction, so a
  - Target: pre-genesis

- **Phase 4b: `get_transfers` OUTGOING filter is a no-op until an outgoing
  - Target: pre-genesis

- **Phase 4b: build concurrency permit stays 1 — raising it is a rule-21
  - Target: pre-genesis

- **GF4b-2 genesis gate — bond-post funding-input-count leak; `stake_in`
  - Target: pre-genesis

- **Block-height representation unification at the WI-2 anchoring seam**
  - Target: pre-genesis

- **Alt-chain supply accumulation advances by the coinbase, not the emission
  - Target: pre-genesis

- **Difficulty-surface newtypes — type `shekyl-difficulty`'s primitive PoW [`18-type-placement`](../.cursor/rules/18-type-placement.mdc)
  - Target: pre-genesis

- **External cryptographic review of the `FcmpMembershipOnly` soundness [`completed/FCMP_MEMBERSHIP_ONLY.md`](./completed/FCMP_MEMBERSHIP_ONLY.md)
  - Target: pre-genesis

- **Emission leg: verify reward→identity binding is structural, not [`design/ARCHIVAL_FIREWALL_GATE6.md`](./design/ARCHIVAL_FIREWALL_GATE6.md)
  - Target: pre-genesis

- **FCMP++ circuit: confirm `incomplete_add_pub` need not constrain `c` [`completed/SHEKYL_OXIDE_UNVENDOR.md`](./completed/SHEKYL_OXIDE_UNVENDOR.md)
  - Target: pre-genesis

- **Corpus-freeze guards: align `address_derivation_freeze` error message [`rust/shekyl-crypto-pq/src/archival_p_freeze.rs`](../rust/shekyl-crypto-pq/src/archival_p_freeze.rs)
  - Target: pre-genesis

- **Block-height-only `unlock_time`: native `Timelock`, a pruned-safe context-free
  - Target: pre-genesis

- **Repo-wide `RingCT`/`rct`/`RCT` → `CT` semantic sweep — a Shekyl tx is simply a
  - Target: pre-genesis

- **Store-backed / pruned-tree path assembly (CT-3 pre-flight F5, [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)
  - Target: pre-genesis

- **C++ path RPC computes a crypto contract (`hash_to_p3`) inline —
  - Target: pre-genesis

- **C++ FCMP++ wallet send path is incomplete; 2026-06-21 debugging [`20-rust-vs-cpp-policy`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  - Target: pre-genesis

- **`get_curve_tree_leaves` daemon endpoint + KAT (CT-3 R1-Q1 deferral [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)
  - Target: pre-genesis

- **Rollback-adjacent frozen-`R_k` recheck on plain resume (CT-3c C1
  - Target: pre-genesis

- **Full all-segment frozen-`R_k` recheck (CT-3c bounded-check deferral,
  - Target: pre-genesis

- **Refresh-over-spend reorg: optimistic-spend `spent_height` invariant +
  - Target: pre-genesis

- **`AlreadyInChain` submit verdict: distinct lock-lifecycle disposition —
  - Target: pre-genesis

- **Watchdog probe bytes: ephemeral in-memory held-bytes store — reversion
  - Target: pre-genesis

- **Submit-error reservation-id placeholder: split submitter error from
  - Target: pre-genesis

- **F41 constant-work-on-Conceal: invariant NAMED + enforcement DECOMPOSED
  - Target: pre-genesis

- **CT-2 Tier B reconstruct-root KATs (staked / non-coinbase maturity [`docs/completed/CT2_ROUND1_CLOSEOUT.md`](./completed/CT2_ROUND1_CLOSEOUT.md)
  - Target: pre-genesis

- **CT-5 real-tree FCMP++ verify — deeper-tree + pin validation (depth-2 case [`docs/completed/DEPTH3_CURVE_TREE_CUTOVER.md`](completed/DEPTH3_CURVE_TREE_CUTOVER.md)
  - Target: pre-genesis

- **Output-class numbering-equivalence re-verification (CT-5c X3 standing [`docs/completed/CT5C_ASSEMBLER_CUTOVER.md`](./completed/CT5C_ASSEMBLER_CUTOVER.md)
  - Target: pre-genesis

- **CT-5d reselect: content-changing re-anchor (lock-transplant), tracked [`docs/completed/CT5D_REANCHOR.md`](./completed/CT5D_REANCHOR.md)
  - Target: pre-genesis

- **CT-5d background opportunistic re-anchor + the eager reorg mark, tracked [`docs/completed/CT5D_REANCHOR.md`](./completed/CT5D_REANCHOR.md)
  - Target: pre-genesis

- **CT-5d broadcast-but-unmined reference orphan, tracked 2026-06-18.** Target:
  - Target: pre-genesis

- **CT-5d re-confirm UX: handle accessor + `(fee, change)` delta on
  - Target: pre-genesis

- **CT-5d: retire the vestigial `SnapshotId` / `SnapshotInvalidated` submit path,
  - Target: pre-genesis

- **Full-segment freeze + prune-retention KAT at production `j=2` leaf count [`docs/completed/CT1_ROUND1_CLOSEOUT.md`](./completed/CT1_ROUND1_CLOSEOUT.md)
  - Target: pre-genesis

- **Wallet-local `O.x → position` match index (`CurveTreeClient` §4.3 scan [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)
  - Target: pre-genesis

- **Confirm segment layer `j` / shard size `E` against mainnet leaf growth [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)
  - Target: pre-genesis

- **Anonymized (Tor/I2P) routing for non-forward segment fetch (CT Round 0 [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)
  - Target: pre-genesis

- **Shard serving on `P`: zstd compression REJECTED by measurement
  - Target: pre-genesis

- **Single-dispatcher nm gate: extend beyond `shekyld` (2026-06-11
  - Target: pre-genesis

- **`SEGMENT_FREEZE_REORG_MARGIN_BLOCKS` dedup (CT-1).** Target: PHASE_2B / [`config/consensus_constants.json`](../config/consensus_constants.json)
  - Target: pre-genesis

- **Gate-6 synchronized-exit wargame round (swan-2/W8, 2026-06-11).** A black [`design/F1_TA3_TA7_LIFETIME_WINDOW.md`](./design/F1_TA3_TA7_LIFETIME_WINDOW.md)
  - Target: pre-genesis

- **Foundation treasury diversification — floor capacity must not be
  - Target: pre-genesis

- **Re-derive genesis-sealed redundancy params against the integer backend
  - Target: pre-genesis

- **Funding-seam entry-standoff: consensus surface, wallet conformance, and the [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **Wallet bond-funding/standoff call site (tracks the `shekyl-standoff`
  - Target: pre-genesis

- **`shekyl-stats` `Z_ALPHA_1E6` provenance vs. the `enc_label` test's
  - Target: pre-genesis

- **`HoldingsUpdate` (partial-unbond/rebond) promoted to genesis scope + pre-seal
  - Target: pre-genesis

- **Archival serve-credit / emission LMDB scans — bound the two unindexed table
  - Target: pre-genesis

- **Emission-path micro-efficiency cluster — address with C-1 wiring / the schema
  - Target: pre-genesis

- **Staker-archival settings are FROZEN; the remaining work is the operator experience, not [`docs/STAKER_OPERATOR_GUIDE.md`](STAKER_OPERATOR_GUIDE.md)
  - Target: pre-genesis

- **Wallet-side archival bond-post construction (design + JoinMarket, PR 0-2a [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`](design/ARCHIVAL_BOND_CONSTRUCTION.md)
  - Target: pre-genesis

- **StakeEngine Model D wiring — deferred work + rule-21 reopens (PR 2c-2a, [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)
  - Target: pre-genesis

- **Archival bond request path — deferred items (PR 2c-2b, landed inert
  - Target: pre-genesis

- **Genesis ceremony tooling: `generate-genesis-address` CLI
  - Target: pre-genesis

- **USER_GUIDE realignment to the Rust CLI surface (2026-06-10 doc
  - Target: pre-genesis

- **Stage 1 trait-extraction chain — closeout audit (2026-05-29, [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **`KeyEngine` inline orchestrator integration — rejected for Stage 1; [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **Post-2g adversarial-corpus methodology + implementation [`docs/completed/RANDOMX_V2_PHASE2H_PLAN.md`](./completed/RANDOMX_V2_PHASE2H_PLAN.md)
  - Target: pre-genesis

- **Refresh bandwidth tradeoff under α — round-trip-bound block [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **F11-S Windows-midrange-PC measurement revisit at stressnet [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **Stage 1 PR 3 engine-property test re-location (trigger:
  - Target: pre-genesis

- **`RecoveredWalletOutput.key_image`: promote to `Option<KeyImage>`
  - Target: pre-genesis

- **`shekyl-fcmp`: resolve `useless_conversion` clippy warnings in
  - Target: pre-genesis

- **Full migration of remaining `SHEKYL_*` FFI constants to the
  - Target: pre-genesis

- **`wallet_storage`: cover loaded-wallet save-as branches in
  - Target: pre-genesis

- **Stage 1 performance baseline measurement before Stage 1 PRs land.** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **`kameo` dependency pin and MSRV alignment before Stage 2 cuts.**
  - Target: pre-genesis

- **View/HW lifecycle bodies in `shekyl-wallet-core`.**
  - Target: pre-genesis

- **Revisit `rust/hard-coded-cryptographic-value` CodeQL suppression
  - Target: pre-genesis

- **Stage 2 — `KeyEngine` migration to actor.** Migrate key material + [`STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)
  - Target: pre-genesis

- **Subaddress mechanism under PQC — dedicated design round (2026-05-31, [#112](https://github.com/Shekyl-Foundation/shekyl-core/pull/112)
  - Target: pre-genesis

- **FA-6 — PQ-safe view-tag pre-filter (T6 closure, genesis).**
  - Target: pre-genesis

- **FA-6b — v31 multisig `tx_extra_pqc_view_tag_hints` ().** Separate from
  - Target: pre-genesis

- **`tx_extra` `0x02` Nonce: shed from the genesis grammar — FA-10 is
  - Target: pre-genesis

- **Phase 2a send path — engine substrate (closed 2026-06).** `LocalPendingTx`
  - Target: pre-genesis

- **Phase 2b planning session — stake state-machine shape (gate for [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  - Target: pre-genesis

- **Stage 3 — `StakeEngine` native actor build.** Build the Phase
  - Target: pre-genesis

- **Owned `AtomicUnits::mul_div_rem` — deferred (rule-21 reversion clause; spawned [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  - Target: pre-genesis

- **Consolidate hand-copied `10^9` / decimal-point constants onto the `shekyl-units`
  - Target: pre-genesis

- **JSON-RPC large-amount precision — string-amount serde at the RPC edge (spawned
  - Target: pre-genesis

- **Confidential stake-UTXO transfer (privacy-compatible; compounds (C)).** [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  - Target: pre-genesis

- **Stage 4 — Remaining-subsystem migrations.** Migrate
  - Target: pre-genesis

- **RPC boundary refinements — idle eviction, `engine_lock`,
  - Target: pre-genesis

- **`Hybrid*` secret types: `Vec<u8>` for fixed-size scalars —
  - Target: pre-genesis

- **`fips204` features-list discipline: drop `default-rng` and [`rust/shekyl-crypto-pq/Cargo.toml`](../rust/shekyl-crypto-pq/Cargo.toml)
  - Target: pre-genesis

- **`epee::wipeable_string` mlock-backed allocator [`contrib/epee/include/wipeable_string.h:83`](../contrib/epee/include/wipeable_string.h)
  - Target: pre-genesis

- **CryptoNote fossil — hardcoded key-image fixup for Monero blocks [`src/blockchain_db/blockchain_db.cpp`](../src/blockchain_db/blockchain_db.cpp)
  - Target: pre-genesis

- **RandomX v2 Phase 3c / Phase 4 — PoW C-core + abstraction deletion** [`docs/design/RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md)
  - Target: pre-genesis

- **Promote 2c-emergent sub-PR design disciplines to project-level [`.cursor/rules/26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc)
  - Target: pre-genesis

- **CL-7 forward-compat audit of trait-owned value/error types [`engine/error/send.rs`](../rust/shekyl-engine-core/src/engine/error/send.rs)
  - Target: pre-genesis

- **`shekyl-tx-builder::SpendInput` derives plain `#[derive(Debug)]` over [`rust/shekyl-tx-builder/src/types.rs`](../rust/shekyl-tx-builder/src/types.rs)
  - Target: pre-genesis

- **Migrate residual consensus-parity Keccak (`keccak256`) call sites to cSHAKE256 / [`shekyl_crypto_hash::keccak256`](../rust/shekyl-crypto-hash/src/lib.rs)
  - Target: pre-genesis

- **Multisig FROST spend path needs the single-sig spend-path consensus fixes.**
  - Target: pre-genesis

- **Serve-credit C++ consensus decisions — Rust equivalence audit + [`REWARD_EMISSION_E3_GATING_ROUND.md`](./completed/REWARD_EMISSION_E3_GATING_ROUND.md)
  - Target: pre-genesis

- **Emission regtest end-to-end — the E4/E5 gate** (surfaced 2026-07-09, [`REWARD_EMISSION_E3_GATING_ROUND.md`](./completed/REWARD_EMISSION_E3_GATING_ROUND.md)
  - Target: pre-genesis

- **Market-bond wallet entry — `first_stake`'s genesis posture cannot
  - Target: pre-genesis

- **Shard assignment for market staking — the `NoShardsAvailable`
  - Target: pre-genesis

- **F5 pruning inherits two constraints from the CompleteTree round**
  - Target: pre-genesis

- **The wallet-RPC server parses every request into a `serde_json::Value`**
  - Target: pre-genesis

- **Emission-claim retire/resubmit driver legs** (surfaced 2026-07-12
  - Target: pre-genesis

- **Q11 balance-exclusion KAT — blob-boundary invariant arm** [`EMISSION_CLAIM_BUILDER.md`](./design/EMISSION_CLAIM_BUILDER.md)
  - Target: pre-genesis

- **Daemon Rust submit engine: bond-post + emission submit batteries — [`EMISSION_CLAIM_BUILDER.md`](./design/EMISSION_CLAIM_BUILDER.md)
  - Target: pre-genesis

- **Single-sig address decode enforces the Bech32m variant** [`rust/shekyl-address/src/address.rs`](../rust/shekyl-address/src/address.rs)
  - Target: pre-genesis

- **Credit-wire cutover has two preconditions the Phase-2 verify cannot satisfy [`cryptonote_core.cpp`](../src/cryptonote_core/cryptonote_core.cpp)
  - Target: pre-genesis

- **Round-2 stressnet: re-pin archival `m`/`n`** (surfaced 2026-07-25
  - Target: pre-genesis

- **Raw-import archival/burn bookkeeping parity** (surfaced 2026-07-09,
  - Target: pre-genesis

- **Serve-credit decision-site flip: Rust becomes the primary decision
  - Target: pre-genesis

- **`tests/performance_tests/` — rule-15 deletion-or-adoption audit**
  - Target: pre-genesis

- **Remove or retain the orphaned `ActivityMetric.total_staked` observable
  - Target: pre-genesis

- **Wallet file backup-exclusion markers (PR 6 lessons canvass §5.12 F1).** [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](./completed/STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
  - Target: pre-genesis

- **Process core-dump disable at wallet-RPC startup (PR 6 §5.12 F2).**
  - Target: pre-genesis

- **Argon2 stack-resident secret copies — cryptographer review (PR 6 §5.12 F3).**
  - Target: pre-genesis

- **Rust `WalletFile` vs C++ `wallet2` advisory-lock cross-test (PR 6 §5.12 F4).**
  - Target: pre-genesis

- **Async `Engine::close` / `change_password` lifecycle (PR 6 PR #83).** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **Shekyl-native end-to-end wallet/daemon test harness [`ELECTRUM_WORDS_REMOVAL_PLAN.md`](./completed/ELECTRUM_WORDS_REMOVAL_PLAN.md)
  - Target: pre-genesis

- **RandomX v2 — Guix reproducible-build obligation pickup (trigger: [`docs/design/RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md)
  - Target: pre-genesis

- **Rules-queue: reconcile the priority-ordering statements across [`00-mission.mdc`](../.cursor/rules/00-mission.mdc)
  - Target: pre-genesis

- **Rules-queue: elevate per-gate reviewer-discipline calibration [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md)
  - Target: pre-genesis

- **Rules-queue: elevate the public-material typed-wrapper exclusion [`docs/completed/STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)
  - Target: pre-genesis

- **Rules-queue: elevate the plan-vs-state-divergence pattern into a [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **Rules-queue: encode the rule-15 trinary reading [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **Rules-queue: consolidate the rules-queue itself into 1–2 PRs.** [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./completed/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  - Target: pre-genesis

- **Rules-queue: encode the pre-flight-FOLLOWUP-scope discipline.** [`docs/completed/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./completed/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md)
  - Target: pre-genesis

- **Non-`Clone` ban on `TransferDetails` — post-M3d structural [`docs/completed/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./completed/STAGE_1_PR_3_M3D_PREFLIGHT.md)
  - Target: pre-genesis

- **`fips203` interior `into_bytes()` Copy on the ML-KEM-768 decap-key [`docs/completed/STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)
  - Target: pre-genesis

- **`derive_output_handle` Python reference script.** Stage 1 PR 3
  - Target: pre-genesis

- **`Engine::ledger()` accessor cleanup.** Stage 1 PR 2 (commit [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **PQC Multisig : Rust engine integration design (carrier).** [`docs/design/V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md)
  - Target: pre-genesis

- **PQC Multisig wire: MSW-1…MSW-8 (pre-genesis, priority 1).**
  - Target: pre-genesis

- **Term hygiene: "rotation" is a §11.8 defect on a noun — rename to
  - Target: pre-genesis

- **PQC Multisig: MSW-6 landing residue.** The scheme_id relaxation
  - Target: pre-genesis

- **PQC Multisig : Option-D residue left standing after the F-6
  - Target: pre-genesis

- **PQC Multisig : external adversarial review (Phase 5).**
  - Target: pre-genesis

- **PQC Multisig : cryptographer review (Phase 6).**
  - Target: pre-genesis

- **PQC Multisig : headless co-signer service.**
  - Target: pre-genesis

- **PQC Multisig : wire `shekyl_pqc_verify_with_group_id` into [`V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md)
  - Target: pre-genesis

- **Historical tree path assembly uses current LMDB state.**
  - Target: pre-genesis

- **Resolution: FCMP++ historical-reference cutover via Stage 5
  - Target: pre-genesis

- **Audit FCMP++ integration for paired computations.**
  - Target: pre-genesis

- **Regression test: `compute_leaf_count_at_height` vs LMDB drain.**
  - Target: pre-genesis

- **Expose FCMP++ verification cache stats via daemon RPC (stressnet F14).**
  - Target: pre-genesis

- **MFA / hardware-token integration for wallet file decryption.**
  - Target: pre-genesis

- **Rust replacements for chaingen-deleted validation invariants.**
  - Target: pre-genesis

- **Coordinated `TestLedgerBuilder` test-infrastructure substrate [`LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`](../rust/shekyl-engine-core/src/engine/local_ledger.rs)
  - Target: pre-genesis

- **Define formal escalation policy for `shekyl-oxide` divergence [`docs/CI_BASELINE.md`](./CI_BASELINE.md)
  - Target: pre-genesis

- **Migrate C++ `transfer_details` consumers to [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **`WALLET_REWRITE_PLAN.md` systemic broken relative-link sweep.**
  - Target: pre-genesis

- **Retire the iai-callgrind→gungraun bench-flake bisect harness (spawned
  - Target: pre-genesis

- **rand 0.9 migration and curve25519-dalek 5 cascade.** [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  - Target: pre-genesis

- **Two `unmaintained` advisories surfaced by `cargo audit` [`docs/design/STAGE_0_HARNESS.md`](./completed/STAGE_0_HARNESS.md)
  - Target: pre-genesis

- **Chore #3: retire every 32-bit target — leading with the security argument (`v3.1.0-alpha.5`, landed on `chore/retire-32bit-targets`).**
  - Target: pre-genesis

- **The ~42 GB/month cover-traffic budget is signed off PROVISIONALLY and has never been measured against actual usage.** Condition of the 2026-08-29 sign-off: build the carrier so a real transaction rides it, then compare actual bytes on the wire against `carrier::PER_NODE_CEILING_BYTES_PER_SEC` and the per-circuit pair [`COVER_TRAFFIC_RESTORATION.md` §3.3](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **§56.5 ruled the cadence memoryless; the shipped law is still bounded uniform, and nothing tracked it.** Carries §57's three exits and §58.2's admission threshold `θ`, both priced at the retired 12.5 s mean [`DAEMON_RELAY_PRIVACY.md` §56.7](design/DAEMON_RELAY_PRIVACY.md)
  - Target: pre-genesis

- **Relay: the `t_core` arrival harness — the witness this path has never
  - Target: pre-genesis

- **Relay: `on_relay_tx` and a missed submit nudge re-decide the zone after
  - Target: pre-genesis

- **Wallet: stop holding a relay constant — ask the daemon whether a
  - Target: pre-genesis

- **Relay: the D9 below-floor observer (§18.4, ruled 2026-08-15). IMPLEMENTED
  - Target: pre-genesis

- **Relay: the zone-route decision family moves to Rust** (in flight,
  - Target: pre-genesis

- **Relay: re-derive `fluff_return_ms` once, when a degree distribution
  - Target: pre-genesis

- **Relay: the `F'` region and §15's launch condition are one condition, and
  - Target: pre-genesis

- **Fleet: arm readouts must record the per-sample series, not a pooled
  - Target: pre-genesis

- **Relay: `full_travel_probability`'s cross-check holds `fluff_return_ms`
  - Target: pre-genesis

- **Relay: `F'` may be per-POSTURE even though §89.2 correctly refused
  - Target: pre-genesis

- **Relay: populate the 48-cell Pi verification surface, then consume it
  - Target: pre-genesis

- **Levin p2p migration — LV-2 payload codec and LV-3 connection-path [`docs/design/LV2_PORTABLE_STORAGE.md`](design/LV2_PORTABLE_STORAGE.md)
  - Target: pre-genesis

- **Daemon PQC phase-1 payload assembly duplicates [`20-rust-vs-cpp-policy`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  - Target: pre-genesis

- **FCMP++ sender-side output verification — inherited `wallet2::sanity_check` [`16-architectural-inheritance`](../.cursor/rules/16-architectural-inheritance.mdc)
  - Target: pre-genesis

- **Hardening-pass commit 8 follow-up: WalletPrefs round-trip
  - Target: pre-genesis

- **`tx_pool` / `blockchain_db` LMDB transactional wrapper — typed
  - Target: pre-genesis

- **`shekyld` `fee_policy_version` daemon-side exposure.** Surfaced [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md)
  - Target: pre-genesis

- **`ActivityMetric` producer actor (wallet-side coherent bundle).** Surfaced by [`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](completed/STAGE_1_PR_7_ECONOMICS_ENGINE.md)
  - Target: pre-genesis

- **Daemon atomic activity snapshot RPC (conditional on RPC upstream).** Same G4 [`docs/WALLET_RPC_RUST.md`](WALLET_RPC_RUST.md)
  - Target: pre-genesis

- **Workspace clippy `-D warnings` cleanup.** Surfaced by the Phase 0
  - Target: pre-genesis

- **`shekyl_difficulty_lwma1_next` FFI shim allocates `Vec<u128>` per [#52](https://github.com/Shekyl-Foundation/shekyl-core/pull/52)
  - Target: pre-genesis

- **C++ bridge `lwma1_next_difficulty` helper allocates two heap [`src/cryptonote_core/blockchain.cpp`](../src/cryptonote_core/blockchain.cpp)
  - Target: pre-genesis

- **RandomX v2 `ExternalProject_Add`: per-`CONFIG` install path and [`external/CMakeLists.txt`](../external/CMakeLists.txt)
  - Target: pre-genesis

- **A UDS listener for the daemon RPC (posture 1 on the daemon)** (added
  - Target: pre-genesis

- **The GUI dials its daemon with nothing said — and a dial that says
  - Target: pre-genesis

- **`shekyld <command>` parses `--rpc-bind-ip` with an IPv4-only helper**
  - Target: pre-genesis

- **Legacy spend-graph analysis utilities: audit against FCMP++, then delete
  - Target: pre-genesis

- **P-scan pruned-fetch bandwidth option over Tor (rejected at ).** The
  - Target: pre-genesis

- **`atomic_write_file` power-loss crash-injection tests.** PR 6 cites
  - Target: pre-genesis

- **Wallet on network filesystems (NFS / SMB).** Advisory lock + atomic
  - Target: pre-genesis

- **Wallet file metadata obfuscation (PR 6 §5.12 F5–F6).** File size and mtime
  - Target: pre-genesis

- **`WalletFile` handle slimming (post–PR 6 `PersistenceEngine`).**
  - Target: pre-genesis

- **FFI C ABI symbol rename: `shekyl_wallet_*` → `shekyl_engine_*`, [`shekyl-ffi`](../rust/shekyl-ffi/)
  - Target: pre-genesis

- **C++ JSON-RPC method-name rename: `wallet_*` → engine-shaped names
  - Target: pre-genesis

- **Chore #4: platform-gate audit sweep — reduced scope after Chore #3 (V4 pre-audit).**
  - Target: pre-genesis

- **Restore semantic thread labels in the Rust subscriber ().**
  - Target: pre-genesis

- **Stack-trace hook: re-route `ST_LOG` back through the logging subsystem once the FFI boundary is safe mid-throw ().**
  - Target: pre-genesis

- **`shekyl-cli` offline signing uses hex blobs on the command line.**
  - Target: pre-genesis

- **`shekyl-cli` key image export uses JSON-RPC format, not C++ binary.** [.cursor/rules/60-no-monero-legacy.mdc]( ../.cursor/rules/60-no-monero-legacy.mdc)
  - Target: pre-genesis

- **Test code `wallet_tools.cpp` still uses mixin/decoy infrastructure.**
  - Target: pre-genesis

- **`removed_flags` shim sunset.**
  - Target: pre-genesis

- **`shekyl-daemon-rpc` staticlib: `tracing::*` calls silently dropped.** [`docs/design/WALLET_REWRITE_PLAN.md`](./design/WALLET_REWRITE_PLAN.md)
  - Target: pre-genesis

- **Re-examine the `/FIiso646.h` deferral.** (Filed as a two-item entry; [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md)
  - Target: pre-genesis

- **MSVC / Windows build-debt cluster (migrated from
  - Target: pre-genesis

- **P-drain mechanism re-walk — CryptoNote holdover audit (rule 16; method note 5:
  - Target: pre-genesis

- **`P`-lane fee uniformity — implementation rider (ratified 2026-07-19,
  - Target: pre-genesis

- **Principal-side default-on Tor — flip `--proxy` from opt-in to default, opt-out loud.**
  - Target: pre-genesis

- **Principal-side `IsolateSOCKSAuth` — give the principal's `DaemonClient`s isolated circuits [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](design/ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)
  - Target: pre-genesis

- **2d-2 SP-R0 — reconcile GC of phantom `bonded_slots`/`p_slot` over the per-`P` transport [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)
  - Target: pre-genesis

- **2d-1 WI-2 — durable removal of SPENT funding outputs from `PScanState::funding_outputs` [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)
  - Target: pre-genesis

- **2d-1 SP-3 — borrow the block in the dual extractor instead of cloning per bonded scanner
  - Target: pre-genesis

- **2d-2 SP-T0 — DQ-T0.4 circuit-isolation measurement has no CI binary source (BLOCKED, not
  - Target: pre-genesis

- **Workspace-wide `rustdoc -D warnings` CI lane (BLOCKED on pre-existing cross-crate warnings).**
  - Target: pre-genesis

- **M1 reward-gate C++ test-support surface — fold the corruption-injection seam off the
  - Target: pre-genesis

- **Segment-freeze pipeline — design round required (opened by `ARCHIVAL_REWARD_GATE_M1.md` [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
  - Target: pre-genesis

- **M1 reward gate — pre-flight process BREACH (PF-1, recorded 2026-07-06; a breach,
  - Target: pre-genesis

- **2d-2 SP-T4a — GF-7 principal-timeline timing correlation is a GENESIS GATE (measure [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](design/ARCHIVAL_BOND_2C_GF7_HOOKS.md)
  - Target: pre-genesis

- **Wallet UX: thin-cover exposure disclosure at bond/claim time (registered 2026-07-19,
  - Target: pre-genesis

- **2d-2 2c-2a — submit-outcome handling: the wallet CONSUMES `SubmitVerdict`; the partition is [`DAEMON_SUBMIT_VERDICT.md`](design/DAEMON_SUBMIT_VERDICT.md)
  - Target: pre-genesis

- **2d-2 2c-2a — posture→submitter dispatch shape: FROZEN 2026-07-04 (user-ratified) — [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](design/ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md)
  - Target: pre-genesis

- **2d-2 2c — `DaemonUrl` newtype: validate `base_url` at construction + house the S1 disclosure.** [`DAEMON_SUBMIT_VERDICT.md`](design/DAEMON_SUBMIT_VERDICT.md)
  - Target: pre-genesis

- **2d-2 2c — the `OwnRemote` config-point disclosure is a mandated duty with no home yet.** The S1
  - Target: pre-genesis

- **2d-2 SP-T3 — onion-route end-to-end validation (the property DQ-T0.4 *cannot* prove).** [`ARCHIVAL_BOND_2D2_SP_T0_TOR.md`](design/ARCHIVAL_BOND_2D2_SP_T0_TOR.md)
  - Target: pre-genesis

- **2d-2 SP-T3 — inbound onion serving-side hardening (the implementation threat model).** The onion [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](design/ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)
  - Target: pre-genesis

- **`ReorgAmplificationDetector` consumer actor (Stage 1 PR 4 R5 [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **`PeerReputationActor` consumer actor (Stage 1 PR 4 R6 [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **`RecoveryActor` consumer actor (Stage 1 PR 4 R6 reframe; [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **`ViewTagAnomalyDetector` consumer actor (Stage 1 PR 4 [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **Diagnostic-stream specification document [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **`RefreshEngine` (c) split-producer/recoverer view-material [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **`ReservationTTLActor` consumer actor (Stage 1 PR 5 R8 [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **`SubmitFailureAnalyzer` consumer actor (Stage 1 PR 5 R9 [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **`TimeoutResolverActor` consumer actor (Stage 1 PR 5 R9 [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **`ReservationAuditActor` consumer actor (Stage 1 PR 5 §5.0.2 [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Cancel-during-`in_flight` ergonomic alternative [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **Eager-discard-on-`SnapshotMerged` opt-in (Stage 1 PR 5 [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **Optional inverse-index seam under `PendingTxActor`'s [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **`MempoolMonitorActor` consumer actor (Stage 1 PR 5 [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **`TxConfirmationTrackerActor` consumer actor (Stage 1 [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Transaction replacement / fee-bump (RBF/CPFP-equivalent) [`00-mission.mdc`](../.cursor/rules/00-mission.mdc)
  - Target: pre-genesis

- **Build-cancel ergonomic refinement (Stage 1 PR 5 [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **Wallet-locked-during-`in_flight` coordination [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **`LedgerEngine` candidate-fetch maturity-filter [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)
  - Target: pre-genesis

- **HW-wallet integration as a `Signer`-impl substitution [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Output-selection alternatives under `OutputSelector` trait [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Submission-strategy actors under [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Wallet-side fee estimator (`WalletSideEstimator`) under [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  - Target: pre-genesis

- **Diagnostic-event encrypted-persistence — conditional [`00-mission.mdc`](../.cursor/rules/00-mission.mdc)
  - Target: pre-genesis

- **Diagnostic-stream consumer-actor PR `diagnostic_consumer_discipline` [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  - Target: pre-genesis

- **Diagnostic-stream specification document — projection- [`STAGE_1_PR_4_REFRESH_ENGINE.md`](completed/STAGE_1_PR_4_REFRESH_ENGINE.md)
  - Target: pre-genesis

- **Sync refresh wrapper generalization over `L: LedgerEngine`.** [`docs/completed/STAGE_1_PR_2_LEDGER_ENGINE.md`](completed/STAGE_1_PR_2_LEDGER_ENGINE.md)
  - Target: pre-genesis

- **`run_refresh_task` holds the engine read-guard across [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **`LedgerReadGuard` field type leaks crate-private [rust-lang/rust#117108](https://github.com/rust-lang/rust/issues/117108)
  - Target: pre-genesis

- **Stage 4 lifecycle async cutover requires `CHANGELOG.md` [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **Stage 5 — `ArchivalEngine` native actor build (simulation-
  - Target: pre-genesis

- **No-tradeability invariant codification (placeholder).** The
  - Target: pre-genesis

- **Transport selection for the staker-archival path (gate 6 /
  - Target: pre-genesis

- **Soundness pass step 0: pin retrieval SLA per class (gate 4–6;
  - Target: pre-genesis

- **Foundation archiver key rotation (gate 4–6; pre-genesis).** **Closed
  - Target: pre-genesis

- **Foundation bond posture (gate 4–6; pre-genesis).** **Closed (spec).**
  - Target: pre-genesis

- **`ARCHIVAL_BOND_FLOOR` numeric pin + genesis `bond_floor_atomic`
  - Target: pre-genesis

- **Archival data scope — sets A/B/C (gate 4–6; pre-genesis).** **Closed
  - Target: pre-genesis

- **Foundation genesis-enumeration — legal / regulatory disclosure
  - Target: pre-genesis

- **Archiver seeding-path transport relaxation (gate 6 / firewall;
  - Target: pre-genesis

- **L14 read-credit soundness: per-(holder, shard), never shard-global
  - Target: pre-genesis

- **L15 diversity under location-hiding (gate 4–6 / architecture;
  - Target: pre-genesis

- **Permanent fee-era backstop must be a trustless terminal subsidy,
  - Target: pre-genesis

- **Age-stratify the foundation floor AND the terminal subsidy toward
  - Target: pre-genesis

- **L12 floor-decay schedule should be coupled to the growth↔entry
  - Target: pre-genesis

- **Bootstrap APR overshoot is a purse-efficiency note, not a
  - Target: pre-genesis

- **Vanguard eligibility flag set is a provisional pin, unseated only by
  - Target: pre-genesis

- **Validate `prev_id` before attestation verify on the alt-chain path
  - Target: pre-genesis


## Post-genesis

Exceptional deferral with a named blocker. This list stays tiny.

- **A4 cold signing (`UnsignedTxBundle` / `SignedTxBundle`).** Genesis ships cold *storage* (seed custody), not cold *signing*. Named blocker: verified display on the offline device and the envelope-sealed bundle are unstarted product work; a half-form is worse than none.
  - Target: post-genesis

- **PQC multisig hardware-wallet integration / BIP-39 derivation parity.** Named blocker: vendor SDK availability and outreach; `HARDWARE_WALLETS.md` authoring is the prerequisite.
  - Target: post-genesis

- **`monero-oxide` un-pin / 40-commit upstream merge.** Named blocker: the vendored pin is intentional at genesis; Operation B is not a launch dependency (`MONERO_OXIDE_VENDOR_STATUS.md`).
  - Target: post-genesis

- **Horizontal scaling via stateless actor pools / signed actor-patch over staker P2P.** Named blocker: no production load or staker P2P distribution surface at genesis; not a lattice/V4 item.
  - Target: post-genesis

## V4

Lattice-only transition, 2–5 years, gated on NIST (or successor) actually
approving primitives such as lattice threshold signatures.

- **Lattice-only spend / drop hybrid classical half** once a NIST (or successor) lattice signature and (if needed) lattice threshold scheme are actually approved and implemented. Not a parking lot for unrelated work.
  - Target: V4
