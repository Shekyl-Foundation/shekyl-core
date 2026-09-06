# Follow-ups

Open residue only. Per `.cursor/rules/95-documentation-lifecycle.mdc` and
`.cursor/rules/15-deletion-and-debt.mdc`, every item is a one-liner with a
`Target:` of **pre-genesis**, **post-genesis**, or **V4**. Essays live in the
owning plan doc. Resolved items are removed — git history is the archive.

Acceptances that are not work items: [`audit_trail/FOLLOWUPS_ACCEPTANCES.md`](audit_trail/FOLLOWUPS_ACCEPTANCES.md).

There is no V3.1 / V3.2 / V3.x release train.

## Pre-genesis


Default. Lands before genesis if it should exist at launch.

- **Delete or justify `tx_extra` 0x0A (`PQC_SPEND_AUTH_PUBKEYS`) — it has no producer.** Found at the C2-R2 signing round (Rick, verified at source): declared (`src/cryptonote_basic/tx_extra.h:48`, `rust/shekyl-wire/src/tx_extra.rs:50`), parsed (`tx_extra.rs:233`), picked (`src/cryptonote_basic/cryptonote_format_utils.cpp:540`) — and nothing anywhere constructs the field; the only write arm is the codec's generic `write_blob` branch. A parse surface with no producer is rule-15 debt and a fuzzing surface for free. Rule 15: delete at the port, or record the future producer that justifies it. — [`CONSENSUS_C2_R2_WEIGHT_FEES.md`](design/CONSENSUS_C2_R2_WEIGHT_FEES.md) Q10
  - Target: pre-genesis

- **The block-weight penalty-free-zone arbitration was punted and never landed.** `GENESIS_TX_WIRE_FORMAT.md` :806–811 flagged the `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE` V1/V2/V5 lineage (300 000 consumed as given) as "the arbitration belongs to the economics doc"; no doc ever received it, and the long-term 1.7× clamps ride along unexamined (owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-G6b; C2 batch R2). **Arbitration received:** [`CONSENSUS_C2_R2_WEIGHT_FEES.md`](design/CONSENSUS_C2_R2_WEIGHT_FEES.md) Q1 (zone, conditional on the GAP-7 floor measurement) and Q2 (the 1.7× clamps) — **proposed, pending maintainer signature**; this row closes when they sign.
  - Target: pre-genesis

- **Attestation verify must move behind PoW before credit-wire population activates.** `verify_block_attestation` runs before `check_hash` on both acceptance paths (blockchain.cpp:5738 < 5818; 2253 < 2347) — free pre-cutover (empty witness), but post-cutover it does up to one hybrid-signature verify per pass record before any work is proven, a DoS surface; the Phase-5 ordering constraint is pinned at both call sites (re-filed: the earlier entry survives only as the truncated headline "Credit-wire cutover has two preconditions the Phase-2 verify cannot satisfy") (owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md) §3; census: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §6.7).
  - Target: pre-genesis

- **Dead hard-fork version dispatch survives from genesis (rule 60).** All eleven `HF_VERSION_*` constants are 1 with unreachable else-arms, four are wholly unreferenced, the voting machinery runs inert on every block with its verdict discarded (blockchain_db.cpp:641), and `HF_VERSION_SMALLER_BP+1` resolving to `UINT64_MAX` silently disables pruned-span requests — delete the dead branches or rule the machinery kept, as its own pass (owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §5.5, CEN-B2/B3; C2 batch R4).
  - Target: pre-genesis

- **`#[serde(default)]` still lets an omitted daemon field become its zero value.** RK-4c refused *unknown* fields on the RPC read surface (`deny_unknown_fields`, `shekyl-rpc-types::chain`/`transactions`), which catches a renamed field but not an omitted one: 27 fields across those two modules default silently if the daemon simply leaves them out, and a zero height or an empty status reads as data. Needs a per-field pass — some absences are legitimate `KV_SERIALIZE_OPT` omissions the oracle vectors depend on, so this is judgement per field, not a sweep (owner: [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md) §3.2).
  - Target: pre-genesis

- **Live-oracle spend-hash KAT: a daemon-captured blob for the FCMP++/PQC spend arms.** Struct-derived cross-language hash parity landed with PR #576 (`pruned_tx_hash_parity.rs`/`.cpp` for the 4-part spend arm, `serve_credit_tx_parity.rs` + C++ leg for the 3-part), binding the two implementations to each other but not yet to a chain. Blocked on the FCMP++ spend path producing a daemon-accepted transaction to capture (`fcmp_spend_e2e.rs`'s self-validated builder is the stand-in); capture alongside `capture_coinbase.py`'s corpus when it exists (owner: [`GENESIS_TX_WIRE_FORMAT.md`](design/GENESIS_TX_WIRE_FORMAT.md) §11).
  - Target: pre-genesis

- **`CEN-L8`'s settlement clause describes an unwired writer, and names the wrong hook.** DRS-P0f slice 3 (2026-09-02) failed CEN-L8 closed to UNREVIEWED: `set_archival_settlement` has **no production caller** (`db_lmdb.cpp:7649` says so in the tree, and calls it "exactly the kind of 'not reachable, so not wrong' that stops being true silently"), while **SO-D7** ruled the writer belongs inside the slash scheduler's per-epoch pass rather than at a separate epoch-close event — which is where the census row puts it. Two questions, one owner: the census row needs re-wording against SO-D7 (census / §10 R8), and the writer needs a production caller before CEN-L8 can be re-reviewed for promotion. Until both, CEN-L8's digest is regression-only. Owner: [`CONSENSUS_STORE_RECONCILIATION.md`](design/CONSENSUS_STORE_RECONCILIATION.md) §5.4.1.
  - Target: pre-genesis (event-driven: writer wired + row re-worded against SO-D7)

- **Connect-path regression for the hash-gated FCMP++ proof-skip (`CEN-M8` fix wiring).** PR #602's unit tests pin `take_tx`'s cache verdict, but no test executes the consumer gate at block connect — reverting `can_skip_fcmp` to presence semantics would leave them green. The regression (an invalid-proof pool tx with `fcmp_verified = 0` must fail the block; its verified twin must connect with the skip) needs a connectable FCMP++ block whose tx is valid in every layer except the membership proof — **the same blocker as the spend-hash-KAT item above** (no daemon-accepted FCMP++ spend builder; `fcmp_spend_e2e.rs`'s self-validated builder is the stand-in). Build it when that builder exists; the M8/G4/J26 register re-review does not wait on it (the code walk covers the wiring), but E2's regression harness should include it. **Why CEN-D2's equivalent was buildable and this is not:** there the failing schema is itself the discriminator, so any generated block exercises the consumer; here the discriminating transaction must be valid in every layer *except* the membership proof, which is exactly what no current builder can produce. Owner: [`CONSENSUS_STORE_RECONCILIATION.md`](design/CONSENSUS_STORE_RECONCILIATION.md) §5.4.1.
  - Target: pre-genesis (blocked on the FCMP++ spend builder, named above)

- **A pruned node keeps whole `pqc_auths` because they have no hash table.** A pruned v3 txid is `cn_fast_hash(prefix, base_ct, pqc_auth_hash, prunable_hash)` and `pqc_auth_hash` is computed from the raw `txs_pqc_auths` bytes, so nameability costs the entire PQ signature slice where `txs_prunable_hash` does the same job in 32 bytes (`db_lmdb.cpp` `prune_tx_data`, PR #576; owner: [`LMDB_SCHEMA.md`](LMDB_SCHEMA.md)). A `txs_pqc_auth_hash` table would close it. **Unmeasured — do not open on the guess:** reopen with a real `pqc_auths`-vs-retained-bytes ratio from a pruned datadir, which an LMDB schema addition and its migration should be justified by.
  - Target: pre-genesis

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

- **`unbond_readiness` query (frozen §2 surface) deferred — blocker: persona addressing.** The exit became reachable with PR-C (the line this one replaces is DISCHARGED: `unstake` + `collect_unstaked` landed on [`StakeFacade`](../rust/shekyl-engine-core/src/engine/stake_facade.rs), wallet-RPC + CLI, 2026-09-03), and its refusals carry the readiness operands (`-29517 data.detail`), so a staker is never blind to WHY an exit refuses. What did NOT land is the standalone pre-flight query `unbond_readiness(P)` from the frozen §2 surface. The named blocker, not a convenience deferral: the frozen signature is persona-addressed, the RPC surface is forbidden from enumerating personas (`principal_stakes()` is RPC-REJECTED as the P↔principal edge), so the query's wire shape is blocked on a persona-addressing design the multi-slot UX round owns. At genesis scope (single slot) the refusal detail is the same information. [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §2.
  - Target: pre-genesis

- **Collected-total earmark warning (§12.3 carve UX, ruled 2026-09-04 with the carve countersign).** The terminal sweep's total is per-`P` predictable (collateral public via the record delta, rewards derivable via §18.10), so an outgoing principal transfer whose amount falls within the cover-draw range of a collected total *this wallet itself built* re-exposes exactly the off-chain amount-match channel the carve concedes. Owed: a **context-bearing warning** at the send surface — rule 82 shape: say *why* (the figure is a per-`P` fingerprint), proceed on acknowledgment. **Warning, never an armed refusal**: a user may deliberately disclose their own amount (they could as easily post it); the duty is to the *unaware* user who earmarks the lump without knowing. Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §12.3.
  - Target: pre-genesis

- **§12.3 carve UNMEASURED bound — rule-21 measurement obligation with a named expected resolution.** The carve's third bound (the cover draw's range blurring the amount-match against the population of predictable per-`P` totals) is recorded as assumed, not established. The measurement that would settle it: draw range against the spacing of realizable per-`P` totals, **reward component included** (it de-clusters what collateral tiers cluster). **Expected resolution is NOT this measurement**: the dust-tolerant retirement gate — letting retirement proceed over a sub-floor residual instead of pinning the pool to exact zero — would retire the total-shaped sweep's necessity and this bound with it. The measurement happens **only if that gate does not ship pre-genesis**; whoever closes the retirement-gate question inherits this row (that decision's owner is the trigger, not a calendar). Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §12.3.
  - Target: pre-genesis

- **Release-asset manifest signing owed before the first non-RC release
  - Target: pre-genesis

- **F-7 structural gate for the test-only FFI exports shipped in the production archive.** The PQC test helpers (`shekyl_pqc_keypair_generate`, `shekyl_pqc_sign_multisig_participant`, added under `shekyl-crypto-pq`'s `test-utils` feature because cmake builds one `-p shekyl-ffi` archive that every binary links) ship in production through feature unification; the header and Rust docs mark them, but nothing structural keeps them out. The curve-tree replica family `shekyl_curve_tree_replica_*` (PR #623 — the core_tests generator's header-root oracle, `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs`) is the same class and belongs to the same gate. Remedy: a separate test-only archive, or a cmake feature that production targets never enable, with an `nm` gate asserting the families' absence from shipped binaries. *(This line was truncated on `dev` — "(added" and nothing after — and is restored here from the Cargo.toml note that cites it.)*
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

- **DRS-P0 multi-PR — blocks DRS-0.** **P0a** schema+CI — **DELIVERED 2026-09-05** (49-row reconciliation registry + heading/registry gate legs; see the P0a registry in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md)); **P0b**
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

- **Drain/claim/unbond dispatch driver — terminal-reject prune + byte-identical resubmit remain (confirmation-observe landed 2026-08-27, #572; the unbond lane joined the residue with #601, which landed the SEAM-side release for a definite first-send refusal — `RejectedTerminal` on the one send the seam itself makes — leaving exactly the driver legs the other two lanes carry: crash-window/ambiguous resubmit, and the driver-side prune for records a future resubmit path re-sends).**
  - **PR-C made this residue USER-VISIBLE (2026-09-03):** `unstake` is reachable, and an ambiguous/held exit now surfaces as `-29522 UNSTAKE_FATE_UNKNOWN` (seal held funds-safe, lane shut, stall alarm in the operator log) with **no recovery verb** — the honest rendering of this unbuilt driver, stated in the contract rather than hidden. The prune half remains a SECURITY item (below); never land resubmit alone.
  - The prune is a **security** item, not only hygiene (raised 2026-08-31, PR-A): a terminal `DoubleSpendConflict` on an Unbond is terminal on *remedy*, not on impossibility — a partial slash then a compensating `Rebond` can restore the balance these bytes bind (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1, UB2 note). The retained copy is the replay channel, and pruning it is what closes it; the reference age window is the only other bound.
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

- **Should the genesis block header carry a real mint timestamp instead of 0?** Surfaced by C2-R3-Q2 ([`CONSENSUS_C2_R3_TIMESTAMPS.md`](completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §5.1): with `timestamp: 0` (`rust/shekyl-genesis-tool/src/builder.rs:181`) the genesis-padded MTP window admits `ts = 1` at block 1; a real mint timestamp would make the chain unable to start "before" its own genesis time for free under the ratified padding rule. A genesis-mint decision (geblock + the pinned block ids across all three networks), explicitly ruled out of C2-R3's scope at ratification (2026-09-01).
  - Target: pre-genesis (any regenesis window)

- **Tx version min/max is written twice and disagrees in form.** `ver_non_input_consensus` dispatches on `HF_VERSION_DYNAMIC_FEE` / `SHEKYL_NG` (`tx_verification_utils.cpp:55–78`); `check_tx_inputs` hardcodes 3..3 (`blockchain.cpp:3493–3506`). Live bounds match because every `HF_VERSION_*` is 1. Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-H2 / CEN-I3 (were RC-68 / RC-82).
  - Target: pre-genesis


- **The pool admits duplicate archival unique-keys that only fail at connect.** Serve-credit `(P,s,E)`, bond-post-per-P, and emission `(P,E)` uniqueness are block-connect rules (`blockchain.cpp:6102–6261`), not `add_tx`. Two conflicting txs can sit in the mempool; a block that includes both is rejected. Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-G7 / CEN-G10 / CEN-G9 (were RC-113 / RC-123 / RC-130).
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

- **Rename `RETENTION_HORIZON_BLOCKS` (hygiene, C2-R1b residue).** The name reads as a reorg bound and cost the program one wrong ruling draft (the tip-derived floor); under the watermark form it is only the archival sweep floor. Rename toward its actual job (e.g. `ARCHIVAL_SWEEP_FLOOR_BLOCKS`) with the [`ARCHIVAL_TIMING_CONSTANTS.md`](design/ARCHIVAL_TIMING_CONSTANTS.md) row updated in the same change.
  - Target: post-genesis

- **Threshold signatures: one missing primitive, two named customers (ruled 2026-09-03).** PQC multisig and quorum-style attestation (C2-R0 candidate C6's decisive constraint) wait on the **same external event**: a practical, standardized threshold construction for the **ML-DSA leg**. The classical half is not the problem — FROST-style Schnorr thresholds are mature for the Ed25519 leg — but hybrid signing means the PQ leg cannot be waved off: a threshold classical signature bolted to k-of-n individual PQ signatures inherits the fat certificate's size *and* its signer-naming (the C6 tier-1 persona-linkage oracle: an **attested, gap-free** presence/absence ledger — absences are *recorded*, not merely unobserved, so the adversary reads a ledger the chain maintains for them — and a **permanent** one: personas that ever signed stay linkable from history even after any later format fix). Whoever notices NIST or the research community shipping a practical lattice threshold scheme reopens **both** customers at once — one row so they cannot be reopened separately. Realistic horizon: years (interactive round complexity; security-analysis maturity). Owner: crypto lane; the V4 row below is the *transition* consumer of the same event.
  - Target: post-genesis

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

- **The ~42 GB/month cover-traffic budget is signed off PROVISIONALLY and has never been measured against actual usage.** Condition of the 2026-08-29 sign-off: build the carrier so a real transaction rides it, then compare actual bytes on the wire against the ceiling. Expected discrepancy and the bar for a real defect are pre-registered [`COVER_TRAFFIC_RESTORATION.md` §3.1c](design/COVER_TRAFFIC_RESTORATION.md). **RUNNABLE as of 2026-09-05** — `shekyld --carrier-development` (hidden) arms the carrier, which nothing outside the gtests could do before; the three-arm method, the count-at-levin-payload trap and the 2 h window are at §3.1c(i). Still unrun.
  - Target: pre-genesis

- **Relay: a transaction mined while the carrier holds it is still SENT — every remaining window, up to ~100 KiB.** The verdict-time `pool_has_tx` gate stops the record and the F-10 observation, but the verdict arrives only on completion, so a transaction mined before its first tick emits all of its windows: `MAX_FRAGMENTS` (5) × `WINDOW_BYTES` (20 480). An earlier entry said "one wasted window", understating it by the fragment cap. Named blocker: cancelling earlier needs an enqueue-cancellation API `NoiseQueues` does not have, and `unbind` clears a whole channel, so cancelling one message would discard its channel-mates. Bounded per transaction rather than per epoch, and it is cover carrying something peers already hold. Reopen if another caller needs cancellation, or if the §3.1c bandwidth measurement shows mined-while-queued traffic is a material share [`COVER_TRAFFIC_RESTORATION.md` §3.1e](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **Relay: the carrier's pool gates NARROW the false-`Silent` window but cannot close it.** `pool_has_tx` releases the txpool lock before returning, so a removal between the second check and `record_stem` still arms an F-10 observation for an absent transaction. Named blocker: closing it needs the txpool to cancel in-flight observations on removal, or `StemWatch::expire` to re-ask membership before counting a `Silent` — the better place, since expiry is where the `Silent` is decided — and both are new plumbing across the FFI into the layer the daemon cutover replaces. Latent: §12.11, the tier that reads these tallies, is unbuilt. The ordinary stem arm does not check at all, so the carrier is the only path that narrows it. Reopen when §12.11 becomes real, or at the cutover [`COVER_TRAFFIC_RESTORATION.md` §3.1e](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **Relay: a carrier verdict of `sent` means the transport ACCEPTED the bytes, not that they reached a peer.** `connections::send` queues an asynchronous write, so a socket failing after acceptance still resolves `CarrierOutcome::Sent` and charges the relay record and the F-10 observation. Named blocker: epee exposes no write-completion signal, and adding one thickens inherited C++ directly beneath the layer the daemon Rust cutover replaces (`20-rust-vs-cpp-policy`); socket completion would still not be peer receipt. Reopen at that cutover, where the write path is Rust-owned. Contracts state the gap today, and the exposure is latent — §12.11, the consumer of those tallies, is unbuilt [`COVER_TRAFFIC_RESTORATION.md` §3.1d](design/COVER_TRAFFIC_RESTORATION.md)
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

- **p2p lane: fix the anchor dial path so it fills `ANCHOR_CONNECTIONS_COUNT` slots instead of destroying the persisted anchor set on first use** — it currently yields at most one anchor-backed connection (zero if every anchor fails), which caps Q-10's `k` at 1. Full trace and the `g_max` consequence in the owning doc — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I4
  - Target: pre-genesis

- **Relay lane: add a derivation check asserting `fluff_return_ms` equals the max over measured zones**, so adding a zone slower than Tor fails loudly instead of silently under-provisioning `F′`; `tests/carrier_window.rs` is the shape — [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md) §91.2
  - Target: pre-genesis

- **Two dead p2p wire structs survive with no callers, inherited dead from the lineage (rule 60).** `connection_entry_base` and its `connection_entry` typedef have zero references tree-wide (last caller removed 2020 in `68ba2887c`); `network_address_old` has only `debug_utilities/object_sizes.cpp`, whose two lines must be deleted with it. p2p-lane work, not RPC-cutover residue. **Ruled for deletion by PWD-B8 (2026-09-04)** — bucket 3, so outside the P2P-2 round's 46-row gate. PWC-F1/PWC-F2 — [`P2P_1_WIRE_CENSUS.md`](design/P2P_1_WIRE_CENSUS.md), [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B8
  - Target: pre-genesis

- **Register `shekyl/p2p-wire-prefix-v1` in [`CRYPTO_DOMAIN_REGISTRY.tsv`](design/CRYPTO_DOMAIN_REGISTRY.tsv) and bump the mechanism-1 count-pin when PWD-T5's prefix derivation gets its call site.** Not registrable in P2P-2: the domain gate requires a registered literal to have a defining file and a `const` site, and this round implements nothing, so a row now would fail CI for being honest about the schedule. The derivation, the three computed prefixes and the pairwise-distinctness assertion are pinned in the ruling — this item is the registry half only. PWC-A1 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T5
  - Target: pre-genesis

- **Execute PWD-T6's PWC-F3 deletion: remove `P2P_DEFAULT_PACKET_MAX_SIZE`, `network_config::packet_max_size`, and `network_config`'s KV serializer.** Ruled, not deferred — the never-sent map would otherwise advertise a 50 MB packet limit against the 100 MB the transport enforces, and PWD-T6 names the authoritative limits so there is one source. The struct keeps its live fields; `handshake_interval`, `config_id` and `send_peerlist_sz` are also write-only but belong to PWD-B1/B2 and PWD-I2. PWC-F3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T6
  - Target: pre-genesis

- **Implement PWD-I2's peerlist-acceptance rules: outbound-only acceptance and the `P2P_MAX_PEERS_IN_HANDSHAKE` per-connection ceiling.** The white-list writer invariant lands with the back-ping deletion and store bump in the row below, which is one composable change. PWC-D1/D3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I2
  - Target: pre-genesis

- **Examine the inherited double-spend no-drop guard (`f7fd209ed`, upstream Monero) and decide it deliberately, so a rewrite re-deriving tx ingest does not drop it silently.** Separate validation surface from the peerlist work above, per [`19-validation-surface-discipline`](../.cursor/rules/19-validation-surface-discipline.mdc). PWC-E7, §5.2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7
  - Target: pre-genesis

- **The rustdoc gate enumerates crates by name, so a crate outside the list is never documented and its errors accumulate unseen — `shekyl-relay` currently has 5.** `rust-audit-test.yml:310-312` gates `shekyl-tor`/`shekyl-p-serve`/`shekyl-p-host`/`shekyl-operator-alarm` and `build.yml:482` gates `shekyl-win-sec`; everything else is ungated. Fix the gate to cover the workspace with named exclusions (the inverse direction) rather than named inclusions, then clear the relay crate's broken intra-doc links — [`45-rust-lint-checks`](../.cursor/rules/45-rust-lint-checks.mdc)
  - Target: pre-genesis

- **Gate PWD-T7's compression invariant mechanically: assert that only notify routes reach `try_compress_message`, and that no message carrying confidential material of any lifetime — session key, node-local secret, reused token — is routed through one.** **Blocker cleared 2026-09-03 by PWD-B3's route classification** (this was "nothing in the tree classifies a command as confidentiality-bearing"): every p2p command is an *invoke* (`net_node.inl:1078`, `:1165`, `:2581`, `:2623`) and all three compressor call sites finalize as notifications, so the reachable set is the cryptonote notify family — public consensus data. Executable now: the check is on the **routes**, not on the command table, since a table-shaped gate would pass while an invoke-carried secret was re-routed through a notify. The invariant is stated at the dispatch site (`rust/shekyl-levin/src/compress.rs`) in the meantime, which is placement, not enforcement — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T7, PWD-B3
  - Target: pre-genesis
- **Size the Levin bucket header's length field, once `NOTIFY_RESPONSE_GET_OBJECTS`'s byte budget has a value.** **Blocker: three inputs are still open** — *(1)* the response byte budget itself (owed: a bandwidth/latency trade for initial sync, needs sync measurements); *(2)* `margin` in `entry_max`, owed to the **consensus lane — C2-R2 owns the derivation** (CEN-G6/G6b), **scoped to the tip-adjacent announce path only** since 2004 is byte-budgeted and `entry_max` has one consumer (2008). **C2-R2 has a proposed value — `margin(k) = min(2^k, 50·LTEM/EM)` for announce-lag `k`, both operands receiver-local — recorded in [`CONSENSUS_C2_R2_WEIGHT_FEES.md`](design/CONSENSUS_C2_R2_WEIGHT_FEES.md) §6, landing on `dev` with the R2 PR (round signed 2026-09-06)**. One coupling from the signing round: the absolute arm's 50 is the SURGE FACTOR (CEN-G6), which Q3's measurement REFUTED and re-derives to ×6 territory — so carry the arm as `S·LTEM/EM` with S = the ratified surge factor, never the literal 50. **Carry the function, not the ×4 constant**: the announce path is gated on `is_synchronized()` (`src/cryptonote_protocol/cryptonote_protocol_handler.inl:538`, definition `cryptonote_protocol_handler.h:111`), which is a **latched boolean, not a height comparison**, so nothing enforces a numeric `k` — the `min`'s absolute arm is what keeps the bound safe when lag exceeds the assumed value; *(3)* the **relay batch bound for `NOTIFY_NEW_TRANSACTIONS`** — **the mechanism is now ruled by PWD-B12** (a byte cap on what a flush releases *and* a byte cap on what a zone holds, with admission refused at the second), **but its two numeric values are owed**, so 2002 still has no computable cap and 2004 is not yet proven to be the largest value the header must express. *This item was briefly marked cleared on 2026-09-03 and re-opened: PWD-B3 fixed the cap's shape, not its value; PWD-B12 fixed 2002's mechanism, not its value.* PWC-A2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T6, PWD-B3, PWD-B12
  - Target: pre-genesis

- **Re-derive `drop_connections(address)`'s host-keyed severing together with the anonymity-zone inbound bound.** It severs every connection sharing a host and scores that host +5 (`src/cryptonote_protocol/cryptonote_protocol_handler.inl:2906-2922`); the remaining blocker is that an onion identity is free to mint, so a per-host key prices nothing — the sweep is now safe on an anonymity zone, not useful there. Re-derives together with PWC-E11's inbound cap, count- or work-based. **The second blocker — host-keying compared `unknown == unknown` — was closed by `fix/anon-zone-address-keying`; the disposition row carries that history and the corrected `is_same_host` finding.** PWC-E9 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7, PWD-I4
  - Target: pre-genesis

- **Carry an anonymity-zone peer's endpoint in the handshake, and delete the `unknown()` sentinel with it.** Scoped to overlays: clearnet's observed-address / claimed-port split is deliberate and stays. **This deletes work, it does not add it:** the sentinel goes, and with it `identifies_a_host()` in `contrib/epee/src/net_utils_base.cpp`, the `drop_connections` early return, and their comments. Rationale and the verification story are in the owning row; admission policy (no endpoint ⇒ not a peer) is a separate ruling with Rick. — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I1, PWD-B10
  - Target: pre-genesis

- **Sweep the tree for comparison tests built only from separately-constructed operands, adding an alias limb where one is missing.** A test that constructs both sides independently never creates the aliasing condition, so it cannot exercise a short-circuit that fires on *identity* — structurally incapable, not weak. **Measured:** with the anon-zone guard misplaced, the separately-constructed limbs (`tests/unit_tests/net.cpp:263-264`) pass while the alias limbs (`:276-277`) fail. Any equality, ordering or identity check with a pointer short-circuit has the same blindness available. Found by `fix/anon-zone-address-keying` — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7
  - Target: pre-genesis

- **Execute PWD-B8's deletion of `m_bad_peer_checker`.** `once_a_time_seconds<43>` has exactly one occurrence tree-wide — its declaration at `src/cryptonote_protocol/cryptonote_protocol_handler.h:213` — and `on_idle` never calls it, so a cadence constant no code reads currently reads as one to anyone auditing the file. **The two lineage-dead structs PWD-B8 also rules are tracked by the `network_address_old` / `connection_entry_base` item above**, which already carries the `object_sizes.cpp` warning — not restated here, so the queue has one owner per subject. PWC-E4a — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B8
  - Target: pre-genesis

- **Implement PWD-B7's affirmative drop verdict — internal failures must not sever peers.** **Three sites, all verified at source:** *(1)* two our-own-state paths return false from `add_tx` with `m_no_drop_offense` unset (`src/cryptonote_core/tx_pool.cpp:785-787`, message literally "internal error"; and the catch-alls `:344`, `:506-509`) and fall through `!tvc.m_no_drop_offense` (`cryptonote_protocol_handler.inl:909-913`) to `drop_connection`; *(2)* the announce path's `check_incoming_block_size` arm (`:536-540`) compares against OUR limit — wrong axis, narrow window; *(3)* the block-sync `prepare_handle_incoming_blocks` arm, which severs the span origin although that call returns false for six our-state reasons (`blockchain.cpp` `m_cancel` `:7025`, `:7035`, `:7076`, `:7188`; `!waiter.wait()` `:7021`, `:7172`) — #620 removed its host-fail score but could not remove the sever, which is the argument for the type. The fix is a **typed tri-state verdict** (attributable form failure = drop / policy-or-state = no drop / internal = no drop, loud log) so an unclassified arm defaults to no-drop. The parse arm stays a drop. Rust-side per rule 20. PWC-E7, PWC-E8 (**not** PWC-E2 — that is the rate-limit absence owned by the PWD-B1 item; the announce-size arm has no census row of its own) — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7
  - Target: pre-genesis

- **Implement 2004 byte-budget truncation continuation — the shipped requester severs a truncating responder.** Verified at source (review round of #616): `handle_response_get_objects` erases only delivered hashes, never consumes `missed_ids` (responder-filled, `cryptonote_protocol_handler.inl:1053`), and drops the peer whenever `m_requested_objects` is non-empty afterwards (`:1174-1202`) — so the ruled byte-budget responder gets disconnected on every truncated batch by today's code. The P2P-3 implementation must: *(1)* mark **deferred-by-budget** distinctly from `missed_ids`' **genuinely-unavailable** (conflation poisons availability bookkeeping); *(2)* re-request the deferred remainder; *(3)* **narrow, never delete** the not-all-returned drop — it is the withholding detector and keeps firing on any shortfall that is not budget-marked. PWC-A2's byte-budget value item is the sizing half; this is the semantics half. — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B3
  - Target: pre-genesis

- **Rule pre-handshake connection admission: the *rate*, and the anonymity-zone gap.** PWD-T5 routed adaptive resource exhaustion to PWD-B1/PWD-B9; PWD-B1 covers only the **post-handshake** phase (its bucket sits on the four invoke entry points), and **PWD-B9 is outbound slot diversity**, so neither reaches an inbound flooder that forces one ML-KEM decapsulation per connection. The current inbound bound is **PWC-E11** — `has_too_many_connections`, per-host, **public zone only**, so **anonymity zones have no inbound per-host cap at all** — and a concurrency cap does not bound churn in any zone. **Unruled, not blocked**: no decision waits on another. Needs its own row rather than a widened PWD-B9, since B9 means outbound in the brief and the index. PWC-E11, PWC-E2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B1, PWD-T5
  - Target: pre-genesis

- **Extend PWD-B1's bucket to *every* dispatch — invoke and notify — and derive its four parameters.** The coverage half is not optional bookkeeping: `NOTIFY_NEW_TRANSACTIONS` is a `HANDLE_NOTIFY_T2` route, so a bucket on the four node-server invoke routes alone leaves transaction floods spending **no tokens**, and **PWD-B12's memory bound assumes B1 is charging that connection**. Closing this item without the coverage change would leave B12's composition claim false in the code while true in the design. Parameters, all four, since a refill rate alone does not define a bucket: *(1)* refill rate; *(2)* capacity and initial fill, which *is* the burst allowance and decides whether a peer that connects and immediately syncs is throttled; *(3)* per-command token cost, since a handshake and a timed-sync are not the same work and an attacker picks whichever is mispriced; *(4)* **the action on exhaustion — throttle or disconnect**, which is **wire-observable**, so leaving it open means conforming peers disagree about whether a slow peer is a hostile one. **Unruled, not blocked.** Needs the honest-sync measurements PWD-B1's falsifier names. PWC-E2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B1
  - Target: pre-genesis

- **Derive PWD-B2's timed-sync `min`/`jitter` split.** The distribution is ruled — bounded uniform `min + U(0, jitter)`, per-connection, re-drawn only on its own fire — and the constraint is fixed: **the mean stays at `P2P_DEFAULT_HANDSHAKE_INTERVAL` (60 s)**. The draw is **uniform** on the criterion of **maximum entropy over a bounded support** — bounded for liveness, max-entropy because a peaked family at the same mean has a recoverable shape (uniform is not *shapeless*; bounded support is itself a signature). **`0` is a valid draw and must not be excluded**: re-rolling truncates the distribution actually realised, which is a pattern even when the family was chosen correctly. The condition is on the **window parameter**, never on a draw. Decorrelation comes from the **per-connection independent draw** — connections established at different moments have unrelated phases whatever the window is — so the window's job is narrower: **decorrelating connections established at nearly the same moment**, which `m_connections_maker_interval` (1 s) makes the common case at startup. Derive the split against that clustering, as a **measurement** — **together with the falsifier's threshold and sample budget, in this one item**, since the window is chosen so the pairwise circular correlation of send phases falls below that threshold: neither number can be picked without the other. Q12-D6a rig. **Unruled, not blocked.** PWC-E1, PWC-E3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B2
  - Target: pre-genesis

- **Re-derive initial-sync verification cost at the Pi-4 floor now that C2-R1a has deleted `PER_BLOCK_CHECKPOINT`.** `DAEMON_RELAY_PRIVACY.md` §74.2 concluded *"the 11-day figure is the worst case"* because the checkpoint skip rescued historical blocks; `fast_check` and `m_blocks_hash_check` no longer occur in `blockchain.cpp`, so the un-checkpointed case is now the only case. Blocker: the replacement figure needs a measurement, not an argument. Rule 76 — [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md)
  - Target: pre-genesis

- **Run the `ρ`/`g_max` sub-round (Q-10) deferred by PWD-I4.** Blocker: it must derive against the *fixed* anchor and white/gray behaviour, so it follows the p2p tree changes rather than preceding them; reopening criterion and the §12.10/§7 reconciliation it must carry are in the owning doc — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I4, PWD-I5
  - Target: pre-genesis

- **Decide `sanitize_peerlist`'s port-0 handling, where the IPv4-only rule collides with `tor_address::unknown()` being port 0.** Blocker: the tor port-0 semantics are disputed (named by #587, not invented here). PWC-D9 — [`P2P_2_DISPATCH_BRIEF.md`](design/P2P_2_DISPATCH_BRIEF.md) PWD-B11
  - Target: pre-genesis

- **p2p lane, one composable change: delete the back-ping and `COMMAND_PING`, insert the inbound peer directly into **gray** after handshake, bound gray occupancy per host, and bump the peerlist store version (which drops the persisted list).** The four are one outcome: `net_node.inl:2766` sits *inside* the `try_ping` callback the deletion removes, so a standalone reroute would be erased by it; without the per-host gray bound the deletion opens a new injection path, since `my_port` is peer-controlled and `append_with_peer_gray` has no same-host eviction; and without the bump, old inbound-earned white entries stay trusted. Public-zone only; behavioural, so PWD-I4 must derive against the fixed composition. PWC-D11 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I1/PWD-I2/PWD-B9/PWD-B10
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

- **Legacy spend-graph analysis utilities (`ancestry`/`depth`/`usage`): audit against FCMP++, then delete** (`prune-known-spent-data` audited and deleted — its eligible set is empty on an amount-0 CT chain) [`EXECUTABLES.md`](EXECUTABLES.md)
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

- **[Shard-visual ruling B — measurement half](V3_SHARD_VISUALIZATION.md) (ratified 2026-09-05; spec § landed).**
  Remaining: designated-reference goldens, full-recipe per-fixture KATs, two-limb avalanche test, skl-pi budget
  matrix. Held by name: build-slowdown directive (P2P focus) + skl-pi occupancy; device slot via coordination.
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

- **Offline schema-aware prune/copy tooling (rule-21 reversion clause).** `shekyl-blockchain-prune` retired (inert since LMDB v6: version guard pinned at 5; copy list held 16 of 49 tables). Reopen on post-genesis operator demand that in-place `--prune-blockchain` + `shekyl-mdb-copy -c` cannot serve, or when S-PRUNE reaches execution in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) — then rebuild in Rust with the table set derived from the schema source of truth, never hand-maintained (precedent: the `SHEKYL_LMDB_TABLES` X-macro, rule 47).
  - Target: post-genesis

- **Horizontal scaling via stateless actor pools / signed actor-patch over staker P2P.** Named blocker: no production load or staker P2P distribution surface at genesis; not a lattice/V4 item.
  - Target: post-genesis

## V4

Lattice-only transition, 2–5 years, gated on NIST (or successor) actually
approving primitives such as lattice threshold signatures.

- **Lattice-only spend / drop hybrid classical half** once a NIST (or successor) lattice signature and (if needed) lattice threshold scheme are actually approved and implemented. Not a parking lot for unrelated work.
  - Target: V4
