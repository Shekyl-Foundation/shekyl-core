# Follow-ups

Open residue only. Per `.cursor/rules/95-documentation-lifecycle.mdc` and
`.cursor/rules/15-deletion-and-debt.mdc`, every item is a one-liner with a
`Target:` of **pre-genesis**, **post-genesis**, or **V4**. Essays live in the
owning plan doc. Resolved items are removed — git history is the archive.

Acceptances that are not work items: [`audit_trail/FOLLOWUPS_ACCEPTANCES.md`](audit_trail/FOLLOWUPS_ACCEPTANCES.md).

There is no V3.1 / V3.2 / V3.x release train.

## Pre-genesis


Default. Lands before genesis if it should exist at launch.

- **Delete the clearnet pipe scaffolding at transport cutover.** `pipe.rs`, the descriptor-handoff FFI, and epee's `network_pipe_ops` are the interim host. The transport layer replaces them; they are not a test host for the option. The deletion set is D13 of the transport-layer design.
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md)
  - Target: pre-genesis

- **State the rule for a peer-exchange address type this node does not recognise.** The union is closed (`ADDR_IPV4`, `ADDR_IPV6`, `ADDR_I2P`, `ADDR_TOR` in `shekyl-levin` `payload/address.rs`) and freezes at genesis. A future network's address type belongs to that network's connector, so an unrecognised type needs a stated rule before then. Not decided in the transport-layer round.
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md)
  - Target: pre-genesis

- **`claim.rs:157` logs per-epoch `AlreadyClaimed` skips at `debug`, which correlates a persona against the public bond record.**
  - Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3
  - Target: pre-genesis

- **Nothing calls `refresh` on a timer, so `ServingConfig::refresh_cadence` and the unused `auto_refresh` preference do not drive the store `WALLET_SIDE_STORE.md` §6.7.2 must measure.**
  - Owner: [`WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §6.7.2
  - Target: pre-genesis

- **CEN-I4's input cap (8) is inherited and unjustified — derive it from a verifier budget at the device floor, or delete it as redundant with CEN-H3's weight limit; price the consolidation-sequence cost in the same round.** The number arrived from RingCT's era with *"bounds proof generation time and tx size"* as its only rationale. Measured 2026-09-24 (`shekyl-wire/tests/input_cap_cost.rs`) on an i9-11950H **and on the Pi 4 floor (skl-pi)**: 6.4 KB per input on the wire; 11.9 ms (i9) / **64.9 ms (floor)** of verifier time per input, linear on both; CEN-H3's `TX_WEIGHT_LIMIT` (149 400) alone admits **22** inputs of this shape, so the cap binds by ~2.75× (corrected 2026-09-24 on #853 review — the first cut read 153 / 19× off the 1 MB parser bound, which no accepted transaction is measured against); per-input linearity means the cap moves no per-block bound (the weight limit does) and splitting a consolidation across transactions costs the verifier *more*; what it bounds is per-transaction work on a transaction that proves invalid at relay — **at the floor, ~0.62 s at 8 and ~1.5 s at 22** — a relay-policy quantity. The privacy side — a wallet with twenty outputs forced into three transactions in a window — is unpriced. **What the floor decided and what it could not:** it changed the absolute milliseconds (5.5×) and not one ratio — linearity, positive per-transaction overhead, splitting-costs-more, and the ~2.75× against H3 are structural and held there; the floor set only the *value* of the relay verifier budget, which is now in hand. Round: state the relay verifier budget against the floor's 0.62 s / 1.5 s; derive the cap or move it to policy and delete the consensus rule. **The deletion is a widening** — the chain would accept nine-input transactions it now refuses — which is free pre-genesis and a hard fork after; the window for making it free closes at genesis. **Two constants part company at that moment and both ends are named here so neither orphans:** the consensus cap (`shekyl_wire::transaction::MAX_FCMP_INPUTS`, read by `rules/tx_inputs.rs::I4`; the C++ `FCMP_MAX_INPUTS_PER_TX` until E4 retires it) and the prover/verifier cap (`shekyl_fcmp::MAX_INPUTS`, refused at `proof.rs`'s prove and verify entry points) — the second must move to whatever bound the round states (the relay budget's, or H3's implied 22), or a prover that refuses at 8 becomes the cap by accident; `shekyl-tx-builder` const-asserts the two equal today, so they cannot part company silently. Falsify by the census row's rationale cell citing a stated budget and a floor measurement, or the rule's deletion with both constants moved. Full analysis: [`design/CHAIN_RULES_SLICE_6.md`](design/CHAIN_RULES_SLICE_6.md) §5.4.
  - Owner: [`CHAIN_RULES_CRATE.md`](design/CHAIN_RULES_CRATE.md) §8
  - Target: pre-genesis

- **The validator's remaining `unreachable!` arms: one structural, two type-carried.** Nine sites were read on #852's branch at its scenario-driver commit (E6 slice 6 review, 2026-09-24; the branch SHA first written here died in a rebase — the era of record is #852's merge into `dev`, and the falsifier below re-reads the tree at any era). Four were SI-7-deferred — a store invariant defending a validator panic — and were converted in the slice to `Corrupt::HoleBelowTip`, the halting class (`rules/mod.rs::recorded`, `pow.rs` D3's seed read, `timestamps.rs` C3's two window reads). One is compiler-proven (`difficulty.rs` `const ONE`, evaluated at build). One is priced-out by parameters with the analysis written at the site (`miner.rs::priced`). **Three remain, and none is remote-reachable today:** (1) *structural* — `timestamps.rs` C2 reads `cx.mtp_window: Option<_>` whose `None` is legal only at genesis and panics on the illegal pair; the fix is the type (a non-optional window above genesis, or a genesis-shaped context — the `connecting.is_zero()` early return is half the split); (2) *local-construction* — `timestamps.rs` `MtpWindow::is_above_median`'s FTL/width arms (the candidate is its own clock; C3 built the window at most eleven wide); (3) *local-construction* — `difficulty.rs` D4's `lwma1_next` `Count | Window | Overflow` arms (a monotone N+1 window past N; the walk refused a decrease before the fold). (2) and (3) would be carried by a `BoundedWindow` type; nothing external reaches either arm. The standard is `miner.rs:477`'s: a `unreachable!` in the validator is a panic a peer can trigger unless the argument is the type or the compiler. Falsify by `rg -n 'unreachable!' rust/shekyl-chain-rules/src --glob '!*tests*' --glob '!harness*'` returning only const-eval and type-carried sites.
  - Owner: [`CHAIN_RULES_CRATE.md`](design/CHAIN_RULES_CRATE.md) §8
  - Target: pre-genesis

- **Propagate the immutable-bond ruling through the `HoldingsUpdate` documentation surface — 151 matching lines across 25 living documents** (measured at `dev@91705e5882`, before this PR's own additions; 214 lines / 35 files including records-was documents, which are **not** in scope). The ruling (2026-09-20, [`V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md); mechanics and deletion set in [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3) fixes a persona's holdings set at the bond post, which makes every doc sentence describing an in-place holdings change wrong in substance rather than merely stale. **Method is PDM-sweep discipline — re-derivation, not find-and-replace:** a sentence that says *"the operator adds shard `k`"* is not repaired by renaming the mechanism, because the event it describes no longer exists; each site is re-derived against rotation, or deleted with its subject. The figure above derives from a count of the matching lines at a stated pin, not from a prior figure, and is expected to move as the deletion set lands. *(The handoff that ordered this row carried 138; the difference is scope, not drift — state the pin and the inclusion rule when re-counting.)* **Owner: the archival bond lane** (the `PSL`/`P2B` surface), which owns §5.3.2's deletions and should sweep the prose with them rather than ahead of them. **The recording PR deliberately did not attempt this.** Falsify by `grep -rc HoldingsUpdate docs/` reporting only records-was documents (`docs/completed/`, `CHANGELOG.md`, and this log's prior entries).
  - Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3
  - Target: pre-genesis
  - Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3.2 — the lane that owns the deletion set owns the prose sweep, and should sweep with the deletions rather than ahead of them

- **Measure the market pull latency for a fresh shard, now that no operator can incrementally add one.** The immutable-bond ruling leaves new-shard coverage **market-pulled**, with the Foundation complete-tree floor as backstop — so a newly frozen shard is covered when some operator next rotates or bonds, never by an existing persona adding it. This is the one place the ruling has a measurable open question rather than a settled answer: **one `shekyl-economics-sim` row** measuring how long a fresh shard waits for market coverage under the rotation-only path, against the floor that is meant to make the wait survivable. Named in [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3.3. Note the ruling claims **no** credit against TJ-7 (sybil-per-shard), which is orthogonal and separately owned. Falsify by the sim carrying a fresh-shard pull-latency measurement with a stated backstop comparison.
  - Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3.3
  - Target: pre-genesis
  - Owner: [`STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md) — the sim that would carry the row; the measurement is a sim row, not a lane's side task

- **Delete `get_version`'s `target_height` zero-sentinel at the wire boundary.** `shekyl-daemon-rpc/src/methods.rs` `wire_target_height` writes `if tip.synchronized { 0 } else { tip.target_height.map(ChainCount::to_raw).unwrap_or(0) }`, overloading a height field to carry a second fact. **This is a wire-surface wart, not a contract change:** inland `ChainTip` (`rust/shekyl-daemon-rpc/src/chain_facts.rs`) is `Option<ChainCount>` (`None` = core-reported 0, C5) beside a separate `synchronized` bool. The sentinel survives only where the POD is flattened into `GetVersionResponse`. **Owner: the daemon-RPC surface's lane** (`RK-`), [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md), whose gate obligations this carries — a JSON-RPC response-shape change, not the wallet's. **Discharge condition:** when it lands, `SyncedChainFacts`'s sentinel arm has nothing left to absorb and the constructor collapses from `synchronized && (target_height == 0 || height >= target_height)` to the flag alone (`rust/shekyl-engine-core/src/engine/daemon/synced_chain_facts.rs`, PR #792, ratified 2026-09-19). Note the wallet's constructor reads **`get_info`**, which has no Rust handler yet, so this deletion does not by itself reach the wallet — the two move independently and the conjunction retires when `get_info` migrates. Falsify by `rg -n 'synchronized \{ 0 \}|if tip.synchronized' rust/shekyl-daemon-rpc/src/methods.rs` returning nothing.
  - Target: pre-genesis

- **The claim-source reply should carry the hash of its own gather tip, so a vouched record needs no bracket.** `get_archival_emission_claim_source` (`src/rpc/archival_claim_source.cpp`) gathers `chain_height` and the record from one `db.height()` read but reports only the height, so the wallet cannot tell **which** chain the record was gathered on. PR #792 closes the reorg-across-the-witness hazard with a bracket — `SyncedChainFacts::bracket` re-reads the block at the witness tip *after* the record and refuses a witness whose block was replaced (`rust/shekyl-engine-core/src/engine/daemon/synced_chain_facts.rs`, minted only in `fetch_vouched_claim_source`). **Two residuals remain, named on `bracket`:** a chain that leaves the witness block and returns to it inside the two-RPC window, and blocks *above* the witness tip that arrived inside the window, which the record may carry and the identity does not cover — so an absence first seen by such a record is stamped at the witness tip, up to that many blocks before it was observed, which is the release-early direction, bounded by one RPC window. Both close only at the source: the reply carrying `top_block_hash` beside `chain_height` from the same read, decoded into `EmissionClaimSource` as a `BlockHash`, after which the bracket's third round trip is deleted and the record vouches for itself. **Owner: the daemon-RPC surface's lane** (`RK-`), [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md) — a JSON-RPC response-shape change with that lane's gate obligations, the same class as the zero-sentinel row above. Falsify by `rg -n 'top_block_hash' src/rpc/archival_claim_source.cpp rust/shekyl-engine-core/src/engine/emission_source.rs` hitting on both sides.
  - Target: pre-genesis

- **Count-versus-height: height-semantics Phase 2f typed ScanResult and the remaining inland ordinals.** Census has no unclear family; wire table and inland/wire convention are in [`HEIGHT_SEMANTICS.md`](design/HEIGHT_SEMANTICS.md) §3. Phase 2f: `ScanResult` heights, refresh echoes, build/journal clocks, the birthday floor (`restore_from_height`), balance, the curve-tree reference clock, and the scan producer (exclusive end `ChainCount::next_height`; JSON block number `usize` only inside the fetch helpers) are `BlockHeight`; the reference spans are `BlockCount` (`SEND_JOURNAL_BLOCK_VERSION` 3, `SYNC_STATE_BLOCK_VERSION` 3, `WALLET_LEDGER_FORMAT_VERSION` 20). No numeric change; wire/FFI stay `u64` (C1). Remainders: stamp-clock COUNT→ORDINAL conversion is optional-not-owed; `get_version` `target_height` wire `0` still `RK-`. Falsify Phase 2f by `ScanResult.processed_height_range` still `Range<u64>`. Falsify the stamp remainder by a production stamp compared as a count against an ordinal from a different clock.
  - Owner: [`HEIGHT_SEMANTICS.md`](design/HEIGHT_SEMANTICS.md)
  - Target: pre-genesis
  - Owner: [`HEIGHT_SEMANTICS.md`](design/HEIGHT_SEMANTICS.md) §3 — the wire table and the inland/wire convention; it outlives each phase's PR

- **Fourteen crates meet the feature-governance trigger ungoverned** (declare a Cargo feature another workspace crate enables, directly or by forwarding) and sit in the exact-hit, shrink-only grandfather list of [`scripts/ci/check_test_only_features.py`](../scripts/ci/check_test_only_features.py), whose docstring owns the detail; two are normal-edge test-feature findings that go first, and the fifteenth entry (`shekyl-crypto-pq`) is F-7's. Falsify by the gate reporting `trigger met and grandfathered (shrink-only): 0`.
  - Target: pre-genesis

- **`PL-D4` — a proper hash-commitment mechanism for the leaf's 4th scalar, succeeding the `PL-D3` Pedersen commitment.** A hash over the leaf field chosen on measured gates and published cryptanalysis, with generated parameters, pinned vectors, a registry row and one shared Rust implementation; it makes the leaf commitment binding beyond discrete log and is what a post-quantum-sound membership leg would prove over ([`design/FCMP_SPEND_LINKABILITY.md`](design/FCMP_SPEND_LINKABILITY.md) §6.5). Ruled 2026-09-14: designed with the V4 lattice-only transition (itself gated on lattice threshold signatures or mature isogeny signatures such as PRISM) as one leaf-format cutover; until then `PL-D3a`'s record beside the point is the post-quantum ownership record for every v3 output.
  - Target: V4

- **CEN-A7's per-block transaction-count bound has two undocumented values: `2^28` (`CRYPTONOTE_MAX_TX_PER_BLOCK`, `cryptonote_basic.h:914`, an element count) and `10^6` (`shekyl_wire::READ_LEN_CAP`, `block.rs:163`).** A knowingly-reproduced deviation in the DRS §7.6 three-field form — *reproduced:* two structural bounds on one field, neither derived; *why:* parity first, and no real block approaches either; *correct:* one constant with a derivation record (a count bound derived from the block-weight limit, or ruled unbounded-below-weight), typed as a count rather than a bare integer so a bytes/count misreading is a compile error. Owner: the wire-format port ([`BLOCK_TX_WIRE_FORMAT_PORT.md`](design/BLOCK_TX_WIRE_FORMAT_PORT.md)), where A6/A7's wire-side invariant register also lands. Falsifier: one constant with a derivation record, or the divergence ruled. Found at [`CHAIN_RULES_SLICE_1.md`](completed/CHAIN_RULES_SLICE_1.md) F2; migrates into the E2 repair-backlog query when minted.
  - Target: pre-genesis

- **The `shekyl-fcmp` fuzz crate is built nowhere in CI.** `fuzz_curve_tree_leaf_hash.rs` compiles against `construct_leaf`'s three-argument `PL-D3` signature (target rewritten by `PL-D3`, verified 2026-09-14); the remaining gap is that the only gate is the file-presence inventory in `rust-audit-test.yml`, so a future stale target would go undetected. Build the fuzz crate in CI (`cargo fuzz build` or `--features fuzzing` check) so a stale target is red.
  - Target: pre-genesis

- **`ARCHIVAL_P_DERIVE_V1`'s regenerator is not citation-gated** — its manifest's `regeneration_command` predates rule 50's `SHEKYL_PINNED_REGEN_DECISION` requirement; arm it the way the gate-4 lifecycle regenerator is armed. Surfaced by the withdrawn V1 retirement ([`ARCHIVAL_ENDPOINT_UPDATE.md`](design/ARCHIVAL_ENDPOINT_UPDATE.md) §5, 2026-09-13).
  - Target: pre-genesis

- **DRS-BENCH redb arm: add when a redb-backed `shekyld` build target exists that reports its backend.** Two binaries, one backend each (ruled 2026-09-14); the first real ratio must come from two real artifacts, since `check`'s `compare()` has only ever run on fabricated fixtures — detail in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) §7.4 stage one. Falsify by: a build producing a second daemon target whose `--version` names `redb`.
  - Target: pre-genesis

- **DRS-W16: `remove_block` deletes at an implicit cursor position its caller sets.** The positioning `mdb_cursor_get(…, MDB_SET)` was removed by inherited commit `22c0fae47b` (subject unrelated to block removal); the delete is correct today only because `BlockchainDB::pop_block` reads the top block through the same write-cursor member one call earlier. Latent, not reachable in this tree — but any `blocks` read inserted between those two calls, or any second caller of `remove_block`, deletes at a valid-but-wrong position, which **succeeds silently** while the explicitly-positioned `block_info` and `block_heights` deletes remove the right rows. Either restore the dropped `MDB_SET` or land the guard at the Rust port. Falsify by `grep -n "MDB_SET" ` over `remove_block` in `src/blockchain_db/lmdb/db_lmdb.cpp`. Mechanism in [`LMDB_WRITE_ATOMICITY_AUDIT.md`](LMDB_WRITE_ATOMICITY_AUDIT.md) §9.
  - Target: pre-genesis

- **No test puts a validating user transaction into a chain and then reorgs or re-derives rewards around it.** The C++ core tests that did (`gen_simple_chain_001`, `gen_simple_chain_split_1`, `gen_chain_switch_1`, `gen_block_reward`, `gen_uint_overflow_*`) had been disabled since 2026-05-05 — the C++ builder never learned the FCMP++/PQC format — and were deleted with that builder (per-test rows: [`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) §9.1). A validating spend exists and is gated per PR (`regtest_e2e.rs` `e2e_fcmp_spend_accepted_by_daemon`); a chain *containing* one that then reorgs does not, and E2's corpus is built from replay over coinbase-only chains — the regime that hid CEN-I12 and SOK-10. Falsify by an E2 corpus store holding at least one Engine-built spend, or a `regtest_e2e` reorg case around one.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) §3.10 (the mutation/reorg corpus family)

- **The archival attestation path is unbuilt end to end, and its pieces are tracked in rows that do not name each other.** `blockchain.cpp:5140` sets `headers_readable` from the coinbase extra and `:5147`/`:5197` branch consensus on it; with no producer the value is constantly `true` with an empty blob (a parsed extra with no `0x0B` tag is the committed empty set), so the records loop inside `if (headers_readable)` runs on every block with zero records — CEN-I12's shape at the mechanism level. (`ERR_HEADERS_UNREADABLE` itself is reachable: attestation verify precedes the I19 coinbase parse check on both paths, `blockchain.cpp:2242`/`:2248`, `:5299`/`:5428`.) Four rows, one mechanism: **(1)** the producer (a coinbase carrying pass records) — the row below; **(2)** the C++ verify-behind-PoW reorder (two rows down) — required only if the producer lands while the C++ daemon is consensus; in Rust, CEN-B4 sits after D1 in `validate`'s order by construction; **(3)** CEN-B4 in Rust — slice 1 deferred it because bond pairs have no store table until E4 S-ARCH; **(4)** the `0x0B` record parser `TXE-Q4` refused (`TX_EXTRA_RUST_CUTOVER.md` §2.2). **What breaks the cluster is the producer**, and its natural home is the block-template writer `TXE-F8` names as unowned: whoever builds the coinbase in Rust builds the record-carrying coinbase, and (2) is then satisfied by Rust's rule order rather than by a C++ reorder. Falsify by `rg 'add_archival_attestation_to_tx_extra\|shekyl_coinbase_extra' src rust` showing a production caller that emits records.
  - Target: pre-genesis
  - Owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md); the writer's home per [`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) TXE-F8

- **`tx_extra` `0x0B` (archival attestation) has a consensus reader and no producer.** `parse_archival_attestation_from_extra` (a shim over `shekyl_tx_extra_field` since the tx_extra cutover, 2026-09-23) decides `headers_readable` for attestation verification (`blockchain.cpp`), and `shekyl-wire` models the tag, but nothing emits one — the C++ `add_archival_attestation_to_tx_extra` was deleted with the C++ codec (its only caller was a test), and `shekyl_coinbase_extra` builds the coinbase extra without it. **The producer is a consensus amendment, not a wiring job:** the coinbase grammar (`CEN-I20`, `GENESIS_TX_WIRE_FORMAT.md` §9.6b) admits exactly `[0x01, 0x02, 0x06, 0x07]` today, so a `0x0B`-carrying coinbase is refused at connect until the grammar row is amended to admit one bounded `0x0B` — that amendment is ruled in the census and the wire spec, then implemented in `check_coinbase_extra_shape` and `build_coinbase_extra` together (`canonical_nonce` is the layout the checker admits; `COINBASE_TAGS` is the tag list a refusal names). This supersedes the earlier entry that grouped `0x0B` with the inherited merge-mining and minergate tags as "no producer found" and slated all three for deletion: that reading was wrong twice, in attributing the `0x03` emission to `get_block_template` (it was `on_add_aux_pow`) and in treating a missing *producer* as evidence of dead code when a live *reader* existed. `0x03` and `0xDE` are now deleted; `0x0B` is kept. **Blocker (rule 22):** the producer cannot be wired before the entry below — attestation verify must move behind PoW before credit-wire population activates — because a coinbase that actually carries pass records is what turns that pre-PoW verify from free into a DoS surface. The producer lands with, or after, that reordering (owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md); census: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §7 #19 round 4).
  - Target: pre-genesis

- **Attestation verify must move behind PoW before credit-wire population activates.** `verify_block_attestation` runs before `check_hash` on both acceptance paths (blockchain.cpp:5738 < 5818; 2253 < 2347) — free pre-cutover (empty witness), but post-cutover it does up to one hybrid-signature verify per pass record before any work is proven, a DoS surface; the Phase-5 ordering constraint is pinned at both call sites (re-filed: the earlier entry survives only as the truncated headline "Credit-wire cutover has two preconditions the Phase-2 verify cannot satisfy") (owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md) §3; census: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §6.7).
  - Target: pre-genesis

- **Hard-fork voting is kept; its reject is still discarded (CEN-B3).** Ruled 2026-09-23: miners decide when a pre-specified upgrade activates, by the existing vote window stepping the hard-fork table (rule 75). Humans still specify what the next row is. The window stays. The dead version-dispatch arms are a separate deletion: a transaction version is 3, `get_transaction_weight_limit` takes no fork version, and the unreferenced Monero-era `HF_VERSION_*` macros are deleted. What is still wrong is that `blockchain_db.cpp` calls `HardFork::add` and ignores a false return, so a block that fails the vote check is connected anyway. Falsify by that call site honoring the reject.
  - Target: pre-genesis
  - Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §5.5 (CEN-B3; C2 batch R4)

- **Split `archival_reorg_depth_blocks`: one setting doing two jobs (rule 05).** The key is the **pass-anchor depth** (how far back a requester anchors so an admitted pass survives any legal reorg; `pass_anchor.rs` `PASS_ANCHOR_DEPTH_BLOCKS`; requirement `≥ reorg cap + L`) — the job it was tuned for — *and* the **reorg cap** `D_max` (`PDM-Q11`, `CEN-E2`; `shekyl_chain_rules::D_MAX` / `RuleSet::reorg_cap` **inherit** it; a detectability boundary on Q11's own requirement). Owed: E4 derives the depth's own value from pass admission's requirement (it may equal 720; it is not the same number), gives it its own key and home, and lands the assertion `PASS_ANCHOR_DEPTH_BLOCKS ≥ reorg_cap` on the production pair (const) and at arm on every nettype (the `SEB > D_MAX` shape) — a fakechain with a shortened cap needs a check that its pair is valid, not a depth that tracks the cap. Until then the inheritance is recorded as inheritance (the key's comment, `reorg.rs`, `DRS_E1_SPRUNE.md` SPR-6). Surfaced by the S-PRUNE review (PR #861, 2026-09-25; SPR-Q1 resolved by this split). Falsify by: `git grep -n 'from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS)' rust/` returning both `D_MAX` and `PASS_ANCHOR_DEPTH_BLOCKS` — two constants still inheriting one key — or a levered regtest that arms a cap with no `depth ≥ cap` check firing.
  - Owner: [`ARCHIVAL_SHARD_FETCH.md`](design/ARCHIVAL_SHARD_FETCH.md) SF-D8 (pass admission, E4)
  - Target: pre-genesis

- **Shard partition: production `T` (transactions per shard; `PDM-Q6` item 5, RULED 2026-09-23 — `SHARD_BYTES` retired as consensus, no A4 rows) gets one const-asserted home (S-PRUNE's constants commit, DRS-E); the verifier reads `[k·T, (k+1)·T)` off `cumulative_tx_count` (S-ARCH); the leaf partition's tie is LANDED (#780) — not an interim assert: one home in `shekyl_fcmp::tree` (`SEGMENT_LAYER_J`, `leaves_per_segment`), consensus-side `SEGMENT_LEAF_COUNT == leaves_per_segment()` compile-time in `shekyl-archival-retention`'s production lib, red-checked by `segment_leaf_count = 26030` (alignment-preserving, so it clears the chunk assert) failing at that pin — and lives until E4 / S-ARCH deletes the freeze (wallet lane; the CT-1 row closed with #780's dedup).** Re-keyed 2026-09-18 from #775's leaf-unit row (`PDM-Q-F33`). Falsify by a second home for a production `T` — a literal in any shipped crate beside the `consensus_constants.json` authority `shekyl_types::SHARD_TX_COUNT` is generated from — or shipped Rust deriving a shard boundary from anything but `cumulative_tx_count` and `T` (a byte length in particular); the spike/sim model constants are out of scope by design. *Falsifier history:* the original "a production `T` in `consensus_constants.json` is red" was inherited from `SHARD_BYTES`'s not-a-tune rule, and `SHARD_BYTES` was retired as consensus 2026-09-23 — the inheritance lapsed, not merely the wording (S-PRUNE SPR-10, 2026-09-25/26). The reason of record for `T`'s home is the JSON's discriminator (`DRS_E3_CURVE_WRITER.md` §3.9): a value goes in iff a schedule, a network or an operator could legitimately name it differently, which an archival policy unit can and a proof-system arity cannot.
  - Owner: [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q6 item 5 (the partition), F33 (dispositions i–iii)
  - Target: pre-genesis

- **Bond admission's shard predicate — RULED, unbuilt; three design questions owed to E4 / S-ARCH.** Bond admission accepts only **valid, closed, final** shards (ruled 2026-09-19; [ARCHIVAL_BOND_ADD_ADMISSION.md](design/ARCHIVAL_BOND_ADD_ADMISSION.md)). **Sizing: a new rule plus an unimplemented old one.** There is **no code predecessor** — `ShardSet::new` enforces only cardinality and duplicate-freeness (`bond_wire.rs:210-227`), and `frozen_segment_count`'s three consumers are the D2 escalation operand, the coverage RPC and freeze / pop-revert, none of them admission — while the **design predecessor is partial**: `PDM-Q6` item 3 already rules the open frontier shard non-bondable (`ARCHIVAL_PRUNED_DAEMON_MODE.md:458-459`), unbuilt and silent on the reorg window, and the existence half has no predecessor at all. Open: the predicate's site; its evaluation height (the `blockchain.cpp:1478-1492` read-point hazard applies — capture the operand before the connecting block advances the chain, or the check is a tautology that passes every test); and whether `ShardSet` gains chain context or a separate check owns it, trading one fallible constructor against a pure one. **Gated on** the A4 length rows (S-CHAIN-W) and S-PRUNE deriving `b_*`. **Discharged when** the predicate exists at its ruled site with a test set that can **fail in both directions** — a **valid closed, final shard is accepted**, and each of a **ghost** `shard_id`, the **open frontier shard**, and a **closed shard still inside `D_max`** is refused — all evaluated at the chosen pre-connect height. A refuse-only test is satisfied by an implementation that rejects everything, and a ghost-only test never exercises the load-bearing closed-and-final leg.
  - Target: pre-genesis

- **`PDM` propagation sweep — DISCHARGED 2026-09-19, four PRs in the ruled order, one per document: `docs/pdm-sweep-psl` (PRINCIPAL_STAKE_LIFECYCLE → LIVING CONTRACT), `docs/pdm-sweep-acm` (ARCHIVAL_CHALLENGE_MECHANISM on the tx unit), `docs/pdm-sweep-v3sa` (V3_STAKER_ARCHIVAL contracted, 1,546 → 1,000 lines), `docs/pdm-sweep-ctc` (CURVE_TREE_CLIENT §7 resolved in two halves); PRs #795, #796, #797, #798 in that order (#798 merges last; it carries this line). Each carries `PDM-Q6` / `PDM-Q12` in its current-tense body, not as an appended banner; `grep -c PDM` at the closing pin: PSL 9, ACM 24, V3SA 25, CTC 21. The row's original text follows as the record of what was found.** *Was:* four documents never received `PDM-Q6` / `PDM-Q12`, and all four still designed against the leaf unit. `grep -c PDM` returned **0** at `dev@8494f2a27` for [V3_STAKER_ARCHIVAL.md](V3_STAKER_ARCHIVAL.md), [ARCHIVAL_CHALLENGE_MECHANISM.md](design/ARCHIVAL_CHALLENGE_MECHANISM.md), [CURVE_TREE_CLIENT.md](design/CURVE_TREE_CLIENT.md) and [PRINCIPAL_STAKE_LIFECYCLE.md](design/PRINCIPAL_STAKE_LIFECYCLE.md). **This is the same failure mode that produced the `CTS-` / `PDM-Q12` collision** ([WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §0): a ruling lands, its design homes are not swept, and the next agent that greps `shard` or `R_k` designs against the retired unit. **Owner: needs one — not the WSS round**, which names the sweep's contents in its §2.2 and refuses it as scope, because a store round silently editing the archival design home repeats the error in the other direction. Leading item: `V3_STAKER_ARCHIVAL.md:18`'s *"The design is unchanged by this correction — only the ship timing"*, which is false since `PDM-Q6`/`Q12` and is the sentence an agent will trust. Note the sweep is a **re-derivation, not a find-and-replace**: `ARCHIVAL_CHALLENGE_MECHANISM.md`'s 3,326,976-byte shard figure survives as the `SHARD_BYTES` boundary metric while its "25,992 leaves × 128" derivation does not (`PDM-Q6` item 4, `RF-D6` row) — and its word **"deterministic" is wrong too**, since under `PDM-Q-F32` a closed shard's size lies in `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)` and shards are no longer fixed-size. Also carries two things a unit sweep would miss: `CURVE_TREE_CLIENT.md` §7.2.1 #5's standing error ("`R_k` plus owned chunks suffice" to build a spend path — they do not), and `PRINCIPAL_STAKE_LIFECYCLE.md`'s §0.1 line drift (`Engine` `mod.rs:585` not L403, `key` `:630` not L452, `stake` `:885` not L681) plus §5 gate 1 / `GF-4b`'s self-declared *"annotated rather than edited"*. **Scope RULED 2026-09-19 (maintainer), two documents:** `V3_STAKER_ARCHIVAL.md` is **contracted, not re-derived** — it keeps only what it alone holds (problem statement, economic design, the firewalled-pseudonym model) and everything mechanism-shaped becomes a **cited pointer** to the owning contract (`PDM`, `SF`, the challenge doc, `PSL`, `WSS`). `CURVE_TREE_CLIENT.md` §7.2–§7.6 resolves in two halves: **serving content (freeze roles 1–3) is deleted** under `PDM-Q12`, and **proving content becomes a pointer to [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.3** as the ruled design of record, with the reopen clause living alongside that ruling; **§7.2.1 #5 dies by deletion** rather than correction. **Sequencing:** the sweep starts **after the WSS round's PR merges**; **one PR per document**, in order `PSL` → `ARCHIVAL_CHALLENGE_MECHANISM` → `V3_STAKER_ARCHIVAL` → `CURVE_TREE_CLIENT`. **Owner: a fresh docs session — not the WSS or RD agents**; review seat unchanged. **Discharged when** each of the four carries `PDM-Q6`/`Q12` in its current-tense body (not as an appended banner) and `grep -c PDM` is non-zero for all four.
  - Target: pre-genesis

- **`PRINCIPAL_STAKE_LIFECYCLE.md` §4a PR-row table: the dated UPDATE / Corrected chains accrete instead of resolving; PR-P4's row is the extreme case.** Hygiene, owner the PSL lane — explicitly *not* the `PDM` propagation sweep (#795 left the chains under its charge). Each row leads with its current status per rule 94 §3, but the load-bearing corrections buried mid-chain (the "dangerous direction" note on `bond_spend_pk`) deserve a current-tense sentence in the row body, with the chain contracted to the ruling dates that still govern. [Owning doc](design/PRINCIPAL_STAKE_LIFECYCLE.md).
  - Target: pre-genesis

- **The leaf-era archival data-scope schema (sets A/B/C, "B + C") survives outside its owner after `PDM-Q6` re-keyed `V3_STAKER_ARCHIVAL.md` §*Archival data scope* and its two declared consumers (`PUBLIC_NARRATIVE_FAQ.md`, `FOUNDATION_ARCHIVAL_DISCLOSURE.md`; #797).** Remaining sites at the 2026-09-19 census: `FOUNDATION_GENESIS_IDENTITY_SET.md:111`, `DAEMON_REDB_STORE.md:2400`, `ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:584`, `ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md:66-169`, `ARCHIVAL_CORPUS_FOSSIL_SWEEP.md:94` (`STAKER_ARCHIVAL_SIM.md` is sealed and stays). Owner the `PDM` lane, which owns the good / skeleton / shard vocabulary: re-key each living site or mark it line-locally superseded. [Owning doc](design/ARCHIVAL_PRUNED_DAEMON_MODE.md).
  - Target: pre-genesis

- **The archiver's serving store needs a retention rule for a dropped shard, and an enforcing site.** How long `P` keeps a shard after a `HoldingsUpdate` drop or a bond release, and what enforces it. Owner: [`ARCHIVAL_SERVING_ROUTE.md`](design/ARCHIVAL_SERVING_ROUTE.md) for the **rule**; the **enforcing site and its test** are [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) `WSS-Q8` — in `P`'s serving store, a separate file owned by the `StakeEngine` (§6.1), **not** `rust/shekyl-curve-tree/src/store/`. **The rule has a builder, and it is landed:** `EngineServeSetPinner` releases a pin only after the shard has been absent from the bond record at **two consecutive epoch opens** (`EPOCHS_BEFORE_PIN_RELEASE = 2`, `rust/shekyl-engine-core/src/engine/stake_engine/departure_ledger.rs:82`; the argument is on `DepartureLedger::observe`, `:202`). The gate moved out of `serve_set_source.rs` into its own module with the two evidence hazards it guards — a sync gap and a rollback under the daemon's sticky `synchronized` flag — since both are statements about the *observer's* timeline rather than about the chain (PR #792). It covers the recovery-fetch consumer — `SF-D10` draws uniformly over the epoch's drawable snapshot and `SO-D8` Q3 §7.4 keeps `D` unfiltered at tip, so *"a dropped pair stays in `D` for `E`"* (`ARCHIVAL_CHALLENGE_MECHANISM.md:197-203`), and the pair stops being drawable before release. It names **no underived operand** (`W₂` is deliberately not an input; rule-21 reopening criterion if `W₂` ever reaches one epoch) and sits far deeper than `ARCHIVAL_REORG_DEPTH_BLOCKS`. `P`'s store **erases on this gate and nothing earlier** — `StoreShardProvider` has no serve-set notion and answers for any present bytes, which is what keeps the obligation met while the pair is still drawable ([WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.2.6). **Discharged when** the serving route carries the rule and `P`'s store has a test for the serving reader's answer past the horizon. Ruling: [`V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md) (2026-09-17, two stores); re-keyed off the leaf-era *"path-assembly serving purpose"* by `PDM-Q6`.
  - Target: pre-genesis

- **Daemon uniformity: "no archival serving state in the daemon, ever" must be written where DRS-E4 S-ARCH will read it.** Ruled 2026-09-17 ([`V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md), two stores): the daemon holds archival consensus state (bonds, serve credits, settlement, slash) and no serving state, because an archiver-backed daemon that behaves differently from a plain one fingerprints the Principal's public address. The archival fast path in the daemon is REJECTED at any performance argument; the criterion is persistent posture-correlated state (forbidden) versus episodic, universally available actions such as the witness fetch (allowed). Pruning posture is part of uniformity: all daemons prune uniformly (PDM owns the default). The constraint belongs in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md)'s S-ARCH / E4 design so the port enforces it, not only the decision log. Carrier: the E4 S-ARCH pre-flight (the DRS lane's doc, rule 94 §6). **Discharged when** `rg -n 'no archival serving state' docs/design/DAEMON_REDB_STORE.md` hits in the S-ARCH / E4 section. **Violation signal** (the constraint broken, whether or not written down): `rg -n 'serving|LeafStore|shard bytes|ServedFrame' rust/shekyl-chain-store/src` returning a definition that serves archival content.
  - Target: pre-genesis

- **`#[serde(default)]` still lets an omitted daemon field become its zero value.** RK-4c refused *unknown* fields on the RPC read surface (`deny_unknown_fields`, `shekyl-rpc-types::chain`/`transactions`), which catches a renamed field but not an omitted one: 27 fields across those two modules default silently if the daemon simply leaves them out, and a zero height or an empty status reads as data. Needs a per-field pass — some absences are legitimate `KV_SERIALIZE_OPT` omissions the oracle vectors depend on, so this is judgement per field, not a sweep (owner: [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md) §3.2).
  - Target: pre-genesis

- **`CEN-L8`'s settlement clause has no production caller; census home is already the slash pass.** DRS-P0f slice 3 (2026-09-02) failed CEN-L8 closed to UNREVIEWED: `set_archival_settlement` has **no production caller**. **SUPERSEDED 2026-09-12:** "census row names the wrong hook" — `CONSENSUS_RULE_CENSUS.md` CEN-L8 already homes settlement in the slash scheduler's per-epoch pass (`SO-D7`); the production caller is ruled-blocked on `SO-D8`, not missing-from-the-row. Remaining (Slice C, unauthorized until Q15's falsifiers fire): the R-B admission rows in `shekyl-chain-rules` — deadline (`h < h_incl ≤ h + CHALLENGE_RESPONSE_BLOCKS`, the constant's **first code reader**; `SO-D8a`), membership against `assignment(h)`, dedup `(P,s,E,h)` exact-get (`SO-D8b`), witness authentication, `SO-D9` (i) — plus writer + gather (`SO-D8c`) and the `SO-D8d` `SI-` row land on the Rust apply/slash path, then `DRS-P0f` re-reviews. Digest is regression-only until then. Owner: [`CONSENSUS_STORE_RECONCILIATION.md`](design/CONSENSUS_STORE_RECONCILIATION.md) §5.4.1.
  - Target: pre-genesis (event-driven: SO writer wired on S-ARCH, then DRS-P0f)
- **`SO-D9` — `ERR_EPOCH_MISMATCH` on the serve-credit admission path is a tautology; RULED (i) 2026-09-13, implementation owed.** (C++ `blockchain.cpp` / `shekyl_ffi.h` line numbers pinned at `dev@37accf6f` with the proposal; identifiers are the grep surface — do not chase HEAD.) `serve_credit.rs:168` refuses when `response.settlement_epoch != ctx.settlement_epoch`, but `ctx.settlement_epoch` is set at `blockchain.cpp:5304` from `sc_settlement_epoch`, parsed out of the same record at `:5124`; `shekyl_archival_verify_serve_credit_vin` has one caller (`:5315`). The check compares the record to a copy of itself — rule 50 "check that cannot fail", second instance in the SO arc. **Ruled (i):** the record's epoch equals `settlement_epoch_at_height(h)` of the validated issuing block — an explicit single-site rule, not the *when*-bound `h_close` leaves implicit. **Re-homed 2026-09-16 (Q15):** lands as a `shekyl-chain-rules` row with the R-B cutover; not a C++ one-liner (`shekyl_ffi.h:2594` is not the call site). Records-was of the LMDB path (Q15: this check does not land there): **two** C++ gates run before the FFI — `current_height > h_close(E)` (`:5188`) refuses a stale header, and `challenge_seal_on_chain(h_open(E), current_height)` (`:5201`) refuses a **future** one — so the only header reaching the tautology with `E ≠ epoch(current_height)` is `current_height = h_close(E)`. That one-block flip is why (i) must not ship on this path; under R-B the operand is the validated issuing `h` and the straddler is admitted when `epoch(h) = E`. **Prohibition:** do not repair the tautology in `blockchain.cpp` — making that check fire is a consensus tightening on the live LMDB daemon for a path being replaced; in chain-rules it is a positive row with a negative fixture and the tautology never ports. Falsify by a `shekyl-chain-rules` `CenRow` whose negative fixture refuses `settlement_epoch ≠ settlement_epoch_at_height(h)` with a typed `InvalidBlock` — not by the C++ assignment disappearing, not by a C++ one-liner that makes the vacuous comparison fire, and not by a full-path future-epoch vector (the seal gate still refuses those on the LMDB path until the cutover). Owner: [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](design/ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) `SO-D9` / Q15; [`ARCHIVAL_SETTLEMENT_WRITER.md`](design/ARCHIVAL_SETTLEMENT_WRITER.md) §13.
  - Target: pre-genesis
- **Serve-credit inclusion incentive and archival weight pricing — the fee-and-weight round Q9 names but nothing scheduled.** Q9 (RULED 2026-09-16, `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.6) leaves three items to a round that did not exist as a work item: (1) **unpaid inclusion** — the witness is unpaid by ruling and the carrier is structurally fee-less (`txnFee != 0` refuses), so inclusion rests on miners carrying zero-fee weight, and a miner at the median is priced to omit; (2) a **prunable-weight discount** for archival bytes (the lever if (1) bites — same weight-path fact, other side); (3) the **cap-raise** to admit one 97-record carrier (~11 KB/block ≈ 2.8 GB/year vs the 42/42/13 split under the amended Q9). Blocked on: the economics sim's inclusion-rate dynamics at median-bound blocks (not on Slice C). Falsify by a sim run showing the inclusion rate of zero-fee carriers at blocks at or above the effective median; if omission is material, (2) is the lever and this row becomes its design round; if not, close (1) as won't-fix and carry (3) alone. Owner: `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.6 ("The residual, held").
  - Target: pre-genesis

- **Connect-path regression for the hash-gated FCMP++ proof-skip (`CEN-M8` fix wiring).** PR #602's unit tests pin `take_tx`'s cache verdict, but no test executes the consumer gate at block connect — reverting `can_skip_fcmp` to presence semantics would leave them green. The regression (an invalid-proof pool tx with `fcmp_verified = 0` must fail the block; its verified twin must connect with the skip) needs a connectable FCMP++ block whose tx is valid in every layer except the membership proof. **The blocker named here was the wrong one.** It read "no daemon-accepted FCMP++ spend builder"; that builder has existed since PR #193 (2026-06-27). The real blocker is narrower and is a question, not a gap: **does the FCMP++ prover error on an inconsistent witness, or emit a proof that fails verification?** The discriminating transaction is built by perturbing one branch scalar in `SpendInput.c1_layers` *before* `sign_bridge.rs`'s proof generation (`:447`), so the PQC auth signed at `:487` is genuinely valid over a false proof — one layer wrong, not two. If the prover hard-fails instead, the perturbation has to move. Build it once that is answered; the M8/G4/J26 register re-review does not wait on it (the code walk covers the wiring), but E2's regression harness should include it. **Why CEN-D2's equivalent was buildable and this is not:** there the failing schema is itself the discriminator, so any generated block exercises the consumer; here the discriminating transaction must be valid in every layer *except* the membership proof, which is exactly what no current builder can produce. Owner: [`CONSENSUS_STORE_RECONCILIATION.md`](design/CONSENSUS_STORE_RECONCILIATION.md) §5.4.1.
  - Target: pre-genesis (blocked on the prover-behaviour question named above, not on a builder)

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

- **`release_readiness` query (frozen §2 surface) deferred — blocker: persona addressing.** The exit became reachable with PR-C (the line this one replaces is DISCHARGED: `unstake` + `collect_unstaked` landed on [`StakeFacade`](../rust/shekyl-engine-core/src/engine/stake_facade.rs), wallet-RPC + CLI, 2026-09-03), and its refusals carry the readiness operands (`-29517 data.detail`), so a staker is never blind to WHY an exit refuses. What did NOT land is the standalone pre-flight query `release_readiness(P)` from the frozen §2 surface. The named blocker, not a convenience deferral: the frozen signature is persona-addressed, the RPC surface is forbidden from enumerating personas (`principal_stakes()` is RPC-REJECTED as the P↔principal edge), so the query's wire shape is blocked on a persona-addressing design the multi-slot UX round owns. At genesis scope (single slot) the refusal detail is the same information. [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §2.
  - Target: pre-genesis

- **LMDB unbond-journal naming excluded from the Unbond → Release rename — carried by the DRS redb port.** The 2026-09-08 rename PR converted all internal Unbond vocabulary to Release but deliberately kept the on-disk LMDB name `archival_bond_unbond_log` and its direct C++ carriers (`m_archival_bond_unbond_log`, `ArchivalBondUnbondLogKey`/`ArchivalBondUnbondRevertValue`, `apply_archival_unbond`, `revert_archival_unbonds_at_height`): the name is pinned row-by-row in the DRS reconciliation registry and schema/atomicity docs that concurrent DRS lanes own (rule 94 §6), and the LMDB store is the redb port's deletion target — renaming a to-be-replaced on-disk name mid-port is churn against the owning lane. Carrier: the DRS redb cutover names its successor table with Release vocabulary; if the redb port is abandoned, this rename lands as its own PR instead. Owner: [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md).
  - Target: pre-genesis

- **`LmdbHashKey::from_bytes` / `Key::compare` still `expect` on redb's fixed-width promise.** The `Tagged<V>` retrofit that folds that expect is the named landing; RTN-7's `From<BlockHash>` / `From<TxHash>` on `Hash32` is the signature it lands against ([`completed/RTN_7_WIRE_HASH_TYPES.md`](completed/RTN_7_WIRE_HASH_TYPES.md) §2). Falsify by `rg 'Tagged<' docs/ rust/` returning a row that names this expect. Owner: [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) (`shekyl-chain-store`, the DRS lane).
  - Target: pre-genesis

- **Collected-total earmark warning (§12.3 carve UX, ruled 2026-09-04 with the carve countersign).** The terminal sweep's total is per-`P` predictable (collateral public via the record delta, rewards derivable via §18.10), so an outgoing principal transfer whose amount falls within the cover-draw range of a collected total *this wallet itself built* re-exposes exactly the off-chain amount-match channel the carve concedes. Owed: a **context-bearing warning** at the send surface — rule 82 shape: say *why* (the figure is a per-`P` fingerprint), proceed on acknowledgment. **Warning, never an armed refusal**: a user may deliberately disclose their own amount (they could as easily post it); the duty is to the *unaware* user who earmarks the lump without knowing. Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §12.3.
  - Target: pre-genesis

- **§12.3 carve UNMEASURED bound — rule-21 measurement obligation with a named expected resolution.** The carve's third bound (the cover draw's range blurring the amount-match against the population of predictable per-`P` totals) is recorded as assumed, not established. The measurement that would settle it: draw range against the spacing of realizable per-`P` totals, **reward component included** (it de-clusters what collateral tiers cluster). **Expected resolution is NOT this measurement**: the dust-tolerant retirement gate — letting retirement proceed over a sub-floor residual instead of pinning the pool to exact zero — would retire the total-shaped sweep's necessity and this bound with it. The measurement happens **only if that gate does not ship pre-genesis**; whoever closes the retirement-gate question inherits this row (that decision's owner is the trigger, not a calendar). Owner: [`PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §12.3.
  - Target: pre-genesis

- **Release-asset manifest signing owed before the first non-RC release tag (added 2026-08-14, SA-6 CBOM close; CORRECTED 2026-08-15 — a wiring task, not an open decision).**
  - Target: pre-genesis

- **F-7 — structural gate for the test-only FFI exports that ship in the production archive; two leak shapes, two remedies, one `nm` gate seeded from a sweep** — record: [`design/F7_TEST_ONLY_FFI_EXPORTS.md`](design/F7_TEST_ONLY_FFI_EXPORTS.md).
  - Target: pre-genesis

- **GENESIS ADDRESS FORMAT: PQ signing anchor decision (address v2) — [`design/WALLET_MESSAGE_SIGNING.md`](./design/WALLET_MESSAGE_SIGNING.md)**
  - Target: pre-genesis

- **FFI *signature* drift has no remedy, unlike FFI *constant* drift [`audit_trail/2026-05-ffi-constant-drift-audit.md`](./audit_trail/2026-05-ffi-constant-drift-audit.md)**
  - Target: pre-genesis

- **TJ-1 (was CRITICAL) — leaf-index beacon MITIGATED 2026-08-24 (`PC-D3`); still closes by TJ-B deleting the vin-carried opening.** [`ARCHIVAL_RESPONSE_FORMAT.md`](design/ARCHIVAL_RESPONSE_FORMAT.md)
  - Target: pre-genesis

- **TJ-2 — `CHALLENGE_RESPONSE_BLOCKS` is PINNED (2026-08-15); the freeze item is discharged, one dependent fix remains.**
  - Target: pre-genesis

- **TJ-3/TJ-4 (HIGH, `(m, n)` re-pin inputs)** (added 2026-07-29, §10.3–§10.4).
  - Target: pre-genesis

- **TJ-7 (HIGH, sweep input) — sybil-per-shard has NO uniqueness constraint, and the cartel attack is DILUTION not multiplication.**
  - Target: pre-genesis

- **TJ-8 (briefing constraint on the Round-2 re-pin) — do NOT credit the witness-binding MAC against the window.**
  - Target: pre-genesis

- **TJ-5 (MEDIUM, fix-in-place)** (added 2026-07-29, §10.5–§10.6).
  - Target: pre-genesis

- **TJ price premise — NOT codeable, tracked here with its falsifiers as reopen triggers (added 2026-07-29, `design/ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §5.3).**
  - Target: pre-genesis

- **Superseded-section cross-reference sweep (docs hygiene, split out by the batching rule — added 2026-07-28).**
  - Target: pre-genesis

- **Live-pin index, independent of doc status (process-structural — added 2026-07-28, from the reopen-(d) Round-0 review).**
  - Target: pre-genesis

- **Daemon chain store (`DRS-*`) — gap-close pass landed in design.** SoT: [`docs/design/DAEMON_REDB_STORE.md`](./design/DAEMON_REDB_STORE.md)
  - Target: pre-genesis

- **`txs` is a zero-write, zero-read LMDB table (P0b DRS-W4).** Handle's only occurrence is its `open()`; inherited-dead deletion candidate — C++ + schema-version change, census/DRS lane owns ([audit §9](LMDB_WRITE_ATOMICITY_AUDIT.md))
  - Target: pre-genesis

- **`hf_starting_heights` deleted at every writable `open()` (P0b DRS-W5).** `mdb_drop(…,1)` at `db_lmdb.cpp:1779`, never re-created — macro table structurally absent at runtime; feeds census R4 ([audit §9](LMDB_WRITE_ATOMICITY_AUDIT.md))
  - Target: pre-genesis

- **DRS-BENCH — resource/privacy/IBD/pop suite (not throughput).** File
  - Target: pre-genesis

- **DRS-D3c — root-and-frontier parity, daemon vs wallet.** **Re-scoped 2026-09-19** by `WSS-Q1`(b) ([`WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §10, §12): the wallet's proving state is **not a leaf store**, so this is no longer a cross-store leaf/position KAT — the subject is parity between the wallet's frontier at `F` and DRS-E3's `curve_tree_*`. It lands with the proving-state increment. Original leaf/position framing (superseded by the re-scope): daemon vs wallet LeafStore, same fixture chain, output index *N* → identical tree position and 128-byte leaf encoding, encodings single-sourced, stores deliberately separate.
  - Target: pre-genesis

- **Round-2 stressnet re-pin of the failure-window `m`/`n` — must be JOINT with reopen (d)** — sliding-window m-of-n is built (`failure_window.rs`; pin [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md)); numerics remain Round-1 provisional. Cannot be sized against honest miss alone: gate-4 grace and `m`/`n` are one surface (`slash_prob(q, m, n)`), and pinning for false-slash alone invalidates reopen (d) (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.6). Falsify by the re-pin recording both false-slash and reopen-(d) inputs, not only an honest-failure CDF.
  - Target: pre-genesis

- **`sweep_all` — deleted in WI-RPC-2b, no Shekyl-native surface; decide whether a sweep primitive returns.**
  - Target: pre-genesis

- **Forfeited-claim record does not survive a wallet restart.** The cadence driver's evaluate-and-forfeit (`ENGINE_CADENCE_DRIVER.md` §4) raises `ClaimForfeited` as a session-lifetime alarm; nothing re-detects the forfeit after a restart, so it is the `AlarmLifetime::LatchedRederived` reopening criterion's named third-class candidate — durable acknowledgment state the channel deliberately does not have yet.
  - Target: pre-genesis

- **Drain/claim/release dispatch driver — terminal-reject prune + byte-identical resubmit remain (confirmation-observe landed 2026-08-27, #572; the release lane joined the residue with #601, which landed the SEAM-side release for a definite first-send refusal — `RejectedTerminal` on the one send the seam itself makes — leaving exactly the driver legs the other two lanes carry: crash-window/ambiguous resubmit, and the driver-side prune for records a future resubmit path re-sends).** UPDATE 2026-09-07: the landing site now exists — the cadence driver (`ENGINE_CADENCE_DRIVER.md` §3 leg 4, `engine/cadence/` `TerminalRejectSlot`) registers and invokes an empty leg-4 slot each tick, wiring-proven by test; the residue is exactly the slot's body (prune + resubmit, landed together per the security note below). The per-epoch claim leg itself landed live in the same PR.
  - **PR-C made this residue USER-VISIBLE (2026-09-03):** `unstake` is reachable, and an ambiguous/held exit now surfaces as `-29522 UNSTAKE_FATE_UNKNOWN` (seal held funds-safe, lane shut, stall alarm in the operator log) with **no recovery verb** — the honest rendering of this unbuilt driver, stated in the contract rather than hidden. The prune half remains a SECURITY item (below); never land resubmit alone.
  - The prune is a **security** item, not only hygiene (raised 2026-08-31, PR-A): a terminal `DoubleSpendConflict` on a Release is terminal on *remedy*, not on impossibility — a partial slash then a compensating `Reinstate` can restore the balance these bytes bind (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1, UB2 note). The retained copy is the replay channel, and pruning it is what closes it; the reference age window is the only other bound.
  - Target: pre-genesis

- **Q11 zero-fee-input emission claim has no settlement evidence** (destitute mint-pays-fee; named blocker: accrual has no claim-match set).
  - Target: pre-genesis

- **Enumerate the greenfield pending set: items whose only callers are tests** (`cargo clippy -p <crate>` vs `--all-targets`).
  - Target: pre-genesis

- **GF-7 `stake_in` change-co-presence residual — shipped with a warning, not closed.**
  - Target: pre-genesis

- **Workspace-wide `deny_unknown_fields` on the remaining wallet-RPC params structs — the F-1 out-of-scope half.**
  - Target: pre-genesis

- **Wallet thin-market entry disclosure — the §13.2 re-disposition's build item.**
  - Target: pre-genesis

- **Solo address registry: decide (a registration tx type is genesis-only)**
  - Target: pre-genesis

- **Release verify: record-floor belt (the `ReinstateRecordFloorBroken` twin)**
  - Target: pre-genesis

- **RPC transport posture — RULED 2026-08-21; RT-W1 landed; RT-W2/W5/W7 authorized** (added 2026-08-21, `docs/design/RPC_TRANSPORT_POSTURE.md`).
  - Target: pre-genesis

- **Daemon Axum: onion-as-remote-RPC docs + operator story** (added 2026-07-10, epee HTTP listener deletion).
  - Target: pre-genesis

- **Daemon Axum: connection caps + live `rpc_connections_count`** (added 2026-07-10, **closed 2026-07-10**).
  - Target: pre-genesis

- **Rust wallet stack: no Windows support (blocks Windows wallet [`WINDOWS_WALLET_SUPPORT.md`](design/WINDOWS_WALLET_SUPPORT.md)**
  - Target: pre-genesis

- **Daemon RPC: restricted-method dual-list single-source** (added 2026-07-10).
  - Target: pre-genesis

- **Phase 4b: `rescan_blockchain` needs an Engine rescan API** — **CLOSED 2026-08-04 (Phase 4c, `feat/wallet-rpc-phase-4c-rescan`)**.
  - Target: pre-genesis

- **Phase 4c: no way to abandon an unconfirmed submitted transaction, so a never-mined tx can wedge `rescan`**
  - Target: pre-genesis

- **Phase 4b: `get_transfers` OUTGOING filter is a no-op until an outgoing history surface lands.**
  - Target: pre-genesis

- **Phase 4b: build concurrency permit stays 1 — raising it is a rule-21 reopen gated on anonymized segment fetch.**
  - Target: pre-genesis

- **GF4b-2 genesis gate — bond-post funding-input-count leak; `stake_in` single-structured-output funding must land before genesis.**
  - Target: pre-genesis

- **Block-height representation unification at the WI-2 anchoring seam** (surfaced 2026-07-11, WI-2 orchestrator review).
  - Target: pre-genesis

- **Alt-chain supply accumulation advances by the coinbase, not the emission subsidy.**
  - Target: pre-genesis

- **Should the genesis block header carry a real mint timestamp instead of 0?** Surfaced by C2-R3-Q2 ([`CONSENSUS_C2_R3_TIMESTAMPS.md`](completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §5.1): with `timestamp: 0` (`rust/shekyl-genesis-tool/src/builder.rs:181`) the genesis-padded MTP window admits `ts = 1` at block 1; a real mint timestamp would make the chain unable to start "before" its own genesis time for free under the ratified padding rule. A genesis-mint decision (geblock + the pinned block ids across all three networks), explicitly ruled out of C2-R3's scope at ratification (2026-09-01).
  - Target: pre-genesis (any regenesis window)

- **The pool admits duplicate archival unique-keys that only fail at connect.** Serve-credit `(P,s,E)`, bond-post-per-P, and emission `(P,E)` uniqueness are block-connect rules (`blockchain.cpp:6102–6261`), not `add_tx`. Two conflicting txs can sit in the mempool; a block that includes both is rejected. Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-G7 / CEN-G10 / CEN-G9 (were RC-113 / RC-123 / RC-130).
  - Target: pre-genesis

- **External cryptographic review of the `FcmpMembershipOnly` soundness [`completed/FCMP_MEMBERSHIP_ONLY.md`](./completed/FCMP_MEMBERSHIP_ONLY.md)**
  - Target: pre-genesis

- **Emission leg: verify reward→identity binding is structural, not [`design/ARCHIVAL_FIREWALL_GATE6.md`](./design/ARCHIVAL_FIREWALL_GATE6.md)**
  - Target: pre-genesis

- **FCMP++ circuit: confirm `incomplete_add_pub` need not constrain `c` [`completed/SHEKYL_OXIDE_UNVENDOR.md`](./completed/SHEKYL_OXIDE_UNVENDOR.md)**
  - Target: pre-genesis

- **Corpus-freeze guards: align `address_derivation_freeze` error message [`rust/shekyl-crypto-pq/src/archival_p_freeze.rs`](../rust/shekyl-crypto-pq/src/archival_p_freeze.rs)**
  - Target: pre-genesis

- **Block-height-only `unlock_time`: native `Timelock`, a pruned-safe context-free ingestion validator, and daemon-side enforcement (flagged 2026-06-23, `feat/scan-refresh-wire-migration`).**
  - Target: pre-genesis

- **Repo-wide `RingCT`/`rct`/`RCT` → `CT` semantic sweep — a Shekyl tx is simply a confidential transaction (flagged 2026-06-22).**
  - Target: pre-genesis

- **Store-backed / pruned-tree path assembly (CT-3 pre-flight F5, [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)**
  - Target: pre-genesis

- **C++ FCMP++ wallet send path is incomplete; 2026-06-21 debugging [`20-rust-vs-cpp-policy`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)**
  - Target: pre-genesis

- **`get_curve_tree_leaves` daemon endpoint + KAT (CT-3 R1-Q1 deferral [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)**
  - Target: pre-genesis

- **Rollback-adjacent frozen-`R_k` recheck on plain resume (CT-3c C1 disposition, 2026-06-12).**
  - Target: pre-genesis

- **Full all-segment frozen-`R_k` recheck (CT-3c bounded-check deferral, 2026-06-12).**
  - Target: pre-genesis

- **Refresh-over-spend reorg: optimistic-spend `spent_height` invariant + orphaned-spend un-mark (Track-2-surfaced + FIXED 2026-06-27).**
  - Target: pre-genesis

- **`AlreadyInChain` submit verdict: distinct lock-lifecycle disposition — DESIGN DECIDED 2026-07-04 (F40, `AlreadyInChain { height }`); interim implementation landed #252; F40 conformance LANDED 2026-07-05 (#254); targeted re-scan executor + F40-R2 breaker LANDED 2026-07-05 (`feat/submit-lifecycle-driver`) — RESOLVED.**
  - Target: pre-genesis

- **Watchdog probe bytes: ephemeral in-memory held-bytes store — reversion clause (rule 21), two independent axes, only one reopens.**
  - Target: pre-genesis

- **Submit-error reservation-id placeholder: split submitter error from orchestrator error (PR-4 / #248 review, deferred to 2c) — RESOLVED 2026-07-04 (2c pre-wiring).**
  - Target: pre-genesis

- **F41 constant-work-on-Conceal: invariant NAMED + enforcement DECOMPOSED (2c design round 2026-07-04, `DAEMON_SUBMIT_VERDICT.md` §3.1) — four implementation obligations open, and a hard ordering constraint.**
  - Target: pre-genesis

- **CT-2 Tier B reconstruct-root KATs (staked / non-coinbase maturity [`docs/completed/CT2_ROUND1_CLOSEOUT.md`](./completed/CT2_ROUND1_CLOSEOUT.md)**
  - Target: pre-genesis

- **CT-5 real-tree FCMP++ verify — deeper-tree + pin validation (depth-2 case [`docs/completed/DEPTH3_CURVE_TREE_CUTOVER.md`](completed/DEPTH3_CURVE_TREE_CUTOVER.md)**
  - Target: pre-genesis

- **Output-class numbering-equivalence re-verification (CT-5c X3 standing [`docs/completed/CT5C_ASSEMBLER_CUTOVER.md`](./completed/CT5C_ASSEMBLER_CUTOVER.md)**
  - Target: pre-genesis

- **CT-5d reselect: content-changing re-anchor (lock-transplant), tracked [`docs/completed/CT5D_REANCHOR.md`](./completed/CT5D_REANCHOR.md)**
  - Target: pre-genesis

- **CT-5d background opportunistic re-anchor + the eager reorg mark, tracked [`docs/completed/CT5D_REANCHOR.md`](./completed/CT5D_REANCHOR.md)**
  - Target: pre-genesis

- **CT-5d broadcast-but-unmined reference orphan, tracked 2026-06-18.** A send-path money-loss hazard; pre-genesis.
  - Target: pre-genesis

- **CT-5d re-confirm UX: handle accessor + `(fee, change)` delta on `ContentChanged`, tracked 2026-06-18.**
  - Target: pre-genesis

- **CT-5d: retire the vestigial `SnapshotId` / `SnapshotInvalidated` submit path, tracked 2026-06-18.**
  - Target: pre-genesis

- **Full-segment freeze + prune-retention KAT at production `j=2` leaf count [`docs/completed/CT1_ROUND1_CLOSEOUT.md`](./completed/CT1_ROUND1_CLOSEOUT.md)**
  - Target: pre-genesis

- **Wallet-local `O.x → position` match index (`CurveTreeClient` §4.3 scan [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)**
  - Target: pre-genesis

- **Anonymized (Tor/I2P) routing for non-forward segment fetch (CT Round 0 [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)**
  - Target: pre-genesis

- **Single-dispatcher nm gate: extend beyond `shekyld` (2026-06-11 single-image amendment).**
  - Target: pre-genesis


- **Gate-6 synchronized-exit wargame round (swan-2/W8, 2026-06-11).** A black [`design/F1_TA3_TA7_LIFETIME_WINDOW.md`](./design/F1_TA3_TA7_LIFETIME_WINDOW.md)
  - Target: pre-genesis

- **Foundation treasury diversification — floor capacity must not be pro-cyclical (swan-2/W4, 2026-06-11; re-scoped swan-3/W12–W13; re-anchored swan-4).**
  - Target: pre-genesis

- **Re-derive genesis-sealed redundancy params against the integer backend (+1 deep-tail margin) before seal (tail-margin finding, 2026-06-13).**
  - Target: pre-genesis

- **Funding-seam entry-standoff: consensus surface, wallet conformance, and the [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **Wallet bond-funding/standoff call site (tracks the `shekyl-standoff` importable surface; 2026-06-16).**
  - Target: pre-genesis

- **`shekyl-stats` `Z_ALPHA_1E6` provenance vs. the `enc_label` test's sensitivity need (separate question; 2026-06-16).**
  - Target: pre-genesis

- **Archival serve-credit / emission LMDB scans — bound the two unindexed table scans (own schema-round PR).**
  - Target: pre-genesis

- **Emission-path micro-efficiency cluster — address with C-1 wiring / the schema round (post-build tuning).**
  - Target: pre-genesis

- **Staker-archival settings are FROZEN; the remaining work is the operator experience, not [`docs/STAKER_OPERATOR_GUIDE.md`](STAKER_OPERATOR_GUIDE.md)**
  - Target: pre-genesis

- **Wallet-side archival bond-post construction (design + JoinMarket, PR 0-2a [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`](design/ARCHIVAL_BOND_CONSTRUCTION.md)**
  - Target: pre-genesis

- **StakeEngine Model D wiring — deferred work + rule-21 reopens (PR 2c-2a, [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **Archival bond request path — deferred items (PR 2c-2b, landed inert 2026-06-19).**
  - Target: pre-genesis

- **Genesis ceremony tooling: `generate-genesis-address` CLI (2026-06-11 derivation-freeze closeout).**
  - Target: pre-genesis

- **Stage 1 trait-extraction chain — closeout audit (2026-05-29, [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)**
  - Target: pre-genesis

- **Refresh bandwidth tradeoff under α — round-trip-bound block [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)**
  - Target: pre-genesis

- **F11-S Windows-midrange-PC measurement revisit at stressnet [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)**
  - Target: pre-genesis

- **Stage 1 PR 3 engine-property test re-location (trigger: the unified `KeyEngine` / `LedgerEngine` / `DaemonEngine` `pub(crate) → pub` visibility-promotion bundle per `STAGE_1_PR_3_KEY_ENGINE.md` §7.7; pre-RC1).**
  - Target: pre-genesis

- **`RecoveredWalletOutput.key_image`: promote to `Option<KeyImage>`.**
  - Target: pre-genesis

- **`shekyl-fcmp`: resolve `useless_conversion` clippy warnings in `frost_sal.rs`.**
  - Target: pre-genesis

- **Full migration of remaining `SHEKYL_*` FFI constants to the JSON-authority pattern (target: post-stressnet, pre-audit-final).**
  - Target: pre-genesis

- **`wallet_storage`: cover loaded-wallet save-as branches in `wallet2::store_to`.**
  - Target: pre-genesis

- **Stage 1 performance baseline measurement before Stage 1 PRs land.** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **`kameo` dependency pin and MSRV alignment before Stage 2 cuts.**
  - Target: pre-genesis

- **Revisit `rust/hard-coded-cryptographic-value` CodeQL suppression when the Rust extractor gains `cfg(test)` awareness.**
  - Target: pre-genesis

- **Stage 2 — `KeyEngine` migration to actor.** Migrate key material + [`STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)
  - Target: pre-genesis

- **Subaddress mechanism under PQC — dedicated design round (2026-05-31, [#112](https://github.com/Shekyl-Foundation/shekyl-core/pull/112)**
  - Target: pre-genesis

- **FA-6 — PQ-safe view-tag pre-filter (T6 closure, genesis).**
  - Target: pre-genesis

- **FA-6b — audit whether the multisig `0x09` view-tag hints are classically linkable (per-wallet-constant clustering without a view key) before the multisig receive path is production-load-bearing.** Separate from FA-6's account-path closure; spec pointer `FA-6_VIEW_TAG_ML_KEM.md` §3.2/§5.1, posture in [`FA-6_CLOSEOUT.md`](completed/FA-6_CLOSEOUT.md) §5. The tag is STAGED with the multisig receive path as producer ([`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) §1.1; PR #825) — this audit gates that producer, not the codec. *(Row body restored 2026-09-22; it had been truncated to its heading.)*
  - Target: pre-genesis
  - Owner: [`V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md) (FA-6b gate, R-A…R-F)

- **Phase 2a send path — engine substrate (closed 2026-06).** `LocalPendingTx`
  - Target: pre-genesis

- **Phase 2b planning session — stake state-machine shape (gate for [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)**
  - Target: pre-genesis

- **Stage 3 — `StakeEngine` native actor build.** Build the Phase
  - Target: pre-genesis

- **Consolidate hand-copied `10^9` / decimal-point constants onto the `shekyl-units` single source (spawned 2026-06-05 by the `AtomicUnits` interim PR).**
  - Target: pre-genesis

- **JSON-RPC large-amount precision — string-amount serde at the RPC edge (spawned 2026-06-05 by the `AtomicUnits` interim PR).**
  - Target: pre-genesis

- **Confidential stake-UTXO transfer (privacy-compatible; compounds (C)).** [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  - Target: pre-genesis

- **Stage 4 — Remaining-subsystem migrations.** Migrate
  - Target: pre-genesis

- **RPC boundary refinements — idle eviction, `engine_lock`, multi-engine registry, snapshot reads, multi-peer archival routing.**
  - Target: pre-genesis

- **`Hybrid*` secret types: `Vec<u8>` for fixed-size scalars — refactor to `[u8; N]` (sequencing trigger: Cluster 2 PR A lands `from_zeroizing` constructors; Lens D ml-dsa upstream API check informs idiomatic landing).**
  - Target: pre-genesis

- **`fips204` features-list discipline: drop `default-rng` and [`rust/shekyl-crypto-pq/Cargo.toml`](../rust/shekyl-crypto-pq/Cargo.toml)**
  - Target: pre-genesis

- **`epee::wipeable_string` mlock-backed allocator [`contrib/epee/include/wipeable_string.h:83`](../contrib/epee/include/wipeable_string.h)**
  - Target: pre-genesis

- **CryptoNote fossil — hardcoded key-image fixup for Monero blocks [`src/blockchain_db/blockchain_db.cpp`](../src/blockchain_db/blockchain_db.cpp)**
  - Target: pre-genesis

- **RandomX v2 SHA-256 digest of the 7-symbol `randomx.h` surface** beside `fork-pin-sha` in `randomx-v2-sys`. Reopen: pin-bump of `external/randomx-v2` or a tarball-CI need (checkout-hygiene conjunct fired in PR #754). [`RANDOMX_V2_PLAN.md`](./design/RANDOMX_V2_PLAN.md)
  - Target: pre-genesis

- **RandomX v2 algorithm-review gate (genesis release checklist)** — Monero production observation window **and** funded v1→v2 delta audit, both recorded with no `00-mission` #1 contraindication. YAML `algorithm-review-gate` stays pending until then. Fallback: `RANDOMX_V1_FALLBACK.md`, not an unpin. [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §1.4
  - Target: pre-genesis

- **RandomX v2 mining floor-vs-ceiling asymmetry — Phases 1–3 parked after Phase 0.** Falsify parked status by Appendix B from a source-verified run. The never-link claim is the §7.1 10-symbol C-ABI list (isolation check 1), not “any miner code under any name.” [`RANDOMX_V2_MINING_ASYMMETRY.md`](./design/RANDOMX_V2_MINING_ASYMMETRY.md)
  - Target: pre-genesis

- **Miner template conformance vector (bless the interface, not a miner).** Publish a versioned `get_block_template` → blob framing → `submitblock` + seed-epoch vector before genesis seal. Falsify by a third-party miner passing it against `dev`. [`RANDOMX_V2_MINING_ASYMMETRY.md`](./design/RANDOMX_V2_MINING_ASYMMETRY.md) §6.3
  - Target: pre-genesis

- **PoW test seam and isolation checks 3/4/6 across the daemon Rust cutover.** Owner: the PR that moves `src/crypto/pow_randomx.{h,cpp}`. Falsify by that PR recording the seam disposition and re-deriving checks 3/4/6 against the new binary. [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §7
  - Target: pre-genesis

- **`rust/shekyl-consensus` fold** — six live Cargo consumers; DRS-E* is not the round that removes them. Falsify by `rg -l 'shekyl-consensus' rust/*/Cargo.toml` returning only the crate itself.
  - Target: pre-genesis

- **Promote 2c-emergent sub-PR design disciplines to project-level [`.cursor/rules/26-sub-pr-design-discipline.mdc`](../.cursor/rules/26-sub-pr-design-discipline.mdc)**
  - Target: pre-genesis

- **CL-7 forward-compat audit of trait-owned value/error types [`engine/error/send.rs`](../rust/shekyl-engine-core/src/engine/error/send.rs)**
  - Target: pre-genesis

- **`shekyl-tx-builder::SpendInput` derives plain `#[derive(Debug)]` over [`rust/shekyl-tx-builder/src/types.rs`](../rust/shekyl-tx-builder/src/types.rs)**
  - Target: pre-genesis

- **Migrate residual consensus-parity Keccak (`keccak256`) call sites to cSHAKE256 / [`shekyl_crypto_hash::keccak256`](../rust/shekyl-crypto-hash/src/lib.rs)**
  - Target: pre-genesis

- **Multisig FROST spend path needs the single-sig spend-path consensus fixes.**
  - Target: pre-genesis

- **Serve-credit C++ consensus decisions — Rust equivalence audit + [`REWARD_EMISSION_E3_GATING_ROUND.md`](./completed/REWARD_EMISSION_E3_GATING_ROUND.md)**
  - Target: pre-genesis

- **Market-bond wallet entry — `first_stake`'s genesis posture cannot earn an emission.**
  - Target: pre-genesis

- **Shard assignment for market staking — the `NoShardsAvailable` stub's discharge.**
  - Target: pre-genesis

- **F5 pruning inherits two constraints from the CompleteTree round** (recorded 2026-08-16; `COMPLETETREE_ACTIVATION.md` §10 item 2).
  - Target: pre-genesis

- **The wallet-RPC server parses every request into a `serde_json::Value`**
  - Target: pre-genesis

- **Q11 balance-exclusion KAT — blob-boundary invariant arm** [`EMISSION_CLAIM_BUILDER.md`](./design/EMISSION_CLAIM_BUILDER.md)
  - Target: pre-genesis

- **Single-sig address decode enforces the Bech32m variant** [`rust/shekyl-address/src/address.rs`](../rust/shekyl-address/src/address.rs)
  - Target: pre-genesis

- **Credit-wire cutover has two preconditions the Phase-2 verify cannot satisfy [`cryptonote_core.cpp`](../src/cryptonote_core/cryptonote_core.cpp)**
  - Target: pre-genesis

- **Raw-import archival/burn bookkeeping parity** (surfaced 2026-07-09,
  - Target: pre-genesis

- **Serve-credit decision-site flip: Rust becomes the primary decision site for `blockchain.cpp:4247`/`:4312`/`:4889–4910`**
  - Target: pre-genesis

- **`tests/performance_tests/` — rule-15 deletion-or-adoption audit** (surfaced 2026-07-03, RandomX v2 test-regime benchmark review).
  - Target: pre-genesis

- **Remove or retain the orphaned `ActivityMetric.total_staked` observable (spawned Stage-1b `stake_factor` delete, commit `7256962`, 2026-07-24).**
  - Target: pre-genesis

- **Wallet file backup-exclusion markers (PR 6 lessons canvass §5.12 F1).** [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](./completed/STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
  - Target: pre-genesis

- **Process core-dump disable at wallet-RPC startup (PR 6 §5.12 F2).**
  - Target: pre-genesis

- **Argon2 stack-resident secret copies — cryptographer review (PR 6 §5.12 F3).**
  - Target: pre-genesis

- **Async `Engine::close` / `change_password` lifecycle (PR 6 PR #83).** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **RandomX v2 — Guix reproducible-build obligation pickup (trigger: Guix integration design pass lands).** (trigger: the first Guix-built `shekyld` that vendors `external/randomx-v2`; the daemon Rust rewrite does not substitute for it) [`docs/design/RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §22
  - Target: pre-genesis

- **Rules-queue: reconcile the priority-ordering statements across [`00-mission.mdc`](../.cursor/rules/00-mission.mdc)**
  - Target: pre-genesis

- **Rules-queue: elevate per-gate reviewer-discipline calibration [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md)**
  - Target: pre-genesis

- **Rules-queue: elevate the public-material typed-wrapper exclusion [`docs/completed/STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)**
  - Target: pre-genesis

- **Rules-queue: elevate the plan-vs-state-divergence pattern into a [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **Rules-queue: encode the rule-15 trinary reading [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **Rules-queue: consolidate the rules-queue itself into 1–2 PRs.** [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./completed/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  - Target: pre-genesis

- **Rules-queue: encode the pre-flight-FOLLOWUP-scope discipline.** [`docs/completed/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./completed/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md)
  - Target: pre-genesis

- **Non-`Clone` ban on `TransferDetails` — post-M3d structural [`docs/completed/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./completed/STAGE_1_PR_3_M3D_PREFLIGHT.md)**
  - Target: pre-genesis

- **`fips203` interior `into_bytes()` Copy on the ML-KEM-768 decap-key [`docs/completed/STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)**
  - Target: pre-genesis

- **`derive_output_handle` Python reference script.** Stage 1 PR 3
  - Target: pre-genesis

- **`Engine::ledger()` accessor cleanup.** Stage 1 PR 2 (commit [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  - Target: pre-genesis

- **PQC Multisig : Rust engine integration design (carrier).** [`docs/design/V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md)
  - Target: pre-genesis

- **PQC Multisig wire: MSW-1…MSW-8 (pre-genesis, priority 1).**
  - Target: pre-genesis

- **Term hygiene: "rotation" is a §11.8 defect on a noun — rename to "activation" (read-per-site, NOT grep-and-replace).**
  - Target: pre-genesis

- **PQC Multisig: MSW-6 landing residue.** The scheme_id relaxation landed subtractively; five items it deliberately did not fold in (each named blocker + target, rule 22 clause 3):
  - Target: pre-genesis
  - **Cross-model co-spend is a BLOCKING E′ ship gate, not a soft item** — MSW-6 removed the consensus refusal of a solo+multisig co-spend on no-externality grounds; correct only if the spend-time binding holds.
  - **`cryptonote_tx_utils.cpp:670` — MSW-6 broke this** (the scheme-id check the relaxation left behind); see the row's history for the site.
  - **`MultisigKeyContainer` is one type over two populations — S2-blocking.**
  - **`tx_extra` tag `0x05` — reserve-vs-free decision.** RULED 2026-09-22 (PR #825): REJECTED, the tag is deleted and the byte retired.
  - **Structural pqc-auth verify → Rust port slice** (the C++ structural check moves behind the FFI).
  - **C-2 (the P0-n gate is a literal denylist).**

- **PQC Multisig : Option-D residue left standing after the F-6**
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

- **PQC Multisig : wire `shekyl_pqc_verify_with_group_id` into [`V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md)**
  - Target: pre-genesis

- **Test-deviation register: every deviation from production configuration is a named row with a reason and a reopening criterion, and the set is gated** (program principle ruled 2026-09-19 on E6 slice 2; owner **the DRS program** — E2's comparator is where "what did this test prove" is judged). Four instances share the shape *the condition that would expose the defect cannot occur in the test*: W12 (`BaseTestDB` overrides 0 of 15 archival hooks, tests green), CEN-I12 / SOK-10 (the e2e's `[0]` on a coinbase-only mine, position ≡ index), the `curve_tree_roots` zero-root regime (permanent below ~160 blocks on FAKECHAIN, self-healing on a real chain). Unavoidable deviations exist (a 10 000-block settlement epoch, a 25 992-leaf freeze), so the form is a register — `docs/design/TEST_DEVIATION_REGISTER.md` + `scripts/ci/check_test_deviations.py`, the `RUST_ONLY_TABLES` / `held_by_cxx` shape — not a ban. First rows named in [`CHAIN_RULES_SLICE_2.md`](completed/CHAIN_RULES_SLICE_2.md) §6 F12 and §4.5 (`drs_bench.py`: real RandomX at a non-production target — a partial with one real half; `curve_tree_header_root_check.cpp`: difficulty 1 as a locus; `--fixed-difficulty=1` at every harness; `SEEDHASH_EPOCH_*`; `SHEKYL_SETTLEMENT_EPOCH_BLOCKS`). Falsifier that **fires** rather than waits: a program-level register proposed from inside a slice is the kind of item that stays proposed, so the trigger is an event that will happen — **the first DRS-E2 pre-flight opened after 2026-09-19 must either carry a test-deviation section for its comparator harness (the register's first live consumer) or reject this row with reasoning — FIRED GREEN 2026-09-19: PR #788's `docs/design/DRS_E2_REPLAY_DRIVER.md` §5 carries four rows in the register's shape and names itself the register's first import.** Next trigger: the register exists before DRS-E2's commit 7 (grading) lands, or that commit rejects this row with reasoning. Closure: `ls docs/design/TEST_DEVIATION_REGISTER.md && python3 scripts/ci/check_test_deviations.py --selftest` succeeding.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) §5 — the register's first live section and its first import

- **CEN-D7's `Fakechain` witness: `shekyl_address::Network` has no variant, so `RuleSet::fakechain` is bound to `--regtest` by the driver's discipline, not by type** (E6 slice 2 F10 / Q10, 2026-09-19). The **wiring** half closed 2026-09-20 (DRS-E2 §7 commit 6b: `shekyl-chain-ingest::schedule::ChainRules` is the production caller, refusing the flag off regtest by construction — the 2301-block regtest replay ran under `fakechain(1)`). Still owed: the **witness** — adding the variant ripples ~12 files in 9 crates and is its own change; until then `Chain::Regtest` in the driver is the stand-in. Falsify by `rg 'Fakechain' rust/shekyl-address/src/network.rs` returning a variant and `RuleSet::fakechain` taking it. Record: [`CHAIN_RULES_SLICE_2.md`](completed/CHAIN_RULES_SLICE_2.md) §4.5.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) RD-Q7 — the witness is the reopening event for its "(a witness) when the variant exists" clause

- **LWMA-1 can derive a zero next-block difficulty from a conforming chain, and CEN-D6 then refuses every successor — a chain-death mode with no floor** (DRS-E2 RD-F17, 2026-09-20). `lwma1_next`'s tail `avg_D · 99·N·(N+1)·T / 200·L` has no floor (`lwma1.rs:176`–`:206`); with every solvetime at the `+6T` clamp it is zero for `avg_D ≤ 6`, and `400 → 66` per maximally slow window, so a live chain under sustained slow blocks walks to zero. The census CEN-D6 row assumed zero was reachable only via a sentinel; amended. Both implementations halt there — the C++ refuses the block (`blockchain.cpp:5494`), the Rust returns the CEN-D6 verdict — so parity holds and the question is the *rule*: does CEN-D6 become a floor of 1 (a consensus change to the ratified algorithm, `docs/completed/DAA_LWMA1.md` §5.3, requiring its own ruling and vectors), or stay a refusal with the death mode accepted and documented? Not the E2 lane's to rule. Falsify by `cen_d6_a_slow_window_of_minimal_work_derives_zero_and_refuses_the_block` (`rules/difficulty_tests.rs`) no longer reaching the refusal — i.e. `lwma1_next` returning non-zero over that window.
  - Target: pre-genesis
  - Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-D6 — the census document that holds the rule; the DAA owner rules through it

- **CEN-F17's row waits on the curve tree's writer, not its reader.** Its operand `n = frozen_segment_count(leaf_count at parent state)` reads a tree S-CURVE (DRS-E1 increment 7) gave a typed read for (`ReadSnapshot::curve_tree()`) but DRS-E3 has not yet written: the summary row is the seal's `EMPTY` on every replayed chain, so a `ChainView` method fed from it would return `0` — a real read of a table nothing writes, the passed-through-fact shape E6 slice 4 Q1 (c) rejected. The *function* (`shekyl-economics::compute_fee_burn`) is Rust and fixtured since the slice-4 precursor; only the operand is owed. Falsify by: `curve_tree().leaf_count > 0` after replaying a chain with at least one output — the day that holds, `ChainView` gains the read and F17 lands with a fixture over a supplied count (`CHAIN_RULES_SLICE_4.md` §3.2, §6).
  - Target: pre-genesis
  - Owner: [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) — DRS-E3 (curve storage); the row and its rule are [`CHAIN_RULES_SLICE_4.md`](design/CHAIN_RULES_SLICE_4.md)'s
- **Capture the BP+ core_tests vectors as committed data in the same TXE commit that deletes the tests.** `feat/tx-extra-rust-cutover` deletes `tests/core_tests/bulletproof_plus.{cpp,h}` with the C++ transaction builder (`TX_EXTRA_RUST_CUTOVER.md` TXE-Q1). Those tests were the C++-side oracle CEN-H19's range-proof cutover KAT would have used when `shekyl-bulletproofs` becomes the daemon's verifier of record (E6 slice 6, per slice 5 Q3 (b)). Capturing the proofs and their verdicts as data — valid and mutated-invalid — before the deletion is cheap and reversible, and removes the coupling between a crypto cutover's evidence and a codec lane's schedule; BP+ also has standard vectors independent of this tree, so the capture is a convenience, not the only oracle. Falsify by: a committed vector file under `rust/shekyl-bulletproofs/tests/vectors/` (or the TXE lane's named home) present at TXE's merge, or TXE's deletion commit stating the standard vectors it points slice 6 at instead.
  - Target: pre-genesis
  - Owner: [`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) — the TXE lane's deletion commit; the consumer is [`CHAIN_RULES_SLICE_5.md`](design/CHAIN_RULES_SLICE_5.md) Q3 / slice 6's H19 cutover

- **Every crate that constructs block or transaction fixtures owns a sanity gate against `validate` at current coverage; today one of three does.** `shekyl-chain-rules` gained `fixture_sanity_tests` (E6 slice 5, 2026-09-23) after CEN-H5 refused three of the crate's own fixtures: the gate walks the closed `TxShape` enum and judges every well-formed shape at every slot it names, so a bad fixture fails when written and a new shape without a gate arm does not compile. `shekyl-chain-store` and `shekyl-chain-ingest` build their own fixtures (`connect_fixtures.rs`, `test_support.rs`) and rely on their connect tests as a de facto gate — which caught a fourth illegal fixture the same hour, but only because the rule that landed happened to touch a test that validates; a fixture used only by a test that does not validate is invisible to it. The asymmetry is known, not discovered. **Preferred end state: delegation** — the store's and ingest's fixtures built from `shekyl_chain_rules::harness::fixture`'s shapes (the coinbase already is), so "valid" is defined once, gated once, and the three crates' fixtures cannot drift into impossibility independently; a private gate in each crate over a private vocabulary is the fallback for what genuinely cannot delegate, and three gates over three vocabularies is the version that reproduces this problem twice more. Falsify by: every `Transaction`-constructing fixture in `rust/shekyl-chain-store` and `rust/shekyl-chain-ingest` calling into `harness::fixture` (grep the two `test_support` / `connect_fixtures` files for `TxPrefix {` literals → zero), or, for a shape that cannot delegate, a `fixture_sanity` module beside it.
  - Target: pre-genesis
  - Owner: [`CHAIN_RULES_CRATE.md`](design/CHAIN_RULES_CRATE.md) — the harness contract (§8); the slice that lands the next rule touching those fixtures carries it, [`CHAIN_RULES_SLICE_5.md`](design/CHAIN_RULES_SLICE_5.md) commit 5 first

- **`shekyl_wire::Transaction` conflates a wire transaction with a pruned node's skeleton; give the two constructors, so a skeleton is unbuildable by accident.** Found by E6 slice 5's H19 layout rule (2026-09-23): every spend fixture in three crates was `Ct::Fcmp { pqc_auths: [], prunable: None }` — the storage-pruned form, whose txid `hash_from_components` (`txid.rs:257`) builds three-part with a zero-mix prunable slot (`txid_parts` `:79–84`) — and every layer accepted it: the codec must (both fields have legitimate empty states for storage and relay), the hasher takes the three-part branch, and the value parses, hashes, round-trips and cannot exist on the wire. The discriminator between "no prunable region" and "the prunable region was discarded" is whether two optional fields happen to be populated — the absence-as-value class at the type level, one layer up from `hash_init` meaning both empty-tree and missing-key. `txid_parts`' own doc (`:72–74`) warns against *reading* a skeleton as a 4-part txid; the fixtures hit the trap by *writing* one, a direction a comment cannot cover. The structural fix, the `RawBlockBytes` / `ChainValid` / `SegmentAvailability` move: `Transaction::full(prefix, base, auths, prunable)` requiring per-input auths and a prunable region, `Transaction::pruned(prefix, base, retained_component_hashes)` taking the discarded regions' hashes explicitly; parsing still yields both (it has to), but nothing constructs a skeleton without naming it. Falsify by: `Transaction {` struct literals outside `shekyl-wire`'s own parser and tests → zero, or the struct's fields private with the two constructors the only way in. TXE landed on `dev` at `50256487f` (2026-09-23); this is the wire lane's design item now, not a slice-5 edit. **First measured consequence (slice 5 commit 8, 2026-09-23):** of the wire twin's 59 refusal arms, **two** (`fee-only ct (no prunable) must have no outputs` / `… must carry empty pqc_auths`) are reachable **only** by a value the C++ cannot hold — a `prunable: None` non-serve-credit — and the crate refuses those same values on CEN-H21 for a different reason; a third arm in the same match is dead by ordering. Two consensus refusal arms guarding a value that cannot exist on the wire is evidence for the constructors, not reasoning (`CHAIN_RULES_SLICE_5.md` §3.1.1). **Second measured consequence (#839 review, 2026-09-23):** the validator's CEN-H23 `by_construction` entry holds that *bytes* cannot reach the rules unparsed; it cannot hold that the value *was* parsed, because the struct is freely constructible — and a hand-built `BondPostKind::Other(BOND_POST_KIND_JOINMARKET)` (the writer's `:666` refusal) makes `serialize()` / `serialized_len()` `.expect` and **panic** inside `tx_form`'s H1. No production caller hand-builds (ingest and pool parse bytes), so the path is test-only today; the parsed-witness constructor is what makes it unrepresentable, and `BondPostKind::Other(u8)` admitting the JoinMarket tag is the same absence-as-value class one level down.
  - Target: pre-genesis
  - Owner: [`GENESIS_TX_WIRE_FORMAT.md`](design/GENESIS_TX_WIRE_FORMAT.md) — §4 (the typed-view boundary, `into_full` / `FullTransaction`) is where the pruned/full distinction is already specified as a *conversion*; this makes it a *construction*. Consumer: [`CHAIN_RULES_SLICE_5.md`](design/CHAIN_RULES_SLICE_5.md) §5 row 4

- **The view-bound rows of slices 2–4 are fixtured against `MockChain` serving computed state, which `50-testing.mdc` now names a false test; audit which have an ingest-side replay witness and give the rest one.** Slice 6's review (2026-09-24) established that a mock *told* a root, a depth or a spent set and *serving* it to the rule proves only that the rule reads what it was handed — none of the evidence about production behaviour a green check implies. Slice 6 fixtures its own view-bound rows (I7, I10–I13, I15, I17, I18, H19-verify) through the ingest replay of captured blocks (`CHAIN_RULES_SLICE_6.md` §5.2). The same shape already exists for the earlier view-bound rows — CEN-D1/D4/D6 over `MockChain` windows, CEN-B5 over a pushed root, CEN-E1 over anchors, CEN-A2/C1/C2 over pushed tips — and `shekyl-chain-ingest`'s pipeline tests replay *some* of those paths against a real store, not all. Enumerate every `implemented` view-bound row, name its ingest-side witness or its absence, and land the missing witnesses as mutations of captured blocks. `MockChain` keeps the two jobs its charter allows (predicate logic on plain values; the faulting view). **The witness is a SCENARIO, not a replay (slice 6 §5.3, ruled 2026-09-24):** the store's and ingest's ~fifty tests that run `validate` over a filler spend migrate to the scenario driver — `mine(n)`, `spend(shape)`, `reorg(depth)` over the production stack (`shekyl-block-template`, `shekyl-tx-builder`, `validate`, `connect`), facts composed from their owners — not to a replayed corpus; the frozen corpora stay for the cases where a specific historical chain is the subject. Owned by the store and ingest lanes; the driver is this row's dependency and E6 slice 6 lands it. Falsify by: a table in `CHAIN_RULES_CRATE.md` §8 with one row per view-bound census row and the scenario test that is its witness, no cell empty.
  - Target: pre-genesis
  - Owner: [`CHAIN_RULES_CRATE.md`](design/CHAIN_RULES_CRATE.md) §8 — the test-plan contract; the instance and the charter are [`CHAIN_RULES_SLICE_6.md`](design/CHAIN_RULES_SLICE_6.md) §5.2

- **The census enumerated the C++ consensus files and walked to the Rust verdict bodies; the shim layer between them was not a subject, and it held rule content.** E6 slice 4's sweep (`CHAIN_RULES_SLICE_4.md` §3.1, 2026-09-21) read `src/shekyl/economics.h` and the C++ sides of `ct_balance_ffi.rs` under R8's discriminator (*would this survive a rule change?*) and found five rule-bearing sites the census never cited — zero-fee and zero-emission arms that decided outcomes before any Rust ran, two Rust-call compositions, and the `CTTypeNull` selection of the coinbase fingerprint gate — plus an uncensused arity clause (`outPk.size() != vout.size()`) that `blockchain_db.cpp:573` cites as the ground for **CEN-L11's** unreachable grading, and one consensus constant with no Rust home. §3.4's FFI scope table records `shekyl-economics` as "interior enumerated: **yes**"; the walk stopped at the Rust body and crossed the shim without reading it (`economics.h` appears nowhere in the census). All six are relocated by the slice-4 precursor. **What remains is the generalisation:** there are 286 FFI exports with C++ sides, and `src/shekyl/{relay_floor_ring,shekyl_daemon_fetch}.h` are unswept (`tx_volume_window.h` is cited by CEN-F20 only because FL-R24 rewrote that row). If the shim layer was not a subject of the enumeration, the 153 denominator measures against an incomplete set. **Second instance (E6 slice 5 commit 8, 2026-09-23), a different shim, the same shape:** enumerating `shekyl-wire/src/transaction.rs`'s 59 refusal arms for the Q1 conformance test found two consensus-adjacent limits with no census row — the holdings shard-set bound (`MAX_HOLDINGS_SHARDS` 4 096 + duplicate-freeness, `ShardSet::new` in `bond_wire.rs`, which the wire's own doc calls a *consensus bound*) and `PQC_MAX_SIGNATURE_BLOB` (CEN-I16 names the key blob's cap, nothing names the signature's). Both were classified **parse** rather than keyed to the nearest J/I row (`CHAIN_RULES_SLICE_5.md` §3.1.1); slice 4's S25 arity gate was the first instance and turned out to ground CEN-L11's grading. Two instances, both found by enumerating something for another reason. **The question for the census lane, now with two grounds:** did the sweep cover `shekyl-wire`'s constants at all — the same question the shim sweep raised about `src/shekyl/*.h`, unanswered. **And a second, separate ask for the same owner (2026-09-23, #839):** the census sits outside `check_doc_code_citations.py`'s checked set — now in its `DEFERRED_DOCS` with the blocker named (21 doc-side resolution failures at `d8ebfd18c`: fourteen ambiguous bare basenames, one deleted file, one undated records-was pin). Twenty of the twenty-four §4.H site cells were stale at `d8ebfd18c`, several exactly one deletion behind — correct at their era and wrong now, the shape that hides best — and the drift cost slice 5 two retractions in one session. Those cells now carry the `symbol` + `file:range` form the gate resolves. **The citation half is DISCHARGED 2026-09-24 (`chore/census-citations-resolve`):** the fourteen basenames qualified from the rows that cite them, the two records-was pins dated at the deleting commit's parent (`ac5bad744`; `is_valid_decomposed_amount` had moved `:1547 → :1588` before it was deleted), the `tx_extra.rs → tx_extra/coinbase.rs` module split re-homed, the slice-5 cells' `d8ebfd18c` eras moved to `4dc5194de` (the merge that landed their files), §7 item 21's era written in the parsed form — 140 census citations resolve at their declared eras and the document is in `DEFAULT_DOCS`. What remains of this row is the shim-sweep question below, unchanged. **Third instance (E6 slice 6 §5.4, 2026-09-24), a prover crate rather than a wire crate, found while measuring something else:** `shekyl_fcmp::MAX_INPUTS = 8` at `proof.rs`'s prove and verify entry points carries the same inherited figure as CEN-I4's `FCMP_MAX_INPUTS_PER_TX`. If the consensus rule moves or is deleted and the prover's constant does not, the prover refuses at eight and **becomes the cap by accident — a consensus rule enforced by a library constant nobody ratified**, invisible to every instrument the program has: not in the census, not in the register, read by no gate (`shekyl-tx-builder` const-asserts the two equal today, so the parting cannot be silent; the question of *which* constants remains). That is a fourth ground for the same question, on a fourth axis: file subject, call direction, reads-versus-writes — and now *which library-crate constants does a consensus rule's value depend on*. Two such constants are known (`READ_LEN_CAP` in the wire, `MAX_INPUTS` in the prover); nothing says they are the only two (a fourth instance surfaced 2026-09-25 and is filed on its own row below as the other half of `TXE-Q6′`, because it is a ruling's open half rather than a constants instance). Falsify by: the census stating, in §3.4 or a new subsection, which shim files and which Rust wire constants were read and under which discriminator; each `src/shekyl/*.h` and each `pub const` bound in `shekyl-wire/src/transaction.rs` either cited by a row or recorded as transport/marshaling-only; **and, for each implemented row whose value is a constant, the library-crate constants that would refuse the same shape independently, each named beside the row or recorded as none.**
  - Target: pre-genesis
  - Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §3.4 — the census lane; the discriminator and the first sweep are [`CHAIN_RULES_SLICE_4.md`](design/CHAIN_RULES_SLICE_4.md) §3.1's

- **The other half of `TXE-Q6′`: a listed transaction's `tx_extra` has no closed grammar, so `0x09`/`0x0A`/`0x0B` blobs ride to the tx size limit with no consensus bound below CEN-H1.** `TXE-Q6′` ([`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) §6, RULED 2026-09-23) closed the coinbase's extra as a whitelist — `[0x01, 0x02(8), 0x06, 0x07]` and nothing else — for one stated reason: *bounding one tag while the rest stayed admissible would bound the door somebody noticed*. Off the coinbase the same door is open. CEN-I19 shapes the two PQC fields and bans the nonce; the staged `0x09` view-tag-hints, `0x0A` spend-auth-pubkeys and `0x0B` attestation tags parse on any transaction to the parser's `READ_LEN_CAP` (1 MB), producerless today, so a spend can carry arbitrary bytes up to CEN-H1's size limit and CEN-M4's relay cap is policy. Found 2026-09-25 re-cutting the M4 conformance trip (E6 slice 6 commit 3): the trip has to carry exactly such a blob to reach the twin's cap arm through I19. The fix already exists in shape — the ruling's whitelist generalised to the non-coinbase grammar, which is smaller (`[0x06, 0x07]` iff outputs, nothing else; `0x0B` when its producer amends the row, on whichever class it names) — which makes this a census question with a consensus answer, not a fresh design round. Cite `TXE-Q6′` from the I19 and I20 census cells when it lands so the two halves read as one ruling (commit 10 of the slice does this for the nonce clause). Falsify by: `check_tx_extra_shape(General)` refusing any tag outside the whitelist, with CEN-I19's census cell stating the grammar and the conformance trip `m4_extra_over_the_relay_cap` no longer constructible as a consensus-admissible transaction.
  - Target: pre-genesis
  - Owner: [`TX_EXTRA_RUST_CUTOVER.md`](design/TX_EXTRA_RUST_CUTOVER.md) §6 — the ruling this is the other half of

- **CEN-I13 over the tree depth at `ref_height` — E6 slice 6's one named successor, blocked on E3 S-CURVE's height-keyed depth read.** The C++ reads the *current* depth (`get_curve_tree_depth()`, `blockchain.cpp:4162`); slice 6 ruled (Q8, 2026-09-24) the operand is the depth **at** `ref_height`, keyed as `curve_tree_roots[h]` is, because current depth is correct only under three dependencies one of which is an ordering argument — a class wrong twice that month. The store holds no per-height depth; E3, the curve-tree grow path, has not begun, and the read is asked of it in [`DRS_E1_SCURVE.md`](design/DRS_E1_SCURVE.md) §2.3 (*What E3 is asked for*). The fallback ordering, ruled 2026-09-25: if E3 can serve it, take it; if E3 won't, current-depth with all three `CHAIN_RULES_SLICE_6.md` §3.3 dependencies written **at the rule**, the ordering one pinned by a test that fails when I13 runs before I10 (available since commit 5 landed I10); if E3 has not got to it — this case — wait. **Blocked — falsify by `rg 'fn depth_at' rust/shekyl-chain-rules/src/view.rs`** → the trait method present with `BatchView`'s impl; then I13 lands as one commit in `rules/tx_against.rs` (the D4 arrangement beside I10–I12) and this row closes.
  - Target: pre-genesis
  - Owner: [`DRS_E1_SCURVE.md`](design/DRS_E1_SCURVE.md) §2.3 — the E3 boundary statement; the deferral record is [`CHAIN_RULES_SLICE_6.md`](design/CHAIN_RULES_SLICE_6.md) §5 row 6

- **CEN-I15 (the FCMP++ proof verifies over I12's anchor) and CEN-H19's verification half (the block's BP+ proofs) — E6 slice 6's two remaining 4.I verification rows, blocked on the scenario driver being able to produce a spend.** Both rows verify a proof, and a proof is valid only against the tree it was made in: no constructed fixture can pass I15 (slice 6 §5.3 — a loader, a replay, a knob and waiting were all refused with the premise), and the four captured chains carry at most one non-coinbase transaction per block (measured 2026-09-25 over `corpus.e2`: heights 71/98, 71/98/109/1025, 81, 761 — one each), so Q9's condition for landing H19-verify as a `validate` fold in this slice is false. The witness both rows wait for is the same object: `Scenario` (`shekyl-chain-ingest/src/scenario.rs`) mining a block that lists a spend built by `shekyl-tx-builder` against a tree the store grew — which today it cannot, because `root_after` is `placeholder_root_after` (*"S-CURVE grows the tree"*, E3). Then I15 lands as one commit in `judge_reference` beside I12 (`shekyl_fcmp::proof::verify` over the proof, the `ToKey` key images, the pseudo-outs, `PqcKeyScalar::from_pqc_public_key` per auth, I12's anchor, `tree_depth + 1` layers, the prefix hash — `blockchain.cpp:4180–4242`; the dependency `shekyl-fcmp`, as daemon-rpc's K12 takes it), I12's staged anchor gains its consumer, and H19-verify lands as the fold over a driven block listing two spends, with the one-bad-proof-among-good fixture. **Blocked — falsify by `rg placeholder_root_after rust/shekyl-chain-ingest/src/scenario.rs`** returning nothing, and a `scenario_tests` test in which `mine_listing` admits a tx-builder spend under `validate`. Not blocked on I13: I15's depth operand is the transaction's own `tree_depth + 1` (`:4220`), which I13 bounds and I15 consumes.
  - Target: pre-genesis
  - Owner: [`CHAIN_RULES_SLICE_6.md`](design/CHAIN_RULES_SLICE_6.md) §5 row 8 — the deferral record; the blocker's owner is the S-CURVE lane ([`DRS_E1_SCURVE.md`](design/DRS_E1_SCURVE.md)), whose tree the driver's spends need

- **CEN-J17's dropped-shard derivation lives in the C++ marshal; in the Rust verifier it belongs inside the verify.** The bond-post drop arm derives the dropped shard by a set-difference in `blockchain.cpp` (`:5065–5078` at the register's pin) and hands the result to the Rust verify, which re-validates shape — operand logic outside the verifier that judges it. Found by the conformance register (`CONSENSUS_STORE_RECONCILIATION.md` CEN-J17), which carried the instruction as a REWRITE-NOTE with no plan home until 2026-09-26; the register now records the fact and this row owns the work. Falsify by: the Rust drop-arm verify taking the pre-state and post-state and deriving the dropped shard itself, the C++ set-difference deleted.
  - Target: pre-genesis
  - Owner: [`ARCHIVAL_BOND_GATE4.md`](design/ARCHIVAL_BOND_GATE4.md) — the drop arm's contract (§ on the post-state the vin carries)

- **A plan row blocked on a named artifact that is COMPLETE should go red — the `DEFERRED_DOCS` self-expiry applied to plan-row blockers.** `DAEMON_REDB_STORE.md` §5's S-ARCH row read "gated on the P0b journal audit" for eighteen days after P0b was RECONCILED (2026-09-05 → read 2026-09-23, `DRS_E1_SARCH.md` §0); rule 22's "a condition that has expired and a condition that is still pending read identically" has now happened four times over in the tree. The precondition for a gate is that blockers cite **rows, not prose** — measured 2026-09-23 over table rows in `docs/design/*.md` matching *gated on / blocked on / waits on*: **119 blockers, 45 name an identifier token a gate could resolve (`P0b`, `PDM-Q3`, `#NNN`, `SI-n`, a family token), 74 name prose** (heuristic scan; `IMPLEMENTATION_INDEX.md` alone holds 20 / 31). So today it is mostly a wish: the gate exists once blockers are written in rule 22's own form — *"blocked on `<ID>` — falsify by `<check>`"* — and the first cut is a phrasing lint on new rows, not a resolver over old ones. Falsify by: a gate that, given a row whose blocker names an index / census / FOLLOWUPS identifier with a status cell, fails when that status is LANDED / RECONCILED / RULED and the row still says blocked; run on the four known instances, it names all four.
  - Target: pre-genesis
  - Owner: [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) §5 — the surface table whose blocker cells are the first population; the lint's home is `scripts/ci/` beside `check_landed_rows_stamped.py`

- **`check_chain_rules_coverage.py` should hold `CHAIN_RULES_CRATE.md`'s figure line as a snapshot and fail when the doc's number is not what it measured — the paired-bump check's shape applied to a figure.** The gate already parses the census and the registry to derive `implemented / validator-enforced / … / enforced` and `ratified / enforced`; the document then repeats those numbers in prose, and nothing checks the pair. Every stale figure this month landed the same way — a number in prose that nothing read: the DRS doc's "46", §9.1's "twenty-seven", FL-R16c's pins losing a ruling, the CEN-D4 three-way, and S-ARCH's `implemented 34` quoted from a tree slice 5 had already moved past (PR #840, `5dd7fae5b`). **Scope:** (1) the gate parses the *latest* dated figure line in `CHAIN_RULES_CRATE.md` (the `**After …:**` paragraph's backticked `consensus:` string) and fails on inequality with its own derivation — a stale figure goes red instead of being noticed; (2) as a byproduct, `--describe` prints the tree it measured as `git describe --always --dirty`, **never bare `rev-parse HEAD`**: a drifted worktree (seven instances recorded in rule 08) would stamp a figure with a commit whose tree is not what was measured — confidently wrong provenance, the failure this lane spent a week on from the other direction; the `-dirty` suffix is the warning. A sha tells a careful reader which tree a figure came from; the equality check means the figure cannot be wrong in the first place, so the check is the subject and the stamp is not a substitute for it. Falsify by: editing the doc's figure by one and watching the gate go red; running in a worktree with an uncommitted change and reading `-dirty` in the stamp.
  - Target: pre-genesis
  - Owner: [`CHAIN_RULES_CRATE.md`](design/CHAIN_RULES_CRATE.md) — the figure's owner and the gate's (`scripts/ci/check_chain_rules_coverage.py`); rule 42's paired-bump gate is the shape to copy

- **CEN-E5's remedy has no writer yet: the ingest driver must run `ReleaseAnchors::conflict_with` at open and apply `AnchorConflict::remedy`** (E6 slice 3, 2026-09-20, Q2 as ruled: a FOLLOWUPS row, never an in-PR conditional on another lane's timing). The check is landed and fixture-proven in `shekyl-chain-rules` (`rules/anchors.rs`, registry `E5 enforced_at(…)`); the *remedy* is the writer's and only the writer can pop: `Remedy::RefuseToRun` at a genesis conflict (wrong network for the binary — do not run), `Remedy::PopTo(count)` otherwise where `count` is a `ChainCount` of `max(h − 2, 1)` blocks (the tip it leaves is `count.tip()`: genesis alone for a conflict at height 1, 2, or 3 — do not read the payload as a tip height), each `pop()` refusing at the floor (`StoreCannot::PopBelowFloor`; a refused pop is itself a reason not to run, C2-R1b F-1(b)). Site: the `shekyl-chain-ingest` open path, before the first `form`. Every network's table is empty today, so the call is a no-op until the first checkpoint release — which is why it must be wired *before* one ships, not after. Falsify by: an ingest test that opens a fixture file whose anchored block differs from a `ReleaseAnchors::for_tests` table and observes the pop (or the refusal at genesis).
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) — the ingest driver's open path (DRS-E2); the callee and the remedy rule are `shekyl-chain-rules`'s (`CHAIN_RULES_SLICE_3.md` §2, §4.2)

- **`Fault::Corrupt` has no writer-halt consumer until the E2 replay driver exists** (E6 slice 2 §4.3, 2026-09-19; owner **the DRS-E2 replay-driver pre-flight, PR #788 — `docs/design/DRS_E2_REPLAY_DRIVER.md` RD-Q4**, where the store API is minted with its caller; until 2026-09-19 11:17 this row named "the E2 lane", which existed in no form — RD-F3). `validate` returns `Fault::Corrupt` (non-monotone or overflowing cumulative work, a zero target) when the *store's* record is inconsistent — an `InvariantViolated` the store did not see itself. `connect` takes a `ChainValid` and never sees it; the receiver is the driver that calls `validate`, and no driver exists yet. What is owed: the driver arms the writer halt at the noted height on `Corrupt`, exactly as a belt does, and the store API it needs (a halt the store did not detect) is minted with that first caller — not before (rule 21). Blocker: the driver is unbuilt; **scheduled** as DRS-E2's commit 1 (RD-Q4 defaults `WriteBatch::refuse_corrupt(Corrupt)`, inside the batch). Falsify by `rg 'Fault::Corrupt' rust/` returning a match site outside `rust/shekyl-chain-rules/`; that site is the consumer and must halt. Record: [`CHAIN_RULES_SLICE_2.md`](completed/CHAIN_RULES_SLICE_2.md) §4.3.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) RD-Q4 — landed as its §7 commit 1 (`WriteBatch::refuse_corrupt`, SI-10); this row closes when the ingest actor calls it (commit 5)

- **Resolution: FCMP++ historical-reference cutover via Stage 5 `ArchivalEngine`.**
  - Target: pre-genesis

- **Audit FCMP++ integration for paired computations.**
  - Target: pre-genesis

- **Regression test: `compute_leaf_count_at_height` vs LMDB drain.**
  - Target: pre-genesis

- **Expose FCMP++ verification cache stats via daemon RPC (stressnet F14).**
  - Target: pre-genesis

- **Rust replacements for chaingen-deleted validation invariants.**
  The chain-switch / fee / key-image arm on the live daemon is `e2e_fcmp_spend_reorg_restores_pool_and_fee` (`rust/shekyl-engine-core/src/engine/regtest_e2e.rs`), armed in `scripts/ci/run_live_daemon_gates.sh`. It covers one tx-conserving pop: key image 1 → 2 → 1, and `get_coinbase_tx_sum`'s fee leg moves by the spend's fee and back. Integer overflow and an alt-chain split remain. Falsify the discharged arm by that test missing from the gate list.
  - Target: pre-genesis

- **Coordinated `TestLedgerBuilder` test-infrastructure substrate [`LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`](../rust/shekyl-engine-core/src/engine/local_ledger.rs)**
  - Target: pre-genesis

- **Define formal escalation policy for `shekyl-oxide` divergence [`docs/CI_BASELINE.md`](./CI_BASELINE.md)**
  - Target: pre-genesis

- **Migrate C++ `transfer_details` consumers to [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **`WALLET_REWRITE_PLAN.md` systemic broken relative-link sweep.**
  - Target: pre-genesis

- **Retire the iai-callgrind→gungraun bench-flake bisect harness (spawned by the gungraun 0.19 migration, 2026-06-16; cause closed 2026-08-14).**
  - Target: pre-genesis

- **rand 0.9 migration and curve25519-dalek 5 cascade.** [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  - Target: pre-genesis

- **Two `unmaintained` advisories surfaced by `cargo audit` [`docs/design/STAGE_0_HARNESS.md`](./completed/STAGE_0_HARNESS.md)**
  - Target: pre-genesis

- **Chore #3: retire every 32-bit target — leading with the security argument (`v3.1.0-alpha.5`, landed on `chore/retire-32bit-targets`).**
  - Target: pre-genesis

- **TRC-1: measure ordinary-operator relay cover across hours and consensus weights.** [`TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md) §8. The ruling that Tor-zone cover is volume (non-exit relay posture) rather than substitution (the protocol carrier) rests on a measurement that has not been taken. Named blocker: falsifier-chain step 1 — the posture is documented (`docs/TOR_RELAY.md`: daemon client = that relay process) and that topology is running. A sidecar client Tor is not this row's subject. Falsify by measuring carried traffic at ordinary operator scale on the shared-instance bind; if originated cells remain distinguishable, the ruling reopens and the carrier's scope re-expands to Tor. Reciprocity sizing is a Foundation measurement, not this row.
  - Target: pre-genesis

- **Relay: a transaction mined while the carrier holds it is still SENT — every remaining window, up to ~100 KiB.** The verdict-time `pool_has_tx` gate stops the record and the F-10 observation, but the verdict arrives only on completion, so a transaction mined before its first tick emits all of its windows: `MAX_FRAGMENTS` (5) × `WINDOW_BYTES` (20 480). An earlier entry said "one wasted window", understating it by the fragment cap. Named blocker: cancelling earlier needs an enqueue-cancellation API `NoiseQueues` does not have, and `unbind` clears a whole channel, so cancelling one message would discard its channel-mates. Bounded per transaction rather than per epoch, and it is cover carrying something peers already hold. §3.1c (2026-09-12) did not show a material share. Reopen if another caller needs cancellation [`COVER_TRAFFIC_RESTORATION.md` §3.1e](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **Relay: the carrier's pool gates NARROW the false-`Silent` window but cannot close it.** `pool_has_tx` releases the txpool lock before returning, so a removal between the second check and `record_stem` still arms an F-10 observation for an absent transaction. Named blocker: closing it needs the txpool to cancel in-flight observations on removal, or `StemWatch::expire` to re-ask membership before counting a `Silent` — the better place, since expiry is where the `Silent` is decided — and both are new plumbing across the FFI into the layer the daemon cutover replaces. Latent: §12.11, the tier that reads these tallies, is unbuilt. The ordinary stem arm does not check at all, so the carrier is the only path that narrows it. Reopen when §12.11 becomes real, or at the cutover [`COVER_TRAFFIC_RESTORATION.md` §3.1e](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **Relay: a carrier verdict of `sent` means the transport ACCEPTED the bytes, not that they reached a peer.** `connections::send` queues an asynchronous write, so a socket failing after acceptance still resolves `CarrierOutcome::Sent` and charges the relay record and the F-10 observation. Named blocker: epee exposes no write-completion signal, and adding one thickens inherited C++ directly beneath the layer the daemon Rust cutover replaces (`20-rust-vs-cpp-policy`); socket completion would still not be peer receipt. Reopen at that cutover, where the write path is Rust-owned. Contracts state the gap today, and the exposure is latent — §12.11, the consumer of those tallies, is unbuilt [`COVER_TRAFFIC_RESTORATION.md` §3.1d](design/COVER_TRAFFIC_RESTORATION.md)
  - Target: pre-genesis

- **§56.5 ruled the cadence memoryless; the shipped law is still bounded uniform, and nothing tracked it.** Carries §57's three exits and §58.2's admission threshold `θ`, both priced at the retired 12.5 s mean [`DAEMON_RELAY_PRIVACY.md` §56.7](design/DAEMON_RELAY_PRIVACY.md)
  - Target: pre-genesis

- **Relay: the `t_core` arrival harness — the witness this path has never had.**
  - Target: pre-genesis

- **Relay: `on_relay_tx` and a missed submit nudge re-decide the zone after origination.**
  - Target: pre-genesis

- **Wallet: stop holding a relay constant — ask the daemon whether a transaction is still in flight.**
  - Target: pre-genesis

- **Relay: the zone-route decision family moves to Rust** (in flight,
  - Target: pre-genesis

- **Relay: re-derive `fluff_return_ms` once, when a degree distribution exists.**
  - Target: pre-genesis

- **Relay: the `F'` region and §15's launch condition are one condition, and neither section says so.**
  - Target: pre-genesis

- **Fleet: arm readouts must record the per-sample series, not a pooled summary — an instrument fix, not a data gap.**
  - Target: pre-genesis

- **Relay: `full_travel_probability`'s cross-check holds `fluff_return_ms` fixed, and `F'` is the axis the region derivation moves.**
  - Target: pre-genesis

- **Relay: `F'` may be per-POSTURE even though §89.2 correctly refused per-ZONE.**
  - Target: pre-genesis

- **Relay: populate the 48-cell Pi verification surface, then consume it per shape.**
  - Target: pre-genesis

- **Levin p2p migration — LV-2 payload codec and LV-3 connection-path.** LV-1 and LV-2a/2b have landed. **LV-3 is not started**, and the [`IMPLEMENTATION_INDEX`](design/IMPLEMENTATION_INDEX.md) `LV-` row recorded that it "still gates on its own design round" — **a round that did not exist**. It exists as of 2026-09-21: P2P-3, with LV-3 as slice 1. Scoped as the connection becoming a **typed, owned Rust object whose identity is PWD-I8's category** — explicitly **not** a port of `p2p_connection_context`, which would carry the category error across the FFI boundary intact (rule 16). [`LV2_PORTABLE_STORAGE.md`](design/LV2_PORTABLE_STORAGE.md) is LV-2's record.
  - Target: pre-genesis
  - Owner: [`P2P_3_IMPLEMENTATION_ROUND.md`](design/P2P_3_IMPLEMENTATION_ROUND.md) §4 slice 1; the slice brief is [`LV3_CONNECTION_OBJECT.md`](design/LV3_CONNECTION_OBJECT.md)

- **Relay lane: add a derivation check asserting `fluff_return_ms` equals the max over measured zones**, so adding a zone slower than Tor fails loudly instead of silently under-provisioning `F′`; `tests/carrier_window.rs` is the shape — [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md) §91.2
  - Target: pre-genesis

- **Execute PWD-T6's PWC-F3 deletion: remove `P2P_DEFAULT_PACKET_MAX_SIZE`, `network_config::packet_max_size`, and `network_config`'s KV serializer.** Ruled, not deferred — the never-sent map would otherwise advertise a 50 MB packet limit against the 100 MB the transport enforces, and PWD-T6 names the authoritative limits so there is one source. The struct keeps its live fields; `handshake_interval`, `config_id` and `send_peerlist_sz` are also write-only but belong to PWD-B1/B2 and PWD-I2. PWC-F3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T6
  - Target: pre-genesis

- **Implement PWD-I2's peerlist-acceptance rules: outbound-only acceptance and the `P2P_MAX_PEERS_IN_HANDSHAKE` per-connection ceiling.** The white-list writer invariant lands with the back-ping deletion in the row below, which is one composable change. **The store bump that row also once carried has already landed** (7 → 8, `fix/peerlist-trust-is-earned`), so it is a completed prerequisite here, not pending work. PWC-D1/D3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I2
  - Target: pre-genesis

- **The rustdoc gate enumerates crates by name, so a crate outside the list is never documented and its errors accumulate unseen — `shekyl-relay` currently has 5.** `rust-audit-test.yml:310-312` gates `shekyl-tor-control-wallet`/`shekyl-p-serve`/`shekyl-p-host`/`shekyl-operator-alarm` and `build.yml:482` gates `shekyl-win-sec`; everything else is ungated. Fix the gate to cover the workspace with named exclusions (the inverse direction) rather than named inclusions, then clear the relay crate's broken intra-doc links — [`45-rust-lint-checks`](../.cursor/rules/45-rust-lint-checks.mdc)
  - Target: pre-genesis

- **Gate PWD-T7's compression invariant mechanically: assert that only notify routes reach `try_compress_message`, and that no message carrying confidential material of any lifetime — session key, node-local secret, reused token — is routed through one.** **Blocker cleared 2026-09-03 by PWD-B3's route classification** (this was "nothing in the tree classifies a command as confidentiality-bearing"): every p2p command is an *invoke* (`net_node.inl:1078`, `:1165`, `:2581`, `:2623`) and all three compressor call sites finalize as notifications, so the reachable set is the cryptonote notify family — public consensus data. Executable now: the check is on the **routes**, not on the command table, since a table-shaped gate would pass while an invoke-carried secret was re-routed through a notify. The invariant is stated at the dispatch site (`rust/shekyl-levin/src/compress.rs`) in the meantime, which is placement, not enforcement — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T7, PWD-B3
  - Target: pre-genesis
  
- **Size the Levin bucket header's length field, once `NOTIFY_RESPONSE_GET_OBJECTS`'s byte budget has a value.** **Blocker: three inputs are still open** — *(1)* the response byte budget itself (owed: a bandwidth/latency trade for initial sync, needs sync measurements); *(2)* `margin` in `entry_max`, owed to the **consensus lane — C2-R2 owns the derivation** (CEN-G6/G6b), **scoped to the tip-adjacent announce path only** since 2004 is byte-budgeted and `entry_max` has one consumer (2008). **C2-R2's value is SIGNED — `margin(k) = min(2^k, S·LTEM/EM)` for announce-lag `k` with S = the ratified surge factor (signed S = 4), both operands receiver-local — recorded in [`CONSENSUS_C2_R2_WEIGHT_FEES.md`](completed/CONSENSUS_C2_R2_WEIGHT_FEES.md) §6, landing on `dev` with the R2 PR (round signed 2026-09-06)**. One coupling from the signing round: the absolute arm's 50 is the SURGE FACTOR (CEN-G6), which Q3's measurement REFUTED — **the signed re-derivation is S = 4 (d24 denomination, Rick 2026-09-06)** — so carry the arm as `S·LTEM/EM` with S = the ratified surge factor, never a literal. *Behavioural consequence of the ×50 refutation, not a change of constant:* at S = 4 with EM at the floor, `margin` is 2 at k = 1, 4 at k = 2, and **flat at 4 for all k > 2** — it no longer grows with lag. Sound within the assumed announce-lag `k ≤ 2`, where the `2^k` arm dominates — growth with lag was headroom for blocks the consensus now forbids. Beyond the assumed lag the receiver-local clamp arm is NOT a soundness guarantee: `margin(∞)`·its-limit is `2·S·LTEM_stale`, while the legal ceiling at the announce height is `2·S·LTEM_{h+k}`, so a far-behind receiver under-admits by LTEM's growth over its actual lag (an earlier revision claimed arbitrary-lag soundness from "no legal block exceeds 2·S·LTEM", silently substituting the stale operand — removed 2026-09-06). **Carry the function, not the ×4 constant**: the announce path is gated on `is_synchronized()` (`src/cryptonote_protocol/cryptonote_protocol_handler.inl:538`, definition `cryptonote_protocol_handler.h:111`), which is a **latched boolean, not a height comparison**, so nothing enforces a numeric `k` — the `min`'s absolute arm is what keeps the bound safe when lag exceeds the assumed value (its receiver-local LTEM lags the true LTEM_{h+k} by ≤ 1.7^(k/⌈min(h,100k)/2⌉) — ≤ 2.2 % in the worst ramp-in case at the assumed k ≤ 2, growing with lag beyond it; liveness-direction only — NOT absorbed by the additive witness term, which budgets the announce's own witness; a beyond-lag receiver recovers via block-sync, and the bounded-lag residual is routed at the PWD-B7 announce-arm item below; consequence stated in the round doc §6); *(3)* the **relay batch bound for `NOTIFY_NEW_TRANSACTIONS`** — **the mechanism is now ruled by PWD-B12** (a byte cap on what a flush releases *and* a byte cap on what a zone holds, with admission refused at the second), **but its two numeric values are owed**, so 2002 still has no computable cap and 2004 is not yet proven to be the largest value the header must express. *This item was briefly marked cleared on 2026-09-03 and re-opened: PWD-B3 fixed the cap's shape, not its value; PWD-B12 fixed 2002's mechanism, not its value.* PWC-A2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T6, PWD-B3, PWD-B12
  - Target: pre-genesis

- **Re-derive `drop_connections(address)`'s host-keyed severing together with the anonymity-zone inbound bound.** It severs every connection sharing a host and scores that host +5 (`src/cryptonote_protocol/cryptonote_protocol_handler.inl:2643-2682`); the remaining blocker is that an onion identity is free to mint, so a per-host key prices nothing — the sweep is now safe on an anonymity zone, not useful there. Re-derives together with PWC-E11's inbound cap, count- or work-based. **The second blocker — host-keying compared `unknown == unknown` — was closed by `fix/anon-zone-address-keying`; the disposition row carries that history and the corrected `is_same_host` finding.** PWC-E9 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7, PWD-I4
  - Target: pre-genesis

- **Carry an anonymity-zone peer's endpoint in the handshake, and delete the `unknown()` sentinel with it.** Scoped to overlays: clearnet's observed-address / claimed-port split is deliberate and stays. **This deletes work, it does not add it:** the sentinel goes, and with it `identifies_a_host()` in `contrib/epee/src/net_utils_base.cpp`, the `drop_connections` early return, and their comments. Rationale and the verification story are in the owning row; admission policy (no endpoint ⇒ not a peer) is a separate ruling with Rick. — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I1, PWD-B10
  - Target: pre-genesis

- **Sweep the tree for comparison tests built only from separately-constructed operands, adding an alias limb where one is missing.** A test that constructs both sides independently never creates the aliasing condition, so it cannot exercise a short-circuit that fires on *identity* — structurally incapable, not weak. **Measured:** with the anon-zone guard misplaced, the separately-constructed limbs (`tests/unit_tests/net.cpp:263-264`) pass while the alias limbs (`:276-277`) fail. Any equality, ordering or identity check with a pointer short-circuit has the same blindness available. Found by `fix/anon-zone-address-keying` — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7
  - Target: pre-genesis

- **Implement 2004 byte-budget truncation continuation — the shipped requester severs a truncating responder.** Verified at source (review round of #616): `handle_response_get_objects` erases only delivered hashes, never consumes `missed_ids` (responder-filled, `cryptonote_protocol_handler.inl:1053`), and drops the peer whenever `m_requested_objects` is non-empty afterwards (`:1174-1202`) — so the ruled byte-budget responder gets disconnected on every truncated batch by today's code. The P2P-3 implementation must: *(1)* mark **deferred-by-budget** distinctly from `missed_ids`' **genuinely-unavailable** (conflation poisons availability bookkeeping); *(2)* re-request the deferred remainder; *(3)* **narrow, never delete** the not-all-returned drop — it is the withholding detector and keeps firing on any shortfall that is not budget-marked. PWC-A2's byte-budget value item is the sizing half; this is the semantics half. — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B3
  - Target: pre-genesis

- **Build the clearnet accept-rate bound D10.3 rules, before any cryptographic work.** The per-connection cost is measured (C5). The rate waits on a stated CPU budget. Onion-service proof-of-work on every published onion is landed (D10.4). There is no daemon-side Tor accept limiter.
  - Owner: [`P2P_TRANSPORT_LAYER.md`](design/P2P_TRANSPORT_LAYER.md) D10
  - Target: pre-genesis

- **Extend PWD-B1's bucket to *every* dispatch — invoke and notify — and derive its four parameters.** The coverage half is not optional bookkeeping: `NOTIFY_NEW_TRANSACTIONS` is a `HANDLE_NOTIFY_T2` route, so a bucket on the four node-server invoke routes alone leaves transaction floods spending **no tokens**, and **PWD-B12's memory bound assumes B1 is charging that connection**. Closing this item without the coverage change would leave B12's composition claim false in the code while true in the design. Parameters, all four, since a refill rate alone does not define a bucket: *(1)* refill rate; *(2)* capacity and initial fill, which *is* the burst allowance and decides whether a peer that connects and immediately syncs is throttled; *(3)* per-command token cost, since a handshake and a timed-sync are not the same work and an attacker picks whichever is mispriced; *(4)* **the action on exhaustion — throttle or disconnect**, which is **wire-observable**, so leaving it open means conforming peers disagree about whether a slow peer is a hostile one. **Unruled, not blocked.** Needs the honest-sync measurements PWD-B1's falsifier names. PWC-E2 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B1
  - Target: pre-genesis

- **Derive PWD-B2's timed-sync `min`/`jitter` split.** The distribution is ruled — bounded uniform `min + U(0, jitter)`, per-connection, re-drawn only on its own fire — and the constraint is fixed: **the mean stays at `P2P_DEFAULT_HANDSHAKE_INTERVAL` (60 s)**. The draw is **uniform** on the criterion of **maximum entropy over a bounded support** — bounded for liveness, max-entropy because a peaked family at the same mean has a recoverable shape (uniform is not *shapeless*; bounded support is itself a signature). **`0` is a valid draw and must not be excluded**: re-rolling truncates the distribution actually realised, which is a pattern even when the family was chosen correctly. The condition is on the **window parameter**, never on a draw. Decorrelation comes from the **per-connection independent draw** — connections established at different moments have unrelated phases whatever the window is — so the window's job is narrower: **decorrelating connections established at nearly the same moment**, which `m_connections_maker_interval` (1 s) makes the common case at startup. Derive the split against that clustering, as a **measurement** — **together with the falsifier's threshold and sample budget, in this one item**, since the window is chosen so the pairwise circular correlation of send phases falls below that threshold: neither number can be picked without the other. Q12-D6a rig. **Unruled, not blocked.** PWC-E1, PWC-E3 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B2
  - Target: pre-genesis

- **Re-derive initial-sync verification cost at the Pi-4 floor now that C2-R1a has deleted `PER_BLOCK_CHECKPOINT`.** `DAEMON_RELAY_PRIVACY.md` §74.2 concluded *"the 11-day figure is the worst case"* because the checkpoint skip rescued historical blocks; `fast_check` and `m_blocks_hash_check` no longer occur in `blockchain.cpp`, so the un-checkpointed case is now the only case. Blocker: the replacement figure needs a measurement, not an argument. Rule 76 — [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md)
  - Target: pre-genesis

- **Measure address volatility for ephemeral-per-boot onion endpoints (PWD-E8), then rule the acceptable dead fraction.** **DEFERRED — and the dependency runs the other way from how this row first read it.** `T` is the mean uptime between restarts of *real nodes*; it cannot be derived or assumed, and until PWD-E7 ships there is no fleet running the thing whose volatility `T` describes, so **the measurement has no subject**. Building E7 first is the only order that can produce `T` at all (Rick, 2026-09-08). **Derived and statable as derived:** `D = P2P_LOCAL_GRAY_PEERLIST_LIMIT × 60 s ≈ 3.5 days`, the mean time a gossiped overlay address sits in a saturated peer's gray list, because `gray_peerlist_housekeeping` draws one random gray entry per zone per 60 s from a 5000-entry pool. **Conjecture until the fleet reports:** the dead fraction `1 − e^(−D/T)` — every figure is conditional on an assumed `T` and may be quoted only as "assuming `T` = <value>, the model gives <x>", never as a property and never in a summary line where the assumption can be dropped. **Falsifier chain, every link a real precondition:** E7 ships → nodes run it → **the fleet is stressed** → `T` is measured under those conditions → the threshold becomes Rick's. Q12-D6a is the *instrument*, not the source; the source is nodes restarting in the wild under load. **A `T` is admissible only with duration (longer than the restart interval it estimates), a stressor (load is what causes the restarts), and heterogeneity (a fleet of identical healthy hosts measures operator discipline, not the network)** — a quiet fleet reports a `T` that flatters the design, and an inadmissible `T` that gets quoted is worse than none because it reads as measured. Do **not** shorten `D` by probing gray harder, do **not** infer an acceptable aggregate from the clean per-case failure, and do **not** substitute a convenient `T`. *(2026-09-09: the chain's first link is discharged — PWD-E7 landed, `shekyl-tor-control-daemon` + `add_ephemeral_tor_zone` — so the measurement now has a subject; the remaining links — fleet runs it, stressed, `T` measured admissibly — stay owed.)* — [`P2P_2_ENDPOINT_ROUND.md`](design/P2P_2_ENDPOINT_ROUND.md) PWD-E8, PWD-E7
  - Target: pre-genesis

- **Package the pinned Tor Expert Bundle beside `shekyld` in release artifacts, so the PWD-E7 default posture engages out of the box.** The default-on ephemeral onion requires a pinned tor binary (SP-T0c gate: `SHEKYL_TOR_BINARY` env → beside the executable → `/opt/shekyl/<version>-<target>/` staging → `PATH`); a distro tor never hash-matches, so without packaging the default silently degrades to "no overlay inbound" on most installs. The staging tier gives provisioned hosts a packaging-free path, but release artifacts still owe the beside-the-executable layout. Blocker: release/packaging pipeline (Guix reproducible artifacts) owns the bundle layout, not the p2p tree — falsify by installing a release artifact on a clean host and checking `shekyld` logs for the ephemeral posture engaging. — [`P2P_2_ENDPOINT_ROUND.md`](design/P2P_2_ENDPOINT_ROUND.md) PWD-E7
  - Target: pre-genesis

- **Run the `ρ`/`g_max` sub-round (Q-10) deferred by PWD-I4.** **Its inputs changed 2026-09-06: the anchor mechanism is deleted, so the `k ≤ 1` anchor-backed-connection cap this sub-round was to derive against no longer exists — there are no anchor-backed connections at all.** Selection is otherwise unchanged and the distinction still matters for this derivation: `connections_maker` remains **white-first up to the `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT` (70 %) target, then gray for the remainder**. Only the anchor-reserved share disappeared — the two-class white/gray ordering did not collapse into a single pool. Blocker: it must derive against the *settled* white/gray behaviour, so it follows the p2p tree changes rather than preceding them — the "fixed anchor behaviour" this once waited on no longer exists to be fixed; reopening criterion and the §12.10/§7 reconciliation it must carry are in the owning doc — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I4, PWD-I5
  - Target: pre-genesis

- **Decide `sanitize_peerlist`'s port-0 handling, where the IPv4-only rule collides with `tor_address::unknown()` being port 0.** Blocker: the tor port-0 semantics are disputed (named by #587, not invented here). PWC-D9 — [`P2P_2_DISPATCH_BRIEF.md`](design/P2P_2_DISPATCH_BRIEF.md) PWD-B11
  - Target: pre-genesis

- **Daemon PQC phase-1 payload assembly duplicates [`20-rust-vs-cpp-policy`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)**
  - Target: pre-genesis

- **FCMP++ sender-side output verification — inherited `wallet2::sanity_check` [`16-architectural-inheritance`](../.cursor/rules/16-architectural-inheritance.mdc)**
  - Target: pre-genesis

- **Hardening-pass commit 8 follow-up: WalletPrefs round-trip property test (`2k.a2` deferred test).**
  - Target: pre-genesis

- **`tx_pool` / `blockchain_db` LMDB transactional wrapper — typed commit-or-abort.**
  - Target: pre-genesis

- **`shekyld` `fee_policy_version` daemon-side exposure.** Surfaced [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md)
  - Target: pre-genesis

- **`ActivityMetric` producer actor (wallet-side coherent bundle).** Surfaced by [`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](completed/STAGE_1_PR_7_ECONOMICS_ENGINE.md)
  - Target: pre-genesis

- **Daemon atomic activity snapshot RPC (conditional on RPC upstream).** Same G4 [`docs/WALLET_RPC_RUST.md`](WALLET_RPC_RUST.md)
  - Target: pre-genesis

- **Workspace clippy `-D warnings` cleanup.** Surfaced by the Phase 0
  - Target: pre-genesis

- **RandomX v2 `ExternalProject_Add`: per-`CONFIG` install path and `IMPORTED_LOCATION_<CONFIG>` for multi-config generators.** in [`external/CMakeLists.txt`](../external/CMakeLists.txt) (multi-config generators; harness/miner-lib opt-in only — the default daemon never builds the C library, so this does not gate `shekyld`)
  - Target: pre-genesis

- **A UDS listener for the daemon RPC (posture 1 on the daemon)** (added 2026-08-22, RT-W2 review).
  - Target: pre-genesis

- **The GUI dials its daemon with nothing said — and a dial that says nothing is constructible.**
  - Target: pre-genesis

- **`shekyld <command>` parses `--rpc-bind-ip` with an IPv4-only helper** (added 2026-08-22, RT-W2 review).
  - Target: pre-genesis

- **Legacy spend-graph analysis utilities (`ancestry`/`depth`/`usage`): audit against FCMP++, then delete** (`prune-known-spent-data` audited and deleted — its eligible set is empty on an amount-0 CT chain) [`EXECUTABLES.md`](EXECUTABLES.md)
  - Target: pre-genesis

- **`atomic_write_file` power-loss crash-injection tests.** PR 6 cites existing unit tests in `shekyl-engine-file/src/atomic.rs` (overwrite semantics, no stray temps) but not simulated crash mid-fsync.
  - Target: pre-genesis

- **Wallet file metadata obfuscation (PR 6 §5.12 F5–F6).** File size and mtime leak wallet presence and activity without decryption.
  - Target: pre-genesis

- **`WalletFile` handle slimming (post–PR 6 `PersistenceEngine`).**
  - Target: pre-genesis

- **FFI C ABI symbol rename: `shekyl_wallet_*` → `shekyl_engine_*`, [`shekyl-ffi`](../rust/shekyl-ffi/)**
  - Target: pre-genesis

- **C++ JSON-RPC method-name rename: `wallet_*` → engine-shaped names (folded into Phase 4b's Shekyl-native RPC method-set work).**
  - Target: pre-genesis

- **Chore #4: platform-gate audit sweep — reduced scope after Chore #3 (V4 pre-audit).**
  - Target: pre-genesis

- **Restore semantic thread labels in the Rust subscriber ().**
  - Target: pre-genesis

- **Stack-trace hook: re-route `ST_LOG` back through the logging subsystem once the FFI boundary is safe mid-throw ().**
  - Target: pre-genesis

- **`removed_flags` shim sunset.**
  - Target: pre-genesis

- **`shekyl-daemon-rpc` staticlib: `tracing::*` calls silently dropped.** [`docs/design/WALLET_REWRITE_PLAN.md`](./design/WALLET_REWRITE_PLAN.md)
  - Target: pre-genesis

- **Re-examine the `/FIiso646.h` deferral.** (Filed as a two-item entry; [`docs/STRUCTURAL_TODO.md`](./STRUCTURAL_TODO.md)
  - Target: pre-genesis

- **MSVC / Windows build-debt cluster (migrated from `STRUCTURAL_TODO.md`, 2026-05-30).**
  - Target: pre-genesis

- **P-drain mechanism re-walk — CryptoNote holdover audit (rule 16; method note 5: "carry from X" is a re-walk trigger, not an exemption).**
  - Target: pre-genesis

- **`P`-lane fee uniformity — implementation rider (ratified 2026-07-19, `V3_WALLET_DECISION_LOG.md` "P-lane fees"; rides the `Unbond` wallet constructor, the SP-R0 arm-#2 production-discharge family).**
  - Target: pre-genesis

- **Principal-side default-on Tor — flip `--proxy` from opt-in to default, opt-out loud.**
  - Target: pre-genesis

- **Principal-side `IsolateSOCKSAuth` — give the principal's `DaemonClient`s isolated circuits [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](design/ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)**
  - Target: pre-genesis

- **2d-2 SP-R0 — reconcile GC of phantom `bonded_slots`/`p_slot` over the per-`P` transport [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **2d-1 WI-2 — durable removal of SPENT funding outputs from `PScanState::funding_outputs` [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **2d-1 SP-3 — borrow the block in the dual extractor instead of cloning per bonded scanner (perf, non-gating; own PR).**
  - Target: pre-genesis

- **2d-2 SP-T0 — DQ-T0.4 circuit-isolation measurement has no CI binary source (BLOCKED, not deferred-by-choice).**
  - Target: pre-genesis

- **Workspace-wide `rustdoc -D warnings` CI lane (BLOCKED on pre-existing cross-crate warnings).**
  - Target: pre-genesis

- **M1 reward-gate C++ test-support surface — fold the corruption-injection seam off the production DB API at reward-gate completion (code-review #263, 2026-07-07).**
  - Target: pre-genesis

- **Segment-freeze pipeline — design round required (opened by `ARCHIVAL_REWARD_GATE_M1.md` [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)**
  - Target: pre-genesis

- **M1 reward gate — pre-flight process BREACH (PF-1, recorded 2026-07-06; a breach, not a precedent).**
  - Target: pre-genesis

- **2d-2 SP-T4a — GF-7 principal-timeline timing correlation is a GENESIS GATE (measure [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](design/ARCHIVAL_BOND_2C_GF7_HOOKS.md)**
  - Target: pre-genesis

- **Wallet UX: thin-cover exposure disclosure at bond/claim time (registered 2026-07-19, PR #337 review thread).**
  - Target: pre-genesis

- **2d-2 2c-2a — submit-outcome handling: the wallet CONSUMES `SubmitVerdict`; the partition is [`DAEMON_SUBMIT_VERDICT.md`](design/DAEMON_SUBMIT_VERDICT.md)**
  - Target: pre-genesis

- **2d-2 2c-2a — posture→submitter dispatch shape: FROZEN 2026-07-04 (user-ratified) — [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](design/ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md) §3.1 is the binding record.**
  - Target: pre-genesis

- **2d-2 2c — `DaemonUrl` newtype: validate `base_url` at construction + house the S1 disclosure.** [`DAEMON_SUBMIT_VERDICT.md`](design/DAEMON_SUBMIT_VERDICT.md)
  - Target: pre-genesis

- **2d-2 2c — the `OwnRemote` config-point disclosure is a mandated duty with no home yet.** The S1
  - Target: pre-genesis

- **2d-2 SP-T3 — onion-route end-to-end validation (the property DQ-T0.4 *cannot* prove).** [`ARCHIVAL_BOND_2D2_SP_T0_TOR.md`](design/ARCHIVAL_BOND_2D2_SP_T0_TOR.md)
  - Target: pre-genesis

- **2d-2 SP-T3 — inbound onion serving-side hardening (the implementation threat model).** The onion [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](design/ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)
  - Target: pre-genesis

- **Wallet-locked-during-`in_flight` coordination [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md)**
  - Target: pre-genesis

- **`LedgerEngine` candidate-fetch maturity-filter [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)**
  - Target: pre-genesis

- **`run_refresh_task` holds the engine read-guard across [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)**
  - Target: pre-genesis

- **`LedgerReadGuard` field type leaks crate-private [rust-lang/rust#117108](https://github.com/rust-lang/rust/issues/117108)**
  - Target: pre-genesis

- **Stage 4 lifecycle async cutover requires `CHANGELOG.md` [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)**
  - Target: pre-genesis

- **Stage 5 — `ArchivalEngine` native actor build (simulation- gated).**
  - Target: pre-genesis

- **[Shard-visual floor re-run trigger](V3_SHARD_VISUALIZATION.md) — STANDING, never "done".** The amended
  performance targets are regression bounds enforced by a named trigger (option (a) of *Where the bound is
  enforced*), because nothing else re-runs them.
  - Target: pre-genesis
  - **Trigger conditions — a change anywhere in the TIMED PATH obliges a floor re-run BEFORE merge.** The
    measured operation is `render_candidate_png_from_params` end to end (render **plus** PNG encode), so the
    trigger is its whole call graph, not just the renderers: `src/render/*.rs`, `src/candidate.rs`,
    `src/compositor.rs`, `src/palette.rs`, `src/entropy.rs`, the encode path in `src/lib.rs`, and a version
    change in the `image`/`imageproc`/`png` dependencies. Naming a subset would let a regression enter through
    the part that was left out.
  - **How:** cross-compile `--example budget_matrix` for `aarch64-unknown-linux-gnu` (skl-pi has no Rust
    toolchain), run the `floor` profile on skl-pi — ping the board first, no sudo — and commit the capture
    under `docs/benchmarks/`.
  - **Verdict discipline:** over-budget cells are a REGRESSION to record against the 2026-09-06 baseline.
    **Never a quiet retune** — moving a number so the matrix passes is the one response that is always wrong.
    A threshold moves only by a *recorded amendment* citing the measurement and ratified by the decider (the
    spec's amendment discipline; that path was exercised 2026-09-06), which is also the reopening path in the
    fallback's reversion clause. Regression first: the default is that the change caused it and the change is
    fixed or reverted. CI's `shard-visual-x86-smoke` does NOT discharge this trigger: it cannot bound the floor
    in either direction.

- **Transport selection for the staker-archival path (gate 6 / networking; forward consideration, NOT yet scheduled).**
  - Target: pre-genesis

- **Soundness pass step 0: pin retrieval SLA per class (gate 4–6; soundness pass — upstream of L15).**
  - Target: pre-genesis

- **Foundation genesis-enumeration — legal / regulatory disclosure (gate 4–6; pre-genesis).**
  - Target: pre-genesis

- **Archiver seeding-path transport relaxation (gate 6 / firewall; soundness pass step 2).**
  - Target: pre-genesis

- **L14 read-credit soundness: per-(holder, shard), never shard-global (gate 4 / consensus crypto; soundness pass step 3).**
  - Target: pre-genesis

- **L15 diversity under location-hiding (gate 4–6 / architecture; soundness pass step 1 — conditional on step 0).**
  - Target: pre-genesis

- **Permanent fee-era backstop must be a trustless terminal subsidy, not the foundation floor (gate 7 / consensus monetary policy; GENESIS-CLASS decision).**
  - Target: pre-genesis

- **Age-stratify the foundation floor AND the terminal subsidy toward the irreplaceable oldest band (gate 5 + gate 7; shape derived, magnitude post-testnet).**
  - Target: pre-genesis

- **L12 floor-decay schedule should be coupled to the growth↔entry crossover, not a free constant (gate 5 / economics; substrate note).**
  - Target: pre-genesis

- **Bootstrap APR overshoot is a purse-efficiency note, not a correctness one (gate 5 / economics; substrate note).**
  - Target: pre-genesis

- **Vanguard eligibility flag set is a provisional pin, unseated only by operation (VG-2 / transport; rule-21 reopen record).**
  - Target: pre-genesis

- **Validate `prev_id` before attestation verify on the alt-chain path (consensus ordering; independent hardening, NOT a defect).**
  - Target: pre-genesis

- **Alt-chain attestation verify resolves bond pubkeys from main-chain state** — `verify_block_attestation` (`blockchain.cpp`, both paths) looks every `p_id` up with `m_db->get_archival_bond_hybrid_pubkey`, and bond joins/updates are applied only when a block's transactions connect (`blockchain_db.cpp` bond-post dispatch), which alt blocks do not do until promotion. So a valid alt chain that contains a bond join followed by a pass from that bond is refused `BOND_ABSENT` at alt time — a split between nodes that saw that chain as main and nodes that saw it as alt. Pre-dates `SF-D8` v2 (#734 added the connecting-chain **anchor-hash** fill but left the key lookup as it was; surfaced in that PR's review). Two candidate fixes, to be ruled not inherited: (i) defer the bond-key leg of the alt-path verify to sequential promotion, where `handle_block_to_main_chain` already re-runs it against connected state (the inherited alt-block model — alt blocks are stored without tx validation and fully validated at switch); or (ii) resolve keys against a connecting-chain bond view. (i) is smaller and matches how every other state-dependent tx check behaves on the alt path. Falsify by a unit test that builds an alt chain `[join(P), …, pass(P)]` off a main chain without `P` and asserts the alt block is accepted into storage.
  - Target: pre-genesis

- **Land round 19: the relay floor follows raw `C` (FL-R20…FL-R23)** — implementation spec at [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md) §11.6, **SIGNED OFF in-channel 2026-09-11; PR A (consensus operand, FL-R24) MERGED to `dev` — PR B (relay policy) and PR C (deletion sweep) remain**: `get_current_fee_per_byte` = `R·C·w_ref/M²` raw; lookback-min admission over `G` = 5 in a Rust predicate (with the A-2 weight-gate property test and a zero-pinned `RELAY_ADMISSION_SLACK_BP`); three PRs — consensus operand (FL-R24) **DONE**, then relay policy, then deletion sweep; **FL-R25 (the dead fourth fee slot deleted, wire now three tiers, `CORE_RPC_VERSION` 3.30) lands before the relay-policy PR**, so PR B is read against a settled wire; delete the pow2 snap, hysteresis, `MIN_REPRESENTABLE_C`, the `fees[0]` clamp, `round_money_up_2` on the served path, the 2 % buffer and the 0.95; wallet path unchanged. FL-R24 (SMA resolution) was decided on FL-E3 first, and PR A landed under it. Replaces the former §7-band restoration row: the snap the band smoothed is deleted (FL-R21), so nothing is restored. Falsify by `rg quantize_pow2_ceil rust/shekyl-economics/src/fee/` returning nothing.
  - Target: pre-genesis

- **Disclose the fee-tier privacy trade in the wallet/CLI tier picker** — rule-81 obligation created by FL-R17's signature; carrier is the engine tier-mapping change. [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md) §7.
  - Target: pre-genesis

- **Block-weight penalty and fee floor price the same expansion off different medians during a surge.** The penalty uses the **effective** median (up to `S·LTEM`); the fee floor and ladder use the **long-term effective** median `LTEM`, which the surge clamp never touches — so during a surge the two paths price the same block against operands that differ by up to `S`. Conservative (the floor over-charges relative to the penalty, up to 4× at `S = 4`). Same class as FL-V1: two paths, two operands. Owner: the fee lane; [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md). Found implementing C2-R2 Q3 (`S = 4`). **Restated 2026-09-12 on the FL-R20 merge:** the original row derived the fee-side operand from the ladder taking `Mfw = min(Mnw, Mlw)` with `Mnw ≥ Mlw`; FL-R20 deleted that two-median computation, and the estimate now reads `LTEM` directly. The divergence survives the deletion — it is the same two operands — but the reason is the operand, not a min, and the factor is `S` rather than the 16× the min-based reading gave.
  - Target: pre-genesis

- **FL-R26: delete `grace_blocks` from the fee-estimate path and the RPC** — FL-R20's un-graced `Mlw` (ruled 2026-09-11) leaves the parameter with no effect on any rung, and a tunable with no effect is worse than no tunable, so it is deleted rather than pinned at zero. **Wire change** — `grace_blocks` is an RPC parameter, so it carries a `CORE_RPC_VERSION` bump and a regenerated oracle vector, which is why it is NOT in PR B; it belongs with the RK-5 wire lane or PR C. What is already true in the tree: the estimate divides by the un-graced long-term effective median, does not construct a graced short-term median, and `fee_2021_scaling.grace_blocks_do_not_move_the_served_ladder` pins that the served ladder does not depend on the parameter. `grace_blocks` is still accepted on the RPC (FL-R26 deletes the field). Reopener (rule 21), cross-referenced to FL-R19: a long-gap construction path — cold signing, offline signing, multisig — may outrun `G` = 5 and reopen the lookahead question; FL-R19's sizing premise was voided on "there is no offline signing" (decision log 2026-09-07), and this row is where that is re-examined. Ruling and the measured inertness (grace ≤ 100 against a 100 000-block window moves the median by at most 100 ranks, and on a flat distribution by nothing) at [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md) §8 FL-R26. Falsify by `rg grace_blocks src/rpc src/cryptonote_core`.

- **FL-R3-STORE (consumer half): the reward/fee path reads `cumulative_tx_count` and `long_term_effective_median` off the store, and the C++ reconstruction code goes** — the *store half* closed 2026-09-17 (PR #772, S-CHAIN-R commit 2b/5: both fields are `block_info` columns written per block and read O(1) as `ReadSnapshot::{cumulative_tx_count, long_term_effective_median}`; requirement and bit-identity gate at [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md) §10.12.2, plan at [DRS_E1_SCHAIN_R.md](completed/DRS_E1_SCHAIN_R.md) §3.6). What remains is the consumer's: `Blockchain::get_tx_volume_window`'s 720-block blob walk (`blockchain.cpp:1917`) and `rebuild_relay_floor_ring`'s ~100 000-entry stepped median (`relay_floor_ring.cpp:181`–`:200`) read the two fields instead and are **deleted**, and the derivation bit-identity gate against the ring's stepped median lands beside that deletion (the store cannot test a value it passes through). Without this the stepped median stays permanent because it worked. **Carrier:** the cutover increment wiring the Rust daemon's reward/fee path onto S-CHAIN-R (rule 20: the deletions are the cutover's). **Falsify by** `rg 'get_block_from_height\(h\)\.tx_hashes' src/cryptonote_core` and `rg rolling_median_t src/cryptonote_core/relay_floor_ring.cpp` returning nothing; remove the row when both do.
  - Target: pre-genesis

- **Repair backlog as one query (DRS §7.6 item 1)** — one gate script over the four homes a knowingly-reproduced deviation lands in (CSR DIVERGENT rows, `STORE_INVARIANT_REGISTER.md`, inline schema notes such as R8b-2, surface-plan finding lists), returning every entry with its ratified state on one denominator with the census's bucket-4 rows; carrier: DRS-E2's pre-flight. Rationale: [DAEMON_REDB_STORE.md](design/DAEMON_REDB_STORE.md) §7.6. Falsify by `scripts/ci/check_repair_backlog.py` (or the name E2's pre-flight picks) printing that denominator.
  - Target: pre-genesis

- ~~**Measure boundary-cell occupancy**~~ — **DONE at round 18**: occupancy 741‰, mean residence 637 blocks, max 13 597; it selected `P` = 720. [FEE_LADDER_DERIVATION.md](design/FEE_LADDER_DERIVATION.md) §10.10 (the figures) and §9 FL-D8 (row closed).
  - Target: pre-genesis

- **Daemon shard-fetch client (`SF-` round): sub-PR 1 BUILT 2026-09-13 as one PR stacked on #734; §9.1 (c) DONE 2026-09-16 (`N = 8`) — what remains** — `shekyl-p-fetch` (dial, `shekyl-pass-request` header, envelope, SOCKS5h reuse, `MAX_INFLIGHT = 8` pinned, `SF-D6` taxonomy, countersignature verify via the shared `verify_pass_transcript`, `Vec<u8>` body, `ContentVerify` hole), the serve-side `SF-D8` countersignature and pre-sign gate, the `PassSigner`/`PassKey` seam, the `serving_route` home, the `RF-R1` update, and `check_p_fetch_dep_cut.py` all landed in that PR plus #746 ([ARCHIVAL_SHARD_FETCH.md](design/ARCHIVAL_SHARD_FETCH.md) §9.1). Open, each with its carrier:
  - Target: pre-genesis
  - **Sub-PR 2 — UNBLOCKED 2026-09-17 (`PDM-Q6` items 1–3 RULED; was blocked on it since PR #723):** the frame codec and the content-verify are **per-tx** over a **byte-bounded `tx_id`-range** body `[b_k, b_{k+1})` (`PDM-Q-F32`; fixed `T` superseded): each fetched tx is re-hashed with `Transaction::txid_parts()` and its components checked against what the node retains — `txs_prunable_hash` (exists) and `txs_pqc_auth_hash` (**both rows landed**, DRS §7.7 item 3 / S-CHAIN-W A3, PR #772). **That per-tx verifier** is what plugs into `ContentVerify`. The leaf-shard scheme — `ServedFrameHeader` (`RF-D4`) + `recompute_segment_r_k` — **does not survive** (`PDM-Q-F25`, ruled) and is deleted, not adapted. Then the scheduler that constructs `PFetchClient` (challenge and organic callers, `SF-D1`, `SF-D10`); `max_body_bytes()` re-derived as `SHARD_BYTES + MAX_TX_SIZE` (F32; ~~`T × max_tx_size`~~ superseded) (the ruling's pricing falsifier). **Q6 item 4 RULED 2026-09-18:** `SF-D8`'s content half reopened → this seam, `expected = (txs_prunable_hash, Option<txs_pqc_auth_hash>)` per `tx_id` in `[b_k, b_{k+1})`, membership against the boundary pair (F32); `SF-D7` re-keyed to `N × (SHARD_BYTES + MAX_TX_SIZE)` with `N = 8` and the `L` candidate **standing as measured** (F32 keeps `SHARD_BYTES` at 3.33 MB as the boundary metric); `SF-D1`'s addressing clause re-keyed (conclusion stands on `RF-R1` alone). Line-local edits in `ARCHIVAL_SHARD_FETCH.md` owed by the `SF-` lane.
  - **§9.1 (c) DONE 2026-09-16 (PR #746):** W₂ on `PFetchClient` (daemon→wallet, 3.33 MB shard-0): cold n=200 p99=48.27 s; warm n=200 p99=12.26 s; soak n=1774 p99=86.06 s; widths 1/2/4/8 all valid, zero sheds; pin `shekyl_p_fetch::MAX_INFLIGHT = 8`. Falsify by `rg SPIKE-PIN rust/shekyl-p-fetch/src` returning nothing.
  - **`L` drop-to-3 candidate (not a pin):** single-attempt cold p99 48.3 s and soak p99 86.1 s both < 120 s — necessary, not sufficient. `archival_attestation_anchor_lag_blocks` stays 4. Blocked on `SF-D6` retry budget (TJ-D) — falsify by a fetch-plus-retry p99 < 120 s once that budget exists, then drop 4→3 in the same PR.
  - **SH-2:** wire the persona's resident attestation key as the `PassKey` `engine-core` binds; until then it binds `NoResidentKey` and every serve is a counted sign refusal (`ServeCounters::sign_failures`). **The counters are not yet an operator surface:** `serving::task` holds the host privately and publishes posture and serve-set alarms only, so `served` / `refused` / `lookup_failures` / `sign_failures` are read by tests alone (`PersonaServing::counters`). Surfacing them on the alarm board is `TJ-D`'s operator surface (`SF-D6`) and lands no later than SH-2, since a resident key that refuses is the first thing it must report. Falsify by `rg 'counters\(\)' rust/shekyl-engine-core/src` returning a non-test read.
  - Organic draw bound `k` is `TJ-D`'s. This file stays in `docs/design/` while `L` is PROVISIONAL and Sub-PR 2 / SH-2 remain; the "archive when (c) pins `N`" criterion expired 2026-09-16.

- **Re-examine the C++-anchored CI gates at the LMDB cutover** — **tracked, not scoped** (2026-09-13). Eight of the 59 gates in `scripts/ci/` encode *"C++ is canonical, Rust mirrors it"*: `check_redb_schema_bijection.py`, `check_redb_schema_key_types.py`, `check_lmdb_schema_coverage.py` (+ `test_check_lmdb_schema_coverage.py`), `check_consensus_invariants.sh`, `check_levin_constant_parity.sh`, `check_segment_freeze_sites.sh`, `test_check_doc_code_citations.py`. Each is **correct now and wrong later**: at the cutover the relation inverts and they become obsolete or backwards. The bijection gate is simply first to surface it — it is symmetric (`extra = set(defined) − set(censused)`, `:119–123`), so the first **redb-only** table fails CI, which is why `PDM-Q-F14`'s `txs_pqc_auths_hash` cannot be added without a second change (**UPDATE 2026-09-16:** that first redb-only table — the undo log — landed in S-CHAIN-W with a `RUST_ONLY_TABLES` `{table: reason}` allowlist, SCW-11, so this specific blocker has expired and the row is admissible; `PDM-Q-F26`. The other seven gates stand as written). **The first redb-only table is the event that retires the mirror assumption**, and that cost belongs to the **E-series**, not to any one round that happens to arrive first — design the mirror→lead transition once at DRS-E1 and let `PDM-Q6` point at it, or it is re-derived at every subsequent redb-only table. Any in-flight exception must be **blocker-keyed, not dated**: the repo's own `DEFERRED_DOCS` shape, whose self-expiry FATAL fires when the blocker clears — *"a gate that quietly excludes what it cannot pass cannot fail"*. The natural key already exists as a genesis-gate observable: [DAEMON_REDB_STORE.md](design/DAEMON_REDB_STORE.md) §8.1, *"production `shekyld` does not link liblmdb"*. Not scoped here deliberately — the cheap moment to name the scope is while it is known which eight and why, not after the cutover when they are failing and someone is deciding under pressure whether a red is real. Falsify by `rg -l 'SHEKYL_LMDB_TABLES|db_lmdb|LMDB_SCHEMA|cryptonote_config' scripts/ci/` returning fewer than eight files, or by `shekyld` no longer linking liblmdb while those gates still assume it does.
    - Target: pre-genesis

- **E6 shaping under `PDM-Q5` / `PDM-Q3`: a below-anchor `RuleSet`, and `ChainView` without a recorded-body accessor** (`PDM-Q-F27`, `F29`, 2026-09-16; [CHAIN_RULES_CRATE.md](design/CHAIN_RULES_CRATE.md) §13, DRS-E6 row). **(1)** `PDM-Q5` band 1 — a fresh node below the release anchor `C`, skeleton only — cannot pass a proof-checking `validate`, so under DRS-D12 it has **no writer** unless `shekyl-chain-rules` issues a `RuleSet` whose `enforced` omits the proof rows; the seam exists (`RuleSet { id, enforced }`, `ISSUED`), the set does not, its selector is anchor-relative (not `RuleSchedule`), and the anchor check's home (census row vs node policy) is Q5's to rule. Owed when `ISSUED` is next touched, as a decision either way. **(2)** `PDM-Q3`'s instrument is the trait surface: no `ChainView` method returns recorded transaction bytes without a `CenRow` and an above-horizon marking (F29's "above-`W`"; `W` retired 2026-09-22) — true by construction at `645d09dc3`, held as a standing property. Falsify (1) by `rg 'const ISSUED' rust/shekyl-chain-rules/src/rule_set.rs` still listing only `GENESIS` when the read-side slice consuming `RuleSetId` from the store lands; falsify (2) by a `ChainView` method whose return type carries a `Transaction` or tx byte slice with no row named in its doc comment. Named blocker for (1): `PDM-Q5`'s anchor ruling (which rows a skeleton is held to) — the *seam* is owed now, the *set's contents* after Q5. **(3) Census consequence, same PR as (1)** (`PDM-Q-F30`, 2026-09-17): `CEN-E1` and `CEN-E2` both carry C2-R1b's *"crossing reopens when DRS/R8 moves checkpoint state"*; a Rust-held release anchor **is** that move, so F27's landing PR re-keys both rows (new site, Q2 crossing answered for a Rust-held table, C2-R0 existence HOLD closed) and retires `CEN-E1`'s dead *"JSON-loaded"* text (F23 deleted that channel). Q11's home is **`CEN-E2`** (`is_alternative_block_allowed`), not E1 — E6's unmerged `tip` note says E1; correct on land. Falsify (3) by `rg 'JSON-loaded' docs/design/CONSENSUS_RULE_CENSUS.md` matching, or by a `Trust::BelowAnchor` arm on `dev` while `CEN-E1`/`CEN-E2`'s notes still read *"trigger … not live"*.
  - Target: pre-genesis

- **Skeleton block payload grows `pqc_auth_hash`** (`PDM-Q-F28`, 2026-09-16; owner **`LV-` / `PWC-`**, not DRS-E). `tx_blob_entry { blob, prunable_hash }` (`cryptonote_protocol_defs.h:49-58`) and its KAT-pinned mirror `shekyl-levin::payload::block::TxBlobEntry` carry the one txid component a pruned receiver cannot compute; under `PDM-Q6` item 2 the skeleton also drops the `pqc_auths` slice, so a band-1 receiver needs **two** to rebuild the 4-part txid and verify the block's tx list. Entry grows an `Option`-shaped field on the identity's predicate — **one field, as first ruled** (a 2026-09-22 amendment adding two length fields was retracted 2026-09-23: `PDM-Q6` item 5 RULED shards fixed-cardinality, no lengths anywhere); the wire's two-supplied form **already landed** on #768 (`Transaction::hash_with_supplied_components`, `transaction/txid.rs`) so the receiver side is ready; a `PWC-` census row records the growth; the levin KATs move. **UNGATED 2026-09-17** — `PDM-Q6` item 2 RULED: the `pqc_auths` slice is discardable, so the field exists. Owed now by `LV-`/`PWC-`; nothing upstream blocks it. Falsify by `TxBlobEntry` in `rust/shekyl-levin/src/payload/block.rs` still carrying one hash field when `SF` sub-PR 2's per-tx verify lands, or by no `PWC-` row naming the growth.
  - Target: pre-genesis

- **Journal horizon asserted at the journals' retirement site** (`PDM-Q1` RULED 2026-09-18, [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q1; F19's "what remains owed is the check"; owner **DRS-E / S-ARCH** — *re-homed 2026-09-22 from S-PRUNE*: the seven journals have no Rust writer outside S-ARCH, so there is no retirement site in S-PRUNE to assert at; S-PRUNE mints the function, [DRS_E1_SPRUNE.md](design/DRS_E1_SPRUNE.md) §12). The seven window-retired archival journals (`PDM-Q-F16`) retire at `tip − (CRB + n·SEB + D_max)` — **a second horizon beside the body horizon by design** (Q2 re-ruled 2026-09-22; was "equal to `W`") — through one function, never a literal. **Built 2026-09-25** as `shekyl_chain_rules::journal_horizon` beside `D_MAX` (`reorg.rs`); `shekyl_archival_failure_window_params` is still the m-of-n `(m, n, serve_budget)`, not this. What remains is the assertion at S-ARCH's retirement site, when those writers land: a violated horizon is a refused retirement. Falsify by a journal row retired at a height not derived through `journal_horizon`, or by the horizon expression appearing as a literal in a second site.
  - Target: pre-genesis

- **Catalogue rows for a REJECTED post kind and a renamed one — `archival_bond_holdings_update_log` (#30), `archival_bond_unbond_log` (#29)** (surfaced 2026-09-22 by the `PDM-Q9` amendment striking `HoldingsUpdate`; owner **DRS**). `HoldingsUpdate` was REJECTED 2026-09-20 (immutable bond; FFI deleted) and `Unbond` is `Release`'s old name, yet both tables stand in the redb catalogue (`schema.rs`) and the LMDB X-macro. Rule 23: REJECTED leaves zero code symbols. Deletion is a layout bump on both stores (the ordinals after #29 shift), so it rides the next DRS layout increment rather than its own PR. Falsify by `rg 'holdings_update_log|unbond_log' rust/shekyl-chain-store/src/schema.rs` matching after that increment.
  - Owner: [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) §7
  - Target: pre-genesis

- **The archiver serving-store rebuild — a wallet-lane design round, unbuilt by design** (`PDM-Q12` amended on #775, 2026-09-18; owner **the wallet lane**). The round exists and Round 1 is ruled: [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) (family `WSS-`). What remains is the serving-store increment's gate — **narrowed 2026-09-23 (#832): two of its three blockers dissolved.** ~~Blocked on the A4 length rows (S-CHAIN-W) and on `b_*` (S-PRUNE's forward pass)~~ — `PDM-Q6` item 5 RULED shards fixed-cardinality: **there are no A4 rows, and the partition is `k = ⌊tx_id / T⌋` over `[k·T, (k+1)·T)`, which the wallet derives from `shekyl_types::storage_ids_through` (the listed total plus one coinbase per block) and `T`, not from `cumulative_tx_count` alone**. Still blocked on E4 / S-ARCH for the leaf-cluster deletion, and behind `WSS-Q1` — *one wallet store with two obligations, or two files* — which is posed and not yet ruled. **The body store keyed by `k` can start now.** The wallet lane owes its own re-key round first (rule 94 §6 — this row is the notice, not the edit): `WSS-Q4`'s deadline (*"the next epoch's open, one block away"*) is **superseded** — the pull window is the whole freeze epoch `close_epoch(k) + 1`, the pull may start at finality (`close_height(k) + D_max ≤ tip`), leaving `≥ SEB − D_max` blocks (`PDM-Q9` amended); `WSS-Q6` keys by `k·T`, not `[b_k, b_{k+1})`; §5 rows 1–2 (the A4 rows and `SHARD_BYTES` as inputs) are replaced by `T` — one const-asserted home, `PDM-Q6` item 5; §6.4's "checkable half / unexamined half" boundary argument is moot (both ends of `[k·T, (k+1)·T)` are arithmetic); `:1004`'s predicate is `discard(k) ⇔ close_epoch(k) + 2 ≤ current_epoch` (`PDM-Q2` re-ruled, `W` retired) and `:1100`'s "two A4 length rows per transaction permanently" is false; `WSS-15`'s per-shard size fingerprint keeps its conclusion but its premise moves — a shard's size is no longer `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)` but `T` transactions of whatever size, so the variance is larger and the finding's remedy should be re-read against it. `WSS-Q8`'s two-epoch pin-release gate is the lapse tail `PDM-Q9` now names as running from `Release`. `PDM-Q6`/`Q12` rebuild `shekyl-curve-tree`'s `LeafStore` around prunable bodies rather than deleting it, and PR #775 makes it *the* serving store; the charter names the substitute and, until this row, no builder. **Round 1 ruled every decision (2026-09-19, PR #790):** fill from the local daemon in the specified-to-scarce window through the ordinary split tx read, verified **against the txid** (`WSS-Q5`); keyed by shard (`[b_k, b_{k+1})` at ruling; `[k·T, (k+1)·T)` since `PDM-Q6` item 5); served **whole-shard** (`WSS-Q7` — the read; verification is per-tx and, under item 5, streams one transaction at a time); erased on the **landed two-epoch pin-release gate** (`WSS-Q8`); recovery intake on the same write-and-verify path; `CompleteTree` a configuration of the same store. Inputs cited from [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md). Falsify by `redb_backend.rs` still exposing `open_frozen_segment_body` / leaf-order streaming when `SF` sub-PR 2's per-tx `ContentVerify` lands, or by a `PersonaServing` that serves bodies from any store this row does not name.
  - Target: pre-genesis

- **`WSS-Q1`(b)'s grading run has not happened — the instrument exists, the rig verdict does not** (2026-09-20; owner **the maintainer**, because the rig is a physical machine this lane cannot reach). [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.3.4 adopts `WSS-Q1`(b) **subject to** four measurements; rows 2 and 3 are timed and now have an instrument — [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) and `rust/shekyl-wss-q1b-bench` — with the corpus, the delta/proving boundary and the rig protocol pinned. **The blocker is named and real** (rule 22): grading requires the §6.3.4 rig — a Pi 4 Model B, 8 GB, aarch64 64-bit userland, USB-SSD, thermally sustained — and the harness **refuses** to emit a verdict anywhere else. Dev-box measurement is available and is not the thing owed. **What the first dev-box run measured, and what it does not settle (2026-09-20, x86):** the worst-case replay (765 600 leaves over 725 blocks) takes **73.9 s** on a quiet box against a **1.105 s** denominator, with the graded path **verified** against its own root, so the binding threshold is the **2 s absolute floor** — the 15 % arm is 0.17 s — and the delta misses it by **~37×** on hardware far faster than the rig. (An earlier run measured 96.8 s while sharing the machine with a C++ compile; both are reported, and the 31 % swing is the concrete argument for the rig protocol's quiet-machine discipline.) Amortized, that replay is **102 ms per block** against a 120 s cadence, which is what decides whether the miss kills the design or moves the work. The direction is not in doubt even though the Cortex-A72 magnitude is, so §6.3.4 row 2's pre-registered miss response — *amortized replay first* — is the likely landing, and `WSS-Q1`(b) reopens only if the amortized form also fails. That is a measurement, not a verdict: the rig grades, and the amortized form is unbuilt, so neither the miss nor the remedy is settled here. The open edge measured **0.197 s** projected over the 790-block buffer against a 5 s threshold; its **attribution was withdrawn 2026-09-20** — the `round-trip bound` figure was a clamp artifact (the floor term exceeded the whole projection), and the harness now reports `Inconsistent` and names no remedy. See the corpus row below before reading the seconds as headroom. **Rows 1 and 4 are not this row's** — `rollback_to_fork`'s refusal semantics and the `build_layers` property tests are behavioural and ride the proving-state increment. Falsify by **two** `schema_version`-1 run records with `rig.grading: true`, one per edge, each cited from §6.3.4: the spend record at `budget.verdict` and the open record at the top-level `verdict`, both reading `pass` or `miss`. *The two schemas differ because the measurements do — the spend edge grades a ratio against a denominator and carries a `budget` object, the open edge grades an absolute and does not — and an earlier form of this row named `budget.verdict` for both, which the open-edge record can never satisfy however the rig run goes.*
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md)
  - Target: pre-genesis
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §7 — the spec that defines the run and holds its record schema. The rig verdict is still the maintainer's to produce (the Pi 4 is a physical machine this lane cannot reach); the spec is what outlives the attempt

- **The Pi 4 is the conservative interim baseline for everything; the *staker* reference class is owed, and its trigger is the settled software package structure** (doctrine recorded 2026-09-20; owner **the maintainer**, discharged at the P-store lane's cutover decision). **The doctrine:** rule 76's [Raspberry Pi 4 floor](../.cursor/rules/76-device-provisioning-floor.mdc) is the absolute conservative baseline for **all** provisioning — works-there-works-anywhere — and that is the right call to make by default. **The annotation that keeps it honest:** for **serving-path** design the Pi is a deliberate **over**-conservatism, not a deployment recommendation. An archiver runs a bonded persona with a Tor service and multi-gigabyte holdings; nobody is claiming that box is a Pi. Budgeting against one anyway is conservative and correct; what was stretched is the **authority cited**, since rule 76's floor is argued from the privacy charter (everyone must be able to run a node, so the floor is a mission commitment) and a staker's box is not that argument's subject. **So the re-grounding is a change of word class, not of design** — *"conservative interim baseline, staker class TBD"* in place of a bare rule-76 citation — applied **at next touch**, not as its own sweep, at: `shekyl-p-fetch/src/client.rs:45` (*"`8 × ~6.7 MB ≈ 53 MB` on the Pi 4 floor (rule 76)"* — the only one that names the rule), and `shekyl-sp-t3-spike/bins/pd_f2_measure.rs:40`, `:145` and `:180`, which read the Pi as the memory fit the `SF-D7` pin is taken against. The numbers stand; only their warrant moves. **The TBD, with a trigger that will arrive on its own (rule 21 shape):** the staker reference class is owed **when the final software package structure is settled**, because *what one box runs is what sizes the box*. Today an archiver's box runs `shekyld` plus the wallet process — `StakeEngine`, the serving task and Tor all co-resident. The Tier 2 `P`-store lane ([WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.2, §6.7) and the C++→Rust cutover together decide whether that co-residency is the shipped shape or whether `P`'s serving splits out. The moment that is settled the class is named **against a known load**, so the reference hardware is a **measurement, not a guess** — which is exactly the discipline that produced the Pi floor in the first place, applied at the staker tier once the machine has a job description. **Rides this row's discharge:** rule 76 gains a scope clarification separating the universal node floor from a staker reference class. Deferred deliberately — nothing needs it sooner, and writing it before the class has a load would invent the number the trigger exists to measure. Falsify by `rg -n 'Pi 4' rust/shekyl-p-fetch rust/shekyl-sp-t3-spike` returning a site that still cites rule 76 as the warrant for a serving-path budget after that file's next substantive edit, or by a named staker reference class existing anywhere while this row is open.
  - Owner: [`WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §6.2
  - Target: pre-genesis
  - Owner: [`WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §6.3.4 — where the rig pins are stated; the doctrine discharges at the P-store lane's cutover decision, which that section's questions carry

- **The open-edge bench has no corpus with realistic block weights, so its volume term is untested rather than measured** (2026-09-20, found by running it; owner **the `WSS-Q1`(b) bench**, [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) §7.2). The first live run against `shekyld --regtest` projected **0.197 s** over the 790-block buffer against a 5 s threshold. **Its `round-trip bound` attribution has been withdrawn** (2026-09-20): it came from clamping `floor × round_trips` to the total, and at the measured values the floor term *exceeds* the projection, so the clamp manufactured a 100 % round-trip share out of two instruments disagreeing. What survives is the **measured** half — `2.0` round trips per block, read from each block's shape — which is the empirical support §6.3.4 row 3's amendment actually needs. It does not go far enough to read as headroom, for a reason the record states in its own numbers: **regtest blocks are coinbase-only**, so the fetch makes exactly `2.0` round trips per block instead of three (`get_transactions` is never called), and each block carries **1 432 B** decoded. A worst-case block is three orders of magnitude larger and pays the third call, so the measured attribution is as much an artifact of an empty corpus as a finding about the path. **What is owed:** a regtest corpus whose blocks carry non-miner transactions at realistic weights, which coinbase mining cannot produce — it needs a wallet spending into the blocks, the machinery `fcmp_spend_e2e` and the regtest e2e suite already have. **The harness no longer lets a thin corpus read as a pass:** `open_edge` measures the sampled blocks against the graded density and **withholds its verdict** below half of it, so the live run reports *"1432 B/block measured vs 300000 graded (0.5 % — TOO THIN TO GRADE)"* instead of 0.19 s and a green tick. **What the corpus is now for (amended 2026-09-20 with `WSS_Q1B_BENCH_SPEC.md` §4.4's density ruling):** not to grade the adversarial window — that is an accepted rule-80 long-tail, because 790 blocks at the 2 400 000 ceiling is ≈ 1.9 GB decoded and no hardware refetches it in 5 s — but to **locate the crossover**: the per-block density at which the 5 s budget stops holding. The ruled grading point is the full-reward zone (300 000 weight, ≈ 237 MB over the buffer, ~47 MB/s decoded), chosen because the measurement there can still surprise; the crossover says how much margin that choice actually has, and is the evidence that would reopen the nominal under rule 21. Falsify by an `open_edge` record whose `projected_round_trips / blocks_projected` is 3.0 and whose `density.sufficient` is true, or by a recorded crossover density.
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §7.2
  - Target: pre-genesis
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §7.2 — the bench's own spec; the untested volume term is a gap in its corpus, not in a consumer

- **Lift the "grade where the measurement can still surprise you" criterion out of the `WSS-Q1`(b) bench spec once a second bench needs it** (2026-09-20; owner **whichever bench picks a corpus point next**). [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) §4.4 states it in general terms with its checkable shape — a table showing both rejected rungs are foregone — but it lives in a **lane** document, where a future bench author has no reason to look. **Deliberately not minted as a cursor rule now** (rule 21, and the reason is rule 15's): a rule with one instance has no oracle, and this criterion has been applied exactly once. **Trigger, and it will arrive on its own:** the next bench that must choose a corpus point, input size or load level either cites §4.4 — in which case the criterion has two instances and earns a home that is not a lane doc — or does not, in which case the miss is the evidence that it needed one. Ratified as the general form by the maintainer 2026-09-20, above the UX argument that originally selected the same value. Falsify by a second bench citing §4.4's criterion, or by a numbered rule stating it.
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §4.4
  - Target: pre-genesis
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §4.4 — the criterion's current home; it lifts out of this doc when a second bench needs it, and until then this is the doc that states it

- **Standing lesson, home unresolved: a gate that exists but does not bite its graded subject** (ratified 2026-09-20 on three instances; owner **the maintainer**, because the ledger is outside this repo). **The defect class:** the gate is real, the test is real, review signs it off — and the artifact whose correctness the verdict rests on is untouched by any of it. **Three instances, all in the `WSS-Q1`(b) bench, all found by its own author auditing what the claims rested on rather than by review:** the `--grade` rig refusal enforced arch, userland and RAM while `cpu_model` was captured and never compared, so any aarch64 host with 7.5 GB passed as the pinned Pi 4; `prover_pin.revision` compiled as `None` and its `.git/HEAD` watch named nothing in a worktree, where `.git` is a file; and the `proof::verify` red-bite covered the control arms and the depth-3 unit tests while `proof::verify` appeared **nowhere** in either binary, so the depth-6 graded path went unchecked and `paths_verified` came from `prove()` returning. **Why it survives review:** each looks like coverage from outside — there *is* a gate, it *does* pass — and the subject it misses is invisible from the gate's own side. **The test that catches it at birth, in one sentence:** *point at the graded artifact and ask which check touches **it**, by `file:line`* — not "is there a check", but which check on which object; an answer naming a sibling (the control arm, the fixture, the crate version) is the defect. **Two follow-through disciplines that make a fix hold:** *refuse, don't annotate* (an unverified graded path produces no record; a failed byte read produces no bytes, not `(0, 0)` — so a clean exit means what a reader assumes), and *keep the claims separate* (verification earns *well-formed*, a control earns *cost-equivalent*; good news must not launder an adjacent claim). It generalizes the tautology-gate note — a gate surviving as a tautology displays green forever — and is the bench-side twin of a map row asserting a state the territory left. **In-repo home if it graduates:** [`47-gate-subject-assertion`](../.cursor/rules/47-gate-subject-assertion.mdc), which today says a gate must assert its **subject exists**; this adds that the subject must be the **graded** one. Not minted as a rule edit here — the cursor rules are the maintainer's, and the same deferral applies as to rule 76's scope clarification. Falsify by the lesson appearing in rule 47 or in whatever artifact the citation row below resolves `principles-and-learnings` to.
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md)
  - Target: pre-genesis
  - Owner: [`WSS_Q1B_BENCH_SPEC.md`](design/WSS_Q1B_BENCH_SPEC.md) §6 — **an interim carrier, not the lesson's home.** The three instances were found here, and this row's subject *is* that no lessons ledger exists in-repo to own it; it moves the moment one does

- **`principles-and-learnings` is cited as a genesis-frozen authority and resolves to nothing** (found 2026-09-20 while filing the lesson above; owner **the maintainer**, because only they know the referent). [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md):1137 — and its copy at [ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md](completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md):2365, both introduced 2026-09-12 — open §4 *"Do not re-derive: read, cite, build on"* with **"Genesis-frozen decisions in `principles-and-learnings` and the consensus census."** **The list has seven entries; six carry working links to real documents. This one is the exception, and it covers the highest-stakes category in it.** `principles-and-learnings` exists nowhere in `shekyl-core` (no file, and **no deletion in git history** — it was never here), nor in `shekyl-dev` or `shekyl-web`. Its sibling in the same sentence, *the consensus census*, does resolve — `CONSENSUS_RULE_CENSUS_1/2/3.md` — it is merely unlinked. **Why this matters beyond tidiness:** a reader is instructed **not to re-derive** these decisions and is sent to an authority they cannot open, which is the one instruction that cannot be followed safely — the alternative to reading it is re-deriving it, which §4 exists to forbid. **Not repaired here, and the blocker is named** (rule 22): the referent is unknown to this lane. The name reads like a Cursor-side memory or rules artifact rather than a repo document, in which case the fix is to say so at the citation — an external authority named as external is followable, a broken repo link is not — or to replace it with the in-repo document that actually holds the genesis-frozen decisions. Guessing between those would mint a wrong citation in a ruled charter. Falsify by §4's first bullet naming an artifact a reader can open, or by `principles-and-learnings` existing at a stated path.
  - Owner: [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) §4
  - Target: pre-genesis
  - Owner: [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) — the document carrying the dangling citation; the referent is the maintainer's to name, but the broken cite lives here and the fix lands here

- **RULED BY MEASUREMENT 2026-09-22 — Windows exposes no per-process socket ceiling, so UNKNOWN there is a CORRECT report, not an unimplemented port. macOS remains a port.** `--in-peers` unset is a Rust decision (`InboundCeiling`): POSIX `getrlimit`, a Linux `/proc/self/fd` count, and a named no-per-process-ceiling on Windows. A soft limit of zero is a ceiling of zero. An unreadable limit or count, an unlimited rlimit, or headroom past the admission counter is unbounded, and the daemon warns with that reason rather than substituting a number. **Measured natively on Win11 23H2 (10.0.22631.7517), MSVC, by the Windows seat:** a single process opened **200,000 sockets with no failure and no error** — the loop stopped at the harness's array cap, not at a refusal. **`_setmaxstdio` is unrelated in both directions**: run 1 passed 200,000 with the CRT limit at its 512 default, and raising it to 8192 produced an identical count. Handles tracked sockets 1:1 (100,000 sockets → 100,724 handles, returning to 723 on close). **So there is no per-process quantity to read**, and the helper returning 0 reports the platform accurately. **The Windows warning now says so** — *"exposes no per-process descriptor limit"* rather than *"cannot read"*, because a failed-read framing would send the next maintainer hunting for an API that does not exist; the non-Windows arm keeps the failed-read wording, since there it is true. Both arms now also name the risk (*"will accept inbound peers without limit"*), since *unbounded* reads as generous rather than as absent to anyone without this row's history. **A CORRECTION TO THIS ROW'S OWN DECODING TABLE, and it would have produced a false finding.** The probe brief said *"`WSAENOBUFS` (10055) → non-paged pool, a SYSTEM resource."* **On the measured box that was wrong.** A connected-socket run failed at 15,306 with `WSAENOBUFS`, exactly as predicted — but instrumenting instead of reading the error off the table showed non-paged pool had moved **8.5 MB across 15,310 connections (~580 B each), with 2.6 GB already in use and 35 GB RAM free**, nowhere near exhaustion, while **15,422 of 16,384 ephemeral ports were consumed (94%)**. The error was the **client** side running out of source ports. Taking the table at face value would have filed *"system pool bounds connections at ~15k"* — a loopback artifact that says nothing about inbound capacity. **A loopback test cannot measure inbound capacity at all**, because every connection burns a local ephemeral port; an accepted socket's uniqueness comes from the remote side, so inbound consumes none. **This also rules the `MaxUserPort` question: the dynamic range bounds OUTBOUND, not inbound.** **And it invalidates loopback as an instrument for this class of question on EVERY platform, not just Windows** — an accepted socket is distinguished by its remote endpoint, so accepting consumes no local ephemeral port, but with both sides on `127.0.0.1` the client's range binds first and nothing about accepting is exercised. Recorded in the rig's own header (`inbound_cost_bench.rs`) so the next person sweeping it does not read a port stall as a daemon property; the ranges are ~28k on Linux and ~16k on Windows, and a real capacity measurement needs multiple source addresses. **Dispositions, with what was measured versus read marked as the seat marked it:** CRT stdio limit — **ruled out, verified both directions**. Ephemeral ports — **outbound only, verified**. Non-paged pool — real but very distant (~580 B per established connection, measured), and **system-wide rather than per-process, so it cannot yield a per-process ceiling**. Per-process handle table — not reached at 200,000; the commonly cited ~16M figure is **unverified and not asserted**. Desktop heap — **not tested, no guess offered**. **Scope, stated as the ruling rather than as a footnote: this is "no per-process ceiling ON THIS BUILD", not "on Windows."** One machine, one build (Win11 23H2 10.0.22631.7517, client SKU). **Server SKUs differ in non-paged pool sizing and sometimes in dynamic-port configuration**, so a Server measurement could move the distant bounds even though it is unlikely to mint a per-process ceiling that does not exist on client. Neither `MaxUserPort` nor `TcpNumConnections` was set on the measured box — both at OS defaults — so a deployment that sets them has not been measured either. **CONSEQUENCE — this promotes `PWD-B1`.** With no *count* available on a shipped platform, a **rate is the only inbound bound Windows offers**, which moves the token bucket from a policy refinement to the only available mechanism there. That is a materially stronger claim on B1's priority than the framing it carries today, and B1's row should inherit it. **STILL OPEN:** *(a)* **macOS is a port and remains one** — `getrlimit` works; only the descriptor count needs `proc_pidinfo` / `PROC_PIDLISTFDS`. *(b)* **The Windows daemon warning has not been read on a running daemon** — experiment 3 did not run, because that box has no `cmake`/`ninja`/`make` and the seat correctly declined to install a toolchain without authorization. The wording above was reviewed against the source at `64aec6be3`, `net_node.inl:647`, and judged to read as a stated limitation rather than a bug; seeing it fire on a live Windows daemon is still owed. *(c)* Offered and not taken up: a desktop-heap arm, and a multi-source-IP run to push past the 16k loopback ceiling and put a real number on concurrent **accepted** sockets.
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I7
  - Target: pre-genesis

- **The inbound-cost rig has an unexplained ceiling at 119 of 128 requested peers, reproducible across two dissimilar machines.** `rust/shekyl-levin/tests/inbound_cost_bench.rs` requested 128 simulated inbound peers and held exactly **119** on both arms: x86-64 (i9-11950H, binary `sha256:b6ef828bff7be8ba…`) and aarch64 (Pi 4 Model B, binary `sha256:56581fd3930fae10…`), both built from the tree at `ae88638d7`. **It is not the per-host cap** — verified directly in both binaries: the refusal string and the `has_too_many_connections` symbol are absent, and the one `max-connections-per-ip` string is the `REMOVED_FLAGS` retirement row. **It is not `--in-peers`**, which resolved to `UINT32_MAX` on those runs. **Identical on two machines with different core counts, memory hierarchies and architectures rules out timing and resource pressure and points at something structural** — in the harness's peer threads, or in the connection path itself. **Not chased**, because it does not move the slope the measurement's conclusion rests on (per-connection cost, which the marginals compute against the *live* count, not the requested one). **A CANDIDATE CLASS, now demonstrated rather than hypothesised:** *the harness constrains the measurement in a way unrelated to the daemon.* On 2026-09-22 a loopback run on Windows stalled at 15,306 with `WSAENOBUFS`, and the cause was the **client's** ephemeral-port range (15,422 of 16,384 consumed) rather than the buffer exhaustion the error names — an instrument artifact that would have been filed as a daemon property. **Source-port exhaustion is the wrong magnitude for 119 and is NOT this cause**, but the class it belongs to is no longer speculative, and the harness — peer threads, per-thread sockets, a 500 ms read timeout, `is_finished()` as the liveness test — is where to look first. **Recorded so the next person to reuse the rig starts from the observation rather than rediscovering it as a bug.** Discharge by naming the mechanism, or by the rig reporting a per-peer failure reason instead of a bare count.
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I7
  - Target: pre-genesis

- **CLOSED 2026-09-22 — the per-host inbound cap is DELETED.** The mechanism, its flag, its Rust policy and its four FFI exports are gone; `is_host_limit` is the total-ceiling check and nothing else, and `--max-connections-per-ip` is retired by name in `REMOVED_FLAGS` so a config still carrying it gets a named message rather than a parse error instead of starting. **Any deployment running an explicit value can return to the derived bound**; where such a value was a time-boxed divergence, this landing is its expiry condition. The residual is the `--in-peers` ceiling, which resolves to `UINT32_MAX` at the default and is **owed a measurement, not a ruling** (row below). *Records-was: the open row, its measurement and its falsifier run, are the record of the incident and move to [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I7.*
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I7
  - Target: pre-genesis
- **`--in-peers` resolves to `UINT32_MAX` at the shipped default, so the inbound ceiling never fires — a MEASUREMENT is owed, not a ruling.** `arg_in_peers` is an `int64_t` sentinel `-1` ([`net_node.cpp`](../src/p2p/net_node.cpp):181) assigned into a `uint32_t max_in_connection_count` ([`p2p_protocol_defs.h`](../src/p2p/p2p_protocol_defs.h):113), compared against an unsigned counter at ([`net_node.inl`](../src/p2p/net_node.inl):234). It became load-bearing on 2026-09-22 when the per-host cap was deleted and this became the only inbound bound. **The target property is descriptors and memory — directly observable — so this is a rule-76 floor measurement (Pi 4), with [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md) §80.7's minimum spec and §80.4's two-arm methodology as the precedent.** §80.4 also names the trap: deriving against typical rather than floor hardware reintroduces hardware-sorted anonymity, and a ceiling tiered by device class makes inbound degree a proxy for a node's hardware. **Two things the measurement must price beyond steady-state RSS:** a **second of accepts**, because the counter is refreshed by a `foreach_connection` recount on a one-second sleep ([`net_node.inl`](../src/p2p/net_node.inl):1111) and that staleness was inert only while the ceiling was unreachable; and **startup peak**, which Q12-R14 measured at ~2x steady-state RSS. **Two numbers, not one** — the shipped default is a floor-device value, and any deployment may override it in config. **MEASURED on both arms 2026-09-22, and the answer is that memory does not bound this ceiling.** Rig: `rust/shekyl-levin/tests/inbound_cost_bench.rs`, `#[ignore]`d, identical `STEPS` on both machines so the cross-machine ratio means something (rule 76 item 3). **Floor arm — the rule-76 floor device (Raspberry Pi 4 Model B Rev 1.4, aarch64), daemon built on it (rule 76 item 4):** baseline `VmRSS` 329,220 KiB; **119 live inbound connections cost 360 KiB in total**, marginal decaying 18.5 → 1.5 → 0.8 → **0.2 KiB** across the sweep — i.e. a quiescent inbound connection is free in RSS on the floor device. **Dev arm — i9-11950H:** baseline 294,756 KiB, 119 connections cost 10,828 KiB, marginal ~81–115 KiB. **Ratios:** baseline 1.12, **peak 1.002**, per-connection total **0.033**. **The two-arm method earned its keep here: the dev arm's per-connection figure does not reproduce on the floor** (30x apart while baseline and peak agree within 12% and 0.2%), so that figure was measuring something that scales with the host — plausibly glibc arena count against core count — rather than connection state. Provisioning against it would have set a network-wide ceiling from an artifact of the measuring machine, which is precisely what rule 76 item 3 exists to catch. **And `VmHWM` is ~539 MiB on BOTH machines, flat across the sweep** (1.68x baseline on the Pi, 1.87x on x86), corroborating Q12-R14's ~2x independently: **the daemon's memory constraint is STARTUP, and it is connection-count independent.** **RESOLVED 2026-09-22 — the safety bound is DERIVED, not picked, and it landed.** The measurement re-pointed the derivation rather than deferring it: two ceilings were being conflated. **The SAFETY bound** — *do not exhaust the process* — is a Rust decision (`shekyl-peer-policy::InboundCeiling`, probed by `shekyl_inbound_ceiling_resolve`): POSIX `getrlimit`, a Linux `/proc/self/fd` count, minus descriptors the daemon has already promised (outbound caps, explicit non-public inbound caps, and the RPC connection budget once those listeners are up). Admission counts live connections, because the once-a-second counter is not the check. **It varies per deployment, which is correct** — it states a fact about one machine, not a network policy — and **nothing is guessed, so no ruling is owed.** Verified live on that arithmetic before the RPC budget joined the reservation: `1024 - 12 - 12 = 1000`, and a raised `ulimit -n 4096` gives `4072`. An explicit `--in-peers` still bypasses the derivation entirely, so `0` remains a legal operator choice distinct from the sentinel. A soft limit of zero is a ceiling of zero. An unreadable limit, an unreadable count, an unlimited rlimit, a platform with no per-process ceiling, or headroom past the admission counter is unbounded: the daemon warns with that reason and does not invent a number. **What remains is the POLICY ceiling and it is a real open question, not a missing measurement:** how much inbound service a node *chooses* to provide below the safety bound. Memory cannot set it (above). The one candidate that could justify a lower number is CPU/bandwidth per connection under load — but note its shape: **that is a RATE, and a rate is bounded by PWD-B1's per-connection token bucket, which is already ruled and unbuilt.** So the policy ceiling may well resolve to *"there isn't one, there's a rate limit"* rather than to a value. **Owner: PWD-B1's row, not this one.** Observation worth a second look by whoever takes that up: both arms held exactly **119 of 128** requested peers, a reproducible drop that is not explained by `--in-peers` (UINT32_MAX) and was not chased here. Falsify by a shipped default that is still the `-1` sentinel when the next p2p slice opens.
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I7
  - Target: pre-genesis
  - Target: pre-genesis
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) **PWD-I7** (the mechanism and its Rust-owned seam) and **PWD-I8** (the accepting-side category the cap is mis-answering, routed to its own round 2026-09-21) — per-host inbound admission, minted 2026-09-21 for this finding and carrying its anchors, pricing and falsifier. *(Re-pointed from "cluster I": a cluster is not an owner — the recorded reason PWD-B11 was minted for PWC-D9.)* The adjacent **outbound** cap's execution record is [`P2P_HANDSHAKE_ADDRESS.md`](design/P2P_HANDSHAKE_ADDRESS.md) §1 job 3

- **A compiled-in seed that goes unreachable costs every node a connect-failure and a flat 3600s suppression, and nothing on the fleet notices.** Observed 2026-09-21: `seedeu` (45.77.66.189) was closed on `12021` from five independent vantage points while its daemon was **active and bound to `0.0.0.0`** — every host-side health check passed throughout. It has since **recovered**, so the cause was a transient provider outage and not the standing misconfiguration first inferred; **the impact claim survives the cause being corrected**. It also **composes with the sibling row**: a dead seed costs a partition slot *and* an hour of suppression, so the reachable set shrinks twice from one outage. **What is owed is DETECTION, not a firewall fix.** Related: three systemd unit conventions are live on the fleet (`shekyld-testnet.service`, `shekyld.service`, `shekyld-testnet-rpc.service`), so a health check keyed on one name reports a running daemon as down — which happened during this survey. **The survey data and the sampling lesson are in the owning plan doc** (PWD-I7, fleet survey). Falsify by a fleet probe finding every compiled seed reachable from off-fleet, or by any existing alarm having fired on this.
  - Target: pre-genesis
  - Owner: [`P2P_3_IMPLEMENTATION_ROUND.md`](design/P2P_3_IMPLEMENTATION_ROUND.md) — fleet reachability is the round's operational surface; PWD-I7's falsifier is blocked on it, since a dialled-but-dead seed runs an independent 3600s clock inside the channel that run measures

- **A refused inbound connection is charged a flat 3600s public-zone window whose own justification does not describe this failure class.** Sibling of the row above: that one explains the partition, this explains why a starved node stays starved. A per-IP refusal destroys the connection *after* TCP succeeds, so it is a **handshake** failure ([`net_node.inl`](../src/p2p/net_node.inl):1561, :1619 — not `:1549`/`:1609`, the connect-fail arms), and `failed_addr_cache::window` ([`net_node.h`](../src/p2p/net_node.h):239-240) returns the flat hour on the FIRST failure. The constant's justification ([`cryptonote_config.h`](../src/cryptonote_config.h):197-201) is *"a failed dial usually means a down host"* — false for an accept-side refusal. The selector's own premise ([`net_node.h`](../src/p2p/net_node.h):221-225) is *"a property of the TRANSPORT, not of the peer"*, and a per-IP refusal is a property of the peer **pair**. `record_addr_failed` ([`net_node.inl`](../src/p2p/net_node.inl):1642) takes an address and nothing else, so the class is known one line above the call and discarded crossing it. Anchors pinned to `dev` `059aca264`. **Not fixed, blocker named** (rule 22): the anon 240s cites a measurement, the public hour asserts one, so a refusal-class window is a **new number needing its own derivation** (rule 76). Falsify by a refused node re-reaching the same seed inside 3600s.
  - Target: pre-genesis
  - Owner: [`Q12_D6A_PEER_DISCOVERY_RUN.md`](design/Q12_D6A_PEER_DISCOVERY_RUN.md) — owns the failed-address window family (it ruled `P2P_ANON_FAILED_ADDR_FORGET_SECONDS = 240` from measured p90 recovery); the public-zone counterpart is the same mechanism and the same instrument

## Post-genesis

Exceptional deferral with a named blocker. This list stays tiny.

- **Hardware-offload wallet capability.** Signing offload to a hardware device, as a wallet capability. Named blocker: no vendor ships firmware that signs hybrid ML-DSA-65 + Ed25519 over FCMP++ witnesses. Zero code exists by design (rule 23 DEFERRED): the v1 envelope layout will be designed against a real device, not guessed in advance. Unused v1 capability bytes are RESERVED in [`WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) without naming this feature.
  - Target: post-genesis

- **PQC multisig hardware-wallet integration / BIP-39 derivation parity.** Named blocker: vendor SDK availability and outreach; `HARDWARE_WALLETS.md` authoring is the prerequisite.
  - Target: post-genesis

- **`monero-oxide` un-pin / 40-commit upstream merge.** Named blocker: the vendored pin is intentional at genesis; Operation B is not a launch dependency (`MONERO_OXIDE_VENDOR_STATUS.md`).
  - Target: post-genesis

- **Offline schema-aware prune/copy tooling (rule-21 reversion clause).** `shekyl-blockchain-prune` retired (inert since LMDB v6: version guard pinned at 5; copy list held 16 of 49 tables). Reopen on post-genesis operator demand that `shekyl-mdb-copy -c` after the daemon's own (uniform, `PDM`) discard cannot serve, or when S-PRUNE reaches execution in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) — then rebuild in Rust with the table set derived from the schema source of truth, never hand-maintained (precedent: the `SHEKYL_LMDB_TABLES` X-macro, rule 47).
  - Target: post-genesis

- **Horizontal scaling via stateless actor pools / signed actor-patch over staker P2P.** Named blocker: no production load or staker P2P distribution surface at genesis; not a lattice/V4 item.
  - Target: post-genesis

- **Transaction replacement / fee-bump (RBF/CPFP-equivalent).** Named blocker: fee-bump only matters under fee competition, and genesis launches on the adaptive floor with empty mempools; the submit lifecycle already keeps a stuck transaction funds-safe (terminal-reject prune/resubmit is the cadence driver's leg 4). Reopen on observed stuck-transaction incidence on the live network.
  - Target: post-genesis

- **MFA / hardware-token integration for wallet file decryption.** Named blocker: same vendor/device class as the hardware-offload deferral above — no token decision exists to design against, and the wallet file already ships Argon2 passphrase encryption at genesis.
  - Target: post-genesis

- **Wallet on network filesystems (NFS / SMB): advisory lock + atomic-rename semantics.** Named blocker: lock and rename guarantees are filesystem-implementation-specific and need real deployments to test against; no pre-genesis user has network-filesystem wallet state to protect.
  - Target: post-genesis

## V4

Lattice-only transition, 2–5 years, gated on NIST (or successor) actually
approving primitives such as lattice threshold signatures.

- **Lattice-only spend / drop hybrid classical half** once a NIST (or successor) lattice signature and (if needed) lattice threshold scheme are actually approved and implemented. Not a parking lot for unrelated work.
  - Target: V4
