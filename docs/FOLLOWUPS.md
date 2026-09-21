# Follow-ups

Open residue only. Per `.cursor/rules/95-documentation-lifecycle.mdc` and
`.cursor/rules/15-deletion-and-debt.mdc`, every item is a one-liner with a
`Target:` of **pre-genesis**, **post-genesis**, or **V4**. Essays live in the
owning plan doc. Resolved items are removed — git history is the archive.

Acceptances that are not work items: [`audit_trail/FOLLOWUPS_ACCEPTANCES.md`](audit_trail/FOLLOWUPS_ACCEPTANCES.md).

There is no V3.1 / V3.2 / V3.x release train.

## Pre-genesis


Default. Lands before genesis if it should exist at launch.

- **Propagate the immutable-bond ruling through the `HoldingsUpdate` documentation surface — 151 matching lines across 25 living documents** (measured at `dev@91705e5882`, before this PR's own additions; 214 lines / 35 files including records-was documents, which are **not** in scope). The ruling (2026-09-20, [`V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md); mechanics and deletion set in [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3) fixes a persona's holdings set at the bond post, which makes every doc sentence describing an in-place holdings change wrong in substance rather than merely stale. **Method is PDM-sweep discipline — re-derivation, not find-and-replace:** a sentence that says *"the operator adds shard `k`"* is not repaired by renaming the mechanism, because the event it describes no longer exists; each site is re-derived against rotation, or deleted with its subject. The figure above derives from a count of the matching lines at a stated pin, not from a prior figure, and is expected to move as the deletion set lands. *(The handoff that ordered this row carried 138; the difference is scope, not drift — state the pin and the inclusion rule when re-counting.)* **Owner: the archival bond lane** (the `PSL`/`P2B` surface), which owns §5.3.2's deletions and should sweep the prose with them rather than ahead of them. **The recording PR deliberately did not attempt this.** Falsify by `grep -rc HoldingsUpdate docs/` reporting only records-was documents (`docs/completed/`, `CHANGELOG.md`, and this log's prior entries).
  - Target: pre-genesis

- **Measure the market pull latency for a fresh shard, now that no operator can incrementally add one.** The immutable-bond ruling leaves new-shard coverage **market-pulled**, with the Foundation complete-tree floor as backstop — so a newly frozen shard is covered when some operator next rotates or bonds, never by an existing persona adding it. This is the one place the ruling has a measurable open question rather than a settled answer: **one `shekyl-economics-sim` row** measuring how long a fresh shard waits for market coverage under the rotation-only path, against the floor that is meant to make the wait survivable. Named in [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §5.3.3. Note the ruling claims **no** credit against TJ-7 (sybil-per-shard), which is orthogonal and separately owned. Falsify by the sim carrying a fresh-shard pull-latency measurement with a stated backstop comparison.
  - Target: pre-genesis

- **Delete `get_version`'s `target_height` zero-sentinel at the wire boundary.** `shekyl-daemon-rpc/src/methods.rs:138` writes `if tip.synchronized { 0 } else { tip.target_height.to_raw() }`, overloading a height field to carry a second fact. **This is a wire-surface wart, not a contract change:** `ChainTip` (`rust/shekyl-daemon-rpc/src/chain_facts.rs:53-56`) already models it correctly — a raw `target_height` beside a separate `synchronized` bool — and its own doc already disclaims the sentinel as *"the handler's"*. The sentinel survives only where the POD is flattened into `GetVersionResponse`. **Owner: the daemon-RPC surface's lane** (`RK-`), [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md), whose gate obligations this carries — a JSON-RPC response-shape change, not the wallet's. **Discharge condition:** when it lands, `SyncedChainFacts`'s sentinel arm has nothing left to absorb and the constructor collapses from `synchronized && (target_height == 0 || height >= target_height)` to the flag alone (`rust/shekyl-engine-core/src/engine/daemon/synced_chain_facts.rs`, PR #792, ratified 2026-09-19). Note the wallet's constructor reads **`get_info`**, which has no Rust handler yet, so this deletion does not by itself reach the wallet — the two move independently and the conjunction retires when `get_info` migrates. Falsify by `rg -n 'synchronized \{ 0 \}|if tip.synchronized' rust/shekyl-daemon-rpc/src/methods.rs` returning nothing.
  - Target: pre-genesis

- **The claim-source reply should carry the hash of its own gather tip, so a vouched record needs no bracket.** `get_archival_emission_claim_source` (`src/rpc/archival_claim_source.cpp`) gathers `chain_height` and the record from one `db.height()` read but reports only the height, so the wallet cannot tell **which** chain the record was gathered on. PR #792 closes the reorg-across-the-witness hazard with a bracket — `SyncedChainFacts::bracket` re-reads the block at the witness tip *after* the record and refuses a witness whose block was replaced (`rust/shekyl-engine-core/src/engine/daemon/synced_chain_facts.rs`, minted only in `fetch_vouched_claim_source`). **Two residuals remain, named on `bracket`:** a chain that leaves the witness block and returns to it inside the two-RPC window, and blocks *above* the witness tip that arrived inside the window, which the record may carry and the identity does not cover — so an absence first seen by such a record is stamped at the witness tip, up to that many blocks before it was observed, which is the release-early direction, bounded by one RPC window. Both close only at the source: the reply carrying `top_block_hash` beside `chain_height` from the same read, decoded into `EmissionClaimSource` as a `BlockHash`, after which the bracket's third round trip is deleted and the record vouches for itself. **Owner: the daemon-RPC surface's lane** (`RK-`), [`DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md) — a JSON-RPC response-shape change with that lane's gate obligations, the same class as the zero-sentinel row above. Falsify by `rg -n 'top_block_hash' src/rpc/archival_claim_source.cpp rust/shekyl-engine-core/src/engine/emission_source.rs` hitting on both sides.
  - Target: pre-genesis

- **Count-versus-height: height-semantics Phase 2b retyped the dispatch clock; Phase 2c/2d remain.** Census has no unclear family; wire table and inland/wire convention are in [`HEIGHT_SEMANTICS.md`](design/HEIGHT_SEMANTICS.md) §3. Phase 2b: `daemon_claimed_tip` / `BlockSource::tip_height` / `anchor_t0` / due / alarm / dispatch `at` are `ChainCount` (no numeric change; pending-post schema v11). Remaining: Phase 2c wire/FFI decode and Phase 2d inland bare-`u64` tail, each with `compile_fail` per new conversion boundary. Falsify 2b by `daemon_claimed_tip` returning anything but `ChainCount`. Falsify Phase 1 by a `daemon_claimed_tip` consumer missing from that table, or a consumer whose protocol quantity is ordinal and whose stamp is compared to a count from a different clock. Filed from PR #792 as the **third instance in a week** of a count read as a height (`WSS-24`'s producer-side conversion, #792's own fixture answering `get_info` with a tip where a count was required, and this wrap) — which is why the order is walk-then-retype and not a bare newtype.
  - Target: pre-genesis

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

- **Delete or justify `tx_extra` 0x0A (`PQC_SPEND_AUTH_PUBKEYS`) — it has no producer.** Found at the C2-R2 signing round (Rick, verified at source): declared (`src/cryptonote_basic/tx_extra.h:48`, `rust/shekyl-wire/src/tx_extra.rs:50`), parsed (`tx_extra.rs:233`), picked (`src/cryptonote_basic/cryptonote_format_utils.cpp:540`) — and nothing anywhere constructs the field; the only write arm is the codec's generic `write_blob` branch. A parse surface with no producer is rule-15 debt and a fuzzing surface for free. Rule 15: delete at the port, or record the future producer that justifies it. — [`CONSENSUS_C2_R2_WEIGHT_FEES.md`](completed/CONSENSUS_C2_R2_WEIGHT_FEES.md) Q10
  - Target: pre-genesis

- **`tx_extra` `0x0B` (archival attestation) has a consensus reader and no producer.** `parse_archival_attestation_from_extra` decides `headers_readable` for attestation verification (`blockchain.cpp`), and `shekyl-wire` models the tag, but the only caller of `add_archival_attestation_to_tx_extra` is `tests/unit_tests/archival_credit_wire.cpp` — no coinbase construction path emits one. This supersedes the earlier entry that grouped `0x0B` with the inherited merge-mining and minergate tags as "no producer found" and slated all three for deletion: that reading was wrong twice, in attributing the `0x03` emission to `get_block_template` (it was `on_add_aux_pow`) and in treating a missing *producer* as evidence of dead code when a live *reader* existed. `0x03` and `0xDE` are now deleted; `0x0B` is kept. **Blocker (rule 22):** the producer cannot be wired before the entry below — attestation verify must move behind PoW before credit-wire population activates — because a coinbase that actually carries pass records is what turns that pre-PoW verify from free into a DoS surface. The producer lands with, or after, that reordering (owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md); census: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §7 #19 round 4).
  - Target: pre-genesis

- **Attestation verify must move behind PoW before credit-wire population activates.** `verify_block_attestation` runs before `check_hash` on both acceptance paths (blockchain.cpp:5738 < 5818; 2253 < 2347) — free pre-cutover (empty witness), but post-cutover it does up to one hybrid-signature verify per pass record before any work is proven, a DoS surface; the Phase-5 ordering constraint is pinned at both call sites (re-filed: the earlier entry survives only as the truncated headline "Credit-wire cutover has two preconditions the Phase-2 verify cannot satisfy") (owner: [`ARCHIVAL_CREDIT_WIRE.md`](design/ARCHIVAL_CREDIT_WIRE.md) §3; census: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §6.7).
  - Target: pre-genesis

- **Dead hard-fork version dispatch survives from genesis (rule 60).** All eleven `HF_VERSION_*` constants are 1 with unreachable else-arms, four are wholly unreferenced, the voting machinery runs inert on every block with its verdict discarded (blockchain_db.cpp:641), and `HF_VERSION_SMALLER_BP+1` resolving to `UINT64_MAX` silently disables pruned-span requests — delete the dead branches or rule the machinery kept, as its own pass (owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §5.5, CEN-B2/B3; C2 batch R4).
  - Target: pre-genesis

- **Shard partition: production `SHARD_BYTES` gets one const-asserted home (with A4, DRS-E); the verifier reads `(b_k, b_{k+1})` from the retained rows (S-ARCH); the leaf partition's tie is LANDED (#780) — not an interim assert: one home in `shekyl_fcmp::tree` (`SEGMENT_LAYER_J`, `leaves_per_segment`), consensus-side `SEGMENT_LEAF_COUNT == leaves_per_segment()` compile-time in `shekyl-archival-retention`'s production lib, red-checked by `segment_leaf_count = 26030` (alignment-preserving, so it clears the chunk assert) failing at that pin — and lives until E4 / S-ARCH deletes the freeze (wallet lane; the CT-1 row closed with #780's dedup).** Re-keyed 2026-09-18 from #775's leaf-unit row (`PDM-Q-F33`). Falsify by a production `SHARD_BYTES` in a second shipped crate or in `consensus_constants.json`, or shipped Rust deriving a shard boundary from anything but the A4 rows — the spike/sim model constants are out of scope by design. Owner: [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) F33 (dispositions i–iii) and Q6 item 4 / F32.
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

- **Release-asset manifest signing owed before the first non-RC release**
  - Target: pre-genesis

- **F-7 — structural gate for the test-only FFI exports that ship in the production archive; two leak shapes, two remedies, one `nm` gate seeded from a sweep** — record: [`design/F7_TEST_ONLY_FFI_EXPORTS.md`](design/F7_TEST_ONLY_FFI_EXPORTS.md).
  - Target: pre-genesis

- **GENESIS ADDRESS FORMAT: PQ signing anchor decision (address v2) — [`design/WALLET_MESSAGE_SIGNING.md`](./design/WALLET_MESSAGE_SIGNING.md)**
  - Target: pre-genesis

- **FFI *signature* drift has no remedy, unlike FFI *constant* drift [`audit_trail/2026-05-ffi-constant-drift-audit.md`](./audit_trail/2026-05-ffi-constant-drift-audit.md)**
  - Target: pre-genesis

- **TJ-1 (was CRITICAL) — leaf-index beacon MITIGATED 2026-08-24 (`PC-D3`); still closes by TJ-B deleting the vin-carried opening.** [`ARCHIVAL_RESPONSE_FORMAT.md`](design/ARCHIVAL_RESPONSE_FORMAT.md)
  - Target: pre-genesis

- **TJ-2 — `CHALLENGE_RESPONSE_BLOCKS` is PINNED (2026-08-15); the freeze item**
  - Target: pre-genesis

- **TJ-3/TJ-4 (HIGH, `(m, n)` re-pin inputs)** (added 2026-07-29, §10.3–§10.4).
  - Target: pre-genesis

- **TJ-7 (HIGH, sweep input) — sybil-per-shard has NO uniqueness constraint,**
  - Target: pre-genesis

- **TJ-8 (briefing constraint on the Round-2 re-pin) — do NOT credit the**
  - Target: pre-genesis

- **TJ-5 (MEDIUM, fix-in-place)** (added 2026-07-29, §10.5–§10.6).
  - Target: pre-genesis

- **TJ price premise — NOT codeable, tracked here with its falsifiers as**
  - Target: pre-genesis

- **Superseded-section cross-reference sweep (docs hygiene, split out by the**
  - Target: pre-genesis

- **Live-pin index, independent of doc status (process-structural — added**
  - Target: pre-genesis

- **Daemon chain store (`DRS-*`) — gap-close pass landed in design.** SoT: [`docs/design/DAEMON_REDB_STORE.md`](./design/DAEMON_REDB_STORE.md)
  - Target: pre-genesis

- **`txs` is a zero-write, zero-read LMDB table (P0b DRS-W4).** Handle's only occurrence is its `open()`; inherited-dead deletion candidate — C++ + schema-version change, census/DRS lane owns ([audit §9](LMDB_WRITE_ATOMICITY_AUDIT.md))
  - Target: pre-genesis

- **`hf_starting_heights` deleted at every writable `open()` (P0b DRS-W5).** `mdb_drop(…,1)` at `db_lmdb.cpp:1779`, never re-created — macro table structurally absent at runtime; feeds census R4 ([audit §9](LMDB_WRITE_ATOMICITY_AUDIT.md))
  - Target: pre-genesis

- **DRS-BENCH — resource/privacy/IBD/pop suite (not throughput).** File
  - Target: pre-genesis

- **DRS-D3c — root-and-frontier parity, daemon vs wallet.** **Re-scoped 2026-09-19** by `WSS-Q1`(b) ([`WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §10, §12): the wallet's proving state is **not a leaf store**, so this is no longer a cross-store leaf/position KAT — the subject is parity between the wallet's frontier at `F` and DRS-E3's `curve_tree_*`. It lands with the proving-state increment. Original leaf/position framing:
  - Target: pre-genesis

- **Round-2 stressnet re-pin of the failure-window `m`/`n` — must be JOINT with reopen (d)** — sliding-window m-of-n is built (`failure_window.rs`; pin [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md)); numerics remain Round-1 provisional. Cannot be sized against honest miss alone: gate-4 grace and `m`/`n` are one surface (`slash_prob(q, m, n)`), and pinning for false-slash alone invalidates reopen (d) (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.6). Falsify by the re-pin recording both false-slash and reopen-(d) inputs, not only an honest-failure CDF.
  - Target: pre-genesis

- **`sweep_all` — deleted in WI-RPC-2b, no Shekyl-native surface; decide**
  - Target: pre-genesis

- **Forfeited-claim record does not survive a wallet restart.** The cadence driver's evaluate-and-forfeit (`ENGINE_CADENCE_DRIVER.md` §4) raises `ClaimForfeited` as a session-lifetime alarm; nothing re-detects the forfeit after a restart, so it is the `AlarmLifetime::LatchedRederived` reopening criterion's named third-class candidate — durable acknowledgment state the channel deliberately does not have yet.
  - Target: pre-genesis

- **Drain/claim/release dispatch driver — terminal-reject prune + byte-identical resubmit remain (confirmation-observe landed 2026-08-27, #572; the release lane joined the residue with #601, which landed the SEAM-side release for a definite first-send refusal — `RejectedTerminal` on the one send the seam itself makes — leaving exactly the driver legs the other two lanes carry: crash-window/ambiguous resubmit, and the driver-side prune for records a future resubmit path re-sends).** UPDATE 2026-09-07: the landing site now exists — the cadence driver (`ENGINE_CADENCE_DRIVER.md` §3 leg 4, `engine/cadence/` `TerminalRejectSlot`) registers and invokes an empty leg-4 slot each tick, wiring-proven by test; the residue is exactly the slot's body (prune + resubmit, landed together per the security note below). The per-epoch claim leg itself landed live in the same PR.
  - **PR-C made this residue USER-VISIBLE (2026-09-03):** `unstake` is reachable, and an ambiguous/held exit now surfaces as `-29522 UNSTAKE_FATE_UNKNOWN` (seal held funds-safe, lane shut, stall alarm in the operator log) with **no recovery verb** — the honest rendering of this unbuilt driver, stated in the contract rather than hidden. The prune half remains a SECURITY item (below); never land resubmit alone.
  - The prune is a **security** item, not only hygiene (raised 2026-08-31, PR-A): a terminal `DoubleSpendConflict` on a Release is terminal on *remedy*, not on impossibility — a partial slash then a compensating `Rebond` can restore the balance these bytes bind (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1, UB2 note). The retained copy is the replay channel, and pruning it is what closes it; the reference age window is the only other bound.
  - Target: pre-genesis

- **Q11 zero-fee-input emission claim has no settlement evidence** (destitute mint-pays-fee; named blocker: accrual has no claim-match set).
  - Target: pre-genesis

- **Enumerate the greenfield pending set: items whose only callers are tests** (`cargo clippy -p <crate>` vs `--all-targets`).
  - Target: pre-genesis

- **GF-7 `stake_in` change-co-presence residual — shipped with a warning,**
  - Target: pre-genesis

- **Workspace-wide `deny_unknown_fields` on the remaining wallet-RPC params**
  - Target: pre-genesis

- **Wallet thin-market entry disclosure — the §13.2 re-disposition's**
  - Target: pre-genesis

- **Solo address registry: decide (a registration tx type is genesis-only)**
  - Target: pre-genesis

- **Release verify: record-floor belt (the `RebondRecordFloorBroken` twin)**
  - Target: pre-genesis

- **RPC transport posture — RULED 2026-08-21; RT-W1 landed; RT-W2/W5/W7 authorized**
  - Target: pre-genesis

- **Daemon Axum: onion-as-remote-RPC docs + operator story** (added
  - Target: pre-genesis

- **Daemon Axum: connection caps + live `rpc_connections_count`** (added
  - Target: pre-genesis

- **Rust wallet stack: no Windows support (blocks Windows wallet [`WINDOWS_WALLET_SUPPORT.md`](design/WINDOWS_WALLET_SUPPORT.md)**
  - Target: pre-genesis

- **Daemon RPC: restricted-method dual-list single-source** (added
  - Target: pre-genesis

- **Phase 4b: `rescan_blockchain` needs an Engine rescan API** —
  - Target: pre-genesis

- **Phase 4c: no way to abandon an unconfirmed submitted transaction, so a**
  - Target: pre-genesis

- **Phase 4b: `get_transfers` OUTGOING filter is a no-op until an outgoing**
  - Target: pre-genesis

- **Phase 4b: build concurrency permit stays 1 — raising it is a rule-21**
  - Target: pre-genesis

- **GF4b-2 genesis gate — bond-post funding-input-count leak; `stake_in`**
  - Target: pre-genesis

- **Block-height representation unification at the WI-2 anchoring seam**
  - Target: pre-genesis

- **Alt-chain supply accumulation advances by the coinbase, not the emission**
  - Target: pre-genesis

- **Should the genesis block header carry a real mint timestamp instead of 0?** Surfaced by C2-R3-Q2 ([`CONSENSUS_C2_R3_TIMESTAMPS.md`](completed/CONSENSUS_C2_R3_TIMESTAMPS.md) §5.1): with `timestamp: 0` (`rust/shekyl-genesis-tool/src/builder.rs:181`) the genesis-padded MTP window admits `ts = 1` at block 1; a real mint timestamp would make the chain unable to start "before" its own genesis time for free under the ratified padding rule. A genesis-mint decision (geblock + the pinned block ids across all three networks), explicitly ruled out of C2-R3's scope at ratification (2026-09-01).
  - Target: pre-genesis (any regenesis window)

- **Tx version min/max is written twice and disagrees in form.** `ver_non_input_consensus` dispatches on `HF_VERSION_DYNAMIC_FEE` / `SHEKYL_NG` (`tx_verification_utils.cpp:55–78`); `check_tx_inputs` hardcodes 3..3 (`blockchain.cpp:3493–3506`). Live bounds match because every `HF_VERSION_*` is 1. Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-H2 / CEN-I3 (were RC-68 / RC-82).
  - Target: pre-genesis

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

- **Block-height-only `unlock_time`: native `Timelock`, a pruned-safe context-free**
  - Target: pre-genesis

- **Repo-wide `RingCT`/`rct`/`RCT` → `CT` semantic sweep — a Shekyl tx is simply a**
  - Target: pre-genesis

- **Store-backed / pruned-tree path assembly (CT-3 pre-flight F5, [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)**
  - Target: pre-genesis

- **C++ FCMP++ wallet send path is incomplete; 2026-06-21 debugging [`20-rust-vs-cpp-policy`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)**
  - Target: pre-genesis

- **`get_curve_tree_leaves` daemon endpoint + KAT (CT-3 R1-Q1 deferral [`docs/completed/CT3_SYNC.md`](./completed/CT3_SYNC.md)**
  - Target: pre-genesis

- **Rollback-adjacent frozen-`R_k` recheck on plain resume (CT-3c C1**
  - Target: pre-genesis

- **Full all-segment frozen-`R_k` recheck (CT-3c bounded-check deferral,**
  - Target: pre-genesis

- **Refresh-over-spend reorg: optimistic-spend `spent_height` invariant +**
  - Target: pre-genesis

- **`AlreadyInChain` submit verdict: distinct lock-lifecycle disposition —**
  - Target: pre-genesis

- **Watchdog probe bytes: ephemeral in-memory held-bytes store — reversion**
  - Target: pre-genesis

- **Submit-error reservation-id placeholder: split submitter error from**
  - Target: pre-genesis

- **F41 constant-work-on-Conceal: invariant NAMED + enforcement DECOMPOSED**
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

- **CT-5d broadcast-but-unmined reference orphan, tracked 2026-06-18.** Target:
  - Target: pre-genesis

- **CT-5d re-confirm UX: handle accessor + `(fee, change)` delta on**
  - Target: pre-genesis

- **CT-5d: retire the vestigial `SnapshotId` / `SnapshotInvalidated` submit path,**
  - Target: pre-genesis

- **Full-segment freeze + prune-retention KAT at production `j=2` leaf count [`docs/completed/CT1_ROUND1_CLOSEOUT.md`](./completed/CT1_ROUND1_CLOSEOUT.md)**
  - Target: pre-genesis

- **Wallet-local `O.x → position` match index (`CurveTreeClient` §4.3 scan [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)**
  - Target: pre-genesis

- **Anonymized (Tor/I2P) routing for non-forward segment fetch (CT Round 0 [`docs/design/CURVE_TREE_CLIENT.md`](./design/CURVE_TREE_CLIENT.md)**
  - Target: pre-genesis

- **Single-dispatcher nm gate: extend beyond `shekyld` (2026-06-11**
  - Target: pre-genesis


- **Gate-6 synchronized-exit wargame round (swan-2/W8, 2026-06-11).** A black [`design/F1_TA3_TA7_LIFETIME_WINDOW.md`](./design/F1_TA3_TA7_LIFETIME_WINDOW.md)
  - Target: pre-genesis

- **Foundation treasury diversification — floor capacity must not be**
  - Target: pre-genesis

- **Re-derive genesis-sealed redundancy params against the integer backend**
  - Target: pre-genesis

- **Funding-seam entry-standoff: consensus surface, wallet conformance, and the [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **Wallet bond-funding/standoff call site (tracks the `shekyl-standoff`**
  - Target: pre-genesis

- **`shekyl-stats` `Z_ALPHA_1E6` provenance vs. the `enc_label` test's**
  - Target: pre-genesis

- **`HoldingsUpdate` (partial-release/rebond) promoted to genesis scope + pre-seal**
  - Target: pre-genesis

- **Archival serve-credit / emission LMDB scans — bound the two unindexed table**
  - Target: pre-genesis

- **Emission-path micro-efficiency cluster — address with C-1 wiring / the schema**
  - Target: pre-genesis

- **Staker-archival settings are FROZEN; the remaining work is the operator experience, not [`docs/STAKER_OPERATOR_GUIDE.md`](STAKER_OPERATOR_GUIDE.md)**
  - Target: pre-genesis

- **Wallet-side archival bond-post construction (design + JoinMarket, PR 0-2a [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`](design/ARCHIVAL_BOND_CONSTRUCTION.md)**
  - Target: pre-genesis

- **StakeEngine Model D wiring — deferred work + rule-21 reopens (PR 2c-2a, [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **Archival bond request path — deferred items (PR 2c-2b, landed inert**
  - Target: pre-genesis

- **Genesis ceremony tooling: `generate-genesis-address` CLI**
  - Target: pre-genesis

- **Stage 1 trait-extraction chain — closeout audit (2026-05-29, [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)**
  - Target: pre-genesis

- **Refresh bandwidth tradeoff under α — round-trip-bound block [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)**
  - Target: pre-genesis

- **F11-S Windows-midrange-PC measurement revisit at stressnet [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./completed/STAGE_1_PR_4_REFRESH_ENGINE.md)**
  - Target: pre-genesis

- **Stage 1 PR 3 engine-property test re-location (trigger:**
  - Target: pre-genesis

- **`RecoveredWalletOutput.key_image`: promote to `Option<KeyImage>`**
  - Target: pre-genesis

- **`shekyl-fcmp`: resolve `useless_conversion` clippy warnings in**
  - Target: pre-genesis

- **Full migration of remaining `SHEKYL_*` FFI constants to the**
  - Target: pre-genesis

- **`wallet_storage`: cover loaded-wallet save-as branches in**
  - Target: pre-genesis

- **Stage 1 performance baseline measurement before Stage 1 PRs land.** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **`kameo` dependency pin and MSRV alignment before Stage 2 cuts.**
  - Target: pre-genesis

- **Revisit `rust/hard-coded-cryptographic-value` CodeQL suppression**
  - Target: pre-genesis

- **Stage 2 — `KeyEngine` migration to actor.** Migrate key material + [`STAGE_1_PR_3_KEY_ENGINE.md`](./completed/STAGE_1_PR_3_KEY_ENGINE.md)
  - Target: pre-genesis

- **Subaddress mechanism under PQC — dedicated design round (2026-05-31, [#112](https://github.com/Shekyl-Foundation/shekyl-core/pull/112)**
  - Target: pre-genesis

- **FA-6 — PQ-safe view-tag pre-filter (T6 closure, genesis).**
  - Target: pre-genesis

- **FA-6b — v31 multisig `tx_extra_pqc_view_tag_hints` ().** Separate from
  - Target: pre-genesis

- **`tx_extra` `0x02` Nonce: shed from the genesis grammar — FA-10 is**
  - Target: pre-genesis

- **Phase 2a send path — engine substrate (closed 2026-06).** `LocalPendingTx`
  - Target: pre-genesis

- **Phase 2b planning session — stake state-machine shape (gate for [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)**
  - Target: pre-genesis

- **Stage 3 — `StakeEngine` native actor build.** Build the Phase
  - Target: pre-genesis

- **Consolidate hand-copied `10^9` / decimal-point constants onto the `shekyl-units`**
  - Target: pre-genesis

- **JSON-RPC large-amount precision — string-amount serde at the RPC edge (spawned**
  - Target: pre-genesis

- **Confidential stake-UTXO transfer (privacy-compatible; compounds (C)).** [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  - Target: pre-genesis

- **Stage 4 — Remaining-subsystem migrations.** Migrate
  - Target: pre-genesis

- **RPC boundary refinements — idle eviction, `engine_lock`,**
  - Target: pre-genesis

- **`Hybrid*` secret types: `Vec<u8>` for fixed-size scalars —**
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

- **Market-bond wallet entry — `first_stake`'s genesis posture cannot**
  - Target: pre-genesis

- **Shard assignment for market staking — the `NoShardsAvailable`**
  - Target: pre-genesis

- **F5 pruning inherits two constraints from the CompleteTree round**
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

- **Serve-credit decision-site flip: Rust becomes the primary decision**
  - Target: pre-genesis

- **`tests/performance_tests/` — rule-15 deletion-or-adoption audit**
  - Target: pre-genesis

- **Remove or retain the orphaned `ActivityMetric.total_staked` observable**
  - Target: pre-genesis

- **Wallet file backup-exclusion markers (PR 6 lessons canvass §5.12 F1).** [`STAGE_1_PR_6_PERSISTENCE_ENGINE.md`](./completed/STAGE_1_PR_6_PERSISTENCE_ENGINE.md)
  - Target: pre-genesis

- **Process core-dump disable at wallet-RPC startup (PR 6 §5.12 F2).**
  - Target: pre-genesis

- **Argon2 stack-resident secret copies — cryptographer review (PR 6 §5.12 F3).**
  - Target: pre-genesis

- **Async `Engine::close` / `change_password` lifecycle (PR 6 PR #83).** [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  - Target: pre-genesis

- **RandomX v2 — Guix reproducible-build obligation pickup** (trigger: the first Guix-built `shekyld` that vendors `external/randomx-v2`; the daemon Rust rewrite does not substitute for it) [`docs/design/RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §22
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

- **Term hygiene: "rotation" is a §11.8 defect on a noun — rename to**
  - Target: pre-genesis

- **PQC Multisig: MSW-6 landing residue.** The scheme_id relaxation
  - Target: pre-genesis

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

- **CEN-D7's motivating consumers have no lever in the Rust validator yet** (E6 slice 2 F10 / Q10, 2026-09-19; owner **the DRS-E2 replay-driver pre-flight, PR #788 — `docs/design/DRS_E2_REPLAY_DRIVER.md` RD-Q7** for the wiring half; the `Network::Fakechain` witness stays its own change). Arm (d) landed the type half: `RuleSet::fakechain(NonZeroU128)` is the one constructor of a `DifficultyRule::Fixed` set and no public-network schedule can yield one (fixture-pinned). What is still owed: (i) the **witness** — `shekyl_address::Network` has three variants and no `Fakechain`, so the constructor is bound to `--regtest` by the daemon's discipline, not by type; adding the variant ripples ~12 files in 9 crates and is its own change; (ii) the **wiring** — nothing in production calls `RuleSet::fakechain` yet, so `scripts/bench/drs_bench.py` (real RandomX cost at a lowered target) and `tests/unit_tests/curve_tree_header_root_check.cpp` (difficulty 1 as a locus) — the two consumers whose needs refused arm (c) — are still served only by the C++ flag. Q10 is RULED, not finished, until both have a Rust-validated path. Falsify (i) by `rg 'Fakechain' rust/shekyl-address/src/network.rs` returning a variant and `RuleSet::fakechain` taking it; (ii) by `rg 'RuleSet::fakechain' rust/` returning a caller outside `rust/shekyl-chain-rules/` (a production one, not the crate's own fixtures). Record: [`CHAIN_RULES_SLICE_2.md`](completed/CHAIN_RULES_SLICE_2.md) §4.5.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) RD-Q7 (the flag and a schedule that names Fakechain, §7 commit 6b; the store leg landed as commit 6) — the `Network::Fakechain` witness is its own change

- **LWMA-1 can derive a zero next-block difficulty from a conforming chain, and CEN-D6 then refuses every successor — a chain-death mode with no floor** (DRS-E2 RD-F17, 2026-09-20). `lwma1_next`'s tail `avg_D · 99·N·(N+1)·T / 200·L` has no floor (`lwma1.rs:176`–`:206`); with every solvetime at the `+6T` clamp it is zero for `avg_D ≤ 6`, and `400 → 66` per maximally slow window, so a live chain under sustained slow blocks walks to zero. The census CEN-D6 row assumed zero was reachable only via a sentinel; amended. Both implementations halt there — the C++ refuses the block (`blockchain.cpp:5494`), the Rust returns the CEN-D6 verdict — so parity holds and the question is the *rule*: does CEN-D6 become a floor of 1 (a consensus change to the ratified algorithm, `docs/completed/DAA_LWMA1.md` §5.3, requiring its own ruling and vectors), or stay a refusal with the death mode accepted and documented? Not the E2 lane's to rule. Falsify by `cen_d6_a_slow_window_of_minimal_work_derives_zero_and_refuses_the_block` (`rules/difficulty_tests.rs`) no longer reaching the refusal — i.e. `lwma1_next` returning non-zero over that window.
  - Target: pre-genesis
  - Owner: [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) CEN-D6 — the census document that holds the rule; the DAA owner rules through it

- **`Fault::Corrupt` has no writer-halt consumer until the E2 replay driver exists** (E6 slice 2 §4.3, 2026-09-19; owner **the DRS-E2 replay-driver pre-flight, PR #788 — `docs/design/DRS_E2_REPLAY_DRIVER.md` RD-Q4**, where the store API is minted with its caller; until 2026-09-19 11:17 this row named "the E2 lane", which existed in no form — RD-F3). `validate` returns `Fault::Corrupt` (non-monotone or overflowing cumulative work, a zero target) when the *store's* record is inconsistent — an `InvariantViolated` the store did not see itself. `connect` takes a `ChainValid` and never sees it; the receiver is the driver that calls `validate`, and no driver exists yet. What is owed: the driver arms the writer halt at the noted height on `Corrupt`, exactly as a belt does, and the store API it needs (a halt the store did not detect) is minted with that first caller — not before (rule 21). Blocker: the driver is unbuilt; **scheduled** as DRS-E2's commit 1 (RD-Q4 defaults `WriteBatch::refuse_corrupt(Corrupt)`, inside the batch). Falsify by `rg 'Fault::Corrupt' rust/` returning a match site outside `rust/shekyl-chain-rules/`; that site is the consumer and must halt. Record: [`CHAIN_RULES_SLICE_2.md`](completed/CHAIN_RULES_SLICE_2.md) §4.3.
  - Target: pre-genesis
  - Owner: [`DRS_E2_REPLAY_DRIVER.md`](design/DRS_E2_REPLAY_DRIVER.md) RD-Q4 — landed as its §7 commit 1 (`WriteBatch::refuse_corrupt`, SI-10); this row closes when the ingest actor calls it (commit 5)

- **Resolution: FCMP++ historical-reference cutover via Stage 5**
  - Target: pre-genesis

- **Audit FCMP++ integration for paired computations.**
  - Target: pre-genesis

- **Regression test: `compute_leaf_count_at_height` vs LMDB drain.**
  - Target: pre-genesis

- **Expose FCMP++ verification cache stats via daemon RPC (stressnet F14).**
  - Target: pre-genesis

- **Rust replacements for chaingen-deleted validation invariants.**
  - Target: pre-genesis

- **Coordinated `TestLedgerBuilder` test-infrastructure substrate [`LocalLedger::from_test_blocks(blocks: Vec<Block>) -> Self`](../rust/shekyl-engine-core/src/engine/local_ledger.rs)**
  - Target: pre-genesis

- **Define formal escalation policy for `shekyl-oxide` divergence [`docs/CI_BASELINE.md`](./CI_BASELINE.md)**
  - Target: pre-genesis

- **Migrate C++ `transfer_details` consumers to [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)**
  - Target: pre-genesis

- **`WALLET_REWRITE_PLAN.md` systemic broken relative-link sweep.**
  - Target: pre-genesis

- **Retire the iai-callgrind→gungraun bench-flake bisect harness (spawned**
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

- **Relay: the `t_core` arrival harness — the witness this path has never**
  - Target: pre-genesis

- **Relay: `on_relay_tx` and a missed submit nudge re-decide the zone after**
  - Target: pre-genesis

- **Wallet: stop holding a relay constant — ask the daemon whether a**
  - Target: pre-genesis

- **Relay: the zone-route decision family moves to Rust** (in flight,
  - Target: pre-genesis

- **Relay: re-derive `fluff_return_ms` once, when a degree distribution**
  - Target: pre-genesis

- **Relay: the `F'` region and §15's launch condition are one condition, and**
  - Target: pre-genesis

- **Fleet: arm readouts must record the per-sample series, not a pooled**
  - Target: pre-genesis

- **Relay: `full_travel_probability`'s cross-check holds `fluff_return_ms`**
  - Target: pre-genesis

- **Relay: `F'` may be per-POSTURE even though §89.2 correctly refused**
  - Target: pre-genesis

- **Relay: populate the 48-cell Pi verification surface, then consume it**
  - Target: pre-genesis

- **Levin p2p migration — LV-2 payload codec and LV-3 connection-path [`docs/design/LV2_PORTABLE_STORAGE.md`](design/LV2_PORTABLE_STORAGE.md)**
  - Target: pre-genesis

- **Relay lane: add a derivation check asserting `fluff_return_ms` equals the max over measured zones**, so adding a zone slower than Tor fails loudly instead of silently under-provisioning `F′`; `tests/carrier_window.rs` is the shape — [`DAEMON_RELAY_PRIVACY.md`](design/DAEMON_RELAY_PRIVACY.md) §91.2
  - Target: pre-genesis

- **Register `shekyl/p2p-wire-prefix-v1` in [`CRYPTO_DOMAIN_REGISTRY.tsv`](design/CRYPTO_DOMAIN_REGISTRY.tsv) and bump the mechanism-1 count-pin when PWD-T5's prefix derivation gets its call site.** Not registrable in P2P-2: the domain gate requires a registered literal to have a defining file and a `const` site, and this round implements nothing, so a row now would fail CI for being honest about the schedule. The derivation, the three computed prefixes and the pairwise-distinctness assertion are pinned in the ruling — this item is the registry half only. PWC-A1 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-T5
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

- **Re-derive `drop_connections(address)`'s host-keyed severing together with the anonymity-zone inbound bound.** It severs every connection sharing a host and scores that host +5 (`src/cryptonote_protocol/cryptonote_protocol_handler.inl:2906-2922`); the remaining blocker is that an onion identity is free to mint, so a per-host key prices nothing — the sweep is now safe on an anonymity zone, not useful there. Re-derives together with PWC-E11's inbound cap, count- or work-based. **The second blocker — host-keying compared `unknown == unknown` — was closed by `fix/anon-zone-address-keying`; the disposition row carries that history and the corrected `is_same_host` finding.** PWC-E9 — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7, PWD-I4
  - Target: pre-genesis

- **Carry an anonymity-zone peer's endpoint in the handshake, and delete the `unknown()` sentinel with it.** Scoped to overlays: clearnet's observed-address / claimed-port split is deliberate and stays. **This deletes work, it does not add it:** the sentinel goes, and with it `identifies_a_host()` in `contrib/epee/src/net_utils_base.cpp`, the `drop_connections` early return, and their comments. Rationale and the verification story are in the owning row; admission policy (no endpoint ⇒ not a peer) is a separate ruling with Rick. — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-I1, PWD-B10
  - Target: pre-genesis

- **Sweep the tree for comparison tests built only from separately-constructed operands, adding an alias limb where one is missing.** A test that constructs both sides independently never creates the aliasing condition, so it cannot exercise a short-circuit that fires on *identity* — structurally incapable, not weak. **Measured:** with the anon-zone guard misplaced, the separately-constructed limbs (`tests/unit_tests/net.cpp:263-264`) pass while the alias limbs (`:276-277`) fail. Any equality, ordering or identity check with a pointer short-circuit has the same blindness available. Found by `fix/anon-zone-address-keying` — [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) PWD-B7
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

- **Hardening-pass commit 8 follow-up: WalletPrefs round-trip**
  - Target: pre-genesis

- **`tx_pool` / `blockchain_db` LMDB transactional wrapper — typed**
  - Target: pre-genesis

- **`shekyld` `fee_policy_version` daemon-side exposure.** Surfaced [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md)
  - Target: pre-genesis

- **`ActivityMetric` producer actor (wallet-side coherent bundle).** Surfaced by [`docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md`](completed/STAGE_1_PR_7_ECONOMICS_ENGINE.md)
  - Target: pre-genesis

- **Daemon atomic activity snapshot RPC (conditional on RPC upstream).** Same G4 [`docs/WALLET_RPC_RUST.md`](WALLET_RPC_RUST.md)
  - Target: pre-genesis

- **Workspace clippy `-D warnings` cleanup.** Surfaced by the Phase 0
  - Target: pre-genesis

- **RandomX v2 `ExternalProject_Add`: per-`CONFIG` install path** in [`external/CMakeLists.txt`](../external/CMakeLists.txt) (multi-config generators; harness/miner-lib opt-in only — the default daemon never builds the C library, so this does not gate `shekyld`)
  - Target: pre-genesis

- **A UDS listener for the daemon RPC (posture 1 on the daemon)** (added
  - Target: pre-genesis

- **The GUI dials its daemon with nothing said — and a dial that says**
  - Target: pre-genesis

- **`shekyld <command>` parses `--rpc-bind-ip` with an IPv4-only helper**
  - Target: pre-genesis

- **Legacy spend-graph analysis utilities (`ancestry`/`depth`/`usage`): audit against FCMP++, then delete** (`prune-known-spent-data` audited and deleted — its eligible set is empty on an amount-0 CT chain) [`EXECUTABLES.md`](EXECUTABLES.md)
  - Target: pre-genesis

- **`atomic_write_file` power-loss crash-injection tests.** PR 6 cites
  - Target: pre-genesis

- **Wallet file metadata obfuscation (PR 6 §5.12 F5–F6).** File size and mtime
  - Target: pre-genesis

- **`WalletFile` handle slimming (post–PR 6 `PersistenceEngine`).**
  - Target: pre-genesis

- **FFI C ABI symbol rename: `shekyl_wallet_*` → `shekyl_engine_*`, [`shekyl-ffi`](../rust/shekyl-ffi/)**
  - Target: pre-genesis

- **C++ JSON-RPC method-name rename: `wallet_*` → engine-shaped names**
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

- **MSVC / Windows build-debt cluster (migrated from**
  - Target: pre-genesis

- **P-drain mechanism re-walk — CryptoNote holdover audit (rule 16; method note 5:**
  - Target: pre-genesis

- **`P`-lane fee uniformity — implementation rider (ratified 2026-07-19,**
  - Target: pre-genesis

- **Principal-side default-on Tor — flip `--proxy` from opt-in to default, opt-out loud.**
  - Target: pre-genesis

- **Principal-side `IsolateSOCKSAuth` — give the principal's `DaemonClient`s isolated circuits [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](design/ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)**
  - Target: pre-genesis

- **2d-2 SP-R0 — reconcile GC of phantom `bonded_slots`/`p_slot` over the per-`P` transport [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **2d-1 WI-2 — durable removal of SPENT funding outputs from `PScanState::funding_outputs` [`ARCHIVAL_BOND_SP_R0_PLAN.md`](design/ARCHIVAL_BOND_SP_R0_PLAN.md)**
  - Target: pre-genesis

- **2d-1 SP-3 — borrow the block in the dual extractor instead of cloning per bonded scanner**
  - Target: pre-genesis

- **2d-2 SP-T0 — DQ-T0.4 circuit-isolation measurement has no CI binary source (BLOCKED, not**
  - Target: pre-genesis

- **Workspace-wide `rustdoc -D warnings` CI lane (BLOCKED on pre-existing cross-crate warnings).**
  - Target: pre-genesis

- **M1 reward-gate C++ test-support surface — fold the corruption-injection seam off the**
  - Target: pre-genesis

- **Segment-freeze pipeline — design round required (opened by `ARCHIVAL_REWARD_GATE_M1.md` [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)**
  - Target: pre-genesis

- **M1 reward gate — pre-flight process BREACH (PF-1, recorded 2026-07-06; a breach,**
  - Target: pre-genesis

- **2d-2 SP-T4a — GF-7 principal-timeline timing correlation is a GENESIS GATE (measure [`ARCHIVAL_BOND_2C_GF7_HOOKS.md`](design/ARCHIVAL_BOND_2C_GF7_HOOKS.md)**
  - Target: pre-genesis

- **Wallet UX: thin-cover exposure disclosure at bond/claim time (registered 2026-07-19,**
  - Target: pre-genesis

- **2d-2 2c-2a — submit-outcome handling: the wallet CONSUMES `SubmitVerdict`; the partition is [`DAEMON_SUBMIT_VERDICT.md`](design/DAEMON_SUBMIT_VERDICT.md)**
  - Target: pre-genesis

- **2d-2 2c-2a — posture→submitter dispatch shape: FROZEN 2026-07-04 (user-ratified) — [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](design/ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md)**
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

- **Stage 5 — `ArchivalEngine` native actor build (simulation-**
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

- **Transport selection for the staker-archival path (gate 6 /**
  - Target: pre-genesis

- **Soundness pass step 0: pin retrieval SLA per class (gate 4–6;**
  - Target: pre-genesis

- **Foundation genesis-enumeration — legal / regulatory disclosure**
  - Target: pre-genesis

- **Archiver seeding-path transport relaxation (gate 6 / firewall;**
  - Target: pre-genesis

- **L14 read-credit soundness: per-(holder, shard), never shard-global**
  - Target: pre-genesis

- **L15 diversity under location-hiding (gate 4–6 / architecture;**
  - Target: pre-genesis

- **Permanent fee-era backstop must be a trustless terminal subsidy,**
  - Target: pre-genesis

- **Age-stratify the foundation floor AND the terminal subsidy toward**
  - Target: pre-genesis

- **L12 floor-decay schedule should be coupled to the growth↔entry**
  - Target: pre-genesis

- **Bootstrap APR overshoot is a purse-efficiency note, not a**
  - Target: pre-genesis

- **Vanguard eligibility flag set is a provisional pin, unseated only by**
  - Target: pre-genesis

- **Validate `prev_id` before attestation verify on the alt-chain path**
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

- **E2 comparator negative control** — every other gate in this programme has been forced red once (rule 47); the LMDB↔redb diff has no such control. One mutation per redb table (flip a byte, drop a row, reorder a dup set) asserting the diff goes red **naming table and key**, written *with* each per-table projection rather than retrofitted; carrier: DRS-E2's pre-flight, beside the repair-backlog query above. Relayed by the maintainer via the E6 slice-1 lane, 2026-09-16. Falsify by the E2 harness's test list containing one forced-red case per table in `rust/shekyl-chain-store/schemas/tables.snap`.
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

- **E6 shaping under `PDM-Q5` / `PDM-Q3`: a below-anchor `RuleSet`, and `ChainView` without a recorded-body accessor** (`PDM-Q-F27`, `F29`, 2026-09-16; [CHAIN_RULES_CRATE.md](design/CHAIN_RULES_CRATE.md) §13, DRS-E6 row). **(1)** `PDM-Q5` band 1 — a fresh node below the release anchor `C`, skeleton only — cannot pass a proof-checking `validate`, so under DRS-D12 it has **no writer** unless `shekyl-chain-rules` issues a `RuleSet` whose `enforced` omits the proof rows; the seam exists (`RuleSet { id, enforced }`, `ISSUED`), the set does not, its selector is anchor-relative (not `RuleSchedule`), and the anchor check's home (census row vs node policy) is Q5's to rule. Owed when `ISSUED` is next touched, as a decision either way. **(2)** `PDM-Q3`'s instrument is the trait surface: no `ChainView` method returns recorded transaction bytes without a `CenRow` and an above-`W` marking — true by construction at `645d09dc3`, held as a standing property. Falsify (1) by `rg 'const ISSUED' rust/shekyl-chain-rules/src/rule_set.rs` still listing only `GENESIS` when the read-side slice consuming `RuleSetId` from the store lands; falsify (2) by a `ChainView` method whose return type carries a `Transaction` or tx byte slice with no row named in its doc comment. Named blocker for (1): `PDM-Q5`'s anchor ruling (which rows a skeleton is held to) — the *seam* is owed now, the *set's contents* after Q5. **(3) Census consequence, same PR as (1)** (`PDM-Q-F30`, 2026-09-17): `CEN-E1` and `CEN-E2` both carry C2-R1b's *"crossing reopens when DRS/R8 moves checkpoint state"*; a Rust-held release anchor **is** that move, so F27's landing PR re-keys both rows (new site, Q2 crossing answered for a Rust-held table, C2-R0 existence HOLD closed) and retires `CEN-E1`'s dead *"JSON-loaded"* text (F23 deleted that channel). Q11's home is **`CEN-E2`** (`is_alternative_block_allowed`), not E1 — E6's unmerged `tip` note says E1; correct on land. Falsify (3) by `rg 'JSON-loaded' docs/design/CONSENSUS_RULE_CENSUS.md` matching, or by a `Trust::BelowAnchor` arm on `dev` while `CEN-E1`/`CEN-E2`'s notes still read *"trigger … not live"*.
  - Target: pre-genesis

- **S-PRUNE needs a rule-26 plan doc before its first increment** (`PDM-Q-F31`, 2026-09-17; owner **DRS-E lane**). The store-side implementation items in [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) §8 — the shard-granular discard predicate `b_{k+1} ≤ first_tx_id(tip − W) ∧ close_height(k) + SEB < tip` (Q2, F32 — no exceptions on any daemon, Q9), the undo-log floor (SCW-7), the A4 length rows (F32), the `pqc_auths` discard consuming `txs_pqc_auth_hash` (F26), `W` entering D11 — land on or adjacent to S-PRUNE (**not** F27's below-anchor mode, which is E6's, nor F28's wire field, which is `LV-`/`PWC-`'s), which is deliberately not extracted ([DAEMON_REDB_STORE.md](design/DAEMON_REDB_STORE.md) §7) and already carries two contracts on its row with no home. E1 got `DRS_E1_SCHAIN_W.md` before its writers; S-PRUNE's successor gets `DRS_E*_SPRUNE.md` before its first increment, and it is where the store invariant (three legs landed, A4's fourth owed), the predicate's enforcement point and §3's reorg discard-side half stop being scattered. Writable now against the charter with `W`, `SEB` and the A4 rows as named inputs; compatible with `PDM-Q-S0` (design, not implementation). **Skeleton landed 2026-09-18** ([DRS_E1_SPRUNE.md](design/DRS_E1_SPRUNE.md), thirteen sections each naming the contract it consolidates, `Status: SKELETON, not a plan`); the plan — DRS-E's increment ordinal, Round-0 pre-flight (carrying Q1's journal-horizon check), commit sequence — is still owed; **its `PDM-Q1` gate cleared 2026-09-18** (Q1 RULED), so it may open now. Falsify by that file's banner still reading `SKELETON` when the first S-PRUNE increment PR opens.
  - Target: pre-genesis

- **Skeleton block payload grows `pqc_auth_hash`** (`PDM-Q-F28`, 2026-09-16; owner **`LV-` / `PWC-`**, not DRS-E). `tx_blob_entry { blob, prunable_hash }` (`cryptonote_protocol_defs.h:49-58`) and its KAT-pinned mirror `shekyl-levin::payload::block::TxBlobEntry` carry the one txid component a pruned receiver cannot compute; under `PDM-Q6` item 2 the skeleton also drops the `pqc_auths` slice, so a band-1 receiver needs **two** to rebuild the 4-part txid and verify the block's tx list. Entry grows an `Option`-shaped field on the identity's predicate; the wire's two-supplied form **already landed** on #768 (`Transaction::hash_with_supplied_components`, `transaction/txid.rs`) so the receiver side is ready; a `PWC-` census row records the growth; the levin KATs move. **UNGATED 2026-09-17** — `PDM-Q6` item 2 RULED: the `pqc_auths` slice is discardable, so the field exists. Owed now by `LV-`/`PWC-`; nothing upstream blocks it. Falsify by `TxBlobEntry` in `rust/shekyl-levin/src/payload/block.rs` still carrying one hash field when `SF` sub-PR 2's per-tx verify lands, or by no `PWC-` row naming the growth.
  - Target: pre-genesis

- **`pruning_seed` wire slot retired — send `0`, ignore received non-zero** (`PDM-Q7` RULED 2026-09-18, [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q7; owner **`LV-` / `PWC-`**, census [P2P_1_WIRE_CENSUS.md](design/P2P_1_WIRE_CENSUS.md), protocol [SHEKYL_P2P_PROTOCOL.md](design/SHEKYL_P2P_PROTOCOL.md)). The stripe engine is removed completely; its advertisement is the bond. The slot on `CORE_SYNC_DATA` and every peerlist entry (Rust mirror `rust/shekyl-levin/src/payload/types.rs:104,149`, `opt_u32` default 0) is retired in **two halves**: a Rust daemon **sends `0`** — the C++ "unpruned" sentinel (`cryptonote_protocol_handler.inl:1979`, `:2810`), so legacy peers read it correctly through the transition — and **ignores** any non-zero it **receives** from legacy C++ peers; the ignore becomes a *drop reason* only after the C++ emitter dies at `DRS-E*`. No framing change. One `PWC-` census row carrying both halves. RPC mirrors (`shekyl-rpc-types/src/p2p.rs:125,241,295`: `pruning_seed`, `next_needed_pruning_seed`) drop at the cutover's `CORE_RPC_VERSION` bump. Falsify by a non-zero `pruning_seed` **sent** by a Rust daemon (a received non-zero is ignored, not red, until the emitter is gone), or by no `PWC-` row naming the retirement when the Rust P2P first sends `CORE_SYNC_DATA`.
  - Target: pre-genesis

- **`prune_blockchain` is REJECTED in the daemon RPC method registry** (`PDM-Q7`, 2026-09-18, [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q7; owner the **`RK-`** daemon-RPC lane, registry [DAEMON_RPC_KV_CUTOVER.md](design/DAEMON_RPC_KV_CUTOVER.md)). Rule 23: a refused name stays in its namespace table marked REJECTED so it is not re-minted; it is not routed in the Rust daemon RPC. *Corrected on review:* `get_blockchain_pruning_seed` is **not** an RPC method — it is the core getter `on_prune_blockchain` calls to fill its response (`src/rpc/core_rpc_server.cpp:1429-1442`); it dies with the C++ stripe engine at `DRS-E*`, not as a registry entry. `DAEMON_RPC_KV_CUTOVER.md` RK-8 lists `prune_blockchain` among methods to port — marked there; the port does not happen. Falsify by `prune_blockchain` routed in `rust/shekyl-daemon-rpc`, or a `pruning_seed` field in any Rust daemon RPC response, or by RK-8 still counting `prune_blockchain` as a port when its slice opens.
  - Target: pre-genesis

- **Delete `--sync-pruned-blocks` — under `PDM-Q5`'s rejection, not `PDM-Q7`'s engine** (2026-09-18; [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q5 and Q7; lands at `DRS-E*`, `S0`). `arg_sync_pruned_blocks` (`src/cryptonote_core/cryptonote_core.cpp:127`) is trust-the-txid-skip-the-proofs with **no anchor**: Q5 REJECTED trust-below-`D_max` as a posture *with* a reorg bound, and this flag is that posture with none — a live implementation of a rejected ruling. Band 1 under the release-carried anchor (Q5, `PDM-Q-F28`) is the successor and the only skeleton-sync path the design admits. Recorded on its own row so the reason survives the stripe engine's deletion. Falsify by a `--sync-pruned-blocks` (or equivalent trust-the-txid) flag in the Rust daemon's CLI.
  - Target: pre-genesis

- **Journal horizon asserted at the journals' retirement site** (`PDM-Q1` RULED 2026-09-18, [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q1; F19's "what remains owed is the check"; owner **DRS-E / S-PRUNE**, plan [DRS_E1_SPRUNE.md](design/DRS_E1_SPRUNE.md) §3). The seven window-retired archival journals (`PDM-Q-F16`) retire at `tip − (CRB + n·SEB + D_max)` — equal to `W` by Q2's ruling — computed through `shekyl_archival_failure_window_params`, never a literal. Both entry paths are bounded but neither is enforced (F19). The assertion lands where retirement is decided, the same discipline as Q2's predicate at S-PRUNE's per-epoch batch; a violated horizon is a refused retirement. Falsify by a journal row retired at a height not derived through `shekyl_archival_failure_window_params`, or by `W` and the journal horizon being two constants.
  - Target: pre-genesis

- **S-CHAIN-W amendment A4 — the two per-tx length rows** (`PDM-Q-F32`, 2026-09-18; owner **DRS-E**, same rung as A3, which landed on #772). Beside the hash rows, permanent, journaled, SI-9-fresh: a `u32` prunable-region length (present ⇔ the tx carried a prunable region at ingest ⇔ its `txs_prunable_hash` row) and a `u32` `pqc_auths` length (present ⇔ 4-part txid ⇔ its `txs_pqc_auth_hash` row) — ingest-time facts that **remain after `discard(k)`**; they are what the shard boundaries `b_*` are derived from, so a skeleton-only node derives the same partition (Q6's reversion (b) holds by construction). [DAEMON_REDB_STORE.md](design/DAEMON_REDB_STORE.md) §7.7 gains its fourth leg, pairwise, when they land; contract in [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) Q6 item 3 (F32). This row replaces the A4 clause of the F26 row that #772 closed. Falsify by `rg 'txs_prunable_len|txs_pqc_auths_len' rust/shekyl-chain-store/src/schema.rs` matching two table constants (names indicative) and §7.7 reading four legs.
  - Target: pre-genesis

- **The archiver serving-store rebuild — a wallet-lane design round, unbuilt by design** (`PDM-Q12` amended on #775, 2026-09-18; owner **the wallet lane**). The round exists and Round 1 is ruled: [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) (family `WSS-`). What remains is the serving-store increment's gate: it is blocked on the A4 length rows (S-CHAIN-W), on `b_*` (S-PRUNE's forward pass), and on E4 / S-ARCH for the leaf-cluster deletion, and behind `WSS-Q1` — *one wallet store with two obligations, or two files* — which is posed and not yet ruled. `PDM-Q6`/`Q12` rebuild `shekyl-curve-tree`'s `LeafStore` around prunable bodies rather than deleting it, and PR #775 makes it *the* serving store; the charter names the substitute and, until this row, no builder. **Round 1 ruled every decision (2026-09-19, PR #790):** fill from the local daemon in the specified-to-scarce window through the ordinary split tx read, verified **against the txid** (`WSS-Q5`); keyed by shard over `[b_k, b_{k+1})`; served **whole-shard** (`WSS-Q7`); erased on the **landed two-epoch pin-release gate** (`WSS-Q8`); recovery intake on the same write-and-verify path; `CompleteTree` a configuration of the same store. Inputs cited from [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md). Falsify by `redb_backend.rs` still exposing `open_frozen_segment_body` / leaf-order streaming when `SF` sub-PR 2's per-tx `ContentVerify` lands, or by a `PersonaServing` that serves bodies from any store this row does not name.
  - Target: pre-genesis

- **`WSS-Q1`(b)'s grading run has not happened — the instrument exists, the rig verdict does not** (2026-09-20; owner **the maintainer**, because the rig is a physical machine this lane cannot reach). [WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.3.4 adopts `WSS-Q1`(b) **subject to** four measurements; rows 2 and 3 are timed and now have an instrument — [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) and `rust/shekyl-wss-q1b-bench` — with the corpus, the delta/proving boundary and the rig protocol pinned. **The blocker is named and real** (rule 22): grading requires the §6.3.4 rig — a Pi 4 Model B, 8 GB, aarch64 64-bit userland, USB-SSD, thermally sustained — and the harness **refuses** to emit a verdict anywhere else. Dev-box measurement is available and is not the thing owed. **What the first dev-box run measured, and what it does not settle (2026-09-20, x86):** the worst-case replay (765 600 leaves over 725 blocks) takes **73.9 s** on a quiet box against a **1.105 s** denominator, with the graded path **verified** against its own root, so the binding threshold is the **2 s absolute floor** — the 15 % arm is 0.17 s — and the delta misses it by **~37×** on hardware far faster than the rig. (An earlier run measured 96.8 s while sharing the machine with a C++ compile; both are reported, and the 31 % swing is the concrete argument for the rig protocol's quiet-machine discipline.) Amortized, that replay is **102 ms per block** against a 120 s cadence, which is what decides whether the miss kills the design or moves the work. The direction is not in doubt even though the Cortex-A72 magnitude is, so §6.3.4 row 2's pre-registered miss response — *amortized replay first* — is the likely landing, and `WSS-Q1`(b) reopens only if the amortized form also fails. That is a measurement, not a verdict: the rig grades, and the amortized form is unbuilt, so neither the miss nor the remedy is settled here. The open edge measured **0.197 s** projected over the 790-block buffer against a 5 s threshold; its **attribution was withdrawn 2026-09-20** — the `round-trip bound` figure was a clamp artifact (the floor term exceeded the whole projection), and the harness now reports `Inconsistent` and names no remedy. See the corpus row below before reading the seconds as headroom. **Rows 1 and 4 are not this row's** — `rollback_to_fork`'s refusal semantics and the `build_layers` property tests are behavioural and ride the proving-state increment. Falsify by **two** `schema_version`-1 run records with `rig.grading: true`, one per edge, each cited from §6.3.4: the spend record at `budget.verdict` and the open record at the top-level `verdict`, both reading `pass` or `miss`. *The two schemas differ because the measurements do — the spend edge grades a ratio against a denominator and carries a `budget` object, the open edge grades an absolute and does not — and an earlier form of this row named `budget.verdict` for both, which the open-edge record can never satisfy however the rig run goes.*
  - Target: pre-genesis

- **The Pi 4 is the conservative interim baseline for everything; the *staker* reference class is owed, and its trigger is the settled software package structure** (doctrine recorded 2026-09-20; owner **the maintainer**, discharged at the P-store lane's cutover decision). **The doctrine:** rule 76's [Raspberry Pi 4 floor](../.cursor/rules/76-device-provisioning-floor.mdc) is the absolute conservative baseline for **all** provisioning — works-there-works-anywhere — and that is the right call to make by default. **The annotation that keeps it honest:** for **serving-path** design the Pi is a deliberate **over**-conservatism, not a deployment recommendation. An archiver runs a bonded persona with a Tor service and multi-gigabyte holdings; nobody is claiming that box is a Pi. Budgeting against one anyway is conservative and correct; what was stretched is the **authority cited**, since rule 76's floor is argued from the privacy charter (everyone must be able to run a node, so the floor is a mission commitment) and a staker's box is not that argument's subject. **So the re-grounding is a change of word class, not of design** — *"conservative interim baseline, staker class TBD"* in place of a bare rule-76 citation — applied **at next touch**, not as its own sweep, at: `shekyl-p-fetch/src/client.rs:45` (*"`8 × ~6.7 MB ≈ 53 MB` on the Pi 4 floor (rule 76)"* — the only one that names the rule), and `shekyl-sp-t3-spike/bins/pd_f2_measure.rs:40`, `:145` and `:180`, which read the Pi as the memory fit the `SF-D7` pin is taken against. The numbers stand; only their warrant moves. **The TBD, with a trigger that will arrive on its own (rule 21 shape):** the staker reference class is owed **when the final software package structure is settled**, because *what one box runs is what sizes the box*. Today an archiver's box runs `shekyld` plus the wallet process — `StakeEngine`, the serving task and Tor all co-resident. The Tier 2 `P`-store lane ([WALLET_SIDE_STORE.md](design/WALLET_SIDE_STORE.md) §6.2, §6.7) and the C++→Rust cutover together decide whether that co-residency is the shipped shape or whether `P`'s serving splits out. The moment that is settled the class is named **against a known load**, so the reference hardware is a **measurement, not a guess** — which is exactly the discipline that produced the Pi floor in the first place, applied at the staker tier once the machine has a job description. **Rides this row's discharge:** rule 76 gains a scope clarification separating the universal node floor from a staker reference class. Deferred deliberately — nothing needs it sooner, and writing it before the class has a load would invent the number the trigger exists to measure. Falsify by `rg -n 'Pi 4' rust/shekyl-p-fetch rust/shekyl-sp-t3-spike` returning a site that still cites rule 76 as the warrant for a serving-path budget after that file's next substantive edit, or by a named staker reference class existing anywhere while this row is open.
  - Target: pre-genesis

- **The open-edge bench has no corpus with realistic block weights, so its volume term is untested rather than measured** (2026-09-20, found by running it; owner **the `WSS-Q1`(b) bench**, [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) §7.2). The first live run against `shekyld --regtest` projected **0.197 s** over the 790-block buffer against a 5 s threshold. **Its `round-trip bound` attribution has been withdrawn** (2026-09-20): it came from clamping `floor × round_trips` to the total, and at the measured values the floor term *exceeds* the projection, so the clamp manufactured a 100 % round-trip share out of two instruments disagreeing. What survives is the **measured** half — `2.0` round trips per block, read from each block's shape — which is the empirical support §6.3.4 row 3's amendment actually needs. It does not go far enough to read as headroom, for a reason the record states in its own numbers: **regtest blocks are coinbase-only**, so the fetch makes exactly `2.0` round trips per block instead of three (`get_transactions` is never called), and each block carries **1 432 B** decoded. A worst-case block is three orders of magnitude larger and pays the third call, so the measured attribution is as much an artifact of an empty corpus as a finding about the path. **What is owed:** a regtest corpus whose blocks carry non-miner transactions at realistic weights, which coinbase mining cannot produce — it needs a wallet spending into the blocks, the machinery `fcmp_spend_e2e` and the regtest e2e suite already have. **The harness no longer lets a thin corpus read as a pass:** `open_edge` measures the sampled blocks against the graded density and **withholds its verdict** below half of it, so the live run reports *"1432 B/block measured vs 300000 graded (0.5 % — TOO THIN TO GRADE)"* instead of 0.19 s and a green tick. **What the corpus is now for (amended 2026-09-20 with `WSS_Q1B_BENCH_SPEC.md` §4.4's density ruling):** not to grade the adversarial window — that is an accepted rule-80 long-tail, because 790 blocks at the 2 400 000 ceiling is ≈ 1.9 GB decoded and no hardware refetches it in 5 s — but to **locate the crossover**: the per-block density at which the 5 s budget stops holding. The ruled grading point is the full-reward zone (300 000 weight, ≈ 237 MB over the buffer, ~47 MB/s decoded), chosen because the measurement there can still surprise; the crossover says how much margin that choice actually has, and is the evidence that would reopen the nominal under rule 21. Falsify by an `open_edge` record whose `projected_round_trips / blocks_projected` is 3.0 and whose `density.sufficient` is true, or by a recorded crossover density.
  - Target: pre-genesis

- **Lift the "grade where the measurement can still surprise you" criterion out of the `WSS-Q1`(b) bench spec once a second bench needs it** (2026-09-20; owner **whichever bench picks a corpus point next**). [WSS_Q1B_BENCH_SPEC.md](design/WSS_Q1B_BENCH_SPEC.md) §4.4 states it in general terms with its checkable shape — a table showing both rejected rungs are foregone — but it lives in a **lane** document, where a future bench author has no reason to look. **Deliberately not minted as a cursor rule now** (rule 21, and the reason is rule 15's): a rule with one instance has no oracle, and this criterion has been applied exactly once. **Trigger, and it will arrive on its own:** the next bench that must choose a corpus point, input size or load level either cites §4.4 — in which case the criterion has two instances and earns a home that is not a lane doc — or does not, in which case the miss is the evidence that it needed one. Ratified as the general form by the maintainer 2026-09-20, above the UX argument that originally selected the same value. Falsify by a second bench citing §4.4's criterion, or by a numbered rule stating it.
  - Target: pre-genesis

- **Standing lesson, home unresolved: a gate that exists but does not bite its graded subject** (ratified 2026-09-20 on three instances; owner **the maintainer**, because the ledger is outside this repo). **The defect class:** the gate is real, the test is real, review signs it off — and the artifact whose correctness the verdict rests on is untouched by any of it. **Three instances, all in the `WSS-Q1`(b) bench, all found by its own author auditing what the claims rested on rather than by review:** the `--grade` rig refusal enforced arch, userland and RAM while `cpu_model` was captured and never compared, so any aarch64 host with 7.5 GB passed as the pinned Pi 4; `prover_pin.revision` compiled as `None` and its `.git/HEAD` watch named nothing in a worktree, where `.git` is a file; and the `proof::verify` red-bite covered the control arms and the depth-3 unit tests while `proof::verify` appeared **nowhere** in either binary, so the depth-6 graded path went unchecked and `paths_verified` came from `prove()` returning. **Why it survives review:** each looks like coverage from outside — there *is* a gate, it *does* pass — and the subject it misses is invisible from the gate's own side. **The test that catches it at birth, in one sentence:** *point at the graded artifact and ask which check touches **it**, by `file:line`* — not "is there a check", but which check on which object; an answer naming a sibling (the control arm, the fixture, the crate version) is the defect. **Two follow-through disciplines that make a fix hold:** *refuse, don't annotate* (an unverified graded path produces no record; a failed byte read produces no bytes, not `(0, 0)` — so a clean exit means what a reader assumes), and *keep the claims separate* (verification earns *well-formed*, a control earns *cost-equivalent*; good news must not launder an adjacent claim). It generalizes the tautology-gate note — a gate surviving as a tautology displays green forever — and is the bench-side twin of a map row asserting a state the territory left. **In-repo home if it graduates:** [`47-gate-subject-assertion`](../.cursor/rules/47-gate-subject-assertion.mdc), which today says a gate must assert its **subject exists**; this adds that the subject must be the **graded** one. Not minted as a rule edit here — the cursor rules are the maintainer's, and the same deferral applies as to rule 76's scope clarification. Falsify by the lesson appearing in rule 47 or in whatever artifact the citation row below resolves `principles-and-learnings` to.
  - Target: pre-genesis

- **`principles-and-learnings` is cited as a genesis-frozen authority and resolves to nothing** (found 2026-09-20 while filing the lesson above; owner **the maintainer**, because only they know the referent). [ARCHIVAL_PRUNED_DAEMON_MODE.md](design/ARCHIVAL_PRUNED_DAEMON_MODE.md):1137 — and its copy at [ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md](completed/ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md):2365, both introduced 2026-09-12 — open §4 *"Do not re-derive: read, cite, build on"* with **"Genesis-frozen decisions in `principles-and-learnings` and the consensus census."** **The list has seven entries; six carry working links to real documents. This one is the exception, and it covers the highest-stakes category in it.** `principles-and-learnings` exists nowhere in `shekyl-core` (no file, and **no deletion in git history** — it was never here), nor in `shekyl-dev` or `shekyl-web`. Its sibling in the same sentence, *the consensus census*, does resolve — `CONSENSUS_RULE_CENSUS_1/2/3.md` — it is merely unlinked. **Why this matters beyond tidiness:** a reader is instructed **not to re-derive** these decisions and is sent to an authority they cannot open, which is the one instruction that cannot be followed safely — the alternative to reading it is re-deriving it, which §4 exists to forbid. **Not repaired here, and the blocker is named** (rule 22): the referent is unknown to this lane. The name reads like a Cursor-side memory or rules artifact rather than a repo document, in which case the fix is to say so at the citation — an external authority named as external is followable, a broken repo link is not — or to replace it with the in-repo document that actually holds the genesis-frozen decisions. Guessing between those would mint a wrong citation in a ruled charter. Falsify by §4's first bullet naming an artifact a reader can open, or by `principles-and-learnings` existing at a stated path.
  - Target: pre-genesis

- **`--max-connections-per-ip` defaults to `1`, so two nodes behind one NAT cannot both hold a public-zone connection to the same peer — and the refused node is told nothing.** Observed 2026-09-21 on a live testnet pair sharing one residential WAN address: daemon A (synced, height 7101) held each seed's inbound slot; daemon B was refused by every seed — 34 consecutive handshakes ending `LEVIN_ERROR_CONNECTION_DESTROYED`, `white_list: 0 / gray_list: 0`, height stuck at 1. **The mechanism is the inherited per-IP cap, not PWD-I1's same-host cap** — `has_too_many_connections` (`src/p2p/net_node.inl:3236`, called at `:241`) counts **inbound** same-host connections against `max_connections`, whose default is `1` (`src/p2p/net_node.cpp:191`); PWD-I1's cap is outbound-only by construction (`!connection_is_income`, `src/p2p/net_node.h:144`) and is not implicated. **Three properties make this more than a tuning default.** (i) It keys on **host**, so a distinct `--p2p-bind-port` does not separate the two nodes — verified by moving B to 12022, which changed nothing; the advertised port is not part of the identity the cap tests. (ii) The reason is logged **only on the refusing node** (`MWARNING "CONNECTION FROM ... REFUSED, too many connections from the same address"`, `:243`); the refused operator sees a destroyed connection, and at the default `log-level=0` sees nothing at all — diagnosis required raising the *other* machine's verbosity, which an operator who owns only their own node cannot do (rule 82: the failure mode has no surface where the affected user is standing). (iii) There is no `--hide-my-port`, so a node that knows it is unreachable cannot decline peerlist candidacy. Affected populations are ordinary, not exotic: CGNAT subscribers, a shared office or household, and any operator running a second node beside a miner. **Tor is not an escape hatch, and the first filing of this row wrongly said it was.** The admission cap does skip non-public zones (`:3238`), so an onion peer connects — but `cryptonote_protocol_handler.inl:452` then refuses chain sync on exactly those zones (*"No chain synchronization over hidden networks (tor, i2p, etc.)"*, inherited with `0dd59b4cc`, whose subject is **broadcasting transactions** over Tor), setting every such peer to `state_normal` before any block is requested. Measured: six onion peers at height 7131, `state=normal`, local height 1, `busy_syncing=false`, zero blocks in 6 minutes on an empty database. The 2741 blocks this node did acquire came from a **LAN** peer in the public zone, not from Tor — misattributed in the first filing, corrected here. **So the two mechanisms compose into a dead end:** a node sharing a WAN address with another node is refused by every public seed, and the only transport left to it cannot serve a chain. It does not sync at all. This also bounds **Tor-by-default** (the intended end state, maintainer 2026-09-21, gated on installation UX, and recorded nowhere in `docs/` — a search returns nothing): that posture cannot carry initial sync while `:452` stands, so it is a change to that line, not only to a default. **This does not stay one refused connection.** The refusal destroys the connection *after* TCP succeeds, so it is charged as a **handshake** failure and draws the flat 3600s public-zone window — each attempt blacklists that seed for an hour, across every seed, so the node re-arms the same refusal instead of retrying into a transient condition. That is the sibling row immediately below, filed separately because it is a different mechanism with a different owner; it is what turns this from a refusal into a dead node. Falsify by two daemons behind one NAT each holding a public-zone connection to the same seed, or by the refusal reaching the refused node's own log.
  - Target: pre-genesis
  - Owner: [`SHEKYL_P2P_PROTOCOL.md`](design/SHEKYL_P2P_PROTOCOL.md) **PWD-I7** — per-host inbound admission, minted 2026-09-21 for this finding and carrying its anchors, pricing and falsifier. *(Re-pointed from "cluster I": a cluster is not an owner — the recorded reason PWD-B11 was minted for PWC-D9.)* The adjacent **outbound** cap's execution record is [`P2P_HANDSHAKE_ADDRESS.md`](design/P2P_HANDSHAKE_ADDRESS.md) §1 job 3

- **A refused inbound connection is charged a 3600s public-zone failure window whose own justification does not describe this failure class.** Sibling of the PWD-I7 row above, filed separately because it is a different mechanism with a different owner: I7 explains why ONE connection is refused, this explains why one refusal turns into a **dead node**. **All line anchors below are pinned to `dev` `f6df3abc2`** and were verified there. An accept-side refusal reaches `record_addr_failed` ([`net_node.inl`](../src/p2p/net_node.inl):1561 and :1619 — **the handshake-fail arms**; the dispatch that opened this lane cited `:1558`, which is not one of them), and `failed_addr_cache::window` ([`net_node.h`](../src/p2p/net_node.h):239) returns a flat `P2P_FAILED_ADDR_FORGET_SECONDS = 3600` for the public zone **on the FIRST failure**. **The constant's own justification is the defect** ([`cryptonote_config.h`](../src/cryptonote_config.h):196-201): *"on a clearnet address a failed dial usually means a down host, and not retrying a down host for an hour is cheap and polite."* That is **false for this failure class** — the host is up, answering everyone else, and refusing only us. The premise the constant is derived from does not hold where it is being applied, so the value is not wrong by a tuning margin; it is derived from a different situation. **The refusal fails at HANDSHAKE, not at connect, and that is what makes it unrecoverable rather than slow.** A per-IP refusal destroys the connection after TCP succeeds, so it lands on `:1561`/`:1619` — and `window()` gives the public zone the flat hour. **Each attempt therefore blacklists that seed for a full hour, across every seed**, so the node does not retry into a transient condition; it re-arms the same refusal indefinitely. (It also explains the observed shape: refusals in bursts with quiet gaps, which reads like an intermittent network fault and is the cache expiring and re-arming.) **The selector's own stated premise is the defect, and it is written down**: *"The window is a property of the TRANSPORT, not of the peer"* ([`net_node.h`](../src/p2p/net_node.h):220-226). This failure class is a direct counterexample — the clearnet transport is healthy; what refuses is a **policy relationship between two peers** that happen to share a host. Worse, the anon branch's justification describes this exact case — *"a peer that is up, correct, and answering everyone else — so the first failure costs minutes and only a persistent one earns the hour"* — and is **unreachable for it**, because the selector keys on zone rather than on what failed. Tor's 240s escalating window ([`net_node.h`](../src/p2p/net_node.h):242-245, ruled at [`Q12_D6A_PEER_DISCOVERY_RUN.md`](design/Q12_D6A_PEER_DISCOVERY_RUN.md) from measured p90 hidden-service recovery, [`cryptonote_config.h`](../src/cryptonote_config.h):251) is the second reason a Tor path degrades gracefully and clearnet does not — the first being PWD-I7's zone exemption. **Not fixed here**: the anon window was set from a measurement, and setting a public-zone window for refusal-class failures without one would mint exactly the unmeasured constant that rule's discipline exists to prevent. What is needed is either a measurement or a distinction between "no answer" and "answered then refused". **The two are already distinguished at the call site and the distinction is then thrown away**, which is the actual gap and also the cheapest place to fix it: the connect-fail arms (`:1549`, `:1609`) and the handshake-fail arms (`:1561`, `:1619`) are *different branches*, and only the connect-fail pair is the "down host" case the constant's justification describes — but `record_addr_failed` takes an address and nothing else, so both arms record the same thing and draw the same hour. The failure class is known one line above the call and is discarded crossing it — `record_addr_failed(const network_address&)` ([`net_node.inl`](../src/p2p/net_node.inl):1642) takes an address and forwards to `record_failure(addr, now)`, which takes no class either, so the discard is **at the call site**, not inside the cache. **A caution on the fix direction, recorded so it is not skipped:** passing the class in is the obvious move, but the public hour appears to be *inherited* rather than derived — the anon 240s cites a measurement, and the public hour's justification is an assertion about down hosts. If so, a policy-refusal window is a **new number needing its own derivation** (rule 76: provisioned, not guessed), not a reuse of either existing one. That is the maintainer's to rule and is why this row does not propose a value. Falsify by a refused node re-reaching the same seed inside 3600s on an unmodified build, or by the handshake-fail arms proving unreachable from an accept-side refusal.
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

- **Offline schema-aware prune/copy tooling (rule-21 reversion clause).** `shekyl-blockchain-prune` retired (inert since LMDB v6: version guard pinned at 5; copy list held 16 of 49 tables). Reopen on post-genesis operator demand that in-place `--prune-blockchain` + `shekyl-mdb-copy -c` cannot serve, or when S-PRUNE reaches execution in [`DAEMON_REDB_STORE.md`](design/DAEMON_REDB_STORE.md) — then rebuild in Rust with the table set derived from the schema source of truth, never hand-maintained (precedent: the `SHEKYL_LMDB_TABLES` X-macro, rule 47).
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
