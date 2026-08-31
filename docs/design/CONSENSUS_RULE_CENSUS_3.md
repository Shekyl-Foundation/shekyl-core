# Consensus-rule census (CEN-1)

**Status:** OPEN — CEN-1 enumeration complete; per-rule design rounds not begun.
**Pinned sha:** `8ba1aae3dbd1e3b03504d5d27c0471bb67f11b9d` (dev tip, 2026-08-31).
Every `file:line` in this document was read at that commit; re-locate before
citing at any other sha.
**Identifier family:** `CEN-` (consensus census), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit that
lands this document (rule 94). Two token forms, both registered: `CEN-1`
names the census work item itself (this document; the effort the
2026-08-30 ruling authorized), and `CEN-<subsystem letter><n>` — optionally
with a letter suffix for a row split after first numbering (`CEN-F4`,
`CEN-G6b`) — names a rule row. Checked against the §2 registry: no
existing family's prefix collides with `CEN-`.
**Decision authority:** the census enumerates; it does not rule. Rulings on
bucket-4 rows are sequenced to later design rounds (the 2026-08-30 ruling:
census precedes rewrite; the census output is the rewrite's specification;
C++ is a legitimate differential-test oracle only for rules deliberately
ratified).
**Sibling walks:** multiple deliberately independent enumerations of the
same surface were commissioned at the same pinned sha; this document is
the `CEN-` walk (steered as census #3). A sibling landed as PR #583:
`CONSENSUS_RULE_CENSUS_2.md`, family `RC-` (plain-text reference until
that PR merges; link on whichever PR lands second).
**Disagreement between the walks is census material for the design
rounds, not a defect to reconcile in either document** — no row here was
diffed against or adjusted toward an `RC-` row; the reconciliation pass
is a later, separate work item. Headline divergences, recorded as
observed facts only: denominators 161 (`CEN-`) vs 167 (`RC-`); bucket
splits 84/23/0/54 vs 93/3/15/56; consensus/policy 152/9 vs 157/10.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
this is longevity work under priority 3 — the Rust consensus rewrite cannot
take the inherited C++ as its specification, because differential-testing
against never-examined behavior converts "nobody looked" into "verified", a
check that cannot fail on the axis that matters (right-for-Shekyl,
[`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc),
[`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc)). An
unlisted rule is ratified by silence; the census exists to close that
failure mode. It trades nothing in security or privacy: it changes no code.

---

## 1. Method — how the denominator was produced

The census must be re-runnable at a later sha and diffable. The procedure:

1. **Entry points.** The block- and transaction-acceptance entry points:

   | Entry | Site |
   | --- | --- |
   | `core::handle_incoming_tx` | `src/cryptonote_core/cryptonote_core.cpp:720` |
   | `core::handle_incoming_block` | `src/cryptonote_core/cryptonote_core.cpp:1327` (and the 6-arg form at `:1335`, `handle_single_incoming_block` `:1371`) |
   | `Blockchain::add_new_block` | `src/cryptonote_core/blockchain.cpp:6609` (2-arg) / `:6626` (3-arg) |
   | `tx_memory_pool::add_tx` | `src/cryptonote_core/tx_pool.cpp:223` (and the engine-attested insert, `:550`) |

2. **Traversal rule.** Worklist over the call graph: starting from the entry
   points, every callee that can return a verdict or abort on the acceptance
   path was read and added to the frontier; serialization helpers, logging,
   metrics, and notification fan-out were not descended into. The traversal
   terminated when the frontier was empty. The storage layer
   (`src/blockchain_db/`) is **in** the frontier because `m_db->add_block`
   can throw on constraint violations and those throws are caught as
   verdicts (`blockchain.cpp:6397`).

3. **Visited-function list** (the frontier at exhaustion; definition sites
   at the pinned sha):

   - `core::handle_incoming_tx` cryptonote_core.cpp:720; `core::check_tx_semantic` :771; `core::check_tx_inputs_keyimages_diff` :913; `core::check_tx_inputs_ring_members_diff` :945; `core::check_tx_inputs_keyimages_domain` :963; `core::add_new_tx` :983/:997; `core::handle_incoming_block` :1327/:1335; `core::check_incoming_block_size` :1408
   - `Blockchain::add_new_block` blockchain.cpp:6609/:6626; `handle_block_to_main_chain` :3100 (2-arg)/:5689 (4-arg); `handle_alternative_block` :2214; `build_alt_chain` :2153; `switch_to_alternative_blockchain` :1386; `rollback_blockchain_switching` :1332; `prevalidate_miner_transaction` :1639; `validate_miner_transaction` :1746; `parent_frozen_segment_count` :1732; `check_block_timestamp` :5514/:5535; `get_adjusted_time` :5480; `complete_timestamps_vector` :2133; `verify_block_attestation` :5565; `get_difficulty_for_next_block` :1082; `get_next_difficulty_for_alternative_chain` :1544; `check_tx_inputs` :3241/:3440; `check_tx_outputs` :3344; `check_commitment_mask_valid` :3287; `check_for_double_spend` :3124; `have_tx_keyimges_as_spent` :3411/:3425; `check_archival_bond_post_input` :4803; `check_archival_serve_credit_input` :5262; `compute_fcmp_verification_hash` :4592; `check_fee` :4397; `get_dynamic_base_fee` :4363; `get_current_fee_per_byte` :4381; `is_tx_spendtime_unlocked` :4505; `check_tx_input` :4532 (caller-less, §5.1); `scan_outputkeys_for_indexes` :256 (caller-less path, §5.1); `get_next_long_term_block_weight` :6548; `update_next_cumulative_weight_limit` :6568; `get_long_term_block_weight_median` :1824; `get_last_n_blocks_weights` :1809; `prepare_handle_incoming_blocks` :6962; `check_against_checkpoints` :6668
   - `tx_memory_pool::add_tx` tx_pool.cpp:223/:537; `insert_attested_tx` :550; `tx_memory_pool::check_tx_inputs` :1716; `is_fcmp_verification_cached` :1735
   - `ver_non_input_consensus` tx_verification_utils.cpp:259/:265 (templated body :49); `ver_mixed_ct_semantics` :212; `get_transaction_weight_limit` :203
   - `get_transaction_signed_payload` tx_pqc_verify.cpp:62; `verify_transaction_pqc_auth` :161
   - `checkpoints::check_block` src/checkpoints/checkpoints.cpp:113/:131; `is_in_checkpoint_zone` :108; `is_alternative_block_allowed` :137; `init_default_checkpoints` :181; `load_checkpoints_from_json` :195
   - `HardFork::check` src/cryptonote_basic/hardfork.cpp:115; `check_for_height` :128 (`do_check_for_height` :121); `do_check` :109; `add` :134; `get_current_version` :360; `get_ideal_version` :365/:372; `reorganize_from_chain_height` :241
   - Helper predicates (cryptonote_basic / cryptonote_core): `check_inputs_types_supported` cryptonote_format_utils.cpp:773; `check_outs_valid` :837; `check_output_types` :971; `check_money_overflow` :869 (`check_inputs_overflow` :874 / `check_outs_overflow` :899); `is_valid_decomposed_amount` :1528; `expand_transaction_1` :130; `parse_and_validate_tx_from_blob` :199; `get_transaction_weight` :321/:393 (clawback :94; pruned :334); `classify_archival_tx` cryptonote_basic.h:353; `count_spend_inputs` :312; `count_serve_credit_inputs` :324; `get_max_tx_size` cryptonote_basic_impl.cpp:88; `get_min_block_weight` :81; `get_block_reward` :93/:148; `get_block_longhash` cryptonote_tx_utils.cpp:766; `get_altblock_longhash` :748
   - CT semantics (`src/fcmp/`): `verCtSemanticsSimple` ct_semantics.cpp:186/:256; `verCtSemanticsFeeOnly` :372; `verCtSemanticsBondPost` :315; `verCtSemanticsEmission` :338; `verArchivalCtBalanceAndRange` :267; `verBulletproofPlus` :132/:139; `is_canonical_bulletproof_plus_layout` ct_types.cpp:240
   - Rust verdict crates reached by FFI from the above (behavior stated from
     the Rust source where the verdict lives): `shekyl-economics`
     (`emission.rs`, `release.rs`), `shekyl-difficulty` (LWMA-1),
     `shekyl-ct-balance`, `shekyl-fcmp` (`shekyl_fcmp_verify`),
     `shekyl-crypto-pq` (`shekyl_pqc_verify`), `shekyl-pow-randomx`
     (`seed_epoch.rs`, hash), `shekyl-archival-retention` (bond_post,
     serve_credit_decisions, admission, failure_window, emission vin
     verify), `shekyl-ffi` shims (`legacy_core.rs`, `pow_randomx_ffi.rs`,
     `archival_ffi/*`)
   - Storage constraint layer: `BlockchainDB::add_block` blockchain_db.cpp
     and `add_transaction`; `BlockchainLMDB::add_block`,
     `add_transaction_data`, `add_output`, `add_spent_key`, curve-tree and
     archival-table write hooks (db_lmdb.cpp) — §4.L

4. **Granularity.** One row per independently ratifiable behavioral
   commitment — the unit a later design round can keep or reject on its
   own: a comparison, an ordering requirement, a consensus-visible
   constant's value, a structural bound. Composite functions contribute
   multiple rows.

5. **Consensus vs relay flag.** Scope is block-acceptance validity plus
   transaction-validity-as-included-in-a-block. The code's own
   discriminator is `kept_by_block` (`tx_pool.cpp:229`): a check skipped
   when `kept_by_block` is true never forks the chain and is flagged
   **policy**; everything on the block path is **consensus**. Policy rows
   are counted in the denominator and flagged, never silently included or
   excluded.

6. **Scope boundary (recorded, not implicit).** Serialization/hash
   *definitions* (block hashing, the tx-hash tree, epee wire formats, the
   pruned-tx hash shape) define identity, not validity; they are census
   subjects only where an acceptance-path *check* consumes them (e.g. the
   curve-tree-root equality, the PQC signed-payload construction). The
   p2p/relay layer above `core::handle_incoming_*` (span scheduling,
   Dandelion++, fluffy-block reassembly) is out of scope except where it
   supplies acceptance inputs (the pool supplement and the attestation
   witness). The wire-format census is separate work
   ([`BLOCK_TX_WIRE_FORMAT_PORT.md`](BLOCK_TX_WIRE_FORMAT_PORT.md)).

7. **Behavioral statements** come from the code read at the pinned sha —
   never from Monero documentation, Monero source, or memory of Monero
   behavior (rules 10/60: the codebases are siblings; Monero is not an
   upstream).

To re-run: repeat 1–3 at the new sha, diff the visited-function list, then
diff rows per function.

## 2. Denominator

Counts at `8ba1aae3d`:

| Quantity | Count |
| --- | --- |
| Entry points | 4 |
| Visited functions (frontier at exhaustion, §1.3; unique backticked names) | 97 |
| Rules (rows in §4) | **161** |
| — consensus-flagged | 152 |
| — policy-flagged | 9 |
| Bucket 1 (Shekyl-specific, spec'd) | 84 |
| Bucket 2 (inherited, ratified on record) | 23 |
| Bucket 3 (inherited, marked for deletion on record) | **0** |
| Bucket 4 (inherited, never examined) | 54 |

Sum check: 84 + 23 + 0 + 54 = 161 = 152 + 9. Every row carries exactly one
bucket; the counts are mechanical (`grep -c '^| CEN-'` and the bucket/flag
columns). Bucket 3 is empty and that is a statement, not an omission:
pre-genesis, inherited rules examined and marked for deletion have been
**deleted** (rule 60: "deleted, not preserved behind version checks"), so nothing live carries
that disposition; removed-rule records (MSW-6, the CLSAG/ring surface, the
claim-era types) appear in §5/§6 as history, not rows. Reproducible counts:

```sh
grep -c '^| CEN-' docs/design/CONSENSUS_RULE_CENSUS_3.md          # rows
grep '^| CEN-' … | awk -F'|' '{gsub(/ /,"",$5); print $5}' | sort | uniq -c  # C/P
grep '^| CEN-' … | awk -F'|' '{gsub(/ /,"",$6); print $6}' | sort | uniq -c  # buckets
```

Inverse spot-check (all six MUST appear as rows, or the census is red — all
present): FCMP++ membership verification (CEN-I15), PQC transaction auth
(CEN-I16–I18), timestamp median (CEN-C2), miner-tx emission check
(CEN-F13–F18), key-image double-spend (CEN-I7 verify-side, CEN-L1
connect-side), PoW (CEN-D1/D2).

## 3. Buckets

1. **Shekyl-specific** — designed for Shekyl with a written spec. Evidence:
   the spec/design doc.
2. **Inherited and ratified** — a design round or decision-log entry
   examined it and kept it. Evidence: a locatable pointer. A remembered
   ratification with no findable record is bucket 4.
3. **Inherited, examined, marked for deletion** — recorded disposition.
4. **Inherited, never examined** — the working set. The row records the
   behavioral statement and its site(s); "is this right for Shekyl?" is
   asked, not answered.

Every bucket-2 evidence pointer in §4 (and every bucket-1 pointer that a
row's bucket assignment turns on) was verified against the pinned tree:
the cited doc line was read and contains the quoted claim. Three pointers
that code comments or first drafts carried were corrected to their real
homes during that verification (§6.5); none failed terminally, so no row
was demoted.

---

## 4. Rows

Columns: **CEN-id** | behavioral statement | enforcement site(s) (`blockchain.cpp` unless another file is named; all under `src/cryptonote_core/` unless pathed) | **C**onsensus / **P**olicy | bucket | evidence | notes. Sites are `file:line` at the pinned sha.

### 4.A Acceptance topology

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | A block whose hash is already known (main, alt, or invalid set) is rejected with `m_already_exists` | 6637 (`have_block` :3094 → `have_block_unlocked` :3062) | C | 4 | — | |
| CEN-A2 | A block whose `prev_id` equals the current tail goes to the main-chain path; any other goes to the alternative path | 6645–6655 | C | 4 | — | routing, but ratifiable: it decides which rule set runs |
| CEN-A3 | The witness-less 2-arg `add_new_block` refuses any block with a non-empty `attestation_root` (a caller dropped the credit-wire witness) | 6619 | C | 1 | `ARCHIVAL_CREDIT_WIRE.md` §3 | hard guard until the miner-local path is rewired (FOLLOWUPS) |
| CEN-A4 | A block whose parent is in neither main nor alt storage is marked orphaned and **not stored**; the p2p layer must re-request ancestry | 2511–2518 | C | 4 | — | |
| CEN-A5 | An incoming block blob larger than the current cumulative weight limit + `BLOCK_SIZE_SANITY_LEEWAY` is rejected before parse | cryptonote_core.cpp:1408–1419, 1342 | C | 4 | — | pre-parse approximation of CEN-G6b's real limit |
| CEN-A6 | A block blob that fails `parse_and_validate_block_from_blob` is rejected | cryptonote_core.cpp:1355 | C | 4 | — | wire-format boundary (§1.6); the parse itself is census subject of `BLOCK_TX_WIRE_FORMAT_PORT.md` |

### 4.B Block header: version, attestation, curve-tree root

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-B1 | Block `major_version` must equal the voted current version — with the shipped single-entry table `{v1, h1, threshold 0}` on all three networks this is exactly `major_version == 1` | 5727 (main, `HardFork::check` → `do_check` src/cryptonote_basic/hardfork.cpp:109); 2242 (alt, `check_for_height` :128 → `do_check_for_height` :121); table src/hardforks/hardforks.cpp:35–50 | C | 2 | rule [`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc) ("minimum hard fork version is 1"); hardforks.cpp:34 "Rebooted chain: all features active from genesis." | |
| CEN-B2 | Block `minor_version` is unconstrained (any value ≥ 0 accepted; 0 reads as a vote for 1) | src/cryptonote_basic/hardfork.cpp:41–50, 109–113 | C | 4 | — | vote signal with nothing to vote for; §5 |
| CEN-B3 | The hard-fork **voting machinery** runs on every connect (rolling window 10080, threshold accounting, per-height version persisted) but is inert: one table entry, threshold 0, nothing to advance to; `HardFork::add`'s reject verdict is discarded at the DB call site | src/cryptonote_basic/hardfork.cpp:134–161; src/blockchain_db/blockchain_db.cpp:641 | C | 4 | — | rule-60 question: delete the machinery or keep as scaffold — a design round's call, not the census's |
| CEN-B4 | The block's `attestation_root` must equal the root recomputed from the (possibly empty) credit-wire witness, and every pass record's P-countersignature must verify against the bond's committed hybrid pubkey; nonce binds coinbase `vout[0]` key and the validated `prev_id` | 5738 (main) / 2253 (alt) → `verify_block_attestation` 5565–5662; verdict in Rust `shekyl_archival_verify_attestation` | C | 1 | `ARCHIVAL_CREDIT_WIRE.md` §3–§4 | pre-cutover: empty witness ⇒ empty-set root. The doc's §3 enforcement-status paragraph is stale (names a deleted `check_attestation_root`, calls the recompute "next slice") — code has the full recompute; §6.4 |
| CEN-B5 | After connect, the header's `curve_tree_root` must equal the root the DB computed by growing the tree with this block's outputs; mismatch pops the block and rejects | 6422–6437 | C | 1 | `docs/FCMP_PLUS_PLUS.md` :264, :281 | skipped on FAKECHAIN; alt path defers to promotion (CEN-K5) |

### 4.C Timestamps

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-C1 | Block timestamp must not exceed local wall-clock + `SHEKYL_DAA_FTL_SECONDS` (540) | 5538 | C | 1 | `config/consensus_constants.json` (`daa_ftl_seconds`); `docs/completed/DAA_LWMA1.md` §4 | constant is config-sourced (bucket 1 by construction); comparison uses the validator's local clock |
| CEN-C2 | Block timestamp must be ≥ the median of the previous `SHEKYL_DAA_MTP_WINDOW` (11) block timestamps — equality accepted, strictly-less rejected | 5519 (main 5749; alt 2307 over alt-chain timestamps + `complete_timestamps_vector` 2133) | C | 2 | `docs/completed/DAA_LWMA1.md` §5.5 (examined in the DAA round, "preserved unchanged"; window re-pinned to 11) | inherited comparison kept; **spec divergence**: the doc says "strictly greater"; the code accepts equality — §6.3 |
| CEN-C3 | Below `SHEKYL_DAA_MTP_WINDOW` blocks of history, any timestamp ≤ FTL is accepted (no median exists yet) | 5547 | C | 4 | — | bootstrap carve-out; window constant is ratified, the carve-out itself is inherited shape |

### 4.D PoW and difficulty

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-D1 | The block's PoW longhash must satisfy the difficulty target (`check_hash(pow, diff)`) | 5818 (main) / 2347 (alt) | C | 1 | `docs/FCMP_PLUS_PLUS.md` is silent here; PoW spec is `RANDOMX_V2_*` (see CEN-D2) — the hash-meets-target comparison itself is the inherited 128-bit check | comparison mechanics `check_hash` inherited: bucket-4 residue noted in §5 |
| CEN-D2 | The longhash function is RandomX v2 via Rust FFI unconditionally (height/version ignored); on FFI failure the hash is forced to `0xff…` so it can never meet a target (fail closed) | cryptonote_tx_utils.cpp:748/:766; src/crypto/pow_registry.cpp:6; src/crypto/pow_randomx.cpp | C | 1 | `RANDOMX_V2_PLAN.md` ("C JIT for mining, Rust interpreter for verification — permanent") | |
| CEN-D3 | RandomX seed block: epoch 2048 blocks with lag 64 — `seedheight(h) = 0 for h ≤ 2112, else (h−65) & ~2047`; seed hash is the block id at that height (alt path: resolved along the alt chain when the seed height is on it) | rust/shekyl-pow-randomx/src/seed_epoch.rs:109; blockchain.cpp:6493, 2327–2345 | C | 1 | `RANDOMX_V2_RUST.md` :392, :790–823 (the seed-epoch constant and typed seedheight formula); `RANDOMX_V2_PLAN.md` :171, :201 (non-tunable protocol constants) | env-overridable for regtest only |
| CEN-D4 | Next-block difficulty is LWMA-1 over the last N+1 (=91) blocks (Rust `lwma1_next_difficulty`); below N blocks of history the genesis difficulty constant (100) applies | 1082–1175; rust/shekyl-difficulty | C | 1 | `docs/completed/DAA_LWMA1.md` §4 (ratified 2026-05-18); `config/consensus_constants.json` `daa_*` | bias 99/200, clamp 6, min-L 1/20 are deliberate bare literals in `lwma1.rs` per the Round-3 disposition |
| CEN-D5 | Alt-chain difficulty: the same LWMA-1 fed by a window stitched from main-chain prefix + alt-chain suffix | 1544–1638 | C | 4 | — | window-stitching shape inherited; LWMA core is CEN-D4's |
| CEN-D6 | Difficulty of zero aborts block acceptance (overflow guard assert) | 5766 / 2324 | C | 4 | — | |
| CEN-D7 | `--fixed-difficulty` overrides the DAA (regtest lever; height 0 forced to 1) | 1084–1087 | C | 4 | — | test-only carve-out live in production binary |

### 4.E Checkpoints and fast-sync trust

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-E1 | In the checkpoint zone, the block id at a checkpointed height must equal the hardcoded/JSON-loaded checkpoint hash | 5829–5837 (main); 2315 (alt; a checkpoint match forces the reorg, 2481) | C | 4 | — | checkpoint tables are **empty** on all networks (src/checkpoints/checkpoints.cpp:181–193); mechanism live, data vacuous |
| CEN-E2 | An alternative block below (or at) the last checkpoint preceding the current height is refused | 2233 (`is_alternative_block_allowed` src/checkpoints/checkpoints.cpp:137) | C | 4 | — | vacuously permissive today (no checkpoints) |
| CEN-E3 | Compiled-in per-block hash list (`m_blocks_hash_check`, PER_BLOCK_CHECKPOINT): inside its range a block's id must equal the compiled hash, and PoW, pool-supplement NIC and per-tx input checks are **skipped** (`fast_check`); pruned-block weights come from the same table | 5786–5804, 5855, 6037, 6073–6081; loaded via `load_compiled_in_block_hashes` 7544 | C | 4 | `DAEMON_RELAY_PRIVACY.md` :12574–12589 examined it and left it open ("a shipping decision nobody has taken") | trust surface; the GF-1 belt (CEN-G8) exists because of this skip |
| CEN-E4 | `check_tx_inputs` (pool wrapper) returns success unchecked when `kept_by_block` and the chain is below the hash-check size | 3246–3254 | C | 4 | — | |
| CEN-E5 | Loading a checkpoint JSON file (`--enforce-dns-checkpointing` era mechanism reduced to file load) can add checkpoints at runtime | src/checkpoints/checkpoints.cpp:195–229; `update_checkpoints` 6699 | C | 4 | — | operator-supplied consensus pins |

### 4.F Miner transaction (structure and emission)

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-F1 | Coinbase has exactly one input, of type `txin_gen` | 1642–1643 | C | 4 | — | |
| CEN-F2 | Coinbase tx version ≥ 3 | 1644 | C | 2 | rule 60 (v3-from-genesis); genesis blob is v3 (`033c…`, cryptonote_config.h:368) | |
| CEN-F3 | Coinbase CT type is `CTTypeNull` (no FCMP++ signature material) | 1645 | C | 2 | rule 60: "`CTTypeNull` for coinbase" | |
| CEN-F4 | Coinbase has exactly 1 output; genesis (caller-derived height 0) exempt | 1673 | C | 1 | `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.3 (F-H); FOLLOWUPS "GENESIS-FREEZE: cap the coinbase output count" | claimed-height spoof closed by CEN-F5 |
| CEN-F5 | `txin_gen.height` must equal the block's chain position | 1677 | C | 4 | — | |
| CEN-F6 | Coinbase `unlock_time` must equal height + `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) | 1683 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` §13 :907 (frozen domain constraint); `CT2_DRAIN_ORDER.md` :248 pins the 60 | value inherited, pinned not re-derived; the same 60 drives coinbase tree-maturity (CEN-L12) |
| CEN-F7 | Coinbase output amounts must not overflow when summed | 1686 (`check_outs_overflow` cryptonote_format_utils.cpp:899) | C | 4 | — | |
| CEN-F8 | Coinbase outputs must be `txout_to_tagged_key` (view-tagged; sole output type) — the same commitment as CEN-H12, enforced separately at the miner-tx surface (the coinbase never passes the H-path) | 1692 (`check_output_types` cryptonote_format_utils.cpp:971) | C | 2 | as CEN-H12 (`GENESIS_TX_WIRE_FORMAT.md` §2.2 :308–309) | |
| CEN-F9 | Coinbase output keys must be canonical, prime-order, non-identity points (Rust batch check) | 1697 (`check_outs_valid` cryptonote_format_utils.cpp:837) | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §2.3 | |
| CEN-F10 | Coinbase commitment masks: canonical prime-order, non-trivial (≠ identity, ≠ G), and ≠ `zeroCommit(amount)` (the amount-leaking fingerprint) | 1699 → 3287–3341; Rust `shekyl_check_commitment_masks` | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §2.3 | |
| CEN-F11 | Genesis (height 0) emission is accepted as configured (`GENESIS_TX` blob per nettype); structure validated, amount not recomputed | 1754–1761; init 508–517 | C | 1 | genesis pipeline (`GENESIS_TRANSPARENCY.md`, `GENESIS_ALLOCATIONS.md`, `FOUNDATION_GENESIS_IDENTITY_SET.md`) | |
| CEN-F12 | Decomposed-denomination check on coinbase outputs is **dead code**: the gate is `if (version == 3)` where `version` is the *hard-fork* version parameter (sole caller passes `m_hardfork->get_current_version()` at :6272), which is always 1 — `is_valid_decomposed_amount` never runs | 1763–1770 (gate); table cryptonote_format_utils.cpp:1528 | C | 4 | — | §5 dead-dispatch material. Load-bearing dead: with the 1-output cap (CEN-F4) and exact payout (CEN-F18) the single output is `emission+fees`, which is essentially never a table denomination — a Rust port implementing this as live would reject nearly every block. `GENESIS_TX_WIRE_FORMAT.md` :454 (Q2) sheds the *chunking*, not this gate |
| CEN-F13 | Base subsidy: `(MONEY_SUPPLY − already_generated) >> 21`, floored at tail subsidy 600 000 000 atomic/block; computed in Rust (`shekyl-economics::block_reward_with_penalty`), C++ is a marshaling shim | 1776 → cryptonote_basic_impl.cpp:93/:148 → rust/shekyl-economics/src/emission.rs:142 | C | 1 | `config/economics_params.json` (`money_supply` 4 294 967 296 000 000 000, `emission_speed_factor_per_minute` 22, `final_subsidy_per_minute` 300 000 000); `docs/ECONOMY_EXPLAINED.md` | 81-vector cross-language KAT pins C++ ↔ Rust |
| CEN-F14 | Weight penalty: median soft-raised to the 300 000-byte free zone; weight ≤ median ⇒ full subsidy; median < weight ≤ 2·median ⇒ quadratic penalty `base·(2m−w)·w/m²` in u128 (fail-closed on overflow); weight > 2·median ⇒ block rejected (**inclusive** bound — exactly 2·median is accepted at zero reward, deliberately diverging from the inherited exclusive bound) | emission.rs:150–176; reject surfaces at 1776–1780 | C | 1 | emission.rs doc-comments + the pinned KAT; divergence recorded in cryptonote_basic_impl.cpp BLOCK_TOO_BIG arm | |
| CEN-F15 | Release-rate multiplier: subsidy scaled by `clamp(tx_volume_avg·10⁶/baseline, 0.8·10⁶, 1.3·10⁶)/10⁶`, then capped to remaining supply | cryptonote_basic_impl.cpp:148; rust/shekyl-economics/src/release.rs:24 | C | 1 | `config/economics_params.json` (`shekyl_release_min/max`, `shekyl_tx_volume_baseline` 50); `docs/ECONOMY_EXPLAINED.md` | `tx_volume_avg` operand from `get_tx_volume_avg` (2111) |
| CEN-F16 | Emission split: subsidy divides into miner and staker legs (`compute_emission_split`, Rust); the coinbase may pay only the miner leg | 1783–1785 | C | 1 | `ARCHIVAL_BUDGET_SCHEDULE.md` §2.2 (F-B1c operand discipline) | |
| CEN-F17 | Fee burn split: fees divide into `miner_fee_income` / staker pool / destroyed (`compute_fee_burn`, Rust, operands: fee sum, tx-volume avg, circulating supply, frozen segment count); the coinbase may pay only `miner_fee_income` | 1791–1792 | C | 1 | `config/economics_params.json` `SHEKYL_BURN_*`; `docs/ECONOMY_EXPLAINED.md`; `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.11.1 | |
| CEN-F18 | The coinbase must pay **exactly** `miner_emission + miner_fee_income` — both overpay and underpay reject | 1794–1803 | C | 1 | same economics set; the exact-equality (vs ≤) is part of the split design | |
| CEN-F19 | `frozen_segment_count` (the D2 escalation operand) must be read at parent state: `m_db->height()` must equal the block's height at the read point or the node halts | 1732–1743 | C | 1 | `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.12 (read point settled: "the single asserting reader"); §6.2 for the operand identity | tautology-resistance documented at the site |

### 4.G Block body (per-tx and block-level, main-chain connect)

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-G1 | No listed tx may already exist in the chain | 5936 (belt: `TX_EXISTS` at lmdb/db_lmdb.cpp:1074) | C | 4 | — | |
| CEN-G2 | Every listed tx hash must resolve from the mempool or the block's pool supplement; otherwise reject with `m_missing_txs` (taken pool txs are returned on any failure) | 5969–6007 | C | 4 | — | tx content ↔ hash agreement is established here by lookup-under-computed-hash; the DB layer trusts it (§5) |
| CEN-G3 | Pool-supplement txs must pass the full non-input consensus set at the current HF version before the block may connect | 5860 (main) / 2380 (alt) | C | 4 | — | the NIC set itself is CEN-H* |
| CEN-G4 | Every listed tx must pass `check_tx_inputs` at connect; failure marks the block invalid and rejects it. FCMP++ txs that verified at pool admission skip only the FCMP proof re-verify (structural checks re-run) | 6036–6064 | C | 1 | skip: `DAEMON_RELAY_PRIVACY.md` §71–§72.1 — `hop` is defined as pool-admission-side verification; moving it re-derives the embargo | cache: CEN-M8 |
| CEN-G5 | When syncing pruned blocks, the block weight must be available from the compiled hash-check table | 6073–6081 | C | 4 | — | |
| CEN-G6 | Weight-limit frozen bounds: long-term window 100 000 blocks, short-term surge ×50 | 6580, 6593; constants cryptonote_config.h | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` §10 :803 (frozen limits — reject on exceed) | |
| CEN-G6b | Weight-limit remainder: effective median = clamp(short-term median, long-term effective median, 50×long-term), floored at the 300 000-byte penalty-free zone (`…FULL_REWARD_ZONE_V5`); **limit = 2 × median**; long-term weight = weight clamped to [median·10/17, median·1.7] | 6440, 6568–6607, 6548–6566, 1809–1870 | C | 4 | — | the V5 reward-zone value's arbitration was explicitly punted "to the economics doc" (`GENESIS_TX_WIRE_FORMAT.md` :806–811) and never landed anywhere — §5; the reward-side 2·median rejection is CEN-F14 |
| CEN-G7 | No two serve-credit vins in one block may carry the same (P, shard, E) — checked across txs against the `ArchivalPairEpochKey` byte encoding | 6102–6131 | C | 1 | `docs/completed/ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md` D-SC-C; PC-D4 non-widening rationale at the site | mirrored in Rust `serve_credit_block_unique` |
| CEN-G8 | Under the compiled-hash fast path, a debit-side bond post (bond_debit > 0) must still authorize against the record's committed `bond_spend_pk` (the GF-1 theft-shaped belt); credit arms stay checkpoint-trusted | 6162–6204 | C | 1 | GF-1: `ARCHIVAL_FIREWALL_GATE6.md` §9.6 :799; `ARCHIVAL_BOND_GATE4.md` §3.5 step 5 | exists because CEN-E3 skips per-tx verify |
| CEN-G9 | No two emission claims in one block may name the same (P, E) pair (Rust `shekyl_emission_block_claims_unique` over 40-byte P‖epoch_le entries) | 6210–6252 | C | 1 | `docs/completed/REWARD_EMISSION_E3_GATING_ROUND.md` §6.2 layer 2 | serve-credit + Unbond same-P same-block deliberately NOT rejected (ratified 2026-07-12, site comment 6147–6152) |
| CEN-G10 | At most one bond post per P per block (Rust `shekyl_archival_bond_post_block_unique`) | 6253–6261 | C | 1 | `ARCHIVAL_BOND_GATE4.md` §3.5 | |
| CEN-G11 | Per non-genesis block, staker inflow (staker emission leg + staker fee-pool share) is accrued to `archival_budget_accrual`, and the destroyed fee share is burn-recorded; operands are exactly `validate_miner_transaction`'s — `compute_emission_split(base_reward, height, genesis_ng_height)` :6347 and `compute_fee_burn(fee_summary, tx_volume_avg, already_generated_coins, frozen_segment_count)` :6350; **neither takes a version** | 6282–6356, 6447–6460; tripwire `scripts/ci/check_archival_reward_gates.sh` | C | 1 | `ARCHIVAL_BUDGET_SCHEDULE.md` §2.2 (F-B1a/c; the tripwire records F-B1b's version-operand discipline as RETIRED) | consensus state write, not a check. The in-code comment at :6293–6306 still narrates the retired `bl.major_version` operand — stale, contradicted by the calls below it (§6.10) |
| CEN-G12 | `already_generated_coins` advances by the full subsidy, clamped at `MONEY_SUPPLY` (single Rust entry point `shekyl_advance_already_generated`; the former two hand-written C++ copies were deleted as a drift pair) | 6374; alt bookkeeping 2303 | C | 1 | site comment 6364–6373 | |
| CEN-G13 | Genesis (height 0) has no staker accrual: its emission is the configured blob, paid whole by the coinbase | 6337–6343 | C | 1 | site comment; genesis docs (CEN-F11) | |

### 4.H Transaction: non-input consensus, semantics, outputs

All rows here are enforced at **both** pool admission (`ver_non_input_consensus` from `tx_pool.cpp:236`) and block connect (pool-supplement verify, CEN-G3) — one rule, two sites — except where noted.

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-H1 | Serialized tx size ≤ `CRYPTONOTE_MAX_TX_SIZE` (1 000 000 bytes) | tx_verification_utils.cpp:66; cryptonote_core.cpp:728 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` §10 :790 (frozen limit) | constant hand-maintained (cryptonote_config.h:42) |
| CEN-H2 | Tx version must be exactly 3 (HF-dispatched min/max collapse to 3 at HF1; independently re-enforced at CEN-I3) | tx_verification_utils.cpp:55–56, 74 | C | 2 | rule 60 v3-from-genesis; `GENESIS_TX_WIRE_FORMAT.md` :491, Q12 ruling :654–655 (deliberate keep; V4 = lattice-only) | dead 1/2-version arms: §5 |
| CEN-H3 | Tx weight ≤ half the minimum block weight minus coinbase reserve (= 149 400) | tx_verification_utils.cpp:82, 203–210 | C | 2 | `DAEMON_SUBMIT_VERDICT.md` §8 row N3 :1271 (examined disposition, submit path) | block-connect side of the same rule not separately examined (§5) |
| CEN-H4 | Non-coinbase tx must have ≥ 1 input | cryptonote_core.cpp:774 | C | 4 | — | |
| CEN-H5 | Input variants: `txin_gen` forbidden outside coinbase; only `txin_to_key` and the three archival variants allowed; `txin_to_script`/`txin_to_scripthash` rejected everywhere (incl. the double-spend visitor and the DB whitelist) | cryptonote_format_utils.cpp:773–801; blockchain.cpp:3162–3168; blockchain_db.cpp:398–402 | C | 4 | — | script variants are fossils: §5 |
| CEN-H6 | Archival vin mixing: serve-credit vins mix with nothing; ≤ 1 bond post; ≤ 1 emission; emission and bond-post never co-reside; key-imaged `txin_to_key` are the only permitted co-residents of a bond post or emission (classification single-sourced in `classify_archival_tx`) | cryptonote_format_utils.cpp:802–833; cryptonote_basic.h:353 | C | 1 | `docs/completed/REWARD_EMISSION_E3_GATING_ROUND.md` §2.1 (Q3 arity), §2.2 (Q11 mixing), §9.5 item 4 | |
| CEN-H7 | Every output must yield a canonical, prime-order, non-identity output key (Rust batch `shekyl_check_output_keys`) | cryptonote_format_utils.cpp:837; via cryptonote_core.cpp:790 | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §2.3 | stricter than the inherited `check_key` |
| CEN-H8 | For v>1: `outPk` count == vout count (also re-checked locally by the mask gate, and at parse) | cryptonote_core.cpp:799; blockchain.cpp:3298; cryptonote_format_utils.cpp `expand_transaction_1` ~:137 | C | 4 | — | |
| CEN-H9 | Output amounts must not overflow on summation; input-side sum covers only `txin_to_key.amount` — archival vins exempt (their value is CT-side/opaque) | cryptonote_core.cpp:808; cryptonote_format_utils.cpp:869–920 | C | 4 | — | exemption comment at site |
| CEN-H10 | No key image may repeat within one tx | cryptonote_core.cpp:819 (`check_tx_inputs_keyimages_diff` :913) | C | 4 | — | archival vins skipped (no key image) |
| CEN-H11 | Key images must be in the prime-order subgroup and not the identity (`ki ≠ identity`, `order·ki == identity`) | cryptonote_core.cpp:835 (`check_tx_inputs_keyimages_domain` :963) | C | 2 | `DAEMON_SUBMIT_VERDICT.md` §8 row M8 :1289 (thin-port disposition, pinned vectors); torsion posture binding per `GENESIS_TX_WIRE_FORMAT.md` :363/:404 | |
| CEN-H12 | Every output must be `txout_to_tagged_key` (view tag required; sole output type from genesis) | cryptonote_format_utils.cpp:971–996; sites cryptonote_core.cpp:843, blockchain.cpp:3393, 1692 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` §2.2 :308–309 ("view_tag becomes mandatory"; "The **sole** genesis output type") | dead grace-period arms: §5; the ML-KEM tag *derivation* is FA-6's (wallet-side) |
| CEN-H13 | Non-coinbase tx version < 3 rejected at output check (dup of CEN-H2, third site) | blockchain.cpp:3348 | C | 2 | as CEN-H2 | |
| CEN-H14 | All vout amounts must be 0 (confidential) — except a well-formed archival **emission** tx, whose non-zero ("loud") vouts are the reward commit set | blockchain.cpp:3355–3374 | C | 1 | zero-amount base: `GENESIS_TX_WIRE_FORMAT.md` §9.6 :769; loud-emission exemption: `REWARD_EMISSION_LEG.md` §5.5 :494–503 ("emission mint is not confidential") | the code comment's `REWARD_EMISSION_VIN_PLAN.md §4` pointer is broken (that §4 is PR sequencing) — §6.5 |
| CEN-H15 | CT type must be `CTTypeNull` or `CTTypeFcmpPlusPlusPqc`; anything else rejected (again in the batch verifier, and `CTTypeNull` re-rejected for non-coinbase at input check) | blockchain.cpp:3376; tx_verification_utils.cpp:221–239; blockchain.cpp:3626 | C | 2 | rule 60 ("Accepted transaction types") | |
| CEN-H16 | `unlock_time` must be < `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500 000 000): timestamp-based unlocks are consensus-rejected; height form otherwise unconstrained for non-coinbase | blockchain.cpp:3384 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` :888–891 (ratified creation cut); Decision 13 per `docs/FCMP_PLUS_PLUS.md` §7 step 0; decision-log 2026-06-14 Time-fields entry (height not manipulable time) | height-based nonzero unlocks remain consensus-legal but relay-banned (CEN-M5) and tree-ignored (CEN-L12) — see §5 |
| CEN-H17 | Output commitment masks (all txs): canonical prime-order, non-trivial; coinbase additionally ≠ `zeroCommit(amount)` | blockchain.cpp:3287–3341 (sites 3401, 1699) | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §2.3 | Rust `shekyl-ct-balance` |
| CEN-H18 | CT cleartext balance: `sum(pseudoOuts) = sum(outPk masks) + fee·H`, canonical points, verified in Rust (`shekyl_verify_ct_balance`), single-sourced with the builder | src/fcmp/ct_semantics.cpp:206–231 | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §2.3; site comment | |
| CEN-H19 | Bulletproof+ layout must be canonical and the aggregate range proof must verify (batched across the block's txs) | ct_semantics.cpp:233–240; ct_types.cpp:240; src/fcmp/bulletproofs_plus.cc | C | 4 | — | the BP+ verifier is inherited C++ (`CPP_INHERITANCE_INVENTORY.md` disposition applies); its place in the FCMP++ tx is Shekyl design — split noted §5 |
| CEN-H20 | Serve-credit-only tx CT shape: no `pqc_auths`, no vouts, zero fee, no outPk/BP+/proof/pseudoOuts, type `CTTypeFcmpPlusPlusPqc`, and the fee-only balance `sum(masks) + fee·H = identity` holds vacuously | tx_verification_utils.cpp:113–131; ct_semantics.cpp:372–401; re-checked at blockchain.cpp:3656–3688 | C | 1 | gate-2 §5 (`docs/completed/ARCHIVAL_RETENTION_GATE2.md`) | |
| CEN-H21 | Bond-post tx CT shape: `pqc_auths` == vin count, ≥ 1 spend input, pseudoOuts == spend count, non-empty FCMP++ proof, and the CT balance with (credit, debit) = (`bond_credit`, `bond_debit`) | tx_verification_utils.cpp:132–148; ct_semantics.cpp:315–336 | C | 1 | `ARCHIVAL_BOND_GATE4.md` | |
| CEN-H22 | Emission tx CT shape: reward total = checked sum of vout amounts, must be > 0; proof presence ⇔ fee inputs present; pseudoOuts == fee-input count; balance `sum(pseudoOuts) + total_reward·H = sum(masks) + fee·H` (mint on the debit slot) | tx_verification_utils.cpp:149–181; ct_semantics.cpp:338–370 | C | 1 | `docs/completed/REWARD_EMISSION_E3_GATING_ROUND.md` §2.2 (`verCtSemanticsEmission`, `pseudoOuts == fee_input_count`, balance-exclusion KATs); `DAEMON_SUBMIT_VERDICT.md` :1445 row EV4 (mint rides the debit slot) | Rust checked-sum shared with CEN-J24 |

### 4.I Transaction inputs — the FCMP++ spend path

Enforced at pool admission (`tx_pool.cpp:304` → `Blockchain::check_tx_inputs`) and at block connect (CEN-G4) — two sites per row unless noted.

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-I1 | Non-serve-credit v≥2 txs must have ≥ 2 outputs | 3466–3474 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` :167 (oracle pass, "earlier 'exactly one' was over-strict"), :469; `DAEMON_SUBMIT_VERDICT.md` §8 row K1 :1321 | |
| CEN-I2 | Non-coinbase txs must be `CTTypeFcmpPlusPlusPqc` (ring-based inputs unrepresentable); the FAKECHAIN carve-out at 3476 exempts this row **and** CEN-I3/I4 (the whole `m_nettype != FAKECHAIN` block) | 3476–3483, 3615–3620 | C | 2 | rule 60; `docs/FCMP_PLUS_PLUS.md` | |
| CEN-I3 | Tx version exactly 3 (min == max == 3, re-stated independently of the HF dispatch); FAKECHAIN exempt (see CEN-I2) | 3493–3506 | C | 2 | as CEN-H2 | |
| CEN-I4 | ≤ `FCMP_MAX_INPUTS_PER_TX` (8) inputs — the cap covers total `vin.size()`, not just the key-image subset; FAKECHAIN exempt (see CEN-I2) | 3485–3491 | C | 1 | `GENESIS_TX_WIRE_FORMAT.md` §10 :788 (frozen), :165 (cap widened in the oracle pass); `docs/FCMP_PLUS_PLUS.md` :1155 | constant hand-maintained (cryptonote_config.h:311), not config/-sourced |
| CEN-I5 | `txin_to_key` key images must be strictly **descending** by `memcmp` — one rule, two guarantees: rejects unsorted AND in-tx-duplicate key images; no-key-image archival vins exempt | 3509–3530 | C | 2 | `GENESIS_TX_WIRE_FORMAT.md` §12 :871; the examination found and fixed a reversed-direction consensus bug against the oracle (:162–163) | overlaps CEN-H10 for the duplicate half |
| CEN-I6 | `key_offsets` must be empty on every `txin_to_key` (no ring offsets exist under FCMP++) | 3599–3605 (also 3552, 3576 on archival co-resident spends) | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 3a; rule 60 (decoy path deleted) | |
| CEN-I7 | No input's key image may already be spent on-chain (per-input DB lookup); the storage layer independently re-enforces at connect (CEN-L1) | 3607–3612 (also 3558, 3582) | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 0 | inverse spot-check row (key-image double spend) |
| CEN-I8 | `pqc_auths` count == vin count (serve-credit excepted: must be zero) | 3636–3643 | C | 1 | `docs/POST_QUANTUM_CRYPTOGRAPHY.md`; `FCMP_SPEND_SIGNING_PREIMAGE.md` | |
| CEN-I9 | `pseudoOuts` count == input count (regular spend; archival shapes use their spend-subset counts, CEN-H21/H22) | 3645–3654 | C | 1 | `docs/FCMP_PLUS_PLUS.md` | |
| CEN-I10 | `referenceBlock` must be an existing main-chain block | 4191–4198 | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 1a | |
| CEN-I11 | `referenceBlock` age window: ≥ `FCMP_REFERENCE_BLOCK_MIN_AGE` (5) and ≤ `FCMP_REFERENCE_BLOCK_MAX_AGE` (100) blocks old | 4200–4220 | C | 1 | `config/consensus_constants.json`; `docs/FCMP_PLUS_PLUS.md` §7 step 1 (incl. the MIN_AGE=5 reorg-margin rationale); value pin = Decision 14 (`docs/CHANGELOG.md` :26396–26399; `docs/audit_trail/2026-05-ffi-constant-drift-audit.md` :69) | no docs/design pin for the values — the CHANGELOG entry is the ruling record |
| CEN-I12 | The membership anchor is the curve-tree root at `referenceBlock`'s height, read from the per-height root table (not the block header — FAKECHAIN headers carry placeholders) | 4224–4226 | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 2 — which says "header field"; table-vs-header divergence flagged in §6.6 | |
| CEN-I13 | `curve_trees_tree_depth` ∈ [1, current tree depth] | 4236–4244 | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 2c | |
| CEN-I14 | The FCMP++ proof must be non-empty | 4246–4252 | C | 1 | `docs/FCMP_PLUS_PLUS.md` | |
| CEN-I15 | FCMP++ membership+spend-auth proof verifies in Rust (`shekyl_fcmp_verify`) over: proof bytes, all key images, all pseudoOuts, per-input PQC leaf hashes (`shekyl_fcmp_pqc_leaf_hash` of each hybrid pubkey), tree root, layers = depth+1, and the tx prefix hash | 4254–4314 | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 4 | inverse spot-check row (membership proof) |
| CEN-I16 | Per-input hybrid PQC auth: `auth_version == 1`; `flags == 0`; `scheme_id` ∈ {1 solo, 2 multisig}; solo key blob exactly `PQC_HYBRID_SINGLE_KEY_LEN` (1996 = Ed25519·32 + ML-DSA-65·1952 + header·12); multisig blob ∈ [3, `PQC_MAX_PUBLIC_KEY_BLOB` 16384] with the exact parse Rust-side | tx_pqc_verify.cpp:161–221 | C | 1 | `docs/POST_QUANTUM_CRYPTOGRAPHY.md`; `PQC_MULTISIG.md` (MSW-1) | inverse spot-check row (PQC auth) |
| CEN-I17 | The PQC-signed payload binds, per input: full tx prefix ‖ CtSig base ‖ keccak256(prunable) ‖ that input's PQC header ‖ keccak256 of **every** input's hybrid pubkey — so neither the FCMP++ proof nor any input's key can be swapped without invalidating signatures | tx_pqc_verify.cpp:62–158 | C | 1 | `FCMP_SPEND_SIGNING_PREIMAGE.md` (:27–:36 states the exact formula) | |
| CEN-I18 | The hybrid signature (Ed25519 **and** ML-DSA, or M-of-N multisig) over keccak256(payload) must verify in Rust (`shekyl_pqc_verify`); serve-credit-only txs are exempt (their signature lives on the vin, CEN-J10) | tx_pqc_verify.cpp:223–243; gate at blockchain.cpp:4348–4356 | C | 1 | `docs/POST_QUANTUM_CRYPTOGRAPHY.md`; `PQC_MULTISIG.md` | |

### 4.J Archival transaction families (all verdicts Rust-side; C++ marshals)

Serve-credit (per input; the whole-tx shape is CEN-H20):

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-J1 | The serve-credit vin is an opaque blob; only the Rust codec parses it (key extraction must succeed) | 5273–5280, 3893 idiom | C | 1 | `ARCHIVAL_RESPONSE_FORMAT.md` RF-D10 :772 (opaque `canonical_bytes`; the code comment's "RF-D1" label is the kept/pruned-boundary decision — §6.5) | |
| CEN-J2 | One pruned pass record per serve-credit vin, in vin order; each within `SERVE_CREDIT_PRUNED_MAX_BYTES` | 3724–3733, 5281–5285 | C | 1 | `ARCHIVAL_RESPONSE_FORMAT.md` RF-D1 :98 (kept/pruned boundary) | |
| CEN-J3 | Pair-epoch dedup: a (P, shard, E) with any existing pass row is rejected (one challenge per pair-epoch until the assignment issuer lands — reopen recorded) | 5287–5312 | C | 1 | `ARCHIVAL_PER_CHALLENGE_RECORD.md` §5.3; PC-D4/PC-D7 site comment with rule-21 reopen | block-level twin CEN-G7 |
| CEN-J4 | The named P must have a bond record | 5314–5319 | C | 1 | gate-2 | |
| CEN-J5 | Claimed epoch ≥ E_first (join epoch + 1) | 5321–5328 | C | 1 | gate-2 | |
| CEN-J6 | P must be `good_through` the claimed epoch | 5330–5335 | C | 1 | gate-2 | |
| CEN-J7 | The credit must land by the epoch's close height (`current_height ≤ H_close`), and the challenge seal block (`H_seal`) must already be on-chain | 5337–5358 | C | 1 | `ARCHIVAL_CHALLENGE_MECHANISM.md`; seal predicate Rust-authoritative (`challenge_seal_on_chain`) | |
| CEN-J8 | P must hold the shard at the derived fire height `H_fire` (deterministic from seal hash, P, shard, E — WS-1 symmetric with the slash consumer), and the shard's frozen segment must exist at `H_fire` | 5376–5402 | C | 1 | `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` | |
| CEN-J9 | The challenged leaf index is **derived** (P, shard, E, prev-block-hash), never read off the vin; its chunk is read from the live consensus leaf table (frozen segments immutable); all-zero prev-hash refused | 5404–5450; PC-D3 binding at 3689–3722 | C | 1 | `ARCHIVAL_RESPONSE_FORMAT.md` RF-D6 :447; `ARCHIVAL_PER_CHALLENGE_RECORD.md` §5.3 (PC-D3: valid in exactly one block — pool records are next-block-only) | PC-D3's derivation is an interim mitigation scheduled for deletion at the credit-wire cutover (2026-08-26 disposition) — rewrite spec must carry the reopen, not the mechanism |
| CEN-J10 | The full response verifies in Rust (`shekyl_archival_verify_serve_credit_vin`): record structure, P's countersignature (the vin-borne hybrid signature), retention-proof legs against the registry sub-root and leaf chunk | 5452–5474 | C | 1 | `ARCHIVAL_RESPONSE_FORMAT.md`; `ARCHIVAL_CHALLENGE_MECHANISM.md` | |

Bond post (per tx; whole-tx shape CEN-H21; spend-subset FCMP verify shares CEN-I15's binding):

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-J11 | Hybrid pubkey length canonical; `p_canonical_id` must recompute from it | 4808–4826 | C | 1 | `ARCHIVAL_BOND_GATE4.md` | |
| CEN-J12 | `bond_spend_pk` coupling: JoinMarket must commit one (canonical length); every other kind must not carry one | 5115–5128, 4838, 4906, 5054 | C | 1 | gate-4 §9.11 | |
| CEN-J13 | Debit arms (Unbond, HoldingsUpdate-drop, and the fast-path belt CEN-G8) authorize only against the record's **committed** `bond_spend_pk`; credit arms (JoinMarket, HU-add, Rebond) authorize with the identity key `P_pubkey` | 4850, 4968, 4957–4962, 5099–5104, 5203–5210 | C | 1 | GF-1: ruled `ARCHIVAL_FIREWALL_GATE6.md` §9.6 :799 (RESOLVED 2026-06-16); mechanics `ARCHIVAL_BOND_GATE4.md` §3.5 step 5 :419 | |
| CEN-J14 | JoinMarket semantics (Rust `shekyl_archival_verify_join_market_bond_post`): kind/shard-set shape, no debit, credit == bonded_total == bond_floor(holdings), record must not already exist | 5130–5148 | C | 1 | gate-4 §3.5; floor from `config/consensus_constants.json` `archival_bond_floor_atomic` | DB-side p_id uniqueness is NOT a constraint (flag-0 put) — verify is sole enforcement (§5) |
| CEN-J15 | JoinMarket admission viability (D3/R3): per-shard r_market + freeze-height/presence facts at parent height must pass `shekyl_archival_check_bond_admission`; drops deliberately ungated | 5150–5201 | C | 1 | `docs/completed/ARCHIVAL_SIM_ECONOMICS_VERDICT.md` / shekyl-archival-retention::admission rationale | |
| CEN-J16 | Unbond semantics (Rust): full exit only (debit == record total, post-total 0, empty holdings), release cooldown elapsed from the P2B-8 last-served anchors, slash settlement current through the anchor | 4832–4897 | C | 1 | gate-4 §3.5 debit path; `config/consensus_constants.json` `release_cooldown_epochs` | |
| CEN-J17 | HoldingsUpdate: add arm = exactly one shard, +FLOOR credit, good-standing record; drop arm = exactly one shard removed, −FLOOR debit, grace-tail/age facts verified (unfrozen shard pinned to the longest horizon) | 4900–5046 | C | 1 | gate-4 §3.4–3.5 | |
| CEN-J18 | Rebond (Rust): interval-log preconditions (single open interval, headroom bound), credit against identity key | 5049–5105 | C | 1 | gate-4 §3.4 (P2B-9 pins 4–6) | |

Reward emission (per tx; whole-tx shape CEN-H22):

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-J19 | The emission vin's opaque blob must parse (Rust extract: claimant P id + claimed epochs, ≥ 1) | 3888–3902 | C | 1 | `REWARD_EMISSION_VIN_PLAN.md` | |
| CEN-J20 | The emission slot's hybrid key must derive the vin's `P_canonical_id` (so the tx-wide hybrid signature over the slot is P's) | 3904–3921 | C | 1 | E3 §8.0.2 | |
| CEN-J21 | referenceBlock/curve-tree context as CEN-I10–I13, required even with zero fee inputs (the vin's membership-only backing proof verifies against that root) | 3942–3980 | C | 1 | `docs/completed/FCMP_MEMBERSHIP_ONLY.md` | |
| CEN-J22 | The signable hash is the prefix hash of the tx **with the emission vin removed**; every property the exclusion loses is re-bound by the Q1 auth message and the reward commit set | 3982–3994 | C | 1 | E3 (F-C1c) | |
| CEN-J23 | Every claimed epoch must have a frozen budget row (closed, unpruned epoch); the as-of-E snapshots are gathered per epoch | 3996–4034 | C | 1 | `ARCHIVAL_BUDGET_SCHEDULE.md`; `EMISSION_CLAIM_BUILDER.md` | |
| CEN-J24 | The reward commit set is the loud (non-zero) vouts in vout order (mask ‖ amount_le ‖ one-time key); zero-amount vouts are ordinary change; reward total is Rust-checked-summed (overflow rejects) | 4036–4084 | C | 1 | E3 §8.0.2 field 7; `REWARD_EMISSION_VIN_PLAN.md` §4 | |
| CEN-J25 | The coarse Rust verify (`shekyl_emission_vin_verify`) decides §7.1 claims 1–5 (claim-window/max-age, work arithmetic vs the frozen snapshots, reward total equality), the membership-only backing proof, and the hybrid auth gate — any non-OK rejects | 4086–4118 | C | 1 | `REWARD_EMISSION_LEG.md` §7.1; `ARCHIVAL_REWARD_ARITHMETIC.md`; `config/consensus_constants.json` `max_claim_age_w`, `settlement_epoch_blocks`, `max_settlement_epochs_per_emission` | this branch mints coins — flagged load-bearing at the site |
| CEN-J26 | Fee-input FCMP++ proof: absent ⇔ zero fee inputs; present ⇒ verifies over the `txin_to_key` subset exactly as CEN-I15 | 4120–4184 | C | 1 | E3 §7.1 step 7 | |

### 4.K Reorg / alternative chains

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-K1 | An alt block claiming height 0 is rejected | 2222–2228 | C | 4 | — | |
| CEN-K2 | Alt-chain linkage: the stored alt chain must connect to the main chain at the claimed height with matching hashes (asserted while rebuilding) | 2153–2205 | C | 4 | — | |
| CEN-K3 | An alt block already stored as an alt block is rejected | 2461 | C | 4 | — | |
| CEN-K4 | Alt blocks are accepted into storage after: version (CEN-B1 at ideal-version-for-height), attestation (CEN-B4), timestamp vs alt-window median (CEN-C2), checkpoint, PoW at alt difficulty (CEN-D1/D5), and **prevalidate**-only miner-tx checks; `validate_miner_transaction`, `check_tx_inputs` and the curve-root check are deferred to promotion | 2214–2509 | C | 4 | — | the deferral is the reorg path's central unexamined design decision (§5) |
| CEN-K5 | Promotion re-validates every block through the full 4-arg main-chain path (all §4.B–§4.J rules); any failure rolls back to the pre-switch chain and discards the failing alt suffix | 1425–1462 | C | 4 | — | |
| CEN-K5b | Each promoted block's credit-wire attestation witness is re-supplied from the hash-keyed alt table (and each demoted block's is captured off its height row before the pop), so the witness survives reorgs in both directions | 1436–1438, 1411–1418, 2469–2477 | C | 1 | `ARCHIVAL_CREDIT_WIRE.md` §3 (CW-2) | |
| CEN-K6 | Reorg trigger: alt cumulative difficulty **strictly greater** than main (equal stays), or an alt block matching a checkpoint forces the switch | 2481–2504 | C | 4 | — | |
| CEN-K7 | Demoted main-chain blocks re-enter as alt blocks (witness carried); on a discarded chain they are dropped | 1404–1419, 1465–1486 | C | 4 | — | |
| CEN-K8 | Alt bookkeeping's `already_generated_coins` is a documented approximation (coinbase-paid, not subsidy); nothing consensus-bearing reads it, and promotion re-reads the ledger | 2277–2303, 1504–1524 | C | 2 | site comment + FOLLOWUPS "Alt-chain supply accumulation" | examined-and-kept with rationale |
| CEN-K9 | Alt-block pool-supplement txs must pass NIC and enter the main pool (`relay_method::block`) or the alt block is rejected | 2378–2420 | C | 4 | — | |
| CEN-K10 | Pool `add_tx` with `kept_by_block` (block/reorg-sourced txs): input-check failure stores the tx anyway as `verification_impossible` (it may become valid again after further reorg) | tx_pool.cpp:305–357 | C | 4 | — | |

### 4.L Storage layer (constraints that reject chain data at write time)

From the §1 traversal of `src/blockchain_db/`. [SANITY]-class corruption guards and IO-error guards are counted once as CEN-L13, not row-per-throw; rows here are chain-rule enforcement.

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-L1 | Key-image uniqueness at block connect is enforced **solely** here: `add_spent_key`'s `MDB_NODUPDATA` put throws `KEY_IMAGE_EXISTS` (covers chain-wide and intra-block duplicates in one txn), caught at blockchain.cpp:6397 → block rejected. The pre-DB `check_for_double_spend` is dead (its only call site is commented out, blockchain.cpp:6024–6030) | db_lmdb.cpp:1411–1425 | C | 4 | — | inverse spot-check row (double spend at connect); pool-side pre-check is CEN-M6 |
| CEN-L2 | A connecting block's `prev_id` must exist and sit at height−1 — the wrong-height arm throws `BLOCK_PARENT_DNE` (:962); a missing parent throws `DB_ERROR` (:959); the only prev-linkage check below `Blockchain` (genesis exempt) | db_lmdb.cpp:951–963 | C | 4 | — | |
| CEN-L3 | Duplicate block hash (`BLOCK_EXISTS`) and duplicate tx hash (`TX_EXISTS`) reject at write | db_lmdb.cpp:948–949, 1071–1074 | C | 4 | — | belt behind CEN-A1/G1 |
| CEN-L4 | The base `add_block` recomputes the block hash (identity never trusted) but stores contained txs under the header's claimed hashes verbatim — content/hash agreement lives upstream (CEN-G2) | blockchain_db.cpp:459, 477–480 | C | 4 | — | recorded absence, see §5 |
| CEN-L5 | DB input-type whitelist duplicates CEN-H5 at write time; unknown bond-post kinds fatal | blockchain_db.cpp:398–402, 363–366 | C | 4 | — | |
| CEN-L6 | Every stored output must carry an outPk commitment and yield an output pubkey; coinbase/emission loud amounts store as amount-0 plus the real commitment | blockchain_db.cpp:424–434; db_lmdb.cpp:1274–1277 | C | 4 | — | |
| CEN-L7 | Archival connect-writers are fatal verify-backstops (never soft-skip): emission claim requires the bond record, re-runs the claimed-epochs dedup and claimability (already-claimed or unclaimable epoch aborts the connect), bond folds' Rust verdicts abort on failure | blockchain_db.cpp:301–395; db_lmdb.cpp:6428–6484, 6541–6597, 6746–6789 | C | 1 | WS-2 journaled check-and-set (E3); `ARCHIVAL_CONSENSUS_STATE.md` (the table/keying/invariants contract, pinned 2026-06-07) | |
| CEN-L8 | Epoch close at each settlement boundary: Rust fold freezes budget(E), r_market and sigma-work rows; accrual-sum overflow aborts (never mints) | db_lmdb.cpp:8326–8442; hook blockchain_db.cpp:655 | C | 1 | `ARCHIVAL_BUDGET_SCHEDULE.md`; `ARCHIVAL_SETTLEMENT_WRITER.md`; `ARCHIVAL_CONSENSUS_STATE.md` §3.5 | |
| CEN-L9 | Slash processing at each height: missed-baseline slashes apply via Rust interval verdicts; balance-invariant violations abort | db_lmdb.cpp:6193, 5911–6042 | C | 1 | `docs/completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1 (m=11/n=13 window, shape genesis-frozen); `config/consensus_constants.json` | |
| CEN-L10 | Segment freezes at each height: first-crossing rule over the append-only leaf count; a frozen segment's layer-2 sub-root must exist in the tree | db_lmdb.cpp:7978–8026 | C | 1 | `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §5.2; `config/consensus_constants.json` `segment_leaf_count` 25992 | |
| CEN-L11 | Curve-tree growth per block: every accepted output becomes a leaf (`shekyl_construct_curve_tree_leaf` over key ‖ commitment ‖ PQC leaf hash), added **pending** with a maturity height. The tree-**grow** verdicts (`hash_grow_selene`, `grow_upper_layers`) abort on failure; the leaf-**construct** verdict does not — a false return at :570–576 silently omits the output from the tree (as do the `continue` arms :562–565), with no verify-time twin | blockchain_db.cpp:500–617; db_lmdb.cpp:8964–9166 | C | 1 | `CURVE_TREE_CLIENT.md`; `docs/FCMP_PLUS_PLUS.md` | soft-skip = a deterministic but permanently unspendable output; FOLLOWUPS one-liner filed (§7) |
| CEN-L12 | Deferred-insertion maturity IS the spend-maturity rule: coinbase leaves enter the tree at height+60, all other outputs at height+`CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (10); `tx.unlock_time` plays **no** role in when an output becomes spendable | blockchain_db.cpp:531–575; drain `drain_pending_tree_leaves` :583 (impl db_lmdb.cpp:8589) | C | 1 | `docs/FCMP_PLUS_PLUS.md` §7 step 1 rationale ("Maturity is enforced by universal deferred tree insertion") | the spec's "staked: max(effective_lock_until…)" arm does not exist in code (claim-era); §6 |
| CEN-L13 | Corruption/desync guards throughout the write and pop paths (serve-credit re-parse, bond-counter overflow, journal-vs-tip belts, trim bounds, pruned-pop refusal, …) abort the operation rather than storing inconsistent consensus state | blockchain_db.cpp / db_lmdb.cpp per §1 traversal | C | 4 | — | counted as one row: sanity class, not independently ratifiable chain behavior |
| CEN-L14 | DB-absent uniqueness (deliberately verify-side only): serve-credit pass bits, bond records (JoinMarket p_id), budget accrual rows, witness rows, curve-root heights are flag-0 overwrites | db_lmdb.cpp:5168–5181, 5591–5615, 4916–4928, 9663–9672, 9618 | C | 4 | — | recorded absences, see §5 |

### 4.M Mempool admission (the `kept_by_block` axis)

`kept_by_block = (tx_relay == relay_method::block)` (tx_pool.cpp:229) — rows it exempts are **policy**.

| id | rule | site(s) | C/P | b | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-M1 | A tx already in the pool (broadcasted) or chain is accepted idempotently without re-verification | cryptonote_core.cpp:999–1009 | P | 4 | — | |
| CEN-M2 | Pool admission runs the full NIC set (CEN-H*) at the current HF version, cached per HF | tx_pool.cpp:236 | C | 4 | — | consensus rules, pool site |
| CEN-M3 | Relay fee floor: fee ≥ 98% of quantized `weight × fee_per_byte`, where fee-per-byte = `0.95·base_reward·ref_weight/median²` off the current reward/medians; unpayable-reward state rejects all | tx_pool.cpp:243–259; blockchain.cpp:4363–4413 | P | 2 | `DAEMON_SUBMIT_VERDICT.md` §8 row P2 :1309 (examined: C + D re-gate F34, KAT against `check_fee`); decision-log 2026-08-16/17 Fh-ceiling ruling ("KAT-pinned — not a literal") | formula constants (0.95, ref weight, quantization mask) themselves never examined as choices; `kept_by_block` exempt — **no consensus fee floor** |
| CEN-M4 | Relay cap on `tx_extra`: ≤ `MAX_TX_EXTRA_SIZE` (24576) | tx_pool.cpp:261–269 | P | 2 | `GENESIS_TX_WIRE_FORMAT.md` §10 :791 (frozen); `DAEMON_SUBMIT_VERDICT.md` §8 row P3 :1310 | canonical-form arbitration deferred to the credit-wire lane (index note); consensus side has no tx_extra bound beyond CEN-H1 |
| CEN-M5 | Relay ban on any nonzero `unlock_time` | tx_pool.cpp:271–278 | P | 2 | `DAEMON_SUBMIT_VERDICT.md` §8 row P1 :1308 | consensus allows height-based unlocks < sentinel (CEN-H16) that the tree then ignores (CEN-L12) — three-layer divergence, §5 |
| CEN-M6 | Relay-side double-spend pre-check against the chain (`have_tx_keyimges_as_spent`) | tx_pool.cpp:283–294 | P | 4 | — | consensus enforcement is CEN-I7 + CEN-L1 |
| CEN-M7 | Pool-side key-image conflict tracking (`insert_key_images`) prevents two pool txs spending one image in the same relay category | tx_pool.cpp:337, 496 | P | 4 | — | |
| CEN-M8 | FCMP++ verification cache: pool stores `H(proof ‖ referenceBlock ‖ key images)`; block connect skips only the proof re-verify when the hash still matches | tx_pool.cpp:485–494, 1735–1743; blockchain.cpp:4592–4625 | C | 1 | `DAEMON_RELAY_PRIVACY.md` §71–§72.1 (embargo-load-bearing placement) | |
| CEN-M9 | Engine-attested local submit (`insert_attested_tx`): a tx the Rust engine verified enters the pool without C++ re-verification; the certificate gate lives in the submit FFI; consensus still re-validates at block connect | tx_pool.cpp:550–640; src/rpc/daemon_submit_ffi.cpp:577 | P | 1 | `DAEMON_SUBMIT_VERDICT.md` §3–§4 | |
| CEN-M10 | Pool lifetime/eviction: non-`kept_by_block` txs expire at `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, `kept_by_block` at the longer alt-block lifetime; stale-reference (`ref_stale`) and weight-cap pruning evict lowest fee/byte first | tx_pool.cpp:1040–1059, 532 | P | 4 | — | |
| CEN-M11 | Zero-fee txs are never flagged for relay (`m_relay` set only when fee > 0) | tx_pool.cpp:519–521 | P | 4 | — | consensus permits zero-fee (archival serve-credit txs are zero-fee by rule CEN-H20) — the attested/block paths carry them |

---

## 5. Cross-cutting findings

Census notes, not rulings. Each names design-round input; none is fixed here
(the census's completion property depends on enumerate-without-fix).

**Dead validation surfaces (unreachable, so outside the §2 denominator; rule-60 material):**

1. **The whole ring-spend validation path is caller-less.** `Blockchain::check_tx_input` (:4532) — with `scan_outputkeys_for_indexes` (:256) and the spend-side `is_tx_spendtime_unlocked` gate inside it — has zero call sites. Ring/unlock spend validation survives as text only. (`is_tx_spendtime_unlocked` itself is still live for the RPC's `get_output_key_mask_unlocked` :2681.)
2. **The 2-arg `handle_block_to_main_chain` (:3100) is caller-less.** Every path uses the 4-arg form: `add_new_block` :6655, promotion :1438, rollback :1370. Answering the census brief's overload question: the "duality" is one live function plus one dead forwarder; there is no second rule set.
3. **`check_for_double_spend` (:3124) is dead** — its only call site is commented out (:6024–6030); the live enforcement is CEN-L1.
4. **HF version dispatch is dead from genesis**: all eleven `HF_VERSION_*` constants are 1 (cryptonote_config.h:278–290); every `>=` branch is always-taken, every else-arm unreachable (tx version 1/2 arms, view-tag grace arms, 2021-scaling legacy arm, per-byte-fee else, and the miner-tx decomposed-amount gate — CEN-F12). Four constants (`CRYPTONIGHT_VARIANT_1`, `EXACT_COINBASE`, `BULLETPROOF_PLUS`, `LONG_TERM_BLOCK_WEIGHT`) are unreferenced in production code (`src/` + `rust/`; `EXACT_COINBASE` and `BULLETPROOF_PLUS` still appear in `tests/core_tests/` — the eventual rule-60 cleanup owes that sweep), contradicting config.h's own "only constants still referenced are kept" claim. One dead-dispatch has a **live behavioral consequence**: `HF_VERSION_SMALLER_BP + 1` = 2 resolves to earliest-height `UINT64_MAX`, so `should_ask_for_pruned_data` (cryptonote_protocol_handler.inl:2065) always refuses — this node never requests pruned spans.
5. **`txin_to_script` / `txin_to_scripthash` variants** exist only to be rejected (three separate reject sites, CEN-H5) — variant fossils.
6. **Unused locals in `check_tx_inputs`**: `sig_index` (:3444) and the `pubkeys` vector (:3532) are ring-era residue, written and never read.

**Enforcement-shape findings:**

7. **The block-connect key-image double-spend check lives only in the storage layer** (CEN-L1): an LMDB `MDB_NODUPDATA` put, caught as an exception two frames up. The rewrite must decide where this rule lives — the current placement means "validation" is completed by a side effect of the write path.
8. **The DB stores contained txs under the header's claimed hashes verbatim** (CEN-L4). Hash/content agreement holds because connect resolves txs *by* hash from pool/supplement (CEN-G2); nothing re-derives the hash at the storage boundary.
9. **Uniqueness rules with no DB constraint** (CEN-L14): serve-credit pass bits, bond records, accrual/witness/root height rows are flag-0 overwrites; the verify layer is the sole enforcement. The PC-D4 comment at blockchain_db.cpp:775–786 records the bug class this tolerance once masked.
10. **`HardFork::add`'s reject verdict is discarded** at blockchain_db.cpp:641 — version validity is enforced only pre-connect (CEN-B1); the DB-side call is bookkeeping that cannot refuse.
11. **The unlock_time triple-divergence**: consensus accepts any height-form `unlock_time` < 500 000 000 (CEN-H16); relay refuses any nonzero value (CEN-M5); the curve tree ignores the field entirely and applies fixed maturities 60/10 (CEN-L12). A field that is consensus-legal, relay-illegal, and semantically inert. The rewrite should carry **one** story.
12. **Fees are pure relay policy**: a block may include a zero-fee tx (no consensus floor, CEN-M3 `kept_by_block` exempt); archival serve-credit txs rely on this.
13. **Two-site drift risk on the ver-NIC set**: the min/max tx-version dispatch (CEN-H2) and the FCMP++-path version pin (CEN-I3) state the same rule twice with different machinery; same for `CTTypeNull` rejection (three sites, CEN-H15). Not drifted today; the census records the pairs so the rewrite collapses them deliberately.
14. **The weight/reward-zone arbitration is an acknowledged hole**: `GENESIS_TX_WIRE_FORMAT.md` :806–811 punted the `FULL_REWARD_ZONE` V1/V2/V5 lineage question "to the economics doc"; no economics doc, decision-log entry, or FOLLOWUPS row ever received it (CEN-G6b). Consumed as given everywhere.
15. **Checkpoint machinery is live with empty data** (CEN-E1/E2/E5): a trust mechanism whose tables no design round has examined; the compiled-hash fast path (CEN-E3) was examined and explicitly left "a shipping decision nobody has taken".
16. **The reorg acceptance design was never examined** (CEN-K4/K6): prevalidate-only alt storage, full validation at promotion, strictly-greater cumulative-difficulty switch — no Shekyl record; inherited shape throughout, now interleaved with Shekyl-specific state (witness re-supply CW-2, archival journals' pop-side belts).
17. **`verify_block_attestation` runs before PoW** on both paths (5738 < 5818; 2253 < 2347). Cheap pre-cutover (empty witness); the Phase-5 ordering constraint (signature leg must sit behind PoW before population activates) is recorded at both sites — the census confirms it is not yet satisfied by ordering today. The FOLLOWUPS entry that carried this constraint survives only as a truncated headline (docs/FOLLOWUPS.md:467 mentions neither PoW nor ordering; the original body is in git at `4ff749085`), so the one-liner is re-filed by this census (§7).
18. **FAKECHAIN carve-outs inside consensus functions** (CEN-I2's type/version gates, CEN-B5's root check, CEN-D7's fixed difficulty, the SEB env override init gate): regtest levers compiled into production paths — enumeration input for the rewrite's test-seam design.
19. **`docs/MERKLE_TREE.md` documents the curve tree, not the block tx-hash tree** its name implies (grounded negative: no `tree_hash`/`get_block_hash` content) — the known naming residue, confirmed.
20. **BP+ range-proof verification is inherited C++** (`src/fcmp/bulletproofs_plus.cc`, CEN-H19) sitting inside an otherwise Rust-verdict CT layer; `CPP_INHERITANCE_INVENTORY.md` carries its file-level disposition, but the census flags it as the largest inherited-crypto verifier still on the acceptance path.

---

## 6. Decision log — where the census met the tree

Corrections logged when reading the tree contradicted the brief, a doc, or a
first assumption (the RK convention). Behavioral statements in §4 follow the
**code**; each divergence below is design-round input, not a fix.

1. **The brief's overload duality dissolved.** `handle_block_to_main_chain`
   has two overloads at :3100/:5689, but the 2-arg form has no callers — the
   question "which paths reach which overload and do their rule sets match"
   answers: one overload, one rule set, one dead forwarder (§5.2).
2. **`kept_by_block` is cleaner than expected.** The brief's consensus/relay
   axis maps exactly onto `tx_relay == relay_method::block` with no residue:
   every policy row in §4.M is gated on it, and nothing else is.
3. **MTP comparison: doc says strict, code accepts equality.**
   `DAA_LWMA1.md` §5.5: "must be strictly greater than the median"; the code
   (5519) rejects only `timestamp < median`. The doc also claims the rule was
   "preserved unchanged" from the inherited validator — the inherited
   comparison is the non-strict one, so the doc mis-states the comparison it
   preserved. Rule 94: code wins for the row (CEN-C2); whether Shekyl *wants*
   strict is the DAA round's question.
4. **`ARCHIVAL_CREDIT_WIRE.md` §3's enforcement-status paragraph is stale.**
   It names `Blockchain::check_attestation_root` (no longer in the tree) and
   calls the recompute-and-compare "the next slice"; the landed code performs
   the full recompute + countersignature verify via
   `shekyl_archival_verify_attestation` (CEN-B4). Spec content stands;
   status paragraph lags.
5. **Three code/doc evidence pointers were broken as written** and are
   corrected in the rows: the loud-vout comment cites
   `REWARD_EMISSION_VIN_PLAN.md §4` (actually PR sequencing; the rule lives
   in `REWARD_EMISSION_LEG.md` §5.5) — CEN-H14; the serve-credit opaque-blob
   comment says RF-D1 (actually RF-D10) — CEN-J1; the escalation read-point
   is settled in `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.12, not
   §6.2 — CEN-F19.
6. **`FCMP_PLUS_PLUS.md` §7 drifts from code in three places.**
   (a) Step 2 says the tree root is read from the block header; code reads
   the per-height root table, deliberately (FAKECHAIN placeholder roots) —
   CEN-I12. (b) Step 3b requires "key image y-normalization: bit 7 of
   byte 31 must be 0"; no such explicit check exists in
   `check_tx_inputs`, `check_tx_semantic`, or the FFI boundary
   (`KeyImage::from_canonical_bytes` is a plain wrapper). Whether the proof
   math inside `shekyl_fcmp_verify` enforces it implicitly is **untested by
   this census** — flagged for the FCMP round, not asserted either way.
   (c) Step 1's maturity note still lists a "staked:
   max(effective_lock_until…)" arm; the code has no staked branch
   (claim-era retired) — CEN-L12.
7. **The block-body assembly trusts hashes downward, not upward.** Expected
   a storage-layer recomputation of contained-tx hashes; found lookup-by-hash
   at connect plus verbatim trust at the DB (§5.8). The census records the
   agreement argument where it actually lives (CEN-G2).
8. **`is_valid_decomposed_amount` was expected to be dead** (confidential
   amounts) — it is live, but only for the miner tx's loud outputs
   (CEN-F12), and the Q2 record shows it was examined and kept-moot rather
   than overlooked.
9. **No anchor drift:** the dispatch sha and the census sha are the same
   commit (`8ba1aae3d`), and every brief anchor resolved at its stated
   line; no re-location was needed.
10. **Two stale in-code narrations, transcribed then caught.** The comment
    block at blockchain.cpp:6293–6306 still narrates the retired F-B1b
    `bl.major_version` accrual operand; the calls below it take no version
    (CEN-G11 — the CI tripwire itself records the discipline as RETIRED).
    And the `if (version == 3)` gate in `validate_miner_transaction`
    reads as a tx-version check but is a dead hard-fork-version branch
    (CEN-F12). Both first drafts of those rows transcribed the comment /
    surface reading; the verification pass corrected them against the
    code. Comment-vs-code divergences are design-round input, not fixed
    here.
11. **FOLLOWUPS itself has truncated entries** (observed, not fixed):
    docs/FOLLOWUPS.md:467 survives as a headline whose body (the
    attestation-behind-PoW ordering constraint) is gone, and entries at
    :941/:944/:947 end mid-sentence — pre-existing damage; the ordering
    one-liner is re-filed by this census (§7), the rest is a docs-hygiene
    item outside census scope.
12. **A sibling independent census exists and was not consulted.** PR #583
    (`CONSENSUS_RULE_CENSUS_2.md`, family `RC-`, same pinned sha) landed
    during this walk. Per the steering rule both PRs carry, the two row
    sets were **not** compared or reconciled — the divergences in the
    header are recorded as facts for the comparison round, which is its
    own work item.

## 7. Follow-ups filed

Findings needing action **outside** the census get FOLLOWUPS one-liners in
the same commit. Four are filed: §5.14 (the punted reward-zone
arbitration), §5.4 (dead HF version dispatch, rule 60), CEN-L11's
soft-skipped leaf-construct verdict (a silently unspendable-output arm),
and the attestation-behind-PoW ordering constraint (§5.17 — re-filed
because its previous entry survives only as a truncated headline, §6.11).
The alt-supply approximation (CEN-K8) already has a live entry and is not
re-filed. Everything else in §5/§6 is design-round input that the
bucket-4 rows themselves carry.
