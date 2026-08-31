# Consensus-rule census — independent second enumeration (RC-)

**Status:** OPEN — independent second census of the consensus-validation
surface. Last-verified 2026-08-31 against `dev` **`8ba1aae3dbd1e3b03504d5d27c0471bb67f11b9d`**.
Every `file:line` below was read at that commit. This document is the
instrument, not a ruling: bucket 4 records the question, never the
answer. No code is specified to change here.
**Identifier family:** `RC-` (rule census, pass 2), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit
that lands this document (rule 94). `CEN-` is left for the sibling first
census (`CONSENSUS_RULE_CENSUS.md`) so the two enumerations cannot mint
colliding tokens. Prefix `RC-` is unique against `RF-` / `RK-` / `RP-` /
`RT-`.
**Sibling:** this is a second, independent walk of the same surface the
first census enumerates. Disagreement between the two documents is
census material, not a defect to reconcile in this PR.
**Process:** docs-only. Enumeration by call graph from the named
acceptance entry points (RK-census convention:
[`DAEMON_RPC_KV_CUTOVER.md`](DAEMON_RPC_KV_CUTOVER.md) §2).
**Decision authority:** Rick.
**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
this is longevity work — a Rust rewrite of consensus cannot start from
inherited-but-unexamined C++ as its specification
([`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc)).
The census precedes the rewrite. It trades nothing in security or
privacy.

---

## 0. Denominator (the completion claim)

| Quantity | Count |
| --- | ---: |
| Validation sites walked (functions that can reject a block or a tx-as-included-in-a-block) | 48 |
| Independently ratifiable rules (rows RC-1…RC-155, RC-157…RC-168) | **167** |
| Consensus | 157 |
| Policy (relay/mempool only; `kept_by_block` discriminator) | 10 |
| Bucket 1 — Shekyl-specific, written spec | 93 |
| Bucket 2 — inherited and ratified, locatable pointer | 3 |
| Bucket 3 — inherited, examined, marked for deletion | 15 |
| Bucket 4 — inherited, never examined | 56 |

Sum check: `93 + 3 + 15 + 56 = 167`. Consensus + policy: `157 + 10 = 167`.
The rows exhaust the denominator. An unlisted rule would be ratified by
silence — the failure mode this census exists to close. RC-156 is unused
(a draft duplicate of RC-53; same bound, already cited on both sites).

### 0.1 Per-subsystem breakdown

| Subsystem | Rows | Bucket 1 | 2 | 3 | 4 | Policy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Block header / identity | RC-1…RC-18 (18) | 4 | 0 | 2 | 12 | 0 |
| PoW / DAA | RC-19…RC-28 (10) | 8 | 1 | 0 | 1 | 0 |
| Timestamp | RC-29…RC-32 (4) | 1 | 0 | 0 | 3 | 0 |
| Miner-tx / emission | RC-33…RC-52 (20) | 13 | 0 | 1 | 6 | 0 |
| Tx parse / semantic | RC-53…RC-72 (20) | 6 | 1 | 2 | 11 | 0 |
| Tx outputs | RC-73…RC-80 (8) | 7 | 0 | 1 | 0 | 0 |
| Tx inputs / FCMP++ | RC-81…RC-99 (19) | 15 | 0 | 3 | 1 | 0 |
| PQC auth | RC-100…RC-108 (9) | 9 | 0 | 0 | 0 | 0 |
| Archival (serve-credit / bond-post / emission) | RC-109…RC-133 (25) | 24 | 0 | 0 | 1 | 0 |
| Reorg / alt-chain | RC-134…RC-142 (9) | 2 | 0 | 0 | 7 | 0 |
| Storage layer | RC-143…RC-150 (8) | 2 | 0 | 0 | 6 | 0 |
| Mempool policy | RC-151…RC-155, RC-157…RC-161 (10) | 1 | 1 | 1 | 7 | 10 |
| Hardfork / version table | RC-162…RC-168 (7) | 1 | 0 | 5 | 1 | 0 |

### 0.2 Inverse spot-check (must be present or the census is red)

| Expected subject | Row |
| --- | --- |
| FCMP++ membership-proof verification | **RC-94** (`shekyl_fcmp_verify`) |
| PQC transaction auth (`tx_pqc_verify.cpp`) | **RC-108** |
| Timestamp-median rule | **RC-31** |
| `validate_miner_transaction` emission check | **RC-47** |
| Key-image double-spend rejection | **RC-85** (per-tx) + **RC-144** (DB uniqueness) |
| PoW check | **RC-24** (`check_hash`) |

---

## 1. Enumeration method (reproducible at a later sha)

1. Pin `git rev-parse HEAD`. Walk the **call graph**, not a keyword grep,
   from these entry points (relocated at `8ba1aae3d`; they match the
   2026-08-31 brief anchors):
   - `core::handle_incoming_block` — `cryptonote_core.cpp:1327` and `:1335`
   - `core::handle_incoming_tx` — `cryptonote_core.cpp:720`
   - `Blockchain::add_new_block` — `blockchain.cpp:6609` and `:6626`
   - `Blockchain::handle_block_to_main_chain` — `:3100` and `:5689`
   - `Blockchain::handle_alternative_block` — `:2214`
   - `Blockchain::check_tx_inputs` — `:3241` and `:3440`
   - `Blockchain::check_tx_outputs` — `:3344`
   - `Blockchain::validate_miner_transaction` — `:1746`
   - `tx_memory_pool::add_tx` — `tx_pool.cpp:223`
   - all of `tx_verification_utils.cpp`, `tx_pqc_verify.cpp`, and the
     validation arms of `cryptonote_tx_utils.cpp` / `cryptonote_format_utils.cpp`
   - `src/blockchain_db/` constraint throws (`KEY_IMAGE_EXISTS`,
     `BLOCK_EXISTS`, `TX_EXISTS`, `BLOCK_PARENT_DNE`)
   - hardfork table (`src/hardforks/hardforks.cpp`) and
     `HardFork::check` / `check_for_height`
2. A **rule** is one independently ratifiable behavioral commitment: a
   comparison, an ordering requirement, a consensus-visible constant, a
   structural bound. `check_block_timestamp` is four rows here (FTL,
   median-window length, comparison operator, genesis-short-circuit),
   not one.
3. **Consensus vs policy** follows `kept_by_block`
   (`tx_relay == relay_method::block`). A rule that never forks the
   chain is **policy** — included in the denominator, marked, never
   silently dropped.
4. The same rule at mempool and block-connect is **one row with both
   sites**. Drifted duplicates are a finding, not a merge.
5. Constants sourced from `config/` enter **bucket 1 by construction**.
   Constants hardcoded elsewhere are their own rows.
6. Behavioral statements come from **this tree at this sha**, never from
   Monero documentation or memory of how Monero works
   ([`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc)).
7. To re-run: start at the entry points, follow every callee that can
   return false / throw a DB constraint / set
   `m_verifivation_failed`, and diff the rule set against this table.

### 1.1 Call graph (acceptance)

```
handle_incoming_tx (core.cpp:720)
  ├─ blob size ≤ get_max_tx_size()                          [also ver_non_input_consensus]
  ├─ parse_and_validate_tx_from_blob → expand_transaction_1
  └─ add_new_tx → tx_memory_pool::add_tx (tx_pool.cpp:223)
        ├─ ver_non_input_consensus  (unless nic_verified_hf_version matches)
        │     semantic + outputs + CT-semantics batch
        ├─ check_fee                 unless kept_by_block     POLICY
        ├─ tx.extra.size()           unless kept_by_block     POLICY
        ├─ unlock_time == 0          unless kept_by_block     POLICY
        ├─ pool key-image spent      unless kept_by_block     POLICY
        └─ Blockchain::check_tx_inputs (wrapper :3241 → inner :3440)
              FCMP++ / PQC / archival / KI

handle_incoming_block (core.cpp:1327/1335)
  ├─ check_incoming_block_size (weight-limit + 100-byte leeway)
  ├─ parse_and_validate_block_from_blob
  └─ Blockchain::add_new_block (:6626)
        ├─ have_block → already-exists
        ├─ prev_id == tip ? handle_block_to_main_chain(:5689)
        └─ else              handle_alternative_block(:2214)
              promotion → handle_block_to_main_chain again (:1438)
```

`handle_block_to_main_chain` **two-arg** (`:3100`) computes
`get_block_hash(bl)` and an empty `block_connect_supplement`, then
forwards to the four-arg (`:5689`). The rule sets are identical; the
duality is a convenience wrapper, not two validators.

`core::handle_block_found` (`:1210`) uses the **two-arg**
`add_new_block` (`:6609`), which refuses a non-empty `attestation_root`
without a witness. P2p/reorg use the three-arg overload.

### 1.2 Main-chain vs alt-chain (the divergence is the census)

| Check | Main (`:5689`) | Alt admission (`:2214`) | On promotion |
| --- | --- | --- | --- |
| Hardfork | `HardFork::check` (current) | `check_for_height` (ideal at height) | re-run main |
| Attestation | yes | yes | re-run main |
| Timestamp FTL | yes (`:5535`) | **no** — vector overload only | re-run main |
| Timestamp median | yes | yes (alt timestamps) | re-run main |
| PoW | RandomX v2 + `check_hash` | `get_altblock_longhash` + alt LWMA-1 | re-run main |
| `prevalidate_miner_transaction` | yes | yes | re-run main |
| `validate_miner_transaction` | yes | **no** | re-run main |
| `check_tx_inputs` / FCMP / PQC | yes (FCMP skippable if pool-cached) | **no** — txs dumped into pool as `relay_method::block` | re-run main |
| `ver_non_input_consensus` | on supplement | on supplement | re-run main |
| Weight / reward / curve-tree root | yes | weight approximated; may zero | re-run main |
| Reorg trigger | n/a | cum. difficulty **or** checkpoint | — |

Alt **admission** is a subset. Consensus at connect is the main-chain
path, which promotion re-enters. A rule enforced only at alt-admission
is still in the denominator (it can keep a block off the alt store).

---

## 2. Buckets

| Bucket | Meaning | Evidence required |
| --- | --- | --- |
| **1** Shekyl-specific | Designed for Shekyl with a written spec (FCMP++, PQC, RandomX v2, staking/archival, `config/`) | pointer to spec/design doc |
| **2** Inherited and ratified | A design round or decision-log entry examined it and kept it | locatable pointer in `docs/`, `docs/design/`, or `docs/completed/` |
| **3** Inherited, examined, marked for deletion | Recorded disposition to delete | pointer |
| **4** Inherited, never examined | Working set. Question asked, not answered | behavioral statement + site |

A remembered ratification with no findable record is bucket **4**.
`config/` constants are bucket **1** by construction.

Flag: **C** = consensus (block-acceptance or tx-as-included-in-a-block).
**P** = policy (relay/mempool only).

---

## 3. Rows

### 3.1 Block header / identity

| ID | Rule (behavior at this sha) | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-1 | Incoming block blob size must be ≤ current cumulative weight limit + `BLOCK_SIZE_SANITY_LEEWAY` (100). Unparsed blobs are rejected on this bound. | `cryptonote_core.cpp:1408–1418` | C | 4 | — | Sanity pre-parse; assumes weight ≥ blob. Constant 100 is local `#define`, not `config/`. |
| RC-2 | A block blob must deserialize via `binary_archive`; failure rejects. | `cryptonote_format_utils.cpp:1457–1470`; caller `cryptonote_core.cpp:1355` | C | 4 | — | `parse_and_validate_block_from_blob` does not check merkle separately. |
| RC-3 | `tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK` (`0x10000000`) fails serialization. | `cryptonote_basic.h:902–903` | C | 4 | — | Bound is 2^28. Not in `config/`. |
| RC-4 | A block whose hash already exists (main or alt) is refused (`m_already_exists`). | `blockchain.cpp:6637–6641`; DB twin RC-143 | C | 4 | — | |
| RC-5 | `prev_id` must equal the main-chain tip or the block is diverted to the alt path. Main-chain connect re-checks `prev_id == top_hash` and fails closed. | `blockchain.cpp:6645–6655`, `:5705–5711` | C | 4 | — | |
| RC-6 | A block whose parent is on neither main nor alt is marked orphaned and not stored. | `blockchain.cpp:2511–2518` | C | 4 | — | Returns `true` with `m_marked_as_orphaned`. |
| RC-7 | Block identity and PoW hashing blob is `serialize(header) ‖ merkle(miner_tx_hash ‖ tx_hashes) ‖ varint(tx_hashes.size()+1)`. There is no separate merkle-root header field. | `cryptonote_format_utils.cpp:1397–1403`, `:1515–1525` | C | 4 | — | Tampering with `tx_hashes` retargets both identity and PoW. |
| RC-8 | `major_version` must equal the hardfork table's current version. | `hardfork.cpp:109–118`; `blockchain.cpp:5726–5732` | C | 4 | — | Table is a single `{1, height 1}` row (RC-162). |
| RC-9 | Voting version is `minor_version`, except `minor_version == 0` counts as vote 1. Vote must be ≥ current fork version. | `hardfork.cpp:41–49`, `:109–112` | C | 4 | — | "Pre-hardfork blocks have minor 0" comment is inherited; Shekyl genesis is version 1. |
| RC-10 | Alt-path hardfork uses `check_for_height` against `get_ideal_version(block_height)`, not the voted current version. | `blockchain.cpp:2241–2247`; `hardfork.cpp:121–131` | C | 4 | — | Diverges from RC-8 whenever vote and ideal disagree. Single-fork table makes them equal today. |
| RC-11 | Witness-less `add_new_block` (2-arg) rejects a non-empty `attestation_root`. | `blockchain.cpp:6609–6623` | C | 1 | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3 | Local-mine / genesis entry. |
| RC-12 | Credit-wire attestation: recompute `attestation_root`, verify pass-record P-countersignatures. Unreadable coinbase extra is a reject, not empty-set. | `blockchain.cpp:5565–5661` (main `:5738`, alt `:2253`) | C | 1 | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) §3–§4 | Marshal-only; verdict is Rust `shekyl_archival_verify_attestation`. |
| RC-13 | Attestation nonce binds `prev_id` (validated predecessor), not producer randomness. All-zero prev hash is refused by the FFI. | `blockchain.cpp:5637–5645` | C | 1 | [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md); RF-D3 | |
| RC-14 | After `add_block`, `bl.curve_tree_root` must equal the DB-computed root. Mismatch pops the block. Exempt on `FAKECHAIN`. | `blockchain.cpp:6422–6436` | C | 1 | [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md); [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) §1 | Checked post-write, then rolled back. |
| RC-15 | Compiled-in per-block checkpoint: if `blockchain_height < m_blocks_hash_check.size()` and expected hash ≠ `null_hash`, block id must equal expected or reject; on match, PoW and per-tx input checks are skipped (`fast_check`). | `blockchain.cpp:5786–5805`, `:5854–5856`, `:6036–6064`; CMake `PER_BLOCK_CHECKPOINT=1` | C | 3 | [`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc); v3-from-genesis has no inherited checkpoint corpus | **Finding.** Default-on. Empty table ⇒ skip never fires; a populated table is a consensus skip of PoW and FCMP. |
| RC-16 | If height is in the runtime checkpoint zone, block hash must match the configured checkpoint. | `blockchain.cpp:5827–5836` (main); alt `:2314–2320` | C | 4 | — | Distinct from RC-15. |
| RC-17 | A future `major_version` above `get_ideal_version()` logs a warning and does **not** reject. | `blockchain.cpp:5713–5723` | C | 3 | rule 60 (version dispatch / "old daemon" UX on a one-fork chain) | Not a consensus reject. Recorded because it is an acceptance-path branch. |
| RC-18 | `tx_hashes` entries already in the DB (`tx_exists`) reject the block. | `blockchain.cpp:5936–5941` | C | 4 | — | Miner tx is not in `tx_hashes`. Duplicate hashes inside `tx_hashes` are not uniquely rejected here — second insert hits RC-147. |

### 3.2 PoW / DAA

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-19 | Next-block difficulty is LWMA-1 over a window of `N+1` timestamps/difficulties (`N = SHEKYL_DAA_WINDOW_N` = 90). | `blockchain.cpp:1082–1174`; `config/consensus_constants.json` `daa_window_n` | C | 1 | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) (ratified 2026-05-18) | |
| RC-20 | If chain height < N, LWMA-1 short-circuits to `SHEKYL_DAA_GENESIS_DIFFICULTY` (100) and ignores the window. | `blockchain.cpp:1160–1168`; alt `:1570–1571` | C | 1 | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md); `config/` `daa_genesis_difficulty` | |
| RC-21 | Target block time T = `SHEKYL_DAA_TARGET_SECONDS` (120). | `config/consensus_constants.json`; used in FTL/MTP projection | C | 1 | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) | |
| RC-22 | PoW hash is RandomX v2 of the hashing blob, seeded at `shekyl_pow_randomx_v2_seedheight(height)`. | `cryptonote_tx_utils.cpp:766–802`; `pow_registry.cpp:6–8` | C | 1 | [`RANDOMX_V2_PLAN.md`](RANDOMX_V2_PLAN.md); [`RANDOMX_V2_SPEC_ANCHORS.md`](RANDOMX_V2_SPEC_ANCHORS.md) | `get_pow_for_height` ignores height and version — always RandomX. |
| RC-23 | If RandomX hash computation fails, the result is set to `0xff…ff` (fail closed). Callers that ignore the bool cannot accept. | `cryptonote_tx_utils.cpp:748–763`, `:784–794` | C | 1 | same RandomX v2 docs; comment at `:787–792` | Alt-path pre-seeds `0xff…ff` (`blockchain.cpp:2325–2326`). |
| RC-24 | PoW accepts iff `hash * difficulty < 2^256` (hash as little-endian 256-bit). FFI failure rejects. | `difficulty.cpp:64–86`; callers `blockchain.cpp:5818`, `:2347` | C | 2 | Rust port deleted the 64/128 split; vectors in `rust/shekyl-difficulty/tests/check_hash_vectors.rs`; comment `difficulty.cpp:52–58` | Inherited comparison, examined and kept in the Shekyl difficulty crate. |
| RC-25 | Alt-chain PoW uses `get_altblock_longhash` with a seed taken from the alt chain if the seed height sits on it, else main. | `blockchain.cpp:2327–2346`; `cryptonote_tx_utils.cpp:748` | C | 1 | RandomX v2 seed-epoch schedule | |
| RC-26 | Alt-chain next difficulty is LWMA-1 over the conceptual `main[0..fork) ++ alt`, window ending at `bei.height-1`. `bei.height==0` asserts. | `blockchain.cpp:1544–1628` | C | 1 | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md) | |
| RC-27 | Seed-epoch env override (`SEEDHASH_EPOCH_*`) is refused on public networks; fakechain-only. | `blockchain.cpp:640–643` | C | 1 | RandomX v2; comment at site | Init-time, not per-block, but it changes the PoW seed schedule. |
| RC-28 | `m_fixed_difficulty` (regtest) replaces LWMA-1 with a constant (1 at genesis). | `blockchain.cpp:1084–1086`, `:1546–1548` | C | 4 | — | Test-only lever on the acceptance path. |

### 3.3 Timestamp

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-29 | Future-time limit: `b.timestamp > now + SHEKYL_DAA_FTL_SECONDS` (540) rejects. | `blockchain.cpp:5535–5541` | C | 1 | [`DAA_LWMA1.md`](../completed/DAA_LWMA1.md); `config/` `daa_ftl_seconds` | **Main path only.** Alt admission uses the vector overload and does not call this. |
| RC-30 | If chain height < `SHEKYL_DAA_MTP_WINDOW` (11), the median check is skipped (timestamp accepted aside from FTL). | `blockchain.cpp:5546–5549` | C | 4 | window length is `config/` (bucket 1 for the constant); the skip-when-short behavior is unexamined | |
| RC-31 | Timestamp must be **not less than** the median of the last `SHEKYL_DAA_MTP_WINDOW` (11) block timestamps. `b.timestamp < median` rejects. | `blockchain.cpp:5514–5525`; main `:5535`; alt `:2307` | C | 4 | window from `config/` / DAA; **comparison operator and inclusive-median semantics have no ratification record** | Inverse-spot-check subject. Median via `epee::misc_utils::median`. |
| RC-32 | `get_adjusted_time` (unlock-time path) projects median `+(WINDOW+1)*T/2` and takes min with `last_ts + T`. Not used by RC-29/31. | `blockchain.cpp:5480–5510` | C | 4 | — | Distinct from block-acceptance timestamp. See also RC-80. |

### 3.4 Miner-tx / emission

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-33 | Coinbase `vin.size() == 1`. | `blockchain.cpp:1642` | C | 4 | — | |
| RC-34 | Coinbase vin must be `txin_gen`. | `blockchain.cpp:1643` | C | 4 | — | |
| RC-35 | Coinbase `version >= 3`. | `blockchain.cpp:1644` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md); v3-from-genesis | |
| RC-36 | Coinbase CT type must be `CTTypeNull`. | `blockchain.cpp:1645` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); [`CT_SURFACE_NAMING_PIN.md`](CT_SURFACE_NAMING_PIN.md) | |
| RC-37 | Coinbase `vout.size() == 1` except at height 0 (genesis multi-output carve-out). Height operand is caller-derived, not `txin_gen.height`. | `blockchain.cpp:1647–1675` | C | 1 | F-H; [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) §12.3 | |
| RC-38 | `txin_gen.height` must equal the caller's chain-position height. | `blockchain.cpp:1677–1681` | C | 4 | — | |
| RC-39 | Coinbase `unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60). | `blockchain.cpp:1683` | C | 4 | 60 is `cryptonote_config.h:45`, not `config/` | |
| RC-40 | Coinbase output amounts must not overflow `uint64` when summed. | `blockchain.cpp:1686–1690` | C | 4 | — | |
| RC-41 | Coinbase output types must be `txout_to_tagged_key` (via `check_output_types`). | `blockchain.cpp:1692`; `cryptonote_format_utils.cpp:971–984` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) tag registry | Dead pre-`HF_VERSION_SHEKYL_NG` arms: RC-167. |
| RC-42 | Coinbase output public keys must be canonical prime-order non-identity (same gate as pool txs). | `blockchain.cpp:1694–1697`; `cryptonote_format_utils.cpp:837–866` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | Miner tx never goes through `check_tx_semantic`; this is the only site. |
| RC-43 | Coinbase commitment masks: canonical prime-order, not identity/G, and `C ≠ zeroCommit(public_amount)`. | `blockchain.cpp:1699–1703`, `:3271–3341` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | Sole mask gate for `CTTypeNull`. |
| RC-44 | Genesis (`block_height == 0`): skip the live reward function; accept configured `GENESIS_TX` amounts. | `blockchain.cpp:1754–1760` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md); [`GENESIS_ALLOCATIONS.md`](../GENESIS_ALLOCATIONS.md) | |
| RC-45 | If `version == 3`, each coinbase output amount must be a "decomposed" amount. | `blockchain.cpp:1763–1769` | C | 3 | rule 60 (dead version dispatch: v3-from-genesis, version already ≥ 3 by RC-35) | Always-on for mined blocks today. Whether decomposed amounts are right-for-Shekyl is unasked. The **dispatch** is bucket 3; the amount constraint itself is the unexamined residue — see RC-46. |
| RC-46 | Coinbase output amounts, when RC-45 fires, must appear in `valid_decomposed_outputs`. | `cryptonote_format_utils.cpp:1528–1532` | C | 4 | — | CryptoNote denomination set. |
| RC-47 | `money_in_use` (sum of coinbase vouts) must equal `miner_emission + miner_fee_income` exactly. Overpay rejects; underpay logs and still rejects (`!=`). | `blockchain.cpp:1746–1805` | C | 1 | `shekyl-economics`; [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md); Stage-1 PR 7 | Inverse-spot-check subject. Weight too large fails `get_block_reward` first. |
| RC-48 | Base subsidy is `shekyl_block_reward` (Rust): median clamp, 2×median reject, weight penalty. C++ is a marshaling shim. | `cryptonote_basic_impl.cpp:93–99`; called at `:1776` | C | 1 | Stage-1 PR 7; `config/economics_params.json` | |
| RC-49 | Emission split: `compute_emission_split(base_reward, height, genesis_ng_height)` partitions miner vs staker legs. | `blockchain.cpp:1782–1785`, `:6347–6348` | C | 1 | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) §2.2 | |
| RC-50 | Fee burn: `compute_fee_burn(fee, tx_volume_avg, circulating_supply, frozen_segment_count)` partitions miner fee / staker pool / destroyed. | `blockchain.cpp:1791–1792`, `:6350–6355` | C | 1 | economics; [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) | `frozen_segment_count` is parent-state (RC-52). |
| RC-51 | `already_generated_coins` advances by `base_reward` through `shekyl_advance_already_generated` (supply clamp in Rust). | `blockchain.cpp:6374`; alt `:2303` | C | 1 | `consensus_constants.json` division-one-site note at `:6369–6373` | Alt advances by coinbase paid, not `base_reward` (FOLLOWUPS; RC-141). |
| RC-52 | `parent_frozen_segment_count(block_height)` requires `m_db->height() == block_height` (tree not yet grown for this block). | `blockchain.cpp:1732–1742`, `:6271` | C | 1 | [`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`](ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md) §6.2 | |

### 3.5 Tx parse / semantic

Reached from `ver_non_input_consensus` (mempool and block supplement)
and from `core::check_tx_semantic`. Sites listed together.

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-53 | Tx blob size ≤ `CRYPTONOTE_MAX_TX_SIZE` (1_000_000). | `cryptonote_core.cpp:728`; `tx_verification_utils.cpp:66–71`; `cryptonote_basic_impl.cpp:88–90` | C | 4 | — | Also on the handle_incoming_tx path before parse. Not in `config/`. |
| RC-54 | Tx must deserialize; `expand_transaction_1` must succeed. | `cryptonote_format_utils.cpp:199–207`, `:130–196` | C | 4 | — | |
| RC-55 | Non-coinbase v2+: `outPk.size() == vout.size()` at expand time. | `cryptonote_format_utils.cpp:137–140` | C | 4 | — | Duplicated at semantic RC-63. |
| RC-56 | Non-serve-credit Bulletproofs+: exactly one BP+, `L.size() ≥ 6`, max amounts ≥ vout count; V reconstructed as `mask * INV_EIGHT`. | `cryptonote_format_utils.cpp:170–192` | C | 2 | BP+ layout is the FCMP++/CT stack's; canonical-form twin is RC-97. Examined as part of FCMP++ cutover | Serve-credit exempt (RF-D9). |
| RC-57 | `vin` must be non-empty. | `cryptonote_core.cpp:774–779` | C | 4 | — | |
| RC-58 | `txin_gen` is forbidden in non-coinbase txs. | `cryptonote_format_utils.cpp:781–786` | C | 4 | — | |
| RC-59 | Only `txin_to_key`, `txin_archival_serve_credit_response`, `txin_archival_bond_post`, `txin_archival_reward_emission` are accepted. Other variants reject. | `cryptonote_format_utils.cpp:773–834` | C | 1 | archival vin taxonomy; [`REWARD_EMISSION_E3_GATING_ROUND.md`](../completed/REWARD_EMISSION_E3_GATING_ROUND.md) Q3/Q11 | |
| RC-60 | Serve-credit vins cannot mix with spend / bond / emission. | `cryptonote_format_utils.cpp:802–807` | C | 1 | gate-2; `classify_archival_tx` | |
| RC-61 | At most one bond-post vin; at most one emission vin; emission cannot mix with bond-post. | `cryptonote_format_utils.cpp:808–833` | C | 1 | E3 gating Q3 arity 1 | |
| RC-62 | Every output public key must be canonical, prime-order, non-identity. | `cryptonote_format_utils.cpp:837–866`; also miner RC-42 | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | Replaces inherited `crypto::check_key`. |
| RC-63 | For `tx.version > 1`, `outPk.size() == vout.size()`. | `cryptonote_core.cpp:797–805` | C | 4 | — | `version > 1` dispatch; v3-from-genesis always true. |
| RC-64 | Sum of input amounts and sum of output amounts must not overflow `uint64`. Archival special vins contribute 0 here. | `cryptonote_format_utils.cpp:869–908`; `cryptonote_core.cpp:808–814` | C | 4 | — | Amounts on `txin_to_key` are 0 under CT; this is a leftover overflow belt. |
| RC-65 | Key images of `txin_to_key` inputs must be unique within the tx. Archival special vins skipped. | `cryptonote_core.cpp:913–942`; semantic caller `:819` | C | 1 | FCMP++ still uses KI as the spend tag; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Inverse-spot-check companion to RC-85/RC-144. Intra-tx, not chain-wide. |
| RC-66 | For `txin_to_key`, no relative offset after the first may be 0 ("duplicate ring members"). Archival special vins skipped. | `cryptonote_core.cpp:945–960` | C | 3 | rule 60: mixin/ring leftover; FCMP requires empty `key_offsets` (RC-84), so this never fires on a well-formed spend | `hf_version` parameter is unused. |
| RC-67 | Key image must not encode the identity point, and `ki * curve_order` must be identity (in-domain). | `cryptonote_core.cpp:963–980` | C | 4 | — | Standard prime-order check; no Shekyl-specific ratification record found. |
| RC-68 | `ver_non_input_consensus` min/max tx version: if `hf < HF_VERSION_DYNAMIC_FEE` then 1..1; elif `hf < HF_VERSION_SHEKYL_NG` then 2..2; else 3..3. All three macros equal 1, so live bound is 3..3. | `tx_verification_utils.cpp:55–78` | C | 3 | rule 60 dead version dispatch; live bound agrees with RC-82 | **Drift:** `check_tx_inputs` hardcodes min=max=3 without the table (RC-82). |
| RC-69 | Tx weight ≤ `get_transaction_weight_limit(hf)` when `hf >= HF_VERSION_PER_BYTE_FEE` (always): `min_block_weight/2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE`. | `tx_verification_utils.cpp:80–87`, `:203–209` | C | 4 | pre-`PER_BYTE_FEE` arm is dead (macro = 1) | Limit formula is inherited scaling. |
| RC-70 | Batch CT semantics: `CTTypeNull` in the batch is an error; unknown types reject; FCMP++/PQC must have canonical BP+ layout; then `verCtSemanticsSimple`. | `tx_verification_utils.cpp:212–256` | C | 1 | FCMP++ / CT semantics | Serve-credit / bond-post / emission excluded from this batch (RC-109, RC-119, RC-127). |
| RC-71 | `nic_verified_hf_version` cache: a pool supplement already verified at this hf is not re-checked. | `tx_verification_utils.cpp:265–284` | C | 4 | — | Correctness depends on hf not changing under the cache. |
| RC-72 | Spend txs (`version >= 2`, not serve-credit-only) must have `vout.size() >= 2`. | `blockchain.cpp:3466–3473` | C | 4 | — | 2-out minimum (change + dest). Unexamined as a Shekyl rule. |

### 3.6 Tx outputs

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-73 | Non-coinbase tx version must be ≥ 3. | `blockchain.cpp:3348–3353` | C | 1 | v3-from-genesis; [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) | |
| RC-74 | Non-emission vouts must have `amount == 0`. Emission txs may carry loud amounts. | `blockchain.cpp:3355–3374` | C | 1 | [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) §4; uses `classify_archival_tx`, not a bare vin count | |
| RC-75 | CT type must be `CTTypeNull` or `CTTypeFcmpPlusPlusPqc`. | `blockchain.cpp:3376–3382` | C | 1 | [`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc); [`CT_SURFACE_NAMING_PIN.md`](CT_SURFACE_NAMING_PIN.md) | |
| RC-76 | Non-coinbase, non-fakechain txs must use `CTTypeFcmpPlusPlusPqc` (`CTTypeNull` is coinbase-only). | `blockchain.cpp:3478–3483`, `:3623–3629` | C | 1 | same | Stricter than RC-75 on the input path. |
| RC-77 | `unlock_time >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500_000_000) rejects (timestamp-based unlock forbidden). | `blockchain.cpp:3384–3389` | C | 1 | FOLLOWUPS "Block-height-only unlock_time"; height-only pin | |
| RC-78 | Outputs must be `txout_to_tagged_key` at `hf >= HF_VERSION_SHEKYL_NG`. | `cryptonote_format_utils.cpp:971–984`; `blockchain.cpp:3392–3396` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) | |
| RC-79 | Non-coinbase commitment masks: same structural/trivial-form gate as RC-43. | `blockchain.cpp:3399–3406` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md) §2.3 | |
| RC-80 | `is_tx_spendtime_unlocked`: if `unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER` treat as height with delta 1 block; else treat as unix time vs `get_adjusted_time`. | `blockchain.cpp:4505–4526` | C | 3 | RC-77 already forbids the timestamp encoding on new txs; the time arm is dead for v3 spends. Still used when reading stored unlock (`:2681`) | Timestamp arm is the deletion target; height arm is unexamined (bucket-4 residue on a bucket-3 dispatch). |

### 3.7 Tx inputs / FCMP++

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-81 | `vin.size() ≤ FCMP_MAX_INPUTS_PER_TX` (8). | `blockchain.cpp:3485–3491`; `cryptonote_config.h:311` | C | 1 | [`GENESIS_TX_WIRE_FORMAT.md`](GENESIS_TX_WIRE_FORMAT.md); [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); also embargo coupling in [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) | Hardcoded, not `config/`. |
| RC-82 | Tx version min and max are both 3 (hardcoded in `check_tx_inputs`). | `blockchain.cpp:3493–3506` | C | 1 | v3-from-genesis | **Drift** vs RC-68's hf table. FAKECHAIN skips this block. |
| RC-83 | `txin_to_key` key images must be strictly decreasing in `memcmp` order (unsorted / equal rejects). Non-KI vins ignored in the order. | `blockchain.cpp:3509–3530` | C | 4 | — | Canonical encoding / uniqueness-adjacent. |
| RC-84 | FCMP++ `txin_to_key.key_offsets` must be empty. Same for bond-post and emission fee inputs. | `blockchain.cpp:3599–3605`, `:3552–3557`, `:3576–3581` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) (no rings) | |
| RC-85 | A `txin_to_key` key image already in the spent-key table rejects (`m_double_spend`). | `blockchain.cpp:3607–3612`, `:3558–3563`, `:3582–3587`; `have_tx_keyimg_as_spent` | C | 1 | FCMP++ nullifier; [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | Inverse-spot-check subject. Chain-wide. Pool twin is policy RC-157. |
| RC-86 | Non-FCMP++ / non-archival classified txs reject ("ring-based inputs are not supported from genesis"). | `blockchain.cpp:3615–3619` | C | 1 | rule 60 | |
| RC-87 | `pqc_auths.size() == vin.size()` except serve-credit-only (which must have empty `pqc_auths`). | `blockchain.cpp:3636–3643`, `:3656–3664` | C | 1 | PQC auth; serve-credit signature-on-vin (gate-2) | |
| RC-88 | Regular FCMP++: `pseudoOuts.size() == vin.size()`. Bond-post/emission: `pseudoOuts.size() == spend_input_count`. | `blockchain.cpp:3645–3654`, `:3787–3794`, `:3934–3940` | C | 1 | FCMP++ | |
| RC-89 | `referenceBlock` must exist on chain. | `blockchain.cpp:4191–4197` (spend); bond `:3797–3801`; emission `:3946–3950` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); `config/` ages | |
| RC-90 | `ref_height ≤ chain_height - FCMP_REFERENCE_BLOCK_MIN_AGE` (5), and the chain must be at least that long. | `blockchain.cpp:4200–4208`; `config/` `fcmp_reference_block_min_age` | C | 1 | `config/consensus_constants.json` | |
| RC-91 | If `chain_height > FCMP_REFERENCE_BLOCK_MAX_AGE` (100), `ref_height ≥ chain_height - 100`. | `blockchain.cpp:4211–4219`; `config/` `fcmp_reference_block_max_age` | C | 1 | `config/consensus_constants.json` | |
| RC-92 | `curve_trees_tree_depth` must be in `(0, current_depth]`. Layers passed to verify are `depth + 1`. | `blockchain.cpp:4235–4244`, `:4291–4292` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | |
| RC-93 | FCMP++ proof bytes must be non-empty. | `blockchain.cpp:4247–4252` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md) | |
| RC-94 | `shekyl_fcmp_verify(proof, key_images, pseudoOuts, pqc_leaf_hashes, tree_root_at_ref, layers, tx_prefix_hash)` must return 0. Tree root is the per-height DB root, not the block header. | `blockchain.cpp:4285–4313` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) | **Inverse-spot-check.** Skippable on block-connect if the tx came from the pool and is FCMP++ (`:6040–6054`) — load-bearing for D++ `hop`. |
| RC-95 | Per-input `shekyl_fcmp_pqc_leaf_hash(hybrid_public_key)` must succeed; hashes are the in-circuit 4th leaf scalar. | `blockchain.cpp:4265–4274` | C | 1 | [`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md); PQC leaf KATs | Distinct from the Keccak binding in RC-107. |
| RC-96 | `PER_BLOCK_CHECKPOINT` + `kept_by_block` + height in hash-check table: `check_tx_inputs` wrapper returns true without running RC-81–RC-108. | `blockchain.cpp:3246–3253` | C | 3 | same as RC-15 | Mempool path into a checkpointed block. |
| RC-97 | Canonical Bulletproofs+ layout (`is_canonical_bulletproof_plus_layout`) for FCMP++ CT. | `tx_verification_utils.cpp:227–232` | C | 1 | FCMP++ / CT | |
| RC-98 | `check_tx_input` (mixin scan + ring signatures + `is_tx_spendtime_unlocked` on referenced outputs) remains in the binary and is **not** called from the FCMP++ `check_tx_inputs` path. | `blockchain.cpp:4532+` | C | 3 | rule 60 (ring path) | Dead for genesis spends. Not a live rule; recorded so a rewrite does not resurrect it by walking the file. |
| RC-99 | In-block `check_for_double_spend` is compiled but the call is commented out; comment says DB `add_block` is the KI uniqueness check. | `blockchain.cpp:6019–6030`, `:3124–3198` | C | 3 | comment at site; uniqueness is RC-144 | Intra-block KI uniqueness before DB: **not enforced in Blockchain**, only at LMDB insert. Two KIs in one block still throw `KEY_IMAGE_EXISTS`. |

### 3.8 PQC auth

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-100 | Every non-coinbase, non-serve-credit v3 tx runs `verify_transaction_pqc_auth`. `pqc_auths.size()` must equal `vin.size()` and be non-empty. | `blockchain.cpp:4348–4356`; `tx_pqc_verify.cpp:161–168` | C | 1 | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md); [`SIGNATURE_ALIGNMENT.md`](SIGNATURE_ALIGNMENT.md) | Inverse-spot-check subject. |
| RC-101 | `auth_version == 1`. | `tx_pqc_verify.cpp:175–179` | C | 1 | PQC auth wire | |
| RC-102 | `flags == 0`. | `tx_pqc_verify.cpp:181–185` | C | 1 | PQC auth wire | |
| RC-103 | `scheme_id ∈ {1 (single), 2 (multisig)}`. Cross-input scheme agreement is **not** required (MSW-6 withdrawn). | `tx_pqc_verify.cpp:187–191`; comment `blockchain.cpp:4325–4347` | C | 1 | [`PQC_MULTISIG.md`](../PQC_MULTISIG.md) §16.3; MSW-6 | |
| RC-104 | Hybrid public key non-empty; scheme 1 length `PQC_HYBRID_SINGLE_KEY_LEN`; scheme 2 length in `[3, PQC_MAX_PUBLIC_KEY_BLOB]`. | `tx_pqc_verify.cpp:193–221` | C | 1 | config PQC constants; MSW-1 | |
| RC-105 | Signed payload = `prefix_blob ‖ ctsig_base ‖ keccak(prunable) ‖ pqc_header ‖ all_input_pqc_key_hashes`. | `tx_pqc_verify.cpp:62–158` | C | 1 | [`FCMP_SPEND_SIGNING_PREIMAGE.md`](FCMP_SPEND_SIGNING_PREIMAGE.md); comment `:92–95` (prunable bind), `:133–143` (cross-input key bind) | |
| RC-106 | Payload is hashed with `cn_fast_hash` (Keccak-256) before `shekyl_pqc_verify`. | `tx_pqc_verify.cpp:227–237` | C | 1 | same | |
| RC-107 | Cross-input PQC key hashes use Keccak, **not** `shekyl_fcmp_pqc_leaf_hash` (Blake2b-512 domain `shekyl-pqc-leaf`). | `tx_pqc_verify.cpp:137–143` | C | 1 | comment at site | |
| RC-108 | `shekyl_pqc_verify(scheme, pk, sig, payload_hash)` must return 0 for every input. | `tx_pqc_verify.cpp:230–243` | C | 1 | [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md) | **Inverse-spot-check.** |

### 3.9 Archival (serve-credit / bond-post / emission)

All bucket 1 (Shekyl-specific). Independently ratifiable commitments
inside the three vin kinds; FFI bodies are one row each with the C++
belts beside them.

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-109 | Serve-credit-only: no pqc_auths, no vouts, fee 0, no outPk/BP+/pseudoOuts/fcmp proof; type FCMP++/PQC; `verCtSemanticsFeeOnly`. | `tx_verification_utils.cpp:113–130`; `blockchain.cpp:3656–3688` | C | 1 | gate-2 §5; [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) | |
| RC-110 | One pruned pass record per serve-credit vin, in vin order; pruned size in `(0, SERVE_CREDIT_PRUNED_MAX_BYTES]`. | `blockchain.cpp:3724–3733`, `:5281–5285` | C | 1 | RF-D1 | |
| RC-111 | Serve-credit `prev_block_hash` is `block_hash(chain_height-1)` (the slot's parent). Pool path is next-block-only (PC-D2). | `blockchain.cpp:3689–3722` | C | 1 | [`ARCHIVAL_PER_CHALLENGE_RECORD.md`](ARCHIVAL_PER_CHALLENGE_RECORD.md) PC-D3/PC-D2 | |
| RC-112 | Duplicate serve-credit for `(P, shard, E)` in the **DB** (pair-epoch, not per-block-height) rejects. Exact-get on `(P,s,E,h)` would be vacuous at connect. | `blockchain.cpp:5308–5312` | C | 1 | PC-D4/PC-D7 comment at `:5287–5307` | Reopen when assignment cutover lands. |
| RC-113 | Duplicate `(P, shard, E)` across txs **in the same block** rejects. Key is `ArchivalPairEpochKey` (not widened with height). | `blockchain.cpp:6083–6130` | C | 1 | [`ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md`](../completed/ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md) D-SC-C; PC-D4 | |
| RC-114 | Serve-credit requires a bond hybrid pubkey for P; settlement epoch after `E_first`; `good_through` at that epoch; `current_height ≤ H_close`; seal block on chain. | `blockchain.cpp:5314–5358` | C | 1 | [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md); [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) | |
| RC-115 | Challenged leaf index is **derived** (`shekyl_archival_challenge_leaf_index`), never read off the vin. Holdings and registry evaluated at `H_fire`. | `blockchain.cpp:5383–5433` | C | 1 | RF-D6; PC-D3; [`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md) §6.2 | |
| RC-116 | `shekyl_archival_verify_serve_credit_vin` over the opaque vin + pruned record + leaf chunk must return OK. | `blockchain.cpp:5452–5474` | C | 1 | [`ARCHIVAL_RESPONSE_FORMAT.md`](ARCHIVAL_RESPONSE_FORMAT.md) | |
| RC-117 | Bond-post hybrid pubkey length is canonical `PQC_HYBRID_SINGLE_KEY_LEN`; `p_canonical_id` must recompute from that pubkey. | `blockchain.cpp:4806–4826` | C | 1 | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | |
| RC-118 | Unbond and HoldingsUpdate must not carry vin-borne `bond_spend_pk` (JoinMarket-coupled). Debit auth pins `pqc_auths[i].hybrid_public_key` to the record's committed `bond_spend_pk`. | `blockchain.cpp:4832–4851`, `:4902–4910`, `:6165–6204` | C | 1 | GF-1; gate-4 §3.5 | Fast-path belt at `:6187` so checkpoint skip cannot split the network. |
| RC-119 | Bond-post CT: `verCtSemanticsBondPost(rv, bond_credit, bond_debit)`; proof non-empty; funding inputs ≥ 1. | `tx_verification_utils.cpp:132–147`; `blockchain.cpp:3772–3832` | C | 1 | gate-4 | Funding-floor copy is disclosed as pending a Rust single-source (`:3772–3779`). |
| RC-120 | Bond-post funding inputs: empty offsets, unspent KIs, FCMP++ over the spend subset (same ref-age/depth as RC-89–94). | `blockchain.cpp:3548–3564`, `:3765–3874` | C | 1 | gate-4; FCMP++ | |
| RC-121 | Unbond / HoldingsUpdate-add / HoldingsUpdate-drop / JoinMarket semantic verify is Rust (`shekyl_archival_verify_*`). C++ marshals record facts. | `blockchain.cpp:4874–4896`, `:4931–4956`, and JoinMarket arm below | C | 1 | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md); [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) | |
| RC-122 | HoldingsUpdate-add pqc auth key must equal identity `P_pubkey`. | `blockchain.cpp:4957–4962` | C | 1 | GF-1 credit path | |
| RC-123 | At most one bond-post per P per block (`shekyl_archival_bond_post_block_unique`). | `blockchain.cpp:6253–6260` | C | 1 | gate-4 §3.5 | Serve-credit + Unbond for the same P in one block is **deliberately allowed** (`:6147–6152`). |
| RC-124 | Emission vin parses only via Rust (`shekyl_archival_emission_vin_extract`); failure rejects. | `blockchain.cpp:3893–3901` | C | 1 | [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) | |
| RC-125 | Emission slot's hybrid key must derive the vin's `P_canonical_id`. | `blockchain.cpp:3904–3921` | C | 1 | E3 C-1 | |
| RC-126 | Emission fee inputs: empty offsets, unspent KIs; `pseudoOuts` match spend count. Zero fee inputs ⇒ `fcmp_pp_proof` must be empty; else FCMP++ as RC-94. | `blockchain.cpp:3566–3588`, `:4122–4183` | C | 1 | E3 Q11 | |
| RC-127 | Emission CT: loud-amount sum > 0, no overflow; `verCtSemanticsEmission(rv, total_reward, spend_count)`. | `tx_verification_utils.cpp:149–180` | C | 1 | E3 §9.5 item 4 | Same `shekyl_checked_sum_amounts` as the input-path operand. |
| RC-128 | Claimed epochs must have a frozen budget row; `shekyl_emission_vin_verify` must return OK; `vout_reward_sum` is the inflation-audit operand. | `blockchain.cpp:4000–4118` | C | 1 | [`REWARD_EMISSION_E3_GATING_ROUND.md`](../completed/REWARD_EMISSION_E3_GATING_ROUND.md) §7.1 | |
| RC-129 | Signable hash for membership-only backing excludes the emission vin wholesale (circularity). Tx-level PQC still covers the full prefix. | `blockchain.cpp:3982–3994` | C | 1 | E3 F-C1c | |
| RC-130 | Duplicate `(P, E)` emission claims in one block reject (`shekyl_emission_block_claims_unique`). | `blockchain.cpp:6244–6251` | C | 1 | E3 §6.2 layer 2 | |
| RC-131 | Per-height staker-inflow accrual = `staker_emission + burn.staker_pool_amount` for every non-genesis block; written in `add_block`. | `blockchain.cpp:6282–6356` | C | 1 | [`ARCHIVAL_BUDGET_SCHEDULE.md`](ARCHIVAL_BUDGET_SCHEDULE.md) §2.2 | Claim-era HF gate deleted (rule 60). |
| RC-132 | Nonzero fee-burn destroyed share is recorded per height (`add_block_burn`) and added to `total_burned`. | `blockchain.cpp:6447–6459` | C | 1 | economics / burn | |
| RC-133 | Long-term block weight = clamp of block weight into `[Ml/1.7, Ml*1.7]` with `Zm = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`. Cumulative weight limit = `2 * effective_median`. | `blockchain.cpp:6547–6606` | C | 4 | comment cites ArticMine 2021 scaling PDF | Inherited scaling; not in `config/`. Weight limit **is** consensus (reward penalty / 2×median reject). |

### 3.10 Reorg / alt-chain

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-134 | Alternative genesis (`block_height == 0`) is rejected. | `blockchain.cpp:2223–2228`; difficulty assert `:1561` | C | 1 | rule 60; comment `:1553–1558` | |
| RC-135 | `checkpoints.is_alternative_block_allowed(chain_height, block_height)` must hold. | `blockchain.cpp:2233–2238` | C | 4 | — | |
| RC-136 | Reorg if alt cumulative difficulty **strictly greater** than main tip's. | `blockchain.cpp:2493–2503` | C | 4 | — | Equality keeps main. |
| RC-137 | Reorg if the alt block is a checkpoint, even without a difficulty win. | `blockchain.cpp:2480–2491` | C | 4 | — | |
| RC-138 | Promotion pops to the fork point and feeds each alt block through **full** `handle_block_to_main_chain`. Failure rolls back. | `blockchain.cpp:1386–1462` | C | 4 | — | This is why skipped alt-admission checks are not silent at connect. |
| RC-139 | Demoted main blocks may be re-inserted as alt (`handle_alternative_block`); failure there is logged, not a switch failure. | `blockchain.cpp:1466–1485` | C | 4 | — | |
| RC-140 | Alt `already_generated_coins` advances by `get_outs_money_amount(miner_tx)` (coinbase paid), not `base_reward`. Not consulted by any consensus decision; promotion re-reads the DB. | `blockchain.cpp:2277–2303` | C | 4 | already in FOLLOWUPS "Alt-chain supply accumulation" | Approximation by construction. |
| RC-141 | Miner notification after reorg must use DB cumulative supply, not the alt bookkeeping copy. | `blockchain.cpp:1508–1524` | C | 1 | comment at site (wrong subsidy → rejected block) | Corrects a would-be consensus-adjacent miner bug. |
| RC-142 | Hardfork voting window is rebuilt from `split_height` after a reorg. | `blockchain.cpp:1494` | C | 4 | — | |

### 3.11 Storage layer

A constraint enforced only by the DB is still a consensus rule.

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-143 | Inserting a block hash that already exists throws `BLOCK_EXISTS`. | `db_lmdb.cpp:948–949` | C | 4 | — | Twin of RC-4. |
| RC-144 | Inserting a spent key image that already exists throws `KEY_IMAGE_EXISTS`; connect catches and rejects the block. | `db_lmdb.cpp:1411–1425`; `blockchain.cpp:6397–6403` | C | 1 | FCMP++ nullifier uniqueness | **Inverse-spot-check.** Only intra-block KI uniqueness once RC-99's caller was removed. |
| RC-145 | Parent of a non-genesis add must be the current top (`prev->bh_height == m_height - 1`), else `BLOCK_PARENT_DNE`. | `db_lmdb.cpp:951–963` | C | 4 | — | |
| RC-146 | Block blobs are appended at `m_height` (`MDB_APPEND`) — height is strictly increasing. | `db_lmdb.cpp:973–978` | C | 4 | — | |
| RC-147 | Inserting a tx hash that already exists throws `TX_EXISTS`. | `db_lmdb.cpp:1071–1074` | C | 4 | — | Twin of RC-18. |
| RC-148 | Duplicate alt-block hash throws. | `db_lmdb.cpp:4738` | C | 4 | — | |
| RC-149 | Coinbase and archival-emission outputs are indexed under amount 0 regardless of plaintext amount. | `db_lmdb.cpp:1361–1368`; add_transaction counterpart | C | 1 | amount-0 CT; emission loud amounts still tree-indexed at 0 | |
| RC-150 | `add_spent_key` is the spent-keys uniqueness constraint; `has_key_image` is the read side for RC-85. | `db_lmdb.cpp:1411–1425`, `:3816` | C | 4 | — | Same table as RC-144. |

### 3.12 Mempool policy (`kept_by_block` discriminator)

Included in the denominator; **P** = does not fork the chain.

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-151 | `kept_by_block = (tx_relay == relay_method::block)`. All policy rows below gate on this. | `tx_pool.cpp:229` | P | 2 | the discriminator is the project's own; used as specified by this census | Meta-rule. |
| RC-152 | Relay fee: `fee ≥ needed - needed/50` (2% buffer) with `needed = quantize(weight * fee_per_byte)`. Skipped if `kept_by_block`. | `tx_pool.cpp:250`; `blockchain.cpp:4397–4412` | P | 4 | fee formula inherited (ArticMine 2021); 2% buffer unexamined | A zero-fee tx can still be in a block. |
| RC-153 | `fee_per_byte = 0.95 * block_reward * REF_WEIGHT / median^2` (integer). | `blockchain.cpp:4363–4377` | P | 4 | same | Used only for RC-152. |
| RC-154 | `tx.extra.size() > MAX_TX_EXTRA_SIZE` (24576) rejects unless `kept_by_block`. | `tx_pool.cpp:261–268`; `cryptonote_config.h:353` | P | 4 | — | |
| RC-155 | Nonzero `unlock_time` rejects at relay unless `kept_by_block`. | `tx_pool.cpp:271–277` | P | 3 | consensus already forbids timestamp unlock (RC-77) and coinbase has its own unlock; this is a **relay** ban on height-locks too | Coinbase never enters the pool this way. A height-locked spend can be in a block. |
| RC-157 | Pool rejects txs whose key images are spent in the pool or chain, unless `kept_by_block`. | `tx_pool.cpp:283–293` | P | 4 | — | `kept_by_block` skip is the "popped block" path; comment TODO `:282`. |
| RC-158 | If `kept_by_block` and `check_tx_inputs` fails, the tx is still inserted (`m_verifivation_impossible`) so it can become valid later. | `tx_pool.cpp:305–350` | P | 4 | — | Consensus will re-check on the next connect (RC-138). |
| RC-159 | Origin-pinned `local` entries do not upgrade to stem/fluff except on a `block` arrival (PoW-backed). | `tx_pool.cpp:448–450` | P | 1 | [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) Q12 | Relay class, not validity. Included because `add_tx` is on the acceptance graph. **Reclassify:** this is relay-privacy, not tx-validity-as-included. Kept as P so the denominator's `add_tx` walk is exhaustive. |
| RC-160 | Mempool prune to `m_txpool_max_weight` after insert. | `tx_pool.cpp:532` | P | 4 | — | Eviction, not a validity rule. |
| RC-161 | `ver_non_input_consensus` is skipped in `add_tx` when `version == nic_verified_hf_version`. | `tx_pool.cpp:237` | P | 4 | — | Consensus still applied when the cache misses (RC-68–70). |

### 3.13 Hardfork / version table

| ID | Rule | Site(s) | Flag | Bucket | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| RC-162 | Main/test/stage hardfork tables are a single entry `{version:1, height:1, threshold:0, time:1341378000}`. | `hardforks.cpp:35–50` | C | 1 | v3-from-genesis; "Rebooted chain: all features active from genesis" | Time `1341378000` is a CryptoNote-era unix stamp. The **single-row table** is Shekyl; the timestamp payload is unexamined (bucket-4 residue on a bucket-1 shape). |
| RC-163 | `HF_VERSION_DYNAMIC_FEE`, `HF_VERSION_PER_BYTE_FEE`, `HF_VERSION_VIEW_TAGS`, `HF_VERSION_SHEKYL_NG` all equal 1. | `cryptonote_config.h:280–289` | C | 3 | rule 60: version dispatch below Shekyl's minimum is dead | Consumers still branch (RC-68, RC-69, RC-167). |
| RC-164 | `HardFork::add` refuses a block that fails `do_check`, then records `heights[current_fork_index].version` (not the block's vote) at that height. | `hardfork.cpp:134–141` | C | 4 | — | |
| RC-165 | Voting window / threshold machinery still runs (`window_size`, `default_threshold_percent`, `last_versions`). With one table row it cannot change the current version. | `hardfork.cpp:134+` | C | 3 | rule 60 (dead voting on a one-fork chain) | |
| RC-166 | `mainnet_hard_fork_version_1_till = 0` (and test/stage twins). | `hardforks.cpp:39,45` | C | 3 | rule 60 | |
| RC-167 | `check_output_types` still has `hf > VIEW_TAGS`, `hf < VIEW_TAGS`, and grace-period mixed-type arms. Unreachable at hf=1 with `SHEKYL_NG=1` (first arm wins). | `cryptonote_format_utils.cpp:985–1001` | C | 3 | rule 60 | |
| RC-168 | After a connect that advances hf, the pool is re-validated at the new version (genesis skipped). With one fork this never fires post-genesis. | `blockchain.cpp:6480–6490` | C | 3 | rule 60 | |

---

## 4. Sum check

IDs RC-1…RC-155 and RC-157…RC-168 = **167** rows. RC-156 was never
issued (the `handle_incoming_tx` blob-size site is already on RC-53).

| Section | IDs | Count | B1 | B2 | B3 | B4 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 3.1 header | 1–18 | 18 | 4 | 0 | 2 | 12 |
| 3.2 PoW | 19–28 | 10 | 8 | 1 | 0 | 1 |
| 3.3 timestamp | 29–32 | 4 | 1 | 0 | 0 | 3 |
| 3.4 miner-tx | 33–52 | 20 | 13 | 0 | 1 | 6 |
| 3.5 parse/semantic | 53–72 | 20 | 6 | 1 | 2 | 11 |
| 3.6 outputs | 73–80 | 8 | 7 | 0 | 1 | 0 |
| 3.7 inputs/FCMP | 81–99 | 19 | 15 | 0 | 3 | 1 |
| 3.8 PQC | 100–108 | 9 | 9 | 0 | 0 | 0 |
| 3.9 archival | 109–133 | 25 | 24 | 0 | 0 | 1 |
| 3.10 reorg | 134–142 | 9 | 2 | 0 | 0 | 7 |
| 3.11 storage | 143–150 | 8 | 2 | 0 | 0 | 6 |
| 3.12 mempool | 151–155, 157–161 | 10 | 1 | 1 | 1 | 7 |
| 3.13 hardfork | 162–168 | 7 | 1 | 0 | 5 | 1 |
| **Total** | | **167** | **93** | **3** | **15** | **56** |

`93+3+15+56 = 167`. Flags: 157 consensus + 10 policy = 167.

Policy rows: RC-151, 152, 153, 154, 155, 157, 158, 159, 160, 161.
RC-159 is flagged P even though the origin-pin has a Shekyl spec — it
is not chain-forking.

Counts were produced by parsing every `| RC-N | … | C|P | 1–4 |` table
row in this file at the pinned sha, then dropping the unused id. A
later editor who adds a row must re-run that parse (or equivalent) and
update §0 and this table in the same edit.

---

## 5. Validation sites (the 48)

Functions that can reject, walked from the entry points:

1. `core::handle_incoming_tx`
2. `core::handle_incoming_block` (both overloads)
3. `core::check_incoming_block_size`
4. `core::add_new_tx`
5. `core::check_tx_semantic`
6. `core::check_tx_inputs_keyimages_diff`
7. `core::check_tx_inputs_ring_members_diff`
8. `core::check_tx_inputs_keyimages_domain`
9. `parse_and_validate_tx_from_blob` / `expand_transaction_1`
10. `parse_and_validate_block_from_blob`
11. `tx_memory_pool::add_tx`
12. `ver_non_input_consensus` (both overloads)
13. `ver_mixed_ct_semantics`
14. `Blockchain::add_new_block` (both)
15. `Blockchain::handle_block_to_main_chain` (wrapper + body)
16. `Blockchain::handle_alternative_block`
17. `Blockchain::switch_to_alternative_blockchain`
18. `Blockchain::check_block_timestamp` (both)
19. `Blockchain::prevalidate_miner_transaction`
20. `Blockchain::validate_miner_transaction`
21. `Blockchain::parent_frozen_segment_count`
22. `Blockchain::check_tx_inputs` (both)
23. `Blockchain::check_tx_outputs`
24. `check_commitment_mask_valid`
25. `Blockchain::check_fee`
26. `Blockchain::verify_block_attestation`
27. `Blockchain::check_archival_bond_post_input`
28. `Blockchain::check_archival_serve_credit_input`
29. `verify_transaction_pqc_auth` / `get_transaction_signed_payload`
30. `HardFork::check` / `check_for_height` / `do_check`
31. `check_hash`
32. `get_block_longhash` / `get_altblock_longhash`
33. `get_difficulty_for_next_block` / `get_next_difficulty_for_alternative_chain`
34. `lwma1_next_difficulty` (Rust FFI)
35. `check_inputs_types_supported`
36. `check_outs_valid` / `check_output_types`
37. `check_money_overflow`
38. `BlockchainLMDB::add_block` (BLOCK_EXISTS, BLOCK_PARENT_DNE)
39. `BlockchainLMDB::add_transaction_data` (TX_EXISTS)
40. `BlockchainLMDB::add_spent_key` (KEY_IMAGE_EXISTS)
41. `BlockchainLMDB::add_alt_block`
42. `shekyl_fcmp_verify`
43. `shekyl_pqc_verify`
44. `shekyl_archival_verify_attestation`
45. `shekyl_archival_verify_serve_credit_vin`
46. `shekyl_emission_vin_verify` / `shekyl_emission_block_claims_unique`
47. `shekyl_archival_verify_unbond_bond_post` / holdings-update / JoinMarket
48. `shekyl_block_reward` / `shekyl_advance_already_generated` / burn+split

---

## 6. Decision log (where the census met the tree)

Recorded in the RK convention: the plan as-briefed vs what the tree
actually contained at `8ba1aae3d`.

1. **Entry-point line numbers survived.** All brief anchors
   (`handle_incoming_block` 1327/1335, `handle_incoming_tx` 720,
   `add_new_block` 6609, `handle_block_to_main_chain` 3100 and 5689,
   `handle_alternative_block` 2214, `check_tx_inputs` 3241/3440,
   `check_tx_outputs` 3344, `validate_miner_transaction` 1746) match
   this sha.

2. **`handle_block_to_main_chain` duality is a wrapper, not two
   validators.** `:3100` hashes and forwards to `:5689` with an empty
   supplement. Rule sets are identical. The brief asked whether they
   diverge; they do not.

3. **Alt-path is a subset; connect is the main path.** Promotion
   (`switch_to_alternative_blockchain:1438`) re-enters
   `handle_block_to_main_chain`, so skipped alt-admission checks
   (FTL, `validate_miner_transaction`, per-tx `check_tx_inputs`) are
   enforced at connect. They remain census rows because they affect
   what is stored as alt and what can trigger a difficulty reorg
   *before* promotion.

4. **FTL is missing on alt admission.** `check_block_timestamp(vector, b)`
   (`:5514`) has no future-time bound. A timestamp `now+541` can sit
   on an alt chain until promotion, which then applies RC-29.
   Recorded as a finding (FOLLOWUPS), not fixed.

5. **Merkle is not a header field.** Identity/PoW bind the tx tree
   through the hashing blob (RC-7). A rewrite that adds an explicit
   `merkle_root` field would be a wire change, not a missing check.

6. **`check_for_double_spend` is not on the live path.** The call is
   commented out (`:6024–6030`). Intra-block KI uniqueness is
   `KEY_IMAGE_EXISTS` at DB insert (RC-144).

7. **`PER_BLOCK_CHECKPOINT` is compiled in** (`CMakeLists.txt` sets it
   to 1). On an empty `m_blocks_hash_check` the skip is inert. A
   populated table skips PoW and FCMP. Bucket 3 under rule 60.

8. **Version dispatch is live syntax, dead semantics.**
   `HF_VERSION_* = 1` and the hardfork table is one row. Several
   arms still test `hf < N`. Bucket 3, not deleted here.

9. **Tx-version bounds exist twice and are written differently.**
   `ver_non_input_consensus` uses an hf table that collapses to 3..3;
   `check_tx_inputs` hardcodes 3..3. Same live bound, drifted
   expression. FOLLOWUPS.

10. **`config/` is not the only consensus-constant home.**
    `FCMP_MAX_INPUTS_PER_TX` (8), `CRYPTONOTE_MAX_TX_SIZE`,
    `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60), `MAX_TX_EXTRA_SIZE`,
    `CRYPTONOTE_MAX_TX_PER_BLOCK`, `BLOCK_SIZE_SANITY_LEEWAY` (100)
    live in headers. Each is its own row.

11. **Fee is policy on the pool path and consensus-absent on connect.**
    `check_fee` is skipped when `kept_by_block`. A block may include
    a zero-fee spend. Whether that is right-for-Shekyl is bucket 4
    (the *skip* is the inherited behavior; the economics of a
    block-included fee is RC-50, which still splits whatever fee is
    present, including zero).

12. **`is_tx_spendtime_unlocked` still has a unix-time arm** after
    RC-77 forbade timestamp encoding on new txs. Bucket 3.

13. **No ratification record found** (searched `docs/V3_WALLET_DECISION_LOG.md`,
    `docs/completed/`, `docs/design/`) for: prev_id linkage, orphan
    policy, merkle-in-hashing-blob, majority-difficulty reorg,
    checkpoint-forced reorg, 2-output minimum, key-image sort order,
    key-image torsion check, coinbase unlock window 60, decomposed
    coinbase amounts, 1 MB tx size, 100-byte block-blob leeway,
    ArticMine long-term weight clamp, 2% fee buffer. Those are
    bucket 4. A remembered "of course we keep that" without a
    locatable pointer stays 4.

14. **Bucket 2 is small on purpose.** Only rows whose *inherited
    comparison* was examined and kept (PoW `check_hash` port,
    BP+ expand-time layout, `kept_by_block` as the project's
    discriminator) sit there. Shekyl-designed machinery is bucket 1
    even when it reuses an inherited type.

15. **This document's family is `RC-`, not `CEN-`.** The brief minted
    `CEN-` for the census program. This is the second independent
    walk; registering `CEN-` here would collide with the sibling
    first census. `RC-` (rule census) is free under rule 94's
    alphabetic-prefix-until-digit test.

---

## 7. How a later sha diffs this census

1. Re-pin HEAD.
2. Re-walk the §1.1 graph. New callee that can reject ⇒ new row.
   Deleted callee ⇒ strike the row (bucket 3 completed, or a
   deletion that this census had not yet classified).
3. Diff this table's sites. A line shift without a behavioral change
   is a census update, not a new rule.
4. Inverse spot-check the six subjects in §0.2. Absence is evidence
   the walk broke.
5. Re-sum buckets. They must equal the row count.

---

## 8. Out of scope (restated)

No code change. No FFI work. No differential test. No ruling on
whether a bucket-4 rule is right for Shekyl. Defects noticed are
census notes and FOLLOWUPS one-liners, not fixes.
