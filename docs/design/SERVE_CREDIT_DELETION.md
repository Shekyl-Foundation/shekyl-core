# The serve-credit deletion

**Status:** OPEN — ruled 2026-10-11, extent re-ruled 2026-10-12
(maintainer), not built. This document is the deletion's pre-flight: what
goes, who consumes it, what stays and what replaces each kept piece. It is
contracted to a record when the change lands.

**Identifiers.** Family `SCD-`: `SCD-#` for a mechanism deleted (§2),
`SCD-K#` for one kept and why (§3), `SCD-B#` for a boundary (§4).

**Pin.** Grounded at `dev@adb2013da`. Sites are named by symbol.

---

## 1. The rule

**C++ is deleted when its Rust replacement serves everything that
consumes it** (maintainer, 2026-10-12). Not when its input can no longer
exist: a mechanism whose input has dried up may still be read, and its
readers may feed code that has landed.

That is the case here. The serve-credit input has no producer, so the
C++ serve-credit table is already never written. Its readers still run,
and they feed the landed Rust wallet through
`get_archival_emission_claim_source`: the persona serving host reads the
shards it owes from that method, Release dispatch reads its exit
operands, and the claim builder reads its per-epoch snapshots. The
replacement for those readers is the Rust daemon serving that method
(`DAEMON_RPC_KV_CUTOVER.md`, `RK-9`), which has not landed. They stay.

**So this change deletes the input and nothing downstream of it.** No
block carries one and nothing produces one, so deleting it changes no
state any reader sees.

A deletion that changes consensus lands on both sides in one change
(rule 07).

## 2. What is deleted

Each row names the consumers of what it deletes. A consumer that is
landed Rust or belongs to another lane is raised with the maintainer
before it is cut (§5).

| # | Deleted | Consumers |
| --- | --- | --- |
| `SCD-1` | **The input, on both sides.** Rust: `Input::ServeCredit`, `Prunable::serve_credit_pruned`, the `TxClass::ServeCreditOnly` class, `TAG_INPUT_SERVE_CREDIT` and the two size constants. C++: `txin_archival_serve_credit_response`, variant tag `0x02`, its binary, JSON and boost serialization, `count_serve_credit_inputs`, `archival_tx_kind::serve_credit_only`, the prunable section's `serve_credit_pruned`, the two size constants | **Rust rules:** CEN-G7's serve-credit arm, CEN-H20, CEN-J2, CEN-J4 to J6 (`judge_serve_credit_bond`), the CEN-I1 skip, and `archival/inputs.rs`, which turns an input into a serve-credit row of the block's archival delta. **Rust submit path:** `SubmitTxKind::ServeCreditOnly` in `shekyl-daemon-rpc` (`phase_a`, `verifier`, `engine`). **Rust producers:** `shekyl-harness-spender` (`Persona::serve_credit_vin`), `shekyl-chain-ingest` (`scenario_archival`, the `DuplicateServeCredit` mutation), `shekyl-chain-store` (`grown.rs`). **Rust initialisers:** `shekyl-tx-weight`, `shekyl-tx-builder`. **C++:** the pool's `'S'` reservation key, three skip arms in `cryptonote_core.cpp`, the connect and pop arms in `blockchain_db.cpp` that write and remove the table's row for an admitted input, the weight and amount-sum arms in `cryptonote_format_utils.cpp`, the static shape check in `tx_verification_utils.cpp`, the admission arm in `blockchain.cpp` |
| `SCD-2` | **The record.** `ArchivalServeCreditResponse`, `ArchivalServeCreditPruned`, the leaf-path preimage and the split countersignature (`shekyl-archival-retention`, `wire.rs`), with the three exports `shekyl_archival_serve_credit_extract`, `shekyl_archival_verify_serve_credit_vin`, `shekyl_archival_challenge_leaf_index`, and the labels only it used | The C++ gate (`SCD-3`) and `get_archival_serve_credit_key`; in Rust, `rules/body.rs` (`ArchivalKey::ServeCredit`) and the harness producer |
| `SCD-3` | **The C++ admission gate.** `Blockchain::check_archival_serve_credit_input`, the block-level duplicate pass, and what only the gate called: `shekyl_archival_serve_credit_epoch_ok`, `_challenge_seal_on_chain`, `_challenge_leaf_chunk_bounds`, `_verify_drop_verdict`, the verify context; and the DB accessors with no other caller (`archival_bond_holds_shard`, `get_archival_shard_segment_at_height`, `archival_bond_join_epoch`, `archival_bond_good_through`, `get_curve_tree_leaf_chunk`) | None but the input's admission arm. Each accessor is confirmed to have no other caller before it goes |

**Tag `0x02` is retired on both sides.** It is recorded as retired in the
C++ variant-tag list and in `shekyl-wire`'s input tags, so it is not
reassigned. Removing the alternative shifts the boost-serialization
indices of the two alternatives after it; that matters only to data
persisted through boost across the change, and the next tag is a
regenesis.

**Tests go with what they tested** (rule 15), each with its reason.

## 3. What is kept, and what replaces it

Each of these is deleted when the Rust daemon serves
`get_archival_emission_claim_source` (`RK-9`) and the wallet reads from
it. Not before.

| # | Kept | What reads it | Replaced by |
| --- | --- | --- | --- |
| `SCD-K1` | The C++ `archival_serve_credit` table, with `archival_serve_credit_pass_count`, its prune and its snapshot arm | The slash scheduler, the emission gather, the last-served reads | The Rust store's issued-draw index and settlement rows, served by the Rust daemon via `RK-9`. Deleted then |
| `SCD-K2` | The C++ slash scheduler | The slash log and slash watermark, which Release verification and the wallet's exit pre-check read | The Rust slash pass over settlement rows. Deleted with `SCD-K1` |
| `SCD-K3` | The C++ emission gather and emission-claim admission | The claim-source method's per-epoch snapshots; the wallet's claim builder | The Rust rules' gather over Served rows and `rules::tx_emission`. Deleted with `SCD-K1` |
| `SCD-K4` | The last-served reads behind Release | Release verification; the method's cooldown anchor | CEN-J16 in Rust over the Rust store. Deleted with `SCD-K1` |
| `SCD-K5` | `get_archival_emission_claim_source`, wire format unchanged | The Rust wallet: the persona serving host, Release dispatch, the backing set, the synced chain facts, the claim orchestrator | The Rust daemon serving it, `RK-9` |
| `SCD-K6` | The regtest injector and its RPC method | `e2e_emission_claim_accepted_and_applied`, the wallet's end-to-end claim test | The Rust store's Fakechain door, when that test runs against the Rust daemon |

With the input gone the injector is the table's only writer, on
Fakechain only. On every other network the table is empty, as it is
today.

## 4. Boundaries

| # | Boundary | Why |
| --- | --- | --- |
| `SCD-B1` | The six captured chains keep their bytes | No chain contains a serve-credit transaction |
| `SCD-B3` | The Rust store's `archival_serve_credit` table and the reads A3 to A5 | After this change its only writer is the Fakechain door. `SO-D10c` and `SO-D12j` put its fate in the admission increment |
| `SCD-B4` | The Rust wallet is not touched (ruled 2026-10-12) | It is the landed consumer the kept C++ serves |
| `SCD-B5` | The C++ JSON input parser's missing final `else` | A defect for every unknown name; nothing is added to C++ |
| `SCD-B6` | Names that only look like the input: the emission vin's `serve_credit_bit`, `ServeCreditRow`/`CreditPair`, `serve_credit_batch_commitment`, `holds_shard_at`, `settlement_window_slashable` | They belong to surviving or successor code |

## 5. Consumers raised before cutting

`SCD-1`'s consumers include landed Rust outside this lane and tests that
use the input as their way to earn a credit. Each needs a disposition
before the input is cut:

1. **The submit path** (`shekyl-daemon-rpc`, `SubmitTxKind::ServeCreditOnly`).
   Landed Rust in the RPC lane. With the input gone the kind is
   unreachable and goes with it.
2. **The Rust rules for the input** (CEN-G7's arm, H20, J2, J4 to J6).
   They are `implemented` census rows. Deleting them needs the census
   status for a row retired by ruling, which the serve-credit
   specification assigns to the Slice C round.
3. **Rust tests that mine a serve-credit transaction to earn a credit**
   (`shekyl-chain-ingest`: `scenario_archival`, `scenario_emission_tests`,
   `scenario_join_tests`, `archival_slash_tests`, `archival_corpus_tests`;
   `shekyl-chain-store`: `grown.rs`, `slash_scan_bench_tests`). They move
   to the Fakechain door or lose the step, test by test.
4. **Fixtures shared with C++ tests:** `serve_credit_tx_parity_v1.json`,
   entry 7 of `pqc_signing_preimage_v1.json`, the serve-credit class of
   `prunable_digest_parity_v1.json`, and the gate-2 and gate-4 KATs. The
   C++ tests that read them test the input or the gate and go with it.
