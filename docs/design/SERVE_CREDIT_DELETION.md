# The serve-credit deletion

**Status:** OPEN — ruled 2026-10-11 (maintainer), not built. This
document is the deletion's pre-flight: one table of what goes, what
succeeds it, and what the C++ daemon stops doing. It is contracted to a
record when the change lands.

**Identifiers.** Family `SCD-`: one `SCD-#` per mechanism deleted (§2)
and per boundary this change does not cross (§3).

**Pin.** Grounded at `dev@adb2013da`. Sites are named by symbol.

---

## 1. Why now, and the rule

The serve-credit input carried a pass record whose pair the prover
named. The secret per-block draw replaces it
([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md)): a
pass is a record in a block's bundle, its pair is derived, and settlement
reads a row. No production code produces the old input, and nothing will.

**The rule (maintainer, 2026-10-11): C++ is deleted as soon as it is
obsolete, not held for `DEL-008`.** Obsolete means one of:

- its input can no longer exist;
- its output feeds nothing;
- its Rust successor is authoritative.

A deletion that changes consensus lands on both sides in one change
(rule 07). Nothing is added to C++.

**Extent: everything the rule reaches.** The input is the root. Its table
has three live readers besides the admission gate, and none of them goes
quiet when the table is empty: the slash scheduler would read every
observed epoch as a miss, the epoch-close gather would credit nobody, and
Release verification would take its permissive branch. Each is deleted
with what only it fed, to where nothing depends on it.

## 2. What is deleted

One row per mechanism. "None until the Rust daemon" means the Rust
validator already has the rule and it is not consensus until the cutover.

| # | C++ mechanism | What it did | Rust successor | What the C++ daemon stops doing |
| --- | --- | --- | --- | --- |
| `SCD-1` | The input: `txin_archival_serve_credit_response`, variant tag `0x02`, its binary, JSON and boost serialization, `count_serve_credit_inputs`, `archival_tx_kind::serve_credit_only`, the prunable section's `serve_credit_pruned` records, the two size constants | Carried one pass record per input, kept half in the input and pruned half in the prunable section | **None, by design.** The pass is a bundle record. Rust's `Input::ServeCredit`, `Prunable::serve_credit_pruned` and the `ServeCreditOnly` class are deleted in the same change | Parsing tag `0x02`. A transaction or block that carries one is malformed |
| `SCD-2` | The record: `ArchivalServeCreditResponse`, `ArchivalServeCreditPruned`, the leaf-path preimage and split countersignature (`shekyl-archival-retention`, `wire.rs`), with `shekyl_archival_serve_credit_extract`, `shekyl_archival_verify_serve_credit_vin`, `shekyl_archival_challenge_leaf_index` | The record's bytes and its verification | **None, by design** | — (Rust, called only by the gate) |
| `SCD-3` | The admission gate: `Blockchain::check_archival_serve_credit_input`, its arm in `check_tx_inputs`, `get_archival_serve_credit_key`, the block-level duplicate pass (CEN-G7's C++ half), the pool's `'S'` reservation key, the static shape check, and the FFI only it called (`shekyl_archival_serve_credit_epoch_ok`, `_challenge_seal_on_chain`, `_challenge_leaf_chunk_bounds`, `_verify_drop_verdict`, the verify context) | CEN-J1 to J10: one challenge per pair-epoch on the beacon, held at the fire height, the frozen segment's leaf, the hybrid countersignature | The bundle verifier (the Slice C round), not yet built. **None until then** | Admitting any serve credit |
| `SCD-4` | The table: `archival_serve_credit` (LMDB), `set_`/`remove_`/`has_archival_serve_credit_bit`, `archival_serve_credit_pass_count`, its prune and its snapshot arm | One row per admitted pass, keyed `(P, shard, epoch, height)` | The issued-draw index's `passed` bit and the settlement row (`SO-D10c`), in the Rust store | Recording passes |
| `SCD-5` | The slash scheduler: `process_archival_slash_at_height`, `process_archival_slash_for_epoch`, `archival_challenge_failed_at_height`, `archival_failure_window_slashable`, `archival_baseline_observed_at_epoch`, `apply_archival_slash_one`, with `shekyl_archival_failure_window_params`/`_slashable` and the beacon's `_challenge_seal_height`/`_fire_height` | Slashed a pair with `m` misses in `n` observations, where "served" was a pass count above zero | The Rust slash pass, which reads the settlement row (`shekyl-chain-rules`, `archival/slash.rs`). **None until the Rust daemon** | Slashing. A bonded persona is never slashed by the C++ |
| `SCD-6` | The emission gather: `gather_archival_epoch_rows_window` and its callers, the `r_market` and `Σwork` writes of `process_archival_epoch_close_at_height` | Credited every pair with a pass in the epoch and froze its market counts and work total at the close | The Rust slash pass's gather over Served rows (`SO-D11`). **None until the Rust daemon** | Crediting anyone. The close still freezes the budget |
| `SCD-7` | Emission-claim admission: the C++ arm that verifies an emission vin against the gathered snapshots, at connect and at submit (CEN-J18 to J26's C++ half), and `txin_archival_reward_emission` if nothing else reads it | Paid a persona its share of an epoch's budget | `rules::tx_emission`, `rules::tx_emission_against`. **None until the Rust daemon** | Admitting any emission claim. No archival reward is paid by the C++ |
| `SCD-8` | The last-served reads: `archival_bond_last_served_epochs`, `archival_bond_all_last_served_epochs`, `shekyl_archival_last_served_scan`, `shekyl_archival_whole_record_last_served`, and the cooldown operands of Release verification | Held a Release until the persona's last served epoch had aged past the cooldown | CEN-J16 in Rust (`rules::tx_bond`), reading the Rust store. **None until the Rust daemon** | Applying the cooldown. See `SCD-B2` |
| `SCD-9` | The claim-source RPC: `get_archival_emission_claim_source`, `fill_archival_emission_claim_source`, the submit facts that carry the same fields | Told a wallet what it could claim | The Rust daemon RPC's item on the `DEL-008` row. **None until the Rust daemon** | Answering it |
| `SCD-10` | The regtest injector: `Blockchain::regtest_inject_archival_serve_credit`, the `inject_archival_serve_credit` RPC method, its client in the regtest harness | Wrote a pass row directly on Fakechain | The Rust store's Fakechain door (`IssueDraws`) | — (test only) |

**Tag `0x02` is retired, on both sides.** It is recorded as retired in
the C++ variant-tag list and in `shekyl-wire`'s input tags, so it is not
reassigned. Removing the alternative shifts the boost-serialization
indices of the two alternatives after it; that matters only to data
persisted through boost across the change, and this is a regenesis.

**Tests go with what they tested** (rule 15), each deletion carrying its
reason at the site or in the commit. That includes the five C++ slash
tests that append 30,000 to 180,000 blocks: they test `SCD-5`.

## 3. Boundaries this change does not cross

| # | Not deleted | Why |
| --- | --- | --- |
| `SCD-B1` | The six captured chains. No chain contains a serve-credit transaction. `emission-claim` contains one injected credit and an emission claim | The bytes are kept while they replay through the Rust rules. Its generator dies with `SCD-7` and `SCD-10`, so the chain cannot be recaptured; if a recapture is ever needed the chain is retired |
| `SCD-B2` | Release in the C++ | With no last-served operand the cooldown predicate has nothing to compare. Whether the C++ Release arm keeps running without it, or is deleted with it, is decided at the site: if the arm cannot be stated without the operand it goes under `SCD-8`, and the table gains the row |
| `SCD-B3` | The Rust store's `archival_serve_credit` table, the reads A3 to A5 and CEN-J16's use of them | After this change its only writer is the Fakechain door. `SO-D10c` rules it re-keyed or deleted when admission lands, and `SO-D12j` defers what its two readers become to that increment. Not this change's, unless ruled in |
| `SCD-B4` | The Rust wallet's claim builder (`shekyl-engine-core`, `emission_source`, `emission_claim`) | It reads `SCD-9`'s RPC and has no source until the Rust daemon serves one. It is the successor's client, not an obsolete mechanism. Flagged: by the letter of the rule its input cannot exist for now |
| `SCD-B5` | The C++ JSON input parser's missing final `else` | An unknown member name leaves a default-constructed input. It is a defect for every unknown name, not this one; nothing is added to C++, and it goes with the parser |
| `SCD-B6` | Names that only look like the input: the emission vin's `serve_credit_bit`, `ServeCreditRow`/`CreditPair` (the close's operands), `serve_credit_batch_commitment` (the secret draw), `holds_shard_at`, `settlement_window_slashable` | They belong to surviving or successor code |

## 4. Order of work

1. This table.
2. `SCD-10`, `SCD-9`: the injector and the claim-source RPC, with their
   callers.
3. `SCD-7`, `SCD-6`, `SCD-8`: claim admission, the gather, the
   last-served reads.
4. `SCD-5`: the slash scheduler.
5. `SCD-3`, `SCD-4`: the gate and the table.
6. `SCD-1`, `SCD-2`: the input and the record, on both sides, and tag
   `0x02` retired.
7. The registers that enumerate what went: the LMDB schema document and
   its coverage gate, the forcing-cells register, the census rows, the
   crypto-domain registry, the FFI ratchet.

The order is by dependency: a reader goes before what it reads.
