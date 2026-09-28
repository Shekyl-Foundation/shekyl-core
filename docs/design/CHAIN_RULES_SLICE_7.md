# `shekyl-chain-rules` slice 7 — census 4.G, the block body, and the four 4.F rows that waited on it (DRS-E6 increment 8)

**Status:** OPEN — **Round 0 pre-flight, written 2026-09-26 against `dev` @
`ad557ac5a` (post-#874, slice 6 closed out; post-#873, DRS-E3's curve-writer
pre-flight).** **Round 0 CLOSED — Q1, Q3–Q8 ruled and Q9 re-ruled at
parity 2026-09-26; Q2 ruled (b) 2026-09-27 by the floor bench (§5.1, §8,
each line-local). Commit 1 landed as #877 (merged `ece3aa4fb`); commit 2,
the four measurements, is #880.** Registered before implementation (rule
94 §5); process per
`26-sub-pr-design-discipline.mdc` (cited here as the pre-flight's shape:
substrate re-read at the pin, artifact execution before a budget becomes a
gate).

Branch commits are named by PR and subject, never by SHA (slice 6's rule at
its head, inherited). A `dev` SHA is an era; every line number in this file
is read at `ad557ac5a` unless its sentence says otherwise.

Parent: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §4.6 (`validate`,
the `BlockRule` class), [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5
(DRS-E6; ordering-table row *4.G Block body — slice 7 — aggregates
4.F/4.H/4.I (weights, fees, listed-tx uniqueness)*). Census:
[`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §4.G, **13** live rows
(CEN-G1–G7, G6b, G9–G13; G8 retired by C2-R1a). Predecessors:
[`CHAIN_RULES_SLICE_4.md`](CHAIN_RULES_SLICE_4.md), whose Q1 (RULED (a),
2026-09-22) sent **F14, F14b, F16, F18** here to land *with the weights
machinery*; [`CHAIN_RULES_SLICE_6.md`](CHAIN_RULES_SLICE_6.md), whose §5.1
predicted this slice's fixture class should be smaller than its own —
falsifiable here (§5.1).

---

## 0. What this slice is

The **block-level rules**: what is true of one block's *body* as a whole,
after every transaction in it has passed `tx_form` and `tx_against` on its
own. In the C++ this is the second half of `handle_block_to_main_chain`
(`blockchain.cpp:5495–5951`): the listed-transaction loop that resolves each
hash to a body and refuses one already on the chain (G1, G2), the
pruned-block refusal (G5), the three cross-transaction uniqueness passes
(G7, G9, G10), the emission bookkeeping the coinbase is judged against
(G11, G12, G13), and — computed *for the next block* at the end of every
connect — the weight medians (G6, G6b, `:6049–6099`) that F14/F14b/F16/F18
consume in `validate_miner_transaction` (`:1525`).

Two things make 4.G unlike 4.I:

- **Most of it is aggregation, not verification.** Eight of the thirteen
  rows either sum, fold or look up. Five refuse on their own predicate:
  G1, G2, G7, G9, G10. G7/G9/G10 already have Rust bodies
  (`shekyl-archival-retention`). G1 is the store's `tx_exists` belt, with
  no view read. G2 has no pairing rule; `Transaction::hash` is the hash,
  not that rule. The crypto is behind us.
- **The heaviest row is a definition, and it is the one the census still
  records as divergent.** G6/G6b's effective median is what the coinbase's
  exact-pay verdict (F18) is a function of. The census ratified **S = 4**
  (C2-R2 Q3, GAP-7 measured on the Pi 4 floor) against Monero's ×50 and
  its cells say the C++ still ships the ×50. **Read at the line, it does
  not** (§3.8): since `1c8594049` (2026-09-12) both C++ sites call the Rust
  clamp, so G6 lands at **parity**, and the divergence this slice carries
  is in two census cells and two register rows, corrected in commit 10.
  Slice 4 Q1 ruled that G6 lands in *its own* slice, in the PR that owns
  the weights — this is that PR; what it owns turned out to be a record
  correction rather than a rule change, which is the better outcome and
  was found by reading the subject instead of the question.

In Rust the home is `validate` (`validate.rs:277`): the `BlockRule` class
(`rules::run::<L1,_>` after the slot loop, `:349`) for the view-bound
refusals, a `FormRule` for G2 (no view; `rules/mod.rs:156`), and
definition rows recorded where derived and carried on `ChainValid` — the D4
precedent (`cumulative_difficulty` left `ConnectFacts` when the validator
derived it, slice 2), which E3's pre-flight names as *the lane's precedent
for "who derives"* (`DRS_E3_CURVE_WRITER.md` §1 item 11).

## 1. Parents — landed? (§7.5.1 (a))

### 1.1 Landed

- **The slot loop and `BlockRule`** (`validate.rs:336–355`): every slot
  through `tx_form` then `tx_against`; L1 runs after, over the block. G7, G9,
  G10 and G1 are L1's shape — span the slots, refuse at the second
  occurrence's `Locus`. G2 is not: it reads no view, so it is a `FormRule`.
- **The definition-row pattern** (slice 5 I12/I17, slice 4 F13/F15/F20):
  recorded as coverage where derived, value staged for its consumer. G6/G6b
  are definitions with four consumers in this slice (F14, F14b, F16, F18)
  and one outside it (the block template, §3.5).
- **The four 4.F rows' bodies** — `shekyl_economics::emission::
  {paid_block_reward, block_weight_limit}`, `emission_share::
  compute_emission_split` — are landed and tested; slice 4 left them
  `pending` in the registry (`census.rs:387–392`) with the median as the one
  missing operand.
- **The archival uniqueness bodies** — `serve_credit_decisions::
  serve_credit_block_unique` (`shekyl-archival-retention/src/
  serve_credit_decisions.rs:460`), `claimed_epochs::
  emission_block_claims_unique` (`:123`), `bond_post::bond_post_block_unique`
  (`:446`) — are the bodies the C++ calls through the FFI (`blockchain.cpp:
  5790`, `:5799`; G7's C++ mirrors the Rust at `:5686–5712`). The crate
  already depends on `shekyl-archival-retention` (H21/H22, slice 5); the
  edge exists.
- **The store records what G6 reads.** `BlockInfo { weight,
  long_term_weight, long_term_effective_median, .. }` (`codec/chain.rs:
  74–101`), one row per height. `ConnectFacts` passes all three through
  (`connect.rs:164–196`), and the ingest's `facts.rs:40–57` table names
  **this slice** as what flips `weight`, `long_term_weight` and
  `long_term_effective_median` from passed-through to derived, and
  `coins_generated` on F14b (the same table, the row above `burned`).
- **The E2 mutation family pins two of this slice's rows.**
  `ReorderedBodies` → CEN-G2, `WrongReward` → CEN-F18
  (`DRS_E2_REPLAY_DRIVER.md` §3.10, `:456–457`), both **Pending — the block
  connects**. The refusal branch is written; the family flips the day the
  row lands, as `DoubleSpend` did for I7.

### 1.2 In flight — DRS-E3, and the surfaces both lanes touch

#873 merged E3's pre-flight the same hour this file was cut. E3 is the lane
slice 6's three deferrals wait on; slice 7 does not wait on it — but the two
lanes will edit the **same four files**, and that is stated here so the
merge is planned rather than discovered:

| surface | E3 adds (`DRS_E3_CURVE_WRITER.md` §6 commit 4, §3.2) | slice 7 adds | conflict class |
| --- | --- | --- | --- |
| `ChainView` trait (`view.rs`), `BatchView`, `MockChain` | `tree_frontier`, `matured_outputs_at`, `depth_at` | the weights-window read (Q2) and `has_transaction` (Q3) | textual — adjacent methods; resolve by keeping both |
| `ChainValid` / the verdict | `TreeGrowth` | `weight`, `long_term_weight`, `long_term_effective_median`, `coins_generated` (Q5) | textual |
| `ConnectFacts` / `facts.rs` | deletes `root_after` (CTW-Q6, commit 6) | wave A flips four passed-through fields (`weight`, `long_term_weight`, `long_term_effective_median`, `coins_generated`) to verdict reads | **semantic** — both lanes shrink `passed_through`; the count E3 states as *6 → 5* is *6 → 1* after E3 and wave A (`burned` remains until wave B); whichever lands second re-counts |
| `RecordedBlock` | — | possibly `weight` + `long_term_weight` (Q2 (a)) | none if Q2 takes (b) |

**E3 LANDED 2026-09-27 (#878, `dev` @ `9fb8fb3f9`), four minutes before
commit 3 branched — so the table above is now records-was, and what it
predicted resolved as follows.** The trait row became adjacency, not
conflict: `tree_frontier`, `leaf_count_at`, `outputs_at` and a derived
`depth_at` were on `ChainView` when commit 3 added `weights_window` and
`has_transaction` beside them — nine implementors, each carrying both. The
`ConnectFacts` row resolved as predicted: `root_after` is gone
(`passed_through` 6 → 5 at E3's landing; wave A takes it to 1). Two things
the table did **not** predict: **(i)** E3 and #880 merged clean textually
and **broke each other semantically** — #880's bench built `ConnectFacts`
with a `root_after` field E3 had deleted, and its G2 test built the
replay's trace with `placeholder_root_after`, which E3 deleted with the
placeholder; `cargo test -p shekyl-chain-store` and `-p shekyl-chain-ingest`
did not compile on `dev` between `9fb8fb3f9` and **#884** (`9d549ead2`),
which repaired both from the E3 side — `trace_with` grows the tree over
the chain it is given and writes the trace's `root_after` from it, so a
caller cannot name a root; `batch_root_going_into` is the one in-batch read
of the root a header must carry, used by `connect_chain`, the prune
builder and the weights bench — and re-held the G2 replays to E3's root
oracle (`compared` at every height, `diverged` empty). Commit 3 had
repaired the same two sites independently; those commits were dropped when
#884 landed and commit 3 was rebuilt on it. **(ii)** The **wave B blocker is
gone**: `leaf_count_at` is F17's operand (`frozen_segment_count` is a
function of the leaf count at the parent state), so §5 row 9's absorption
condition is met and F17, F18, G11 and G13 return to this slice as wave A's
tail. Slice 6's I13 (`depth_at` is its operand) and I15/H19-verify (a
scenario spend against a real tree) are unblocked by the same landing; they
are slice 6's FOLLOWUPS rows, not this slice's, and are named so their
owner hears it.

**One dependency runs from this slice into E3, and it is not a merge
surface.** G2 (§3.1) is a precondition for E3's correctness: E3's drain
order is the tree's leaf order, the leaf order is consensus, and a block
whose bodies connect in an order the header did not commit to puts outputs
into the tree in that order on one node and another order on the next.
E3's replay oracle (its commit 5) detects the divergence after it exists;
G2 refuses the block before it does. Named here so E3 reads it as a
dependency it inherits, not a row it waits to see.

**The one hard dependency runs the other way.** F17 (fee burn) needs
`frozen_segment_count`, a function of the curve-tree leaf count E3 will
record per height (`curve_tree_leaf_counts[h + 1]`, E3 §3.4). F18 needs
F17's `miner_fee_income`; G11's accrual needs both F16's and F17's legs.
So **F17, F18, G11 and G13 wait on E3's leaf count**, exactly as slice 4
recorded (*F17 on E3, F18 blocked (F14b, F17)*). This slice lands the
median and everything the median unblocks (F14, F14b, F16, G12) and names
F17/F18/G11/G13 as its one successor wave — absorbed here if E3's commit 4
lands inside the slice's window, else the named successor (§5 row 9,
falsifier stated). That is slice 6's I13 shape.

### 1.3 Not a parent, but a consumer: the block template

`shekyl-block-template` takes `EmissionContext { median_weight, .. }` from
its caller (`block-template/src/tests.rs:114`, `:297`) — the producer prices
the coinbase against a median *somebody hands it*. Today the scenario
driver hands `FULL_REWARD_ZONE`. When G6 lands as a `pub fn` in the rules
crate (the `mtp_median_at` shape the template already reads,
`block-template/src/tests.rs:104`), the template reads the same definition
the validator judges by, and the driver's constant goes. **Not this slice's
edit** — the template is TXE-F8's — but its consumer is named so the
function's signature is shaped for two readers, not one (Q4).

## 2. Row-body audit (§7.5.1 (b)) — 17 rows, pins read at `ad557ac5a`

Bucket and class from the census; the C++ site re-read at this pin (the
census's line numbers are its own era's — `5936–5941` for G1 is `5516–5522`
today — and are **not** corrected here; the census re-pin is commit 10's).

| row | b | what the C++ does at `ad557ac5a` | Rust body today | proposed disposition |
| --- | --- | --- | --- | --- |
| **G1** | 4 | `m_db->tx_exists(tx_id)` → `reject_block_form` (`:5516–5522`); the miner tx is not in `tx_hashes`; a duplicate *inside* `tx_hashes` is refused by the second insert (`TX_EXISTS`, L3) | store belt SI-3 (`tx_indices` insert, `connect.rs:529`); **no view read** for the question | **`BlockRule`** over a new `ChainView::has_transaction(&TxHash) -> bool` (the `has_key_image` shape, K1; one body with the store's read); refuses at the listing's `Locus`. Q3 asks whether the Rust rule also refuses the intra-block duplicate the C++ leaves to its belt |
| **G2** | 4 | `take_tx` from the pool, else the block supplement; a hash resolving to neither → `MISSING_TXS` outcome, not a rejection (`:5551–5588`); **body ↔ hash agreement is established by lookup under the computed hash** | **nothing binds a listed body to `tx_hashes[i]`** — E2's `ReorderedBodies` connects (§1.1) | **`FormRule`** (form stage, no view — `rules/mod.rs:156`): `transactions.len() == tx_hashes.len()` and `hash(body_i) == tx_hashes[i]` for every `i`; refuses at `Locus::Tx { slot: TxSlot::Listed(i) }` for the first mismatching index, `Locus::Block` for a length mismatch. The *resolution* half (pool/supplement) is the ingest's and E5's, not a rule; the *agreement* half is consensus and is the row (§3.1) |
| **G3** | 4 | supplement txs pass `ver_non_input_consensus` before connect (`:5440`) | `validate` runs `tx_form` on **every** listed body regardless of where the ingest got it (`validate.rs:336`); there is no pool path into `validate` | **`by_construction`** on `validate`'s slot loop; falsifier: a listed body failing an H row refuses the block (exists: the slot-loop tests) |
| **G4** | 1 | every listed tx through `check_tx_inputs` at connect (`:5636–5648`); pool-verified txs skip only the FCMP re-verify, hash-gated (M8) | `tx_against` on every slot, unconditionally (`validate.rs:340`); the crate has no admission cache and no skip | **`by_construction`** on the same loop; the M8 skip is a *cost* behaviour of the C++ (a re-verify of a proof already verified over the same bytes has the same verdict), recorded as such — **not** a divergence (§3.2). Falsifier: a listed spend failing I7 refuses the block (exists) |
| **G5** | 4 | `n_pruned > 0` → `reject_block_internal` (`:5659–5663`): a pruned block has no weight source | `tx_form` refuses the storage-pruned form before this stage (H-rows; the wire's `into_full` is the only door, `transaction.rs:2089`) | **`by_construction`** on the wire's full-transaction type; falsifier: the H fixture that refuses the pruned form. Confirm at commit 2 that such a fixture exists at both sites; if not, it is this slice's to add (§3.3) |
| **G6** | 2 | window 100 000 (`cryptonote_config.h:61`), short-term window 100 (`:53`), `S` **50 in the shipped C++** vs **4 ratified** (`consensus_constants.json:16`); LTEM = `max(zone, median(long_term_weight over last min(100 000, h)))` (`:6077–6082`) | `shekyl_economics::block_weight::{effective_median, long_term_weight, BLOCK_WEIGHT_SURGE_FACTOR}` — the clamps, over a median **no Rust path builds**; the two windows exist **only** as C++ defines (§3.4) | **definition row** `effective_median_at(view, connecting)` in `rules/block_weight.rs`, over a bulk weights read (Q2); the two windows become `const`s generated from `consensus_constants.json` (slice 6 Q5's shape; **the JSON gains two keys**, Q6) |
| **G6b** | 2 | `effective = clamp(short_median, LTEM, S·LTEM)`, floored at the zone (`:6084–6097`); `limit = 2·median` (`:6099`); `long_term_weight = clamp(weight, LTEM/1.7, LTEM·1.7)` via `shekyl_long_term_block_weight` (`:6062`) | the same two clamps, landed and tested | **definition row** beside G6: the clamp applied, `long_term_weight` of the candidate derived; **both values carried on the verdict** (Q5) so `facts.rs`'s pass-through deletes |
| **G7** | 1 | cross-tx `(P, shard, E)` set; duplicate → `reject_block_form` (`:5686–5712`); unparseable vin rejects | `serve_credit_block_unique(&[(P, shard, E)])` | **`BlockRule`** adopting the body; the triple read off the wire's serve-credit input; refuses at the second occurrence's `Locus::Input` |
| **G9** | 1 | `(P ‖ E)` pairs across txs; `shekyl_emission_block_claims_unique != 1` → reject (`:5788–5795`); serve-credit + Release same-P same-block deliberately admitted | `emission_block_claims_unique(&[(P, E)])` | **`BlockRule`** adopting the body; the *not-rejected* pair is a positive fixture, not an omission |
| **G10** | 1 | `shekyl_archival_bond_post_block_unique != 1` → reject (`:5797–5804`) | `bond_post_block_unique(&[P])` | **`BlockRule`** adopting the body |
| **G11** | 1 | accrual = `staker_emission + staker_pool_amount`; burn = `actually_destroyed`; operands **verify's exact** `base_reward`, `fee_summary`, volume window, supply, `frozen_segment_count` (`:5890–5904`); a state write, not a check | `compute_emission_split`, `compute_fee_burn` landed; the ingest's `burned` is the *producer's* priced figure (`facts.rs:55`) | **definition row** — but `frozen_segment_count` is E3's (§1.2). **Successor wave** with F17/F18; the shape is written now, the commit waits on `leaf_count` |
| **G12** | 1 | `already_generated_coins = shekyl_advance_already_generated(prev, base_reward)` (`:5930`) — `base_reward` is the **paid, penalised** reward (`:5860–5868`) | `advance_already_generated` landed; the ingest advances by the **producer's** priced reward (`facts.rs:213–223`) | **definition row** landing with F14b (the paid reward is F14b's output); verdict carries `coins_generated`; the ingest's composed line deletes |
| **G13** | 1 | height 0: no staker leg, coinbase pays the configured blob whole (`:5886–5892`) | F11 (genesis arm) landed | the **height-0 arm of G11's definition**, with its own fixture; lands with G11 |
| **F14** | 1 | `weight > 2·median` rejects; `== 2·median` passes at zero subsidy (recorded divergence, slice 4 table 3) (`:1525`, `get_block_reward`) | `emission::block_weight_limit`, `paid_block_reward` | **lands** — the median is G6's; refuses at `Locus::Block` |
| **F14b** | 2 | the penalty curve | `apply_weight_penalty` inside `paid_block_reward` | **lands** — a definition (the paid reward), consumed by G12 and F18 |
| **F16** | 1 | emission split into miner / staker legs | `compute_emission_split` + the shim's `block_emission == 0` short-circuit moved into Rust (slice 4 F5) | **lands** — operand is F14b's paid reward |
| **F18** | 1 | coinbase pays **exactly** `miner_emission + miner_fee_income` | — | **successor wave** (needs F17's `miner_fee_income`); E2's `WrongReward` flips then |

Count: **14 rows land in wave A** (G1, G2, G3, G4, G5, G6, G6b, G7, G9, G10,
G12, F14, F14b, F16 — of which G3/G4/G5 are by construction, so **11
implemented + 3 by-construction**), **4 in wave B** (G11, G13, F18, and F17
from slice 4's residue). Registry `implemented 75 → 86` after A, `→ 90`
after B; `by-construction 11 → 14`.

## 3. Findings from the code sweep

### 3.1 G2 is the row E2 has been waiting for, and it is a gap today — read at the line on review (2026-09-26)

**Where the merkle's leaves come from decides the grading, and they come
from the declared list.** `shekyl_wire::Block::pow_blob` (`shekyl-wire/src/block.rs:233–235`)
builds the tree over `[miner_transaction.hash(), transaction_hashes…]` —
the header's *declared* hashes, never the bodies — so B6 (identity) and D2
(PoW) bind the declared list. The bodies arrive positionally in
`Candidate { block, transactions }` and `ValidatedBlock::derive`
(`shekyl-chain-rules/src/block.rs:353–356`) recomputes every identity **from the body**; nothing
compares the two. The crate says so itself: `Candidate`'s doc
(`shekyl-chain-rules/src/block.rs:81–83`) — *"nothing about it has been checked, including whether
`transactions` are the bodies `block.transaction_hashes` names; that is a
4.G rule and lands with its slice."* The type does not satisfy G2 — and
that sentence is what makes this a **deferral, not a gap**: someone saw the
comparison was missing, wrote down which row owns it, and it is arriving
in that row's slice. The pre-flight's first cut called it a gap; the cite
is the evidence it was scheduled.

**What a connect does with the disagreement — the divergence leads.** The
store keys each body under its computed identity (`connect.rs:403–407`), so
*wrong body under the right txid* is unreachable through this path. What
*is* reachable is worse in a different direction. `record_tx` assigns dense
tx ids and **global output ids in body order** (`connect.rs:534`,
`:596–610`) while `BLOCKS` persists the block as received, declared list
included (`:417`). So two honest nodes handed the same block with its
bodies in different orders **both connect it and disagree on every output
index in it**; E3's drain order (its pre-flight §3.3, *stated as the
invariant it is*) puts those outputs into the curve tree in that
disagreeing order; the roots diverge with no error anywhere, and B5 splits
the two nodes at the next block. That is a consensus split that no log
line reports. The *substitution* case — a valid body not in the declared
list connects, N hashes committed and N bodies recorded with one covered
by no block id — is real and comes second: it at least leaves a detectable
orphan.

**The merkle is checked by the identity, not by a rule — written down so
nobody adds the missing check.** Monero's connect compares a computed
`tree_hash` against the block; the census's G-rows were read against that
habit twice on review (Q8's "root arm", Q9's first ruling). In this design
the tree hash over the declared list is an *input to the identity*: B6
records the identity computed over it, D2 judges the PoW over it, and a
different list is a different block — there is no mismatch left for a rule
to detect, and a rule added to detect one would compare a value to itself.
The only hash-against-hash comparison 4.G owns is G2's, bodies against the
declared list, per index. Same shape as Q9: the census names a check, and
the implementation reaches the requirement by another route.

**This makes G2 a precondition for E3's correctness, not only a 4.G row.**
E3's drain order is the tree's leaf order and the leaf order is consensus;
E3's replay oracle (its commit 5) would catch the divergence, but only
after it existed. §1.2 records the dependency in that direction.

**The belt, and where it sits.** The C++'s lookup-under-hash has a Rust
twin in the **corpus loader**: `verified_tx(height, index, want, blob)`
(`corpus.rs:325–340`, `:362`) refuses a body whose hash is not the declared
hash at that index. Every captured replay is safe because of it.
`Candidate::new` has four producers (corpus, scenario driver, two fixture
files) and no live peer path yet — **not peer-reachable today**, reachable
the day E5/p2p ingest builds a `Candidate` from network bodies, a path that
inherits no belt because the belt is the corpus's. That is **CEN-L1's
class — not L1's severity.** L1 was reachable by any peer holding two valid
spends the day it was found; G2 is reachable by no peer today and will be
by every peer the day the ingest path exists. Same shape (a consumer-side
belt standing where the census placed a validator rule), reached *before*
its peer path rather than after — which is the difference between a
finding and an incident, and is why the row is disclosed and not escalated.

**Commit 2 (a), measured 2026-09-26 — through the driver, as ruled.**
`shekyl-chain-ingest/src/body_pairing_tests.rs`. The driver's first
two-body block (`mine_listing(vec![a, b])`, two anchored harness spends at
`FIRST_SPEND_HEIGHT`) **connects**; the template declares `[a, b]`. Replayed
through the production pipeline against three fresh stores with the
driver's own facts (the harness's `trace_of` refuses at height 1 on B5 — its
synthetic roots are not the driver's placeholders — so the replay trace is
built from what the driver priced): **as listed, connects; bodies swapped,
connects, same block identities; `b` substituted by an unlisted `c`,
connects.** The store's output order followed the bodies in every case —
under `[a, b]` `a`'s outputs take the lower global indices, under `[b, a]`
`b`'s do (`output_origin` over the whole table, the two vectors unequal) —
and in the substitution `c`'s outputs are recorded while `b`, the hash the
header committed to, has no body behind it. That is the divergence §3.1
predicted, observed on two stores rather than argued: two honest nodes with
the same block in different body orders hold different output tables, and
`GlobalOutputIndex`'s own doc says leaves enter the tree in `(maturity,
gindex)` order. The tests pin today's connects and flip when commit 6 lands
G2 — a refusal before then means the row landed early, and the census
flips, not the file.

**Updated 2026-09-27 (#884).** The parenthetical above is the pre-E3 wall,
and it is not the structure. `placeholder_root_after` is gone, and B5
reads the header against the store, not against the trace. The replay
trace is `trace_with` over the chain being replayed: the economics are
what the driver priced, and `root_after` is that chain's `GrownTree`
(the same constructor `trace_of` uses, so the root is the chain's).
Each run holds CTW-5 — `roots.compared()` over every height,
`diverged()` empty — on the chain it connected, swap and substitution
included.

**Where the pin has been witnessed, corrected.** The read's first
statement — *the pin was never witnessed* — was wrong and is withdrawn.
E2's family runs every mutation through the production pipeline against a
real store over a **constructed** harness chain (`test_support::chain(n)`,
`mutation_tests.rs:401`); for `ReorderedBodies` that chain's block `AT`
lists two harness spends so there is something to swap (`:361–375`), and
the pinned-connects assertion runs there (`:261–275`). So *connects* is
what a run showed. What is true is narrower: on the **captured** chains the
mutation is `Unmutable::TooFewBodies { listed: 1 }` (`:549`) because every
captured block lists at most one body — and the family does not run on the
captured chains at all (§3.7). Commit 2 therefore builds the two-body block
**through the driver** (`mine_listing(listed: Vec<Transaction>)` takes a
vector; the bodies need not be spends, so I15's tree is not a prerequisite)
and replays the reorder and a substitution through production paths, so
the row's own witness is the driver's, per `50-testing.mdc`.

**Q7 — RULED 2026-09-26, the proposed grading taken:** the *set* is bound
by the merkle, the *pairing* is not; G2 lands as a `FormRule` —
`transactions.len() == transaction_hashes.len()` at `Locus::Block`,
`hash(body_i) == transaction_hashes[i]` at `Locus::Tx { slot:
TxSlot::Listed(i) }` for the first mismatching index — consensus-relevant, one CHANGELOG line, disclosed as L1's
class reached before its peer path existed, not as an incident. The corpus
loader's check stays, tested as a belt (slice 6 re-pointed the SI-1 tests
the same way).

### 3.2 G4's "skip" is a cost, not a rule

The census cell reads *"FCMP++ txs that verified at pool admission skip
only the FCMP proof re-verify"*. Read at `:5636–5648` and the M8 note above
it: the skip is hash-gated on the pool's verification cache, and *"when the
skip holds, all structural checks still run."* A verifier that re-verifies
a proof it already verified over identical bytes reaches the same verdict;
the skip changes what a connect *costs*, not what it *accepts*. Rust has no
pool at connect and re-verifies everything (I15, when it lands). Recorded
as by-construction with that sentence at the registry entry, so the next
reader does not build a cache to "match".

### 3.3 G5 depends on a refusal this crate inherits from the wire

The pruned form has no weight; the C++ refuses the block. In Rust the
pruned body cannot reach `validate`: `Transaction` is the full form and the
wire's pruned type converts through `into_full` (`transaction.rs:2089`) or
not at all. That makes G5 by construction on a type — the F2/F8 shape —
**provided** a fixture holds it. Slice 6's I18 doc asserts *"the
storage-pruned form, which `tx_form` refuses before this stage"*; the
fixture that makes that sentence a test is located at commit 2, and added
if it is prose.

**Commit 2 (b), measured 2026-09-26: it was prose, and the guess about the
row was wrong.** The one existing pruned-form test asked I14 *alone* on the
body (`tx_inputs_tests.rs`, `i14_an_empty_proof_on_a_spend_is_refused`), with
a comment saying `tx_form` would refuse it on **H19**'s layout first. Run
through `tx_form` at both sites, the pruned spend is refused on **H18** —
the cleartext balance, because the pseudo-outs it sums live in the prunable
region and are gone with it. The fixture is now
`g5_the_storage_pruned_spend_is_refused_before_any_block_rule_sees_it`, at
both sites, naming H18; the I14 test's comment is corrected. G5's registry
entry credits this test (commit 8). A sentence about which row fires is a
claim about the implementation, and this one had been carried since slice 5
without being run.

**The correction travels (review of commit 2, 2026-09-26).** It is the
skeleton finding from the other direction: a shape's refusing row is
determined by *where its data lives*, not by what its prose says. Every
comment in the 4.F/4.H/4.I test files that names which row refuses was
swept against whether a fixture asks for that row (`rg` over `refused on
X` / `is X's refusal` / `X's refusal first`, ~30 sites). All but two are
asserted by the test beneath them. The two named a row **no fixture had
ever asked**: I14's *"H19's refusal first"* (wrong — H18) and
`h20_every_departure_from_the_serve_credit_shape_is_refused`'s *"a `Null`
CT (that one is H15's first)"*, listed among the departures since slice 5
and never constructed. Asked at both sites, that one **held**: H15 fires
before H20 sees the shape. One wrong and one right out of two is the
expected yield of unverified prose, and the population is now zero: every
row-naming comment in those files has a fixture behind it. The rule the
sweep leaves is the one slice 6's I17 KAT and this slice's G2 read both
stated — *a comment asserting which rule refuses is a claim about the
implementation, and the ones written before a fixture existed are all
unverified the same way.*

### 3.4 The two windows live only in `cryptonote_config.h`

`consensus_constants.json` carries the surge factor (`:16`, `4`) and the
zone (`:17`, `300000`) — the two values C2-R2 signed. It does **not** carry
the long-term window (`100000`, `cryptonote_config.h:61`) or the short-term
window (`100`, `:53`); those are C++ `#define`s with no Rust twin, and the
economics crate's `build.rs` generates from the JSON. Slice 6 Q5 ruled the
reference-window ages into `build.rs`-generated consts so *a production
build cannot compile a hand copy*. The same shape here means **two new JSON
keys** and — the one C++ touch this slice would make — the two defines
pointed at the generated macros, as `…FULL_REWARD_ZONE_V5` already is
(`:60`). Rule 20: a define is marshaling, not logic. **Q6.**

**The short-term window has a third reader, and it is not the weight
system's (found on review, 2026-09-27).** `CRYPTONOTE_REWARD_BLOCKS_WINDOW`
is read at three sites: the short-term median (`blockchain.cpp:6085`), the
fee estimator's own assertion (`:4321`), and the RPC fee-estimate
`grace_blocks` ceiling (`rpc_facts_ffi.cpp:165`, `:1526`
`shekyl_rpc_fee_grace_blocks_max`, consumed by `shekyl-daemon-rpc`
`methods.rs:1048`). Rule 05 asks whether that is one mechanism doing two
jobs. Read at the estimator: `grace_blocks` is how many blocks ahead a fee
estimate must still clear, and the estimate is the median over this
window — so an estimate cannot be asked to hold past the horizon the
median it is built from has already rolled out of. The ceiling is
**derived from** the window, not a second number that happens to equal
it; splitting them would mint a constant with no derivation of its own.
Disposition, into Q6: one JSON key, **three named readers**, and the RPC
ceiling's doc says it is the median's horizon by derivation — so a future
retune of the window moves the ceiling *because it should*, and the
coupling is recorded rather than hidden.

### 3.5 Two readers of one median, one of them a producer — and the parity capture

The block template is the second consumer of G6 (§1.3): the Rust producer
prices its coinbase against the median the Rust validator judges by, one
derivation (Q4). *Records-was:* this section's first cut framed the
template as where `S = 4` versus `×50` would first matter operationally;
§3.8 shows there is no ×50 to diverge from. What remains is the capture
I17's KAT made the pattern for — **a C++-built block at the C++'s weight
limit, accepted by the Rust validator on G6, taken while both
implementations exist** — the same reasoning and the same window as the
signing-preimage KAT, opposite sign: a parity pin, not a divergence pin.
None of the four captured chains approaches the bound, so the mock holds
the arithmetic at its boundaries (`S·LTEM` exactly / one over; the zone
exactly / one under; `min(window, h)` at low heights, §3.9's early-chain
arm) and the round trip is a `#[ignore]`d live-lane test against a
regtest daemon, not left to memory.

**PREMISE REFUTED at the run (2026-09-28, commit 4 (c)).** *"At the C++'s
weight limit"* assumed the C++ producer fills to the consensus bound. It
does not: `fill_block_template` admits a body past the median only when
its fee exceeds the coinbase penalty it causes (`tx_pool.cpp:2135–2146`),
so with a pool of 50 standard-fee spends the C++ built a block of
305 738 bytes — one body past the 300 000 median — and left 27 in the pool,
against a limit of 600 000. The producer's bound is **economic, at `M`**;
the validator's is **2 × M**, and no C++ producer reaches it, so a block at
the limit is a Rust-producer-built object and belongs to F14's live-lane
test (§5 row 5). The capture taken is the block the C++ *does* build, at
its fee/penalty equilibrium — a function of `M`, hence a sharper G6
witness than a block at the limit would have been, and the first captured
block on which the weight penalty is non-zero (F14b, F18). Vector
`median-full`.

### 3.6 What the cost of the median is — unmeasured, and measured before it gates

A full median over 100 000 `long_term_weight`s per connect is
`O(n log n)` on `u64`s — ~1.7 M comparisons — plus **the read**: 100 000
`block_info` rows out of redb per block, or a dense projection of the one
column. The C++ keeps a rolling-median cache (`:216`,
`m_long_term_block_weights_cache_rolling_median`) precisely to avoid this.
Rule 76: the number that matters is the Pi 4 floor's, not this machine's.
**B9 applies:** the read shape (Q2) is chosen *after* a bench of both
candidate reads over a 100 000-block synthetic store on the floor, and the
figure lands in this file's §5.1 before commit 4 begins. If the full
recompute is under the connect budget on the floor, the rolling cache is
not built — an index that exists to make a consensus computation fast is
store-side plumbing, but it is also a second place the answer lives.

### 3.7 The corpus has one shape, and six subjects are outside it

Every captured block lists **at most one** non-coinbase body (slice 6
measured it over `corpus.e2`; §3.1 met it again as `TooFewBodies`). That
is one shape hole with several consequences, and it is worth stating as a
class rather than re-finding it a row at a time:

- **The mutation family's witness is the harness chain, twelve of twelve.**
  Every mutation in `Mutation::ALL` is judged over `test_support::chain(n)`
  through the production pipeline and a real store — legitimate under
  `50-testing.mdc` (production paths, constructed subject whose rule is
  the mutation's) — and **none runs over the captured chains**
  (`mutation_tests.rs`; `vectors_tests.rs` replays the corpus and asserts
  admission only). A reader of §3.10's table sees twelve graded mutations
  and may read that as captured-chain coverage; it is coverage of the
  harness chain. The `Unmutable` arm reports the corpus's shape correctly
  when asked — which is the arm doing its job — but a family that *could*
  run on the corpus and is `Unmutable` for a mutation on every chain in it
  should say so louder than a status, because it reads as coverage in the
  table and is coverage of nothing there.
- **Every cross-transaction row has no captured-chain witness.** L1 (two
  spends, one image), G2 (two bodies, reordered), G7/G9/G10 (two archival
  forms, one key), and H19-verify's fold (two BP+ proofs, one batch — slice
  6 Q9's measured condition) all need ≥ 2 listed bodies in one block. Six
  subjects, one hole.
- **`mine_listing(Vec<Transaction>)` is the tool that closes it for all
  six at once.** The driver can list two admissible bodies today; only the
  proof-bearing subjects (H19-verify, and I15's) wait on E3's tree.

**Commit 2's check, in the answerable form:** for each mutation in
`Mutation::ALL`, on each of the four captured chains, does it apply or
report `Unmutable` — and with which cause? If `ReorderedBodies` is the only
all-four `Unmutable`, the corpus is adequate and this was one gap; if
others are, the corpus has the shape hole above and the driver's two-body
block is the fix for the set. Either answer goes into §5.1 as a number.

**Answered 2026-09-26** (`vectors_tests::the_family_over_the_corpus_names_what_it_cannot_reach`,
which holds the answer as a test — a change in it is a change in the corpus's
shape or the family's, and this section moves with it). Twelve mutations ×
four chains: **two are unreachable on all four**, and the census says which
is whose. `PowUnderWrongSeed` is the *environment's* (`NoPowEnvironment`: the
census supplies no PoW leg). **`ReorderedBodies` is the corpus's** —
`TooFewBodies { listed: 0 }` and `{ listed: 1 }` on every block of every
chain — **and it is the only one.** So the corpus is adequate for eleven of
twelve and this was one gap, closed by commit 2 (a)'s driver block. One
more shape fact fell out, not asked for: **`DoubleSpend` is unreachable on
the two chains named for spends** (`spend-1in-2out`, `spend-depth3` —
`NothingSpentBefore`: each carries exactly **one** spend, at 81 and 761)
and reachable on the two archival chains (`bond-post`, `emission-claim`,
which carry two, at 71 and 98). The spend chains are the thinner spend
witnesses; the family's `DoubleSpend` arm runs on the harness chain and is
unaffected, but a captured-chain witness for I7/L1 would come from the
archival captures, not the spend ones. The rows that fire everywhere fire
from the heights one would expect: the header rows at 0, the timestamp
rows at 1, the spend rows at each chain's first spend.

**Why the `DoubleSpend` fact is the sharper half (review of commit 2).**
It is not a gap the census flags — the mutation *applies*, on two chains —
and it passes. It is a **subject distribution nobody chose**: the family's
most important case is exercised only where two spends happen to co-occur,
and the two chains *named* for spends carry one each, so the rule everyone
cares about is witnessed on the chains nobody thinks of as its subject.
Not urgent; legible is the fix. The driver can now list bodies (commit 2
(a)), so a driver-built chain with **two spends in two blocks** — a spend
chain that is also `DoubleSpend`'s subject — is the same kind of work as
the two-body block and rides with the mutation rows in **§5 row 7**, where
`DoubleSpend` gains a witness whose name says what it is.

**UPDATE 2026-09-28 (commit 4 (c)) — the shape hole closes on the corpus.**
The `median-full` capture (§3.5) is a C++-built chain whose block 211 lists
**23 bodies** and whose blocks 212–213 carry the other 27 spends. The census
re-run over five chains (`the_family_over_the_corpus_names_what_it_cannot_reach`,
its assertion moved with it): **`ReorderedBodies` applies on a captured
chain, first at 211**; `PowUnderWrongSeed` is the only all-chains
`Unmutable`, and it is the environment's. `DoubleSpend` applies at 212 on a
chain whose fifty spends are its subject — the distribution this section
called unchosen now has a chain named for its content. Every
cross-transaction row (L1, G2, G7/G9/G10, H19-verify's fold) has a
captured-chain witness with ≥ 2 listed bodies in one block. §5 row 7's
driver-built two-spend chain is still owed for the *mutation* rows' own
fixtures; what it is no longer owed for is a corpus witness.

### 3.8 The ×50 is gone from the C++; the census and the register did not notice (read 2026-09-26)

The census G6 and G6b cells (`CONSENSUS_RULE_CENSUS.md:410–411`) say *"the
shipped C++ constant is the refuted ×50, a known divergence until the store
port implements the signed value"*; the register grades both **DIVERGENT**
for that one cause (`CONSENSUS_STORE_RECONCILIATION.md:920–921`, reviewed
at `eb1b60198`, 2026-09-11). At `ad557ac5a` the C++ has no ×50:
`update_next_cumulative_weight_limit` calls
`shekyl_effective_block_weight_median` (`blockchain.cpp:6090`), which is
`shekyl_economics::effective_median` over `BLOCK_WEIGHT_SURGE_FACTOR`
(`economics/build.rs:56`, generated from `consensus_constants.json:16` = 4);
the long-term clamp is `shekyl_long_term_block_weight` (`:6062`); no
`SURGE` literal survives in `blockchain.cpp` or `cryptonote_config.h`; the
FFI pins `shekyl_effective_block_weight_median(zone, zone × 100) == 4 × zone`
(`shekyl-ffi/src/legacy_tests.rs:1108–1111`); and the template reads the
median that clamp set (`:1905`). The commit is `1c8594049` *consensus: own
the surge clamp in Rust; both C++ sites consume it* — **2026-09-12, one day
after the register's review**. Both rows were true at their pin and have
been false as status for two weeks; nothing re-graded them because the fix
landed in a lane that did not own the register.

Three consequences. **(i)** G6 lands at parity: one derivation, one key,
both languages. **(ii)** Q9's `RuleSet`-knob refusal strengthens — there is
no C++ value to be compatible *with*, so an entry carrying `50` would
encode a number that exists nowhere and give it institutional standing.
**(iii)** Commit 10 re-reviews CEN-G6/G6b in the register at the landing
tree; if both go CHECKED-CONFORMANT the gate's tally moves **125 / 3 / 5 →
127 / 1 / 5** and CEN-I4 (`:600`) is the register's only recorded
divergence — derived from `check_conformance_coverage.py` at that tree, not
from this arithmetic, and said plainly in the CHANGELOG if it holds.

**The mechanism, named because it recurs:** the reviewer read Q9's text and
the census cells it cites, and ruled — without reading `blockchain.cpp`. A
census cell describing implementation state is a claim about code, not the
code (rule 16's corollary); the elaborate producer-side exposure the first
ruling constructed was internally consistent and about a system that
stopped existing on 2026-09-12. Reading the question is not reading the
subject.

### 3.9 C2-R2 Q1 had three legs and one falsifier, on the wrong leg

The 300 000-byte zone **was** arbitrated — `CONSENSUS_C2_R2_WEIGHT_FEES.md`
§Q1 (`:223–284`, SIGNED 2026-09-06): a tx-capacity leg, a throughput-floor
leg, and the GAP-7 verification-cost leg, discharged on the Pi 4 floor.
Read leg 1 at `:233–244`: *"a typical 2-output spend runs ≈ 4–8 kB (**an
estimate** — prefix + extra + BP+ + FCMP proof; **not a measured corpus**),
putting the zone at roughly **35–75** typical transactions per free
block."* The estimate counted the per-output PQC extra (≈ 1.1 KB) and did
not count the per-**input** hybrid auth. Slice 6's I4 round then measured
real spends through the production builder (`CHAIN_RULES_SLICE_6.md:
903–917`, floor run `:1003–1018`): **13 584 bytes** for one input and two
outputs, **58 720** at eight, **6.4 KB per input** of which 5.4 KB is the
hybrid auth. So the zone holds **≈ 22** typical transactions penalty-free,
**≈ 5** at eight inputs — a third of the ruling's premise. Q1's only stated
falsifier (`:277–280`) is on leg 3; nothing was armed to fire when a corpus
replaced the estimate, so the measurement landed in slice 6, sat beside a
ruling it refutes, and no mechanism connected them.

**Disposition (rule 15 — a design round, not this slice's):** reopen **Q1
leg 1 only**, with the corpus as input — state the objective (how many
transactions a block carries without penalty, and why), run the leg on the
I4 table, derive or confirm; legs 2 and 3 and the signature stand. A
FOLLOWUPS row carries it, owner the census (which owns §10 R2). The value's
home gains the comment it lacks (`_comment_block_weight_zone`, citing Q1
and its condition — rule 91's constant-doc class). Slice 7 consumes the
zone by name and is unaffected by the outcome; `TX_WEIGHT_LIMIT = zone/2 −
600` (`transaction.rs:158`) moves with it and is FL-R16c's to re-read.
Before genesis: the window in which this is free closes at exactly one
point.

**The lesson beyond the row, proposed for `22-no-lazy-deferral.mdc`'s
falsifier section:** *a multi-leg ruling needs a falsifier per leg.* One
falsifier on a three-leg ruling retires the whole ruling's reopening
criterion to whichever leg someone happened to pick; the ruling then reads
as equally settled across all three when one is a measurement and two are
estimates. A leg that says "an estimate" in its own text is a leg that has
named its falsifier and not armed it.

### 3.10 The weight formula: bytes track inputs; the clawback's dimension is unmeasured

`Transaction::weight = size + bp_plus_weight_clawback` (`shekyl-wire/src/
transaction.rs:226`) is Monero's formula, and C2-R2 does not examine it
(no mention of the clawback in the round). Half the "why is this here?" is
answered by the I4 measurement already: **6.4 KB and 11.9 ms per input,
linear within 5 % on both machines** (`CHAIN_RULES_SLICE_6.md:911–917`,
`:1011–1018`) — bytes track verification cost proportionally in the input
dimension, which is the load-bearing one, so the formula's byte basis is
defensible there and that sentence is recorded as the answer.

**What the measurement does not cover, stated precisely (corrected on
review, 2026-09-27).** The I4 sweep varied inputs 1→8 **at two outputs
throughout**, and found BP+ constant (2.7 ms i9, 34.9 ms Pi). But the
clawback is a function of the **padded output count** and is zero at two
or fewer (`bp_plus_weight_clawback`, `transaction.rs:226`) — so every
transaction the sweep timed had a clawback of zero, and what it shows is
that BP+ is input-independent, **not** that the proof's cost is fixed in
the dimension the clawback prices. The first cut of this section framed the
clawback as "a size adjustment on a fixed-cost proof"; that framing ran
ahead of the evidence. The honest open question is one measurement wide:
**time BP+ verification across padded output counts (2, 4, 8, 16) and set
it against the clawback's curve** — if the cost is flat there too, the
clawback prices nothing Shekyl pays and the question is why it is carried;
if it scales, Monero's adjustment may be pricing the right thing and the
question is whether the curve fits. A FOLLOWUPS row, owner the census.

Same family, smaller: `DYNAMIC_FEE_PER_KB_BASE_FEE_V5`
(`cryptonote_config.h:70`) has **no reader** outside its own header — a
dead define; the fee floor was derived in the FL rounds and does not
inherit the zone through it. It goes with Q6's two-define edit (the same
file, left in good shape; disclosed, not "while we're here").

## 4. Stage placement — proposed, shaped by §8

| stage | rows | why |
| --- | --- | --- |
| form (`FormRule`, no view) | G2 | body ↔ hash is a property of the candidate's bytes alone |
| `validate`, **before** the slot loop (`BlockRule`, view) | **G1** | the C++'s order (`tx_exists` `:5516` before `check_tx_inputs` `:5639`), the cheap check first — and the only order under which G1 has a witness on spends: after the loop, I7 refuses a re-listed spend at its input and L1 refuses a doubled one, and G1 never fires (Q8). Pinned by a test that fails if the order flips |
| `validate`, after the slot loop (`BlockRule`, view) | G7, G9, G10 | span the slots; read only the block; beside L1 |
| `validate`, definition rows (before the coinbase's 4.F consumers) | G6, G6b, then F14 → F14b → F16 → G12 (→ F17 → F18 → G11/G13 in wave B) | the D4 arrangement: the median yields, the penalty consumes, the paid reward advances the supply |
| by construction | G3, G4, G5 | the slot loop and the wire's full type |

The definition chain is one sequence, `judge_emission`, in the shape of
`judge_reference`: G6 yields the median, G6b the long-term weight, F14
refuses or F14b yields the paid reward, F16 splits it, G12 advances the
supply — each recorded where it yields, the successors recorded vacuous
when an operand is absent. Wave B extends the sequence in place.

## 5. Commit plan — Round 0 (proposed)

| # | commit | gate |
| --- | --- | --- |
| 1 | **This file amended on review; the index row; the §5.1 expectation table** — written before commit 2, so the overrun signal has a subject | — |
| 2 | **LANDED 2026-09-26 (cost 1 — the estimate said 2; the driver listed two bodies at the first attempt, and the one wall was a fixture's: `trace_of`'s roots are not the driver's, §3.1). 2026-09-27: that wall was the pre-E3 placeholder; §3.1's update is the structure.** Measurements, no rules: (a) the two-body block through `mine_listing`, the reorder and a substitution replayed through it — all three connect; output order follows the bodies; the unlisted body is recorded (`body_pairing_tests.rs`, pins that flip at commit 6); (b) the pruned-form fixture at both sites — it was prose, and the row is **H18**, not H19 (§3.3); (c) the weights-read bench, `#[ignore]`d in `shekyl-chain-store` (`weights_read_bench_tests.rs`), run at N = 100 000 on the desktop and, cross-compiled, on the Pi 4 floor — (b) 36.6 ms against (a) 598 ms there, 0.5 % of the zone-point verify; **Q2 RULED (b)** (§5.1, the budget cell filled by that run); (d) the `Unmutable` census over the corpus — `ReorderedBodies` the only corpus-shape gap, `DoubleSpend` unreachable on the two spend-named chains (§3.7) | — |
| 3 | **LANDED 2026-09-27 (cost 1).** `ChainView::weights_window(end, at_most) -> AtHeight<Vec<RecordedWeights>>` — the up-to-`at_most` recorded blocks strictly below `end`, `AboveTip` past `tip + 1`, a hole inside the window SI-7 and never a shorter vector — and `ChainView::has_transaction(&TxHash) -> bool`; **no default bodies** (a default that answered "no weights" or "no such transaction" would make G6 and G1 silently vacuous on a mock, the opposite of E3's derived `depth_at`), so all nine implementors carry both. The store's body is one range cursor over `block_info` (`chain_reads::weights_below`, the shape the floor chose) and `tx_indices` membership (`tx_reads::has_transaction`), each shared by `BatchView` and `ReadSnapshot` so the validator and the pool/template read one answer. `MockChain` records weights per pushed block — `push` names the zone for both, `push_weighing` names them — and a transaction set (`with_transaction`); **no existing fixture moved** (§5.1's tally: still 0). The store's conformance test holds both reads to the store's over every `end` × `at_most` shape, the hole test holds the SI-7 arm the mock cannot reach, and `RecordedWeights` is a named projection, not a tuple, so the two columns cannot be swapped by position. Built on `dev` after #884 repaired E3's two breaks of commit 2 (§1.2) | commit 2 (c) |
| 4 | **LANDED 2026-09-28 (cost 3 against 2 — over; the falsifier fires, and the reason is the third part).** Three commits. **(a) Q6:** `block_weight_long_term_window_blocks` / `block_weight_short_term_window_blocks` into `consensus_constants.json` under both membership tests; `shekyl_economics::params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, BLOCK_WEIGHT_SHORT_TERM_WINDOW}` generated; the two C++ `#define`s expand to the generated macros; `DYNAMIC_FEE_PER_KB_BASE_FEE_V5` deleted; `blocks_to_surge_saturation`'s local `100` reads the window; the rpc-types digest re-pinned. **(b) G6 / G6b** in `rules/block_weight.rs`: `Medians::derive` before the slot loop (one `weights_window` read over `W_long`, the short window its suffix), `Weights::derive` after it (the block's weight and its long-term clamp); values on `ValidatedBlock::weights` (Q5); `effective_median_at` public and read by the ingest's `ChainFacts` for the producer (Q4) — the scenario driver prices against it, not the zone constant. **The median's even-count arm is the C++'s** (`get_mid`: floor of the two middles' mean), pinned against a sorted reference over both parities — a lower-middle median would agree on every odd window and disagree on every even one, and the short window is 100. The clamps at their boundaries; the short window's suffix at exactly `W_short` by a mean neither half carries; **the early-chain arm pinned deliberately** — block 0's weight moves a seven-block median (nothing aged out), and a young, light chain reads the zone on both medians, which is the arm every `chain_of(n)` fixture exercises. **Parity over the corpus:** the replay compares the verdict's `weight`, `long_term_weight` and `long_term_effective_median` against the trace's at every connected height (`RunReport::weights`, E3's oracle shape, rewind-retracting) — **2 194 / 2 194 heights match** across the five captured chains (1 979 on the four that existed before (c), 215 on `median-full`, its over-median block included); a negative control plants a wrong median at one height and the report names it. The synthetic harness's `TraceEconomics` can no longer name the three values: `GrownTree` derives them as it grows (the `trace_with` move, one row over). **(c) The parity capture (§3.5, Q9 (iii)) — and its premise refuted at the run.** `e2e_cxx_template_fills_to_its_median` overfills a regtest pool with 50 daemon-accepted spends (13 235 bytes each, I4's shape at one input) and mines one block. The premise was *a C++-built block at the C++'s limit*; **the C++ producer does not build one** — `fill_block_template` admits a body past the median only if its fee outweighs the coinbase penalty it causes (`tx_pool.cpp:2135–2146`, *"would decrease coinbase"*), so at standard fees it stopped one body past the **median**: 305 738 bytes, 23 spends, 27 left in the pool, against a limit of 600 000. The 2 × M bound is the validator's refusal (F14) that no C++ producer reaches; a block at it is a Rust-producer-built object and is F14's live-lane test (row 5), not this capture's. What the C++ does build is the sharper G6 witness: its weight sits at the C++'s fee/penalty equilibrium, a function of `M`, so a Rust median that differed prices a different penalty on this block (F14b, F18 — the first captured block *over* the median, where the penalty is live). Captured as the fifth vector, `median-full` (also the first captured chain with more than one listed body per block — §3.7's shape hole closes on the corpus, and `ReorderedBodies` gains a corpus witness). The third commit is the overrun: a live-lane capture is a build of the daemon and both E2 tools before the first spend, and the estimate priced the definitions, not the capture | commit 3 |
| 5 | **F14, F14b, F16, G12** — the sequence completed through the paid reward; `ConnectFacts.{weight, long_term_weight, long_term_effective_median, coins_generated}` read off the verdict, the ingest's four composed lines deleted (`Provenance::passed_through` re-counted with E3's) | commit 4 |
| 6 | **G2** as a `FormRule` in `form`; E2's `ReorderedBodies` flips from pinned-connects to refusing at `Locus::Tx { slot: Listed(0) }`; `MissingBody` (→ `Locus::Block`) and `SubstitutedBody` (→ `Listed(i)`) join it | commit 2 (a) |
| 7 | **G1** as a `BlockRule` **before** the slot loop, **G7, G9, G10** after it beside L1 (§4); the order pinned by a test in which a re-listed spend is refused on G1, not I7; G9's admitted pair as a positive fixture; the driver gains `RelistedTransaction` and `DoubledListing` (→ G1, `Locus::Tx { slot: Listed(second) }`), `DuplicateServeCredit`, `DuplicateClaim`, `DuplicateBondPost` (→ `Locus::Input` at the second occurrence), `OverweightBlock` (→ F14, `Locus::Block`) — **written spec-first in `DRS_E2_REPLAY_DRIVER.md` §3.10 at commit 2**, each row's locus derived from the refusal's own evidence (Q8), so the rows carry the distinguishing work before there is code to check them against; **and a driver-built spend chain with two spends in two blocks, so `DoubleSpend` has a witness on a chain named for spends** (§3.7) | commit 3 |
| 8 | **G3, G4, G5** registry entries, `by_construction` with their falsifiers named; conformance re-check (the register's G rows, `:640–646`, re-read against the crate) | commit 7 |
| 9 | **Wave B — F17, F18, G11, G13 — ABSORBED (2026-09-27): E3 landed `leaf_count_at` with `BatchView`'s impl (#878), the condition this row named, so the deferral is not taken.** Lands after row 5 as one commit extending `judge_emission` — F17's `frozen_segment_count` from the leaf count at the parent state (F19's single-read discipline), F18's exact-pay over F16's and F17's legs, G11's accrual and burn as definitions, G13 as G11's height-0 arm — and `WrongReward` flips from pinned to refusing at `Locus::Tx { slot: Miner }`. *Records-was:* the row as written — wave B a named successor, falsifier `rg 'fn leaf_count_at\|fn depth_at' rust/shekyl-chain-rules/src/view.rs` → present with `BatchView`'s impl; the falsifier fired the day after it was written | commit 5 |
| 10 | **Docs:** census 4.G re-pinned at the landing tree, **G6/G6b's *"shipped ×50 … until the port"* clauses corrected** (§3.8); the register's CEN-G6/G6b rows **re-reviewed at the landing tree** (DIVERGENT → CHECKED-CONFORMANT if the read holds; tally derived from `check_conformance_coverage.py`, not by hand); `CHAIN_RULES_CRATE.md` §4.3 (the two reads), §4.6 (`judge_emission`, the verdict's seven values and Q5's test); `DAEMON_REDB_STORE.md` §7.5; index; FOLLOWUPS (the F14-family residue closed; the wave-B row if deferred; the two rows §3.9/§3.10 opened); CHANGELOG — G2 (Q7, one line), and if the tally is 127 / 1 / 5, that CEN-I4 is the register's only recorded divergence | — |

Ten commits is the rule-06 ceiling; commit 9 is the one that may leave.

### 5.1 The expectation, written at commit 1 (2026-09-26, before commit 2)

Two kinds of number, split on purpose. **Commit counts and coverage** are
written now, before any measurement, so the overrun signal has a subject
(slice 6 §5.1's rule). **The one budget** — what a connect may spend
reading the weights window on the Pi 4 floor — is written by commit 2's
bench, not before it (B9: a budget set from intuition is the failure the
bench exists to catch). Its cell below says so.

| commit | lands | cost | falsifier applies |
| --- | --- | --- | --- |
| 1 | this file on review; index; this table | 1 (on #877) | — |
| 2 | four measurements, no rules (§5 row 2): the two-body driver block with the reorder and a substitution replayed; the pruned-form fixture located or added; the weights-read bench on the floor; the `Unmutable` census over the corpus | 2 — the driver has never listed two bodies, and the first attempt at anything the driver has never done has cost a commit each time (slice 6 §5.3.3) | yes |
| 3 | `ChainView::{weights_window, has_transaction}` — trait, `BatchView`, `MockChain`, the store's conformance test, one commit both sides. **Landed at 1 (2026-09-27)**, carrying two repairs E3's landing owed #880's tests (§1.2) | 1 | yes |
| 4 | G6 / G6b in `judge_emission`; the two windows generated; boundary and low-height fixtures. **Landed at 3 (2026-09-28)** — the third is the parity capture (§5 row 4 (c)), which the estimate did not price | 2 | yes |
| 5 | F14, F14b, F16, G12 through the paid reward; four `ConnectFacts` fields read off the verdict; four composed lines deleted | 2 | yes |
| 6 | G2 as a `FormRule`; `ReorderedBodies` flips; `MissingBody`, `SubstitutedBody` | 1 | yes |
| 7 | G1 before the loop, G7/G9/G10 after; the order pinned; seven mutations | 2 | yes |
| 8 | G3/G4/G5 by construction; conformance re-check | 1 | yes |
| 9 | wave B — **absorbed**, E3 landed (`leaf_count_at`) on 2026-09-27; F17, F18, G11, G13 as one commit after row 5 | 2 | yes |
| 10 | docs: census 4.G re-pin and the G6/G6b correction; the register's two rows re-reviewed; crate contract; index; FOLLOWUPS; CHANGELOG | 1 | yes |

**Expectation: fifteen commits, fourteen if wave B defers.** Registry
`implemented 75 → 86` after wave A (`→ 90` with B), `by-construction 11 →
14`; E2's family `12 → 19` mutations, `WrongReward` and `ReorderedBodies`
flipped from pinned to refusing. **The signal:** more than **eighteen**
commits *excluding wave B* means the substrate was not as finished as this
table claims — the answerable form, as slice 6 wrote it.

**Slice 6's prediction, held here as the thing this slice can falsify:**
*the fixture class should be smaller* (slice 6 §5.1 — seven fixture
commits there, because the substrate had constructed state no rule asked
about). Every fixture already carries `weight` and `long_term_weight`, so
the prediction is **≤ 2 fixture commits**. The counter-evidence to watch
for is Q2 (a) — if `RecordedBlock` grows two fields, **ten** construction
sites move (`rg 'RecordedBlock \{'` at the pin: store 4, rules 6) and the
prediction fails through the read shape rather than through the rules,
which would be a different lesson from slice 6's and should be recorded
as one.

**The budget cell — filled at commit 2: desktop 2026-09-26, the floor
2026-09-27.** `shekyl-chain-store`'s `weights_read_bench` (`#[ignore]`d;
`SHEKYL_WEIGHTS_BENCH_BLOCKS=100000 cargo test -p shekyl-chain-store
--release weights_read_bench -- --ignored --nocapture`) builds a
100 000-block store through the production `judge` + `connect` and times
the two Q2 shapes over one read snapshot. The floor run is the same test
binary cross-compiled for `aarch64-unknown-linux-gnu` (`cargo test
--release --no-run --target …`, `aarch64-linux-gnu-gcc` as the linker) and
run on **skl-pi — Raspberry Pi 4 Model B, Cortex-A72 ×4 (`CPU part 0xd08`),
7.8 GB, Ubuntu 26.04**, one run of N = 100 000:

| read | Pi 4 floor | desktop (i9-11950H) | floor multiplier |
| --- | ---: | ---: | ---: |
| (a) `N` point reads through `block_info`, full decode each — Q2 (a) | **598 ms** long, 0.56 ms short | 113.6 ms long, 0.11 ms short | 5.3× |
| (b) one range cursor over `block_info`, decoded once each — Q2 (b) | **36.6 ms** for both windows | 10.2 ms | 3.6× |
| the two medians (`select_nth_unstable`) | 0.93 ms | 0.15 ms | 6.2× |

Same rows read on both machines (asserted equal). The shapes separate by
**16× on the floor** (11× on the desktop — the ratio **widened**, as the
pre-statement below said the A72's caches would push a cursor-versus-
descents comparison), and the long window's point lookups are the whole
cost on either machine.

**Q2 — RULED (b) by the floor run, under the decision rule written before
it (below).** (b) costs a connect **36.6 ms** on the floor for the long
window: **0.5 %** of GAP-7's 7.23 s zone-point verify on the same board,
an order of magnitude under the 5 % line. (a) at 598 ms would have been
8.3 % and failed the same rule. So: the bulk `ChainView::weights_window`
read lands in commit 3; **no materialised column** — Q2's pre-empted
fallback is not reached for. The negative control held: (a) did not beat
(b) on either machine. The 100 000-block build itself ran at 4.2 ms a
block on the Pi (422 s) against 0.56 ms on the desktop (56 s), a 7.5×
multiplier on the connect path — recorded because it is the first floor
figure for `judge` + `connect` per block, not because commit 3 needs it.

**What the floor run can and cannot touch — stated before it runs (the I4
round's discipline; review of commit 2).** The I4 round found BP+
degrading **13×** on the A72 against **5.5×** for the per-input work: a
ratio measured on the desktop does not survive the floor just because the
structure does. The two shapes here have different memory-access profiles
— 100 000 point lookups are 100 000 B-tree descents with little locality,
one cursor is a sequential walk — and the A72's caches are far smaller, so
the 11× **could widen or narrow**; that ratio is the floor's to set. What
the floor **cannot** touch: the rows read are the same (asserted), and (a)
cannot become cheaper than (b) — a point read does everything a cursor
step does and then some. *(The first cut also claimed the medians sit
"three orders below either read on any machine"; that was wrong on the
desktop's own table — 0.15 ms is 68× below the 10.2 ms cursor and above
the 0.11 ms short point read — and a cross-machine ratio is exactly what
rule 76 says to measure, not assert. Withdrawn on review; the floor set
it at 0.93 ms, 39× below the cursor.)* So the floor decides **one thing**: whether (b)'s absolute
cost sits inside the connect budget or the materialised column is reached
for. **The decision rule, written now so the number does not write it:**
(b) stands if its floor time for the long window is **≤ 5 % of the
zone-point verify on the same board** (GAP-7: 7.23 s, so ≤ ~360 ms); above
that, (b) plus the column with its check against the source (Q2's
pre-empted fallback); (a) is not chosen at any result, and a floor run in
which (a) beats (b) is a bench defect to find before it is a finding.

The bench met three fixture walls, and DRS-E3 has since removed one of
them. **Updated 2026-09-27:** the shared `connect_fixtures` root was
`[0xc0 + h; 32]` and stopped at height 63 (slice 6 met that cap too).
That function is gone. The bench reads `batch_root_going_into` — the
in-batch `root_at`, the same read `connect_chain` and the prune builder
use — and does not carry a root of its own. What remains is the shared
`FixtureSubstrate`'s clock, fixed at 1 000 000, so a 100 000-block chain
at 120 s spacing needs its own clock, **and a fixed difficulty**: at that
spacing the live LWMA floors a small genesis difficulty to zero over
~8 000 blocks (D6 refused; measured), and 1 s spacing overflows the
cumulative sum within a second of wall time. The bench builds under
`RuleSet::fakechain(Some(7), D_MAX)`, the ingest's regtest shape. The
clock and the difficulty are the bench's walls, not the rules'. They are
the first evidence about slice 6's prediction (§5.1's fixture-commit
tally: 0 so far; the bench's chain builder is its own file, its root is
not).

## 6. What this slice does not build

- **The pool's resolution of hashes to bodies** (G2's first half,
  `MISSING_TXS`) — E5's and the ingest's; a rule judges the pairing, not
  the fetch.
- **A rolling-median cache** unless §3.6's bench says the floor needs it.
- **F17** and the leaf count — E3's, consumed here in wave B.
- **The block template's median read** — TXE-F8's edit, shaped for by Q4.
- **The census re-pin of 4.G's line numbers** — commit 10's, not §2's.
- **C++ deletions** beyond the two `#define`s (Q6) — E4's.

## 7. Round log

- **Round 0** (2026-09-26): pre-flight written at `ad557ac5a`; every G row
  and the four F rows read at the line; the E3 collision surfaces
  enumerated from #873's merged pre-flight; nine questions. Review the
  same day corrected this file's own counts — eight aggregations, wave A
  is 14 rows, `passed_through` is *6 → 1* after E3 and wave A — and G2's
  class: a `FormRule`, which is the no-view form stage
  (`rules/mod.rs:156`). A view-less `BlockRule` is not a class the crate
  has.
- **Q7 RULED 2026-09-26**, and Q8's two G2 loci with it: length mismatch at
  `Locus::Block`, first hash mismatch at `Locus::Tx { slot: Listed(i) }`. The claim that
  the `ReorderedBodies` pin was never witnessed is withdrawn in §3.1: the
  pin ran on the harness chain (`mutation_tests.rs:261`, two bodies at
  `:361`); the captured chains are `TooFewBodies` and the family does not
  run there (§3.7).

## 8. Questions for the reviewer — Round 0

- **Q1 — the two waves, and E3. RULED 2026-09-26: the default — slice 6's
  precedent applied.** Nothing in wave A depends on E3, and wave B is a
  named successor with a falsifier (§5 row 9), not a hold. F17/F18/G11/G13
  wait on E3's per-height leaf count (§1.2); this slice lands wave A and
  absorbs B if E3's commit 4 merges inside the window. The alternative —
  hold the whole slice for E3 — was refused for the reason slice 6 refused
  waiting on I13.
- **Q2 — the weights read.** G6 needs the last 100 `weight`s and the last
  min(100 000, h) `long_term_weight`s. **(a)** `RecordedBlock` gains both
  fields and the rule loops `block_at` — no new method, ten fixture sites
  move, 100 000 full-record decodes per connect; **(b)** a bulk
  `ChainView::weights_window(end, n) -> Vec<(BlockWeight, LongTermWeight)>`
  — one method, the store projects the two columns, fixtures untouched;
  **(c)** the store keeps a rolling median and the view exposes
  `long_term_median_before(h)` — rejected before asking for slice 4 Q1
  (c)'s reason: a derivation dressed as a read, and a second home for a
  consensus value. Default **(b)**, *conditional on commit 2 (c)'s bench
  on the floor*: if a 100 000-row projection read is not under budget
  there, (b) with a store-side dense column is the fallback, and (c) is
  reopened on the measured number, not on intuition. **Deferral
  CONFIRMED 2026-09-26, with the fallback pre-empted:** a store-side dense
  column is a **materialised view of data the store already holds** — the
  class E3's pre-flight met four times in two days and answered once
  (`DRS_E3_CURVE_WRITER.md` §3.7: `undo_log_floor`, `CURVE_TREE_META`, a
  per-height depth, the pending set; *"a view becomes a query; if
  performance later argues for materialising one, it materialises **with**
  a check against its source"*) — so if the bench forces it, it arrives
  with that check (an SI row: the column's entry at `h` equals
  `block_info[h]`'s, held on every connect and by the conformance test),
  never as an authority a rule reads without the source beside it. Written
  now so the bench result does not decide it under pressure. **RULED (b)
  2026-09-27 by the floor run** (§5.1's cell): on the Pi 4 the range cursor
  reads both windows in 36.6 ms — 0.5 % of the zone-point verify on the
  same board, an order of magnitude inside the 5 % rule — against 598 ms
  for the point reads; the ratio widened to 16× on the floor. The bulk
  `weights_window` read lands in commit 3 with no materialised column;
  the fallback stays pre-empted and unreached. Round 0 is closed.
- **Q3 — G1's intra-block half. RULED 2026-09-26: the default, for a
  better reason than the one given.** G1 refuses *"already on the chain
  **or earlier in this block**"*. The reason is not tidiness ("one
  predicate, one `Locus`"). The alternative — leave the intra-block case
  to L1 and G7/G9/G10 — is a **coverage claim over transaction classes**:
  every duplicate body is caught because a spend has a key image or an
  archival form has its row. True today; silently false the day a class
  arrives with neither — and the serve-credit form already demonstrates a
  class with no key image. A predicate that refuses duplication directly
  is robust to new classes; a union of class rows must be re-verified
  whenever one is added, by someone who will not know they are obliged
  to. It is also the belt-versus-rule correction again: the C++ reaches
  this only through `TX_EXISTS` on the second insert; making it a rule is
  not duplicating the belt, it is putting the refusal where the census
  says it lives. The class rows stay as the rows they are.
- **Q4 — the median's signature, for two readers.** `pub fn
  effective_median_at<V: ChainView>(view: &V, connecting: BlockHeight) ->
  Result<EffectiveMedian, ViewRead<V::Fault>>` returning both the
  effective median and the LTEM (the template needs the first, G6b the
  second). **RULED 2026-09-26: the default — I17's shape one row over.**
  One derivation, two consumers, the second reader being the template
  rather than the daemon. The precedent is named in the row because the
  alternative keeps reappearing by different doors — slice 4 Q1 (c), the
  template reading the store's recorded `long_term_effective_median(tip)`
  — and SCR-19's one-block staleness is the same objection each time.
- **Q5 — what the verdict carries.** Four values (`weight`,
  `long_term_weight`, `long_term_effective_median`, `coins_generated`) so
  `facts.rs` deletes four composed lines and `ConnectFacts` reads them
  from `ChainValid`, the D4 precedent. **RULED 2026-09-26: yes, and the
  test that keeps the verdict from becoming a fact bundle is stated:** *a
  value belongs in the verdict iff the validator must compute it to reach
  the verdict.* All four pass — `weight`, `long_term_weight` and the LTEM
  are read by the G rows, `coins_generated` by the F rows — so carrying
  them is free; the computation already happened. `burned` stays
  passed-through until F17 because the **same test gives the other
  answer** (no rule reads it yet), which is what makes it a test rather
  than a preference. `ChainValid` will carry seven values after this
  slice; the next four arrive under this sentence, or not at all. The
  alternative (keep them in `ConnectFacts` as passed-through and let the
  ingest recompute) is the two-sources class the seam exists to close.
- **Q6 — the two windows into `consensus_constants.json`.** Add
  `block_weight_short_term_window_blocks: 100` and
  `block_weight_long_term_window_blocks: 100000`; `shekyl-economics`'s
  `build.rs` generates them; the two C++ defines point at the generated
  macros. **RULED 2026-09-26: yes — mechanical under the JSON's membership
  rule.** `consensus_constants.json`'s `_comment` names two tests, both
  required: (1) a different value makes a different chain — both windows
  pass (a different window is a different median, a different limit, a
  different set of valid blocks); (2) a schedule, network or operator
  could legitimately name it differently — both pass (a network with
  another block time would). Both tests, both keys; a lookup, not a
  judgement, which is what the pair was for. The one C++ touch is two
  `#define` lines pointed at the generated macros (rule 20, marshaling),
  plus the dead `DYNAMIC_FEE_PER_KB_BASE_FEE_V5` deleted from the same
  file (§3.10, disclosed). **Amended on review (2026-09-27):** the
  short-term window's key has **three readers, not one** — the median,
  the fee estimator's assertion, and the RPC `grace_blocks` ceiling
  (§3.4) — and the third is included, not split: the ceiling is the
  median's horizon by derivation, so it reads the same key and its doc
  says why; a retune of the window moves it because it should. The
  alternative — Rust consts with a sentinel test against the header —
  leaves the value with two hand-written homes.
- **Q7 — G2's grade. RULED 2026-09-26: the proposed grading, taken.**
  §3.1 read the connect path: bodies are keyed by computed identity, so a
  body under the wrong txid is not how a reorder lands; a reorder or a
  substitution connects, and the reorder's consequence — output indices
  assigned in body order, into E3's leaf order — is a silent consensus
  split, which leads the finding. A `FormRule`, disclosed as **L1's class,
  not L1's severity** — reached before its peer path exists rather than
  after, the difference between a finding and an incident (one CHANGELOG
  line). The `Candidate` doc's *"a 4.G rule and lands with its slice"* is
  cited in the row as the evidence the type defers deliberately. Commit 2
  still constructs the two-body block through the driver: the family's
  pin ran on the harness chain, never on a captured one (§3.7). The
  alternative — a pairing gap with no security line — was the first cut
  of §3.1, and the connect read refutes it.
- **Q8 — the loci. RULED 2026-09-26 under two tests, read at the code
  rather than from the labels.** *The first test:* **a locus must be
  derivable from the refusal's own evidence** — what the rule computed on
  its way to refusing, not what the fixture author knows or the mutation
  changed. A rule that cannot name the place has a coarser locus than
  claimed, and an `ExpectedPlace` at the finer one asserts what the rule
  never established. *The second:* **two rows sharing a locus and a
  trigger are indistinguishable to a mutation**, and `ExpectedPlace`
  passes silently when the wrong row refuses (slice 5's Q8, `WrongReward`
  keyed to a row that would never refuse) — so for each shared locus
  there must be a mutation that trips one row and not the other, written
  before commit 2's table, not after. **Two corrections to the doc
  first:** `Locus::Listed { slot }` is not a variant — `Locus` is `Block |
  Tx { slot: TxSlot } | Input { slot, input }`, `TxSlot` is `Miner |
  Listed(usize) | Lone` (`verdict.rs:136–165`); the spelling is `Locus::Tx
  { slot: TxSlot::Listed(i) }`. *The general shape, recorded here as the
  evidence behind the census-sweep FOLLOWUPS row's fifth mechanism:* a
  design document named a symbol that does not exist, the name propagated
  toward E2's mutation rows, and nothing would have compiled against it
  until commit 2 — the fourth document-names-a-missing-symbol instance
  this month, and unlike a stale line pin it is invisible to the citation
  gate, which resolves paths and ranges rather than identifiers. The
  symbols are enumerable (`rustdoc --output-format json`, or `rg 'pub
  (enum|struct|fn|const) '`), so a doc-cited Rust path could be checked by
  the mechanism that checks census coverage. And the review's premise that G1 has a
  *root arm* whose evidence names no slot is refused at the line: **no
  rule compares a merkle root to anything** — the tree hash over the
  declared list is an *input to the identity* (`Block::pow_blob`,
  `shekyl-wire/src/block.rs:233–235`; B6 records it, D2 judges the PoW
  over it), so a different list is a different block, not a mismatch. The
  only hash-against-hash comparison in 4.G is G2's, per index by
  construction. **Under the first test:** G2 — length at `Locus::Block`
  (no slot in evidence), first mismatching index at `Locus::Tx { slot:
  Listed(i) }` (the rule computed exactly *i*); G1 — both arms (on the
  chain / earlier in this block) at `Locus::Tx { slot: Listed(i) }`, the
  slot whose hash the rule looked up, the second occurrence for the
  intra-block arm; G7/G9/G10 at `Locus::Input { slot, input }`, the vin
  the key was read from; F14 at `Locus::Block` — the census cell (`:391`)
  is the weight-limit arm, whose evidence is the block's summed weight;
  the coinbase's claim is F18's (`:396`) at `Locus::Tx { slot: Miner }`,
  where `WrongReward` already points. Definitions record only. **Under
  the second test, the finding — an ordering, not a locus:** G1's
  chain-duplicate arm shares its *trigger* with I7 (a re-listed spend's
  key image is spent) and its intra-block arm with L1 (a doubled spend's
  image appears twice). If G1 runs after the slot loop, I7 refuses at
  `Locus::Input` first and L1 catches the double before G1 sees the hash
  — **G1 would have no witness on any spend**. So G1 runs **before** the
  slot loop (§4), the C++'s own order (`tx_exists` `:5516` before
  `check_tx_inputs` `:5639`), and the order is pinned by a test that
  fails when it flips — ordering arguments being the class wrong twice
  this month. The remaining shared loci separate by trigger:
  `Locus::Block` carries G2-length (`MissingBody`) and F14
  (`OverweightBlock`) beside B5/C1/C2/D1, each with a mutation that trips
  one and not the others; `Locus::Input` carries G7/G9/G10 beside L1, I7
  and I18, each keyed to a different input variant, so one body cannot
  trip two. The seven mutation rows (§5 row 7) are written spec-first at
  commit 2 from these loci.
- **Q9 — the divergence going live. RE-RULED 2026-09-26: G6 lands at
  parity; the divergence is in the record, not the code.** *Records-was,
  the question as asked:* with G6 the Rust validator would refuse a block
  whose short-term median exceeds `4 × LTEM` where the C++ accepts up to
  `50 ×`; default, land it as ratified with a live-lane divergence test
  and a CHANGELOG line under consensus. *The first ruling took that
  default and was wrong* — it read the question and the census cells it
  cites and never read `blockchain.cpp`; §3.8 has the read. **Ruled:** (i)
  no rule change — both languages compute `S = 4` from one key since
  `1c8594049`; (ii) the census G6/G6b cells and the register's two
  DIVERGENT rows are corrected in commit 10, re-reviewed at the landing
  tree, and if the gate derives 127 / 1 / 5 the CHANGELOG says plainly
  that CEN-I4 is the register's only recorded divergence; (iii) the
  live-lane test is a **parity capture in I17's KAT shape** (§3.5) — a
  C++-built block at the C++'s limit accepted by the Rust validator on G6
  while both implementations exist. The `RuleSet` knob carrying `50` is
  refused for a stronger reason than rule 16's user-absent inversion: the
  rule set is where a future reader learns what Shekyl permits, and there
  is no C++ value to be compatible with — the entry would encode a number
  that exists nowhere and give a refuted value institutional standing.
