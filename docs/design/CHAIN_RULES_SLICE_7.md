# `shekyl-chain-rules` slice 7 — census 4.G, the block body, and the four 4.F rows that waited on it (DRS-E6 increment 8)

**Status:** OPEN — **Round 0 pre-flight, written 2026-09-26 against `dev` @
`ad557ac5a` (post-#874, slice 6 closed out; post-#873, DRS-E3's curve-writer
pre-flight).** Nine questions in §8; implementation begins when they are
ruled. Registered before implementation (rule 94 §5); process per
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
- **The heaviest row is a definition, and it is the one with the recorded
  divergence.** G6/G6b's effective median is what the coinbase's exact-pay
  verdict (F18) is a function of. The shipped C++ clamps the short-term
  median at **×50** the long-term; the census ratified **S = 4**
  (C2-R2 Q3, GAP-7 measured on the Pi 4 floor). Landing G6 makes the Rust
  validator refuse blocks the C++ accepts near the surge bound. Slice 4 Q1
  ruled that this divergence lands in *its own* slice, in the PR that owns
  the weights, so it cannot be buried — this is that PR.

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
| **G2** | 4 | `take_tx` from the pool, else the block supplement; a hash resolving to neither → `MISSING_TXS` outcome, not a rejection (`:5551–5588`); **body ↔ hash agreement is established by lookup under the computed hash** | **nothing binds a listed body to `tx_hashes[i]`** — E2's `ReorderedBodies` connects (§1.1) | **`FormRule`** (form stage, no view — `rules/mod.rs:156`): `transactions.len() == tx_hashes.len()` and `hash(body_i) == tx_hashes[i]` for every `i`; refuses at `Locus::Listed { slot }`. The *resolution* half (pool/supplement) is the ingest's and E5's, not a rule; the *agreement* half is consensus and is the row (§3.1) |
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
4.G rule and lands with its slice."* The type does not satisfy G2; it names
G2 as owed.

**What a connect does with the disagreement.** The store keys each body
under its computed identity (`connect.rs:405–407`), so *wrong body under the
right txid* is unreachable through this path. Two things are body-dependent
all the same: `BLOCKS` persists the block as received, declared list
included (`connect.rs:417`), so the record lists hashes whose bodies were
never recorded or are recorded in another order; and `record_tx` assigns
dense tx ids and **global output ids in body order** (`connect.rs:534`,
`:596–610`) — a reorder that connects gives outputs different indices than
a header-ordered node, and E3's drain order (§3.3 of its pre-flight) puts
them into the curve tree in that order: root divergence at the next block,
B5 splits the chain silently. A *substitution* — a valid body not in the
declared list — connects too: N hashes committed, N bodies recorded, one of
them covered by no block id.

**The belt, and where it sits.** The C++'s lookup-under-hash has a Rust
twin in the **corpus loader**: `verified_tx(height, index, want, blob)`
(`corpus.rs:325–340`, `:362`) refuses a body whose hash is not the declared
hash at that index. Every captured replay is safe because of it.
`Candidate::new` has four producers (corpus, scenario driver, two fixture
files) and no live peer path yet — **not peer-reachable today**, reachable
the day E5/p2p ingest builds a `Candidate` from network bodies, a path that
inherits no belt because the belt is the corpus's. That is CEN-L1's shape
(a consumer-side belt where the census placed a validator rule), one step
earlier in time.

**The pin was never witnessed.** The first cut of this section said E2's
`ReorderedBodies` is *pinned connects* (`DRS_E2_REPLAY_DRIVER.md:457`). On
every captured chain the mutation is `Unmutable::TooFewBodies { listed: 1 }`
(`mutation_tests.rs:549`) — slice 6's one-body-per-block measurement again.
"Connects" is what the code path would do, not what a run showed. Commit
2's measurement therefore constructs a **two-body block through the
driver** (`mine_listing(listed: Vec<Transaction>)` takes a vector; the
bodies need not be spends, so I15's tree is not a prerequisite) and replays
the reorder and a substitution through it.

**Grading proposed for Q7:** the *set* is bound by the merkle, the
*pairing* is not; G2 lands as a `FormRule` — `transactions.len()
== transaction_hashes.len()` at `Locus::Block`, `hash(body_i) ==
transaction_hashes[i]` at `Locus::Listed { slot }` for the first mismatch —
consensus-relevant and disclosed as L1's class caught before its peer path
existed, not as an incident. The corpus loader's check stays, tested as a
belt (slice 6 re-pointed the SI-1 tests the same way).

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

### 3.5 Two readers of one median, one of them a producer

The block template is the second consumer of G6 (§1.3). It is also where
`S = 4` versus `×50` will first *matter operationally*: a Rust producer
prices its coinbase at the ratified median and a C++ validator near the
surge bound accepts a block a Rust validator refuses, or the reverse. That
is the CSR-3a divergence slice 4 named, arriving through the producer.
Nothing to build — the E2 conformance run grades it — but the run's
`WrongReward` and a new `SurgeBoundReward` mutation should be *planned*
against the captured chains: none of the four carry a surge, so the mock
holds the arithmetic at the four boundaries (`S·LTEM` exactly / one over;
zone exactly / one under) and the divergence is stated as a `#[ignore]`d
live-lane test, not left to memory.

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

## 4. Stage placement — proposed, shaped by §8

| stage | rows | why |
| --- | --- | --- |
| form (`FormRule`, no view) | G2 | body ↔ hash is a property of the candidate's bytes alone |
| `validate`, after the slot loop (`BlockRule`, view) | G1, G7, G9, G10 | span the slots; G1 reads the chain, the others read only the block |
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
| 2 | **Measurements, no rules:** (a) the G2 grade — replay `ReorderedBodies` and state what the store does (§3.1); (b) locate or add the pruned-form fixture at both sites (§3.3); (c) the weights-read bench on the floor (§3.6) — three numbers into §5.1 | — |
| 3 | **`ChainView` grows** — the weights read (Q2's shape) and `has_transaction` — trait, `BatchView`, `MockChain`, the store's conformance test holding the mock to the store, **one commit, both sides** (slice 6 §5.1's rule) | commit 2 (c) |
| 4 | **G6 / G6b** as `judge_emission`'s first two definitions in `rules/block_weight.rs`; the two windows as generated consts (Q6); the mock holds the clamps at their boundaries, the captured chains replay through both | commit 3 |
| 5 | **F14, F14b, F16, G12** — the sequence completed through the paid reward; `ConnectFacts.{weight, long_term_weight, long_term_effective_median, coins_generated}` read off the verdict, the ingest's four composed lines deleted (`Provenance::passed_through` re-counted with E3's) | commit 4 |
| 6 | **G2** as a `FormRule` in `form`; E2's `ReorderedBodies` flips from pinned-connects to refusing at `Locus::Listed` | commit 2 (a) |
| 7 | **G1, G7, G9, G10** as `BlockRule`s after L1; G9's admitted pair as a positive fixture; the driver gains `DuplicateListing`, `DuplicateServeCredit`, `DuplicateClaim`, `DuplicateBondPost` spec-first in `DRS_E2_REPLAY_DRIVER.md` §3.10 | commit 3 |
| 8 | **G3, G4, G5** registry entries, `by_construction` with their falsifiers named; conformance re-check (the register's G rows, `:640–646`, re-read against the crate) | commit 7 |
| 9 | **Wave B — F17, F18, G11, G13** if E3's `leaf_count` has landed; else **the named successor**, one FOLLOWUPS row, falsifier `rg 'fn leaf_count_at\|fn depth_at' rust/shekyl-chain-rules/src/view.rs` → present with `BatchView`'s impl, then this row lands as one commit extending `judge_emission` and `WrongReward` flips | E3 commit 4 |
| 10 | **Docs:** census 4.G re-pinned at the landing tree; `CHAIN_RULES_CRATE.md` §4.3 (the two reads), §4.6 (`judge_emission`, the verdict's four values); `DAEMON_REDB_STORE.md` §7.5; index; FOLLOWUPS (the F14-family residue closed; the wave-B row if deferred); CHANGELOG (the `S = 4` divergence going live in the validator is consensus-relevant, and G2 if commit 2 grades it as more than a pairing) | — |

Ten commits is the rule-06 ceiling; commit 9 is the one that may leave.

### 5.1 The expectation, to be written at commit 1

Left empty on purpose: the cost column is written after commit 2's three
measurements, not before them (B9). What is already known: slice 6 §5.1
predicts *the fixture class should be smaller* here because every fixture
already carries `weight` and `long_term_weight`. The counter-evidence to
watch for is Q2 (a) — if `RecordedBlock` grows two fields, **ten**
construction sites move (`rg 'RecordedBlock \{'` at the pin: store 4,
rules 6), and the prediction is falsified by the read shape rather than by
the rules.

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

## 8. Questions for the reviewer — Round 0

- **Q1 — the two waves, and E3.** F17/F18/G11/G13 wait on E3's per-height
  leaf count (§1.2). Default: this slice lands wave A and names wave B as
  its successor with the falsifier in §5 row 9, absorbing it if E3's commit
  4 merges inside the slice's window. The alternative — hold the whole
  slice for E3 — is refused for the reason slice 6 refused waiting on I13:
  nothing in wave A depends on it, and the median is what unblocks the
  template. Confirm.
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
  reopened on the measured number, not on intuition.
- **Q3 — G1's intra-block half.** The C++ refuses a hash listed twice in
  one block only by the belt (`TX_EXISTS` on the second insert). Every
  duplicate body is *also* caught by a class row — L1 (a spend's key
  image), G7/G9/G10 (the archival forms) — so the Rust rule could leave
  the intra-block case to them. Default: G1 refuses *"already on the chain
  **or earlier in this block**"* — one predicate, one `Locus`, and the
  outcome the C++ reaches through two mechanisms reached through one;
  the class rows stay as the rows they are. Rule 71 is satisfied either
  way (both refuse); the question is which row names the refusal.
- **Q4 — the median's signature, for two readers.** `pub fn
  effective_median_at<V: ChainView>(view: &V, connecting: BlockHeight) ->
  Result<EffectiveMedian, ViewRead<V::Fault>>` returning both the
  effective median and the LTEM (the template needs the first, G6b the
  second). Default as stated; the alternative — the template reads the
  store's recorded `long_term_effective_median(tip)` — is slice 4 Q1 (c)
  by another door (SCR-19: one block stale).
- **Q5 — what the verdict carries.** Four values (`weight`,
  `long_term_weight`, `long_term_effective_median`, `coins_generated`) so
  `facts.rs` deletes four composed lines and `ConnectFacts` reads them
  from `ChainValid`, the D4 precedent. `burned` stays passed-through until
  F17. Default yes; the alternative (keep them in `ConnectFacts` as
  passed-through and let the ingest recompute) is the two-sources class
  the seam exists to close.
- **Q6 — the two windows into `consensus_constants.json`.** Add
  `block_weight_short_term_window_blocks: 100` and
  `block_weight_long_term_window_blocks: 100000`; `shekyl-economics`'s
  `build.rs` generates them; the two C++ defines point at the generated
  macros. Default yes — slice 6 Q5's shape, and the one C++ touch is two
  `#define` lines (rule 20, marshaling). The alternative — Rust consts
  with a sentinel test against the header — leaves the value with two
  hand-written homes.
- **Q7 — G2's grade.** §3.1 read the connect path: bodies are keyed by
  computed identity, so a body under the wrong txid is not how a reorder
  lands; a reorder or a substitution can still connect, and the
  `ReorderedBodies` pin has not run. Default, as §3.1 proposes: a
  `FormRule`, disclosed as L1's class caught before a peer path exists
  (one CHANGELOG line). Commit 2 still constructs the two-body block,
  because that pin was `TooFewBodies` on every captured chain. The
  alternative — treat it as a pairing gap with no security line — is
  what the first cut of §3.1 said, and the connect read refutes it.
- **Q8 — the loci.** G1 at `Locus::Listed { slot }`. G2's length
  mismatch at `Locus::Block`, its first hash mismatch at
  `Locus::Listed { slot }` (§3.1). G7 at `Locus::Input { slot, input }`
  (the vin carries the triple); G9/G10 at `Locus::Input` likewise; F14
  at `Locus::Block`; the definitions record only. Default as stated;
  E2's §3.10 rows are written from these before the rules exist, as
  slice 6 did.
- **Q9 — the divergence going live.** With G6, the Rust validator refuses
  a block whose short-term median exceeds `4 × LTEM` where the C++
  accepts up to `50 ×`. Slice 4 Q1 named this a CSR-3a pass condition.
  Default: land it as ratified, with (i) the census G6/G6b cells' *"until
  the port"* clause closed in commit 10, (ii) a `#[ignore]`d live-lane
  test constructing the divergence (§3.5), and (iii) one CHANGELOG line
  under consensus. The alternative — a `RuleSet` knob carrying `50` until
  the C++ is retired — is a version dispatch for a network with no
  deployed users (rule 16's user-absent inversion) and is refused.
