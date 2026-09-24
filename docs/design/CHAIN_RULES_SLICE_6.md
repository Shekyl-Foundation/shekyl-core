# `shekyl-chain-rules` slice 6 — census 4.I, the transaction's inputs under FCMP++ (DRS-E6 increment 7)

**Status:** OPEN — **Round 0 pre-flight written 2026-09-23 against `dev` @
`4dc5194de` (post-#839, slice 5 landed). Rulings owed on Q1–Q9 (§8);
implementation does not begin before Round 1 and before the §1.2 capture
gate opens.** Registered before implementation (rule 94 §5).

Parent: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §4.6 (`tx_against`,
`tx_form`), [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 (DRS-E6;
ordering-table row *4.I Tx inputs (FCMP++) — slice 6 — `tx_against`; verify
bodies behind `shekyl_fcmp_verify` / `shekyl_pqc_verify` are Rust already
(adopt); after 4.H*). Census: [`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md)
§4.I, **20** rows CEN-I1…I20 (the ordering table's "18" predates I19,
2026-09-06, and I20, 2026-09-23). Predecessor:
[`CHAIN_RULES_SLICE_5.md`](CHAIN_RULES_SLICE_5.md), whose §5.1 scoped this
slice's fixture cascade and whose conformance table left fourteen arms
that arm themselves against this slice's rows (§1.3).

---

## 0. What this slice is

The **view-bound per-transaction rules**: everything about one non-coinbase
transaction that needs the recorded chain — is this key image spent, does
`referenceBlock` exist and sit inside the age window, what was the
curve-tree root at that height — **plus** the crypto cutover slice 5
deferred here on Q3 (b): the FCMP++ membership-and-spend-auth proof, the
per-input hybrid PQC signature, and the BP+ range proof (CEN-H19's
verification half). In the C++ this is `Blockchain::check_tx_inputs`
(`blockchain.cpp:3360–4289` at `4dc5194de`) plus `verify_transaction_pqc_auth`
(`tx_pqc_verify.cpp:162–243`), run at pool admission and at connect. In
Rust the home is
[`tx_against`](../../rust/shekyl-chain-rules/src/validate.rs)
(`tx_against(tx, view, rule_set) -> Result<Verdict<RuleCoverage>, V::Fault>`),
today `Ok(Ok(EMPTY))` — the last of the crate's four entry points still a
stub.

Not every 4.I row is view-bound. The census's 4.I is *"the FCMP++ input
path"* as the C++ organises it, and that path holds stateless checks the
C++ happened to place there (I1 output count, I3 version, I4 input cap,
I5 ordering, I6 empty offsets, I8/I9 arities, I14 non-empty proof, I16
auth structure, I19/I20 `extra` shape). Those are `tx_form`'s by the
crate's partition — *view-dependence and nothing else* (slice 2 Q1) — and
land as `TxRule`s beside the 4.H rows. §4 places every row.

The verify bodies are Rust already: `shekyl_fcmp::proof::verify` (behind
`shekyl_fcmp_verify`, `legacy_fcmp.rs:390`), `shekyl_crypto_pq`'s hybrid
and multisig verify (behind `shekyl_pqc_verify`, `legacy_core.rs:219`),
`shekyl_fcmp::leaf::PqcKeyScalar` (behind `shekyl_fcmp_pqc_key_scalar`).
This slice **adopts** them the way slice 5 adopted `shekyl-ct-balance`: the
rule calls the crate body directly; the FFI shim keeps its C++ caller until
E4 retires it. One finding (§3.1) is that one binding step is *not* Rust.

## 1. Parents — landed? (§7.5.1 (a))

### 1.1 Landed

- **Slice 5 (#839, `4dc5194de`).** `TxRule` / `TxContext` / `run_tx` /
  `run_tx_unrecorded`; `TxKind::of(slot)`; `TxClass` with the bond terms
  on the class; 17 4.H rows implemented, 5 by construction; H19's layout
  half as a `TxRule` run unrecorded; the fixture-sanity gate; one spend body
  (`fixture::spend`) across the three crates; the conformance table with
  its fourteen self-arming arms (§1.3).
- **TXE (`50256487f`, `3ab84bab6`).** One `tx_extra` codec; CEN-I19's shape
  and CEN-I20's coinbase grammar hold in `shekyl_wire::tx_extra::check_tx_extra_shape`,
  which the C++ now calls through `shekyl_tx_extra_shape_of`. The Rust
  holder for I19/I20 exists; this slice gives it a row.
- **Store reads the rows need.** `ChainView::has_key_image` (I7),
  `block_at(height)` and `root_at(height)` (I10–I12), `tip()`.
  `Store::height_of(hash)` exists (`read.rs:246`) but is **not on
  `ChainView`** — §1.4.

### 1.2 The capture gate — slice 5 §5.1, now this slice's first wall

Every spend fixture in `shekyl-chain-rules`, `shekyl-chain-store` and
`shekyl-chain-ingest` carries **filler** proof material by declaration:
`bp_plus_layout_for` (canonical layout, filler scalars), `fcmp_proof:
[0xF0]`, `pqc_auth_filler()` (empty key and signature). I15, I18 and H19's
verification half will refuse **all of them at once**, and the fix is not a
constant. Slice 5 §5.1 scoped the answer: **five captured transactions**,
generated once through the production Engine and committed as test data
under `rust/shekyl-chain-rules/tests/vectors/` with their block context —
1-in/1-out, 1-in/2-out, one bond post and one emission with one fee spend
each, one depth-3 variant. The generators exist:
`e2e_fcmp_spend_accepted_by_daemon` (`regtest_e2e.rs:933`) and
`e2e_fcmp_spend_over_depth3_tree` (`:1360`).

The FOLLOWUPS row (*Captured spends for the verification era*) says
*"slice 6's pre-flight, which does not open until the vectors exist."* This
pre-flight is open. **Read as written, that sentence forbids this
document; read for its purpose, it forbids landing I15/I18/H19-verify
without the vectors, which is the gate that matters.** The second reading
is taken here and disclosed (rule 22: a deferral's condition is re-read,
not inherited); **Q1** asks the reviewer to confirm it and to name the
capture's owner, because the generator lives in `shekyl-engine-core`'s
regtest — another lane's crate — and the captured blobs' *block context*
(reference block, root at `ref_height`, membership set, tree depth) is what
`MockChain` must be taught to serve (§4.3).

**Until the vectors land, this slice can land every row that does not
verify a proof** — the stateless rows in `tx_form`, I7, I10–I13 in
`tx_against` — because the filler fixtures pass those. The verification
rows (I15, I17/I18, H19-verify) are the commits behind the gate.

### 1.3 What slice 5 left armed here

The conformance table (`rules/tx_conformance_tests.rs`) holds the wallet's
wire twin to `tx_form` by each row's registry status, and **fourteen of its
arms are keyed to rows this slice flips**: I1 ×2, I4, I5, I6, I8, I9, I16,
J2, J11, J12, H19 ×3. Each begins asserting *the day its row is registered
`implemented`*: the twin's tripping transaction must then be refused by
`tx_form` on that row. Nothing in this slice needs to touch that table for
those rows — a row flipped without the crate actually refusing fails there
first. Two things this slice **does** owe the table: the dead-arm ordering
argument (`key-image input(s) but no prunable proof`) names two orderings
this slice's proof verification may disturb — re-check it; and I19's row
(`check_tx_extra_shape …`) is the one arm whose fragment is a source line,
not a message.

CEN-H24's falsifier (`h24_cannot_fire_on_an_input_i6_admits`) asserts that
`tx_form` **still accepts** the offsets fixture. **I6 landing flips it:**
the `expect` fails, and the assertion becomes I6's refusal. That is the
commit that lands I6, not a follow-up.

### 1.4 View surface this slice needs and does not have

Three C++ reads in `check_tx_inputs` have no `ChainView` method:

| C++ read (at `4dc5194de`) | Row | `ChainView` today | Needed |
| --- | --- | --- | --- |
| `m_db->block_exists(rv.referenceBlock, &ref_height)` `:4113` | I10 | `block_at(height)` — height-keyed only | **`height_of(&BlockHash) -> AtHeight/Option<BlockHeight>`**; the store has it (`read.rs:246`), the trait does not |
| `m_db->get_curve_tree_depth()` `:4162` | I13 | — | **the tree's depth** — a curve-tree state read (E3 S-CURVE), *current* in the C++ (§3.3 asks whether it should be at `ref_height`) |
| `m_db->get_curve_tree_root_at_height(ref_height)` `:4152` | I12 | `root_at(height)` ✓ | — |

A `ChainView` method is a contract change to `CHAIN_RULES_CRATE.md` §4.3 and
to every implementer (`BatchView` in the store, `MockChain` in the harness,
E5's pool decorator). It is the S-CHAIN-W shape — the store lane adds the
read, this lane consumes it — and **Q2** asks which lane lands the trait
change and in which PR. The stateless rows and I7 do not wait on it.

### 1.5 In flight

No adjacent lane edits `shekyl-chain-rules`. S-ARCH (#840) landed the
archival reads on `dev`; S-PRUNE and the E3 curve-tree lane are the ones
whose contracts §1.4 touches. Checked at each commit as slice 5 checked
TXE.

## 2. Row-body audit (§7.5.1 (b)) — 20 rows, pins read at `4dc5194de`

Every pin below was **read at the line**, not inferred from a diff (slice 5
row 9's retraction is why). The census's own 4.I `site(s)` cells are stale
by the same TXE shift and older drift; they are re-pinned in this slice's
docs commit with their era, as slice 5 did for 4.H.

| Row | Rule | C++ site read | Rust body today | Operand | Stage (§4) |
| --- | --- | --- | --- | --- | --- |
| I1 | non-serve-credit tx has ≥ 2 outputs | `blockchain.cpp:3386–3394` (`check_tx_inputs`, before the nettype gate) | twin `:1965`, `:2010` (two arms, one row) | class + `outputs.len()` | `tx_form` |
| I2 | non-coinbase CT is `FcmpPlusPlusPqc` | `:3396–3403` **inside `m_nettype != FAKECHAIN`**; the `else` at `:3539–3544` refuses a non-FCMP tx on every nettype | — (H15 holds the `Null` half unconditionally) | `ct` type | **subsumed by H15 + the type set** — Q3 |
| I3 | version exactly 3 | `:3413–3426` inside the FAKECHAIN gate; `ver_non_input_consensus` `:74` unconditional | H2 by construction (`TX_VERSION`) | — | **by construction** (H2/H13's property, fourth site) — Q3 |
| I4 | `vin.size() ≤ FCMP_MAX_INPUTS_PER_TX` (8) | `:3405–3411` inside the FAKECHAIN gate — **the one row the gate genuinely exempts** | twin `:1843`; `shekyl_fcmp::MAX_INPUTS = 8`; `cryptonote_config.h:311` | `inputs.len()`, a const | `tx_form` — Q3 |
| I5 | key images strictly descending | `:3430–3450` (`memcmp >= 0` rejects) | twin `:1875`; H10 refuses the equal case | `ToKey` images | `tx_form`; **H10 becomes I5's equality arm** — Q4 |
| I6 | `key_offsets` empty | `:3523–3529` regular; `:3472`, `:3496` archival co-resident | twin `:1865` | `ToKey.key_offsets` | `tx_form`; **flips H24's falsifier** |
| I7 | key image not spent on-chain | `:3531–3536` regular (`have_tx_keyimg_as_spent`); `:3478`, `:3502` archival; CEN-L1 re-enforces at connect | `ChainView::has_key_image` | view | `tx_against` |
| I8 | `pqc_auths.len() == vin.len()` (serve-credit: 0) | `:3560–3567`; `tx_pqc_verify.cpp:169` | twin `:2018`; H20 holds the serve-credit zero; H21/H22 the archival counts | lengths | `tx_form` |
| I9 | `pseudoOuts.len() == inputs` (regular); archival subsets are H21/H22's | `:3569–3577` | twin `:2060`; H18 reads them | lengths | `tx_form` |
| I10 | `referenceBlock` is a main-chain block | `:4113–4119` (`block_exists`, → `ref_height`) | — | **hash → height** (§1.4) | `tx_against` |
| I11 | `ref_height` ∈ `[chain_height − 100, chain_height − 5]` | `:4121–4141` (two guards; the `chain_height <` clauses are the genesis-window arms) | — | `ref_height`, `tip`; `FCMP_REFERENCE_BLOCK_{MIN,MAX}_AGE` from `config/consensus_constants.json` | `tx_against`; constants as `RuleSet` data or consts — Q5 |
| I12 | anchor = root **at `ref_height`**, read from the record never the header | `:4152` (`get_curve_tree_root_at_height(ref_height)`) | `ChainView::root_at` ✓ | view | `tx_against`, a **definition** row recorded at its derivation (D4's shape) |
| I13 | `curve_trees_tree_depth ∈ [1, depth]`; layers = depth + 1 | `:4162–4170` (`get_curve_tree_depth()` — *current*) | — | **tree depth** (§1.4) | `tx_against` — §3.3 |
| I14 | proof non-empty | `:4173–4178` | `Prunable::fcmp_proof` | — | `tx_form`; the wire's dead arm was this row's shadow |
| I15 | FCMP++ proof verifies over images, pseudo-outs, PQC key scalars, root, layers, signable hash | `:4181–4242` (scalars `:4192–4201`, verify `:4221–4234`) | `shekyl_fcmp::proof::verify`; `leaf::PqcKeyScalar` | proof, I12's root, I13's layers, **the signable hash** (§3.2) | `tx_against`, **behind the capture gate** |
| I16 | per-input auth structure: version 1, flags 0, scheme ∈ {1, 2}, solo key = 1996 B, multisig ∈ [3, 16384] | `tx_pqc_verify.cpp:176–215` | twin `:1930` (cap only) | `PqcAuth` fields; `PQC_HYBRID_SINGLE_KEY_LEN`, `PQC_MAX_PUBLIC_KEY_BLOB` | `tx_form` |
| I17 | signed payload = prefix ‖ CT base ‖ keccak(prunable) ‖ input's PQC header ‖ keccak of every input's key | `tx_pqc_verify.cpp:62–158` — **assembled in C++** | `Transaction::pqc_signing_payload_hashes` (`shekyl-wire:1552`) — the wallet's copy | the whole tx | `tx_against`… **§3.1: a second implementation, and the C++ is the one of record** |
| I18 | hybrid / multisig signature verifies over keccak(payload) | `tx_pqc_verify.cpp:231–243`; gate `blockchain.cpp:4277–4285` | `shekyl_crypto_pq` verify (behind `shekyl_pqc_verify`) | I17's payload | **behind the capture gate** |
| I19 | `extra` PQC field shape (`0x06` `1120·n`, `0x07` `64·n`, exactly one each iff `n > 0`) | `cryptonote_format_utils.cpp:694–715` (`check_tx_extra_shape` → `shekyl_tx_extra_shape_of`) | `shekyl_wire::tx_extra::check_tx_extra_shape` ✓ | `extra`, `outputs.len()` | `tx_form` — **adopt**; the conformance arm is pending on it |
| I20 | coinbase `extra` grammar | same adapter with `is_coinbase`; `blockchain.cpp:1443–1450` (miner) | `check_coinbase_extra_shape` ✓ | `extra`, kind | `tx_form` at `Miner`, or 4.F's `form` stage — Q6 |

Ancillary, read while there: the `else` at `:3539–3544` and the `switch`
`case CTTypeNull` at `:3550` are what slice 5's Q9 retraction rested on;
both re-read here at `4dc5194de` and unchanged.

## 3. Findings from the code sweep

### 3.1 CEN-I17's binding is assembled in C++ — the slice-4 shim class, load-bearing

`get_transaction_signed_payload` (`tx_pqc_verify.cpp:62–158`) builds the
bytes the PQC signature covers: the serialized prefix, the CT base, the
keccak of the **prunable** region (`:92–113`), the input's own PQC header
(`:116–130`), and the keccak of **every** input's hybrid key (`:133–143`).
That is rule content — it decides what a signature *binds*, which is what
makes swapping a proof or an input's key detectable — and it runs in C++
before `shekyl_pqc_verify` sees a byte. The Rust that exists is the
wallet's: `Transaction::pqc_signing_payload_hashes` in `shekyl-wire`
(`:1552–1608`), the twin's copy of the same construction, reconciled with
the C++ by nothing but the fact that signed transactions currently verify.

Under slice 4's discriminator (*would this survive a rule change?*): no —
change the binding and every signature is judged against different bytes.
So the payload derivation is **rule content in a shim**, and this slice's
I17 must have a Rust body *of record*: either the wire's, promoted from
"the wallet's copy" to the derivation both validator and wallet call, or a
new one in `shekyl-chain-rules` that the wire is then held to (the slice 5
Q1 shape, one level down). **Q7.** Whichever, `FCMP_SPEND_SIGNING_PREIMAGE.md`
`:27–36` is the spec and the pinned vectors are the falsifier.

### 3.2 The signable hash I15 verifies against is derived in C++ too

`shekyl_fcmp_verify`'s last argument is `tx_prefix_hash` — for an emission
it is the prefix hash *with the emission vin removed* (CEN-J22). The
derivation is C++-side (`get_transaction_prefix_hash` and J22's variant).
`shekyl-wire` hashes prefixes (`Transaction::hash`, `txid_parts`); whether
it computes J22's excluded form is a pre-flight read owed before I15's
commit. Same class as §3.1, smaller.

### 3.3 I13 reads the *current* depth; I12 reads the root *at `ref_height`*

`get_curve_tree_depth()` at `:4162` has no height argument; the root at
`:4152` does. A proof built against the tree at `ref_height` carries that
tree's depth; the range check `[1, current_depth]` admits it whether or not
the tree has grown since, and `shekyl_fcmp::proof::verify` is told
`layers = depth + 1` from the *transaction's* field. The two operands are
consistent only because depth is monotone. Not a divergence — but the Rust
row should say which depth it reads and why, and the view method §1.4 asks
for should be height-keyed if the curve-tree lane can serve it that way
(the same reason I12 is). **Q8.**

### 3.4 The FAKECHAIN gate — the rule-71 question, on the rows that own it

Slice 5 Q9 located a rule-71 violation on CEN-H15 and was refuted: the gate
at `:3396` is CEN-I2's, and H15's own sites are unconditional. The gate
still exists, and the census marks **I2, I3 and I4 "FAKECHAIN exempt"**.
Read at `4dc5194de`, the exemption is real for exactly **one** of them:

- **I2** — the `else` at `:3539–3544` refuses a non-FCMP transaction on
  every nettype; the gate only chooses *which* refusal fires. Behaviour
  does not vary. Not exempt.
- **I3** — `ver_non_input_consensus` `:74` checks the version bounds
  unconditionally, at both of its sites. Behaviour does not vary. Not
  exempt.
- **I4** — `FCMP_MAX_INPUTS_PER_TX` is checked **only** inside the gate
  (`:3405`); `shekyl_fcmp_verify` refuses `ki_count > MAX_INPUTS` (=8) as
  code 1, but a nine-input transaction reaches it only if the proof is
  verified, and `skip_fcmp_verify` is a parameter. **Behaviour varies by
  nettype here**, and only here — rule 71's prohibition, on one row.

This is the guard variant's lesson applied forward (rule 16, the H15
instance): a nettype-conditional check is evidence of nothing until the
behaviour beneath it is read. The Rust I4 is unconditional (Q3); whether
the C++ gate is deleted, and by whom, is the C++ lane's question — the
census's three "FAKECHAIN exempt" annotations are corrected to one in this
slice's docs commit, with the reading recorded.

### 3.5 Half the family is stateless, and the census filed it under inputs

Eleven of twenty rows (I1, I3, I4, I5, I6, I8, I9, I14, I16, I19, I20) need
no view. The census groups by *C++ function*; the crate partitions by
*view-dependence*. Those eleven are `TxRule`s in `tx_form`, judged at the
pool's slot and at every listed slot exactly as 4.H's are, and the
conformance arms slice 5 left for them are already keyed to `tx_form`.
`tx_against` gets I7 and I10–I13 as view-bound rules, I15 and I18 as the
verification rows over operands `tx_against` derives (I12's root, I13's
layers), and — if Q7 lands the derivation here — I17 as a definition row.
The stage table is §4.

### 3.6 BP+ verification is batched at the block; FCMP++ is per transaction

Slice 5 §3.4: the C++ verifies BP+ **once across the block's transactions**
(`verCtSemanticsSimple` over `rvv`, `ct_semantics.cpp:140–196`), so H19's
verification half belongs to `validate` as a fold, not to `tx_form`. FCMP++
(`:4221`) and PQC (`:4280`) are per transaction and belong to `tx_against`.
Two different placements for three verifications; §4 has them; **Q9** asks
whether the BP+ fold is this slice's or a `validate`-side commit with its
own fixture (the batch has a negative fixture the per-tx path cannot
express: one bad proof among good ones).

## 4. Stage placement — proposed, shaped by §8

| Stage | Rows | Substrate |
| --- | --- | --- |
| `tx_form` (stateless `TxRule`s) | I1, I4, I5 (with H10 as its equality arm), I6, I8, I9, I14, I16, I19, I20 | consts beside the rules (`MAX_FCMP_INPUTS`, `PQC_HYBRID_SINGLE_KEY_LEN`, `PQC_MAX_PUBLIC_KEY_BLOB`), pinned to `cryptonote_config.h` and equal to the wire's, as slice 5 Q5 |
| `tx_against` (view-bound `TxRule`s — a new `TxAgainstRule` with `check(cx, view)`, the `BlockRule` shape at tx grain) | I7, I10, I11; I12 as a **definition** recorded at derivation (root at `ref_height`); I13 | `ChainView::height_of`, the tree depth (§1.4); `ReferenceWindow { min_age: 5, max_age: 100 }` as `RuleSet` data or consts (Q5) |
| `tx_against`, behind the capture gate | I15 (proof), I18 (signature), I17 (the payload — definition or verification per Q7) | `shekyl-fcmp`, `shekyl-crypto-pq` as dependencies of the rules crate; the captured vectors; `MockChain` serving the vectors' block context |
| by construction / subsumed | I2 (type set + H15), I3 (`TX_VERSION`, with H2/H13) | registry entries credit the existing falsifiers — Q6's list-and-iterate shape |
| `validate` (block fold) | H19's verification half — one BP+ verify over the block's proofs | Q9 |

## 5. Commit plan — sketch, finalised at Round 1

On slice 4 Q7's rule: rules first; shared substrate where the rules need
it; anything cross-lane last; **the capture gate splits the plan in two.**

| # | Commit | Gate |
| --- | --- | --- |
| 1 | Stateless 4.I rows in `tx_form`: I1, I4, I6, I8, I9, I14, I16; I5 taking H10's equality arm; each with its negative fixture at both sites | none — the conformance arms for I1, I4, I5, I6, I8, I9, I16 arm themselves here; H24's falsifier flips here |
| 2 | I19/I20 adopted: `tx_form` calls `check_tx_extra_shape`; the fixtures gain conforming `extra` (the fixture-sanity gate will say so) | none |
| 3 | `TxAgainstRule`; I7 over `has_key_image`; I2/I3 registry entries | none |
| 4 | `ChainView::height_of` + the depth read; I10, I11, I12 (definition), I13 | **Q2** — the view contract |
| 5 | I17's derivation of record (Q7) with `FCMP_SPEND_SIGNING_PREIMAGE.md`'s vectors pinned | none |
| 6 | Captured vectors under `tests/vectors/`; `MockChain` serves their context; the fixture builders load them | **§1.2 capture** — Q1 |
| 7 | I15 over `shekyl_fcmp::proof::verify`; I18 over `shekyl_crypto_pq`; H19's verification half per Q9 | commit 6 |
| 8 | Conformance table: re-check the dead-arm ordering; I19's arm | — |
| 9 | Docs: census 4.I re-pinned at the landing tree (read, not diffed); the "FAKECHAIN exempt" annotations corrected to I4 alone (§3.4); `CHAIN_RULES_CRATE.md` §4.3/§4.6; index; FOLLOWUPS; CHANGELOG | — |

Commits 1–5 land without the vectors. If the capture is another lane's and
lands later, this slice's PR is commits 1–5 + 8–9 with 6–7 a named
successor — a **split**, disclosed here in advance, not a deferral (rule
22).

## 6. What this slice does not build

- **The pool.** `tx_against` takes any `ChainView`; E5's decorator is E5's.
- **CEN-L1** (the store's own spent-image check at connect) — the store's
  belt, already landed; I7 is the validator's rule.
- **Curve-tree state.** I12/I13 *read* the tree; E3 S-CURVE writes it.
- **C++ deletions.** The FAKECHAIN gate (§3.4), the C++ payload assembly
  (§3.1) — retired with E4, not here.

## 7. Round log

- **Round 0** (2026-09-23): pre-flight written at `4dc5194de`; every pin
  read at the line; nine questions.

## 8. Questions for the reviewer — Round 0

- **Q1 — the capture gate (§1.2).** Confirm the reading: the FOLLOWUPS
  row's "pre-flight does not open" gates the *verification commits*, not
  this document. And name the capture's owner: the generator is
  `shekyl-engine-core`'s regtest; the consumer is this crate's `tests/vectors/`.
  Default: this lane runs the generator and commits the blobs, in a commit
  that touches only test data and the harness, with the engine lane told.
- **Q2 — the view contract (§1.4).** `ChainView::height_of(&BlockHash)` and
  a tree-depth read are contract changes to `CHAIN_RULES_CRATE.md` §4.3 and
  every implementer. Which lane lands them, and is the depth read
  height-keyed (Q8)? Default: this slice adds `height_of` (the store
  already has it; `MockChain` gains it) in commit 4; the depth read is the
  E3 lane's method and I13 waits on it.
- **Q3 — I2, I3, I4 (§3.4).** I2 subsumed by H15 plus the `Ct` type set
  (registry: `by_construction`, crediting H15's fixture and the type's
  falsifier, list-and-iterate); I3 by construction on `TX_VERSION` (H2/H13's
  falsifier, fourth row on the list); I4 a `tx_form` rule, unconditional.
  Default as stated.
- **Q4 — H10 into I5.** The C++ has one arm (`memcmp >= 0`) for "sorted"
  and "distinct". H10 landed as its own row in slice 5 (refuses the equal
  case). Options: (a) I5 refuses `<=` and H10 keeps its row as the equality
  sub-case — two rows, one predicate, recorded on both; (b) H10 is
  re-registered as subsumed by I5. Default (a): the census has two rows and
  a row is not deleted by a slice.
- **Q5 — the reference window's constants.** `FCMP_REFERENCE_BLOCK_MIN_AGE`
  / `MAX_AGE` (5 / 100) come from `config/consensus_constants.json`. As
  `RuleSet` fields (the F21 shape, varying by schedule step) or as consts
  beside the rule pinned to the JSON (slice 5 Q5's shape)? Default: consts —
  no schedule step varies them, and the first that does is their first
  `RuleSet` reader.
- **Q6 — I20's stage.** The coinbase grammar is judged at `Miner`. As a
  `tx_form` rule with a **new** `TxScope::Coinbase` (the enum has `All` and
  `NonCoinbase` today, `rules/mod.rs:320`; the first rule that is
  coinbase-*only*), or in 4.F's `form` stage beside F1–F10 as a `FormRule`?
  Default: `tx_form` with the new scope — it is a per-transaction rule on
  the coinbase's own bytes, judged where the other per-transaction rules
  are, and adding the variant is the enum doing what it was shaped for
  (rule 21: a variant with a caller).
- **Q7 — I17's body of record (§3.1).** (a) Promote the wire's
  `pqc_signing_payload_hashes` to the derivation of record and have I17
  call it — one function, wallet and validator; (b) a derivation in this
  crate, the wire held to it by the conformance table. Default (a): the
  wire already carries it, the spec has vectors, and (b) would mint a
  second copy to reconcile a second copy.
- **Q8 — I13's depth operand (§3.3).** Current depth (C++ parity) or depth
  at `ref_height` (consistent with I12)? Default: at `ref_height` if the
  curve-tree lane can serve it, with the C++ reading recorded as a
  parity-not-divergence note; else current, with the monotonicity argument
  written at the rule.
- **Q9 — H19's verification half (§3.6).** In this slice as a `validate`
  fold over the block's proofs (one BP+ verify, the C++'s batch), or its own
  commit after the vectors with the one-bad-proof-among-good fixture?
  Default: this slice, commit 7, if the vectors carry ≥ 2 spends per block
  context; else a named successor.
