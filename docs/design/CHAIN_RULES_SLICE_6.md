# `shekyl-chain-rules` slice 6 — census 4.I, the transaction's inputs under FCMP++ (DRS-E6 increment 7)

**Status:** OPEN — **Round 1 RULED 2026-09-24 (Q1–Q9, §8, each line-local);
implementation begins on §5 in the ruled order — capture first.** Round 0
pre-flight written 2026-09-23 against `dev` @ `4dc5194de` (post-#839, slice 5
landed), amended on review `ca218306c`. Registered before implementation
(rule 94 §5).

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
`layers = depth + 1` from the *transaction's* field.

**The first draft of this section said the two reads are consistent
"because depth is monotone". That is false, and the review caught it
before it was recorded** (the shape that has been wrong twice this month).
`trim_curve_tree` runs on pop (`blockchain_db.cpp:878`), recomposes every
upper layer narrow and **writes `depth = num_upper_layers`**
(`db_lmdb.cpp:8869–8896`, with its own comment: *"Trim shrinks the tree,
so the old structure can have more or deeper upper-layer chunks than the
new one"*). Depth decreases across a reorg that crosses a layer boundary.

What actually holds, named as the dead arm names its orderings:

1. **Depth is a function of leaf count alone** — `num_upper_layers` is
   recomposed from the leaf-chunk layer, deterministically (`:8775–8852`).
2. **The tree at any recorded height is a prefix of the current tree.**
   Leaves are appended by connect and removed only by pop, and pop removes
   the *newest* leaves; so if `ref_height ≤ tip`, `leaf_count(now) ≥
   leaf_count(ref_height)`, hence `depth(now) ≥ depth(ref_height)` by (1).
3. **I10 runs before I13** (`:4113` before `:4162`): a `ref_height` the
   reorg removed is refused as *not a main-chain block* before the depth
   check sees it. So (2)'s premise holds whenever I13 is reached.

Break any of the three — a depth not derived from leaf count, a pop that
does not remove the newest leaves, an I13 evaluated before I10 — and the
current-depth read admits a proof whose layers exceed the tree it is
verified against. The Rust row records all three at the rule; the
height-keyed depth read (**Q8**) removes the dependence on (3) entirely,
which is why it is the default.

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
the C++ gate is deleted, and by whom, is the C++ lane's question.

**Two of three annotations wrong makes the annotation unreliable wherever
it appears, so the correction is a sweep, not two cells.** Every
`FAKECHAIN` mention in the census, and every `m_nettype … FAKECHAIN` gate
in the consensus C++ (`blockchain.cpp`, `cryptonote_core.cpp`, `tx_pool.cpp`,
`tx_verification_utils.cpp`, `blockchain_db/`), read at `4dc5194de`:

| Where | What the annotation says | What the code does | Verdict |
| --- | --- | --- | --- |
| CEN-I2 `:458` | "the FAKECHAIN carve-out … exempts this row" | the `else` at `:3539` refuses a non-FCMP tx on every nettype | **wrong** — behaviour does not vary; correct in the docs commit |
| CEN-I3 `:459` | "FAKECHAIN exempt" | `ver_non_input_consensus :74` bounds the version on every nettype, at both sites | **wrong** — correct |
| CEN-I4 `:460` | "FAKECHAIN exempt" | `FCMP_MAX_INPUTS_PER_TX` checked only at `:3405`, inside the gate | **right** — the one live rule-71 branch on the transaction path |
| CEN-B5 `:339` | "FAKECHAIN skip retired 2026-09-05 (PR #623)" | no gate at the B5 site (`:1396–1460` read) | **right** |
| CEN-D3 `:358` | env override | `:498–505`: the `SEEDHASH_EPOCH_*` lever **refuses to run** off fakechain | right — fail-closed *toward* the public network; a lever, not a rule branch |
| CEN-H15 `:440` | (slice 5's correction) | unconditional at `:3550` and `tvu:223` | right |
| CEN-I12 `:468` | "the in-code FAKECHAIN comment states a consequence" | comment only | right |
| §10 R8 `:684` | "CEN-I2's carve-out block, CEN-B5's skip, CEN-D7, CEN-D3's env override" | I2's block is really I4's (above); B5 retired; D7 is `RuleSet` data in Rust; D3 fail-closed | one item mis-attributed (I2 → I4) — correct |
| `blockchain.cpp:312`, `:498` | — | settlement-epoch and seed-epoch overrides refuse on public networks | levers, fail-closed — not rows |
| `:341`, `:348` | — | hard-fork table construction | data, not a check |
| `:392` | — | `m_db->fixup()` skipped on fakechain | store maintenance, not consensus |
| `:2625` | — | `get_output_distribution` start height | RPC, not consensus |
| `:4710` | — | `regtest_inject_archival_serve_credit` refuses off fakechain | test lever, fail-closed |
| `cryptonote_core.cpp:269/478/517/627/1655` | — | init-time levers and the pool's fakechain flag | E5's to read when the pool lands; none is a validation branch |

So on the whole consensus surface **one** nettype-conditional *behaviour*
remains: I4. The census's two false annotations and §10 R8's
mis-attribution are corrected in this slice's docs commit; the sweep is
recorded here so the correction is checkable against these lines.

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

## 5. Commit plan — Round 1 (2026-09-24), capture first

On slice 4 Q7's rule — rules first, shared substrate where the rules need
it, anything cross-lane last — **reordered by Q1's ruling: the vectors are
commit 1**, so every commit built on them exercises them, and a fixture
bug and a verification bug are never in the same commit. *Records-was:*
the Round-0 sketch had the eleven stateless rows first on filler fixtures
and the vectors sixth; that ordering was ruled out as producing one commit
doing two things.

| # | Commit | Gate |
| --- | --- | --- |
| 1 | **The captured chains** — **blocks, not transactions** (§5.2). For each of the five shapes — 1-in/1-out, 1-in/2-out, one bond post and one emission with a fee spend each, one depth-3 — the regtest chain the generator produced, from genesis through the block that carries the spend, committed as `.block` blobs under `rust/shekyl-chain-ingest/tests/vectors/<shape>/` with a manifest naming the spend's txid, its `referenceBlock` height and the shape; generated once through `e2e_fcmp_spend_accepted_by_daemon` / `e2e_fcmp_spend_over_depth3_tree` against a daemon built at the landing tree. **The consumer of record is `shekyl-chain-ingest`**, which replays every chain through `form` → `validate` → `connect` against a real `redb` store — the root at `ref_height`, the spent set, the tree depth are *derived* by the code that derives them in production. The rules crate reads the same blobs for its predicate tests (`fixture::spend` / `listed` load the transaction out of its block); the store's `spend(ki, outputs)` becomes a loader; the fixture-sanity gate says which builders moved | **Q1 (ii)** — if the capture is another lane's or slow, WAIT here; do not fall back to filler |
| 2 | Stateless 4.I rows in `tx_form`: I1, I4, I6, I8, I9, I14, I16; I5 with H10 kept as its equality row (Q4 (a)); each with its negative fixture at both sites, mutated from a captured spend | commit 1 — the seven self-arming conformance arms for these rows fire here; H24's falsifier flips here |
| 3 | I19/I20 adopted: `tx_form` calls `check_tx_extra_shape`; **`TxScope::Coinbase`** minted for I20 with its doc pinning *runs at `Miner`*, never *when `is_coinbase()`*; `the_kind_is_derived_from_the_slot_not_the_bytes` gains the I20 case (Q6) | commit 1 |
| 4 | `TxAgainstRule` (view-bound, `check(cx, view)`); I7 over `has_key_image`; I2 and I3 registry entries `by_construction`, list-and-iterate (Q3) | commit 1 |
| 5 | `ChainView::height_of` (this slice adds it; the store has it, `MockChain` gains it); I10, I11 (consts 5/100 pinned to `consensus_constants.json`, Q5), I12 as a definition recorded at derivation | commit 1; the trait change disclosed to E5 and the store lane |
| 6 | I13 over **depth at `ref_height`** | **E3 S-CURVE** — the one gating relationship (Q2 + Q8): the height-keyed depth read is E3's method; if E3 cannot serve it, current-depth with the three §3.3 dependencies written **at the rule** |
| 7 | I17 as **(c)**: the wire's `pqc_signing_payload_hashes` becomes the one derivation; the daemon calls it through a coarse FFI (`shekyl_tx_pqc_signing_payloads`, TXE's shape); **byte-identity gate first** — real transactions through both the C++ assembly and the Rust body, identical payloads required, multi-input and serve-credit shapes included (the `mining_parity` pattern) — then `tx_pqc_verify.cpp:62–158` becomes the call (Q7) | commit 1 (the shapes come from the vectors); touches `src/cryptonote_core/tx_pqc_verify.cpp` and `shekyl-ffi` — rule 20's minimal shim |
| 8 | I15 over `shekyl_fcmp::proof::verify`; I18 over `shekyl_crypto_pq` through I17's payloads; H19's verification half as a **`validate` fold** over the block's BP+ proofs (Q9), if the captured contexts carry ≥ 2 spends per block — else a named successor, disclosed at commit 1 | commits 1, 6, 7 |
| 9 | Conformance table: re-check the dead-arm ordering (`key-image input(s) but no prunable proof`) now that verification sits in the path; I19's arm | commit 8 |
| 10 | Docs: census 4.I re-pinned at the landing tree (read, not diffed); the FAKECHAIN corrections from §3.4's sweep (I2, I3, §10 R8); `CHAIN_RULES_CRATE.md` §4.3 (`height_of`), §4.6 (`TxAgainstRule`, `TxScope::Coinbase`); index; FOLLOWUPS (the capture row closed; the I17 shim finding); CHANGELOG | — |

Ten commits is the rule-06 ceiling. If commit 6 waits on E3 past the
slice's window, it is the one named successor; nothing else in the plan
depends on it.

### 5.2 The witness is the real chain, and the mock has a two-line charter (ruled 2026-09-24)

The Round-0 draft had `MockChain` *serving* the captured block context —
`root_at(ref_height)` handed the captured root, the spent set handed the
captured images — and the verification rows fixtured against that. The
review named it for what it is: **not a weaker witness but a false test**.
A mock told a value and serving it back proves the rule reads what it was
handed; a proof verified against a root nobody recomputed says nothing
about whether the store would compute that root, whether the leaf is in the
tree, or whether production would accept the spend. Now
`50-testing.mdc`, *"A fixture that constructs the state a rule reads back is
not a test of the rule"*, with this slice as the instance.

**So, for every view-bound and verification row (I7, I10–I13, I15, I17,
I18, H19-verify):**

- **The witness is the ingest replay.** `shekyl-chain-ingest` connects the
  captured blocks against a real store; `tx_against` reads the derived
  state through `BatchView`; I15 verifies a real proof against a root the
  test derived over a membership set that exists because blocks put it
  there. Positive fixture: the captured spend connects. Negative fixtures:
  **mutations of the captured transaction replayed the same way** — the
  spend re-submitted after its block (I7), a `referenceBlock` not in the
  chain (I10), one 6 blocks too young and one 101 too old (I11), a
  `tree_depth` above the tree's (I13), one flipped byte in the proof (I15),
  one in the signature (I18), one in the range proof (H19). Every one goes
  through the production path with production state.
- **The rules crate's own fixtures are not parity evidence** for these
  rows, and the crate's doc has said so since increment 1. They keep
  exactly the two jobs the rule allows: predicate logic on plain values
  (I11's window arithmetic at its four boundaries; I5's ordering; I12's
  *derivation* being recorded), and the faulting view (a store fault
  propagates as `Fault`, never as a verdict). `MockChain`'s doc comment
  carries this charter so a third job cannot be added without editing the
  sentence that forbids it.
- **The store's twin-chain conformance test stays**: its subject is the
  mock's fidelity to `BatchView`'s read API, not any rule.

This is why commit 1 captures **blocks** and puts the vectors in the
**ingest** crate: both witnesses derive from one artifact, and the artifact
is the thing production consumes. The rules crate depending on the store
would violate G1 (`check_chain_rules_no_store.sh`); the ingest crate
depends on both and is where the real chain is allowed to live.

**What commit 1 actually built (2026-09-24), and two limits it carries.**
The artifact is not a layout minted for this slice: it is **the DRS-E2
replay pair**, produced by E2's own tools driven from the generators —
`shekyl-chain-replay fetch` for `corpus.e2` (every block and every listed
transaction's full bytes, RD-F15-verified against the headers) and
`shekyl-e2-trace-export` for `trace.e2` (the per-block facts and the
daemon's logical-state digest at the tip, one LMDB snapshot taken while the
daemon is alive, because the harness deletes the data dir on drop). Beside
them, `txs/<txid>.tx` — each listed transaction's bytes — for the rules
crate, which may not read the corpus (G1) but may read a real transaction
and mutate one field. `shekyl-chain-ingest/src/vectors_tests.rs` replays
every captured chain through `pipeline::run` — the same composition the
replay binary makes — against a fresh `redb` store and holds the store's
digest to the daemon's; **fails on an empty vector set** (rule 47). First
result: `spend-1in-2out`, 82 blocks connected, digest MATCH, 46 rows
exercised.

- **Limit 1 — the root is a passed-through fact until E3.** The trace's
  `root_after` per block is the C++ daemon's; the Rust store persists and
  keys it (`root_at`) but does not yet *derive* it — that is E3 S-CURVE's
  writer. So for I12/I15 today the replay witnesses *parity with the
  daemon's root*, not an independent derivation. That is E2's design
  (replay C++-accepted blocks; grade disagreement), and it is one level
  better than the mock — the root is a real tree's, computed by production
  code, over the membership set the blocks created — but it is not the
  end state, and this sentence is what says so. E3 landing the writer turns
  the same test into the independent witness with no change to it.
- **Limit 2 — the default lane mocks exactly one thing: CEN-D2's hash.**
  RandomX light mode is ~0.6 s a block; the depth-3 chain is ~750 blocks.
  `every_captured_chain_replays_and_matches_the_daemons_digest` runs under
  `MockSubstrate` with the **real clock** (the mock's 2023 default refused
  block 1 on C1 as future-dated — caught on the first run) and the
  always-satisfying longhash. D1/D2 are not this test's subject; their
  witness is the `#[ignore]`d `replays_every_captured_chain_under_the_production_substrate`
  in the live lane and E2's own gate. Every other row a chain exercises is
  judged against real state under both.

**Commit 1 is split in two, disclosed here (rule 22: a split re-schedules
inside the PR).** 1a — the vectors, the capture hook, the ingest witness,
`MockChain`'s charter (landed `6fd74abee`, `231132849`). 1b — *as first
planned*, the fixture migration: builders become loaders over `txs/*.tx`.
**That plan was measured before it was written and found to have the wrong
shape (§5.3): a captured spend is valid only in the chain it came from, so
"loader" is not a thing; and the question underneath — what happens to
every test that runs `validate` over a filler spend once verification
lands — has an answer that is not a fixture at all.**

### 5.3 The driver — 1b redefined (RULED 2026-09-24)

**The measurement.** 121 `spend(`/`listed(` sites across 19 files in three
crates. On a `validate`/`connect` path — where I15/I18/H19-verify will
refuse filler — sit the store's `connect_fixtures.rs` (which calls the real
`validate`; 42 sites across `read_tests`, `output_read_tests`,
`amendments_tests`, `pop_tests`, `connect_tests`), the ingest's
`pipeline_tests`/`mutation_tests`/`corpus_tests`, and the rules crate's
`refused_listed` and positive controls (52 sites). About fifty tests in two
other lanes' crates, whose subjects are SI rows, pops, sequencing and
grading — none about proofs. Four dispositions were tabled: (A) stop
using spend-bearing blocks — impossible where the subject *is* a key image;
(B) replay captured chains under those tests; (C) a knob that skips proof
verification in tests — **refused**, it is `m_nettype != FAKECHAIN` in Rust,
the pattern §3.4 just enumerated for deletion; (D) land verification last
and let that commit carry the cascade — what the plan did implicitly while
hiding that the cascade is fifty tests.

**The ruling: none of the four.** All four are downstream of a premise
nobody stated — that a test fixture is *constructed*. Accept that and
every path is a variation on making the construction pass the rules: a
loader, a replay of someone else's construction, a knob, or waiting for
the rules to notice. That is the Monero paradigm — the thing under test
becomes the apparatus — and (B) is it in better clothes: replaying a
captured chain still consumes an artifact rather than driving the
machinery. **We are not transcribing the C++; we are rewriting it.** What
exercises production is a **scripted driver**: *mine N blocks; build a
spend of this shape; submit; mine; reorg two deep; submit again* — the
blocks from the block producer, the transactions from `shekyl-tx-builder`,
validation from `validate`, storage from `connect`. No fixture exists; the
test names a scenario and the production path produces the state. Where
it stops being possible is the genuinely unreachable state — a torn
commit, a corrupt row, a fault the substrate cannot be asked for — which is
exactly `50-testing.mdc`'s second carve-out, the same boundary.

**Can it be driven in-process, with no daemon?** Yes — read at source, the
machinery is mostly there, and the two gaps are production code:

- **Have:** spend production end to end — `shekyl-wire/tests/fcmp_spend_e2e.rs`
  builds a real depth-3 tree through the production `CurveTreeClient`,
  assembles a path through `assemble_path`, signs through
  `shekyl_tx_builder::sign_transaction`, verifies through
  `shekyl_fcmp::proof::verify`, `shekyl_ct_balance`, `Bulletproof::verify`,
  serializes to a `Transaction` — in seconds. Validation and storage:
  `form`/`validate`/`connect`. PoW: regtest fixed difficulty 1, every hash
  satisfies; `ProductionSubstrate` or the real-clock mock, per test, stated.
  Tree state: `shekyl_curve_tree` derives roots and layers in Rust.
- **Gap 1 — no Rust block template.** `construct_miner_tx` /
  `create_block_template` are C++. **This is TXE-F8** ("the block template
  has no Rust owner"), already recorded; the driver is the first consumer
  that makes it claimable. Every piece is Rust already —
  `shekyl_economics` (reward, emission split, fee burn),
  `shekyl_crypto_pq::output::construct_output` (the coinbase output the
  C++ calls through `shekyl_construct_output`), `build_coinbase_extra`,
  the wire types; nothing composes them.
- **Gap 2 — `ConnectFacts` derivation.** `connect` takes `Fact<_>` with
  `Origin::{Derived, PassedThrough}`; today `root_after`,
  `coins_generated`, `burned` and `long_term_effective_median` are passed
  through from the C++ trace.

**Placement, ruled.** Gap 1 → a **new crate, `shekyl-block-template`** —
named for what it is in production, `create_block_template`'s successor,
not for the test that forced it. *Not* in `shekyl-tx-builder`: that crate
is wallet-side and signs with wallet keys; template assembly is
daemon-side, and a coinbase has no inputs, no signature, no wallet keys —
the only overlap is "fills a wire structure," which is the wire's job. The
coinbase and the header assembly both live here, because they are one
function in C++ for a reason: the header's `curve_tree_root` and the
coinbase's outputs are computed against the same height and context.
**Store-free by construction** — it needs height, `prev_id`, the root,
the median, `already_generated_coins`, all chain facts, all supplied by
the caller in a context struct, none read: pure over inputs, no
`shekyl-chain-store` edge, no `redb` in its graph, gated by the same cargo
tree check as `shekyl-chain-rules`. Three named consumers at birth: this
driver now; `get_block_template`'s Rust handler when the RPC moves; the
built-in miner when it moves. TXE-F8's row becomes this crate's row.

Gap 2 → **the composition belongs to the caller, and the store computes
nothing.** C2-R8 decides it: the store persists consensus facts computed
by consensus-owned functions inside the write transaction; it never
computes one. `Fact<Derived>` means the value was derived *by its owner*,
not that the store derived it — putting the derivation in
`shekyl-chain-store` would make the store the owner, which is the
prohibition, and E3 landing the curve-tree writer persists what
`shekyl-curve-tree`'s grow returns; it does not compute the root in the
store (that would be `blockchain_db.cpp:663`'s fusion rebuilt in Rust, the
single thing the ruling exists to prevent). So: each fact from its owner —
`root_after` from `shekyl-curve-tree`, `coins_generated` and `burned` from
`shekyl-economics`, cumulative difficulty from D4 in `shekyl-difficulty`,
`long_term_effective_median` from wherever G6 lands in slice 7 — and the
driver assembles them **once**, handing the same assembly to the template
builder as context and to `connect` as `ConnectFacts`. One composition,
two consumers. That is S-ARCH's Q4 answer one layer up (primitives only;
composition is the caller's), and it makes the driver honest about what it
proves: a scenario exercises four owned derivations, not the store against
itself.

**Cost.** Proving a spend ≈ 1–2 s; a depth-3 tree from scratch, seconds;
mining at difficulty 1, nothing. A scenario is seconds; fifty tests sharing
a handful of driven stores is under a minute. Pay it *differently*: drive
a scenario once per shape, let many assertions share the resulting store,
keep the frozen corpora (§5.2) for the cases where a **specific historical
chain** is the subject rather than a shape — and keep the daemon-backed
`regtest_e2e` as what it is, the parity witness that the C++ *accepts* what
the Rust built.

**1b is therefore:** `shekyl-block-template` (TXE-F8 claimed); the
scenario driver over the production stack in `shekyl-chain-ingest`, with
the facts composed from their owners; this slice's own rows landed on it.
The store's and ingest's ~fifty tests migrate to **scenarios, not
replays**, owned by their lanes, the FOLLOWUPS row pointing at the driver.
I15/I18/H19-verify wait on that migration either way; the difference is
that what they wait for is worth having afterwards.

#### 5.3.1 The crate — landed (2026-09-24), and what its tests do by design

`rust/shekyl-block-template` is `build(&TemplateContext) → Template`: pure
over the context, store-free (held by `check_chain_rules_no_store.sh`,
which now names both crates), composing the owners — `construct_output`
and `build_coinbase_extra` for the coinbase, `paid_block_reward` →
`compute_emission_split` + `compute_fee_burn` for the amount, the reward
priced at the block weight *including* the coinbase (a fixed point in the
coinbase's own varint, sought in at most ten passes — the C++ `try_count`
budget, `blockchain.cpp:1830`). The header's timestamp is
`max(now, median + 1)`: the least C2 admits, no earlier than the clock —
**and checked against C1's bound with the rule's own predicate**, not
reasoned about (review, 2026-09-24: the one property the builder argued
instead of asserting; the condition is reachable — a window stamped near
the limit carries a median ahead of when its blocks landed, and a
behind-clock producer finds `median + 1 > now + FTL`. The builder now
refuses first, and `the_builders_c1_refusal_is_the_validators` constructs
the chain and shows the same header refused on C1 by a behind clock).
`nonce` is zero — the template is what the miner searches.

**The re-pricing's one non-convergence, answered (review question).** Is
there a reachable weight that fails to settle? Yes, exactly one shape: in
the penalty zone, a reward sitting on a varint boundary `2^(7L)` such that
the amount priced with an `(L+1)`-byte coinbase encodes in `L` bytes and
the amount priced with an `L`-byte coinbase encodes in `L+1` — a two-cycle
with no fixed point, which no pass budget resolves. It is constructed in
`a_reward_exactly_on_a_varint_boundary_in_the_penalty_zone_is_refused_not_looped`:
at `2^35` with a ~317 kB block against the 300 kB zone the band of
`already_generated` is ≈`4.0e10` atomic units wide (about one block's
emission late in the curve), and one unit either side of it the loop
settles. The C++ fails the same band at the same budget (its comment names
the case), so this is a builder refusal both producers share, not a
divergence — and the budget is pinned to the C++ figure
(`MAX_REPRICING_PASSES = 10`) so it stays one.

**Is the band a wall? (review, 2026-09-24).** The band is a function of
supply *and* weight, so the question was whether, at a supply inside it,
*every* weight fails — no template, no block, `already_generated` never
advances: a liveness stall. It is not. The same test holds the supply
inside the band and sweeps every body weight in the penalty zone with the
owners' arithmetic: at a fixed supply the amount still falls with weight
at ~10⁶ atomic units per byte, so it crosses each varint boundary in a
window about one byte wide — **3 of 300 000 body weights cycle**, and the
nearest settling weight to the constructed one is **one byte** away. The
test then *builds* at one spend fewer and one spend more and both settle.
The refusal means "build a different body", which a producer does on the
next template; nothing further to say.

The second question the slice asks — *what should our Rust test do by
design?* — is answered in the crate doc and its `tests.rs`, and the answer
is **the validator is the falsifier**: a template is judged by `form →
validate` on a harness chain, and the test asserts that every landed 4.F
row (F1, F3, F4, F5, F6, F7, F9, F10) and the header rows it satisfies
from the tip's facts (A2, B1, B5, C1, C2) appear in the coverage record —
so a row that stops judging the template fails the test, not only a row
that refuses it. What the validator has not landed (F18 over F13–F17/F20,
pending G6 at slice 7) is stated as the identity it will falsify: the paid
amount equals the owners' split on the template's own reported operands.
The remaining tests are the design's own clauses, not C++ behaviour: one
`txin_gen` at the connecting height and one output; `unlock = h + window`;
the extra is the I20 grammar and names `r·G`; wire round-trip; purity
(same context → same bytes; a different `r` → a different one-time key and
the same amount); the priced weight is the carried weight; and refusals
that are caller conditions (a body without a fee is not listable, an
inconsistent supply record, an unlock that overflows, a KEM key the
construction refuses) rather than consensus verdicts. Byte-parity with
`create_block_template` is the daemon-backed `regtest_e2e`'s job, as §5.3
says — not this crate's.

#### 5.3.2 The driver's two shape rulings (RULED 2026-09-24)

`connector.rs:285` takes `ConnectFacts` from the trace (`NoFacts`
otherwise); a scenario driver needs a second provider, and the ruling on
where it lives and how it is driven:

- **Facts seam — `Composed` is production, not test support.** By the
  argument that redefined 1b: written as test support it is a second
  implementation the daemon redoes; written in production and called by
  the driver it is the boundary advancing. `Composed` is the composition
  live ingest will use — facts assembled from their owners
  (`coins_generated`/`burned` from the template's priced figures via
  `shekyl-economics`; `long_term_weight` from `shekyl_economics::
  long_term_weight`; `root_after` passed through until E3 S-CURVE writes
  the tree, §6; the median passed through until G6). It lands in
  `shekyl-chain-ingest` beside the connector with the driver as first
  consumer; E3 then flips one field's `Origin` from `PassedThrough` to
  `Derived` inside a function that exists, instead of promoting test code.
  `Trace` is E2-only and lives with E2's harness. Two impls, one seam.
  **Disposition: STAGED (rule 23)** — `Composed`'s production consumer is
  E3's live ingest; its consumer today is the scenario driver (landed,
  §5.3.3). **Falsify by:** `rg -n 'Composed::new' rust --glob '*.rs'`
  returns a caller outside `#[cfg(test)]` / `*_tests.rs` — checked when
  E3 lands; if E3 lands and this still returns only the driver, the seam
  was not the boundary advancing and this row reopens.
  **Landed:** `shekyl-chain-ingest/src/facts.rs` — `FactsFor` (one
  method, read against the batch view the verdict was judged on),
  `impl FactsFor for Trace`, `Composed<P: PricedAt>` with `Priced`
  {`block_reward`, `burned`, `root_after`, `long_term_effective_median`};
  `Connector<F: FactsFor>` (`ConnectorArgs::facts`), the pipeline
  instantiating `Connector<Trace>`. `Composed` folds the parent's
  `coins_generated` through `advance_already_generated` and clamps
  `long_term_weight`; it **does not re-derive the emission** — F13/F15/F20
  are landed definitions whose value stays off the verdict until F14b by
  ruling (`CHAIN_RULES_SLICE_4.md` §4), and a second copy in ingest is the
  duplication the seam prevents. Every origin is `PassedThrough` and a
  test pins that per field, so the flip is visible when a row lands. All
  four captured replays connect through the seam unchanged.

  **Why the labelling matters (review, 2026-09-24):** `Derived` is what
  `Provenance::is_parity_evidence` trusts. Marking a self-computed field
  `Derived` would let a driver-built store claim parity evidence for a
  field no rule judged — so the operational definition ("the validator
  derived it") is load-bearing, not bookkeeping. **And `PassedThrough` now
  folds two distances from done into the E6 counter**
  (`Provenance::passed_through`): a field *composed* here — a provisional
  source that becomes a deletion when its row lands — and a field with
  *no source yet*, supplied by the caller exactly as the trace supplied
  it. Not worth a third variant; worth the per-field test recording
  which is which, so the count decomposes: **4 composed** (`weight`,
  `long_term_weight`, `coins_generated`, `burned`) **+ 2 unsourced**
  (`root_after` until S-CURVE grows the tree; `long_term_effective_median`
  until G6). Read "six passed through" as that, not as six unsourced.

  **The `coins_generated` fold is thinner than it sounds, and that is what
  makes it safe:** parent's record + the producer's priced reward, through
  `advance_already_generated`. The reward came from the template, which
  got it from `shekyl-economics`; the only ingest-local logic is the
  addition. One source, one owner, one `+`. "Ingest computes
  `coins_generated`" reads like a second implementation and it is not —
  that reading is exactly what the seam exists to prevent, so it is
  named here before someone makes it.
- **One event at a time — and the reason is the miner's, not the
  sequencer's.** Template generation *is* serial: a miner cannot build
  `h+1` until `h` is connected. The driver models that path faithfully;
  teaching the sequencer a synchronous source would make it less like
  production. **What this does not cover, stated:** the driver exercises
  `form → validate → connect` and deliberately *not* the sequencer's
  lookahead — replay-with-a-trace covers that. Two instruments, two
  subjects; scenario coverage is not ingest-end-to-end coverage, and the
  driver's doc says so.

#### 5.3.3 The driver — landed (2026-09-24), and the third gap

`shekyl-chain-ingest/src/scenario.rs` (test-only in ingest for now; a
`scenario` TEST_ONLY feature lands with the first cross-crate consumer,
the store's fixture migration). `Scenario::open(name)` → `mine(n)`,
`mine_listing(txs)` (a refusal is data), `rewind_to(h)`, `facts()`,
`close()`. Each block: ask the connector what the chain is → price a
coinbase with `shekyl-block-template` → `form` under a driver-owned clock
(`Clocked<P>`, 120 s per block; the free longhash by default, real RandomX
under `Clocked<ProductionSubstrate>` — the `#[ignore]`d twin mines under
it in 17 s) → `Apply` through `Connector<Composed<Ledger>>`, the ledger
answering `PricedAt` from the template. Its own tests: six blocks, every
one judged by the eight landed 4.F rows and A2/B1/B5/C1/C2; the record is
the fold of what the templates priced; F20's window and C2's median read
back as the producer expects; a rewind to 2 pops two, mining resumes on
the new tip with the fold restarting from block 2. **One event at a time**
and the doc says what that does not cover (the sequencer's lookahead —
replay's subject).

**The third gap, as predicted.** Two gaps were measured (template,
facts); writing the driver surfaced a third, and it is production: **the
producer's read path** — what the chain *is*, read on the view the
validator judges against and through the validator's own definitions. It
landed as `Connector`'s `TemplateFacts → ChainFacts` message (tip, root at
the connecting height, parent's emission, total burned, F20 window, C2
median — inside one write closure so the view is the `BatchView` the rules
read) and three producer-facing exports from `shekyl-chain-rules`:
`tx_volume_window` (F20's definition, now two-position: view fault outer,
`Corrupt::TxCountNotMonotone` inner, so no caller matches a stale arm that
cannot occur), `mtp_median_at` (C3's padded median) and
`EMISSION_SPLIT_EPOCH` (F21). Each is public for one stated reason: the
producer prices at the operands it will be judged by, read from the
definition, not a second copy. That is `get_block_template`'s read path
in the shape E3 will serve it — more production than the measurement
found, which is the signal the framing was right.

**Placeholders, each named at the line that sets it:** `root_after`
(S-CURVE grows the tree), the effective median weight and the long-term
median (G6, slice 7), the frozen-segment count (E4). Each is the caller's
pass-through exactly as the trace supplied it.

**The `unreachable!` finding — raised above a FOLLOWUPS row on review, and
acted on (2026-09-24).** The count reported here was four; the review's
was nine, and reading every site gave a different picture in both
directions. `difficulty.rs` `const ONE`'s bare arm is compiler-proven (a
const item; if reachable the crate would not build — the strongest
argument available, needing no message). `miner.rs::priced` has the
analysis written at the site and is the in-tree standard: *a `unreachable!`
in the validator is a panic a peer can trigger unless the argument is the
type or the compiler.* **Four were SI-7-deferred** — `match view.block_at(h)?
{ Recorded(b) => b, AboveTip => unreachable!(…) }` at `rules/mod.rs::recorded`,
`pow.rs` D3's seed read, and `timestamps.rs` C3's genesis and window reads
— each arguing "the store would have faulted first". That is a store
invariant defending a validator panic: refusing and dying are different,
and the validator's job is the first. The taxonomy already had the answer
one layer up (`Fault::Corrupt` halts the writer, never a verdict), so the
four now raise **`Corrupt::HoleBelowTip { at }`** through a narrower
`ViewRead<VF> { View, Corrupt }` — no stale arm for a definition to match —
and `a_hole_below_the_tip_is_the_halting_fault_not_a_panic` constructs the
SI-7-breaking view (`HoleyView`: tip says four, `block_at(2)` says
`AboveTip`) and pins the fault at C3, at `validate`, and at the producer's
`mtp_median_at` (inner position). CHANGELOG carries it as
security-relevant. **Three remain**, none remote-reachable, in FOLLOWUPS
with the type fix named: C2's `Option<MtpWindow>` in the context
(structural — the fix is the type, not the arm), and two local-construction
bounds a `BoundedWindow` would carry.

**Carried, not done here:** slices 2–4's view-bound rows (the D family's
windows, B5's root, E1's anchors) have fixtures of the same shape against
`MockChain`, with ingest-side replay coverage in some places and not all.
That is an audit of the earlier slices, filed in FOLLOWUPS with the crate
contract as owner, so it is chosen rather than found.

## 6. What this slice does not build

- **The pool.** `tx_against` takes any `ChainView`; E5's decorator is E5's.
- **CEN-L1** (the store's own spent-image check at connect) — the store's
  belt, already landed; I7 is the validator's rule.
- **Curve-tree state.** I12/I13 *read* the tree; E3 S-CURVE writes it.
- **C++ deletions.** The FAKECHAIN gate (§3.4), the C++ payload assembly
  (§3.1) — retired with E4, not here.

## 7. Round log

- **Round 0** (2026-09-23): pre-flight written at `4dc5194de`; every pin
  read at the line; nine questions. Amended on review (`ca218306c`): the
  monotone-depth argument refuted at source (`trim_curve_tree` shrinks
  depth), the FAKECHAIN sweep, Q7(c), Q1's scoping call.
- **Round 1** (2026-09-24): Q1–Q9 RULED, recorded on each question below.
  Q9 was ruled on a structural argument the reviewer flagged as possibly
  missing the second option; §8 Q9 says what the second option was and why
  the structural argument covers placement but not sequencing.

## 8. Questions for the reviewer — Round 0

- **Q1 — the capture gate (§1.2), and the scoping call under it. RULED 2026-09-24: reading CONFIRMED (the row's purpose is that verification cannot be *tested* without real proofs; a document planning verification is not the thing needing vectors); scoping (ii), CAPTURE FIRST — and the deciding argument is not the day-or-not. (i) produces one commit doing two things, and one of them — migrating spend fixtures across three crates — has revealed something every time it has happened this month (H5 caught coinbase bodies, H19-layout caught skeletons, H7/H11 caught filled points); a commit that migrates fixtures AND lands verification makes a fixture bug and a verification bug indistinguishable at review. (ii) also has the vectors exercised by every commit built on them rather than only at the end, and the `spend(ki, outputs)` redesign is not extra cost — I15 binds the image to the output through the proof, so captured values were always coming. If the capture is another lane's or slow, that is a reason to WAIT, not to fall back to (i).** The
  reading first: the FOLLOWUPS row's "pre-flight does not open" is taken
  to gate the *verification commits*, not this document — a narrowing of
  the row's plain text, disclosed as such; confirm or refuse. Then the
  owner: the generator is `shekyl-engine-core`'s regtest, the consumer is
  this crate's `tests/vectors/`; default, this lane runs the generator and
  commits the blobs in a test-data-and-harness-only commit, the engine lane
  told. **Then the scoping call that is easier now than after commit 5.**
  Landing the eleven stateless rows on filler fixtures (commits 1–5) is
  safe today and *guarantees* that I15/I18/H19-verify later reject every
  spend fixture in three crates at once — the cascade slice 5 §5.1 named.
  Two shapes: **(i) split** — commits 1–5 land now on filler, the vectors
  and 6–7 land as one atomic fixture migration behind them (possibly a
  second PR); the cost is one very large commit that does two things
  (migrate fixtures, land verification). **(ii) capture first** — the
  vectors land as commit 1, every fixture builder loads them from the
  start, and the stateless rows land on real spends; the cost is that
  nothing in this slice lands until the engine-side generator has run,
  and a `spend(ki, outputs)`-shaped API is redesigned before the rows that
  do not need it. Default **(ii)** if the capture is this lane's and takes
  under a day; **(i)** if it is another lane's or the block-context
  serving in `MockChain` (§4.3) turns out to be the larger design. State
  which.
- **Q2 — the view contract (§1.4). RULED 2026-09-24 with Q8 as ONE dependency, not two: `height_of` in commit 4; depth-at-`ref_height` as I13's operand; both put I13 behind E3, recorded as a single gating relationship rather than two rows naming the same lane.** `ChainView::height_of(&BlockHash)` and
  a tree-depth read are contract changes to `CHAIN_RULES_CRATE.md` §4.3 and
  every implementer. Which lane lands them, and is the depth read
  height-keyed (Q8)? Default: this slice adds `height_of` (the store
  already has it; `MockChain` gains it) in commit 4; the depth read is the
  E3 lane's method and I13 waits on it.
- **Q3 — I2, I3, I4 (§3.4). RULED default 2026-09-24, with slice 5's Q6 condition applying: I2's and I3's shared `by_construction` entries name every row they serve (`credited_to_this_falsifier`, the gate's list check) and fail when any stops being vacuous.** I2 subsumed by H15 plus the `Ct` type set
  (registry: `by_construction`, crediting H15's fixture and the type's
  falsifier, list-and-iterate); I3 by construction on `TX_VERSION` (H2/H13's
  falsifier, fourth row on the list); I4 a `tx_form` rule, unconditional.
  Default as stated.
- **Q4 — H10 into I5. RULED (a) 2026-09-24: the census has two rows, and collapsing them in the registry makes the registry disagree with the denominator; H10 landed with its own fixture, so (b) would retire an implemented row to tidy a predicate.** The C++ has one arm (`memcmp >= 0`) for "sorted"
  and "distinct". H10 landed as its own row in slice 5 (refuses the equal
  case). Options: (a) I5 refuses `<=` and H10 keeps its row as the equality
  sub-case — two rows, one predicate, recorded on both; (b) H10 is
  re-registered as subsumed by I5. Default (a): the census has two rows and
  a row is not deleted by a slice.
- **Q5 — the reference window's constants. RULED consts 2026-09-24 — the F21 test as slice 5's Q5; nothing varies 5/100 by schedule step.** `FCMP_REFERENCE_BLOCK_MIN_AGE`
  / `MAX_AGE` (5 / 100) come from `config/consensus_constants.json`. As
  `RuleSet` fields (the F21 shape, varying by schedule step) or as consts
  beside the rule pinned to the JSON (slice 5 Q5's shape)? Default: consts —
  no schedule step varies them, and the first that does is their first
  `RuleSet` reader.
- **Q6 — I20's stage. RULED 2026-09-24: `tx_form` with the new `TxScope::Coinbase`, and one thing PINNED in the variant's doc: `Coinbase` means *runs at `TxSlot::Miner`*, never *runs when `is_coinbase()`*. Slice 5's Q2 derived the kind from the slot precisely because a bytes-derived kind lets a coinbase-shaped submission exempt itself from the rows that refuse it; a coinbase-only scope is exactly where that could re-enter through the back door. `the_kind_is_derived_from_the_slot_not_the_bytes` gains an I20 case: a coinbase-shaped body at `Lone` is NOT judged under I20 (and is refused by the non-coinbase rows), and a non-coinbase body at `Miner` IS.** The coinbase grammar is judged at `Miner`. As a
  `tx_form` rule with a **new** `TxScope::Coinbase` (the enum has `All` and
  `NonCoinbase` today, `rules/mod.rs:320`; the first rule that is
  coinbase-*only*), or in 4.F's `form` stage beside F1–F10 as a `FormRule`?
  Default: `tx_form` with the new scope — it is a per-transaction rule on
  the coinbase's own bytes, judged where the other per-transaction rules
  are, and adding the variant is the enum doing what it was shaped for
  (rule 21: a variant with a caller).
- **Q7 — I17's body of record (§3.1). RULED (c) 2026-09-24, with a BYTE-IDENTITY GATE before the C++ assembly is deleted: replacing `tx_pqc_verify.cpp:62–158` with a call preserves consensus behaviour only if the Rust body emits identical bytes on real inputs. The spec vectors (`FCMP_SPEND_SIGNING_PREIMAGE.md:27–36`) pin the specification; they do not establish that two implementations agree on the shapes the e2e builds. TXE's `mining_parity` test is the pattern — feed real transactions through both, require identical payloads, then delete — and multi-input and serve-credit shapes belong in that test specifically, since those are where divergence could hide.** A signing payload is not a
  validation rule in its failure mode: a rule that diverges splits
  consensus; a payload that diverges makes **every** signature invalid,
  loudly, on the first spend — the e2e reds. So a conformance test (a
  second Rust copy held to a first) buys less here than it did for the
  wire twin. What divergence *can* do is hide on the shapes the e2e does
  not exercise — multi-input, serve-credit inputs, mixed archival — and
  then a class of transactions is unsignable until someone builds one.
  The question is therefore not detection but **which implementation is
  the specification**. Options: (a) promote the wire's
  `pqc_signing_payload_hashes` to the derivation of record and have I17
  call it; (b) a derivation in this crate, the wire held to it; **(c) one
  implementation in `shekyl-wire`, called by the wallet directly and by
  the daemon through the FFI — the shape TXE just landed for the
  `tx_extra` codec, in the same crate, with the coarse-call pattern
  (`shekyl_tx_extra_shape_of`) already built.** (c) removes the problem
  rather than monitoring it: the C++ assembly at `tx_pqc_verify.cpp:62–158`
  is *replaced* by a call, so there is nothing left to reconcile. Default
  **(c)**, with the spec's vectors (`FCMP_SPEND_SIGNING_PREIMAGE.md`
  `:27–36`) pinned on the one body, and the C++ side of the cut scoped as
  the shim's minimal marshaling (rule 20) — the E4 direction, taken one
  function early because this row's correctness is the reason to.
- **Q8 — I13's depth operand (§3.3). RULED 2026-09-24: depth at `ref_height`, one dependency with Q2. The default is right for the reason the re-derivation exposed: the three dependencies include an ORDERING one (I10 before I13), and ordering arguments are the class that has been wrong twice this month; height-keyed removes it rather than documenting it. If E3 cannot serve it, current-depth is acceptable — but then the three dependencies live AT THE RULE, not in this document, because the slice doc gets archived and the rule does not.** Current depth (C++ parity) or depth
  at `ref_height` (consistent with I12)? Default: at `ref_height` if the
  curve-tree lane can serve it, with the C++ reading recorded as a
  parity-not-divergence note; else current, with the monotonicity argument
  written at the rule.
- **Q9 — H19's verification half (§3.6). RULED 2026-09-24 on a structural argument: a batch verify is inherently multi-transaction and `tx_form` is per-transaction, so batching cannot live in `tx_form` without abandoning the batch or smuggling block scope into a per-tx rule — H19-verify's home is block-level. The reviewer asked whether that misses the second option. It does not miss it, because the second option was never about placement: both options placed the fold in `validate`; they differed on SEQUENCING — this slice (commit 7, if the vectors carry ≥ 2 spends per block context) versus a named successor after the vectors, owning the one-bad-proof-among-good fixture. The structural argument settles the home; the sequencing follows Q1's (ii): the vectors land first, so the ≥ 2-spends condition is decidable at commit 1, and the fold lands in this slice if it holds. If the captured contexts carry one spend each, the fold is a named successor, disclosed here, not a deferral found later.** In this slice as a `validate`
  fold over the block's proofs (one BP+ verify, the C++'s batch), or its own
  commit after the vectors with the one-bad-proof-among-good fixture?
  Default: this slice, commit 7, if the vectors carry ≥ 2 spends per block
  context; else a named successor.
