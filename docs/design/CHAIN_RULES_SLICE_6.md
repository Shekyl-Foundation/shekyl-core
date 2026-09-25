# `shekyl-chain-rules` slice 6 — census 4.I, the transaction's inputs under FCMP++ (DRS-E6 increment 7)

**Status:** OPEN — **Round 1 RULED 2026-09-24 (Q1–Q9, §8, each line-local);
implementation begins on §5 in the ruled order — capture first.** Round 0
pre-flight written 2026-09-23 against `dev` @ `4dc5194de` (post-#839, slice 5
landed), amended on review 2026-09-23 (PR #852, commit *docs: slice 6 Round
0 amended on review*). Registered before implementation (rule 94 §5).

Branch commits are named by PR and subject, never by SHA: the branch was
rebased once already and every SHA the first cut of this file pinned to
its own commits stopped existing (six, found 2026-09-24 — one of them in
the CSR-3a register, where the citation gate would have refused it). A
`dev` SHA is an era; a branch SHA is a promise the next rebase breaks.

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
| I1 | non-serve-credit tx has ≥ 2 outputs | `blockchain.cpp:3386–3394` (`check_tx_inputs`, before the nettype gate) | twin `:1982` (spend face; bond-post face `:2040`; at `dev@a1159f1a2`, re-read 2026-09-24 — `:1965` at `4dc5194de`), `:2010` (two arms, one row) | class + `outputs.len()` | `tx_form` |
| I2 | non-coinbase CT is `FcmpPlusPlusPqc` | `:3396–3403` **inside `m_nettype != FAKECHAIN`**; the `else` at `:3539–3544` refuses a non-FCMP tx on every nettype | — (H15 holds the `Null` half unconditionally) | `ct` type | **subsumed by H15 + the type set** — Q3 |
| I3 | version exactly 3 | `:3413–3426` inside the FAKECHAIN gate; `ver_non_input_consensus` `:74` unconditional | H2 by construction (`TX_VERSION`) | — | **by construction** (H2/H13's property, fourth site) — Q3 |
| I4 | `vin.size() ≤ FCMP_MAX_INPUTS_PER_TX` (8) | `:3405–3411` inside the FAKECHAIN gate — **the one row the gate genuinely exempts** | twin `:1859` (at `dev@a1159f1a2`; `:1843` at `4dc5194de`); `shekyl_fcmp::MAX_INPUTS = 8`; `cryptonote_config.h` `FCMP_MAX_INPUTS_PER_TX` (`:312` at `dev@a1159f1a2`; the census's `:311` was P0f's and one line stale when read) | `inputs.len()`, a const | `tx_form` — Q3 |
| I5 | key images strictly descending | `:3430–3450` (`memcmp >= 0` rejects) | twin `:1891` (at `dev@a1159f1a2`; `:1875` at `4dc5194de`); H10 refuses the equal case | `ToKey` images | `tx_form`; **H10 becomes I5's equality arm** — Q4 |
| I6 | `key_offsets` empty | `:3523–3529` regular; `:3472`, `:3496` archival co-resident | twin `:1881` (at `dev@a1159f1a2`; `:1865` at `4dc5194de`) | `ToKey.key_offsets` | `tx_form`; **flips H24's falsifier** |
| I7 | key image not spent on-chain | `:3531–3536` regular (`have_tx_keyimg_as_spent`); `:3478`, `:3502` archival; CEN-L1 re-enforces at connect | `ChainView::has_key_image` | view | `tx_against` |
| I8 | `pqc_auths.len() == vin.len()` (serve-credit: 0) | `:3560–3567`; `tx_pqc_verify.cpp:169` | twin `:2047` (at `dev@a1159f1a2`; `:2018` at `4dc5194de`); H20 holds the serve-credit zero; H21/H22 the archival counts | lengths | `tx_form` |
| I9 | `pseudoOuts.len() == inputs` (regular); archival subsets are H21/H22's | `:3569–3577` | twin `:2089` (at `dev@a1159f1a2`; `:2060` at `4dc5194de`); H18 reads them | lengths | `tx_form` |
| I10 | `referenceBlock` is a main-chain block | `:4113–4119` (`block_exists`, → `ref_height`) | — | **hash → height** (§1.4) | `tx_against` |
| I11 | `ref_height` ∈ `[chain_height − 100, chain_height − 5]` | `:4121–4141` (two guards; the `chain_height <` clauses are the genesis-window arms) | — | `ref_height`, `tip`; `FCMP_REFERENCE_BLOCK_{MIN,MAX}_AGE` from `config/consensus_constants.json` | `tx_against`; constants as `RuleSet` data or consts — Q5 |
| I12 | anchor = root **at `ref_height`**, read from the record never the header | `:4152` (`get_curve_tree_root_at_height(ref_height)`) | `ChainView::root_at` ✓ | view | `tx_against`, a **definition** row recorded at its derivation (D4's shape) |
| I13 | `curve_trees_tree_depth ∈ [1, depth]`; layers = depth + 1 | `:4162–4170` (`get_curve_tree_depth()` — *current*) | — | **tree depth** (§1.4) | `tx_against` — §3.3 |
| I14 | proof non-empty | `:4173–4178` | `Prunable::fcmp_proof` | — | `tx_form`; the wire's dead arm was this row's shadow |
| I15 | FCMP++ proof verifies over images, pseudo-outs, PQC key scalars, root, layers, signable hash | `:4181–4242` (scalars `:4192–4201`, verify `:4221–4234`) | `shekyl_fcmp::proof::verify`; `leaf::PqcKeyScalar` | proof, I12's root, I13's layers, **the signable hash** (§3.2) | `tx_against`, **behind the capture gate** |
| I16 | per-input auth structure: version 1, flags 0, scheme ∈ {1, 2}, solo key = 1996 B, multisig ∈ [3, 16384] | `tx_pqc_verify.cpp:176–215` | twin `:1947` (at `dev@a1159f1a2`; `:1930` at `4dc5194de`) (cap only) | `PqcAuth` fields; `PQC_HYBRID_SINGLE_KEY_LEN`, `PQC_MAX_PUBLIC_KEY_BLOB` | `tx_form` |
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
| CEN-I4 `:460` | "FAKECHAIN exempt" | `FCMP_MAX_INPUTS_PER_TX` checked only at `:3405`, inside the gate | **right** — the one live rule-71 branch on the transaction path. UPDATE 2026-09-24: the Rust rule landed unconditional (commit 2); the register row is DIVERGENT with identity-on-Fakechain as the failure, the census cell states both behaviours, and the cap's *value* is measured and owed a derivation (§5.4). UPDATE 2026-09-24 (#853 review): the measurement's ceiling corrected from the 1 MB parser bound to CEN-H3's weight limit — the cap binds ~2.75× (22 admitted), not 19× (153); the test's prefix hash now binds the `extra` the wire carries; `shekyl-tx-builder` const-asserts the prover's and the validator's caps equal |
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
| 2 | **LANDED 2026-09-24.** Stateless 4.I rows in `tx_form`: I1, I4, I6, I8, I9, I14, I16; I5 with H10 kept as its equality row (Q4 (a)); each with its negative fixture at both sites. Judged in three bands: the 4.H line (H1 first — the byte bound), then H20–H22 and H19's layout, then I1, I4, I5, I6, I8, I9, I14, I16. A transaction that fails its shape and an input-path row is named by the shape (a proof-less bond post is H21, not I1). That is the C++ caller's order (`ver_non_input_consensus`, then the BP+ layout, then `check_tx_inputs`), and it is the right one here for that reason — not because the caller is inherited. The input cap still precedes proof verification: I15 and the H19 batch fold run after `tx_form` returns. Commit 2's first cut had placed the I rows ahead of H20–H22 from `check_tx_inputs`' internal order; #853's review read the caller. The rows live in `rules/tx_inputs.rs`. I8/I9/I14 judge `TxClass::Spend`; the archival counts stay H20–H22's (the census names the split). I4 is **unconditional** (rule 71): the C++ gates it on `m_nettype != FAKECHAIN`, §3.4's one varying cell. I16's multisig floor is the container header (3); the exact parse is I17/I18's. **Fixture consequence, disclosed:** `fixture::listed` grew to two outputs and `pqc_auth_filler` to a 1996-byte solo key blob — the fewest I1 and I16 admit — and the store's 22 `spend(k, 1)` sites moved with it (two count pins moved by exactly the second output). The negative fixtures are mutations of the harness spend, not of a captured one: the captured spends are real and pass every new row through the ingest replay (the four vectors, unchanged); the "mutated from a captured spend" form waits on the loader that the scenario's real-spend commit brings | commit 1 — the seven self-arming conformance arms for these rows fire here (I9's trip re-cut to keep H18's balance, since the balance precedes the count here and in the C++); H24's falsifier flipped (`h24_cannot_fire_on_an_input_i6_admits` asserts I6 at both sites); the pruned-form bond-post arm with no outputs records H21 as its refusal (commit 2 wrote I1 here, reading `check_tx_inputs` alone; #853's review read the caller — `ver_non_input_consensus`'s arms run first, so a lone bond post never reaches the output count in the C++ either — and the twin's bond-post face of I1 is now a recorded divergence for the same reason), the C++'s order |
| 3 | **LANDED 2026-09-25.** I19/I20 adopted in `rules/tx_extra.rs`: I19 (`TxScope::All`) parses and holds the PQC field shape on every transaction — `check_pqc_field_shape_of` on the coinbase, `check_tx_extra_shape(General)` off it; I20 (**`TxScope::Coinbase`**, minted with its doc pinning *runs at `Miner`*, never *when `is_coinbase()`*) holds the grammar through `check_coinbase_extra_shape`. Placed between H7 and H9, where `check_tx_semantic` runs the adapter. `the_kind_is_derived_from_the_slot_not_the_bytes` pins the scope predicate; `tx_extra_tests::i20_is_the_slots_rule_not_the_bytes` holds the Q6 cases through `tx_form` (a coinbase body at `Lone` is H5's, the grammar's nonce on a spend at `Lone` is I19's, a spend at `Miner` is I20's). Coverage 64 → 66. **Disclosed:** (a) the census words *"off the coinbase, no `0x02`"* under I20; a `Coinbase`-scoped rule never sees a listed transaction and the C++ emits that refusal from I19's site, so the crate refuses it on **I19** — commit 10 moves the clause in the census cell (a relocation between two rows one adapter serves; §3.4 sweep item). (b) Fixture migration: every harness coinbase and spend now carries its `extra` (`fixture::coinbase_extra`, `fixture::pqc_extra`); trips that change an output count re-fit it; the H1/H3 size fixtures grow the filler proof instead of the extra, and the miner-slot vacuity fixture is oversized by outputs (the codec's 1 MB per-field cap bounds it from above). (c) `alt::test_block_bytes` in the store no longer borrows the harness coinbase — a codec snapshot pinned to another lane's fixture would have demanded a `SCHEMA_VERSION` bump for a codec that did not change. (d) **A semantic conflict on `dev`, fixed here:** S-ALT's `alt_tests.rs` (#858) landed with one-output spends after I1 (#853) refused them — both PRs green alone, `cargo test -p shekyl-chain-store` red at their merge; seven fixtures moved to two outputs. (e) Finding, filed as **the other half of `TXE-Q6′`** (its own FOLLOWUPS row, owner `TX_EXTRA_RUST_CUTOVER.md` §6): a listed transaction's `extra` may carry `0x09`/`0x0A`/`0x0B` blobs up to the parser's 1 MB with no consensus bound below H1 — I19 shapes the PQC fields and bans the nonce, nothing else. The coinbase's grammar was closed for exactly this reason (*bounding one tag while the rest stayed admissible bounds the door somebody noticed*); one transaction class over, the door is open, and the fix is the ruling's whitelist generalised. The M4 conformance trip is re-cut as a parseable over-cap extra so it exercises the policy disagreement it is for — and is the construction that showed the door. **Ruled 2026-09-25 on (a):** I20 stays `Coinbase`-scoped and the nonce clause moves to I19 — the tiebreaker is where the enforcement lives (the C++ emits it from I19's site, the crate does too; a census cell describes the rule that refuses, not the ruling that decided) — and the move must not lose the ruling's unity: both cells cite `TXE-Q6′` | commit 1 |
| 4 | **LANDED 2026-09-25.** `TxAgainstRule` (view-bound: `check(cx, view) -> Result<Verdict<()>, V::Fault>`, run by `run_tx_against`, vacuous-recorded out of scope like `TxRule`) in `rules/tx_against.rs`; **I7** (`NonCoinbase`) looks every `ToKey` image up through `ChainView::has_key_image` and refuses at **`Locus::Input { slot, input }`** — the place E2's mutation table named for it before the rule existed (`DRS_E2_REPLAY_DRIVER.md` §3.10, `DoubleSpend`), so the ingest's `DoubleSpend` mutation flipped from its pinned SI-1 halt to the refusal with no test loosened, and its pinned-gap arm was deleted with the hole. I2 and I3 are `by_construction` registry entries crediting the wire's falsifiers (`i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase`, `f2_the_wire_admits_one_transaction_version`), list-and-iterate through `credited_to_this_falsifier` (Q3). Coverage 66 → 68; by-construction 9 → 11. **Disclosed, three scope changes:** (a) **SECURITY FINDING, closed here: CEN-L1 lands as a `BlockRule`** (`rules::run::<L1,_>` after the slot loop). With I7 alone, two listed transactions each spending the same key image once passed `validate` and tripped the store's **fatal** SI-1 — a writer halt reachable by **any peer holding two valid spends of its own output**. Graded as the `unreachable!`-conversion class, not as a placement correction: a store invariant defending a validator gap, and the difference between refusing and dying. How it happened is the attribution — §6 of this plan said L1 was the store's belt; the census I7 cell says *"CEN-L1 re-enforces at connect"*; the census's own L1 row gives L1 to the validator — two documents and a plan agreeing on a wrong attribution, which is exactly what C2-R8 Q6 ruled belts and rules apart to prevent, and **the first case where the conflation reached code**. The halt is what it cost. L1 refuses at the second occurrence's `Locus::Input`. **Commit 10's sweep looks for the pattern, not the instance:** any census cell that names a belt (`SI-n`, `MDB_NODUPDATA`, "the store re-enforces") as the enforcement of a row the census assigns to the validator. (b) **`tx_against` takes the slot** (`tx_against(tx, slot, view, rule_set)`): deriving at `Lone` and re-homing the locus afterwards put the coinbase through H5 at the wrong slot; both stages now derive at the slot they judge, and `Locus::rehome` is deleted — `CHAIN_RULES_CRATE.md` §4.6's signature moves with commit 10. (c) The store's two SI-1 tests reached the belt through a double spend `judge` now refuses; they reach it through the one door left — the spent-keys table moving under a judged token (`connect_fixtures::connect_with_image_planted_under_the_token`). That is a belt tested **as a belt** rather than as a rule, and it is the state those tests should always have been in; each says so beside its assertion, so the re-pointing reads as the reason and not as accommodation | commit 1 |
| 5 | **LANDED 2026-09-25, two commits (cost 2, inside the §5.1 estimate).** `ChainView::height_of(&BlockHash) -> Option<BlockHeight>` — the trait method, `BatchView`'s impl (one body with `ReadSnapshot::height_of`, `chain_reads::height_of`) and `MockView`'s in one commit; the store's conformance read test holds the mock's `height_of` to the store's over every recorded hash and an unrecorded one. **I10, I11, I12 in `rules/tx_against.rs`, in the D4 arrangement:** I10 *yields* `ref_height` (`I10::reference_height`, refusing at `Locus::Tx` — the C++ names the transaction), I11 measures it (`I11::window`, the two guards as two `checked_sub_count`s, and `I11::check`), I12 reads the anchor at it (`I12::anchor`, a definition recorded where derived; the value is **staged** for I15, commit 8, and dropped until then). `REFERENCE_BLOCK_{MIN,MAX}_AGE` are `const`s beside the rule (Q5), generated from `config/consensus_constants.json` by `build.rs` (a production build cannot compile a hand copy), with sentinels at the baseline 5/100 and `reference_window_is_the_json_authoritys` as the falsifier that the consts are still that file. The reference sequence is `judge_reference` in `rules/tx_against.rs` — I10 yields, I11 and I12 are the successor list recorded vacuous when there is no operand — and `validate` calls it. **`tx_against`'s fault widens to `ViewRead<V::Fault>`:** I12 is the first view-bound row to read a per-height record, and a root missing at a height I10 just found recorded is `Corrupt::HoleBelowTip`, never a verdict — `CHAIN_RULES_CRATE.md` §4.6 moves with commit 10. Coverage 68 → 71. **Witness, per the review's charter:** the mock holds I11's boundary arithmetic (`MIN_AGE` exactly / one younger; `MAX_AGE` exactly / one older; a chain younger than `MIN_AGE`) and the fault classification a driven chain cannot produce (`i12_a_missing_root_at_the_reference_height_is_corrupt_not_a_verdict`); the rows *operating* are the driver's — E2's mutation family gains `UnknownReference` (I10) and `ReferenceTooRecent` (I11), spec-first in `DRS_E2_REPLAY_DRIVER.md` §3.10 with a new `ExpectedPlace::Listed`, through the production pipeline against a real store — and the captured chains' real spends replay through all three (`vectors_tests`). The old edge of the window (`MAX_AGE + 1`) is the mock's alone: the fixture family's `root_after` bytes cannot build a chain past 63. **Disclosed — the finding the first commit is:** every chain the harness, the store and the ingest built listed spends at heights 1–3 and referenced `[0x99; 32]`, a block no chain holds; consensus admits a spend only at height `MIN_AGE` or above, referencing a block that many below. I10/I11 are the first rules to read either fact — the fixture substrate had been constructing state no rule had asked about, the class rule 50 names. The fixture move landed first as its own commit (`fixture::anchored_at` is the one anchoring body every crate's chain builder calls; `spendable_chain`, `spendable_prefix`, `FIRST_SPEND_HEIGHT` derive the floor from the constant's name), behaviour-neutral, so the rule commit is reviewable alone. Also touched: the three `compile_fail` doctests on `validate` gained `height_of` — a `compile_fail` that fails for a missing trait method passes for the wrong reason | commit 1; the shape disclosed to E5 (the pool's decorator implements `height_of`) and the store lane |
| 6 | **DEFERRED 2026-09-25 — the slice's one named successor.** I13 over **depth at `ref_height`**. **Blocker:** the height-keyed depth read is E3 S-CURVE's to write, and E3 has not begun — no plan, branch or PR exists; the store holds the *current* depth only (`CurveTreeState.depth`, S-CURVE C1) and a per-height record only for roots (`curve_tree_roots[h]`). Asked of E3 in its boundary statement, `DRS_E1_SCURVE.md` §2.3 (*What E3 is asked for*), as `ChainView::depth_at(height) -> AtHeight<TreeDepth>` keyed as `root_at` is. **Falsify by:** `rg 'fn depth_at' rust/shekyl-chain-rules/src/view.rs` → present, with `BatchView`'s impl. **Owner:** `DRS_E1_SCURVE.md` §2.3; the FOLLOWUPS row carries it past this document's archival. **Why not current-depth now (the fallback ordering, ruled in review 2026-09-25):** *if E3 can serve it, take it; if E3 **won't**, current-depth with all three §3.3 dependencies written at the rule — the slice doc archives, the rule does not; if E3 simply has not got to it, that is this case, not a reason to take the weaker read.* One of the three dependencies is an ordering argument (I10 refuses a `ref_height` a reorg removed before I13 reaches it), and ordering arguments have been wrong twice this month and right once by luck; height-keyed removes it rather than documenting it. **New since commit 5, for whichever branch is taken:** I10 exists, so the ordering dependency is a fact about `tx_against`'s body, not a plan — if current-depth is ever taken, pin it with a test that fails when I13 runs before I10 (a view whose `height_of` refuses the reference and whose depth read would otherwise pass), which is better than a sentence and was not available before commit 5 | — |
| 7 | I17 as **(c)**: the wire's `pqc_signing_payload_hashes` becomes the one derivation; the daemon calls it through a coarse FFI (`shekyl_tx_pqc_signing_payloads`, TXE's shape); **byte-identity gate first** — real transactions through both the C++ assembly and the Rust body, identical payloads required, multi-input and serve-credit shapes included (the `mining_parity` pattern) — then `tx_pqc_verify.cpp:62–158` becomes the call (Q7) | commit 1 (the shapes come from the vectors); touches `src/cryptonote_core/tx_pqc_verify.cpp` and `shekyl-ffi` — rule 20's minimal shim |
| 8 | I15 over `shekyl_fcmp::proof::verify`; I18 over `shekyl_crypto_pq` through I17's payloads; H19's verification half as a **`validate` fold** over the block's BP+ proofs (Q9), if the captured contexts carry ≥ 2 spends per block — else a named successor, disclosed at commit 1 | commits 1, 6, 7 |
| 9 | Conformance table: re-check the dead-arm ordering (`key-image input(s) but no prunable proof`) now that verification sits in the path; I19's arm | commit 8 |
| 10 | Docs: census 4.I re-pinned at the landing tree (read, not diffed); **the I19/I20 nonce clause moved to I19's cell with `TXE-Q6′` cited from both cells** (row 3 (a), ruled 2026-09-25 — the enforcement's home decides the cell; the citation keeps the two halves one ruling); the FAKECHAIN corrections from §3.4's sweep (I2, I3, §10 R8); `CHAIN_RULES_CRATE.md` §4.3 (`height_of`), §4.6 (`TxAgainstRule`, `TxScope::Coinbase`); index; FOLLOWUPS (the capture row closed; the I17 shim finding); CHANGELOG | — |

Ten commits is the rule-06 ceiling. If commit 6 waits on E3 past the
slice's window, it is the one named successor; nothing else in the plan
depends on it.

### 5.1 The expectation for commits 3–10, written before commit 3 (2026-09-25)

Commits 1a, 1b and 2 landed as #852 and #853 (with the census resolver
#854 between them), on a branch that ran to twenty-two commits — the
overrun recorded in #852's body with its reason. The remaining rows resume
on `feat/chain-rules-slice-6-rows`, cut from `dev@fc6d87ca5` with all
three merged, and **this table is the branch's first commit**: an
expectation stated before the work, so an overrun is a signal with a
subject rather than a number nobody predicted.

| commit | lands | cost | falsifier applies |
| --- | --- | --- | --- |
| 3 | I19/I20 in `tx_form`; `TxScope::Coinbase` | 1 | yes |
| 4 | `TxAgainstRule`; I7 over `has_key_image`; I2/I3 by-construction | 1 | yes |
| 5 | `ChainView::height_of` **and `BatchView`'s impl in `shekyl-chain-store`, one commit, both sides** — the trait is the rules crate's and the impl is the store's, and a trait change without its impl is a broken build inside a commit, not a tolerable interval. I10, I11, I12. The disclosure to the store lane is about the *shape* they inherit (`height_of`'s contract), not a warning about a gap | 1–2 | yes |
| 6 | I13 over depth at `ref_height` | 1 if E3 S-CURVE serves it; else the named successor — **the successor, 2026-09-25: E3 has not begun (§5 row 6)** | yes |
| 7 | I17 (c): the payload derivation as a production body in `shekyl-wire`, the FFI shim, the byte-identity gate against the C++ on real multi-input and serve-credit shapes — before `tx_pqc_verify.cpp:62–158` can go | 2, may run to 3–4 | **no — exempt.** This is a cross-crate cutover of TXE's coarse-call shape, which took its own PR; it was always sized like one. An overrun here says a cutover took what a cutover takes, not that the substrate was unfinished. Named so the signal, if it fires, fires for the right reason |
| 8 | I15 over `proof::verify`; I18 through I17's payloads; H19-verify as a `validate` fold — witnessed by the captured chains' real proofs, gated on 5 and 7 only | 1–2 | yes |
| 9 | conformance re-check (the dead arm's ordering; I19's arm) | 1 | yes |
| 10 | docs: 4.I re-pinned to function anchors with eras — into a census that is now in the citation gate's `DEFAULT_DOCS` (#854), so the re-pin is checked the moment it lands; index; CHANGELOG | 1 | yes |

**Expectation: nine commits, ten if I13 lands.** Coverage 64 → 74
implemented (75 with I13; I2 and I3 count as by-construction, not
implemented). **The signal:** more than ten commits *excluding commit 7's
overrun* means the substrate was not as finished as this table claims —
that is the answerable form. Commit 7's overrun is excluded because it
would fire the signal for a reason the table already knows.

Two things the sequence also inherits, recorded here so they are not
re-derived: the branch names its own commits by PR and subject, never by
SHA (six pins died in the last rebase — the rule at this file's head); and
rule-08 instances 12–14 (a `cargo fmt` reverting a buffer; a `git checkout`
write-back; a branch-switch write-back caught by "a file I did not edit
shows modified") go into `08-worktree-hygiene.mdc` with commit 10.

### 5.2 The witness is the real chain, and the mock has a three-job charter (ruled 2026-09-24; the third job 2026-09-25)

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
  exactly the three jobs the rule allows: predicate logic on plain values
  (I11's window arithmetic at its four boundaries), the faulting view (a
  store fault propagates as `Fault`, never as a verdict), and a state a
  conforming store refuses to hold (`WithholdingView` withholds one
  per-height read and the assertion is `Corrupt::HoleBelowTip`, never a
  verdict — the third job, named 2026-09-25, because the dense mock
  produces neither absence case and the SI-7 fault had no other test).
  "This reference is on the chain" and "this root is what the tree grew"
  stay the driver's. `MockChain`'s doc comment carries the charter.
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
`MockChain`'s charter (landed in #852: *four regtest chains captured whole*;
*the vectors carry their genesis*). 1b — *as first
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
- **Gap 1 — no Rust block template — CLOSED by commit 1a (#852), records-was.**
  As found at Round 0: `construct_miner_tx` / `create_block_template` were
  C++ only — TXE-F8, "the block template has no Rust owner" — with every
  piece already Rust (`shekyl_economics` for reward, emission split and fee
  burn; `shekyl_crypto_pq::output::construct_output`, which the C++ calls
  through `shekyl_construct_output`; `build_coinbase_extra`; the wire
  types) and nothing composing them. `shekyl-block-template` composes them
  now (placement ruled below); the driver is its first consumer. **What
  remains is consumer wiring, not a gap:** `get_block_template`'s Rust
  handler and the built-in miner (E3), named on the TXE-F8 row.
- **Gap 2 — `ConnectFacts` derivation — PARTLY CLOSED by commit 1a, the
  rest named.** As found: `connect` takes `Fact<_>` with
  `Origin::{Derived, PassedThrough}` and `root_after`, `coins_generated`,
  `burned` and `long_term_effective_median` were all passed through from
  the C++ trace. `Composed` (§5.3.2) derives four; the two with no Rust
  source yet are recorded as such, not passed off as derived.

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
median — on the `BatchView` the rules read, through `ChainStore::inspect`,
which aborts the batch so a template read is not a commit) and three
producer-facing exports from `shekyl-chain-rules`:
`tx_volume_window` (F20's definition, returning `ViewRead`: the view's
fault or `Corrupt::TxCountNotMonotone`, so no caller matches a stale arm
that cannot occur), `mtp_median_at` (C3's padded median, the same
`ViewRead`) and `EMISSION_SPLIT_EPOCH` (F21). A hole below the tip is
`Corrupt::HoleBelowTip` and halts the writer, the class a rule raises.
Each export is public for one stated reason: the
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
was nine-with-four-unread, and reading every site gave a different
picture in both directions — including that two of the "unread" four were
the same `AboveTip` shape as the two the review had named. **Both
enumerations were partial and both were wrong in the same direction**,
because the sites that looked different at a glance were identical at the
line; the count that held was the one taken by reading every site, not by
grepping and classifying the hits by their surroundings. `difficulty.rs` `const ONE`'s bare arm is compiler-proven (a
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
SI-7-breaking view (`WithholdingView` withholding `block_at(2)`: the tip
says four, that read says `AboveTip`) and pins the fault at C3, at
`validate`, and at the producer's `mtp_median_at` (inner position). The
variant names the missing record (`PerHeightRecord`); those four reads are
the block row, and a root read (CEN-I12, the producer's `root_at`) names
the curve-tree root so the store's SI-7 cell is the table that was read. CHANGELOG carries it as
security-relevant. **Three remain**, none remote-reachable, in FOLLOWUPS
with the type fix named: C2's `Option<MtpWindow>` in the context
(structural — the fix is the type, not the arm), and two local-construction
bounds a `BoundedWindow` would carry.

**Carried, not done here:** slices 2–4's view-bound rows (the D family's
windows, B5's root, E1's anchors) have fixtures of the same shape against
`MockChain`, with ingest-side replay coverage in some places and not all.
That is an audit of the earlier slices, filed in FOLLOWUPS with the crate
contract as owner, so it is chosen rather than found.

### 5.4 CEN-I4 — the divergence recorded, the cost measured, the derivation owed (2026-09-24)

**The record first.** Commit 2 landed I4 unconditional while the CSR-3a
register still graded it CHECKED-CONFORMANT and the census row still read
"FAKECHAIN exempt" — Q9's situation with the polarity reversed: Q9 graded
a divergence that did not exist, this left a deliberate one under a
conformant grade. Both fixed in this commit: the register row is
**DIVERGENT** with its pass condition stated (on Fakechain the Rust refuses
a nine-input transaction the C++ admits, *by ruling*; identity there is the
failure, and a comparator reporting it has reproduced the ruling, not found
a defect); the census row states the C++'s behaviour and the Rust's beside
it; the tally moved to 125/3/5 and the gate re-derived it. The ruling is
not in question — rule 71, an exemption that served a builder being
deleted, and a cap the test network could not test while relaxed there —
only the record was missing, the half Q9 taught is easy to skip.

**Then the question the number never answered: what does the cap bound?**
`cryptonote_config.h`'s `FCMP_MAX_INPUTS_PER_TX` (`:312` at `dev@a1159f1a2`;
`:313` before the rebase that moved it one line) says *"bounds proof
generation time and tx size"*.
Generation time is the sender's cost; consensus does not protect a sender
from waiting. The one objective a consensus input cap defensibly bounds is
**the verifier work one transaction can impose**, and that is observable.
`shekyl-wire/tests/input_cap_cost.rs` (measurement lane, `#[ignore]`d)
builds real 1/2/4/8-input spends through the production builder over a
real depth-3 tree and times the production verifiers. On an i9-11950H,
release, 2026-09-24 — **not the Pi 4 floor** (rule 76; the floor run
follows below, same day — this table is the desktop reference the floor
multiplier is read against):

| inputs | tx bytes | proof | auths | BP+ | verify | of which proof | auths | BP+ | prove |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 13 584 | 4 896 | 5 381 | 642 | 26.1 ms | 23.3 ms | 0.21 ms | 2.6 ms | 0.54 s |
| 2 | 20 352 | 6 208 | 10 762 | 642 | 37.4 ms | 34.2 ms | 0.42 ms | 2.7 ms | 0.86 s |
| 4 | 33 824 | 8 768 | 21 524 | 642 | 59.8 ms | 56.2 ms | 0.79 ms | 2.9 ms | 1.50 s |
| 8 | 58 720 | 11 840 | 43 048 | 642 | 109.2 ms | 104.6 ms | 1.72 ms | 2.9 ms | 2.88 s |

Read off the table: **6.4 KB per input** on the wire (5.4 KB of it the
hybrid auth — a 1 996-byte key and a 3 385-byte signature — plus ~1 KB of
proof growth and 64 bytes of prefix), **11.9 ms of verifier time per
input** (11.6 ms of it the membership proof; the hybrid signature is 0.2 ms;
the BP+ is a fixed 2.7 ms over the two outputs), fixed overhead ~7.1 KB and
~15 ms per transaction. Linear within 5% across the sweep (the proof's
per-input growth is mildly *sub*linear: 1.3 KB early, 0.8 KB by 4→8).
(Re-run 2026-09-24 after the #853 corrections below: bytes identical,
10.9 ms/input, 254 ms at 22 inputs — the corrections change what the
proof binds to and which ceiling the cap is read against, not the proof's
size or its verifier time. Second re-run the same day after the auths were
moved onto the canonical per-input payload hashes — production's two-phase
form, `pqc_signing_payload_hashes` over the assembled body with
provisional headers, in place of a prefix-hash stand-in — with the
verifier's per-input hashing now inside the auth timer: 11.3 ms/input,
auths 0.22 ms/input, 263 ms at 22. The hashing is noise beside ML-DSA
verification; the figures above stand.)

**CORRECTED 2026-09-24 (#853 review) — the ceiling.** The first cut of
this section read the cap against `MAX_TX_SIZE` (1 MB) and reported the
cap binding "by a factor of nineteen" with 153 inputs admitted. That is
the **parser's** refusal, not the bound an accepted transaction meets:
CEN-H3 refuses any transaction whose *weight* exceeds `TX_WEIGHT_LIMIT`
(149 400; `shekyl_wire::transaction::TX_WEIGHT_LIMIT`, const-asserted to
the C++ `get_transaction_weight_limit`), seven times tighter. For this
two-output shape weight equals bytes (the BP+ clawback is zero at two
outputs), so H3 admits **22** inputs at this slope, not 153. The test now
computes the implied cap from `TX_WEIGHT_LIMIT` and reports the parser
cap beside it, asserting the parser's is the wider. The same review found
the test's prefix hash omitted the `extra` the wire carried — the proof
was bound to bytes the transaction did not serialize; fixed, and the same
defect in `fcmp_spend_e2e.rs` with it. Every number below that depended
on the ceiling is restated; the structural findings did not depend on it.

**What that says.** (1) **The cap is the binding constraint, by a factor
of ~2.75 against the ceiling that binds.** CEN-H3's weight limit admits
**22** inputs at this slope; the cap refuses at 8. It is doing independent
work — so it is not dead weight, and the question is what the work is.
(The 1 MB parser bound would admit 153; it is not a consensus bound and
no accepted transaction is measured against it.) (2) **It does not bound per-block
verifier work.** Per-input cost is linear and per-transaction overhead is
positive, so a block's verifier time is set by the block weight limit,
and splitting twenty inputs across three transactions costs the verifier
*more* (three BP+s, three proof bases, 21 KB more wire) than one
transaction would. A block full of eight-input spends and a block full of
one-input spends verify in the same time per byte; the cap moves no
per-block bound. (3) **What it does bound is per-transaction work on a
transaction that turns out invalid** — the relay path's exposure to a peer
handing over garbage that costs full verification before refusal. At the
cap that is ~109 ms per garbage transaction here; at the H3-implied 22
it would be ~0.25 s. Whether 0.25 s is acceptable is a **relay-policy**
question about an unverified peer's byte budget, which the pool already
prices per byte — not a consensus question about a valid transaction's
shape. (4) **Prove time is the sender's:** 2.9 s for eight inputs here, and
it is linear too.

**The side nobody had written down.** A cap truncates the input-count
distribution. A wallet holding twenty spendable outputs cannot consolidate
in one transaction; it emits three in a short window from one wallet —
a timing correlation a single twenty-input transaction does not produce.
On a chain whose design objective is origin and linkage privacy that is a
trade, and it is currently made by inheritance. Note what the cap does
*not* buy: uniformity. Input count is public and correlates with wallet
state at any ceiling; the honest alternative for uniformity is fixed-count
transactions padded with dummy inputs — each needing a real membership
proof at 6.4 KB and 12 ms — which is almost certainly not worth it, but it
is the claim "the cap gives us privacy" would have to mean.

**Disposition: keep, as inherited and unjustified, with the derivation
owed.** Deleting a consensus bound on a reachability argument nobody has
run at the floor is worse than carrying one for a slice. The derivation
round — with the floor measurement **in hand** (below, same day; the
first cut of this paragraph listed it as the round's first step): state
the verifier budget a single unverified transaction may consume at relay;
derive the cap from it against the floor's 64.9 ms/input, or move the
bound to relay policy and delete the consensus rule as redundant with
CEN-H3's weight limit (which then caps inputs at 22 for this shape); and
price the consolidation-sequence cost in the same row so the trade is
made knowing both sides. Until that round, `rules/tx_inputs.rs::I4`
carries the number and this section carries the reason it is not yet a
reason. The `shekyl_fcmp::MAX_INPUTS = 8` in the prover and verifier is
the same inherited figure and moves with it (`shekyl-tx-builder`
const-asserts the two equal; see the caveat on operands in that
assertion's comment — the prover counts spends, I4 counts the whole
`vin`).

**Two things the desktop measurement is not.** It is not the floor (rule
76) — the floor run follows. And
it is not a claim about the FCMP++ prover's scaling past eight — the
prover refuses more, so the read past the cap is the slope, which the test
asserts is a line within 5% so the read is honest.

**The floor, run (skl-pi, Raspberry Pi 4 Model B, Cortex-A72 ×4,
`rustc` 1.94 aarch64, release, 2026-09-24, 51 °C, the test as #853's
commit *CEN-I4 graded DIVERGENT by ruling; the input cap's cost measured*
carried it — before the #853-review corrections, which change what the
proof binds to and which ceiling is read, not the bytes or the time):**

| inputs | tx bytes | verify | of which proof | auths | BP+ | prove |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 13 584 | 166.7 ms | 130.6 ms | 1.1 ms | 34.9 ms | 3.0 s |
| 2 | 20 352 | 229.1 ms | 191.9 ms | 2.2 ms | 35.0 ms | 4.8 s |
| 4 | 33 824 | 351.6 ms | 312.7 ms | 4.1 ms | 34.8 ms | 8.3 s |
| 8 | 58 720 | 621.0 ms | 578.1 ms | 8.0 ms | 34.9 ms | 15.3 s |

Bytes identical to the i9 (the wire is deterministic). **64.9 ms of
verifier time per input** at the floor (63.9 ms the proof; 1.0 ms the
hybrid auth), a fixed **34.9 ms** BP+, linearity held (the test's 5%
assertion passed there too). The floor multiplier is **5.5×** on the
per-input verifier cost and **13× on the BP+**; prove time 15.3 s at eight
inputs, the sender's. **The BP+ number is not an artifact, and it matters
for the budget's shape:** the range proof degrades harder on the A72 than
the membership proof the cap is about, so the fixed per-transaction
overhead that makes splitting expensive is *more* dominant on the floor
than on the desktop — 35 ms of the 167 ms a one-input spend costs there,
against 2.7 of 26 on the i9. The floor strengthens splitting-costs-more
rather than merely preserving it. **The relay-budget value, at the floor:** ~0.62 s
of verifier work per eight-input transaction that proves invalid; ~1.5 s
per 22-input one (H3's ceiling; the first cut wrote "10 s per 153-input",
read off the parser bound — corrected above). That is the number the
round decides against — and it is a narrower question than the first cut
made it: the cap's whole effect at the floor is the difference between
0.62 s and 1.5 s of wasted verifier time per garbage transaction. (The Pi
table stands: the prefix-hash fix changes what the proof binds to, not
its size or verifier time, and the bytes are identical either way.)

**What the floor decided and what it could not (review, 2026-09-24).** The
Pi 4 changed the absolute milliseconds and not one ratio: linearity,
positive per-transaction overhead, splitting-costs-more and the ~2.75×
against CEN-H3's weight limit are structural and held on the floor exactly
as on the i9. The floor set one number — the *value* of the relay verifier
budget (0.62 s at 8, 1.5 s at 22) — and a re-run returning five and a half
times the milliseconds reopened nothing above.
**The deletion, when the round ends there, is a widening:** the chain would
accept nine-input transactions it now refuses. Pre-genesis that is free;
after genesis it is a hard fork. The window for making it free closes at
genesis. **And two constants part company at that moment**, both named so
neither orphans: the consensus cap (`shekyl_wire::transaction::MAX_FCMP_INPUTS`, read
by `rules/tx_inputs.rs::I4`; the C++ `FCMP_MAX_INPUTS_PER_TX` until E4 retires
it) and the prover/verifier cap (`shekyl_fcmp::MAX_INPUTS`, refused at
`proof.rs`'s prove and verify entry points). The second moves to whatever
bound the round states, or a prover that refuses at eight becomes the cap
by accident — a consensus rule enforced by a library constant nobody
ratified. Three claims were tested here and two came back opposite to what
the inherited constant implies: "bounds proof generation time" is the
sender's 2.9 s; "bounds tx size" is answered by H3's 22, which makes the
cap load-bearing rather than redundant; and the linear cost with positive
overhead is what decides the round, because it shows the cap bounds a
relay-policy quantity and nothing else — the CEN-M4 shape, one rule over.

## 6. What this slice does not build

- **The pool.** `tx_against` takes any `ChainView`; E5's decorator is E5's.
- **SI-1** (the store's own spent-image check at connect) — the store's
  belt, already landed. *(Corrected 2026-09-25, commit 4: this line first
  named **CEN-L1** here, as the belt. The census gives L1 — one image spent
  twice across a block's transactions — to the validator, and it landed in
  commit 4 as a `BlockRule`; §5 row 4 (a) has why leaving it to the belt
  was a remotely triggerable halt.)*
- **Curve-tree state.** I12/I13 *read* the tree; E3 S-CURVE writes it.
- **C++ deletions.** The FAKECHAIN gate (§3.4), the C++ payload assembly
  (§3.1) — retired with E4, not here.

## 7. Round log

- **Round 0** (2026-09-23): pre-flight written at `4dc5194de`; every pin
  read at the line; nine questions. Amended on review (#852, *docs: slice 6
  Round 0 amended on review*): the
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
- **Q2 — the view contract (§1.4). RULED 2026-09-24 with Q8 as ONE dependency, not two: `height_of` in commit 4 *(moved to commit 5 by the §5.1 amendment of 2026-09-24 — the trait method and `BatchView`'s impl land together, and commit 4 is I7's)*; depth-at-`ref_height` as I13's operand; both put I13 behind E3, recorded as a single gating relationship rather than two rows naming the same lane.** `ChainView::height_of(&BlockHash)` and
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
