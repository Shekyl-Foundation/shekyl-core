# `shekyl-chain-rules` slice 5 — census 4.H, the transaction on its own (DRS-E6 increment 6)

**Status:** OPEN — **implementation LANDED 2026-09-23, commits 1–9 (§5);
Round 1 RULED 2026-09-23 (Q1–Q9, §8, each line-local, with the commit-time
amendments recorded on their rulings).** Stays in `design/` until the PR
merges and the §5.1 slice-6 capture scope has an owner that is not this
file. Round 0 pre-flight written 2026-09-23 against
`dev` @ `387fa84a9` (post-#834, slice 4 landed). **The TXE lane
(`feat/tx-extra-rust-cutover`, `TX_EXTRA_RUST_CUTOVER.md`) is in flight on
an adjacent worktree and is this slice's boundary — §1.2.**

Parent: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §4.6 (`tx_form`),
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 (DRS-E6; ordering table
row *4.H Tx non-input — slice 5 — `tx_form`; the pool shares it*).
Census: [`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §4.H, 24
rows CEN-H1…H24. Predecessor:
[`CHAIN_RULES_SLICE_4.md`](CHAIN_RULES_SLICE_4.md) (its §3.1 shim-layer
finding is the method this pre-flight applies to a second shim, §3.1
below).

---

## 0. What this slice is

The **stateless per-transaction rules**: everything about one transaction
that is decidable from its bytes alone, with no chain state. In the C++
this is one function, `ver_non_input_consensus`
(`tx_verification_utils.cpp:259`), run at **two sites** — pool admission
(`tx_pool.cpp`) and block connect over the pool supplement (CEN-G3) — and
the census's 4.H family is that function's contents plus the parse boundary
(H23) and one belt the C++ runs elsewhere (H24). In Rust the home is
[`tx_form`](../../rust/shekyl-chain-rules/src/validate.rs)
(`tx_form(tx, rule_set) -> Verdict<RuleCoverage>`), today the stub
`Ok(RuleCoverage::EMPTY)`; `validate` already calls it for the miner
transaction and every listed transaction and re-homes a `TxSlot::Lone`
refusal to the real slot. **The pool (DRS-E5) will call the same function**
— that is the contract's whole point (`CHAIN_RULES_CRATE.md:37`: *"Pool
admission calls the same `tx_form` / `tx_against`"*) — but the pool is not
this slice's to build (§6).

What makes this slice different from slice 4: **the rule content already
exists in Rust, in the wrong crate.** `shekyl_wire::Transaction::validate`
and `validate_context_free_pruned` (`rust/shekyl-wire/src/transaction.rs:1673`,
`:1984`) implement, by this pre-flight's count, **fourteen** of the
twenty-four rows as a parse-adjacent validator that the **wallet** calls
(`engine/block_fetch.rs:200`, `:256`, `:258`) and the **daemon's Rust never
does** — `chain-ingest`'s corpus reader parses with `from_bytes`
(`corpus.rs:317`) and no `validate`. That is slice 4 §3.1's finding in a
second shim, with two differences: this shim is Rust, and it is
*load-bearing for the wallet* today. §3.1 and Q1 are about it.

---

## 1. Parents — landed? (§7.5.1 (a))

### 1.1 Landed

- **Slice 4 (#834, `387fa84a9`).** `tx_form`'s call site and the
  `TxSlot::Lone` re-homing have existed since the scaffold; slice 4 added
  the miner transaction's own family (4.F), so `validate` now runs 4.F at
  `TxSlot::Miner` **and** `tx_form` on the same transaction. Which 4.H rows
  apply to a coinbase is therefore a live question (Q2), not a corner.
- **`RowStatus::ByConstruction`** (slice 4 Q4) — the status several 4.H
  duplicate/redundant rows want (H13, H10, H24; §2).
- **Rust bodies the C++ already marshals to** (adopt, per the ordering
  table): `shekyl_ct_balance::{check_output_keys, check_commitment_masks,
  verify_ct_balance, amount_commitment}` (H7, H17, H18, the balance halves
  of H20–H22); `shekyl_checked_sum_amounts` (H22's reward total, shared
  with CEN-J24); `Transaction::weight()` (`transaction.rs:1477`, H3's
  operand).
- **`shekyl-bulletproofs`** — `verify` / `batch_verify`
  (`rust/shekyl-bulletproofs/src/lib.rs:139`, `:175`) exist and the
  tx-builder proves with them. The **daemon verifies BP+ in C++**
  (`src/fcmp/bulletproofs_plus.cc`), which the census calls *"the largest
  inherited-crypto implementation still on the acceptance path"* with only
  a tentative categorization (`CPP_INHERITANCE_INVENTORY.md:190`). H19's
  verification half is a crypto cutover, not an adoption — Q3.

### 1.2 In flight — the TXE boundary — **LANDED under this slice, 2026-09-23**

**UPDATE 2026-09-23 (rebase onto `d8ebfd18c`, #837):** TXE merged to `dev`
(`50256487f` *tx_extra: one constructor for the coinbase grammar*,
`3ab84bab6`; **CEN-I20** minted — the coinbase `extra` grammar). The
boundary held: no TXE file was edited by this slice, and the only place the
landing reached the slice was the conformance test's coinbase baseline,
which the twin now refuses without a `0x01` pubkey — fixed by building
that fixture's `extra` with the wire's own `build_coinbase_extra`, so the
grammar carries the fixture from here. Consequence 2 fired as predicted:
the 4.H pins moved (§5 row 9 has the re-resolution). The rest of this
section is the pre-flight's record of the boundary as it was.

`feat/tx-extra-rust-cutover` (4 commits at `fa94d7f43`, unmerged) touches:
`shekyl-wire/src/tx_extra.rs`, `shekyl-ffi` (`tx_extra_ffi.rs`,
`tx_extra_codec_ffi.rs`, `lib.rs`), the C++ consensus files
(`blockchain.cpp`, `cryptonote_core.cpp`, `blockchain_db.cpp`,
`cryptonote_format_utils.{cpp,h}`, `cryptonote_tx_utils.{cpp,h}`,
`fcmp/ct_semantics.{cpp,h}`), the C++ transaction builder and **the
`core_tests` that went dark with it** (`transaction_tests`,
`bulletproof_plus`, `integer_overflow`, `chain_switch_1`, …), and
`docs/FOLLOWUPS.md`.

Consequences for this slice, stated so they are checkable at each commit:

1. **No file TXE touches is edited here.** Slice 5 is crate-side Rust
   (`shekyl-chain-rules`, its tests, its `Cargo.toml`) plus its own doc
   surfaces. In particular **`shekyl-wire/src/tx_extra.rs` and
   `Transaction::from_bytes` are not touched**, and CEN-I19 (the `0x06`/`0x07`
   shape — TXE's `bytes-taking I19 form`) is 4.I's row and TXE's subject,
   not 4.H's.
2. **The 4.H census pins into `blockchain.cpp` / `cryptonote_core.cpp` /
   `ct_semantics.cpp` will move under TXE.** This pre-flight cites the
   C++ by **symbol**, verified live on `dev` (§2's *site* column;
   `rg` at `387fa84a9`), and the landing PR's docs commit — last, per
   slice 4 Q7 — re-resolves line pins against whatever `dev` holds then.
   If TXE lands first, the pins follow it; if slice 5 lands first, TXE's
   docs commit owns the shift. Either order is fine because neither lane
   edits the other's pins in the same commit.
3. **The BP+ `core_tests` TXE deletes were H19's differential oracle on
   the C++ side.** **Q3 RULED (b) and decoupled (2026-09-23):** the
   vectors are captured as committed data **in the same TXE commit that
   deletes the tests** — cheap, reversible, and it removes the artificial
   deadline; and BP+ has standard vectors independent of this tree, so the
   C++ tests were never the only oracle. The request is with the TXE lane
   (a FOLLOWUPS row carries it until that commit lands); slice 6's cutover
   KAT reads the captured data.
4. **`docs/FOLLOWUPS.md`** is the one shared textual surface (both lanes
   add rows). Resolve at merge by keeping both; no row is shared.

---

## 2. Row-body audit (§7.5.1 (b)) — 24 rows at `387fa84a9`

Columns: the census row; the live C++ body (symbol, file; line pins are
the census's and move under TXE); the Rust body **today** — where the
predicate already runs in Rust, and in which crate; the proposed
disposition. *Wire* means `shekyl_wire::Transaction::validate` /
`validate_context_free_pruned`; *CT* means `shekyl-ct-balance`.

| Row | C++ body (live on `dev`) | Rust body today | Proposed disposition |
| --- | --- | --- | --- |
| **H1** size ≤ 1 000 000 | `ver_non_input_consensus_templated` rule 1 (`get_max_tx_size`) | Wire: `from_bytes` refuses `> MAX_TX_SIZE` before decode; `validate_context_free_pruned` re-checks the serialized size | **Implement** as a `TxRule` on `serialized_len()`; the bound is a `RuleSet` parameter (Q5) pinned to `CRYPTONOTE_MAX_TX_SIZE` and held equal to `shekyl_wire::MAX_TX_SIZE` |
| **H2** version == 3 | rule 2/3 (`min_tx_version..max_tx_version`, collapses to `3..3` at HF1) | `Transaction::read` admits one version (`TX_VERSION`) — already CEN-F2's **by-construction** ground | **`by_construction`** on `shekyl_wire::transaction::TX_VERSION` with F2's falsifier; **one entry serves H2, H13 and I3's re-check** (Q6) |
| **H3** weight ≤ 149 400 | rule 4 (`get_transaction_weight_limit` = `min_block_weight/2 − COINBASE_BLOB_RESERVED_SIZE`) | `Transaction::weight()` (operand only; no bound in Rust) | **Implement**; the limit is **derived** from two `RuleSet`/config values, never restated as 149 400 (Q5) |
| **H4** non-coinbase ≥ 1 input | `check_tx_semantic` | Wire (`inputs.is_empty()` refused) | **Implement** (trivial; row-keyed) |
| **H5** input-variant whitelist | `check_inputs_types_supported`; `check_tx_inputs` dispatch; DB backstop | Wire: sole-`gen` rule; the type system admits only the five `Input` arms — `txin_to_script*` are **unrepresentable** in `shekyl_wire::Input` | **Split**: the `gen`-outside-coinbase half **implement**; the script-variant half **`by_construction`** on `shekyl_wire::Input` (falsifier: the enum has five arms, none a script) |
| **H6** archival vin mixing | `check_inputs_types_supported:720–737`; `classify_archival_tx` | Wire: all-or-none serve-credit, ≤ 1 bond post, ≤ 1 emission, emission ∌ bond post | **Implement**, single-sourced through a Rust `classify` (Q4) that H14, H20–H22 also read — the C++'s own single-sourcing, kept |
| **H7** canonical output keys | `check_outs_valid` → `shekyl_check_output_keys` (FFI) | CT `check_output_keys` (the FFI's body) | **Adopt** — call the crate; the FFI stays for the C++ until cutover. Slice 4's F9 already calls the same body for the coinbase |
| **H8** `outPk` count == vout count | `check_tx_semantic`; mask gate; `expand_transaction_1` | Wire: committed-base arity is shape-aware per §2.5 (`CtBase::commitments` read with `n_out`) | **`by_construction`** on the wire read (falsifier: a `Ct` whose commitment count ≠ output count cannot be parsed) — or implement if Q1 rules the wire validator is not a ground |
| **H9** output-amount sum no overflow | `check_money_overflow` | Wire: `try_fold(checked_add)` | **Implement** (row-keyed; `checked_add`, per the F7 discipline) |
| **H10** no repeated key image in-tx | `check_tx_inputs_keyimages_diff` | Wire: strictly-descending key images (CEN-I5's rule) forbids duplicates | **`by_construction`** on I5's ordering — but I5 is a 4.I row **not yet landed**; until slice 6 lands I5 the falsifier has no Rust rule to point at. **Implement** as its own cheap predicate in slice 5, and let slice 6 decide whether it collapses into I5 (Q6) |
| **H11** key images in prime-order subgroup, ≠ identity | `check_tx_inputs_keyimages_domain` | None in Rust for the KI domain (wire says so: *"out of scope … needs EC"*); CT has the point checks for **outputs** | **Implement** in `rules/tx.rs` on `shekyl-ct-balance`'s point primitives (or `curve25519-dalek` through it) — a new Rust body, with pinned vectors (the census names DSV M8's) |
| **H12** every output `txout_to_tagged_key` | `check_tx_outputs`; `check_output_types` | `shekyl_wire::Output` carries `view_tag` unconditionally — one output tag (CEN-F8's by-construction ground) | **`by_construction`** on `shekyl_wire::Output`, F8's falsifier, one entry serving H12 and F8 (Q6) |
| **H13** version < 3 rejected at output check | `check_tx_outputs` (`blockchain.cpp`) | as H2 | **Same entry as H2** (Q6) |
| **H14** all vout amounts 0, except a loud emission | `check_tx_outputs` via `classify_archival_tx` | **Absent** in Rust (wire deliberately permits non-zero non-coinbase amounts since C-1) | **Implement**, reading the Q4 `classify` |
| **H15** CT type ∈ {Null, FcmpPlusPlusPqc}; Null re-rejected for non-coinbase | `check_tx_outputs`; `ver_mixed_ct_semantics`; input check | `shekyl_wire::Ct` has two arms — other types **unrepresentable**; the "Null ⇒ coinbase" coupling is in wire `validate_context_free_pruned` | **Split**: type set **`by_construction`** on `shekyl_wire::Ct`; the Null-for-non-coinbase half **implement** |
| **H16** `unlock_time` < 500 000 000 | `check_tx_outputs` | Wire: `>= UNLOCK_TIME_BLOCK_SENTINEL` refused | **Implement**; the sentinel a `RuleSet` parameter pinned to `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (Q5) |
| **H17** commitment masks canonical, non-trivial; coinbase ≠ `zeroCommit(amount)` | `check_commitment_mask_valid` → CT (FFI) | CT `check_commitment_masks`; slice 4's **F10** already runs it for the coinbase | **Adopt** for listed transactions; the coinbase half is F10 (Q2 decides whether H17 also records on `TxSlot::Miner`) |
| **H18** CT balance `Σ pseudoOuts = Σ masks + fee·H` | `verCtSemanticsSimple` → `shekyl_verify_ct_balance` (FFI) | CT `verify_ct_balance` | **Adopt** |
| **H19** BP+ layout canonical **and** aggregate range proof verifies (batched across the block's txs) | `ver_mixed_ct_semantics`; `ct_types.cpp`; **`bulletproofs_plus.cc` (C++ verifier)** | Layout half in wire `validate` (`nbp == 1`, `|L| = |R| = 6 + log₂`); verification half: `shekyl_bulletproofs::batch_verify` exists but **verifies nothing on the acceptance path** | **Split** (Q3): layout **implement** in slice 5; verification is a crypto cutover with its own KATs — slice 5 or slice 6 per Q3. Batching is a **block**-level fold over `tx_form`'s per-tx claims, which is 4.G/`validate`'s, not `tx_form`'s |
| **H20** serve-credit-only CT shape | NIC serve-credit arm + `verCtSemanticsFeeOnly` | Wire: the serve-credit shape (no outputs, empty `pqc_auths`, no spend material); CT `verify_ct_balance` (fee-only form) | **Implement** shape (row-keyed) + **adopt** balance |
| **H21** bond-post CT shape + balance with (credit, debit) | NIC bond-post arm + `verCtSemanticsBondPost` | Wire: `pqc_auths == n_in`, `pseudoOuts == spend count`, proof non-empty; CT balance body | **Implement** shape + **adopt** balance. **The funding-input half** (empty offsets, unspent KIs, FCMP++ over the spend subset) is **4.I** (I10–I15) and not this slice's |
| **H22** emission CT shape: reward total > 0, proof ⇔ fee inputs, balance with mint on the debit slot | NIC emission arm + `verCtSemanticsEmission`; `shekyl_checked_sum_amounts` | `shekyl_checked_sum_amounts`'s Rust body; CT balance body | **Implement** shape + **adopt** sum and balance |
| **H23** must deserialize and expand | `parse_and_validate_tx_from_blob`; `expand_transaction_1` | `Transaction::from_bytes` **is** the parse; `tx_form` receives a parsed `Transaction`, so an unparseable blob never reaches it | **`by_construction`** on `shekyl_wire::Transaction::from_bytes` — the same shape as CEN-A6 (slice 1) for the block. Falsifier: `tx_form`'s signature takes `&Transaction`, not bytes |
| **H24** ring-members residue (`key_offset` ≠ 0 after the first) | `check_tx_inputs_ring_members_diff` | Wire requires `key_offsets` **empty** (CEN-I6), so H24 can never fire | **Rule-60 deletion residue with a named disposition** (census §10 R5). Not a Rust rule: at cutover the C++ body is deleted. Registry status until then: Q7 |

**Count.** 24 rows → **9 implement**, **5 adopt-or-implement-plus-adopt**
(H7, H17, H18, H20–H22 pair shape with an adopted body), **6
by-construction or shared-entry** (H2/H13, H5-script half, H8, H12,
H15-type half, H23), **1 split across slices** (H19), **1 deletion
residue** (H24), and **1** whose Rust body is new crypto surface (H11).
The figure after landing, on §8's defaults: `implemented 34 → ~56`,
`by-construction 4 → ~9`. The exact count is Round 1's, after Q1–Q7.

---

## 3. Findings from the code sweep

### 3.1 The wire crate is a second validator (slice 4 §3.1's class, in Rust)

`shekyl_wire::Transaction::validate` / `validate_context_free_pruned`
carry, as of `387fa84a9`, the predicates for **H1, H4, H5 (mixing), H6,
H8, H9, H15 (Null-coupling), H16, H19 (layout), H20–H22 (shapes)**, plus
4.I content that is not this slice's (**I5** descending key images, **I6**
empty offsets, **I19** the `0x06`/`0x07` shape, the §10 input cap, the
`≥ 2`-output anti-deanonymization rule). Every refusal is an
`io::Error::other(String)` — **no row keying**, no coverage, no
distinction between a parse failure and a consensus refusal. Its doc
comment names what it is: *"Mirror the oracle's rejects exactly, no
stricter"* — a wallet-side twin of the C++ validator, written so that a
transaction the wallet builds is not refused at submit.

Three facts decide what to do with it, and they pull in different
directions:

1. **It is load-bearing for the wallet, not the daemon.** Callers:
   `shekyl-engine-core/src/engine/block_fetch.rs` (three sites — the
   scanner's pruned and full ingestion). The daemon's Rust paths
   (`chain-ingest`, `chain-store`, `chain-rules`) never call it; they parse
   with `from_bytes` and rely on the C++ validator of record. So there are
   **three** copies of 4.H today: the C++ (of record), the wire twin (the
   wallet's), and — after this slice — `tx_form`.
2. **The wire crate cannot host the rules.** It *"intentionally has no
   dependency for elliptic-curve math"* (`transaction.rs:1661`), so H7, H11,
   H17, H18 cannot live there; and it has no `RuleSet`, so H1/H3/H16's
   parameters are `const`s. A validator that cannot host a third of the
   family is not the family's home.
3. **The wallet needs the twin to keep working.** Moving the content to
   `shekyl-chain-rules` and having the wallet call `tx_form` makes the
   wallet stack depend on the consensus crate (and transitively on
   `shekyl-economics`, `shekyl-ct-balance`, `shekyl-difficulty`, …). That
   is the *right* dependency direction in principle — one validator — and
   a real build-graph change in practice (`shekyl-engine-core` is large;
   `shekyl-chain-rules` pulls the store's view traits). Not a slice-5
   decision to make silently.

**Proposed (Q1 default): `tx_form` is the validator; the wire twin is
demoted to a *conformance-tested pre-check*.** Concretely: (a) every 4.H
row lands as a row-keyed `TxRule` in `rules/tx.rs`; (b) a conformance test
in `shekyl-chain-rules` builds, for each wire refusal arm, the transaction
that trips it, and asserts `tx_form` refuses it **on the named row** —
the wire twin's arms become fixtures for the crate, so a divergence
between the two Rust copies fails a test rather than surfacing at submit;
(c) the wire crate's `validate` keeps its callers and gains a doc header
naming `tx_form` as the rule of record and the conformance test as the
tie; (d) the question of the wallet calling `tx_form` directly is filed
with a falsifier (the build-graph cost measured), owner
`WALLET_REWRITE_PLAN.md` or the engine's contract, not decided here.

### 3.1.1 What the enumeration found — LANDED with commit 8, 2026-09-23

**Why the table has arms for rows the crate has not implemented.** That is
the design, and the more valuable thing in the commit. A rule arm is held
to its row *by the row's registry status*, read at test time: implemented →
refused on the row; by construction → the tripping value does not
round-trip the wire; pending → nothing yet. So the **fourteen** pending-row
arms (I1 ×2, I4, I5, I6, I8, I9, I16, J2, J11, J12, H19 ×3 — counted from
the table's `rule(…)` rows with a trip; the review's "twelve" was my
under-count) begin asserting **the day their row flips**, with no pin to
update and no one touching the test. It gets stronger on its own. This is
exactly the shape the H24 proxy (§8 Q7) could not have: H24 has no row to
read a status from, so its test carries a pin and an instruction instead.

Classifying all 59 sites, rather than sampling the fourteen predicates,
turned up things a sample would not have. Each is recorded in the table
row's `note` and here; none is this slice's to fix beyond recording.

- **The twin refuses a policy cap as if it were consensus.** `MAX_TX_EXTRA`
  (24 576) is `CEN-M4`, flag P: *"consensus side has no tx_extra bound
  beyond CEN-H1."* The twin refuses a 24 577-byte `extra`; `tx_form`
  accepts it (H1 and H3 both pass). Recorded as a **divergence with
  `Outcome::Accepted`**, keyed to `PolicyRow::M4` — the fourth arm. A
  wallet pre-check saying what the pool will refuse is legitimate; the
  census row it answers to is the policy one, and the E5 admission policy
  is where the Rust holder of M4 will live.
- **Two arms are reachable only by the storage-pruned form.** The twin's
  fee-only arm (`prunable: None` ⇒ no outputs, empty `pqc_auths`) asserts
  H20's shape on *any* transaction without a prunable region. Since `RF-D1`
  the serve-credit carries one, and its own shape arm fires first — so the
  fee-only arm is reachable only by a `prunable: None` **non**-serve-credit
  transaction, which the C++ has no value for (its prunable is always a
  struct) and which `Option<Prunable>` admits. The crate classifies by the
  vin and refuses the same values on **H21** (a bond post with no funding
  spend). Recorded as divergences with `Outcome::RefusedOn(H21)`; the owner
  is the FOLLOWUPS row for `Transaction::full/pruned` (the pruned form made
  unrepresentable at the boundary, not refused twice for two reasons).
- **One arm is dead — by ordering, and only by ordering.** `{n_ki} key-image
  input(s) but no prunable proof` cannot fire because (1)
  `validate_context_free_pruned` runs first and its `>= 2` arm forces
  `n_out >= 2` for any key-imaged tx, and (2) inside the fee-only arm the
  *outputs* check precedes this one. Classified **invariant** with **both
  orderings named in the note**, because an ordering argument is exactly
  what a newly inserted rule breaks: slice 6 adds proof verification to
  this path, and whoever reorders it must find out they have made a dead
  arm live. **Re-check owed at slice 6's pre-flight.** The proof's
  non-emptiness is `CEN-I14`'s, held elsewhere.
- **The holdings shard-set bound has no census row.** `MAX_HOLDINGS_SHARDS`
  (4 096) and duplicate-freeness are `ShardSet::new`'s (`bond_wire.rs`),
  which `ARCHIVAL_BOND_ADD_ADMISSION.md` names as *the one fallible
  constructor*; the wire mirrors it so two decoders cannot diverge, and the
  wire's own doc calls it a *consensus bound*. No `CEN-` row names it.
  Classified **parse** (a codec's well-formedness, owned by the codec's own
  gate) rather than keyed to the nearest J-row — the Q8 mis-keying this
  slice's review named. **This is a finding about the census, not a
  classification problem**, and it is the second of its kind: slice 4's
  shim sweep found the S25 arity gate uncensused, and it turned out to
  ground CEN-L11's grading. Two consensus-adjacent limits with no row, both
  found by enumerating something for a different reason. The question for
  the census lane — *did the sweep cover `shekyl-wire`'s constants at all?*
  — is the same question slice 4 raised about `src/shekyl/*.h`, still
  unanswered; it is now carried on that FOLLOWUPS row with both grounds.
  A slice does not amend the census on its own.
- **The signature-blob cap has no census owner either.** `CEN-I16` names
  `PQC_MAX_PUBLIC_KEY_BLOB` as the multisig key blob's bound (→ `Rule(I16)`);
  nothing names `PQC_MAX_SIGNATURE_BLOB`. The wire's doc calls both DoS
  ceilings *decoupled from correctness*. Classified **parse**, note says
  why; same disposition as the shard bound.
- **`CEN-I5` subsumes `CEN-H10` on the wire.** The twin has one arm
  (*strictly descending*), which refuses a repeat as a non-descent. Keyed
  to I5 (pending); H10 is landed in the crate and refuses the repeat on its
  own row. When I5 lands the arm's row asserts the crate refuses the
  ascending pair on I5 — the self-arming form.
- **`CEN-I6`'s arm is the one H24's proxy waits on.** The table row for
  *non-empty key_offsets* is `Rule(I6)`, pending; when I6 flips, this row
  demands that `tx_form` refuse the offsets fixture on I6 — the assertion
  §8 Q7's proxy says must be added by hand to `h24_…`. The conformance row
  arms itself; the H24 test still carries its instruction because its
  subject is H24's vacuity, which is a different sentence.

### 3.2 `validate` runs `tx_form` on the coinbase

`validate.rs:315–327` judges `TxSlot::Miner` through `judge_tx` (→
`tx_form` + `tx_against`) exactly as it judges listed transactions. In the
C++, `ver_non_input_consensus` runs on **pool-supplement** transactions
only; the coinbase gets `prevalidate_miner_transaction` (4.F) and three
4.H bodies called from the block path (`check_tx_outputs` at
`blockchain.cpp:1692` — H12; `check_commitment_mask_valid` at `:1699` —
H17; and the `Null`-type admission — H15). So for the coinbase the 4.H
family is **partly applicable, partly overlapping 4.F, and partly
non-coinbase-only by statement** (H4, H13, H15's Null re-rejection, H5's
`gen` half). Slice 4 already fixtures the overlapping predicates at
`TxSlot::Miner` under F-rows (F3 = Null, F8/F9/F10 = H12/H7/H17 for the
coinbase). Q2.

### 3.3 The archival taxonomy is single-sourced in C++ and needs to be in Rust

`classify_archival_tx` (`cryptonote_basic.h`) is read by
`check_inputs_types_supported`, `check_tx_inputs`, `check_tx_outputs` and
the NIC arms — H6, H14, H20, H21, H22 all key off its `kind` and
`spend_input_count`. The wire crate has the pieces
(`is_serve_credit_only`, `spend_input_count`, `serve_credit_input_count`,
the per-arm counts inside `validate_context_free_pruned`) but no single
classification value. Q4 proposes one — in `shekyl-chain-rules`, not the
wire crate, since it is a rule-side notion ("what kind of transaction is
this, for the purpose of which shape applies").

### 3.4 H19 is the slice's only crypto cutover, and it is batched at the block

The BP+ *layout* is a per-tx predicate. The *proof* is verified in the C++
**batched across all the block's transactions** (`ver_mixed_ct_semantics`
collects `rvv` over the supplement and verifies once). A per-tx `tx_form`
that verified each proof alone would be correct and slower; the batch
belongs to `validate` (a fold over the listed transactions' proofs after
`tx_form` has accepted each layout), which makes the verification half a
**block-level** consumer of a per-tx claim — the same shape as D4's window
over recorded work. And it is a cutover: `shekyl-bulletproofs` has never
been the verifier of record. Q3.

### 3.5 What the daemon's Rust does not do today

`chain-ingest` parses transactions (`corpus.rs:317`) and hands them to
`validate` without any 4.H check; `chain-store` connects what `validate`
accepts. Until this slice lands, **a store fed by E2's corpus records
transactions the Rust never judged as transactions** — which is exactly
the ratchet the coverage gate exists to show: `tx_form` records
`RuleCoverage::EMPTY`, and `covers_landed` holds `validate` to the landed
set only. Landing 4.H moves the ratchet; it does not need a new gate.

---

## 4. Substrate this slice adds (sketch; shaped by §8)

- **`rules/tx.rs`** — `pub(crate) trait TxRule: Rule { fn check(cx: &TxContext) -> Verdict<()> }`
  (the third rule class the module docs promised, `rules/mod.rs:48`);
  `judge_tx!` in the `judge_form!` / `judge_block!` family; the 4.H
  structs. **`TxContext { tx: &Transaction, kind: TxKind, rule_set: &RuleSet }`**
  where `TxKind` is `Coinbase | Listed` (Q2) — derived in `tx_form` from
  `tx.is_coinbase()`, never passed by the caller, so the pool cannot
  mis-declare it.
- **`Archival` classification** (Q4, amended): `enum TxClass { Spend, ServeCreditOnly, BondPost { spends, credit, debit }, Emission { spends }, Coinbase }`
  derived once per transaction, consumed by H6/H14/H20–H22; refuses the
  mixings H6 names as it derives (the C++'s `classify_archival_tx` does
  both jobs too). `credit` and `debit` are the one post's terms, copied
  at derivation. The class does not store an input index.
- **`RuleSet` parameters** (Q5): `max_tx_size`, `max_tx_weight` (derived:
  `min_block_weight / 2 − coinbase_blob_reserved`), `unlock_time_sentinel`
  — pinned by parsing `cryptonote_config.h` as slice 4's two were, and
  held equal to the wire crate's constants by test.
- **Coverage**: `tx_form` returns the 4.H rows it evaluated; `validate`
  unions per slot as today. A row that is non-coinbase-only records as
  evaluated-vacuous on the coinbase, the E1-at-unanchored-height precedent
  (Q2).
- **Fixtures**: one negative fixture per implemented row asserting **the
  row at `TxSlot::Lone`** (the pool's position) and, through `validate`, at
  `TxSlot::Listed(n)`; the §3.1 conformance test over the wire twin's
  arms; pinned vectors for H11 (KI domain) — DSV M8's, re-derived.

---

## 5. Fixtures per row and commit plan — Round 1 (2026-09-23)

On slice 4 Q7's rule (rules first; shared substrate where the rules need
it; anything cross-lane last). Every implemented row gets a negative
fixture asserting **the row at `TxSlot::Lone`** and, through `validate`,
at `TxSlot::Listed(n)`; every by-construction entry a falsifier; every
parameter a pin that parses `cryptonote_config.h` and an **equality test**
against the wire crate's constant (Q5 as ruled — a test, not a comment).

| # | Commit | What |
| --- | --- | --- |
| 1 | `TxRule` / `TxContext` / `judge_tx!` — **LANDED `73afbce67`** with H1, H3, H4, H16 | The third rule class; `TxKind::{Coinbase, Listed}` derived from the **slot** (`tx_form(tx, slot, rule_set)`; Q2 as amended); scope on each rule (`All` / `NonCoinbase`), out-of-scope rows recorded vacuous. Landed with the four rows whose operands are frozen constants so no item arrived without a consumer (rule 21): H1 size, H3 weight, H4 ≥ 1 input, H16 unlock sentinel |
| 2 | The limits (Q5 as amended) — **LANDED in commit 1** | `MAX_TX_SIZE`, `UNLOCK_TIME_SENTINEL`, `COINBASE_BLOB_RESERVED` as `const`s in `rules/tx.rs`, `max_tx_weight()` **derived** from `FULL_REWARD_ZONE / 2 − COINBASE_BLOB_RESERVED` — never restated as 149 400; pins parse `cryptonote_config.h`; equality tests against `shekyl_wire::transaction::{MAX_TX_SIZE, UNLOCK_TIME_BLOCK_SENTINEL}`. Not `RuleSet` fields: F21's test |
| 3 | `TxClass` (Q4) — **LANDED `2723fd5a9`** with H5 (`gen` half), H6, H9, H14 | Rule-side archival classification, derived once at `TxContext::derive`; H5 and H6 judged as it derives, recorded at the derivation site. H16 corrected to `NonCoinbase` (the `:1692` pin named a site the coinbase does not reach). Three fixtures in the crate and one in the store listed coinbase-shaped bodies; H5 refused them |
| 4 | Structural rows — **LANDED `7c44aca09`**: H10, H15 (Null half; Q9), H20, H19's layout half (refuses under `H19`, records nothing; the row stays `pending` for slice 6's verification half) | H21/H22 are shape *and* balance in one row each and land whole in commit 5. What the layout rule found: every spend fixture in all three crates was the storage-pruned form (outputs, no prunable region, no `pqc_auths`) — the skeleton a pruned node keeps, not a wire transaction — and round-tripped only because the codec must accept skeletons. Fixed with per-input filler auths, a canonical-layout filler BP+, one pseudo-out per spend; a spend is therefore 4-part, the store's `spend_with_pqc_auth` deleted, the 3-part non-coinbase body in A3/T3/T4 is the serve-credit fixture. Root cause filed in FOLLOWUPS: `Transaction` conflates the wire form and the pruned form |
| 5 | Adopted crypto rows | H7, H17 (listed txs; the coinbase half is F10), H18, the H20–H22 balances — all through `shekyl-ct-balance`. **Fixture pass (2026-09-23), fixed in this commit, not ahead of it — the rule's landing is what shows it catching something real:** the other crates' fixtures fill *structure*-typed values with byte patterns, which a hash or a root tolerates (a bag of bytes) and a curve point does not: `chain-ingest/src/test_support.rs:131` `key: [0x80; 32]` and `:142` `commitments: vec![[0xa0; 32]]`; `chain-store/src/store/connect_fixtures.rs:54` `key: [0x80 + i; 32]` and `:66` `commitments: [0xa0 + i; 32]` (N distinct per output); `chain-store/src/store/output_read_tests.rs:193–194` the recorded `[0x81; 32]` / `[0xa1; 32]` pins that follow from them. H7 refuses the keys, H17 the masks; and **H11 (commit 6) refuses every store spend fixture's key image** — `connect_fixtures.rs:42` `spend(key_image: u8, …)` writes `[fill; 32]` by its *signature*, so that fix changes an API used across the store's connect and pop tests, not a handful of literals. **One table, not three** (ruled 2026-09-23): output keys, commitments and key images all want distinct canonical points and no 4.H rule links them, so a single pinned table `fixture::POINTS` serves all three; ceiling **16** (the wire's `MAX_OUTPUTS`; the widest store fixture has 2; key images draw from the same table at other indices). The extension point is `harness::fixture`'s `G`/`2·G`, pinned by `miner_tests::fixture_points_are_what_they_claim` through `shekyl_ct_balance::check_output_keys` / `check_commitment_masks` — the table's gate asserts pointness and pairwise distinctness, which is all a fixture needs of it. **The `output_read_tests.rs:193–194` pins are derived from the table by name, never re-pinned as literals** — an expected-value change is where a pin quietly becomes "the code does what the code does". `reference_block` / roots / hashes stay as they are: bags |
| 6 | H11 | KI domain: prime-order, ≠ identity — new Rust body on the crate's point primitives, DSV M8's vectors re-derived and pinned |
| 7 | By-construction entries (Q6, Q7) — **LANDED `c795c203f` + `d87cc3871`** | Registered: H2 and H13 (F2's falsifier), H8 (`h8_the_wire_reads_one_commitment_per_output`), H12 (F8's), H23 (`doctest:tx_form`); `by-construction 4 → 9`. **Not registered, as planned here, and the plan was wrong:** H5's script half and H15's type half are halves of rows already `implemented` — a row has one status; H24 is **bucket 3** and the registry excludes bucket-3 rows by design, so it has no `CenRow` to carry any status (Q7's amendment, §8). **Q6's condition landed as a MECHANISM:** a shared falsifier calls `credited_to_this_falsifier(&[rows…])` and the coverage gate refuses a shared falsifier whose body does not name every served row as `CenRow::<id>` (`check_chain_rules_coverage.py`, selftest green + red) |
| 8 | The §3.1 conformance test (Q1 as ruled) — **LANDED (this commit)** | `rules/tx_conformance_tests.rs`. **Enumerated:** all **59** `Err(` sites in `shekyl-wire/src/transaction.rs` are rows of one table, checked against the file itself (`include_str!`: the count, and each fragment found as many times as listed). **Four arms, pinned `(parse 15, rule 38, policy 1, invariant 5)`** — the review asked for a third arm so an assertion-shaped site is never forced into the nearer bucket; the classification needed a fourth, because one site (`MAX_TX_EXTRA`) is **CEN-M4**, a policy row: the crate already keeps policy rows in their own enum so one is never counted as consensus, and forcing it into `Rule` would be the mis-keying the third arm exists to prevent. Every in-memory rule arm carries the transaction that trips **it** (the twin's message is matched, placeholder-aware, so an earlier arm firing is a failure); the crate is then held to the row **by the row's registry status** — implemented → refused on that row; by construction → the value does not round-trip the wire; pending → nothing yet, and the assertion **arms itself** when the row flips (no pin to update — the shape H24's proxy could not have). Read-face rule arms must be by-construction rows or mirrored by an in-memory arm keyed to the same row (checked). The baseline (coinbase, two-output spend, serve-credit) passes **both** copies. **Findings the table surfaced** (§3.1.1) |
| 9 | Docs — **LANDED (this commit)** | **Landing figures** (coverage gate at head): `implemented 34 → 56` of 153 census rows; `by-construction 4 → 9`; `enforced 145 → 140` per-block rows; 4.H: 17 `implemented`, 5 `by_construction`, H19 `pending` with its layout half running, H24 bucket 3 (no row). Tests: `shekyl-chain-rules` 193 + 15 doctests, `shekyl-chain-store` 292, `shekyl-chain-ingest` 74, all green; coverage-gate selftest 63 refusals. **Census 4.H pins re-resolved — twice.** At `f17fba8e6` the window diff over the wire crate and the three 4.H C++ files was empty and I wrote "the pins stand" — an inference from *the files did not move in the window* to *the pins are right*, which does not follow. Re-run at `d8ebfd18c` (#837, after rebase): TXE **had landed** (`50256487f`, `3ab84bab6`; CEN-I20 minted), moving `cryptonote_format_utils.cpp` by −260/−280 lines and `blockchain.cpp` by −2 — and reading the pinned lines showed the `blockchain.cpp` and `cryptonote_core.cpp` pins were **already stale before the window** (H13's `3348–3353` pointed at `have_tx_keyimges_as_spent`; H5's `3162–3168` at a FIXME comment; H8's `797–805` at the tx_extra shape check). **Twenty 4.H site cells re-pinned to function anchors at `d8ebfd18c`**, each cell carrying its era. *Records-was:* the first pass re-pinned sixteen and wrote that the other eight "did not move" — the same inference, made a second time in the same paragraph that retracted it, because the window diff had been scoped to `src/cryptonote_core` and `src/cryptonote_basic` and **`src/fcmp/ct_semantics.cpp` had moved −46 lines** (TXE deleted `:86–131`). The review asked whether the eight had been verified by reading the pinned lines; reading them re-pinned five more (H18, H19, H20/H21's `ct_semantics` halves, H22 — all exactly −46, so they had been right before the window — and H23, whose `199–208` was the `_base_` variant). **Four cells verified by reading the pinned lines and left:** H2 (`tx_verification_utils.cpp:55–78`, the version bounds and the check at `:74`), H3 (`:82`, `:203–209`), H10 (`cryptonote_core.cpp:819`, `:913–943`), H11 (`:835`, `:963–981`). The re-read also refuted Q9's DIVERGENT grading of CEN-H15 (§8 Q9). The twin's `Err(` count at `d8ebfd18c` is still 59 (the conformance table holds). `CHAIN_RULES_CRATE.md` §4.6 (the `TxRule` class, the slot-derived kind, the landed rows, the twin's demotion) and §8.5 (the fixture-sanity gate; the conformance table and **why it has arms for unimplemented rows**); index row; FOLLOWUPS (the skeleton row's first measured consequence; the shim-sweep row's second instance and the `shekyl-wire`-constants question for the census lane); CHANGELOG |

**H19's verification half** stays `pending` in the registry (Q3 (b)),
with the layout half's fixture landed under it and the blocker named:
*blocked on slice 6's proof-body cutover — falsify by `shekyl-bulletproofs`
KAT equal to the C++ verifier over the pinned corpus.* The corpus is
decoupled from TXE's schedule by §1.2 item 3 as amended.

---

## 5.1 The slice-6 cascade, scoped now (2026-09-23)

Every spend fixture in the three crates carries **filler** proof material —
`fixture::bp_plus_layout_for` (canonical layout, filler scalars),
`fcmp_proof: [0xF0]`, `pqc_auth_filler()` (empty blobs), a `TWO_G`
pseudo-out. Nothing landed verifies any of it, and that is stated on each
builder. **Slice 6's verification bodies will refuse every one of them at
once**, and the fix is not a constant: a real proof is needed, and proving
is expensive, so per-test generation is not the answer. The answer is
**capture** — generate once through the production Engine (the capability
exists: `e2e_fcmp_spend_accepted_by_daemon`, `regtest_e2e.rs:865`, builds a
spend a live daemon accepts), commit the bytes as test data, have the
fixtures load them — the `TX_EXTRA_PQC_ROUND_TRIP.json` shape: derive
once, commit the result, never make the test depend on a deriver.

**The capture surface, from what the fixtures actually use** (grep at
`6e7cc9db4`): the store's `spend(ki, outputs)` is called with `outputs = 1`
thirty-three times and `outputs = 2` four times; the ingest's `spend` and
the harness's `listed` are 1-in/1-out; every spend has **one** input. So
the verification-era fixture set is **three shapes**: 1-in/1-out,
1-in/2-out, and — for H21/H22 — one bond-post and one emission with one fee
spend each; plus one **tree-depth** variant (the depth-3 mine exists,
`regtest_e2e.rs:1064`) so a proof is not only ever verified against a
depth-2 tree. Five captured transactions, each a `.tx` blob under
`rust/shekyl-chain-rules/tests/vectors/` with the block context the proof
is against (reference block, tree root, membership set) beside it. That is
cheap and permanent. What would make it a design problem is a fixture that
needs its own shape — H19's layout tests up to 16 outputs are *layout*
tests and stay filler; the 16-output *verified* spend is not a shape any
fixture needs.

The key images the captured spends consume are theirs, so the store's
`spend(key_image: u8, …)` API — which fills the image — cannot survive
capture as it stands: a captured spend has one key image, and a test that
needs "the same body with a different image" needs a different capture or
must accept SI-1's view. That is the API change the H11 note in §5 commit 5
already forecasts, arriving from a second direction.

Filed as a FOLLOWUPS row owned by `CHAIN_RULES_CRATE.md` (the harness
contract) with slice 6's pre-flight as the consumer; the sanity gate's
failure text names the mechanism so the red is read as a finding.

## 6. What this slice does not build

- **The pool** (DRS-E5). `tx_form` stays callable on its own; the pool's
  admission path, its view decorator for `tx_against`, and G3's
  supplement re-verification are E5's and 4.G's.
- **4.I** — every input-side rule (I5 ordering, I6 empty offsets, I10–I15
  membership and reference age, I19 the extra shape): slice 6. H21's
  funding-input half goes with them.
- **The wallet calling `tx_form`** (§3.1 (d)) — filed, not built.
- **Anything TXE touches** (§1.2).
- **H24's C++ deletion** — a cutover-time deletion; this slice records the
  disposition (Q7), it does not delete C++.
- **The C++ NIC path.** As in every slice: no C++ behaviour changes; the
  C++ remains the validator of record until cutover.

---

## 7. Round log

- **Round 0 (2026-09-23, `dev` @ `387fa84a9`).** This document. 24 rows
  audited by symbol against live C++ and against the Rust that exists.
  The headline finding is §3.1: fourteen rows already run in Rust, in the
  wire crate, for the wallet only. Rulings owed on Q1–Q8.
- **Round 1 (2026-09-23).** The headline verified independently at source
  (`:1984`, `:1673`, an inner `validate` at `:714`, 59 `Err(` sites;
  production caller `block_fetch.rs:200`). Q1 (a) with the enumerated
  subject; Q2 default; Q3 (b), decoupled from TXE by capturing the vectors
  in the deletion commit; Q4/Q5 default, the constant equality a test;
  Q6 yes on the any-row-stops-being-vacuous condition; **Q7 overridden to
  `by_construction`** on I6's exclusion; Q8 proceed. §5 is the plan.

---

## 8. Questions for the reviewer — Round 0

- **Q1 — the wire twin (§3.1). RULED (a), 2026-09-23 — with the conformance test's subject ENUMERATED, not sampled: all 59 `Err(` sites classified (§5 commit 8). AMENDED at review before commit 8 (2026-09-23): THREE arms, not two — parse / rule → row / "neither: an invariant" — so an assertion-shaped site is never forced into the nearer bucket and keyed to a row that does not exist (the Q8 mis-keying, 59 times); the count reported as three numbers. LANDED with FOUR: one site is `CEN-M4`, a POLICY row, and the crate keeps policy rows in a separate enum precisely so one is never counted as consensus — `Arm::Policy(PolicyRow)`; pinned `(15, 38, 1, 5)`. Findings: §3.1.1. The finding's weight, as ruled: ~fourteen consensus predicates have two implementations — the wallet's Rust twin and the daemon's C++ — and nothing reconciles them; a transaction one accepts and the other rejects is undetectable today.** Default **(a)**: `tx_form` is the rule of
  record; every row lands row-keyed in `rules/tx.rs`; a conformance test
  in the crate holds the wire twin's refusal arms to named rows; the wire
  twin keeps its wallet callers and a header naming the tie; the wallet →
  `tx_form` dependency question is filed with a measured-cost falsifier.
  **(b)**: `tx_form` calls `Transaction::validate()` and records the rows
  it "covers" wholesale — rejected in advance: an `io::Error` string is
  not a row, and slice 2's assert-the-row discipline (which Q8 of slice 4
  just re-earned) has no purchase on it. **(c)**: delete the wire twin now
  and make the wallet call `tx_form` — the right end state, but a
  build-graph change to `shekyl-engine-core` this slice should not carry
  silently; if you want it, it is its own commit with the cost measured.
- **Q2 — the coinbase under `tx_form` (§3.2). RULED default, 2026-09-23; AMENDED at commit 1 and the amendment RULED better than the default (2026-09-23): the kind derives from the SLOT, not from `is_coinbase()`. A sole-`gen` transaction submitted alone or listed in a block is coinbase-shaped; a bytes-derived kind would classify it `Coinbase` and exempt it from H5, the row whose job is refusing it — the input would select the rules it is judged under. The C++ has no gap only because `ver_non_input_consensus` never sees a coinbase, an accident of call site. Principle, recorded on `TxKind`: a classification that selects which rules apply must come from outside the thing being classified; authority sits with what the adversary does not author. `tx_form(tx, slot, rule_set)`; the pool holds only `Lone`.** `validate` already runs
  `tx_form` on `TxSlot::Miner`. Default: `TxContext::kind` is derived from
  `is_coinbase()`; each 4.H rule declares its scope (`All`, `NonCoinbase`);
  out-of-scope rows record as evaluated-vacuous (E1's precedent); the
  overlapping predicates (H7/H12/H17 on a coinbase) **run again** under
  their H row rather than being skipped because F9/F8/F10 ran — two rows,
  one body, both recorded, no cross-family "already checked" reasoning in
  the validator. Alternative: `validate` skips `tx_form` for the miner and
  4.F is the coinbase's whole family — cleaner coverage, but it diverges
  from the C++'s three coinbase-side 4.H calls and from the contract's
  "`validate` calls `tx_form` … for the miner tx and each listed tx"
  (`CHAIN_RULES_CRATE.md:645`).
- **Q3 — H19's verification half (§3.4). RULED (b), 2026-09-23, decoupled from TXE's schedule: vectors captured as committed data in TXE's deletion commit (§1.2 item 3).** The BP+ range-proof check is a
  **crypto cutover**: `shekyl-bulletproofs` would become the verifier of
  record for the daemon where `bulletproofs_plus.cc` is today. **(a)** land
  layout in slice 5 (row-keyed, `tx_form`), and the batched verification in
  slice 5 too as a `validate`-level fold, with a differential KAT against
  the C++ verifier through the existing FFI over a pinned corpus of
  tx-builder proofs (valid, and mutated invalid) — **pinned before TXE's
  `core_tests` deletion merges, or regenerated**; **(b)** layout in slice 5,
  verification with slice 6's proof bodies (`shekyl_fcmp_verify`,
  `shekyl_pqc_verify` are Rust already) so all three proof verifications
  cut over in one reviewable place. Default **(b)**: one row half-landed
  needs a status the registry does not have; if (b), H19's registry entry
  stays `pending` with the layout half's fixture landed under it and the
  verification half's blocker named (*falsify by: `shekyl-bulletproofs`
  KAT equals C++ over the pinned corpus*). If (a), the KAT provenance
  question above is yours to rule.
- **Q4 — one archival classification (§3.3). RULED default, 2026-09-23. AMENDED after review: `BondPost` carries `{ spends, credit, debit }` copied from the one post at derivation, not an index back into the inputs — a failed re-lookup was a classifier bug reported as CEN-H21. `Emission` is `{ spends }`; its index was unread.** Default: a rule-side
  `TxClass` in `shekyl-chain-rules`, derived once, consumed by H6, H14,
  H20–H22; refuses H6's mixings as it derives. Alternative: put it on
  `shekyl_wire::Transaction` — it fits the wire crate's "shape" vocabulary
  but makes the codec carry a consensus classification, which is the
  §3.1 error in miniature.
- **Q5 — parameters. RULED default, 2026-09-23 — the wire-constant equality is a TEST, not a comment. AMENDED at commit 1 and RULED on reason one (2026-09-23): the limits are `const`s beside their rules, not `RuleSet` fields, by F21's test — a limit joins the set when a schedule step can name a different one, and no schedule step varies `max_tx_size`, the weight limit or the sentinel. Everything else ruled survives: parsed from `cryptonote_config.h`, `max_tx_weight()` derived and never restated, wire equality a test. Reason two as first written (Fault's width) was MISATTRIBUTED and is corrected in `fault.rs`: `Stale::Seed` carries two `BlockHash`es; it is `Stale::RuleSet` that carries `formed_under` / `in_force` by value, because slice 2 Q10's runtime-parameterised rule set made `RuleSetId` stop being a key. That is Q10's first presented cost; the honest statement is "`Fault` is large because `RuleSetId` is not a key", not "because limits would be fields", and the fix if it ever matters is boxing `Stale::RuleSet`'s payload, keeping the by-value comparison.** `max_tx_size` (1 000 000), `unlock_time_sentinel`
  (500 000 000) and the **derived** `max_tx_weight`
  (`min_block_weight / 2 − coinbase_blob_reserved` = 149 400) as `RuleSet`
  fields, pinned by parsing `cryptonote_config.h` and held equal to the wire
  crate's `MAX_TX_SIZE` / `UNLOCK_TIME_BLOCK_SENTINEL` by test. `MAX_OUTPUTS`
  (16) and `MAX_FCMP_INPUTS` (8) are **not** 4.H rows (they are §10 wire
  caps and 4.I's input cap) and stay where they are.
- **Q6 — duplicate and redundant rows. RULED yes, 2026-09-23, on one condition: an entry serving N rows names every row it serves, and its falsifier fails when ANY of them stops being vacuous — otherwise it is one test counted N times.** H13 is H2's third site; H12 is
  F8's ground on a listed tx; H5's script half and H15's type half are
  enum-arm facts. Default: **one `by_construction` entry may serve several
  rows** — the registry lists each row with the same `(property,
  falsifier)`; the gate already accepts a repeated falsifier. H10 is
  implemented in slice 5 as its own predicate (cheap, row-keyed) and slice
  6 decides at I5 whether it collapses.
- **Q7 — H24's status. OVERRIDDEN 2026-09-23: `by_construction`, property = CEN-I6's exclusion of the input H24 checks, not `held_by_cxx` — `held_by_cxx` requires a test showing the holder REJECTS (the condition that found A1/A4 untested), and a rule that cannot fire has no rejection to show; the entry would fail its own condition on arrival. AMENDED at commit 7 and the amendment TAKEN AS LANDED (review, 2026-09-23): H24 is BUCKET 3 and the registry excludes bucket-3 rows by design, so there is no `CenRow::H24` to carry `by_construction` or any status — that is the bucket working, not a gap in it; re-bucketing so an instrument could hold a status would be fitting the subject to the instrument. The FALSIFIER exists anyway (`h24_cannot_fire_on_an_input_i6_admits`), was a labelled proxy and is no longer one (review, 2026-09-23): it asserts the residue predicate on an empty offset list and on `[7, 0]`, and that `tx_form` still accepts the offsets fixture — the acceptance is the gap, and the `expect` fails on its own the day a row refuses that fixture, and is indexed from BOTH ends: the census cell cites the test, the test names `CEN-H24` — H24 is outside every counting instrument, and those two are the only things that index it (`d87cc3871`).** It is deletion residue with a named disposition
  (census §10 R5) and can never fire under CEN-I6. The registry today has
  `pending`, `implemented`, `enforced_at`, `by_construction`, `held_by_cxx`.
  Default: **`held_by_cxx`** until cutover deletes the C++ body, with the
  census row carrying *"deleted at cutover; never a Rust rule"* — the
  status that already means "the C++ holds this, Rust does not implement
  it". Alternative: a new `RowStatus::Retired` — rejected in advance (rule
  23: a retired row is REJECTED's shape, and the census row is its record;
  no code symbol).
- **Q8 — sequencing against TXE (§1.2). RULED proceed now, 2026-09-23.** Default: slice 5 proceeds now on
  the boundary stated in §1.2; the docs commit re-resolves 4.H pins against
  `dev` at landing; whichever lane lands second owns any pin shift. If you
  would rather TXE land first so the pins are resolved once, say so and
  Round 1 waits on its merge — the code commits do not depend on it either
  way.
- **Q9 — the Fakechain `Null` exemption (found at commit 3, `7c44aca09`).
  RULED unconditional, 2026-09-23; its DIVERGENT grading REFUTED the same
  day (below).** *As posed:* the C++ re-rejects `CTTypeNull` for a
  non-coinbase transaction only when `m_nettype != FAKECHAIN`
  (`blockchain.cpp:3398`) — nettype selecting control flow on the consensus
  surface, rule 71's prohibition verbatim, inherited so C++ tests could
  build spends without proofs: the stub builder TXE-Q1 deletes. The regtest
  e2e builds real FCMP spends and never needed it. `H15` is unconditional.
  *(The "only when" was the error — see the refutation.)* **Arm
  (d)** — data on the Fakechain rule set, the slice-2 fixed-difficulty
  shape — was rejected: it would make H15 the first 4.H rule to read
  rule-set data for a carve-out whose only consumer is a builder being
  deleted, inheriting a workaround into the design built to escape it, and
  putting a Fakechain-only branch into the crate that just spent a slice
  removing one. **The divergence claim is REFUTED (row 9's pin
  re-resolution at `d8ebfd18c`, 2026-09-23) — the ruling stands, its
  grading does not.** The CSR-3a row was set `DIVERGENT` on the claim that
  the C++ accepts a `Null`-CT spend on Fakechain. It does not: the gate at
  `blockchain.cpp:3396–3402` is CEN-I2's *earlier* refusal, and below it
  H15's own pinned site `ver_non_input_consensus`
  (`tx_verification_utils.cpp:223`), `check_tx_inputs`'s `switch`
  (`:3550–3554`) and the `else` at `:3539–3544` each refuse `Null` for a
  non-coinbase on every nettype. I read the gate and not the belt under it
  — rule 16's corollary, *"true of the design and false of the
  implementation"*, committed by the lane that quotes it. `H15` stays
  unconditional; the C++ is too; CSR-3a is `CHECKED-CONFORMANT` with the
  mis-grading recorded as records-was, and the census H15 note corrected.
  The Fakechain gate remains rule 71's prohibition verbatim — owned by
  CEN-I2/I3/I4's "FAKECHAIN exempt", where slice 6 meets it.
