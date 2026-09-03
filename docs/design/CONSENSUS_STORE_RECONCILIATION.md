# Consensus rewrite ↔ daemon chain store — reconciliation

**Status:** OPEN. Reconciles two design programs that target the same six
C++ files on orthogonal cuts and, until this document, did not reference each
other in either direction. Records the **2026-09-01 countermand** (§0) and its
blast radius across both programs' binding decisions.

**Pinned:** `dev` @ `47bfa66c3` (the merge of PR #593) for the row-level reads;
**re-verified at `bf317111f`** (PR #592, C2-R3) and again at **`4b9807c5e`**
(PR #596, C2-R1) — the census has been re-bucketed twice under this document.
C1 close recorded 87 / 14 / 2 / 68; C2-R3 promoted CEN-C2/C3 to bucket 2
(87 / 16 / 2 / 66); C2-R1 then moved three more rows to bucket 3, so the live
split is **86 / 16 / 5 / 64** (total still 171). The **18-row store-enforced set and its 7 / 1 / 10
bucket split are unchanged** (re-derived mechanically at the later sha); every
aggregate below is stated in whichever denominator it belongs to.

**Identifier family:** `CSR-*` (registered at birth, rule 94 §1; prefix checked
tree-wide — zero hits before this document — and unique against every
registered family under alphabetic-until-digit: distinct from `CB-`, `CEN-`,
`CR-`, `CT-`, `CT-ACT-`, `CW-`).

**Sources reconciled:**

| Program | Document | Family | What it cuts by |
| --- | --- | --- | --- |
| All-Rust consensus rewrite | [`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) | `CEN-` | **rule** (171 behavioral statements) |
| Daemon chain store | [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) | `DRS-` | **DB call surface** (97 `m_db->` methods → S-TXN…S-PRUNE) |

**This document rules nothing about consensus content.** It establishes where
the two programs overlap, records the countermand, and lists the decisions each
program must now re-take. Ratification is Rick's, per item — **CSR-1…CSR-5 were
ruled 2026-09-01** (§8); CSR-3 and CSR-4 are applied in
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) in the same PR. **No consensus
rule and no schema is decided by any of them; the only queue effect is CSR-5's
relative ordering (R8 earlier than R6) — no fixed slot.**

---

## 0. The countermand (2026-09-01, Rick)

> "I am at this moment countermanding the earlier decision because what we have
> realized is that the glitches and irregularities in the C++ have been proven
> to be so bad that we need a complete rewrite before we can, in good
> conscience, release this software."

**What is countermanded:** the standing posture that the inherited C++ is a
*base* — sound enough to decompose in place, ship behind, and replace
incrementally. Concretely this retires the load-bearing rationale of
**DRS-D5** (decompose first in C++/LMDB), the three **DRS-D2** reopen bridges
(§5.2), **DRS-P0c**'s FIX-IN-CPP-FIRST default, and the 2026-07-26 storage-split
ruling's clause that coding to LMDB is acceptable *because the base is
established*.

**What is not countermanded:** the census's own oracle discipline (§6.1), the
pre-genesis deadline logic (census §6 finding 12), and rule 20's Rust-first
policy — which the countermand strengthens rather than changes.

### 0.1 The evidence, on record

The countermand is not an assertion this document has to take on faith; the
census already carries the findings that support it. Recorded here so the
ruling cites evidence rather than sentiment:

| Census row / finding | What it establishes |
| --- | --- |
| **CEN-L11** (b1) | The leaf-**construct** verdict is not checked: a false return at `blockchain_db.cpp:570–576` (and the `continue` arms at :562–565) **silently omits an accepted output from the curve tree**, with no verify-time twin. Deterministic, and a permanently unspendable output. |
| **CEN-B3** (b4) | `HardFork::add`'s **reject verdict is discarded** at the DB call site; the voting machinery runs on every connect and is inert. |
| **CEN-L1** (b4) | Block-connect key-image uniqueness is enforced **solely** as an LMDB `MDB_NODUPDATA` exception caught two frames up; the pre-DB `check_for_double_spend` is **dead**. |
| **CEN-L15** (b3) | A dead Monero-v4 RCT-era dispatch arm still sits on the write path (`if (blk.major_version >= 4)`, live major is 1). |
| **CEN-L14** (b4) | Five archival uniqueness rules have **no DB constraint at all** — flag-0 overwrites; `blockchain_db.cpp:775–786` records the bug class that tolerance once masked. |
| **§6 finding 2** | The **unlock_time triple-divergence**: one field that is consensus-legal (CEN-H16), relay-illegal (CEN-M5), and semantically inert (CEN-L12), with no single owner. |
| **§6 finding 5** | The **reorg acceptance design has no examined-decision record anywhere** — steering searched the decision log, `docs/design`, and `docs/completed`. |
| **§6 finding 8** | FAKECHAIN/regtest levers are **compiled into consensus paths** (CEN-I2, CEN-B5, CEN-D7, CEN-D3). |
| **§6 finding 11** | **70 of 171 rows carried open questions at C1 close** (**69** live after C2-R3 and C2-R1: 5 bucket-3 + 64 bucket-4); most of the inherited consensus surface has no specification other than its own source. |

The counterweight the census also records (Survey A O-4) stands and is not
disturbed: the bucket-1/2 surfaces — DAA, economics KATs, FCMP++/PQC, archival
— are in good shape, and the census **closes** them. The countermand is about
the inherited residue, not about Shekyl's own specified work.

### 0.2 Why "incremental" was never available anyway

Census §6 finding **10** is independently fatal to the decompose-in-place
posture, and predates the countermand:

> The staking consensus is **interleaved, not layered** (256 archival/bond/shard
> references inside `blockchain.cpp`). A rewrite plan that assumes it can port
> the "Monero part" and keep the "Shekyl part" separately is **wrong at the
> outset**.

DRS-C's surface partition is a cut through that interleaving. It is still a
useful *analytical* cut (§5.1, where CSR-4 rules it analysis-only); it was
never a seam along which the C++ could
be safely half-replaced.

---

## 1. The two programs did not meet

Measured at the pin, both directions:

```
grep -c 'DAEMON_REDB\|DRS-'          docs/design/CONSENSUS_RULE_CENSUS.md   → 0
grep -c 'CONSENSUS_RULE_CENSUS\|CEN-' docs/design/DAEMON_REDB_STORE.md      → 0
```

**Zero cross-references in either direction**, while both programs name the same
files as their subject:

| File | CEN rows enforcing here | DRS treatment |
| --- | --- | --- |
| `cryptonote_core/blockchain.cpp` | **92** | the god object; DRS-C partitions its 97 `m_db->` methods |
| `blockchain_db/lmdb/db_lmdb.cpp` | **14** | the store; DRS-E1 replaces it |
| `cryptonote_core/tx_pool.cpp` | **11** | DRS-C surface **S-POOL** |
| `cryptonote_core/cryptonote_core.cpp` | **12** | connect caller; DRS-B consumer |
| `blockchain_db/blockchain_db.cpp` | **10** | base write path; DRS-C **S-CHAIN-W** |
| `hardfork.cpp` | **4** | DRS-P0c wart register (`hf_versions`) |

This is not duplicated work — that would be easy to spot. It is **two
refactoring programs aimed at the same files along different axes, neither
aware the other is coming.** Whichever lands second re-derives its analysis
against a file the first one reshaped.

---

## 2. The overlap, measured

Of the census's **171** rows, **18** have an enforcement site inside
`src/blockchain_db/` — the store DRS replaces:

| Bucket | Rows | Meaning |
| --- | --- | --- |
| **1** (Shekyl-spec'd, ratified) | 7 — CEN-H5, L7, L8, L9, L10, L11, L12 | the rewrite consumes the spec directly |
| **3** (delete) | 1 — CEN-L15 | rule-60 deletion, executes in census R5 |
| **4** (open question) | 10 — CEN-B3, K3, L1, L2, L3, L4, L5, L6, L13, L14 | **must be ruled before the store is designed** |

The 10 bucket-4 rows are the load-bearing set: each is a consensus rule whose
*placement* is currently an accident of the LMDB write path, and each becomes
the new store's implicit specification if the store is designed before the rule
is ruled.

---

## 3. Row-level map — census rows × DRS-C surfaces

| CEN row | b | Rule (abbreviated) | DRS-C surface | Design question the store must answer |
| --- | --- | --- | --- | --- |
| CEN-L1 | 4 | KI uniqueness = `MDB_NODUPDATA` exception, caught 2 frames up; pre-DB check dead | **S-OUT-KI** + S-CHAIN-W | Is double-spend rejection a *validation* or a *storage constraint*? |
| CEN-L2 | 4 | `prev_id` exists at height−1; blobs appended at `m_height` (`MDB_APPEND`) | **S-CHAIN-W** | redb has no `MDB_APPEND`; the monotonicity guarantee needs an explicit invariant |
| CEN-L3 | 4 | `BLOCK_EXISTS` / `TX_EXISTS` reject at write; **only** connect-time uniqueness for the miner tx | **S-CHAIN-W** + S-TX | Miner-tx uniqueness has no upstream twin — port it or specify one |
| CEN-L4 | 4 | Block hash recomputed; contained txs stored under **claimed** hashes verbatim | **S-CHAIN-W** | Recorded absence — does the new store trust claimed hashes? |
| CEN-L5 | 4 | Input-type whitelist duplicated at write time | S-CHAIN-W | Deliberate belt or accidental duplicate of CEN-H5? |
| CEN-L6 | 4 | Every stored output carries an outPk commitment; amount-0 indexing | **S-OUT-KI** | Indexing choice has no record (recorded judgment disagreement) |
| CEN-L13 | 4 | Corruption/IO guards abort rather than store inconsistent state | cross-surface | Sanity class — becomes the error taxonomy of the Rust store |
| CEN-L14 | 4 | Five archival uniqueness rules have **no** DB constraint (flag-0 overwrites) | **S-ARCH** | Verify-side-only by design, or by omission? |
| CEN-B3 | 4 | Hardfork voting inert; `HardFork::add` reject verdict **discarded** at the DB call site | S-CHAIN-W / P0c | DRS-P0c's `hf_versions` wart — same defect, two registers |
| CEN-K3 | 4 | Alt-block duplicate rejected; DB belt `MDB_NODUPDATA` | **S-ALT** | Belt survives the engine change only if re-specified |
| CEN-H5 | 1 | Input-variant whitelist (three sites incl. the DB) | S-CHAIN-W | ratified — port all three sites or collapse deliberately |
| CEN-L7 | 1 | Archival connect-writers are fatal verify-backstops | **S-ARCH** | ratified; WS-2 journaled check-and-set |
| CEN-L8 | 1 | Epoch close at settlement boundary; accrual overflow aborts | **S-ARCH** | ratified — **"the DB is the enforcement site"** |
| CEN-L9 | 1 | Slash processing per height; fatal on interval-decision failure | **S-ARCH** | ratified |
| CEN-L10 | 1 | Segment freeze; registry row CREATE-only (`MDB_NOOVERWRITE`) | **S-ARCH** | ratified; redb needs an explicit CREATE-only equivalent |
| CEN-L11 | 1 | Curve-tree growth; **construct verdict unchecked → silent omission** | **S-CURVE** | ratified spec, defective implementation — §0.1 |
| CEN-L12 | 1 | Deferred-insertion maturity **is** the spend-maturity rule (60/10) | **S-CURVE** | ratified; third leg of the unlock_time divergence |
| CEN-L15 | 3 | Dead Monero-v4 RCT accumulation arm on the write path | S-CHAIN-W | delete, do not port |

**Surface load** (recomputed from the table above; CEN-L1 and CEN-L3 each map to
two surfaces and are counted under both, so the column sums to 20, not 18):
**S-CHAIN-W 8** (1 ratified), **S-ARCH 5** (4 ratified), **S-OUT-KI 2**,
**S-CURVE 2** (both ratified), **S-TX 1**, **S-ALT 1**, and CEN-L13
cross-surface. DRS's own note that archival *drivers* live
inside `BlockchainLMDB` (§3.5, "not in the 97 but adjacent") is confirmed
row-by-row here.

---

## 4. The collision: census R8 **is** the DRS store-design question

The census's §10 queue already contains a batch whose stake statement is,
verbatim, the question DRS-C and DRS-E1 exist to answer:

> **R8 — Storage-layer enforcement placement** · CEN-L1–L6, L13, L14 (8)
> "Validation completed by a side effect of the write path" (KI uniqueness as an
> LMDB exception, verbatim-hash storage, verify-side-only uniqueness) becomes
> **the rewrite's implicit spec** — the rewrite must place each rule
> deliberately or inherit the accident.

And DRS §3.4 rule 1:

> God object = **orchestration**, not row count in LMDB.

These are the same decision. Two design rounds, two identifier families, two
review cadences, one question. **Census R8 and DRS-C/E1 must not run
independently** — whichever runs first silently fixes the other's answer.

**CSR-1 rules the ownership:** census **R8 is the ruling instrument**; DRS-C's
surface map is its *input*, not a competing authority. R8's 8 rows plus
CEN-B3 and CEN-K3 (the two store-enforcing bucket-4 rows R8 does not carry)
are the rule set; the DRS surface column in §3 is how R8's output is handed
to the store design.

**CSR-1 does not re-batch anything.** CEN-B3 is batched in R4 and CEN-K3 in R1,
and §10's membership is exhaustive and sum-checked **as of C1 close**
(70 = 68 + 2 — the queue is frozen at that denominator, which is why R3's
promotion of CEN-C2/C3 to bucket 2 did not disturb it); moving them would break
that sum. They stay where they are — the store design **consumes
their rulings from R1/R4 wherever those land**. R8 remains 8 rows. What CSR-1
establishes is only which instrument *rules* a store-enforced rule, not which
batch carries it.

---

## 5. Consequences for the DRS decisions

### 5.1 DRS-D5 — decompose first, engine swap second

**Rationale retired** (§0), **mechanism survives in reduced form.** D5's stated
basis is "one variable at a time (R-4)" — a debugging-attribution argument, not
a migration argument, so the countermand does not touch its logic. What it
touches is the *premise* that a C++ decomposition is worth landing as
production code.

**CSR-4 ruling (Rick, 2026-09-01): DRS-C is analysis-only.** It does not ship as
C++ refactor PRs. This is close to forced by decisions already taken rather than
a fresh call — rule 20 (Rust-first) and
[`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc) both
argue against spending review bandwidth improving a file the countermand just
scheduled for wholesale replacement, and §5.5's P0c inversion already commits
this document to the same logic. DRS-C's value is **analytical**: the surface
partition is how the rewrite is scoped and reviewed. `DAEMON_REDB_STORE.md`
§3.5's "one surface per PR" shape is amended accordingly.

### 5.2 DRS-D2 — the reopen bridges have no referent

All three triggers bridge to the same place: *"ship genesis-on-LMDB; DRS-E\*
post-genesis."* Two independent reasons that is now unavailable:

**Scope note (2026-09-02):** this retires the bridges of **D2-R1 and D2-R2**.
**D2-R3 survives** — it is an *engine* trigger (BENCH failing the IBD floor),
not a ship-the-C++ trigger — but its "stay LMDB" arm now means a **Rust** store
over LMDB via the rewrite, never retaining the C++ implementation.

1. **Sequencing** (Rick, 2026-09-01): testnet is gated on this work plus
   consensus plus the wallet. Genesis is downstream of testnet. A milestone
   downstream of the work cannot arrive before it, so "genesis ships on LMDB"
   describes a state that cannot occur. The honest reading of a D2 reopen under
   this sequencing is **"testnet slips"**, which is a schedule outcome, not a
   technical bridge.
2. **The countermand:** shipping genesis-on-LMDB ships the C++ that has been
   ruled unshippable.

§1.5's "Tier-A LMDB genesis is a first-class success, not a scar" is off the
menu for the same two reasons. **D2-R1's 2027-04-01 date now measures against a
milestone that cannot arrive early.**

**CSR-2 ruling (Rick, 2026-09-01) — re-anchor to an event, not a new date.**
Emptying an anchor without replacing it is half a ruling, and it gets
rediscovered later as a gap; a *new fixed date* would carry the same failure
mode as the old one. D2-R1 is therefore re-anchored to **testnet-gate
completion**, whose three legs are named and independently observable:

| Leg | Complete when |
| --- | --- |
| **R8 dispatched** | the census has ruled the storage-layer placement rows (CSR-1) |
| **Consensus rewrite complete** | the all-Rust consensus port has retired the C++ reference for every ratified rule |
| **Wallet complete** | the remaining ~10% of the wallet rewrite lands |

An event-based trigger cannot be outrun by its own subject the way the calendar
one was. What it bridges *to* is unchanged by this ruling and is not a technical
fallback: under the countermand a D2 reopen means **testnet slips**, recorded as
a schedule outcome, never a return to shipping the C++.

### 5.3 DRS-D6 — engine choice: closed, and heed is dead

redb stands. **heed is retired by Rick's own argument, not by BENCH:** its sole
advantage over redb is on-disk format compatibility with the C++ LMDB, and
**not a single block has been mined on any network**. Every peer is at height 1
(observed 2026-09-01,
[`CONSENSUS_C2_R3_TIMESTAMPS.md`](../completed/CONSENSUS_C2_R3_TIMESTAMPS.md)),
and that genesis block is **regenerated deterministically** from the
`GENESIS_TX` / `GENESIS_NONCE` constants in `cryptonote_config.h` whenever the
store is empty (`blockchain.cpp:513`) — in any engine, at trivial cost. The
genesis rows are a *derived artifact of a repo constant*, not state: they carry
no information the source tree does not already hold. So there is nothing on
disk to preserve, and on-disk format compatibility is worth zero. Format compatibility with a corpus that does not exist
is worth zero, and LMDB→heed→redb is two switchovers to reach where one gets
you. This retires the caution recorded against a Rust-orchestrator-first path
(the 15 `mdb_set_compare`/`mdb_set_dupsort` comparators at
`db_lmdb.cpp:1751–1761` only matter to a reader of someone else's file).

**Register as a closed line** alongside DEL-006 ("V4 heed-as-destination
without pointer"), so the option is not re-proposed.

### 5.4 DRS-D11 / A2 / E2 — the digest's epistemic status changes

This is the countermand's sharpest consequence, and the census already has the
correct formulation while DRS does not.

Census header, **as it read before CSR-3a**:

> C++ is a differential-test oracle **only for rules ratified on record**.

That hedge was the right *direction* and far better than DRS's phrasing — but
§5.4.1 shows it is **not sufficient on its own**, and the census header has been
extended in the same PR so both documents now carry the conformance axis.

DRS-A2 / D11 / E2 use the unhedged form — "**trusted** LMDB digests",
"redb matches trusted LMDB digests". Under the countermand that phrasing is
wrong: you cannot hold up an implementation as a trusted oracle in the same
breath as ruling it defective. The digest **survives with changed status**:

| | Before | After |
| --- | --- | --- |
| For **bucket-1/2** rules (**102** live at `4b9807c5e`; 101 at C1 close) **that carry an affirmative conformance record** | oracle | **oracle — unchanged.** Shekyl-spec'd or ratified-inherited, and the census closes them |
| For **bucket-1/2** rules on the **conformance-exception register** (§5.4.1) | oracle | **not an oracle.** The spec is ratified; *this implementation* is known not to meet it |
| For **bucket-3/4** rules (**69** live at `4b9807c5e`; 70 at C1 close) | oracle | **not an oracle.** A digest match proves the rewrite reproduced *behavior*, defects included |
| As a **regression** instrument | — | **strengthened.** Over DRS-TLB-generated corpora it detects unintended change during extraction, which is all [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §6.2 ("Totality at linear cost") ever needed |

#### 5.4.1 The conformance-exception register (CSR-3a)

**A bucket is not a conformance claim.** The census's buckets say whether a
rule is *specified and ratified on record* — they say nothing about whether the
C++ **implements** the spec it was ratified against. Those are different axes,
and collapsing them is how a defect gets laundered into correctness evidence.

**CEN-L11 is the proof that the bucket-only rule is unsound**, and this document
already carried the counterexample two sections above its own rule: it is
**bucket 1** (ratified spec — [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md),
[`FCMP_PLUS_PLUS.md`](../FCMP_PLUS_PLUS.md)) *and* its implementation silently
omits an accepted output from the curve tree, with no verify-time twin. Under a
bucket-only rule, redb faithfully reproducing that omission would score as a
**correctness match**. It is the exact opposite.

**Corrected rule — the C++ is a correctness oracle for a rule only when both
hold:**

1. the rule is **ratified on record** (census bucket 1 or 2), **and**
2. the row carries an **affirmative conformance record** — someone checked that
   the C++ implements the spec it was ratified against, and wrote the result
   down.

**Condition 2 is deliberately affirmative, and this is a correction of the first
attempt at it.** CSR-3a originally stated it negatively — *no recorded
divergence* — which is **fail-open**: the register is explicitly not proven
complete, so absence from it means **unreviewed**, not conformant, and an
unexamined bucket-1/2 row would have collected correctness-oracle status by
default. That is the same laundering hazard one level up: instead of a bucket
standing in for conformance, an *unfinished search* would have. Under a
countermand that ruled this implementation defective, the default must fail
closed.

**Three states, not two:**

| State | Meaning | Digest is |
| --- | --- | --- |
| **CHECKED-CONFORMANT** | affirmative record that the C++ meets its ratified spec | a **correctness oracle** (with condition 1) |
| **DIVERGENT** | on the register below | **regression only** |
| **UNREVIEWED** | no conformance check on record — **the default** | **regression only** |

**As of 2026-09-02 the CHECKED-CONFORMANT set holds thirty rows** — the four
store-enforced promotions (CEN-H5, L7, L9, L10) plus the twenty-six §4.J
archival-family rows (P0f slice 4). All six reviewable store-enforced rows and
all of §4.J are now reviewed. **CEN-L12** is DIVERGENT (coupled to CEN-L11); **CEN-L8**
was reviewed and **failed closed to UNREVIEWED** — one of its clauses names
behavior that is not wired, so it can be neither conformant nor divergent.
Every row outside this register remains UNREVIEWED by construction, so the
digest is still a regression instrument everywhere else. That reads as a strong claim, and it is the honest consequence of the
countermand: ruling an implementation defective and then treating it as a
correctness oracle for everything nobody has looked at yet is the contradiction
CSR-3a exists to remove. Populating the set is **DRS-P0f**'s work, per row, on
record — a deliverable minted for exactly this, because P0d is Digest v0 and
cannot produce a conformance verdict.

**The register lists REVIEWED rows only, in either outcome.** Absence from it is
not an entry and not a claim — it *is* the UNREVIEWED state, which keeps the
table finite (it never has to enumerate 171 rows) while keeping the default
closed.

**Every entry pins the sha it was reviewed at.** A conformance claim is a claim
about code at a commit; without the pin the record rots silently as the tree
moves. The register schema carries the sha inside Evidence.

| Row | Conformance state | Evidence | Digest acceptance |
| --- | --- | --- | --- |
| **CEN-H5** | **CHECKED-CONFORMANT** | Reviewed at `6bc2de8f2` (P0f, 2026-09-02). Rule = the vin whitelist. **Three sites, all agreeing with the spec and with each other:** (1) `check_inputs_types_supported` (`cryptonote_format_utils.cpp:773–834` — census range confirmed, function identity confirmed): `txin_gen` in a non-coinbase returns false; the four accepted variants (`txin_to_key` + three archival) increment counters; **every other variant, including `txin_to_script`/`txin_to_scripthash`, returns false**; (2) the double-spend visitor (`blockchain.cpp:3232–3258`): `txin_to_script` and `txin_to_scripthash` each `return false`, `txin_gen` and the three archival variants `return true` with recorded rationale; (3) the DB whitelist (`blockchain_db.cpp:398–402`): unhandled variants `throw`, aborting the write txn. **Path decomposition (checked, not assumed):** site 1 runs on the **relay/pool** path only (`core::check_tx_semantic`, `cryptonote_core.cpp:782`); **connect-path coverage is sites 2 and 3**, and site 3 is unconditional because every stored tx passes `add_transaction`. **Scope: connect + relay admission. Pop/revert not in scope — that is P0b's subject.** Spec: `REWARD_EMISSION_E3_GATING_ROUND.md` Q3/Q11 vin taxonomy | Digest identity **required**; a match on this row **is** correctness evidence |
| **CEN-L7** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02). All four clauses hold. **Never soft-skip:** the connect dispatch's `else` throws FATAL on an unknown bond-post kind (`blockchain_db.cpp:363–366`), an unparseable emission vin throws (`:384`), and the input-type `else` throws (CEN-L5's site). **Emission claim requires the bond record:** `load_archival_bond_value` failure throws (`db_lmdb.cpp:6443`). **Dedup + claimability re-run:** `shekyl_archival_claimed_epochs_check_and_set` — `INSERTED` proceeds, `ALREADY_CLAIMED` throws *"dedup breach at connect"*, and any other code throws *"unclaimable epoch at connect"* (`:6474–6484`); the code comment cites §6.2 **"Never a soft skip"** in those words. **Bond folds abort on failure:** unbond checks `fold_rc` directly and additionally refuses a **holdings invariant breach** (`post_held_shard_count != 0` → throw, `:6594–6597`); holdings-update add/drop and rebond return their verdict from a lambda into the shared writer `apply_archival_bond_record_update` (`:6746`, the census's own cited site), which is the **single checked site** — `fold_rc != 0` throws (`:6778`), as do a missing record and a `shard_add_epochs`/`held_shard_ids` length desync (`:6758–6760`). The `return rc` shape is correct, not a discarded verdict: the helper owns the check for all three arms. **Scope: connect path only; the pop/revert twins exist and are P0b's.** Spec: WS-2 journaled check-and-set (E3), `ARCHIVAL_CONSENSUS_STATE.md` | Digest identity **required**; a match **is** correctness evidence — subject to §7.1.1, as this is an S-ARCH row |
| **CEN-L8** | **UNREVIEWED** — *partial findings recorded; deliberately not promoted* | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02) and **failed closed.** Two clauses verify: the Rust fold freezes `budget(E)`, `r_market` and sigma-work (`shekyl_archival_epoch_close_compute`, `compute_rc` checked → throw; both row writes error-checked, `db_lmdb.cpp:8352–8385`), and **accrual-sum overflow aborts rather than wrapping** — `amount > UINT64_MAX - budget_atomic` → *"FATAL: archival budget accrual sum overflow on close"* (`:8418`), so it can never mint. **The third clause could not be assessed.** The row states that a settlement `(passes, issued)` fold refusal aborts the same `add_block` write txn, but no settlement fold runs on the epoch-close path, and `set_archival_settlement` **has no production caller at all** — stated in the tree itself at `db_lmdb.cpp:7649`: *"latent today only because `set_archival_settlement` has no production caller yet — which is exactly the kind of 'not reachable, so not wrong' that stops being true silently."* Independently, **SO-D7 ruled the writer belongs inside the slash scheduler's per-epoch pass, NOT at a separate epoch-close event**, so the census row also appears to attribute it to the wrong hook. **That is a census question, not a conformance verdict** — routed to the census/R8 rather than decided here. The row stays UNREVIEWED because a clause that names unwired behavior can be neither conformant nor divergent | **Regression only.** Promotion requires the settlement clause to be re-stated against SO-D7 and then re-reviewed once the writer has a production caller |
| **CEN-L9** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02). Every fatality the rule names is present and loud. **Interval verdict:** `shekyl_archival_slash_open_interval_to_append` — `APPEND` and `COALESCE` are the only accepted outcomes; anything else throws *"archival slash interval decision failed (code N)"* (`db_lmdb.cpp:6021–6024`). **No-bond:** throw (`:5926`). **Shard-not-held:** `it == shards.end()` → throw (`:5968`). **Bonded-underflow:** checked **twice** — per-P (`bond.bonded_total_atomic < slashed_amount`) and global (`slashed_amount > bonded_total`), each throwing (`:6027`, `:6036`). **Burned-overflow:** `burned_total > UINT64_MAX - slashed_amount` → throw (`:6041`). Additional invariants beyond the rule: active write txn, `shard_add_epochs` desync, and the interval log's codec cap. **Every arm aborts; no discarded verdict.** **Scope: the slash *apply* path at connect.** The upstream `m=11/n=13` baseline-miss decision (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1) lives in the challenge mechanism and is **not** in this row's scope; pop/revert is P0b's | Digest identity **required**; a match **is** correctness evidence — subject to §7.1.1, as this is an S-ARCH row |
| **CEN-L10** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 2, 2026-09-02). All four clauses hold. **(1) First-crossing rule:** `frozen_segment_count(leaf_count) = leaf_count / SEGMENT_LEAF_COUNT` (`shekyl-archival-retention/src/segment_freeze.rs:71–73`) is the **single division site** §5.1 requires; C++ reaches it only through `shekyl_archival_frozen_segment_count` (`archival_ffi/schedule.rs:221–223`, a pure pass-through), and the connect loop (`db_lmdb.cpp:8014–8026`) writes exactly the newly-completed shards, with its lower bound `next` derived by a reverse-peek over the writer's own table so each shard freezes **exactly once, at its first crossing**. Pinned by the boundary table test `frozen_segment_count_boundary_table` (`segment_freeze.rs:152`). **(2) Layer-2 sub-root must exist:** a missing chunk `throw0`s FATAL and a malformed one `throw0`s on size — no soft-skip (`:8020–8027`). **(3) CREATE-only:** `mdb_put(..., MDB_NOOVERWRITE)` with `MDB_KEYEXIST` → `throw` naming the O-2 overwrite adversary (`:8533–8536`); the frozen-shard counter increments **where the row is created**, so counter and table cannot drift. **(4) Geometry:** `segment_leaf_count` 25992 (`consensus_constants.json:41`) with a compile-time assert tying it to `SELENE × HELIOS × SELENE` (`segment_freeze.rs:44–49`), and the writer always writes the constant while the row keeps its self-describing copy, exactly as §5.2's reversion clause specifies. **Every arm walked** (absent write-txn, cursor open, key-size, cursor error, missing/malformed chunk, KEYEXIST, put error, counter overflow) — **all abort loudly; no discarded verdict.** Spec: `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §4.1/§4.4/§5.1/§5.2. **Scope: connect path only.** The §4.4 counter's pop-symmetry is **P0b's** subject, not reviewed here | Digest identity **required**; a match on this row **is** correctness evidence — **but see §7.1.1**: this is an S-ARCH row, and E2 may not act on it for the archival surface until archival digest coverage exists. The verdict is valid; the *gate it feeds* has its own precondition |
| **CEN-L11** | **DIVERGENT** | Leaf-**construct** verdict unchecked: a false return at `blockchain_db.cpp:570–576` (and the `continue` arms :562–565) silently omits an accepted output from the tree — deterministic, permanently unspendable, no verify-time twin. Live FOLLOWUPS row | Identity is **not** the pass condition. Needs a reviewed expected-divergence or a replacement KAT asserting the corrected behavior; **reproducing the omission fails** |
| **CEN-L12** | **DIVERGENT** *(coupled to CEN-L11 — same code path)* | Reviewed at `6bc2de8f2` (P0f, 2026-09-02). The **maturity arithmetic conforms exactly**: coinbase `block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (=60, `cryptonote_config.h:45`), all others `+ CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (=10, `:49`), applied identically to both live target variants (`blockchain_db.cpp:545–560`); `unlock_time` appears **nowhere** in the collect/maturity path, as the rule requires; the spec's **staked** arm is excluded per this row's own census note (claim-era retired — `effective_lock_until` has **zero** live code references, only comments at `shekyl_types.h:135` and `cryptonote_config.h:297`). **What fails is the spec's *universality* clause** — FCMP_PLUS_PLUS.md §7, "**All** outputs (coinbase, regular, and staked) are deferred". Three arms can drop an accepted output before it is ever made pending: `else continue` (`:562`, non-whitelisted target types) and `i >= outPk.size() continue` (`:565`) are **belts** — defended upstream by CEN-H5's whitelist and by four `outPk.size() != vout.size()` checks (`blockchain.cpp:3372`, `:4114`, `cryptonote_core.cpp:799`, `cryptonote_format_utils.cpp:137`) — but the unchecked `shekyl_construct_curve_tree_leaf` verdict at `:570` is **CEN-L11's live defect**, and it breaches L12's own clause. **L12 cannot be promoted while L11 stands.** Scope: connect path only; pop/revert is P0b | Identity is **not** the pass condition. Promotion is gated on L11's divergence closing; a match meanwhile records reproduction of the same omission |

**Who produces the affirmative records: `DRS-P0f`** (minted 2026-09-02 in the
DRS P0 envelope). This closes a gap this document opened: CSR-3a required E2 to
consult a CHECKED-CONFORMANT set while **no scheduled artifact produced one** —
P0d's deliverable is Digest v0, and §5.5 said P0d/P0e survive unchanged. An
obligation with no producer is a dangling requirement, which under rules 15/16
is exactly the tech debt this program is supposed to avoid. P0f is that
producer, and it is the **only** way a row leaves UNREVIEWED.

##### P0f slice 4 — §4.J, the archival transaction families (26 rows, all bucket 1)

Reviewed at **`4b9807c5e`** (2026-09-02). These rows share three C++ verify
branches, each **walked end-to-end once** and cited per row rather than
re-derived 26 times:

- **Walk W-SC** — serve-credit: `Blockchain::check_archival_serve_credit_input`
  (`blockchain.cpp:5349–5560`) plus the tx-shape gate (`:3720–3800`).
  **Every verdict is discriminated and checked**; the whole ordered predicate
  sequence is mirrored in Rust (`shekyl-archival-retention::serve_credit_decisions`)
  and **pinned by the standing equivalence KAT**
  (`serve_credit_equivalence_kat_v1.json`, Rust leg
  `serve_credit_equivalence_kat.rs`, C++ leg
  `archival_serve_credit_equivalence.cpp`) — the AUDITED DECISION header
  requires re-authoring the fixture on any predicate change.
- **Walk W-BP** — bond-post: `blockchain.cpp:4808–5290`. Four kind arms plus
  the shared debit-auth pin (`shekyl_archival_debit_auth_pin`, rc discriminated
  three ways, all non-OK reject) and the credit-arm identity-key check, present
  on every credit path.
- **Walk W-EM** — emission: `blockchain.cpp:3888–4190`. Extract, key-derivation,
  reference-context, per-epoch snapshot, reward-set, coarse-verify and
  fee-proof arms all reject on their discriminated codes.

**Tier justification (applies to every row below):** verdict bodies are Rust —
the crates the rewrite keeps (`shekyl-archival-retention`, the archival FFI
verify family); the C++ carries marshaling, DB reads and sequencing, with the
sequencing itself KAT-pinned on W-SC; every FFI verdict return in all three
walks is checked at its call site (verified by reading, not grep); operand
*derivations* (epochs, heights, H_fire, leaf index, chunk bounds) are
Rust-side FFI calls, with the exceptions noted per row.

| Row | State | Evidence (all at `4b9807c5e`) |
| --- | --- | --- |
| CEN-J1 | **CHECKED-CONFORMANT** | W-SC. Parse failure rejects (`:5361`); the RF-D1 comment holds in code — "nothing here reads inside the bytes", structural bounds live in the Rust parser |
| CEN-J2 | **CHECKED-CONFORMANT** | W-SC. `pruned_records.size() != num_inputs` rejects (`:3786`) with index-`i` pairing stated; per-record size bound rejects (`:5366`) |
| CEN-J3 | **CHECKED-CONFORMANT** | W-SC. `archival_serve_credit_pass_count > 0` rejects (`:5392`). **REWRITE-NOTE:** the pair-epoch-wide bound is a *documented interim* — `assign_epoch` exists in Rust with **no FFI export and no consensus caller**, and the code carries a rule-21 REOPEN ("reject unless this block's assignment names this pair") for the assignment cutover. The rewrite should implement the cutover semantics, not fossilize the beacon bound → routed to that reopen + census §10 |
| CEN-J4 | **CHECKED-CONFORMANT** | W-SC. Missing bond substrate rejects (`:5398`) |
| CEN-J5 | **CHECKED-CONFORMANT** | W-SC. `shekyl_archival_serve_credit_epoch_ok` (Rust predicate) rejects (`:5406`) |
| CEN-J6 | **CHECKED-CONFORMANT** | W-SC. `archival_bond_good_through` rejects (`:5414`) |
| CEN-J7 | **CHECKED-CONFORMANT** | W-SC. `current_height > h_close` rejects; seal-on-chain is **Rust-authoritative** (`challenge_seal_on_chain`), called here and mirrored from one source; the seal-hash DB read is try/caught to a reject with the corrupt-read policy question named in place (`:5420–5457`) |
| CEN-J8 | **CHECKED-CONFORMANT** | W-SC. `H_fire` derived by Rust FFI from (seal hash, P, shard, E); `archival_bond_holds_shard(…, h_fire)` rejects (`:5466–5475`); WS-1 h_fire symmetry with the slash consumer documented at the site |
| CEN-J9 | **CHECKED-CONFORMANT** | W-SC. Leaf index **derived** (`shekyl_archival_challenge_leaf_index`, rc-checked reject; RF-D6 "never read off the vin"); PC-D3 binds to `prev_block_hash`, all-zero refused FFI-side; chunk bounds Rust-only ("same one-site family as the freeze rule") (`:5489–5516`) |
| CEN-J10 | **CHECKED-CONFORMANT** | W-SC. `shekyl_archival_verify_serve_credit_vin` rc-checked reject (`:5551–5556`); chunk read is all-or-nothing before the FFI ("no partial-fill path reaches the FFI verifier") |
| CEN-J11 | **CHECKED-CONFORMANT** | W-BP. Length gate, recompute-failure gate, and hint-mismatch gate each reject (`:4892–4909`) |
| CEN-J12 | **CHECKED-CONFORMANT** | W-BP. JoinMarket requires canonical-length `bond_spend_pk` (`:5201`); Unbond/HoldingsUpdate/Rebond each reject a non-empty one (`:4922`, `:4990`, `:5138`), and a kind-agnostic catch-all rejects the residue (`:5208`) — **all five sites agree** |
| CEN-J13 | **CHECKED-CONFORMANT** | W-BP. Debit arms authorize via `shekyl_archival_debit_auth_pin` (three-way rc, all non-OK reject, `:4828–4855`); credit arms check the identity key on every path (add `:5041`, Rebond `:5183`, JoinMarket `:5288`) |
| CEN-J14 | **CHECKED-CONFORMANT** | W-BP. `shekyl_archival_verify_join_market_bond_post` rc-checked reject (`:5216–5231`) |
| CEN-J15 | **CHECKED-CONFORMANT** | W-BP. Admission FFI rc-checked reject with decoded reason (`:5273–5284`); the per-shard facts (r_market, freeze/presence) are gathered C++-side as **marshaled operands**, decided Rust-side |
| CEN-J16 | **CHECKED-CONFORMANT** | W-BP. `shekyl_archival_verify_unbond_bond_post` rc-checked reject (`:4958–4980`); last-served scan selection itself asks Rust (`shekyl_archival_last_served_scan`) |
| CEN-J17 | **CHECKED-CONFORMANT** | W-BP. Both arm verifies rc-checked (`:5034`, `:5123`). **REWRITE-NOTE:** the drop arm derives the dropped shard by a C++ set-difference (`:5065–5078`) — operand logic in the marshal; the Rust verify re-validates shape, but in the rewrite this derivation belongs inside the verify → routed to the rewrite via this register |
| CEN-J18 | **CHECKED-CONFORMANT** | W-BP. `shekyl_archival_verify_rebond_bond_post` rc-checked reject (`:5156–5179`) |
| CEN-J19 | **CHECKED-CONFORMANT** | W-EM. `extract_rc != OK \|\| len == 0` rejects (`:3952–3961`) |
| CEN-J20 | **CHECKED-CONFORMANT** | W-EM. Key-derivation failure and derived-id mismatch each reject (`:3970–3980`) |
| CEN-J21 | **CHECKED-CONFORMANT** | W-EM. `block_exists`, min/max age windows, and depth range each reject (`:4005–4034`) — the same context contract as CEN-I10–I13, enforced with zero fee inputs |
| CEN-J22 | **CHECKED-CONFORMANT** | W-EM. Signable hash computed with the emission vin removed (`:3982–3994` region read); consumed by the coarse verify whose rc is checked (J25). The hash *construction* is C++-side operand derivation — noted, pinned by the round's signing-order tests per the census row |
| CEN-J23 | **CHECKED-CONFORMANT** | W-EM. `!snaps[k].has_budget_row` rejects per claimed epoch (`:4070–4076`) |
| CEN-J24 | **CHECKED-CONFORMANT** | W-EM. `outPk` count gate, loud-vout selection in vout order, missing-key reject, and `shekyl_checked_sum_amounts` overflow reject (`:4099–4143`) |
| CEN-J25 | **CHECKED-CONFORMANT** | W-EM. `shekyl_emission_vin_verify` rc-checked reject (`:4151–4177`) |
| CEN-J26 | **CHECKED-CONFORMANT** | W-EM + the FCMP arm. Absent⇔zero-fee-inputs enforced both directions (`:4186` no-proof-with-inputs reject at `:3889`); present ⇒ `shekyl_fcmp_verify` rc-checked reject (`:4351+`). **REWRITE-NOTE:** `skip_fcmp_verify` is a **pool-admission verification cache**, and the in-code comment marks it **load-bearing for the D++ embargo's `hop` definition** (`DAEMON_RELAY_PRIVACY.md` §71) — the rewrite must preserve that timing semantics or re-derive the embargo before changing where verification runs; the cache-condition's own derivation is reviewed under §4.I, not here |

**Section-level REWRITE-NOTE (routed to the rewrite through this register):**
W-SC's correctness is currently held by a **deliberate two-implementation
mirror** (C++ predicate sequence + Rust `serve_credit_decisions`) kept honest
by the equivalence KAT. That is the right *interim* structure and exactly the
arrangement the rewrite exists to retire: one implementation, the KAT surviving
as its pinning vectors, the mirror deleted.

**Examined and excluded:** **CEN-L12** — its notes record that the spec's
`staked: max(effective_lock_until…)` arm "does not exist in code", but that arm
is **claim-era and retired**, so the *live* spec and the code agree. A retired
spec clause is not an implementation divergence.

**The register is NOT proven complete, and must not be read as such.** It was
seeded by examining this document's 18 store-enforced rows plus a keyword sweep
of bucket-1/2 rows census-wide; a keyword sweep cannot establish absence.
**Obligation (CSR-3a):** determining the full set is a **DRS-P0f / census** job —
P0f's conformance review and DRS-E2's parity claims must consult this register
and extend it, and no parity claim may assert *correctness* for a bucket-1/2 row
until that row has been checked against it. Rows enter the register from either
side: a census round finding a divergence, or P0's wart pass finding one.

**CSR-3:** propagate the census's oracle clause into DRS-A2/D11/E2 — **not
verbatim.** CEN-L11 shows the ratification-only form is insufficient, so what
propagates is the **corrected two-condition rule** (§5.4.1), and the census
header is updated in the same change so the specification input does not retain
the unsafe version.
A "digest-identical extraction" claim over a bucket-4 rule is a statement about
fidelity to a defect, and must say so.

### 5.5 DRS-P0 — survives, rationale inverted

P0a (inventory + CI), P0b (atomicity/journals), P0d/P0e (digest) survive
unchanged, and **P0f is added** (§5.4.1 — the per-row conformance register,
without which E2's correctness arm has no producer): they are evidence-gathering, and the rewrite needs that evidence
more than a patch-in-place programme did.

**P0c inverts.** Its default is FIX-IN-CPP-FIRST; under the countermand the
default becomes **RECORD-AND-SPECIFY** — a wart is characterised precisely
enough that the Rust implementation gets it right, and fixed in C++ only where
the defect blocks the C++ from serving as a *bucket-1/2* oracle in the interim.
Fixing C++ that is scheduled for deletion is the debt rule 20 and
[`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc) exist to
prevent. CEN-L11 is the test case: a live FOLLOWUPS row, a ratified spec, and a
defective implementation on a file being deleted.

### 5.6 DRS-D4 — substantially discharged

"Wallet rewrite owns reviewer/decision-maker bandwidth first" was explicitly a
**bandwidth** constraint, not a technical dependency. Phase 5 closed 2026-08-19
(#507) and the wallet is ~90% (Rick, 2026-09-01). D4 no longer gates DRS-C.

---

## 6. Consequences for the census

### 6.1 The oracle clause is the census's, and it holds

**Corrected 2026-09-02 (CSR-3a) — the clause needed extending, not just
propagating.** The census's hedge was the right direction and much better than
DRS's unhedged phrasing, which is why §5.4 reached for it. But ratification is
**necessary, not sufficient**: CEN-L11 is bucket-1 ratified with an
implementation that does not meet its spec. The census header now carries the
conformance condition as well, so the rewrite's specification input cannot be
cited for the unsafe rule.

### 6.2 R8 gains an explicit consumer

R8's output was previously "input to the rewrite" in the abstract. It is now
the **specification input to the Rust chain store's schema and write path**
(`shekyl-chain-store`, DRS-E1). R8 should not be scheduled behind batches that
do not block store design. §10's proposed order runs R3 → R1 → R2 → R4 → R5 →
**R8** → R6 → R7 → R9 — **five** batches ahead of the one the store waits on,
not six as this document first stated (Rick, 2026-09-01; the miscount was
independent of any sha and is corrected here rather than silently). With **R3
now ruled and landed** (PR #592), the batches still *unruled* ahead of R8 are
**R1, R2, R4, R5 — four**.

**CSR-5 (partially ruled 2026-09-01, no slot locked).** R8's position was set
before it had a named downstream consumer, and it now has one that no other
batch ahead of it has: **DRS-E1's schema design cannot start until R8 rules**.
Direction ratified — R8 moves earlier than R6. **The specific slot is
deliberately not fixed here:** the count that motivated it was wrong twice over
(miscounted at five-as-six, then overtaken when R3 landed), and locking a number
against a moving denominator buys a second correction pass. Recompute against
`dev` at dispatch time; this document does not re-order the queue, which is a
census ruling.

### 6.3 The pre-genesis deadline is unchanged and now doubly load-bearing

Census §6 finding 12 (Survey A O-3): *"Every bucket-4 item is cheapest now —
pre-genesis they are free; post-genesis they are permanent. This deadline
applies whether or not the rewrite happens."* The countermand does not move
this; it adds a second population (the store's schema) with the same shape.

---

## 7. What this document does **not** decide

| Not decided | Owner |
| --- | --- |
| Any consensus rule's content or placement | census §10 batches (R8 for the store rows) |
| The C2 queue order — **except** CSR-5's relative ordering (R8 before R6); the slot is not fixed | census ruling |
| DRS-C's *implementation* detail — how the surface partition is used to scope rewrite increments (the ship-as-C++-PRs question is **ruled**: analysis-only, §5.1) | rewrite scoping |
| **When** the testnet-gate legs complete (the *anchor* is **ruled**: the testnet-gate event, §5.2) | Rick |
| redb schema design | DRS-0 / DRS-E1, after R8 |
| Testnet date | Rick |

---

## 8. Work items

| ID | Item | Blocks | Status |
| --- | --- | --- | --- |
| **CSR-1** | R8 is the ruling instrument for store-enforced rules; DRS-C's surface map is its input (§4) | store design | **RATIFIED 2026-09-01** — R8's 8 rows independently re-verified all bucket-4 at `bf317111f`, so "R8 stays 8 rows, B3/K3 not re-batched" holds |
| **CSR-2** | Re-anchor D2-R1 — its milestone cannot arrive early (§5.2) | DRS schedule honesty | **RATIFIED 2026-09-01, with a replacement anchor** — re-anchored to the **testnet-gate event** (three named legs), not a new calendar date |
| **CSR-3** | Propagate the census oracle clause into DRS-A2/D11/E2 (§5.4) | every parity claim | **RATIFIED + APPLIED** — A2, D11, E2 and the §7 flowchart label now scope the digest by ratification **and** conformance |
| **CSR-3a** | The **conformance register** (§5.4.1): a bucket says a rule is *ratified*, never that the C++ *implements* it | every parity claim asserting correctness | **OPEN** — **30 rows CHECKED-CONFORMANT** (store-enforced 4 + §4.J 26); CEN-L8 failed closed to UNREVIEWED (P0f slices 1–4, 2026-09-02); CEN-L11 and **CEN-L12** DIVERGENT; CEN-L12 (spec's staked arm) examined and excluded as retired. **Not proven complete**; **DRS-P0f** (minted 2026-09-02) and the census own extending it, and E2 must consult it before calling any match correctness |
| **CSR-4** | DRS-C's PR shape (§5.1) | DRS-C PR shape | **RULED: analysis-only** — does not ship as C++ refactor PRs; `DAEMON_REDB_STORE.md` §3.5 amended, D5's cell annotated |
| **CSR-5** | Re-price R8's §10 queue position (§6.2) | R8 dispatch | **DIRECTION RULED, no slot fixed** — R8 moves earlier than R6 (it alone has a named downstream consumer); the count is recomputed at dispatch, not locked here |
| **CSR-6** | Add the missing cross-references in both documents (§1) | drift prevention | **Landed with this PR** |
| **CSR-7** | Record heed as a closed line beside DEL-006 (§5.3) | prevents re-proposal | **Landed with this PR** |

---

## 9. Decision log

| Date | Decision | Record |
| --- | --- | --- |
| 2026-07-26 | Storage split: wallet redb, daemon LMDB; reopened for consensus machinery only | superseded in part by 2026-09-01 |
| 2026-08-30/31 | Census precedes rewrite; C++ is a differential oracle only for rules ratified on record | stands, and now propagates to DRS (§5.4) |
| 2026-09-01 | Testnet is gated on this work + consensus + wallet; genesis downstream of testnet | Rick, §5.2 |
| 2026-09-01 | heed retired: no block has been mined on any network — every peer is at height 1, and that genesis block is **regenerated deterministically** from the `GENESIS_TX` / `GENESIS_NONCE` constants in `cryptonote_config.h` whenever the store is empty (`blockchain.cpp:513`), in any engine. There is no persisted state to preserve, so format compatibility is worth zero | Rick, §5.3 |
| **2026-09-01** | **Countermand: the inherited C++ is not a base. A complete rewrite gates release.** | **Rick, §0** |
| 2026-09-01 | C2-R3 (timestamps) ruled and landed (PR #592) mid-work; census re-bucketed to 87/16/2/66. Store-enforced set re-derived at `bf317111f` — unchanged | header, §2 |
| **2026-09-01** | **CSR-1…CSR-5 ruled (Rick), from an independent fresh-clone review.** CSR-1 ratified; CSR-2 ratified *with* an event-based replacement anchor (an emptied trigger with no replacement is half a ruling); CSR-3 ratified and applied; CSR-4 ruled analysis-only; CSR-5 ruled in direction only. Two arithmetic corrections folded: §6.2 said six batches ahead of R8 where §10's order shows **five**, and R3's landing leaves **four** unruled ahead | §5.1, §5.2, §5.4, §6.2, §8 |
| **2026-09-02** | **DRS-P0f slice 4 — all 26 §4.J rows CHECKED-CONFORMANT** at `4b9807c5e`, via three end-to-end branch walks (W-SC / W-BP / W-EM) with every FFI verdict checked and W-SC's predicate sequence KAT-pinned on both legs. Three REWRITE-NOTEs recorded (assign_epoch cutover reopen; drop-arm set-difference in the marshal; skip_fcmp_verify's embargo-load-bearing cache) plus the section-level note that the C++/Rust mirror is interim structure the rewrite retires | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 3 — the archival-journal family; all six reviewable store-enforced rows now reviewed.** **CEN-L7 → CHECKED-CONFORMANT** (the three bond-fold connect arms return their Rust verdict into one checked site, `apply_archival_bond_record_update`, so `return rc` is correct rather than a discarded verdict). **CEN-L9 → CHECKED-CONFORMANT** (every named fatality present; bonded-underflow checked twice, per-P and global). **CEN-L8 → failed closed to UNREVIEWED**: two clauses verify, but its settlement `(passes, issued)` clause names behavior that does not run — `set_archival_settlement` has **no production caller**, a hazard the tree itself flags at `db_lmdb.cpp:7649` — and **SO-D7 places that writer in the slash scheduler's pass, not epoch close**, so the row's wording is a **census question routed to R8**, not a conformance verdict | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 2 — CEN-L10 → CHECKED-CONFORMANT** at `4b9807c5e`. First-crossing division confined to one Rust site and pinned by a boundary table; layer-2 sub-root existence and the CREATE-only O-2 refusal both fatal; geometry constant structurally asserted against the fcmp widths. Every error arm aborts loudly. **Recorded precision:** L10 is an S-ARCH row, so although the verdict promotes it, **§7.1.1 still bars E2 from acting on it for the archival surface until archival digest coverage exists** — a conformance verdict and a coverage gate are different preconditions | §5.4.1 |
| **2026-09-02** | C2-R1 (reorg/alt) landed (PR #596) during this slice; census re-bucketed again to **86 / 16 / 5 / 64** (three rows to bucket 3 — the deleted per-block-checkpoint fast path). **CEN-H5, CEN-L11 and CEN-L12 re-verified as still bucket 1 at `4b9807c5e`**, so the P0f verdicts stand | header, §5.4 |
| **2026-09-02** | **DRS-P0f slice 1 — the register's first verdicts.** Reviewed at `6bc2de8f2`: **CEN-H5 → CHECKED-CONFORMANT** (three sites agree with the spec and each other; relay coverage via `check_tx_semantic`, connect coverage via the visitor and the unconditional DB backstop). **CEN-L12 → DIVERGENT**, coupled to CEN-L11: its maturity arithmetic conforms exactly, but the spec's *universality* clause fails because L11's unchecked construct verdict can drop an accepted output before it is made pending — **L12 cannot be promoted while L11 stands**, a coupling the census recorded as two independent rows. Scope reviewed: connect + relay; pop/revert is P0b's. **Census pointer drift found:** CEN-H5's site 2 is cited `blockchain.cpp:3162–3168` but the double-spend visitor is at `:3232–3258` at this sha — C2-R3's commits moved the file after the census pin `ab3cc98e6` | §5.4.1 |
| **2026-09-02** | **CSR-3 corrected on review — the bucket axis is not the conformance axis.** A census bucket records that a rule is *ratified*, not that the C++ *implements* it. CEN-L11 is bucket-1 ratified with an implementation that silently omits an accepted output, so the bucket-only rule would have scored redb reproducing that defect as a **correctness match**. Oracle status now requires ratification **and** an **affirmative** conformance record; **CSR-3a** opens the register, seeded with CEN-L11 and explicitly not proven complete. **Corrected again the same day:** the condition was first written negatively (*no recorded divergence*), which is fail-open against an incomplete register — absence means unreviewed, not conformant. Three states now (CHECKED-CONFORMANT / DIVERGENT / UNREVIEWED), default regression-only, and the checked set is currently **empty** pending DRS-P0d | §5.4, §5.4.1 |
| **2026-09-02** | **The countermand was recorded but not applied to DRS's live instructions**, and CSR-3a's obligation had no producer. Both fixed: DRS's status line, D2-R1's trigger/bridge, the §6.4 divergence-class default, A3, D8, P0c, the genesis checklist and §17.2 now carry the ruled state (dated history preserved); **DRS-P0f minted** as the per-row conformance register that populates CHECKED-CONFORMANT; and **DRS-E2's acceptance condition is now per-state** — blanket digest identity would have required redb to reproduce CEN-L11's defect to pass | §5.4.1, §5.5 |

---

## 10. One-sentence summary

**Two programs were partitioning the same six files along different axes with
no cross-reference; the census's R8 batch and the daemon store's schema design
are one decision, and the 2026-09-01 countermand retires the decompose-in-place
posture, empties the D2 reopen bridges, and demotes the C++ from trusted oracle
to a differential reference for rules that are **both** ratified on record **and**
carrying an affirmative conformance record — a bucket is not a conformance
claim, and an unfinished search is not one either (CSR-3a).**
