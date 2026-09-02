# Consensus rewrite ↔ daemon chain store — reconciliation

**Status:** OPEN. Reconciles two design programs that target the same six
C++ files on orthogonal cuts and, until this document, did not reference each
other in either direction. Records the **2026-09-01 countermand** (§0) and its
blast radius across both programs' binding decisions.

**Pinned:** `dev` @ `47bfa66c3` (the merge of PR #593) for the row-level reads;
**re-verified at `bf317111f`** (the merge of PR #592) when C2-R3 landed mid-work.
The census's buckets moved under this document — CEN-C2/C3 were ruled and
promoted to bucket 2, so the live split is **87 / 16 / 2 / 66** where C1 close
recorded 87 / 14 / 2 / 68. The **18-row store-enforced set and its 7 / 1 / 10
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
| **§6 finding 11** | **70 of 171 rows carried open questions at C1 close** (**68** live after C2-R3 ruled CEN-C2/C3); most of the inherited consensus surface has no specification other than its own source. |

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
useful *analytical* cut (§5.4); it was never a seam along which the C++ could
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
| For **bucket-1/2** rules (**103** live; 101 at C1 close) **that the C++ is known to implement conformantly** | oracle | **oracle — unchanged.** Shekyl-spec'd or ratified-inherited, and the census closes them |
| For **bucket-1/2** rules on the **conformance-exception register** (§5.4.1) | oracle | **not an oracle.** The spec is ratified; *this implementation* is known not to meet it |
| For **bucket-3/4** rules (**68** live; 70 at C1 close) | oracle | **not an oracle.** A digest match proves the rewrite reproduced *behavior*, defects included |
| As a **regression** instrument | — | **strengthened.** Over DRS-TLB-generated corpora it detects unintended change during extraction, which is all §6.2 ever needed |

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
2. **no divergence between that ratified spec and the C++ implementation is on
   record** for the row.

A row failing (2) goes on the register below: the digest is a **regression**
instrument for it until the divergence is closed or the spec is re-ratified
against actual behavior.

| Row | Divergence | Status |
| --- | --- | --- |
| **CEN-L11** | Leaf-**construct** verdict unchecked; a false return at `blockchain_db.cpp:570–576` (and the `continue` arms :562–565) silently omits an accepted output from the tree — a deterministic, permanently unspendable output. Live FOLLOWUPS row | **REGRESSION-ONLY.** A digest match records reproduction of the omission, never conformance |

**Examined and excluded:** **CEN-L12** — its notes record that the spec's
`staked: max(effective_lock_until…)` arm "does not exist in code", but that arm
is **claim-era and retired**, so the *live* spec and the code agree. A retired
spec clause is not an implementation divergence.

**The register is NOT proven complete, and must not be read as such.** It was
seeded by examining this document's 18 store-enforced rows plus a keyword sweep
of bucket-1/2 rows census-wide; a keyword sweep cannot establish absence.
**Obligation (CSR-3a):** determining the full set is a **DRS-P0d / census** job —
P0d's digest definition and DRS-E2's parity claims must consult this register
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
unchanged: they are evidence-gathering, and the rewrite needs that evidence
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
| **CSR-3a** | The **conformance-exception register** (§5.4.1): a bucket says a rule is *ratified*, never that the C++ *implements* it | every parity claim asserting correctness | **OPEN, seeded** — CEN-L11 confirmed; CEN-L12 examined and excluded. **Not proven complete**; DRS-P0d and the census own extending it, and E2 must consult it before calling any match correctness |
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
| **2026-09-02** | **CSR-3 corrected on review — the bucket axis is not the conformance axis.** A census bucket records that a rule is *ratified*, not that the C++ *implements* it. CEN-L11 is bucket-1 ratified with an implementation that silently omits an accepted output, so the bucket-only rule would have scored redb reproducing that defect as a **correctness match**. Oracle status now requires ratification **and** no recorded spec-vs-implementation divergence; **CSR-3a** opens the register, seeded with CEN-L11 and explicitly not proven complete | §5.4, §5.4.1 |

---

## 10. One-sentence summary

**Two programs were partitioning the same six files along different axes with
no cross-reference; the census's R8 batch and the daemon store's schema design
are one decision, and the 2026-09-01 countermand retires the decompose-in-place
posture, empties the D2 reopen bridges, and demotes the C++ from trusted oracle
to a differential reference for rules that are **both** ratified on record **and**
free of a recorded spec-vs-implementation divergence — a bucket is not a
conformance claim (CSR-3a).**
