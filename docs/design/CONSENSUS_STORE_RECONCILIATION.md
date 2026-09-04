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
split is **86 / 25 / 5 / 55** (total still 171) — C2-R1b promoted nine bucket-4 rows into bucket 2 on 2026-09-03, which is why the register's 102-row denominator is now a dated snapshot rather than the live set. The **18-row store-enforced set and its 7 / 1 / 10
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
| **CEN-L11** (b1) | *(Historical — **fixed and promoted 2026-09-04**, see §5.4.1.)* The leaf-**construct** verdict was not checked: a false return, and two `continue` arms beside it, **dropped an output from the curve tree** with no verify-time twin. Re-walked at the fix: all three arms were unreachable through admission, so this was a latent silent-failure surface rather than the live fund-loss path recorded here. They now abort. |
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
| CEN-H5 | 1 | Input-variant whitelist (one live rule site + typed connect dispatch + DB backstop; the double-spend visitor site is **dead**) | S-CHAIN-W | ratified — port site 1 + the typed dispatch; the dead visitor is deletion residue, not a port target (§5.4.1 CEN-H5, corrected 2026-09-03) |
| CEN-L7 | 1 | Archival connect-writers are fatal verify-backstops | **S-ARCH** | ratified; WS-2 journaled check-and-set |
| CEN-L8 | 1 | Epoch close at settlement boundary; accrual overflow aborts | **S-ARCH** | ratified — **"the DB is the enforcement site"** |
| CEN-L9 | 1 | Slash processing per height; fatal on interval-decision failure | **S-ARCH** | ratified |
| CEN-L10 | 1 | Segment freeze; registry row CREATE-only (`MDB_NOOVERWRITE`) | **S-ARCH** | ratified; redb needs an explicit CREATE-only equivalent |
| CEN-L11 | 1 | Curve-tree growth; construct verdict now checked → **fail-closed** (was a silent omission; fixed 2026-09-04) | **S-CURVE** | ratified spec, implementation conformant since the fix — §5.4.1 |
| CEN-L12 | 1 | Deferred-insertion maturity **is** the spend-maturity rule (60/10) | **S-CURVE** | ratified; third leg of the unlock_time divergence |
| CEN-L15 | 3 | Dead Monero-v4 RCT accumulation arm on the write path | S-CHAIN-W | delete, do not port |
| *(post-map mint)* C2-R1b-Q1c | 2 | **Prune watermark** (`m_properties` key `archival_prune_watermark_epoch`): the prune's monotonic same-txn receipt; `pop_block` refuses below its epoch's open height; exempt from every revert (F-2) | **S-CHAIN-W** (pop path) | Minted 2026-09-03, after this map landed — named here so the DRS decomposition carries the floor with the pop path; the refusal predicate (`pop_target_allowed`) must survive any store re-home at the same single-funnel property |

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

**CEN-L11 is the proof that the bucket-only rule is unsound** — it was
bucket-1 ratified while its implementation silently dropped an accepted output
(fixed 2026-09-04, but the point is that ratification alone never showed it) —
and this document
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

**DRS-P0f row coverage is COMPLETE OVER THE 2026-09-02 SET** (slices 1–8, all at the
shas pinned per slice): the **102** bucket-1/2 rows that existed when P0f ran have a recorded disposition. **That denominator has since grown:** C2-R1b promoted **nine** rows into bucket 2 on 2026-09-03, so the current bucket-1/2 set is **111** and those nine carry no conformance record — **UNREVIEWED by default**, which is CSR-3a's own set-growth obligation firing for the first time. Disposition of the 102 — **99 CHECKED-CONFORMANT**, **1 DIVERGENT** (CEN-B5, the
rule-71 FAKECHAIN skip, which census R9 owns),
**2 failed closed to UNREVIEWED**
(CEN-L8, whose settlement clause names an unwired writer; CEN-I12, whose anchor source is internally split). UNREVIEWED remains
the default for anything outside bucket 1/2 — bucket-3/4 rows have no ratified
spec to review against until the census's design rounds rule them. **CEN-B5** (rule-71 skip) is the sole divergent row; **CEN-L11** and **CEN-L12** were re-reviewed and promoted at PR #609's merged fix (2026-09-04). **Both S-graded findings are closed:** CEN-M8/G4/J26 were promoted at PR #602's merged fix, and **CEN-D2 with CEN-D1 at PR #604's** (2026-09-03) — no S-graded divergence remains. Failed closed for the two distinct reasons already given above: **CEN-L8**,
whose settlement clause names behaviour that is not wired, and **CEN-I12**,
whose anchor source disagrees with itself — neither can be called conformant
or divergent.
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
| **CEN-H5** | **CHECKED-CONFORMANT** | Reviewed at `6bc2de8f2` (P0f slice 1, 2026-09-02); **evidence corrected at `8c760d276` (2026-09-03, Copilot round 1) — slice 1 cited dead code as connect coverage.** Rule = the vin whitelist. **Live enforcement:** (1) `check_inputs_types_supported` (`cryptonote_format_utils.cpp:773–834`): `txin_gen` in a non-coinbase returns false; the four accepted variants (`txin_to_key` + three archival) increment counters; **every other variant, including `txin_to_script`/`txin_to_scripthash`, returns false**. This one site carries the full rule and runs on **both** paths: relay/pool admission via `core::check_tx_semantic` (`cryptonote_core.cpp:782`), run **exactly once per pool entrant**: `add_tx` runs it itself for any caller not asserting prior verification (`tx_pool.cpp:236–241` — every fresh relay entrant, since the `nic_verified_hf_version` default is 0), while the `kept_by_block` callers (`blockchain.cpp:862`/`:2467`/`:5988`) deliberately pass equal versions because their bytes were verified caller-side (the supplement check next) or previously admitted — and the CEN-M8 tolerance is downstream input checks only — and **connect** via `ver_non_input_consensus` Rule 5 (`tx_verification_utils.cpp:90`) on the pool supplement, block-fatal on main (`blockchain.cpp:5941`) and alt (`:2449`). (2) Connect-side variant typing in `check_tx_inputs` for **every** block tx, pool-sourced or supplement: the FCMP++ arm requires `txin_to_key` in spend position (`:3649–3656`) and the archival arms are typed by `classify_archival_tx`. (3) The DB write backstop (`blockchain_db.cpp:398–402`): unhandled variants `throw`, aborting the write txn — but it **accepts `txin_gen` as miner-shaped** (`:286–290`), so it backstops the script-variant clause only, never the txin_gen clause. **Struck as evidence: the double-spend visitor (`:3232–3258`).** Its only call is commented out (`blockchain.cpp:6106`, *"ND: this is not needed"*) — a fact the census already recorded **twice** (§5 dead-surface item 3; CEN-L1's row) and slice 1 failed to cross-check — and the visitor's body *accepts* `txin_gen`, so even alive it would not enforce that clause. REWRITE-NOTE: the visitor is rule-15 deletion residue, routed with the §10 R5 script-variant fossils; the rewrite carries site 1 + the typed connect dispatch, not three copies. **Engine-submit precision:** `insert_attested_tx` (`tx_pool.cpp:550`; sole caller `daemon_submit_ffi.cpp:833`) inserts a local, engine-built tx without re-running site 1 in C++ — its vin shape is CEN-M9's attested surface, and the connect-side typing in (2) still applies to it. **Scope: connect + relay admission. Pop/revert not in scope — that is P0b's subject.** Spec: `REWARD_EMISSION_E3_GATING_ROUND.md` Q3/Q11 vin taxonomy | Digest identity **required**; a match on this row **is** correctness evidence |
| **CEN-L7** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02). All four clauses hold. **Never soft-skip:** the connect dispatch's `else` throws FATAL on an unknown bond-post kind (`blockchain_db.cpp:363–366`), an unparseable emission vin throws (`:384`), and the input-type `else` throws (CEN-L5's site). **Emission claim requires the bond record:** `load_archival_bond_value` failure throws (`db_lmdb.cpp:6443`). **Dedup + claimability re-run:** `shekyl_archival_claimed_epochs_check_and_set` — `INSERTED` proceeds, `ALREADY_CLAIMED` throws *"dedup breach at connect"*, and any other code throws *"unclaimable epoch at connect"* (`:6474–6484`); the code comment cites §6.2 **"Never a soft skip"** in those words. **Bond folds abort on failure:** unbond checks `fold_rc` directly and additionally refuses a **holdings invariant breach** (`post_held_shard_count != 0` → throw, `:6594–6597`); holdings-update add/drop and rebond return their verdict from a lambda into the shared writer `apply_archival_bond_record_update` (`:6746`, the census's own cited site), which is the **single checked site** — `fold_rc != 0` throws (`:6778`), as do a missing record and a `shard_add_epochs`/`held_shard_ids` length desync (`:6758–6760`). The `return rc` shape is correct, not a discarded verdict: the helper owns the check for all three arms. **Scope: connect path only; the pop/revert twins exist and are P0b's.** Spec: WS-2 journaled check-and-set (E3), `ARCHIVAL_CONSENSUS_STATE.md` | Digest identity **required**; a match **is** correctness evidence — subject to §7.1.1, as this is an S-ARCH row |
| **CEN-L8** | **UNREVIEWED** — *partial findings recorded; deliberately not promoted* | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02) and **failed closed.** Two clauses verify: the Rust fold freezes `budget(E)`, `r_market` and sigma-work (`shekyl_archival_epoch_close_compute`, `compute_rc` checked → throw; both row writes error-checked, `db_lmdb.cpp:8352–8385`), and **accrual-sum overflow aborts rather than wrapping** — `amount > UINT64_MAX - budget_atomic` → *"FATAL: archival budget accrual sum overflow on close"* (`:8418`), so it can never mint. **The third clause could not be assessed.** The row states that a settlement `(passes, issued)` fold refusal aborts the same `add_block` write txn, but no settlement fold runs on the epoch-close path, and `set_archival_settlement` **has no production caller at all** — stated in the tree itself at `db_lmdb.cpp:7649`: *"latent today only because `set_archival_settlement` has no production caller yet — which is exactly the kind of 'not reachable, so not wrong' that stops being true silently."* Independently, **SO-D7 ruled the writer belongs inside the slash scheduler's per-epoch pass, NOT at a separate epoch-close event**, so the census row also appears to attribute it to the wrong hook. **That is a census question, not a conformance verdict** — routed to the census/R8 rather than decided here. The row stays UNREVIEWED because a clause that names unwired behavior can be neither conformant nor divergent | **Regression only.** Promotion requires the settlement clause to be re-stated against SO-D7 and then re-reviewed once the writer has a production caller |
| **CEN-L9** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 3, 2026-09-02). Every fatality the rule names is present and loud. **Interval verdict:** `shekyl_archival_slash_open_interval_to_append` — `APPEND` and `COALESCE` are the only accepted outcomes; anything else throws *"archival slash interval decision failed (code N)"* (`db_lmdb.cpp:6021–6024`). **No-bond:** throw (`:5926`). **Shard-not-held:** `it == shards.end()` → throw (`:5968`). **Bonded-underflow:** checked **twice** — per-P (`bond.bonded_total_atomic < slashed_amount`) and global (`slashed_amount > bonded_total`), each throwing (`:6027`, `:6036`). **Burned-overflow:** `burned_total > UINT64_MAX - slashed_amount` → throw (`:6041`). Additional invariants beyond the rule: active write txn, `shard_add_epochs` desync, and the interval log's codec cap. **Every arm aborts; no discarded verdict.** **Scope: the slash *apply* path at connect.** The upstream `m=11/n=13` baseline-miss decision (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1) lives in the challenge mechanism and is **not** in this row's scope; pop/revert is P0b's | Digest identity **required**; a match **is** correctness evidence — subject to §7.1.1, as this is an S-ARCH row |
| **CEN-L10** | **CHECKED-CONFORMANT** | Reviewed at `4b9807c5e` (P0f slice 2, 2026-09-02). All four clauses hold. **(1) First-crossing rule:** `frozen_segment_count(leaf_count) = leaf_count / SEGMENT_LEAF_COUNT` (`shekyl-archival-retention/src/segment_freeze.rs:71–73`) is the **single division site** §5.1 requires; C++ reaches it only through `shekyl_archival_frozen_segment_count` (`archival_ffi/schedule.rs:221–223`, a pure pass-through), and the connect loop (`db_lmdb.cpp:8014–8026`) writes exactly the newly-completed shards, with its lower bound `next` derived by a reverse-peek over the writer's own table so each shard freezes **exactly once, at its first crossing**. Pinned by the boundary table test `frozen_segment_count_boundary_table` (`segment_freeze.rs:152`). **(2) Layer-2 sub-root must exist:** a missing chunk `throw0`s FATAL and a malformed one `throw0`s on size — no soft-skip (`:8020–8027`). **(3) CREATE-only:** `mdb_put(..., MDB_NOOVERWRITE)` with `MDB_KEYEXIST` → `throw` naming the O-2 overwrite adversary (`:8533–8536`); the frozen-shard counter increments **where the row is created**, so counter and table cannot drift. **(4) Geometry:** `segment_leaf_count` 25992 (`consensus_constants.json:41`) with a compile-time assert tying it to `SELENE × HELIOS × SELENE` (`segment_freeze.rs:44–49`), and the writer always writes the constant while the row keeps its self-describing copy, exactly as §5.2's reversion clause specifies. **Every arm walked** (absent write-txn, cursor open, key-size, cursor error, missing/malformed chunk, KEYEXIST, put error, counter overflow) — **all abort loudly; no discarded verdict.** Spec: `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §4.1/§4.4/§5.1/§5.2. **Scope: connect path only.** The §4.4 counter's pop-symmetry is **P0b's** subject, not reviewed here | Digest identity **required**; a match on this row **is** correctness evidence — **but see §7.1.1**: this is an S-ARCH row, and E2 may not act on it for the archival surface until archival digest coverage exists. The verdict is valid; the *gate it feeds* has its own precondition |
| **CEN-L11** | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: seeded DIVERGENT 2026-09-02 as a live fund-loss path; re-walked as latent and fixed fail-closed by PR #609, 2026-09-04)* | Re-reviewed at `ab4693d0e` (2026-09-04; contains the `dev` merge `a72e38550` = PR #609, and no file cited here differs between the two). **Every accepted output becomes a leaf, or the block does not connect.** The collector's three skip arms are gone: the unsupported-target arm throws (`blockchain_db.cpp:561`), the short-`outPk` arm throws (`:570`), and the construct verdict is consumed rather than discarded — a false return throws (`:589`) — each naming the vout index, the tx hash and the admission gate that forecloses it. The foreclosure walk from the fix PR stands at this sha: CEN-H12/F8 fix the target type, four `outPk.size()` gates fix the length, and the canonical/prime-order point gates fix both leaf inputs (`shekyl_check_output_keys` via `check_outs_valid`; `shekyl_check_commitment_masks` via `check_commitment_mask_valid`; coinbase legs in `prevalidate_miner_transaction`). Those three gate definitions carry LOAD-BEARING DOWNSTREAM pointers back to the collector (`cryptonote_format_utils.cpp:860`, `:987`; `blockchain.cpp:3265`), so loosening one is found by reading, not by a crashed node. **Evidence is behavioural, not only a walk:** five LMDB regressions (`archival_substrate_lmdb.cpp:3083–3149`) — one refusal per arm, a key and a commitment the leaf builder cannot encode, each asserting that `batch_abort` leaves height, tx count and output count untouched, and an accept control that pins the actual refuser — plus the Rust falsifier `shekyl-ffi/tests/leaf_gate_agreement.rs` (each gate accepts exactly what `construct_leaf` encodes; the probe set exercises both verdicts per gate). Red-observation is recorded in PR #609; at this sha all pass (`unit_tests --gtest_filter='archival_substrate_lmdb.cen_l11_*'`, `cargo test -p shekyl-ffi --test leaf_gate_agreement`). **History:** the seed row recorded a live loss; the fix PR re-walked it as latent (all three arms unreachable through admission) and hardened it anyway, since fail-closed costs nothing over dead arms and a silent surface is what this register exists to find. That PR merged under a title reading *"register 99/1/2"*, written before its round 6 withdrew the promotion — **withdrawn-in-PR, records-was:** the register was 97 / 3 / 2 at that merge, and 99 / 1 / 2 is the figure only this re-review produces, one PR later than the title claims | Digest identity **required**; a match on this row **is** correctness evidence — a rewrite reproducing the silent omission **fails** |
| **CEN-L12** | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: DIVERGENT coupled to CEN-L11 from P0f slice 1; fixed with it by PR #609)* | Re-reviewed at `ab4693d0e` (2026-09-04). The maturity arithmetic always conformed — coinbase `+CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60), everything else `+CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (10), on both live target variants (`blockchain_db.cpp:542–552`), `unlock_time` absent from the computation, the claim-era staked arm retired. The clause that failed was the spec's **universality** ("every accepted output"), and it now holds by the same fail-closed collector recorded under CEN-L11: an output that cannot become a leaf refuses the block rather than connecting without one. One defect, one fix, both rows closed | Digest identity **required**; a match on this row **is** correctness evidence |

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
| CEN-J26 | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: DIVERGENT coupled to M8, round 2)* | Re-reviewed at `a45916c66` (round 6). W-EM + the FCMP arm. Absent⇔zero-fee-inputs enforced both directions (`:4186`/`:3889`); "present ⇒ verifies" now holds: a present fee-input proof either verifies at connect (`shekyl_fcmp_verify` rc-checked, `:4351+`) or carried an admission-verified matching hash — the only skip the hash-gated cache grants. **REWRITE-NOTE:** `skip_fcmp_verify` is a **pool-admission verification cache**, embargo-load-bearing per the in-code note (`DAEMON_RELAY_PRIVACY.md` §71) — the rewrite must preserve that timing semantics or re-derive the embargo first | Digest identity **required**; a match on this row **is** correctness evidence |

**Section-level REWRITE-NOTE (routed to the rewrite through this register):**
W-SC's correctness is currently held by a **deliberate two-implementation
mirror** (C++ predicate sequence + Rust `serve_credit_decisions`) kept honest
by the equivalence KAT. That is the right *interim* structure and exactly the
arrangement the rewrite exists to retire: one implementation, the KAT surviving
as its pinning vectors, the mirror deleted.

##### P0f slice 5 — §4.F, miner transaction and emission (16 rows)

Reviewed at **`4b9807c5e`** (2026-09-02). One walk, **W-MT**:
`prevalidate_miner_transaction` + `validate_miner_transaction`
(`blockchain.cpp:1653–1822`), plus the economics boundary
(`cryptonote_basic_impl.cpp:93–170`, `src/shekyl/economics.h`) and the
operand derivations (`get_tx_volume_avg` `:2170`,
`parent_frozen_segment_count` `:1745–1756`, `hardforks.cpp:35–37`).

| Row | State | Evidence (all at `4b9807c5e`) |
| --- | --- | --- |
| CEN-F2 | **CHECKED-CONFORMANT** | W-MT. `version >= 3` asserted (`:1662`) |
| CEN-F3 | **CHECKED-CONFORMANT** | W-MT. `ct_signatures.type == CTTypeNull` asserted (`:1663`) |
| CEN-F4 | **CHECKED-CONFORMANT** | W-MT. `height == 0 \|\| vout.size() == 1` (`:1690`), with the claimed `txin_gen` height forced to EQUAL the caller-derived height immediately after — the exemption **cannot be spoofed** from the block's own claim. **REWRITE-NOTE:** the genesis exemption is **load-bearing today** (testnet's shipped `GENESIS_TX` carries 5 outputs — verified at the blob per the in-code note), and there is a rule-21 reopen for mined multi-output coinbases; the rewrite must carry the exemption *and* the caller-derived-operand anti-spoof structure, not just the cap |
| CEN-F8 | **CHECKED-CONFORMANT** | W-MT. `check_output_types(b.miner_tx, hf_version)` asserted (`:1705`) — the same contract as CEN-H12, applied to the miner tx here because it bypasses pool admission |
| CEN-F9 | **CHECKED-CONFORMANT** | W-MT. `check_outs_valid` applied at `:1710` with the in-code note that the miner tx never passes `core::check_tx_semantic`, so the §2.3 output-point rule is enforced at this second site — deliberate two-path coverage, documented in place |
| CEN-F10 | **CHECKED-CONFORMANT** | W-MT. `check_commitment_mask_valid` (`:3346+`) drives `shekyl_check_commitment_masks` with the rc discriminated **three ways** (non-canonical point / trivial amount-leaking form / other), each rejecting |
| CEN-F11 | **CHECKED-CONFORMANT** | W-MT. `block_height == 0` accepts as configured with `base_reward = money_in_use` (`:1786–1791`); the genesis blob's provenance was verified under slice 1 (`blockchain.cpp:513`, `GENESIS_TX`/`GENESIS_NONCE`) |
| CEN-F13 | **CHECKED-CONFORMANT** | Economics boundary. The shim states — and the read confirms — **"Nothing is computed here"**: base subsidy, soft-median clamp, 2·median rejection and the 128-bit penalty are canonical in `shekyl-economics` via `shekyl_block_reward`, status discriminated. **Pinned by the 81-vector KAT asserted from BOTH languages** (`EconomicsC2aPrime.Layer1WeightPenaltyPinnedVectors` / `c2a_prime_layer1_weight_penalty_pinned_vectors`) |
| CEN-F14 | **CHECKED-CONFORMANT** | Same boundary. `SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG` maps to the reject at `:1793–1795`; the recorded divergence comment at `cryptonote_basic_impl.cpp:122–135` remains accurate as read |
| CEN-F15 | **CHECKED-CONFORMANT** | Same boundary — the release-rate clamp lives in `shekyl-economics/src/release.rs`, reached through the same single FFI call; nothing recomputed C++-side |
| CEN-F16 | **CHECKED-CONFORMANT** | `compute_emission_split` (`economics.h:95`) is a pure FFI shim over `shekyl_calc_emission_share` + `shekyl_split_block_emission` (`:1797`) |
| CEN-F17 | **CHECKED-CONFORMANT** | `compute_fee_burn` (`economics.h:63`) is a pure FFI shim over `shekyl_calc_burn_pct` + `shekyl_compute_burn_split_escalated` (`:1804`) |
| CEN-F18 | **CHECKED-CONFORMANT** | W-MT. **Both directions**: overpay rejects (`money_in_use > reward`, `:1809`) and inexactness rejects (`!=`, `:1815`) — exact-equality confirmed, not `≤` |
| CEN-F19 | **CHECKED-CONFORMANT** | `parent_frozen_segment_count` asserts `db_height == block_height` (THROW) before reading the leaf count (`:1750–1756`), so the count is the **parent's by construction**. **REWRITE-NOTE:** the in-code warning is itself load-bearing — the check's teeth depend on the *operand* being a pre-`add_block` snapshot, and "simplifying" the call to read the live height makes it a **permanent tautology** that still passes every test. The rewrite should make the read-point structural (a type or a snapshot handle), not a convention guarded by a comment |
| CEN-F20 | **CHECKED-CONFORMANT** | `get_tx_volume_avg` (`:2170`) computes the integer mean of `tx_hashes.size()` over the prior `SHEKYL_TX_VOLUME_WINDOW` blocks exactly as the rule states, with the short-chain clamp arms read. **REWRITE-NOTE:** this is a **second implementation** — `shekyl-economics/src/activity.rs` maintains the same 720-block rolling mean; the rewrite collapses to one, and the census's own wart (window constant not in `config/`) rides along |
| CEN-F21 | **CHECKED-CONFORMANT** | Pinned end-to-end: `HF_VERSION_SHEKYL_NG = 1` (`cryptonote_config.h:289`) → the sole mainnet fork entry `{version 1, height 1}` (`hardforks.cpp:35–37`) → `get_earliest_ideal_height_for_version` returns **1** (`hardfork.cpp:383–394`) → consumed at `:1796` |

##### P0f slice 6 — §4.H, transaction non-input consensus (13 rows; H5 was slice 1)

Reviewed at **`4b9807c5e`** (2026-09-02). Walks: **W-TO** =
`Blockchain::check_tx_outputs` (`blockchain.cpp:3403–3465`; the census's
3348–3389 drifted +~70 under C2-R3, same as H5's site 2), **W-VU** =
`tx_verification_utils.cpp:55–240`, **W-FU** =
`cryptonote_format_utils.cpp:800–1000`, **W-CT** = `ct_semantics.cpp:206–401`.

| Row | State | Evidence (all at `4b9807c5e`) |
| --- | --- | --- |
| CEN-H2 | **CHECKED-CONFORMANT** | W-VU. `min_tx_version`/`max_tx_version` both collapse to 3 at HF1 given `HF_VERSION_SHEKYL_NG = 1` (expressions read at `:55–56`, constant pinned in slice 5); out-of-range rejects |
| CEN-H6 | **CHECKED-CONFORMANT** | W-FU. All five mixing bans reject: serve-credit×anything, >1 bond post, >1 emission, emission×bond, bond×serve (`:802–833`) |
| CEN-H7 | **CHECKED-CONFORMANT** | W-FU. `shekyl_check_output_keys` batch check, rc-checked reject (`:859–864`); empty-vout early-true is vacuous, not a skip |
| CEN-H12 | **CHECKED-CONFORMANT** | W-FU. `txout_to_tagged_key` asserted per output on the always-taken `hf_version >= SHEKYL_NG` arm (`:975–984`). **REWRITE-NOTE:** the VIEW_TAGS-era `else` arms below it are dead from genesis — rule-60 deletion residue for R5; the rewrite carries only the one live arm |
| CEN-H13 | **CHECKED-CONFORMANT** | W-TO. `tx.version < 3` rejects (`:3407`). **REWRITE-NOTE:** this is the version rule's *third* site (with H2's table and its other site) — census §6 finding 6's two-site-drift class; the rewrite collapses to one |
| CEN-H14 | **CHECKED-CONFORMANT** | W-TO. Zero-amount ban with the emission exemption keyed on `classify_archival_tx(tx.vin).kind` — **the same classifier `check_tx_inputs` uses**, with the in-code note explaining why a bare vin count would leak the ban on malformed pairings. **REWRITE-NOTE (positive):** single-classifier-both-sites is the anti-drift structure to keep |
| CEN-H15 | **CHECKED-CONFORMANT** | W-TO `:3433–3439` + W-VU's per-shape `rv.type` checks — Null or FcmpPlusPlusPqc only, everything else rejects |
| CEN-H16 | **CHECKED-CONFORMANT** | W-TO. `unlock_time >= 500 000 000` sentinel rejects (`:3441–3447`) — the consensus leg of the unlock_time triple-divergence, exactly as the census composition finding describes |
| CEN-H17 | **CHECKED-CONFORMANT** | W-TO `:3458+` → the same three-way-discriminated `shekyl_check_commitment_masks` verified under CEN-F10 |
| CEN-H18 | **CHECKED-CONFORMANT** | W-CT. Cleartext balance **single-sourced in Rust** (`shekyl-ct-balance::verify_ct_balance`), rc-checked reject (`:222–231`), then BP+ verification |
| CEN-H20 | **CHECKED-CONFORMANT** | W-VU `:113–131` (no pqc_auths / no RCT material / type gate) + W-CT `:372+` + the connect-side re-check read under slice 4's W-SC (`blockchain.cpp:3724–3760`) — all three legs reject |
| CEN-H21 | **CHECKED-CONFORMANT** | W-VU `:132–148` (pqc_auths == vin count, pseudoOuts == spend count, type) + `ct::verCtSemanticsBondPost` → the shared `verArchivalCtBalanceAndRange` with `shekyl_archival_verify_bond_post_ct_balance` rc-checked (W-CT `:262–309`) |
| CEN-H22 | **CHECKED-CONFORMANT** | W-VU `:149–181` (checked reward sum, overflow reject, pqc_auths/pseudoOuts/type) + the same shared W-CT tail for the emission arm |

##### P0f slice 7 — §4.I, the FCMP++ spend path (18 rows)

Reviewed at **`4b9807c5e`** (2026-09-02). Walks: **W-TI** = the spend-path
gates in `check_tx_inputs` (`blockchain.cpp:3536–3740`, census lines drifted
+~70 as established), **W-RB** = the reference-block/proof block
(`:4251–4390`), **W-PQ** = `tx_pqc_verify.cpp` (whose real path is
`src/cryptonote_core/`, not the census's `src/fcmp/` — pointer drift recorded)
plus its gate (`:4405–4415`).

| Row | State | Evidence (all at `4b9807c5e`) |
| --- | --- | --- |
| CEN-I1 | **CHECKED-CONFORMANT** | W-TI. Too-few-outputs rejects with `m_too_few_outputs` |
| CEN-I2 | **CHECKED-CONFORMANT** | W-TI. `!is_fcmp_pp` rejects; second sites re-reject ring-based inputs and non-coinbase `CTTypeNull` (`:3676–3690`). **REWRITE-NOTE:** multi-site belts of one rule — H13's collapse class |
| CEN-I3 | **CHECKED-CONFORMANT** | W-TI. `min = max = 3` **hardcoded at the site**, independent of the HF dispatch, exactly as the row states. **REWRITE-NOTE:** the whole gate block sits under `m_nettype != FAKECHAIN` — the §6-finding-8 test-lever class (R9): the rewrite needs a *designed* test seam, not a nettype carve-out around consensus gates |
| CEN-I4 | **CHECKED-CONFORMANT** | W-TI. `vin.size() > FCMP_MAX_INPUTS_PER_TX` (8, `cryptonote_config.h:311`) rejects — the cap covers total `vin.size()`, confirmed |
| CEN-I5 | **CHECKED-CONFORMANT** | W-TI. `memcmp >= 0` rejects — strictly descending, so duplicate and mis-ordered key images fail the **same** check (the row's "one rule, two guarantees") |
| CEN-I6 | **CHECKED-CONFORMANT** | W-TI. Non-empty `key_offsets` rejects (`:3663`) |
| CEN-I7 | **CHECKED-CONFORMANT** | W-TI. `have_tx_keyimg_as_spent` per input rejects (`:3667`) — the verify-side belt in front of CEN-L1's storage enforcement, both now on the register. **REWRITE-NOTE:** the same multi-site-belt observation as CEN-I2 — this belt and CEN-L1's storage-side enforcement are two sites of one commitment (H13's collapse class); the rewrite carries one site *(marker minted round 5 — the slice-7 decision row already named I7, but no row carried it)* |
| CEN-I8 | **CHECKED-CONFORMANT** | W-TI. `pqc_auths.size() != vin count` rejects for non-serve-credit; serve-credit must be **empty** (`:3695–3720`) |
| CEN-I9 | **CHECKED-CONFORMANT** | W-TI. `pseudoOuts == num_inputs` for regular spends; archival shapes excepted here because their own counts are enforced in W-VU (slice 6) |
| CEN-I10 | **CHECKED-CONFORMANT** | W-RB. `block_exists(rv.referenceBlock)` rejects (`:4251`; the two twins at `:3856`/`:4005` are the archival copies read in slice 4) |
| CEN-I11 | **CHECKED-CONFORMANT** | W-RB. Both windows reject: min-age 5 and max-age, each with the correct boundary arithmetic as read |
| CEN-I12 | **UNREVIEWED** — *failed closed (round 6, 2026-09-03)* | The anchor source is **internally split**, so there is no unambiguous spec to affirm against: `FCMP_PLUS_PLUS.md` §7 step 2's normative pseudocode says `get_curve_tree_root_at(ref_height)` (the table read the code performs, `blockchain.cpp:4285`) while its own prose two paragraphs later says `get_block_header(rv.referenceBlock).curve_tree_root` — and the census row records the table-vs-header divergence as an open §7 item. Slice 7 promoted on the in-code rationale (FAKECHAIN headers carry placeholder roots), but **an in-code rationale is not a ratification**, and the FAKECHAIN-shaped reasoning is itself rule-71-adjacent. Same shape as CEN-L8: a clause whose own source disagrees with itself can be neither conformant nor divergent | **Regression only.** Promotion requires the §7 table-vs-header item reconciled (census owns it), then re-review |
| CEN-I13 | **CHECKED-CONFORMANT** | W-RB. `depth == 0 \|\| depth > current` rejects; layers = depth+1 at the verify call (the FFI-boundary convention documented in `shekyl-ffi`) |
| CEN-I14 | **CHECKED-CONFORMANT** | W-RB. Empty proof rejects (`:4306`) |
| CEN-I15 | **CHECKED-CONFORMANT** | W-RB. `shekyl_fcmp_verify` rc-checked reject. The **verification cache** (`can_skip_fcmp`, `:6128–6129`) is `found_tx_in_pool && is_ct_fcmp_pp_pqc` — structural checks still run under the skip, and the in-code note marks the skip **load-bearing for the D++ embargo's `hop`**. **Amended by slice 8: the cache condition itself is CEN-M8's subject and was found DIVERGENT (S0)** — presence does not imply pool admission *verified* (the `kept_by_block` tolerance admits failed txs with `fcmp_verified = 0`). This row's verify-when-run is conformant; the skip's admission gate is M8's divergence, recorded there. *(Round 2, 2026-09-03: reviewed for the CEN-G4/J26 coupling and deliberately NOT flipped — this row's ratified clause is the verify call's operand binding, and its census row delegates the skip to M8 in terms: "Skippable on block connect only via the pool cache (CEN-M8)". The cache's defect breaches M8/G4/J26's clauses, not this one.)* |
| CEN-I16 | **CHECKED-CONFORMANT** | W-PQ. `auth_version == 1`, `flags == 0`, `scheme_id ∈ {single, multisig}`, per-scheme key-length bounds — each rejects (`:175–223`) |
| CEN-I17 | **CHECKED-CONFORMANT** | W-PQ. Signed payload binds prefix ‖ CtSig base ‖ keccak256(prunable) ‖ per-input PQC header ‖ **all** inputs' key hashes (`:62–158`), the cross-input bind included |
| CEN-I18 | **CHECKED-CONFORMANT** | W-PQ. `shekyl_pqc_verify` rc-checked reject (`:230–243`). **Interaction verified, not assumed:** the gate carries `&& !is_archival_serve_credit_only` (`:4408`), so serve-credit txs (whose auths are empty by H20's rule) never reach the size gate that would reject them. The hybrid scheme's own adequacy is the signature-alignment round's subject, not this row's |

##### P0f slice 8 — the small sections (§4.A/B/C/D/G/K/M, 22 rows) — **P0f row coverage complete**

Reviewed at **`4b9807c5e`** (2026-09-02). The gravest finding of the whole
review — **CEN-M8, graded S0 on the §7.2 ladder** — is presented first. The
table below is the record of per-row verdicts (the completion header above
carries the current totals; this prose deliberately does not repeat them).

| Row | State | Evidence (all at `4b9807c5e`) |
| --- | --- | --- |
| **CEN-M8** | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: found DIVERGENT at S0, slice 8; ruled FIX 2026-09-03; fixed by PR #602)* | Re-reviewed at `a45916c66` (round 6, 2026-09-03 — the tree contains PR #602's merged fix, `dev` merge `a566a4668`). The skip is now **hash-gated as ratified**: `can_skip_fcmp = found_tx_in_pool && fcmp_verification_cached` (`blockchain.cpp:6139`), where `take_tx` computes `is_fcmp_verification_cached(meta, tx)` — `fcmp_verified` set **and** the recorded `H(proof ‖ referenceBlock ‖ key images)` matching the parsed bytes — while the meta still exists, **defined false on every exit path including the removal-failure catch** (`tx_pool.cpp:891`, reset at the catch). Admission-verified txs keep the skip (the D++ embargo's `hop` unchanged); a `kept_by_block`-tolerated tx with `fcmp_verified = 0` pays full verification. Four unit tests pin the verdict contract (admission-failed false / hash-match true / stale-hash false / failure-return reset), red-observed against presence semantics; the connect-path wiring regression remains a FOLLOWUPS item against the FCMP++ spend-builder blocker — the promotion rests on the code walk plus the verdict tests, with that boundary stated | Digest identity **required**; a match on this row **is** correctness evidence |
| CEN-A3 | **CHECKED-CONFORMANT** | Witness-less 2-arg `add_new_block` asserts `attestation_root == empty_attestation_root()` (`:6655`) — a dropped witness cannot connect silently |
| CEN-B1 | **CHECKED-CONFORMANT** | `HardFork::do_check` requires `block_version == heights[current].version` **and** `voting_version >=` (`hardfork.cpp:109–113`); with the single `{1,1}` entry (slice 5) major_version must equal 1; called on main (`:5833`) and alt |
| CEN-B4 | **CHECKED-CONFORMANT** | `verify_block_attestation` on both paths (`:5843` main, `:2312` alt) → Rust verdict, logged per code. The **runs-before-PoW ordering** is the census §6 finding 7's live FOLLOWUPS row — already on record, not re-opened here |
| CEN-B5 | **DIVERGENT** *(rule-71 counterexample — the silent FAKECHAIN skip)* | Re-walked round 6: slice 8 cited the compare at `:6462–6472` and **missed the guard one line above it** — the whole post-connect root check is wrapped in `m_nettype != FAKECHAIN` (`:6468` at this sha), while the ratified rule says **every** mismatch rejects and rule 71 names this exact skip as "the counter-example this rule exists to retire" (`.cursor/rules/71-network-uniformity.mdc:60–72`, census batch R9 owns the family). Not production-reachable (FAKECHAIN is the test chain type), so no §7.2 S-grade — but a nettype-conditioned consensus check is the divergence class rule 71 bans, and "testnet passed" logic-coverage claims are weakened exactly as the rule predicts. **REWRITE-NOTE** (kept from the prior verdict): connect-then-check-then-compensating-pop is inherited arrangement — the rewrite checks the root **before** txn commit, and uniformly across nettypes (the test generator must produce real roots instead of the check being skipped) | Identity is **not** the pass condition; promotion is gated on the R9 uniformity retirement (check runs on every nettype, or the exception is ratified loud per rule 71) |
| CEN-C1 | **CHECKED-CONFORMANT** | Spec-of-record is **C2-R3**, and conformance is against it: the saturating FTL bound has one site (`timestamp.rs:66–67`), reached from the **one** C++ consensus caller (`blockchain.cpp:5612`) through the FFI wrapper that names itself the ONE site; pinned by the both-language `MTP_BOUNDARY_V1` vectors |
| CEN-C2 | **CHECKED-CONFORMANT** | Strict `>` has exactly one site (`timestamp.rs:103–106`, with the comment saying so); same caller, same vectors |
| CEN-C3 | **CHECKED-CONFORMANT** | Genesis right-padding is the `[genesis_ts; WINDOW]` fill in `check_timestamp_rule` (`:155–158`); verdict precedence (WindowTooWide → AboveFtl → NotAboveMedian) as ratified |
| CEN-D1 | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: DIVERGENT coupled to CEN-D2, review round 6; fixed with it by PR #604)* | Re-reviewed at `813d2ed37` (2026-09-03). The `check_hash` dispatch was always conformant (`:5843` main, `:2296` alt; u128 comparison; KAT per CEN-D1b). The clause that failed was this row's own **"FFI failure rejects"**, and it now holds by the same three-site gating recorded under CEN-D2 — one defect, one fix, both clauses closed | Digest identity **required**; a match on this row **is** correctness evidence |
| CEN-D2 | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: found DIVERGENT at S1 in review round 4; ruled FIX 2026-09-03; fixed by PR #604)* | Re-reviewed at `813d2ed37` (2026-09-03 — the `dev` merge of PR #604). The schema half was always conformant (`pow_registry.cpp` returns RandomX unconditionally). **The fail-closed clause now holds at every difficulty:** the verifier's returned bool is the gate at **all three** consumers — main connect rejects before `check_hash` (`blockchain.cpp:5828–5840`), the alt path rejects on `get_altblock_longhash`'s new bool return (`:2285–2294`), and the precompute worker refuses to cache an uncomputed hash (`:6773–6781`), which mattered because a table hit is trusted downstream without re-checking. The `0xff…` sentinel survives as a belt for display-only callers (RPC `pow_hash` fills), and both comments that overstated it ("guarantees `check_hash()` rejects it") now name the bool as the gate. **Attribution checked, not assumed:** the verifier-failure arms deliberately omit `m_bad_pow` while genuine `check_hash` failure still sets it (`:5847`, `:2300`) — walked to both consumers (`cryptonote_protocol_handler.inl:685`, `:1531`), where the flag selects fail-score `P2P_IP_FAILS_BEFORE_BLOCK` (10) versus 1 and the peer is **dropped either way**. **The principled reason is that the two verdicts are different claims:** `m_bad_pow` asserts *this block's PoW is bad*, while a verifier failure asserts nothing about the block at all — we could not compute the hash. Attributing the second as the first would be wrong whoever caused it. **Inducibility, checked against the FFI's actual taxonomy** (`pow_randomx_ffi.rs`, `shekyl_ffi.h` §PoW): the codes that can be *returned* are boundary-contract failures — `ERR_NULL_PTR` (a null seedhash/out buffer, caller-side and never attacker-controlled) and `ERR_DATA_TOO_LARGE` (`data_len > 2 MiB`) — while `ERR_CACHE_DERIVE_FAILED` and `ERR_INTERNAL` are **reserved and never returned**: under `panic = "abort"` a derivation OOM or panic aborts the process rather than returning failure. `ERR_DATA_TOO_LARGE` is the only data-dependent code and is unreachable here, because the hashed input is `get_block_hashing_blob` — a serialized block header plus a 32-byte tree root and a length varint, on the order of a hundred bytes, which does **not** grow with transaction count or block weight. So a peer cannot farm these events; and were that ever to change, the flag would still be the wrong verdict and the peer is dropped regardless. **Evidence is behavioural, not only a walk:** five verdict-contract unit tests (`pow_longhash_gate.cpp`) plus two connect-path regressions (`gen_block_pow_verifier_failure_{main,alt}`) that run at test difficulty **1** — exactly where the belt fails open — and assert rejection *as unproven*; reverting either consumer turns them red (observed). The test seam's containment is itself gated (`scripts/ci/check_pow_test_seam.sh`, three invariants, in the bundled grep job), and it publishes with release/acquire so a worker cannot observe the pointer without an edge to the schema's construction | Digest identity **required**; a match on this row **is** correctness evidence |
| CEN-D3 | **CHECKED-CONFORMANT** | `seedheight` matches the rule symbol-for-symbol (`seed_epoch.rs:109–115`: `0 for h ≤ blocks+lag, else (h−lag−1) & !(blocks−1)`, 2048/64); one Rust site, C++ calls the FFI (`:669`); the FAKECHAIN schedule override **warns loudly** at startup |
| CEN-D4 | **CHECKED-CONFORMANT** | LWMA-1 canonical in `shekyl-difficulty::lwma1_next` behind the FFI; the C++ window-gather (`:1082–1175` region) is operand marshaling with the trim invariant documented in place |
| CEN-G4 | **CHECKED-CONFORMANT** *(re-reviewed post-fix — history: DIVERGENT coupled to M8, round 2)* | Re-reviewed at `a45916c66` (round 6). Per-tx `check_tx_inputs` at connect with failure → `add_block_as_invalid` + `bvc.m_verifivation_failed` + txs returned (`:6143–6156` at this sha) — the dispatch conforms, and the clause's precondition now holds: with the hash-gated cache the skip is granted **only** to admission-verified bytes, exactly "FCMP++ txs that verified at pool admission skip only the FCMP proof re-verify (structural checks re-run)" | Digest identity **required**; a match on this row **is** correctness evidence |
| CEN-G7 | **CHECKED-CONFORMANT** | Cross-tx `(P, shard, E)` set over the whole block; unparseable vin rejects; duplicate insert rejects (`:6178–6200`) |
| CEN-G9 | **CHECKED-CONFORMANT** | `(P ‖ E)` 40-byte pairs collected across txs, decided by Rust `shekyl_emission_block_claims_unique != 1` → reject (`:6280–6288`) |
| CEN-G10 | **CHECKED-CONFORMANT** | `shekyl_archival_bond_post_block_unique != 1` → reject (`:6290–6294`) |
| CEN-G11 | **CHECKED-CONFORMANT** | The inflow uses **verify's exact operands** (F-B1c discipline documented at `:6303–6360`: one version read, one escalation-operand read, conservation stated as coinbase + accrual + burn = base_reward + fees); the pattern is CI-enforced by `scripts/ci/check_archival_reward_gates.sh` (present) |
| CEN-G12 | **CHECKED-CONFORMANT** | The supply clamp is Rust-side (`shekyl_advance_already_generated`), and the in-code note records that the former **two hand-written copies** (main + alt) were already collapsed onto the one entry — the drift pair this register would otherwise have flagged, fixed before we got here |
| CEN-G13 | **CHECKED-CONFORMANT** | Genesis pays the configured blob (F11) and the accrual rides `add_block` for non-genesis blocks only, per the `:6321` block-version-floor note |
| CEN-K5b | **CHECKED-CONFORMANT** | Promoted blocks re-supply the witness from the hash-keyed alt store (`:1450`; stored `:2545`; demote twin `:1428`); consumed by B4's verify on the alt path |
| CEN-M5 | **CHECKED-CONFORMANT** | `!kept_by_block && tx.unlock_time` rejects with `m_nonzero_unlock_time` (`tx_pool.cpp:271–277`) — the relay leg of the unlock_time triple-divergence, exactly as ratified |
| CEN-M9 | **CHECKED-CONFORMANT** | `insert_attested_tx` computes the verification hash on the same derivation as the P2P path and inserts with `fcmp_verified` set accordingly (`:609–614`); key-image insertion failure and add-failure both unwind |

**Examined and excluded — CEN-L12's *staked arm* only, not the row:** its
notes record that the spec's `staked: max(effective_lock_until…)` arm "does not
exist in code", but that arm is **claim-era and retired**, so its absence is not
a divergence. **CEN-L12 itself was DIVERGENT** on the spec's universality
clause until CEN-L11's fix (2026-09-04) closed it: with the leaf collector
aborting instead of skipping, no accepted output can be dropped before it is
made pending, so universality holds. Both rows are CHECKED-CONFORMANT — see
their §5.4.1 register rows.

**Coverage vs. set growth — two different claims (updated 2026-09-03).** The
register was first seeded by this document's 18 store-enforced rows plus a
keyword sweep; P0f then replaced that seed with a SOURCE-based enumeration and
completed coverage over **all** of the census's bucket-1/2 rows (102 at the
2026-09-02 bucket split). What remains open is the **set itself**: bucket-3/4
rows promoted to 1/2 by the census's design rounds enter this register
**UNREVIEWED** and need a P0f-style review before any correctness claim, and a
row whose bucket or code moves before the freeze must be re-reviewed
(re-bucketing happened twice under P0f's own branch). **Obligation (CSR-3a):**
extension stays a **DRS-P0f / census** job, and no parity claim may assert
*correctness* for a bucket-1/2 row until that row has been checked here. Rows
enter from either side: a census round finding a divergence, or P0's wart pass
finding one.

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
prevent. CEN-L11 was the test case: a live FOLLOWUPS row, a ratified spec, and a
defective implementation on a file being deleted. It was ultimately fixed in
place (2026-09-04) because the change is three aborts and their falsifier, and
leaving a silent surface in the oracle the rewrite is differentially checked
against costs more than the debt it avoids — the narrow §6.4 FIX-IN-CPP
reasoning, recorded here so the rule's boundary stays visible.

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
**necessary, not sufficient**: CEN-L11 was bucket-1 ratified with an
implementation that did not meet its spec (fixed 2026-09-04; the argument for
the conformance condition stands on the fact that the gap existed at all). The census header now carries the
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
| **CSR-3a** | The **conformance register** (§5.4.1): a bucket says a rule is *ratified*, never that the C++ *implements* it | every parity claim asserting correctness | **ROW COVERAGE COMPLETE OVER THE 2026-09-02 SET** — the **102** bucket-1/2 rows that existed then are disposed: **99 CHECKED-CONFORMANT / 1 DIVERGENT / 2 failed closed** over P0f's **102-row** snapshot (the live bucket-1/2 set is **111** after C2-R1b's nine promotions, which are UNREVIEWED pending review): CEN-B5 (rule-71 FAKECHAIN skip; R9 owns); CEN-L8 and CEN-I12 failed closed. **Both S-grades are closed** — CEN-M8/G4/J26 promoted at PR #602's merged fix, CEN-D2/D1 at PR #604's — and **CEN-L11/L12 were promoted at PR #609's** (2026-09-04); the examined-and-excluded note on L12 covers its **staked arm only** (a retired claim-era clause), not the row. **Coverage is complete over that snapshot, and the live set has already outgrown it** — C2-R1b's nine promotions (2026-09-03) are UNREVIEWED, as any future bucket promotion is on arrival; **DRS-P0f** and the census own reviewing them; E2 must consult the register before calling any match correctness |
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
| **2026-09-02** | **DRS-P0f slice 8 — the small sections; ROW COVERAGE COMPLETE.** 21 rows conformant (C-rows verified against the C2-R3 spec-of-record with the both-language MTP vectors; D3's seedheight matched symbol-for-symbol; G12's former drift pair found already collapsed). **CEN-M8 DIVERGENT at S0:** the spec ratified a hash-gated proof-skip; the code gates on pool **presence** alone, and the `kept_by_block` tolerance admits failed txs with `fcmp_verified = 0` — so an invalid FCMP++ proof can connect with verification skipped. The exact required check exists (`is_fcmp_verification_cached`) with only a template-path caller. Per the §7.2 ladder, S0 is **fix-or-risk-accept, Rick's call**; the §6.4 narrow FIX-IN-CPP class applies and the fix is a few lines. I15/J26 evidence amended (their cache sentence had overstated). **Final: 102/102 bucket-1/2 rows disposed — 98 / 3 / 1** *(2026-09-03 round 2: CEN-G4 and CEN-J26 re-coupled to M8 — 96 / 5 / 1; round 4: CEN-D2 re-flipped DIVERGENT at S1; round 6: M8 promoted post-fix-merge, B5/D1 re-flipped, I12 failed closed; 2026-09-03: D2/D1 promoted at PR #604's merge — 97 / 3 / 2; 2026-09-04: L11/L12 promoted at PR #609's merge — 99 / 1 / 2; see those rows)* | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 7 — all 18 §4.I rows CHECKED-CONFORMANT** at `4b9807c5e`, including the serve-credit/PQC-gate interaction verified explicitly and the verification cache's condition read at its derivation site. Census pointer drift recorded: `tx_pqc_verify.cpp` lives in `src/cryptonote_core/`, not `src/fcmp/`. REWRITE-NOTEs: the FAKECHAIN carve-out around the spend gates (R9's designed-test-seam), and the multi-site belts (I2, I7) joining H13's collapse class *(2026-09-03 round 6: CEN-I12 failed closed to UNREVIEWED — its anchor source is internally split; see the round-6 row)* | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 6 — all 13 remaining §4.H rows CHECKED-CONFORMANT** at `4b9807c5e`. CT balance and output-key checks confirmed Rust-single-sourced with discriminated verdicts; H14's emission exemption confirmed to share one classifier with `check_tx_inputs` (anti-drift structure worth keeping). REWRITE-NOTEs: H12's dead VIEW_TAGS arms (R5 residue); H13 as the version rule's third site (collapse to one) | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 5 — all 16 §4.F rows CHECKED-CONFORMANT** at `4b9807c5e`. Economics arithmetic confirmed Rust-canonical ("nothing is computed here" holds as read; 81-vector KAT both languages); F18's exact-pay verified in both directions; F21 pinned constant→table→function→caller. REWRITE-NOTEs: F4's load-bearing genesis exemption + anti-spoof structure; F19's tautology hazard should become structural in the rewrite; F20's duplicated 720-mean collapses to one implementation | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 4 — all 26 §4.J rows CHECKED-CONFORMANT** at `4b9807c5e`, via three end-to-end branch walks (W-SC / W-BP / W-EM) with every FFI verdict checked and W-SC's predicate sequence KAT-pinned on both legs. Three REWRITE-NOTEs recorded (assign_epoch cutover reopen; drop-arm set-difference in the marshal; skip_fcmp_verify's embargo-load-bearing cache) plus the section-level note that the C++/Rust mirror is interim structure the rewrite retires *(2026-09-03 round 2: CEN-J26 re-flipped DIVERGENT, coupled to CEN-M8)* | §5.4.1 |
| **2026-09-02** | **DRS-P0f slice 3 — the archival-journal family; all six reviewable store-enforced rows now reviewed.** **CEN-L7 → CHECKED-CONFORMANT** (the three bond-fold connect arms return their Rust verdict into one checked site, `apply_archival_bond_record_update`, so `return rc` is correct rather than a discarded verdict). **CEN-L9 → CHECKED-CONFORMANT** (every named fatality present; bonded-underflow checked twice, per-P and global). **CEN-L8 → failed closed to UNREVIEWED**: two clauses verify, but its settlement `(passes, issued)` clause names behavior that does not run — `set_archival_settlement` has **no production caller**, a hazard the tree itself flags at `db_lmdb.cpp:7649` — and **SO-D7 places that writer in the slash scheduler's pass, not epoch close**, so the row's wording is a **census question routed to R8**, not a conformance verdict | §5.4.1 |
| **2026-09-04** | **CEN-L11 and CEN-L12 re-reviewed at the merged fix and PROMOTED — register 99 / 1 / 2 over P0f's 102-row snapshot; CEN-B5 is the sole DIVERGENT row.** Re-reviewed at `ab4693d0e` (contains the `dev` merge `a72e38550` = PR #609; no cited file differs between the two). All three collector arms abort at connect (`blockchain_db.cpp:561`, `:570`, `:589`), the construct verdict is consumed, the three foreclosing gates carry their reverse pointers, and the evidence is behavioural at this sha: the five `cen_l11_*` LMDB regressions and the Rust falsifier both pass (red-observation recorded in #609). L12's universality clause closes with it. **Register-only PR, by design:** the fix and its promotion were split so the promotion could pin a sha containing the *merged* fix — the rule this register applied to CEN-M8 and CEN-D2/D1 — and so that register churn stops riding fix PRs (#609 spent its last four rounds on doc text over a code half that was stable from round 5). **Two early-promotion leaks recorded, not rewritten:** (1) PR #609 merged under the title *"… — register 99/1/2"*, written before its round 6 withdrew the promotion, so merge commit `a72e38550` carries a figure the tree did not have at that sha — **withdrawn-in-PR, records-was:** 97 / 3 / 2 at that merge, 99 / 1 / 2 only from this re-review — and a `git log --grep` on it lands one PR early. This row is the durable correction, since the commit body cannot be edited; (2) `IMPLEMENTATION_INDEX.md`'s CSR cell already read "CEN-L11 and CEN-L12 were fixed and promoted 2026-09-04" beside a 97 / 3 / 2 count that contradicted it — the withdrawal missed that sentence, and this PR makes it true rather than deleting it. Both are the lesson #602's rounds already drew: **counts do not belong in PR titles**, and a withdrawal must sweep every surface the claim reached. **Not in this PR:** the nine C2-R1b rows (UNREVIEWED; their own P0f round), CEN-I12 (a census ruling), CEN-B5 (R9) | §5.4.1 |
| **2026-09-04** | **CEN-L11 and CEN-L12 FIXED; promotion deferred to a merged sha — register holds at 97 / 3 / 2 over P0f's 102-row snapshot.** The register's seed row turned out to be **mis-framed**: L11 was recorded as a live fund-loss path, but all three of its skip arms are unreachable for any validated tx — CEN-H12/F8 forecloses the target-type arm, four size-equality gates the `outPk` arm, and two point gates (`check_outs_valid`, `check_commitment_mask_valid`, both with coinbase legs in `prevalidate_miner_transaction`) the construct arm, whose only attacker-supplied inputs are the output key and the commitment. `check_outs_valid`'s own comment had named this hazard for its own existence; nothing connected it back to L11. Latent, therefore, not live — and the posed fail-closed-vs-documented-skip question resolves without a trade, since fail-closed costs nothing over dead arms while documented-skip preserves a silent surface. All three now abort, naming their foreclosing gate; the gates carry reverse pointers (relaxing one surfaces as a connect-time abort, not a widened rule); and a Rust falsifier asserts gate/leaf-builder agreement, red-observed. L12's universality clause follows directly. **Promotion is NOT claimed here:** this document's schema pins the sha the code was reviewed at, and the rule it applies to CEN-M8 and CEN-D2/D1 makes that a sha containing the *merged* fix — so both rows stay DIVERGENT until a follow-up review, exactly as those two did. 39 core-test chains connect with zero aborts | §5.4.1 |
| **2026-09-03** | **CEN-D2 and CEN-D1 re-reviewed at the merged fix and PROMOTED — register 97 / 3 / 2; no S-graded divergence remains.** Reviewed at `813d2ed37`: all three consumers gate on the verifier's bool (main connect, alt path, and the precompute worker whose table is trusted downstream), the sentinel survives as a belt for display-only callers, and both overstating comments now name the bool as the gate. **The `m_bad_pow` omission was walked to its consumers rather than accepted as stated** (`cryptonote_protocol_handler.inl:685`, `:1531`): the flag selects fail-score 10 versus 1 and the peer is dropped either way, and the principled ground is that the two verdicts are different claims — `m_bad_pow` asserts *this block's PoW is bad*, a verifier failure asserts only that we could not compute the hash. Inducibility was checked against the FFI's actual taxonomy rather than assumed: the returnable codes are boundary-contract (`ERR_NULL_PTR`, `ERR_DATA_TOO_LARGE`), the local-fault codes are reserved and never returned (OOM/panic aborts under `panic = "abort"`), and the only data-dependent code is unreachable because the hashed input is the ~100-byte block **hashing blob**, which does not grow with block size. An earlier draft of this rationale had the taxonomy backwards and is corrected here. Promotion rests on behaviour, not only a walk: five verdict-contract unit tests plus two connect-path core-test regressions at difficulty 1, red-observed against each consumer. **Both S-graded findings of the whole review are now closed** (S0 by PR #602, S1 by PR #604); the DRS-0 blocker line clears | §5.4.1, §7.2 |
| **2026-09-03** | **CEN-D2/D1 S1 ruled FIX (Rick) — PR #604.** The verifier's bool is now the gate at all three consumer sites (main connect, alt via `get_altblock_longhash`'s new bool return, and the longhash worker, which never caches an uncomputed hash); the `0xff…` sentinel stays as a belt for display-only callers and both overstating comments are corrected. The main/alt rejection arms deliberately omit `m_bad_pow` — a local verifier failure is not evidence against the block. `get_altblock_longhash` also now routes through the single `IPowSchema` dispatch point, collapsing a second direct FFI call site; a loud-named test-only schema override provides the failure seam, with five verdict-contract unit tests (two red-observed). Rows stay DIVERGENT until re-reviewed at a sha containing the merged fix | §5.4.1, §7.2 |
| **2026-09-03** | **Round 6 (Copilot, PR #599) + the #602 merge: six verdicts move; register 95 / 5 / 2.** **Promoted:** CEN-M8, CEN-G4, CEN-J26 re-reviewed at `a45916c66` (contains `dev` merge `a566a4668` = PR #602) — the skip is hash-gated as ratified, false on every failure path, verdict-contract unit tests in tree; the connect-path wiring regression stays a FOLLOWUPS item (spend-builder blocker) and the promotion rests on the code walk + verdict tests, boundary stated in the rows. **Re-flipped:** CEN-B5 — slice 8 cited the root compare and missed the `m_nettype != FAKECHAIN` guard one line above it; rule 71 names this exact silent skip its counter-example, census R9 owns the retirement (no §7.2 S-grade: FAKECHAIN-only). CEN-D1 — its own clause includes "FFI failure rejects", breached by D2's difficulty-1 fail-open; coupled to D2, one fix closes both. **Failed closed:** CEN-I12 — the anchor source is internally split (§7 step 2 pseudocode says the table read the code performs; the prose says the header field; the census row records the divergence as an open §7 item), and an in-code rationale is not a ratification — the CEN-L8 shape. **Also this round:** origin/dev merged (conflict in FOLLOWUPS resolved keeping both sides), and the FOLLOWUPS M8 S0 item is discharged (fix merged, rows re-reviewed) with the D2 item extended to carry D1 | §5.4.1, §7.2 |
| **2026-09-03** | **Round 5 (Copilot, PR #599): residue sweep.** CEN-I7's REWRITE-NOTE marker minted (the slice-7 dated row named I2 *and* I7 for H13's collapse class, but only I2's row carried a marker — routed count now **15**: 14 row-level + 1 section-level); DRS's live DRS-0 blocker line extended with the §7.2 consequence the round-4 grade already implied (S1 blocks DRS-0, so CEN-D2's fix-or-accept now appears in the blocker status alongside PR #602's merge); the DRS banner's pre-P0f "explicitly incomplete" rationale re-anchored to coverage-vs-set-growth; provenance labels corrected (index UPDATE rounds 1–3 → 1–4; D11 cell round 2 → rounds through 4) | §5.4.1, §7.2 |
| **2026-09-03** | **Round 4 (Copilot, PR #599): CEN-D2 re-flipped DIVERGENT at S1 — the fail-closed sentinel fails open at difficulty 1; register now 95 / 6 / 1.** The `0xff…` sentinel written on verifier failure passes `check_hash` at difficulty 1 (the crate's own test says so, `check_hash.rs:163–165`), both validation paths ignore the verifier's bool, `--fixed-difficulty` is a general daemon arg on any nettype, and organic LWMA-1 has no floor above CEN-D6's zero-guard — so (FFI failure ∧ difficulty 1) connects a block whose PoW was never verified. **Slice 8's evidence cell said the arm "stands as read" — the recorded tell of a light walk, and the read was wrong**; the in-tree comment's own guarantee ("guarantees check_hash() rejects it") overstates its constant, and the census row ratified the overstatement (census D2 row annotated in this round). Sibling sweep found no second difficulty-1-class hole (D5/K1's zero sentinel is caught by D6; H16's sentinel is a comparison). Graded **S1** (consensus correctness, connect path — not fund-safety: the trigger is a local verifier failure, not attacker input); per the ladder S1 blocks DRS-0 — **fix-or-accept is Rick's**, FOLLOWUPS carries the sketch (consume the verifier's bool at the validation sites; sentinel stays as a belt). The slice-8 register header also stops restating totals — live prose counts were re-rotting every round | §5.4.1, §7.2 |
| **2026-09-03** | **Round 2 (Copilot, PR #599): the M8 coupling propagates — CEN-G4 and CEN-J26 re-flipped DIVERGENT; register now 96 / 5 / 1.** Slice 8's amendments scoped the S0's breach to CEN-M8 alone; review showed two rows' **own clauses** are breached by the presence-gated cache — G4's "FCMP++ txs *that verified at pool admission* skip" and J26's "present ⇒ verifies" — the CEN-L11→L12 coupling test, applied consistently (a reversal of slice-8 prose, owned here). **CEN-I15 reviewed for the same coupling and deliberately held CHECKED-CONFORMANT:** its clause is the verify call's operand binding, and its census row delegates the skip to M8 in terms. **Also corrected:** round 1's own claim that `add_tx` hard-rejects every entrant — the check is conditional on `version != nic_verified_hf_version` (default 0 catches every fresh relay entrant; the `kept_by_block` callers at `blockchain.cpp:862`/`:2467`/`:5988` deliberately pass equal versions because caller-side checks ran); the routed REWRITE-NOTE count corrected 24 → **14** (13 row-level + 1 section-level; the rest were decision-log echoes); §7.1.1's E2 bar restated over the whole S-ARCH surface (CEN-L7/L9/L10 are its CHECKED-CONFORMANT rows), not L10 alone; the completion claim split into coverage-complete vs. set-growth. **Ruled 2026-09-03 (Rick): the S0 gets the FIX, not a risk-accept** — hash-gate the skip via `is_fcmp_verification_cached` surfaced through `take_tx` (**PR #602**, branch `fix/cen-m8-hash-gated-proof-skip`); M8, G4 and J26 stay DIVERGENT until re-reviewed at a sha containing the merged fix | §5.4.1, §7.2 |
| **2026-09-03** | **CEN-H5 evidence corrected on review (Copilot round 1, PR #599) — the register row cited dead code as connect coverage.** The double-spend visitor's only call is commented out (`blockchain.cpp:6106`) — a fact the census already recorded twice (§5 dead-surface item 3; CEN-L1's row), which slice 1 failed to cross-check — and the visitor's body *accepts* `txin_gen`. Live coverage re-walked and re-cited: site 1 is block-fatal on the pool supplement via `ver_non_input_consensus` Rule 5 (`blockchain.cpp:5941` main / `:2449` alt); site 1 runs once per pool entrant — in `add_tx` for any caller not asserting prior verification (`tx_pool.cpp:236–241`), caller-side for the equal-version `kept_by_block` re-inserts (this clause corrected in round 2); `check_tx_inputs` types every block tx's inputs at connect (`:3649–3656`); the DB backstop covers script variants only (it accepts `txin_gen` as miner-shaped, `blockchain_db.cpp:286–290`). **Verdict unchanged — the rule is enforced; the register cited the wrong enforcer.** Same round: CEN-L12's `:562` belt re-attributed CEN-H5 → **CEN-H12** (that arm switches on *output target* types, not vin variants). The register doing exactly its job: an inherited claim — our own slice-1 prose included — is a hypothesis | §5.4.1, §3 |
| **2026-09-02** | **DRS-P0f slice 2 — CEN-L10 → CHECKED-CONFORMANT** at `4b9807c5e`. First-crossing division confined to one Rust site and pinned by a boundary table; layer-2 sub-root existence and the CREATE-only O-2 refusal both fatal; geometry constant structurally asserted against the fcmp widths. Every error arm aborts loudly. **Recorded precision:** L10 is an S-ARCH row, so although the verdict promotes it, **§7.1.1 still bars E2 from acting on it for the archival surface until archival digest coverage exists** — a conformance verdict and a coverage gate are different preconditions | §5.4.1 |
| **2026-09-02** | C2-R1 (reorg/alt) landed (PR #596) during this slice; census re-bucketed again to **86 / 16 / 5 / 64** (three rows to bucket 3 — the deleted per-block-checkpoint fast path). **CEN-H5, CEN-L11 and CEN-L12 re-verified as still bucket 1 at `4b9807c5e`**, so the P0f verdicts stand | header, §5.4 |
| **2026-09-02** | **DRS-P0f slice 1 — the register's first verdicts.** Reviewed at `6bc2de8f2`: **CEN-H5 → CHECKED-CONFORMANT** (three sites agree with the spec and each other; relay coverage via `check_tx_semantic`, connect coverage via the visitor and the unconditional DB backstop). **CEN-L12 → DIVERGENT**, coupled to CEN-L11: its maturity arithmetic conforms exactly, but the spec's *universality* clause fails because L11's unchecked construct verdict can drop an accepted output before it is made pending — **L12 cannot be promoted while L11 stands**, a coupling the census recorded as two independent rows. Scope reviewed: connect + relay; pop/revert is P0b's. **Census pointer drift found:** CEN-H5's site 2 is cited `blockchain.cpp:3162–3168` but the double-spend visitor is at `:3232–3258` at this sha — C2-R3's commits moved the file after the census pin `ab3cc98e6` *(2026-09-03: the connect-coverage clause in this row cited the dead visitor — corrected, see the 2026-09-03 row; verdict unchanged)* | §5.4.1 |
| **2026-09-02** | **CSR-3 corrected on review — the bucket axis is not the conformance axis.** A census bucket records that a rule is *ratified*, not that the C++ *implements* it. CEN-L11 is bucket-1 ratified with an implementation that silently omits an accepted output, so the bucket-only rule would have scored redb reproducing that defect as a **correctness match**. Oracle status now requires ratification **and** an **affirmative** conformance record; **CSR-3a** opens the register, seeded with CEN-L11 and explicitly not proven complete. **Corrected again the same day:** the condition was first written negatively (*no recorded divergence*), which is fail-open against an incomplete register — absence means unreviewed, not conformant. Three states now (CHECKED-CONFORMANT / DIVERGENT / UNREVIEWED), default regression-only, and the checked set is currently **empty** pending DRS-P0d *(as written that day; the producer was corrected P0d→P0f and P0f has since completed row coverage over the 102 rows then in bucket 1/2 — 99/1/2 after the 2026-09-04 L11/L12 promotion, see the P0f rows above)* | §5.4, §5.4.1 |
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
