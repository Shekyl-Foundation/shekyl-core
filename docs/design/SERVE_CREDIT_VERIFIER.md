# The serve-credit verifier hole (CEN-J8, J9, J10) — Round 0 (`SCV-`)

**Status: ROUND 0 — OPEN; six questions POSED (§8), none ruled.** Written
2026-10-02 at `dev@d0bcc0c5e`. Pre-flight under
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
**no implementation commit cuts against this document until §8 is ruled**
(rule 26's halt condition). Identifier families **`SCV-`** (findings) and
**`SCV-Q`** (questions) are registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 (rule 94;
`check_index_prefix_uniqueness.py --prefix` returned DISTINCT, clear of
the 111 registered families).

**The short version.** The brief asked how to build CEN-J8–J10 in Rust from
`PDM-Q6` item 4's re-keyed preimage. The answer is that J8–J10, as censused,
describe a mechanism that is **retired by ruling**: the beacon fire schedule,
the sampled leaf, and the leaf-path proof. Their successor is not a
re-keyed version of the same vin. It is **`SO-D8`'s shape R-B**: the record
names its issuing block `h`, membership is `(P, s) ∈ assignment(h)`, the
deadline is `W₂`, and the witness authenticates against `h`'s coinbase. `P`'s
countersignature is the landed `SF-D8` transcript, with no shard bounds in
it. That successor is already specified in full as
[`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§8 ("Slice C"). Slice C is **not authorized**. Its second precondition
waits on a lane that scoped the same work out as waiting on Slice C, and
that lane has now closed. The central finding is that circular,
ownerless deferral (`SCV-1`). The central question is who owns Slice C
and whether to authorize it (`SCV-Q3`).

---

## 0. Ground — which tree each citation resolves in

Read at **`dev@d0bcc0c5e`** in a fresh worktree. Every line cite below is at
that pin unless it is marked **[PR-b]**.

**[PR-b]** means `origin/feat/drs-e4-commit6-digest@583214b5f`. That branch
is DRS-E4's PR-b: **22 commits not on `dev`, and no open pull request** at
the time of writing (`gh pr list --state all --search head:…` returns
nothing). The brief was written as if PR-b were `dev`. The following
resolve **only** on PR-b:

- `DEL-008` (`DAEMON_REDB_STORE.md:2670`);
- `scripts/ci/check_inland_height_u64.py` and its ceiling of 170;
- the deletion of `serve_credit_decisions.rs`, its equivalence KAT, fixture,
  C++ leg and both fuzz targets (commit 10d, `583214b5f`);
- the FOLLOWUPS row *"Serve-credit acceptance (CEN-J8–J10) has no Rust rule"*;
- `DRS_E4_ARCHIVAL_WRITER.md` closed as record under `docs/completed/`;
- `DRS_E4_SLASH_LOG_ROUND.md` (`SLK-Q1`, `SLK-Q2`).

On `dev` at this pin, the mirror **still exists**, and so does a production
caller of it (`SCV-9`).

`SlashLogKey { height: BlockHeight, seq }` is on both trees (`ids.rs:507` on
`dev`, `:519` on PR-b). `CONSENSUS_STORE_RECONCILIATION.md:496–498` grades
J8–J10 on `dev`; PR-b shifts those rows by one line.

**Consequence for sequencing.** Every implementation row in §6 cuts on a
tree that contains PR-b, either after it merges or on top of it. Nothing
here edits PR-b's files. The findings addressed to that lane (`SCV-10`) are
recorded here for it to act on.

---

## 1. What runs today, measured

| Validator | What a serve-credit vin faces | Where |
| --- | --- | --- |
| Rust (`shekyl-chain-rules`) | H20 shape; G7 block-level `(P, shard, E)` uniqueness; L7 "the persona has a record"; then it is recorded | `rules/tx.rs:543–556`; `rules/body.rs:286–311`; `archival/inputs.rs:40–58` |
| C++ (`blockchain.cpp`) | parse, size, pair-epoch dedup (J3), record (J4), `E_first` (J5), `good_through` (J6), `h_close` and seal-on-chain (J7), held at `H_fire` (J8), segment at `H_fire`, derived leaf index (J9), chunk bounds, chunk read, FFI verify (J10) | `check_archival_serve_credit_input`, `:4751–4968` |

CEN-I18's vacuity on the credit form is correct, as the brief says
(`tx_against_tests.rs:668`). `census.rs:492–494` lists J8–J10 as `pending`,
alongside all twenty-six 4.J rows.

**The live gate's freeze dependency is not where the brief placed it.**
The gate reads the frozen-segment registry directly:
`get_archival_shard_segment_at_height`, `:4886` →
`db_lmdb.cpp:5090–5111`, which is LMDB table `archival_shard_segment`. It
then reads the leaf chunk with `get_curve_tree_leaf_chunk` (`:4933`). It
never calls `shekyl_archival_frozen_segment_count`. `blockchain.cpp:1504` is
`parent_frozen_segment_count`, which is CEN-F17's D2 escalation operand: a
different consumer, ruled divergent under CEN-L10. The gate depends on the
freeze only through the table the freeze writer fills (`db_lmdb.cpp:7419`).
See `SCV-7`.

---

## 2. The brief's §7, answered

### 2.1 The current bounds expression

**Shard `k` holds the transactions whose cumulative archival length *before*
them lies in `[k·W, (k+1)·W)`** (`SHT-Q2`, RULED 2026-09-29). The sources:

- `shekyl_types::shard_of(cum_before) = ⌊cum_before / W⌋` and `shard_start(k) = k·W`
  (`shekyl-types/src/archival/mod.rs:134`, `:142`);
- `W = SHARD_LENGTH = 3,000,000` bytes, PROVISIONAL, with one home
  (`:128`, from `config/consensus_constants.json`
  `archival_shard_length_bytes`);
- the operand is `block_info.cumulative_archival_len`, read through
  `closed_shards_through` / `closed_shards_before`
  (`shekyl-chain-rules/src/rules/miner.rs:564`).

`PDM-Q6` item 4's `(k·T, (k+1)·T)` is superseded. The PDM file has not
re-keyed its own rows 1, 3, 4 and 6 (`ARCHIVAL_PRUNED_DAEMON_MODE.md:850–856`
still say `T`). Only `DRS_E4_ARCHIVAL_WRITER.md:89–91` states the `W` form.

*Hazard, so nobody trips on it:* the letter `W` also names
`MAX_CLAIM_AGE_W_EPOCHS = 26`, a count of epochs (`archival/mod.rs`, just
below), and `W₂` (`CHALLENGE_RESPONSE_BLOCKS`). The PDM banner says this
outright. Any successor code writes `SHARD_LENGTH`, never `W`.

**Under the successor, the bounds are not a signed term** (§2.2). They are
the witness's off-chain membership check
(`ARCHIVAL_CHALLENGE_MECHANISM.md:160–169`, step 2: each transaction is
verified against the two hash rows and placed in the shard). They enter
consensus only through closure: bond admission's closed-shard predicate
(`SCV-6`) and `closed_shards_through`.

### 2.2 The successor preimage — what is signed, what the verifier derives

The successor admission rule is `SO-D8` shape R-B
(`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §2.1 item 3, `:561`, and §8's
admission row). R-B was ruled 2026-09-13. SO-D8a–e and Q15 were ruled
2026-09-16. It authenticates a record with **two** signatures. **Neither
signature contains the shard's bounds.**

| Signature | Signer | Message | Domain | Verifier's derived terms |
| --- | --- | --- | --- | --- |
| `P`'s countersignature (`SF-D8`, LANDED 2026-09-13 (a0)) | `P`, at read time, without knowing the read is a challenge (`RF-D8` (i) retraction) | `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]`, 80 B | `SCHEME_DOMAIN_ATTESTATION` (`shekyl/archival-attestation-scheme-v2`) | `anchor_hash` comes from the **connecting** chain at the carried `anchor_height`, which must lie in `[h − 720 − L, h − 720]`; `p_id` is recomputed from the bond's committed hybrid key |
| The witness's signature (Q8, Q9, Q12, Q13 RULED) | The producer of block `h`, from a non-output key derived from coinbase output 0's `combined_ss` | `cSHAKE256_32` over the carrier's length-framed records in vin order. **Bytes PROPOSED, not ruled** (§7.6.1) | `shekyl/archival-witness-key-v1` for the `0x0C` commitment; the set-commitment customization is PROPOSED | The witness pk's hash must equal `h`'s coinbase `0x0C` field; membership is `(P, s) ∈ assignment(h)`, derived from `block_hash(h − 1)` over `D` at `h_open(E)`; the deadline is `h_incl − W₂ ≤ h < h_incl`; `E = epoch(h)` (SO-D9 (i)); dedup is `(P, s, E, h)` |

The record carries `(P, s, E, h)` on the kept side, along with the Ed25519
leg. It carries `nonce` and `anchor_height` in the prunable entry (the RF
post-close note, `ARCHIVAL_RESPONSE_FORMAT.md:6–35`). The verifier
**derives** `anchor_hash`, `assignment(h)`, `epoch(h)`, and the expected
witness commitment. It is **never told** any of them. That is the
discipline `wire.rs:349–360` states, carried over intact.

**One owner of the countersignature check.** The check is
`attestation_wire::verify_pass_countersignature` (`:371`), which calls
`verify_pass_transcript` (`:408`). The B4 FFI calls it
(`archival_ffi/attestation.rs:316`), and so does the fetch client
(`p-fetch/src/client.rs:288`). An R-B rule calls the same function. No
second derivation exists or is needed.

**`PDM-Q6` item 4 row 1's "signs `shard_id` and `(k·T, (k+1)·T)`" is not
reconciled with any of this.** Row 1 was written on 2026-09-18 against
`wire.rs`'s vin preimage. It never names `SF-D8`, which had landed five
days earlier, and its own `SF-D8` row says that countersignature is
"unchanged". Under `SHT-Q2`, `(k·W, (k+1)·W)` is a constant function of the
already-signed `shard_id`, so signing it binds nothing. The term was
non-vacuous only under F32's chain-derived `(b_k, b_{k+1})`, which item 5
retired on 2026-09-23. That is `SCV-2`, and `SCV-Q2` asks whether to strike
it.

**No byte layout for the R-B record is written in one place.** `SO-D8`
§2.1 item 1 names the kept ceiling (`117 → 127`) and says "the RF round
reopens". `ARCHIVAL_RESPONSE_FORMAT.md` carries no such reopen: it has no
`SO-D8`, `R-B`, `PDM` or `SHT` text. This round does not invent the layout
(`SCV-3`).

### 2.3 The freeze-dependent clauses

- **J9 dies whole.** Its three operands (the derived leaf index, the chunk
  bounds, the leaf-chunk read) and `PC-D3`'s prev-hash binding are on the
  deletion surface that `RF-D8` (i)'s retraction confirmed
  (`ARCHIVAL_CREDIT_WIRE.md:57–104`; `ARCHIVAL_RESPONSE_FORMAT.md:1008–1013`).
  The reason is that `P` cannot countersign a preimage that names the
  challenged leaf without learning which request is the challenge. Under
  the tx unit there is no leaf to sample at all
  (`ARCHIVAL_PRUNED_DAEMON_MODE.md:851`, row 2). `PC-D3`'s job was closing
  TJ-1's leaf-index beacon (FOLLOWUPS `:270`). That job leaves with the
  index. Its block binding is replaced by `h`.
- **J8's second clause ("the shard's frozen segment must exist at
  `H_fire`") dies with the freeze** (`PDM-Q12`). Its job was "the shard is
  a real, finished unit", and that job is carried by bond admission's
  closed-and-final shard predicate. That predicate is **RULED and unbuilt**,
  and its blocker dissolved by ruling (`SCV-6`). Membership in `D` covers
  the rest: a pair is drawable only if it holds its shard at `h_open(E)`.
  The Rust store has no frozen-segment registry to read
  (`get_archival_shard_segment_at_height` is dead under `SAR-5`). So a
  literal port of this clause is **unbuildable**, not merely undesirable.
- **J8's first clause ("`P` holds the shard at `H_fire`") leaves admission
  and moves to settlement.** Under R-B the fire path is deleted from
  admission (SO-D8 §8, "Deleted"). The holding question is asked by the
  settlement writer, per drawn pair, at the draw's height ("not held ⇒ write
  no row", SO-D8 Q3 (3.3), `:1347`), and by slash eligibility
  (`archival/slash.rs:202–235`, which already derives `H_fire` and calls
  `holds_shard_at` in Rust).
  - This answers **`ARW-Q2`'s open half**
    (`DRS_E4_ARCHIVAL_WRITER.md` §3.3): an as-of-height holdings consumer
    does survive, so the slash log stays history.
  - It also changes **`SLK-Q1`'s premise** [PR-b]. That premise is "the
    fold is asked at `h_fire ∈ (H_seal, H_close]`"; under R-B it becomes
    the draw height. This round flags the change to that round and does
    not rule it (`SCV-8`).

### 2.4 The signing side's scope

**There is no production signer of a serve credit today.** The brief's
premise that "the wallet signs the retired terms today" is false at this
pin:

- `scenario_archival.rs:24–30` says so directly.
- The only `SCHEME_DOMAIN_SERVE_CREDIT` signatures are made by KAT tests
  (`tests/gate2_serve_credit_kat.rs`) and `wire.rs`'s own `#[cfg(test)]`
  helper.
- Every fixture credit carries a `[0x5c; 64]` marker.
- The Rust validator verifies nothing.

The successor's signers are on **daemon and archiver surfaces, not the
wallet's**:

- `P`'s countersign is `p-serve::countersign::sign_pass_transcript`
  (`:141`), which is **landed**. Its production key is unwired:
  `PassKey` is `NoResidentKey`, which always refuses
  (`p-host/src/signer.rs:68`).
- The witness signer is unbuilt. It is the Rust miner-tx constructor's job
  (Q8: `derive_witness_keypair`, the `0x0C` field, the memory-only seed ring
  of Q10).
- The carrier builder is unbuilt. It assembles `serve_credit_only` carriers
  of at most 42 records, fail-whole, with resubmission inside `W₂` (Q9).

The verifier and its signers therefore change together, as the brief
expected. "Together" means the Slice C unit, not a wallet change.

### 2.5 The C++'s disposition — already ruled

The brief calls this a new question. **It is ruled three times over:**

1. **`PDM-Q3`** (2026-09-18, `ARCHIVAL_PRUNED_DAEMON_MODE.md:377–400`) rules
   that the C++ verifier's leaf read is "the one residual consensus reader"
   and that it "dies at E4 / S-ARCH". The ruling's falsifier is "the C++
   leaf read still live after E4's verifier lands".
2. **`SO-D8` Q15** (2026-09-16, `§8` `:2221–2229`): "The LMDB daemon keeps
   today's beacon / `h_close` / seal gates until `shekyl-chain-rules` is the
   live validator". There is also an explicit **prohibition** on repairing
   anything in `blockchain.cpp` (FOLLOWUPS `:229`).
3. **`DEL-008`** [PR-b]: the gate and its FFI delete at the cutover.

The C++ keeps running unchanged and is deleted at the cutover. It is the
divergent validator by design, the same way CEN-L10 is. Divergence
on real chains is nil, because no chain carries a vin credit the C++
could have accepted from a real signer (`ARW-13`).

**The one gap left: `DEL-008`'s trigger has no conjunct requiring the
successor's Rust rows to exist.** The trigger is "the Rust daemon is
consensus". If that fires before Slice C lands, the cutover deletes the
only gate and opens the hole on the live chain. See `SCV-Q5`.

### 2.6 The commit table

See §6. It covers this round's own post-ruling work. Slice C's plan is
SO-D8 §8, which this document cites rather than duplicates.

---

## 3. Old rows to successor rows

| Censused row | Mechanism it encodes | Successor (SO-D8 R-B, §8 admission row) | Disposition |
| --- | --- | --- | --- |
| CEN-J3 pair-epoch dedup | one beacon challenge per pair-epoch | `(P, s, E, h)` exact-get; `h` is in the past and in the DB | superseded by ruling (SO-D8b) |
| CEN-J7 `≤ H_close`, seal on chain | the beacon window | `h_incl − W₂ ≤ h < h_incl`; `block_at(h)` exists | superseded (SO-D8a) |
| CEN-J8 held at `H_fire`; frozen segment exists | the fire schedule; the freeze | membership `(P, s) ∈ assignment(h)`; holding moves to settlement (3.3); closure moves to bond admission | superseded / moved (§2.3) |
| CEN-J9 derived leaf index, chunk read, `PC-D3` | the sampled leaf | — | deleted by ruling (`RF-D8` (i) retraction) |
| CEN-J10 response verifies (path, countersignature) | the leaf path plus the leaf preimage | `SF-D8` countersignature + witness authentication + `0x0C` content | superseded (SF-D8, Q8/Q12/Q13) |
| *(new)* SO-D9 (i) | — | `epoch(h) = E` at the operand `h` | ruled, lands as a new row |

The new `CEN-` ids are minted at Slice C (SO-D8 §8). This round mints none.
The **validation surface is one** (rule 19): J3, J7, J8, J9 and J10 change
together with J1/J2's wire (the `h` field, rule 42). Slice 8 cannot land
J8–J10 as a unit separate from that surface.

---

## 4. The interim — what the Rust validator does until Slice C

Today the Rust validator admits any well-formed credit from a persona that
has a record. Nothing in Rust signs a real credit, and nothing in Rust
verifies one. There are three candidate interims; `SCV-Q1` rules among
them.

- **(a) Fail closed — default.** A single row refuses every serve-credit
  vin with a typed `InvalidBlock`. Its reopening criterion (rule 21) is
  Slice C's rows landing, and its falsifier is a vin-borne credit admitted
  while that row exists. The case for it:
  - Mission 1 binds: an admission hole in the consensus validator is a
    security defect, not a feature gap.
  - Rule 21's shape is reject-now-with-reopening over pre-provisioned
    acceptance.
  - No production signer exists (§2.4).
  - No captured chain carries a vin credit (`ARW-13`). `emission-claim`'s
    credit is the injector's row, not a vin, so E2's digest parity is
    unaffected.

  **What it costs, priced.** Nine test call sites mine or build a
  vin credit through `validate → connect`. Those are
  `shekyl-chain-ingest/src/scenario_archival_tests.rs` ("the next block's
  credit connects", which is the writer's credit-arm witness) and
  `shekyl-chain-store` `connect_fixtures::credited` and its callers.
  - Their subject is the **writer's** credit row, so rule 50 lets the
    fixture be constructed through a production path.
  - The production path that still writes a credit row is the injector
    door: `ChainStore::regtest_inject_serve_credit`, under
    `Trust::UNANCHORED`, unjournaled (`archival_write.rs:470–504`).
  - The witness therefore splits in two:
    1. the mined vin becomes a **typed-refusal** assertion, the row's own
       negative fixture;
    2. the writer's row and `pop` behaviour are witnessed through the
       injector.
  - The second witness is weaker on one axis: the injector is
    unjournaled, so `pop` cannot lift its row. The pop-lifts-the-credit
    case needs a journaled door or waits for Slice C. That is a disclosed
    gap, not a silent one.
- **(b) Keep admitting, documented.** This is today's state. It is
  honest only if the Rust validator never becomes consensus first. `SCV-Q5`
  makes that a gate, so (b) is (a)'s risk moved into `DEL-008`.
- **(c) Port J8's first clause now**, as an `H_fire` holding check in Rust
  symmetric with `slash.rs`. **Rejected as the default.** It builds code
  Slice C deletes (the fire path), and it closes nothing that matters: a
  persona holding a shard can still credit itself without serving, because
  J10 is the teeth.

---

## 5. Findings

| ID | Finding | Ground | Addressed to |
| --- | --- | --- | --- |
| **SCV-1** | **The successor's authorization waits in a circle, and the lane on the circle has closed.** (1) SO-D8 §8 precondition 2 (`:2272–2286`): membership against `assignment(h)` and dedup `(P,s,E,h)` "wait here, with the writer call site", and the falsifier is "a production caller of the settlement write on the Rust apply/slash path". (2) DRS-E4 §2.2 (`DRS_E4_ARCHIVAL_WRITER.md:316`; `:337` [PR-b]) scopes "the settlement writer … out: blocked on the per-challenge admission cutover". (3) `ARCHIVAL_SETTLEMENT_WRITER.md` §5.1 (`:324`) says the writer "cannot be live before the cutover". Each document hands the unit to the other, and DRS-E4 is closed as record [PR-b]. No open lane can fire precondition 2's falsifier. This is a deferral whose blocker is a deferral (rule 22's new section [PR-b]), and it now has no owner. The same event goes by four names: "the cutover", "the assignment cutover", "the per-challenge admission cutover", "E4 / S-ARCH". | the three cites | maintainer — `SCV-Q3` |
| **SCV-2** | `PDM-Q6` item 4 row 1's signed bounds term is unreconciled with `SF-D8`, and under `SHT-Q2` it binds nothing (§2.2). Three places carry it forward as the successor: the C++ comment PR-b wrote (`blockchain.cpp` above `check_archival_serve_credit_input` [PR-b]), PR-b's FOLLOWUPS row, and the brief. | PDM `:794–797`, `:850`; `ARCHIVAL_SHARD_FETCH.md` `SF-D8`; `shard_of` | maintainer — `SCV-Q2` |
| **SCV-3** | No single document states the R-B record's layout. SO-D8 §2.1 item 1 says "the RF round reopens" (`h` on the kept side, rule 42), but `ARCHIVAL_RESPONSE_FORMAT.md` records no reopen. The `PDM-Q6` item-4 rule ("reopenings get a dated sub-section in the owning doc") is unmet in RF, CREDIT_WIRE and PER_CHALLENGE_RECORD. A grep for `PDM`, `SHT`, `tx_id` and "tx unit" returns zero hits in each. So item 4's own reversion falsifier ("the owning doc's dated sub-section cites no leaf-specific premise") cannot be evaluated. | PDM `:843–845`, `:866–868`; RF banner | Slice C's precondition (§6 sizing) |
| **SCV-4** | **The pass record has two ruled carriers.** CEN-B4 verifies `SF-D8` countersignatures in the block's attestation witness, recomputed against the header's `attestation_root` (census `:338`; `ARCHIVAL_CREDIT_WIRE.md` §3 shape 4; landed C++ `verify_block_attestation`). SO-D8 Q9 (§7.6, RULED 2026-09-16) puts records in ordinary `serve_credit_only` transactions, "never the coinbase", with residence per `RF-D10`. Both verify through the same function (§2.2), so the verify code is one. The **carrier** is two. | census B4; SO-D8 §2.1 item 8; `SETTLEMENT_WRITER.md:651–654` | maintainer — `SCV-Q4` |
| **SCV-5** | SO-D9's sentence that "(i) on the R-A operand flips exactly one block per epoch" is not true at this pin. J7's window is `h_seal(E) < h ≤ last_block(E)`, with `h_seal = E·SEB + 1` (`constants.rs:78`) and `last_block = (E+1)·SEB − 1` (`settlement_schedule.rs:171`; the rename at `9ca950f4a` was value-preserving). Every admissible slot is therefore inside epoch `E`, and (i) evaluated at the connecting height is implied by J7 and cannot fail on its own. **Moot**, because (i) lands on R-B's operand `h`, where it is independent. This is recorded so that nobody writes a `CenRow` at the R-A operand whose negative fixture J7 refuses first. | FOLLOWUPS `:229`; SO-D8 `:2310` | Slice C (the SO-D9 row's fixture) |
| **SCV-6** | The bond-admission closed-and-final shard predicate, which now carries J8's "the shard exists" job, is RULED and unbuilt. Its FOLLOWUPS row says it is "gated on the A4 length rows (S-CHAIN-W) and S-PRUNE deriving `b_*`". Both gates dissolved by ruling: `PDM-Q6` item 5 says "A4 is not owed" (2026-09-23), and `SHT-Q2` retired `b_*` for `shard_of(cumulative_archival_len)`, which `closed_shards_through` reads today. A fired condition read as pending. | FOLLOWUPS `:209`; PDM `:975` | slice 8 (a 4.J bond row) |
| **SCV-7** | The brief's account of how the C++ gate depends on the freeze has three errors. (1) It cites `blockchain.cpp:1504`, which is CEN-F17's operand; the gate reads LMDB `archival_shard_segment` (`db_lmdb.cpp:5090`). (2) It says the verifier "supplies [the terms] from `LeafStore::frozen_segment`". That echoes `wire.rs:352`'s table, which is wrong about the live verifier: `LeafStore::frozen_segment` (`shekyl-curve-tree/src/store/redb_backend.rs:2189`) has no consensus caller, only a bench and a test. (3) It calls the C++ disposition unruled (§2.5). Recorded under rule 16's corollary: a grouping someone else drew is a claim about its members. | §1, §2.5 | this round (corrected here); `wire.rs:352` dies with the preimage at Slice C |
| **SCV-8** | Under R-B, `SLK-Q1`'s premise that the fold is asked at `h_fire ∈ (H_seal, H_close]` changes to the draw height. The horizon arithmetic re-derives from that, not from `H_close`. | [PR-b] `DRS_E4_SLASH_LOG_ROUND.md` §2 | the `SLK-` round |
| **SCV-9** | On `dev`, the deleted-on-PR-b mirror **had** a production caller. The Rust validator's G7 calls `serve_credit_decisions::serve_credit_block_unique` (`rules/body.rs:307`). The brief's "zero production callers" was true of D-SC-A/B (the gate mirror) and false of D-SC-C. Commit 10d handled it (G7 re-homed to `second_occurrence` [PR-b]), so this is not a defect in PR-b. It is a precision note on a claim that will otherwise be cited as precedent. | `body.rs:307`; `583214b5f` | record |
| **SCV-10** | PR-b's FOLLOWUPS row has two problems. (a) It is **duplicated**: lines 17 and 18 are byte-identical. (b) It labels the rows "J8 (seal on chain), J9 (fire-height schedule) and J10 (the leaf-preimage signature)". The census defines seal-on-chain as **J7**, J8 as holding at `H_fire`, J9 as the derived leaf index, and J10 as the response verify (`CONSENSUS_RULE_CENSUS.md:490–493`). | [PR-b] `docs/FOLLOWUPS.md:17–18` | PR-b's lane (not edited here) |
| **SCV-11** | Leaf-unit and `T`-era text is still stated as current in the docs Slice C reads first. The grep surface is `rg -n 'LeafStore::frozen_segment\|segment_subroot_rk\|\(b_k, b_\{k\+1\}\)\|k·T' docs/design`. Owners: RF (`:501–556`, `:579–585`), PER_CHALLENGE_RECORD (`:175–181`), CREDIT_WIRE (`:59–64`; its banner still says "Round opened … No wire byte-layout is pinned yet" against its own `:342` "RESOLVED"), CHALLENGE_MECHANISM (`:108–114`, `:163`), and PDM item 4 (`:850–856`, `T`). Separately, five documents attribute "the test IS a read" to `ARCHIVAL_CHALLENGE_MECHANISM.md` §9. It is `ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §9 (`:988`). | the grep | each owning doc; **not this PR** (rule 26: not a redesign) |

---

## 6. Commit sequence and the expectation, written before the work

These are this round's own rows **after §8 is ruled**. They are not Slice
C's; SO-D8 §8 is Slice C's plan.

| # | Commit | Cost | What would make it larger |
| --- | --- | --- | --- |
| 1 | **This document** and the index rows (`SCV-`, `SCV-Q`, the §7 doc row). FOLLOWUPS is not touched here: the J8–J10 row lives on PR-b, and its re-key is commit 5 | S | — |
| 2 | **Census dispositions** (`SCV-Q6`): J3, J7, J8, J9 and J10 marked superseded-by-ruling with a pointer to SO-D8 §8; `census.rs` statuses only if the ruling changes them (the enum may have no "superseded" arm, and adding one is a census-crate change) | S–M | `RowStatus` lacking an arm for a row retired by ruling |
| 3 | **The interim row** (`SCV-Q1` (a)): one `CenRow` refusing every serve-credit vin, with its negative fixture on a driven chain; the nine credit-mining sites moved to a typed-refusal assertion plus the injector door; the pop-lifts-credit gap disclosed | M | a test whose real subject is the credit's *admission* rather than the writer's row, which would have no honest home until Slice C |
| 4 | **`DEL-008`'s conjunct** (`SCV-Q5`), on PR-b's tree or after it merges | S | — |
| 5 | **Docs** (rule 91): line-local pointers in `PDM-Q6` item 4 rows 1, 3 and 4 (the `W` re-key and `SCV-Q2`'s ruling), SLK §2 (`SCV-8`), FOLLOWUPS `:209` (`SCV-6`'s fired blocker), FOLLOWUPS `:229` (`SCV-5`) | S | — |

**Expectation: five commits.** **The signal:** more than **seven** means
the substrate was not what this document claims. The most likely cause is
commit 3 finding a test whose subject is the admission itself. The estimate
and the signal are recorded separately at close, as slice 7 did
(`CHAIN_RULES_SLICE_7.md` §5.1).

**Slice C, sized for the maintainer (not a plan).** SO-D8 §8 is the plan.
What it needs before it can cut:

1. the circle in `SCV-1` broken: one owner for admission rows plus the writer call site;
2. Q9's set-commitment bytes ruled (§7.6.1, PROPOSED);
3. the R-B record layout written once (`SCV-3`, the RF reopen with its rule-42 bump);
4. `SCV-4`'s carrier ruled;
5. the bond-admission shard predicate (`SCV-6`) built or ruled independent.

Its evidence plan lists **twenty** numbered items (§8 "Evidence plan").
Its surface spans four crates:

- `shekyl-chain-rules`: the rows, the `DrawableSet`, the cache;
- `shekyl-archival-retention`: the urn feed and the settle fold;
- `shekyl-crypto-pq`: the witness derivation, with a registry row and the
  census pin moving `30 → 31`;
- `shekyl-block-template`: the `0x0C` writer and the seed ring.

Add the carrier builder and the persisted `D` digest's schema snapshot. By
the slice-7 yardstick (fifteen estimated, eighteen landed), Slice C is
**two to three increments**, not one PR. That figure is a reading of
SO-D8's own tables, not a measurement.

---

## 7. What this round did not find, and what it did not examine

**Examined at source:** the C++ gate end to end (`:4751–4968`) and its call
site (`:3615–3672`); the FFI verify's order (`serve_credit.rs:112–273`);
`wire.rs`'s preimage; `challenge.rs`'s seal, fire and leaf derivations;
`challenge_assignment.rs`'s status; `held_at_height.rs`; `slash.rs`'s
`H_fire` read; the Rust G7, L7 and H20 sites; `attestation_wire`'s two
verifiers; `p-serve`'s signer; the signer search across `rust/` and `src/`;
`PDM-Q3`, Q6 items 4–5 and Q12; `ARCHIVAL_CHALLENGE_MECHANISM.md` §2;
`ARCHIVAL_CREDIT_WIRE.md` §1–§2; SO-D8 §2.1, §7.4 and §8; RF's banner and
`RF-D8` (i); DRS-E4 §0, §2 and §3.9; DEL-008 [PR-b]; SLK §2 [PR-b]; the
FOLLOWUPS rows named in §5.

**Not examined, and nothing above should be read as covering them:**
`ARCHIVAL_SHARD_FETCH.md` past its SF-D8 row; SO-D8 §6 and §7.2's
integrity layers and cache (Slice C's internals); the emission-claim side
of 4.J (J19–J26); bond-post rows J11–J18 beyond `SCV-6`; the economics of
unpaid inclusion (FOLLOWUPS `:231`).

**No test was run.** This is a documentation round, and none of its claims
is a measurement. Rule 26's artifact execution applies to Slice C's
pre-flight, not here.

---

## 8. Questions for the maintainer (`SCV-Q`), each with a default

- **`SCV-Q1` — the interim.** *Default (a):* fail closed (§4). The Rust
  validator refuses every serve-credit vin with a typed row until Slice C's
  rows land. The cost is priced in §4. *Alternatives:* (b) keep admitting
  and rely on `SCV-Q5`; (c) port J8's first clause (rejected in §4).
- **`SCV-Q2` — `PDM-Q6` item 4 row 1's bounds term.** *Default:* **struck.**
  The successor's `P`-signed message is `SF-D8`'s as landed. A constant
  function of an already-signed `shard_id` binds nothing, and re-keying the
  landed signer and verifier to add it buys nothing (rule 05). PDM row 1
  gets a line-local edit pointing here (rule 23). *Alternative:* sign the
  chain-derived **tx-id range** of shard `k`, which is non-vacuous. This is
  rejected as the default because the witness already checks membership
  off-chain, and `P`'s view of the range adds no consensus evidence.
- **`SCV-Q3` — who owns Slice C, and whether it is authorized.** *Default:*
  Slice C is **one unit**: the admission rows plus the settlement writer's
  Rust call site, which `SCV-1` shows each document assigning to the other.
  It is owned by E6 slice 8, the lane the census already gives 4.J. Its
  authorization is gated on items 2–5 of §6's sizing paragraph, not on a
  falsifier that no lane will fire. *Alternative:* a named successor round
  (an `SO-` continuation) that owns it, with slice 8 consuming its rows.
- **`SCV-Q4` — the carrier.** *Default:* SO-D8 Q9's `serve_credit_only`
  carrier. It is later (2026-09-16 against 2026-08-03), more specific
  (batching, fail-whole, the weight split), and `RF-D10`'s residence is
  landed. CEN-B4's attestation-witness arm is B4's owner's to re-key. B4's
  empty-root slice is the only one exercised today, so nothing live moves.
  *Alternative:* the attestation witness as the carrier, which would make
  SO-D8 §2.1 item 8's weight arithmetic moot.
- **`SCV-Q5` — `DEL-008`'s trigger.** *Default:* add the conjunct "and
  `census.rs` lists the Slice C admission rows as `implemented`". The
  falsifier is a cutover PR that deletes `check_archival_serve_credit_input`
  while those rows are `pending`. Without the conjunct, the cutover is the
  event that opens the hole on the live chain.
- **`SCV-Q6` — the census rows.** *Default:* J3, J7, J8, J9 and J10 are
  marked **superseded by ruling** in `CONSENSUS_RULE_CENSUS.md`, with a
  pointer to SO-D8 §8 and to this file (rule 23's grep surface). J9 is
  marked **deleted by ruling**. No new `CEN-` ids are minted here; Slice C
  mints them (SO-D8 §8). PR-b's FOLLOWUPS row (falsifier: J8–J10 reading
  other than `pending`) is re-keyed to the successor rows' ids when they
  exist.

---

## 9. Documentation owed (rule 91)

When §8 is ruled, the owed edits are §6's commit 5 rows, plus:

- `IMPLEMENTATION_INDEX.md` §7's row for this document;
- the census pointer (`SCV-Q6`);
- the FOLLOWUPS J8–J10 row's re-key (on PR-b's tree), naming this document
  as the round that answered the "how".

This document then archives to `docs/completed/` when Slice C opens its own
pre-flight or rules this round's questions in place.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-02 | **Round 0 executed at `dev@d0bcc0c5e`.** Families `SCV-` / `SCV-Q` registered at birth. Eleven findings and six questions posed, none ruled. The brief's chain (PDM-Q6 item 4 → SHT-Q2 → slice 8) is replaced by its real one: SO-D8 R-B ← {Q9 bytes, the R-B record layout, the carrier, the bond shard predicate, an owner for the writer call site}. The brief's `dev` premises that resolve only on DRS-E4 PR-b are marked [PR-b] throughout. |
