# The per-challenge pass record — design round (PC)

**Status:** **RULED 2026-08-24**, opened and ruled in the same sitting because
the ruling was made on the record before the round existed and this document is
its transcription. `PC-D1`…`PC-D7` ruled; implementation lands in this round's
PR, not a later one.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
and **[`07-consensus-atomic-cutovers`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
is opted into**: this changes an admission path in place, on a genesis-frozen
wire. Disposition IDs **`PC-D1` … `PC-Dn`**, registered at birth per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc); prefix `PC-`
checked unique against CB/CR/CT/CW/DS/GF/LV/MR/MS/MSW/OA/PF/PR/RF/RP/SA/SH/SO/
SP/TJ/VG/WI/WP/WS.

**Freezes:** the serve-credit vin layout, the leaf-index derivation, and the
admission uniqueness key. All three are pre-genesis-frozen; a wrong byte is
permanent. This is the design-first category by the standing rule, which is why
it is a round rather than a commit.

---

## 1. The finding, and why a counter cannot answer it

2-of-3 settlement needs consensus to know how many of a pair's three challenges
passed. The reflex is a count on the record.

**A count on the record is forgery.** Whoever writes the record chooses the
number: write `3`, settle `Served`, with one read performed or none. That is
`RF-D8`'s criterion word for word — *a value the verifier derives locally must
not be transported, because transporting it lets the prover choose it* — and it
is the identical defect as a supplied `R_k` or a supplied leaf index, which
`RF-D6`/`RF-D8` already refused on exactly these grounds. It is refused here on
the same grounds. **No tally field, ever.**

**But the count was never supposed to be on the record.** Three challenges are
three separate events in three separate blocks, each already in the attestation
path, each nonce-bound to its own block. Consensus counts them by **enumerating
the blocks of the epoch and counting the attestations it finds** — which is what
`SO-D1`'s enumerate-and-write writer already does. Nobody writes a number; the
chain is the number.

That is unforgeable in a way no field can be: to claim three passes you must
produce three blocks each carrying a witness-signed attestation naming you, and
each of those signatures binds to a block you do not control.

### 1.1 The consequence that reverses the record's granularity

If the count cannot be a field, then **the record cannot be per-epoch** — because
"per-epoch" means one artifact standing for three events, and the only way to
express three-in-one is the count just refused. So the record is **per-challenge**.

---

## 2. Verified at source: the current wire cannot express this at all

Grounded on `dev@863a9bf4f`, 2026-08-24.

**The record has no block.** `ArchivalServeCreditResponse` is
`{p_canonical_id, shard_id, settlement_epoch, ed25519_countersignature}`
(`ArchivalServeCreditResponse`). It is structurally keyed per-`(P, s, E)`. There is no way to
represent two distinct challenges for one pair-epoch, and the old-vin dedup
(`has_archival_serve_credit_bit`, in `check_archival_serve_credit_input`)
would reject the second as a duplicate of the first.

**The leaf index cannot vary per challenge.** `challenge_leaf_index`'s preimage
was `p_id ‖ shard_id_le ‖ settlement_epoch_le` (`challenge_leaf_index`, before
this round). For a given
`(P, s, E)` the index is a **constant**.

### 2.1 The asymmetry that makes this easy to miss

`RF-D5` already made the attestation nonce
`H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)` — **block-bound**. The opening is
not.

So three per-challenge records under today's derivation would carry three
**genuinely distinct countersignatures** and three **identical openings**. The
signatures would look like three events; the work would be one. A prover that
fetched one leaf once satisfies all three, and every signature verifies.

That is worse than "proves nothing per-challenge": **it is an artifact that
looks like three tests and contains one.** Half the record varies per block and
half does not, and the varying half is exactly what makes the constant half easy
to miss — **a reviewer checking "do these three records differ?" sees yes and
stops.** That is the hazard this round exists to close, and it is stated first
because it is the one a careful reader would otherwise walk past.

---

## 3. The ruling

### `PC-D1` — no tally field on the wire, ever

Any field a prover populates that consensus then consumes is prover-chosen.
Refused under `RF-D8`'s criterion. Stated as a standing prohibition rather than a
decision about one field, because the next person who needs a number on a record
will reach for the same shape.

**Scope — the wire/local split, stated so the rule is not over-applied.** This
governs **transported** values. It does not reach a value the verifier derives or
counts locally and stores in its own LMDB; that is the *endorsed* side of
`RF-D8`, whose own resolution was "the verifier reads it from its own LMDB".
`SO-D2`'s settlement row keeps `passes` and `issued` for exactly that reason —
node-computed from chain state, never transported, one enforcing writer, the same
argument that makes its `outcome` byte safe. **This round makes that row more
correct, not less: a local materialisation is the only place a count is safe.**

### `PC-D2` — the block is **implicit**: the record rides its own producer's block

**The miner that closes the block issues the challenge.** There is no thundering
herd to arbitrate and never was, so the witness for a challenge is the producer
of the block the challenge belongs to — and the record rides that producer's
block.

That makes the block **unforgeable without carrying it**, the same property the
attestation path already gets for free:

- Nothing goes on the wire. **`ArchivalServeCreditResponse`'s fields do not
  move.**
- There is no claimed block for admission to validate, because there is no
  claim — consensus reads the block it is already validating.
- **There is no path where a record names a block it did not come from.** Not
  "a check rejects it": the state is unrepresentable.

**The alternative was considered and is strictly worse.** Broadcasting records
for any miner to include requires carrying the block, admission verifying the
claim, and a rule for what makes a claimed block legitimate — more wire, more
surface, and a new forgery axis, to buy flexibility the mechanism does not need.
Cheaper *and* more robust is not a trade, so this is ruled rather than balanced.

### `PC-D3` — `challenge_leaf_index` takes `block_hash(h−1)`

The preimage gains the **hash**, not the height.

**Height and hash are not equivalent and the difference is the ruling.** A height
is a *reference* a reorg can silently repoint at a different block; a hash
*names* the block. And the nonce already binds `block_hash(h−1)` and
`cb_out_key` (`RF-D5`), so taking the same term keeps the record with **one**
block reference. A second, weaker reference could disagree with the first — and
a record carrying two references that can diverge is a record with a state
nobody has reasoned about.

Chosen deliberately rather than by picking the field that serializes smaller;
under `PC-D2` nothing serializes at all, so size was never the axis.

**Domain separator bumps** to `shekyl/archival-serve-challenge-leaf-v2` (rule
30). The derivation changed; leaving the label would let two implementations
disagree silently on a value feeding the signature preimage. Pre-genesis there is
no migration — the bump exists so one label never names two functions.

#### The preimage, stated so a second implementation can be built against it

```text
preimage = P_id[32] ‖ LE64(shard_id) ‖ LE64(settlement_epoch) ‖ block_hash(h−1)[32]
tau      = cSHAKE256(N = "", S = "shekyl/archival-serve-challenge-leaf-v2", preimage)[0..32]
index    = LE_u64(tau[0..8]) mod segment_leaf_count        (0 when the count is 0)
```

This is written out because the implementation is not a specification: a reader
who can only recover the layout by reading `challenge.rs` cannot check
`challenge.rs`. **`LE64` here and `BE` in the ledger key of `PC-D4` is not an
inconsistency** — the key is big-endian so its prefixes sort, and this preimage
is little-endian because it always was; neither property is available to the
other and unifying them would break one of the two.

**How the shipped derivation was checked against it.** An independent cSHAKE256
was written from FIPS 202 / SP 800-185 against the above — not by transcribing
`challenge.rs` — its Keccak-f[1600] sponge validated against `hashlib.shake_256`
and its customized path against NIST SP 800-185 cSHAKE256 Sample #3. It
reproduces both fixture indices (13,125 and 14,593). The vector is pinned in
`challenge.rs` as `the_v2_derivation_matches_an_independently_computed_vector`,
and it is observed to go red on a byte-order swap, a reordered preimage, a
big-endian `tau` read, and a reverted label — the four ways a second
implementation is *differently wrong* while every self-comparison still passes.

### `PC-D4` — the ledger key widens to `(P, s, E, block)`

This is where consensus stores the enumeration `PC-D5` counts. Under `PC-D2` the
block is the including block, so the key means **one record per producer per
pair-epoch**: a producer cannot submit two for the same pair in one block, and
cannot submit for a block it did not produce.

**The old-vin dedup — `has_archival_serve_credit_bit`, called from
`check_archival_serve_credit_input` — becomes the uniqueness enforcer**
under the widened key. A duplicate is then not a double-count some check must
catch — it is the same key, refused by the structure.

#### 3.4.1 Field order is ruled, and it is the reason the prune survives

**Append. `P_id[32] ‖ BE(shard)[8] ‖ BE(E)[8] ‖ BE(block_height)[8]` — 56 B,
every existing offset unchanged.**

`delete_archival_serve_credit_before_epoch` reads the epoch **by offset**
(`+40`) and so do the gather and the slash walk. Appending keeps the epoch at
40, so the prune, the dedup and every cursor scan keep working **by
construction** rather than by being found and updated. Putting the block before
the epoch would leave all of them compiling, scanning, and pruning the wrong
rows with nothing failing.

**Height in the key, hash in the derivation — and these are not inconsistent.**
They answer different questions:

- The **derivation** (`PC-D3`) must name the block *absolutely*, because it
  enters a signature preimage, and because the nonce already binds
  `block_hash(h−1)`; a second, weaker reference could disagree with the first.
- The **key** may use the height, because serve-credit rows are **block-owned**:
  `BlockchainDB::pop_block` → `remove_transaction` deletes a popped block's rows
  vin-driven (`BlockchainDB::remove_transaction_data`). A popped block's rows
  go with it, so a
  height cannot be silently repointed at a different block while its rows
  survive. The property that makes the height safe here is the removal, not the
  height.

#### 3.4.2 The pop path cannot rebuild the widened key — found by grounding it

`BlockchainDB::remove_transaction(const crypto::hash& tx_hash)`
reconstructs the key **from the vin alone** via
`get_archival_serve_credit_key(resp, …)`. Under `PC-D2` the block is *not on the
vin*, so the widened key is not reconstructible there: the removal has the
record but not the block it rode in on.

**Ruled: thread the block height into the removal** rather than read it from
ambient chain state. `height()` happens to hold the right value at that point in
`pop_block`, and depending on that is the invariant-held-by-circumstance shape
this codebase keeps paying for — it has no name, no test, and breaks silently
when the call order changes.

This is `PC-D2`'s one real cost: making the block implicit on the wire means
every consumer that needs it must be *given* it, and the pop path is the one
that had been getting it for free from a field.

### `PC-D5` — consensus counts by enumeration

`passes(P, s, E)` is the number of admitted records for that pair-epoch, counted
by walking them. No field carries a tally anywhere on the wire.

### `PC-D6` — the four readers must be taught what three rows mean, and the gather explicitly

**This is the round's largest surface and its highest-risk change.** Widening the
key changes a table with four readers — the vin dedup, the slash-window walk, the
fast-path miss check, and the emission gather.

**The gather is the one that cannot be left to infer.** It cursor-walks the table
and pushes one `credit_pairs` entry **per row**
(`process_archival_epoch_close_at_height`, no
value-byte gate). Three keys where it expects one **triples `credit_pairs` and
inflates `r_market` — silently, with no error and no test failing** unless a test
asserts the fold.

So the gather **folds the enumeration back to one credit per pair-epoch, and the
fold is written explicitly** rather than emerging from the key order. This is the
same shape as `SO-D1`'s enumerate-and-write: consensus counts by enumeration, and
whoever consumes the enumeration states how it collapses.

**This is `CR-D2`'s four-reader problem arriving through the key rather than the
value** — recorded that way because the class is what makes it findable next
time, not the instance.

**Payment stays per-pair-epoch**, which the fold is what preserves. Three passes
credit a pair once. No economic disposition opens — but note it is now preserved
*by the fold* rather than by the key, so the fold is load-bearing and gets a test
that fails if it is removed.

**Landed, and the removal test confirmed the site was silent.** With the fold
deleted, **exactly one** test in the whole suite goes red — the one written for
it. Every other assertion stays green: each row is legitimate, each index is
correct, the arrays are well formed, and the only symptom is a count three times
too large where nothing was looking. That is the empirical form of "silent
failure site", and it is worth recording that the pre-existing emission tests —
which do assert on `credit_pairs.size()` — could not catch it, because they seed
one row per pair-epoch and so never build the state the fold acts on.

The test asserts on the **pair count**, not on a downstream reward figure: the
fold's absence is only visible on the axis the fold acts on, and a reward
assertion would have coupled it to the economics.

### `PC-D7` — HALF collapsed, and the other half is the count bound

**Corrected 2026-08-24, during implementation.** This entry read
"COLLAPSED by `PC-D2`" and that was wrong by half.

The opening draft had admission verify that a record's claimed block was a real
assignment. That check did **two** jobs, and the collapse discharged both when
`PC-D2` only retires one:

1. **Verify a claimed block reference** — genuinely dead. Under `PC-D2` nothing
   is claimed; the record arrives in the block that produced it and consensus
   reads that block directly. Correctly collapsed.
2. **Verify that this block's assignment names this pair** — **survives.** It
   is the *count bound* (how many blocks may carry a record for one pair-epoch)
   and the anti-adaptive-selection check, and `PC-D2` says nothing about
   either.

**What made this visible was the code, not a re-reading.** Widening the ledger
key makes the admission dedup
`has_archival_serve_credit_bit(P, s, E, h)` **vacuous**: `h` is the block under
validation, which is not in the DB yet, so no row can ever match and every
duplicate would be admitted. With job (2) discharged, nothing at all would bound
the record count — a pair could file in every block of the epoch and inflate its
own pass count. **That is the free-rider margin `TJ R1` closes**: an unbounded
or self-selected record set prices the test below the job.

**Disposition — the dedup stays pair-epoch-wide.**
`archival_serve_credit_pass_count(P, s, E) > 0` rejects, which is exactly the
one-credit-per-pair-epoch bound the live mechanism already implies, and leaves
consensus behaviour **byte-identical** to before the key widened.

**Named blocker (rule 22) for the surviving half:** `assign_epoch` exists in
`challenge_assignment.rs` with **no FFI export and no consensus caller**, and
the live issuer is still the one-challenge-per-pair-epoch beacon. So the
three-row state is **unreachable by construction today** — nothing issues three
challenges. Wiring the assignment is an issuance-mechanism cutover with its own
round; enforcing `count < CHALLENGES_PER_PAIR_PER_EPOCH` *without* that issuer
would change consensus now, still permit adaptive selection, and buy nothing.

**Reopen criterion (rule 21):** when the assignment cutover lands, the dedup
relaxes from "any row for this pair-epoch" to "this block's assignment names
this pair" — count bound and selection check in one.

**Written into the cutover's own inputs**, not only here:
`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.5.1 carries both this bound and the interim
floor-weakening below, because a reader planning that work reads §9.5's
build/hold split and would never reach this round's record. An argument *for* a
piece of work belongs where that work is planned.

The `SO-D8` dependency this entry claimed to discharge is discharged **for the
schema only**. The three-record *semantics* still waits on the urn; the schema
does not.

### The interim property this creates, stated plainly

Until the assignment cutover, the live beacon lets a response land anywhere in
its `H_fire` window while `PC-D3` makes the leaf index vary **per block**. So a
prover gets roughly `CHALLENGE_RESPONSE_BLOCKS` leaf draws and needs only one it
holds: the sampled-leaf floor weakens from "the one assigned leaf" to "the best
of a window of leaves".

Recorded rather than treated as a redesign trigger, for two reasons: `RF-D8`
already rules this floor **weak-but-nonzero** and justifies it on what survives
total witness collusion, not on its strength; and the end state restores
per-challenge binding, because pinning responses to their assignment blocks is
what the assignment cutover *is*. It is an interim property of running the new
derivation under the old issuer — and it is the second reason that cutover is
worth doing, alongside the count bound.

## 4. What this costs — and the cost was already priced

Three openings instead of one, at ~1,920 B each.

**That is the price already on the record.** `ARCHIVAL_SETTLEMENT_WRITER.md`
§2.1 computed block occupancy as `k = 3·D/SEB` — challenges per block, one
record each, at 5,204 B per record. It already assumed per-challenge records.
**The per-epoch reading would have been cheaper than what was priced, not
dearer**: it would have been one record per pair-epoch, a third of the budgeted
volume, because it was doing a third of the testing.

So §2.1's figures stand unchanged — ~10 KB/block at genesis `D ≈ 4,096`, 156 KB
at `D ≈ 100 k`, ~506 KB at `D ≈ 324 k` against a 300 KB penalty threshold. No
re-derivation is owed, and the honest price is the one already carried.

---

## 5. Blast radius — everything this touches

Enumerated at source before implementation, per rule 26's substrate pass.
Sites are named by **function**, not by line number: this round's own edits moved
every line cited in the opening draft, which is the same drift that made
`ARCHIVAL_CHALLENGE_MECHANISM.md` §5.6 unreachable (see `path.rs`'s header).
A function name survives an insertion; a line number is stale as soon as
somebody works above it.
**`PC-D2` emptied the wire column and `PC-D6` filled the schema one** — the work
moved from serialization to the four readers.

**Does NOT change (and this is the round's main saving):** the vin layout,
`ArchivalServeCreditResponse`'s fields, `canonical_bytes`' length, the pruned
half, `SERVE_CREDIT_PRUNED_MAX_BYTES` and its pinned twin, and — because no
persisted block byte moves — **rule 42 does not fire and no version constant
bumps.** Each was on the opening draft's list and each comes off with the block
going implicit. Recorded so nobody re-adds a schema bump "to be safe": a bump
with no wire change is a false signal that costs the next reader a grounding
pass.

| # | Site | Change |
|---|---|---|
| 1 | `challenge.rs::challenge_leaf_index` | preimage gains `block_hash(h−1)`; separator → `-v2` |
| 2 | `wire.rs::signature_preimage` | **VERIFIED** — takes the derived index as an operand, so it binds the block through it; no signature over a transported value |
| 3 | `serve_credit.rs` (FFI) | derives the index with the block hash it is validating; verifies the opening against it |
| 4 | `shekyl_ffi.h` + `check_archival_serve_credit_input` | `shekyl_archival_challenge_leaf_index` signature widens by the hash |
| 5 | **`m_archival_serve_credit` key 48 → 56 B** | append `BE(block_height)`; every existing offset unchanged (§3.4.1) |
| 6 | old-vin dedup | **stays PAIR-EPOCH** (`archival_serve_credit_pass_count > 0`) until the assignment cutover — the exact-get would be vacuous; see the corrected `PC-D7` |
| 6c | SCE-1 within-block pass | **stays pair-epoch too** — the block is common-mode inside one block, so widening adds no discrimination; bytes pinned by the equivalence fixture |
| 6d | **slash-applied trio** (`has/set/remove_archival_slash_applied`) | **not on the original list** — shared `ArchivalServeCreditKey` by coincidence of shape; per-pair-epoch by design, so they move to the new `ArchivalPairEpochKey` rather than widening |
| 6b | `remove_transaction` / `pop_block` | **must be threaded the block height** — the vin no longer carries it (§3.4.2) |
| 7 | **Emission gather (`gather_archival_emission_epoch_snapshot`'s scan)** | **folds rows → one `credit_pairs` per pair-epoch, explicitly** — the silent-inflation site; **LANDED**, with `emission_gather_folds_three_challenges_into_one_credit_pair` as its removal test |
| 8 | Slash-window walk (`archival_failure_window_slashable`) | reads "served" as a count over the widened key, not key-presence |
| 9 | Fast-path miss check (same function, the early-out arm) | same |
| 10 | `delete_archival_serve_credit_before_epoch` | **unchanged by construction** — the epoch stays at offset 40 (§3.4.1) |
| 11 | Block-level SCE-1 uniqueness pass | **RESOLVED THE OTHER WAY** — stays PAIR-EPOCH. The enumeration assumed the widened key propagates here; it does not, because within one block the block component is common-mode and adds no discrimination. See row 6c. |
| 12 | `gate2_serve_credit_kat.rs` | fixtures gain the block hash in the index derivation |
| 13 | `serve_credit_tx_parity.rs` | **RE-ANCHORED** — the conditional resolved to yes: the derived index moved, so the countersignature re-signed and the kept blob's bytes moved with it. Its own guard fired ("gate-2 blobs moved under the parity pin"). It lives in `shekyl-wire`, outside the two crates this round was testing — see §5.4. |
| 14 | `failure_window.rs` | **VERIFIED SAFE, comments corrected** — it consumes a per-epoch `served` **boolean**, computed C++-side, so the row multiplicity never reaches it. Its prose named a `per-(P, s, E)` ledger that no longer exists. |
| 14b | ~~`attestation_settlement_window.rs`~~ | **NO SUCH FILE, and never any such file.** The enumeration named it; nothing else in the tree does. Half of row 14 was unfalsifiable from the moment it was written — see §5.4. |
| 15 | `SO-D1`'s writer | its `passes` is this round's enumeration — the two rounds meet here |
| 16 | `ArchivalServeCreditKey` (`shekyl_types.h`) | 48 → 56 B, and **`SO-D2`'s settlement key rides it** — see §5.2 |
| 17 | `append_archival_block_unique_keys`' `'S'` reservation key | **not on the original list** — found by grounding the derivation site; see §5.3 |
| 18 | `regtest_inject_archival_serve_credit` | **not on the original list** — a writer taking `(P, s, E)` as arguments, so `PC-D4` widens its signature too; it already warns its bit is not block-owned, which the widened key makes literal |

### 5.4 What auditing the table itself turned up

The blast-radius table was this round's checklist, and at close-out it was
audited **against the code** rather than read. Three rows were wrong in ways
worth recording, because each is a different failure of an enumeration:

- **Row 11 resolved the opposite way.** It assumed the widened key propagates to
  the within-block uniqueness pass. It does not — the block is common-mode
  inside one block. An enumeration written before the implementation can assert
  a *direction*, not just a site, and the direction is the part that needs
  checking.
- **Row 13's conditional resolved to "yes", and its target sits outside the
  crates this round was testing.** `serve_credit_tx_parity.rs` is in
  `shekyl-wire`; running `-p shekyl-archival-retention -p shekyl-ffi` all round
  reported green over a **red** test. The fixture's own guard caught it the
  moment the right target ran — the tooling was the gap, not the test.

  **And it recurred once more before the round closed**, which is what settles
  it as a tooling defect rather than an oversight: registering the `-v2`
  separator edited `CRYPTO_DOMAIN_REGISTRY.tsv`, which is pinned by a test in
  `shekyl-crypto-pq` — a crate this round never touched. Green locally, red in
  CI, the same shape and the same cause. **The affected-crate set is not
  derivable from the diff's directory names**: a shared file has consumers
  anywhere. CI runs
  `cargo test --locked --workspace --exclude shekyl-randomx-differential`,
  and that — not a `-p` list assembled from what looks related — is the gate.
- **Row 14 named a file that has never existed.** `attestation_settlement_window.rs`
  appears nowhere in the tree or in any commit; nothing else in the repository
  mentions it. Half that row was **unfalsifiable from the moment it was
  written** — a checklist item that could never be discharged and never fail,
  which reads as coverage for as long as nobody looks. Rule 47's shape applied
  to a design doc: an item must be able to be *wrong*.

Recorded rather than silently corrected: a table used as a checklist earns the
same standard as the code it lists.

### 5.0 The ABI hazard the C++ half must clear FIRST

`ShekylArchivalVerifyCtx` gained `prev_block_hash` **mid-struct**, between
`block_hash_at_seal` and `registry_segment_subroot_rk` (offset 48). Until
`shekyl_ffi.h` mirrors the field *at the same offset*, C++ constructs the
smaller struct and every field after it is misread — and if C++ is also the
shorter struct, Rust reads 32 bytes past its end.

**This does not fail the way the guard suggests it will.** The
`SHEKYL_ARCHIVAL_VERIFY_ERR_PREVHASH_UNPOPULATED` refusal keys on an all-zero
hash; what Rust reads past the end of a short struct is stack residue, not
zeros, so the refusal stays silent and the index derives from garbage. The
symptom is a nondeterministically failing C++ test with a path mismatch — a
prover-shaped failure for a wiring defect, which is the exact
misattribution `PC-D3`'s guard exists to prevent, arriving through the one
channel the guard cannot see.

So the header edit is the **first** move of the FFI half, not a step within it.

**Resolved structurally, not by care.** Both sides now pin the offsets —
`const _: () = assert!(core::mem::offset_of!(...))` in `codes.rs`,
`static_assert(offsetof(...))` in `shekyl_ffi.h`, on the pattern
`ShekylStemTallyRow` already uses. Offsets and not merely `sizeof`, because a
field *moving* preserves the size: a size pin would have accepted the one
mutation this hazard is actually about. The four pinned fields are
platform-independent — everything at or before `segment_leaf_count` is
fixed-width, so no pointer or `size_t` participates.

A note in a design doc is read by whoever already suspects the problem. This
one is now a compile error on both sides.

### 5.0b The read nothing covered

The FFI half added one line of production behaviour that no test observed:
`check_tx_inputs`' read of `block_hash(h−1)`. Every archival test calls
`check_archival_serve_credit_input` **directly** and supplies the hash itself,
so replacing the production read with the null hash left **all 18 serve-credit
tests green**.

This was found by biting the read rather than by reading the tests — the tests
looked like coverage because they exercise the derivation thoroughly; what they
never touch is where its operand comes from. A parameter is not covered by
tests that pass it.

Closed by `gate2_check_tx_inputs_derives_the_block_hash_from_the_chain`, which
drives the public entry point so the hash comes from the chain, and which is
observed red on both the null-hash substitution and an
`h` / `h−1` off-by-one. It doubles as the direct demonstration of `PC-D2`'s
next-block-only property: the same record, byte-identical on the wire, is
accepted against one parent and refused against another.

### 5.1 Interaction with `SO-D8`

`SO-D8` (cross-epoch admission: a response naming `E` landing in `E+1`) becomes
**per-challenge rather than per-epoch** — same boundary, finer grain. Under
`PC-D2` it also sharpens: since the record rides its producer's block, a
challenge issued in the epoch's last `W₂` blocks is a record whose *including*
block is past the credit deadline. It does not resolve `SO-D8`; the cutover round
inherits the finer statement.

### 5.2 The consequence for `SO-D2` that must not be missed

`SO-D2` ruled the settlement key **byte-identical to `ArchivalServeCreditKey`**
so one key probes both tables. That key now widens to 56 B — but the settlement
table is **per-pair-epoch by design** (`SO-D1`: one row per pair with
`issued ≥ 1`), so it must **not** widen with it.

So the two keys stop being the same shape, and `SO-D2`'s "one key probes both
tables" rationale expires. That is a **retired justification, not a defect**: the
tables now answer questions at different granularities — evidence per challenge,
verdict per pair-epoch — which is exactly the split `PC-D6` draws. The settlement
key keeps `(P, s, E)` and stops borrowing `ArchivalServeCreditKey`.

**The type they adopt is `ArchivalPairEpochKey`** (48 B, byte-identical to
what `ArchivalServeCreditKey` was), added by this round for exactly this reason.
The slash-applied trio is its other consumer — see row 6d, which the original
enumeration missed for the same reason `SO-D2` was caught: one key type was
serving two granularities because their shapes happened to coincide.

**Landed code affected:** `BlockchainLMDB::set_archival_settlement` /
`get_archival_settlement` / `delete_archival_settlement_for_epoch` currently
build `ArchivalServeCreditKey` (PR #554). They need their own 48-byte key type
once that key widens. Flagged here because #554 is open and merges first;
whoever lands this round owns the follow-through.

### 5.3 How the record reaches its block: the pool is transport

Grounding the derivation site surfaced a site the enumeration missed, and with
it a question the ruling did not obviously answer: **serve-credit txs go through
the mempool.** The pool reserves a `'S' ‖ P ‖ shard ‖ E` key for
them (`append_archival_block_unique_keys`), and no C++ code constructs such a
tx — they are produced elsewhere and
relayed.

**This is not a contradiction of `PC-D2`, and the distinction is worth stating
because the first reading looks like one.** `PC-D2` says the miner that closes
the block *issues the challenge*; **`P` produces the response**. The pool is how
that response travels from `P` to the miner. `PC-D2` constrains the record's
**validity binding** — it verifies only in a block whose `prev_id` matches its
derivation — not its **transport**. "There is no path where a record names a
block it did not come from" still holds exactly: nothing on the wire names a
block at all.

**The new consequence is that a pooled record is next-block-only.** Once another
block connects, its derivation is bound to a hash that is no longer the tip's,
and it can never be admitted. That is the mechanism working — a response is
valid in exactly one block — but it had to be checked rather than assumed, since
a stale record served from a cache into a block template would produce invalid
blocks.

**Checked, and no fix is owed.** `m_input_cache` is cleared in both
`on_blockchain_inc` and `on_blockchain_dec`, so
`is_transaction_ready_to_go` re-runs the real gate against the new tip and a
stale record fails there — before it can enter a template. Recorded as a
verified fact rather than left as a worry, because the next reader will have the
same one.

**The `(P, s, E)` pool key is left alone.** It is narrower than `PC-D4`'s
widened ledger key, which invites widening it to match — but within a single
block `(P, s, E)` is unique anyway (each of the three challenges rides its own
block), so the narrow key is consensus-adequate. The only question it raises is
stale *eviction*, which is liveness, not consensus, and which the existing
`last_failed_id` path already handles. Widening it here would be a change made
for symmetry with a different key serving a different purpose.
