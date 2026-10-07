# Archival serve credit — specification

**Status:** OPEN — Round 0 of SO-D8 Slice C. The design is the maintainer's
brief of 2026-10-07 (the secret per-block draw). Nothing in this document is
built. §13 lists what is ruled, what is provisional, and what is posed for
ruling; nothing posed there is decided in the body.

**Authority.** This is the single specification of the serve-credit
mechanism: draw, request, receipt, carrier, admission, miss derivation and
settlement. Where another document states the mechanism differently, this
one governs and the other is a record of how the design got here. Decision
history stays where it is: the decision log
([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md)) and the ruling
records in the round documents listed in §15.

**Pin.** Every statement about what the code does today is cited
`file:line` at `dev@0e1d1d6126` and is collected in §2. Everything else is
specification.

**Identifiers.** Family `SCS-`: `SCS-P#` for a question posed for ruling
(§13.3), `SCS-F#` for a defect found while grounding (§14).

**Process.** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
a design round on consensus behaviour. No implementation commit lands
before §13.3 is ruled and the preconditions in §11 hold.

---

## 1. The mechanism in one page

An archiver bonds under a persona `P` and holds shards. The unit of
obligation is the pair `(P, s)`. Each settlement epoch `E`, the chain
tests whether each pair serves its shard, and pays or penalises on the
result.

1. **Draw.** The producer of block `h` commits to a secret seed in its
   coinbase. The seed and the block's hash select a number of pairs from
   the epoch's drawable set. Only the producer knows which.
2. **Read.** The producer reads each drawn pair's shard from `P` over
   `P`'s onion service, with the same request an ordinary reader sends.
   `P` cannot tell a challenge from any other read.
3. **Receipt.** `P` signs for what it delivered. The signature is the
   last bytes of the response.
4. **Carrier.** Within `W₂` blocks the producer files the receipts in
   carrier transactions, each of which also reveals the seed.
5. **Admission.** Every node checks, once, when the carrier's block
   connects: that the seed is the one committed, that each record is a
   draw of that seed, and that `P`'s receipt covers it.
6. **Issuance and misses.** A draw is *issued* when its seed is revealed.
   An issued draw with no admitted receipt by `h + W₂` is a miss. Nobody
   asserts a miss.
7. **Settlement.** After the epoch's last reveal can have landed, a
   beacon selects three of each pair's issued draws. Two or three passes
   among them settles the pair **Served**; fewer settles **Missed**;
   fewer than three issued draws settles **NonObservation**.
8. **Consequence.** Served earns the epoch's reward share. Missed is an
   observation in the failure window; `m` misses in `n` observations
   slashes. NonObservation is neither.

Three properties the rest of the document exists to keep:

- **Indistinguishability.** `P` cannot know whether a read is a challenge,
  cannot know whether it has been drawn, and cannot learn mid-epoch that
  its outcome is settled. It must serve every read until the epoch ends.
- **Unpredictability.** No outsider can compute `P`'s challenge windows.
- **Derived, never asserted.** A miss is the absence of a receipt for an
  issued draw. No party can write one.

---

## 2. What the code does today (at `dev@0e1d1d6126`)

This section is the only place the document describes current behaviour.

| Subject | Today | Where |
| --- | --- | --- |
| Live challenge mechanism | One beacon challenge per pair-epoch. The derived-assignment issuer is not wired | `src/cryptonote_core/blockchain.cpp:4746-4749` |
| The public urn | Exists and is tested; no production caller, no FFI export. Draws without replacement in waves, from `block_hash(h − 1)` | `rust/shekyl-archival-retention/src/challenge_assignment.rs:151`, `:250-253`, `:278-280`; `src/blockchain_db/blockchain_db.h:2047-2048` |
| Drawable-set construction, assignment cache, membership check | Not in code under any name | grep for `DrawableSet`, `EpochAssignmentCache`, `is_assigned`, `at_epoch_open`: no hits |
| Serve-credit acceptance | One C++ gate. The Rust validator has no rule for CEN-J8–J10 | `src/cryptonote_core/blockchain.cpp:4702`, `:4714`; `rust/shekyl-chain-rules/src/census.rs:492-494` |
| Serve-credit dedup | Pair-epoch-wide: any earlier pass for `(P, s, E)` refuses the next | `src/cryptonote_core/blockchain.cpp:4760` |
| Serve-credit vin record | Kept: `p_canonical_id`, `shard_id`, `settlement_epoch`, a 64-byte Ed25519 leg. Pruned: a segment path and a 3,309-byte ML-DSA leg. The signed preimage is over a leaf path | `rust/shekyl-archival-retention/src/wire.rs:59-64`, `:81-84`, `:379-402` |
| Receipt (`SF-D8` v3) | `P` signs `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id ‖ D`, 112 bytes, under `shekyl/archival-attestation-scheme-v3`. Carried on the block-level attestation record, a different record from the vin | `rust/shekyl-archival-retention/src/pass_anchor.rs:64-65`, `:355-372`; `attestation_wire.rs:136-144`; `rust/shekyl-crypto-pq/src/signature.rs:109` |
| Block attestation (CEN-B4) | No Rust rule; the witness is carried unjudged. The C++ path verifies it | `rust/shekyl-chain-rules/src/census.rs:331`; `block.rs:113-115`; `src/cryptonote_core/blockchain.cpp:5089` |
| Anchor window | `L + 1` hashes for `[h − 720 − L, h − 720]`, keyed on the including block's predecessor. `L = 4`, depth 720 | `rust/shekyl-archival-retention/src/pass_anchor.rs:70`, `:73-74`, `:122-131` |
| Serving route | Single-pass serve, 400 / 404 / 503, refusal trailer, signature over `D` as the last bytes | [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) |
| `P`'s serving key | Not wired. The serving task is given `NoResidentKey` | `rust/shekyl-engine-core/src/engine/stake_engine/serving/start.rs:247` |
| Coinbase tag `0x0C` | Does not exist. The highest tx-extra tag is `0x0B`, and the coinbase grammar admits neither | `rust/shekyl-wire/src/tx_extra/mod.rs:79`; `tx_extra/coinbase.rs:57-62` |
| Witness key, witness seed ring | Not in code | grep for `derive_witness_keypair`, `LABEL_WITNESS`: no hits |
| Coinbase transaction secret | Random per block and not retained. The Rust builder takes it from the caller; the C++ builder generates it | `rust/shekyl-block-template/src/lib.rs:191-194`; `src/cryptonote_core/cryptonote_tx_utils.cpp:79` |
| Settlement fold | `settle_epoch(passes, issued)`: NonObservation below 2 issued, Served at 2 or more passes, else Missed | `rust/shekyl-archival-retention/src/attestation.rs:192-203` |
| Settlement rows | A 3-byte row type and an FFI exist. No production code writes or reads one | `rust/shekyl-archival-retention/src/settlement_row.rs:43`, `:157`; `src/blockchain_db/lmdb/db_lmdb.cpp:6928-6929`; `rust/shekyl-chain-store/src/archival_snapshot.rs:235` |
| Slash fold | Reads "any pass", not a settlement row | `rust/shekyl-chain-rules/src/archival/mod.rs:317-318`; `src/blockchain_db/lmdb/db_lmdb.cpp:5361-5362` |
| Accrual | A pair earns for an epoch on "any pass" | `rust/shekyl-chain-rules/src/archival/close.rs:344-352` |
| Failure window | `m = 11`, `n = 13`; a two-valued observation with no NonObservation arm | `config/consensus_constants.json:46-47`; `rust/shekyl-archival-retention/src/failure_window.rs:258-265` |
| Signature schemes | Ed25519 + ML-DSA-65 hybrid. The canonical encoding already carries a scheme byte: values 1 (single) and 2 (multisig) | `rust/shekyl-crypto-pq/src/signature.rs:66-67`, `:152-154`; `multisig.rs:18` |
| Bond record | One identity key (`hybrid_pubkey`), from which `p_canonical_id` is derived. No second key field | `rust/shekyl-types/src/archival/bond.rs:262-265`; `rust/shekyl-archival-retention/src/id.rs:20-21` |
| `RowStatus` | Five arms. None for a row retired by ruling | `rust/shekyl-chain-rules/src/census.rs:62-148` |

---

## 3. Terms and parameters

File names without a directory are under
`rust/shekyl-archival-retention/src/`.

| Symbol | Meaning | Value | Source |
| --- | --- | --- | --- |
| `E` | Settlement epoch | — | `epoch(h)` under the rule set's schedule |
| `SEB` | Blocks per epoch | 10,000 | `SETTLEMENT_EPOCH_BLOCKS`, `constants.rs:245` |
| `h_open(E)`, `h_close(E)` | First and last block of `E` | — | the settlement schedule |
| `W₂` | Blocks within which a carrier for `h` is admissible | 500 | `CHALLENGE_RESPONSE_BLOCKS`, `constants.rs:180-186` |
| `D` | The drawable set of `E`: the pairs held at `h_open(E)`, in canonical order. Also its size | — | §4.1 |
| `h` | The block whose producer draws | — | — |
| `h_incl` | The block that includes a carrier | — | — |
| `j` | Index of a draw within block `h`, from 0 | `u32` | — |
| counted draws | Draws selected per pair at settlement | 3 | ruled; replaces "challenges per pair per epoch" |
| threshold | Passes among the counted draws that settle Served | 2 | `SERVE_THRESHOLD_PASSES`, `attestation.rs:71` |
| `L` | Anchor lag | 4 (PROVISIONAL) | `PASS_ANCHOR_LAG_BLOCKS`, `pass_anchor.rs:73-74` |
| anchor depth | How far below its tip a requester anchors | 720 | `PASS_ANCHOR_DEPTH_BLOCKS`, `pass_anchor.rs:70` |
| `(m, n)` | Failure window | (11, 13) | `consensus_constants.json:46-47` |
| full-pair weight | Draw weight of a pair not visibly short | 1/16 | PROVISIONAL (§13.2) |
| count cap | Ceiling on draws per block, as a multiple of `3·D/SEB` | 3 | PROVISIONAL (§13.2) |
| catch-up point | Share of the epoch by which the top-up aims to finish | 70 % | PROVISIONAL (§13.2) |
| minimum horizon | Floor on the top-up horizon | 200 blocks | PROVISIONAL (§13.2) |

A pair is **visibly short** at `h` if fewer than 3 of its draws in `E`
are issued by reveals admitted in blocks below `h`. The **visible
shortfall** at `h` is the sum over `D` of `max(0, 3 − visibly issued)`.

---

## 4. The draw

### 4.1 The drawable set

`D` is the set of pairs `(P, s)` such that `P`'s bond record held `s` in
the state after block `h_open(E)` connects, including that block's slash
pass. A bond that joined in `E` or later is excluded. A `CompleteTree`
record contributes every shard `s` with
`closed_and_final(view, s, h_open(E), reorg_cap)`
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.4 pin 2). `D` is fixed for the epoch: a pair slashed or released during
`E` stays in it, and the filter for such pairs is at settlement (§9.3).

Canonical order is `p_canonical_id` bytes, then `shard_id` numerically.
`index(P, s)` is a pair's position in that order, and is constant through
`E`.

### 4.2 Commit

The producer of `h` derives two secrets from the coinbase output's
`combined_ss`, each under its own HKDF label on the existing
`shekyl-output-derive-v1` salt:

- the **draw seed**, 32 bytes;
- the **witness key**, an Ed25519 + FN-DSA-1024 pair (§6.2).

They are sibling derivations. Revealing the seed reveals nothing about the
witness key. That separation is load-bearing: a party that could derive
the witness key from a revealed seed could author carriers for `h`, and
`P` itself could compute its nonce, sign its own receipt and file it.

The coinbase's `0x0C` field commits to both:

- `C = cSHAKE256_32("shekyl/archival-draw-seed-commit-v1", seed)`;
- the witness-key commitment, `cSHAKE256_32` of the canonical witness
  public key under `shekyl/archival-witness-key-v1`.

The layout of `0x0C` is posed (`SCS-P1`). The block hash covers the
coinbase, so both are fixed before proof of work.

How the producer comes to hold `combined_ss` again after a restart is
posed (`SCS-P3`): the brief requires the key material to be re-derivable,
and no coinbase secret is re-derivable in the tree today (§2).

### 4.3 Count

The number of draws at `h` is public and is a function of issued counts
only. No outcome enters it. With `u = max(0, visible shortfall at h −
in flight at h)` and `H` the horizon in blocks:

```text
target(h) = min( D/SEB + u/H ,  3 · 3·D/SEB )
```

- `D/SEB` is the base rate: one draw per pair per epoch. It keeps draws
  flowing to the end of every epoch, so the public count never signals
  that challenges have stopped.
- `u/H` is the top-up. It spreads the visible shortfall over the horizon.
- **In flight at `h`** is the total draw count of the blocks in
  `[h − W₂, h − 1]` whose seed is not yet revealed. Blocks whose seed has
  landed are already in the visible counts and are not subtracted again.
- **`H`**: with `r = h − h_open(E)`, `H = max(200, 0.7·SEB − r)` while
  `r < 0.7·SEB`, and `H = max(200, SEB − W₂ − r)` after.

The count is the integer part of a running total, so fractions carry
between blocks. In integers, with a 32-bit fractional carry that starts
at zero at `h_open(E)`:

```text
t      = ( min(D·H + SEB·u, 9·D·H) << 32 ) / (SEB·H)      (u128, floor)
acc    = carry(h − 1) + t
count  = acc >> 32
carry  = acc & (2^32 − 1)
```

`count(h)` and `carry(h)` are consensus state, written when `h` connects
(§10).

### 4.4 Selection

Draw `j` at `h`, for `0 ≤ j < count(h)`, picks one pair **with
replacement**, weight 1 for a pair visibly short at `h` and 1/16
otherwise:

```text
for attempt = 0, 1, 2, …
    x = cSHAKE256("shekyl/archival-draw-v1",
                  seed ‖ block_hash(h) ‖ j_le[4] ‖ attempt_le[4])
    i = uniform(x[0..8], D)            (rejection-sampled, as the urn does)
    pair = the pair with index i
    if pair is visibly short at h:  select pair
    else if x[8] & 0x0F == 0:       select pair
    otherwise continue
```

The candidate is uniform over the static set and is accepted outright if
short and with probability 1/16 otherwise, which gives the 16 : 1 weights.
This form is chosen so that a verifier needs only the epoch's static
index and one pair's issued count per attempt. The form of the mapping is
posed (`SCS-P4`).

The block hash covers the coinbase, so the seed is fixed before proof of
work and cannot be ground offline: every candidate hash is a different
seed commitment's worth of work, and only a hash that meets difficulty is
a block.

Only the producer knows its draws until it reveals the seed.

---

## 5. The request

Every shard request is byte-identical in format and issued by one client
code path, whether organic or a challenge.

- **Organic reader.** `nonce` is 32 random bytes.
- **Challenge.**
  `nonce = cSHAKE256_32("shekyl/archival-challenge-nonce-v1", seed ‖ block_hash(h) ‖ j_le[4])`.
  To `P` it is indistinguishable from random. After the reveal it is
  verifiably bound to `(h, j)`, so one receipt cannot serve two draws.
- **Anchor.** `anchor_height` and `anchor_hash` are the requester's chain
  at its tip minus 720, for every caller.
- **Timing.** The producer spreads its reads at random over many block
  intervals inside `W₂`. This is client policy, not consensus.
- **Ordering.** The client builds no carrier for `h` until every read of
  `h` has completed or been abandoned. A carrier reveals the seed, and
  the seed exposes that block's remaining reads.

The request header, `P`'s gate and `P`'s serving route are as
[`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) states them.

---

## 6. The receipt

### 6.1 What `P` signs

`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8] ‖ D[32]`,
where `D` is the delivery digest of the response
([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) `SF-D8`). The
signature claims that `P` delivered these bytes for this request. It does
not claim `P` stores them.

### 6.2 Scheme

- **Algorithm tag.** The canonical signature and key encodings already
  open with `version(1) ‖ scheme(1) ‖ reserved(2)`. The scheme byte is the
  algorithm tag. The receipt uses a new value, 3: Ed25519 + FN-DSA-1024.
  A later change of scheme is a new value and a version bump under
  [`42-serialization-policy`](../../.cursor/rules/42-serialization-policy.mdc).
- **FN-DSA-1024 (level V)**, inside the hybrid structure, for the receipt
  and for the witness's carrier signature. Ruled (§13.1).
- **Implementation.** The `fn-dsa` crate, pinned to an exact version with
  its four sub-crates. The crate is pre-standard: its keys and signatures
  will change when FIPS 206 is final. §11 carries the FOLLOWUPS row and
  the genesis gate.
- **Signature domain.** A new scheme domain for the receipt under scheme
  3. One label never names two messages or two schemes.

Sizes, from the crate's fixed encodings (1,793-byte verifying key,
1,280-byte signature):

| Object | Ed25519 + ML-DSA-65 | Ed25519 + FN-DSA-1024 |
| --- | --- | --- |
| Canonical public key | 1,996 B | 1,837 B |
| Canonical signature | 3,385 B | 1,356 B |

### 6.3 The receipt key

The bond record carries two keys:

- the **identity key**, Ed25519 + ML-DSA-65, unchanged. It defines
  `p_canonical_id` and authorizes JoinMarket and Reinstate;
- a **receipt key**, Ed25519 + FN-DSA-1024, used for nothing but
  receipts. The identity key's signature on the JoinMarket post binds it.

The reason is algorithm isolation: persona identity stays on a finalized
standard, and the pre-standard scheme touches only signatures whose value
expires within an epoch. Ruled; it reopens `SF-D13` under rule 21
(§13.1). The receipt key is derived as the persona's other keys are; the
serving task receives a signing capability and never a key.

---

## 7. Carrier and reveal

### 7.1 The carrier

A carrier is a `serve_credit_only` transaction: every input is a pass
record for one block `h`, there are no outputs and no fee. It carries:

- the **seed** of `h`, whole;
- the **records**, one per input, in input order;
- the **witness public key** and one **witness signature** over the set
  commitment (§7.3).

A reveal for `h` is admissible only in a block `h_incl` with
`h < h_incl ≤ h + W₂`.

**The seed is revealed whole, with records, and never per draw.** A
per-draw reveal would let a producer reveal only failing draws, which is
a miss assertion in disguise. A carrier with no records is refused
(`n ≥ 1`), so a reveal is never on chain without records.

One block's records can exceed one transaction's weight limit (§7.4).
Every carrier for `h` carries the same whole seed and is admitted on its
own. Whether that is what "revealed once" means is posed (`SCS-P2`).

A carrier that fails any member's check is refused whole, naming the
member. The witness refiles the honest members within `W₂`
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.6.2).

### 7.2 The record

| Part | Field | Width |
| --- | --- | --- |
| Kept | input tag | 1 |
| Kept | `p_canonical_id` | 32 |
| Kept | `shard_id` | varint, ≤ 10 |
| Kept | `h` | varint, ≤ 10 |
| Kept | `j` | varint, ≤ 5 |
| Prunable | `anchor_height` | 8 |
| Prunable | `D` | 32 |
| Prunable | receipt signature | 1,356 |

The record carries `j` and not the nonce: the nonce is recomputed from
the seed. It carries no epoch: `E = epoch(h)`. The exact layout, its
residence in the transaction and the rule-42 version bump are the
record-layout input of Round 0 (`SCS-P5`).

### 7.3 The set commitment (Q9, PROPOSED)

One witness signature per carrier, over

```text
cSHAKE256_32("shekyl/archival-serve-credit-batch-v1", X)
frame(r) = varint(len(r)) ‖ r
```

with members in input order, each member the record's full serialization
(kept then prunable), and `n ≥ 1` a structural check on the carrier.

Two forms of `X` are posed (`SCS-P6`):

- **As §7.6.1 proposed:** `X = frame(r₁) ‖ … ‖ frame(rₙ)`.
- **Amended (recommended):** `X = seed[32] ‖ frame(r₁) ‖ … ‖ frame(rₙ)`,
  so everything the carrier carries sits under the one signature. The
  seed leads at fixed width and needs no frame.

Vectors, computed with a standalone cSHAKE256 checked against the NIST
SP 800-185 samples. Record bytes are the byte values named; `[a..b]` is
the run of bytes `a` through `b` inclusive.

| # | Members | As proposed | Amended, seed = `0x11` × 32 |
| --- | --- | --- | --- |
| 1 | `[00..3f]` | `1944c130df0e82eac6e54c154221acd8a33613c575e7f8306243405243cf2243` | `e8a18b0229aa0093c56ae88878192ea1ea1c2bc5eeb2c8265987f55fe3a6eeca` |
| 2 | `[00..3f]`, `[40..9f]` | `3e530b648b7fc967869175eb820f068948409ba65982d24a864aa435bcf35436` | `c1d7fc91165c9a956a8f5822cb322aa4e662fe1533416f3c8a54a621eff20075` |
| 3a | `[00..0f]`, `[10..3f]` | `ffca99bc71ae0c81832d3102cf32546bc78e223ca745816b3abc16d2bd64e686` | `21d9fdcb038bd34ca0358a74b7c1324a6ba62dc35e6d4a19dff83e98c59c6bf7` |
| 3b | `[00..1f]`, `[20..3f]` | `7cbacf9f7d050272864c6f958d9a2ba828961ef839c630200a1aa1ba7f6df452` | `dd023948c9ed734819600f776c4dedde4715977ae8f53c584ebceb01e61a5d22` |
| 4 | `a5` × 127, `5a` × 128 | `e2bae559b454604c81e9d1732ff2e2ad2ef64b01235d9b894c370f8ac93e9984` | `722cba02ed17973fd9ab9b8cf31b5e2e32c1332504b58b09a0b6ca81aff9844a` |

- Vectors 1, 3a and 3b have byte-identical unframed concatenations. With
  framing dropped all three hash to
  `5ecdb623ea2b2fd035315cb080e74ed7cad1c886b4c354934d6973c41af624e0`.
  They are the only vectors that go red when framing is dropped.
- Vector 4 crosses the one-byte / two-byte varint boundary (127 encodes as
  `7f`, 128 as `80 01`).
- The brief's fifth vector, "with a seed present", is row 2 of the amended
  column.

### 7.4 Size

Per record: at most 58 B kept and 1,396 B prunable, 1,454 B. Per carrier:
32 B of seed kept; 1,837 B of witness key and 1,356 B of witness signature
prunable.

A carrier under `TX_WEIGHT_LIMIT` (149,400,
`rust/shekyl-wire/src/transaction.rs:156-158`) holds
`⌊(149,400 − 3,225) / 1,454⌋ = 100` records.

Against the figure this replaces
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.6, `97 × 3,411 + 16,143 = 347,010` B per block at 97 draws):

| Draws per block | Carriers | Bytes per block | Of which kept |
| --- | --- | --- | --- |
| 97, the old figure's count | 1 | 144,263 | 5,658 |
| 117, the sim's mean at no dropout (§12) | 2 | 176,568 | 6,850 |
| 156, the sim's mean at 30 % dropout | 2 | 233,274 | 9,112 |

At the same 97 draws the load is 42 % of the old figure. These are worst
cases on the varints; the weight rule for the prunable part is the
fee-and-weight round's.

---

## 8. Kept and prunable data

Every daemon prunes. There is no class of node that keeps everything: a
shard's prunable bodies are discarded at the epoch boundary after its
freeze. So verification of the prunable parts is stated as one thing:

**Once, at connect, by every node. Never after the prune.** A node syncing
from scratch accepts that history on the chain it follows.

Settlement runs long after connect and must be computable by a node that
has pruned. It therefore reads only kept data.

- **Kept:** each carrier's seed (32 B) and each record's `(P, s, h, j)`.
  From these any node recomputes the draws, the issued-draw index, each
  pair's counted draws, and which have pass records.
- **Prunable:** the witness key and signature, `P`'s receipts, `D`, the
  anchor fields, and with them the input of the set commitment. All are
  checked at connect and never needed again.

At connect, admission also confirms that the kept seed is the one the
witness signature covers, through the set commitment. That is what the
amended form of §7.3 provides.

---

## 9. Admission, issuance and settlement

### 9.1 Admission

For a carrier naming `h`, in block `h_incl`. Checks run in this order;
the order decides which refusal a test observes. Each refusal is a typed
verdict naming its census row.

0. Structure: the carrier is `serve_credit_only`, `n ≥ 1`, every record
   names the same `h`, and `h < h_incl ≤ h + W₂`.
1. `cSHAKE256_32("shekyl/archival-draw-seed-commit-v1", seed) = C(h)`,
   read from `h`'s `0x0C`.
2. The witness public key hashes to `h`'s witness-key commitment, and the
   witness signature verifies over the set commitment.
3. For each record: `j < count(h)`, and `(P, s)` is draw `j` at `h`
   (§4.4, at the issued counts visible at `h`).
4. The nonce recomputed from `(seed, block_hash(h), j)`.
5. `anchor_height ≥ h − 720 − L`, and the anchor block is on the
   connecting chain below `h_incl`. Its hash is read from that chain, on
   the alternative chain above the fork point when the block is validated
   there.
6. Inclusion by `h + W₂`. `W₂` is the only window; there is no separate
   read window.
7. `P`'s receipt verifies under the bond record's receipt key over the
   transcript of §6.1, with the recomputed nonce, the looked-up anchor
   hash and the carried `D`.
8. Dedup on `(P, s, E, h, j)`.

Whether step 5 needs an upper bound is posed (`SCS-P7`).

### 9.2 Issuance and misses

- A draw `(h, j)` is **issued** when a carrier revealing `h`'s seed is
  admitted. Every draw of `h` is issued by the first such carrier,
  whether or not that carrier holds its record.
- An issued draw with no admitted record by `h + W₂` is a **miss**. It is
  derived and never asserted.
- A block whose seed is never revealed issues nothing: no passes and no
  misses.

### 9.3 Settlement

Settlement of `E` is computed once, by the settlement writer, in the
slash pass. It reads kept data only.

1. **Beacon.** `b = block_hash(h_close(E) + W₂)`. By then every reveal
   for `E` has landed or can no longer land.
2. **Per pair in `D` with at least one issued draw**, take its issued
   draws in `(h, j)` order.
   - Fewer than 3 issued: **NonObservation**.
   - Otherwise select 3 of them uniformly without replacement, by a
     partial Fisher–Yates driven by
     `cSHAKE256("shekyl/archival-settlement-select-v1", b ‖ p_canonical_id ‖ shard_id_le[8] ‖ E_le[8] ‖ k_le[4] ‖ attempt_le[4])`,
     rejection-sampled.
   - 2 or 3 of the selected draws have an admitted record: **Served**.
     Fewer: **Missed**.
3. **Not held.** The drop filter lives at settlement, not at the draw
   ([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
   §7.4 (3.3)): a pair that stopped holding its shard during `E` is not
   charged for what followed. The height that filter reads replaced "the
   fire height", which no longer exists; it is posed (`SCS-P12`).
4. **The row** is `outcome ‖ passes ‖ issued`: `passes` is the number of
   selected draws with a record (0 to 3) and `issued` is the pair's issued
   count. What `issued` does above 255 is posed (`SCS-P8`).

Because any issued draw may be one of the three, `P` cannot learn
mid-epoch that its outcome is settled. Re-rolling the selection costs the
producer of the beacon block a block reward. If review judges that too
cheap, the beacon hashes several blocks.

The const-assert that ties the threshold to the draws becomes "counted
draws = 3, threshold = 2".

### 9.4 Consumers

The slash fold and reward accrual read the settlement row. Neither reads
"any pass". An absent row and a NonObservation row are both outside the
failure window. This is a precondition (§11), not a consequence: under
the secret draw, "any pass" would count every pair the draw did not reach
as a miss.

---

## 10. The issued-draw index

**Chosen: stored, revertible consensus state.** Recomputing is not
available. `count(h)` depends on the counts of the previous `W₂` blocks
and on the visible shortfall, each of which depends on earlier counts
back to `h_open(E)`. And admitting a record for `h` needs the issued
counts as they stood at `h`, up to `W₂` blocks in the past.

Two tables, both written in the connect batch and undo-logged with it:

- **Per block `h`:** `count(h)`, `carry(h)`, the visible shortfall at
  `h`, and whether `h`'s seed has been revealed.
- **Per pair, per epoch:** its issued draws as `(h, j, h_reveal)`, where
  `h_reveal` is the block that first admitted `h`'s seed. The count
  visible at any `h′` is the number with `h_reveal < h′`.

A record's admitted pass is the existing serve-credit row, re-keyed
`(P, s, E, h, j)`.

**Reorg.** A pop reverts the batch: the reveals a popped block admitted
are un-issued, the counts of blocks above the fork point are discarded
and recomputed on the new chain, and the per-pair lists lose the entries
whose `h` or `h_reveal` was popped. Nothing outlives the block that wrote
it. A carrier that was in a popped block is re-admissible on the new
chain if `h` survives and `h_incl ≤ h + W₂` still holds.

**Pruning.** Both tables for `E` are dropped after the settlement of `E`
is final.

---

## 11. Preconditions and sequencing

1. **The settlement writer is wired.** The slash fold and accrual read
   the settlement row with its NonObservation floor (§9.4). Today both
   use "any pass" (§2).
2. **Production `ContentVerify`** is written against the
   transaction-range unit.
3. **This specification lands before code.**
4. **Implementation follows in increments**, each its own PR.

Carried with the implementation:

- **FOLLOWUPS:** update `fn-dsa` and regenerate vectors when FIPS 206 is
  final.
- **Genesis gate:** no genesis on a pre-1.0 `fn-dsa`.
- **Census:** a `RowStatus` arm for a row retired by ruling. It names the
  successor rows, and the gate requires each successor `Implemented`.
  CEN-J8, J9 and J10 are the first rows to use it.
- **Registry:** a row in
  [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) for every
  label in §16, landing with its constant (`SCS-F4`).

---

## 12. What the sim says

`cargo run --release -p shekyl-economics-sim -- --secret-draw`, model and
predictions fixed before the run
([`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md)
§5.13, results §5.14). 324,000 pairs, eight seeds per cell, the count
rule and weighting of §4, a reveal lag uniform on `0..=W₂`, and each
block independently unrevealed with the stated probability.

| Dropout | Pairs short of 3 issued: mean (min – max) | Draws per pair, drawn / issued | Draws per block, mean / max | Fetch per won block |
| --- | --- | --- | --- | --- |
| 0 % | 0.46 % (0.45 – 0.48) | 3.61 / 3.61 | 117.1 / 172 | 351 MB |
| 10 % | 1.10 % (1.03 – 1.18) | 3.92 / 3.53 | 127.1 / 208 | 381 MB |
| 30 % | 3.83 % (3.65 – 3.95) | 4.81 / 3.36 | 155.9 / 292 | 468 MB |

- **The provisional bar holds.** At most 3 % short at 10 % dropout: the
  largest share over eight seeds is 1.18 %.
- **The brief's own model reads "in flight" differently** — every draw of
  the last `W₂` blocks, revealed or not — and under that reading the run
  reproduces the brief's figures: 1.40 / 2.63 / 6.21 % short. §4.3 states
  the other reading because it leaves a third to a half as many pairs
  short for about 4 % more draws (`SCS-P9`).
- **`(m, n)`.** An honest pair at a 0.30 per-read failure misses an
  observed epoch with probability 0.216 under 2-of-3. At `(11, 13)` the
  false-slash bound over the bond's life is `2.85 × 10⁻⁴`. The
  observation rate is 0.995 / 0.989 / 0.962, so a pair that never serves
  reaches 11 misses in 11.05 / 11.12 / 11.44 epochs. The window is not
  what the secret draw strains.
- **The witness's load is new and unmeasured.** A won block costs its
  producer about 117 to 156 whole-shard reads inside `W₂`. A producer
  with a tenth of the hashrate wins about 50 blocks per window: roughly
  17.6 GB of reads, or 290 KB/s sustained (`SCS-P10`).
- **Unpaid service.** A pair that settles NonObservation served the epoch
  for nothing: 0.46 % / 1.10 % / 3.83 % of pair-epochs. Separately, an
  observed epoch settles Missed for an honest pair at 0.216 under the
  0.30 read failure, which is the 2-of-3 rule's cost and is much larger.
  Neither is priced in currency.

The sim does not model the reads, dropout that is correlated in time or
selective, or carry-over from the previous epoch.

---

## 13. Rulings

### 13.1 Ruled (maintainer, 2026-10-07)

| # | Ruling |
| --- | --- |
| R1 | The secret per-block draw replaces the public urn: commit, draw with replacement, reveal with records |
| R2 | **FN-DSA-1024 (level V)** for the receipt and the witness carrier signature. Against ML-DSA-65 it is smaller (1,280 B against 3,309 B), faster, and carries more margin |
| R3 | **A separate receipt key** in the bond record, bound by the identity key's signature on the JoinMarket post. Reopens `SF-D13` under rule 21 |
| R4 | **The witness carrier signature** is FN-DSA under the same algorithm tag and level as the receipt |
| R5 | Settlement selects the three counted draws at close by beacon. Replaces "the first three" |
| R6 | A draw is issued only by reveal; an unrevealed block issues nothing |
| R7 | The seed is revealed whole, with records, within `[h, h + W₂]`; per-draw reveal is forbidden |
| R8 | `W₂` is the only window. The anchor's lower bound is keyed on `h` |

### 13.2 Provisional (rule 21; reopen on the sim or on testnet measurement)

| # | Value | Reopen when |
| --- | --- | --- |
| V1 | Full-pair weight 1/16 | A better setting is measured |
| V2 | Count rule of §4.3: base 1 per pair per epoch, catch-up by 70 %, minimum horizon 200, cap 3 × nominal | Same |
| V3 | Bar: at most 3 % of pairs short of 3 at 10 % producer dropout | The sim or testnet exceeds it. The sim reads 1.18 % |

### 13.3 Posed for ruling

Each states a default. Nothing here is decided in the body.

| # | Question | Default |
| --- | --- | --- |
| `SCS-P1` | **Layout of `0x0C`.** It must commit to the seed and to the witness key, and Q13 ruled its length at 32 bytes for the witness key alone. (a) 64 bytes, the two commitments side by side. (b) 32 bytes, one hash over witness key and seed, both of which the carrier reveals | (a). It reopens Q13's length under rule 21 |
| `SCS-P2` | **"Revealed once" against the weight limit.** One block's records need two carriers (§7.4). Each carrier carries the whole seed and is admitted on its own, or the first carrier reveals and later ones reference it | Each carries the seed: 32 B kept per carrier, and admission stays one rule |
| `SCS-P3` | **How coinbase key material is re-derivable.** Q10 ruled a memory-only ring and named a re-derivable `tx_key` as a fallback, not built. The brief requires re-derivation. What the coinbase secret is derived from (the miner's persistent secret and which block inputs), and that two templates at one height may then share it | Reopen Q10 under rule 21; derive from the miner's secret, the parent hash and the height |
| `SCS-P4` | **The form of the draw mapping.** §4.4 samples the static set and accepts by weight. The alternative, a cumulative-weight index over the pairs as they stood at `h`, needs an order statistic over historical state at every verification | §4.4 |
| `SCS-P5` | **The record layout** (§7.2), its residence in the transaction, and the rule-42 version bump. This is Round 0's record-layout input | §7.2 |
| `SCS-P6` | **Q9 bytes.** The set commitment as §7.6.1 proposed, or amended to cover the seed. Vectors for both are in §7.3 | Amended |
| `SCS-P7` | **An upper bound on `anchor_height`.** The brief keys only a lower bound on `h`. `P`'s own gate holds the anchor within `L` of `P`'s tip minus 720 at read time, and admission requires the anchor block to exist below `h_incl` | No further bound |
| `SCS-P8` | **`issued` above 255.** The row stores one byte and the existing type refuses a larger count. With replacement a larger count is possible, however unlikely, and a refusal there halts settlement | Saturate at 255; the outcome needs only "at least 3" |
| `SCS-P9` | **The reading of "in flight"** in the count rule (§4.3, §12) | Unrevealed draws only |
| `SCS-P10` | **The witness's read load** (§12). Whether a producer's reader at about 117 reads per won block needs a floor-device measurement before the count rule is pinned | Measure before pinning |
| `SCS-P11` | **Which record carries the secret-draw pass.** Two records exist today: the serve-credit vin and the block-level attestation record (§2). §7 specifies the vin in a `serve_credit_only` carrier, which retires the attestation path's pass records and CEN-B4's operand | The vin |
| `SCS-P12` | **The height the settlement drop filter reads.** The ruled filter asks whether the pair held its shard "at the fire height", and the beacon that defined one is gone. Per draw: a draw at `h` of a pair that did not hold its shard in the state after `h` connects (slashes strictly above `h` not yet applied, as `holds_shard_at` reads) is not counted as issued for that pair | Per draw, at `h` |

---

## 14. Defects found while grounding

Doc against code, or doc against doc, at the pin. None is fixed here
unless noted.

| # | Finding |
| --- | --- |
| `SCS-F1` | `CRYPTO_DOMAIN_REGISTRY.tsv:104` marks `shekyl/archival-challenge-assignment-v1` `shekyl-live`. Its only caller chain is the urn, which no production code calls |
| `SCS-F2` | `rust/shekyl-chain-store/src/schema.rs:576` cites `db_lmdb.cpp:5471` for `archival_challenge_failed_at_height`. It is at `:5351` |
| `SCS-F3` | `rust/shekyl-tx-builder/Cargo.toml:41` takes `fips204` at a caret requirement; `shekyl-crypto-pq` pins it exactly |
| `SCS-F4` | The brief asks for a registry row for every new label in this PR. The registry has no status for a label without a constant, and the gate fails a row whose constant is not in code (`scripts/ci/domain_registry_gate.sh:129-162`). The rows land with the constants; §16 lists the labels |
| `SCS-F5` | The brief places both persona keys as "HKDF children of the same per-persona seed in the stake-engine actor". The actor holds no seed: persona keys are derived from the wallet master seed by slot when the engine is assembled, and the actor is handed the derived bundle (`rust/shekyl-engine-core/src/engine/stake_engine/actor.rs:34-35`; `lifecycle/assemble.rs:423`). The receipt key is derived the same way, under a new label |
| `SCS-F6` | The brief records that the beacon selection "replaces the 'first three' settlement ruled 2026-10-07". No such ruling is in the decision log at the pin. The entry of 2026-10-07 this PR adds records both |
| `SCS-F7` | `ARCHIVAL_CHALLENGE_MECHANISM.md` §1 states as settled doctrine that every bonded pair is challenged every epoch. Under the secret draw a share of pairs is not reached (§12), and they settle NonObservation |
| `SCS-F8` | `ARCHIVAL_CHALLENGE_MECHANISM.md` §2 has the pass record "broadcast as a transaction; any miner may include it". Under R-B the record is filed by the producer of `h` in a carrier that producer signs |
| `SCS-F9` | `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.6.1 distinguishes "unpruned validators" from "a pruned node". No such split exists: every daemon prunes (§8) |
| `SCS-F10` | `rust/shekyl-wire/src/transaction.rs:202` calls the pruned-record ceiling a twin of a `cryptonote_config.h` constant. `src/cryptonote_config.h:417-423` says it deliberately has no copy there |

---

## 15. Documents this replaces, and what stays in them

Each keeps its rulings and their history. Its statement of the mechanism
is replaced by a pointer here.

| Document | What it still owns |
| --- | --- |
| [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) | The SO-D8 round's rulings (R-B, `SO-D8a`–`e`, Q3, Q8–Q13), the drawable set's construction (§7.4), carrier semantics (§7.6.2), Slice C's plan and evidence list (§8) |
| [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) | The challenge round's doctrine and forks, the 2-of-3 argument (§3), parameter discipline (§9) |
| [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) | The fetch client: `SF-D1`–`D13`, the delivery digest and its transcript (`SF-D8`), the client's outcome table (`SF-D6`) |
| [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) | The credit-wire round's record of the deleted mechanism and the deletion surface |
| [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) | The settlement writer's rulings (`SO-D1`–`D7`): enumeration, key and value, when it runs |

---

## 16. Labels this specification mints

None has a constant or a registry row yet (`SCS-F4`).

| Label | Mechanism | Use |
| --- | --- | --- |
| `shekyl/archival-draw-seed-commit-v1` | cSHAKE256 | `C`, §4.2 |
| `shekyl/archival-draw-v1` | cSHAKE256 | Selection stream, §4.4 |
| `shekyl/archival-challenge-nonce-v1` | cSHAKE256 | Challenge nonce, §5 |
| `shekyl/archival-settlement-select-v1` | cSHAKE256 | Counted-draw selection, §9.3 |
| `shekyl/archival-serve-credit-batch-v1` | cSHAKE256 | Set commitment, §7.3 (string settled in SO-D8 §7.6.1) |
| `shekyl/archival-witness-key-v1` | cSHAKE256 | Witness-key commitment (SO-D8 §7.9) |
| a draw-seed label | HKDF info | The seed, from `combined_ss`, §4.2 |
| witness-key labels | HKDF info | The witness key's two legs, §4.2 |
| a receipt-key label | HKDF info | The persona's receipt key, §6.3 |
| a receipt scheme domain | signature domain | Receipts under scheme 3, §6.2 |
| a carrier scheme domain | signature domain | The witness signature under scheme 3, §7.3 |

The HKDF and scheme-domain strings are named when their constants land.

---

## 17. Wargames

| Attack | Outcome |
| --- | --- |
| Grind the seed offline | Useless: draws depend on `block_hash(h)` |
| Withhold a mined block to re-roll draws | Costs a block reward |
| Never reveal | NonObservation only; no misses |
| Reveal but omit a pass | A manufactured miss, contained by 2-of-3 |
| Reveal before reads finish | Exposes that block's remaining reads; the client's ordering rule prevents it |
| Producer offline mid-reads | NonObservation; resumable within `W₂` from re-derivable key material (`SCS-P3`) |
| Knock a producer offline | Suppresses observations only; cannot target a `P` |
| One receipt for two draws | Impossible: the nonce is bound to `(h, j)` |
| Fingerprint challenge requests | Prevented only by one client code path and identical formats |
| Learn mid-epoch that the epoch is settled, then stop serving | Prevented: the three counted draws are selected at close |
| Read the public draw count to see that challenges have stopped | Prevented: the base rate keeps draws flowing to the end of every epoch |
| Derive the witness key from a revealed seed and author carriers, or `P` signs its own receipt | Prevented: the seed and the witness key are sibling derivations (§4.2) |
| File one of a block's two carriers and withhold the other | The same as omitting passes: manufactured misses, contained by 2-of-3 |
| Re-roll the settlement beacon | Costs the beacon block's producer a block reward |
