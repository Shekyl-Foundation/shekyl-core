# Archival serve credit — specification

**Status:** OPEN — Round 0 of SO-D8 Slice C, **RULED 2026-10-07**. The
design is the maintainer's brief of that date (the secret per-block draw)
and the rulings on the questions this document posed (§13). Nothing in
this document is built.

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

**Identifiers.** Family `SCS-`: `SCS-P#` for a question this round posed
and its ruling (§13.3), `SCS-F#` for a defect found while grounding (§14).

**Process.** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc):
a design round on consensus behaviour. No implementation commit lands
before the preconditions in §11 hold.

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
   connects: that the seed is the one committed, which pair each record's
   draw index selects, and that the pair's receipt covers it. A record
   does not name its pair; the pair is derived.
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
| The public urn | Deleted 2026-10-10. It had no production caller. The secret draw's hash side is what replaced the selection; the draw producer is not live | was `rust/shekyl-archival-retention/src/challenge_assignment.rs`; `src/blockchain_db/blockchain_db.h:2047-2048` |
| Drawable set | `DrawableSet::at_epoch_open` is built. It enumerates tip bonds. The journal walk that recovers a Release or a slash is not | `rust/shekyl-chain-rules/src/archival/drawable.rs` |
| Assignment cache, membership check | Not in code | grep for `EpochAssignmentCache`, `is_assigned`: no hits |
| Serve-credit acceptance | One C++ gate. The Rust validator has no rule for CEN-J8–J10 | `src/cryptonote_core/blockchain.cpp:4702`, `:4714`; `rust/shekyl-chain-rules/src/census.rs:492-494` |
| Serve-credit dedup | Pair-epoch-wide: any earlier pass for `(P, s, E)` refuses the next | `src/cryptonote_core/blockchain.cpp:4760` |
| Serve-credit vin record | Kept: `p_canonical_id`, `shard_id`, `settlement_epoch`, a 64-byte Ed25519 leg. Pruned: a segment path and a 3,309-byte ML-DSA leg. The signed preimage is over a leaf path | `rust/shekyl-archival-retention/src/wire.rs:59-64`, `:81-84`, `:379-402` |
| Receipt (`SF-D8` v3) | `P` signs `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id ‖ delivery_digest`, 112 bytes, under `shekyl/archival-attestation-scheme-v3`. Carried on the block-level attestation record, a different record from the vin | `rust/shekyl-archival-retention/src/pass_anchor.rs:64-65`, `:355-372`; `attestation_wire.rs:136-144`; `rust/shekyl-crypto-pq/src/signature.rs:109` |
| Block attestation (CEN-B4) | No Rust rule; the witness is carried unjudged. The C++ path verifies it | `rust/shekyl-chain-rules/src/census.rs:331`; `block.rs:113-115`; `src/cryptonote_core/blockchain.cpp:5089` |
| Anchor window | `L + 1` hashes for `[h − 720 − L, h − 720]`, keyed on the including block's predecessor. `L = 4`, depth 720 | `rust/shekyl-archival-retention/src/pass_anchor.rs:70`, `:73-74`, `:122-131` |
| Serving route | Single-pass serve, 400 / 404 / 503, refusal trailer, signature over the delivery digest as the last bytes | [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) |
| `P`'s serving key | Not wired. The serving task is given `NoResidentKey` | `rust/shekyl-engine-core/src/engine/stake_engine/serving/start.rs:247` |
| Coinbase tag `0x0C` | Does not exist. The highest tx-extra tag is `0x0B`, and the coinbase grammar admits neither | `rust/shekyl-wire/src/tx_extra/mod.rs:79`; `tx_extra/coinbase.rs:57-62` |
| Witness key, witness seed ring | Not in code | grep for `derive_witness_keypair`, `LABEL_WITNESS`: no hits |
| Coinbase transaction secret | Random per block and not retained. The Rust builder takes it from the caller; the C++ builder generates it | `rust/shekyl-block-template/src/lib.rs:191-194`; `src/cryptonote_core/cryptonote_tx_utils.cpp:79` |
| Settlement fold | `settle_pair`: three of a pair's counted draws selected by the beacon, NonObservation below 3, Served at 2 passes among the three, else Missed (§9.3). The Rust slash pass calls it for every pair with a draw in the epoch | `rust/shekyl-archival-retention/src/settlement_select.rs`; `rust/shekyl-chain-rules/src/archival/slash.rs` |
| Settlement rows | The Rust slash pass writes one per pair with a counted draw, ahead of the slash it decides. The issued-draw index and its digest (§10) have no block writer yet; a Fakechain-only door stands in for admission. The C++ store keeps the table's handle with no writer | `rust/shekyl-types/src/archival/settlement.rs`; `rust/shekyl-chain-store/src/store/archival_write.rs` (`write_settlements`, `regtest_issue_draws`); `rust/shekyl-chain-store/src/archival_snapshot.rs` (`disposition`) |
| Slash fold | Rust: reads the settlement row; Missed is the only candidate. C++, consensus until `DEL-008`: reads "any pass" on the one-challenge beacon | `rust/shekyl-chain-rules/src/archival/slash.rs`; `src/blockchain_db/lmdb/db_lmdb.cpp` (`archival_challenge_failed_at_height`) |
| Accrual | Rust: a pair earns for an epoch iff its settlement row is Served; the slash pass gathers, an epoch after the close (`ARCHIVAL_SETTLEMENT_WRITER.md` §15). C++, consensus until `DEL-008`: on "any pass", at the close | `rust/shekyl-chain-rules/src/archival/close.rs` (`Transition::gather`); `src/blockchain_db/lmdb/db_lmdb.cpp` (`process_archival_epoch_close_at_height`) |
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
| `D` | The drawable set of `E`: the pairs held at `h_open(E)`, in canonical order. In a formula, `D` is the set's size | — | §4.1 |
| `delivery_digest` | The 32-byte digest of the response `P` delivered, salted with the nonce. `SF-D8` writes it `D`; this document does not | — | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) `SF-D8` |
| `h` | The block whose producer draws | — | — |
| `h_incl` | The block that includes a carrier | — | — |
| `j` | Index of a draw within block `h`, from 0 | `u32` | — |
| `K` | Reads the witness may make of one draw. A consensus constant: admission refuses a record whose `attempt` is `K` or more. Three, because the failure window is sized on three reads (§12) and each further read is another request the persona must serve | 3 | ruled 2026-10-07 (`SCS-P13`) |
| `attempt` | Which read of a draw produced a record, from 0 | one byte, `< K` | §5, §7.2 |
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

For each block it builds, the producer generates two secrets from fresh
randomness, as independent values:

- the **draw seed**, 32 bytes;
- the **witness key**, an Ed25519 + FN-DSA-1024 pair (§6.2).

Neither is derived from anything else. In particular neither comes from
the coinbase output's shared secret: the coinbase recipient knows that
secret and would learn the seed at once. And neither comes from a
persistent producer secret: that would be a long-lived secret in a
publicly addressed daemon, would let a thief learn every future seed
before its reveal, and would act as a miner-identity oracle.

The two must be independent of each other. A party that could derive the
witness key from a revealed seed could author carriers for `h`, and `P`
itself could compute its nonce, sign its own receipt and file it.

Both are held in memory only, in the ring
[`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.7 rules (Q10): keyed by height, capacity `W₂`, wiped on drop, never
persisted. A producer that restarts loses them. That loss is harmless by
construction: an unrevealed block issues nothing (§9.2), its pairs settle
on their other draws or as NonObservation, and the count rule tops the
shortfall up (§4.3).

The coinbase's `0x0C` field is one 32-byte commitment to both:

```text
cSHAKE256_32("shekyl/archival-draw-commit-v1", witness_pk ‖ seed)
```

with `witness_pk` the canonical encoding of the witness public key
(1,837 bytes, fixed) and `seed` the 32 bytes. Every carrier reveals both,
so no check needs one without the other. The field's length is the 32
bytes Q13 ruled. The block hash covers the coinbase, so the commitment is
fixed before proof of work.

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
  `[max(h − W₂, h_open(E)), h − 1]` whose seed is not yet revealed. Blocks
  whose seed has landed are already in the visible counts and are not
  subtracted again. The range stops at the epoch's open: a block of
  `E − 1` drew from `E − 1`'s set, and its reveal cannot reduce `E`'s
  shortfall.
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
otherwise. It samples the static set and accepts by weight:

```text
zone = (2^64 − 1) − ((2^64 − 1) mod D)
for attempt = 0, 1, …, 255
    x = cSHAKE256_32("shekyl/archival-draw-v1",
                     seed ‖ block_hash(h) ‖ j_le[4] ‖ attempt_le[4])
    v = LE64(x[0..8])
    if attempt < 255 and v ≥ zone:   continue
    i = v mod D
    if attempt = 255:                select the pair with index i
    if that pair is visibly short:   select it
    if x[8] & 0x0F = 0:              select it
    otherwise continue
```

The candidate is uniform over the static set, accepted outright if short
and with probability 1/16 otherwise, which gives the 16 : 1 weights. A
verifier needs only the epoch's static index and one pair's issued count
per attempt. The loop is capped: the 256th attempt selects its candidate
whatever its weight, so the draw always terminates on a fixed bound.

**The pair is derived, not carried.** `(P, s)` is a function of
`(seed, block_hash(h), j)` and the issued counts visible at `h`. A record
names `j` and nothing else about its pair (§7.2), so it cannot name the
wrong one.

The block hash covers the coinbase, so the seed is fixed before proof of
work and cannot be ground offline: only a hash that meets difficulty is a
block.

Only the producer knows its draws until it reveals the seed.

### 4.5 Vectors for the selection

`seed = 0x11 × 32`, `block_hash(h) = 0x22 × 32`, computed with a
standalone cSHAKE256 checked against the NIST SP 800-185 samples. Each
cell is the selected index and the number of attempts it took.

| `D` | Visibly short | `j = 0` | `1` | `2` | `3` | `4` | `5` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | indices 0 to 3 | 3, 1 | 2, 1 | 3, 1 | 2, 5 | 0, 1 | 2, 2 |
| 8 | none | 3, 6 | 4, 5 | 1, 18 | 2, 7 | 7, 9 | 4, 7 |
| 8 | all | 3, 1 | 2, 1 | 3, 1 | 4, 1 | 0, 1 | 5, 1 |

**The cap.** At `j = 28,409,462`, with `D = 8` and no pair short,
attempts 0 to 254 are all refused, so the 256th selects: index 1, in 256
attempts. Without the cap the draw would run to attempt 284 and select
index 5. This is the vector that goes red if the cap is dropped or moved.

These become the KAT that pins `(seed, h, j, issued state) → (P, s)`
when the function lands, beside a test-only replay assertion that a
fixture's carried pairs equal the derived ones. There is no runtime field
to compare against.

---

## 5. The request

### 5.1 One request machinery

**Every shard fetch, challenge or organic, goes through the same client
code path:** the same header format, the same envelope handling, the same
stall retries inside a read, the same timeouts, the same classification
of outcomes, and the same rule for the circuit a read rides. `P` must see no difference between a
challenge and an ordinary read.

There is one fetch entry point. It takes the header its caller built and
returns one outcome type to every caller. The request layer has no
challenge-only path and no parameter that says which kind of caller it
serves. What is the challenger's own sits outside it:

- **where the nonce comes from**: derived for a challenge, random for an
  organic read;
- **the challenger's bookkeeping**: which draw, which read of it, when to
  read again, and filing the record.

The test of the rule: a challenge fetch and an organic fetch for the same
shard produce byte-identical requests apart from the nonce.
`shekyl-p-fetch` holds it today at its request builder
(`a_request_differs_from_another_only_in_its_nonce`); the challenger's
caller extends it end to end when it exists (§11).

### 5.2 The header

- **Anchor.** `anchor_height` and `anchor_hash` are the requester's chain
  at its tip minus 720, for every caller.
- **Nonce: fresh for every read, for every caller.**
  - Organic: 32 new random bytes.
  - Challenge:
    `cSHAKE256_32("shekyl/archival-challenge-nonce-v1", seed ‖ block_hash(h) ‖ j_le[4] ‖ attempt[1])`,
    with `attempt` the read's index, from 0. To `P` it is
    indistinguishable from random, and no two reads of a draw share one.
    After the reveal it is verifiably bound to `(h, j, attempt)`, so one
    receipt cannot serve two draws.
- **Inside one read the header does not change on a stall.** `SF-D6`'s
  stall retries, seconds apart, repeat it for every caller
  ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md)). Its one retry
  after a 400 derives a fresh anchor and keeps the nonce.

Nonce vectors, `seed = 0x11 × 32`, `block_hash(h) = 0x22 × 32`:

| `j` | `attempt` | Nonce |
| --- | --- | --- |
| 0 | 0 | `b9601207ca7b74d36da0ee2402b83418e94408a7815e33d318db0ff783da45dc` |
| 0 | 1 | `61a3796f42ab53642e53458b5b6012c6102aacbce03c9ea20796407776df2248` |
| 0 | 2 | `f8bfae392e076cf3415bd37f1584a48abefbae56cb6fe89329b98955cc1b76d4` |
| 1 | 0 | `65bf6d43f77b2e7f71e2ff7a5e3a570257be3ce73f8760a76152f92773bdb31b` |

A nonce computed without the `attempt` byte is
`87ade5ae…03adc456` for `j = 0`; it matches no row, which is what goes
red if the byte is dropped.

### 5.3 The challenger's schedule

None of this is request behaviour, and none of it is consensus except the
bound `K`.

- **Timing.** The producer spreads its reads at random over many block
  intervals inside `W₂`.
- **Re-reads.** A read, in `SF-D6`'s sense, ends in a verified body or in
  one typed outcome.
  - A challenge read that ends **stall-class** — a circuit timeout, a
    failed connect, a silent close, a truncated body: no exchange
    completed — is read again later, with the next `attempt` and so a new
    nonce. At most `K = 3` reads of a draw, consecutive reads at least 30
    blocks apart (PROVISIONAL, §13.2), at random times in what remains of
    `W₂`.
  - A read that ended in a completed exchange is final, as `SF-D6` rules
    it: a 404, a 503, the refusal trailer, a malformed or overlong reply,
    a bad countersignature, refused content, or a second 400. `P` answered.
  - The record is filed for the first read that succeeds, and names that
    read's `attempt`. A draw whose third read fails, or that runs out of
    window, is abandoned.
- **Fresh circuit per read, by credentials.** Every read, for every
  caller, presents SOCKS credentials no other read presents, and Tor's
  default `IsolateSOCKSAuth` gives each its own rendezvous circuit
  ([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) `SF-D3`, reopened
  and ruled 2026-10-07). This is the request layer's rule, not the
  challenger's: it holds for organic reads the same. A re-read arrives on
  a new circuit with a new nonce, so to `P` it is one more request for
  that shard, and `P` cannot tie a producer's reads to each other by the
  circuit they come in on.
  - The 30-block spacing is scheduling only. It is no longer what makes
    the circuit fresh. Circuit reuse length is not a second mechanism:
    two reads present different credentials, so they do not share a
    circuit at any `MaxCircuitDirtiness`.
  - A new circuit shares this daemon's entry guard with the last one, so
    the reads of a draw are still not fully independent tries. How far
    from independent is what `BA-T31` measures (§12).
  - An operator who points the daemon at a Tor of their own must not
    disable `IsolateSOCKSAuth` on its `SocksPort`.
  - The credentials are derived from the read's nonce, so they exist
    only between the daemon and its own Tor. A local controller
    subscribed to that Tor's `STREAM` events can read them; nothing of
    ours logs them, a nonce does not mark a read as a challenge without
    the seed, and after the reveal a challenge's nonces are public
    (`SF-D3`).
- **Ordering.** The client builds no carrier for `h` until every read of
  `h` has completed or been abandoned. A carrier reveals the seed, and
  the seed exposes that block's remaining reads.

The request header, `P`'s gate and `P`'s serving route are as
[`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) states them.

---

## 6. The receipt

### 6.1 What `P` signs

`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8] ‖ delivery_digest[32]`,
where `delivery_digest` is the digest of the response
([`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) `SF-D8`). The
signature claims that `P` delivered these bytes for this request. It does
not claim `P` stores them.

### 6.2 Scheme

- **Algorithm tag.** The canonical signature and key encodings already
  open with a four-byte header: a version byte, a scheme byte, two
  reserved bytes. The version byte is 1 on a key (`HYBRID_KEY_VERSION`)
  and 2 on a signature (`HYBRID_SIG_VERSION`, the nested combiner; a
  version-1 signature is refused at parse —
  `rust/shekyl-crypto-pq/src/signature.rs:52`, `:66`). The new scheme
  keeps both values. The scheme byte is the algorithm tag. The receipt uses a new value, 3: Ed25519 + FN-DSA-1024.
  A later change of scheme is a new value and a version bump under
  [`42-serialization-policy`](../../.cursor/rules/42-serialization-policy.mdc).
- **FN-DSA-1024 (level V)**, inside the hybrid structure, for the receipt
  and for the witness's carrier signature. Ruled (§13.1).
- **Implementation.** The `fn-dsa` crate, pinned to an exact version with
  its four sub-crates. The crate is pre-standard: its keys and signatures
  will change when FIPS 206 is final. §11 carries the FOLLOWUPS row and
  the genesis gate.
- **Signature domain.** A new scheme domain for the receipt under scheme
  3, `shekyl/archival-receipt-scheme-v1`; the witness's carrier signature
  has its own, `shekyl/archival-witness-carrier-scheme-v1`. One label
  never names two messages or two schemes.
- **Key generation.** The receipt key is seeded (§6.3). The witness's key
  is not: it is drawn from the OS for one block and is never derived from
  anything (§4.2).

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
(§13.1). The receipt key is derived from the wallet master seed when the
engine is assembled, by persona slot and under its own label, exactly as
the identity key is. The stake-engine actor is handed the derived keys
and holds no seed; the serving task receives a signing capability and
never a key.

---

## 7. Carrier and reveal

### 7.1 The carrier

A carrier is a `serve_credit_only` transaction: every input is a pass
record for one block `h`, there are no outputs and no fee. It carries:

- kept: the **seed** of `h`, whole, and **`h`**, once;
- the **records**, one per input, in input order;
- prunable: the **witness public key** and one **witness signature** over
  the set commitment (§7.3).

A reveal for `h` is admissible only in a block `h_incl` with
`h < h_incl ≤ h + W₂`.

**The seed is revealed whole, with records, and never per draw.** A
per-draw reveal would let a producer reveal only failing draws, which is
a miss assertion in disguise. A carrier with no records is refused
(`n ≥ 1`), so a reveal is never on chain without records.

**Every carrier for `h` carries the whole seed** and is admitted on its
own. One block's records can exceed one transaction's weight limit
(§7.4), so a block may need more than one carrier.

A carrier that fails any member's check is refused whole, naming the
member. The witness refiles the honest members within `W₂`
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.6.2).

### 7.2 The record

| Part | Where | Field | Width |
| --- | --- | --- | --- |
| Kept | the input | input tag | 1 |
| Kept | the input | `j` | varint, ≤ 5 |
| Prunable | the prunable section | `attempt` | 1 |
| Prunable | the prunable section | `anchor_height` | 8 |
| Prunable | the prunable section | `delivery_digest` | 32 |
| Prunable | the prunable section | receipt signature | 1,356 |

- **A record names `j` and nothing else about its draw.** `(P, s)` is
  derived from `(seed, block_hash(h), j)` (§4.4). `h` is the carrier's.
  `E = epoch(h)`. The nonce is recomputed from the seed, `j` and the
  carried `attempt` (§5.2). `attempt` is prunable: it is read once, at
  connect, to recompute the nonce, and nothing after needs it.
- The kept part is in the input and the prunable part in the prunable
  section, following the existing split between the serve-credit vin and
  its pruned record.
- One rule-42 version bump covers the record and the carrier together.

### 7.3 The set commitment (Q9, RULED 2026-10-07)

One witness signature per carrier, over

```text
cSHAKE256_32("shekyl/archival-serve-credit-batch-v1",
             seed[32] ‖ h_le[8] ‖ frame(r₁) ‖ … ‖ frame(rₙ))
frame(r) = varint(len(r)) ‖ r
```

with members in input order, each member the record's full serialization
(its kept bytes, then its prunable bytes), and `n ≥ 1` a structural check
on the carrier. The seed and `h` lead at fixed width and need no frame.
Everything the carrier carries sits under the one signature: the seed,
`h`, and each record's `j` with its prunable fields, `attempt` among
them. The vectors below are over opaque member bytes and do not move
with the record's layout.

Vectors, computed with a standalone cSHAKE256 checked against the NIST
SP 800-185 samples. `seed = 0x11 × 32`, `h = 1,000,000`
(`40 42 0f 00 00 00 00 00`). Member bytes are the byte values named;
`[a..b]` is the run of bytes `a` through `b` inclusive.

| # | Members | Commitment |
| --- | --- | --- |
| 1 | `[00..3f]` | `a75502337d8e6b440413009dcc6a96650354ab194abfe1289dbc0f685a6cf14b` |
| 2 | `[00..3f]`, `[40..9f]` | `cd10b6b4cb65ee0028868f2a62e7b0b5df85b1d6f6ea6d3ff88b680c15053c0b` |
| 3a | `[00..0f]`, `[10..3f]` | `f32bddca0eb179ed027b4421d5cff58a707b03b140ec54b0161dc57932f2fd6d` |
| 3b | `[00..1f]`, `[20..3f]` | `91f5ca7a11d3b1120206fb683655ee379b3c69153f6e14d7c859fbae185056ac` |
| 4 | `a5` × 127, `5a` × 128 | `47d951c68a20dda3111eab91a320338f0c9adde3319bbda4450ad6d784f7a782` |
| 5 | as 2, at `h = 1,000,001` | `b1d20f8af7d47aa5ea0b046e84c7d655d2a61314badba546f2840e7a7e4807c4` |

- Vectors 1, 3a and 3b have byte-identical unframed member
  concatenations. With framing dropped all three hash to
  `e29a89bdfc18d9e2ee971720a3784c5e4a15ae7e4101bb8492ec4d6ec9716b8f`.
  They are the only vectors that go red when framing is dropped.
- Vector 4 crosses the one-byte / two-byte varint boundary (127 encodes as
  `7f`, 128 as `80 01`).
- Vector 5 differs from 2 only in `h`. It goes red if `h` is left out of
  the commitment.
- Every vector carries a seed; a commitment without one is not a form of
  this construction.

### 7.4 Size

Per record: at most 6 B kept and 1,397 B prunable, 1,403 B. Per carrier:
at most 42 B kept (the seed and `h`); 1,837 B of witness key and 1,356 B
of witness signature prunable; 3,235 B.

A carrier under `TX_WEIGHT_LIMIT` (149,400,
`rust/shekyl-wire/src/transaction.rs:156-158`) holds
`⌊(149,400 − 3,235) / 1,403⌋ = 104` records.

Against the figure this replaces
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§7.6, `97 × 3,411 + 16,143 = 347,010` B per block at 97 draws):

| Draws per block | Carriers | Bytes per block | Of which kept |
| --- | --- | --- | --- |
| 97, the old figure's count | 1 | 139,326 | 624 |
| 117, the sim's mean at no dropout (§12) | 2 | 170,621 | 786 |
| 156, the sim's mean at 30 % dropout | 2 | 225,338 | 1,020 |

At the same 97 draws the load is 40 % of the old figure, and what a
pruned node keeps is under 1 KB a block. These are worst cases on the
varints; the weight rule for the prunable part is the fee-and-weight
round's.

---

## 8. Kept and prunable data

Every daemon prunes. There is no class of node that keeps everything: a
shard's prunable bodies are discarded at the epoch boundary after its
freeze. So verification of the prunable parts is stated as one thing:

**Once, at connect, by every node. Never after the prune.** A node syncing
from scratch accepts that history on the chain it follows.

Settlement runs long after connect and must be computable by a node that
has pruned. It therefore reads only kept data.

- **Kept:** each carrier's seed and `h`, and each record's `j`. From these
  and the issued-draw index any node recomputes the draws, each pair's
  counted draws, and which have pass records.
- **Prunable:** the witness key and signature, `P`'s receipts, the delivery digests, each
  record's `attempt`, the anchor fields, and with them the input of the set commitment. All are
  checked at connect and never needed again.

At connect, admission also confirms that the kept seed, `h` and each `j`
are the ones the witness signature covers, through the set commitment
(§7.3).

---

## 9. Admission, issuance and settlement

### 9.1 Admission

For a carrier naming `h`, in block `h_incl`. Checks run in this order;
the order decides which refusal a test observes. Each refusal is a typed
verdict naming its census row.

1. **Structure.** The carrier is `serve_credit_only`, `n ≥ 1`, no `j`
   repeats within it, and `h < h_incl ≤ h + W₂`. `W₂` is the only window;
   there is no separate read window.
2. **Commitment.**
   `cSHAKE256_32("shekyl/archival-draw-commit-v1", witness_pk ‖ seed)`
   equals `h`'s `0x0C`.
3. **Witness signature.** It verifies under `witness_pk` over the set
   commitment (§7.3).
4. **Each record's pair.** `j < count(h)`, and `(P, s)` is derived as
   draw `j` at `h` (§4.4), at the issued counts visible at `h`.
5. **Nonce.** `attempt < K`, or the carrier is refused. The nonce is
   recomputed from `(seed, block_hash(h), j, attempt)` with one hash
   (§5.2).
6. **Receipt.** `P`'s receipt verifies under the bond record's receipt
   key over the transcript of §6.1: the recomputed nonce, the carried
   `anchor_height`, the hash of the block at that height on the
   connecting chain (the alternative chain above the fork point when the
   block is validated there), the derived `shard_id`, and the carried
   `delivery_digest`. The anchor block must exist below `h_incl`.
7. **Dedup** on `(h, j)`, which is `(P, s, E, h, j)` with the pair and
   epoch derived.

**No bound on `anchor_height` is checked.** The nonce contains
`block_hash(h)`, so no receipt for `(h, j)` can predate `h`: a lower
bound keyed on `h` is implied and is not a separate check. An upper bound
is `P`'s to keep: `P`'s own gate holds the anchor within `L` of `P`'s tip
minus 720 at read time. The anchor stays on the wire for that gate and
for organic reads.

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
slash pass. It reads kept data and the issued-draw index only.

1. **Beacon.** `b = block_hash(h_close(E) + W₂)`. By then every reveal
   for `E` has landed or can no longer land.
2. **Which issued draws count for a pair.** A draw at `h` counts for its
   pair only if the pair held its shard in the state after `h` connects,
   read as `holds_shard_at` reads it: slashes strictly above `h`. A pair
   that stopped holding its shard during `E` is not charged for the draws
   that followed.
3. **Per pair in `D` with at least one such draw**, take them in `(h, j)`
   order.
   - Fewer than 3: **NonObservation**.
   - Otherwise select 3 of them uniformly without replacement, by the
     partial Fisher–Yates below.
   - 2 or 3 of the selected draws have an admitted record: **Served**.
     Fewer: **Missed**.
4. **The row** is `outcome ‖ passes ‖ issued`: `passes` is the number of
   selected draws with a record (0 to 3), and `issued` is the count from
   step 2, **saturating at 255**. The list of issued draws is the operand
   of the selection; the byte needs only to say "at least 3".

The selection, for a pair whose counted draws are the list `L` in
`(h, j)` order, `n = |L| ≥ 3`:

```text
for k = 0, 1, 2
    r    = n − k
    zone = (2^64 − 1) − ((2^64 − 1) mod r)
    for attempt = 0, 1, …, 255
        x = cSHAKE256_32("shekyl/archival-settlement-select-v1",
              b ‖ p_canonical_id[32] ‖ shard_id_le[8] ‖ E_le[8] ‖ k_le[4] ‖ attempt_le[4])
        v = LE64(x[0..8])
        if attempt < 255 and v ≥ zone:   continue
        break
    swap L[k] and L[k + (v mod r)]
the three counted draws are L[0], L[1], L[2]
```

The zone is the rejection of §4.4 and removes the modulo bias; the cap is
§4.4's, so the loop is total. `n` is the list's length, not the row's
saturating byte.

Vectors, with `b = 0x33×32`, `p_canonical_id = 0x44×32`, `shard_id = 7`,
`E = 5`. Each entry is the position in the original `(h, j)` order of
`L[0]`, `L[1]`, `L[2]` after the three swaps. Every draw is accepted on
its first attempt.

| `n` | Counted positions |
| --- | --- |
| 3 | 2, 0, 1 |
| 4 | 0, 3, 2 |
| 5 | 1, 2, 4 |
| 10 | 6, 3, 8 |
| 255 | 101, 80, 189 |
| 1,000 | 896, 786, 146 |
| 10, with `p_canonical_id = 0x45×32` | 7, 1, 2 |
| 10, with `shard_id = 8` | 0, 8, 2 |
| 10, with `b = 0x34×32` | 8, 0, 4 |

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

**The window.** From a Missed epoch the slash fold walks back through the
pair's earlier rows. Served and Missed are observations. An absent row and
a NonObservation row are passed over, not a stop: stopping would let a
producer withhold one reveal, push a non-server's pair below three issued
draws in one epoch, and clear its window. The walk stops where the
record's standing ends (before the join, or across a reinstatement), at
`n` observations, and at the retention horizon (ruled 2026-10-09). The
horizon is the one the settlement rows' own prune uses, a single constant
for both, so the walk never reads a row a store may have deleted. The
rule is `m` misses within the last `n` observations inside the retained
window. The horizon leaves twice `n` epochs to find `n` observations in,
so it shortens a walk only when fewer than half a pair's epochs are
observed; the code asserts that relation
(`ARCHIVAL_SETTLEMENT_WRITER.md` §14.4 step 3).

### 9.5 Settlement integrity

Three local checks at the settlement writer, none on chain
(`SO-D8d`, [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§6; their form under the stored index ruled 2026-10-07). A failure of any
of them is a store-invariant Fault that halts the writer. It is never a
verdict on a block, never a clamp and never a skipped row.

1. **The index equals its digest.** As each seed's draws are issued, at
   admission, every `(P, s, h, j)` is folded into a running digest for
   the epoch (§10). At settlement the writer hashes every draw the stored
   index holds — the same draws admission folded, including a draw the
   selection then drops because the pair no longer held the shard — and
   compares. Hashing only the counted draws of §9.3 would disagree with
   the digest on an honest node after a mid-epoch slash or release. A
   stored list that lost, gained or changed a draw after admission does
   not reproduce the digest. The pair of a draw is derived from `j`, so a
   record cannot name a pair its draw did not select; what this guards is
   the stored lists the selection reads.
2. **`D` equals a re-walk.** A 32-byte digest of `D` is written in the
   connect batch at `h_open(E)` and undo-logged with it. The writer
   re-walks `D` from the bond journals and compares. Draws are selected
   against `D` as of `h_open(E)`, so a `D` that drifted between admission
   and settlement would change which pair a draw names.
3. **`passes ≤ issued`**, a typed halt, beneath both. The row type holds
   the tighter `passes ≤ counted` — `counted` is three, or none below
   three issued — which implies it. The fold selects at most three and
   only then counts, so the halt names a defect of the fold; it is never
   clamped and the row is never skipped.

Checks 1 and 3 are one store-invariant row, `SI-25`
(`STORE_INVARIANT_REGISTER.md`), with the fact that an epoch settles
once. Check 2 lands with admission.

Nothing is re-derived at settlement. Check 1 costs one hash per issued
draw over the stored index. The selection reads that index and then keeps
a subset; the hash covers the index, not the subset. The walk's time on the
floor device is not measured
([`BENCHMARK_ALIGNMENT.md`](BENCHMARK_ALIGNMENT.md) `BA-T32`). The digest
does not cover the per-block counts, which admission reads and settlement
does not.

---

## 10. The issued-draw index

**Chosen: stored, revertible consensus state.** Recomputing is not
available. `count(h)` depends on the counts of the previous `W₂` blocks
and on the visible shortfall, each of which depends on earlier counts
back to `h_open(E)`. And admitting a record for `h` needs the issued
counts as they stood at `h`, up to `W₂` blocks in the past.

Two tables and one cell, all written in the connect batch and undo-logged
with it:

- **Per block `h`:** `count(h)`, `carry(h)`, the visible shortfall at
  `h`, and whether `h`'s seed has been revealed.
- **Per pair, per epoch:** its issued draws as `(h, j, h_reveal, passed)`,
  where `h_reveal` is the block that first admitted `h`'s seed and
  `passed` is whether a record for the draw has been admitted. The count
  visible at any `h′` is the number with `h_reveal < h′`. The first
  carrier for `h` derives every draw of `h` and writes them all. The
  store keys the rows `(E, P, s, h, j)`: one epoch is one range, and
  inside it a pair's draws are adjacent in `(h, j)` order.

- **Per epoch, one 32-byte cell: the running digest of the issued
  draws.** It starts at zero. Each issued draw adds

  ```text
  cSHAKE256_32("shekyl/archival-issued-index-v1",
               p_canonical_id[32] ‖ shard_id_le[8] ‖ E_le[8] ‖ h_le[8] ‖ j_le[4])
  ```

  to it as a 256-bit little-endian integer, modulo `2^256`. A sum does
  not depend on order: admission folds draws in the order blocks reveal
  them, and settlement walks them pair by pair. It guards a local store
  against its own drift, so it is not asked to resist an adversary who
  chooses the draws.

  Vectors, `E = 5`, `shard_id = 7`: the draws `(0x44×32, h = 1,000,000,
  j = 0)`, `(0x44×32, 1,000,000, 1)` and `(0x45×32, 1,000,001, 0)`. After
  the first the cell is
  `bfd102a54a70d66500e5aa5a15c8e11aa13653be7ea706101c1d0ed6923ffce9`,
  after the second
  `9a32f23e5e03cab824e593d674dc90552ef10973da5a2c90f1ff833854d35941`,
  and after all three, in any order,
  `053b7619b7c9a1dee912ba0905b91ccb33b8eeb958117c98456e36ea41e99ec8`.

A record's admitted pass is the `passed` bit of its draw's index row, and
nothing else (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10c`). The serve-credit
row keyed `(P, s, E, h)` is not kept beside it: admission re-keys or
deletes that table when it lands. The digest covers issuance only, so
setting the bit does not move it.

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

1. **This specification lands before code.**
2. **The settlement writer is wired before the secret draw goes live.**
   The slash fold and accrual read the settlement row with its
   NonObservation floor (§9.4). **Done in the Rust validator**
   (`ARCHIVAL_SETTLEMENT_WRITER.md` §14 and §15). The C++ daemon uses
   "any pass" for both until `DEL-008` (§2).
3. **Production `ContentVerify`** is written against the
   transaction-range unit.
4. **The FN-DSA integration follows**, then the mechanism, in increments,
   each its own PR.

Carried with the implementation:

- **Vectors.** The selection KAT of §4.5, the cap vector included; the
  set-commitment KAT of §7.3; the settlement-selection KAT of §9.3; the
  nonce vectors of §5.2 and the digest vectors of §10; the integrity
  fixture of §9.5 (an index, and separately a `D`, perturbed between
  admission and settlement, each halting the writer); the one-machinery
  test of §5.1, end to end through the challenger's caller; a test-only replay assertion that a
  fixture's carried pairs equal the derived ones; and a fixture that two
  constructions of a block yield distinct seeds, witness keys and `0x0C`
  commitments (§4.2), which fails if either secret is ever derived from
  something two blocks share.
- **`fn-dsa`.** An exact version pin on the crate and its four
  sub-crates. Key-generation **and** verification vectors pinned on both
  x86_64 and aarch64: key generation and verification are integer-only in
  the crate, and signing uses hardware `f64`, so it is the two integer
  paths that must agree across the supported architectures. Landed with
  the scheme ([`FN_DSA_HYBRID.md`](FN_DSA_HYBRID.md) §3). A seeded signing
  vector is pinned beside them and gives the same bytes on x86_64 with
  AVX2, on x86_64 without it, and on aarch64 under emulation; the run on
  aarch64 hardware is owed.
- **FOLLOWUPS:** update `fn-dsa` and regenerate vectors when FIPS 206 is
  final.
- **Genesis gate:** no genesis on a pre-1.0 `fn-dsa`.
- **Census:** a `RowStatus` arm for a row retired by ruling. It names the
  successor rows, and the gate requires each successor `Implemented`.
  CEN-J8, J9 and J10 are the first rows to use it.
- **Registry:** a row in
  [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) for every
  label in §16, landing with its constant. The registry has no status for
  a label without one.
- **Deletions** (§11.1).

### 11.1 Deleted with the implementation, and why

[`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc): a
surface this design replaces is deleted in the change that replaces it,
with the reason recorded, and is not left inert.

| Deleted | Where it is today | Why |
| --- | --- | --- |
| The attestation path's pass records and witness | `rust/shekyl-archival-retention/src/attestation_wire.rs:136-144`, `:214-219`, `:234-236` | The pass is carried by the serve-credit input in a carrier (`SCS-P11`). Two records for one fact is the duplication `SCV-4` found |
| CEN-B4's operand: the block's attestation witness, its root in the header and its verify path | `rust/shekyl-chain-rules/src/block.rs:113-115`; `src/cryptonote_core/blockchain.cpp:5089`; `rust/shekyl-ffi/src/archival_ffi/attestation.rs:161` | With no pass record on the block there is nothing for the root to commit to or the rule to judge |
| The anchor window | `rust/shekyl-archival-retention/src/pass_anchor.rs:113-131` | Admission checks no anchor bound (§9.1); the anchor hash is one lookup by height |
| The public urn | deleted 2026-10-10; was `rust/shekyl-archival-retention/src/challenge_assignment.rs` | Replaced by the secret draw. `DrawablePair` moved to `drawable_pair.rs`. The other rows in this table stay until their implementations land |
| The serve-credit input's leaf-path preimage, its segment path and its split signature legs | `rust/shekyl-archival-retention/src/wire.rs:59-64`, `:81-84`, `:379-402` | The record is `j` kept and the receipt prunable (§7.2); the receipt signs the delivery transcript |
| The beacon's fire height and seal | `rust/shekyl-chain-rules/src/archival/slash.rs:10-11` and the C++ gate at `src/cryptonote_core/blockchain.cpp:4714` | One challenge per pair-epoch is replaced by per-block draws |

The implementing change enumerates the full surface behind each row,
including the peer-to-peer and store fields that carry the attestation
witness.

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
- **"In flight" is unrevealed draws only** (`SCS-P9`). The other reading —
  every draw of the last `W₂` blocks, revealed or not — double-counts
  draws already in the visible counts. Under it the run reads
  1.40 / 2.63 / 6.21 % short.
- **`(m, n)`.** An honest pair at a 0.30 per-read failure misses an
  observed epoch with probability 0.216 under 2-of-3. At `(11, 13)` the
  false-slash bound over the bond's life is `2.85 × 10⁻⁴` per pair, and
  `0.689` for an archiver holding the maximum 4,096 shards, against the
  feasibility module's provisional `10⁻³` per archiver. Neither figure
  depends on the observation rate, so dropout does not move them.

  `0.689` is `1 − (1 − p)^4096`, which treats an archiver's pairs as
  failing independently. One persona serves every shard from one host and
  one onion service, so they do not: the chance of at least one false
  slash can be lower than the figure, and false slashes would come many
  at once. It is an exposure on the module's axis, not a probability.

  That figure credits **one read per draw**. The module credits one try
  because failures inside a single window cluster, so a retry there is
  not an independent try. Under this design the witness reads a draw
  again hours later (§5.3), and whether reads that far apart fail together
  is not measured. The window depends only on `x`, the probability that a
  draw goes unread after all three reads:

  **`(11, 13)` clears the per-archiver budget when `x ≤ 0.2076`**
  (`ESR-11`, sim plan §5.15). That boundary assumes no model of how the
  reads correlate. To show the range, a mixture in which a share `ρ` of
  first-read failures is common to all three reads and the rest are
  independent, at the retained per-read failure `p = 0.30`:

  | `ρ` | `x` | Missed observation | Per archiver at 4,096 shards |
  | --- | --- | --- | --- |
  | 1.00 (the calibration) | 0.300 | 0.216 | `6.89 × 10⁻¹`, exceeds |
  | 0.50 | 0.164 | 0.071 | `8.23 × 10⁻⁶`, clears |
  | 0.25 | 0.095 | 0.025 | `1.07 × 10⁻¹⁰`, clears |
  | 0.00 (independent) | 0.027 | 0.002 | `1.70 × 10⁻²²`, clears |

  `ρ` is not what a run observes. A run observes `p`, `x`, and
  `c = x / p`: of draws whose first read failed, the share whose two
  later reads also failed. In the mixture `c = ρ + (1 − ρ)·p²`, so the
  boundary is `c ≤ 0.692` at `p = 0.30`, which is `ρ ≤ 0.661`.

  **`(m, n)` stays open and is not re-pinned on the one-read figure**
  (ruled 2026-10-07): loosening the window there would weaken the
  detection of pairs that do not serve, to solve a problem the re-reads
  may already solve. `x` at hour-scale spacing is measured first
  ([`BENCHMARK_ALIGNMENT.md`](BENCHMARK_ALIGNMENT.md) `BA-T31`). The
  observation rate is 0.995 / 0.989 / 0.962, so a pair that never serves
  reaches 11 misses in 11.05 / 11.12 / 11.44 epochs.
- **The witness's load is new and unmeasured.** A won block costs its
  producer about 117 to 156 whole-shard reads inside `W₂`. A producer
  with a tenth of the hashrate wins about 50 blocks per window: roughly
  17.6 GB of reads, or 290 KB/s sustained. It is measured on a
  mining-class box, not the floor device, and does not gate
  (`SCS-P10`; [`BENCHMARK_ALIGNMENT.md`](BENCHMARK_ALIGNMENT.md) `BA-T30`).
- **Unpaid service.** A pair that settles NonObservation served the epoch
  for nothing: 0.46 % / 1.10 % / 3.83 % of pair-epochs. Separately, an
  observed epoch settles Missed for an honest pair at 0.216 under the
  0.30 read failure, which is the 2-of-3 rule's cost and is much larger.
  Neither is priced in currency.

The sim does not model the reads, or dropout that is correlated in time
or selective. It runs one epoch from its open, which is the whole state
of the count rule: the carry starts at zero and in-flight stops at the
epoch's open (§4.3), so no epoch's counts depend on the one before.

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
| R8 | `W₂` is the only window. Admission checks no bound on the anchor (`SCS-P7`) |
| R9 | The in-flight count stops at `h_open(E)` (§4.3). Ratified on review |
| R10 | The settlement selection as §9.3 states it: candidate bytes, rejection zone, swap, the cap, and the vectors. Ratified on review |
| R11 | `SO-D8d`'s three integrity layers carry over in the form of §9.5. The first is a running digest folded at admission and checked against every stored issued draw, not only the draws the selection keeps; nothing is re-derived at settlement. Closes `SCS-F11` |
| R12 | The witness reads a draw again when a read ends stall-class, as its own policy above `SF-D6` (§5.3). `(m, n)` is not re-pinned on the one-read figure; the unread share at hour-scale spacing is measured first (§12) |
| R13 | **One request machinery** for every shard fetch: one entry point, a caller-built header, one outcome type, no challenge-only path in the request layer (§5.1) |
| R14 | **A fresh nonce for every read**, for every caller; a challenge's is bound to `(h, j, attempt)`. The record carries `attempt` as one prunable byte and admission refuses `attempt ≥ K`, `K = 3` (`SCS-P13`) |
| R15 | **A fresh circuit per read, by SOCKS credentials**, for every caller: `SF-D3` reopened under rule 21 and ruled (§5.3). The spacing is scheduling only |

### 13.2 Provisional (rule 21; reopen on the sim or on testnet measurement)

| # | Value | Reopen when |
| --- | --- | --- |
| V1 | Full-pair weight 1/16 | A better setting is measured |
| V2 | Count rule of §4.3: base 1 per pair per epoch, catch-up by 70 %, minimum horizon 200, cap 3 × nominal | Same |
| V3 | Bar: at most 3 % of pairs short of 3 at 10 % producer dropout | The sim or testnet exceeds it. The sim reads 1.18 % |
| V4 | Consecutive reads of a draw are at least 30 blocks apart. Challenger scheduling, not consensus | `BA-T31` shows the unread share still falling, or already flat, at a different spacing |

### 13.3 The twelve questions this round posed — RULED 2026-10-07

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P1` | Layout of `0x0C` | **32 bytes, one commitment** over `witness_pk ‖ seed` under its own domain. Every carrier reveals both, so no check needs one without the other. Q13's length stands |
| `SCS-P2` | "Revealed once" against the weight limit | **Each carrier carries the whole seed** |
| `SCS-P3` | Re-derivable coinbase key material | **Dropped; Q10 stands.** The seed and the witness key are fresh randomness per block, independent of each other, in memory only. A value derived from the coinbase shared secret is known to the coinbase recipient. A persistent witness secret is rejected. Loss is harmless: NonObservation, never misses |
| `SCS-P4` | The form of the draw mapping | **Rejection sampling over the static set**, capped at 256 attempts, the cap pinned by a vector (§4.4, §4.5) |
| `SCS-P5` | The record layout | **Kept: input tag and `j`.** `(P, s)` is derived. `h` is the carrier's, beside the seed. Prunable per record: `attempt` (added by `SCS-P13`), `anchor_height`, `delivery_digest`, the receipt. One rule-42 bump for record and carrier. A selection KAT and a test-only replay assertion; no runtime field (§7.2) |
| `SCS-P6` | Q9 bytes | **Amended:** the commitment covers the seed, `h`, and each record's `j` with its prunable fields (§7.3) |
| `SCS-P7` | A bound on `anchor_height` | **None.** The lower bound keyed on `h` is implied by the nonce, which contains `block_hash(h)`, and is not checked (§9.1) |
| `SCS-P8` | `issued` above 255 | **Saturate.** The list of issued draws is the selection's operand |
| `SCS-P9` | The reading of "in flight" | **Unrevealed draws only** |
| `SCS-P10` | The witness's read load | **Measure, do not gate.** A mining-box measurement, filed as `BA-T30`. The count rule is provisional already |
| `SCS-P11` | Which record carries the pass | **The serve-credit input.** The attestation path's pass records and CEN-B4's operand are deleted with reason (§11.1) |
| `SCS-P12` | The height the settlement drop filter reads | **Per draw, at `h`:** the state after `h` connects, strictly above a same-block slash (§9.3) |

---

### 13.4 Posed on review, and ruled 2026-10-07

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P13` | The nonce of a re-read: derived from `(seed, h, j)` alone it would return to `P` an hour later with a new anchor, which only a challenge does | **A fresh nonce for every read, for every caller.** A challenge's nonce takes the read's `attempt`; the record carries `attempt` as one prunable byte; admission recomputes the nonce with one hash and refuses `attempt ≥ K`, `K = 3` (§5.2, §7.2, §9.1) |

---

## 14. Defects found while grounding

Doc against code, or doc against doc, at the pin. A row says so where the
change that carries this specification fixes it; the rest are open.

| # | Finding |
| --- | --- |
| `SCS-F1` | `CRYPTO_DOMAIN_REGISTRY.tsv:104` marks `shekyl/archival-challenge-assignment-v1` `shekyl-live`. Its only caller chain is the urn, which no production code calls |
| `SCS-F2` | `rust/shekyl-chain-store/src/schema.rs:576` cites `db_lmdb.cpp:5471` for `archival_challenge_failed_at_height`. It is at `:5351` |
| `SCS-F3` | `rust/shekyl-tx-builder/Cargo.toml:41` takes `fips204` at a caret requirement; `shekyl-crypto-pq` pins it exactly |
| `SCS-F4` | The brief asks for a registry row for every new label in the spec PR. The registry has no status for a label without a constant, and the gate fails a row whose constant is not in code (`scripts/ci/domain_registry_gate.sh:129-162`). **Accepted 2026-10-07:** the rows land with the constants; §16 lists the labels |
| `SCS-F5` | The brief places both persona keys as "HKDF children of the same per-persona seed in the stake-engine actor". The actor holds no seed: persona keys are derived from the wallet master seed by slot when the engine is assembled, and the actor is handed the derived bundle (`rust/shekyl-engine-core/src/engine/stake_engine/actor.rs:34-35`; `lifecycle/assemble.rs:423`). **Accepted 2026-10-07:** the receipt key is derived the same way, under a new label (§6.3) |
| `SCS-F6` | The brief records that the beacon selection "replaces the 'first three' settlement ruled 2026-10-07". No such ruling was in the decision log at the pin. The entry of 2026-10-07 records both |
| `SCS-F7` | `ARCHIVAL_CHALLENGE_MECHANISM.md` §1 states as settled doctrine that every bonded pair is challenged every epoch. Under the secret draw a share of pairs is not reached (§12), and they settle NonObservation. **Fixed:** the doctrine there now says every pair is drawable and names the unreached share |
| `SCS-F8` | `ARCHIVAL_CHALLENGE_MECHANISM.md` §2 has the pass record "broadcast as a transaction; any miner may include it". Under R-B the record is filed by the producer of `h` in a carrier that producer signs. **Fixed** there |
| `SCS-F9` | `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.6.1 and §7.6.2 distinguished "unpruned validators" from "a pruned node". No such split exists: every daemon prunes (§8). **Fixed:** §7.6.1 is replaced by a pointer here and §7.6.2 says every node verifies at connect |
| `SCS-F10` | `rust/shekyl-wire/src/transaction.rs:202` calls the pruned-record ceiling a twin of a `cryptonote_config.h` constant. `src/cryptonote_config.h:417-423` says it deliberately has no copy there |
| `SCS-F11` | `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §6 (`SO-D8d`) rules three local integrity layers for a writer that re-derives `issued` by replaying the urn: per-record assignment equality, a persisted digest of `D` compared against a re-walk, and `passes ≤ issued`. Under §10 here `issued` is stored at admission and read at settlement, so the first layer has no second derivation to compare. Which layers carry over is not ruled. §6 there is unchanged and says so. **Ruled 2026-10-07 (R11):** the first layer becomes a running digest folded at admission and checked against every stored issued draw, including a draw the selection then drops; the second and third carry over (§9.5). §6.2 of the proposal states the same check |

---

## 15. Documents this replaces, and what stays in them

The mechanism text this specification supersedes is deleted from each and
replaced by a pointer here. Text that describes code as it runs today
stays until that code is deleted (§11.1), and is marked.

| Document | What it still owns |
| --- | --- |
| [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) | The SO-D8 round's standing rulings: R-B, `SO-D8a`–`d`, the drawable set's construction (Q3, §7.4), the dedicated witness key and its `0x0C` home (Q8, §7.5), the carrier's form and fail-whole (Q9, §7.6), the memory-only ring (Q10, §7.7), the `0x0C` content rule (Q13, §7.8), Slice C's plan and evidence list (§8). `SO-D8e`'s urn and ring, Q8's derivation and Q12's bare hash are superseded and gone |
| [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) | The challenge round's doctrine and forks, the read, the 2-of-3 argument (§3), parameter discipline (§9), and its record of the urn as landed code |
| [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) | The fetch client: `SF-D1`–`D13`, the delivery digest and its transcript (`SF-D8`), the client's outcome table (`SF-D6`). Its countersigning key and admission window describe live code |
| [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) | The attestation path as it runs today, and the deletion surface of the round before it |
| [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) | The settlement writer's rulings (`SO-D1`–`D7`): enumeration, key and value, when it runs |

--- | --- |
| [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) | The SO-D8 round's rulings (R-B, `SO-D8a`–`e`, Q3, Q8–Q13), the drawable set's construction (§7.4), carrier semantics (§7.6.2), Slice C's plan and evidence list (§8) |
| [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) | The challenge round's doctrine and forks, the 2-of-3 argument (§3), parameter discipline (§9) |
| [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) | The fetch client: `SF-D1`–`D13`, the delivery digest and its transcript (`SF-D8`), the client's outcome table (`SF-D6`) |
| [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) | The credit-wire round's record of the deleted mechanism and the deletion surface |
| [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) | The settlement writer's rulings (`SO-D1`–`D7`): enumeration, key and value, when it runs |

---

## 16. Labels this specification mints

Each row lands with its constant. Four have: the settlement selection and
the issued-index term (`rust/shekyl-archival-retention/src/settlement_select.rs`,
2026-10-08), and the two scheme domains (`SCHEME_DOMAIN_RECEIPT`,
`SCHEME_DOMAIN_WITNESS_CARRIER` in `rust/shekyl-crypto-pq/src/signature.rs`,
2026-10-09). The rest have no constant or registry row yet.

| Label | Mechanism | Use |
| --- | --- | --- |
| `shekyl/archival-draw-commit-v1` | cSHAKE256 | The `0x0C` commitment over `witness_pk ‖ seed`, §4.2 |
| `shekyl/archival-draw-v1` | cSHAKE256 | Selection stream, §4.4 |
| `shekyl/archival-challenge-nonce-v1` | cSHAKE256 | Challenge nonce, over `(seed, block_hash(h), j, attempt)`, §5.2 |
| `shekyl/archival-issued-index-v1` | cSHAKE256 | One issued draw's term in the epoch's running digest, §10 |
| `shekyl/archival-settlement-select-v1` | cSHAKE256 | Counted-draw selection, §9.3 |
| `shekyl/archival-serve-credit-batch-v1` | cSHAKE256 | Set commitment, §7.3 |
| a receipt-key label | HKDF info | The persona's receipt key, from the master seed, §6.3 |
| `shekyl/archival-receipt-scheme-v1` | signature domain | Receipts under scheme 3, §6.2 |
| `shekyl/archival-witness-carrier-scheme-v1` | signature domain | The witness signature under scheme 3, §7.3 |

The HKDF string is named when its constant lands.
The seed and the witness key have no label: they are fresh randomness.

---

## 17. Wargames

| Attack | Outcome |
| --- | --- |
| Grind the seed offline | Useless: draws depend on `block_hash(h)` |
| Withhold a mined block to re-roll draws | Costs a block reward |
| Never reveal | NonObservation only; no misses |
| Reveal but omit a pass | A manufactured miss, contained by 2-of-3 |
| Reveal before reads finish | Exposes that block's remaining reads; the client's ordering rule prevents it |
| Producer offline mid-reads, or restarted | Not resumable: the seed and the witness key were in memory only. NonObservation for that block; the count rule tops the shortfall up |
| Knock a producer offline | Suppresses observations only; cannot target a `P` |
| One receipt for two draws | Impossible: the nonce is bound to `(h, j)` |
| Fingerprint challenge requests | Prevented only by one client code path and identical formats |
| Remember nonces, stall every first request, serve only a nonce that returns | A returning nonce does not mark a challenge. Inside one read the stall retries repeat the nonce, seconds apart, and an organic read retries the same way, so `P` serving a returning nonce serves every caller's retries alike. Across reads nothing returns: a challenger's re-read carries a fresh nonce, as every new read does (`SCS-P13`) |
| Stall every first request for a shard and serve the second | Costs `P` nothing against a challenger that re-reads, and degrades every organic reader the same way; `P` cannot tell which requests are challenges, so it cannot aim it |
| File a record for a fourth read | Refused: `attempt ≥ K` |
| Link a producer's reads, or a re-read to the read that failed, by the circuit they arrive on | Prevented: every read presents its own SOCKS credentials and rides its own rendezvous circuit (`SF-D3`) |
| Flood `P`'s onion so honest reads fail for months | The operator must be able to see it and act; that visibility is not built (FOLLOWUPS, *Operator visibility of serving attacks and slash risk*) |
| An honest pair misses reads on a bad day and walks toward a slash | Up to three reads of a draw, spread across `W₂`; how far that goes depends on how often all three fail, which is unmeasured (§12) |
| Learn mid-epoch that the epoch is settled, then stop serving | Prevented: the three counted draws are selected at close |
| Read the public draw count to see that challenges have stopped | Prevented: the base rate keeps draws flowing to the end of every epoch |
| Derive the witness key from a revealed seed and author carriers, or `P` signs its own receipt | Prevented: the seed and the witness key are independent random values (§4.2) |
| Steal a producer's long-lived secret and learn every future seed | No such secret exists: nothing is derived and nothing is persisted |
| The coinbase recipient learns the seed early | Prevented: the seed is not derived from the coinbase shared secret |
| A record names a pair the draw did not select | Impossible: the record names only `j`; the pair is derived |
| Run the selection loop without bound | Prevented: the 256th attempt selects |
| File one of a block's two carriers and withhold the other | The same as omitting passes: manufactured misses, contained by 2-of-3 |
| Re-roll the settlement beacon | Costs the beacon block's producer a block reward |
