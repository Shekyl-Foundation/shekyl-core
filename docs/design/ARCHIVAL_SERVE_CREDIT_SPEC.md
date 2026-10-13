# Archival serve credit — specification

**Status:** OPEN — Round 0 of SO-D8 Slice C. **RULED 2026-10-07** (the
secret per-block draw, §13.1–§13.4) and **re-ruled 2026-10-11** (one bundle
per block replaces the carrier transaction, §13.5). Six questions found
while writing that in were ruled 2026-10-12 (§13.6). One raised on
review is ruled (§13.7), and two defects found on review are amended
(§13.8). Built so far: the draw's functions, the
settlement selection and fold, the issued-draw tables behind a test door,
and the FN-DSA scheme with the receipt key's derivation (§2). No block path
issues a draw or admits a pass.

**Authority.** This is the single specification of the serve-credit
mechanism: draw, request, receipt, bundle, admission, miss derivation and
settlement. Where another document states the mechanism differently, this
one governs and the other is a record of how the design got here. Decision
history stays where it is: the decision log
([`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md)) and the ruling
records in the round documents listed in §15.

**Pin.** Every statement about what the code does today is cited
`file:line` at `dev@834471689` and is collected in §2. Everything else is
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
4. **Bundle.** Within `W₂` blocks the producer files one bundle for `h`:
   the seed, the witness key and signature, and every receipt it holds.
   Any later miner includes it beside the block it builds.
5. **Admission.** Every node checks, when the including block connects:
   that the seed is the one committed, which pair each draw selects, and
   that each pass's receipt covers its pair. A bundle is admitted whole or
   not at all. Nothing in it names a pair; the pair is derived.
6. **Issuance and misses.** Every draw of `h` is *issued* when `h`'s
   bundle is admitted. A draw with no receipt in the bundle is a miss. A
   block with no bundle by `h + W₂` issues nothing. Nobody asserts a miss.
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

## 2. What the code does today (at `dev@834471689`)

This section is the only place the document describes current behaviour.
It was re-read whole at this pin on 2026-10-11. Four clauses were carried
from the previous pin without re-reading the code behind them: the serving
route's behaviour, that the coinbase secret is not retained, the 2-pass
threshold inside `SettlementRow::settle`, and the body of the C++ accrual.
The settlement lane's `SO-D12` increment 1 (PR #1032) merged on
2026-10-12, after that re-read. The two rows it changed, the `0x0C` tag
and the draw state inside *Settlement rows*, were re-read at
`dev@ea08906388` and say so; every other row stands at the pin above.

| Subject | Today | Where |
| --- | --- | --- |
| Live challenge mechanism | One beacon challenge per pair-epoch: the gate derives `h_fire` and the leaf index itself. No producer bounds how many blocks may challenge a pair; the gate names the secret-draw producer and the admission cutover as the blocker | `src/cryptonote_core/blockchain.cpp:4636-4641`, `:4724`, `:4757` |
| The public urn | Deleted 2026-10-10. It had no production caller. `DrawablePair` stays, in its own module. The secret draw's hash side replaced the selection; the draw producer is not live. One C++ header comment still names `assign_epoch` as existing in Rust | was `rust/shekyl-archival-retention/src/challenge_assignment.rs` (grep for `challenge_assignment`: one doc comment, `drawable_pair.rs:8`); `rust/shekyl-archival-retention/src/drawable_pair.rs:17`; `src/cryptonote_core/blockchain.cpp:4636`; `src/blockchain_db/blockchain_db.h:2012` |
| Drawable set | `DrawableSet::at_epoch_open` is built and has no caller outside its own tests. It enumerates tip bonds. The journal walk that recovers a Release or a slash is not built. The slash pass reads the slash log per draw to decide which draws count; it does not build the set | `rust/shekyl-chain-rules/src/archival/drawable.rs:27`, `:44`, `:9-13`; `rust/shekyl-chain-rules/src/archival/slash.rs:361`; `rust/shekyl-archival-retention/src/held_at_height.rs:104` |
| Assignment cache, membership check | Not in code | grep for `EpochAssignmentCache`, `is_assigned`: no hits |
| Serve-credit acceptance | One C++ gate. The Rust validator has no rule for CEN-J8–J10 | `src/cryptonote_core/blockchain.cpp:4591`, `:4603` (called `:3513`); `rust/shekyl-chain-rules/src/census.rs:502-504` |
| Serve-credit dedup | Pair-epoch-wide: any earlier pass for `(P, s, E)` refuses the next | `src/cryptonote_core/blockchain.cpp:4650` |
| Serve-credit vin record | Kept: `p_canonical_id`, `shard_id`, `settlement_epoch`, a 64-byte Ed25519 leg. Pruned: a segment path and a 3,309-byte ML-DSA leg. The signed preimage is over a leaf path | `rust/shekyl-archival-retention/src/wire.rs:59-64`, `:81-84`, `:379-402` |
| Receipt (`SF-D8` v3) | `P` signs `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id ‖ delivery_digest`, 112 bytes, under `shekyl/archival-attestation-scheme-v3`, with the identity key under scheme 1. Carried on the block-level attestation record, a different record from the vin. `SCHEME_DOMAIN_RECEIPT` (scheme 3) is defined; nothing outside tests signs or verifies under it | `rust/shekyl-archival-retention/src/pass_anchor.rs:64-65`, `:355-372`; `attestation_wire.rs:138-146`; `rust/shekyl-crypto-pq/src/signature.rs:116`, `:124`; `rust/shekyl-p-serve/src/countersign.rs:171-175` |
| Block attestation (CEN-B4) | A Rust rule, `rules::attestation::B4`, registered `implemented`. Its one caller is main-chain `validate`. The C++ path still verifies through the FFI, on the main and the alt chain | `rust/shekyl-chain-rules/src/rules/attestation.rs:79`, `:85-86`; `census.rs:334`; `validate.rs:415`; `block.rs:118`; `src/cryptonote_core/blockchain.cpp:4979`, `:5057` (called `:2135`, `:5138`) |
| Anchor window | `L + 1` hashes for `[h − 720 − L, h − 720]`, keyed on the including block's predecessor. `L = 4`, depth 720 | `rust/shekyl-archival-retention/src/pass_anchor.rs:70`, `:73-74`, `:122-132`; `config/consensus_constants.json:33`, `:36` |
| Serving route | Single-pass serve, 400 / 404 / 503, refusal trailer, signature over the delivery digest as the last bytes | [`ARCHIVAL_SERVING_ROUTE.md`](ARCHIVAL_SERVING_ROUTE.md) |
| `P`'s serving key | Wired. The serving task is given `ResidentPassKey`: a weak handle to the stake actor, which signs the transcript with the identity key (`hybrid_sign_sk`). The receipt key is derived into `ArchivalPKeys` (two HKDF labels); nothing signs with it | `rust/shekyl-engine-core/src/engine/stake_engine/serving/start.rs:257`; `serving/pass_key.rs:70`, `:103`; `rust/shekyl-crypto-pq/src/archival_p.rs:224`, `:229`, `:596-599`, `:762` |
| Coinbase tag `0x0C` | Exists, and is required in every coinbase (CEN-I20, `implemented`): one 32-byte draw commitment, in a fixed place in the coinbase's tag order. Rust's coinbase writer draws it. Nothing reads it back as a commitment to open: no verifier is on the connect path (re-read at `dev@ea08906388`) | `rust/shekyl-wire/src/tx_extra/mod.rs:86` (`TX_EXTRA_TAG_DRAW_COMMITMENT`); `tx_extra/coinbase.rs:66` (`COINBASE_TAGS`); `rust/shekyl-chain-rules/src/rules/tx_extra.rs:111` (`I20`); `census.rs:493` |
| Witness key, witness seed ring | Not in code. `draw_commit` takes a witness key as bytes and `ChallengeDraw` carries a `seed` field; nothing derives, generates or holds either. `SCHEME_DOMAIN_WITNESS_CARRIER` is a label with no signer | grep for `derive_witness_keypair`, `LABEL_WITNESS`, `WitnessRing`, `seed_ring`, `draw_seed`, `witness_key`: no hits; `witness_pk`: `rust/shekyl-archival-retention/src/secret_draw.rs:115` only; `rust/shekyl-archival-fetch-sched/src/read.rs:391-393`; `rust/shekyl-crypto-pq/src/signature.rs:128` |
| The draw's functions | Built, with this document's vectors pinned in the module: `select_draw`, `draw_commit`, `challenge_nonce`, `serve_credit_batch_commitment`, `draw_horizon`, `draw_count`. Only `challenge_nonce` has a caller outside tests, `ChallengeDraw::nonce` under `challenge_read`, and `challenge_read` has no caller outside tests. The other five reach only the crate's re-export | `rust/shekyl-archival-retention/src/secret_draw.rs:79`, `:115`, `:127`, `:141`, `:164`, `:186` (vectors `:239`, `:396`, `:417`); `lib.rs:207-211`; `rust/shekyl-archival-fetch-sched/src/read.rs:406-407`, `:436` |
| Coinbase transaction secret | Random per block and not retained. The Rust builder takes it from the caller; the C++ builder generates it | `rust/shekyl-block-template/src/lib.rs:193-196`; `src/cryptonote_core/cryptonote_tx_utils.cpp:79` |
| Settlement fold | `settle_pair`: three of a pair's counted draws selected by the beacon, NonObservation below 3, Served at 2 passes among the three, else Missed (§9.3). The Rust slash pass calls it for every pair with a draw in the epoch | `rust/shekyl-archival-retention/src/settlement_select.rs:150` (`select_counted` `:75`); `rust/shekyl-chain-rules/src/archival/slash.rs:215`, `:270` |
| Settlement rows | The Rust slash pass writes one per pair with a counted draw, ahead of the slash it decides. The issued-draw index and its digest (§10) have no block writer; a Fakechain-only door, `regtest_issue_draws`, is their one writer and is not journaled. The per-block draw state (`count`, `carry`, the shortfall, `revealed`) and the drawable set's digest are shaped as tables with view reads (`ChainView::block_draws`, `drawable_digest`) and have no block writer (re-read at `dev@ea08906388`: `rust/shekyl-chain-store/src/schema.rs:768`, `:777`; `rust/shekyl-chain-rules/src/view.rs:581`, `:587`). The C++ store keeps the table's handle with no writer; a revert and a prune delete remain | `rust/shekyl-types/src/archival/settlement.rs:137`; `rust/shekyl-chain-store/src/schema.rs:580`, `:733`, `:742`; `rust/shekyl-chain-store/src/store/archival_write.rs:357` (`write_settlements`), `:609` (`regtest_issue_draws`), `:599`; `rust/shekyl-chain-ingest/src/connector.rs:490`; `rust/shekyl-chain-store/src/archival_snapshot.rs:224` (`disposition`); `src/blockchain_db/lmdb/db_lmdb.cpp:1693`, `:6622`, `:6784` |
| Slash fold | Rust: reads the settlement row; Missed is the only candidate. C++, consensus until `DEL-008`: reads "any pass" on the one-challenge beacon | `rust/shekyl-chain-rules/src/archival/slash.rs:410`, `:424`; `src/blockchain_db/lmdb/db_lmdb.cpp:5298`, `:5308` (`archival_challenge_failed_at_height`) |
| Accrual | Rust: a pair earns for an epoch iff its settlement row is Served; the slash pass gathers, an epoch after the close (`ARCHIVAL_SETTLEMENT_WRITER.md` §15). C++, consensus until `DEL-008`: on "any pass", at the close | `rust/shekyl-chain-rules/src/archival/close.rs:501`, `:514` (`Transition::gather`); `src/blockchain_db/lmdb/db_lmdb.cpp:7510` (`process_archival_epoch_close_at_height`) |
| Failure window | `m = 11`, `n = 13`. `BaselineObservation` is two-valued. The Rust slash pass gathers through `settlement_window_slashable`, which passes over a NonObservation row and an absent row. The C++ path marshals the two-valued form | `config/consensus_constants.json:46-47`; `rust/shekyl-archival-retention/src/failure_window.rs:357-363`, `:461`, `:507`, `:544`; `rust/shekyl-chain-rules/src/archival/slash.rs:455` |
| Signature schemes | The canonical encoding carries a scheme byte: 1 (Ed25519 + ML-DSA-65), 2 (multisig container), 3 (Ed25519 + FN-DSA-1024). Scheme 3's one consumer outside tests is the receipt key's generation in `ArchivalPKeys`. `verify_pqc_auth` refuses it | `rust/shekyl-crypto-pq/src/signature.rs:66-67`, `:74`, `:169-174`, `:516-529`; `multisig.rs:18`; `fn_dsa_hybrid.rs:269`, `:344`; `archival_p.rs:762` |
| Bond record | Two key fields: the identity key (`hybrid_pubkey`), from which `p_canonical_id` is derived, and the debit authorizer (`bond_spend_pk`). No receipt-key field | `rust/shekyl-types/src/archival/bond.rs:262-269`; `rust/shekyl-archival-retention/src/id.rs:21` |
| `RowStatus` | Five arms: `Pending`, `Implemented`, `EnforcedAt`, `ByConstruction`, `HeldByCxx`. None for a row retired by ruling | `rust/shekyl-chain-rules/src/census.rs:62-125` |

---

## 3. Terms and parameters

File names without a directory are under
`rust/shekyl-archival-retention/src/`.

| Symbol | Meaning | Value | Source |
| --- | --- | --- | --- |
| `E` | Settlement epoch | — | `epoch(h)` under the rule set's schedule |
| `SEB` | Blocks per epoch | 10,000 | `SETTLEMENT_EPOCH_BLOCKS`, `constants.rs:245` |
| `h_open(E)`, `h_close(E)` | First and last block of `E` | — | the settlement schedule |
| `W₂` | Blocks within which the bundle for `h` is admissible | 500 | `CHALLENGE_RESPONSE_BLOCKS`, `constants.rs:180-186` |
| `D` | The drawable set of `E`: the pairs held at `h_open(E)`, in canonical order. In a formula, `D` is the set's size | — | §4.1 |
| `delivery_digest` | The 32-byte digest of the response `P` delivered, salted with the nonce. `SF-D8` writes it `D`; this document does not | — | [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) `SF-D8` |
| `h` | The block whose producer draws | — | — |
| `h_incl` | The block that includes `h`'s bundle | — | — |
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
| `M` | Blocks before the end of `W₂` by which the challenger files a bundle. Challenger policy, not consensus | 30 | PROVISIONAL (§13.2) |
| `c` | The bundle section's budget, as a multiple of the count cap | 2 | PROVISIONAL (§13.2) |

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
witness key from a revealed seed could author a bundle for `h`, and `P`
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
(1,837 bytes, fixed) and `seed` the 32 bytes. The bundle reveals both,
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
`(seed, block_hash(h), j)` and the issued counts visible at `h`. A pass is
one bit at position `j` of the bundle's bitmap (§7.2). Nothing names a
pair, so nothing can name the wrong one.

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
- **Ordering.** The client builds no bundle for `h` until every read of
  `h` has completed or been abandoned. A bundle reveals the seed, and
  the seed exposes that block's remaining reads.
- **Filing.** The client files the bundle by `h + W₂ − M`, with `M = 30`
  blocks (PROVISIONAL, §13.2), so that inclusion latency and an ordinary
  reorg leave it inside its window. A bundle with no passes is filed all
  the same (§7.1).

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
  and for the witness's signature on the bundle. Ruled (§13.1).
- **Implementation.** The `fn-dsa` crate, pinned to an exact version with
  its four sub-crates. The crate is pre-standard: its keys and signatures
  will change when FIPS 206 is final. §11 carries the FOLLOWUPS row and
  the genesis gate.
- **Signature domain.** A new scheme domain for the receipt under scheme
  3, `shekyl/archival-receipt-scheme-v1`; the witness's signature on the
  bundle has its own, `shekyl/archival-witness-bundle-scheme-v1`, minted
  with its constant when the verifier is built. The bundle commitment is
  a different message from the carrier's set commitment, so it does not
  take the carrier's label, `shekyl/archival-witness-carrier-scheme-v1`;
  that constant has no signer and is not used for the bundle. One label
  never names two messages or two schemes
  ([`30-cryptography`](../../.cursor/rules/30-cryptography.mdc)).
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
  **It is mandatory** (ruled on review of PR #1046, 2026-10-12): there is
  one JoinMarket form and it carries the key, and the record's field is
  typed and fixed-length. A pair whose record had no key would be in `D`
  with no key for the `h_open(E)` snapshot to hold, and the snapshot could
  not be built (§9.6), which would refuse every bundle of that epoch.

The reason is algorithm isolation: persona identity stays on a finalized
standard, and the pre-standard scheme touches only signatures whose value
expires within an epoch. Ruled; it reopens `SF-D13` under rule 21
(§13.1). The receipt key is derived from the wallet master seed when the
engine is assembled, by persona slot and under its own two labels, one for
each half of the hybrid, exactly as the identity key is
(`shekyl-archival-p-receipt-ed25519-v1`,
`shekyl-archival-p-receipt-fn-dsa-1024-v1`; `ARCHIVAL_P_RECEIPT_ED_INFO` and
`ARCHIVAL_P_RECEIPT_FN_DSA_INFO` in `rust/shekyl-crypto-pq/src/archival_p.rs`).
It shares no seed with the identity key. The stake-engine actor is handed the derived keys
and holds no seed; the serving task receives a signing capability and
never a key.

---

## 7. The bundle

Ruled 2026-10-11 (`SCS-P14`–`SCS-P31`, §13.5). The carrier transaction
this section used to specify is gone, with the defect that removed it
recorded as `SCS-F13`.

### 7.1 One object per block

The bundle for block `h` is one object:

- the **reveal**: the seed of `h`, `h`, the witness public key, and one
  witness signature over the bundle commitment (§7.3);
- the **pass bitmap**: exactly `count(h)` bits, bit `j` set when draw `j`
  has a record;
- the **records**: one per set bit, in ascending `j`.

Rules:

- **Whole or not at all.** A block admits a bundle with every record, or
  does not admit it. There is no state in which `h`'s seed is revealed and
  some of its records are pending.
- **One per `h`.** A chain admits at most one bundle for `h`.
- **A bundle with no passes is valid, and where `count(h) > 0` it is
  required of an honest producer.** It is what issues `h`'s misses
  (§9.2).
- **A block with `count(h) = 0`** has a bundle with an empty bitmap. It is
  valid, issues nothing, and marks `h` revealed. Accepting it keeps the
  rule uniform; a producer does not file it, which is challenger policy
  (`SCS-P33`). It still costs one unit of the section budget (§7.4,
  `SCS-P40`), so it cannot be used to fill a section for free.
- **The reveal and its records are one object**, so the seed is never on
  chain without them. Nothing is revealed per draw.
- **Only the producer can author a bundle**, because the witness signature
  covers every byte of it. Anyone may relay one or include it in a block.
- **A refused bundle is a producer defect.** The producer corrects and
  files again. The seed and the witness key stay in the ring (§4.2) until
  the bundle is included, so it can.
- **A bundle is not a transaction.** It has no inputs, no outputs and no
  fee, takes no part in the fee median or the penalty curve, and displaces
  no fee-paying transaction. Its space is budgeted on its own (§7.4).

The bundle for `h` is admissible only in a block `h_incl` with
`h < h_incl ≤ h + W₂`.

### 7.2 Kept and prunable parts

| Part | Field | Width |
| --- | --- | --- |
| Kept | seed | 32 |
| Kept | `h` | 8 |
| Kept | `count` | 4 |
| Kept | pass bitmap | `⌈count / 8⌉` |
| Prunable, once | witness public key | 1,837 |
| Prunable, once | witness signature | 1,356 |
| Prunable, per record | `attempt` | 1 |
| Prunable, per record | `anchor_height` | 8 |
| Prunable, per record | `delivery_digest` | 32 |
| Prunable, per record | receipt signature | 1,356 |

- **A record names nothing.** Its `j` is the position of its bit. `(P, s)`
  is derived from `(seed, block_hash(h), j)` (§4.4). `E = epoch(h)`. The
  nonce is recomputed from the seed, `j` and the carried `attempt` (§5.2).
- **The kept part states its own `count`** (`SCS-P39`). A bitmap's bytes
  do not say how many bits it has: 13 bytes fit any count from 97 to 104.
  With `count` beside it the kept part parses on its own, the padding
  bits are checkable with no chain, and a section's draws can be summed
  from its references alone. Admission holds the stated `count` to
  `count(h)` (§9.1 step 3).
- The bitmap has a fixed length, so there is no list of `j` to frame and no
  repeat to refuse.
- Every record is the same width, 1,397 bytes.
- One rule-42 version bump covers the bundle.

**The bitmap** (`SCS-P35`): draw `j` is bit `j mod 8` of byte `⌊j / 8⌋`,
least significant bit first. Padding bits are zero, and a set padding bit
refuses the bundle. **The records** follow in ascending `j` over the set
bits, and their number equals the number of set bits; any other count
refuses.

### 7.3 The bundle commitment and the header root

Ruled:

- **The witness signs one commitment over the whole bundle**: the seed,
  `h`, the bitmap, and every record in order.
- **The block header's root covers each bundle the block admits**, in
  ascending `h`. Each bundle contributes its kept bytes and
  `cSHAKE256_32` of its prunable bytes.

The commitment (`SCS-P35`, ruled 2026-10-12):

```text
cSHAKE256_32("shekyl/archival-serve-credit-bundle-v1",
             seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap ‖ r₁ ‖ … ‖ rₙ)
```

which is the kept part followed by the records, with `count` the kept
part's, the bitmap `⌈count / 8⌉` bytes, and each record
`attempt[1] ‖ anchor_height_le[8] ‖ delivery_digest[32] ‖ receipt[1,356]`.

- **Nothing is framed, and that rests on one fact:** every record is the
  same width. `count` fixes the bitmap's length, the bitmap's set bits fix
  the number of records, and 1,397 bytes fixes where each ends. The width
  is fixed because FN-DSA-1024's signature is padded to 1,280 bytes and
  the canonical hybrid encoding is fixed-length (§6.2). **A scheme whose
  signature is not fixed-width breaks this construction**, and needs
  frames or a different commitment along with its version bump.
- **A new label.** The bundle commitment does not take
  `shekyl/archival-serve-credit-batch-v1`: one label never names two
  messages. That label, `serve_credit_batch_commitment`
  (`rust/shekyl-archival-retention/src/secret_draw.rs`), its vectors and
  its registry row are superseded and stay in the tree beside the new
  ones (§11.1, re-ruled 2026-10-12); nothing calls them.
- **The header field is renamed** (`SCS-P34`): the block header's
  `attestation_root` becomes `bundle_root`, in the same rule-42 bump that
  changes what it commits to. The field keeps its place; it does not keep
  a name for a value it no longer holds.
- **The prunable hash and the header root**, fixed with the verifier's
  implementation (PR #1047, open):

  ```text
  prunable_hash = cSHAKE256_32("shekyl/archival-bundle-prunable-v1",
                               witness_pk[1,837] ‖ witness_sig[1,356] ‖ r₁ ‖ … ‖ rₙ)

  root = cSHAKE256_32("shekyl/archival-bundle-root-v1",
                      n_le[4] ‖ ref₁ ‖ … ‖ refₙ)
  refᵢ = seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap[⌈count / 8⌉] ‖ prunable_hash[32]
  ```

  A reference is self-delimiting, because it states its `count`
  (`SCS-P39`), so the root needs no length frame and is recomputable on
  an alternative block with no chain (§9.1). The verifier on PR #1047
  was first built with each reference framed by its byte length, before
  the count was in the kept part; it moves to this form with that PR.
  The vectors for all three hashes are pinned in the verifier's tests.

### 7.4 Size and the section budget

Per record: 1,397 B, all prunable. Per bundle: `44 + ⌈count(h) / 8⌉` B
kept; 3,193 B of witness key and signature plus 1,397 B per pass,
prunable.

| Draws at `h`, all passed | Kept | Prunable |
| --- | --- | --- |
| 97 | 57 B | 138,702 B |
| 117, the sim's mean at no dropout (§12) | 59 B | 166,642 B |
| 156, the sim's mean at 30 % dropout | 64 B | 221,125 B |
| 292, the count cap at `D` = 324,000 | 81 B | 411,117 B |
| 2,791, the count cap at `D` = 3,100,000 | 393 B | 3,902,220 B |

The count cap is `⌊9·D / SEB⌋ + 1`: the per-block target is at most
`9·D / SEB` and the carry adds less than one (§4.3).

**The section budget is counted in draws, and every bundle costs at least
one.** A bundle is charged `max(count, 1)`. The charges of the bundles a
block `b` admits sum to at most

```text
c · (⌊9·D / SEB⌋ + 1)
```

with `c = 2` (PROVISIONAL, §13.2) and **`D` the largest `D` among the
epochs of the bundles in the section** (`SCS-P20`, `SCS-P33`). That is `c`
bundles at the count cap for any `D`: without the `+ 1` a network below
about 555 pairs could never admit one. A section spans at most two epochs,
because `W₂ < SEB`. It is one addition per bundle, and the bytes follow
from it.

**Why at least one** (`SCS-P40`). A zero-draw bundle is admissible
(§7.1), and charged by its draws it would cost nothing: one block could
then carry one for every zero-draw block of the last `W₂`, up to 500
bundles, 1.6 MB of bodies and 500 witness-signature verifications, under a
budget meant to hold a section to `c` bundles at the count cap. Charged
one, a block admits at most `c · (⌊9·D / SEB⌋ + 1)` bundles whatever
their draws. That is 2 on a network small enough to have zero-draw
blocks, and at maturity the two-bundles-at-the-cap reading is unchanged,
since a bundle with draws is charged its draws.

- `c` must not bind on the first build. Its value comes from measurement:
  the section's bytes, propagation to Tor peers, the orphan rate, and
  `BA-T33` on the floor device.
- A template takes bundles earliest `h` first.
- `MAX_ATTESTATION_RECORDS = 256` cannot stay a fixed number: the count cap
  passes it at `D` = 324,000.

### 7.5 References, bodies and the queue

A block carries **references**, never bundle bodies.

- **A reference** is a bundle's kept bytes and the hash of its prunable
  bytes: `76 + ⌈count / 8⌉` B, so 76 to 113 B at `D` = 324,000, growing
  with the bitmap (`SCS-F17`).
- **Bodies live in one store keyed by that hash.** A body is fetched when
  needed and accepted on hash equality.
- **A main-chain block pulls its bodies at connect**, normally from the
  local queue. **An alternative block pulls them only at the switch.** An
  alternative chain whose bodies cannot be fetched is never switched to.
- **A node that relays a block must serve its bodies.** Refusing is
  attributable misbehaviour.
- **A body is stored only if** a block with valid proof of work references
  it, or the queue admitted it.
- **The reference's bitmap length fixes the body's maximum size**, so an
  oversized fetch is refused before it completes.
- **Every stored body has a holder**: the queue, an alternative block, or a
  main-chain block not yet past `D_max`. The store's invariant register
  checks it.

**The queue** is the pool's own structure for bundles, separate from
transactions (DRS-E5).

- Admission is the bundle rule of §9.1 run against the tip.
- Keyed by `h`, one per `h`, the first valid one wins. Bounded at `W₂`
  entries.
- An entry leaves when its bundle is admitted on chain, when `h` is
  popped, or when its window closes.
- After a reorg every entry is checked again by the same rule.
- **The bundle of a popped block returns to the queue from the body
  store**, if `h` survives and the window is open. This is this
  document's reading of the two rulings together (a main-chain block not
  past `D_max` holds its bodies; the queue is re-checked after a reorg),
  not a sentence of either; it is what §10's re-admission rests on.
- Persisted, and reconciled at open.

A bundle travels the way a block's origination travels. It has no
Dandelion++ stem: `0x0C` already makes its author public, and the
producer's node broadcast block `h` with no origin protection
(`SCS-P25`).

### 7.6 Retention and sync

- **The prunable part is archival content in the shard domain.** `SHT-Q1`
  defines the domain by "carries prunable data", so bundles join it.
  **Its place in the domain** (`SCS-P38`, ruled 2026-10-12): after the
  transactions of the including block `h_incl`, the block's bundles in
  ascending `h`, which is the order the header root already covers. **Its
  length** is its prunable bytes, `3,193 + 1,397 ·` (set bits): a function
  of the kept bitmap, so a pruned node recomputes it with nothing new
  stored, and the header root binds it. The cumulative-length fold reads
  it at connect and undoes it at pop, as it does a transaction's. That
  formula holds because records are a fixed width (§7.3): a scheme with
  variable-width signatures would need the length stated, not derived.
- **It is kept until past `D_max`**, because a reorg must be able to check
  the bundle again. It is then discarded and filled back from archivers
  like everything else.
- **Sync** is skeleton forward, then backfill: kept bytes are checked
  against the header root, and prunable bytes against the per-bundle hash.
- **For the shard-size derivation:** the largest bundle's length, at the
  count cap with every draw passed, is the maximum-object input `SHT-Q2`'s
  rule needs from this mechanism; it is a function of `D` (§7.4). `SHT-Q2`'s rule that no single object exceeds
  the shard size now has an object that grows.

---

## 8. Kept and prunable data

Every daemon prunes. There is no class of node that keeps everything: a
shard's prunable bodies are discarded at the epoch boundary after its
freeze.

- **At connect, every node that holds a bundle's prunable bytes verifies
  them**: the witness signature and every receipt (§9.1).
- **A node syncing the skeleton** checks each bundle's kept bytes against
  the header root and accepts that history on the chain it follows.
- **A backfilled bundle is accepted on hash equality**: its prunable
  bytes against the term the header root covers (`SCS-P36`). That is the
  whole rule; it is uniform and needs no history. Verifying its receipts
  again is possible while the `h_open(E)` snapshot can still be rebuilt,
  which the bond journals' horizon bounds (`journal_horizon`), and is
  required nowhere. The earlier rule here, "never after the prune", is
  withdrawn (`SCS-P22`).

Settlement runs long after connect and must be computable by a node that
has pruned. It therefore reads only kept data.

- **Kept:** each bundle's seed, `h` and pass bitmap. From these and the
  issued-draw index any node recomputes the draws, each pair's counted
  draws, and which of them passed.
- **Prunable:** the witness key and signature, and each record's receipt,
  delivery digest, `anchor_height` and `attempt`.

The kept bytes are bound twice: by the header root, and by the witness
signature, whose commitment covers them (§7.3).

---

## 9. Admission, issuance and settlement

### 9.1 Admission

Admission is a block rule. A block whose bundle section fails any check
below is invalid; nothing admits part of a section or part of a bundle.
Checks run in this order, and the order decides which refusal a test
observes. Step 7 runs over every record before step 8 runs over any;
within step 8 records go in ascending `j`, each anchor check before its
own receipt. Each refusal is a typed verdict naming its census row.

**The section**, for block `h_incl`:

1. **Form.** The references are in strictly ascending `h`, so no `h`
   repeats. Each reference parses: its bitmap is exactly `⌈count / 8⌉`
   bytes for the `count` it states, with zero padding. The header root
   recomputes from them (§7.3).
2. **Budget.** The sum of `max(count, 1)` over the section, taken from
   the references' stated counts, is within the section budget (§7.4).

Both are computed from the references and nothing else. The budget's
value needs `D`, which is chain state; where that is not known at an
alternative block's arrival, the sum is still taken and its comparison
waits for the switch. A reference that understates its `count` to pass
this sum is refused at step 3.

**Each bundle**, naming `h`:

3. **Structure.** `h < h_incl ≤ h + W₂`. No bundle for `h` is already
   admitted on this chain. The reference's stated `count` equals
   `count(h)`. The number of records equals the number of set bits. `W₂` is the only
   window; there is no separate read window.
4. **Commitment.**
   `cSHAKE256_32("shekyl/archival-draw-commit-v1", witness_pk ‖ seed)`
   equals `h`'s `0x0C`.
5. **Witness signature.** It verifies under `witness_pk` over the bundle
   commitment (§7.3).
6. **Each set bit's pair.** `(P, s)` is derived as draw `j` at `h`
   (§4.4), at the issued counts visible at `h`.
7. **Nonce.** `attempt < K`, or the bundle is refused. The nonce is
   recomputed from `(seed, block_hash(h), j, attempt)` with one hash
   (§5.2).
8. **Receipt.** `P`'s receipt verifies under `P`'s receipt key over the
   transcript of §6.1: the recomputed nonce, the carried `anchor_height`,
   the hash of the block at that height on the connecting chain, the
   derived `shard_id`, and the carried `delivery_digest`.
   **`anchor_height < h`, or the bundle is refused** (`SCS-P32`).

**What a forged bundle can cost a node.** The commitment is checked before
either signature, and until `h`'s producer releases its bundle nobody
else can open `h`'s `0x0C`. After that the seed and the witness key are
public, so anyone can build a body that opens the commitment. What stops
it there:

- **The witness signature is checked next, before any receipt.** A body
  the producer did not sign costs the node one signature verification and
  no receipt verification.
- **A node that already holds a valid bundle for `h` drops any other
  before that check**: the queue is one per `h`, first valid wins (§7.5).
- **A body fetched for a block's reference is checked by hash first**, so
  a mutated body is refused before it is parsed.

So the exposure is one witness-signature verification per forged body, per
node, for the blocks whose valid bundle that node has not yet received:
at most `W₂` heights. It is bounded by the relay layer's ordinary
per-peer limits, not by proof of work.

**The receipt key is read from the `h_open(E)` bond snapshot, the same
snapshot `D` is drawn from** (`SCS-P19`). It is one type with two methods:
the drawable pairs, and each pair's receipt key. The draw and this rule
both take it as their argument, so they cannot read different heights.
There is no setting for the height: a key read anywhere else lets a pair
in `D` lack a key, which would refuse the whole bundle. Bond records are
immutable, and a receipt key does not change for the life of its record.
The settlement filter of §9.3 step 2 is a different question and keeps
its own read at `h`.

**What a bundle's validity depends on:** the chain through `h`, its own
bytes, and that snapshot. Nothing above `h` enters it, apart from the
window and the one-per-`h` rule, so a bundle that was valid in a popped
block is valid again on any chain that keeps `h`, while its window lasts.
The anchor is held below `h` by the rule itself (step 8), not by today's
constants.

**No node can be made to include a bundle, and no rule acts on its
absence** (`SCS-P15`). A block built without a given bundle cannot be told
apart from one whose miner had not received it. Forcing inclusion would
let a producer that withholds its bundle halt the chain. A bundle that no
miner includes through all of `W₂` leaves `h` unrevealed: NonObservation,
never misses.

**Alternative chains** (`SCS-P23`). When an alternative block arrives,
only the stateless checks run: the section's form, the root, and the
budget where `D` is known at or below the fork point. Otherwise the budget
waits for the switch. Everything else runs at the switch, in the full
validate over the switch's batch view. An alternative chain with an
invalid bundle fails there and rolls back, at the cost of a heavier
chain's proof of work. No bond state is rebuilt at the fork point.

**The anchor's bounds** (`SCS-P7`, amended 2026-10-12 by `SCS-P32`).

- **Below:** none is checked. The nonce contains `block_hash(h)`, so no
  receipt for `(h, j)` can predate `h`; `P`'s own gate holds the anchor
  within `L` of `P`'s tip minus the anchor depth at read time.
- **Above:** `anchor_height < h`, checked at admission. It is what makes
  "nothing above `h` enters a bundle's validity" a property of this rule.
  An honest read satisfies it because `W₂ + L ≤` anchor depth, and that
  relation is asserted on every rule set, as rule-set data (rule 71), so
  a set that shortens the epoch or the depth cannot break it silently.
  A Fakechain schedule that breaks it is refused where it is built, as a
  typed error (PR #1047). The daemon's regtest epoch lever does not reach
  that constructor in Rust today; the replay tool's epoch flag is the one
  input that does.

The anchor stays on the wire for `P`'s gate and for organic reads.

### 9.2 Issuance and misses

- Every draw `(h, j)`, for `0 ≤ j < count(h)`, is **issued** when `h`'s
  bundle is admitted.
- A draw whose bit is set is a **pass**. A draw whose bit is clear is a
  **miss**. Both are written in the batch of the block that admits the
  bundle. A miss is the absence of a receipt in the bundle; nothing
  asserts one.
- A block with no bundle admitted by `h + W₂` issues nothing: no passes
  and no misses.

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

### 9.6 The verifier and its two contracts

Three lanes build this mechanism (`SCS-P31`). This slice builds validity:
the pure verifier. The settlement lane (`SO-D12`) builds state: it
implements the view on its store, calls the verifier at admission, and
writes what the verifier returns. DRS-E5 builds transport: the body store,
the queue, references in the alternative store, and the view on the
switch's batch view.

Two types cross those boundaries, and both are defined here before anyone
builds against them: **the view**, which is everything the verifier reads,
and **the kept projection**, which is what it returns for the writer. The
signatures below are the shape. Names can move in review; what each
carries cannot without a change to this section.

**The verifier** lives in `shekyl-chain-rules`. It is a pure function,
names no store type, writes nothing, and is tested against a fixture view.

```rust
/// Stateless: form, the header root, and the budget when `D` is known.
/// Runs on a block's references alone, so it runs on an alternative
/// block at arrival. A reference states its own `count` (`SCS-P39`), so
/// nothing is asked of the chain.
pub fn check_section(
    refs: &[BundleRef],
    header_root: &[u8; 32],
    budget: Option<u64>,          // None: `D` not known here; compared at the switch
) -> Result<SectionCharge, SectionRefused>;   // the sum of max(count, 1)

/// Everything else, for one bundle. Receipts included.
pub fn verify_bundle<V: BundleView>(
    reference: &BundleRef,
    body: &BundleBody,
    h_incl: BlockHeight,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Admitted, BundleRefused<V::Fault>>;
```

A refusal is a typed verdict naming its census row and, for a record, the
draw `j` that failed. Three outcomes are not verdicts on a block:

- **a view fault**, the store's own failure (§9.5);
- **the body is not the one referenced**: its hash is not the reference's.
  The block committed to the reference, and a block whose body cannot be
  had is not connected. This is checked before anything else;
- **the view could not answer** something it should hold: the drawable epoch of
  `epoch(h)`, the hash at `h` or at an anchor, a drawn pair's key, or the
  `0x0C` of a block it holds. Every coinbase carries exactly one `0x0C`
  (CEN-I20), so a known block with none is the view's failure, not the
  block's.

`draw_count(h)` answering "no such block" does refuse the bundle: it names
a block this chain does not have. A `0x0C` that the bundle's seed and
witness key do not open is the refusal of step 4.

**Not in this tree.** The verifier is implemented on PR #1047, which is
open: `check_section`, `verify_bundle`, `open_body`, the bundle's types
and hashes, and census rows CEN-J29 to J37, registered `pending` because
the cutover is what wires it. This section is the contract that PR is
built to; §2 says what the tree itself holds.

**The view.** One method for each thing §9.1 reads, and nothing else.

```rust
pub trait BundleView {
    type Fault;

    /// `count(h)`, as written when `h` connected (§4.3). `None`: no such
    /// block on this chain.
    fn draw_count(&self, h: BlockHeight) -> Result<Option<u32>, Self::Fault>;
    // A draw index `j` is 32 bits (§3), so a count is. A store that holds
    // it wider refuses a value that does not fit; it does not truncate.

    /// `h`'s `0x0C` commitment (§4.2).
    fn draw_commitment(&self, h: BlockHeight) -> Result<Option<[u8; 32]>, Self::Fault>;

    /// The hash of the block at `height` on this chain. Read twice: at
    /// `h`, for the selection and the nonce, and at each record's
    /// `anchor_height`, for the receipt's transcript.
    fn block_hash(&self, height: BlockHeight) -> Result<Option<BlockHash>, Self::Fault>;

    /// Whether the pair at `index` in `D` is visibly short at `h`: fewer
    /// than 3 of its draws in `epoch(h)` issued by bundles admitted in
    /// blocks below `h` (§3). This is the issued counts visible at `h`,
    /// in the one form the selection asks for.
    fn visibly_short(&self, h: BlockHeight, index: u64) -> Result<bool, Self::Fault>;

    /// Whether a bundle for `h` is already admitted on this chain.
    fn revealed(&self, h: BlockHeight) -> Result<bool, Self::Fault>;

    /// The `h_open(E)` drawable epoch: `D`, and each pair's receipt key.
    fn drawable_epoch(&self, epoch: SettlementEpoch) -> Result<Option<&DrawableEpoch>, Self::Fault>;
}
```

- `D`, as a number, is the drawable epoch's length. The view has no second
  source for it.
- Every answer is a function of the chain through `h`, except `revealed`,
  which is the one-per-`h` rule. That is §9.1's reorg property, stated as
  an interface.
- The store's view, the switch's batch view and the fixture each implement
  it. The queue runs the verifier against the tip through the store's.

**The drawable epoch** (`SCS-P19`): the `h_open(E)` snapshot, as one type.
The type is `DrawableEpoch`, not `EpochSnapshot` as this section first
named it: `shekyl-chain-rules` already had an `EpochSnapshot` in its
epoch-close code, and one name must not mean two things in one crate
(renamed on PR #1047, 2026-10-13; §9.6 allows a name to move in review).
It lives in `shekyl-archival-retention`
beside `secret_draw.rs`: that crate already holds `DrawablePair` and the
draw's functions and depends on `shekyl-crypto-pq` for the key type, so
the draw and the verifier reach it without a new edge. `SO-D12`'s
increment 2 builds it.

```rust
pub struct DrawableEpoch { /* private */ }

impl DrawableEpoch {
    /// The epoch this is the `h_open(E)` state of.
    pub fn epoch(&self) -> SettlementEpoch;
    /// `D`.
    pub fn len(&self) -> u64;
    /// The pair at `index` in canonical order (§4.1).
    pub fn pair(&self, index: u64) -> Option<DrawablePair>;
    /// The receipt key of the pair at `index`.
    pub fn receipt_key(&self, index: u64) -> Option<&FnDsaHybridPublicKey>;
}
```

- **A drawable epoch in which a pair has no receipt key cannot be built.** Its
  one constructor takes the epoch, each persona's id with its receipt
  key's bytes, and the pairs, and fails on a pair whose persona has no
  key or a key that does not parse. The settlement lane feeds it from
  each persona's bond record as of `h_open(E)`. So "a pair in `D` lacks a key" is
  not a state the verifier meets.
- **Both methods read one value.** `select_draw` is given `len()`; the
  verifier indexes `pair()` and `receipt_key()` with the index it
  returned. There is no height parameter on either.
- **It must be buildable for an epoch whose bonds have since been
  released or slashed.** That is why `SO-D12`'s Release journal stores the
  whole bond record: the receipt key is rebuilt as of `h_open(E)` with
  the holdings.
- A key is stored per persona and returned per pair; the verifier decodes
  a persona's key once per bundle.

**The kept projection.** What the verifier returns on success, and all the
writer needs.

```rust
pub struct Admitted {
    /// The bundle's kept bytes, parsed: the reference's content.
    pub kept: BundleKept,
    /// One entry per draw `j` of `h`, in order: the derived pair and
    /// whether it passed (`SCS-P37`).
    pub draws: Vec<DerivedDraw>,
}

pub struct BundleKept {
    pub h: BlockHeight,
    pub seed: [u8; 32],
    pub passes: PassBitmap,   // exactly `count(h)` bits
}

pub struct DerivedDraw {
    pub index: u64,           // position in `D`
    pub pair: DrawablePair,
    pub passed: bool,
}
```

- `BundleKept` is the kept part of §7.2 and nothing more. It is what the
  header root covers, what a pruned node retains, and what settlement
  reads.
- The writer turns `draws` into index rows `(E, P, s, h, j) →
  (h_incl, passed)`, folds each into the epoch's digest, marks `h`
  revealed, and updates the visible counts (§10). It derives nothing.
- `draws` is part of the contract (`SCS-P37`, ruled 2026-10-12): without
  it the writer would run the selection a second time for every draw,
  the misses included. One derivation, one KAT.

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
  where `h_reveal` is the block that admitted `h`'s bundle and `passed`
  is the draw's bit in it. The count visible at any `h′` is the number
  with `h_reveal < h′`. Admitting the bundle for `h` derives every draw of
  `h` and writes them all, each with its pass bit. The
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

A pass is the `passed` bit of its draw's index row, and nothing else
(`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10c`). It is written with the row,
from the bundle's bitmap. The serve-credit row keyed `(P, s, E, h)` is not
kept beside it: that table goes with the serve-credit record (§11.1). The
digest covers issuance only, so the bit is not part of it.

**Reorg.** A pop reverts the batch: the reveals a popped block admitted
are un-issued, the counts of blocks above the fork point are discarded
and recomputed on the new chain, and the per-pair lists lose the entries
whose `h` or `h_reveal` was popped. Nothing outlives the block that wrote
it. A bundle that was in a popped block returns to the queue from the
body store (§7.5) and is re-admissible on the new chain if `h` survives and
`h_incl ≤ h + W₂` still holds: nothing above `h` enters its validity
(§9.1). Past its window it is lost, and `h` settles as an unrevealed
block: NonObservation, never misses.

**A pop does not strand the evidence.** DRS-E5 states that as a
requirement on the pop and left the mechanism to this slice
(`DRS_E5_POOL_ALT_PRUNE.md` §3, CEN-K10). The mechanism is the bundle
queue's re-check after a reorg, and the holding store is the body store:
a main-chain block not yet past `D_max` holds its bundles' bodies, so when
it is popped the bodies are still there and their bundles go back to the
queue (§7.5, `SCS-P27`, `SCS-P28`). Every node that connected the popped
block holds them; a node that never saw that block gets the bundle as it
gets any other, from the queue's relay or as a body fetched for the block
that next references it. Nothing is re-filed and nothing is re-signed.

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
   each its own PR. Increments 3 and 4 of
   [`FN_DSA_HYBRID.md`](FN_DSA_HYBRID.md) are this slice's (`SCS-P26`):
   - increment 3 first, the bond record carrying `receipt_sign_pk`, in
     Rust only;
   - then the `h_open(E)` snapshot's receipt-key read and the bundle rule;
   - increment 4's signing capability, with `FND-4`'s one decoded key,
     built here. `P` switches from the identity key to the receipt key
     in the same change as `SO-D12`'s cutover: no verifier accepts an
     FN-DSA receipt before it.
5. **Bundle transport is DRS-E5's**: the queue, the body store and the
   fetch at the switch (§7.5). This slice supplies the rule they run.
6. **The shapes under this slice are the settlement lane's** (`SO-D12`,
   [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) §16):
   the `0x0C` draw commitment, the per-block draw state, the digest of
   `D` and the snapshot. This slice designs against them as inputs, and
   meets them only through the view (§9.6).

**This slice's order of work** (`SCS-P31`):

1. This specification, with the contracts of §9.6.
2. FN-DSA increment 3.
3. The verifier, pure, against the fixture view.
   - Vectors: the bundle commitment, the root over references, the
     bitmap projection, and the selection and nonce KATs re-pinned.
   - Red edits, each of which must turn a test red: a bundle missing one
     record's draw; a key read from any height other than `h_open(E)`; a
     budget sum one over; a reference whose prunable hash does not match
     its body.
4. FN-DSA increment 4's signing capability.
5. The sim, re-run through the production functions. Bundle loss is
   modelled as late, per-block NonObservation against the V3 bar.
   **Prediction, recorded before the run: the `(m, n)` figures of §12 do
   not move**, because they depend on the read-failure rate and not on
   the observation rate.
6. After the build, on testnet: `M`, `c`, `BA-T33`, propagation and the
   orphan rate.

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
  successor rows, and the gate requires each successor `Implemented`, or
  `ByConstruction` where the bundle cannot express the refused case
  (`SO-D9` (i) and membership; `SCS-P30`). CEN-J8, J9 and J10 are the
  first rows to use it. Their successors are block rules (`SCS-P16`).
- **The sim** calls the production draw functions instead of carrying its
  own count rule and selection (`SCS-F15`), with a term for bundles lost
  to a reorg or an expired window. Implemented as a new mode beside the
  old one, `--secret-draw-production` (PR #1050, merged 2026-10-12):
  `ESR-13` (§12).
- **Registry:** a row in
  [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) for every
  label in §16, landing with its constant. The registry has no status for
  a label without one.
- **Deletions** (§11.1).

### 11.1 Superseded surfaces, and when each goes

**Re-ruled 2026-10-12 (maintainer): landed Rust is not deleted to make
room for this design, and C++ goes only when it is unreachable or fully
replaced.** The table below is the list of surfaces the bundle
supersedes. None is deleted by this slice's changes, which are additive
(PR #1046, PR #1047). The fate of each is decided at the settlement
lane's cutover, when the verifier is wired and its replacement is live;
the C++ rows go at `DEL-008`. The change that had begun deleting the
serve-credit input, PR #1043, was closed unmerged.

The column headed "Deleted" reads "superseded" until then.

| Deleted | Where it is today | Why |
| --- | --- | --- |
| The attestation path's pass records and witness | `rust/shekyl-archival-retention/src/attestation_wire.rs:138-146` and its witness types | The pass is carried by the bundle (`SCS-P16`). The attestation record is not reused for it: its parser, its record and its count ceiling are replaced. The header field survives, renamed `bundle_root` (`SCS-P34`) |
| The serve-credit input, the `serve_credit_only` class, and the CEN-J rows that judge them | `rust/shekyl-wire/src/transaction.rs` (`ServeCredit`, `is_serve_credit_only`); `rust/shekyl-chain-rules/src/rules/tx.rs` (`TxClass::ServeCreditOnly`) | `SCS-P16`. Superseded, not deleted: its fate is decided at the cutover, beside the verifier |
| The C++ sidecar path | `src/cryptonote_protocol/cryptonote_protocol_defs.h`; the demote and promote handling in `src/cryptonote_core/blockchain.cpp`; the witness table in `src/blockchain_db/lmdb/db_lmdb.cpp`; `rust/shekyl-ffi/src/archival_ffi/attestation.rs` | At `DEL-008`, with no reuse and no FFI for bundles (`SCS-P24`) |
| CEN-B4's operand: the block's attestation witness, its root in the header and its verify path | `rust/shekyl-chain-rules/src/block.rs:118`; `src/cryptonote_core/blockchain.cpp:5057`; `rust/shekyl-ffi/src/archival_ffi/attestation.rs:161` | The attestation record is gone, so the rule as written has no operand. The bundle section's root takes the header field, renamed `bundle_root`. **CEN-B4 is retired by ruling for a new row** (`SCS-P34`), through the census arm of §11, so B4 points at its successor |
| The anchor window | `rust/shekyl-archival-retention/src/pass_anchor.rs:113-131` | Admission checks no anchor *window*: no lower bound, and for the upper one a single comparison, `anchor_height < h` (§9.1, `SCS-P32`). The anchor hash is one lookup by height |
| The public urn | deleted 2026-10-10; was `rust/shekyl-archival-retention/src/challenge_assignment.rs` | Replaced by the secret draw. `DrawablePair` moved to `drawable_pair.rs`. The other rows in this table stay until their implementations land |
| The serve-credit input's leaf-path preimage, its segment path and its split signature legs | `rust/shekyl-archival-retention/src/wire.rs:59-64`, `:81-84`, `:379-402` | The receipt signs the delivery transcript and rides in the bundle (§7.2). Superseded with the serve-credit record; decided at the cutover |
| The beacon's fire height and seal | `rust/shekyl-chain-rules/src/archival/slash.rs:10-11` and the C++ gate at `src/cryptonote_core/blockchain.cpp:4724` | One challenge per pair-epoch is replaced by per-block draws |

Where a row's lines are not restated in §2 they are from the previous pin.
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

**Re-run on the production functions, with bundle loss (`ESR-13`,
2026-10-12).** The mode is `--secret-draw-production`
(`rust/shekyl-economics-sim/src/secret_draw_production.rs`, PR #1050,
merged 2026-10-12), and the sim plan records its predictions, results and
a review addendum
([`ECONOMICS_SIM_PRODUCTION_REBASE.md`](ECONOMICS_SIM_PRODUCTION_REBASE.md)
§5.17 to §5.19). The count is `draw_count`'s and every draw is
`select_draw`'s; a bundle is filed, included or lost whole. The predictions
were committed before the results.

- **The bar holds:** 1.02 % short (0.98–1.09) at 10 % dropout with the
  filing margin `M = 30`.
- **The `(m, n)` figures above did not move**, as predicted: they depend
  on the read-failure rate, not on the observation rate.
- **The integer count rule and the `f64` one agree** in every block of
  every epoch run.
- **With `M = 30`, loss to a reorg near the deadline has no effect**: the
  latest honest inclusion is clear of the blocks such a reorg reaches.
  With `M = 0`, 0.4 % of bundles arrive late and the short share rises by
  0.05 to 0.14 points.
- **A producer that files at the last admissible block is the costly
  case.** At `M = 30` it loses no bundle and still doubles the short
  share, to 2.17 %. At a 3-block margin with a 10 % loss rate it reads
  3.48 %, over the bar. This is the evidence behind V5.

Neither run models the reads, or dropout or loss that is correlated in
time or aimed at particular blocks. It runs one epoch from its open, which is the whole state
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
| R7 | The seed is revealed whole, with records, within `[h, h + W₂]`; per-draw reveal is forbidden. Since 2026-10-11 this holds by structure: the reveal and the records are one bundle (`SCS-P14`) |
| R8 | `W₂` is the only window. Admission checks no lower bound on the anchor (`SCS-P7`). *Amended 2026-10-12 (`SCS-P32`):* it does check an upper bound, `anchor_height < h` |
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
| V5 | Filing margin `M = 30` blocks before the end of `W₂`. Challenger policy, not consensus (`SCS-P18`) | Measured inclusion latency and the natural reorg tail give a different figure; or testnet shows honest bundles lost at a meaningful rate, which also reopens the window |
| V6 | Section budget multiple `c = 2` (`SCS-P20`) | It binds on the first build; or section bytes, propagation to Tor peers, the orphan rate or `BA-T33` say otherwise |

### 13.3 The twelve questions this round posed — RULED 2026-10-07

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P1` | Layout of `0x0C` | **32 bytes, one commitment** over `witness_pk ‖ seed` under its own domain. Every carrier reveals both, so no check needs one without the other. Q13's length stands |
| `SCS-P2` | "Revealed once" against the weight limit | **Each carrier carries the whole seed.** SUPERSEDED 2026-10-11 (`SCS-P14`): one bundle, one seed |
| `SCS-P3` | Re-derivable coinbase key material | **Dropped; Q10 stands.** The seed and the witness key are fresh randomness per block, independent of each other, in memory only. A value derived from the coinbase shared secret is known to the coinbase recipient. A persistent witness secret is rejected. Loss is harmless: NonObservation, never misses |
| `SCS-P4` | The form of the draw mapping | **Rejection sampling over the static set**, capped at 256 attempts, the cap pinned by a vector (§4.4, §4.5) |
| `SCS-P5` | The record layout | **Kept: input tag and `j`.** `(P, s)` is derived. `h` is the carrier's, beside the seed. Prunable per record: `attempt` (added by `SCS-P13`), `anchor_height`, `delivery_digest`, the receipt. One rule-42 bump for record and carrier. A selection KAT and a test-only replay assertion; no runtime field. The kept half is SUPERSEDED 2026-10-11 (`SCS-P17`): a pass bitmap replaces the input tag and `j` (§7.2) |
| `SCS-P6` | Q9 bytes | **Amended:** the commitment covers the seed, `h`, and each record's `j` with its prunable fields. The bytes are SUPERSEDED 2026-10-11 (`SCS-P16`); the coverage stands, with the bitmap in place of each `j` (§7.3) |
| `SCS-P7` | A bound on `anchor_height` | **None.** The lower bound keyed on `h` is implied by the nonce, which contains `block_hash(h)`, and is not checked (§9.1) *Amended 2026-10-12 (`SCS-P32`):* "none" is the lower bound's answer. An upper bound, `anchor_height < h`, is checked at admission (§9.1) |
| `SCS-P8` | `issued` above 255 | **Saturate.** The list of issued draws is the selection's operand |
| `SCS-P9` | The reading of "in flight" | **Unrevealed draws only** |
| `SCS-P10` | The witness's read load | **Measure, do not gate.** A mining-box measurement, filed as `BA-T30`. The count rule is provisional already |
| `SCS-P11` | Which record carries the pass | **The serve-credit input.** The attestation path's pass records and CEN-B4's operand are deleted with reason (§11.1). REVERSED 2026-10-11 (`SCS-P16`): the block-level bundle carries the pass |
| `SCS-P12` | The height the settlement drop filter reads | **Per draw, at `h`:** the state after `h` connects, strictly above a same-block slash (§9.3) |

---

### 13.4 Posed on review, and ruled 2026-10-07

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P13` | The nonce of a re-read: derived from `(seed, h, j)` alone it would return to `P` an hour later with a new anchor, which only a challenge does | **A fresh nonce for every read, for every caller.** A challenge's nonce takes the read's `attempt`; the record carries `attempt` as one prunable byte; admission recomputes the nonce with one hash and refuses `attempt ≥ K`, `K = 3` (§5.2, §7.2, §9.1) |

### 13.5 Reopened and ruled 2026-10-11 — the bundle

The reopen began as four questions about carriers surviving a reorg.
Grounding them showed that a carrier had no way to travel at all
(`SCS-F12`), and under that, one defect: §9.2 let one transaction issue
draws whose records were in another (`SCS-F13`). The maintainer replaced
the carrier with one bundle per block. Each reversal below is recorded
under rule 21 as a re-alignment.

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P14` | What carries a block's reveal and its records | **One bundle per block `h`**: the reveal and every pass record for `h`. A block admits it whole or not at all. A bundle with no passes is valid and, where the block has draws, required; it is what issues `h`'s misses (§7.1; the zero-draw block is `SCS-P33`) |
| `SCS-P15` | Partial inclusion, refusal, and forced inclusion | **None of the three exists.** A valid bundle's validity depends only on the chain through `h`, its own bytes and the `h_open(E)` snapshot, so no node can refuse it. No rule acts on a bundle's absence. Non-inclusion through all of `W₂` is NonObservation for `h`, never misses (§9.1) |
| `SCS-P16` | What `SCS-P14` reverses | **`SCS-P11` is reversed:** the pass is carried by the block-level bundle. The serve-credit input, the `serve_credit_only` class and the CEN-J rows are superseded, and the successors of J8–J10 are block rules (CEN-J29 to J37). *Re-ruled 2026-10-12:* superseded is not deleted; landed Rust stays until the cutover decides it (§11.1). `SCV-4` (one record for one fact) and R-B (the producer is the witness) still hold. **Fail-whole is the bundle's** (proposal §7.6.2 (B)): a refused bundle is a producer defect, corrected and filed again; admitting records one at a time stays rejected. **`n ≥ 1` is dropped:** R7 holds by structure. The set commitment becomes the bundle commitment, and `serve_credit_batch_commitment` and the §7.3 vectors are regenerated |
| `SCS-P17` | Where the bundle sits and what commits to it | **Beside the block, not in the block blob.** The header root covers each bundle in `h` order: its kept bytes and a hash of its prunable bytes. Kept: the seed, `h`, and a pass bitmap of exactly `count(h)` bits, which replaces the list of `j`. Prunable: the witness key and signature, and per record the receipt, delivery digest, anchor and `attempt`. Settlement reads only kept data (§7.2, §7.3) |
| `SCS-P18` | The admission window against reorgs | **`W₂` stays the only consensus window**; the miss deadline and the beacon do not move. **`W₂ + D_max` is REJECTED.** The challenger files by `h + W₂ − M`, `M = 30` blocks, PROVISIONAL and challenger policy. Reopen: testnet shows honest bundles lost at a meaningful rate |
| `SCS-P19` | The height the receipt key is read at | **The `h_open(E)` bond snapshot, the one `D` is drawn from.** One snapshot type with two methods, taken as an argument by the draw and by the bundle rule. No setting. The settlement filter of `SCS-P12` keeps its own read at `h` (§9.1) |
| `SCS-P20` | How much bundle a block may carry | **A budget counted in draws:** the admitted bundles' `count(h)` sum to at most `c · 9·D / SEB`, `D` of the including block's epoch, `c = 2` PROVISIONAL. Templates take the earliest `h` first. `MAX_ATTESTATION_RECORDS = 256` cannot stay fixed. *As ruled; the formula and the charge were amended since:* the budget is `c · (⌊9·D / SEB⌋ + 1)` with `D` the largest among the epochs of the bundles in the section (`SCS-P33`), and a bundle is charged `max(count, 1)` (`SCS-P40`). §7.4 states the rule in force |
| `SCS-P21` | Weight | **The section is outside the fee median and the penalty curve** and displaces no fee-paying transaction. This dissolves two items of the FOLLOWUPS row *Serve-credit inclusion incentive and archival weight pricing*: unpaid inclusion and the cap raise |
| `SCS-P22` | Retention and sync | **The prunable part is archival content in the shard domain**, kept until past `D_max`, then discarded and backfilled. Sync is skeleton forward, then backfill. §8's "never after the prune" is withdrawn. The largest bundle's prunable size is an input to the shard-size derivation (§7.6) |
| `SCS-P23` | Alternative chains | **Stateless checks on arrival; everything else at the switch**, in the full validate. An alternative chain with an invalid bundle fails at the switch and rolls back. No bond state is rebuilt at the fork point (§9.1) |
| `SCS-P24` | The C++ side | **None.** Bundles exist only in Rust and go live with the Rust daemon. The C++ sidecar path is a `DEL-008` deletion: no reuse and no FFI (§11.1) |
| `SCS-P25` | Dandelion++ for bundles | **WITHDRAWN.** Authorship is public through `0x0C`, and block `h` was broadcast with no origin protection. Reopen: block-origination privacy is designed |
| `SCS-P26` | Who builds FN-DSA increments 3 and 4 | **This slice.** Increment 3 first: `receipt_sign_pk` in the bond record, Rust only. Then the snapshot read and the bundle rule. Increment 4's signing capability, with `FND-4`'s one decoded key, is built in this slice; `P` switches from the identity key to the receipt key in the same change as `SO-D12`'s cutover, because no verifier accepts an FN-DSA receipt before it. The FN-DSA lane closes at increment 2 (§11) |
| `SCS-P27` | How a bundle reaches a block and a node | **By reference.** Blocks carry references; bodies live in one store keyed by hash and are fetched when needed. A relayer must serve the bodies of the blocks it relays. An alternative chain whose bodies cannot be fetched is never switched to (§7.5) |
| `SCS-P28` | Where a bundle waits for inclusion | **A separate bundle queue in the pool**, not a transaction record: keyed by `h`, one per `h`, bounded at `W₂`, admitted by the bundle rule against the tip, re-checked after a reorg, persisted (§7.5) |
| `SCS-P29` | The pool's fee floor for a transaction returned from a popped block | **No bypass based on how a transaction arrived.** "`kept_by_block` skips `policy_form`" is deleted in DRS-E5 (`E5-Q1`, partly reopened). The ruling of 2026-10-02 applied |
| `SCS-P30` | Housekeeping | **`SCV-Q5`'s gate accepts `ByConstruction`** for a rule the bundle cannot express: `SO-D9` (i) and membership. §2 is re-pinned whole. The proposal's §2.2 is restated as referential integrity only, and its evidence item 11 is marked as not yet true. The sim calls the production draw functions (`SCS-F15`) |
| `SCS-P31` | Which lane builds what | **Three lanes, split by what needs checking** (rule 19). This slice: validity — this specification, the verifier's view trait, the pure verifier in `shekyl-chain-rules`, and FN-DSA increments 3 and 4. `SO-D12`: state — its increment 1, the snapshot in its increment 2, and one cutover increment (rule 07) that implements the view on its store, calls the verifier at admission, writes the kept projection, and deletes the attestation path. DRS-E5: transport. **The contracts between lanes are the view trait and the kept projection type**, defined here first (§9.6) |

### 13.6 Posed 2026-10-11, ruled 2026-10-12

Found while writing the bundle into §7 and §9, and the contracts into
§9.6. All six ruled as recommended, with three adjustments, marked.

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P32` | `SCS-P15` says a bundle's validity depends on nothing above `h`, but the receipt's anchor was held below `h` only by today's constants | **Admission checks `anchor_height < h`, and `W₂ + L ≤` anchor depth is asserted on every rule set**, as rule-set data. Recorded as an **amendment to `SCS-P7`**, not a reversal: P7's reason for no lower bound stands (§9.1) |
| `SCS-P33` | The budget's integer form: `c · 9·D / SEB` floors to zero below about 555 pairs; a bundle from the previous epoch was counted against the new `D`; a block can have `count(h) = 0` | **Budget = `c · (⌊9·D / SEB⌋ + 1)`, with `D` the largest `D` among the epochs of the bundles in the section.** *Adjusted wording:* one rule, not a two-epoch exception. **A `count(h) = 0` bundle is admissible**, which keeps the rule uniform; not filing it is challenger policy (§7.1, §7.4) |
| `SCS-P34` | Whether the header root is the existing `attestation_root` field, and CEN-B4's fate | **Reuse the field and rename it**, `bundle_root`, in the same rule-42 bump. *Adjusted:* the rename; a field does not keep a name for a value it no longer holds (rule 93). **B4 is retired by ruling for a new row**, through the census arm. `SCS-F19` is smaller than it read: DRS-E5 has nothing to reopen (§14) |
| `SCS-P35` | The bundle's bytes | **The commitment of §7.3 under a new label; the bitmap least significant bit first with zero padding, checked.** *Stated outright:* records follow in ascending `j` over the set bits and their number equals the popcount, or the bundle is refused; and "no frame" rests on fixed-width records, which rests on FN-DSA-1024's padded signature and the fixed canonical encoding, written down where a scheme change will meet it (§7.2, §7.3). `…-batch-v1` and its registry row are superseded; *re-ruled 2026-10-12*, they are not deleted (§11.1) |
| `SCS-P36` | What a backfill verifies | **Hash equality against the header root's term is the acceptance rule.** Re-verifying receipts is optional and bounded by the bond journals' horizon. This corrects `SCS-P22`'s "can be re-verified" (§8) |
| `SCS-P37` | Whether the verifier returns the derived draws | **Yes.** `Admitted::draws` is part of the contract between the verifier and the writer, in §9.6 beside the view trait, and the settlement lane sees it before it builds its cutover increment |

### 13.7 Posed on review, ruled 2026-10-12

| # | Question | Ruling |
| --- | --- | --- |
| `SCS-P38` | `SCS-P22` puts a bundle's prunable part in the shard domain, which `SHT-Q1` orders by transactions and `SHT-Q2` cuts by cumulative length bound through the txid. A bundle's position, its length and what binds the length were not stated, and they decide shard boundaries | **As recommended.** Position: after the including block's transactions, the block's bundles in ascending `h`, the header root's order. Length: `3,193 + 1,397 ·` (set bits), a function of the kept bitmap. **Two sentences added by the ruling:** the length formula depends on fixed-width records; and the largest bundle's length is the `SHT-Q2` maximum-object input for the shard-size lane (§7.6) |

### 13.8 Amended on review, 2026-10-12

Two defects in the section budget, found on review of this change and
resolved here.

- **`SCS-P39` is confirmed by the maintainer (2026-10-12), read as built
  on PR #1047.** On review of that PR's earlier tree he had ruled another
  fix for the same defect: the count taken from the chain as an
  `Option<u32>`, with the budget check waiting for the switch wherever the
  chain had none. **That ruling is withdrawn** in favour of this one. His
  reasons: every node computes the same sum from the same bytes, on the
  main chain and on an alternative block alike, so no node can disagree
  about the budget; an overstated count can only fail the budget on a
  bundle that was invalid anyway; an understated one passes at arrival and
  is refused by the full check, at connect or at the switch; and the
  withdrawn form left the budget unchecked until the switch for every
  bundle above the fork point, where this one bounds an alternative
  section on arrival. The cost is 4 kept bytes per bundle.
- **`SCS-P40`** was reviewed as built on the same PR, with nothing asked
  of it.

| # | Defect | Amendment |
| --- | --- | --- |
| `SCS-P39` | The budget was to be checked "on references alone", but a reference held only the bitmap's bytes, which do not determine `count(h)` (13 bytes fit 97 to 104). The sum of draws was therefore not computable without the chain, and the padding bits were not checkable at all without it | **The kept part states `count` (4 bytes, after `h`).** A reference parses on its own; the section's form and its sum of draws are stateless; the header root covers the count and needs no length frame. Admission holds the stated count to `count(h)`. Amends `SCS-P17`'s kept part. Considered and not taken: leaving the reference as it was and calling the budget a stateful check, which would have left an alternative block's section unbounded until the switch for every bundle above the fork point |
| `SCS-P40` | A zero-draw bundle is admissible (`SCS-P33`) and, charged by its draws, free. One block could carry up to `W₂` of them | **A bundle is charged `max(count, 1)`.** A section holds at most `c · (⌊9·D / SEB⌋ + 1)` bundles whatever their draws. Amends `SCS-P20`. Considered and not taken: refusing zero-draw bundles, which would reverse `SCS-P33`'s uniform rule; and a separate cap on the number of bundles, a second constant for what one charge already bounds |

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
| `SCS-F12` | **A carrier had no way to travel.** At `dev@258b4d851` the C++ pool never relays a zero-fee transaction (`src/cryptonote_core/tx_pool.cpp:1179`), a zero-fee transaction from a peer fails the fee check, and the Rust submit path calls the zero-fee arm unreachable (`rust/shekyl-daemon-rpc/src/submit/verifier.rs:59-62`). A carrier returned to the pool by a pop was never relayed and failed the template's re-check against the new tip. No Rust pool policy existed. **Dissolved 2026-10-11:** there is no carrier; bundles travel by `SCS-P27` and `SCS-P28` DRS-E5 filed the pop's half of this as a FOLLOWUPS row, *A popped serve-credit carrier survives the C++ pool's pop path and is never relayed again*, to be closed by this slice naming the re-inclusion mechanism and the holding store. §10 names them; the row is removed |
| `SCS-F13` | **§9.2 let one transaction issue draws whose records were in another.** A block could need two carriers (§7.4, as it stood), and the first admitted carrier issued every draw of `h`. The miner of a late block could include one and leave out the other: about 104 pairs took misses, at no cost, with the pairs chosen in advance because carriers are public. An honest reorg, or a second carrier that no miner picked up, did the same with no attacker. **Fixed 2026-10-11** by `SCS-P14` |
| `SCS-F14` | `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §2.2 records the reorg case as "safe, recorded as checked". What it shows is that no connected record references a removed block. It does not show that an honest receipt survives a reorg, and its evidence item 11 ("re-inclusion admits") was false at the tree (`SCS-F12`). **Fixed** there with this change |
| `SCS-F15` | `rust/shekyl-economics-sim/src/secret_draw.rs` carries its own count rule, in `f64`, and its own weighted selection, and calls no function of `rust/shekyl-archival-retention/src/secret_draw.rs`. Its module documentation says the draw has no production owner. §12's figures are from the sim's rule, not the consensus one. Open: owed with the sim's next run (§11) |
| `SCS-F16` | This document's §2 was pinned at `dev@0e1d1d6126` and still said CEN-B4 had no Rust rule; its banner said nothing was built while §16 listed landed constants; §15 carried a second, older copy of its table. **Fixed** with this change |
| `SCS-F17` | The bundle brief gives a reference as under 100 B. With a 32-byte prunable hash and, since `SCS-P39`, a 4-byte count, it is `76 + ⌈count(h) / 8⌉` B: 113 B at the count cap for `D` = 324,000, and 425 B at `D` = 3,100,000. §7.5 states the range. The brief also gives that cap as 291; with the carry it is 292 (§7.4) |
| `SCS-F18` | `ARCHIVAL_SETTLEMENT_WRITER.md` §16.6 on PR #1032 recorded `SO-D12d` as "the FN-DSA lane builds increments 2 to 4". `SCS-P26` supersedes it for increments 3 and 4. **Fixed** on that branch by the settlement lane, 2026-10-12 |
| `SCS-F19` | DRS-E5 (PR #1026, merged 2026-10-12) dissolved its alternative-tier CEN-B4 work (`E5-Q4` δ, `E5-17`) because this slice deleted B4's operand, and under `SCS-P17` and `SCS-P23` a block again carries a root recomputed when an alternative block arrives. **Closed 2026-10-12, smaller than it read:** what δ did was a bond read at the alternative chain's cheap tier. What returns is a stateless recomputation from references, with no bond read, and DRS-E5's brief already asks for that arrival check. δ stays dissolved; DRS-E5 reopens nothing |

---

## 15. Documents this replaces, and what stays in them

The mechanism text this specification supersedes is deleted from each and
replaced by a pointer here. Text that describes code as it runs today
stays until that code is deleted (§11.1), and is marked.

| Document | What it still owns |
| --- | --- |
| [`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) | The SO-D8 round's standing rulings: R-B, `SO-D8a`–`d`, the drawable set's construction (Q3, §7.4), the dedicated witness key and its `0x0C` home (Q8, §7.5), fail-whole and resubmission (Q9, §7.6.2 (B), now the bundle's; `SCS-P16`), the memory-only ring (Q10, §7.7), the `0x0C` content rule (Q13, §7.8), Slice C's plan and evidence list (§8). `SO-D8e`'s urn and ring, Q8's derivation and Q12's bare hash are superseded and gone |
| [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) | The challenge round's doctrine and forks, the read, the 2-of-3 argument (§3), parameter discipline (§9), and its record of the urn as landed code |
| [`ARCHIVAL_SHARD_FETCH.md`](ARCHIVAL_SHARD_FETCH.md) | The fetch client: `SF-D1`–`D13`, the delivery digest and its transcript (`SF-D8`), the client's outcome table (`SF-D6`). Its countersigning key and admission window describe live code |
| [`ARCHIVAL_CREDIT_WIRE.md`](ARCHIVAL_CREDIT_WIRE.md) | The attestation path as it runs today, and the deletion surface of the round before it |
| [`ARCHIVAL_SETTLEMENT_WRITER.md`](ARCHIVAL_SETTLEMENT_WRITER.md) | The settlement writer's rulings (`SO-D1`–`D7`): enumeration, key and value, when it runs |

---

## 16. Labels this specification mints

Each row lands with its constant. Six have: the settlement selection and
the issued-index term (`rust/shekyl-archival-retention/src/settlement_select.rs`,
2026-10-08), the two scheme domains (`SCHEME_DOMAIN_RECEIPT`,
`SCHEME_DOMAIN_WITNESS_CARRIER` in `rust/shekyl-crypto-pq/src/signature.rs`,
2026-10-09), and the two receipt-key labels
(`rust/shekyl-crypto-pq/src/archival_p.rs`, 2026-10-10). The rest have no
constant or registry row yet.

| Label | Mechanism | Use |
| --- | --- | --- |
| `shekyl/archival-draw-commit-v1` | cSHAKE256 | The `0x0C` commitment over `witness_pk ‖ seed`, §4.2 |
| `shekyl/archival-draw-v1` | cSHAKE256 | Selection stream, §4.4 |
| `shekyl/archival-challenge-nonce-v1` | cSHAKE256 | Challenge nonce, over `(seed, block_hash(h), j, attempt)`, §5.2 |
| `shekyl/archival-issued-index-v1` | cSHAKE256 | One issued draw's term in the epoch's running digest, §10 |
| `shekyl/archival-settlement-select-v1` | cSHAKE256 | Counted-draw selection, §9.3 |
| `shekyl/archival-serve-credit-batch-v1` | cSHAKE256 | The carrier's set commitment. Superseded by the bundle commitment (`SCS-P35`); the constant, its vectors and its registry row stay (§11.1) |
| `shekyl/archival-serve-credit-bundle-v1` | cSHAKE256 | The bundle commitment, §7.3 |
| `shekyl-archival-p-receipt-ed25519-v1` | HKDF info | The Ed25519 half of the persona's receipt key, from the master seed, §6.3 |
| `shekyl-archival-p-receipt-fn-dsa-1024-v1` | HKDF info | The FN-DSA-1024 half of the same key, §6.3 |
| `shekyl/archival-receipt-scheme-v1` | signature domain | Receipts under scheme 3, §6.2 |
| `shekyl/archival-witness-carrier-scheme-v1` | signature domain | The witness's signature on a carrier. Landed as a constant with no signer; not used for the bundle (§6.2) |
| `shekyl/archival-witness-bundle-scheme-v1` | signature domain | The witness's signature on the bundle, under scheme 3, §7.3. Minted with the verifier |

Four are minted with their constants on the verifier's PR (#1047, open;
rule 30), and have no constant in this tree until it merges: the witness's bundle signature domain, the bundle
commitment, `shekyl/archival-bundle-prunable-v1` and
`shekyl/archival-bundle-root-v1` (§7.3).
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
| Derive the witness key from a revealed seed and author a bundle, or `P` signs its own receipt | Prevented: the seed and the witness key are independent random values (§4.2) |
| Steal a producer's long-lived secret and learn every future seed | No such secret exists: nothing is derived and nothing is persisted |
| The coinbase recipient learns the seed early | Prevented: the seed is not derived from the coinbase shared secret |
| A record names a pair the draw did not select | Impossible: the record names only `j`; the pair is derived |
| Run the selection loop without bound | Prevented: the 256th attempt selects |
| File one of a block's two carriers and withhold the other | Not expressible since 2026-10-11: one bundle per block, admitted whole (`SCS-P14`). Under carriers this was open to any miner, not only the producer (`SCS-F13`) |
| Re-roll the settlement beacon | Costs the beacon block's producer a block reward |

### 17.1 Wargames of the bundle (2026-10-11)

One row at least for each item of §13.5 to §13.8.

| Item | Attack or failure | Outcome |
| --- | --- | --- |
| `SCS-P14` | The miner of a late block includes the part of `h`'s reveal that issues the draws and leaves out the part holding a chosen pair's passes | Not expressible: the reveal and every record are one object, admitted whole. This was free and targetable under carriers (`SCS-F13`) |
| `SCS-P14` | A producer with no passes files nothing, to hide that its reads all failed | Then `h` is unrevealed: NonObservation. An honest producer files the empty bundle, which issues the misses. A producer that prefers silence could always choose it |
| `SCS-P14` | The producer signs two different bundles for `h` | A chain admits one per `h`. The choice between them is the producer's, which is the power to omit a pass it already had; contained by 2-of-3 |
| `SCS-P15` | A node refuses a valid bundle on some local ground | No ground exists: validity is a function of the chain through `h`, the bundle's bytes and the snapshot |
| `SCS-P15` | Every miner leaves `h`'s bundle out for all of `W₂` | NonObservation for `h`. It takes every block for about 500 blocks: majority-hashrate censorship, outside the threat model |
| `SCS-P15` | A producer withholds its bundle to stall the chain | Nothing waits on a bundle; no rule acts on absence |
| `SCS-P16` | A third party slips a bad record into an honest bundle so it is refused whole | The witness signature covers every record; only the producer can author one. A refused bundle is a producer defect, corrected and filed again while the seed is in the ring |
| `SCS-P16` | Records admitted one at a time as a free-weight channel | Stays rejected; a bundle is admitted whole inside a draw-counted budget |
| `SCS-P17` | Alter a kept bitmap after the prunable bytes are gone | The header root covers the kept bytes, and the header is under proof of work |
| `SCS-P17` | Set a bit with no record, or carry a record with no bit | Refused at structure: the record count equals the number of set bits, and the bitmap is exactly `count(h)` bits |
| `SCS-P18` | An honest reorg pops the block holding a bundle filed near the end of its window | Re-admitted from the queue while the window lasts; past it, NonObservation. The margin `M` is what keeps honest filing clear of the natural reorg tail |
| `SCS-P18` | A producer files at the last block of the window on purpose | The same as filing late by accident: its own block risks NonObservation. No pair takes a miss from it |
| `SCS-P19` | A pair is drawn from one height's bond state and its receipt key read from another's, so a drawn pair has no key and the bundle is refused whole | Not constructible: one snapshot value is the argument of both |
| `SCS-P19` | A persona changes its receipt key mid-epoch to void receipts already given | Bond records are immutable; the key does not change for the record's life |
| `SCS-P20` | A miner fills the section to crowd out transactions or bloat blocks | The budget is two bundles at the count cap, each bundle is bound to a mined block and admitted once, and the section displaces no transaction |
| `SCS-P20` | A backlog after an outage starves the oldest windows | Templates take the earliest `h` first, and the budget is about four times the mean demand |
| `SCS-P21` | A miner at the fee median is priced to leave bundles out | The section is outside the median and the penalty curve; including a bundle costs the miner no fee |
| `SCS-P22` | A syncing node is fed a false bitmap for an old block | Kept bytes are checked against the header root in the skeleton pass |
| `SCS-P22` | A backfilled body does not match what the chain committed to | Refused on the per-bundle hash |
| `SCS-P23` | An alternative chain carries an invalid bundle to make nodes do work | It costs a heavier chain's proof of work; the chain fails at the switch and rolls back |
| `SCS-P23` | Alternative blocks sent at low cost to trigger receipt verification | Only stateless checks run on arrival; no signature is verified before the switch |
| `SCS-P24` | The C++ daemon and the Rust daemon disagree on a bundle | No C++ path parses or judges one; bundles go live with the Rust daemon |
| `SCS-P25` | An observer links a bundle's first relay to the producer's node | Already public: `0x0C` names the author, and the node broadcast block `h` itself |
| `SCS-P26` | `P` starts signing receipts under the new key before a verifier for it is live | Prevented: the capability is built ahead, and the switch of key is part of the cutover that makes the verifier live |
| `SCS-P27` | A relayer sends a block and refuses its bundle bodies | Attributable misbehaviour; the block is not connected, and an alternative chain is not switched to, until the bodies arrive from someone |
| `SCS-P27` | Fill the body store with junk | A body is stored only if a block with valid proof of work references it or the queue admitted it; the reference's bitmap bounds its size; every stored body has a holder |
| `SCS-P28` | Flood the queue with bundles | One per `h`, at most `W₂` entries. Before the producer releases a bundle nobody else can open that block's `0x0C`. After, a forged body costs a node one witness-signature verification and no receipt verification, only for heights whose valid bundle it does not yet hold (§9.1) |
| `SCS-P28` | Send a second valid bundle for `h` to displace the first | The first valid one wins in a queue; the block's reference decides which body a node needs |
| `SCS-P29` | Mine a zero-fee transaction, then orphan the block to get it into every pool | No fee-floor bypass by arrival path; the returned transaction meets the same policy as any other |
| `SCS-P30` | "Retired by ruling" read as "dropped", so the `DEL-008` gate opens on rows nobody implemented | The retired status names successor rows, and the gate reads each as `Implemented` or `ByConstruction` |
| `SCS-P32` | On a short-epoch rule set, a reorg above `h` changes an anchor's hash and voids an honest bundle | Not constructible: `anchor_height < h` is checked, and every rule set asserts `W₂ + L ≤` anchor depth |
| `SCS-P33` | A network with few pairs can never admit a bundle, so it never observes and never pays | The budget is `c` bundles at the count cap for any `D` |
| `SCS-P33` | A producer files bundles for its zero-draw blocks to use up other blocks' sections | Each is charged one unit of the budget (`SCS-P40`), and there is one per `h`, so they cannot fill a section for free; the `SCS-P40` row gives the bound |
| `SCS-P34` | One header field read as an attestation root by old code and as a bundle root by new | The field is renamed in the bump that changes its meaning, and B4 is retired for a new row; no code path reads the old name |
| `SCS-P35` | Two different bundles with one commitment | `count` fixes the bitmap, the popcount fixes the number of records, each record is 1,397 bytes; padding bits are checked. A scheme with variable-width signatures would break this, and §7.3 says so |
| `SCS-P36` | A node refuses to backfill an old bundle because it cannot rebuild the snapshot | Hash equality is the acceptance rule; nothing requires the snapshot |
| `SCS-P31` | Two lanes each build their own reading of what the verifier needs, and the store's view answers a different question from the one the verifier asks | The view trait and the kept projection are fixed in §9.6 before either is built; the verifier is tested against a fixture view, so it cannot lean on a store type |
| `SCS-P37` | The writer's own derivation of a draw's pair disagrees with the verifier's, so a receipt is checked against one pair and the pass is recorded for another | One derivation: the verifier returns the derived draws and the writer derives nothing |
| `SCS-P38` | Two nodes place a bundle's bytes at different points in the shard domain, or count different lengths for it, and cut shards at different boundaries | The position is the header root's order and the length is a function of the kept bitmap, so both are consensus data already |
| `SCS-P39` | A block's references understate their counts so the section passes the budget at arrival | The stated count is held to `count(h)` at admission, so the block is invalid; the cost is the block's proof of work |
| `SCS-P39` | Two sections with one root, by moving a byte between a bitmap and the hash beside it | Not constructible: each reference states its count, which fixes its bitmap's length |
| `SCS-P40` | A miner fills its block's section with zero-draw bundles from the last `W₂` blocks, to make every node fetch and verify them | Each costs one unit, so the section holds at most `c · (⌊9·D / SEB⌋ + 1)` of them: 2 on a network small enough to have zero-draw blocks |
