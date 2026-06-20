# Shekyl Genesis Transaction / Block Wire Format — Specification

**Status:** Round 0 design draft (2026-06-20). **This document, once ratified,
IS the genesis freeze** for the binary block/tx wire format: the Rust serializer
implements *it* (not C++), the differential corpus proves conformance *to it*,
and the C++ daemon is edited to match it where we deliberately diverge.
**Process:** multi-round design ([`26-sub-pr-design-discipline`]) — this is a
consensus + FFI surface. **Parents:**
[`CONSENSUS_PORT_SEQUENCE.md`](CONSENSUS_PORT_SEQUENCE.md) (Stage 1d),
[`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).

## 0. Posture — creation, not transcription

This is a fresh-genesis chain with no chain history. C++ is the **starting
proposal**, not the answer. For every field and every variant arm we record a
deliberate disposition:

- **Ratify** — keep exactly as C++ emits it, because it is intended (document
  *why*).
- **Shed** — remove from the genesis format entirely (no producer, or inherited
  cruft). Requires editing the C++ oracle too (a "gate-(c)" deliberate change).
- **Reshape** — keep the capability, change the layout to drop heritage.
- **Spec** — Shekyl-native; the layout exists only in C++/`shekyl-archival-*`
  source, so writing it here is its *only* human-readable definition.

Pre-genesis is the **only** window where Shed/Reshape are free: no migration
code, just regenerated test wallets. Post-genesis each is a hardfork. Every dead
arm or vestigial field is also **consensus-critical parser-differential surface**
and **fingerprinting surface** — shedding shrinks the area two implementations
can disagree over and the area a network observer can probe, so it serves the
mission order (privacy > security > correctness, [`00-mission`]) directly, not
just tidiness.

## 1. Decisions (locked 2026-06-20)

1. **Clean Shekyl-owned crate.** The canonical serializer lives in a new
   Shekyl crate (working name `shekyl-tx-wire`; final placement per
   [`25-rust-architecture`] — candidate under `shekyl-consensus`). It owns the
   **entire** genesis tx/block format with Shekyl-shaped types: one unified input
   enum (no split between core and archival arms), no `Pruned`/`NotPruned`
   generic, no ring vestige. The vendored `shekyl-oxide` `block`/`transaction`/
   `fcmp` serializer is **retired**; consumers migrate to the new crate.
2. **Clean-sheet arbitration.** Make the deliberate cuts now (shed dead arms,
   drop ring vestige, shed dust chunking) with **matching C++ edits**, so the
   differential gate tracks the *arbitrated* layout, not raw C++.
3. **`shekyl-oxide` block/tx is a permanent fork, not an upstream patch.** Monero
   cherry-picking has stopped; this is Shekyl's frozen format that merely started
   from monero-oxide. We do **not** plan to upstream it or "re-vendor to
   convergence" (that would risk a future re-vendor silently reverting a
   genesis-format decision). Crypto primitives in `shekyl-oxide` remain vendored;
   the block/tx/rct *protocol* code is ours ([`10-shekyl-first`]).

## 2. The arbitration table

Source cites are `src/cryptonote_basic/cryptonote_basic.h` unless noted.

### 2.1 Input arms (`txin_v`, :316)

| Tag | C++ arm | Disposition | Rationale / layout |
|---|---|---|---|
| `0xff` | `txin_gen` (:126) | **Ratify** | coinbase height (varint). |
| `0x00` | `txin_to_script` (:135,851) | **Shed** | CryptoNote placeholder, no producer. Remove from genesis tag space. |
| `0x01` | `txin_to_scripthash` (:148,852) | **Shed** | idem. |
| `0x02` | `txin_to_key` + `key_offsets` (:163,166) | **Reshape → `txin_fcmp`** | drop `key_offsets` (ring-decoy vestige; FCMP++ proves against the full set) and the by-amount machinery. **OPEN:** confirm `key_image` is the only field the daemon FCMP++ verify consumes (needs a spend blob — §6 Q1). |
| `0x03` | `txin_stake_claim` (:176) | **Spec + ratify** | `VARINT(amount) VARINT(staked_output_index) VARINT(from_height) VARINT(to_height) k_image[32]`. |
| `0x04` | `txin_archival_serve_credit_response` (:290) | **Spec + ratify** (coordinate w/ archival track) | `p_canonical_id[32] VARINT(shard_id) VARINT(settlement_epoch) segment_subroot_rk[32] leaf_index_in_segment(u32 LE) leaf_bytes[ARCHIVAL_LEAF_BYTES] path{c1_layers,c2_layers : vec<vec<hash>>} hybrid_signature(varint+bytes)`. |
| `0x05` | `txin_archival_bond_post` (:264) | **Spec + ratify + UNIFY** (unrepresented in Rust today) | `hybrid_public_key(varint+bytes) p_canonical_id[32] post_kind(u8) holdings{kind_u8, [shard_ids vec if ShardSetCompact]} VARINT(bonded_total_atomic) VARINT(bond_credit) VARINT(bond_debit)`. |

The archival arms (0x04/0x05) are **Shekyl-native with no spec outside C++** —
making this table their only human-readable definition and the highest
load-bearing corpus cells. Their layouts must be ratified **in coordination with
the archival workstream** (the `certify_draw` actor track is orthogonal, but the
*byte layout* of these vins is owned here once frozen). **OPEN (§6 Q4):** confirm
these layouts are archival-final before freezing.

### 2.2 Output arms (`tx_out`)

| Tag | C++ arm | Disposition | Layout |
|---|---|---|---|
| `0x00` | `txout_to_script` (:857) | **Shed** | dead. |
| `0x01` | `txout_to_scripthash` (:858) | **Shed** | dead. |
| `0x02` | `txout_to_key` (:859) | **OPEN (§6 Q3)** | `key[32]`. Shed if no producer (coinbase + spends use tagged/staked). |
| `0x03` | `txout_to_tagged_key` (:860) | **Ratify** | `key[32] view_tag(1)`. |
| `0x04` | `txout_to_staked_key` (:861) | **Ratify** | `key[32] view_tag(1) lock_tier(1)`. |

Each output is preceded by `VARINT(amount)` (cleartext for coinbase/staked; `0`
for confidential spend outputs).

### 2.3 RCT section

| Element | Source | Disposition |
|---|---|---|
| type byte | rctTypes.h:167-168,200 | **Ratify** — already minimal: `Null=0`, `FcmpPlusPlusPqc=7`; C++ rejects all other type values. This is *already created, not inherited* (Monero's ~8-variant enum is gone). |
| coinbase `Null`-but-committed (`outPk`/`enc_amounts`/`enc_labels`) | rctTypes.h:209-212 | **Ratify as the exception.** Shekyl-intended for FCMP++ tree-leaf commitment uniformity (Monero's null coinbase has no commitments). Explicitly **not** the spend template. |
| base: `VARINT(fee)` + `referenceBlock[32]` (Fcmp only) | rctTypes.h:205-206 | **Ratify** — `referenceBlock` lives in the **base**. |
| base arrays: `enc_amounts[nout×9]`, `enc_labels[nout×9]`, `outPk[nout×32]` (no length prefix) | rctTypes.h:213-280 | **Ratify** — sized by `vout`. |
| `pqc_auths` (non-coinbase): `nvin ×` `{auth_version(1) scheme_id(1) flags(u16 LE) hybrid_public_key(varint+bytes) hybrid_signature(varint+bytes)}` at **tx level**, EOF-tolerant on read | basic.h:334-353,491-517 | **Ratify** — tx-level, between base and prunable; read tolerates truncation (pruned form). |
| prunable (type≠Null): `VARINT(nbp)` `bpp×nbp` `VARINT(curve_trees_tree_depth)` `VARINT(proof_len)` `fcmp_pp_proof[proof_len]` `pseudoOuts[nvin×32]` | rctTypes.h:347-410 | **Ratify**. |

### 2.4 Coinbase construction

| Element | Source | Disposition |
|---|---|---|
| dust / power-of-10 chunking (`decompose_amount_into_digits`) | tx_utils.cpp:155-166 | **Shed (likely).** Ring-era decoy-uniformity heritage; pointless once coinbase outputs are committed. Captured regtest coinbases already have `vout=1`. **OPEN (§6 Q2):** confirm `max_outs`/decomposition never yields >1 output in genesis params; if so, formalize "coinbase = single output." |

## 3. Canonical genesis layout (post-arbitration)

Byte order, top to bottom. `V(x)` = varint; `[n]` = n raw bytes; `vec(f)` =
`V(len)` then `len ×` f.

```
Block            := BlockHeader  Transaction(miner)  V(n_tx)  n_tx×Hash[32]
BlockHeader      := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32]
Transaction      := V(version=3)  TxPrefix  Rct
TxPrefix         := V(unlock_time)  vec(Input)  vec(Output)  V(extra_len) extra[extra_len]
Input            := tag(1) ...        # tags: ff gen | 02 fcmp | 03 stake_claim | 04 serve_credit | 05 bond_post   (00/01 SHED)
Output           := V(amount) tag(1) ...   # tags: 03 tagged_key | 04 staked_key   (00/01 SHED; 02 OPEN)
Rct              := rct_type(1) ...
  if Null  (coinbase):  enc_amounts[nout×9]  enc_labels[nout×9]  outPk[nout×32]
  if Fcmp  (spend):     V(fee) referenceBlock[32] enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]
                        PqcAuths  Prunable
PqcAuths         := nvin × { auth_version(1) scheme_id(1) flags(u16 LE) vec(u8) vec(u8) }   # EOF-tolerant (pruned form omits)
Prunable         := V(nbp) nbp×BpPlus  V(tree_depth) V(proof_len) fcmp[proof_len]  pseudoOuts[nvin×32]
```

(`txin_fcmp` body, `BpPlus` body, and the archival-arm bodies are detailed in
§2; full byte tables land in Round 1 once the OPEN items resolve.)

## 4. Architecture of the clean crate

- **One unified `Input` / `Output` enum** — Shekyl arms only; the archival arms
  (`bond_post`, `serve_credit_response`) are folded in here, not split across
  `shekyl-archival-retention` (which keeps the *semantic* types; the **wire**
  encoding is owned by `shekyl-tx-wire`). This closes the bond-post parse gap.
- **No `Pruned`/`NotPruned` generic.** Pruning is `prunable: Option<…>` /
  an explicit pruned view, not a type parameter threaded through every consumer.
- **Explicit `Rct { base, pqc_auths, prunable }`** matching §2.3 — `referenceBlock`
  in `base`, `curve_trees_tree_depth` in `prunable`, `pqc_auths` tx-level — fixing
  the three misplacements in the current `shekyl-oxide` model.
- **Migration:** the ~58 consumer sites in `shekyl-tx-builder`, `shekyl-scanner`,
  `shekyl-engine-core`, `shekyl-ffi`, `shekyl-cli` move from
  `shekyl_oxide::{block,transaction}` to the new crate. `shekyl-oxide`'s block/tx
  modules are deleted; its crypto primitives stay.

## 5. Gate-(c) C++ oracle changes (deliberate, pre-genesis)

These are **genesis-format definition**, not "patching C++" — they *remove*
inherited cruft ([`60-no-monero-legacy`]) so the oracle emits the arbitrated
format:

1. Remove `txin_to_script`/`txin_to_scripthash`/`txout_to_script`/
   `txout_to_scripthash` from `txin_v`/`tx_out` + the `VARIANT_TAG` lists.
2. Reshape `txin_to_key` → drop `key_offsets` (pending Q1).
3. Force single-output coinbase / remove dust decomposition (pending Q2).

Each lands as its own change with C++ + Rust + a locked vector, byte-identity
re-verified against the *new* oracle. Until a given cut lands, the corpus pins
the pre-cut bytes; the cut flips both sides together.

## 6. Open questions (resolve before Round 1 freeze)

- **Q1 — `txin_fcmp` minimal fields.** Does the daemon FCMP++ verify read
  `amount`/`key_offsets` at all, or only `key_image`? Needs a real spend blob
  (capture via the regtest harness once a spend path runs).
- **Q2 — coinbase output count.** Does `decompose_amount_into_digits` +
  `max_outs` ever yield >1 coinbase output under genesis params? If never,
  formalize single-output and shed the chunking.
- **Q3 — `txout_to_key` (0x2) producer.** Anything emit plain (non-tagged,
  non-staked) outputs? If not, shed.
- **Q4 — archival arm finality.** Are `txin_archival_bond_post` /
  `serve_credit_response` layouts archival-workstream-final, or still moving?
  Don't freeze a layout the archival track may still change.
- **Q5 — crate scope.** Does `shekyl-tx-wire` also own block-header/PoW-hash
  serialization, or only tx? (Block currently in `shekyl-oxide::block`.)

## 7. Differential methodology (extends CONSENSUS_PORT_SEQUENCE §3)

- **Positive corpus:** raw daemon blobs (coinbase ✓ captured; spend, staked,
  multi-tx, each archival vin) → `read` then `write` == arbitrated bytes.
- **Negative/boundary corpus:** a structured fuzzer + hand-built cases — the
  EOF-tolerant `pqc_auths` boundary (truncation before/at/into prunable; partial
  length prefix), shed-tag rejection (a `0x00`/`0x01` input must be **rejected**
  by both impls post-cut), over-long PQC blobs — gate = **identical accept/reject**,
  not round-trip.
- **The spec is the freeze; the corpus exercises it; the test proves conformance
  to the written layout** — not to an unreadable pile of blobs.

## 8. Sequencing

1. Round 0 (this doc) → review.
2. Resolve §6 OPEN items at source (+ capture a spend blob).
3. Round 1: freeze the byte tables; ratify archival arms with the archival track.
4. Stand up `shekyl-tx-wire` to the spec; positive+negative corpus green vs the
   (gate-(c)-adjusted) oracle.
5. Migrate consumers; delete `shekyl-oxide` block/tx.
6. Land gate-(c) C++ cuts (each its own consensus change).
