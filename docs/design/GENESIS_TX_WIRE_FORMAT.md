# Shekyl Genesis Transaction / Block Wire Format — Specification

**Status:** Round 0 **approved** 2026-06-20; assembling the Round-1 freeze-gate
list (§6). **This document, once ratified, IS the genesis freeze** for the binary
block/tx wire format: the Rust serializer implements *it* (not C++), the
differential corpus proves conformance *to it*, and the C++ daemon is edited to
match it where we deliberately diverge. **Process:** multi-round design
([`26-sub-pr-design-discipline`]) — consensus + FFI surface. **Parents:**
[`CONSENSUS_PORT_SEQUENCE.md`](CONSENSUS_PORT_SEQUENCE.md) (Stage 1d),
[`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).

**Round-0 review outcome:** direction + both locked decisions approved. Two
privacy concerns raised in review were checked against source and **retracted**
(`view_tag` and `enc_labels` are Shekyl-created mechanisms, not vestige — ratify
stands); their rationale is now recorded as binding rules (§2.2, §2.3) per the §0
"document why" requirement. The freeze-gate list (§6) gained four additions
beyond the original Q1–Q5.

## 0. Posture — creation, not transcription

This is a fresh-genesis chain with no chain history. C++ is the **starting
proposal**, not the answer. For every field and every variant arm we record a
deliberate disposition:

- **Ratify** — keep exactly as C++ emits it, because it is intended (document
  *why* — a ratify with no recorded rationale is an unfinished decision).
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
   Shekyl crate (working name `shekyl-tx-wire` — but per Q5 it owns block +
   header + PoW hashing-blob + tx, so the name undersells it; final name/placement
   per [`25-rust-architecture`], candidates `shekyl-wire` or folded into
   `shekyl-consensus`). It owns the **entire** genesis tx/block format with
   Shekyl-shaped types: one unified input enum (no split between core and archival
   arms), no `Pruned`/`NotPruned` generic, no ring vestige. The vendored
   `shekyl-oxide` `block`/`transaction`/`fcmp` serializer is **retired**;
   consumers migrate to the new crate.
2. **Clean-sheet arbitration.** Make the deliberate cuts now (shed dead arms,
   drop ring vestige, shed dust chunking) with **matching C++ edits**, so the
   differential gate tracks the *arbitrated* layout, not raw C++.
3. **`shekyl-oxide` block/tx is a permanent fork, not an upstream patch.** Monero
   cherry-picking has stopped; this is Shekyl's frozen format that merely started
   from monero-oxide. We do **not** plan to upstream it or "re-vendor to
   convergence" (that would risk a future re-vendor silently reverting a
   genesis-format decision). Crypto primitives in `shekyl-oxide` remain vendored;
   the block/tx/rct *protocol* code is ours ([`10-shekyl-first`]).
4. **This PR precedes — and is the first slice of — the broader `shekyl-oxide`
   un-vendor.** Extracting the protocol serializer here removes the part that was
   never legitimately vendored, shrinking the remaining vendored surface to the
   crypto primitives (which un-vendor handles afterward). Sequencing it the other
   way would rename the block/tx surface only to delete it here — touching the
   ~58-site surface twice. Recorded in
   [`../V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md) (2026-06-20).

## 2. The arbitration table

Source cites are `src/cryptonote_basic/cryptonote_basic.h` unless noted.

### 2.1 Input arms (`txin_v`, :316)

| Tag | C++ arm | Disposition | Rationale / layout |
|---|---|---|---|
| `0xff` | `txin_gen` (:126) | **Ratify** | coinbase height (varint). |
| `0x00` | `txin_to_script` (:135,851) | **Shed** | CryptoNote placeholder, no producer. Remove from genesis tag space. |
| `0x01` | `txin_to_scripthash` (:148,852) | **Shed** | idem. |
| `0x02` | `txin_to_key` + `key_offsets` (:163,166) | **Reshape → `txin_fcmp`** | drop `key_offsets` (ring-decoy vestige; FCMP++ proves against the full set) and the by-amount machinery. **OPEN:** confirm `key_image` is the only field the daemon FCMP++ verify consumes (needs a spend blob — §6 Q1). |
| `0x03` | `txin_stake_claim` (:176) | **Spec + ratify** | `VARINT(amount) VARINT(staked_output_index) VARINT(from_height) VARINT(to_height) k_image[32]`. `staked_output_index` is a **global** output index (:179, confirmed) — not an amount-output-index, so no by-amount heritage smuggled. |
| `0x04` | `txin_archival_serve_credit_response` (:290) | **Spec + ratify** (Wave 2; coordinate w/ archival track) | `p_canonical_id[32] VARINT(shard_id) VARINT(settlement_epoch) segment_subroot_rk[32] leaf_index_in_segment(u32 LE) leaf_bytes[ARCHIVAL_LEAF_BYTES] path{c1_layers,c2_layers : vec<vec<hash>>} hybrid_signature(varint+bytes)`. |
| `0x05` | `txin_archival_bond_post` (:264) | **Spec + ratify + UNIFY** (Wave 2; unrepresented in Rust today) | `hybrid_public_key(varint+bytes) p_canonical_id[32] post_kind(u8) holdings{kind_u8, [shard_ids vec if ShardSetCompact]} VARINT(bonded_total_atomic) VARINT(bond_credit) VARINT(bond_debit)`. |

The archival arms (0x04/0x05) are **Shekyl-native with no spec outside C++** —
making this table their only human-readable definition and the highest
load-bearing corpus cells. They freeze in **Wave 2** (§6 Q4, §8), under a single
combined wire+semantics sign-off with the archival workstream.

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

**`view_tag` (1 byte) — RATIFY, rationale recorded.** Not Monero vestige: it is
the view-tag fast-reject *rederived into Shekyl's hybrid X25519 path* —
`keccak256("view_tag" ‖ output_derivation)[0]` off the X25519 ECDH output
(`rust/shekyl-scanner/src/shared_key.rs:65`), used as the scan prefilter
(`bench_fixtures.rs`, `first_output_exits_via_view_tag_mismatch`). **Accepted
tradeoff (binding):** a deliberately-accepted 1-byte scan-correlation cost in
exchange for the prefilter; recorded here as an *accepted* cost, not a silently
inherited one.

### 2.3 RCT section

| Element | Source | Disposition |
|---|---|---|
| type byte | rctTypes.h:167-168,200 | **Ratify** — already minimal: `Null=0`, `FcmpPlusPlusPqc=7`; C++ rejects all other type values. Already created, not inherited (Monero's ~8-variant enum is gone). **Type *value* numbering** is a Q7 decision. |
| coinbase `Null`-but-committed (`outPk`/`enc_amounts`/`enc_labels`) | rctTypes.h:209-212 | **Ratify as the exception.** Shekyl-intended for FCMP++ tree-leaf commitment uniformity (Monero's null coinbase has no commitments). Explicitly **not** the spend template. |
| base: `VARINT(fee)` + `referenceBlock[32]` (Fcmp only) | rctTypes.h:205-206 | **Ratify** — `referenceBlock` lives in the **base**. |
| base arrays: `enc_amounts[nout×9]`, `enc_labels[nout×9]`, `outPk[nout×32]` (no length prefix) | rctTypes.h:213-280 | **Ratify** — sized by `vout`. See the `enc_labels` invariant below. |
| `pqc_auths` (non-coinbase): `nvin ×` `{auth_version(1) scheme_id(1) flags(u16 LE) hybrid_public_key(varint+bytes) hybrid_signature(varint+bytes)}` at **tx level**, EOF-tolerant on read | basic.h:334-353,491-517 | **Ratify** — tx-level, between base and prunable; read tolerates truncation (pruned form). |
| prunable (type≠Null): `VARINT(nbp)` `bpp×nbp` `VARINT(curve_trees_tree_depth)` `VARINT(proof_len)` `fcmp_pp_proof[proof_len]` `pseudoOuts[nvin×32]` | rctTypes.h:347-410 | **Ratify** — but `bpp` and `fcmp_pp_proof` interiors are a freeze gap, see §6 Q6. |

**`enc_labels` indistinguishability invariant — BINDING serializer rule.** Every
output carries a fixed-size `enc_label` (9 B), **real or zero-sentinel, never
elided** — so the presence/absence of a real label is unobservable to any
non-recipient. This is a normative privacy invariant, not "sized by vout"
incidentally: a future "optimization" that drops empty labels silently breaks it.
The genesis freeze nails it shut. Sources:
`rust/shekyl-crypto-pq/src/label.rs:179` (normative invariant),
`rust/shekyl-engine-core/src/outbound_label.rs:8` and
`rust/shekyl-ffi/src/lib.rs:3593` (ungated), `curve_tree_decode.rs:189,245`
(`zero_enc_label()` sentinel emission).

### 2.4 Coinbase construction

| Element | Source | Disposition |
|---|---|---|
| dust / power-of-10 chunking (`decompose_amount_into_digits`) | tx_utils.cpp:155-166 | **Shed (likely).** Ring-era decoy-uniformity heritage; pointless once coinbase outputs are committed. Captured regtest coinbases already have `vout=1`. **OPEN (§6 Q2):** confirm `max_outs`/decomposition never yields >1 output in genesis params; if so, formalize "coinbase = single output." |

## 3. Canonical genesis layout (post-arbitration)

Byte order, top to bottom. `V(x)` = varint (format pinned per §6 Q10); `[n]` = n
raw bytes; `vec(f)` = `V(len)` then `len ×` f.

```
Block            := BlockHeader  Transaction(miner)  V(n_tx)  n_tx×Hash[32]
BlockHeader      := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32]
Transaction      := V(version=3)  TxPrefix  Rct
TxPrefix         := V(unlock_time)  vec(Input)  vec(Output)  V(extra_len) extra[extra_len]
Input            := tag(1) ...        # tags: ff gen | 02 fcmp | 03 stake_claim | 04 serve_credit | 05 bond_post   (00/01 SHED; numbering = Q7)
Output           := V(amount) tag(1) ...   # tags: 03 tagged_key | 04 staked_key   (00/01 SHED; 02 OPEN)
Rct              := rct_type(1) ...
  if Null  (coinbase):  enc_amounts[nout×9]  enc_labels[nout×9]  outPk[nout×32]
  if Fcmp  (spend):     V(fee) referenceBlock[32] enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]
                        PqcAuths  Prunable
PqcAuths         := nvin × { auth_version(1) scheme_id(1) flags(u16 LE) vec(u8) vec(u8) }   # EOF-tolerant (pruned form omits)
Prunable         := V(nbp) nbp×BpPlus  V(tree_depth) V(proof_len) fcmp[proof_len]  pseudoOuts[nvin×32]
```

`BpPlus` and `fcmp[proof_len]` interiors are genesis-frozen but defined in the
crypto crates, **not opaque** — see §6 Q6. `txin_fcmp` body and the archival-arm
bodies are in §2; full byte tables land in Round 1 once the OPEN items resolve.

## 4. Architecture of the clean crate

- **Scope (Q5 resolved): owns block + header + PoW hashing-blob + tx.** The
  header is the same genesis-freeze class as the tx; the block embeds the miner tx
  inline (block serialization already depends on tx serialization → one crate, no
  seam); and the PoW hashing-blob (which header bytes feed RandomX, in what order)
  is a cross-platform bit-determinism invariant tightly coupled to header
  serialization, so splitting invites drift. **Clean boundary:** this crate
  produces the canonical hashing blob; `shekyl-pow-randomx` consumes it and
  computes the hash (the RandomX computation stays put).
- **One unified `Input` / `Output` enum** — Shekyl arms only; the archival arms
  (`bond_post`, `serve_credit_response`) are folded in here, not split across
  `shekyl-archival-retention` (which keeps the *semantic* types; the **wire**
  encoding is owned here). This closes the bond-post parse gap.
- **No `Pruned`/`NotPruned` generic, but no `Option<prunable>` footgun either.**
  Honest parse result `Transaction { prunable: Option<Prunable>, .. }`; plus a
  typed view `into_full() -> Result<FullTransaction, PrunedError>` where
  `FullTransaction` *guarantees* `prunable` present. Consensus code that requires
  a full tx takes `FullTransaction`, so "pruned tx where full required" is
  unrepresentable at the one boundary it matters — without threading a generic
  through every consumer.
- **Explicit `Rct { base, pqc_auths, prunable }`** matching §2.3 — `referenceBlock`
  in `base`, `curve_trees_tree_depth` in `prunable`, `pqc_auths` tx-level — fixing
  the three misplacements in the current `shekyl-oxide` model.
- **Migration:** the ~58 consumer sites in `shekyl-tx-builder`, `shekyl-scanner`,
  `shekyl-engine-core`, `shekyl-ffi`, `shekyl-cli` move off
  `shekyl_oxide::{block,transaction}`. `shekyl-oxide`'s block/tx modules are
  deleted; its crypto primitives stay. **Sequence the delete to not collide with
  in-flight wallet-rewrite work** in `shekyl-engine-core`/`shekyl-scanner` (§8).

## 5. Gate-(c) C++ oracle changes (deliberate, pre-genesis)

These are **genesis-format definition**, not "patching C++" — they *remove*
inherited cruft ([`60-no-monero-legacy`]) so the oracle emits the arbitrated
format:

1. Remove `txin_to_script`/`txin_to_scripthash`/`txout_to_script`/
   `txout_to_scripthash` from `txin_v`/`tx_out` + the `VARIANT_TAG` lists.
2. Reshape `txin_to_key` → drop `key_offsets` (pending Q1).
3. Force single-output coinbase / remove dust decomposition (pending Q2).
4. Any tag renumbering decided in Q7.

Each lands as its own change with C++ + Rust + a locked vector, byte-identity
re-verified against the *new* oracle. Until a given cut lands, the corpus pins
the pre-cut bytes; the cut flips both sides together (§7 atomic-flip).

## 6. Freeze-gate list (resolve before Round 1)

Format: **ID — item.** *(status)* disposition / what's needed.

- **Q1 — `txin_fcmp` minimal fields.** *(OPEN, needs spend blob + source)* Does the
  daemon FCMP++ verify read `amount`/`key_offsets` at all, or only `key_image`?
- **Q2 — coinbase output count.** *(OPEN, source-resolvable)* Does
  `decompose_amount_into_digits` + `max_outs` ever yield >1 coinbase output under
  genesis params? If never, formalize single-output and shed the chunking.
- **Q3 — `txout_to_key`(0x2) producer.** *(OPEN, source-resolvable)* Anything emit
  plain (non-tagged, non-staked) outputs? If not, shed.
- **Q4 — archival arm finality.** *(RESOLVED → two-wave freeze)* Freeze in **two
  waves**: Wave 1 = settled surface (gen, fcmp, stake, outputs, rct) — stand up
  the crate + corpus green on these. Wave 2 = `0x4`/`0x5` once the archival
  workstream signs off, under a **single combined wire+semantics sign-off** (do
  not recreate the two-owner split that produced the `shekyl-oxide` confusion).
- **Q5 — crate scope.** *(RESOLVED → yes)* Own block header + PoW hashing-blob +
  tx; `shekyl-pow-randomx` consumes the blob. Rename the crate (it's more than
  "tx-wire"); see §1/§4.
- **Q6 — proof / Bp+ canonical-serialization coverage.** *(OPEN — the freeze is
  incomplete without it)* `fcmp_pp_proof` and `nbp×BpPlus` are the largest, most
  complex consensus bytes, genesis-frozen (prover and verifier must agree
  byte-for-byte), and they live in the kept-vendored `crypto/fcmps` /
  generalized-bulletproofs crates — a genesis-frozen surface *outside this spec*.
  The freeze must cover it **by reference**: "the proof / BpPlus canonical byte
  layout is part of this freeze, defined at `<fcmps location>`, frozen at
  `<commit>`." **Cross-link:** the 4 Shekyl-stamped crypto files flagged for
  crypto-crate triage may be exactly the proof-serialization divergence (recon /
  root-hash-convention) — meaning the kept-vendored set carries genesis-frozen
  *format*, which raises the bar on that triage.
- **Q7 — tag-numbering decision.** *(OPEN, your call)* We shed the dead arms but
  kept Monero's tag *values* (`gen=0xff`, spends at `0x2`, holes at `0x0`/`0x1`).
  Decide deliberately: renumber densely (`gen=0x0, fcmp=0x1, stake=0x2,
  serve_credit=0x3, bond_post=0x4`) **or** keep inherited values with a stated
  reason. Same for the **rct type value** (`Fcmp=7` is "next after Monero's six";
  clean-sheet would be `1`) and the **top-level variant tags**
  `transaction=0xcc` / `block=0xbb` (basic.h:862-863) — confirm those aren't a
  frozen wire surface, or arbitrate them too. Keep-by-default is the
  half-transcription §0 rejects; it's a freeze either way.
- **Q8 — `enc_label` indistinguishability invariant.** *(RESOLVED → §2.3)*
  Recorded as a binding serializer rule (fixed-size every output, real-or-zero,
  never elided). Listed here so the freeze gate carries it.
- **Q9 — `view_tag` rationale.** *(RESOLVED → §2.2)* Ratify w/ recorded
  rationale (X25519 scan prefilter; accepted 1-byte scan-correlation cost).
- **Q10 — varint format.** *(OPEN — Round-1 must)* §3 uses `V(x)` everywhere but
  never pins the encoding; "corpus is spec" can't rest on the most fundamental
  primitive being unwritten. Proposed pin: the LEB128-style little-endian
  base-128 varint — 7 data bits/byte, MSB = continuation, **canonical** (no
  redundant trailing-zero byte; over-long encodings rejected) — as implemented in
  `rust/shekyl-oxide/shekyl-oxide/io/src/lib.rs` (`read_varint`/`write_varint`).
- **Q11 — staked-output cleartext amount vs cover model.** *(OPEN, privacy —
  coordinate w/ staking)* Cleartext is consistent with public bonds, but net flow
  is *stake + cover*, not clean bond — verify the on-chain amount doesn't leak
  what the cover is meant to obscure.

## 7. Differential methodology (extends CONSENSUS_PORT_SEQUENCE §3)

- **Positive corpus:** raw daemon blobs (coinbase ✓ captured; spend, staked,
  multi-tx, each archival vin) → `read` then `write` == arbitrated bytes.
- **Negative/boundary corpus:** a structured fuzzer + hand-built cases — the
  EOF-tolerant `pqc_auths` boundary (truncation before/at/into prunable; partial
  length prefix), shed-tag rejection (a `0x00`/`0x01` input must be **rejected**
  by both impls post-cut), over-long PQC blobs, non-canonical varints — gate =
  **identical accept/reject**, not round-trip.
- **Atomic-flip awareness (gate-(c) window).** Each shed/reshape cut lands in C++
  and Rust together. *Before* a cut, C++ still accepts the old form; *after*, both
  reject it. The differential gate must **track which side of each cut it is on**
  and never assert "Rust rejects" against a "C++ accepts" oracle during the
  window — same discipline as tracking the layout flip.
- **The spec is the freeze; the corpus exercises it; the test proves conformance
  to the written layout** — not to an unreadable pile of blobs.

## 8. Sequencing

1. Round 0 (this doc) → **approved**.
2. Resolve §6 OPEN items at source (Q1–Q3, Q6 location, Q10) + **capture a spend
   blob**; bring Q7/Q11 (+ Q4 Wave-2) to you for the calls.
3. **Round 1 (Wave 1):** freeze the settled byte tables (gen, fcmp, stake,
   outputs, rct, header, pow-blob), pin the varint, reference the proof/BpPlus
   freeze (Q6).
4. Stand up the clean crate to the Wave-1 spec; positive + **negative** corpus
   green vs the (gate-(c)-adjusted) oracle.
5. Migrate consumers; delete `shekyl-oxide` block/tx — **sequenced to avoid
   colliding with in-flight wallet-rewrite work**.
6. Land gate-(c) C++ cuts (each its own consensus change, atomic-flip).
7. **Wave 2:** freeze archival `0x4`/`0x5` under the combined wire+semantics
   sign-off; extend the crate + corpus.
