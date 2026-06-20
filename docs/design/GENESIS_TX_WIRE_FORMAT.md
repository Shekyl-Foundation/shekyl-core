# Shekyl Genesis Transaction / Block Wire Format — Specification

**Status:** Round 0 **approved** 2026-06-20; freeze-gate (§6) resolved down to two
items — **Q11** (staked amount vs cover model, a staking call) and **Q4 Wave-2**
(archival arm sign-off). Q1–Q10 + Q5 are closed (incl. Q1 at source: `txin_fcmp`
= `key_image` only; Q7 clean tag renumber). The Round-1 / Wave-1 freeze is ready
pending the Q11 call. **This document, once ratified, IS the genesis freeze** for the binary
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

### 2.0 Genesis tag scheme (Q7 resolved — clean renumber)

**Decision:** Monero is a proven *pattern*, not a *basis*. We will never meet the
old chain on-wire, so we number tags as Shekyl needs them — dense from `0x00`,
not the inherited values. The `§2.1`/`§2.2` "Tag" columns below are the **C++
source** values; the **genesis** values are this scheme. The renumber is a
gate-(c) cut (C++ `VARIANT_TAG`s + the rct type enum flip with Rust atomically,
§5/§7). *(Exact assignments below are the proposed scheme; ratified at Round 1.)*

```
Input arm tag        Output arm tag       rct type
  0x00  gen             0x00  tagged_key    0x00  Null (coinbase)
  0x01  fcmp            0x01  staked_key    0x01  Fcmp (spend)
  0x02  stake_claim     (plain key shed)
  0x03  archival_serve_credit
  0x04  archival_bond_post
```

The dead `script`/`scripthash` arms are gone from the tag space entirely (not
holes); the surviving arms pack densely. The top-level C++ `transaction=0xcc` /
`block=0xbb` variant tags never appear on the consensus blob (confirmed: no
wire usage) — they are not a genesis surface and carry no tag-scheme decision.

### 2.1 Input arms (`txin_v`, :316)

| Tag | C++ arm | Disposition | Rationale / layout |
|---|---|---|---|
| `0xff` | `txin_gen` (:126) | **Ratify** | coinbase height (varint). |
| `0x00` | `txin_to_script` (:135,851) | **Shed** | CryptoNote placeholder, no producer. Remove from genesis tag space. |
| `0x01` | `txin_to_scripthash` (:148,852) | **Shed** | idem. |
| `0x02` | `txin_to_key` + `key_offsets` (:163,166) | **Reshape → `txin_fcmp`** (Q1 resolved) | Genesis `txin_fcmp` = `k_image[32]` **only**. `key_offsets` is consensus-**required empty** for FCMP++ inputs (`blockchain.cpp:3715`); `amount` is `0` and unused — FCMP++ membership is `shekyl_fcmp_verify` against the curve-tree root, not the legacy ring path (`scan_outputkeys_for_indexes`/`get_output_key` by amount+offsets). Both vestigial → dropped. |
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
| `0x02` | `txout_to_key` (:859) | **Shed (Q3 resolved)** | No genesis producer — coinbase emits tagged_key; the Rust tx-builder always sets a `view_tag` (`shekyl-tx-builder/src/wire.rs:94-98` → tagged_key); the only `txout_to_key` site is legacy `wallet2.cpp:13220` building a *synthetic local* tx prefix (retiring), not an on-chain producer. **`view_tag` becomes mandatory** — every transfer output is tagged_key. |
| `0x03` | `txout_to_tagged_key` (:860) | **Ratify** (genesis `0x00`) | `key[32] view_tag(1)`. The sole transfer/coinbase output type. |
| `0x04` | `txout_to_staked_key` (:861) | **Ratify** (genesis `0x01`) | `key[32] view_tag(1) lock_tier(1)`. |

Each output is preceded by `VARINT(amount)` (cleartext for coinbase/staked; `0`
for confidential spend outputs). With plain `txout_to_key` shed, the output type
shape carries a `view_tag` unconditionally — the Rust `Output` type makes
`view_tag` non-optional (no `Option<u8>`), so a view-tag-less output is
unrepresentable.

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
| dust / power-of-10 chunking (`decompose_amount_into_digits`) | tx_utils.cpp:155-166 | **Shed (Q2 resolved).** The block template hardcodes `max_outs = 1` (`blockchain.cpp:1900`), so the decompose-then-merge loop *always* collapses the reward to a **single output** — the chunking is already dead weight. Formalize "coinbase = exactly one output"; the genesis serializer need not represent multi-output coinbases. |

## 3. Canonical genesis layout (post-arbitration)

Byte order, top to bottom. `V(x)` = varint (format pinned per §6 Q10); `[n]` = n
raw bytes; `vec(f)` = `V(len)` then `len ×` f.

```
Block            := BlockHeader  Transaction(miner)  V(n_tx)  n_tx×Hash[32]
BlockHeader      := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32]
Transaction      := V(version=3)  TxPrefix  Rct
TxPrefix         := V(unlock_time)  vec(Input)  vec(Output)  V(extra_len) extra[extra_len]
Input            := tag(1) ...        # genesis tags: 00 gen | 01 fcmp | 02 stake_claim | 03 serve_credit | 04 bond_post
Output           := V(amount) tag(1) ...   # genesis tags: 00 tagged_key | 01 staked_key   (plain key shed; view_tag mandatory)
Rct              := rct_type(1) ...         # 00 Null (coinbase) | 01 Fcmp (spend)
  if Null  (coinbase, exactly one output):  enc_amounts[1×9]  enc_labels[1×9]  outPk[1×32]
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
   `txout_to_scripthash` **and plain `txout_to_key`** from `txin_v`/`tx_out` + the
   `VARIANT_TAG` lists (Q3: no genesis producer of plain key).
2. **Renumber the surviving tags to the §2.0 dense scheme** — input/output
   variant tags + the rct type enum (`Null=0x00`, `Fcmp=0x01`). One pervasive
   atomic flip (C++ `VARIANT_TAG` values + Rust), so the corpus re-pins on the
   post-renumber bytes.
3. Reshape `txin_to_key` → `txin_fcmp`, drop `key_offsets` (pending Q1).
4. Remove the `decompose_amount_into_digits` machinery — `max_outs=1` already
   forces a single coinbase output (Q2 resolved), so the decomposition is dead
   code; formalize the single-output invariant.

Each lands as its own change with C++ + Rust + a locked vector, byte-identity
re-verified against the *new* oracle. Until a given cut lands, the corpus pins
the pre-cut bytes; the cut flips both sides together (§7 atomic-flip).

## 6. Freeze-gate list (resolve before Round 1)

Format: **ID — item.** *(status)* disposition / what's needed.

- **Q1 — `txin_fcmp` minimal fields.** *(RESOLVED at source)* Consensus *requires*
  `key_offsets` empty for FCMP++ inputs (`blockchain.cpp:3706-3721`), and `amount`
  is `0`/unused (membership via `shekyl_fcmp_verify` / curve tree, not the ring
  path). Genesis `txin_fcmp` = `k_image[32]` only. A spend blob is still useful as
  a positive-corpus item but is no longer a design blocker.
- **Q2 — coinbase output count.** *(RESOLVED)* `max_outs=1` (`blockchain.cpp:1900`)
  always collapses the reward to **one** output; shed the decompose machinery and
  formalize single-output (§2.4, §5).
- **Q3 — `txout_to_key`(0x2) producer.** *(RESOLVED → shed)* No genesis producer:
  coinbase + the Rust tx-builder (`wire.rs:94-98`) emit tagged_key; the only
  `txout_to_key` site is legacy `wallet2.cpp:13220` (synthetic-local, retiring).
  **`view_tag` becomes mandatory** (§2.2).
- **Q4 — archival arm finality.** *(RESOLVED → two-wave freeze)* Freeze in **two
  waves**: Wave 1 = settled surface (gen, fcmp, stake, outputs, rct) — stand up
  the crate + corpus green on these. Wave 2 = `0x4`/`0x5` once the archival
  workstream signs off, under a **single combined wire+semantics sign-off** (do
  not recreate the two-owner split that produced the `shekyl-oxide` confusion).
- **Q5 — crate scope.** *(RESOLVED → yes)* Own block header + PoW hashing-blob +
  tx; `shekyl-pow-randomx` consumes the blob. Rename the crate (it's more than
  "tx-wire"); see §1/§4.
- **Q6 — proof / Bp+ canonical-serialization coverage.** *(RESOLVED → freeze by
  reference)* The wire layer length-prefixes the proof as opaque bytes
  (`fcmp.rs:191`); the canonical interiors are defined in
  `rust/shekyl-oxide/crypto/fcmps/src/lib.rs` (FCMP++) and
  `rust/shekyl-oxide/shekyl-oxide/fcmp/bulletproofs/src/lib.rs` (Bp+). Round 1
  cites these + the pinned commit as part of the freeze. **Cross-link stands:**
  these kept-vendored crates carry genesis-frozen *format*, raising the bar on the
  crypto-crate triage (the 4 Shekyl-stamped files may be exactly this — recon /
  root-hash-convention).
- **Q7 — tag-numbering decision.** *(RESOLVED → clean dense renumber)* Monero is a
  proven *pattern*, not a *basis*: tags renumbered to the §2.0 dense scheme
  (inputs `0x00`–`0x04`, outputs `0x00`–`0x01`, rct `Null=0x00`/`Fcmp=0x01`); dead
  arms gone from the tag space, not held as holes. Top-level `transaction=0xcc` /
  `block=0xbb` (basic.h:862-863) confirmed **not on any consensus-wire surface**,
  so no decision needed. Lands as a gate-(c) atomic flip (§5).
- **Q8 — `enc_label` indistinguishability invariant.** *(RESOLVED → §2.3)*
  Recorded as a binding serializer rule (fixed-size every output, real-or-zero,
  never elided). Listed here so the freeze gate carries it.
- **Q9 — `view_tag` rationale.** *(RESOLVED → §2.2)* Ratify w/ recorded
  rationale (X25519 scan prefilter; accepted 1-byte scan-correlation cost).
- **Q10 — varint format.** *(RESOLVED — pinned)* LEB128-style little-endian
  base-128 varint — 7 data bits/byte, MSB = continuation, **canonical** (no
  redundant trailing-zero byte; over-long encodings rejected) — as implemented in
  `rust/shekyl-oxide/shekyl-oxide/io/src/lib.rs` (`read_varint`/`write_varint`).
  This is the `V(x)` of §3; non-canonical varints are a negative-corpus reject
  case (§7).
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
2. Q1–Q10 + Q5 closed (Q1 resolved at source). **Remaining before the Wave-1
   freeze:** your **Q11** call (staked amount vs cover) + **Q4 Wave-2** archival
   sign-off. A spend blob is captured later as a positive-corpus item, not a
   blocker.
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
