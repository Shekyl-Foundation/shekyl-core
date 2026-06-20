# Shekyl Genesis Transaction / Block Wire Format — Specification

**Status:** Round 0 **approved** 2026-06-20. Freeze-gate (§6) **resolved for
Wave 1**: Q11 resolved (staking is the `P` model — cleartext `txout_to_staked_key`
+ `txin_stake_claim` shed; the bond floor is *public-but-covered-and-dissociated*
on the Wave-2 `bond_post` arm, no Wave-1 impact) and merged into Q4; Q12 resolved
(genesis tx **`version = 3`**, kept deliberately — `V4` = future lattice-only).
**Round-1 / Wave-1 freeze drafted** (§9–§14: byte tables, resource bounds,
hashing layer, reject rules, domain constraints) — pending your ratification, plus
two new creation cuts it surfaced (trailing-byte exact-consumption; explicit
`fcmp_proof` cap). Settled surface = `gen`+`fcmp` inputs, `tagged_key` output, ct,
header, pow-blob, tx `version=3`. The only deferred surface is **Wave 2** (the
`P`-model staking-archival arms), which freezes later with the staking-archival
workstream by design. **This document, once ratified, IS the genesis freeze** for the binary
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
   the block/tx/ct *protocol* code is ours ([`10-shekyl-first`]).
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
gate-(c) cut (C++ `VARIANT_TAG`s + the ct type enum flip with Rust atomically,
§5/§7). *(Exact assignments below are the proposed scheme; ratified at Round 1.)*

```text
Wave-1 frozen (settled surface):
  Input arm        Output arm         ct type
  0x00  gen        0x00  tagged_key   0x00  Null (coinbase)
  0x01  fcmp                          0x01  Fcmp (spend)

Wave-2 (P-model staking-archival; tags finalized at the Wave-2 freeze):
  0x02  archival_serve_credit_response   # gate-2 serve-credit
  0x03  archival_bond_post               # gate-4 join-Market/bond (carries P)

Shed entirely (no genesis producer — removed from the tag space):
  txin/txout script + scripthash; plain txout_to_key;
  txout_to_staked_key (cleartext stake out); txin_stake_claim (cleartext claim)
```

**Staking is the `P` model, not a staking-specific arm (Q11 resolved).** Genesis
staking is transfer-shaped admission under the firewalled pseudonym `P`. The
cleartext claim wire is **deleted** for genesis, and cleartext `txout_to_staked_key`
+ `txin_stake_claim` are **shed** (`PHASE_2B_SECTION7_DRAFT.md:288`,
`PHASE_2B_FSM_RETOOL.md:94`). What the privacy model actually is:

- **A public bond floor *is* on the wire — necessarily.** The `bond_post` arm
  (Wave 2) carries `bonded_total_atomic == bond_credit == bond_floor(holdings)`
  (cleartext; `==`, not `≥`), riding the CT balance
  (`Σ pseudoOuts = Σ out_masks + fee + bond_credit`,
  `rust/shekyl-archival-bond-builder/src/lib.rs`). Consensus must verify the bond
  meets the floor, so this amount **cannot be hidden**; `==` (not `≥`) closes the
  over-bond Sybil fingerprint (`PHASE_2B_SECTION7_DRAFT.md:84`).
- **Privacy = `P` dissociation + cover, not a hidden floor.** The floor is
  decorrelated from the staker by (a) the firewalled pseudonym `P`, and (b) the
  **cover**: the principal sends `bond_floor + cover` to `P`; `P` stakes the floor
  and holds the `cover` as a **confidential change-to-`P` output** in the
  surrounding CT transaction, so linking a known principal spend to the public bond
  post requires *guessing the cover* (`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §SP-2.d,
  :471-516). The `cover` is an ordinary confidential `tagged_key` output — **no
  special wire field**; `CoverAmount` orchestration ships inert and lands with 2d
  bond-tx assembly (genesis-adjacent).
  - **Wave-2 security crux (not a wire item):** the cover defense reduces entirely
    to the **entropy of the cover draw** (`:479-480` is "requires guessing the
    cover"). There is a built-in tension — `P` holds the cover as *working capital*
    (`:472`), and an amount chosen for operational utility pulls toward
    predictability (correlated with `P`'s activity), while the correlation defense
    wants high entropy. The `shekyl-standoff` entry-draw exists to arbitrate
    exactly this. It is a Wave-2 / `CoverAmount` property to pin (genesis-adjacent,
    2C2B:625) — it does **not** touch the Wave-1 surface, but it is the security
    crux of the cover model and must be pinned before the bond-tx assembly lands.
- Admission + reward outputs are otherwise ordinary main-tree stealth
  (`tagged_key`, confidential); reward emission is membership-only with **no
  published nullifier/tag** (`PHASE_2B_FSM_RETOOL.md:87-94`).

So Q11 resolves: the genesis wire carries a **public, necessarily-clear bond
floor**, and the staker's real economic position is masked by `P` + cover — not by
hiding the floor. The cover rides normal CT (no special field), so there is **no
Wave-1 wire impact**; the `bond_post` floor freezes with Q4 in Wave 2.

The dead `script`/`scripthash` arms are gone from the tag space entirely (not
holes). The top-level C++ `transaction=0xcc` / `block=0xbb` variant tags never
appear on the consensus blob (confirmed: no wire usage) — not a genesis surface.

### 2.1 Input arms (`txin_v`, :316)

| Tag | C++ arm | Disposition | Rationale / layout |
|---|---|---|---|
| `0xff` | `txin_gen` (:126) | **Ratify** | coinbase height (varint). |
| `0x00` | `txin_to_script` (:135,851) | **Shed** | CryptoNote placeholder, no producer. Remove from genesis tag space. |
| `0x01` | `txin_to_scripthash` (:148,852) | **Shed** | idem. |
| `0x02` | `txin_to_key` + `key_offsets` (:163,166) | **Reshape → `txin_fcmp`** (Q1 resolved) | Genesis `txin_fcmp` = `k_image[32]` **only**. `key_offsets` is consensus-**required empty** for FCMP++ inputs (`blockchain.cpp:3715`); `amount` is `0` and unused — FCMP++ membership is `shekyl_fcmp_verify` against the curve-tree root, not the legacy ring path (`scan_outputkeys_for_indexes`/`get_output_key` by amount+offsets). Both vestigial → dropped. |
| `0x03` | `txin_stake_claim` (:176) | **Shed (Q11 resolved)** | The cleartext claim wire is **deleted for genesis**. Staking is the `P` model: transfer-shaped admission, reward emission membership-only with **no published nullifier/tag** (`PHASE_2B_FSM_RETOOL.md:87-94`, `PHASE_2B_SECTION7_DRAFT.md:288`). No `txin_stake_claim` on the genesis wire. |
| `0x04` | `txin_archival_serve_credit_response` (:290) | **Spec + ratify** (Wave 2; coordinate w/ archival track) | `p_canonical_id[32] VARINT(shard_id) VARINT(settlement_epoch) segment_subroot_rk[32] leaf_index_in_segment(u32 LE) leaf_bytes[ARCHIVAL_LEAF_BYTES] path{c1_layers,c2_layers : vec<vec<hash>>} hybrid_signature(varint+bytes)`. |
| `0x05` | `txin_archival_bond_post` (:264) | **Spec + ratify + UNIFY** (Wave 2; unrepresented in Rust today) | `hybrid_public_key(varint+bytes) p_canonical_id[32] post_kind(u8) holdings{kind_u8, [shard_ids vec if ShardSetCompact]} VARINT(bonded_total_atomic) VARINT(bond_credit) VARINT(bond_debit)`. |

The archival arms (`serve_credit` 0x04, `bond_post` 0x05) **are** the genesis
staking-archival mechanism (the `P` model): `bond_post` is the gate-4 join-Market
event carrying `P`'s `hybrid_public_key` + `p_canonical_id`
(`ARCHIVAL_BOND_GATE4.md`, `PHASE_2B_FSM_RETOOL.md` §9); `serve_credit` is the
gate-2 serve-credit response. Shekyl-native, no spec outside
C++/`shekyl-archival-*` — this table is their only human-readable definition and
the highest load-bearing corpus cells. They freeze in **Wave 2** (§6 Q4, §8)
under a **single combined wire+semantics sign-off** with the staking-archival
workstream — which now subsumes Q11 (staking has no separate wire surface).

### 2.2 Output arms (`tx_out`)

| Tag | C++ arm | Disposition | Layout |
|---|---|---|---|
| `0x00` | `txout_to_script` (:857) | **Shed** | dead. |
| `0x01` | `txout_to_scripthash` (:858) | **Shed** | dead. |
| `0x02` | `txout_to_key` (:859) | **Shed (Q3 resolved)** | No genesis producer — coinbase emits tagged_key; the Rust tx-builder always sets a `view_tag` (`shekyl-tx-builder/src/wire.rs:94-98` → tagged_key); the only `txout_to_key` site is legacy `wallet2.cpp:13220` building a *synthetic local* tx prefix (retiring), not an on-chain producer. **`view_tag` becomes mandatory** — every transfer output is tagged_key. |
| `0x03` | `txout_to_tagged_key` (:860) | **Ratify** (genesis `0x00`) | `key[32] view_tag(1)`. The **sole** genesis output type. |
| `0x04` | `txout_to_staked_key` (:861) | **Shed (Q11 resolved)** | Retire C++ legacy — genesis staking outputs are ordinary main-tree stealth (`tagged_key` to `P`); the principal is a `C_stake` Pedersen commitment kept **off-wire** in the wallet's `StakeInstance`, and tier/lock metadata is off-wire too (`PHASE_2B_STAKE_LIFECYCLE.md:259,466`). No on-chain staked-output type. |

Each output is preceded by `VARINT(amount)` (cleartext for the coinbase output;
`0` for confidential transfer outputs). With plain `txout_to_key` **and**
`txout_to_staked_key` shed, **`tagged_key` is the sole genesis output type** — the
Rust `Output` makes `view_tag` non-optional (no `Option<u8>`), so a view-tag-less
output is unrepresentable. Staking outputs are just `tagged_key` to `P`; their
commitment + lock metadata live off-wire.

**`view_tag` (1 byte) — RATIFY, rationale recorded.** Not Monero vestige: it is
the view-tag fast-reject *rederived into Shekyl's hybrid X25519 path* —
`keccak256("view_tag" ‖ output_derivation)[0]` off the X25519 ECDH output
(`rust/shekyl-scanner/src/shared_key.rs:65`), used as the scan prefilter
(`bench_fixtures.rs`, `first_output_exits_via_view_tag_mismatch`). **Accepted
tradeoff (binding):** a deliberately-accepted 1-byte scan-correlation cost in
exchange for the prefilter; recorded here as an *accepted* cost, not a silently
inherited one.

### 2.3 CT section

**Terminology:** *CT = confidential transaction.* There is no RingCT — Monero's
rings/decoys are gone — so this PR says **CT**, not RCT. The C++ `rct*` source
names (`rctTypes.h`, `rct_signatures`) are cited as-is here and rename to `ct*`
via the gate-(c) JSON change (§5; `CONSENSUS_PORT_SEQUENCE.md` Pin A).

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
Transaction      := V(version=3)  TxPrefix  Ct        # genesis version=3 (Q12: deliberate keep; V4 = future lattice-only)
TxPrefix         := V(unlock_time)  vec(Input)  vec(Output)  V(extra_len) extra[extra_len]
Input            := tag(1) ...        # Wave-1: 00 gen | 01 fcmp.  Wave-2 (P-model): 02 serve_credit | 03 bond_post.  (stake_claim shed)
Output           := V(amount) tag(1) ...   # 00 tagged_key — sole genesis output (staked_key + plain key shed; view_tag mandatory)
Ct               := ct_type(1) ...          # 00 Null (coinbase) | 01 Fcmp (spend)
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
- **Explicit `Ct { base, pqc_auths, prunable }`** matching §2.3 — `referenceBlock`
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

1. Remove the dead/shed arms from `txin_v`/`tx_out` + the `VARIANT_TAG` lists:
   `txin_to_script`/`txin_to_scripthash`/`txout_to_script`/`txout_to_scripthash`
   (CryptoNote), plain `txout_to_key` (Q3), and **`txout_to_staked_key` +
   `txin_stake_claim`** (Q11 — cleartext staking retired; genesis uses the `P`
   model). The archival arms (`serve_credit`/`bond_post`) stay (Wave 2).
2. **Renumber the surviving tags to the §2.0 dense scheme** — input/output
   variant tags + the ct type enum (`Null=0x00`, `Fcmp=0x01`). One pervasive
   atomic flip (C++ `VARIANT_TAG` values + Rust), so the corpus re-pins on the
   post-renumber bytes.
3. Reshape `txin_to_key` → `txin_fcmp`, drop `key_offsets` (pending Q1).
4. Remove the `decompose_amount_into_digits` machinery — `max_outs=1` already
   forces a single coinbase output (Q2 resolved), so the decomposition is dead
   code; formalize the single-output invariant.
(Tx `version` stays `3` — Q12 resolved keep-with-reason, no gate-(c) change.)

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
- **Q4 — archival / staking-archival arm finality.** *(RESOLVED → two-wave freeze)*
  Wave 1 = settled surface (`gen`+`fcmp` inputs; `tagged_key` output; ct; header;
  pow-blob) — stand up the crate + corpus green on these. Wave 2 = the **P-model
  staking-archival arms** (`serve_credit` 0x02, `bond_post` 0x03 — now incl. Q11's
  staking surface) once the staking-archival workstream signs off, under a
  **single combined wire+semantics sign-off** (don't recreate the two-owner split
  that produced the `shekyl-oxide` confusion). The workstream is in flux
  (`STAKER_ARCHIVAL_SIM` iter 3; `certify_draw` track), so these tags are **not**
  Wave-1 frozen.
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
  (inputs `0x00`–`0x04`, outputs `0x00`–`0x01`, ct `Null=0x00`/`Fcmp=0x01`); dead
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
- **Q11 — staked amount vs cover model.** *(RESOLVED → public floor + cover + `P`;
  merged into Q4)* Cleartext `txout_to_staked_key` + `txin_stake_claim` are shed,
  but genesis staking is **not** amount-less on the wire: the `bond_post` arm
  (Wave 2) carries a **public bond floor** (`bonded_total == bond_credit ==
  bond_floor`, `==` not `≥`), necessarily clear because consensus must verify the
  bond meets the floor. Privacy is **`P` dissociation + cover**, not a hidden
  floor: the principal sends `bond_floor + cover`; the `cover` is a confidential
  change-to-`P` output, so correlating a known principal spend to the public post
  requires guessing it (`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §SP-2.d:471-516). `==`
  closes the over-bond Sybil fingerprint (`PHASE_2B_SECTION7_DRAFT.md:84`). The
  cover is ordinary CT (no wire field) → **no Wave-1 impact**; the `bond_post`
  floor freezes with Q4 in Wave 2. *(Corrects an earlier "no public amount"
  framing.)*
- **Q12 — transaction version value.** *(RESOLVED → keep `3`, deliberately)*
  Applying Q7 ("choose, don't inherit-by-default") lands on **keep `version = 3`** —
  the *opposite* of the tag renumber, because the number `3` carries real Shekyl
  meaning. It is the established genesis version across `CURRENT_TRANSACTION_VERSION`
  (`cryptonote_config.h:48`), the binaries, and the docs (incl.
  `docs/VERSIONING.md`), and it slots into the canonical **V3-genesis → V4
  lattice-only** roadmap (`00-mission.mdc:19`), where the fully-PQC future is `4`.
  Keeping `3` also makes it unambiguous in C++ review that *Shekyl's v3 is not
  Monero's v1* (CryptoNote). Tags renumbered because their values were meaningless
  to Shekyl; `version` stays `3` because its value is load-bearing. **No gate-(c)
  change.**

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
   outputs, ct, header, pow-blob), pin the varint, reference the proof/BpPlus
   freeze (Q6).
4. Stand up the clean crate to the Wave-1 spec; positive + **negative** corpus
   green vs the (gate-(c)-adjusted) oracle.
5. Migrate consumers; delete `shekyl-oxide` block/tx — **sequenced to avoid
   colliding with in-flight wallet-rewrite work**.
6. Land gate-(c) C++ cuts (each its own consensus change, atomic-flip).
7. **Wave 2:** freeze archival `0x4`/`0x5` under the combined wire+semantics
   sign-off; extend the crate + corpus.

---

# Round 1 — Wave-1 freeze (byte tables + bounds + hashes + reject rules)

**Status:** Round-1 draft (2026-06-20), for ratification. A genesis freeze is not
just byte order — it is also the **bounds**, the **hashes**, and the
**canonical-form/reject rules**, each of which freezes identically. All
source-confirmed at `dev`. Integers little-endian; `V(x)` = canonical varint
(§6 Q10); `cn_fast_hash` = keccak-256.

## 9. Wave-1 frozen byte layout

Genesis tags per §2.0. *(The C++ oracle still emits pre-renumber tag values until
the gate-(c) flip lands, §5; the captured corpus in `src/tests/vectors/` reflects
pre-renumber tags until recapture.)*

**9.1 BlockHeader** — `V(major) · V(minor) · V(timestamp) · prev[32] · nonce(u32 LE) · curve_tree_root[32]`; genesis `major=1, minor=0` (§13).
**9.2 Block** — `BlockHeader · Transaction(miner) · V(n_tx) · n_tx×Hash[32]`.
**9.3 Transaction** — `V(version=3) · TxPrefix · Ct`.
**9.4 TxPrefix** — `V(unlock_time) · vec(Input) · vec(Output) · V(extra_len) · extra[extra_len]`.
**9.5 Inputs** — `gen 0x00`: `tag(1) · V(height)`. `fcmp 0x01`: `tag(1) · key_image[32]` (no `amount`/`key_offsets`, Q1).
**9.6 Outputs** — `tagged_key 0x00` (sole type): `V(amount) · tag(1) · key[32] · view_tag(1)` (amount cleartext for coinbase, `0` for confidential spend outputs).
**9.7 Ct** — `ct_type(1)` then:
- `Null` (coinbase, 1 output): `enc_amounts[1×9] · enc_labels[1×9] · outPk[1×32]`
- `Fcmp` (spend): `V(fee) · referenceBlock[32] · enc_amounts[nout×9] · enc_labels[nout×9] · outPk[nout×32] · PqcAuths · Prunable`

  `enc_amount`/`enc_label` = 8B value + 1B tag (9B); `outPk` = 32B commitment;
  the `enc_label` indistinguishability invariant (§2.3) is binding.
**9.8 PqcAuths** (spend only; count = `nvin`, **no length prefix**; EOF-tolerant on read) — per input: `auth_version(1) · scheme_id(1) · flags(u16 LE) · V(pk_len)·pk · V(sig_len)·sig`.
**9.9 Prunable** (Fcmp) — `V(nbp=1) · BpPlus · V(curve_trees_tree_depth) · V(proof_len) · fcmp_proof[proof_len] · pseudoOuts[nvin×32]`. `BpPlus` + `fcmp_proof` interiors frozen by reference (§6 Q6).

## 10. Resource bounds (frozen limits — reject on exceed)

| Bound | Value | Enforced | Constant |
|---|---|---|---|
| inputs / tx | **8** | blockchain.cpp:3618 | `FCMP_MAX_INPUTS_PER_TX` (config:211) |
| outputs / tx | **16** | BP+ layout (rctSigs.cpp:211; tx_verification_utils.cpp:213) | `BULLETPROOF_PLUS_MAX_OUTPUTS` (config:241) |
| tx size | **1,000,000** | tx_verification_utils.cpp:63 | `CRYPTONOTE_MAX_TX_SIZE` (config:44) |
| tx_extra | **24,576** | cryptonote_tx_utils.cpp:579 | `MAX_TX_EXTRA_SIZE` (config:254) |
| PQC pubkey blob | **1,996** single / 13,974 multisig-max | cryptonote_basic.h:347 | `PQC_HYBRID_SINGLE_KEY_LEN` / `PQC_MAX_PUBLIC_KEY_BLOB` (config:291) |
| PQC sig blob | **3,385** single / 23,697 multisig-max | cryptonote_basic.h:350 | `PQC_HYBRID_SINGLE_SIG_LEN` / `PQC_MAX_SIGNATURE_BLOB` (config:293) |
| `nbp` | **== 1** (one aggregated BP+) | tx_verification_utils.cpp:213 | `is_canonical_bulletproof_plus_layout` |
| `curve_trees_tree_depth` | `0 < depth ≤ chain depth` (dynamic) | blockchain.cpp:3964,4070 | — |
| `fcmp_proof` len | **NO explicit cap** (only tx-size) | — | **GAP — add an explicit cap at genesis (creation cut)** |

Each is a §7 negative-corpus reject case (a 9-input or 17-output tx must be
rejected by both impls).

## 11. Hashing layer (consensus identities)

- **Tx hash** = `cn_fast_hash` over concatenated component hashes (format_utils.cpp:1200-1252):
  - coinbase (`Null`, no pqc): **3-part** `H(prefix) · H(base) · null_hash`
  - spend (`Fcmp`, pqc present): **4-part** `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`

  where `H(prefix)` = `get_transaction_prefix_hash` (version + prefix fields),
  `H(base)` = hash of `serialize_ct_base`, `H(pqc_auths)` = hash of the serialized
  pqc_auths vec, `H(prunable)` = hash of prunable (`null_hash` for coinbase).
- **Pruning stable (pruned == full).** `pqc_auths` are **unprunable** (kept in the
  pruned form, format_utils.cpp:1204) and `prunable_hash` is retained, so all
  components match → identical tx hash. *(The EOF-tolerant pqc-auths-empty form is
  a genuinely different tx with the 3-part hash — correct, not a collision.)*
- **Block hash** = `cn_fast_hash( V(len) · hashing_blob )`, where
  `hashing_blob = BlockHeader · tx_tree_hash · V(tx_count+1)`. The `V(len)` prefix
  comes from `get_object_hash` serializing the blob as a string
  (format_utils.h:178-183, .cpp:1303-1323). **The PoW hash uses `hashing_blob`
  WITHOUT the `V(len)` prefix** — the two preimages differ.
- **tx_tree_hash** = Merkle tree-hash over `[ miner_tx_hash, tx_hashes… ]`
  (format_utils.cpp:1449-1472).
- The block-202612 hash special-case is Monero chain history — a dead pre-genesis
  branch; **shed** ([`60-no-monero-legacy`]); the vendored Rust `block.rs` carries
  it and the clean crate must drop it.

## 12. Canonical-form / reject rules (must-reject enumeration)

- **Inputs strictly ascending by key image** — `memcmp(ki, last) >= 0 → reject`
  (blockchain.cpp:3642-3663). One rule, two guarantees: rejects **unsorted** AND
  **in-tx duplicate** key images. (fcmp inputs; gen has none.)
- **Non-canonical varints rejected** (Q10).
- **unlock_time timestamp form rejected** — `unlock_time >=
  CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL (500,000,000) → reject` (blockchain.cpp:3473).
  unlock_time is a **block height only** — a creation cut (Monero allowed the
  timestamp form); otherwise unconstrained for non-coinbase.
- **Trailing bytes — GAP at the oracle; CLOSE at genesis.** `parse_and_validate_tx_from_blob`
  (format_utils.cpp:183) does **not** check exact consumption (no remaining-bytes
  check, no re-serialize compare), so appended garbage yields a different blob for
  the same tx (malleability). **The genesis Rust serializer MUST enforce exact
  consumption** (reject trailing bytes on tx + block parse) — a deliberate creation
  cut; the matching C++ fix is a gate-(c) change.
- Cross-tx/chain double-spend (key image already spent) — blockchain.cpp:3521
  (chain-state, not a parse rule).

Gate = **identical accept/reject** (§7), not round-trip.

## 13. Domain constraints (validator-enforced consensus rules)

- **Coinbase:** `vin.size()==1` (blockchain.cpp:1524); `vin[0]==gen` (1525);
  `gen.height==block height` (1529); `ct type==Null` (1527); single output
  (`max_outs=1`, 1900); `unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`
  (`=60`, 1535); outputs sum == block reward (`validate_miner_transaction`).
- **pqc_auths binding:** `count == vin.size()` (blockchain.cpp:3752);
  `auth_version == 1` (tx_pqc_verify.cpp:169); `scheme_id ∈ {1 single, 2 multisig}`
  (tx_pqc_verify.cpp:181); **`flags == 0` — unknown bits rejected, not ignored**
  (tx_pqc_verify.cpp:175); serve_credit txs carry **empty** pqc_auths.
- **referenceBlock window:** `tip − FCMP_REFERENCE_BLOCK_MAX_AGE(100) ≤ ref_height
  ≤ tip − FCMP_REFERENCE_BLOCK_MIN_AGE(5)` (blockchain.cpp:3946-3954). (§2.3
  specifies the field; this is its validity window.)
- **CT balance:** `Σ pseudoOuts == Σ outPk + fee` (+ `bond_credit` for bond-post) —
  `verRctSemanticsSimple` / `shekyl_fcmp_verify` (tx_verification_utils.cpp:234;
  blockchain.cpp:4125). The general spend rule (the bond floor §2.0 is the
  bond-post case of this).
- **Versions:** block `major=1, minor=0`; tx `version=3` (Q12). The format is
  version-frozen — a later format is a hard fork (V4 = lattice-only).

## 14. Round-1 findings (new creation cuts surfaced by the freeze pass)

1. **Trailing-byte malleability gap** (§12) — close at genesis: the Rust
   serializer enforces exact consumption; C++ gate-(c) matches.
2. **`fcmp_proof` has no explicit length cap** (§10) — add one at genesis rather
   than relying on the 1 MB tx-size bound (a tighter, explicit consensus limit).

Both are pre-genesis creation cuts (free now, hard forks later).
