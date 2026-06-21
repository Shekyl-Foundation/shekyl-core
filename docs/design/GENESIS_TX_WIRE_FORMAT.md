# Shekyl Genesis Transaction / Block Wire Format — Specification

**Status:** Round 0 **approved** 2026-06-20. Freeze-gate (§6) **resolved for
Wave 1**: Q11 resolved (staking is the `P` model — cleartext `txout_to_staked_key`
+ `txin_stake_claim` shed; the bond floor is *public-but-covered-and-dissociated*
on the `bond_post` arm, no spend-surface impact) and merged into Q4; Q12 resolved
(genesis tx **`version = 3`**, kept deliberately — `V4` = future lattice-only).
**Spec-grounded — scope A (2026-06-20).** A design-doc review (the authoritative
specs in `docs/design/`, **not** the C++/Rust code, which is known-incomplete for
Shekyl-native elements) corrected the earlier code-derived draft; §15 catalogs the
gaps with cites. **Settled Shekyl-native arms are specced here from the design
docs** — `bond_post` incl. **`bond_spend_pk`** (gate-4 §3.4.1, §9.11),
`serve_credit` (gate-2 §5.1.1, §9.10), `tagged_key` output + **`tx_extra` 0x06/0x07**
(FA-6, §9.6a), corrected **`view_tag`** (ml_kem_ss/HKDF, §2.2). The **reward-emission
+ membership-only** arms are a **deferred sub-freeze** — tag + rule-interactions
pinned here, internal layout owned by their PRs (`REWARD_EMISSION_VIN_PLAN.md` /
`FCMP_MEMBERSHIP_ONLY.md`), not in code yet (§2.1). The **inherited Monero-lineage
surface** (block/header/hashing/coinbase shape/ct framing/bounds/varint) is
C++-oracle-validated and stable. **Authority:** design docs for Shekyl-native; C++
only for inherited.

**Not a freeze.** Pre-ratification obligations (review 2026-06-20, F1–F6):

1. **Impl catch-up — absorbed by the §4 clean-crate build + scanner migration, not
   standalone pre-work.** (a) `bond_spend_pk`: the **GF-1 key derivation already
   exists + is KAT'd** (`archival_p.rs:120-123,235`; `kat_archival_p_derive_v1.rs`) —
   what is open is only its **wire / consensus-record / sig-preimage surfacing**,
   which the clean crate encodes per §9.11. **Do not patch the current
   `bond_wire.rs`:** §4 retires that encoder into the clean crate, so patching it now
   is throwaway. (b) **FA-6 ML-KEM `view_tag`** (F2): the scanner+builder switch off
   the old X25519/keccak path (`shared_key.rs:65`; FA-6 impl is *"a separate PR"*,
   FA-6:13) **rides the ~58-consumer scanner migration** (§8) — 2d-1 (P-scan) is a
   scan pipeline that needs that scanner anyway. A `view_tag` frozen as ML-KEM
   against a scanner still on X25519 makes **every output silently fail to scan**,
   and the wire byte-corpus round-trips clean and never catches it → needs the
   **scan-time KAT** (§6 Q13), separate from byte-identity.
2. **Arm taxonomy + generalized §12/§13 (F1).** The frozen ki-ordering and
   `pqc_auths` rules were written for key-image-bearing fcmp spends; the no-ki arms
   (serve_credit, bond_post, and the deferred emission/membership-only) don't fit
   them. §2.5 states the genesis tx shapes + mixing; §12/§13 are generalized across
   the arm taxonomy so landing a deferred arm doesn't silently move a frozen rule.
3. **Deferred sub-freezes (F3), not "frozen by reference."** `reward_emission` +
   membership-only are **not in code yet**, so their layout is a forward promise:
   genesis **tag pinned here** (emission `0x04` dense / `0x06` C++),
   rule-interactions pinned (§2.5/§12/§13), internal layout owned by their PRs.
   Landing those PRs **may refine** these rules — noted, not silent. (It's just the
   two of us — a deferred sub-freeze we adjust together beats a false "frozen.")
4. **Differential corpus** green vs the gate-(c) oracle **plus** the scan-time KAT.

Until these close, the **inherited** surface is oracle-stable and the
**Shekyl-native** surface is spec-grounded; **neither is *ratified*.**

**This document is the genesis freeze instrument** for the binary block/tx wire
format: once ratified, the Rust serializer implements *it* (not C++), the
differential corpus proves conformance *to it*, and the C++ daemon is edited to
match where we deliberately diverge. **It is not yet ratified** (the four
obligations above). §9–§14 — byte tables, bounds (per-tx + block-level), hashing
(preimage + RandomX seed), the recursive canonical-encoding invariant + reject
rules, domain constraints — **stand for the inherited surface** (C++-oracle-validated)
and are spec-grounded for the Shekyl-native additions (§9.6a/§9.10/§9.11), pending
the obligations above. Scope (single wave, **no separate Wave 2**):
`gen`+`fcmp`+`serve_credit`+`bond_post` inputs (+ deferred `reward_emission` and
membership-only, §2.1), `tagged_key` output, ct, header, pow-blob, tx `version=3`.
**rule-21 reopen** (a testnet-revealed change) stays free pre-genesis. **Process:**
multi-round design ([`26-sub-pr-design-discipline`]) — consensus + FFI surface.
**Parents:** [`CONSENSUS_PORT_SEQUENCE.md`](CONSENSUS_PORT_SEQUENCE.md) (Stage 1d),
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

### 1.1 Implementation status (2026-06-21)

The clean serializer and the first gate-(c) cut **landed** — PR #168
(`feat/shekyl-wire` → dev), a consensus atomic-flip PR:

- **`shekyl-wire` crate** — coinbase, FCMP++ spend, archival arms (incl.
  `bond_spend_pk`), hashing (§11), `tx_extra` (§9.6a), and structural validation
  (§10/§12). Coinbase block/tx/hash + `tx_extra` are **live-oracle byte-identical**
  to the daemon; the FCMP++ spend is **synthetic round-trip only** (the live KAT is
  blocked — see below).
- **Gate-(c) §5 item 2 — the dense tag renumber** — C++ `VARIANT_TAG`s + the ct type
  enum (via the `consensus_constants.json` authority + every drift tripwire), with all
  three nets' `GENESIS_TX` **re-pinned** (the genesis blob embeds the tag bytes, so the
  old-tag genesis could no longer be hashed). Dead arms are **parked at `0xf0+`**, not
  yet type-removed — that shed is §5 item 1, deferred. Daemon builds + starts + mines
  dense coinbases; full Rust workspace green (1724 tests; RandomX excluded per its gate).
- **EOF-tolerant pruned / fee-only ct shape (§4 / §9.8 / §2.5)** — `Ct::Fcmp.prunable`
  is `Option<Prunable>` and `Ct::read` is `BufRead` + EOF-tolerant: the full spend
  carries nvin `pqc_auths` + a prunable proof; the fee-only / serve-credit form ends
  right after the base (empty `pqc_auths`, no prunable). `hash()` is 4-part (pqc
  present) / 3-part (fee-only) per the C++ oracle; `validate()` is shape-aware.
  Synthetic round-trip validated; live byte/hash parity for these **post-genesis**
  shapes is pending a captured blob (as for the spend KAT).
- **Self-audit hardening pass** (multi-perspective audit + Copilot round 7) — fixed a
  latent **consensus hash bug** (the 4-part `H(pqc_auths)` preimage was missing the
  leading `varint(N)` count prefix the C++ `std::vector` archiver emits — see §11;
  invisible until the live spend-hash KAT, now pinned by a synthetic golden); enforced
  **`Null` ct ⟺ coinbase** + **PQC blob caps** in `validate()`; required a
  **coinbase-shape miner tx** in `Block::read` (so the embedded EOF ct-discrimination
  is only ever applied to a tail-less `Null`); capped **outputs at parse**; and made
  the archival `Holdings` / `BondPost.post_kind`-`bond_spend_pk` couplings **enums**
  so the silent round-trip-to-different-value shapes are unrepresentable.

**Still open** — this doc stays Round-1 *spec-grounded, ratification pending*:
- **Live FCMP++ spend KAT** — blocked on the daemon spend path; quarantined on
  `feat/shekyl-wire-spend-kat`. Spends are synthetic-validated until it lands.
- **Gate-(c) §5 items 1 / 3 / 4** — dead-arm type-removal shed; `txin_fcmp` reshape
  (drop `key_offsets`); decompose removal / single-output coinbase.
- **§8 step 4** — the ~58-consumer migration off `shekyl-oxide` block/tx.
- **Non-spend Fcmp residuals** — the EOF-tolerant fee-only form (above) is in; what
  remains is the **`bond_post` pseudoOuts↔spend-subset exact coupling** (a §13 F1/F3
  forward obligation owned by the emission / membership-only PRs — `validate()` bounds
  it, doesn't pin it), the **§4 `into_full`/`FullTransaction`** ergonomic (lands with
  the §8 consumer migration), and the live byte/hash parity for the fee-only / bond_post
  shapes. True storage-pruned txs (prunable dropped + external prunable hash) stay
  post-genesis / p2p scope.
- The F1–F6 freeze obligations and the §2.1 deferred sub-freezes remain.

## 2. The arbitration table

Source cites are `src/cryptonote_basic/cryptonote_basic.h` unless noted.

### 2.0 Genesis tag scheme (Q7 resolved — clean renumber)

**Decision:** Monero is a proven *pattern*, not a *basis*. We will never meet the
old chain on-wire, so we number tags as Shekyl needs them — dense from `0x00`,
not the inherited values. The renumber **landed** via PR #168 (§1.1): the C++
`VARIANT_TAG`s + ct type enum now emit these dense values atomically with Rust and a
3-net `GENESIS_TX` re-pin (§5 item 2 / §7). The `§2.1`/`§2.2` "Tag" columns below are
therefore the **pre-renumber C++ source** values — historical, kept for the
disposition mapping; the live C++ **and** genesis values are this dense scheme.

```text
Genesis tags (single-wave freeze):
  Input arm                    Output arm         ct type
  0x00  gen                    0x00  tagged_key   0x00  Null (coinbase)
  0x01  fcmp                                      0x01  Fcmp (spend)
  0x02  archival_serve_credit  (gate-2 serve-credit; non-spending)
  0x03  archival_bond_post     (gate-4 join-Market/bond; carries P; JoinMarket-only at genesis)

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
  carries `bonded_total_atomic == bond_credit == bond_floor(holdings)`
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
  - **Security crux (off-wire, genesis-adjacent):** the cover defense reduces
    entirely to the **entropy of the cover draw** (`:479-480` is "requires guessing
    the cover"). There is a built-in tension — `P` holds the cover as *working
    capital* (`:472`), and an amount chosen for operational utility pulls toward
    predictability (correlated with `P`'s activity), while the correlation defense
    wants high entropy. The `shekyl-standoff` entry-draw exists to arbitrate
    exactly this. It is a `CoverAmount` property to pin (genesis-adjacent,
    2C2B:625) — it does **not** touch the wire surface, but it is the security
    crux of the cover model and must be pinned before the bond-tx assembly lands.
- Admission + reward outputs are otherwise ordinary main-tree stealth
  (`tagged_key`, confidential); reward emission is membership-only with **no
  published nullifier/tag** (`PHASE_2B_FSM_RETOOL.md:87-94`).

So Q11 resolves: the genesis wire carries a **public, necessarily-clear bond
floor**, and the staker's real economic position is masked by `P` + cover — not by
hiding the floor. The cover rides normal CT (no special field), so there is **no
spend-surface impact**; the `bond_post` floor is frozen with Q4 (single wave, §13).

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
| `0x04` | `txin_archival_serve_credit_response` (:290) | **Spec + ratify** (gate-2 §5.1.1; non-spending) | Full layout + sig-preimage in **§9.10** (`leaf_bytes[128]`; c1/c2 branch scalars ≤256; preimage le64/le32). |
| `0x05` | `txin_archival_bond_post` (:264) | **Spec + ratify + UNIFY** (gate-4 §3.4.1; JoinMarket-only) | Full layout + sig-preimage in **§9.11** — **incl. `bond_spend_pk`** (GF-1 debit authorizer, JoinMarket-only, on wire + sig-preimage). **The current C++/Rust impl omits `bond_spend_pk` — must be added.** |
| `0x04` (dense) | `txin_archival_reward_emission` | **Deferred sub-freeze** — layout owned by `REWARD_EMISSION_VIN_PLAN.md` | Staker reward-emission vin (loud reward, Form-C `reward_P(E)`; **ML-DSA-65 auth** — single-vs-dual still open, plan §2:231; membership-only backing; per-epoch dedup on the bond record `claimed_settlement_epochs`, **not** a key image). Genesis tag **pinned `0x04` dense / `0x06` C++** (plan:118 "next free binary tag 0x06"). **Not in code yet** → a forward promise, not a freeze (**≠ Q6**, which references *existing* vendored crypto). Rule-interactions pinned §2.5/§12/§13; landing its PR may refine them. |
| (no own vin tag) | membership-only spend / backing | **Deferred sub-freeze** — owned by `FCMP_MEMBERSHIP_ONLY.md` | An fcmp-class spend input **with no key_image**; authority = the `R_O` Schnorr leg (`R_O`/`s_α`/`s_y`) **inside the SAL proof** (:52,80-82), not a separate vin field or `pqc_auths` slot. Backs emission; anti-replay = the emission per-epoch dedup (the proof does **not** reject duplicate tuples, :397). Likely an fcmp **proof variant**, not a new vin tag (plan:118 reserves only `0x06`); its wire signalling of "no key image" is **owned by its PR** — the genesis format must accommodate a no-ki spend (§9.5/§12 refined on landing). |

The archival arms (`serve_credit` 0x04, `bond_post` 0x05) **are** the genesis
staking-archival mechanism (the `P` model): `bond_post` is the gate-4 join-Market
event carrying `P`'s `hybrid_public_key` + `p_canonical_id`
(`ARCHIVAL_BOND_GATE4.md`, `PHASE_2B_FSM_RETOOL.md` §9); `serve_credit` is the
gate-2 serve-credit response. Shekyl-native, no spec outside
C++/`shekyl-archival-*` — this table is their only human-readable definition and
the highest load-bearing corpus cells. They are **frozen with the rest** (single
wave, §6 Q4); fields final per gate-4 §3 + certify_draw (#165). Rule-21 reopen = a
testnet-revealed change (pre-genesis free). Genesis constraint: `bond_post ⇒
JoinMarket` (§13). (Q11 has no separate wire surface — staking rides these arms.)

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

**`view_tag` (1 byte) — RATIFY, derivation corrected from the spec.** A scan
fast-reject prefilter, but per **FA-6 §4.2** (the authoritative spec) it is keyed
on the **ML-KEM** shared secret, not X25519:
`view_tag = HKDF-SHA512(ikm = ml_kem_ss, salt = "shekyl-view-tag-prefilter-v1",
info = "shekyl-view-tag-prefilter" ‖ output_index_le64)[0]`
(`rust/shekyl-crypto-pq/src/derivation.rs:263`). The scanner does **universal
ML-KEM decap → view_tag compare → X25519 on match** (FA-6 §4.7). **Accepted
tradeoff (binding):** a deliberately-accepted 1-byte scan-correlation cost for the
prefilter. *(Corrects an earlier keccak/X25519 derivation that cited a stale path.)*

### 2.3 CT section

**Terminology:** *CT = confidential transaction.* There is no RingCT — Monero's
rings/decoys are gone — so this PR says **CT**, not RCT in prose. Per
`CT_SURFACE_NAMING_PIN.md`, renaming the C++ `rct*` source symbols (`rctTypes.h`,
`rct_signatures`) to `ct*` is **deferred to Phase 5** (wallet2 retirement),
**not** a genesis change: the wire **tags + type values are already
genesis-locked**, and `binary_archive` is positional (ignores names), so the
rename has **no genesis-wire effect**.

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

### 2.5 Genesis tx shapes + arm-mixing (F1 — the freeze obligation by-reference doesn't discharge)

A genesis freeze that admits six input arms must say **which combinations form a
valid tx** and **how the cross-cutting rules (§12 ordering/dedup, §13 auth) apply
per arm** — otherwise landing a deferred arm later silently moves a "frozen" rule,
the exact failure freezing exists to prevent. Arm-mixing **is** expected:
membership-only backing and full key-image spends share a tx and the same verifiers
(`FCMP_MEMBERSHIP_ONLY.md:254`). So the resolution is **generalize the rules across
the arm taxonomy** (not "one arm class per tx"), plus state the shapes:

| Tx shape | Inputs | ct | pqc_auths (§13) | key images (§12) | Status |
|---|---|---|---|---|---|
| **Coinbase** | `[gen]` exactly | `Null` | **none** | none | settled |
| **Spend** (the transfer) | `fcmp×(1..8)` | `Fcmp` | one slot per input | each input, strictly ascending | settled |
| **Bond-post** | `fcmp×(funding)` + **one `bond_post`** + cover output | `Fcmp` | fcmp slots **+ the bond_post slot** (identity-key credit / `bond_spend_pk` debit, gate-4 §3.4.1:278) | the fcmp inputs only; bond_post has none | settled |
| **Serve-credit** | one `serve_credit` (non-spending) | n/a | **empty** — sig is **on the vin** (§9.10) | none | settled |
| **Emission** | `reward_emission` + membership-only backing (no ki) [± fcmp] | per plan | ML-DSA-65 (emission) + `R_O` legs in-proof (backing); **count rule refined by its PR** | fcmp inputs only; no-ki arms exempt — anti-replay = per-epoch dedup | **deferred sub-freeze** |

**Mixing rule (binding for the settled shapes):** within one tx, key-image-bearing
inputs (`fcmp`) and no-key-image inputs (`gen`/`serve_credit`/`bond_post`/emission/
membership-only) may coexist only as the table allows; §12 (ki ordering+dedup)
ranges over the **ki-bearing** subset, and §13 (auth) is **per-arm**. The
**emission** row is a deferred sub-freeze: its exact input multiset, the emission
auth count (single/dual ML-DSA), and membership-only's in-tx replay protection are
owned by `REWARD_EMISSION_VIN_PLAN.md` / `FCMP_MEMBERSHIP_ONLY.md` and **will refine
this table + §12/§13** — recorded as a forward obligation, not silently assumed.

## 3. Canonical genesis layout (post-arbitration)

Byte order, top to bottom. `V(x)` = varint (format pinned per §6 Q10); `[n]` = n
raw bytes; `vec(f)` = `V(len)` then `len ×` f.

```
Block            := BlockHeader  Transaction(miner)  V(n_tx)  n_tx×Hash[32]
BlockHeader      := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32]
Transaction      := V(version=3)  TxPrefix  Ct        # genesis version=3 (Q12: deliberate keep; V4 = future lattice-only)
TxPrefix         := V(unlock_time)  vec(Input)  vec(Output)  V(extra_len) extra[extra_len]
Input            := tag(1) ...        # 00 gen | 01 fcmp | 02 serve_credit | 03 bond_post  (+ deferred 04 reward_emission, membership-only — §2.5; stake_claim shed; bond_post = JoinMarket-only)
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

**Status (2026-06-21):** item 2 (the dense renumber) **landed** via PR #168 — with
the dead arms *parked* at `0xf0+` rather than type-removed, so item 1 stays open.
Items 1, 3, 4 remain, each its own atomic-flip cut.

1. Remove the dead/shed arms from `txin_v`/`tx_out` + the `VARIANT_TAG` lists:
   `txin_to_script`/`txin_to_scripthash`/`txout_to_script`/`txout_to_scripthash`
   (CryptoNote), plain `txout_to_key` (Q3), and **`txout_to_staked_key` +
   `txin_stake_claim`** (Q11 — cleartext staking retired; genesis uses the `P`
   model). The archival arms (`serve_credit`/`bond_post`) stay (frozen, single wave).
2. **✅ LANDED (PR #168) — Renumber the surviving tags to the §2.0 dense scheme** —
   input/output variant tags + the ct type enum (`Null=0x00`, `Fcmp=0x01`). One
   pervasive atomic flip (C++ `VARIANT_TAG` values + Rust + the 3-net genesis
   re-pin), so the corpus re-pins on the post-renumber bytes. Dead arms parked at
   `0xf0+` (their full type-removal is item 1, deferred).
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
- **Q4 — archival arm finality.** *(RESOLVED → single-wave freeze)* The archival
  arms (`serve_credit` 0x02, `bond_post` 0x03) are **frozen with the rest** — their
  wire fields are final per gate-4 §3 + the certify_draw work (#165), no WIP
  markers in the wire source. **Reopen clause (rule-21):** if testnet reveals a
  needed change it lands then (pre-genesis = free). `bond_post` is
  **JoinMarket-only at genesis** (`bond_post.rs:44` rejects other `post_kind`s;
  Rebond/Unbond/HoldingsUpdate are post-genesis). The still-moving parts
  (cover-entropy `shekyl-standoff` draw; bond magnitude/duration) are **off-wire**
  (cover = a confidential output; magnitude/duration = constants that fill
  `bonded_total`/`bond_credit`), so they don't touch the bytes. *(Collapses the
  earlier two-wave split — there is no separate Wave 2.)*
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
  carries a **public bond floor** (`bonded_total == bond_credit ==
  bond_floor`, `==` not `≥`), necessarily clear because consensus must verify the
  bond meets the floor. Privacy is **`P` dissociation + cover**, not a hidden
  floor: the principal sends `bond_floor + cover`; the `cover` is a confidential
  change-to-`P` output, so correlating a known principal spend to the public post
  requires guessing it (`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §SP-2.d:471-516). `==`
  closes the over-bond Sybil fingerprint (`PHASE_2B_SECTION7_DRAFT.md:84`). The
  cover is ordinary CT (no wire field) → **no impact on the spend surface**; the
  `bond_post` floor is frozen with Q4 (single wave). *(Corrects an earlier "no
  public amount" framing.)*
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
- **Q13 — `view_tag` scan-time conformance (F2).** *(OPEN — pre-genesis blocker)*
  §2.2 freezes `view_tag` as **ML-KEM-derived** (FA-6 §4.2; `derivation.rs:263`),
  but the live scanner + builder still compute the **old X25519/keccak** path
  (`shared_key.rs:65`) and FA-6's impl is *"a separate PR after spec review; not
  bundled"* (FA-6:13). A genesis `view_tag` frozen on the new derivation against a
  scanner on the old one makes **every output silently fail to scan** — and because
  the bytes round-trip, the §7 **wire corpus stays green and never catches it**.
  This is *more* insidious than `bond_spend_pk` (which surfaces as a missing field).
  **Freeze gate:** (a) the FA-6 scanner + builder switch lands pre-genesis (named
  impl blocker alongside `bond_spend_pk`); (b) a **scan-time KAT** — derive ECDH /
  ML-KEM → compute `view_tag` → match a captured output — is part of the freeze,
  **separate from** wire byte-identity. Resolve before ratification.

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

1. Round 0 → **approved**; Round 1 → **spec-grounded, ratification pending** — the
   §9–§14 tables stand for the inherited surface; the header's obligations (F1–F6:
   impl catch-up incl. the FA-6 `view_tag` switch, the §2.5 arm taxonomy, the §2.1
   deferred sub-freezes, corpus + scan-KAT) gate ratification.
2. **Implementation** (next): rebase the worktree onto current `dev` + relocate
   Decision-4 to the slice-2 plan; capture a spend blob + the archival-arm blobs as
   positive-corpus items. *(The two "blockers" are **not** a discrete pre-step —
   `bond_spend_pk`'s wire surfacing lands in the clean crate (step 3); the FA-6
   `view_tag` switch rides the scanner migration (step 4). Don't patch the
   to-be-retired `bond_wire.rs`.)*
3. Stand up the clean crate to the spec-grounded layout (**incl. `bond_spend_pk` per
   §9.11 — derivation already done, this is the wire encoding**); positive +
   **negative** corpus green vs the (gate-(c)-adjusted) oracle (incl. the §12
   canonical-form rejects), **plus the §6 Q13 scan-time `view_tag` KAT** (wire
   byte-identity alone cannot catch a derivation mismatch).
4. Migrate the ~58 consumers (**incl. the scanner's FA-6 ML-KEM `view_tag` switch +
   the Q13 scan-KAT — 2d-1 P-scan needs this scanner regardless**); delete
   `shekyl-oxide` block/tx — **sequenced to avoid colliding with in-flight
   wallet-rewrite work**.
5. Land gate-(c) C++ cuts (each its own consensus change, atomic-flip): **tag
   renumber ✅ (PR #168)**; then `txin_fcmp` reshape, shed dead/staking arms,
   single-output coinbase, exact-consumption + exact-proof-length, reward-zone
   de-gating (all pending).

Off-doc handoffs: the reward-zone *value* → economics (§14.3 has the sized
starting number); RandomX v2 epoch/lag → `shekyl-pow-randomx` at the Stage-3
cutover (deliberate-by-construction, our fork).

---

# Round 1 — Wave-1 freeze (byte tables + bounds + hashes + reject rules)

**Status:** Round-1 **spec-grounded, ratification pending** (per the header's F1–F6
obligations) — **not yet frozen**. A genesis freeze is not just byte order — it is
also the **bounds**, the **hashes**, and the **canonical-form/reject rules**, each
of which freezes identically. The tables below are **C++-oracle-validated for the
inherited surface** and **spec-grounded for the Shekyl-native additions** (§9.6a /
§9.10 / §9.11 / the §13 per-arm rules). All source-confirmed at `dev`. Integers
little-endian; `V(x)` = canonical varint (§6 Q10); `cn_fast_hash` = keccak-256.

## 9. Wave-1 byte layout (spec-grounded)

Genesis tags per §2.0. *(The C++ oracle still emits pre-renumber tag values until
the gate-(c) flip lands, §5; the captured corpus in `src/tests/vectors/` reflects
pre-renumber tags until recapture.)*

**9.1 BlockHeader** — `V(major) · V(minor) · V(timestamp) · prev[32] · nonce(u32 LE) · curve_tree_root[32]`; genesis `major=1, minor=0` (§13).
**9.2 Block** — `BlockHeader · Transaction(miner) · V(n_tx) · n_tx×Hash[32]`.
**9.3 Transaction** — `V(version=3) · TxPrefix · Ct`.
**9.4 TxPrefix** — `V(unlock_time) · vec(Input) · vec(Output) · V(extra_len) · extra[extra_len]`.
**9.5 Inputs** — `gen 0x00`: `tag(1) · V(height)`. `fcmp 0x01`: `tag(1) · key_image[32]` (no `amount`/`key_offsets`, Q1).
**9.6 Outputs** — `tagged_key 0x00` (sole type): `V(amount) · tag(1) · key[32] · view_tag(1)` (amount cleartext for coinbase, `0` for confidential spend outputs).
**9.6a `tx_extra` PQC fields** (inside `extra` of §9.4 — genesis-pinned internal structure, not opaque; FA-6 / POST_QUANTUM_CRYPTOGRAPHY / CT2 §3.1):
- **`0x06` KEM ciphertext** — **per output**: `varint(len) · x25519_eph[32] · ML-KEM-768 ct[1088]` (≈1120 B each).
- **`0x07` PQC leaf hashes** — **per tx**: `h_pqc[32] × n_outputs` concatenated in vout order (`h_pqc = Blake2b(pqc_pk)`); **not self-describing** — consensus parses `32·n_outputs` (n from `vout`). Feeds the curve-tree leaf `{O.x, I.x, C.x, h_pqc}`.
**9.7 Ct** — `ct_type(1)` then:
- `Null` (coinbase, 1 output): `enc_amounts[1×9] · enc_labels[1×9] · outPk[1×32]`
- `Fcmp` (spend): `V(fee) · referenceBlock[32] · enc_amounts[nout×9] · enc_labels[nout×9] · outPk[nout×32] · PqcAuths · Prunable`

  `enc_amount`/`enc_label` = 8B value + 1B tag (9B); `outPk` = 32B commitment;
  the `enc_label` indistinguishability invariant (§2.3) is binding.
**9.8 PqcAuths** (spend only; count = `nvin`, **no length prefix**; EOF-tolerant on read — the empty/pruned form parses, but a spend then fails verify, §13) — per input: `auth_version(1) · scheme_id(1) · flags(u16 LE) · V(pk_len)·pk · V(sig_len)·sig`.
**9.9 Prunable** (Fcmp) — `V(nbp=1) · BpPlus · V(curve_trees_tree_depth) · V(proof_len) · fcmp_proof[proof_len] · pseudoOuts[nvin×32]`. `BpPlus` + `fcmp_proof` interiors frozen by reference (§6 Q6); `proof_len == proof_size(nvin, tree_depth)` and Bp+ length is exact by `nout` (§10, canonical-form).
**9.10 `archival_serve_credit` (0x02)** (gate-2 §5.1.1) — `p_canonical_id[32] · V(shard_id) · V(settlement_epoch) · segment_subroot_rk[32] · leaf_index_in_segment(u32 LE) · leaf_bytes[128] · path{ V(c1_layers) · per-layer[ V(branch_scalars ≤256) · scalar[32]… ], V(c2_layers) · same } · V(sig_len)·hybrid_signature`. Non-spending; carries **empty** pqc_auths. **Sig-preimage** (gate-2 §5.2) uses fixed-width `le64`/`le32` (NOT the wire varints), customization `"shekyl/archival-serve-credit-response-v1"`, over the c1+c2 branch sections only.
**9.11 `archival_bond_post` (0x03)** (gate-4 §3.4.1) — `V(pk_len)·hybrid_public_key · p_canonical_id[32] · post_kind(1) · [ V(bspk_len)·bond_spend_pk  // iff post_kind==JoinMarket ] · holdings{ kind(1), [V(shard_count ≤4096)·shard_id(V)… if ShardSetCompact] } · V(bonded_total_atomic) · V(bond_credit) · V(bond_debit)`. **JoinMarket-only at genesis**; `bonded_total == bond_credit == bond_floor`, `bond_debit==0`. **`bond_spend_pk`** is the **GF-1 debit authorizer** (gate-6 §9.6, 2026-06-16): on the wire **iff JoinMarket** AND bound into the cSHAKE256 **sig-preimage** (customization `"shekyl/archival-bond-post-v1"`; preimage = `tx_prefix_hash · p_canonical_id · post_kind · encode_bond_spend_commitment · holdings · {bonded_total,bond_credit,bond_debit}_le64`) — keeps `P_pubkey` identity-only so the identity key never authorizes a value-out. `hybrid_pubkey_len`/`bond_spend_pk_len ≤ 2048`. **Auth placement (F5):** the bond_post **vin body carries no signature** — authorization is the **tx-level `pqc_auths` slot aligned with this vin** (§13; gate-4 §3.4.1:278), identity key on a credit, `bond_spend_pk` on a debit. *(The GF-1 `bond_spend` **key derivation already exists** (`archival_p.rs:120-123`, KAT'd); only the **wire/record/sig-preimage surfacing** is open, and it lands in the clean crate (§4) — the current `bond_wire.rs` encoder is **retired, not patched**.)*

## 10. Resource bounds (frozen limits — reject on exceed)

| Bound | Value | Enforced | Constant |
|---|---|---|---|
| inputs / tx | **8** | blockchain.cpp:3618 | `FCMP_MAX_INPUTS_PER_TX` (config:211) |
| outputs / tx | **16** | BP+ layout (rctSigs.cpp:211; tx_verification_utils.cpp:213) | `BULLETPROOF_PLUS_MAX_OUTPUTS` (config:241) |
| tx size | **1,000,000** | tx_verification_utils.cpp:63 | `CRYPTONOTE_MAX_TX_SIZE` (config:44) |
| tx_extra | **24,576** | cryptonote_tx_utils.cpp:579 | `MAX_TX_EXTRA_SIZE` (config:254) |
| PQC pubkey blob | **1,996** single / 13,974 multisig-max | cryptonote_basic.h:347 | `PQC_HYBRID_SINGLE_KEY_LEN` / `PQC_MAX_PUBLIC_KEY_BLOB` (config:291) |
| PQC sig blob | **3,385** single / 23,697 multisig-max | cryptonote_basic.h:350 | `PQC_HYBRID_SINGLE_SIG_LEN` / `PQC_MAX_SIGNATURE_BLOB` (config:293) |
| `nbp` / Bp+ len | **`nbp==1`** AND Bp+ byte length **exact by `nout`** | tx_verification_utils.cpp:213 | `is_canonical_bulletproof_plus_layout`; canonical-form corollary |
| `curve_trees_tree_depth` | `0 < depth ≤ chain depth` (dynamic) | blockchain.cpp:3964,4070 | — |
| `fcmp_proof` len | **exact: `proof_len == proof_size(nvin, tree_depth)`** | reject mismatch | `shekyl_fcmp::tree::proof_size` (tree.rs:549; ffi:1225) — both inputs on-wire; canonical-form corollary |

**Block-level bounds** (not just per-tx):

| Bound | Value | Constant |
|---|---|---|
| tx / block | **0x10000000** | `CRYPTONOTE_MAX_TX_PER_BLOCK` (config:45) |
| block weight | median-window limit (long-term window **100,000**; short-term surge **×50**) | `CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE` / `…_SURGE_FACTOR` (config) |

**Fossil flag (→ economics / block-weight owner, not this doc):**
`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE` has **V1/V2/V5** variants
(20,000 / 60,000 / 300,000, config:58-60) — Monero-hardfork lineage. A fresh
genesis has **one** reward zone, not three version-gated ones referencing forks
that never happened here; freezing V1/V2/V5 would immortalize Monero fork history
in the block-weight rule. Surfaced in the bounds pass; the arbitration belongs to
the economics doc.

Each is a §7 negative-corpus reject case (a 9-input / 17-output tx, or an
over-cap block, must be rejected by both impls).

## 11. Hashing layer (consensus identities)

- **Tx hash** = `cn_fast_hash` over concatenated component hashes (format_utils.cpp:1137/1163-1182):
  - coinbase (`Null`, no pqc): **3-part** `H(prefix) · H(base) · null_hash`
  - spend (`Fcmp`, pqc present): **4-part** `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`,
    used iff `has_pqc && !pqc_auths.empty()` where `has_pqc = version≥3 && vin[0] != gen`
    (a `gen`-first tx hashes 3-part like a coinbase).

  where `H(prefix)` = `get_transaction_prefix_hash` (version + prefix fields),
  `H(base)` = hash of `serialize_ct_base`, `H(pqc_auths)` = hash of the serialized
  pqc_auths vec, `H(prunable)` = hash of prunable (`null_hash` for coinbase).
  ⚠️ The `H(pqc_auths)` preimage is **count-prefixed**: the hash serializes
  `pqc_auths` with the **generic `std::vector` archiver** (format_utils.cpp:1169 →
  `begin_array(cnt)` → leading `varint(N)`), so the preimage is `V(N) · auth₀ · … ·
  auth_{N-1}` — **unlike** the tx *body*, where the count is implicit (`vin.size()`,
  no prefix; basic.h:505-516). The two C++ paths legitimately differ; the Rust
  `hash()` must prepend `V(N)` for the hash component only.
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
- **PoW = preimage + seed; the seed is RandomX v2's, not stock.** The above pins
  the PoW *preimage*; PoW determinism also requires the **seed/epoch** — which
  block's hash seeds the cache, the epoch length, the lag (a verifier on the wrong
  seed diverges). The genesis PoW is **Shekyl's own RandomX v2 fork**
  (`external/randomx-v2` + `rust/shekyl-pow-randomx`; in-tree, intentionally
  uncompiled, lands at the Stage-3 RPC cutover), so the seed/epoch is a
  **Shekyl-owned genesis value, deliberate by construction** — not stock to ratify.
  The freeze anchors on **`shekyl-pow-randomx`** (`Seedhash` + cache derivation,
  per `RANDOMX_V2_PHASE2F_PLAN.md`) plus the daemon's epoch-from-height
  (`seedhash.rs:90`) — **not** the stock C++ `rx-slow-hash.c` (`2048`/`64`,
  rx-slow-hash.c:137-188), which is only the v1 lineage. Pin v2's epoch/lag from
  that owner when v2 lands.

## 12. Canonical-form / reject rules (must-reject enumeration)

**The canonical-encoding invariant (the unifier).** A valid blob is **exactly the
bytes that re-serialize to themselves** — `write(read(b)) == b` — enforced
**recursively at every nesting boundary**: the tx within the block, and every
length-prefixed sub-region (a `vec` whose declared length leaves slack, a
`V(extra_len)` that under-reads). Trailing bytes, non-canonical varints (Q10), and
the exact proof/Bp+ length (§10) are all **corollaries** of this one rule, not a
scattered list. The §7 round-trip gate (`write(read(b)) == b`) *is* this invariant;
state it once, the rest follow. Instances:

- **Inputs strictly ascending by key image** — `memcmp(ki, last) >= 0 → reject`
  (blockchain.cpp:3642-3663). One rule, two guarantees: rejects **unsorted** AND
  **in-tx duplicate** key images. **Scoped to key-image-bearing inputs** (`fcmp`
  spends). The **no-key-image arms** (`gen`, `serve_credit`, `bond_post`, and the
  deferred `reward_emission` / membership-only backing) carry no key image and are
  **exempt** from this ordering; their anti-replay is **arm-specific** — coinbase by
  height; bond_post by the consensus bond record; **emission + membership-only by
  per-epoch dedup on the bond record (`claimed_settlement_epochs`), NOT a key
  image** (`FCMP_MEMBERSHIP_ONLY.md:28,397` — the SAL proof does **not** reject
  duplicate tuples; with no key image, in-tx replay protection is the emission
  dedup). **Deferred (F1/F3):** how a no-ki input orders *relative to* ki-bearing
  inputs in a mixed tx, and membership-only's exact in-tx dedup, are owned by the
  emission/membership-only PRs and will refine this rule.
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
- **pqc_auths binding (per-arm — F1/F5).** `pqc_auths` is **tx-level**, aligned
  with `vin[]`; per-slot content and the count rule depend on the input arm:
  - **fcmp spend** — one slot per input (the spend auth); `auth_version==1`
    (tx_pqc_verify.cpp:169), `scheme_id ∈ {1 single, 2 multisig}` (:181),
    **`flags==0`** — unknown bits rejected, not ignored (:175).
  - **bond_post** — occupies a **tx-level `pqc_auths` slot aligned with its vin
    index** (gate-4 §3.4.1:278), **not** a sig on the vin body: identity key
    authorizes credit, `bond_spend_pk` authorizes debit (gate-6 §9.6).
  - **serve_credit** — carries **empty** `pqc_auths`; its `hybrid_signature` is
    **on the vin** (§9.10) — the exception to a per-vin slot.
  - **coinbase (`gen`)** — **no** `pqc_auths`.
  - **reward_emission** (deferred) — **ML-DSA-65** over a domain-separated vin
    context (single-vs-dual open, `REWARD_EMISSION_VIN_PLAN.md §2:231`).
  - **membership-only** (deferred) — authority is the `R_O` Schnorr leg **inside
    the SAL proof** (`FCMP_MEMBERSHIP_ONLY.md §4`); no `pqc_auths` slot, no ki.

  So the rule is **per-arm**, not a flat `count == vin.size()`. For the common
  all-`fcmp` spend, `count == vin.size()` holds (blockchain.cpp:3752); a bond-post
  tx's count includes its bond_post slot; serve_credit/coinbase are the empty/none
  exceptions. **Parse vs verify (precise):** the EOF-tolerant parse (§9.8) *accepts*
  the empty (pruned) form, but a spend with empty or partial `pqc_auths` **fails
  verification** (`tx_pqc_verify.cpp:159`: `size != vin.size() || empty → reject`) —
  *pruned form parses, full form required to verify*, not "empty invalid
  everywhere." **Deferred (F3):** the emission auth count (single/dual ML-DSA) and
  membership-only placement are owned by their PRs and will refine this rule.
- **referenceBlock (wire = 32 B block hash):** validity window `tip −
  FCMP_REFERENCE_BLOCK_MAX_AGE(100) ≤ ref_height ≤ tip − FCMP_REFERENCE_BLOCK_MIN_AGE(5)`
  (blockchain.cpp:3946-3954). **Canonical selection (CURVE_TREE_CLIENT §5):**
  `reference_height = tip − 6` (REF_ANCHOR_AGE; wallet-uniform to prevent
  fingerprinting — distinct from `SPENDABLE_AGE=10`), with proactive re-anchor at
  `+50` (REBUILD_AT) before the MAX_AGE cutoff.
- **CT balance:** `Σ pseudoOuts == Σ outPk + fee` (+ `bond_credit` for bond-post) —
  `verRctSemanticsSimple` / `shekyl_fcmp_verify` (tx_verification_utils.cpp:234;
  blockchain.cpp:4125). The general spend rule (the bond floor §2.0 is the
  bond-post case of this).
- **Archival arms (single-wave, spec-grounded):** `bond_post` is **JoinMarket-only
  at genesis** (`post_kind==JoinMarket`, else reject — `bond_post.rs:44`); for
  JoinMarket `bonded_total == bond_credit == bond_floor(holdings)` and
  `bond_debit==0` (`bond_post.rs`); its **identity signature rides a tx-level
  `pqc_auths` slot aligned with the vin** (gate-4 §3.4.1:278; F5), not the vin body.
  `serve_credit` is **non-spending** (empty pqc_auths; `hybrid_signature` **on the
  vin**; gate-2 retention proof). **Reopen (rule-21):** testnet may force a wire
  change pre-genesis (free).
- **Versions:** block `major=1, minor=0`; tx `version=3` (Q12). The format is
  version-frozen — a later format is a hard fork (V4 = lattice-only).

## 14. Round-1 adopted refinements (2026-06-20)

Both §14 cuts **adopted**, each stronger than first proposed; §10/§11 completed:

1. **Canonical-encoding invariant (adopted, generalized).** The trailing-byte cut
   becomes the recursive canonical-form rule (§12): `write(read(b)) == b` at every
   nesting boundary. Trailing bytes, non-canonical varints (Q10), and exact
   proof/Bp+ length are all corollaries of this one rule.
2. **Exact determined lengths (adopted, tighter than a cap).** `fcmp_proof` is
   `proof_len == proof_size(nvin, tree_depth)` **exactly** (§10) — no cap value, no
   magic constant; Bp+ byte length is exact by `nout`. Canonical-form corollaries.
3. **§10 completed** with block-level bounds (`CRYPTONOTE_MAX_TX_PER_BLOCK`,
   block-weight machinery). **Reward-zone (resolved):** shed the V1/V2/V5 fork-era
   gating (fossil — the live code already uses only `_V5`) → **one** genesis
   penalty-free zone, **sized for Shekyl tx weight, not transcribed 300 K**. Math:
   a 1-in/2-out Shekyl transfer ≈ **~9 KB** (PQC pk 1,996 + sig 3,385 + FCMP++
   ~2.5 K + Bp+ ~0.7 K + outputs/base ~0.5 K) ≈ ~5–6× a Monero tx; to hold a
   comparable ~175–225 tx/block at the floor → **≈ 2,000,000 B (2 MB)**. It is a
   **soft floor** (penalty above; median grows; ≥ 2× `MAX_TX_SIZE`), so economics
   owns the final number — this is the sized starting value, not freeze-critical,
   and lives in `config`/block-weight, **not** this wire-format doc.
4. **§11 completed**: PoW = preimage + seed; the seed is **RandomX v2's** (Shekyl's
   fork — `external/randomx-v2` + `shekyl-pow-randomx`, genesis PoW landing at the
   Stage-3 RPC cutover), owned by `shekyl-pow-randomx` per `RANDOMX_V2_PHASE2F_PLAN`
   — a deliberate Shekyl genesis value by construction, **not** stock `rx-slow-hash.c`.

All free pre-genesis (hard forks later).

## 15. Design-doc + structural review (2026-06-20) — changelog (applied above)

This section is a **changelog, not a pending plan**: every correction below is
already reflected in the body (§2–§14). It records *why* the earlier code-derived
draft was wrong so the reasoning isn't lost.

**Method correction (the root cause).** The genesis format has two layers, and
they have different authorities:
- **Inherited Monero-lineage** (block, header, tx-prefix framing, varint,
  hashing, coinbase shape, ct base/prunable framing, bounds): the C++ daemon is a
  *complete* oracle (validated against a live blob). §9–§14 hold for these.
- **Shekyl-native** (archival arms, the per-output PQC scan fields, the
  reward-emission economy, the membership-only spend): the **design docs +
  Rust impl are the authority**; the **C++ is incomplete** (e.g. it omits
  `bond_spend_pk`). Differential-testing these against C++ is invalid. §2/§9 were
  built code-first and are wrong/incomplete here.

**Gaps found (spec-grounded, cited):**

1. **`bond_post` omits `bond_spend_pk`** — gate-4 §3.4.1 puts it on the wire
   (JoinMarket-conditional, `varint len + canonical bytes`) **and** in the
   cSHAKE256 sig-preimage (`encode_bond_spend_commitment`); it is the GF-1
   debit-authorizer (gate-6 §9.6, 2026-06-16) that keeps `P_pubkey` identity-only.
   The **key derivation already exists** (`archival_p.rs:120-123`, KAT'd); only the
   **wire/record/sig-preimage surfacing** is open and lands in the clean crate (§4),
   **not** by patching the to-be-retired `bond_wire.rs`. **Security-critical.**
2. **`tx_extra` 0x06 (PQC KEM ct) is not opaque** — per output:
   `varint(len) · x25519_eph[32] · ML-KEM-768 ct[1088]` (≈1120 B)
   (FA-6 / POST_QUANTUM_CRYPTOGRAPHY §Phase 2; `extra.rs` `PqcKemCiphertext`).
3. **`tx_extra` 0x07 (PQC leaf hashes)** = per-tx `h_pqc[32] × n_outputs`
   concatenated (vout order), **not self-describing** — parsed by output count
   (FA-6 §3.1; CT2_DRAIN_ORDER §3.1; `h_pqc = Blake2b(pqc_pk)`).
4. **`view_tag` derivation is wrong in §2.2** — it is `HKDF-SHA512(ml_kem_ss,
   salt=shekyl-view-tag-prefilter-v1, label‖output_index_le64)[0]`, off the
   **ML-KEM** shared secret (FA-6 §4.2; `derivation.rs:263`), *not* keccak off the
   X25519 ECDH. Correct the §2.2 rationale.
5. **Two genesis input arms are absent** — `txin_archival_reward_emission` (loud
   reward; Form-C `reward_P(E)=floor(budget·capped_P/Σwork)`, u128-numerator;
   per-epoch dedup on the bond record; **ML-DSA-65 auth** (single-vs-dual open,
   plan §2:231; a hard merge blocker)) and the **membership-only spend** (no
   key_image; `R_O`/`s_α`/`s_y`
   Schnorr; backs emission). Owned by `REWARD_EMISSION_LEG.md` /
   `REWARD_EMISSION_VIN_PLAN.md` / `FCMP_MEMBERSHIP_ONLY.md`; **not in code yet**
   (deferred to the emission-vin PR). The genesis format includes them.
6. **CT rename is Phase-5** (wallet2 retirement), **not** a genesis gate-(c)
   change (`CT_SURFACE_NAMING_PIN.md`); wire tags + type values are already
   genesis-locked. Fix the §2.3/§5 framing.
7. **`referenceBlock`** wire is 32 B (correct), but the canonical *selection* is
   `reference_height = tip − 6` with proactive rebuild at `+50`
   (`CURVE_TREE_CLIENT.md §5`); §13 had only the 5–100 validity window.

**Confirmed correct** (no change): block-hash `varint(len)` prepend; PoW
preimage; coinbase `+60` maturity; `ct` Null/Fcmp values; `enc_amount`/`enc_label`
9 B; `serve_credit` sig-preimage (le64/le32 fixed-width); `nbp==1`; the §10 bounds.
(Several agent-flagged "divergences" — reward-hidden, dedup-nullifier, coinbase
`+10` — were against an *assumed* freeze, not this one, and do not apply.)

**Applied (changelog — reflected in the body above, not pending).**

*Pass 1 (gaps 1–7, spec-grounding):* `bond_spend_pk` + preimage → §2.1/§9.11;
`tx_extra` 0x06/0x07 → §9.6a; `view_tag` derivation → §2.2; reward-emission +
membership-only → §2.1; CT rename → Phase-5 (§2.3/§5); `referenceBlock` selection →
§13.

*Pass 2 (structural review F1–F6, 2026-06-20):*
- **F4** — status scrubbed to one (spec-grounded, **not** ratified): header, §8,
  §9, §14.
- **F2** — FA-6 ML-KEM `view_tag` named a pre-genesis impl blocker + a **scan-time
  KAT** added (because the wire byte-corpus can't catch a derivation mismatch):
  header, §6 Q13, §8.
- **F1** — genesis tx-shape + **arm-mixing taxonomy** (§2.5); §12 (ki ordering/dedup
  scoped to ki-bearing inputs) and §13 (`pqc_auths` per-arm) generalized across the
  full arm set.
- **F5** — `bond_post` identity sig placed in a **tx-level `pqc_auths` slot aligned
  with the vin** (§9.11/§13).
- **F3** — reward-emission + membership-only relabeled **deferred sub-freeze** (not
  "frozen by reference"); emission genesis tag pinned (`0x04` dense / `0x06` C++):
  §2.1, header.
- **F6** — this section reframed as a changelog.

The inherited surface (§9.1–9.9 framing, §10–§12) carries over unchanged.

**Still open before ratification:** the two impl blockers (`bond_spend_pk`, the
FA-6 `view_tag` scanner/builder switch), the scan-time `view_tag` KAT, and the
emission / membership-only **deferred sub-freezes** (which may refine §2.5/§12/§13
when their PRs land).
