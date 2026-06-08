# Archival firewall — gate 6 (`P` lifecycle + pseudonym hygiene)

**Status:** **Round 1 draft (2026-06-07).** Crypto layer + `P` hybrid derivation pinned
below (§9). Network/timing/output rounds still open. Not soundness-closed.
Per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
adversarial rounds run before Stage 3 `StakeEngine` production code.

**Global PQC policy:** Hybrid genesis stack (Ed25519 + ML-DSA-65 spend auth; X25519 +
ML-KEM-768 output encryption) is **not** re-litigated here — see
[`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md). Gate 6 pins only the
**archival `P` fork** of that stack: domain-separated HKDF labels, account-level
`HybridPublicKey` for the bond record, and firewall coupling.

**Scope:** Everything required so a **firewalled pseudonym `P`** — public by function
for archival — does **not** re-link to the principal across crypto, network, timing,
output, and bond-funding surfaces over `P`'s whole life.

**Upstream:** [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §*Firewalled-pseudonym
identity model*; [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4
(transfer-shaped admission); [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) (emission
cadence, batching, `good_through`); [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
(public retention timeline at settlement-epoch resolution).

**Out of scope here (interface only):**

| Item | Owner |
|------|-------|
| Retention-proof construction / 8c verifier bytes | Gate 2 soundness |
| `ArchivalBondRecord` slash wire, `good_through` interval log | Gate 4 |
| `Σwork` servo, admission principal economics | Gate 1 / gate 7 |
| Full `ArchivalEngine` query-serving | Stage 5 |
| Entitlement / `C_stake` / 3C subtree | Deleted |

**Why now:** Emission Layer 1 and the archival read contract pin **what is public**
(`P_id`, per-`(P, shard, E)` retention bits, shard-set, performance timeline).
Gate 6 pins **what must stay hidden** (`P` ↔ principal) and the **wallet/daemon/network
obligations** that maintain the firewall — including rotation, lapse, and transport
discipline named in the honest residual and F1 epoch-length coupling.

---

## 1. Public vs hidden — the contract gate 6 enforces

| Consensus-public (by function) | Must remain hidden (gate 6) |
|--------------------------------|-----------------------------|
| `P_id`, holdings descriptor, bond posture | Principal identity, spend graph, view key |
| Shard-set, longevity, per-epoch retention bits | Which human/entity operates `P` |
| `R_market`, `Σwork`, reward amounts (loud) | Correlation of multiple `P` to one principal |
| Challenge reachability (peers must find `P`) | Network path from principal device to `P` rendezvous |

**Priority binding ([`00-mission.mdc`](../../.cursor/rules/00-mission.mdc)):** Priority-2
on the reward path is **firewall discipline**, not hidden reward amounts. Failure mode:
long-lived correlation of `P`'s public activity against the principal, plus **cross-
pseudonym intersection** when one principal runs multiple `P`s without per-`P` hygiene.

**Not a security claim:** Multi-`P` per principal is **privacy hygiene**, not Sybil
defense — per-shard bonds carry Sybil cost ([`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md)
§*Per-shard retention bonds*).

---

## 2. Four firewall layers + bond-funding

Gate 6 is maintained across **five surfaces** (four classic layers plus bond-funding).
Each surface has **wallet**, **daemon**, and **network/ops** obligations; this doc
names invariants first — wire-level hooks land in later rounds.

### 2.1 Crypto layer

**Goal:** `P` keys and signing paths are **cryptographically independent** of principal
spend keys — not algebraic offsets, not shared nonce streams, not shared scan tags.

**Genesis pin (carry from V3 / PHASE_2B):**

- `P` = **HKDF-derived sub-wallet** from master seed (independent keypair; dual scan:
  principal + `P`).
- Principal→`P` stake-in, `P`→principal unstake drain, reward sweeps = **ordinary
  `RCTTypeFcmpPlusPlusPqc` transfers** on the main tree; base FCMP++ privacy is necessary
  but **not sufficient** (timing/output still leak).
- Reward emission = **membership-only control** on `P`'s backing UTXOs — no published
  dedup tag; no stake-keyed nullifier on the emission path.

**Round 1 pin:** §9 — hybrid `P` derivation, `P_canonical_id`, dual-scan contract.
**Still open:** multisig `P` (V3.1 defer), hardware-offload `P` signing boundaries.

### 2.2 Network layer

**Goal:** Peers reach `P` for challenges and fetches **without** learning where the
principal lives or which clearnet IP serves archival bytes.

**Genesis posture (sim-backed — L16):**

- Heavy archival fetch path → **onion-service ↔ Tor-client rendezvous** (slowest Tor
  config). `P`'s location must not link to the principal → **no clearnet fallback** for
  production archival serving under the firewall threat model.
- Operating regime: L10 `L2–L6` latency band is **by construction**, not a stress corner
  ([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) L16).

**Contained sub-questions (soundness pass step 2):**

- Archiver **seeding-path** transport relaxation — smaller than clearnet-serving; must
  not re-introduce principal↔`P` linkage ([`FOLLOWUPS.md`](../FOLLOWUPS.md) gate-6 transport
  items).

**Round-open:** Arti integration surface, peer handshake that presents `P` without
principal metadata, challenge-delivery path vs fetch path separation.

### 2.3 Timing layer

**Goal:** Principal financial activity and `P` archival activity are **not alignable**
by an observer — emission cadence, claim batching, unstake drains, and rotation events
must not form a standing correlation channel.

**Couplings already pinned elsewhere:**

| Mechanism | Source | Gate-6 role |
|-----------|--------|-------------|
| Settlement-epoch emission cadence (~14 d default) | Emission leg §3 | Batches work claims; reduces drip timing tell |
| `MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` per `P` | Emission leg §3 | Default batch; single-epoch claim = test-only |
| Per-epoch retention ledger resolution | Archival state / F1 | **Public liveness fingerprint** at epoch granularity |
| `MAX_CLAIM_AGE_W` | Archival state §2.4 | Deliberate lapse forfeiture vs decorrelation |

**E-4 threat (named):** Fine-grained per-epoch retention timeline + shard-set adjacency
across **`P_old` → `P_new` rotation** re-links identities if rotation is cosmetic
(same storage, same shard set, adjacent epochs). **Rotation must change observable
behavior**, not only `P_id`.

**Round-open:** jitter policy (wallet-local vs daemon-assisted), rotation cadence vs
`W`, joint pin of `SETTLEMENT_EPOCH_BLOCKS` with gate-6 decorrelation (archival state
§9.2 when landed).

### 2.4 Output layer

**Goal:** Reward receipts and principal returns do **not** create spend-graph links
between `P` and principal beyond what a disciplined user already avoids on ordinary
transfers.

**Genesis pin (carry from PHASE_2B §2.4):**

- Rewards → **stealth outputs `P` controls** (loud amounts; privacy is firewall not
  hiding reward size).
- Terminal unstake = **decorrelated drain** `P`→principal — not a lump sweep that
  ties reward history to a single principal output cluster in one block.
- **Unbond refund** ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2.4): release
  creates a P-attributed output at public `bond_floor` amount; mixes in the FCMP++ set like
  any output — same decorrelated-drain discipline as reward receipts (amount is public;
  spend anonymity is tree membership).

**Round-open:** minimum delay / output-count discipline between last emission and
drain; change-output handling on bond-funding transfers.

### 2.5 Bond-funding layer (fifth surface)

**Goal:** Posting per-shard bonds does not become a **principal→`P` correlation channel**
(lump funding from a fresh principal output immediately before first emission).

**Open disposition (joint with gate 4 join-Market):** **fund-from-earnings ramp** vs lump
initial bond vs mixed — wallet hygiene spec, not consensus rule. Consensus sees bond
sufficiency at join-Market; **how** `P` acquired collateral and **when** join-Market
fires relative to principal activity is observability the firewall must address
([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §6).

---

## 3. `P` lifecycle — events gate 6 must cover

```text
[seed] → derive P → announce/backing (off-chain) → join-Market (on-chain bond anchor)
       → serve + challenges → paying emissions → bond updates / slash / re-bond
       → optional rotation P_old → P_new → lapse / decorrelation
       → terminal drain → retire P
```

| Phase | Consensus-visible? | Gate-6 load-bearing |
|-------|-------------------|---------------------|
| HKDF derive `P` | No | Independent material; scan isolation |
| Off-chain announce + backing presentation | Peers see | Backing before join-Market; no principal metadata |
| **join-Market** | Yes (bond record create, `E_join`) | **Standing timing event** — defang via §2.3/§2.5; cannot hide in mint |
| First **paying** emission | Yes (mint + dedup) | Decorrelate from principal funding |
| Ongoing service | Yes (retention bits, holdings) | Network path; epoch-timeline fingerprint |
| Rotation | Yes (new `P_id`, holdings transfer) | Decorrelate timeline + shard-set adjacency |
| Deliberate lapse > `W` | Yes (forfeiture) | Acceptable decorrelation cost |
| Terminal drain | Yes (transfer) | Output decorrelation |

**Registration fusion:** No separate *registration tx type*; **join-Market** is the
on-chain anchor ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)). Off-chain backing
**precedes** join; first **paying** emission follows by ≥ one settlement-epoch lag.

**Two rotation concepts (do not conflate — see
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1):**

| Kind | `P_canonical_id` | Wallet instance key |
|------|------------------|---------------------|
| **Backing UTXO rotation** (E-4 hygiene) | Unchanged | Same `P_canonical_id`; update rotatable `backing_outputs` |
| **`P` pseudonym rotation** (decorrelation) | New | New instance; `p_slot` increment → new keys |

Sim step-0 **pseudonym rotation** → pure over-enumeration (new slot; burn old) — reversion:
per-root subkey only; never cross-authorizing master
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*Step 0*).

---

## 4. Invariants (load-bearing)

1. **No principal material on `P` wire paths** — addresses, view tags, enc labels, and
   scan hooks for `P` must not reuse principal derivation labels or linkable tags.
2. **Reachability without location** — any peer that must challenge `P` can do so via
   the agreed rendezvous layer without learning clearnet operator location.
3. **Emission timing ≠ principal timing** — a watcher cannot align principal spends and
   `P` emissions to a single clock better than chance + public epoch boundaries, under
   stated wallet discipline.
4. **Rotation is not cosmetic** — `P_new` must not be trivially linkable to `P_old` via
   epoch-adjacent retention on the same shard-set with the same network fingerprint.
5. **Cross-`P` hygiene** — multiple `P` from one principal require **per-`P`** network,
   timing, and output discipline; intersection is the residual class named in V3 honest
   residual.
6. **Bond funding does not default-link** — wallet default must not fund bonds from a
   traceable fresh principal→`P` pattern without an documented alternative path.

Violations are **privacy failures**, not consensus faults — but genesis ships with
wallet/daemon defaults that **enforce** the invariants or loud-fail into unsafe posture
(pre-genesis: loud fail per user-absent-context discipline).

---

## 5. Consumer map — who implements what

| Component | Gate-6 responsibilities |
|-----------|-------------------------|
| **`shekyl-wallet-core` / `StakeEngine`** | `P` HKDF; dual scan; build emission/drain txs; rotation ceremony; bond-funding UX defaults; local jitter |
| **`shekyld` (daemon)** | Peer reachability to `P`; challenge routing; optional policy hooks — **must not** require principal identity for archival RPC |
| **Transport stack** | Onion rendezvous for serving; seeding-path rules (step 2) |
| **GUI / mobile** | Surface rotation/lapse warnings; no principal↔`P` linking in logs or RPC |

**Stage 3 blocker:** `StakeEngine` replaces `is_active_staker(entity_id)` — gate 6 **is**
the staking identity surface ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2).

---

## 6. Design rounds (planned)

| Round | Focus | Exit criterion |
|-------|-------|----------------|
| **0** | Scaffold + invariant frame + consumer map | **Done** |
| **1** | HKDF/`P_id` wire + crypto layer hooks | **Draft** — §9; reviewer sign-off pending |
| **2** | Network + transport (L16 → production shape) | Rendezvous path specified; seeding relaxation bounded |
| **3** | Timing + rotation + `W` / epoch-length joint pin | E-4 mitigations named with testable wallet defaults |
| **4** | Output + bond-funding hygiene | Drain/ramp defaults; threat-model §7 rebase in PHASE_2B |
| **5** | Cross-layer adversarial pass | Soundness-depth sign-off for Stage 3 |

**Parallel (not gated on gate-6 closure):** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
schema implementation; PHASE_2B §3–§7 FSM retool off rebased §2.4.

---

## 7. Implementation checklist (pre-code)

- [x] Pin `P` HKDF labels + `P_canonical_id` alignment with emission leg (§9 — draft).
- [ ] Land `ARCHIVAL_P_DERIVE_V1` KAT vectors + `shekyl-crypto-pq` `archival_p` module.
- [ ] Pin off-chain announce/backing presentation wire (daemon + wallet).
- [ ] Pin rotation ceremony (over-enumeration; holdings/bond migration).
- [ ] Pin network rendezvous requirement for production archival serving.
- [ ] Pin wallet defaults: emission batching, drain decorrelation, bond-funding ramp.
- [ ] Pin epoch-length disposition jointly with gate-2 cadence + gate-6 decorrelation.
- [ ] Rebase PHASE_2B §7 threat model — draft:
      [`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md) (review → land).
- [ ] Stage 3 test vectors: cross-layer linkability negatives.

---

## 9. Round 1 — `P` hybrid derivation (genesis pin, draft)

### 9.1 Design disposition

| Question | Disposition |
|----------|-------------|
| Hybrid vs classical-only `P`? | **Hybrid** — same FIPS 203/205 stack as V3 genesis; `ArchivalBondRecord.P_pubkey` is `HybridPublicKey` ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §6.2). |
| Same algorithms as principal? | **Yes** — independence is **HKDF domain separation**, not different primitives. |
| Where does code live? | New module in `shekyl-crypto-pq` (e.g. `archival_p.rs`). **Do not** mutate frozen [`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) v1 / `ADDRESS_DERIVATION_V1` KATs. |
| Principal `AllKeysBlob` shape? | **Unchanged.** `P` material is a **parallel** derivation path from the same `master_seed_64`. |
| Account-level ML-DSA for `P`? | **Yes** — bond record and `pqc_auths` need a stable per-`P` `HybridPublicKey`. Principal account keys carry Ed25519 + ML-KEM only; per-output ML-DSA stays on the output path. `P` adds **account-level** ML-DSA via deterministic seeded keygen (same helper as [`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs) `keygen_from_seed`). |

### 9.2 Inputs and slot index

```text
master_seed_64   // wallet file — same as principal ([account.rs](../../rust/shekyl-crypto-pq/src/account.rs))
network, format  // DerivationNetwork + SeedFormat — same salt_for() as principal
p_slot: u32      // rotation slot; genesis default 0; increment on pure over-enumeration rotation
```

**Slot rule:** `p_slot` is wallet-persisted stake metadata (not consensus). Rotation burns the
old slot's operational use and derives `P_new` at `p_slot' = p_slot + 1` (or next free slot
per wallet policy — numeric rule pinned at implementation; minimum requirement: **new slot ⇒
new keys**). Consensus sees only the resulting `P_canonical_id`.

### 9.3 HKDF pipeline (mirrors `account.rs`)

Reuse the principal salt and wide-reduce discipline:

```text
salt = salt_for(network, format)
       // e.g. b"shekyl-master-derive-v1-mainnet-bip39"

HKDF-SHA-512(salt, ikm = master_seed_64, info = LABEL || p_slot.to_le_bytes(), L = …)
```

| Output | Info label (`LABEL`) | `L` | Consumer |
|--------|----------------------|-----|----------|
| `spend_wide` | `shekyl-archival-p-ed25519-spend-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 spend |
| `view_wide` | `shekyl-archival-p-ed25519-view-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 view |
| `kem_d_z` | `shekyl-archival-p-ml-kem-768-v1` | 64 | `ml_kem_chacha_seed_from_d_z` → ML-KEM-768 KG (same SHA3-ChaCha intermediary as principal; **separate `d_z`** from label) |
| `ml_dsa_seed` | `shekyl-archival-p-ml-dsa-65-v1` | 32 | `keygen_from_seed` → ML-DSA-65 keypair (ChaCha20Rng seeded) |

**Forbidden info labels on the `P` path:** `shekyl-ed25519-spend`, `shekyl-ed25519-view`,
`shekyl-ml-kem-768`, and the entire `shekyl-output-derive-v1` / `shekyl-pqc-output` tree.

**ML-KEM intermediary (unchanged function, archival-only input):**

```text
chacha_seed = SHA3-256( b"shekyl-mlkem-chacha-seed" || kem_d_z )
(ek, dk)    = ML-KEM-768.KeyGen(ChaCha20Rng::from_seed(chacha_seed))
```

The SHA3 prefix is **shared** with principal — collision resistance comes from distinct
`kem_d_z` bytes from distinct HKDF info labels.

### 9.4 Wallet-side key bundle (`ArchivalPKeys`)

Logical struct the wallet holds in `StakeEngine` session state (names illustrative;
exact Rust types follow `shekyl-crypto-pq` wrappers):

```text
ArchivalPKeys {
  p_slot:                    u32,
  spend_pk, spend_sk:         Ed25519 spend (typed SpendPublicKey / SpendSecret),
  view_pk, view_sk:           Ed25519 view   (typed ViewPublicKey / ViewSecret),
  ml_kem_ek, ml_kem_dk:       ML-KEM-768 account keys,
  x25519_pk:                  montgomery(view_pk),   // same map as principal
  hybrid_sign_pk, hybrid_sign_sk: Hybrid{ed25519=spend, ml_dsa=account ML-DSA},
  hybrid_bond_id:             HybridPublicKey,       // == hybrid_sign_pk; bond-record identity
  p_canonical_id:             [u8; 32],              // §9.5
}
```

**Not persisted at rest:** secret fields are re-derived from `master_seed_64` + `p_slot` on
wallet open (same discipline as `AllKeysBlob` ML-KEM decap key). Persist only `p_slot` and
public `p_canonical_id` / holdings metadata in stake ledger state.

**Receive address:** `P`'s Shekyl address uses `(spend_pk, view_pk, ml_kem_ek)` — same
encoding as principal ([`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) public
layout), different bytes. Peers challenge the **`p_canonical_id`** / bond record identity;
payment address is a separate presentation layer.

### 9.5 `P_canonical_id` (consensus alignment)

Must match emission leg §6.1 exactly:

```text
bond_bytes = HybridPublicKey::to_canonical_bytes()   // scheme_id = 1 (ed25519_ml_dsa_65)
p_canonical_id = cSHAKE256(
  customization = "shekyl/archival-p-id-v1",
  input         = bond_bytes
)[0..32]
```

**Verifier rule:** wallet, daemon, and consensus must compute the same `bond_bytes` from the
same `HybridPublicKey`. Any encoding drift between wallet derivation and emission vin is a
consensus fault.

**Customization versioning:** `shekyl/archival-p-id-v1` is independent of HKDF label
versioning — both bump only on a documented hard-fork / migration (V4 or identity redesign).

### 9.6 Signing and scanning contracts

**Spend / emission (`pqc_auths`):**

- `P` transactions use `scheme_id = 1` (`ed25519_ml_dsa_65`).
- `hybrid_public_key` in each input's `PqcAuthentication` = `hybrid_sign_pk` (account-level,
  not per-output `shekyl-pqc-output` derivation).
- Per-output ML-DSA inside FCMP++ leaves still uses the **output** derivation path when
  constructing spends — account ML-DSA is the container key; output secrets remain per-index.
  Stage 3 must not conflate the two surfaces.

**Dual scan (wallet):**

| Scan path | View material | Output derivation | Must not share |
|-----------|---------------|-----------------|----------------|
| Principal | principal `view_sk` | `combined_ss` from principal decap | — |
| `P` | `P.view_sk` | `combined_ss` from `P` decap | principal view tags, principal `enc_label` domain |

Scanner runs **two independent identification pipelines** keyed on different view secrets.
Merging into one scan loop without domain separation is a firewall violation.

**Membership-only emission:** Backing UTXOs are spent on `P`'s keys; verifier omits key
image from spent set per emission leg — crypto surface unchanged; only the signing keys are
`P`'s hybrid material.

### 9.7 V4 reversion clause (per `21-reversion-clause-discipline.mdc`)

| Artifact | Current | Reopen when | Re-evaluation |
|----------|---------|-------------|---------------|
| HKDF info labels `…-v1` | §9.3 table | V4 lattice-only migration specifies successor primitives | New labels `…-v2`; new KAT suite; hybrid `scheme_id` coexistence per [`VERSIONING.md`](../VERSIONING.md) |
| `shekyl/archival-p-id-v1` | §9.5 | `HybridPublicKey` canonical encoding changes | New customization string; bond-record migration doc |
| `scheme_id = 1` on `P` spends | §9.6 | `scheme_id = 3` (lattice threshold) ships for archival spends | PHASE_2B + emission leg amendment; multisig `P` (V3.1) may precede |

**Not a reopening criterion:** "uncertainty about long-term PQC posture" — that is why V3 is
hybrid and V4 is gated; gate 6 does not ship a classical-only `P` escape hatch.

### 9.8 Round 1 exit checklist

- [x] HKDF label table with `-v1` suffixes and `p_slot` binding.
- [x] Account-level ML-DSA disposition for bond `HybridPublicKey`.
- [x] `P_canonical_id` wire aligned to emission leg §6.1.
- [x] Dual-scan and signing-surface separation stated.
- [x] V4 reversion clauses named.
- [ ] Reviewer sign-off on Round 1 draft.
- [ ] `ARCHIVAL_P_DERIVE_V1` KAT manifest (fixed `master_seed` + `p_slot` → known `p_canonical_id`).
- [ ] `shekyl-crypto-pq::archival_p` implementation + unit tests.

---

## 10. Related documents

| Doc | Relationship |
|-----|----------------|
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | Parent wallet scope; §2.4 admission shape |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Emission timing, batching, `P` id |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Public retention timeline |
| [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) | L16 transport; soundness pass step 3 |
| [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) | Phase 2b `phase2b_gate6_p_registration` |
| [`POST_QUANTUM_CRYPTOGRAPHY.md`](../POST_QUANTUM_CRYPTOGRAPHY.md) | Global hybrid policy; `HybridPublicKey` encoding |

---

## Revision history

- **2026-06-07 (Round 1 draft):** §9 — `P` hybrid derivation (HKDF labels, `ArchivalPKeys`,
  `P_canonical_id`, dual-scan, account-level ML-DSA, V4 reversion clauses).
- **2026-06-07 (Round 0 open):** Initial scaffold — four layers + bond-funding; `P`
  lifecycle; invariants; round plan; E-4 / epoch-length / L16 couplings named.
