# Archival firewall — gate 6 (`P` lifecycle + pseudonym hygiene)

**Status:** **Round 1 closed (2026-06-13)** — crypto layer + `P` hybrid derivation pinned (§9);
GF-1 per-tx-type verifier contract resolved and GF-2 dual-scan enforcement made architectural;
reviewer sign-off recorded (§9.8), with post-sign-off review refinements (C-1/C-2/C-3) folded in.
**Round 2 (network + transport) is next.** Round-1 carries: the `ARCHIVAL_P_DERIVE_V1` KAT manifest
+ `archival_p` implementation (§7), and the **C-1 confirm-at-source dependency** — the emission
vin-layer ML-DSA equality check (a hard merge blocker, §9.8) must land before the `archival_p`
impl is wired into emission. Network/timing/output rounds still open. Not soundness-closed.
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
| Per-epoch serve-credit ledger resolution | Archival state / F1 | **Public liveness fingerprint** at epoch granularity |
| `MAX_CLAIM_AGE_W` | Archival state §2.4 | Forfeiture horizon + hot-state bound (not decorrelation — F1 T-A1) |

**`W` vs. batch cap (GF-11, no new pin):** `MAX_CLAIM_AGE_W = 26 >
MAX_SETTLEMENT_EPOCHS_PER_EMISSION = 15` is already pinned in
[`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1. The **batch cap (15)**, not
the forfeiture horizon (26), is therefore the binding constraint on how many settlement epochs a
single emission may claim — a `P` cannot legally widen its claim window to the forfeiture horizon
to thin its timing fingerprint. This ordering is a consensus fact, not a gate-6 decorrelation
lever.

**E-4 threat (named):** Fine-grained per-epoch retention timeline + shard-set adjacency
across **`P_old` → `P_new` rotation** re-links identities if rotation is cosmetic
(same storage, same shard set, adjacent epochs). **Rotation must change observable
behavior**, not only `P_id`.

**T-A1 update (2026-06-07).** At lean equilibrium, scarcity-spread produces **unique
portfolios** (~98% singleton) — the privacy shadow of coverage working correctly. Timeline
re-linkage is a **non-channel**; **portfolio = public identity** when rotation preserves
storage (rational for scarce-shard income). Rotation does **not** reset the observation
window: effective `T_obs` = operator **lifetime**. T-A3–T-A7 must hold against that window;
see [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md).

**Honest disclosure:** re-linkability across rotation is portfolio-bound; decorrelation
requires abandoning scarce-shard income. Forced cohort portfolios price ~97% deep
under-coverage — not a viable mitigation without Form-C / reward-shape reopen.

**F1 disposition:** conditionally finally accepted (qual wargame §9.8). Form-C reopen **not
triggered**. Wallet disclosure draft: [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §10.

**Round-open:** jitter policy; drain-spacing defaults (consensus cluster pinned —
[`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §7).

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

**GF-4 status:** the drain **delay floor** is already pinned (`≥ RELEASE_COOLDOWN ×
SETTLEMENT_EPOCH_BLOCKS`, [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §7), so
"how long after last emission" is closed. The genuinely-open piece is the **terminal-drain
output-count discipline** — a single lump sweep still re-links the reward history to one
principal cluster even with the delay satisfied. That output-count discipline is the **Round 4
hard exit** (§6), not a Round-1 carry.

### 2.5 Bond-funding layer (fifth surface)

**Goal:** Posting per-shard bonds does not become a **principal→`P` correlation channel**
(lump funding from a fresh principal output immediately before first emission).

**Gate-7 input (closed bonds-only, 2026-06-11):** there is **no consensus admission
minimum** — `ADMISSION_MIN_ATOMIC` was deleted from the emission leg
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §10.2;
[`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) ledger G7). Bond sufficiency at
join-Market (gate 4) is the **only** consensus-checked funding obligation on `P`. Any
funding minimum or ramp shape is therefore **this layer's policy alone**, owned here
end-to-end; nothing upstream constrains it.

**Policy pin (2026-06-11): no funding minimum, at any layer.** The wallet imposes **no
minimum** on principal→`P` transfers. Rationale, by surface: *consensus* — admission
amounts do no consensus work (gate 7); *Sybil pricing* — market identities are priced
by `bond_floor × shards` at join-Market, not by `P`'s balance; *economics* — the
gate-7 sim showed admission-side locks macro-immaterial at every tested magnitude;
*privacy* — stake-in amounts are confidential (ordinary FCMP++ transfer), so a
prescribed minimum is unobservable on-chain and does no firewall work — this layer's
real threats are funding **shape and timing** (lump-vs-ramp, join-Market adjacency),
which a minimum does not address. A floor with no load-bearing surface is optionality
debt. **Reversion (rule 21):** reopen iff a named gate-6 threat or V3.x consensus
change makes an amount floor load-bearing (e.g., a future emission rule that reads
`P`-balance, or a demonstrated dust-funding attack on wallet scan performance);
re-evaluation is a §2.5 round with the threat named, not a reflex re-derivation.

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
       → optional rotation P_old → P_new (portfolio-changing) → lapse / forfeit
       → terminal drain → retire P
```

| Phase | Consensus-visible? | Gate-6 load-bearing |
|-------|-------------------|---------------------|
| HKDF derive `P` | No | Independent material; scan isolation |
| Off-chain announce + backing presentation | Peers see | Backing before join-Market; no principal metadata |
| **join-Market** | Yes (bond record create, `E_join`) | **Standing timing event** — defang via §2.3/§2.5; cannot hide in mint |
| First **paying** emission | Yes (mint + dedup) | Decorrelate from principal funding |
| Ongoing service | Yes (retention bits, holdings) | Network path; epoch-timeline fingerprint |
| Rotation | Yes (new `P_id`, holdings transfer) | Portfolio change only — cosmetic swap insufficient (T-A1) |
| Deliberate lapse > `W` | Yes (forfeiture) | Forfeiture economics — does not decorrelate without portfolio change |
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
4. **Rotation is not cosmetic (network leg)** — `P_new` must not share principal clearnet
   path / network fingerprint. **Portfolio/timeline leg superseded by T-A1:** cosmetic
   rotation with fixed storage is rational and re-linkable on public holdings (F1 residual);
   see [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9.7.
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
| **`shekyl-wallet-core` / `StakeEngine`** | `P` HKDF; build emission/drain txs; rotation ceremony; bond-funding UX defaults; local jitter |
| **`StakeEngine` — `P`-scan identification context** | **Sole owner of `P.view_sk` and the `P`-scan pipeline** — a Gate-6 forward requirement on the PHASE_2B FSM retool, not inherited from claim-era §4.6 (§9.6 ownership-boundary clause). `P`-output identification descends from `P`'s `combined_ss`/decap, structurally disjoint from the principal `LedgerEngine` scan; outputs route by which decap matched, never cross-assigned |
| **`LedgerEngine` — principal-scan context** | Owns principal `view_sk`; **must not** receive `P.view_sk` or `P` decap material; principal scan never claims a `P`-destined output |
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
| **1** | HKDF/`P_id` wire + crypto layer hooks | **Done** (2026-06-13) — §9 GF-1 dual-key verifier contract resolved; GF-2 dual-scan enforcement made architectural; reviewer sign-off recorded (§9.8). **Lone carry:** `ARCHIVAL_P_DERIVE_V1` KAT manifest + `archival_p` module (impl, §7). |
| **2** | Network + transport (L16 → production shape) | Rendezvous path specified; seeding relaxation bounded. **Entry gates (R1-named):** challenge-response Levin message class added to the anonymity-routable set (GF-3); pre-join backing-presentation transport requirement pinned (GF-5); Arti HS-hosting source verification as an entry gate (GF-12); `P`-tx-type wire-size fingerprint characterized + dummy/fragmentation policy decided (GF-6); Tor HS key lifecycle either in-scope or named in the honest residual (GF-9). |
| **3** | Timing + rotation + `W` / epoch-length joint pin | E-4 mitigations named with testable wallet defaults. **Exit gate (R1-named):** within-epoch claim jitter min/max bounds pinned (GF-10). |
| **4** | Output + bond-funding hygiene | Drain/ramp defaults; threat-model §7 rebase in PHASE_2B. **Hard exits (R1-named):** terminal-drain **output-count** discipline pinned (GF-4 — delay floor already pinned, see §2.4); join-Market structural-distinguishability characterized + minimum separation from bond-funding pinned (GF-7). |
| **5** | Cross-layer adversarial pass | Soundness-depth sign-off for Stage 3 |

**Parallel (not gated on gate-6 closure):** [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md)
schema implementation; PHASE_2B §3–§7 FSM retool off rebased §2.4.

---

## 7. Implementation checklist (pre-code)

- [x] Pin `P` HKDF labels + `P_canonical_id` alignment with emission leg (§9).
- [x] Pin per-tx-type verifier contract — account `hybrid_sign_pk` is bond-record identity only;
      per-input auth is per-output (GF-1, §9.6).
- [ ] Land `ARCHIVAL_P_DERIVE_V1` KAT vectors + `shekyl-crypto-pq` `archival_p` module.
- [ ] Pin off-chain announce/backing presentation wire (daemon + wallet).
- [ ] Pin rotation ceremony (over-enumeration; holdings/bond migration).
- [ ] Pin network rendezvous requirement for production archival serving.
- [ ] Pin wallet defaults: emission batching, drain decorrelation, bond-funding ramp
      (T-A4/T-A6 conditional passes; [`F1_TA3_TA7_LIFETIME_WINDOW.md`](F1_TA3_TA7_LIFETIME_WINDOW.md) §9).
- [ ] Land wallet disclosure §10 in UX copy.
- [x] SEB pinned (10_000) — joint gate-2 cadence + epoch-granularity fingerprint (`ARCHIVAL_TIMING_CONSTANTS.md` §1.2).
- [ ] Rebase PHASE_2B §7 threat model — draft:
      [`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md) (review → land).
- [ ] Stage 3 test vectors: cross-layer linkability negatives — **including the GF-2
      cross-pipeline non-cross-assignment test** (no output emitted to both principal and `P`
      scan contexts; §9.6).

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

HKDF-SHA-512(salt, ikm = master_seed_64, info = LABEL || p_slot.to_le_bytes(), L = per-row)
```

`L` is **pinned per output** in the table below (it is not a free parameter): `64` for the
Ed25519 wide-reduce and ML-KEM `d_z` paths, `32` for the ML-DSA-65 seed — matching
[`account.rs`](../../rust/shekyl-crypto-pq/src/account.rs) (`L=64` wide-reduce) and
[`derivation.rs`](../../rust/shekyl-crypto-pq/src/derivation.rs) `keygen_from_seed(seed: &[u8; 32])`.

| Output | Info label (`LABEL`) | `L` | Consumer |
|--------|----------------------|-----|----------|
| `spend_wide` | `shekyl-archival-p-ed25519-spend-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 spend |
| `view_wide` | `shekyl-archival-p-ed25519-view-v1` | 64 | `wide_reduce_to_scalar` → Ed25519 view |
| `kem_d_z` | `shekyl-archival-p-ml-kem-768-v1` | 64 | `ml_kem_chacha_seed_from_d_z` → ML-KEM-768 KG (same SHA3-ChaCha intermediary as principal; **separate `d_z`** from label) |
| `ml_dsa_seed` | `shekyl-archival-p-ml-dsa-65-v1` | 32 | `keygen_from_seed` → ML-DSA-65 keypair (ChaCha20Rng seeded) |

**Forbidden info labels on the `P` path:** `shekyl-ed25519-spend`, `shekyl-ed25519-view`,
`shekyl-ml-kem-768`, and the entire `shekyl-output-derive-v1` / `shekyl-pqc-output` tree.

**Info-string concatenation note (micro, KAT-authoring).** `info = LABEL || p_slot.to_le_bytes()`
is **not length-prefixed**. It is unambiguous under the current label set — the labels are
non-prefix-free with respect to each other and `p_slot` is fixed-width (4 B LE) — so no two
`(LABEL, p_slot)` pairs collide. The only way to break this is **adding a new label** whose bytes
are a prefix of an existing label's `LABEL || slot` concatenation. **Disposition:** lock a
single-byte separator (`LABEL || 0x00 || p_slot.to_le_bytes()`) into the `ARCHIVAL_P_DERIVE_V1`
KAT at manifest-authoring time, so the wire is fixed before any label is ever added. No wire
change now (the current concatenation is safe and unimplemented); this is a note to the KAT
author, not a Round-1 reopener.

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
  hybrid_bond_id:             HybridPublicKey,       // == hybrid_sign_pk; bond-record IDENTITY only
  p_canonical_id:             [u8; 32],              // §9.5
}
```

**`hybrid_bond_id` is identity-only.** It is the on-wire `P_pubkey` that keys the bond record
and `p_canonical_id`; it is **never** used as a per-input `PqcAuthentication.hybrid_public_key`.
Per-input spend authority — including emission backing inputs and the terminal drain — is the
**per-output** `shekyl-pqc-output` derivation (the §9.6 GF-1 contract). The account ML-DSA key
inside `hybrid_sign_sk` signs bond-record / emission-identity material, not individual inputs.

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

**Signing surfaces by transaction type (`pqc_auths`) — GF-1 contract:**

`P` transactions use `scheme_id = 1` (`ed25519_ml_dsa_65`). The account-level `hybrid_sign_pk`
(= `hybrid_bond_id`, §9.4) is the **bond-record identity**: it appears on the wire **only** as
the `P_pubkey` field feeding `P_canonical_id` (§9.5), and is **never** a per-input
`PqcAuthentication.hybrid_public_key`. Per-input authentication always uses the **per-output**
`shekyl-pqc-output` derivation, exactly as principal spends do. The earlier draft conflated the
container identity with the per-input auth key; they are distinct surfaces and the verifier
checks each against a different key.

| `P` tx type | Account `hybrid_sign_pk` role | Per-input `pqc_auths.hybrid_public_key` | Verifier |
|-------------|-------------------------------|------------------------------------------|----------|
| **join-Market / bond-post** (gate 4) | `P_pubkey` **identity** — creates the bond record keyed by `P_canonical_id` | **per-output** (ordinary funding inputs; key image present) | create/lookup `ArchivalBondRecord` by `P_canonical_id`; funding inputs via standard key-image path |
| **reward emission** ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.3) | `P_pubkey` **identity** on the emission vin — bond lookup + dedup keying | **backing inputs:** ML-DSA verifies against the **`pqc_pk` committed in the *same proven leaf, at the same input index*** — the membership proof commits `H(pqc_pk)` as an in-circuit extra leaf scalar (`with_extra_scalars`, index-bound), and the vin recomputes `H(pqc_pk)` from the supplied key and demands equality with **that** leaf's committed scalar ([`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) §7), **no key image**. **fee inputs** (`txin_to_key`): **per-output**, key image present | §7.1 emission order; backing auth is membership-only + the vin-layer ML-DSA equality check (**C-1 carried dependency, §9.8** — not yet landed); fee inputs standard |
| **ordinary transfer / terminal drain / reward-output spend** | **none on wire** | **per-output**, key image present | standard FCMP++ path — **no `P`-typing** |

**Why ordinary `P` transfers carry no identity field:** they are byte-shaped identically to
principal transfers, so a verifier cannot (and must not) tell a `P` drain from any other
transfer — that indistinguishability is the firewall property (§4 invariant 1), not a gap.
Only emission and bond-post transactions self-identify, via the `P_pubkey` field and the
archival-bond-table lookup. There is no "is this a `P` spend?" branch on the ordinary spend
path, and so no account-level key on it.

**Dual scan (wallet) — GF-2 architectural enforcement:**

| Scan path | View material | Output derivation | Owner | Must not share |
|-----------|---------------|-----------------|-------|----------------|
| Principal | principal `view_sk` | `combined_ss` from principal decap | `LedgerEngine` | — |
| `P` | `P.view_sk` | `combined_ss` from `P` decap | `StakeEngine` | principal view tags, principal `enc_label` domain |

The firewall here is **structural, not a naming convention.** Its soundness rests on the crypto,
not on which actor runs the scan: each pipeline's per-output secrets descend from a **distinct
`combined_ss`** (distinct ML-KEM decap key + distinct Ed25519 ECDH), so an output that matches
one pipeline's `combined_ss` **cannot** match the other's at the full one-time-key check — the
discriminator is the decap layer, not a downstream label. The output-derive labels
(`shekyl-pqc-output`, `enc_label`) are **shared by construction**; the domain separation that
makes them safe lives entirely in the upstream `combined_ss` / decap material, which is why
pinning that is the load-bearing requirement.

**Ownership boundary (Gate-6 forward requirement on the PHASE_2B retool).** The dual-scan pipeline
(principal + `P`) is an authoritative genesis pin
([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.1 carry-over — "`P` HKDF
sub-wallet … dual scan"). Assigning sole ownership of `P.view_sk` to `StakeEngine` (separate from
the principal `LedgerEngine` scan) is a Gate-6 **requirement the FSM retool must honor**, not a
fact inherited from current PHASE_2B text: §4.6's `StakeEngine` trait surface is **claim-era /
pending retool** (flagged STRATUM in the PHASE_2B header; authority is
[`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)), so it is not yet a binding ownership pin. The
crypto basis above holds regardless of the actor assignment; this clause pins the assignment so
the retool lands it rather than leaving it implicit.

A **single shared scan loop is acceptable only** if each candidate output is routed by which
`combined_ss`/decap matched, with no cross-assignment — an output is emitted to exactly one
pipeline. Merging the two into one identification context keyed on a single view secret, or
allowing an output to be tried-then-claimed by both contexts, is a firewall violation.

**Negative test (Round-1 named, folded into §7 cross-layer linkability negatives):** no output
is ever emitted to both the principal and `P` pipelines; a `P`-destined output presented to the
principal scan context produces no match, and vice versa. This is the cross-pipeline
non-cross-assignment test. **Defensive invariant (C-3):** "exactly one pipeline" is cryptographically
guaranteed at the full one-time-key check (distinct `combined_ss` ⇒ at most one match), so a
double-match is impossible by construction — the implementation must therefore **loud-fail**
(not silently pick one) if both pipelines' full-key checks ever pass for a single output. Assert
the double-match-is-unreachable invariant rather than assuming it.

**Membership-only emission:** Backing UTXOs are spent under `P`'s **per-output** key material
(not the account key); the verifier omits the key image from the spent set per the emission
leg. Because there is **no key image** on this path, the entire quantum spend-authority property
rests on one binding: the membership proof and the ML-DSA check must reference the **same proven
leaf at the same input index**, not merely each reference *a* leaf. The mechanism that delivers
this ([`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) §7, verified at source 2026-06-13): the
`Fcmp` membership leg commits `H(pqc_pk)` as an **in-circuit extra leaf scalar**
(`fcmps::Input::with_extra_scalars`) on the proven leaf, and the per-input challenge binds the
input index (§4.2/§8.2); the vin layer recomputes `H(pqc_pk)` from the supplied key and demands
equality with *that leaf's* committed scalar. An attacker who proves membership of a victim's
leaf cannot substitute their own `pqc_pk` (its hash would not match the leaf-committed scalar),
and cannot forge ML-DSA under the victim's `pqc_pk`. **Caveat (C-1):** the in-circuit half is
implemented in `FcmpMembershipOnly`; the **vin-layer ML-DSA equality check is a not-yet-landed
hard merge blocker** (§9.8 carried dependency). Until it lands, backing ownership reduces to
classical security. Only the bond-record **identity** (`P_pubkey`) is `P`'s account-level hybrid
material; the spend authority is per-output, per the table above.

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
- [x] Dual-scan and signing-surface separation stated (GF-1 per-tx-type contract; GF-2 architectural enforcement).
- [x] V4 reversion clauses named.
- [x] Reviewer sign-off on Round 1 draft (2026-06-13 — GF-1 resolved, GF-2 made architectural, GF-8/11/4 corrected, downstream round criteria named).
- [ ] `ARCHIVAL_P_DERIVE_V1` KAT manifest (fixed `master_seed` + `p_slot` → known `p_canonical_id`).
- [ ] `shekyl-crypto-pq::archival_p` implementation + unit tests.

**Carried dependencies (confirm-at-source before the impl + emission verifier land):**

- **C-1 — emission backing-input quantum spend-authority binding.** The GF-1 §9.6 emission
  contract rests entirely on the membership proof and the ML-DSA check binding the **same
  proven leaf at the same input index**. **Verified at source (2026-06-13,
  [`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) §7/§8.2/§9):** the in-circuit
  `H(pqc_pk)` extra-leaf-scalar binding (`with_extra_scalars`) is index-bound and **implemented**
  in `FcmpMembershipOnly`; the **vin-layer ML-DSA equality check** (recompute `H(pqc_pk)` from
  the supplied key, demand equality with the leaf-committed scalar) is a **hard merge blocker**
  named in `FCMP_MEMBERSHIP_ONLY.md` §7/§9 and `REWARD_EMISSION_LEG.md` §12 — **not yet landed**.
  **Obligation:** the emission vin verifier must implement and test this equality check before
  the `archival_p` impl is wired into emission construction; until it lands, no quantum
  spend-authority guarantee exists on the backing path (classical security only). This is a
  dependency Gate 6 leans on, not a Gate-6 deliverable — it discharges in the emission vin PR.

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

- **2026-06-13 (Round 1 post-sign-off review refinements):** Closure-review items on the
  sign-off itself. **C-1** — recorded the emission backing-input quantum spend-authority binding
  as a **named carried dependency** (§9.8) rather than a citation that read as closed; verified
  at source ([`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) §7/§8.2/§9) that the membership
  proof and ML-DSA check bind the **same proven leaf at the same input index** (in-circuit
  `H(pqc_pk)` extra scalar, index-bound — implemented), and that the **vin-layer ML-DSA equality
  check is a not-yet-landed hard merge blocker** that must precede the `archival_p` impl + emission
  verifier; sharpened the §9.6 emission row and membership-only paragraph accordingly. **C-2** —
  re-anchored the GF-2 ownership boundary: the dual-scan pipeline is the authoritative §2.1 genesis
  pin, but `StakeEngine`'s sole ownership of `P.view_sk` is a Gate-6 **forward requirement on the
  PHASE_2B FSM retool**, not inherited from claim-era §4.6 (flagged STRATUM); the crypto basis
  (distinct `combined_ss`/decap) is independent of the actor assignment. **C-3** — added the
  loud-fail defensive invariant to the cross-pipeline negative test (double-match is unreachable
  by construction; the impl must assert it, not assume it). Micro — recorded the §9.3 info-string
  non-prefix-free safety argument + the separator-byte-at-KAT-authoring disposition (no wire change
  now).
- **2026-06-13 (Round 1 closed):** Adversarial pass disposition. GF-1 — rewrote §9.6 with a
  per-tx-type verifier-contract table: account `hybrid_sign_pk` is bond-record **identity only**
  (`P_pubkey`), never a per-input auth key; emission backing inputs authenticate against the
  leaf-committed per-output `pqc_pk` (membership-only); fee inputs / ordinary transfers / drains
  use per-output keys; ordinary `P` transfers carry no `P`-typing. §9.4 `hybrid_bond_id` note
  strengthened to identity-only. GF-2 — made dual-scan firewall **architectural**: `StakeEngine`
  owns `P.view_sk` as a separate identification context, separation rests on distinct
  `combined_ss`/decap (not a naming convention), shared scan loop allowed only with
  match-routing; named the cross-pipeline non-cross-assignment negative test; added `P`-scan
  ownership rows to the §5 consumer map. Corrections — GF-8 (§9.3 `L = …` placeholder fixed; `L`
  values were already pinned in the table), GF-11 (§2.3 cross-ref that `W=26 > 15` is pinned in
  `ARCHIVAL_TIMING_CONSTANTS` §1), GF-4 (§2.4 note: delay floor already pinned, output-count is
  the open R4 hard exit). §6 round table + §7 checklist updated; remaining findings folded as
  named R2/R3/R4 entry/exit criteria. Reviewer sign-off recorded (§9.8); KAT manifest +
  `archival_p` impl remain the lone carry.
- **2026-06-07 (Round 1 draft):** §9 — `P` hybrid derivation (HKDF labels, `ArchivalPKeys`,
  `P_canonical_id`, dual-scan, account-level ML-DSA, V4 reversion clauses).
- **2026-06-07 (Round 0 open):** Initial scaffold — four layers + bond-funding; `P`
  lifecycle; invariants; round plan; E-4 / epoch-length / L16 couplings named.
