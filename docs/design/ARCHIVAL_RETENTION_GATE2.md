# Archival serve-credit — gate 2 (epoch challenge + loud 8c wire)

**Status:** **Round 1 obligation pinned (2026-06-08).** On-demand **serving** semantics;
no continuous-storage proof. Byte-exact wire + verifier crate open (membership layer
constructible per [`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md)).

**Scope:** How `serve_credit_bit(P_id, shard, E)` is **earned** — one affirmative epoch
challenge per bonded shard, Merkle opening to `R_k`, consensus verify, slash on miss.
Writes the gate-2-internal surface in [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §6.

**Legacy name:** `retention_bit` in emission formulas = **`serve_credit_bit`** (misnomer; means
"passed this epoch's on-demand check," not "stored continuously").

**Authority chain:**

| Doc | Role |
|-----|------|
| [`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) | Constructibility — Merkle PoR to `R_k` |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2 | Segment = shard; frozen `R_k`; subtree level |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `serve_credit_bit` ledger; invariants 1–4 |
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Slash on failed challenge; join gates bit writes |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Off-chain delivery; `P` signature binding |
| [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) | `CHALLENGE_RESOLUTION_BLOCKS`, SEB |
| [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](ARCHIVAL_FAILURE_CONFIRMATION_PIN.md) | Sliding-window m-of-n pinned; escalation rejected (Round-1) |

**Out of scope here:** emission economics (gate 1); bond-post wire (gate 4); wallet FSM;
onion RPC message formats (gate 6 + `ANONYMITY_NETWORKS.md`); per-fetch payment for organic
retrieval volume (§0.4 reopen); PoRep-class independent storage (priced alternative, not genesis).

---

## 0. Obligation (Round 1 — solved shape)

**Product.** Foundation guarantees **B+C exist** somewhere durable and auditable. Market
archivers provide **reach + privacy + participation** — shard data available from many
firewalled pseudonyms `P` on demand, not a second durability domain over public bytes.

**Paid good.** Successful **response to demand** when tested — not a ledger of 24/7 disk
possession. Quiet epochs with no organic fetch and no challenge: no credit, no slash, silence.

**Protocol (consensus / hash / convergence only):**

1. **P bonds** to shard `s` (join-Market, gate 4).
2. **Each epoch `E`:** one **guaranteed baseline** challenge per `(P, s)` — the demand floor so
   honest `P` can earn even with no organic traffic. **Scheduling after a miss** —
   **sliding-window m-of-n** pinned in
   [`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](ARCHIVAL_FAILURE_CONFIRMATION_PIN.md) §1; genesis
   implements baseline + slash-on-miss tally; escalation FSM rejected.
3. **Leaf index `ℓ`** — deterministic, public (`H(P, s, E)`-style); pre-knowledge does not
   help (must still produce the opening when fired).
4. **Challenge fire time** within `E` — **beacon-unpredictable** (reachability: `P` must be
   reachable across the epoch, not post-and-vanish at a known minute).
5. **P posts** verifying opening to `R_k`, signed as `P`, by deadline.
6. **Consensus** verifies hash path + signature; nodes converge.
7. **Affirmative pass** → `serve_credit_bit`; **miss** → slash (gate 4).

Fetch-on-demand at test time **is** providing the service for that test. There is no
cryptographic barrier to verifying shards — only a prior **wrong statement** ("proved
continuous private storage") that this section retires.

### 0.1 Load-bearing pins

**Affirmative pass, not absence-of-failure.** Credit requires **demonstrated response this
epoch**. "Bonded and never slashed" is not credit — unreachable `P` must not earn.

**Timing unpredictability** targets **reachability**, not leaf secrecy. Leaf grinding is
secondary (hashpower-gated; `P` still had to answer). Predictable fire time lets `P`
post-and-vanish; unpredictable fire time is the service shape.

### 0.2 Architecture consequences (relabel, no new crypto)

| Topic | Disposition |
|-------|-------------|
| **`serve_credit_bit`** | "Passed epoch on-demand check" — rename from `retention_bit` in prose; emission wire may keep legacy field name until sweep |
| **L15 `R_target` / three-nines** | **Reach/availability** over serving endpoints — not market durability (foundation floor only) |
| **Market redundancy** | Redundancy of **pseudonyms** ≤ redundancy of **operators**; firewall makes the gap unmeasurable by design — **accepted**; Sybil cost = bond sizing (existing lever), not durability risk |
| **Organic user fetches** | Actual service (users fetch; **no** per-fetch consensus payment at genesis) |

### 0.3 Reopen clause — traffic-proportional pay

**Rejected at genesis:** consensus credit proportional to **attributed organic retrieval
volume** ("`P` served user `W`"). Baseline epoch challenge has no witness to fake; volume
pay needs attributable serves, `W` can be `P`'s cheap Sybil → **self-dealing** without chain
capture.

**Reopen:** Form-C economics review + threat-model amendment + explicit auditor/attribution
protocol if "pay for measured real traffic" is ever desired.

### 0.4 PoRep alternative (calibration, not plan)

True **independent durable storage** (second domain beyond foundation) requires slow
P-specific sealing (PoRep-class). Priced upper bound; not genesis for this obligation.

---

## 1. Statement (normative)

For settlement epoch `E`, shard `s` (segment `k`), and archiver `P` with
`P_id = P_canonical_id`:

**Prover** (`P`, serving shard `s`) produces opening `π` proving correct leaf `L_ℓ` at
segment-relative index `ℓ` under frozen sub-root `R_k(s)`:

```text
VerifyPath(L_ℓ, π, R_k) = true
```

using `shekyl-fcmp::tree` grow/trim rules ([`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) §1.2).

**Verifier** (consensus) accepts iff:

1. `P` has an `ArchivalBondRecord` and `shard s ∈ holdings` at response height.
2. `P ∈ Market` for epoch `E` (gate 4 §2.2).
3. `E ≥ E_join + 1` (no pre-join bits — gate 4 §1.4).
4. Opening verifies against checkpointed `R_k` for `(s, E)`.
5. `ℓ` matches deterministic epoch index (§3.3).
6. Response arrives by credit deadline (§4).
7. Response carries valid `P` hybrid signature (§5.2).

**Effect on accept:** `serve_credit_bit(P_id, s, E) := true` (consensus write at block connect).

**Loud 8c:** Forging acceptance without producing a valid opening at **fire time** is
infeasible under hash collision resistance. **Not claimed:** continuous offline possession
between challenges (§0).

---

## 2. Shard geometry (consensus inputs)

Gate 2 **consumes** segment geometry from [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2;
it does not redefine it.

| Field | Source | Gate-2 use |
|-------|--------|------------|
| `shard_id` / `segment_id` | Shard registry (consensus state §3.2) | Challenge + ledger key |
| `segment_leaf_count` | Registry at epoch close | `ℓ_j = τ_j mod segment_leaf_count` |
| `R_k` | Segment checkpoint / `shard_content_hash` | Path verification root |
| `segment_leaf_base` | Global tree position of segment start | Optional audit; challenges use **segment-relative** `ℓ_j` |

**Genesis provisional:** subtree **level 2** (~26k leaves per segment per `CURVE_TREE_CLIENT`
§7.2.2). Numeric `segment_leaf_count` is fixed at CT-1 sizing review; until then verifier
uses registry value committed at epoch close.

**Rejected:** Whole-chain-root challenges (`V3_STAKER_ARCHIVAL.md` legacy §"Verification") —
superseded by `R_k`-local paths (8c feasibility §4).

---

## 3. Challenge derivation (deterministic, no challenge tx)

Challenges are **not** a separate on-chain transaction type at genesis. Every full node
derives identical `(ℓ, H_fire, R_k)` from consensus-visible state (§3.3–§3.4).

### 3.1 Constants (genesis pin)

| Constant | Value | Role |
|----------|-------|------|
| `CHALLENGES_PER_EPOCH` | **1** | Guaranteed on-demand test per `(P,s,E)` — demand floor (§0) |
| `CHALLENGE_RESOLUTION_BLOCKS` | **10_000** | Slash grace after `H_close` — [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) |
| `CHALLENGE_BEACON_SEAL_BLOCKS` | **1** (provisional) | Blocks after `H_open` before `block_hash(H_seal)` is fixed — `shekyl-archival-retention::CHALLENGE_BEACON_SEAL_BLOCKS` |
| `CHALLENGE_RESPONSE_BLOCKS` | **TBD (byte pin)** | Blocks after `H_fire` to accept credit; must end before `H_close` |

### 3.2 Epoch heights (ordering)

```text
E                 = settlement epoch under test
H_open            = first block with settlement_epoch(height) == E
H_close           = last block with settlement_epoch(height) == E
H_fire            = beacon height ∈ (H_open, H_close]     // §3.4
H_credit_deadline = H_close
H_slash_deadline  = H_close + CHALLENGE_RESOLUTION_BLOCKS
```

**Round 0 error (do not implement):** `H_fire` in epoch `E+1` — incompatible with E-close
emission read.

### 3.3 Leaf index (deterministic)

```text
τ = cSHAKE256(
  customization = "shekyl/archival-serve-challenge-leaf-v1",
  input         = P_id[32]
                  || shard_id_le64
                  || E_le64
)

ℓ = uint64(τ) mod segment_leaf_count(shard, E)
```

`ℓ` is knowable at epoch open; `P` must still be **reachable at `H_fire`**.

### 3.4 Fire time (beacon — reachability)

```text
H_seal = H_open + CHALLENGE_BEACON_SEAL_BLOCKS    // early in E; provisional pin = 1
span   = H_close − H_seal                         // known once H_seal exists
H_fire = H_seal + ( uint64(beacon) mod max(span − 1, 1) ) + 1

beacon = cSHAKE256(
  customization = "shekyl/archival-serve-challenge-fire-v1",
  input         = block_hash(H_seal)
                  || P_id[32]
                  || shard_id_le64
                  || E_le64
)
```

**Knowable at `H_seal`:** `ℓ` (§3.3) and `H_fire` are fixed; `P` must post in
`(H_fire, H_close]` — cannot post-and-vanish at epoch open. Unpredictable at `H_open`
(`block_hash(H_seal)` unknown).

**Load-bearing:** unpredictability is **when** the opening must post, not **which** leaf.

**Grinding (exotic):** colluding miner may bias `H_fire` within `E`; hashpower-gated; `P` must
still serve a valid opening.

### 3.5 Who is challenged

After `H_fire`, for each `P_id` with `ArchivalBondRecord` where:

- `shard_id ∈ holdings` at `H_fire`, and
- `P ∈ Market` for settlement epoch `E` (E-close snapshot),

consensus expects **affirmative** response by `H_credit_deadline`, else slash after
`H_slash_deadline` (§6).

**Foundation `CompleteTree`:** same path; slash semantics differ (gate 4 §4.2). Serve-credit
for emission (E-2).

---

## 4. Response window and serve-credit timing

```text
Timeline (settlement epoch E):

  H_open ─── … ─── H_fire ─── … ─── H_close ─── … ─── H_slash_deadline ───►
                  (beacon; ℓ      (emission      (slash if no
                   known)          reads bit)     serve_credit)
```

| Event | Height | Consensus action |
|-------|--------|------------------|
| `H_fire` known | `H_fire` ∈ `(H_open, H_close]` | Derive `ℓ`; deliver challenge to `P` (gate 6) |
| **Affirmative pass** | `H_fire < height ≤ H_credit_deadline` | Set `serve_credit_bit(P_id,s,E)` |
| Emission read | `H_close` | Finalized bit for `E` (invariant 2) |
| Slash | `height > H_slash_deadline` | No bit → gate-4 slash |

**Quiet epoch:** no organic fetch and challenge not yet fired → no bit, no slash.

**One bit per `(P_id, shard, E)`:** single opening per epoch challenge (§3.1).

---

## 5. Wire — `txin_archival_serve_credit_response`

New non-spending vin type (consensus). One vin per `(P_id, shard, E)` affirmative pass.
(Legacy alias in drafts: `txin_archival_retention_response`.)

### 5.1 Logical fields

```text
ArchivalServeCreditResponse {
  p_canonical_id:           [u8; 32],
  shard_id:                 u64,
  settlement_epoch:         u64,          // E
  segment_subroot_rk:       [u8; 32],     // must match registry at H_fire
  leaf_index_in_segment:    u32,          // must equal ℓ from §3.3
  leaf_bytes:               [u8; 128],
  path:                     SegmentPathOpening,

  hybrid_signature:         HybridSignature,
}
```

```text
SegmentPathOpening {
  // Replays shekyl-fcmp::tree from leaf_bytes to R_k.
  // Same layer discipline as shekyl-curve-tree::AssembledPath but rooted at
  // segment sub-root, not full-chain reference block.
  c1_layers:                Vec<Vec<[u8; 32]>>,
  c2_layers:                Vec<Vec<[u8; 32]>>,
  // Verifier checks c1.len() + c2.len() + 1 == segment_path_depth(shard)
}
```

**Forbidden on this vin:** mint fields; bond_credit/debit; `claimed_settlement_epochs`
mutation; FCMP++ membership proof (8c feasibility §6.3).

### 5.1.1 Byte layout (genesis pin)

Vin type tag **`4`** (`txin_archival_serve_credit_response`). Varint discipline matches
[`shekyl-oxide` `Input`](../../rust/shekyl-oxide/shekyl-oxide/src/transaction.rs) /
`shekyl-io`. Reference implementation: `shekyl-archival-retention::wire`.

```text
u8                      vin_type = 4
[32]                    p_canonical_id
varint                  shard_id
varint                  settlement_epoch
[32]                    segment_subroot_rk
u32_le                  leaf_index_in_segment
[128]                   leaf_bytes
varint                  c1_layer_count
repeat c1_layer_count:
  varint                c1_branch_scalar_count   (≤ 256)
  repeat scalar_count:
    [32]                selene/helios child scalar
varint                  c2_layer_count
repeat c2_layer_count:  (same shape as c1 branches)
varint                  hybrid_signature_len
[hybrid_signature_len]  HybridSignature::to_canonical_bytes()
```

`encode(path)` for §5.2 is the concatenation of the **c1** and **c2** branch sections only
(layer counts + branch bodies), **not** the leading type tag or identity fields.

**Preimage vs wire:** §5.2 uses `shard_id_le64` and `settlement_epoch_le64` (fixed width);
on-wire fields use varints. Do not substitute wire bytes for preimage fields.

### 5.2 Signature preimage

```text
sig_preimage = cSHAKE256(
  customization = "shekyl/archival-serve-credit-response-v1",
  input         = p_canonical_id
                  || shard_id_le64
                  || settlement_epoch_le64
                  || segment_subroot_rk
                  || leaf_index_le32
                  || leaf_bytes
                  || encode(path)
)
```

Signer: `P`'s hybrid key from gate-6 §9 (`ArchivalPKeys.hybrid_sign_sk`). Verifier checks
against `ArchivalBondRecord.P_pubkey`.

### 5.3 Verifier order (consensus)

Fail-fast:

1. **Structural** — field bounds.
2. **Bond posture** — record exists; `shard_id ∈ holdings`; `E ≥ E_join + 1`.
3. **Market** — `good_through(P,E)` at E-close.
4. **Leaf replay** — `leaf_index_in_segment == ℓ` from §3.3.
5. **Fire time** — `current_height > H_fire` (challenge has fired).
6. **Geometry** — `segment_subroot_rk` matches registry at `H_fire`.
7. **Path verify** — `VerifyPath(leaf_bytes, path, R_k)` via `shekyl-fcmp::tree`.
8. **Signature** — hybrid verify on §5.2 preimage.
9. **Credit deadline** — `current_height ≤ H_credit_deadline`.
10. **Idempotency** — reject duplicate if `serve_credit_bit` already set.

On accept: `serve_credit_bit(P_id, shard_id, E) := true` (**affirmative pass only**).

**Not verified:** spend authority on leaf; amount; output ownership.

---

## 6. Slash handoff (gate 4 consumer)

Gate 2 **does not** implement slash accounting. It emits a **verifiable failure** predicate:

```text
challenge_failed(P_id, shard, E) :=
  H_current > H_slash_deadline
  ∧ ¬ serve_credit_bit(P_id, shard, E)
  ∧ ArchivalBondRecord existed for P with shard in holdings at H_fire
```

On first block connect where `challenge_failed` is true, consensus calls gate-4
`slash(P, shard)` ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §4.2).

**T-A16 margin:** `CHALLENGE_RESOLUTION_BLOCKS` (10_000) ≫ typical onion round-trip;
release cooldown (20_000 blocks) > challenge window — timing cluster verified.

**Per-shard slash:** Failed challenge on shard `s` slashes **that shard's bond floor**;
holdings lose `s`; `== bond_floor` pin prevents partial theater.

---

## 7. Delivery (gate 6 interface)

| Layer | Responsibility |
|-------|----------------|
| **Consensus** | Derives challenge; verifies response vin; writes bit; triggers slash |
| **Gate 6** | Delivers `(P_id, shard, E, ℓ_j, R_k, H_deadline)` to `P` via onion rendezvous |
| **Wallet / archiver** | Holds set B; constructs openings; broadcasts response tx |

Challenge payload is **public** (derivable from chain); onion layer hides **reachability**,
not challenge secrecy.

**Production fallback:** If off-chain delivery fails, honest `P` still derives challenge from
chain and may self-respond — delivery is operational, not soundness.

---

## 8. `pop_block` revert

Within [`ARCHIVAL_REORG_DEPTH_BLOCKS`](../ARCHIVAL_TIMING_CONSTANTS.md) (720 blocks):

On disconnect of block `H` that **set** `serve_credit_bit(P,s,E)`: clear bit.

On disconnect of block `H` that **recorded** `slash(P,s)` from challenge failure: revert
slash per gate-4 §5 (bond credit restore, event log pop).

**Order:** Same atomic LMDB txn as gate-4 bond mutations (gate-4 §5).

**Cross-epoch:** Reorg deeper than `ARCHIVAL_REORG_DEPTH` does not roll back retention bits
(emission validity reads finalized E-close state; timing constants §2.4).

---

## 9. Shard registry writes (gate-2 adjacent)

Gate 2 **reads** `shard_id → { segment_leaf_count, R_k, segment_leaf_base }` at epoch
close. Registry updates are driven by curve-tree checkpoint connect (C++ daemon); gate-2
verifier treats registry as authoritative at `H_anchor`.

**Invariant:** `R_k` immutable after segment freeze (`CURVE_TREE_CLIENT.md` §7.2).

---

## 10. Implementation plan

| Step | Deliverable |
|------|-------------|
| 1 | `shekyl-archival-retention` crate — `verify_segment_path`, challenge replay, KAT from `shekyl-curve-tree` fixtures |
| 2 | C++/Rust `txin_archival_retention_response` deserializer + consensus hook |
| 3 | Connect bit write to archival LMDB tables (substrate reconciliation) |
| 4 | Slash scheduler at `H_deadline` (gate-4 hook) |
| 5 | Gate-6 wallet: construct response + hybrid sign |
| 6 | Worst-case verify benchmark → confirm no ZK reopen (8c §9.1 criterion 1) |

---

## 11. Checklist

**Round 1 obligation (pinned):**

- [x] §0 serving semantics; affirmative-pass credit; timing beacon
- [x] `serve_credit_bit` rename; L15 reach relabel; traffic-pay reopen §0.3
- [x] Leaf deterministic + fire unpredictable (§3.3–§3.4)
- [x] Epoch ordering (`H_fire` inside `E`, credit at `H_close`)

**Open (implementation):**

- [x] Byte-exact serialization + domain labels frozen (`shekyl-archival-retention::wire`, §5.1.1)
- [ ] KAT vectors (single opening per epoch)
- [x] `shekyl-archival-retention` verify crate (challenge replay + path verify; CT-4 cross-check KAT)
- [ ] Emission / consensus field rename sweep (`retention_bit` → `serve_credit_bit`)

---

## 12. Related documents

| Doc | Relationship |
|-----|--------------|
| [`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) | Cryptographic disposition |
| [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) | Pre-pass fossils |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Reads `retention_bit` for `work_P` |
| [`ANONYMITY_NETWORKS.md`](../ANONYMITY_NETWORKS.md) | Challenge delivery class |

---

## Changelog

- **2026-06-08:** Round 1 — §0 on-demand serving obligation; `serve_credit_bit`; beacon fire.
- **2026-06-08:** Round 0 draft — membership wire; ordering fix (review amendment).
