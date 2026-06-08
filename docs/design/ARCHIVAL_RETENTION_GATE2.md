# Archival retention proof — gate 2 (challenge + loud 8c wire)

**Status:** **Round 0 spec (2026-06-08).** Construction bytes and verifier contract pinned;
implementation (`shekyl-archival-retention`, C++/Rust vin, KATs) open. Cryptographic
disposition: **BUILD** per [`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md).

**Scope:** How `retention_bit(P_id, shard, E)` is **earned** — challenge derivation,
Merkle-opening response wire, verifier order, grace/slash handoff to gate 4, `pop_block`
revert. Writes the gate-2-internal surface deferred in
[`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §6.

**Authority chain:**

| Doc | Role |
|-----|------|
| [`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) | Constructibility — Merkle PoR to `R_k` |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2 | Segment = shard; frozen `R_k`; subtree level |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `retention_bit` ledger; invariants 1–4 |
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Slash on failed challenge; join gates bit writes |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Off-chain delivery; `P` signature binding |
| [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) | `CHALLENGE_RESOLUTION_BLOCKS`, SEB |

**Out of scope here:** emission economics (gate 1); bond-post wire (gate 4); wallet FSM;
onion RPC message formats (gate 6 + `ANONYMITY_NETWORKS.md`); ZK PoR (deferred per 8c §6.2).

---

## 1. Statement (normative)

For settlement epoch `E`, shard `s` (segment `k`), and archiver `P` with
`P_id = P_canonical_id`:

**Prover** (holder of set **B** for `s`) produces, for each sample index `j ∈ [0, m)`, an
opening `π_j` proving possession of leaf `L_{ℓ_j}` at segment-relative index `ℓ_j` under
frozen sub-root `R_k(s)`:

```text
VerifyPath(L_{ℓ_j}, π_j, R_k) = true
```

using `shekyl-fcmp::tree` grow/trim rules ([`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) §1.2).

**Verifier** (consensus) accepts iff:

1. `P` has an `ArchivalBondRecord` and `shard s ∈ holdings` at response height.
2. `P ∈ Market` for epoch `E` (gate 4 §2.2).
3. `E ≥ E_join + 1` (no pre-join bits — gate 4 §1.4).
4. All `m` samples verify against the checkpointed `R_k` for `(s, E)`.
5. Response arrives before slash deadline (§4).
6. Response carries valid `P` hybrid signature (§5.2).

**Effect on accept:** `retention_bit(P_id, s, E) := true` (consensus write at block connect).

**Loud 8c:** Forging acceptance without set-B material is infeasible under collision
resistance of the path hash and unpredictability of `ℓ_j` (§3).

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
derives identical `(ℓ_j, R_k)` from consensus-visible state.

### 3.1 Constants (genesis pin)

| Constant | Value | Role |
|----------|-------|------|
| `RETENTION_SAMPLES_PER_CHALLENGE` (`m`) | **3** | Independent leaf indices per `(P,s,E)` |
| `CHALLENGE_RESOLUTION_BLOCKS` | **10_000** | Response + slash grace (one SEB) — [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) |
| `CHALLENGE_ANCHOR_OFFSET_BLOCKS` | **1** | Anchor block = first block of settlement epoch `E+1` |

`m = 3` mitigates partial-storage free-riding (~1/26k per sample → ~1/26k³ joint miss mass
at level-2 segment scale; 8c feasibility §7).

### 3.2 Anchor height

```text
E        = settlement epoch under test
H_close  = height of last block with settlement_epoch(height) == E
H_anchor = H_close + CHALLENGE_ANCHOR_OFFSET_BLOCKS    // first block of epoch E+1
H_deadline = H_anchor + CHALLENGE_RESOLUTION_BLOCKS
```

**Rationale:** Anchor uses a **future** block hash relative to epoch `E` body (block in
`E+1`), satisfying unpredictability (`V3_STAKER_ARCHIVAL.md` §"Challenge unpredictability").
Issuing at `E+1` open avoids coupling bit timing to intra-epoch challenge-close ordering
(gate 4 §2.2 partial-epoch pin).

### 3.3 Per-sample index

```text
block_hash_anchor = block_hash(H_anchor)    // 32 bytes; consensus hash

τ_j = cSHAKE256(
  customization = "shekyl/archival-retention-challenge-v1",
  input         = block_hash_anchor
                  || P_id[32]
                  || shard_id_le64
                  || E_le64
                  || j_le32                    // j ∈ {0, 1, …, m-1}
)

ℓ_j = uint64(τ_j) mod segment_leaf_count(shard, E)
```

**Domain labels** are normative; changing them is a consensus fork.

### 3.4 Who is challenged

At `H_anchor`, for each `P_id` with `ArchivalBondRecord` where:

- `shard_id ∈ holdings` at `H_anchor`, and
- `P ∈ Market` for settlement epoch `E` (evaluated at E-close snapshot carried forward),

consensus expects a valid response by `H_deadline` or initiates slash (§6).

**Foundation `CompleteTree`:** same challenge path on **B**; slash semantics differ (gate 4
§4.2 whole-bond). Retention bit still written for emission exclusion rules (E-2).

---

## 4. Response window and retention bit timing

```text
Timeline (settlement epochs):

  …─── epoch E ───│─── epoch E+1 ─── … ─── epoch E+1 + grace ───►
                  H_close   H_anchor              H_deadline
                            (issue)                 (slash if no accept)
```

| Event | Height | Consensus action |
|-------|--------|------------------|
| Challenge materialized | `H_anchor` | Nodes derive `(ℓ_j, R_k)`; off-chain delivery to `P` (gate 6) |
| Valid `txin_archival_retention_response` included | `H_anchor < H ≤ H_deadline` | Verify openings; set `retention_bit(P_id,s,E)` on connect |
| No accepting response | first connect with `height > H_deadline` | Gate-2 failure → gate-4 `slash(P,s)` (§6) |

**One bit per `(P_id, shard, E)`:** Partial sample success is **rejected** — all `m` openings
must verify in the **same** response vin (or batched vins in one tx — implementation choice;
semantics: one atomic accept).

**Emission read:** `retention_bit` for epoch `E` is consumed at **E-close** for
`R_market(s,E)` / `work_P(E)` (archival state invariant 2). Practical pin: bit must be set
by `H_close` or the archiver is treated as **not retained** for `E` (no retroactive set
after E-close — invariant 2).

**Load-bearing tightening:** Response must be accepted with `height ≤ H_close` **or**
within a pinned grace that ends before E-close accounting runs. Default pin:

```text
H_deadline ≤ H_close    // NOT the longer CHALLENGE_RESOLUTION_BLOCKS into E+1 for bit credit
```

**Conflict resolution (2026-06-08):** `CHALLENGE_RESOLUTION_BLOCKS = 10_000` is the
**slash adjudication** window (T-A16 margin for onion latency). **Retention credit** for
epoch `E` requires response before **`H_close`** (end of `E`). After `H_close` without bit:
no `retention_bit`; slash may still fire during `E+1` grace if response never arrived.

This separates **liveness accounting** (epoch-close bit) from **bond enforcement** (longer
slash window). Wargame / stressnet may revisit; reopen via gate-2 amendment + timing cluster.

---

## 5. Wire — `txin_archival_retention_response`

New non-spending vin type (consensus). One vin per `(P_id, shard, E)` response.

### 5.1 Logical fields

```text
ArchivalRetentionResponse {
  p_canonical_id:           [u8; 32],
  shard_id:                 u64,
  settlement_epoch:         u64,          // E
  segment_subroot_rk:       [u8; 32],     // must match registry at H_anchor
  samples:                  [RetentionSample; m],

  // Binding (gate 6 / hybrid PQC)
  hybrid_signature:         HybridSignature,   // over domain-separated preimage
}
```

```text
RetentionSample {
  leaf_index_in_segment:    u32,          // must equal ℓ_j from §3.3
  leaf_bytes:               [u8; 128],    // set-B leaf; construct_leaf layout
  path:                     SegmentPathOpening,
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

### 5.2 Signature preimage

```text
sig_preimage = cSHAKE256(
  customization = "shekyl/archival-retention-response-v1",
  input         = p_canonical_id
                  || shard_id_le64
                  || settlement_epoch_le64
                  || segment_subroot_rk
                  || encode(samples)           // canonical sample serialization
)
```

Signer: `P`'s hybrid key from gate-6 §9 (`ArchivalPKeys.hybrid_sign_sk`). Verifier checks
against `ArchivalBondRecord.P_pubkey`.

### 5.3 Verifier order (consensus)

Fail-fast:

1. **Structural** — `samples.len() == m`; field bounds; duplicate `leaf_index` rejected.
2. **Bond posture** — record exists; `shard_id ∈ holdings`; `E ≥ E_join + 1`.
3. **Market** — `good_through(P,E)` at E-close (interval log).
4. **Challenge replay** — recompute each `ℓ_j` from `block_hash(H_anchor)` per §3.3;
   `leaf_index_in_segment == ℓ_j`.
5. **Geometry** — `segment_subroot_rk` matches shard registry at `H_anchor`.
6. **Path verify** — for each sample, `VerifyPath(leaf_bytes, path, R_k)` via
   `shekyl-fcmp::tree` (same primitives as wallet path assembly).
7. **Signature** — hybrid verify on §5.2 preimage.
8. **Deadline** — `current_height ≤ H_close` for retention credit (§4); else reject vin
   (slash path may still apply separately).
9. **Idempotency** — if bit already set, vin is no-op or reject duplicate (pin: **reject**
   duplicate to limit spam).

On accept (step 8 pass): `retention_bit(P_id, shard_id, E) := true`.

**Not verified:** spend authority on leaf; amount; output ownership.

---

## 6. Slash handoff (gate 4 consumer)

Gate 2 **does not** implement slash accounting. It emits a **verifiable failure** predicate:

```text
challenge_failed(P_id, shard, E) :=
  H_current > H_deadline
  ∧ ¬ retention_bit(P_id, shard, E)
  ∧ ArchivalBondRecord existed for P with shard in holdings at H_anchor
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

On disconnect of block `H` that **set** `retention_bit(P,s,E)`: clear bit.

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

## 11. Round 0 exit checklist

- [x] Statement + Merkle-opening shape (8c BUILD)
- [x] Challenge derivation (`cSHAKE`, `m`, anchor/deadline)
- [x] Response vin logical fields + verifier order
- [x] `P` signature binding
- [x] Slash predicate → gate 4
- [x] `pop_block` scope
- [ ] Byte-exact serialization (varint layout, layer encoding)
- [ ] KAT vectors (fixed segment + 3 samples)
- [ ] Verify-budget benchmark at projected depth
- [ ] Resolve §4 `H_deadline` vs `H_close` tension in stressnet (may amend)
- [ ] Reviewer sign-off Round 0 → Round 1 (cadence / off-chain payload)

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

- **2026-06-08:** Round 0 — challenge derivation, response vin, verifier order, slash handoff;
  §4 retention-credit vs slash-window split flagged for stressnet.
