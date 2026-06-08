# Archival retention proof — gate 2 (challenge + loud 8c wire)

**Status:** **Round 0 draft (2026-06-08) — membership wire sketched; retention soundness
OPEN.** Byte-exact serialization, verifier crate, and KATs are **held** until
[`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md) §7.5
(reacquisition-asymmetry hinge) closes. Membership layer: constructible; retention layer: not
settled.

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

**Loud 8c (target):** Forging acceptance without set-B material is infeasible. **Round 0
gap:** Merkle opening + `P` signature proves **membership + responder identity**, not
**prior retention** — see feasibility §7.5. Round 1 must close the hinge before this
statement is load-bearing.

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
| `CHALLENGE_ANCHOR_LEAD_BLOCKS` | **TBD (Round 1)** | Blocks before `H_close(E)` at which `H_anchor` falls **inside** `E` |
| `CHALLENGE_CREDIT_MAX_BLOCKS` | **TBD (Round 1)** | Max blocks after `H_anchor` for `retention_bit` credit; must satisfy §4 ordering |

`m = 3` mitigates partial-storage free-riding (~1/26k per sample → ~1/26k³ joint miss mass
at level-2 segment scale; 8c feasibility §7).

### 3.2 Anchor height (Round 0 bug — ordering unresolved)

```text
E        = settlement epoch under test
H_open   = first block with settlement_epoch(height) == E
H_close  = last block with settlement_epoch(height) == E
H_anchor = H_close − CHALLENGE_ANCHOR_LEAD_BLOCKS     // MUST satisfy H_open < H_anchor ≤ H_close
H_credit_deadline = H_close                            // emission reads bit at E-close (invariant 2)
H_slash_deadline  = H_close + CHALLENGE_RESOLUTION_BLOCKS
```

**Round 0 error (do not implement):** `H_anchor = H_close + 1` (first block of `E+1`) is
**incompatible** with `retention_bit(P,s,E)` finalized at `H_close(E)` — the challenge would
issue after the emission read. This is a **consensus ordering** defect, not a latency margin
question; stressnet cannot fix it.

**Unpredictability:** `H_anchor` must be a block **inside epoch `E`** whose hash was unknown
when the archiver committed to serve `E` (future-within-`E` beacon). `CHALLENGE_ANCHOR_LEAD`
pins how late in `E` the anchor falls; Round 1 must derive it jointly with §7.5 credit window.

**Grindable beacon (secondary):** Single `block_hash(H_anchor)` lets the miner of `H_anchor`
bias `ℓ_j` toward cheap-to-reacquire leaves. Mitigations: multi-block commit-reveal anchor,
or `m` hashes from distinct heights in `E`. Moot until §7.5 closes; still note for Round 1.

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

After `H_anchor` (within `E`), for each `P_id` with `ArchivalBondRecord` where:

- `shard_id ∈ holdings` at `H_anchor`, and
- `P ∈ Market` for settlement epoch `E` (evaluated at E-close snapshot),

consensus expects a valid response by `H_credit_deadline` for bit credit, and by
`H_slash_deadline` for slash adjudication if no bit (§6).

**Foundation `CompleteTree`:** same challenge path on **B**; slash semantics differ (gate 4
§4.2 whole-bond). Retention bit still written for emission exclusion rules (E-2).

---

## 4. Response window and retention bit timing (consensus ordering — pin in Round 1)

```text
Timeline (single settlement epoch E):

  H_open ─── … ─── H_anchor ─── … ─── H_close ─── … ─── H_slash_deadline ───►
                    (indices known)     (emission    (slash if no bit;
                                         reads bit)    not for credit)
```

| Event | Height constraint | Consensus action |
|-------|-------------------|------------------|
| Challenge materialized | `H_anchor` ∈ `(H_open, H_close]` | Derive `(ℓ_j, R_k)`; deliver to `P` (gate 6) |
| Valid response — **credit** | `H_anchor < height ≤ H_credit_deadline = H_close` | Set `retention_bit(P_id,s,E)` |
| Emission accounting | `height = H_close` | Read finalized bit (invariant 2); no retroactive set |
| Slash adjudication | `height > H_slash_deadline = H_close + CHALLENGE_RESOLUTION_BLOCKS` | `challenge_failed` → gate-4 slash |

**Determinacy (not empirical):** `H_credit_deadline = H_close` and `H_slash_deadline`
post-close are **orthogonal roles**. Stressnet measures onion RTT against
`CHALLENGE_CREDIT_MAX_BLOCKS` (Round 1 pin, likely `≪ SEB`), not whether credit precedes
emission read — that ordering is **spec logic**.

**Storage-soundness (feasibility §7.5):** Even with correct ordering, point-sample Merkle
openings do not prove set-B retention unless reacquisition within
`H_anchor…H_credit_deadline` is prohibitively expensive. Round 1 chooses hinge closure
(bulk-range challenge, L14-primary credit, short credit window, etc.) **before** wire freeze.

**One bit per `(P_id, shard, E)`:** All `m` openings must verify atomically in one accept.
**`m = 3`:** Partial-deletion defense only; not zero-storage reacquire (feasibility §4).

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
8. **Credit deadline** — `current_height ≤ H_credit_deadline` (§4); else reject for bit
   (slash path separate per `H_slash_deadline`).
9. **Idempotency** — if bit already set, vin is no-op or reject duplicate (pin: **reject**
   duplicate to limit spam).

On accept (step 8 pass): `retention_bit(P_id, shard_id, E) := true`.

**Not verified:** spend authority on leaf; amount; output ownership.

---

## 6. Slash handoff (gate 4 consumer)

Gate 2 **does not** implement slash accounting. It emits a **verifiable failure** predicate:

```text
challenge_failed(P_id, shard, E) :=
  H_current > H_slash_deadline
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

## 11. Round 0 / Round 1 checklist

**Round 0 (draft — partial):**

- [x] Membership statement + Merkle-opening shape
- [x] Challenge derivation sketch (`cSHAKE`, `m`)
- [x] Response vin logical fields + verifier order (membership layer)
- [x] `P` signature binding (identity, not storage)
- [x] Slash predicate → gate 4 (height naming fixed §4)
- [x] `pop_block` scope
- [x] **Named** retention-soundness gap (feasibility §7.5)

**Round 1 (blocking before bytes/KATs):**

- [ ] Close reacquisition-asymmetry hinge (feasibility §7.5 A–E)
- [ ] Pin `CHALLENGE_ANCHOR_LEAD` + `CHALLENGE_CREDIT_MAX` inside epoch `E`
- [ ] Beacon grinding mitigation (if still point-sample)
- [ ] Byte-exact serialization
- [ ] KAT vectors
- [ ] Verify-budget benchmark at **chosen** challenge shape

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

- **2026-06-08:** Round 0 draft — membership wire sketched; §7.5 hinge + §4 ordering fix
  (review amendment).
