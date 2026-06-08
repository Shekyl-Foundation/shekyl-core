# Archival retention proof (loud 8c) — constructibility pass

**Status:** **Feasibility pass complete (2026-06-08).** Disposition: **BUILD** (Merkle-opening
retention proof, shard-local to `R_k`). Not a ZK primitive at genesis; not a reopen of reward
economics unless verification-cost or binding barriers fail at gate-2 spec review.

**Inputs:** [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) §5 (test
surface after fossil purge); [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) set B;
[`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2; [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.1, §6.

**Out of scope here:** Gate-2 wire bytes, challenge cadence pin, wallet/daemon RPC for
challenge delivery (separate gate-2 design doc). This pass answers: **can the statement be
built soundly at all?**

---

## 1. What loud 8c is (and is not)

### 1.1 Migration from confidential 8a

Pre-rebasing **8a** was *confidential reward soundness* — a hidden entitlement amount an
adversary might inflate undetectably. Pay-for-service rebasing makes emission **loud**:
verifiers recompute `reward_P(E)` from public `Σwork`, `R_market`, and bond state
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §4).

**Loud 8c** is *retention-proof unforgeability*: an adversary without set-B material for
shard `s` must not be able to set `retention_bit(P, s, E)` and thereby inflate
`work_P(E)` / `Σwork(E)`.

| | Old 8a | Loud 8c |
|---|--------|---------|
| Secret forged | Reward amount | Storage / retention |
| Detection | Silent (bad) | Loud recompute (good) |
| Proof family | Confidential range / entitlement | Proof-of-retrievability (PoR) |
| On-chain footprint | Hidden in RCT | Public ledger bit + optional opening |

### 1.2 Formal statement (genesis target)

**Parameters:** settlement epoch `E`, shard `s` with frozen sub-root `R_k`, archiver
public id `P_id`, challenge seed `τ` (unpredictable at challenge issue — §4).

**Prover (holder of set B for shard `s`):** Given leaf position `ℓ` derived from `τ` within
segment `k` (= shard `s`), produce opening `π` consisting of:

- the 128-byte curve-tree leaf `L_ℓ` at position `ℓ` (set B), and
- the sibling path of Selene/Helios layer digests from `L_ℓ` to sub-root `R_k`.

**Verifier (consensus / challenger):**

1. Recompute `root' = HashPath(L_ℓ, π)` using `shekyl-fcmp::tree` grow rules.
2. Accept iff `root' = R_k` and `R_k` matches the checkpointed sub-root for `(s, E)` (header
   chain / segment registry).
3. Accept iff response is bound to `P_id` (§5) and within grace (gate 4).

**Effect:** Set `retention_bit(P_id, s, E) := true` (gate-2 write; emission reads at
E-close).

**Soundness (8c):** For negligible `ε`, no PPT adversary without set-B bytes for shard `s`
wins acceptance with probability > `ε` over random `τ`, except with negligible probability
over the hash.

---

## 2. Substrate inventory (what already exists)

| Asset | Location | 8c relevance |
|-------|----------|--------------|
| 128-byte leaf format (`O.x`, `I.x`, `C.x`, `h_pqc`) | `shekyl-fcmp::tree::construct_leaf` | Opening includes exact leaf bytes challenged |
| Layer hash grow/trim | `shekyl-fcmp::tree` | Verifier replay path to `R_k` |
| Frozen sub-root `R_k` per segment | `CURVE_TREE_CLIENT.md` §7.2 | **Shard-local** challenge — rejects whole-tree-root fork |
| Segment = subtree-aligned position range | §7.2.2 | Challenge position `ℓ ∈ [k·E, (k+1)·E)` |
| LMDB `curve_tree_leaves` + checkpoints | C++ daemon (landed) | Set-B source material |
| Wallet path assembly (owned output) | `shekyl-curve-tree` (in progress) | **Same math**, different leaf index (random, not owned) |
| Retention ledger interface | `ARCHIVAL_CONSENSUS_STATE.md` §3.1 | Output bit only — construction deferred |

**Gap (expected):** No gate-2 verifier crate, no challenge wire, no `P`-bound response
envelope. These are **engineering**, not unknown cryptography.

---

## 3. Prior art map

| Family | Fit | Notes |
|--------|-----|-------|
| **Merkle PoR** (classic file PoR) | **Primary** | Random index + Merkle opening to committed root — exact shape after `R_k` pin |
| **PDP / PoST** (provable data possession) | Adjacent | Overkill for public CT leaves; ZK variants unnecessary if openings are public |
| **FCMP++ membership proof** | **Wrong tool** | Proves spend authority at a leaf; 8c proves **possession of historical leaf bytes**, not spend |
| **Verifiable storage (Filecoin, etc.)** | Analogous economics | Replication market + challenge; Shekyl uses bond slash instead of collateral token |
| **BitTorrent infohash | `R_k` | Content-addressed segment fetch — integrity, not substitute for per-epoch challenge |

**Conclusion:** Genesis 8c is **standard Merkle PoR** over a **public** committed tree
segment, not a new ZK relation. The research risk is **not** "does PoR exist" but
**binding, sampling rate, and verify cost at chain scale**.

---

## 4. Challenge generation (unpredictability)

[`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) §"Challenge unpredictability": challenged
leaf must not be grindable from pre-stored subset.

**Pinned pattern (BUILD):**

```text
τ = H( block_hash[H_challenge] ‖ P_id ‖ s ‖ E ‖ domain_sep )
ℓ = τ mod |segment_k|   // position within shard's leaf range
```

- `H_challenge` is at or after challenge issue height; leaf index unknown before that block
  exists (future-block-hash style).
- Domain separation: `cSHAKE256("shekyl/archival-retention-challenge-v1", …)` (exact bytes at
  gate-2 spec).

**Mitigation if single-sample weak:** Require `m` independent indices per `(P,s,E)` (e.g.
`m = 3`) drawn from distinct future hashes in the settlement epoch window; bit set only if
all pass. Cost: `m × verify_path`; still O(depth) per sample, no ZK.

**Rejection:** Whole-tree-root challenges (concept doc legacy §"Verification") — superseded
by `R_k`-local challenges per [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2.1.

---

## 5. Binding proof to `P` (Sybil vs retention)

PoR alone proves **someone** has bytes; gate-2 must prove **`P` who claims shard `s`**
responded.

**BUILD disposition (layered):**

1. **Reachability layer (gate 6):** Challenges delivered to `P`'s onion rendezvous; response
   signed with `P`'s hybrid archival keys (gate-6 Round 1 HKDF material).
2. **Consensus layer:** Response submitted in gate-2 vin or challenge-response tx that names
   `P_id` and references active bond record for shard `s`.
3. **Slash layer (gate 4):** Failure to respond within `CHALLENGE_RESOLUTION_BLOCKS` triggers
   slash; T-A16 margin satisfied by 10_000-block window vs release cooldown 20_000 blocks
   ([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)).

**Not required:** Proof that leaf `L_ℓ` is spendable by `P` — set B leaves are public CT
data; retention is possession, not ownership.

---

## 6. Candidate constructions

### 6.1 Recommended — explicit Merkle opening (BUILD)

**Prover sends:** `(ℓ, L_ℓ, siblings[], layer_metadata)` — size O(tree depth) × 32-byte
digests + 128-byte leaf.

**Verifier:** Replay `hash_grow` / `hash_trim` per `shekyl-fcmp::tree`; compare to `R_k`.

**Why not ZK at genesis:**

- Set-B leaves are **public** on chain (curve_tree_leaves LMDB); opening does not leak more
  than already committed.
- V3 explicitly assumes path verify is **cheap on-chain** (hash chain, not pairing-heavy FCMP).
- ZK would add prover complexity and audit surface without privacy gain on public leaves.

**PQC note:** `h_pqc` is part of the 128-byte leaf; path verify is agnostic to PQC — no
lattice proof inside 8c.

### 6.2 Deferred — succinct ZK PoR

**Reopen criterion:** Block-size budget cannot fit O(depth) opening at projected mainnet depth
+ segment count, **after** batching challenges off-chain with on-chain commitment only.

**Disposition:** Defer. Measure at gate-2 spec with concrete depth from `FCMP` checkpoint
table (~level-2 segment ≈ 26k leaves per §7.2.2).

### 6.3 Rejected — FCMP++ membership as retention proof

Membership proves spend authority relative to **current** tree root for **owned** outputs.
Retention must prove **historical leaf at ℓ** relative to **frozen `R_k`**. Different root,
different witness, different soundness story. **Do not conflate.**

---

## 7. Soundness sketch

**Theorem target (informal):** If `HashPath` is collision-resistant on the grow/trim
domain, adversary without `L_ℓ` and correct siblings for challenged `ℓ` cannot forge
acceptance except with negligible probability in `|segment|`.

**Partial storage:** Single random `ℓ` per epoch detects fraction `1/|segment|` missing mass
in expectation. For segment size ≈ 26k leaves, one sample per epoch is weak against
holding 99% and omitting 1% — **mitigate with small `m`** (§4) or epoch-cumulative
sampling (challenge cadence > 1 per E).

**Free-rider on peers:** PoR proves local possession at challenge time; lazy re-fetch from
peers may pass one sample if peer serves fast enough. V3 routes **retrieval latency** to
query routing, not reward — orthogonal to 8c. Economic deterrence: bond at stake per shard.

**Grinding:** Future-block `τ` prevents choosing `ℓ` after seeing which leaf is stored.

---

## 8. Verification cost and state growth

**Per challenge verify:** O(tree depth) hashes — same order as wallet path verify; depth
from checkpoint (typically modest vs segment width).

**State (consensus):** Per `(P_id, shard, E)` bit + derived `R_market` — bounded by
`W = 26` prune horizon ([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)).
Not 8c-specific; already accepted in archival economics.

**Irony (named, bounded):** Loud reward accounting reads replicated retention state; cost is
the product of design, not a surprise. 8c does not worsen it — it **replaces** silent ZK
entitlement with detectable work fraud.

**Load test gate:** Gate-2 spec must include worst-case openings per block at max
archivers × `m` samples; reject ZK deferral path only if measurement passes.

---

## 9. Disposition

| Question | Answer |
|----------|--------|
| **Constructible?** | **Yes** — Merkle PoR to `R_k` on existing `shekyl-fcmp::tree` primitives |
| **New primitive needed?** | **No** — composition of landed hash-path + segment pin |
| **ZK required at genesis?** | **No** — public leaves; hash-path verify |
| **Economics reopen?** | **No** — failure would be verify-cost or sampling, not Σwork shape |
| **Next deliverable** | Gate-2 spec: wire format, `m`, cadence, response tx, verifier crate |

### 9.1 Reopening criteria (reversion clause)

Reopen **BUILD** disposition only if:

1. **Verify budget** — worst-case on-chain openings exceed block limit at projected depth +
   archiver count (evidence: benchmark + gate-2 spec review).
2. **Binding failure** — cannot bind response to `P_id` without breaking gate-6 firewall
   (threat-model review amendment).
3. **Segment pin breaks** — subtree-aligned `R_k` cannot be checkpointed compatibly with
   mainnet growth (substrate reconciliation failure).

Reopen **economics / reward leg** only if (1) forces ZK PoR that cannot meet verifier
budget **and** no off-chain challenge with on-chain commit is acceptable — full Form-C style
review, not a gate-2 patch.

---

## 10. Implementation path (ordered)

1. **Gate-2 design doc** — challenge/response wire, verifier API, `m` and cadence (owns
   construction bytes deferred in consensus contract §6).
2. **`shekyl-archival-retention` crate (proposed)** — verify-only path replay; KAT vectors
   from `shekyl-fcmp::tree` + fixed segment fixture.
3. **Substrate reconciliation** — confirm `R_k` checkpoints in LMDB match §7.2 model;
   `pop_block` depth vs `ARCHIVAL_REORG_DEPTH_BLOCKS`.
4. **Integrate slash trigger** — gate 4 consumes gate-2 failure signal (already interface-pinned).

---

## 11. Related documents

| Doc | Relationship |
|-----|--------------|
| [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) | Pre-pass test surface |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Reads `retention_bit`; §6 gate-2-internal |
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Slash on failed challenge |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumes bits for `work_P` |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | Segment / `R_k` authority |

---

## Changelog

- **2026-06-08:** Initial constructibility pass — BUILD (Merkle opening to `R_k`).
