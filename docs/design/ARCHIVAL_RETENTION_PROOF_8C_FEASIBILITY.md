# Archival retention proof (loud 8c) — constructibility pass

**Status:** **Feasibility pass — membership sub-problem closed; retention soundness OPEN
(2026-06-08, amended).** Merkle opening to frozen `R_k` is **constructible as a membership
witness** on public set-B leaves. It is **not yet shown** to be **storage-sound** (store vs
reacquire-on-demand) without an explicit reacquisition-asymmetry argument or a strengthened
challenge shape. Do **not** crystallize byte-exact wire / verifier crate until the hinge in
§7.5 is resolved.

**Inputs:** [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) §5 (test
surface after fossil purge); [`V3_STAKER_ARCHIVAL.md`](../V3_STAKER_ARCHIVAL.md) set B;
[`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §7.2; [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.1, §6.

**Out of scope here:** Byte-exact gate-2 serialization and verifier crate (see
[`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md)); wallet/daemon RPC for
challenge delivery. This pass answers: **can the statement be
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

**Soundness target (8c — two layers):**

1. **Membership (closed at this pass):** For negligible `ε`, no adversary without correct
   `(L_{ℓ_j}, path_j)` for challenged indices wins `VerifyPath` against `R_k`.
2. **Retention / possession (OPEN — §7.5):** No adversary without **set-B material for shard
   `s` held (or regenerable only at cost ≫ response window)** wins acceptance at scale.

The feasibility pass proved (1). Treating (1) as (2) is a **category error** when leaves are
public and recomputable from chain history.

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

**Gap (expected):** No gate-2 verifier crate or byte-exact wire yet; Round 0 logical spec in
[`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md). No `P`-bound response
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

**Conclusion:** Genesis 8c is **Merkle membership** over a **public** committed tree
segment — the easy half. Classic file PoR assumes **private** content where the opening
proves possession because the challenger cannot name the leaf without the prover's copy.
Here leaves are **public CT tuples** (`V3_STAKER_ARCHIVAL.md` set **B**; `construct_leaf`
inputs on chain). The research risk is **storage soundness** (reacquisition cost vs deadline),
not "does Merkle verify exist."

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

**Multi-sample `m` (threat-model pin):** `m` independent indices per `(P,s,E)` (provisional
`m = 3`) bounds **partial deletion** (stored most of segment, omitted a fraction). It does
**not** bound the **zero-storage + reacquire** adversary, who fetches exactly the `m` named
leaves (+ siblings) on demand — cost Θ(`m`), not Θ(`|segment|`). Raising `m` does not help
that adversary until reacquisition of one sample is expensive. **`m` is the wrong lever until
§7.5 closes.**

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

### 7.1 Membership layer (proved)

If `HashPath` is collision-resistant, an adversary without correct `(L_ℓ, siblings)` for
challenged `ℓ` cannot forge acceptance except with negligible probability in `|segment|`.

### 7.2 Partial-deletion sampling (conditional on storage)

If the adversary **stores** the segment and **deletes** a random fraction `f`, then one
uniform `ℓ` detects with probability ≈ `f`; `m` samples detect with probability ≈
`1 − (1−f)^m`. At `|segment| ≈ 26k`, `m = 3`, `f = 0.10` ⇒ P(catch) ≈ 27% per epoch.
This is the **only** threat model where provisional `m = 3` is meaningful.

### 7.3 Grinding (membership layer only)

Future-block `τ` prevents the prover from **choosing** `ℓ` after committing to a stored
subset. It does **not** prevent reacquiring the revealed `ℓ` after `H_anchor`.

### 7.4 Insufficient dismissals (rejected)

- **"Bond at stake"** — slash follows failed challenge; it does not make a **passing**
  forged response impossible.
- **"Lazy re-fetch from peers is orthogonal"** — if re-fetch is cheap, the challenge **is**
  the free-rider equilibrium (`STAKER_ARCHIVAL_SIM.md` L14 residue: *challenge-faking cost*).
- **"Verify is cheap"** — true and irrelevant; soundness rests on **generate/reacquire** cost
  vs deadline, not verify cost.

### 7.5 Reacquisition-asymmetry hinge (OPEN — load-bearing)

**Adversary (zero-storage):** At `H_anchor`, learn `(ℓ_0…ℓ_{m−1})`. Reacquire each
`L_{ℓ_j}` and path siblings; sign as `P`; submit before deadline. Passes membership verify
and `P` signature. Stored **zero** of set **B**.

**Why this is fatal unless closed:** Set-B leaves are `{O.x, I.x, C.x, h(pqc_pk)}` — public
on chain (`CURVE_TREE_CLIENT.md` §4.1, §7). Any party with chain history + drain replay (or
a bulk fetch from foundation / another archiver / set-C corpus) can build openings **without**
having retained the shard. Signature binds **who answered**, not **that P held B before the
challenge**.

**Order-of-magnitude costs (provisional level-2 segment, `E ≈ 26k` leaves):**

| Reacquisition path | Work / bytes | vs `CHALLENGE_RESOLUTION_BLOCKS` (10_000 ≈ 14 d @ 120 s) |
|--------------------|--------------|-----------------------------------------------------------|
| **On-wire opening only** | `m × (128 + depth×32)` ≈ **2–4 KiB** crypto material | Trivial |
| **Fetch `m` leaves + siblings from foundation peer** | KB + onion RTT (L16 worst case still ≪ 14 d) | Trivial |
| **Block-derived drain of full segment** | O(`E`) leaf reconstructions + auxiliary **C** for position range; ~**3.3 MiB** leaves alone | Feasible in grace window; not a retention proof |
| **Hold set B (design intent)** | Full segment + shard-local **C** auxiliary | What economics assumes |

**Verdict:** As stated, 8c proves **membership in the committed segment**, not **retention of
set B**. The hinge question:

> Is reacquisition of the challenged opening **materially more expensive** than holding the
> segment, relative to the **credit deadline** (must precede `H_close(E)` — gate-2 §4)?

If **no** → free-rider equilibrium; `R_market` counts reacquirers; L15 replica
**independence** fails (all replicas derivable from public chain + foundation); L14 cold-tail
challenges are forgeable by fetch-on-demand.

**Candidate closures (disposition TBD — gate-2 Round 1):**

| Direction | Idea | Tradeoff |
|-----------|------|----------|
| **A — Short credit window** | Bit credit only if response in `≪ SEB` blocks after `H_anchor` inside epoch `E` | Must not break onion path; may still allow KB fetch |
| **B — Bulk-range challenge** | Prove contiguous random sub-range of size `R ≫ m` (e.g. 256–1024 leaves), not `m` points | Larger on-chain verify budget; closer to "hold segment" |
| **C — L14-primary** | Explicit challenge only tops up unread tail; reward bit from **served retrieval credits** | Cold shards remain hard; couples gate 2 to gate 6 fetch |
| **D — PoRep / encoding** | Replica-specific encoding (Filecoin-class) | New primitive; likely ZK or heavy verify |
| **E — Asymmetric regeneration bound** | Prove segment rebuild from **C** alone exceeds deadline (quantitative) | Requires pinned segment size + drain benchmark; may fail |

Until one closure is chosen and bounded, **economics reopen** on storage-soundness grounds
(§9.1 criterion 4), not merely verify-budget grounds.

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
| **Membership witness constructible?** | **Yes** — Merkle opening to `R_k` on `shekyl-fcmp::tree` |
| **Retention sound (as stated)?** | **OPEN** — public leaves + reacquire path; §7.5 hinge |
| **New primitive needed?** | **Maybe** — depends on hinge closure (A–E); not ruled out |
| **ZK required at genesis?** | **No** for membership; **TBD** if hinge forces succinct proof of bulk hold |
| **Economics reopen?** | **Yes if hinge fails** — storage-soundness is the trigger, not verify budget |
| **Next deliverable** | Gate-2 Round 1: resolve §7.5 + fix challenge/epoch ordering (gate-2 §4); **then** bytes/KATs |

### 9.1 Reopening criteria (reversion clause)

Reopen **membership BUILD** only if hash-path verify fails substrate review.

Reopen **retention soundness** (default until §7.5 closes) when:

1. **Reacquisition asymmetry** — demonstrated cost to produce valid openings without set **B**
   is **not** ≫ credit deadline (benchmark + threat model). **This criterion is active.**
2. **Verify budget** — worst-case on-chain openings exceed block limit (after hinge shape
   chosen).
3. **Binding failure** — cannot bind response to `P_id` without breaking gate-6 firewall.
4. **Segment pin breaks** — `R_k` checkpoint model incompatible with growth.

Reopen **economics / reward leg** if (1) fails and no closure A–E restores storage-soundness
without breaking L14/L15 premises — full Form-C review, not a gate-2 patch.

---

## 10. Implementation path (ordered)

1. **Gate-2 Round 1** — close §7.5 hinge + fix epoch ordering ([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md)
   §4 amended); **hold** byte-exact wire until then.
2. **`shekyl-archival-retention` crate (proposed)** — verify-only membership replay; KATs
   **after** challenge shape frozen.
3. **Substrate reconciliation** — confirm `R_k` checkpoints in LMDB match §7.2 model;
   `pop_block` depth vs `ARCHIVAL_REORG_DEPTH_BLOCKS`.
4. **Integrate slash trigger** — gate 4 consumes gate-2 failure signal (already interface-pinned).

---

## 11. Related documents

| Doc | Relationship |
|-----|--------------|
| [`ARCHIVAL_CORPUS_FOSSIL_SWEEP.md`](ARCHIVAL_CORPUS_FOSSIL_SWEEP.md) | Pre-pass test surface |
| [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) | Gate-2 wire + verifier (Round 0) |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Reads `retention_bit`; §6 gate-2-internal |
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Slash on failed challenge |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumes bits for `work_P` |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | Segment / `R_k` authority |

---

## Changelog

- **2026-06-08:** Membership BUILD; retention hinge §7.5 OPEN (review amendment). Initial Merkle opening pass.
