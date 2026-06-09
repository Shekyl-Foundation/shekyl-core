# Archival retention proof (loud 8c) — constructibility pass

**Status:** **BUILD for on-demand serving obligation (2026-06-08, Round 1).** Merkle opening
to `R_k` + consensus verify + affirmative serve-credit is the correct statement for the
market layer ([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §0). Continuous
offline possession is **out of scope**; §7.5 reacquisition "hinge" retired as wrong statement.

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

**Loud 8c** is *serve-credit unforgeability*: an adversary who cannot produce a valid
opening when the epoch challenge fires must not earn `serve_credit_bit(P, s, E)` and thereby
inflate `work_P(E)` / `Σwork(E)`.

| | Old 8a | Loud 8c |
|---|--------|---------|
| Secret forged | Reward amount | Serve-credit / availability |
| Detection | Silent (bad) | Loud recompute (good) |
| Proof family | Confidential range / entitlement | On-demand opening + consensus verify |
| On-chain footprint | Hidden in RCT | `serve_credit_bit` + response vin |

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

**Effect:** Set `serve_credit_bit(P_id, s, E) := true` (gate-2 write; emission reads at
E-close).

**Soundness (8c — on-demand serving):** At challenge fire, no adversary produces a valid
`(L_ℓ, path, P_sig)` without being able to **serve** correct shard bytes for `ℓ` relative to
`R_k`. Continuous disk possession between challenges is **not claimed** (gate-2 §0).

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

### 7.5 Retired — "reacquisition hinge" (wrong statement)

Round 0 treated fetch-on-demand at test time as failure. **Round 1 (gate-2 §0):** that *is*
the service when tested — the paid good is **response to demand**, not 24/7 disk attestation.
Foundation owns durability; market owns reach + privacy + participation.

**PoRep** remains the priced path to **independent durable storage** (second domain); not
genesis. **Traffic-proportional pay** for organic retrieval volume is a named reopen (gate-2
§0.3) — self-dealing via Sybil requesters.

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
| **On-demand serve-credit constructible?** | **Yes** — opening + verify + affirmative bit (gate-2 §0) |
| **Continuous storage provable cheaply?** | **No** — not the market claim; PoRep if ever needed |
| **New primitive at genesis?** | **No** — consensus/hash/convergence |
| **ZK at genesis?** | **No** |
| **Economics reopen?** | **Only** traffic-proportional pay (§0.3 reopen) or PoRep durability fork |
| **Next deliverable** | Byte-exact wire + verifier crate + field rename sweep |

### 9.1 Reopening criteria (reversion clause)

Reopen **BUILD** if hash-path verify fails substrate review or verify budget exceeds block
limit.

Reopen **economics** for: (a) **traffic-proportional pay** (gate-2 §0.3), (b) **PoRep
independent storage** fork, (c) binding failure at gate-6 firewall.

---

## 10. Implementation path (ordered)

1. **Gate-2 Round 1** — [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §0 obligation pinned.
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
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | Reads `serve_credit_bit`; §6 gate-2-internal |
| [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) | Slash on failed challenge |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumes bits for `work_P` |
| [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) | Segment / `R_k` authority |

---

## Changelog

- **2026-06-08:** Round 1 — on-demand serving BUILD; §7.5 hinge retired.
- **2026-06-08:** Membership layer; initial Merkle opening pass.
