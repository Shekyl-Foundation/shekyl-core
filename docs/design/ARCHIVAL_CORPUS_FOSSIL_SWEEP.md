# Archival corpus fossil sweep (2026-06-08)

**Purpose:** Before the **8c retention-proof constructibility** pass, enumerate doc claims
that still assume **superseded models** so feasibility work tests the **current** design,
not ghosts from confidential staking, bundled emission, or pre-F1 timing rationale.

**Method:** Grep for dissolved entities + manual read of rationale clauses in the
archival SSOT web (`ARCHIVAL_TIMING_CONSTANTS`, gate 4/6, emission leg, consensus state,
PHASE_2B trilogy, `V3_STAKER_ARCHIVAL`, F1 wargame). Classify each hit:

| Class | Meaning |
|-------|---------|
| **FOSSIL** | Stale rationale — implementer could act on it; **fix in this sweep** |
| **RECORD** | Correct historical dissolution / rejection table — keep |
| **STRATUM** | Large superseded body retained for audit trail — **do not implement from**; read `PHASE_2B_FSM_RETOOL` + emission leg instead |
| **OPEN** | Intentionally unresolved — 8c or gate-6 rounds own it |

**Dissolved models (search targets):**

`N_arch`, `ν`, confidential staking / 3C subtree, `N_S = x·G_S`, bundled first-emission
bond, `REORG_HORIZON` (→ retention vs reorg split), SEB-as-F1-lever, lapse-as-decorrelation,
relative-u16 `EpochSet` on wallet, output-keyed `StakeId`, tier_num claim wire,
Reserve-DLEQ entitlement.

---

## 1. FOSSIL — fixed in this sweep

| Location | Stale claim | Correct disposition |
|----------|-------------|---------------------|
| `PHASE_2B_SECTION7_DRAFT.md` §7 | "SEB is the structural F1 lever"; SEB reconsideration branch | SEB pinned; **not** F1 lever (`ta1_f1_seb_coarse`); portfolio axis is structural — see `ARCHIVAL_TIMING_CONSTANTS.md` §1.2 |
| `PHASE_2B_FSM_RETOOL.md` checklist | "SEB structural lever" open | Closed — T-A1 v2 + timing pin |
| `ARCHIVAL_FIREWALL_GATE6.md` §2.3, §3 table | `W` = "forfeiture vs decorrelation"; lapse > `W` = "acceptable decorrelation cost" | `W` = forfeiture/state bound only; lapse **without portfolio change does not decorrelate** (F1 T-A1) |
| `V3_STAKER_ARCHIVAL.md` challenge interval | `MAX_CLAIM_AGE_W` trades state vs "gate-6 decorrelation" | State growth vs **forfeiture economics** |
| `ARCHIVAL_CONSENSUS_STATE.md` §9.2 | "Defer numeric pin" on SEB; lapse headroom vs decorrelation trade | SEB **pinned** 10_000; joint gate-2/gate-6 note is **cadence/fingerprint resolution**, not SEB vote |

---

## 2. FOSSIL — remaining (fix before implementation cut)

| Location | Stale claim | Action |
|----------|-------------|--------|
| `ARCHIVAL_FIREWALL_GATE6.md` §3 rotation row | "Decorrelate timeline + shard-set adjacency" | Rewrite: portfolio leg primary; timeline channel empty at lean eq (T-A1) |
| `ARCHIVAL_CONSENSUS_STATE.md` §2 honest residual | "Rotation (gate 6) is the named decorrelation tool" | Qualify: **portfolio-changing** rotation only; cosmetic `P_id` swap insufficient |
| `PHASE_2B_SECTION7_DRAFT.md` T-A14 | "Lapse past `W` for decorrelation" | Reframe: forfeiture vs income UI; **not** a decorrelation tool |
| `ARCHIVAL_FIREWALL_GATE6.md` §9.8 checklist | "Pin epoch-length jointly with gate-6 decorrelation" | SEB pinned; remaining = jitter/drain defaults (Round 3–4) |
| `PHASE_2B_STAKE_LIFECYCLE.md` §3–§8 body | Live `G_S`, `N_S`, `EpochSet` u16, stake-claim nullifier reorg paths | **STRATUM** — see §4 below; do not implement wallet from this file without `PHASE_2B_FSM_RETOOL.md` |

---

## 3. RECORD — correct as-is (not fossils)

These mention dissolved primitives **to reject** them:

- `REWARD_EMISSION_LEG.md` — no `N_arch` / `N_S` table; join-Market before paying emission
- `ARCHIVAL_CONSENSUS_STATE.md` §2 — gate-3 ν dissolution
- `ARCHIVAL_BOND_GATE4.md` §3.1 — rejects zero-mint emission as join vehicle
- `PHASE_2B_FSM_RETOOL.md` — join-Market seam; deletes `StakeId`; `ClaimedEpochSet` on bond record
- `ARCHIVAL_TIMING_CONSTANTS.md` — `REORG_HORIZON` deleted; retention/reorg split; `W` forfeiture rationale
- `F1_TA3_TA7_LIFETIME_WINDOW.md` — rotation without storage change does not decorrelate
- `STAKER_ARCHIVAL_SIM.md` — "SEB is not the F1 lever" (empirical)

---

## 4. STRATUM — implementation-dangerous historical body

**`PHASE_2B_STAKE_LIFECYCLE.md`** (~1.9k lines) interleaves:

1. **Current** archival rebasing (§7 threat model, emission leg pointers, join-Market)
2. **Retired** confidential-staking wallet design (§3.3 `EpochSet`, §4.7 `x·G_S` reorg,
   §8.5 `G_S` KAT, Round-2 table row with u16 bitmask / stake-claim nullifier set)

The §7 retool and `PHASE_2B_FSM_RETOOL.md` supersede (2) for genesis. An implementer
grep-hitting §5.2 or §8.5 without the retool doc will build the **wrong wallet**.

**Disposition:** Treat §3–§6 pre-retool wallet protocol as **archived stratum** until a
dedicated deletion pass lands (per `15-deletion-and-debt.mdc`). Implementation authority:
`PHASE_2B_FSM_RETOOL.md` → `REWARD_EMISSION_LEG.md` → `ARCHIVAL_BOND_GATE4.md`.

---

## 5. What 8c must test (clean statement after sweep)

Strip fossils; these are the **load-bearing 8c assumptions** the constructibility pass
must confirm or refute.

### 5.1 Statement shape (from `V3_STAKER_ARCHIVAL.md` set B + consensus contract)

**Challenge:** Sample shard `s`, settlement epoch `E`, archiver `P`. Verifier checks
**proof-of-retrievability** that `P` holds deep archival material sufficient to build an
**FCMP++ historical reference proof** — Merkle path from a challenged leaf position to
shard root `R_k` — using **set B** (segment leaves + per-shard canonical auxiliary in
the shard's height range).

**On pass:** Set `serve_credit_bit(P, s, E)` in consensus serve-credit ledger
(`ARCHIVAL_CONSENSUS_STATE.md` §3.1). Challenge metadata (leaf index, block hash) stays
gate-2-internal.

**On fail (within grace):** Slash path via gate 4 (bond forfeiture); does not retroactively
void honest prior epochs (`good_through`).

### 5.2 Soundness property (loud 8c)

**Unforgeability:** No PPT adversary without set-B material for `(s, E)` can produce a
verifier-accepting serve-credit proof that sets `serve_credit_bit(P,s,E)`.

**Not** the old confidential 8a (hidden reward amount). Inflation detection is **loud
recompute** of emission amounts from public `Σwork` / bond state; 8c guards **work credit**
fraud (claiming retention/service without storage).

### 5.3 Crypto substrate constraints (constructibility checklist)

| Constraint | Source | 8c pass must address |
|------------|--------|----------------------|
| Curve-tree shard roots `R_k` | FCMP++ / `CURVE_TREE_CLIENT.md` | Path relation the proof attests |
| PQC hybrid leaves | Shekyl genesis tx type | Leaf format in path / witness |
| Random leaf / future-block-hash challenge | Gate 2 (interface) | Prover cannot grind challenge after seeing leaf |
| L14 retrieval-as-proof | `V3_STAKER_ARCHIVAL.md` | On-chain bit is primary liveness signal; proof may be off-chain with on-chain commit |
| Per-`(P,s,E)` granularity | Emission `work_P(E)` | Cannot coarsen without breaking `R_market` / Σwork |
| State cost bounded | `W`, retention horizon | Proof verification cost × ledger size must be viable at full history |

### 5.4 Explicit non-requirements (fossils removed)

8c **does not** need to:

- Hide `ν` or per-`P` counts (ν dissolved; public `P_id` ledger)
- Prove confidential reward amounts (loud emission)
- Support stake-claim nullifiers `N_S = x·G_S` (deleted)
- Enable 19-month-deep `pop_block` revert (`ARCHIVAL_REORG_DEPTH_BLOCKS` = 720)
- Make lapse > `W` decorrelate identities (forfeiture only)

### 5.5 Constructibility pass — **complete**

[`ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md):
**BUILD** — Merkle opening PoR to frozen `R_k` (not FCMP++ membership, not ZK at genesis).
Gate-2 Round 0: [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md); verifier crate + KATs next.

---

## 6. Cross-ref hygiene

After this sweep, SSOT chain for timing:

`ARCHIVAL_TIMING_CONSTANTS.md` → consumers (gate 4, consensus state, emission, gate 6,
sim, P2B-5). No consumer should re-derive `prune_horizon = max(W, REORG/SEB)`.

---

## Changelog

- **2026-06-08:** Initial sweep; five active-rationale fossils fixed; 8c test surface §5.
