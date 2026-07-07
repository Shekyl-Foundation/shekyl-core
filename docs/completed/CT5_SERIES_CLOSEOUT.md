# CT-5 — series closeout: the FCMP++ spend path is real and daemon-validated

**Status:** **COMPLETE, 2026-06-27.** The CT-5 series (5a–5d) shipped, and its last
open validation gate — the **depth-3+ real-tree FCMP++ verify** (the #162 reopening
trigger) — is now resolved and validated end-to-end against a locally-built daemon
(PR #197). What remains is a set of **named rule-21 deferrals** (§4), not unfinished
CT-5 work.

**Mission framing.** CT-5 retired the last cryptographic placeholder on the spend
path: a wallet now builds an FCMP++ membership proof against the **real** curve-tree
path the daemon verifies, and the daemon **accepts** it over a real chain. FCMP++
membership is the privacy mechanism (mission #2 — privacy is the product), so "the
wallet can actually spend on a real chain, at any tree depth it reaches" is the
precondition this series established.

---

## 1. The arc

| Slice | Deliverable | Record |
| --- | --- | --- |
| **CT-5a/b** | `CurveTreeActor` + block→tree ingest; **verify-at-ingest** vs the header root; reference-block selection + the C2 spendability gate | [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md), [`CT5_ROUND1_CLOSEOUT.md`](CT5_ROUND1_CLOSEOUT.md) (PR #149) |
| **CT-5c** | **Assembler cutover** — real `assemble_path` into the 2A signer; retired the synthetic membership vectors | [`CT5C_ASSEMBLER_CUTOVER.md`](CT5C_ASSEMBLER_CUTOVER.md) |
| **CT-5d** | The **reprove re-anchor** (content-preserving: same inputs, fresh reference, re-assemble + re-sign) + the clean-fail fallback | [`CT5D_REANCHOR.md`](CT5D_REANCHOR.md) |
| **#162** | Partial (narrow) branch-chunk padding so a **depth-2** real-tree proof verifies | depth-2 RESOLVED 2026-06-19 |
| **Track 2** | The keystone: the **first daemon-accepted FCMP++ spend** over the real RPC transport (depth-2) | PR #193 (north-star); unblocked the Tier-B fixture |
| **#197** | The **depth-3+** gate: the daemon's `grow`/`trim` curve-tree producers recompose narrow (`== build_layers`), so a wallet syncs **and spends** over a depth-3 tree | RESOLVED + validated 2026-06-27 |

## 2. What "complete" means here

Both halves of the verify surface are proven against a live daemon, at depth-2 **and**
depth-3:

- **Ingest / reconstruct parity** — the wallet's `build_layers` reconstruction equals
  the daemon's per-height header root at every height: depth-2 (`recon_kat`,
  `recon_tier_b`) and depth-3 (the wallet `refresh` succeeds over a real depth-3 tree).
- **Submit / verify parity** — a wallet-built proof, serialized into a tx and sent over
  the wire, is **accepted by the daemon's consensus `shekyl_fcmp_verify`**: depth-2
  (the Track-2 keystone) and depth-3 (`e2e_fcmp_spend_over_depth3_tree`).

The depth-3+ case was the open risk (#162's reopening trigger): it required the daemon
and the wallet to agree on the root at the **first Selene branch layer**, and they did
not — the daemon's in-place incremental upper-layer propagation dropped the
pre-existing sibling at a *deepen*. PR #197 fixed the **producer** (rule 16 /
#162-retraction discipline — conforming `build_layers` to the daemon would have frozen
a consensus defect at genesis), for **both** `grow` and `trim`. See
[`DEPTH3_CURVE_TREE_CUTOVER.md`](DEPTH3_CURVE_TREE_CUTOVER.md).

## 3. Validation surface (the gates that prove §2)

- `e2e_fcmp_spend_over_depth3_tree` — wallet `refresh` + **daemon-accepted spend** over
  a real depth-3 tree (701 leaves, daemon depth 2).
- `e2e_trim_curve_tree_restores_grow_root` — the reorg twin: `trim == grow⁻¹` across a
  Selene leaf-chunk-boundary `pop_blocks`.
- the **Track-2 keystone** — daemon-accepted depth-2 spend over the real transport.
- `recon_kat` (6/6) + `recon_tier_b` (3/5) — reconstruct parity over the depth-2
  fixtures, unchanged against the fixed code.
- `curve_tree_freeze` — the daemon-replica freeze tests (the drop-the-sibling
  divergence reproduced, the corrected recompose telescoped to `build_layers`).

## 4. Named deferrals (rule-21 — deferred-by-design, not CT-5 gaps)

Tracked with reopening triggers in `FOLLOWUPS.md`; none blocks the completion claim:

- **CT-5c per-input reconstruction reuse** (perf) — reopen on a measured send-latency
  budget (no speculative perf ahead of its trigger).
- **CT-5c X3 output-class numbering re-verification** — a *standing* precondition for
  any future PR that adds an output class to the curve tree.
- **CT-5d reselect — content-changing re-anchor** (lock-transplant) — V3.1+; the
  clean-fail fallback is genesis-safe.
- **CT-5d background opportunistic re-anchor** + the eager reorg mark — V3.1+,
  measurement-gated (the lazy submit-centric slice is authoritative now).
- **CT-2 Tier-B, 2 of 5** — `staked_output_uses_max_lock_and_spendable` (awaits the
  engine staking *send* path, built separately) and
  `scanner_extra_0x07_matches_daemon_on_adversarial_extra` (awaits a hand-crafted C++
  duplicate/malformed-`0x07` oracle). A CT-2 item ordered after CT-5, not CT-5 core.

## 5. What CT-5 unblocks

The spend path is now real and daemon-validated at every tree depth a real chain
reaches. Downstream, this is the precondition for **2d-2 bond-post broadcast** (a
bond-post *is* an FCMP++ spend, which over a live chain runs against a depth-3+ tree).
**2d-1** (the read-side `P`-scan) is independent — it needs none of the curve-tree
spend path — and is worked separately.

**References.** PRs #149 (5a/b), #162 (depth-2 padding), #193 (Track-2 keystone),
#197 (depth-3 producer fix) + #198 (this closeout + the cutover note);
[`DEPTH3_CURVE_TREE_CUTOVER.md`](DEPTH3_CURVE_TREE_CUTOVER.md); the CT-5 records in §1;
`V3_WALLET_DECISION_LOG.md` (2026-06-27).
