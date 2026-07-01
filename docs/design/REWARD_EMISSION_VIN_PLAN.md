# Reward emission vin — implementation plan (sub-PR sequence)

**Status:** design plan, pre-flight complete (2026-06-13). Authored under
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(multi-round, consensus-critical, FFI boundary) and
[`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
(evaluated in §4 — exception does **not** apply; standard splitting governs).
**Currency-check (2026-07-01):** PR-E0 has since **LANDED** — the F-S1 substrate fix (full-bond writer `put_archival_bond_value` + retention `claimed_epochs.rs` / `reward_arithmetic.rs`, §1.5 / §3). **PR-E1/E2/E3 remain the gated live front** (the C-1 ML-DSA hard gate = PR-E3 step 8). The 2026-06-13 readiness block below is the point-in-time record from before PR-E0 merged. The Round-0 substrate
re-audit (A2 audit-against-actual-code) is recorded in §1; **Design Round 1**
(external review — 8 findings, F-E1–F-E3 are PR-E3 holds; follow-on M-1–M-3
cross-track / sourcing tightenings) is recorded in §R1 (R1.A binding message,
R1.B remainder, R1.C M-findings); rounds 2–N and the per-sub-PR pre-flight
passes follow before any implementation cut.

**Readiness disposition (2026-06-13 review).** The arithmetic/economic substrate
is **frozen** (M-1 both halves, R1.B remainder, the pure-integer contract gate,
the §3.5 accumulator schema confirmed at source). **PR-E0 is ready to branch
now** — it is an independent latent-bug precursor with zero open dependencies.
**PR-E1/E2/E3 are gated** on the §8 *gating cluster*, whose two hard blockers are
**M-2** (numerator as-of-E sourcing — supply keystone, §R1.C; closes with Q10)
and **Q9/F-E3** (intra-block dedup atomicity). This is a go for the precursor and
a not-yet for the acceptance flip — not a monolithic yes.

**Specification of record:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)
(§5 envelope, §6 bond record, §7 verification, §12 checklist). This document
is the *implementation plan* downstream of that spec; it does not amend
consensus rules. Where this plan and the spec disagree, the spec wins and the
disagreement is a plan bug (`05-system-thinking.mdc`).

**Membership primitive of record:**
[`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) §7 (quantum gate), §9
(carries inherited by this PR series).

---

## 0. What this document is / is not

- **Is:** the sub-PR decomposition, the pre-flight substrate inventory, the
  ML-DSA hard-gate binding constraint, the `stake_claim`/`C_stake` deletion
  surface, the KAT plan, and the open design questions to close in rounds.
- **Is not:** a re-derivation of the economics, the bond lifecycle, or the
  membership-only soundness reduction — those are closed in their own docs.
- **Symbol discipline (A2 / L-1):** rows below freeze **symbol names and
  files**; line numbers are at the 2026-06-13 audit pin and are treated as
  ephemeral. Each sub-PR's pre-flight re-reads the cited symbols at its own
  pin before code lands.

---

## 0.1 Architecture: Rust-first, push the FFI boundary forward

This is a Rust rewrite (`10-shekyl-first.mdc`, `20-rust-vs-cpp-policy.mdc`).
The emission vin is **all new consensus code**, and every one of its
load-bearing surfaces is squarely on the Rust side of the rule-20 test:

- **Parses untrusted input** — the vin deserializer and field validation.
- **Defines a cryptographic contract** — membership-only backing + the ML-DSA
  quantum gate (§2).
- **Integer arithmetic on amounts** — work recompute, three-channel reward
  recompute, the loud-inflation balance check (`checked_*`, not silent
  C++ overflow).

Therefore the **default is: new emission logic lives in Rust; C++ is the thin
marshaling shim that calls across the FFI.** This is not a "while we're here"
migration of inherited C++ — it is writing the *new* code on the correct side
of the boundary the first time, which is cheaper than the Stage-5 cutover that
would otherwise have to migrate it later (the asymmetry in
`16-architectural-inheritance.mdc` §"pre-genesis discount" applied forward).

**Precedent to follow, not invent:** archival consensus logic already lives in
Rust behind FFI — `shekyl_fcmp_verify`, the `shekyl_archival_*` family
(`shekyl_archival_epoch_close_compute`, `shekyl_archival_good_through`, …),
and the `claimed_epochs_check_and_set` dedup core. The emission verify joins
that family as `shekyl_emission_vin_verify`; it does not add a parallel C++
verification path in `blockchain.cpp`.

**What necessarily stays C++ (rule-20 C++-if: touches epee/LMDB/Boost):**
the `transaction` / `txin_v` envelope, epee wire serialization, the LMDB
tables, and the mempool. The `txin_archival_reward_emission` **variant member
+ wire transport** must exist in C++ because the tx object is C++. The
discipline is to keep that C++ surface as thin as possible — transport and
marshaling only — and to put **parse-for-verification, validation, crypto,
and arithmetic in Rust**, with Rust owning the canonical byte layout the
verify consumes.

**Drift control.** To avoid a C++-parse / Rust-parse double-decode that can
diverge, the vin's **canonical consensus encoding is specified and owned in
Rust** (spec-first wire format per `05-system-thinking.mdc`); the C++ struct
serializes/transports exactly those bytes, and `shekyl_emission_vin_verify`
re-parses the canonical bytes as the single source of validation truth. The
C++ struct carries only what the mempool/explorer need beyond the opaque
backing blob. The exact marshaling contract (snapshot struct vs DB-read
callbacks for bond/work/tree state) is an open design-round question (§8 Q7).

**Daemon-side touches follow the same rule.** PR-E3's C++ shim lands in daemon
consensus code (`blockchain.cpp`, `tx_pool.cpp`, `blockchain_db.cpp`). The
daemon is not part of the wallet rewrite and this PR series does not rewrite
it — but every daemon file this work opens is an opportunity to push the
boundary forward rather than thicken the C++: keep the shim minimal, route new
logic through the Rust FFI, and leave the file in better Rust-forward shape
than found. A full daemon rewrite is an eventual (post-wallet) goal; these
incremental "touched-it-so-improved-it" cuts shrink that future scope and
de-risk the Stage-5 transition. This is the `16-architectural-inheritance.mdc`
"leave the file in good shape after my edit" discipline applied to the daemon
— **not** a `15-deletion-and-debt.mdc` "while we're here" expansion: PR scope
stays the emission vin, and unrelated daemon migration is a separate planning
activity (`20-rust-vs-cpp-policy.mdc`).

---

## 1. Pre-flight substrate inventory (A2)

### 1.1 C++ `txin_v` variant system — `src/cryptonote_basic/cryptonote_basic.h`

Existing alternatives and their wire tags: `txin_gen` (binary `0xff`),
`txin_to_script` (`0x0`), `txin_to_scripthash` (`0x1`), `txin_to_key`
(`0x2`), `txin_stake_claim` (`0x3`), `txin_archival_serve_credit_response`
(`0x4`), `txin_archival_bond_post` (`0x5`). **Next free binary tag: `0x06`.**
Registration sites: the `txin_v` `std::variant` typedef, the three
`VARIANT_TAG` blocks (binary/json/debug), and the `get_signature_size`
visitor. The closest existing shape is `txin_archival_bond_post` (carries
`hybrid_public_key` + `holdings` + bond scalars, no key image,
`get_signature_size → 0`).

### 1.2 Verification dispatch

- **`tx_verification_utils.cpp` `check_tx_semantics`** — RCT-semantics gate;
  has dedicated branches for serve-credit (fee-only) and bond-post
  (`verRctSemanticsBondPost`), and a `skip_rct_semantics_batch` path for
  stake-claim-only txs.
- **`blockchain.cpp` `check_tx_inputs`** — tx-class detection
  (`is_stake_claim_only`, `is_archival_serve_credit_only`,
  `is_archival_bond_post_tx`), per-class input handling, and a
  `RCTTypeFcmpPlusPlusPqc` switch with per-class branches; full spends call
  `shekyl_fcmp_verify`.
- **`cryptonote_format_utils.cpp` `check_inputs_types_supported`** —
  structural allow/forbid of txin combinations (§7.1 step 1 hook).
- **`tx_pool.cpp` `get_key_image`** — pool key-image extraction
  (`txin_to_key`, `txin_stake_claim` today).

### 1.3 ML-DSA primitive (hard-gate dependency) — ready

`shekyl-crypto-pq/src/signature.rs`: `SignatureScheme::verify(public_key:
&HybridPublicKey, message, signature: &HybridSignature) -> Result<bool>`,
impl `HybridEd25519MlDsa` over `fips204::ml_dsa_65` (workspace pin
`fips204 = "0.4.6"`). `HybridPublicKey { ed25519: [u8;32], ml_dsa: Vec<u8> }`,
canonical encoding `to_canonical_bytes()` (1996 B, scheme id 1).
`H(pqc_pk)` = `derivation::hash_pqc_public_key` (Blake2b-512, `DOMAIN_PQC_LEAF`,
wide-reduced to a Selene leaf scalar); the C++ FFI mirror is
`shekyl_fcmp_pqc_leaf_hash`.

### 1.4 FCMP membership-only FFI seam — **the gap (§9 carry)**

`FcmpMembershipOnly` (new/read/verify/proof_size) exists **only** in
`shekyl-oxide` (`fcmp/fcmp++/src/lib.rs`). The `shekyl-fcmp` wrapper
(`proof.rs`) and the C ABI (`shekyl-ffi` `shekyl_fcmp_verify`,
`src/shekyl/shekyl_ffi.h`) wrap **only** the full `FcmpPlusPlus` path (with
key images). There is **no** `shekyl-fcmp` membership-only wrapper, **no**
`shekyl_fcmp_membership_only_verify` C ABI, and **no** C++ call site. All of
this is net-new in this PR series.

### 1.5 Archival bond state — present, with one substrate finding

Present and consumable: `archival_bond` LMDB table, `ArchivalBondValue` v4
codec (`shekyl_types.h`) with `claimed_settlement_epochs` and
`first_paying_emission_height` fields; read API (`load_archival_bond_value`,
`archival_bond_good_through`, `archival_bond_join_epoch`, …); Rust dedup
`claimed_epochs_check_and_set` / `claimed_epochs_contains`
(`shekyl-archival-retention/src/claimed_epochs.rs`).

**Finding F-S1 (substrate bug — RESOLVED in PR-E0).** `put_archival_bond_record`
reconstructs a **fresh** `ArchivalBondValue` from scalar args and does **not**
set `claimed_settlement_epochs` / `first_paying_emission_height`. The slash
apply/revert paths load the full bond and then call `put_archival_bond_record`,
which therefore **wiped** the claimed-epoch set and first-paying height on
every slash update. **(F-E5, round 1):** the bug is in the writer's
reconstruction, so it wiped for **any** load-modify-store caller. **Fix
(PR-E0):** added a full-bond LMDB writer `put_archival_bond_value(p_id, bond)`
that serializes the entire decoded record; `put_archival_bond_record` now
delegates to it (the sole remaining caller is JoinMarket connect — a fresh-P
create with no prior claims, so the scalar-arg path is correct there). The two
load-modify-store callers (`apply_archival_slash_one`,
`revert_archival_slashes_at_height`) now mutate the loaded bond in place and
write through `put_archival_bond_value`, so the v4 fields survive. Caller audit
confirmed these are the only load-modify-store sites; gate-4 holdings-update /
re-bond connect paths do not exist yet (genesis: JoinMarket-only) and will be
written under the same discipline when PR-B1/B2/B3 land. There is still **no
production LMDB write path** for claimed epochs and **no C++ FFI** for
`claimed_epochs_check_and_set` — that FFI is deferred to its first consumer,
the emission write path (PR-E3), per spec §6.3 ("FFI surface deferred to its
first consumer") and `15-deletion-and-debt.mdc` (no unused surface). Disposition:
§3 PR-E0 (landed).

### 1.6 Consensus constants

`max_claim_age_w` is fully wired (C++ `SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W` via
`generate_consensus_constants.py`; Rust `MAX_CLAIM_AGE_W` via
`shekyl-archival-retention/build.rs`). `settlement_epoch_blocks` (10000) and
`max_settlement_epochs_per_emission` (15) are **JSON + hardcoded-Rust only**
— not emitted by the C++ generator or `archival-retention/build.rs`
(`REWARD_EMISSION_LEG.md` §12 open item).

### 1.7 `HybridPublicKey` wire (the `P_pubkey` field)

`FOUNDATION_GENESIS_IDENTITY_SET.md` §5 — canonical 1996-byte
`to_canonical_bytes()`. On-chain precedent: `txin_archival_bond_post`
`hybrid_public_key` is a length-bounded `std::vector<uint8_t>`
(`PQC_HYBRID_SINGLE_KEY_LEN`). The emission vin's `P_pubkey` is the same
canonical bytes (not a `ShekylAddress`).

---

## 2. ML-DSA hard merge gate (binding constraint)

`FcmpMembershipOnly` is classically secure only (`R_O` leg is curve25519).
The entire quantum spend-authority property of emission backing rests on the
vin verifying an **ML-DSA-65 signature** over the vin context, against the
`pqc_pk` whose hash `H(pqc_pk)` the membership proof binds in-circuit
(`FCMP_MEMBERSHIP_ONLY.md` §7). Per the absence-of-claim-is-claim-of-absence
rule this is a **merge blocker**, not a checklist item:

> The consensus-activating sub-PR (**PR-E3**) is not mergeable unless its
> verify path (a) recomputes `hash_pqc_public_key(P_pubkey)` and demands it
> equal the in-circuit leaf-committed `H(pqc_pk)`, **and** (b) verifies an
> ML-DSA-65 signature under that `pqc_pk` over a domain-separated vin context.

The gate **primitive** is built in PR-E1; the gate **call** is in PR-E3. The
quantum-forgery wargame (`FCMP_MEMBERSHIP_ONLY.md` §7) is the acceptance frame
for PR-E3's gate tests.

**Open (design round):** is the vin auth ML-DSA-65-only (the quantum half) or
the full `HybridEd25519MlDsa` (ed25519 + ML-DSA)? §10.1 of the spec sizes
"two ML-DSA-65 auths"; the ed25519 half adds nothing against a CRQC but costs
bytes. Default to **ML-DSA-65-only** for the gate; confirm in rounds. What
exactly the signature commits to (tx hash? vin context? settlement-epoch
set?) is pinned as a proposal in **R1.A** for the round to attack.

---

## R1. Design Round 1 — review dispositions (2026-06-13)

External review anchored to `REWARD_EMISSION_LEG.md` §4 / §4.5 / §5 /
§6.4.1 / §6.5 (source, not the plan's self-description). Direction approved.
Eight findings: **F-E1–F-E3 are PR-E3 holds** — each is a chain-split or
unauthorized-mint path as the plan read pre-round; F-E4 is a binding proposal
to attack; F-E5 widens PR-E0; F-E6–F-E8 are open questions. Affected sub-PR and
section text is patched in place; the two drafted artifacts (R1.A, R1.B) are
recorded in full here.

| # | Class | Disposition | Lands |
|---|---|---|---|
| F-E1 | consensus / reorg | Explicit `h > h_close(E)` **and** `MAX_CLAIM_AGE_W` bounds, not row-absence proxies | PR-E3 step 1; boundary KAT |
| F-E2 | consensus / supply | Remainder disposition pinned (R1.B: floor + burn-the-dust) + single-source `reward_arithmetic` both sides | PR-E3 step 5; §8 |
| F-E3 | consensus / double-mint | Intra-block `(P,E)` uniqueness (check/set fusion or block-assembly pass) | PR-E3 step 3; §8 |
| F-E4 | security / replay | Binding-message proposal pinned (R1.A) | §2; §8 Q1 |
| F-E5 | scope | F-S1 affects **every** `put_archival_bond_record` caller, not just slash | PR-E0 (landed): full-bond writer; slash apply/revert converted |
| F-E6 | open | `holdings` (static) vs `held(P,E)` (per-epoch) snapshot semantics | §8 |
| F-E7 | open | same-tx backing + key-imaged fee double-use | §8 |
| F-E8 | open | zero-work/zero-reward emission + arithmetic widths | §8 |

### R1.A — F-E4: ML-DSA auth binding-message proposal (attack in round 2)

The membership proof already binds `signable_tx_hash` + input index
(`FCMP_MEMBERSHIP_ONLY.md` §5.3), so the *proof* cannot be replayed. The ML-DSA
auth is a **separate artifact** that must bind equivalently or it can be lifted
out and replayed. Proposal — one canonical auth digest; every ML-DSA-65 auth in
the vin signs it:

```text
emission_auth_msg = cSHAKE256(
  customization = "shekyl/archival-emission-auth-v1",
  input = length-prefixed (TupleHash-style) concat, in order, of:
    P_canonical_id            // 32 B = §6.1 cSHAKE(P_pubkey) — pseudonym identity
    P_pubkey.canonical_bytes  // exact hybrid key (no substitution)
    holdings_digest           // canonical HoldingsDescriptor encoding
    settlement_epochs         // exact claimed set, count-prefixed (epoch replay)
    work_claim_digest         // canonical hash of the full WorkClaimVector
    reward_commit_set_digest  // ordered vout: (commitment, amount_plain, one-time key)
    signable_tx_hash          // tx prefix + pseudo-outs (cross-tx replay)
)[0..64]
```

Two ML-DSA-65 auths (the §10.1 two-auth byte budget), both over
`emission_auth_msg`:

- **Auth-B (backing):** under the `pqc_pk` whose `H(pqc_pk)` the `Fcmp` leg
  proved in-circuit — the §7-wargame quantum spend-authority defense. This is
  the load-bearing gate; without it backing reduces to classical security.
- **Auth-P (pseudonym):** under `P_pubkey`'s ML-DSA component — binds
  claim/dedup/mint to P's quantum identity (an attacker who somehow produced a
  valid backing proof still cannot redirect the mint to a different P).

Field rationale (each closes a named lift):

- `signable_tx_hash` — cross-tx replay (mirrors the proof's own §5.3 binding).
- `reward_commit_set_digest` — mint-destination swap; bound **explicitly** even
  though `signable_tx_hash` covers the prefix, so the property survives any
  future change to what the tx hash spans.
- `settlement_epochs` + `work_claim_digest` — cross-epoch / cross-work replay.
- `P_pubkey` / `P_canonical_id` — pseudonym substitution.

Hash family: **cSHAKE256**, matching the §6.1 `P_canonical_id` derivation
(already in the archival consensus path; `sha3` already a workspace dep,
`17-dependency-discipline.mdc`). This is a vin-layer consensus digest, **not**
an FCMP transcript challenge, so it correctly joins the cSHAKE/archival family
rather than the Blake2b FCMP transcript family — no new hash family enters
either path. Domain tag distinct from §6.1's `shekyl/archival-p-id-v1` and from
the membership transcript tags.

Open sub-questions for the round: (1) is **Auth-P** necessary, or is the
backing leaf's `pqc_pk` already derivationally bound to `P_pubkey` such that
Auth-B + the in-circuit leaf binding pins P? If so, collapse to one auth and
re-pin §10.1 sizing. (2) ML-DSA-65-only confirmed (ed25519 half adds nothing
against a CRQC).

### R1.B — F-E2: remainder disposition recommendation (for the gate-1 pin)

Form C is `reward_P(E) = floor(budget(E)·capped_P(E) / Σwork(E))`. Floor strands
up to `N_P − 1` atomic units (`Σ_P floor(·) ≤ budget`), contradicting §4.0's
exact "`Σ reward = budget`" against §5.4's **zero-tolerance** vout compare.

**Pinned recommendation: floor + burn-the-dust (unminted remainder), with
u128 numerator-before-divide.**

1. **Operation order:** compute `budget·capped_P` as **u128** *before* dividing
   by `Σwork` (no intermediate precision loss). `capped_P` / `Σwork` accumulate
   in u64; the product needs u128 (see F-E8).
2. **Rounding:** floor (integer division).
3. **Remainder:** the `≤ N_P − 1` atomic shortfall is **unminted** — never
   minted, not rolled, not redistributed.

Why burn-the-dust over largest-remainder (Hamilton): **per-P independence is a
hard architectural constraint here, not a preference.** Emissions are per-P and
asynchronous across many blocks; the verifier checks one P's emission against
the finalized epoch row (the §4.4 accumulator, an O(1) read). Largest-remainder
makes P's `+1` depend on the *rank* of P's fractional remainder among **all**
market P at E — forcing the verifier to enumerate the full cohort per emission
(exactly the full-ledger re-walk §4.4 exists to avoid) and breaking the
per-P-pure-function property that both the zero-tolerance compare and
wallet/consensus bit-identity require. Burn-the-dust keeps `reward_P(E)` a pure
function of `(P, E, finalized row)`; the dust is supply-**safe** (under-mint,
never over-mint) and is the same flavor as §4.5's already-accepted "offline P's
share unminted." Roll (carry to next epoch) is rejected: cross-epoch state +
reorg coupling.

**Spec consequence (gate-1 pin — APPLIED 2026-06-13, `REWARD_EMISSION_LEG.md`
§4.0).** The refinement landed at the **integer-payout layer**, not the Form-C
row: §4.0's Form-C row keeps the **real-valued** normalization identity
(`Σ_P reward_P = budget` whenever `Σ Curve > 0`) — the property that
distinguishes C from A (A strands budget pre-rounding) — and the integer pin
sits one layer down in the notation block: `reward_P(E) = floor(budget·capped_P
/ Σwork)`, u128 numerator before divide, the `≤ (N_P−1)`-atomic floor remainder
**unminted** (`Σ minted ≤ budget`, supply-safe), with a residual-collision
guard distinguishing it from the `Curve` residual the existing reversion clause
governs, and a rule-21 reopen clause. The naive edit (weakening the Form-C
row's `=` to `≤`) was rejected for exactly the C-vs-A reason. Spec and plan are
now reconciled; no further §4.0 action.

**Single source of truth:** PR-E3's recompute **imports the canonical
`reward_arithmetic` crate** — not a third reimplementation — and the wallet
build path (`REWARD_EMISSION_LEG.md` §11) imports the **same** crate.
Zero-tolerance compare is sound only when both sides are bit-identical by
construction (project no-third-copy-of-an-arith-function rule). The verify is
the **third** Form-C consumer after the sim (`shekyl-staking-sim/reward.rs`,
`REWARD_EMISSION_LEG.md` §4.0) and the economics engine. **The canonical crate
already exists:** `shekyl-archival-retention/src/reward_arithmetic.rs` exposes
`curve_milli`, `reward_share_floor` (docstring: "dust stays unminted"),
`scarcity_milli`, `g_age_milli`, and `mul_div_floor` (u128 intermediate) — so
R1.B's floor + burn-the-dust + numerator-first recommendation is the crate's
**shipped behavior**, and PR-E3 imports it rather than reimplementing.

### R1.C — Round-1 follow-on: cross-track & sourcing tightenings (M-1/M-2/M-3)

Second-pass review against `ARCHIVAL_SIM_ECONOMICS_VERDICT.md` and
`ARCHIVAL_CONSENSUS_STATE.md`. M-1 is load-bearing (a cross-document genesis
dependency neither doc currently connects) and is now closed both halves;
**M-2 is the supply-conservation keystone and a PR-E3 hard blocker** (numerator
as-of-E sourcing — it does *not* fold quietly into step 4; it gates the
acceptance flip and closes only with Q10, see below and §8); M-3 is the
single-source completeness extension to channel 1, a PR-E3 construction mandate.

**M-1 has two halves, both addressed 2026-06-13 — half (a)
economics-preservation: PASS (PR 1.5), integer `Curve` frozen at milli; half (b)
cross-arch determinism: closed (golden-vector KAT runs on x86_64 + aarch64), with
the wallet-side single-source the single carry into PR-E3 (see §9).**
`reward_arithmetic`'s **integer** `Curve` is the function PR-E3 mints money with
at **zero tolerance** (§5.4). Two distinct properties hide under "freeze the
integer Curve": **(a)** does the integer `Curve` *preserve the emergent
economics* the float sim validated, and **(b)** do the wallet build path and the
consensus recompute produce *bit-identical* integer values across
implementations and arches for the §5.4 compare. They are closed by different
mechanisms; PR 1.5 addresses (a) only.

**Half (a) — economics preservation (PASS).** The thin per-point reconciliation
KAT (`ε_curve ≤ 0.002`, `ARCHIVAL_SIM_ECONOMICS_VERDICT.md`, 2026-06-09) is the
wrong sufficiency standard on its own — a per-point deviation can propagate
across a sweep and flip a boundary-grazing metric — so the **full integer-sweep
comparison (PR 1.5)** was run on the *homeostasis* frame, which measures that
propagation instead of assuming it: *does the integer backend keep the network
within every homeostasis bound at least as well as the validated float model?*
**Result (full 325-scenario sweep, `--curve-impl=integer` vs `=float`):** the
load-bearing decentralization invariant `spread`/`spread_windowed`
(`max_actor_share < 0.20`) is **325/325 clean** on both backends and integer is
**never below float** on any aggregate. Integer is therefore **not worse** than
the float object — the bar. The +3/+2/+1 on `deep_history`/`churn_stable`/
`all_pass` is **not** a directional edge: the metrics are dependent (`all_pass`
is the conjunction), so those are one-or-two threshold-grazing scenarios flipping
across correlated metrics — reshuffling noise, not five wins. Flooring is a
systematic *down*-bias (see tail-margin note); "integer ≥ float in aggregate"
must not harden into "flooring is benign." Only **4/325** scenarios bifurcate
materially (|Δ frac_under| > 0.30), all at operating-band extremes (servo gain
400 black swans; the g≈2.5 age-weight band edge). A milli→micro
(`WORK_MILLI_SCALE` ×1000) discriminating sweep is what makes the verdict
load-bearing rather than reassuring — it did **not** reduce the material count
(4→4, aggregate slightly worse), converting "the residuals look like band
extremes" into proof of class: **three of four (servo-400) are dynamical, not
arithmetic** (finer fixed-point cannot move a bifurcation); **the fourth
(`layer2_coloc_g2.5`) is genuinely quantization-driven** — micro rescued it
(0→0.70 → 0→0.00) — so the milli freeze does *not* validate it away, and it is
routed to the band-interior carry + the raise-`N` re-check in
`ARCHIVAL_REWARD_ARITHMETIC.md` §Economic-tolerance. **Disposition (a):** PR 1.5
**PASSES**; the integer `Curve` is frozen at `WORK_MILLI_SCALE = 1_000` (milli)
for PR-E3. Raising the scale is rejected (overflow re-audit cost for zero
homeostasis gain; freezing at milli also keeps F-E8's u128 width audit valid
as-is). `WORK_MILLI_SCALE` is now a **load-bearing consensus invariant** (it sets
the fixed-point scale the zero-tolerance compare runs in) and carries a
compile-time guard + "changing this forks the chain" note in
`reward_arithmetic.rs`. **Reopen criterion (rule 21):** the servo-400 / g≈2.5
fragility is addressable only by operating-envelope discipline — a servo-gain
ceiling and a band-interior age-weight target, set and confirmed on **testnet**;
reopen if testnet operates near those edges. **Tail-margin note (second-pass
scan):** integer biases the redundancy tail thinner (`min_r` 26↓/17↑,
`sole_source_shard_epochs` 76↑/49↓) in-envelope — no invariant breaks (no shard
to `min_r = 0` that float kept ≥ 1) — because `floor()` discards the fractional
work-credit float optimistically counted. Consequence: tune redundancy /
`R_target` bands against the **integer backend** (+1 deep-tail replica margin),
and watch `sole_source_shard_epochs` on testnet. PR-E3's economics KATs remain
flagged for regeneration only if a future re-tune reshapes the curve. Evidence:
`ARCHIVAL_SIM_ECONOMICS_VERDICT.md` (PR 1.5 section).

**Half (b) — cross-implementation / cross-arch determinism (KAT gap closed
2026-06-13; one residual = PR-E3 mandate).** Two properties carry the §5.4
zero-tolerance compare: (i) the integer arithmetic produces bit-identical values
across arches, and (ii) every implementation single-sources `reward_arithmetic`
(no second copy).

*Determinism, property (i).* `reward_arithmetic` is pure fixed-width integer
arithmetic — `u64` operands, `u128` intermediates, no `usize`/`isize`, and
`#![deny(clippy::float_arithmetic)]` forbids floating point. Rust defines every
fixed-width integer operation identically on all targets, so cross-arch
bit-identity holds **by construction**; the risk is a *future regression* (an
accidental float/`usize`, or a reordered `mul_div_floor` that floors early). The
**gap found earlier** — the old `determinism_curve_milli_cross_check` was a
same-arch in-process double-call of `curve_milli` that exercised neither a second
arch nor the **Form-C division path** (`reward_share_floor` / `mul_div_floor`) —
is now **closed**: `shekyl-archival-retention/tests/reward_arithmetic_determinism_kat.rs`
pins golden vectors for `g_age_milli`, `scarcity_milli`, `curve_milli`,
`mul_div_floor` (including a vector that overflows the `u64` product, forcing the
u128 path, and one that pins the u128-before-divide order: `floor(7·3/4)=5`, not
`(7/4)·3=3`), `reward_share_floor`, and the Σ-minted-≤-budget burned-dust
property. The weak double-call was reduced to an honest plateau/scale pin. The
vectors **execute** on `x86_64` (`build.yml` `cargo test --workspace`) and on
`aarch64` under qemu-user (`depends.yml`), so the cross-arch claim is verified,
not assumed.

*Single-source, property (ii).* The **consensus** path already single-sources
`reward_arithmetic` (`consensus_state.rs` imports it; there is no second
implementation). The **wallet build** path that produces `reward_amount_plain`
does not exist until PR-E3 (FFI), so its single-source import is a **PR-E3
construction mandate**, not a closeable item now — it is pinned in R1.B/M-3 and
restated in §9. Half (b) is therefore **closed**, with the wallet-side import the
single carry into PR-E3.

**M-2 (supply-conservation keystone — PR-E3 hard blocker; sourcing pin that
*closes with Q10*).** This is the supply-conservation keystone and a **hard
blocker for PR-E3**, not a discipline note: the credited numerator
`capped_P(E)` must be P's **exact** term in the finalized denominator
`Σwork(E)`, or a P over-claims a live-recomputed fat numerator against a stale
finalized denominator (`R_market(s)` has drifted up since close as more
replication landed) and breaks R1.B's `Σ minted ≤ budget` — a silent over-mint.

**Schema confirmed at source (`ARCHIVAL_CONSENSUS_STATE.md`, pulled 2026-06-13).**
The §3.5 accumulator persists **only the aggregate** `Σwork(E)` plus per-shard
`R_market(s,E)` and `serve_credit_bit(P,s,E)` (§5 prune table; §3.3); per-P
`capped_P(E)` keyed by P is named only as a *non-consensus-visible*
incremental-maintenance option (§3.5), **not** a stored record. **The vin
therefore reconstructs the numerator**, so the entire supply property rests on
every as-of-E input being frozen-at-E and queryable-as-of-E.

**The operative pin (numerator side).** The step-4 `work_P(E)` recompute uses
the **identical as-of-E frozen inputs the denominator was finalized from** — so
numerator = P's term in the finalized `Σwork(E)` *by construction*, and no input
reads live state. Three of the four inputs are already pinned frozen-immutable:
`R_market(s,E)` is single-valued + finalized-and-immutable at E-close (§4
invariants 1–2, derived from the E-indexed ledger §3.3); `serve_credit_bit(P,s,E)`
is E-indexed (§3.1); `good_through(P,E)` is derivable at close (§3.4 / invariant
4) and shard `age` as-of-E is a deterministic function of `E` and the freeze
epoch (§3.2). **The fourth input, `held(P,E)`, is exactly Q10/F-E6 (§8 item 10),
still open** — so M-2 is *not* fully resolved: it **cannot close until Q10
closes** (`held(P,E)` pinned frozen-at-E and queryable-as-of-E). It is **not** a
schema gap (the schema supports the reconstruction), but it **is** a load-bearing
sourcing pin gated on Q10, not a closed item.

**Resolve M-2 and Q7 jointly — same question, two sides.** The Q7 FFI snapshot
*is* the frozen as-of-E state the numerator must source from. Snapshot-by-value
keeps `shekyl_emission_vin_verify` a pure function of `(P, E, finalized row)` —
exactly what this pin wants and what makes the verify auditable in isolation — so
the snapshot struct's field set is precisely M-2's frozen-input set. The two are
decided together in the round (arithmetic side = M-2, ABI side = Q7), not
separately.

**M-3 (single-source completeness — extend the mandate to channel 1).** R1.B's
canonical-crate mandate named the Form-C division + `Curve` (channels 2/3), but
PR-E3 step 4's **work** recompute (channel 1: `scarcity_milli =
floor((1/R)·g(age)·1000)`) read as bare "`checked_*` arithmetic" — the
identical zero-tolerance/bit-identity hazard one channel up, and the `age`
fixed-point division is exactly where two implementations drift. Verified at
source: the canonical crate **already exposes** `scarcity_milli(...)` and
`g_age_milli(...)` beside `curve_milli`/`reward_share_floor`. **Extend the
single-source mandate to step 4:** scarcity + `g(age)` import the crate, on
both the verify and the wallet build path — otherwise step 4 is the fourth copy
the mechanism exists to prevent.

**Minor (band scope).** `ε_curve ≤ 0.002` is a **sim float-vs-integer
reconciliation band only** and never reaches consensus — §5.4 is exact equality
and R1.B's zero-tolerance is correct. A contributor porting the sim's
reconciliation logic must not carry the band into the verify.

---

## 3. Sub-PR decomposition (sequenced)

Each sub-PR is short-lived off `dev`, fits the `06-branching.mdc` 5-day /
10-commit envelope, and lands behind the property that **no emission tx is
acceptable until PR-E3**. PR-E1/E2 are additive and inert; PR-E3 is the
single consensus-activating cut; PR-E4 is removal; PR-E5 is wiring/docs.
Function-body-replacement contracts (A1) freeze the inert surfaces so PR-E3 is
a body-fill, not a signature churn.

**Sequencing refinement (2026-07-01) — gate-last; see §3.0.** The "single
consensus-activating cut" is **split**: E3 lands the verify **body** (non-activating,
KAT-tested), and a final gate PR — **C-1** — is the activating cut (ML-DSA gate + the
consensus whitelist flip). This supersedes the "no emission tx acceptable until PR-E3"
framing above with "…until **C-1**."

### 3.0 Gate-last sequencing — C-1 as the final activating merge

**Source-check (dev, 2026-07-01): consensus default-rejects emission vins.**
`check_inputs_types_supported` ([`cryptonote_format_utils.cpp:691`](../../src/cryptonote_basic/cryptonote_format_utils.cpp))
is a whitelist — `{txin_archival_serve_credit_response, txin_archival_bond_post,
txin_stake_claim, txin_to_key}` — with a default-reject `else` ("wrong variant type").
So a `txin_archival_reward_emission` added to the `txin_v` variant (PR-E2) is **rejected by
consensus** until it is explicitly added to that whitelist. This is the precondition
"gate-last" requires, and it is met.

**The rule the check yields:** the whitelist entry **is** the activation, so it must ride
with **C-1**, not with E3's verify body. If E3 whitelisted emission while the ML-DSA auth was
stubbed, consensus would accept an *unauthed* emission — the exact hole. So:

| Merge | Lands | On-chain | Gate |
|-------|-------|----------|------|
| **E1** | membership-only wrapper + ML-DSA vin-auth primitive + C ABIs (wrap **built** `FcmpMembershipOnly` [`shekyl-fcmp-proofs/lib.rs:360`] / `hash_pqc_public_key` [`shekyl-crypto-pq/derivation.rs:58`]) | inert | Q7 for the seam; the two primitives are **buildable-now** (no snapshot-ABI dep) |
| **E2** | `txin_archival_reward_emission` codec (Rust-owned encode/parse/validate) + C++ transport shim | **inert on BOTH paths** — unwhitelisted → rejected at block verify **and** mempool insertion | Q1 (auth count → wire freeze) |
| **E3** | `shekyl_emission_vin_verify` **verify body, steps 1–7**; KAT-tested at the Rust layer; **not on the consensus dispatch** (still unwhitelisted) | inert on chain | design cluster: **M-2, Q9, Q10, Q7** |
| **C-1** | **the activating cut** — ML-DSA gate (mints the `AuthVerified` witness) **+** add emission to `check_inputs_types_supported` **+** C++ shim dispatch (`check_tx_inputs` → marshal → Rust verify → apply) | **consensus now accepts *authed* emission** | `07-consensus-atomic-cutovers`; merge blocker = ML-DSA present + tested; most-scrutinized, isolated from codec mechanics |
| **E4 / E5** | delete `stake_claim`/`C_stake` (after C-1) / constants + KAT + audit-scope + docs | — | E4 merge gate = **emission accepted-and-applied on regtest through the real C-1 path** (below) |

**Mempool/relay inertness (source-verified, dev 2026-07-01).** The whitelist runs on *both*
acceptance paths, not just block verify: `check_inputs_types_supported` is inside
`core::check_tx_semantic` (Rule 5 of `ver_non_input_consensus`), which is called at
**`tx_pool.cpp:171` (mempool `add_tx`)** and **`blockchain.cpp:2371` (block verify)**. So an
unwhitelisted `txin_archival_reward_emission` is rejected **at pool insertion** — it cannot
relay or sit in a mempool as an un-minable nuisance. E2 is inert unqualified.

**The auth stub must be fail-closed by construction — witness-typed, not a flag (load-bearing).**
"Auth stubbed at the boundary" is safe *only* if the stub cannot pass. A stub returning
`auth_ok = true` just relocates the unauthed-emission hole from the whitelist to the stub. So
E3's verify body takes the auth result as an **unforgeable `AuthVerified` witness input it cannot
construct itself** — nothing in E3 (or its KATs) can mint the witness, so E3 **physically cannot
accept an authed emission**. C-1 does not flip a flag; it **supplies the real ML-DSA witness
minter**. This is the same witness-typing discipline as `unbond(ExitedConfirmed)` — the stub is
*unrepresentable-to-pass*, not a TODO someone can fill wrong. (Fail-closed by type is the pin
that makes gate-last safe even mid-sequence.)

**E4's "proven" is a concrete merge gate, not a judgment call.** Removing `txin_stake_claim` /
`C_stake` is the one **irreversible** step, so E4 merges only on **emission accepted-and-applied
on a regtest chain through the real C-1 consensus path** — *not* E3's Rust KAT. The KAT proves the
verify math; only the regtest run proves the consensus **dispatch** functions end-to-end. Replace,
prove on-chain, *then* remove.

**Start-here (the design cluster is a first move, not a parallel note).** E2's codec cannot freeze
(Q1, auth-count → wire freeze) and E3's work-vector semantics cannot settle (M-2, Q9) until the §8
cluster closes — so **E2/E3 are blocked on the cluster, not on E1**. The genuine buildable-now
front is *two things in parallel*: **(1) E1's two primitives** (no snapshot-ABI dep, startable
now) and **(2) the M-2/Q7/Q9/Q1 design round**. E2 opens when the cluster closes.

**Why gate-last (vs the prior "PR-E3 bundles activation + auth").** Gate-*first* would block
the whole body (E1–E3) on the auth seam; the *one-PR* form makes the highest-risk review (the
ML-DSA gate) inseparable from codec mechanics. Gate-last lets E1→E3 land and be KAT-tested
against known vectors with auth stubbed at the boundary, and isolates **C-1** as the single
most-scrutinized merge — the thing that must be true before emission can mint spendable value
on a real chain. The upstream design cluster (§8: M-2/Q7 keystone, Q9, Q1) still gates E2/E3
**unchanged** — gate-last moves only the auth + activation to the end.

### PR-E0 — bond-state write-path correctness (precursor, substrate fix) — LANDED

Scope: fix Finding **F-S1** (widened per **F-E5**). The root cause was that
`put_archival_bond_record` reconstructs a fresh `ArchivalBondValue` from scalar
args, dropping `claimed_settlement_epochs` + `first_paying_emission_height` —
so the wipe hit **every** load-modify-store caller, not only slash.
Disposition (implemented): added a full-bond LMDB writer
`put_archival_bond_value(p_id, bond)` (BlockchainDB virtual + no-op base +
testdb stub + BlockchainLMDB impl) that serializes the whole record;
`put_archival_bond_record` delegates to it (sole caller: JoinMarket connect,
fresh-P create — scalar path correct). The two load-modify-store callers
(`apply_archival_slash_one`, `revert_archival_slashes_at_height`) mutate the
loaded bond in place and write through the full-bond writer, preserving the v4
fields. A thin public reader `get_archival_bond_value` was added for the
regression test. Caller audit (`git grep put_archival_bond_record`) confirmed
the three callers (connect/apply/revert); no gate-4 holdings-update / re-bond
connect path exists yet (genesis: JoinMarket-only), so "all callers" is
satisfied today and the discipline carries to PR-B1/B2/B3 when those paths land.
The `claimed_epochs_check_and_set` / `claimed_epochs_contains` C++ FFI is **not**
in this PR: it has no consumer until the emission write path (PR-E3), and adding
an unused FFI is dead surface (`15-deletion-and-debt.mdc`; spec §6.3 defers the
FFI to its first consumer). No emission behavior; independent correctness fix
that PR-E3 depends on.
**Gate (met):** `archival_substrate_lmdb.cpp` extended with three tests —
`bond_v4_fields_survive_full_writer`, `bond_v4_fields_survive_load_modify_store`
(slash apply), `bond_v4_claimed_set_survives_reorg_revert` (slash revert) —
asserting claimed-epoch + first-paying-height survival across the writer, a
slash, and its reorg revert. All 17 `archival_substrate_lmdb.*` tests pass.
*Reversion: could have folded into PR-E3, but it is pre-existing and
independently testable, so it split per `15-deletion-and-debt.mdc` bisection
discipline.*

### PR-E1 — membership-only FFI seam + ML-DSA gate primitive (additive Rust/FFI)

Scope (all inert — no C++ caller yet):
- `shekyl-fcmp`: `verify_membership_only(...)` wrapping `FcmpMembershipOnly::read`
  + `verify` — mirror `proof::verify` minus the key-image array; re-export the
  membership-only types. Frozen signature (A1).
- C ABI `shekyl_fcmp_membership_only_verify(...)` in `shekyl-ffi` + header decl
  in `shekyl_ffi.h`, parallel to `shekyl_fcmp_verify`.
- ML-DSA vin-auth primitive: given `P_pubkey` canonical bytes, a vin-context
  message, and a `HybridSignature`, verify ML-DSA-65 and recompute
  `hash_pqc_public_key` for the caller to match against the in-circuit leaf.
  Rust + C ABI.

**Gates:** membership-only verify roundtrip through the wrapper; **deser
cross-type rejection at the FFI seam** (the §9 carry — feed membership-only
bytes to the full verify ABI, assert reject); ML-DSA gate positive + negative
(wrong `pqc_pk`, tampered sig). `fmt` + `clippy -D warnings` + full suite.

### PR-E2 — `txin_archival_reward_emission` codec: Rust-owned, C++ transport shim (additive, inert)

**Rust (authority):** the canonical vin encoding + parser + structural
validation, in a `shekyl-*` crate (e.g. `shekyl-archival-retention` or a new
`shekyl-emission` module), spec §5.3 fields (`P_pubkey` hybrid canonical
bytes, `holdings`, `settlement_epochs`, `work_claim` = `WorkEpochClaim` /
`ShardWorkEntry`, `MembershipOnlyBacking`, loud reward fields). Untrusted-input
parse → Rust (rule 20). Exposed via FFI for C++ to (de)serialize through if
needed, with a frozen canonical byte layout (A1).

**C++ (thin transport only):** `txin_archival_reward_emission` struct in
`cryptonote_basic.h` carrying the canonical bytes (length-bounded blob, after
the bond-post `hybrid_public_key` pattern) plus only the fields the
mempool/explorer must read without the Rust parser; append to `txin_v`; three
`VARIANT_TAG`s (binary `0x06`, json/debug `"archival_reward_emission"`);
`get_signature_size → 0`; boost serialize; JSON. The C++ side does **no**
semantic validation — it transports bytes the Rust codec owns.

Inert: `check_inputs_types_supported` continues to reject the type until
PR-E3. **Gates:** Rust canonical-encoding roundtrip + property/fuzz parse
(the untrusted-input surface); C++ epee/boost/JSON transport roundtrip
(`staking.cpp`-style); cross-check that C++-transported bytes re-parse
identically in Rust (single-source-of-truth check, drift control per §0.1).

### PR-E3 — consensus verify wiring: Rust verify behind FFI (the activating cut; §7.1) **[hard gate]**

The §7.1 fail-fast verification is implemented **in Rust** as
`shekyl_emission_vin_verify`, joining the `shekyl_archival_*` / `shekyl_fcmp_*`
FFI family (§0.1). C++ `check_tx_inputs` / `check_tx_semantics` become a thin
shim: marshal the canonical vin bytes + the consensus-state snapshot it needs,
call the Rust verify, apply the returned verdict and connect-effects. New
arithmetic and crypto never re-appear as C++ logic.

**Rust (`shekyl_emission_vin_verify`)** — owns the fail-fast order:
1. **Finalization & claim-age bounds (F-E1)** — for every claimed `E`, enforce
   **explicitly**, as structural checks, `current_block_height > h_close(E) =
   (E+1)·SETTLEMENT_EPOCH_BLOCKS` (the §4.5 finalization invariant — deterministic
   and order-independent under reorg, unlike the row-presence side effect) **and**
   `E ≥ C − MAX_CLAIM_AGE_W` (the §6.6 upper bound — explicit window check, not a
   prune-on-insert row-absence proxy), *in addition to* reading the finalized
   `Σwork(E)` row.
2. **Bond posture** — record exists, holdings match, `E ≥ E_join + 1`.
3. **Dedup** — `claimed_epochs_check_and_set` (already Rust; PR-E0 FFI),
   returning the epochs to commit. **Intra-block double-mint guard (F-E3):**
   the check (verify-time) and set (connect-time) are split across the FFI, so
   two same-block emissions from the same `P` claiming the same `E` both see `E`
   unset and both commit → `E` minted twice. PR-E3 must specify where the
   same-`(P,E)` collision is caught: either the set is applied within the
   connecting transaction's scope so tx2 sees tx1's set, **or** block
   assembly/connect runs an explicit `(P, E)` uniqueness pass across all
   emission vins in the block. Dedup is per-`P`, so the collision is strictly
   same-`P`-same-`E`-same-block. (Open: §8 F-E3.)
4. **Work** — recompute `work_P(E)` and compare to `work_claim`. **As-of-E
   sourcing (M-2):** every input — `R_market(s,E)`, `held(P,E)`,
   `serve_credit_bit(P,s,E)`, shard `age` — is read from the **frozen as-of-E
   snapshot that produced `Σwork(E)`** (sound by `ARCHIVAL_CONSENSUS_STATE.md`
   §4 invariant 2 + E-indexing), **never** live state, or the credited numerator
   drifts from P's term in the finalized denominator and R1.B supply
   conservation breaks. **Channel-1 single source (M-3):** `scarcity_milli` /
   `g_age_milli` import the canonical `reward_arithmetic` crate (same mandate as
   step 5), not bare `checked_*`.
5. **Economics** — recompute three-channel `reward_P(E)` via the **canonical
   `reward_arithmetic` crate** (single source of truth, R1.B — not a third
   reimplementation), compare to `reward_amount_plain` and vout sum
   (zero-tolerance loud inflation check). Remainder disposition per R1.B
   (floor + burn-the-dust, u128 numerator-before-divide); the gate-1 §4.0
   wording refinement must land in the spec before this code.
6. **Membership-only backing** — PR-E1 (`shekyl_fcmp_membership_only_verify`),
   **not** `shekyl_fcmp_verify`.
7. **FCMP balance** — fee `txin_to_key` via existing `shekyl_fcmp_verify`.
8. **ML-DSA gate (§2, R1.A)** — recompute `H(pqc_pk)`, demand equality with the
   in-circuit leaf scalar, and verify the ML-DSA-65 auth(s) over
   `emission_auth_msg` (R1.A binding).

**C++ (thin shim):**
1. **Structural pre-gate** — extend `check_inputs_types_supported` to accept
   exactly one emission vin + zero-or-more fee `txin_to_key`; forbid
   `txin_stake_claim` co-occurrence. (Type-shape gate at the variant layer
   stays C++; field-level structural checks — epoch list monotone/unique/≤15 —
   move into the Rust parse/verify.)
   - Marshal consensus-state snapshot (bond record, archival work state, tree
     root, height/epoch, economics params) across the FFI — **or** expose
     DB-read callbacks; boundary shape is §8 Q7.
   - On accept, apply returned bond mutations + claimed-epoch commits via the
     connect/`pop_block` hooks in `blockchain_db.cpp`; revert on reorg (§8).

**Merge blocker:** step 8 must be present and tested (§2). **Gates / KATs**
(in Rust where the logic lives): minimal valid emission accepts; cross-block
double-claim rejects; **intra-block same-`(P,E)` double-claim rejects (F-E3)**;
work-mismatch rejects; inflation/vout-sum mismatch rejects; ML-DSA-forgery
rejects (wargame); **finalization-boundary KAT (F-E1)** — cite `E` at
`h_close(E)` → reject, at `h_close(E)+1` → accept, and a reorg straddling
`h_close(E)` neither strands nor double-applies; **claim-age boundary** — `E`
at `C − W` accepts, at `C − W − 1` rejects; reorg dedup-revert roundtrip at the
C++ connect/pop layer.

### PR-E4 — delete `txin_stake_claim` / `C_stake` admission (removal)

Scope: delete the enumerated surface in §5. `C_stake` is spec-only (no C++
symbol) — confirm no residual. *Sequencing Q (§8): land before PR-E3 as a
precursor, or after? Pre-genesis both are safe; leaning **after** so the
replacement is proven before the replaced mechanism is removed.*
**Gates:** build clean post-deletion; rewrite/delete `staking.cpp` and the
`fuzz_claim_reward` target per `60-no-monero-legacy.mdc`.

### PR-E5 — constants wiring + KAT completion + audit-scope + doc sweep

Scope: wire `settlement_epoch_blocks` + `max_settlement_epochs_per_emission`
through `archival-retention/build.rs` (mirror `max_claim_age_w`) so the Rust
verify (PR-E3) consumes them from generated constants, not hardcode; emit the
C++ `generate_consensus_constants.py` `KEYS_INTEGER` mirror **only** for the
fields the thin C++ shim's structural pre-gate actually reads (most live only
on the Rust side now per §0.1); finish any remaining KAT vectors; update `AUDIT_SCOPE.md`
§staking (entitlement out, emission in); tick `REWARD_EMISSION_LEG.md` §12 and
close the `FCMP_MEMBERSHIP_ONLY.md` §9 carries; `CHANGELOG.md`.

---

## 4. `07-consensus-atomic-cutovers.mdc` analysis

**Evaluated; exception does NOT apply — the work splits per `06-branching.mdc`.**
Criterion 1 (consensus-rule boundary) is met (new accepted txin type, new
verify rules). **Criterion 2 (indivisible under flag decomposition) is not
met:** the emission txin type is *additive* — PR-E1/E2 introduce inert
machinery (no tx is acceptable), PR-E3 is the single point that flips
acceptance, and PR-E4 removes the independent `stake_claim` path. This is a
clean flag-style decomposition with consensus-safe intermediates at every cut
(no validator reaches a different conclusion about any block until PR-E3
lands, and PR-E3 is itself one atomic acceptance flip). Because criterion 2
fails, the named exception is unavailable and standard splitting is mandatory,
which matches the chosen plan. PR-E3 remains a single PR because the
acceptance flip + its verify steps are one indivisible consensus unit, but it
is sized within the normal envelope, not under the §07 carve-out.

---

## 5. Deletion surface — `txin_stake_claim` / `check_stake_claim_input` / `C_stake`

`C_stake`: **no symbol** under `src/` (spec-only retired path). Enumerated
`stake_claim` sites (freeze by symbol; lines at audit pin):

| File | Symbol / role |
|---|---|
| `cryptonote_basic.h` | `txin_stake_claim` struct + serialize; `txin_v` member; `get_signature_size` case; 3 `VARIANT_TAG`s (binary `0x3`) |
| `cryptonote_boost_serialization.h` | `serialize(txin_stake_claim)` |
| `json_object.{h,cpp}` | decl + variant visitor + `elem.name` branch + per-type serializer |
| `cryptonote_format_utils.cpp` | amount aggregation; `check_inputs_types_supported` mixing rules |
| `blockchain.cpp` | `is_stake_claim_only`, skip-FCMP branch, stake-claim verify path, `check_stake_claim_input`, per-block aggregate, double-spend visitor |
| `blockchain.h` | `check_stake_claim_input` decl |
| `blockchain_db.cpp` | connect (`add_spent_key` + watermark + pool debit) / pop revert |
| `cryptonote_core.cpp` | duplicate-key-image, ring-member-diff skip, key-image domain check |
| `tx_verification_utils.cpp` | `skip_rct_semantics_batch` stake-claim path |
| `tx_pool.cpp` | `get_key_image` stake-claim arm |
| `wallet2.cpp` | claim-tx construction |
| `tests/unit_tests/staking.cpp` | serialization + variant tests (delete/rewrite) |
| `rust/shekyl-staking/fuzz/fuzz_targets/fuzz_claim_reward.rs` | mirrors claim math |
| `rust/shekyl-engine-state/src/staker_pool.rs` | `estimate_reward` documents the claim math (re-anchor or retire) |

---

## 6. Test / KAT plan

- **Codec (PR-E2):** Rust canonical-encoding roundtrip + parse fuzz (authority);
  C++ binary/json/boost transport roundtrip; C++→Rust re-parse identity check.
- **FFI seam (PR-E1):** membership-only roundtrip; **deser cross-type
  rejection** (membership bytes → full ABI → reject); ML-DSA gate ±.
- **Consensus KATs (PR-E3, spec §12):** minimal valid emission accepts;
  cross-block + **intra-block same-`(P,E)`** double-claim reject (F-E3);
  work-mismatch rejects; **ML-DSA-forgery rejects** (§2 wargame, R1.A binding);
  economics-mismatch rejects (incl. the `≤(N_P−1)` dust boundary, R1.B);
  **finalization-boundary + claim-age-boundary KATs** (F-E1); reorg
  dedup-revert roundtrip.
- **Substrate (PR-E0, landed):** claimed-epoch + first-paying-height survival
  across the full-bond writer, slash apply, and slash reorg-revert (the three
  `put_archival_bond_record` callers today; holdings-update / re-bond connect
  paths land under the same discipline in PR-B1/B2/B3, F-E5).
- **Deletion (PR-E4):** clean build; legacy tests rewritten to HF1 rules.

---

## 7. Threat-model addenda frame (A3) — to close in design rounds

Adversarial objectives to probe before PR-E3 closure (non-exhaustive):
quantum backing-forgery (the §2 gate — load-bearing); **mint-destination swap
via an under-bound ML-DSA auth** (R1.A — bind vout set + tx hash);
double-claim across reorg boundaries and the finalization boundary (F-E1);
**intra-block same-`(P,E)` double-mint** (F-E3); work/economics over-claim via
fixed-point edge; **supply leak / over-mint via the floor remainder** (R1.B);
emission-vin + fee-input mixing to launder a key-image spend (F-E7);
vin-context signature replay across txs/epochs; empty / duplicate-input
vacuity at the vin layer (§8.2 of the membership doc defers input-distinctness
here); **zero-reward block-space spam** (F-E8). Each routes to in-scope,
discipline note, or named forward-action (A5).

## 8. Open design questions (for the rounds)

**Gating cluster (round-2 leverage order).** The substrate is frozen (§R1.C
M-1, R1.B, the pure-integer gate); **PR-E0 has zero open dependencies and is
ready to branch now** (§3 PR-E0 — a latent field-wipe precursor independent of
every open economic question). **PR-E1/E2/E3 are gated** on the cluster below.
Two are silent over-mint / double-mint blockers that PR-E3 **must not branch
without** — exactly the class the pre-implementation freeze exists to catch
before code makes them expensive:

| Item | Gates | Severity | Status |
|------|-------|----------|--------|
| **M-2** numerator as-of-E sourcing (§R1.C) | **PR-E3** | **hard blocker** (silent over-mint) | open; **closes with Q10**; resolve jointly with Q7 |
| **Q9 / F-E3** intra-block `(P,E)` dedup atomicity | **PR-E3** | **hard blocker** (double-mint) | open |
| **Q7** FFI snapshot vs callbacks | PR-E1/E3 | sequencing | open; resolve jointly with M-2 |
| **Q10 / F-E6** `held(P,E)` frozen-at-E | PR-E3 (and M-2) | sequencing | open; M-2 depends on it |
| **Q1 / F-E4** auth count | **PR-E2** (wire freeze) | sequencing | message pinned (R1.A); count open |
| **Q3 / Q11 (F-E7) / Q12 (F-E8)** | PR-E3 | acceptance-path policy | round-closable; not deep |

Round-2 order of leverage: (1) pull `ARCHIVAL_CONSENSUS_STATE.md` and resolve
**M-2 + Q7 jointly** (numerator sourcing / snapshot ABI / accumulator schema —
the supply keystone; schema pulled and confirmed in §R1.C M-2); (2) pin **Q9**'s
dedup atomicity model; (3) **Q1** auth count (unblocks PR-E2's wire); (4) the
policy trio **Q3 / Q11 / Q12**. M-2 and Q9 are the two PR-E3 must not branch
without.

### 8.0 Round-2 opener — cluster state-map + leans (SCOPING, 2026-07-01)

These began as **leans to be ratified in Round 2** (honest-reopen standard, like the DQ set).
Verified at source: the cluster is a **design round over an *implemented* substrate**, not a
build — the economics and epoch-close state are landed; what is open is pinning contracts.

**Update 2026-07-01 — Q9 and Q1 RATIFIED (leans → pinned, §8.0.1); `held(P,E)` two-condition
check DONE (the flagged grep landed — hybrid + straddle-safe verified); Q7 resolved-by-pattern.**
So the keystone round's **design decisions are closed**. The remaining concrete work is the **one
build item** (`held(P,E)` as-of-E interval marshaling) + **E2's wire freeze**, now unblocked by
Q1's two-auth answer.

| Item | Built (verified `dev`) | Open — the lean to ratify |
|------|------------------------|---------------------------|
| **Q7** FFI seam | `shekyl_archival_verify_*` **snapshot-by-value** pattern ([`archival_ffi.rs:346`](../../rust/shekyl-ffi/src/archival_ffi.rs) — C++ reads LMDB, marshals scalars/arrays by value, Rust verify pure) | **resolved by house pattern** — emission verify follows it; work = enumerate the field set |
| **M-2** numerator as-of-E | `r_market_count` / `sigma_work_milli` / `scarcity` / `curve_milli` + `EpochCloseOutputs` (`consensus_state.rs`); schema implemented 2026-06-12; invariant-2 finalized-immutable-at-E-close | pin the **as-of-E snapshot field set** = the Q7 struct; every field from the frozen E-close materialization, never live |
| **Q10 `held(P,E)`** | *(two-condition pin below)* | the one genuine design piece |
| **Q9** dedup atomicity | `claimed_epochs_check_and_set` ([`claimed_epochs.rs:99`](../../rust/shekyl-archival-retention/src/claimed_epochs.rs)) | **PINNED** (§8.0.1) — check/set **fused in tx-connect scope**, mark rolls back with the tx |
| **Q1** ML-DSA auth count | binding message pinned (R1.A) | **PINNED** (§8.0.1) — **two auths** (rotation-forced); E2's vin freezes around two auth fields |

**`held(P,E)` frozen-at-E — two conditions (verified at source, avoiding the "reuses what's
built" over-claim):**

- **(a) Frozen-E accessor — reuse the *logic*, build the *marshaling* (lean).** The frozen-E
  membership **function** is built and is exactly what `R_market` already uses:
  `market_member_at_epoch(join_E, E, bad_intervals, is_foundation)` → `good_through`
  ([`consensus_state.rs:97`](../../rust/shekyl-archival-retention/src/consensus_state.rs)). What is
  **not** built is the as-of-E *accessor* feeding it P's intervals: there is **no `BondEventLog`
  reader in the Rust crate**, and the C++ `has_archival_bond_shard` is **tip-relative**
  (`db_lmdb.cpp:5054` — the Pin-4-flagged read). So the round's **one build item** is the as-of-E
  interval **marshaling** for the emission snapshot (C++ reads P's persisted intervals + `join_E`,
  marshals by value; Rust runs the built `market_member_at_epoch`) — **not** the tip-read. Reuse
  the logic; build the accessor.
- **(b) Straddle-safe — VERIFIED built.** `good_through`
  ([`consensus_state.rs:84–92`](../../rust/shekyl-archival-retention/src/consensus_state.rs))
  evaluates the intervals **as-of the queried E** (`settlement_epoch < iv.end_exclusive` closes a
  straddling interval at E for the query), so the as-of-E materialization is a pure function of
  ≤E-close events. This is the property that makes `held(P,E)` snapshot-by-value-able at all, and
  it holds in the built code. **State it explicitly in the pin:** if a post-E event could
  retroactively alter a straddling interval, `held(P,E)` would not be snapshottable and the
  snapshot-by-value seam would break for that one field — so the pin *is* this property, not just
  "which source."

#### 8.0.1 Q9 and Q1 — ratified 2026-07-01 (leans → pinned)

**Q9 — dedup atomicity: fused check/set in tx-connect scope, tx-atomic.** One place the
uniqueness lives; tx2 reads what tx1 wrote. A block-assembly sweep is not just double work — it is
a **second validator that has to stay consistent with the first**, the "validate twice, reconcile
later" shape where the two drift and disagree. `claimed_epochs_check_and_set` is already the fused
primitive, so this is **pin-the-model-to-built-code, not build.** The pin that must not stay
implicit: the check **and** the set live in the **same LMDB transaction scope as the tx-connect**,
so a tx that fails later in connect does **not** leave its epoch marked claimed — the mark **rolls
back with the tx**. Same `pop_block`-atomicity discipline pinned for the tree: the mark's
durability is tied to the tx's, never written ahead of it.

**Q1 — ML-DSA auth count: two auths (rotation-forced).** `P` is **rotatable between stake and
claim**, so "the bonded output was `P`'s" (proven at stake, by membership) and "`P` authorizes this
payout" (at claim) are provably about **potentially different personas**. The membership proof
anchors the bond to the **`P`-that-staked** and says nothing about the **`P`-that-claims-now**; if
those can differ by rotation, **one auth structurally cannot close the gap** — the gap is real, not
hypothetical. So **two auths, over two distinct statements with two distinct binding messages**:

- **stake-side** — binds `P`-that-staked ↔ the bond (membership).
- **claim-side** — binds `P`-that-claims ↔ **this specific emission**: the binding message commits
  to the **payout output(s) minted and the epoch `E`**, so a valid claim-auth **cannot be replayed**
  against a different payout or a different `E`.

**Wire-freeze consequence (why Q1 gated E2).** Two auths ⇒ E2's vin carries **two auth fields**, and
the emission vin's authenticated-field count / byte-shape **freezes around that** — two distinct
signatures, not one checked twice. This is why answering Q1 unblocks the **wire freeze**, not merely
the verify body. **Rotation-fit note:** the claim-side auth carries the reward to the **current**
`P` — reward **follows the rotation** (the persona that staked earns it, the persona that claims
receives it, distinct operator-controlled keys). Same degree of freedom as the **drain-and-rotate**
model (profit-taking = rotation) surfacing at the emission layer — the emission wire and the
persona-rotation firewall are **designed to fit**, not accidentally compatible.

**Round status.** With Q9 and Q1 pinned, Q7 resolved-by-pattern, and `held(P,E)` two-condition-
checked, the keystone round's **design is closed**. Concrete deliverables: (1) `held(P,E)` as-of-E
interval **marshaling** (the one build, reusing `market_member_at_epoch`); (2) the M-2/Q7 as-of-E
snapshot **field set** (now including the **two** auth fields from Q1); (3) E2's **wire freeze**
around that field set. Buildable-now front unchanged: **E1's two primitives + this round in
parallel**; E2 opens on the wire freeze.

1. **ML-DSA vin auth shape (F-E4) — gates PR-E2 (wire freeze), not just E3.**
   *Proposal pinned in R1.A* for the round to attack (binding message, two auths,
   cSHAKE family). Remaining: is Auth-P necessary or does the leaf→`P_pubkey`
   derivation already pin P? The binding *message* is pinned (R1.A) but the auth
   *count* is not, and the auth bytes are in the vin wire — so **PR-E2's canonical
   encoding cannot freeze until this is answered**. ML-DSA-65-only confirmed.
2. **PR-E4 sequencing** — delete `stake_claim` before or after PR-E3.
3. **Input distinctness** — does the emission vin require backing-input
   distinctness (membership proof does not dedup, §8.2)? Enforce at vin layer?
4. **Codec ownership** — *resolved (§0.1): Rust owns the canonical encoding +
   parse + validation; C++ transports the bytes.* Remaining sub-question: does
   the explorer/mempool need any decoded field surfaced on the C++ struct, or
   does the opaque blob + a few transport scalars suffice?
5. **`WorkClaimVector` bound** — `shard_id` encoding + per-epoch entry bound
   vs `holdings` descriptor (interface trails `ARCHIVAL_CONSENSUS_STATE.md`).
6. **`P_canonical_id`** derivation site (cSHAKE, spec §6.1) — Rust (default
   per §0.1, joins the crypto on the Rust side).
7. **FFI marshaling boundary (§0.1, PR-E3) — gates PR-E1/E3; resolve with M-2.**
   Does `shekyl_emission_vin_verify` take a consensus-state *snapshot struct*
   (bond record, archival work state, tree root, height/epoch, economics params)
   by value, or *DB-read callbacks* into C++ LMDB? Snapshot is simpler to audit
   and keeps the verify pure; callbacks avoid copying large work state. **Decide
   jointly with M-2 (§R1.C):** the snapshot struct *is* M-2's frozen as-of-E
   numerator-input set, so snapshot-by-value is the shape that makes the verify a
   pure function of `(P, E, finalized row)`. Affects the `shekyl_archival_*`-family
   ABI shape; sets the FFI seam built in PR-E1.

### Round-1 open items (must close before PR-E3 code; F-E2/F-E3 consensus-load-bearing)

8. **Remainder disposition (F-E2)** — *closed on the spec/disposition side*:
   pinned in R1.B, **applied in §4.0** (2026-06-13), and already the canonical
   crate's shipped behavior (`reward_share_floor` = floor + "dust stays
   unminted", `mul_div_floor` = u128 numerator-first). Only remaining gate is
   PR 1.5 economic-equivalence for the integer `Curve` (M-1).
9. **Intra-block `(P,E)` uniqueness (F-E3) — PR-E3 hard blocker.** Pick
   check/set fusion within the connecting tx scope vs an explicit block-assembly
   uniqueness pass. **Consensus double-mint hole until pinned** — one of the two
   silent-over-mint blockers (with M-2) that PR-E3 must not branch without; the
   acceptance path cannot be written around an unpinned dedup atomicity model.
10. **Holdings snapshot semantics (F-E6) — gates M-2 closure.** §6.4.1 says
    holdings "compatible," §5.3 "must match," but work is recomputed over
    per-epoch `held(P,E)` (§4.1), which may differ from *current* holdings if a
    gate-4 flow ran between epochs. Pin `held(P,E)` **frozen-at-E and
    queryable-as-of-E**, which snapshot the vin `holdings` field must match, and
    how a mid-batch holdings change is handled. **Load-bearing for M-2:**
    `held(P,E)` is the one M-2 numerator input not yet pinned frozen-immutable
    (the other three are — §R1.C M-2), so **M-2 cannot close until this closes**,
    and it is decided jointly with Q7 (the snapshot ABI that carries `held(P,E)`).
11. **Same-tx backing + fee double-use (F-E7)** — §5.2 permits key-imaged fee
    `txin_to_key` alongside keyless membership-only backing; the threat model
    names mixing to launder a key-image spend. Decide whether one output may be
    both membership-only backing *and* a key-imaged fee input (possibly inside
    the §7.5 intra-epoch-unbacked model — state it) or the backing set must
    exclude same-tx-spent outputs.
12. **Zero-work / zero-reward emission (F-E8)** — §4.3's R-ceiling dead zone
    (`R > 1000·g(age)` → `scarcity_milli = 0`) plus `Curve(0)` lets a `P` with
    all shards in the dead zone recompute `work_P = 0`, `reward = 0`. Reject a
    zero-reward emission (block-space spam) or accept with zero vout?
    (`reward_share_floor` already returns 0 cleanly when `capped == 0`, so the
    arithmetic is well-defined; the open part is the accept/reject policy.) Width
    check **confirmed at source:** `mul_div_floor` already uses a u128
    intermediate for the `budget·capped_P` product; `Σ scarcity_milli` work
    accumulation stays u64.

## 9. Inherited forward-actions (`FCMP_MEMBERSHIP_ONLY.md` §9 carries)

- ML-DSA backing auth → **PR-E3 hard gate** (§2).
- FFI entry point + `shekyl-fcmp` wrapper + C++ call site + vin deserializer +
  emission KATs → **PR-E1/E2/E3/E5**.
- FFI-seam variant of the deser cross-type test → **PR-E1**.
- Vin-layer input-distinctness rule (if required) → **PR-E3** (§8 Q3).
- **M-1 half (a) — economics preservation (PR 1.5)** → **PASS 2026-06-13**;
  integer `Curve` frozen at `WORK_MILLI_SCALE = 1_000`. Homeostasis-frame sweep:
  `spread` 325/325 clean, integer **not worse** than float on any aggregate;
  4/325 material bifurcations — three servo-400 (dynamical, micro did not move
  them), one g≈2.5 band edge (quantization-driven, micro-rescued → band-interior
  carry). Evidence: `ARCHIVAL_SIM_ECONOMICS_VERDICT.md` (PR 1.5).
- **M-1 half (a) carries → testnet operating-envelope:** servo-gain ceiling;
  band-interior age-weight target (the g≈2.5 upper edge is quantization-fragile
  at the frozen milli scale); tune the **testnet-tunable** redundancy / `R_target`
  operating bands against the **integer backend** with a **+1 deep-tail replica
  margin** (tail-margin finding: integer thins `min_r` / raises
  `sole_source_shard_epochs` in-envelope because flooring discards work-credit
  float over-counted — no invariant breaks). PR-E3 economics KATs regenerate only
  on a future re-tune.
- **M-1 half (a) carry → genesis-seal (pre-genesis, blocks the seal):** the same
  +1 over-optimism applies to the **genesis-sealed** redundancy params, which the
  testnet-watch carry above cannot fix (a sealed value cannot move without a fork).
  The L12 genesis deep-replica floor `r_target_deep` and any genesis-sealed
  `R_target`/redundancy floor (currently provisional, float-calibrated —
  `STAKER_ARCHIVAL_SIM.md` §L12) must be **re-derived against the integer backend
  with a +1 deep-tail replica margin before the seal**. Availability-scoped
  (Foundation complete-tree B+C seeds are the durability backstop), not a
  durability escalation. Tracked in `docs/FOLLOWUPS.md` V3.0 pre-genesis queue so
  it cannot slip into genesis at its float value by omission.
- **M-1 half (b) — cross-arch bit-identical determinism** → **closed 2026-06-13;
  one carry into PR-E3.** Prerequisite for the §5.4 zero-tolerance compare.
  Determinism holds **by construction** (pure fixed-width integer arithmetic, no
  float/`usize`, `#![deny(clippy::float_arithmetic)]`); the golden-vector KAT is
  the regression guard. The inadequate `determinism_curve_milli_cross_check`
  (same-arch double-call of `curve_milli` only) is superseded by
  `shekyl-archival-retention/tests/reward_arithmetic_determinism_kat.rs`, which
  pins `g_age_milli`, `scarcity_milli`, `curve_milli`, `mul_div_floor` (overflow
  → u128 path; `floor(7·3/4)=5` pins u128-before-divide order), `reward_share_floor`,
  and the Σ-minted-≤-budget burned-dust property. The KAT **executes** on both
  `x86_64` (`build.yml`) and `aarch64` under qemu-user (`depends.yml`). Consensus
  path single-sources `reward_arithmetic`. **Carry into PR-E3:** the wallet build
  path that emits `reward_amount_plain` must import the same `reward_arithmetic`
  crate (no second implementation) — un-closeable until that path is built;
  pinned in R1.B/M-3.

## 10. Related documents

| Doc | Relationship |
|---|---|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consensus spec of record (§5–§7, §12) |
| [`FCMP_MEMBERSHIP_ONLY.md`](../completed/FCMP_MEMBERSHIP_ONLY.md) | Backing primitive; §7 quantum gate; §9 carries |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | gate 2/3 schema + `W`; §3.5 accumulator + §4 invariant 2 (M-2 as-of-E sourcing) |
| [`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`](../completed/ARCHIVAL_SIM_ECONOMICS_VERDICT.md) | economics validation track; PR 1.5 integer-sweep gate (M-1) |
| [`ARCHIVAL_REWARD_ARITHMETIC.md`](ARCHIVAL_REWARD_ARITHMETIC.md) | canonical `reward_arithmetic` Q-format + KAT bands (R1.B, M-3) |
| [`FOUNDATION_GENESIS_IDENTITY_SET.md`](FOUNDATION_GENESIS_IDENTITY_SET.md) | `HybridPublicKey` wire (§5) |
