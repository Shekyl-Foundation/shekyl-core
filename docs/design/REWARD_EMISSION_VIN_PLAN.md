# Reward emission vin — implementation plan (sub-PR sequence)

**Status:** design plan, pre-flight complete (2026-06-13). Authored under
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(multi-round, consensus-critical, FFI boundary) and
[`07-consensus-atomic-cutovers.mdc`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
(evaluated in §4 — exception does **not** apply; standard splitting governs).
No production code has landed against this plan. The Round-0 substrate
re-audit (A2 audit-against-actual-code) is recorded in §1; **Design Round 1**
(external review — 8 findings, F-E1–F-E3 are PR-E3 holds) is recorded in §R1;
rounds 2–N and the per-sub-PR pre-flight passes follow before any
implementation cut.

**Specification of record:** [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md)
(§5 envelope, §6 bond record, §7 verification, §12 checklist). This document
is the *implementation plan* downstream of that spec; it does not amend
consensus rules. Where this plan and the spec disagree, the spec wins and the
disagreement is a plan bug (`05-system-thinking.mdc`).

**Membership primitive of record:**
[`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) §7 (quantum gate), §9
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

**Finding F-S1 (substrate bug, latent today).** `put_archival_bond_record`
reconstructs a **fresh** `ArchivalBondValue` from scalar args and does **not**
set `claimed_settlement_epochs` / `first_paying_emission_height`. The slash
apply/revert paths load the full bond and then call `put_archival_bond_record`,
which therefore **wipes** the claimed-epoch set and first-paying height on
every slash update. **(F-E5, round 1):** the bug is in the writer's
reconstruction, so it wipes for **any** load-modify-store caller — gate-4
holdings-update / re-bond flows carry the same latent wipe; PR-E0 enumerates
all callers, not just slash. There is also **no production LMDB write path** for
claimed epochs and **no C++ FFI** for `claimed_epochs_check_and_set` yet
(spec §6.3: "FFI surface deferred to its first consumer" — that consumer is
this PR). Disposition: §3 PR-E0.

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
| F-E5 | scope | F-S1 affects **every** `put_archival_bond_record` caller, not just slash | PR-E0 widened |
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

**Spec consequence (gate-1 pin, not yet applied — spec is the authority, §0):**
§4.0's "`Σ reward_P = budget` whenever `Σ Curve > 0`" refines to "`Σ minted ≤
budget`; the `≤ (N_P−1)`-atomic floor remainder is unminted (supply-safe),
consistent with §4.5." Land this wording in `REWARD_EMISSION_LEG.md` §4.0
before PR-E3 code.

**Single source of truth:** PR-E3's recompute **imports the canonical
`reward_arithmetic` crate** — not a third reimplementation — and the wallet
build path (`REWARD_EMISSION_LEG.md` §11) imports the **same** crate.
Zero-tolerance compare is sound only when both sides are bit-identical by
construction (project no-third-copy-of-an-arith-function rule). The verify is
the **third** Form-C consumer after the sim (`shekyl-staking-sim/reward.rs`,
`REWARD_EMISSION_LEG.md` §4.0) and the economics engine; if `reward_arithmetic`
does not yet exist as the shared canonical crate, a PR-E3 precursor extracts
the sim's Form-C into it and re-points the existing consumers — that extraction
is the single-source mechanism, not a fourth copy.

---

## 3. Sub-PR decomposition (sequenced)

Each sub-PR is short-lived off `dev`, fits the `06-branching.mdc` 5-day /
10-commit envelope, and lands behind the property that **no emission tx is
acceptable until PR-E3**. PR-E1/E2 are additive and inert; PR-E3 is the
single consensus-activating cut; PR-E4 is removal; PR-E5 is wiring/docs.
Function-body-replacement contracts (A1) freeze the inert surfaces so PR-E3 is
a body-fill, not a signature churn.

### PR-E0 — bond-state write-path correctness (precursor, substrate fix)

Scope: fix Finding **F-S1** (widened per **F-E5**). The root cause is that
`put_archival_bond_record` reconstructs a fresh `ArchivalBondValue` from scalar
args, dropping `claimed_settlement_epochs` + `first_paying_emission_height` —
so the wipe hits **every** load-modify-store caller, not only slash
(gate-4 holdings-update / re-bond round-trips carry the same latent wipe).
Disposition: make the writer load-modify-store (preserve all fields) or stop
routing field-preserving updates through the reconstructing path; **enumerate
every caller** of `put_archival_bond_record` as part of the fix, not just the
slash path. Add the C++ FFI for `claimed_epochs_check_and_set` /
`claimed_epochs_contains` and a full-bond LMDB writer. No emission behavior;
this is an independent correctness fix that PR-E3 depends on.
**Gate:** archival LMDB unit tests (`archival_substrate_lmdb.cpp`) extended to
assert claimed-epoch + first-paying-height survival across **slash apply/revert
*and* holdings-update / re-bond** cycles (all callers, per F-E5).
*Reversion: could fold into PR-E3, but it is pre-existing and independently
testable, so it splits per `15-deletion-and-debt.mdc` bisection discipline.*

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
4. **Work** — recompute `work_P(E)` from archival state; compare to
   `work_claim` (`checked_*` integer arithmetic, rule 20).
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
- **Substrate (PR-E0):** claimed-epoch + first-paying-height survival across
  slash apply/revert **and** holdings-update / re-bond cycles (all callers, F-E5).
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

1. **ML-DSA vin auth shape (F-E4)** — *proposal pinned in R1.A* for the round
   to attack (binding message, two auths, cSHAKE family). Remaining: is Auth-P
   necessary or does the leaf→`P_pubkey` derivation already pin P? ML-DSA-65-only
   confirmed.
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
7. **FFI marshaling boundary (§0.1, PR-E3)** — does `shekyl_emission_vin_verify`
   take a consensus-state *snapshot struct* (bond record, archival work state,
   tree root, height/epoch, economics params) by value, or *DB-read callbacks*
   into C++ LMDB? Snapshot is simpler to audit and keeps the verify pure;
   callbacks avoid copying large work state. Decide in the rounds; affects the
   `shekyl_archival_*`-family ABI shape.

### Round-1 open items (must close before PR-E3 code; F-E2/F-E3 consensus-load-bearing)

8. **Remainder disposition (F-E2)** — *recommendation pinned in R1.B*
   (floor + burn-the-dust, u128-numerator-first, canonical `reward_arithmetic`
   both sides). Closes when the gate-1 §4.0 spec wording lands and the crate
   import is confirmed for both verify and wallet-build.
9. **Intra-block `(P,E)` uniqueness (F-E3)** — pick check/set fusion within the
   connecting tx scope vs an explicit block-assembly uniqueness pass. Consensus
   double-mint hole until pinned.
10. **Holdings snapshot semantics (F-E6)** — §6.4.1 says holdings "compatible,"
    §5.3 "must match," but work is recomputed over per-epoch `held(P,E)` (§4.1),
    which may differ from *current* holdings if a gate-4 flow ran between epochs.
    Pin which snapshot the vin `holdings` field must match and how a mid-batch
    holdings change is handled.
11. **Same-tx backing + fee double-use (F-E7)** — §5.2 permits key-imaged fee
    `txin_to_key` alongside keyless membership-only backing; the threat model
    names mixing to launder a key-image spend. Decide whether one output may be
    both membership-only backing *and* a key-imaged fee input (possibly inside
    the §7.5 intra-epoch-unbacked model — state it) or the backing set must
    exclude same-tx-spent outputs.
12. **Zero-work / zero-reward emission (F-E8)** — §4.3's R-ceiling dead zone
    (`R > 1000·g(age)` → `scarcity_milli = 0`) plus `Curve(0)` lets a `P` with
    all shards in the dead zone recompute `work_P = 0`, `reward = 0`. Reject a
    zero-reward emission (block-space spam) or accept with zero vout? Also
    confirm `reward_arithmetic` widths (u64 for `Σ scarcity_milli` work
    accumulation; u128 for the `budget·capped_P` product, R1.B) so a legitimate
    large early-chain emission does not hit a wrong-width `checked_mul` reject.

## 9. Inherited forward-actions (`FCMP_MEMBERSHIP_ONLY.md` §9 carries)

- ML-DSA backing auth → **PR-E3 hard gate** (§2).
- FFI entry point + `shekyl-fcmp` wrapper + C++ call site + vin deserializer +
  emission KATs → **PR-E1/E2/E3/E5**.
- FFI-seam variant of the deser cross-type test → **PR-E1**.
- Vin-layer input-distinctness rule (if required) → **PR-E3** (§8 Q3).

## 10. Related documents

| Doc | Relationship |
|---|---|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consensus spec of record (§5–§7, §12) |
| [`FCMP_MEMBERSHIP_ONLY.md`](FCMP_MEMBERSHIP_ONLY.md) | Backing primitive; §7 quantum gate; §9 carries |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | gate 2/3 schema + `W` (work recompute substrate) |
| [`FOUNDATION_GENESIS_IDENTITY_SET.md`](FOUNDATION_GENESIS_IDENTITY_SET.md) | `HybridPublicKey` wire (§5) |
