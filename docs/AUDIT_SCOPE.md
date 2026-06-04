# FCMP++ 4-Scalar Leaf Circuit Audit Scope

> **Last updated:** 2026-04-04
>
> **Phase:** 9 — Security Audit Preparation

## Summary

Commission a scoped third-party security review of Shekyl's modification to
the FCMP++ curve tree leaf format, extending from 3 scalars (upstream Monero)
to 4 scalars (Shekyl, with PQC binding).

The 4th scalar (`H(pqc_pk)`) cryptographically binds a post-quantum public
key (ML-DSA-65) to each curve tree leaf. This is the core modification that
enables Shekyl's dual-layer security model: classical FCMP++ membership proof
+ quantum-resistant spend authorization. The audit must verify that this
extension preserves the zero-knowledge proof system's security properties.

---

## Scope

### In-Scope

1. **4-scalar leaf circuit modification**
   - Verify adding `H(pqc_pk)` as 4th Pedersen commitment term preserves:
     - **Soundness** — cannot prove membership for non-existent leaves
     - **Zero-knowledge** — proof does not leak which leaf was used
     - **Completeness** — honest prover can always produce a valid proof
   - Review chunk size and branching factor impact (Selene: 38, Helios: 18)
     with 4-scalar leaves vs. upstream 3-scalar leaves

2. **Shekyl fork modifications to monero-fcmp-plus-plus**
   - `FcmpPpLeaf` struct changes (3→4 scalar tuple, 96→128 bytes per leaf)
   - Circuit constraint additions for the 4th scalar
   - Generalized Schnorr Protocol (GSP) transcript changes
   - Key image and pseudo-output public input handling unchanged (verify)

3. **PQC commitment binding**
   - Circuit correctly constrains 4th leaf scalar = `H(pqc_pk)`
   - `H(pqc_pk)` computation: Blake2b-512 with domain separator
     `shekyl-pqc-leaf`, implemented in `rust/shekyl-fcmp/src/lib.rs`
   - Public input handling for `H(pqc_pk)` values in `shekyl_fcmp_verify()`
   - No information leakage about `pqc_pk` beyond the hash value

4. **Cross-check: proof verification FFI boundary**
   - `shekyl_fcmp_verify()` parameter handling (key images, pseudo-outs,
     PQC hashes, tree root, tree depth)
   - Verify that the Rust↔C++ FFI does not introduce data corruption,
     truncation, or misalignment of proof inputs

### Out-of-Scope

- Full FCMP++ proof system re-audit (covered by Veridise audit of upstream)
- KEM implementation (standard FIPS 203 ML-KEM-768)
- ML-DSA signing (standard FIPS 204 ML-DSA-65)
- Classical cryptography (Ed25519, Bulletproofs+)
- Networking, consensus, database, or RPC code
- Economic model (staking, fee burn, emission)

---

## Targeted Review: Unclamped Montgomery DH Composition

> **Scope:** Separate from the 4-scalar leaf audit above. Can be
> commissioned as a smaller targeted review or folded into a broader
> wallet-crypto audit. Must be completed before mainnet.

### Summary

Shekyl's hybrid KEM classical component performs unclamped Montgomery DH
over Curve25519 rather than RFC 7748 X25519. The protocol binds the X25519
public key to the Ed25519 view key via the standard Edwards→Montgomery
birational map and uses the view secret key directly as the unclamped
Montgomery scalar. Low-order Montgomery point rejection replaces X25519's
scalar clamping as the cofactor-safety mechanism.

This is a novel cryptographic composition with four properties that require
independent verification:

1. **Edwards→Montgomery correctness and edge cases**
2. **Unclamped DH safety** (scalar not clamped; cofactor safety via
   point rejection)
3. **Low-order point rejection** (completeness of the check)
4. **Identity composition** (view-scanning identity collapsed with
   encap identity: KCI implications, forward-secrecy properties)

For the protocol specification of these properties, see
`POST_QUANTUM_CRYPTOGRAPHY.md` §X25519 Binding to View Key and
§DH Semantics.

### In-Scope

1. **Edwards→Montgomery conversion correctness**
   - `ed25519_pk_to_x25519_pk`: birational map with non-canonical y
     rejection, identity rejection, and zero-u rejection
   - `ed25519_sk_as_montgomery_scalar`: unclamped scalar interpretation
   - `is_low_order_montgomery`: cofactor-8 low-order point detection
   - Verify: is the set of rejected inputs exactly the set of inputs
     that would produce exploitable DH outputs?
   - Verify: does sign-bit ambiguity (two Edwards points per Montgomery
     u-coordinate) cause any interoperability or security issue?
   - File: `rust/shekyl-crypto-pq/src/montgomery.rs`

2. **Unclamped DH safety analysis**
   - Sender-side: `construct_output`, `rederive_combined_ss` in `output.rs`
   - Recipient-side: `scan_output`, `scan_output_recover` in `output.rs`
   - `encapsulate` / `decapsulate` in `kem.rs`
   - Verify: with the view secret interpreted as `Scalar::from_bytes_mod_order`
     (already reduced mod ℓ), does the absence of clamping introduce any
     information leakage or DH-output bias beyond what low-order rejection
     addresses?
   - Verify: is there a timing or side-channel distinction between clamped
     and unclamped scalar multiplication in `curve25519-dalek`?
   - Files: `rust/shekyl-crypto-pq/src/output.rs`, `rust/shekyl-crypto-pq/src/kem.rs`

3. **Low-order point rejection completeness**
   - The check is `(Scalar::from(8) * point).is_identity()`
   - Verify: does this correctly identify all 12 low-order points on
     Curve25519's Montgomery form (orders 1, 2, 4, 8)?
   - Verify: no valid transaction ephemeral key can be falsely rejected
   - Verify: constant-time behavior of the rejection check
   - Test vectors: `docs/test_vectors/PQC_TEST_VECTOR_005_X25519_DERIVATION.json`

4. **KCI and forward-secrecy composition**
   - The view-scanning identity and KEM-encap identity are now the same key
     (view key in Edwards form = DH key in Montgomery form)
   - Verify: does this collapse introduce a key-compromise impersonation
     (KCI) path that did not exist when the keys were independent?
   - Verify: forward secrecy against a quantum adversary still depends only
     on the ML-KEM component, not on the classical DH
   - Verify: the composition `HKDF(unclamped_dh_ss || ml_kem_ss)` remains
     a secure combiner when the DH scalar is a mod-ℓ-reduced Ed25519 scalar

5. **FFI boundary and C++ integration**
   - `shekyl_view_pub_to_x25519_pub` FFI export
   - `get_account_address_from_str`: derives X25519, assembles 1216-byte
     `m_pqc_public_key`
   - `generate_pqc_key_material`: derives X25519 from view key at wallet keygen
   - `wallet2::load`: post-load consistency check
     (`m_pqc_secret_key[0..32] == m_view_secret_key`)
   - Verify: no C++ call site reintroduces clamping or constructs X25519
     keys independently of the canonical derivation
   - Files: `rust/shekyl-ffi/src/lib.rs`, `src/shekyl/shekyl_ffi.h`,
     `src/cryptonote_basic/cryptonote_basic_impl.cpp`,
     `src/cryptonote_basic/account.cpp`, `src/wallet/wallet2.cpp`

### Key Questions for the Reviewer

1. Does unclamped Montgomery DH with explicit low-order point rejection
   provide security equivalent to RFC 7748 X25519 for this use case
   (DH secret is an Ed25519 scalar, already reduced mod ℓ)?

2. Is `(Scalar::from(8) * point).is_identity()` the complete and correct
   low-order check for Curve25519's Montgomery form, covering all 12
   points of order dividing the cofactor?

3. Does the Edwards→Montgomery conversion produce correct results for
   all valid Ed25519 public keys, including points near the identity and
   points with non-zero torsion component?

4. Is the HKDF combiner `HKDF(unclamped_dh_ss || ml_kem_ss)` a sound
   KEM combiner when the DH input scalar is not independently random but
   is deterministically derived from the Ed25519 view key?

5. Does collapsing the scanning identity and the DH-encap identity into
   a single key introduce a KCI path, or is this equivalent to the
   existing Monero stealth-address model where the view key was already
   the ECDH identity?

---

## Materials to Provide

| Material | Location | Description |
|----------|----------|-------------|
| Forked monero-oxide repository | `shekyl/monero-oxide` (branch `fcmp++`) | Shekyl's fork with 4-scalar modifications |
| Diff from upstream | `git diff 92af05e0..HEAD` in monero-oxide | Precise changeset under review |
| `shekyl-fcmp` crate | `rust/shekyl-fcmp/` | Rust FCMP++ integration: leaf hashing, proof calls |
| `shekyl-crypto-pq` crate | `rust/shekyl-crypto-pq/` | PQC crypto: KEM, output construction/scanning, Montgomery conversion |
| `shekyl-ffi` crate | `rust/shekyl-ffi/` | FFI exports called from C++ |
| FCMP++ specification | `docs/FCMP_PLUS_PLUS.md` | Full technical reference |
| PQC specification | `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | PQC key derivation, DH semantics, X25519 binding |
| X25519 derivation test vectors | `docs/test_vectors/PQC_TEST_VECTOR_005_X25519_DERIVATION.json` | Pinned Ed25519→X25519 derivation, unclamped DH, combined_ss |
| 4-scalar leaf proof test vectors | `tests/data/fcmp_test_vectors/` | FCMP++ proof test vectors |
| Stressnet results | `stressnet_reports/` | 4-week sustained-load test data |

---

## Auditor Guidance

### Key questions for the auditor

1. Does adding a 4th Pedersen generator to the leaf commitment introduce any
   algebraic relationship that could be exploited to break soundness?

2. Does the 4th scalar's hash-based derivation (`H(pqc_pk)`) satisfy the
   binding requirements for the Pedersen commitment scheme?

3. Are the chunk widths (38/18) still optimal or safe with 128-byte leaves
   instead of 96-byte leaves? Are there performance or security edge cases
   at tree depth boundaries?

4. Does the GSP transcript correctly commit to all 4 leaf scalars, preventing
   selective disclosure or substitution of the PQC binding?

5. Is there any information leakage about the leaf index through the 4th
   scalar (e.g., timing, algebraic distinguishability)?

### Reference material

- Veridise FCMP++ audit report (upstream Monero, 3-scalar leaves)
- Generalized Schnorr Protocol construction papers
- Helios/Selene curve cycle specification

---

## Success Criteria

- **No soundness breaks found** — no way to prove membership for fabricated leaves
- **No zero-knowledge property violations** — proof reveals nothing about the spent leaf
- **Completeness preserved** — honest prover with valid leaf always succeeds
- **No binding weaknesses** — 4th scalar cannot be substituted without detection
- **Written report** with severity classifications (Critical / High / Medium / Low / Informational)

---

## Timeline

| Milestone | Target |
|-----------|--------|
| Stressnet gate passes (Phase 7.7) | Prerequisite |
| Audit engagement begins | After stressnet gate |
| Expected audit duration | 2–4 weeks |
| Deliverable | Written security assessment report |
| Finding remediation window | 2 weeks after report delivery |
| Re-audit of fixes (if needed) | 1 week |

---

## V3.1 PQC Multisig — Expanded Audit Surface

> **Added:** 2026-04-13
>
> **Scope:** V3.1 equal-participants PQC multisig protocol
> (PQC_MULTISIG.md). This section extends the audit scope above to cover
> the multisig-specific attack surface introduced in V3.1.

### In-Scope

1. **KDF domain separation** (`shekyl-crypto-pq/src/multisig_receiving.rs`)
   - 8 distinct HKDF-Expand labels for key/nonce derivation
   - No label collision across single-signer and multisig paths
   - Correct ikm/info binding for all derivation contexts

2. **HKDF-derived Ed25519 scalar for FCMP++ prover**
   - `derive_multisig_signing_key` produces a valid Ed25519 scalar
   - Bit-clamping behavior is correct for the FCMP++ circuit
   - No bias in derived scalars

3. **FCMP++ proof binding to Y_prover**
   - `multisig_pqc_leaf_hash` correctly binds the rotating prover's key
   - `fcmp_proof_commitment` in `ProverOutput` is collision-resistant
   - Equivocation detection via commitment comparison is sound

4. **Rotating prover assignment grinding resistance**
   - `rotating_prover_index` uses `cn_fast_hash(group_id || tx_secret_key_hash || reference_block_hash || output_index)`
   - Cost to grind a favorable assignment exceeds feasibility threshold
   - Output-index binding prevents per-output grinding

5. **SpendIntent validation pipeline** (14 checks, SS9.2–SS9.4)
   - Structural, temporal, chain-state, and balance validation
   - No bypass via malformed fields or edge-case timing

6. **Honest-signer invariants I1–I7** (`invariants.rs`)
   - All 7 invariants correctly enforced at their specified points
   - Assembly consensus (I6) rejects mixed commitments

7. **AEAD message encryption** (`encryption.rs`)
   - ChaCha20-Poly1305 with HKDF-derived per-message keys and nonces
   - Key zeroization after use
   - No nonce reuse across message types, senders, or counters

8. **CounterProof verification** (SS13.4)
   - 8-rule verification pipeline prevents forged advancement
   - Rescan-required state prevents advancement on stale local state

9. **Griefing defense** (`GriefingTracker`)
   - Per-output cost is bounded
   - Rate limiting prevents resource exhaustion from invalid outputs

### Out-of-Scope

- DKG ceremony (uses `dkg-pedpop`, covered by its own audit)
- GUI components (presentation layer, no crypto)
- Relay transport (network layer, no crypto)

### Deliverables

This scope overlaps with Phase 5 (adversarial review) and Phase 6
(cryptographer review). Findings from either review are tracked in
`docs/FOLLOWUPS.md` and remediated via targeted branches.

---

## Confidential stake claim verifier (Round 1 pin)

> **Status:** Round 1 closed on economics and **(B)**; **(C)** **closed on 3C** (2026-06-04)
> per [`design/CONFIDENTIAL_STAKING.md`](design/CONFIDENTIAL_STAKING.md) §6.4.3; implementation
> Round 2. Pre-mainnet review gate (same class as the leaf-layout audit).

### Summary

Shekyl's confidential staking model replaces cleartext `txin_stake_claim` + watermark
validation with **non-spending** claim transactions (`txin_stake_claim_v2`) that prove
**staking-subtree** FCMP++ membership (current root, **5-scalar leaf**), per-epoch
**stake-claim nullifiers** `N_S = x·G_S`, **`h_bind`** binding of `(tier, creation)`,
**arithmetic** window enforcement, and a **verifier-recomputed rational multiplier**
`N/D = tier_num·ΣK_S / SCALE`.

The verifier is a **derivative** of upstream FCMP++ + SAL machinery; it must not
weaken soundness, zero-knowledge, or inflation bounds established for spends.

### In-scope (review targets)

1. **`h_bind` binding (P1)** — Staking-subtree membership (5-scalar leaf) + verify the 5th
   scalar equals `H("stake-bind" ‖ tier ‖ creation)` for the **revealed** `(tier, creation)`.
   The **single revealed `tier`** must drive both the `h_bind` recompute and `tier_num`
   (loud-reject invariant; KAT). `creation` stamped into `h_bind` is the canonical
   **`eligible_height`** (item 2a), identical between the consensus stamp and the claim's
   window arithmetic.

2. **Window arithmetic (P1)** — `creation < S ≤ creation + tier_lock(tier)` for every claimed
   `S`, with **`creation ≜ eligible_height`** (matures past `MIN_AGE = 5`). No historical-root
   checkpointing (3C subsumes the former lower-bound mechanism).

2a. **Canonical stake-creation height — cross-subsystem conservation (P1).** The accrual
   anchor (claim verifier, in `h_bind`) and the `band_sum`-entry height (servo/economics)
   **must be one named definition** (`eligible_height`), referenced by both so they cannot
   drift. **`accrual-before-counted` is forbidden** — accrual anchored earlier than
   `band_sum` entry silently breaks §9 step-2 conservation (`Σ accrued > budget`, no reject;
   inflation). The dangerous drift is **cross-subsystem** (verifier vs servo, different code
   paths), not within the verifier; audit the single-source definition, not two hand-matched
   formulas. See [`CONFIDENTIAL_STAKING.md`](design/CONFIDENTIAL_STAKING.md) §2 (canonical
   block), §4.1, §9 step 2.

3. **Multiplier integrity (P1)** — Recompute `N = tier_num(tier)·Σ_S K_S`, `D = SCALE`;
   `reward = floor(N·amount/D)` ([`CONFIDENTIAL_STAKING.md`](design/CONFIDENTIAL_STAKING.md) §9).

4. **Entitlement (A) — reserve-DLEQ class + bounded remainder** — Relation
   `N·C~ − D·C_claim − C_ρ ∈ ⟨G⟩` with **committed** remainder `C_ρ`, BP+ range `0 ≤ ρ < D`,
   rounding toward under-claim, FS domain `shekyl-stake-entitlement-v1`. **Two traps:**
   (a) omitting `C_ρ` → rounding over-claim (P1 inflation); (b) revealing `ρ` →
   `amount mod (D/gcd)` deanonymization (P2). Both closed by commit-and-range (§6.4.1).

5. **Claim linkability (B1)** — `G_S`, `S_le64`, `MAX_EPOCHS_PER_CLAIM = 15`,
   ClaimLinkability vs SAL separation. **DDH split** (§6.3): `x·G_S` unlinkable from
   `x·Hp(O)` across independent NUMS bases — explicit audit assumption.

6. **Nullifier set separation + cross-tree atomicity** — Stake-claim table; reorg rewind;
   cross-tree stake/unstake `pop_block` atomicity (append-only leaves; claim-after-unstake).

7. **Inflation backstop (layered)** — Range proof; **(A)** bounded remainder; **`ρ_cap`** —
   separate failure modes; **`ρ_cap` does not fix tier/window forgery**.

8. **Consensus constants** — `SCALARS_PER_LEAF` per-tree param (`=5` subtree); 5th-position
   Selene NUMS generator (cbindgen guard + KAT); `h_bind` hash-to-field canonical/collision-safe (KAT).

9. **Rejected paths** — **3A** non-membership (novel ZK primitive); **3B** coarse window
   (P1 inflation); spend-and-restake; B2-primary; reveal remainder `ρ`; wire-supplied
   multiplier without recompute; persist `x` in wallet sealed blob; receipt-token liquid
   staking (distinct from confidential stake-UTXO transfer — see upstream §6.4.3).

### Out-of-scope

- Full re-audit of upstream Veridise FCMP++ (reference their report; review delta only).
- Economics calibration (LWMA window length, band count) — engineering/simulation, not
  proof soundness.
- Wallet actor FSM (see Phase 2b design doc); except where wallet bugs could broadcast
  structurally invalid claims caught by consensus.

### Deliverables

- Threat model + proof sketches for **`h_bind` binding**, **window arithmetic**, **rational
  multiplier**, **(A) bounded-remainder**, **(B1)** with verifier ordering.
- Test vectors: `STAKE_CLAIM_GS.json`, **`h_bind` / `creation` encoding**, 5th-position
  Selene generator + `SCALARS_PER_LEAF=5`, bounded-remainder entitlement vectors (Round 2).
  **Drop:** former `τ·H_t` / `C~_amt` encoding and historical-root-checkpoint vectors (3C
  supersedes).
- C++ verifier entry point (name TBD Round 2, e.g. `shekyl_fcmp_verify_stake_claim`)
  listed in release checklist when implemented.

### Related design pins

| Pin | Doc |
|-----|-----|
| Wire sketch | `CONFIDENTIAL_STAKING.md` §6.4.8 |
| Wallet mirror | `PHASE_2B_STAKE_LIFECYCLE.md` §8.5, §3.3.1 (R0-D8) |
| Staked leaf amendment | `FCMP_PLUS_PLUS.md` §15 |
| Inflation / `M` | `CONFIDENTIAL_STAKING.md` §9 |
| **(C) tier/window** | `CONFIDENTIAL_STAKING.md` §6.4.3 |

---

## Related Documents

- `docs/FCMP_PLUS_PLUS.md` — Full FCMP++ specification
- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` — PQC specification
- `docs/RELEASE_CHECKLIST.md` — Mainnet release gates
- `tests/stressnet/README.md` — Stressnet operational guide
- `shekyl-dev/docs/TESTNET_REHEARSAL_CHECKLIST.md` — Testnet rehearsal runbook
