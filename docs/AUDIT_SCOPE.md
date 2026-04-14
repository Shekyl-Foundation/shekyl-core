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

## Targeted Review: Edwards→Montgomery DH Composition

> **Added:** 2026-04-13
>
> **Scope:** Separate from the 4-scalar leaf audit above. Can be
> commissioned as a smaller targeted review or folded into a broader
> wallet-crypto audit.

### Summary

The X25519 component of the hybrid KEM no longer uses `x25519-dalek`'s
clamped DH. Instead, the Ed25519 view secret key is used directly as an
unclamped Montgomery scalar via `curve25519-dalek`, and the X25519 public
key is derived from the Ed25519 view public key via the standard
Edwards→Montgomery birational map `u = (1 + y) / (1 - y) mod p`.

This introduces a cryptographic composition (view-key-as-Montgomery-scalar,
unclamped DH, explicit low-order point rejection) that warrants reviewer
attention.

### In-Scope

1. **`montgomery.rs` conversion functions**
   - `ed25519_pk_to_x25519_pk`: Edwards→Montgomery public key conversion
     with non-canonical y rejection, identity rejection, and zero-u rejection
   - `ed25519_sk_as_montgomery_scalar`: unclamped scalar conversion
   - `is_low_order_montgomery`: cofactor-8 low-order point check
   - File: `rust/shekyl-crypto-pq/src/montgomery.rs`

2. **Unclamped DH sites in `output.rs`**
   - `construct_output`: sender-side DH with recipient X25519 pub
   - `scan_output` / `scan_output_recover`: recipient-side DH with
     ephemeral X25519 pub from `kem_ct_x25519`
   - `rederive_combined_ss`: proof-time DH re-derivation
   - Low-order point rejection on both sides (recipient: mandatory;
     sender: defense-in-depth)
   - File: `rust/shekyl-crypto-pq/src/output.rs`

3. **Unclamped DH in `kem.rs`**
   - `encapsulate` / `decapsulate`: same unclamped pattern
   - `keypair_generate`: test-only unclamped keygen
   - File: `rust/shekyl-crypto-pq/src/kem.rs`

4. **FFI export `shekyl_view_pub_to_x25519_pub`**
   - File: `rust/shekyl-ffi/src/lib.rs`

5. **C++ callers of the derived X25519 key**
   - `get_account_address_from_str`: derives X25519 from view key, assembles
     1216-byte `m_pqc_public_key`
   - `generate_pqc_key_material`: derives X25519 from view key for wallet
     keygen
   - `wallet2::load`: post-load consistency check
     `m_pqc_secret_key[0..32] == m_view_secret_key`

### Key Questions for the Reviewer

1. Does the unclamped Montgomery DH with explicit low-order point rejection
   provide equivalent security to X25519's clamped DH for this use case?

2. Is the low-order point rejection check (`mul_by_cofactor().is_identity()`)
   sufficient to prevent small-subgroup information leakage against the
   view secret scalar?

3. Does the Edwards→Montgomery conversion correctly handle all edge cases
   (non-canonical y, identity, torsion points)?

4. Is the composition "HKDF(unclamped_x25519_ss || ml_kem_ss)" sound when
   the X25519 scalar is an unreduced Ed25519 scalar?

---

## Materials to Provide

| Material | Location | Description |
|----------|----------|-------------|
| Forked monero-oxide repository | `shekyl/monero-oxide` (branch `fcmp++`) | Shekyl's fork with 4-scalar modifications |
| Diff from upstream | `git diff 92af05e0..HEAD` in monero-oxide | Precise changeset under review |
| `shekyl-fcmp` crate | `rust/shekyl-fcmp/` | Rust FCMP++ integration: leaf hashing, proof calls |
| `shekyl-ffi` crate | `rust/shekyl-ffi/` | FFI exports called from C++ |
| FCMP++ specification | `docs/FCMP_PLUS_PLUS.md` | Full technical reference |
| PQC specification | `docs/POST_QUANTUM_CRYPTOGRAPHY.md` | PQC key derivation, signing |
| Test vectors | `tests/data/fcmp_test_vectors/` | 4-scalar leaf proof test vectors |
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

## Related Documents

- `docs/FCMP_PLUS_PLUS.md` — Full FCMP++ specification
- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` — PQC specification
- `docs/RELEASE_CHECKLIST.md` — Mainnet release gates
- `tests/stressnet/README.md` — Stressnet operational guide
- `shekyl-dev/docs/TESTNET_REHEARSAL_CHECKLIST.md` — Testnet rehearsal runbook
