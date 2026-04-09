# PQC Multisig for Shekyl

> **Last updated:** 2026-04-07

## Purpose

This document specifies how multisignature spend authorization integrates with
Shekyl's post-quantum cryptography (`pqc_auth`) framework.

Multisig is implemented in two phases:

- **V3 (HF1):** Hybrid signature list — M individual hybrid signatures from
  the existing `Ed25519 + ML-DSA-65` scheme, carried in an extended
  `pqc_auth` container. Uses only proven, NIST-backed primitives.
- **V4 (future):** Lattice-based composite threshold signatures — a single
  compact on-chain signature produced by M-of-N participants via distributed
  key generation. Requires further research maturity before deployment.

## Design Principles

1. **Ship proven primitives first.** The V3 signature-list approach reuses the
   existing hybrid scheme (`scheme_id = 1`) with zero new cryptographic
   assumptions. Lattice threshold signatures are theoretically elegant but not
   yet NIST-standardized or thoroughly audited.
2. **Tolerate known costs over unmodeled risks.** The signature-list approach
   adds ~5.3 KB per additional signer. This is a known, bounded cost.
   Multisig transactions represent well under 1% of on-chain volume (Monero
   data confirms multisig usage is negligible — and on-chain
   indistinguishable from single-key spends due to secret-splitting). The
   aggregate chain growth impact is noise.
3. **Preserve full-chain anonymity.** All multisig coordination happens
   off-chain. On-chain transactions must remain indistinguishable from
   single-key spends at the FCMP++ membership proof layer. The `pqc_auth`
   field carries authorization material, not membership proof data.
4. **Protect long-duration staked outputs.** The primary use case driving V3
   multisig is securing staked positions locked for 25,000–150,000 blocks
   (35–208 days). A single key controlling a locked position for months is a
   single point of failure. Multisig staked outputs and claim transactions
   address this directly.

## Classical Multisig: Removed

Shekyl NG does not carry forward Monero's classical multisig implementation.

Monero's additive N-of-M scheme on Ed25519 uses secret-splitting to
reconstruct a single spend key from multiple participants. This design had
known bugs until mid-2022 (PR #8149), remains flagged as experimental, has
no formal specification, no completed third-party audit, and is CLI-only
with negligible real-world usage.

On the rebooted Shekyl chain, the classical multisig code is removed:

- `account_base::make_multisig` and its secret-splitting machinery are
  deleted from `account.cpp`.
- The MMS (Multisig Messaging System) transport layer is not carried forward.
- No classical multi-round signing coordination (MMS-style) exists in the
  codebase. PQC multisig uses file-based signing rounds; optional FROST
  SAL uses structured round coordination via Rust wallet crates.
- Wallet file format does not include classical multisig key state.
- `wallet2.cpp` contains zero classical multisig code: all multisig
  functions (`make_multisig`, `exchange_multisig_keys`, `export_multisig`,
  `import_multisig`, `sign_multisig_tx`, etc.), member variables, JSON
  serialization fields, MMS file handling, and scattered `m_multisig`
  guard branches have been removed.

**All multisig on Shekyl NG is PQC multisig (`scheme_id = 2`).**

### Architecture: Single Classical Key + PQC Multisig

The FCMP++ layer uses a single classical key. The M-of-N authorization
lives entirely in the `pqc_auth` layer:

```text
FCMP++ layer:       coordinator constructs membership proof → single proof covers all inputs
PQC auth layer:     M-of-N hybrid signatures → scheme_id = 2

Transaction building:
  1. Coordinator builds tx body with single classical key (standard FCMP++ proof construction)
  2. Coordinator computes canonical signing payload
  3. M signers each produce independent hybrid (Ed25519 + ML-DSA-65) signatures
  4. Coordinator assembles pqc_auths and broadcasts
```

This eliminates the dual-layer coordination problem entirely. There is no
sequencing of membership proof multisig rounds followed by PQC signing
rounds — the FCMP++ layer is always single-key, and the PQC layer handles
all multi-party authorization.

The classical key used at the FCMP++ layer is held by the coordinator (or
derived from a shared secret agreed during group setup). This key is NOT
the security boundary for multisig — the `pqc_auth` M-of-N threshold is.
An attacker who compromises the classical key alone cannot spend: they
still need M hybrid PQC signatures.

For Shekyl, multisig is being designed with wallet GUI integration from
launch, which should improve adoption over Monero's CLI-only experience —
but the power-user nature of the feature means it will never dominate
transaction volume.

---

## V3: Hybrid Signature List (HF1)

### Overview

A new `scheme_id` value extends the existing `PqcAuthentication` container to
carry M hybrid signatures and M hybrid public keys. Each signer produces a
complete `Ed25519 + ML-DSA-65` hybrid signature over the same canonical
signing payload. The verifier checks all M signatures independently.

### Scheme Registry Extension

| `scheme_id` | Name | Description |
|---|---|---|
| 1 | `ed25519_ml_dsa_65` | Single-signer hybrid (existing V3) |
| 2 | `ed25519_ml_dsa_65_multisig` | M-of-N hybrid signature list (V3 multisig) |

### PqcAuthentication Structure (scheme_id = 2)

```text
PqcAuthentication {
  u8   auth_version        // 1
  u8   scheme_id           // 2
  u16  flags               // reserved, must be 0
  u8   n_total             // N (total authorized signers)
  u8   m_required          // M (threshold)
  u8   sig_count           // number of signatures present (must equal m_required)
  HybridPublicKey[n_total] ownership_keys    // all N public keys (defines the multisig group)
  HybridSignature[m_required] signatures     // M signatures from the signing subset
  u8[m_required] signer_indices              // which of the N keys produced each signature
}
```

### Canonical Serialization

```text
MultisigPqcAuth {
  u8   auth_version
  u8   scheme_id           // 2
  u16  flags               // 0
  u8   n_total
  u8   m_required
  u8   sig_count
  // ownership keys: N × HybridPublicKey (same encoding as scheme_id=1)
  for i in 0..n_total:
    HybridPublicKey[i]
  // signatures: M × HybridSignature (same encoding as scheme_id=1)
  for i in 0..m_required:
    HybridSignature[i]
  // signer indices: M bytes, each in range [0, n_total)
  for i in 0..m_required:
    u8 signer_index[i]
}
```

Constraints:

- `auth_version = 1`
- `scheme_id = 2`
- `flags = 0`
- `1 <= m_required <= n_total <= MAX_MULTISIG_PARTICIPANTS` where
  `MAX_MULTISIG_PARTICIPANTS = 7`
- `sig_count == m_required`
- All `signer_index` values must be unique and in range `[0, n_total)`
- `signer_index` array must be sorted ascending (canonical ordering)
- Each `HybridPublicKey` and `HybridSignature` uses the same canonical
  encoding defined in `POST_QUANTUM_CRYPTOGRAPHY.md` for `scheme_id = 1`

#### Consensus participant cap

`MAX_MULTISIG_PARTICIPANTS = 7` is a consensus constant. Transactions with
`n_total > 7` are invalid and rejected at the structural validation stage.

Rationale: 5-of-7 is the realistic ceiling for treasury management. Going
above 7 signers pushes coordination complexity into "custom tooling"
territory with no practical benefit. The cap also bounds the maximum
`pqc_auth` size to ~37 KB (see Transaction Size Impact below), limiting
the DoS surface from oversized payloads. If a genuine need for 8+ signers
emerges, the V4 lattice threshold scheme (`scheme_id = 3`) produces a
compact fixed-size signature regardless of N.

### Wire Format Mapping (C++ ↔ Rust)

The C++ `pqc_authentication` struct is intentionally unchanged from
single-signer V3. It carries three fields:

```text
pqc_authentication {
  u8                scheme_id          // discriminator: 1 = single, 2 = multisig
  std::string       hybrid_public_key  // opaque blob
  std::string       hybrid_signature   // opaque blob
}
```

C++ never parses multisig internals. It reads `scheme_id`, passes the two
blobs to the Rust FFI verifier, and receives a boolean result. All
deserialization, structural validation, and cryptographic verification
happens inside `rust/shekyl-crypto-pq`.

For `scheme_id = 2`, the logical structure described above is packed into
the two blob fields as follows:

**`hybrid_public_key` blob (ownership material):**

```text
u8   n_total                           // N (total authorized signers)
u8   m_required                        // M (threshold)
HybridPublicKey[0]                     // canonical encoding, 1996 bytes each
HybridPublicKey[1]
...
HybridPublicKey[n_total - 1]
```

Expected blob size: `2 + (n_total × 1996)` bytes.

**`hybrid_signature` blob (authorization material):**

```text
u8   sig_count                         // must equal m_required from key blob
HybridSignature[0]                     // canonical encoding, 3385 bytes each
HybridSignature[1]
...
HybridSignature[sig_count - 1]
u8   signer_indices[0]                 // which key each signature corresponds to
u8   signer_indices[1]
...
u8   signer_indices[sig_count - 1]
```

Expected blob size: `1 + (sig_count × 3385) + sig_count` bytes.

**Why this mapping:**

- **No C++ struct changes.** The existing boost serialization for
  `pqc_authentication` handles `scheme_id` + two blob fields. Adding
  multisig requires zero changes to the C++ serialization layer.
- **Rust owns all parsing.** The Rust FFI function receives `scheme_id` and
  both blobs. For `scheme_id = 1`, it parses single key + single signature.
  For `scheme_id = 2`, it parses the multisig-encoded blobs. The dispatch is
  a match on `scheme_id` at the top of the verify function.
- **Cross-blob validation.** The Rust verifier must read `m_required` from
  the key blob and `sig_count` from the signature blob and confirm they
  match. This is an atomic check — both blobs are required to validate
  either.

**FFI function signature (planned extension):**

The existing `shekyl_pqc_verify` function signature already accepts
`scheme_id`, key blob, signature blob, and message. No new FFI entry points
are needed — the Rust implementation dispatches internally based on
`scheme_id`. This minimizes the C++ integration surface.

```rust
// Existing signature — unchanged
pub extern "C" fn shekyl_pqc_verify(
    scheme_id: u8,
    pubkey_blob: *const u8, pubkey_len: usize,
    sig_blob: *const u8, sig_len: usize,
    message: *const u8, message_len: usize,
) -> bool;
```

For `scheme_id = 2`, this function internally:
1. Deserializes the key blob into N `HybridPublicKey` values + threshold params
2. Deserializes the signature blob into M `HybridSignature` values + signer indices
3. Performs all structural and cryptographic validation checks
4. Returns `true` only if every check passes

### Signed Payload

The signed payload is identical to single-signer V3:

```text
signed_payload =
  cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(RctSigningBody)
    || H(serialize(RctSigPrunable))
    || serialize(PqcAuthHeader)
    || H(pqc_pk_0) || ... || H(pqc_pk_{N-1})
  )
```

Where `PqcAuthHeader` for multisig includes:

```text
PqcAuthHeader {
  auth_version
  scheme_id           // 2
  flags
  n_total
  m_required
  HybridPublicKey[n_total]   // all N ownership keys
}
```

All M signers sign the same payload. The signatures themselves are excluded
from the payload (no self-reference).

### Verification Rule

For `scheme_id = 2`, validation succeeds only if ALL of the following hold:

1. Standard transaction structural checks pass.
2. Existing privacy-layer checks pass.
3. Canonical PQC field decoding succeeds.
4. `m_required <= n_total <= 7` and `sig_count == m_required`.
5. `signer_index` array is sorted ascending with no duplicates.
6. For each of the M signatures at position `i`:
   - Let `key = ownership_keys[signer_indices[i]]`
   - `Ed25519.verify(signed_payload, sig.ed25519_sig, key.ed25519_pub)` succeeds
   - `ML-DSA.verify(signed_payload, sig.ml_dsa_sig, key.ml_dsa_pub)` succeeds
7. If any individual signature fails either check, the entire spend
   authorization is invalid.

### Adversarial Analysis

The following attacks were evaluated during the design of `scheme_id = 2`.
Each maps to a specific validation requirement in the Rust verifier.

**Attack 1: Scheme downgrade.**
An attacker takes a multisig UTXO (committed with `scheme_id = 2` group
identity) and submits a spend transaction with `scheme_id = 1`, using one
of the N individual keypairs to produce a valid single-signer hybrid
signature.

*Mitigation:* The output's ownership commitment must bind to the
`multisig_group_id`, which includes `scheme_id`, `n_total`, `m_required`,
and all N public keys. A `scheme_id = 1` spend produces a different
ownership derivation and fails to match the output. The consensus layer
must reject any spend where the spending `scheme_id` does not match the
output's committed scheme.

*Validation:* Hard reject in `tx_pqc_verify.cpp` before calling the Rust
FFI. The output's ownership material determines the expected scheme — the
spender cannot override it.

**Attack 2: Signer index manipulation.**
An attacker submits M signatures but manipulates `signer_indices` to map
two signatures to the same key (duplicate index), to an out-of-range
index, or to an unsorted order that could confuse the verifier.

*Mitigation:* The Rust verifier enforces three hard checks on
`signer_indices`:
1. Every index is in range `[0, n_total)`.
2. The array is sorted in strictly ascending order.
3. No duplicate values (implied by strict ascending, but checked explicitly).

*Validation:* Hard reject before any signature verification begins. Fail
fast on structural invalidity.

**Attack 3: Blob truncation or padding.**
An attacker submits a `hybrid_public_key` blob that claims `n_total = 3`
but contains fewer than 3 keys' worth of bytes (truncation), or extra
trailing bytes (padding), hoping the parser reads past the buffer or
ignores surplus data.

*Mitigation:* The Rust deserializer computes the expected blob size from
the declared parameters and rejects any mismatch:
- Key blob: exactly `2 + (n_total × 1996)` bytes.
- Signature blob: exactly `1 + (sig_count × 3385) + sig_count` bytes.

Any deviation — short, long, or with trailing garbage — is a hard reject.
No tolerant parsing. No ignoring of extra bytes.

*Validation:* Checked at the top of deserialization, before any key or
signature bytes are read.

**Attack 4: Key substitution in group.**
A participant who is one of N signers replaces another participant's
public key in the `ownership_keys` array with a second copy of their own
key, giving themselves control of M keys out of N and the ability to spend
unilaterally.

*Mitigation:* The `multisig_group_id` hash covers all N keys in their
canonical order. Any key substitution produces a different group ID that
does not match the output's commitment. The attacker cannot forge a valid
spend against an output they did not originally participate in creating.

*Validation:* The Rust verifier recomputes the group ID from the supplied
keys and confirms it matches the output's committed ownership material.
Additionally, the verifier rejects duplicate public keys in the
`ownership_keys` array — no two entries may be byte-identical.

**Attack 5: sig_count / m_required mismatch.**
The `sig_count` field lives in the signature blob; `m_required` lives in
the key blob. An attacker could set `sig_count > m_required` (submitting
extra signatures to reach a different threshold interpretation) or
`sig_count < m_required` (hoping the verifier short-circuits after fewer
checks).

*Mitigation:* The Rust verifier reads `m_required` from the key blob and
`sig_count` from the signature blob and enforces exact equality. This is a
cross-blob validation — the verifier must parse both blobs before
accepting either.

*Validation:* Hard reject if `sig_count != m_required`. This check
occurs after blob length validation but before any signature verification.

**Attack 6: Signature replay across groups.**
M valid signatures produced for multisig group A are submitted against a
different multisig group B's output, where some participants overlap
between groups.

*Mitigation:* The signed payload includes the `PqcAuthHeader`, which
contains all N ownership keys for the specific group. Signatures are
cryptographically bound to the exact group composition. Signatures
produced for group A's payload will fail verification against group B's
payload even if individual keys appear in both groups.

*Validation:* Inherent in the signature scheme — no additional check
needed beyond correct payload construction.

**Summary of verifier checks (execution order):**

| Order | Check | Reject condition |
|---|---|---|
| 1 | Scheme match | Spending `scheme_id` ≠ output's committed scheme |
| 2 | Parameter bounds | `n_total = 0`, `m_required = 0`, `m_required > n_total`, or `n_total > 7` |
| 3 | Key blob length | Actual length ≠ `2 + (n_total × 1996)` |
| 4 | Sig blob length | Actual length ≠ `1 + (sig_count × 3385) + sig_count` |
| 5 | Threshold match | `sig_count ≠ m_required` |
| 6 | Index validity | Any `signer_index ∉ [0, n_total)` |
| 7 | Index ordering | `signer_indices` not strictly ascending |
| 8 | Key uniqueness | Any two `ownership_keys` are byte-identical |
| 9 | Group ID match | Recomputed `multisig_group_id` ≠ output commitment |
| 10 | Signatures (×M) | Any Ed25519 or ML-DSA verification failure |

All checks 1–9 are structural and occur before any expensive cryptographic
operations. This fail-fast ordering minimizes the cost of rejecting
malformed transactions and limits denial-of-service exposure from
oversized multisig payloads.

### Transaction Size Impact

With per-input `pqc_auths`, the authorization overhead is now per-input.
A typical 2-in/2-out multisig transaction is larger than a single-input
equivalent because each input carries its own `PqcAuthentication` entry.

Measured per-signer contribution (from V3 phase-1 measurements):

- `HybridPublicKey`: 1,996 bytes
- `HybridSignature`: 3,385 bytes

| Configuration | Keys | Signatures | Auth overhead | vs single-signer |
|---|---|---|---|---|
| Single (scheme 1) | 1,996 | 3,385 | ~5,385 | baseline |
| 2-of-3 | 5,988 | 6,770 | ~12,769 | +7,384 (~2.4x) |
| 3-of-5 | 9,980 | 10,155 | ~20,153 | +14,768 (~3.7x) |
| 5-of-7 (max) | 13,972 | 16,925 | ~30,921 | +25,536 (~5.7x) |
| **7-of-7 (worst case)** | **13,972** | **23,695** | **~37,680** | **+32,295 (~7.0x)** |

The consensus cap `MAX_MULTISIG_PARTICIPANTS = 7` bounds the worst-case
`pqc_auth` overhead to ~37 KB. At sub-0.1% of transaction volume, even the
worst case has negligible impact on aggregate chain growth.

### Multisig Group Identity

The multisig group is defined by the ordered set of N `HybridPublicKey`
values. The group identity (for address generation and UTXO matching) is:

```text
multisig_group_id = cn_fast_hash(
  "shekyl-multisig-group-v1"
  || u8(n_total)
  || u8(m_required)
  || HybridPublicKey[0] || HybridPublicKey[1] || ... || HybridPublicKey[n_total-1]
)
```

Note: the domain separator string `"shekyl-multisig-group-v1"` is
provisional. The exact byte-level constant will be finalized in the Rust
implementation (`rust/shekyl-crypto-pq`) and published as part of the test
vector set to avoid any future collision risk with other hash-domain uses.

This deterministic group ID allows wallets to identify outputs belonging to
the multisig group during scanning.

### Staking Integration

Multisig staked outputs use the same `txout_to_staked_key` format. The
ownership key in the staking output references the multisig group identity.

Claim transactions (`txin_stake_claim`) from multisig staked outputs require
`scheme_id = 2` authorization with the same M-of-N threshold.

Lock enforcement is unchanged — the protocol-level lock applies regardless
of whether the staked output uses single-signer or multisig authorization.

### Wallet Implementation Notes

#### Key generation

Each participant generates their own hybrid keypair independently. The N
public keys are exchanged out-of-band and assembled into the multisig
group. No DKG protocol is required — this is a significant simplification
over the V4 lattice threshold approach.

#### Classical key management

The FCMP++ layer uses a single classical key held by the coordinator
(or derived from a shared secret agreed during group setup). This key is
NOT the multisig security boundary — it only satisfies the membership proof
layer. The M-of-N PQC threshold is the authorization gate.

#### Per-output PQC key coordination

Each signer must derive the per-output PQC keypair for the output being
spent from their copy of the KEM shared secret. The coordinator distributes
the ML-KEM ciphertexts during the signing request phase so each signer can
independently compute the combined shared secret and derive the correct
per-output PQC keypair for authorization.

#### Signing protocol (file-based)

The V3 signing transport is file-based exchange. No MMS or real-time
transport is required. The flow:

1. **Coordinator** builds the complete transaction body (prefix + RCT with
   single classical key).
2. **Coordinator** computes the canonical signing payload and exports it as
   a JSON blob file ("signing request").
3. Each **signer** imports the signing request, reviews the transaction
   details, signs with their hybrid keypair, and exports their signature
   blob file ("signature response").
4. **Coordinator** collects M signature response files, assembles the
   `pqc_auth` container, and broadcasts the transaction.

The Tauri wallet implements this as "Export signing request" / "Import
signature" / "Assemble and broadcast" actions. Real-time transport (MMS,
QR relay, peer-to-peer) is a follow-up UX enhancement, not a prerequisite.

#### ML-DSA signature non-determinism

ML-DSA signatures are non-deterministic (hedged signing per FIPS 204). The
same signer signing the same payload twice produces different valid
signatures. Implications:

- Signature blobs must not be compared for equality or cached across
  signing attempts.
- If a signer needs to re-sign (network failure, timeout, changed their
  mind), the coordinator accepts the replacement and discards the old
  signature.
- The coordinator uses "replace by signer index" semantics, not
  deduplication.

#### Transaction hash finality

The transaction hash includes the full serialized `pqc_auth` including
signatures. Different signing subsets for the same M-of-N group (e.g.,
signers {0,1} vs {0,2} in a 2-of-3) produce different tx hashes. The tx
hash is finalized only after the coordinator assembles all M signatures.

Signers operate on the canonical signing payload, which is deterministic
and independent of the signing subset. The coordinator must not share a
"final tx hash" with signers before assembly is complete.

#### GUI integration

The Tauri wallet should expose multisig group creation and signing
coordination in the GUI, especially integrated with the staking flow
("Create multisig staking position"). See Rollout Dependencies below for
the staking FFI prerequisite.

### Rollout Dependencies

#### Phase split

The multisig feature ships in two sub-phases to avoid blocking on the
Tauri↔wallet2 FFI staking bridge (which is currently a stub):

- **Phase A: Multisig spends.** Regular send/transfer transactions with
  `scheme_id = 2`. Requires only the PQC multisig Rust implementation,
  FFI dispatch, consensus validation, and wallet CLI/GUI signing flow.
  No dependency on staking FFI.

- **Phase B: Multisig staking.** Creating multisig staked outputs and
  claiming rewards with M-of-N authorization. Blocked by: single-signer
  staking must be wired through the Tauri↔wallet2 FFI bridge first.
  The GUI `stake` and `get_staking_info` commands in `commands.rs` are
  currently error stubs.

Phase B must not block Phase A. Multisig spends are useful independently
of staking integration.

#### Codebase removals (blocking Phase A) — DONE

Classical multisig code has been removed:

- ~~Remove `account_base::make_multisig` and classical secret-splitting from
  `account.cpp`.~~ Done.
- ~~Remove MMS transport code.~~ Done (`message_store.h/cpp`,
  `message_transporter.h/cpp` deleted; `wallet2.h` no longer includes them).
- ~~Remove or gate any wallet paths that produce v2 multisig transactions.~~ Done.
  All classical multisig types (`multisig_info`, `multisig_sig`,
  `multisig_kLR_bundle`, `multisig_tx_set`), public/private multisig API
  methods, and multisig wallet state fields have been removed from `wallet2.h`.
- ~~Confirm no residual classical multisig state in wallet file serialization.~~
  Done. Boost serialization functions and FIELD() entries for multisig types
  have been removed.
- ~~Remove classical multisig from wallet API layer
  (`wallet2_api.h`, `wallet.h`, `wallet.cpp`, `pending_transaction.cpp`).~~
  Done. Removed `MultisigState` struct, all virtual multisig declarations,
  `publicMultisigSignerKey`, `signMultisigParticipant`, multisig helper
  functions, multisig transaction creation/restore, and multisig threshold
  checks from PendingTransaction commit path.

### Wallet File Format

Adding PQC multisig state to the wallet requires a file format version
bump:

- New fields: `m_pqc_multisig_keys` (the N hybrid public keys defining the
  group), `m_pqc_multisig_group_id` (the deterministic group identity
  hash), `m_pqc_multisig_n` and `m_pqc_multisig_m` (group parameters).
- Existing single-signer V3 wallets opened with multisig-aware code find
  these fields absent — default to empty/none. No migration needed.
- New multisig wallets are created fresh. Converting a funded wallet to
  multisig is not supported (same constraint as Monero).
- The wallet file version number is bumped. Older wallet binaries that
  encounter the new format must refuse to open with a clear error message,
  not silently corrupt.
- Classical multisig wallet state (`m_multisig_keys`,
  `m_multisig_threshold`, etc.) is removed from the serialization format
  entirely.

### FFI Contract

#### Consensus path

The existing `shekyl_pqc_verify` FFI function handles both `scheme_id = 1`
and `scheme_id = 2` via internal dispatch. It returns a bare `bool`. This
is intentional — the consensus path must be minimal with no error-message
side channels.

#### Debug/logging path

A separate function is provided for wallet-side debugging and operator
logging:

```rust
#[repr(u8)]
pub enum PqcVerifyError {
    Ok = 0,
    InvalidSchemeId = 1,
    BlobLengthMismatch = 2,
    ParameterBoundsViolation = 3,
    ThresholdMismatch = 4,
    SignerIndexOutOfRange = 5,
    SignerIndexNotSorted = 6,
    DuplicateOwnershipKey = 7,
    GroupIdMismatch = 8,
    Ed25519FailureAtIndex = 9,    // low nibble: signer index
    MlDsaFailureAtIndex = 10,     // low nibble: signer index
    DeserializationError = 255,
}

pub extern "C" fn shekyl_pqc_verify_debug(
    scheme_id: u8,
    pubkey_blob: *const u8, pubkey_len: usize,
    sig_blob: *const u8, sig_len: usize,
    message: *const u8, message_len: usize,
) -> u8;  // returns PqcVerifyError discriminant
```

This function is used only by the wallet and logging paths, never in
consensus validation. The error enum matches the adversarial analysis check
ordering so operators can pinpoint exactly where validation failed.

### Fuzz Testing Requirements

The Rust deserializer is the entire security boundary for multisig — C++
passes opaque blobs and trusts the boolean result. Malformed blobs are the
primary DoS vector.

Required `cargo-fuzz` targets (hard prerequisite before testnet):

| Target | Input | Coverage |
|---|---|---|
| `fuzz_multisig_key_blob` | Random bytes → `MultisigKeyContainer::from_canonical_bytes` | Length checks, parameter bounds, key parsing |
| `fuzz_multisig_sig_blob` | Random bytes → `MultisigSigContainer::from_canonical_bytes` | Length checks, index validation, signature parsing |
| `fuzz_multisig_verify` | Random `(scheme_id, key_blob, sig_blob, message)` → `shekyl_pqc_verify` | Full dispatch path including cross-blob validation |
| `fuzz_group_id` | Random key arrays → `multisig_group_id` computation | Hash stability, no panics on edge-case inputs |

Minimum bar: **10M iterations per target with zero panics, zero OOM, zero
unbounded allocations.** Any panic is a bug. Any allocation proportional to
attacker-controlled length fields without bounds checking is a
vulnerability.

The fuzz harness should include a "valid-then-corrupt" mode: generate a
structurally valid multisig blob, then flip random bits/truncate/extend to
exercise the boundary between valid and invalid inputs.

---

## FROST Threshold SAL for FCMP++ Classical Keys

> **Status: DEFERRED to V4.** FROST SAL is architecturally incompatible with
> HKDF-derived per-output `y`. In V3, `y` is deterministically derived from
> the KEM shared secret via `derive_output_secrets`, making it per-output and
> not FROST-shareable. FROST SAL requires `y` to be a DKG group key (constant
> per wallet, not per output). The V4 resolution is a Carrot-style address
> scheme where multisig wallets use DKG-shared `y` and single-sig wallets use
> HKDF-derived per-output `y`, gated by address type. The code below remains
> for reference and V4 implementation.

### Overview

While the V3 PQC multisig layer (`scheme_id = 2`) handles M-of-N hybrid
signature authorization, the FCMP++ classical layer (the membership proof)
is constructed by a single coordinator holding the spend key `x`. This
creates a single-point-of-failure at the classical key layer.

**FROST SAL** (Flexible Round-Optimized Schnorr Threshold — Spend
Authorization and Linkability) addresses this by threshold-sharing the
classical spend key `y` across N participants using `modular-frost`'s
`Ed25519T` ciphersuite. The coordinator retains `x` (not shared) and the
FROST group key `Y = y * T` replaces the single-signer `y` in the FCMP++
proof construction.

### Architecture

```text
Classical key decomposition:  O = x*G + y*T
  x: held by coordinator (not threshold-shared)
  y: FROST threshold-shared across N participants via DKG

FCMP++ proof flow (multisig):
  1. Coordinator creates FrostSalSession per input (rerandomizes output)
  2. Coordinator exports signing request with FROST round-1 data
  3. M participants produce FROST signing shares
  4. Coordinator aggregates shares → SpendAuthAndLinkability
  5. Coordinator calls prove_with_sal() → complete FCMP++ proof
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `FrostSalSession` | `rust/shekyl-fcmp/src/frost_sal.rs` | Per-input FROST SAL state machine |
| `FrostSigningCoordinator` | `rust/shekyl-fcmp/src/frost_sal.rs` | Nonce aggregation, share collection, multi-input orchestration |
| `prove_with_sal()` | `rust/shekyl-fcmp/src/proof.rs` | Proof construction from pre-aggregated SAL |
| `DkgSession` | `rust/shekyl-fcmp/src/frost_dkg.rs` | State-machine DKG ceremony (3-round PedPoP) |
| `SerializedThresholdKeys` | `rust/shekyl-fcmp/src/frost_dkg.rs` | Threshold key serialization/deserialization |
| `MultisigDkgSession` | `rust/shekyl-wallet-core/src/multisig/dkg.rs` | Wallet-level DKG orchestration wrapper |
| `MultisigGroup` | `rust/shekyl-wallet-core/src/multisig/group.rs` | Group metadata, PQC keypairs, threshold keys |
| `MultisigSigningSession` | `rust/shekyl-wallet-core/src/multisig/signing.rs` | Wallet-level multi-input signing orchestration |
| FROST SAL FFI | `rust/shekyl-ffi/src/lib.rs` | C ABI for session/coordinator/signer lifecycle |
| FROST DKG FFI | `rust/shekyl-ffi/src/lib.rs` | C ABI for key import/export/validation |
| Multisig RPC handlers | `rust/shekyl-wallet-rpc/src/multisig_handlers.rs` | JSON-RPC endpoints for signing coordination |

**Note:** C++ wallet FROST integration (`wallet2.cpp`/`wallet2_ffi.cpp`)
has been removed. All FROST multisig logic now lives in the Rust wallet
crates (`shekyl-wallet-core`, `shekyl-wallet-rpc`). The Rust FFI functions
remain behind `#[cfg(feature = "multisig")]` for any future C++ consumers.

### DKG Setup

Before FROST signing, participants must complete a Distributed Key
Generation (DKG) ceremony to produce `ThresholdKeys<Ed25519T>`. The DKG
uses the `dkg-pedpop` crate's `KeyGenMachine` state machine:

1. `KeyGenMachine::new(params, context)` → round-1 coefficients
2. `SecretShareMachine::generate_secret_shares(rng, commitments)` → encrypted shares
3. `KeyMachine::calculate_share(rng, shares)` → `BlameMachine`
4. `BlameMachine::complete()` → `ThresholdKeys<Ed25519T>`

`MultisigDkgSession` in `shekyl-wallet-core` wraps this state machine
with type-safe round transitions and error handling. DKG messages are
exchanged as files (air-gap compatible); they are **not** exposed over
RPC due to the `dkg-pedpop` types lacking `serde` serialization support.

The resulting `ThresholdKeys` are serialized and stored in `MultisigGroup`
alongside the PQC keypair material and group metadata.

### Signing Protocol (Rust-native)

The FROST signing protocol is orchestrated through `MultisigSigningSession`
in `shekyl-wallet-core` and exposed via JSON-RPC in `shekyl-wallet-rpc`:

1. **`multisig_create_signing`**: Creates a `MultisigSigningSession` with
   `FrostSalSession` per input and a `FrostSigningCoordinator`.

2. **`multisig_sign_preprocess`**: The local participant generates FROST
   commitments (nonces) for all inputs.

3. **`multisig_sign_add_preprocess`**: Commitments from remote participants
   are added to the coordinator.

4. **`multisig_sign_nonce_sums`**: Once all preprocesses are collected, the
   coordinator computes aggregated nonce sums per input.

5. **`multisig_sign_own`**: The local participant produces FROST signing
   shares using the aggregated nonces.

6. **`multisig_sign_add_shares`**: Shares from remote participants are
   added to the coordinator.

7. **`multisig_sign_aggregate`**: The coordinator aggregates all shares
   into `SpendAuthAndLinkability` pairs and calls `prove_with_sal()` to
   produce the final FCMP++ proof.

All byte fields in RPC are hex-encoded for transport. PQC hybrid
signatures are assembled alongside the FROST proof as in non-FROST mode.

### Transition to Lattice Threshold

FROST SAL provides classical threshold signing as a bridge. When lattice
threshold research matures sufficiently for a NIST-backed standard, the
FROST SAL layer will be replaced by a lattice threshold scheme that
provides quantum resistance for both the classical and PQC layers.

---

## V4: Lattice-Based Composite Threshold (Future)

### Motivation

The V3 signature-list approach is functional but scales linearly in
transaction size with the number of signers. For configurations beyond
3-of-5, the size overhead becomes material. A lattice-based threshold
scheme produces a single compact signature regardless of M or N.

### Core Concept

In lattice cryptography, the hardness assumption is finding short vectors
in a high-dimensional lattice (Module-LWE / SIS problems).

- Each participant's private key is a short vector `s_i` (small
  coefficients).
- The composite public key is the vector sum:
  `pk = s_1 + s_2 + ... + s_N`
- To sign, any M participants each produce a partial short vector `p_j`.
- The verifier receives the sum: `sigma = p_1 + p_2 + ... + p_M`
- Verification succeeds if `sigma` is sufficiently short AND satisfies the
  lattice equation for `pk`.

The threshold property comes from the fact that only M short vectors are
needed to reach a valid short `sigma`; fewer than M vectors fail the
equation. The remaining (N-M) vectors stay secret.

### Advantages Over Signature List

- Single compact `pqc_auth` field (~7-9 KB for any M-of-N, vs linear
  scaling).
- True threshold security (no single party can spend).
- Single-equation verification (constant time, independent of N).
- Preserves full-chain anonymity (threshold math happens off-chain).

### Barriers (Realistic)

- **Research maturity:** Threshold lattice signatures (e.g. "Threshold
  Dilithium" variants from 2024-2026 literature) are not NIST-standardized.
  Specific scheme selection requires further survey.
- **DKG complexity:** Distributed key generation must be secure against
  malicious participants. This adds protocol steps and attack surface that
  the V3 approach avoids entirely.
- **Performance:** Lattice operations are heavier than Ed25519. Partial
  signing rounds add latency during coordination (not during on-chain
  validation).
- **Audit requirements:** A formal security review of the chosen threshold
  scheme is mandatory before consensus activation.

### Integration Plan

| `scheme_id` | Name | Target |
|---|---|---|
| 3 | `lattice_threshold_composite` | V4 (HF2+) |

The `PqcAuthentication` container carries the composite public key and
summed signature. Verification is a single lattice relation check.

### Rollout Phases

Shekyl uses a feature-driven upgrade policy (see `docs/UPGRADE_POLICY.md`).
Phases advance when their prerequisites are met, not on a fixed calendar.
Lattice threshold standards are not yet finalized by NIST.

| Phase | Feature | Prerequisite |
|---|---|---|
| V4.0 | Scheme selection and Rust prototype in `rust/shekyl-crypto-pq` | V3 mainnet stabilized |
| V4.1 | DKG protocol implementation in Tauri wallet | V4.0 prototype reviewed |
| V4.2 | Testnet experiment with `scheme_id = 3` behind feature gate | V4.1 complete |
| V4.3 | Security audit and mainnet activation (HF2+) | V4.2 go report; formal audit |

### Hybrid Fallback

During the V4 transition period, `scheme_id = 2` (signature list) remains
valid. Wallets can offer both options. `scheme_id = 3` becomes mandatory
only after a grace period following activation.

### Open Research Items

- Select a specific lattice threshold scheme from recent literature and
  evaluate against Shekyl's size/performance constraints.
- Define the DKG protocol and its security model (honest-majority vs
  dishonest-majority).
- Benchmark signing time, verification time, and tx size for realistic
  M-of-N configurations.
- ~~Publish test vectors once the Rust prototype is complete.~~
  Published as `docs/PQC_TEST_VECTOR_002_MULTISIG.json` (wire-format sizes,
  verification pipeline, and adversarial inputs for `scheme_id = 2`).

---

## Use Cases

### Treasury Management

Organizations holding significant SHEKYL — development funds, community
treasuries, business operating accounts — require that no single person can
unilaterally spend. A 2-of-3 or 3-of-5 multisig ensures cooperative
authorization.

### Staking Security

Staked positions locked at the long tier (150,000 blocks / ~208 days)
represent months of illiquidity with real yield at stake. A single key
controlling that position is a single point of failure for 7 months.
Multisig staked outputs require M-of-N authorization for claim transactions
and for the eventual unlock-and-spend.

### Inheritance and Recovery

A 2-of-3 setup where the owner holds two keys and a trusted party holds one
allows normal day-to-day operation (owner uses their two keys) while
providing estate recovery if the owner is incapacitated.

### Escrow

Buyer, seller, and arbitrator each hold a key in a 2-of-3. Direct
settlement requires buyer + seller agreement. Disputes are resolved by the
arbitrator co-signing with the aggrieved party.

---

## Privacy Considerations

### On-Chain Indistinguishability

For V3 (signature list), multisig transactions are distinguishable from
single-signer transactions by their `scheme_id` and larger `pqc_auth` size.
This is a privacy trade-off accepted for V3 given negligible multisig
volume.

For V4 (lattice threshold), the composite signature is the same size
regardless of M or N, but the `scheme_id` still differs from single-signer.
True indistinguishability would require all transactions to use the same
scheme — this is a V5+ consideration if multisig adoption grows
significantly.

### FCMP++ Anonymity

Neither V3 nor V4 multisig affects the FCMP++ membership proof layer. The
`pqc_auths` field carries authorization material, not membership proof data.
The anonymity set (full UTXO set) is unchanged.

---

## Relationship to Other Documents

| Document | Relevant changes |
|---|---|
| `POST_QUANTUM_CRYPTOGRAPHY.md` | `scheme_id` registry extended; deferred scope updated; classical multisig removed from implementation notes |
| `V3_ROLLOUT.md` | Multisig tx size guidance with `MAX_MULTISIG_PARTICIPANTS = 7` ceiling; classical multisig removal noted; staking FFI dependency flagged |
| `DESIGN_CONCEPTS.md` | Staking section references multisig as operational security option |
| `STAKER_REWARD_DISBURSEMENT.md` | Claim transactions support multisig authorization |
| `RELEASE_CHECKLIST.md` | Multisig testing items and fuzz targets to be added |
| `account.cpp` | `make_multisig` and classical secret-splitting code removed |
| `wallet2.h` | All classical multisig types, methods, fields, and MMS integration removed |
| `wallet_errors.h` | `mms_error`, `no_connection_to_bitmessage`, `bitmessage_api_error` removed |
| `wallet/api/wallet2_api.h` | `MultisigState` struct, all virtual multisig API declarations removed |
| `wallet/api/wallet.h` | Multisig method override declarations removed |
| `wallet/api/wallet.cpp` | Multisig helpers, implementations, `PRE_VALIDATE_BACKGROUND_SYNC` multisig guard, `signMultisigParticipant` removed |
| `wallet/api/pending_transaction.cpp` | `multisigSignData`, `signMultisigTx`, multisig threshold check removed |
| `device_trezor/protocol.*` | `translate_klrki`, `MoneroMultisigKLRki`, `m_multisig`, and cout decryption removed |
| `wallet_tools.cpp` | `m_multisig*` wallet resets removed |
| `trezor_tests.cpp` | `multisig_sigs.clear()` removed |
| `functional_tests/multisig.py` | Deleted (classical multisig functional test) |
| `cold_signing.py` | `multisig_txset` assertion removed |

---

## References

- Monero multisig documentation: <https://docs.getmonero.org/multisignature/>
- Monero MMS guide: <https://web.getmonero.org/resources/user-guides/multisig-messaging-system.html>
- Esgin et al., "Practical Exact Proofs from Lattices" (2019)
- Lyubashevsky et al., lattice-based ring/group signature constructions (2022-2026)
- NIST PQC standards: ML-DSA (FIPS 204), ML-KEM (FIPS 203)
- Shekyl PQC spec: `docs/POST_QUANTUM_CRYPTOGRAPHY.md`
- Shekyl staker disbursement: `docs/STAKER_REWARD_DISBURSEMENT.md`
