# FCMP++ Full-Chain Membership Proofs — Specification

> **Last updated:** 2026-04-07
>
> **Parent document:** `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

## Purpose

This document is the comprehensive technical reference for Shekyl's FCMP++
(Full-Chain Membership Proofs) implementation. It covers the cryptographic
structure, consensus rules, database schema, wallet integration, and
performance characteristics.

FCMP++ replaces ring signatures entirely. Every spend proves membership in
the *entire* UTXO set without revealing which output is being spent. Combined
with Shekyl's hybrid post-quantum spend authorization, this gives every
transaction full-UTXO-set anonymity with quantum-resistant ownership — a
combination no other cryptocurrency offers.

This is the consensus-critical reference for implementors working on FCMP++
verification in `src/cryptonote_core/blockchain.cpp` and the Rust FFI layer
in `rust/shekyl-fcmp/`.

---

## 1. Curve Tree Structure

The FCMP++ anonymity set is the entire UTXO set, represented as a **curve
tree** — a Merkle-like hash tree built over an elliptic curve cycle.

### Helios/Selene Alternating Layers

The tree alternates between two elliptic curve groups:

| Layer | Curve | Role |
|-------|-------|------|
| Leaves (layer 0) | Selene | 4-scalar tuples representing outputs |
| Layer 1 | Helios | Hashes of Selene leaf groups |
| Layer 2 | Selene | Hashes of Helios layer-1 groups |
| Layer 3 | Helios | ... |
| ... | alternating | ... |
| Root | depends on depth | Single hash committing to the entire tree |

**Helios** and **Selene** form a prime-order curve cycle (each curve's
scalar field is the other's base field), enabling efficient recursive hash
computations. The alternating structure allows the zero-knowledge proof to
"step through" the tree without revealing which path was taken.

The tree is **append-only**: each new output is **indexed into the tree when
it is created** (in the block that contains the transaction). **Spend
maturity** (coinbase unlock, regular spendable age, and FCMP++
`referenceBlock` depth rules) is enforced by consensus separately — outputs
are not withheld from the tree until unlock. Spent outputs remain in the tree
permanently. Removing spent outputs would reveal which output was spent,
breaking the anonymity guarantee.

### 4-Scalar Leaf Format

Each UTXO occupies one leaf in the tree. A leaf is a 4-scalar tuple
(128 bytes):

```text
Leaf = { O.x, I.x, C.x, H(pqc_pk) }
```

| Scalar | Source | Meaning |
|--------|--------|---------|
| `O.x` | x-coordinate of output public key | Identifies the output |
| `I.x` | x-coordinate of key image | Prevents double-spending |
| `C.x` | x-coordinate of Pedersen commitment | Binds the hidden amount |
| `H(pqc_pk)` | `shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)` | Binds the ML-DSA-65 public key |

The 4th scalar (`H(pqc_pk)`) is Shekyl-specific. It cryptographically
binds the post-quantum public key to the curve tree leaf, creating the
foundation for dual-layer security. Upstream Monero's FCMP++ uses a
3-scalar leaf; Shekyl extends this to 4 scalars.

**x-only representation:** All three point scalars (`O.x`, `I.x`, `C.x`)
are the x-coordinates only — y-coordinates are not stored in the tree or
included in the flat leaf array. The circuit recovers y from x via the
curve equation inside its `on_curve` gadget. This means a single output's
leaf data is exactly 4 field elements (128 bytes), not 6 or 8.

The hash function for the 4th scalar uses Blake2b-512 with domain separator
`shekyl-pqc-leaf`, implemented in `rust/shekyl-fcmp/src/lib.rs` and
exposed via `shekyl_fcmp_pqc_leaf_hash()`.

---

## 2. Dual-Layer Security Model

FCMP++ transactions achieve quantum-resistant spend authorization through two
independent but linked layers. Both must hold for a spend to be valid.

### Layer 1: FCMP++ Membership Proof (In-Circuit PQC Commitment)

The FCMP++ proof is a zero-knowledge argument that the prover knows openings
to leaves in the curve tree whose 4th scalars are the `H(pqc_pk)` values
supplied as public inputs. The proof does not reveal which leaves are spent
— the entire UTXO set serves as the anonymity set.

The `H(pqc_pk)` values are passed to `shekyl_fcmp_verify()` as the
`pqc_pk_hashes_ptr` parameter. The proof succeeds only if the prover
committed to leaves containing those exact hashes.

### Layer 2: Per-Input PQC Signature (Authorization)

Each input carries a `PqcAuthentication` structure containing a hybrid
Ed25519 + ML-DSA-65 signature over a canonical payload. The signature proves
that the signer possesses the ML-DSA-65 secret key corresponding to the
`pqc_pk` whose hash was proven in-circuit.

### Security Guarantee

Together, the two layers guarantee:

- **Layer 1** proves: "the spent output exists in the tree and its PQC
  public key hash is `H(pqc_pk)`" (anonymous, zero-knowledge).
- **Layer 2** proves: "the signer knows the secret key for `pqc_pk`"
  (non-interactive, binding).

An attacker who breaks only EC discrete log cannot forge the ML-DSA-65
signature. An attacker who breaks only ML-DSA cannot forge the FCMP++ curve
tree membership proof (which is classical). The hybrid construction requires
both to be compromised simultaneously.

---

## 3. Proof Format

### FCMP++ Membership Proof

The proof blob (`fcmp_pp_proof` in `rctSigPrunable`) is an opaque byte
array produced by the Rust `shekyl_fcmp_prove()` function. It encodes:

- Generalized Schnorr Protocol (GSP) transcripts for each input
- Curve tree path commitments across Helios/Selene layers
- Key image linkability proofs
- Pseudo-output balance commitments

The proof verifier (`shekyl_fcmp_verify()`) checks:

| Property | What is verified |
|----------|-----------------|
| Membership | Referenced leaves exist in the curve tree at `tree_root` |
| Key images | Match the key images in the transaction inputs |
| Pseudo outputs | Match the Pedersen commitments (balance proof) |
| PQC binding | `H(pqc_pk)` values match the committed 4th leaf scalars |

### Proof Size

The proof size scales with the number of inputs and the tree depth:

| Inputs | Estimated proof size |
|--------|---------------------|
| 1 | ~2.5 KB |
| 2 | ~4.5 KB |
| 4 | ~8.5 KB |
| 8 (max) | ~16.5 KB |

---

## 4. Transaction Format

### RCTTypeFcmpPlusPlusPqc (type = 7)

Shekyl's only non-coinbase transaction type. Defined in `rctTypes.h`.

```text
TransactionV3 {
  prefix: TransactionPrefixV3
  rct_signatures: rctSig {
    type: RCTTypeFcmpPlusPlusPqc   // = 7
    txnFee: u64
    ecdhInfo: [EcdhTuple]
    outPk: [key]
    referenceBlock: hash            // block hash anchoring curve tree snapshot
    pseudoOuts: [key]               // in rctSigPrunable
    bp_plus: [BulletproofPlus]      // range proofs (unchanged)
    curve_trees_tree_depth: u8      // tree depth at referenceBlock
    fcmp_pp_proof: bytes            // opaque FCMP++ proof blob
  }
  pqc_auths: [PqcAuthentication]    // one per input; hybrid Ed25519 + ML-DSA-65
}
```

**Only two RCT type values exist.** The `rctTypes.h` enum contains
`RCTTypeNull = 0` (coinbase only) and `RCTTypeFcmpPlusPlusPqc = 7` (all
non-coinbase spends). Legacy Monero types (`RCTTypeFull` through
`RCTTypeBulletproofPlus`) are not defined; associated structs (`mgSig`,
`clsag`, `rangeSig`, non-plus `Bulletproof`, `RCTConfig`, etc.) and ring /
CLSAG signing and verification code have been removed from the codebase.

The `rctSigBase` struct has no `mixRing` member. `rctSigPrunable` holds only
`bulletproofs_plus`, `pseudoOuts`, `curve_trees_tree_depth`, and
`fcmp_pp_proof`. The `serialize_rctsig_prunable` API has no `mixin`
parameter.

### `tx_extra`: Hybrid KEM ciphertext tag (`0x06`)

Outputs carry hybrid KEM material for per-output PQC key derivation. The field
`tx_extra_pqc_kem_ciphertext` is tagged `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
(`0x06` in `tx_extra.h`). The payload is a single `blob` whose length is
**N × 1120** bytes: **N** concatenated hybrid ciphertexts, one per transaction
output in **vout order**. Each 1120-byte entry is
`x25519_ephemeral_pk[32] || ml_kem_768_ct[1088]` — the X25519 ephemeral
public key followed by the ML-KEM-768 ciphertext (FIPS 203). Both components
are required for correct hybrid KEM decapsulation.

### `tx_extra`: PQC leaf hash tag (`0x07`)

Each output's derived ML-DSA-65 public key is hashed to produce a 32-byte
`H(pqc_pk)` value (Blake2b-512 with domain separator `shekyl-pqc-leaf`,
via `shekyl_fcmp_pqc_leaf_hash()`). These hashes are stored in the field
`tx_extra_pqc_leaf_hashes`, tagged `TX_EXTRA_TAG_PQC_LEAF_HASHES` (`0x07`
in `tx_extra.h`). The payload is a single `blob` of **N × 32** bytes:
**N** concatenated 32-byte hashes, one per transaction output in **vout
order**.

The curve tree insertion code (`collect_outputs` in `blockchain_db.cpp`)
extracts these hashes and commits them as the 4th leaf scalar. If the tag
is absent (pre-existing outputs before this feature), a 32-byte zero
placeholder is used. This field is emitted by both `construct_miner_tx`
(coinbase) and `create_claim_transaction` (claim), and by the regular
wallet transfer path.

### Coinbase KEM self-encapsulation

Coinbase transactions do not carry `pqc_auths` (no real inputs to sign).
Coinbase outputs still need a distinct per-output `H(pqc_pk)` in the curve
tree. When `hard_fork_version >= HF_VERSION_FCMP_PLUS_PLUS_PQC` and the miner
address includes a PQC encapsulation key, `construct_miner_tx` performs the same
hybrid KEM encapsulation **to the miner’s own address** for each coinbase
output as a transfer would: one 1120-byte hybrid ciphertext per output in the
`0x06` blob, standard HKDF per-output derivation, shared secret wiped after
use. This prevents all coinbase outputs to the same miner from sharing an
identical `H(pqc_pk)` pattern (which would link rewards). Spending a matured
coinbase then follows the normal recipient path (decapsulate from `tx_extra`,
rederive per-output keys, sign with `pqc_auths` on the spend transaction).

### Transaction Hash Computation

```text
tx_hash = cn_fast_hash(prefix_hash || base_rct_hash || pqc_auths_hash || prunable_hash)
```

`pqc_auths_hash` is `cn_fast_hash` of the canonical serialization of the full
`pqc_auths` vector (see `cryptonote_format_utils.cpp`). Coinbase transactions
omit PQC authorization fields; non-coinbase FCMP++ transactions must have
`pqc_auths.size() == vin.size()`.

The `prunable_hash` covers `fcmp_pp_proof`, `curve_trees_tree_depth`,
`pseudoOuts`, and `BulletproofPlus` range proofs.

---

## 5. Block Header Commitment

Each block header contains a `curve_tree_root` field (`crypto::hash`,
32 bytes) that commits to the state of the curve tree after processing
all transactions in the block.

### Serialization

The field is always serialized (genesis-native, no version gating) in both
the binary archive and Boost serialization. Initialized to `null_hash` at
genesis.

### Block Template Creation

`Blockchain::create_block_template` snapshots the current DB curve tree
root into the header before mining begins.

### Block Validation

`Blockchain::handle_block_to_main_chain` verifies that `curve_tree_root`
matches the locally-computed tree root after `add_block` grows the tree.
A mismatch rejects the block.

### RPC Exposure

The `block_header_response` RPC response includes `curve_tree_root` as a
hex string.

### `get_curve_tree_path` JSON-RPC

The `get_curve_tree_path` endpoint returns Merkle authentication paths
for one or more outputs. The wallet uses these paths to construct FCMP++
proofs.

**Request:** `{ "output_indices": [uint64, ...] }`

**Response:**
```json
{
  "reference_block": "hex hash",
  "reference_height": 12345,
  "tree_depth": 3,
  "leaf_count": 4200,
  "paths": [...]
}
```

Request is limited to 64 output indices per call (`MAX_OUTPUTS_PER_RPC_REQUEST`).

Each `path_entry` contains a hex-encoded `path_blob` with the following
binary layout:

```text
Layer 0 (leaf layer):
  position[2]           -- LE uint16, leaf index within the chunk
  leaf_scalars[N*128]   -- all leaves in the chunk (N <= 38), 128 bytes each

Layer 1..depth-1 (internal layers):
  position[2]           -- LE uint16, child index within the parent chunk
  sibling_hashes[M*32]  -- all children in the parent chunk (M <= chunk_width)
```

Chunk widths: 38 for Selene layers (even), 18 for Helios layers (odd).
The verifier identifies the proven element by its position; all other
entries in the chunk are authentication siblings.

### `get_curve_tree_info` JSON-RPC

Returns the current curve tree state summary.

**Request:** `{}`

**Response:** `{ "root": hex, "depth": uint8, "leaf_count": uint64, "height": uint64 }`

### `get_curve_tree_checkpoint` JSON-RPC

Retrieves a stored checkpoint at a specific block height (for fast-sync).
Checkpoints are stored every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` blocks.

**Request:** `{ "block_height": uint64 }`

**Response:** `{ "root": hex, "depth": uint8, "leaf_count": uint64, "block_height": uint64 }`

Returns an error if no checkpoint exists at the requested height.

---

## 6. Per-Input Signed Payload Layout

Implementation entry point: `cryptonote::get_transaction_signed_payload()` in
`src/cryptonote_core/tx_pqc_verify.cpp` (declared in `tx_pqc_verify.h`).

Each `pqc_auths[i]` signs a payload that commits to the full transaction
state:

```text
signed_payload_i = cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(RctSigningBody)
    || H(serialize(RctSigPrunable))
    || serialize(PqcAuthHeader_i)
    || H(pqc_pk_0) || H(pqc_pk_1) || ... || H(pqc_pk_{N-1})
)
```

`H(serialize(RctSigPrunable))` is `cn_fast_hash` of the serialized prunable
data (`fcmp_pp_proof`, `pseudoOuts`, `curve_trees_tree_depth`,
`BulletproofPlus`). This 32-byte digest directly binds the PQC signature
to the FCMP++ proof, preventing an attacker from substituting different
prunable data without invalidating PQC signatures.

The final concatenation of **all** inputs' PQC public-key hashes binds each
signature to the complete set of authorized keys, preventing key-substitution
attacks where an attacker replaces one input's PQC key without invalidating
other inputs' signatures.

### Coverage Analysis

| Field | Covered via | Binding |
|-------|-----------|---------|
| `referenceBlock` | `RctSigningBody` (in `rctSigBase`) | Anchors the tree snapshot |
| All key images | `TransactionPrefixV3` (in `vin`) | Prevents key image substitution |
| `fcmp_pp_proof` | `H(RctSigPrunable)` in signed payload | Direct proof binding |
| `pseudoOuts` | `H(RctSigPrunable)` in signed payload | Pseudo-output binding |
| `curve_trees_tree_depth` | `H(RctSigPrunable)` in signed payload | Tree depth binding |
| `BulletproofPlus` | `H(RctSigPrunable)` in signed payload | Range proof binding |
| `H(pqc_pk)` values | `PqcAuthHeader_i` + all-inputs hash tail | Full PQC key binding |

### PqcAuthHeader Layout (Per-Input)

```text
PqcAuthHeader_i {
    auth_version    u8
    scheme_id       u8
    flags           u16
    hybrid_public_key   HybridPublicKey   // for input i
}
```

The `hybrid_signature` is excluded from the header (it is what is being
computed). See `docs/POST_QUANTUM_CRYPTOGRAPHY.md` for the canonical
encoding of `HybridPublicKey`.

---

## 7. Verification Order

The following is the consensus-critical verification sequence for
`RCTTypeFcmpPlusPlusPqc` transactions in `Blockchain::check_tx_inputs`.
Steps are ordered to fail fast on cheap checks before expensive proof
verification.

### Step 0: Structural Pre-Checks

- `tx.version == 3`
- `tx.vout.size() >= 2`
- `tx.vin.size() <= FCMP_MAX_INPUTS_PER_TX`
- `tx.unlock_time < CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL`
  (Decision 13: timestamp-based unlock times are rejected in consensus)
- All inputs are `txin_to_key` (no `txin_gen` except coinbase)
- Key images are sorted and unique
- No key image is already spent (double-spend check)

### Step 1: referenceBlock Validation

```text
1a. block_exists(rv.referenceBlock, &ref_height) must be true
1b. ref_height >= tip - FCMP_REFERENCE_BLOCK_MAX_AGE    (not too old)
1c. ref_height <= tip - FCMP_REFERENCE_BLOCK_MIN_AGE    (not too recent)
```

Constants from `cryptonote_config.h`:
- `FCMP_REFERENCE_BLOCK_MAX_AGE = 100` (~3.3 hours at 2-minute blocks)
- `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` (reorg safety margin)

> **Design rationale (MIN_AGE = 5):** Maturity is enforced by universal
> deferred tree insertion: outputs only enter the curve tree after their
> type-specific maturity period (coinbase: 60 blocks, regular: 10 blocks,
> staked: max(lock_until, 10 blocks)).  MIN_AGE therefore only needs to
> provide a reorg safety margin — 5 blocks (~10 minutes) is sufficient
> to ensure the referenced tree state is stable.

### Step 2: Curve Tree State Lookup

```text
2a. tree_root = get_curve_tree_root_at(ref_height)
2b. tree_depth = get_curve_tree_depth_at(ref_height)
2c. rv.p.curve_trees_tree_depth == tree_depth
```

The tree root and depth at `referenceBlock` height anchor the proof. A
mismatch in `curve_trees_tree_depth` is a consensus failure.

The per-block tree root is stored in the block header's `curve_tree_root`
field. The `check_tx_inputs` code retrieves it via
`m_db->get_block_header(rv.referenceBlock).curve_tree_root`.

### Step 3: Input Structural Checks (FCMP++ Specific)

For each input `i` in `tx.vin`:

```text
3a. in_to_key.key_offsets.empty() == true
    (FCMP++ replaces ring members; no key offsets allowed)
3b. Key image y-normalization: bit 7 of byte 31 must be 0
    (FCMP++ requires y-normalized key images)
```

### Step 4: FCMP++ Proof Verification

```text
proof       = rv.p.fcmp_pp_proof
key_images  = [ tx.vin[i].k_image for i in 0..num_inputs ]
pseudo_outs = rv.p.pseudoOuts
pqc_hashes  = [ shekyl_fcmp_pqc_leaf_hash(extract_ml_dsa_pk(pqc_auths[i]))
                for i in 0..num_inputs ]
tree_root   = (from Step 2a)
tree_depth  = rv.p.curve_trees_tree_depth

result = shekyl_fcmp_verify(
    proof.data(), proof.size(),
    key_images_flat, num_inputs,
    pseudo_outs_flat, num_inputs,
    pqc_hashes_flat, num_inputs,
    tree_root, tree_depth
)
```

### Step 5: PQC Commitment Cross-Check

```text
for i in 0..num_inputs:
    ml_dsa_pk = extract_ml_dsa_component(pqc_auths[i].hybrid_public_key)
    computed_hash = shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)
    assert computed_hash == pqc_hashes[i]
```

Defense-in-depth check. May be omitted if pqc_hashes are computed directly
from `pqc_auths` in the same code path.

### Step 6: Per-Input PQC Signature Verification

```text
6a. pqc_auths[i].auth_version == 1
6b. pqc_auths[i].scheme_id in {1, 2}   (single-signer or multisig)
6c. pqc_auths[i].flags == 0
6d. Compute signed_payload_i
6e. shekyl_pqc_verify(scheme_id, hybrid_public_key, hybrid_signature,
                       signed_payload_i) == true
```

### Step 7: Bulletproof+ Range Proof Verification

Standard BulletproofPlus verification for output range proofs, handled by
`verRctSemanticsSimple` (batch verification of BP+ and pseudo-output sum
checks) called from `ver_mixed_rct_semantics` in `tx_verification_utils.cpp`.

---

## 8. FFI Boundary (Rust ↔ C++)

All FCMP++ cryptographic operations are implemented in Rust and called
from C++ through the `shekyl-ffi` crate.

### Crate Architecture

```text
rust/
├── shekyl-encoding/        # Generic Bech32m blob encode/decode, proof HRP constants
├── shekyl-address/         # Network-aware segmented Bech32m address encoding
├── shekyl-fcmp/            # FCMP++ proof ops, curve tree, leaf hashing
├── shekyl-crypto-pq/       # PQC signing, KEM, derivation (re-exports shekyl-address)
├── shekyl-tx-builder/      # Native Rust tx signing: BP+, FCMP++, ECDH, PQC (replaces C++ FFI round-trips)
├── shekyl-ffi/             # C ABI exports (libshekyl_ffi.a)
└── Cargo.toml              # Workspace root
```

### Key FFI Functions

| C function | Rust source | Purpose |
|-----------|-------------|---------|
| `shekyl_sign_transaction()` | `shekyl-ffi/src/lib.rs` | Native Rust tx signing (BP+, FCMP++, ECDH, pseudo-outs) via `shekyl-tx-builder` |
| `shekyl_fcmp_prove()` | `shekyl-ffi/src/lib.rs` | Generate FCMP++ proof (variable-length witness) |
| `shekyl_fcmp_verify()` | `shekyl-ffi/src/lib.rs` | Verify FCMP++ proof |
| `shekyl_fcmp_proof_len()` | `shekyl-ffi/src/lib.rs` | Estimate proof byte length |
| `shekyl_fcmp_pqc_leaf_hash()` | `shekyl-ffi/src/lib.rs` | Hash ML-DSA-65 pubkey for leaf |
| `shekyl_fcmp_derive_pqc_keypair()` | `shekyl-ffi/src/lib.rs` | Derive per-output PQC keypair |
| `shekyl_fcmp_outputs_to_leaves()` | `shekyl-ffi/src/lib.rs` | Convert outputs to 4-scalar leaves |
| `shekyl_frost_sal_session_new()` | `shekyl-ffi/src/lib.rs` | Create FROST SAL session per input |
| `shekyl_frost_sal_get_rerand()` | `shekyl-ffi/src/lib.rs` | Get rerandomized output from session |
| `shekyl_frost_sal_aggregate_and_prove()` | `shekyl-ffi/src/lib.rs` | Aggregate FROST shares and produce FCMP++ proof |
| `shekyl_frost_sal_session_free()` | `shekyl-ffi/src/lib.rs` | Free FROST SAL session handle |
| `shekyl_frost_keys_import()` | `shekyl-ffi/src/lib.rs` | Import serialized FROST threshold keys |
| `shekyl_frost_keys_export()` | `shekyl-ffi/src/lib.rs` | Export serialized FROST threshold keys |
| `shekyl_frost_keys_group_key()` | `shekyl-ffi/src/lib.rs` | Extract 32-byte Ed25519T group key |
| `shekyl_frost_keys_validate()` | `shekyl-ffi/src/lib.rs` | Validate M-of-N params against threshold keys |
| `shekyl_frost_keys_free()` | `shekyl-ffi/src/lib.rs` | Free FROST threshold keys handle |
| `shekyl_pqc_verify()` | `shekyl-ffi/src/lib.rs` | Verify hybrid PQC signature |
| `shekyl_kem_encapsulate()` | `shekyl-ffi/src/lib.rs` | Hybrid KEM encapsulation |
| `shekyl_kem_decapsulate()` | `shekyl-ffi/src/lib.rs` | Hybrid KEM decapsulation |
| `shekyl_address_encode()` | `shekyl-ffi/src/lib.rs` | Bech32m address encoding (network-aware) |
| `shekyl_address_decode()` | `shekyl-ffi/src/lib.rs` | Bech32m address decoding (network-aware) |
| `shekyl_encode_blob()` | `shekyl-ffi/src/lib.rs` | Generic Bech32m blob encoding with arbitrary HRP |
| `shekyl_decode_blob()` | `shekyl-ffi/src/lib.rs` | Generic Bech32m blob decoding |

### C++ Header

All FFI declarations are in `src/shekyl/shekyl_ffi.h`. Functions use
`#[no_mangle] pub extern "C" fn` in Rust and are declared with
`extern "C"` linkage in the header.

### Build Integration

`cmake/BuildRust.cmake` compiles the entire Rust workspace into
`libshekyl_ffi.a` (static library) with the `--locked` flag for
reproducible builds. The static library is linked into C++ targets via
`${SHEKYL_FFI_LINK_LIBS}`.

---

## 9. Database Schema (LMDB)

The curve tree and related metadata are stored in five LMDB tables.

### Curve Tree Tables

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `curve_tree_leaves` | `global_output_index` (u64) | 128-byte leaf data `{O.x, I.x, C.x, H(pqc_pk)}` | All UTXO leaves |
| `curve_tree_layers` | `(layer_idx << 56 \| chunk_idx)` (u64) | 32-byte hash | Internal Helios/Selene layer hashes |
| `curve_tree_meta` | key string (`"root"`, `"leaf_count"`, `"depth"`) | variable | Current tree state |
| `curve_tree_checkpoints` | `block_height` (u64, MDB_INTEGERKEY) | `root[32] + depth[1] + leaf_count[8]` (41 bytes) | Periodic snapshots for fast sync |

### Transaction tables (pruned blob split)

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `txs_pruned` | `tx_id` (u64) | prefix + `rctSigBase` only | Canonical pruned prefix |
| `txs_pqc_auths` | `tx_id` (u64) | `pqc_auths` bytes (optional) | Split from `txs_pruned` so pruning can delete PQC auth data |
| `txs_prunable` | `tx_id` (u64) | Bulletproofs+, FCMP++, pseudoOuts | Deleted after tx-data pruning |

`get_pruned_tx_blob` / `get_tx_blob` concatenate `txs_pruned` + `txs_pqc_auths` (if present) + `txs_prunable` (if present). The in-memory `transaction::pqc_auths_offset` records the split point when serializing.

### Output Metadata Table

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `output_metadata` | `global_output_index` (u64) | `output_pruning_metadata_t` (packed struct) | Wallet scanning after tx pruning |

The `output_pruning_metadata_t` struct stores per-output scan data:
output public key, Pedersen commitment, unlock_time, block height, and a
pruned flag. This allows wallets to scan for owned outputs even after the
full transaction data has been pruned.

**Invariant (PQC restore):** `output_metadata` does **not** duplicate the
`tx_extra` hybrid KEM ciphertexts (`TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`, `0x06`).
Wallet restore and PQC key re-derivation still read those ciphertexts from the
**transaction prefix** stored in `m_txs_pruned`. Any future “deep prune” mode
must **not** delete or truncate `m_txs_pruned` in a way that removes `tx_extra`
while leaving outputs discoverable, or ML-KEM ciphertexts needed for PQC
material would be lost.

### Database API

```cpp
// Curve tree state
std::array<uint8_t, 32> get_curve_tree_root() const;
uint8_t get_curve_tree_depth() const;
uint64_t get_curve_tree_leaf_count() const;
bool get_curve_tree_layer_hash(uint8_t layer, uint64_t chunk, uint8_t* hash_out) const;
bool get_curve_tree_leaf(uint64_t global_output_index, uint8_t* leaf_out) const;

// Checkpoints
void save_curve_tree_checkpoint(uint64_t block_height);
bool get_curve_tree_checkpoint(uint64_t block_height, std::vector<uint8_t>& data) const;
uint64_t get_latest_curve_tree_checkpoint_height() const;
void prune_curve_tree_intermediate_layers(uint64_t checkpoint_height);

// Output metadata (pruning support)
void store_output_metadata(uint64_t global_output_index, const output_pruning_metadata_t& meta);
output_pruning_metadata_t get_output_metadata(uint64_t global_output_index) const;
bool is_output_pruned(uint64_t global_output_index) const;
bool prune_tx_data(uint64_t depth = 0);  // depth 0 → CRYPTONOTE_TX_PRUNE_DEPTH
uint64_t get_last_pruned_tx_data_height() const;
bool tx_has_verification_data(const crypto::hash& tx_hash) const;
```

---

## 10. Per-Output PQC Key Derivation

Every output has a unique PQC keypair derived deterministically from the
combined KEM shared secret, enabling wallet restore from seed.

### Hybrid KEM (X25519 + ML-KEM-768)

The sender performs a hybrid key encapsulation:

```text
1. X25519 KEM:     ss_classical = X25519(ephemeral_sk, recipient_pk)
2. ML-KEM-768 KEM: ss_pq, ciphertext = ML-KEM-768.Encaps(recipient_ml_kem_pk)
3. Combined:       shared_secret = HKDF-SHA-512(
                       salt = "shekyl-kem-v1",
                       ikm  = ss_classical || ss_pq,
                       info = ""
                   )
```

The hybrid KEM ciphertexts are stored in `tx_extra` as
`tx_extra_pqc_kem_ciphertext`: tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (`0x06`),
field `blob` = concatenation of **N** 1120-byte hybrid ciphertexts
(`x25519_ephemeral_pk[32] || ml_kem_768_ct[1088]`, N = number of outputs),
in vout order.

### Per-Output Keypair Derivation

From the combined shared secret, each output derives its own PQC keypair:

```text
output_seed = HKDF-Expand(
    prk  = shared_secret,
    info = "shekyl-pqc-output" || output_index (LE u32),
    len  = 32
)
ml_dsa_keypair = ML-DSA-65.KeyGen(seed = output_seed)
```

This is implemented in `rust/shekyl-crypto-pq/src/derivation.rs` and
exposed via `shekyl_fcmp_derive_pqc_keypair()`.

### Wallet Restore from Seed

The wallet master seed derives three sub-keys:

```text
spend_key   = HKDF-Expand(master, "shekyl-spend", 32)
view_key    = HKDF-Expand(master, "shekyl-view", 32)
ml_kem_key  = HKDF-Expand(master, "shekyl-ml-kem", 32)
```

On restore, the wallet scans the chain for owned outputs (using classical
stealth address derivation), then rederives the PQC keypair for each output
using the stored combined shared secret (`m_combined_shared_secret` in
`transfer_details`). The function `rederive_all_pqc_keys()` handles this
during the first refresh after restore.

---

## 11. Bech32m Address Format

Shekyl uses a segmented Bech32m address format to accommodate the large
PQC key material while staying within the Bech32m checksum's proven error
detection range.

### Format

```text
shekyl1<version><classical_payload> / skpq1<pqc_part_a> / skpq21<pqc_part_b>
```

| Segment | HRP | Content | Max length |
|---------|-----|---------|------------|
| Classical | `shekyl1` | Version byte + spend pubkey + view pubkey | ~103 chars |
| PQC part A | `skpq1` | First half of ML-KEM-768 public key | ~990 chars |
| PQC part B | `skpq21` | Second half of ML-KEM-768 public key | ~990 chars |

Each segment is independently Bech32m-encoded with its own checksum,
keeping every segment under Bech32m's 1023-character proven detection
limit.

### Display

For human-readable display (QR codes, clipboard), only the classical
segment is shown by default. The full address (all three segments) is
used for machine-to-machine communication and is required for sending
funds (the PQC segments carry the ML-KEM public key needed for hybrid
KEM encapsulation).

### Network HRPs

Network discrimination is handled via the Human-Readable Part (HRP):

| Network | Classical HRP | PQC part A HRP | PQC part B HRP |
|---------|---------------|----------------|----------------|
| Mainnet | `shekyl` | `skpq` | `skpq2` |
| Testnet | `tshekyl` | `tskpq` | `tskpq2` |
| Stagenet | `sshekyl` | `sskpq` | `sskpq2` |

### Implementation

Address encoding lives in two standalone crates:

- `rust/shekyl-encoding/` — generic Bech32m blob encode/decode with
  arbitrary HRPs. Also defines HRP constants for wallet proofs
  (`shekylspendproof`, `shekyltxproof`, `shekylreserveproof`, `shekylsig`,
  `shekylmultisig`, `shekylsigner`).
- `rust/shekyl-address/` — network-aware segmented Bech32m address
  encoding. Depends on `shekyl-encoding`. Defines the `Network` enum,
  HRP lookup tables, and the `ShekylAddress` struct with `encode()` /
  `decode()` / `decode_for_network()`.

`shekyl-crypto-pq` re-exports `shekyl-address` as its `address` module
for backward compatibility.

FFI exports: `shekyl_address_encode()`, `shekyl_address_decode()`,
`shekyl_encode_blob()`, `shekyl_decode_blob()` — all in
`rust/shekyl-ffi/src/lib.rs`, declared in `src/shekyl/shekyl_ffi.h`.

Base58 has been fully removed from the C++ codebase. The address
chokepoints (`get_account_address_as_str`, `get_account_address_from_str`)
call the Rust FFI. Wallet proofs, message signatures, and signer keys
use `shekyl_encode_blob` / `shekyl_decode_blob` with purpose-specific
HRPs. There are no remaining Base58 code paths.

---

## 12. Checkpoint and Pruning Strategy

### Curve Tree Checkpoints

The curve tree is checkpointed every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL`
(10,000) blocks during `add_block`. Each checkpoint stores:

```text
checkpoint = root[32 bytes] + depth[1 byte] + leaf_count[8 bytes]
```

Checkpoints are stored in the `curve_tree_checkpoints` LMDB table
(MDB_INTEGERKEY, keyed by block height).

**Purpose:** Fast-sync resumption. A syncing node can skip to the latest
checkpoint and rebuild only the tree state from that point forward, rather
than replaying the entire chain.

### Intermediate Layer Pruning

`prune_curve_tree_intermediate_layers(checkpoint_height)` selectively
removes intermediate layer entries (layers 1 through depth-2) whose chunk
indices fall below the boundary implied by the previous checkpoint's
`leaf_count`. Only chunks that are fully "sealed" by the previous
checkpoint are deleted -- the current live layers, the leaf layer (layer
0), and the root layer are always preserved. Old checkpoint records
(except the two most recent) are garbage-collected. Pruning is
automatically triggered after each `save_curve_tree_checkpoint` call in
`add_block`. Pruned layers can be recomputed on demand from the leaf data.

### Transaction Data Pruning

`prune_tx_data(depth)` removes `txs_prunable`, `txs_prunable_hash`, and
`txs_pqc_auths` for transactions in blocks below `height - depth`
(default `depth`: `CRYPTONOTE_TX_PRUNE_DEPTH` = 5000 when `depth == 0`).
It stores `output_pruning_metadata_t` for each affected output, then
deletes verification data. For RCT coinbase outputs, output lookups use
amount `0` in the amount index (matching `add_transaction`), not the
plaintext `vout.amount`. A `tx_prune_next_block` watermark in `m_properties`
stores the first block height not yet processed (with one-time read of legacy
`last_pruned_tx_data_height` as last-inclusive + 1) so runs are idempotent.
If any expected transaction row is missing (`TX_DNE`) during a pruning batch,
the batch now fails immediately and does not advance the watermark, preventing
partial-prune state from being recorded as completed.
`Blockchain::update_blockchain_pruning()`
calls `prune_tx_data` when the node is in stripe-pruning mode so the
chain prunes incrementally.

The `--prune-blockchain` CLI flag triggers both stripe-based pruning and
this tx-data pass at startup.

---

## 13. Performance Budget

### Transaction Size

| Component | Per-input | Per-tx (2-in/2-out) |
|-----------|----------|---------------------|
| FCMP++ proof | ~2.5 KB | ~4.5 KB |
| Pseudo outputs | 32 B | 64 B |
| BP+ range proofs | — | ~1.5 KB |
| `pqc_auths[i]` (single-signer, per input) | ~5.3 KB | ~10.6 KB |
| `ecdhInfo` + `outPk` | — | ~256 B |
| Prefix (vin, vout, extra) | — | ~0.5 KB |
| **Total typical** | | **~17-18 KB** |

### Verification Time

| Check | Time | Cacheable |
|-------|------|-----------|
| FCMP++ proof (per input) | ~35 ms | Yes |
| BP+ range proofs (batched) | ~5 ms | Yes |
| PQC auth (per input) | ~18 ms | Yes |
| Structural checks | < 0.1 ms | No |
| **Total (first verify)** | **~58 ms** (2-input) | |
| **Total (cached, block inclusion)** | **~0.1 ms** | |

### Proof Generation Time (Wallet)

| Scenario | Latency |
|----------|---------|
| Cold (first spend after restore) | ~60-90 seconds |
| Precomputed paths (common case) | ~2-5 seconds |

Wallet precomputation maintains tree paths for spendable outputs. When
the user initiates a send and paths are precomputed, the remaining work
is the GSP proof and PQC signing (~2-5 seconds). The Tauri GUI wallet
shows a progress indicator for cold generation and triggers background
precomputation on sync.

---

## 14. Verification Caching

FCMP++ proof verification (~35 ms per input) is deterministic for a given
`(proof, referenceBlock, key_images)` tuple. The mempool exploits this by
storing a verification cache hash in `txpool_tx_meta_t`:

```text
fcmp_verification_hash = cn_fast_hash(proof || referenceBlock || key_images)
```

### Cache Fields

Two fields were carved from the existing 76-byte padding in
`txpool_tx_meta_t` (struct stays 192 bytes):

| Field | Type | Purpose |
|-------|------|---------|
| `fcmp_verification_hash` | `crypto::hash` (32 bytes) | Deterministic cache key |
| `fcmp_verified` | 1-bit flag | Whether verification has been cached |

### Cache Flow

1. **Mempool acceptance:** `tx_memory_pool::add_tx` stores the cache hash
   after successful FCMP++ verification.
2. **Block template / reorg:** `is_transaction_ready_to_go` checks the
   cached hash via `is_fcmp_verification_cached()`. If the recomputed hash
   matches and `fcmp_verified == 1`, it seeds `m_input_cache` to skip
   re-running `shekyl_fcmp_verify()`.
3. **Invalidation:** The cache is zeroed if the tx is removed and re-added
   to the pool, or if the tx blob changes.

### Impact

Without caching, block validation cost scales as O(transactions x 58ms).
With caching, the amortized cost for mempool-originated transactions
approaches zero. Only transactions received directly in a block (not
previously in the mempool) pay the full verification cost.

---

## 15. Staking and FCMP++

Staked outputs (`txout_to_staked_key`) use the same 4-scalar leaf format:

```text
Leaf = { O.x, I.x, C.x, H(pqc_pk) }
```

**Universal deferred curve-tree insertion:** All outputs (coinbase, regular,
and staked) are deferred: they enter a pending table at creation time and
only drain into the curve tree once their type-specific maturity height is
reached.  Maturity heights are:
- **Coinbase:** `block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60)
- **Regular:**  `block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` (10)
- **Staked:**   `max(lock_until, block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE)`

The `pending_tree_leaves` LMDB table (keyed by `maturity_height`,
DUPSORT/DUPFIXED with 128-byte leaf values) stores pre-computed leaves.
On each `add_block`, `drain_pending_tree_leaves` collects all entries with
`maturity_height <= block_height`, deletes them from the pending table,
journals each entry in the `pending_tree_drain` table (keyed by block height,
136-byte values: 8-byte maturity + 128-byte leaf), and appends the leaf data
to the curve tree growth batch. `pop_block` reads the drain journal to
restore drained leaves to pending and recomputes each block output's leaf
to remove it from pending.

Because `FCMP_REFERENCE_BLOCK_MIN_AGE` (5) is now a reorg safety margin
only (not a maturity enforcement mechanism), the tree is guaranteed to
contain only matured outputs.

**Claim validation:** `txin_stake_claim` inputs are validated against
the staked output's `lock_until`, watermark, and computed reward (using
128-bit integer arithmetic for precision). The `lock_until > current_height`
check ensures outputs are only claimable after their lock period expires.
Additionally, `check_stake_claim_input` verifies the staked output's leaf
is present in the curve tree by checking
`staked_output_index < get_curve_tree_leaf_count()` and reading the leaf
data with `get_curve_tree_leaf()`. If the output hasn't been inserted
into the tree (e.g., deferred insertion pending), the claim is rejected.

**PQC ownership cross-check:** For each stake claim input `i`, the
`H(pqc_pk)` stored at bytes 96–128 of the curve tree leaf must match
`shekyl_fcmp_pqc_leaf_hash(pqc_auths[i].hybrid_public_key)`. This
prevents an attacker from claiming rewards for an output they do not
control the PQC key for.

**Claim reward outputs must be indistinguishable from regular outputs.**
Claim reward outputs MUST be regular `txout_to_tagged_key` outputs (not
staked), use `RCTTypeFcmpPlusPlusPqc` with Bulletproofs+ range proofs to
hide the reward amount, and go through the standard KEM derivation so
their PQC keys are unique and unlinkable. Once a reward output matures
into the curve tree, spending it must be indistinguishable from spending
any other output. Specifically:

- Reward outputs use confidential amounts (Pedersen commitment + BP+
  range proof), not plaintext amounts with `RCTTypeNull`.
- Per-output PQC keys are derived via the standard hybrid KEM path
  (X25519 + ML-KEM-768 → HKDF → ML-DSA-65 keypair), with the ML-KEM
  ciphertext embedded in `tx_extra` under tag `0x06`.
- Claim transactions include a dummy change output (amount = 0) to
  match the 2-output structure of regular transactions, preventing
  structural fingerprinting.
- The `txin_stake_claim` input type is inherently distinguishable on
  the input side (it references a global output index). This is an
  accepted trade-off: the *claim action* is visible, but the *reward
  output* that results from it must blend into the anonymity set once
  it enters the curve tree.

**Phase 4 implementation (completed):**

1. Consensus: `check_tx_inputs` rejects `RCTTypeNull` for all non-coinbase
   v3 transactions. Claim transactions must use `RCTTypeFcmpPlusPlusPqc`.
   Within the FCMP++ handler, a dedicated claim sub-path verifies
   pseudo-out determinism (`zeroCommit(claim_amount)`), PQC ownership
   cross-check, and batch pool balance — while skipping membership proof
   verification (not applicable to `txin_stake_claim` inputs).
2. Wallet: `wallet2::create_claim_transaction()` uses `RCTTypeFcmpPlusPlusPqc`
   with BP+ range proofs, hybrid KEM derivation for per-output PQC keys,
   ML-KEM ciphertext in `tx_extra` (`0x06`), `H(pqc_pk)` leaf hashes in
   `tx_extra` (`0x07`), and a 2-output structure (reward + dummy change).
3. Consensus: BP+ range proofs on claim tx outputs go through the standard
   `verRctSemanticsSimple` batch verification path alongside regular
   transaction outputs.

**Batch pool balance check:** The total of all claim amounts in a
transaction is summed and checked against `staker_pool_balance` once (in
`check_tx_inputs`), rather than checking each claim individually. This
prevents multiple claims in the same block from overdrawing the pool.

**Sorted inputs:** Stake claim key images must be sorted in ascending
order, enforced alongside the existing `txin_to_key` sort check.

---

## 16. Failure Modes

| Check | Failure | Error |
|-------|---------|-------|
| referenceBlock unknown | Block hash not in DB | `tvc.m_verifivation_failed` |
| referenceBlock too old | `ref_height < tip - MAX_AGE` | `tvc.m_verifivation_failed` |
| referenceBlock too recent | `ref_height > tip - MIN_AGE` | `tvc.m_verifivation_failed` |
| tree depth out of range | `curve_trees_tree_depth` 0 or > current | `tvc.m_verifivation_failed` |
| key_offsets non-empty | Ring members present in FCMP++ tx | `tvc.m_verifivation_failed` |
| key image not y-normalized | Sign bit set on key image | `tvc.m_verifivation_failed` |
| FCMP++ proof invalid | `shekyl_fcmp_verify` returns false | `tvc.m_verifivation_failed` |
| `pqc_auths` count mismatch | `pqc_auths.size() != vin.size()` | `tvc.m_verifivation_failed` |
| PQC signature invalid | `shekyl_pqc_verify` returns false | `tvc.m_verifivation_failed` |
| Key image double-spend | Key image already in DB | `tvc.m_double_spend` |
| Stake claim PQC mismatch | Leaf `H(pqc_pk)` ≠ `pqc_auths[i]` hash | `tvc.m_verifivation_failed` |
| Stake claim pool overdraw | Sum of all claim amounts > pool balance | `tvc.m_verifivation_failed` |
| Stake claim amount overflow | `total_claimed` wraps `uint64_t` | `tvc.m_verifivation_failed` |

---

## 17. Constants

| Constant | Value | Location |
|----------|-------|----------|
| `FCMP_REFERENCE_BLOCK_MAX_AGE` | 100 | `cryptonote_config.h` |
| `FCMP_REFERENCE_BLOCK_MIN_AGE` | 5 (reorg safety margin) | `cryptonote_config.h` |
| `FCMP_MAX_INPUTS_PER_TX` | 8 | `cryptonote_config.h` |
| `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` | 10,000 | `cryptonote_config.h` |
| `RCTTypeFcmpPlusPlusPqc` | 7 | `rctTypes.h` |
| `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` | 0x06 | `tx_extra.h` |
| `TX_EXTRA_TAG_PQC_LEAF_HASHES` | 0x07 | `tx_extra.h` |
| `ML_KEM_768_CT_BYTES` | 1088 | `tx_extra.h` |
| `X25519_CT_BYTES` | 32 | `tx_extra.h` |
| `HYBRID_KEM_CT_BYTES` | 1120 (32 + 1088) | `tx_extra.h` |
| `PQC_LEAF_HASH_BYTES` | 32 | `tx_extra.h` |
| `HF_VERSION_FCMP_PLUS_PLUS_PQC` | 1 | `cryptonote_config.h` |

---

## 18. Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Curve tree LMDB schema (leaves, layers, meta) | **Done** | `db_lmdb.h`, `db_lmdb.cpp` |
| Curve tree checkpoint table | **Done** | `db_lmdb.h`, `db_lmdb.cpp` |
| Output metadata table (`m_output_metadata`) | **Done** | `db_lmdb.h`, `db_lmdb.cpp` |
| `curve_tree_root` in block header | **Done** | `cryptonote_basic.h`, `blockchain.cpp` |
| referenceBlock age validation | **Done** | `blockchain.cpp` |
| key_offsets empty check | **Done** | `blockchain.cpp` |
| Key image y-normalization check | **Done** | `blockchain.cpp` |
| FCMP++ proof FFI call | **Done** | `blockchain.cpp` → `shekyl_fcmp_verify()` |
| Verification caching (mempool FCMP++ hash) | **Done** | `tx_pool.cpp`, `blockchain.cpp` |
| `genRctFcmpPlusPlus` (wallet-side proof) | **Done** | `rctSigs.cpp` |
| Wallet tree-path precomputation | **Done** | `wallet2.cpp` |
| PQC key rederivation from stored secret | **Done** | `wallet2.cpp` |
| Restore-from-seed PQC rederivation | **Done** | `wallet2.cpp` |
| `prune_tx_data` + `txs_pqc_auths` split | **Done** | `db_lmdb.cpp`, `cryptonote_basic.h` |
| `get_curve_tree_path` RPC | **Done** | `core_rpc_server.cpp` |
| `get_curve_tree_info` RPC | **Done** | `core_rpc_server.cpp` |
| `get_curve_tree_checkpoint` RPC | **Done** | `core_rpc_server.cpp` |
| CI: Rust workspace + FCMP crate build | **Done** | `.github/workflows/build.yml` |
| CI: Determinism check + Bech32m tests | **Done** | `.github/workflows/build.yml` |
| Hardware device FCMP++ stubs | **Done** | `device.hpp`, `device_default.cpp`, `device_ledger.cpp` |
| Trezor protocol legacy RCT removal | **Done** | `protocol.cpp`, `protocol.hpp` |
| Legacy RCT stripping (types 1-6, all structs, all src/) | **Done** | `rctTypes.h/cpp`, `rctSigs.h/cpp`, all consumers |
| Non-plus Bulletproof code removal | **Done** | `bulletproofs.h`, `bulletproofs.cc` |
| `RCTConfig` parameter removal from tx construction | **Done** | `cryptonote_tx_utils.h/cpp`, `wallet2.h/cpp` |
| RPC `low_mixin` field removal | **Done** | `core_rpc_server.cpp`, `core_rpc_server_commands_defs.h` |
| Staked output curve-tree leaves | **Done** | `blockchain_db.cpp` |
| Stake claim curve-tree leaf presence check | **Done** | `blockchain.cpp` (`check_stake_claim_input`) |
| Stake claim wired in `check_tx_inputs` | **Done** | `blockchain.cpp` (FCMP++ handler, claim sub-path) |
| Stake claim PQC ownership cross-check | **Done** | `blockchain.cpp` (FCMP++ handler, `H(pqc_pk)` leaf vs `pqc_auths`) |
| Stake claim batch pool balance check | **Done** | `blockchain.cpp` (FCMP++ handler, sum-then-check) |
| Stake claim sorted input enforcement | **Done** | `blockchain.cpp` (sorted-ins block handles `txin_stake_claim`) |
| Stake claim key images in `remove_transaction` | **Done** | `blockchain_db.cpp` |
| Integer-only reward computation | **Done** | `blockchain.cpp` (`check_stake_claim_input`, `mul128`/`div128_64`) |
| Dead `check_ring_signature` removal | **Done** | `blockchain.cpp`, `blockchain.h` |
| Dead `expand_transaction_2` removal | **Done** | `blockchain.cpp`, `blockchain.h` |
| PQC `auth_version`/`flags` consensus checks | **Done** | `tx_pqc_verify.cpp` |
| Single-signer key size validation | **Done** | `tx_pqc_verify.cpp` |
| Dead `verRctNonSemanticsSimple` / cache removal | **Done** | `rctSigs.h/cpp`, `tx_verification_utils.h/cpp` |
| Universal deferred tree insertion | **Done** | `pending_tree_leaves` / `pending_tree_drain` DB tables, `blockchain_db.cpp` |
| Per-input `pqc_auths` field | **Done** | `cryptonote_basic.h` |
| Per-input PQC signature verification | **Done** | `tx_pqc_verify.cpp` |
| PQC signed payload binds prunable data + all H(pqc_pk) | **Done** | `tx_pqc_verify.cpp` |
| `pqc_authentication` deserialization size bounds | **Done** | `cryptonote_basic.h` |
| `pseudoOuts` gated in generic `rctSigBase` serializer | **Done** | `rctTypes.h` |
| `pop_block()` height symmetry fix | **Done** | `blockchain_db.cpp` |
| Ring-based validation path removed (genesis-native) | **Done** | `blockchain.cpp` |
| `tx_extra` KEM blob tag `0x06` (N × 1120 bytes hybrid ct) | **Done** | `tx_extra.h`, `cryptonote_format_utils.cpp` |
| `tx_extra` leaf hash tag `0x07` (N × 32 bytes) | **Done** | `tx_extra.h`, `cryptonote_format_utils.cpp` |
| Curve tree leaves use actual `H(pqc_pk)` from `tx_extra` | **Done** | `blockchain_db.cpp` (`collect_outputs`, `make_leaf`) |
| Coinbase KEM self-encapsulation + `H(pqc_pk)` emission | **Done** | `cryptonote_tx_utils.cpp` (`construct_miner_tx`) |
| Consensus rejects `RCTTypeNull` for non-coinbase v3 txs | **Done** | `blockchain.cpp` (`check_tx_inputs`) |
| Claim tx: `RCTTypeFcmpPlusPlusPqc` with BP+ range proofs | **Done** | `wallet2.cpp` (`create_claim_transaction`) |
| Claim tx: 2-output structure (reward + dummy change) | **Done** | `wallet2.cpp` (`create_claim_transaction`) |
| Claim tx: hybrid KEM derivation for per-output PQC keys | **Done** | `wallet2.cpp` (`create_claim_transaction`) |
| Claim tx: per-output PQC signing (not wallet master key) | **Done** | `wallet2.cpp` (`create_claim_transaction`) |
| Claim tx: pseudo-outs as `zeroCommit(claim_amount)` | **Done** | `wallet2.cpp` (`create_claim_transaction`) |
| Wallet KEM key generation (`kem_keypair_generate`) | **Done** | `account.cpp` |
| Full hybrid ciphertext in tag 0x06 (1120 bytes/output) | **Done** | `cryptonote_tx_utils.cpp`, `wallet2.cpp` |
| KEM decapsulation during wallet scanning | **Done** | `wallet2.cpp` (`process_new_transaction`) |
| `transfer_selected_rct` FCMP++ (no decoys, genRctFcmpPlusPlus) | **Done** | `wallet2.cpp` |
| `construct_tx_with_tx_key` KEM encap + 0x06/0x07 for outputs | **Done** | `cryptonote_tx_utils.cpp` |
| Per-input PQC auth with derived ML-DSA-65 keys | **Done** | `wallet2.cpp` (`transfer_selected_rct`) |
| Fee estimation for FCMP++ proof size | **Done** | `wallet2.cpp` (`estimate_rct_tx_size`) |
| GUI wallet QR code (full Bech32m address) | **Done** | `shekyl-gui-wallet` |
| GUI wallet fee preview on Send page | **Done** | `shekyl-gui-wallet` |
| `rct::key::operator!=` for key-vs-key comparison | **Done** | `rctTypes.h` |
| RAII scope guard for PQC signing keypair buffers | **Done** | `wallet2.cpp` (`transfer_selected_rct`) |
| MSVC-compatible `binary_archive` construction | **Done** | `wallet2.cpp` |
| Stressnet tooling (load gen, monitor, config) | **Done** | `tests/stressnet/` |
| 4-scalar leaf circuit (x-only + H(pqc_pk)) in monero-oxide fork | **Done** | `crypto/fcmps/` (monero-oxide `fcmp++` branch) |
| `FcmpPlusPlus::verify` accepts `pqc_pk_hashes` parameter | **Done** | `shekyl-oxide/fcmp/fcmp++/src/lib.rs` (monero-oxide) |
| 4-scalar leaf circuit audit scope | **Done** | `docs/AUDIT_SCOPE.md` |
| Cargo-fuzz targets (6 targets) | **Done** | `rust/shekyl-fcmp/fuzz/`, `rust/shekyl-crypto-pq/fuzz/` |
| Rust unit test suite (proof, tree, leaf, kem, address, derivation) | **Done** | `rust/shekyl-fcmp/src/`, `rust/shekyl-crypto-pq/src/` |
| C++ unit tests (FCMP++ specific) | **Done** | `tests/unit_tests/fcmp.cpp` |
| PQC rederivation benchmark (criterion) | **Done** | `rust/shekyl-crypto-pq/benches/pqc_rederivation.rs` |
| CLSAG device interface removal | **Done** | `device.hpp`, `device_default.cpp/hpp`, `device_ledger.cpp/hpp` |
| `get_outs`/`get_outs.bin` RPC removal | **Done** | `core_rpc_server.h/cpp`, `core_rpc_ffi.cpp`, `shekyl-daemon-rpc` |
| Dead HF constant cleanup (mixin, CLSAG, etc.) | **Done** | `cryptonote_config.h` |
| Zstd Levin P2P compression | **Done** | `levin_base.h/cpp`, `levin_compression.h/cpp`, `net_node.inl` |
| `P2P_SUPPORT_FLAG_ZSTD_COMPRESSION` handshake flag | **Done** | `cryptonote_config.h` (0x02) |
| Stake-claim rollback: watermark + pool-balance restoration | **Done** | `blockchain_db.cpp` (`remove_transaction`) |
| Txpool `txin_stake_claim` key-image handling (6 functions) | **Done** | `tx_pool.cpp` |
| `get_inputs_money_amount` / `check_inputs_overflow` stake-claim support | **Done** | `cryptonote_format_utils.cpp` |
| `remove_transaction_keyimages` no-early-return fix | **Done** | `tx_pool.cpp` |
| RPC `estimate_claim_reward` integer math fix | **Done** | `core_rpc_server.cpp` |
| Staking unit tests (GTest) | **Done** | `tests/unit_tests/staking.cpp` |
| Staking core tests (chaingen) | **Done** | `tests/core_tests/staking.cpp` + `staking.h` |
| Staking tier edge-case tests (Rust) | **Done** | `rust/shekyl-staking/src/tiers.rs` |
| Real `prove()` in `shekyl-fcmp` (SAL + FCMP circuit + pseudo-outs) | **Done** | `rust/shekyl-fcmp/src/proof.rs` |
| Real `verify()` in `shekyl-fcmp` (batch verifiers: Ed25519/Selene/Helios) | **Done** | `rust/shekyl-fcmp/src/proof.rs` |
| FFI `shekyl_fcmp_prove` returns `ShekylFcmpProveResult` with pseudo-outs | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| FFI `shekyl_fcmp_verify` accepts `signable_tx_hash` parameter | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| C++ callers updated for new FFI signatures | **Done** | `rctSigs.cpp`, `blockchain.cpp`, `wallet2.cpp` |
| Staking reward fuzz target | **Done** | `rust/shekyl-staking/fuzz/fuzz_targets/fuzz_claim_reward.rs` |
| FROST SAL module (`frost_sal.rs`) | **Done** | `rust/shekyl-fcmp/src/frost_sal.rs` |
| `prove_with_sal()` for multisig proof construction | **Done** | `rust/shekyl-fcmp/src/proof.rs` |
| FROST DKG key management (`frost_dkg.rs`) | **Done** | `rust/shekyl-fcmp/src/frost_dkg.rs` |
| FROST SAL FFI (session new/get_rerand/aggregate_and_prove/free) | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| FROST DKG FFI (keys import/export/validate/group_key/free) | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| FFI `shekyl_fcmp_prove` variable-length witness format | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| `genRctFcmpPlusPlus` accepts leaf chunk entries | **Done** | `rctSigs.h/cpp` |
| Daemon RPC `chunk_outputs_blob` in `get_curve_tree_path` | **Done** | `core_rpc_server.cpp`, `core_rpc_server_commands_defs.h` |
| Wallet `fcmp_precomputed_path` stores `leaf_chunk_entries` | **Done** | `wallet2.h/cpp` |
| C++ wallet FROST session lifecycle (`prepare_multisig_fcmp_proof`) | **Done** | `wallet2.cpp` |
| C++ wallet FROST signing request (v3 format) | **Done** | `wallet2.cpp` |
| C++ wallet FROST aggregation in `import_multisig_signatures` | **Done** | `wallet2.cpp` |
| C++ wallet FROST threshold key import/export | **Done** | `wallet2.h/cpp` |
| FROST SAL unit tests (4 tests) | **Done** | `rust/shekyl-fcmp/src/frost_sal.rs` |
| FROST DKG unit tests (4 tests) | **Done** | `rust/shekyl-fcmp/src/frost_dkg.rs` |
| FROST FFI lifecycle tests (8 tests) | **Done** | `rust/shekyl-ffi/src/lib.rs` |
| `shekyl-tx-builder` crate (native Rust signing) | **Done** | `rust/shekyl-tx-builder/` |
| `shekyl_sign_transaction` FFI export | **Done** | `rust/shekyl-ffi/src/lib.rs`, `shekyl_ffi.h` |
| Wallet RPC `native-sign` feature (`transfer_native`) | **Done** | `rust/shekyl-wallet-rpc/src/wallet.rs` |
| `wallet2_ffi_prepare_transfer` / `_finalize_transfer` stubs | **Done** (stubs) | `src/wallet/wallet2_ffi.cpp`, `wallet2_ffi.h` |
| `shekyl-tx-builder` unit tests (19 tests) | **Done** | `rust/shekyl-tx-builder/src/tests.rs` |

---

## 19. Testing & Fuzzing

### Fuzz Targets

Eleven `cargo-fuzz` targets exercise the critical parsing, crypto, multisig, and staking boundaries:

| Target | Crate | What it tests |
|--------|-------|---------------|
| `fuzz_fcmp_proof_deserialize` | `shekyl-fcmp` | Malformed, truncated, and oversized proof blobs |
| `fuzz_curve_tree_leaf_hash` | `shekyl-fcmp` | Arbitrary 4×32-byte leaf inputs, PQC scalar boundary values |
| `fuzz_block_header_tree_root` | `shekyl-fcmp` | Mismatched `curve_tree_root` between prove and verify |
| `fuzz_bech32m_address_decode` | `shekyl-crypto-pq` | Random strings through Bech32m decoder, wrong HRPs, bad checksums |
| `fuzz_kem_decapsulate` | `shekyl-crypto-pq` | Corrupted ML-KEM ciphertexts, wrong-length keys and ciphertexts |
| `fuzz_multisig_verify` | `shekyl-crypto-pq` | Multisig verify path with malformed group IDs, signatures, and payloads |
| `fuzz_multisig_key_blob` | `shekyl-crypto-pq` | Randomized multisig key-blob decode and bounds checks |
| `fuzz_multisig_sig_blob` | `shekyl-crypto-pq` | Randomized multisig signature-blob decode and validation |
| `fuzz_group_id` | `shekyl-crypto-pq` | Group-id parser and canonicalization edge cases |
| `fuzz_claim_reward` | `shekyl-staking` | Random accrual records; reward overflow, monotonicity, and bound invariants |
| `fuzz_tx_deserialize_fcmp_type7` | `shekyl-fcmp` | Transaction-structured FCMP++ deserialization: pseudoOuts, proof blobs, PQC hashes, corrupted types |

CI runs a smoke gate that ensures this required fuzz harness inventory exists (`.github/workflows/build.yml`, `verify fuzz harness inventory (smoke gate)`).

For the full pre-release fuzz campaign (10M runs per harness), run:

```bash
cd rust/shekyl-fcmp/fuzz && cargo +nightly fuzz run fuzz_fcmp_proof_deserialize -- -runs=10000000
cd rust/shekyl-fcmp/fuzz && cargo +nightly fuzz run fuzz_curve_tree_leaf_hash -- -runs=10000000
cd rust/shekyl-fcmp/fuzz && cargo +nightly fuzz run fuzz_block_header_tree_root -- -runs=10000000
cd rust/shekyl-fcmp/fuzz && cargo +nightly fuzz run fuzz_tx_deserialize_fcmp_type7 -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_bech32m_address_decode -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_kem_decapsulate -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_multisig_verify -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_multisig_key_blob -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_multisig_sig_blob -- -runs=10000000
cd rust/shekyl-crypto-pq/fuzz && cargo +nightly fuzz run fuzz_group_id -- -runs=10000000
cd rust/shekyl-staking/fuzz && cargo +nightly fuzz run fuzz_claim_reward -- -runs=10000000
```

### Rust Unit Tests

Comprehensive tests cover prove/verify round-trips (including a full
end-to-end `prove_verify_roundtrip` test that generates random Ed25519 keys,
constructs a single-leaf tree, proves membership, verifies the proof, and
checks that tampered key images and wrong tree roots are rejected), edge
cases (empty inputs, max inputs, truncated proofs, tampered key images),
hash grow/trim inverse properties, leaf serialization layout, PQC keypair
derivation determinism, Bech32m address encoding/decoding, and cross-crate
consistency between `hash_pqc_public_key` and
`PqcLeafScalar::from_pqc_public_key`.

```bash
cd rust && cargo test --workspace
```

### Staking Tests

#### C++ Unit Tests (`tests/unit_tests/staking.cpp`)

- `txin_stake_claim` and `txout_to_staked_key` binary serialization round-trips (boundary values, all tiers)
- Reward integer math: `mul128`/`div128_64` vs `double`-precision divergence at large `total_weighted_stake`
- Cumulative reward over a multi-block accrual range
- Dust floor-division edge cases (reward < 1 atomic unit)
- `get_output_staking_info` for staked and non-staked outputs
- `get_inputs_money_amount` with mixed `txin_to_key` + `txin_stake_claim`
- `check_inputs_overflow` with large claim amounts
- `check_inputs_types_supported` acceptance and rejection
- Stake weight/yield multiplier tier ordering via FFI
- `set_staked_tx_out` construction and variant type checks

#### C++ Core Tests (`tests/core_tests/staking.cpp`)

18 chaingen replay tests covering:

- **Lifecycle**: staked output creation with `construct_staked_tx` helper
- **Invalid claims**: inverted range, oversized range (>10000), future height, wrong watermark, wrong amount, non-staked output, output not in tree
- **Lock enforcement**: invalid tier (3), wrong `lock_until`, zero `lock_until`
- **Rollback**: pool balance and watermark restoration via callbacks
- **Txpool**: mempool key-image tracking
- **Adversarial**: sorted-input enforcement, all-tiers staking

#### Rust Tests (`rust/shekyl-staking/src/tiers.rs`)

10 edge-case tests: exhaustive invalid tier ID rejection (3..255), ordering invariants, positive parameter assertions, contiguous ID verification.

#### Rust Fuzz (`rust/shekyl-staking/fuzz/`)

`fuzz_claim_reward`: generates random accrual records and stake parameters, verifies no overflow, reward ≤ pool, weight monotonicity, and cumulative bounds.

### C++ Unit Tests

`tests/unit_tests/fcmp.cpp` covers:

- `RCTTypeFcmpPlusPlusPqc` serialization round-trip
- `key_image_y_normalize` correctness and idempotency
- `referenceBlock` staleness constant validation
- `key_offsets` empty enforcement for FCMP++ type
- `get_pseudo_outs` routing (prunable vs base for FCMP++ type)
- `curve_tree_root` block header serialization round-trip
- Empty FCMP++ proof rejection by `shekyl_fcmp_verify` (in `check_tx_inputs`)
- `compute_fcmp_verification_hash` determinism and cache-key sensitivity (6 tests)
- `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` constant validation
- `FCMP_REFERENCE_BLOCK_MIN_AGE` value and ordering assertions

`tests/unit_tests/deferred_insertion.cpp` covers (Decision 14):

- Outputs not drainable before their maturity height
- Coinbase maturity window (60 blocks) boundary
- Regular tx maturity window (10 blocks) boundary
- Drain journal add/retrieve/remove atomicity round-trip
- Insertion ordering determinism across two LMDB instances

`tests/unit_tests/pending_tree_fuzz.cpp` covers:

- Add/remove round-trip for pending tree leaves
- Multi-height drain correctness
- Drain journal entry CRUD operations
- Randomized stress test (100 leaves, random maturity heights)
- Single-leaf removal from multi-leaf pending set

### C++ Core Tests (chaingen)

`tests/core_tests/fcmp_tests.cpp` covers:

- `gen_fcmp_tx_valid`: full FCMP++ transaction construction (proof + PQC auth) and pool acceptance
- `gen_fcmp_tx_double_spend`: double-spend rejection for FCMP++ transactions
- `gen_fcmp_tx_reference_block_too_old`: stale referenceBlock rejection
- `gen_fcmp_tx_reference_block_too_recent`: too-recent referenceBlock rejection
- `gen_fcmp_tx_timestamp_unlock_rejected`: timestamp-based unlock_time rejection (Decision 13)

### PQC Rederivation Benchmark

`rust/shekyl-crypto-pq/benches/pqc_rederivation.rs` uses Criterion to
benchmark the full per-output key rederivation pipeline:

1. ML-KEM-768 decapsulation
2. HKDF-SHA-512 seed derivation + ML-DSA-65 keygen
3. Blake2b-512 public key hash

Target: **< 100ms per output** on x86_64.

```bash
cd rust/shekyl-crypto-pq && cargo bench --bench pqc_rederivation
```

---

## monero-oxide Fork Integration Status

The FCMP++ Rust crypto stack depends on the
[Shekyl Foundation monero-oxide fork](https://github.com/Shekyl-Foundation/monero-oxide)
(`fcmp++` branch). In `shekyl-core`, these crates are now vendored under
`rust/shekyl-oxide/` and consumed through path dependencies from
`rust/shekyl-fcmp/Cargo.toml`:

- `shekyl-fcmp-plus-plus`
- `shekyl-generators`
- `helioselene`
- `ec-divisors`

### Current Pin

The vendored snapshot source of truth is:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`

This metadata records the upstream repo/branch/commit used for the current
vendored crate copy.

### Circuit Integration Status

The `full-chain-membership-proofs` circuit in the monero-oxide fork has been
modified to support Shekyl's 4-scalar leaf format. The `FcmpCurves` trait now
includes `const EXTRA_LEAF_SCALARS: usize = 1`, and `Curves` in the
`shekyl-fcmp-plus-plus` wrapper sets this to `1`. The `FcmpPlusPlus::verify`
accepts `pqc_pk_hashes: Vec<SeleneF>` to pass the 4th scalar through to the
circuit.

**x-only leaf optimization:** During implementation, we discovered that the
upstream circuit's internal (x,y) coordinate representation for O, I, C was
unnecessary for the flat leaf array and membership proof. The `on_curve` and
blinding proof gadgets still operate on full (x,y) points internally, but
the leaf flattening (`flatten_leaves`) and `tuple_member_of_list` membership
gadget now use **x-only coordinates**:

```text
Upstream (original):  [O.x, O.y, I.x, I.y, C.x, C.y]   — 6 scalars per output
Shekyl (implemented): [O.x, I.x, C.x, H(pqc_pk)]        — 4 scalars per output
```

This means the leaf layer width is `4 * LAYER_ONE_LEN` (not `6 * ...` or
`8 * ...`). The y-coordinates are recovered from x via the curve equation
inside the circuit's `on_curve` gadget — they are never stored in the tree
or transmitted in the flat leaf array.

**Completed upstream changes** (monero-oxide `fcmp++` branch):

- `FcmpCurves::EXTRA_LEAF_SCALARS` trait constant with `leaf_tuple_width()`
- `Path`, `Branches`, `RootBranch`, `InputProofData` extended with
  `output_extra_scalars` / `leaves_extra_scalars`
- `flatten_leaves` produces `[O.x, I.x, C.x, extras...]` per output
- `first_layer()` constrains `extra_leaf_vars == extra_leaf_public_values`
  and includes extras in `tuple_member_of_list`
- Extra leaf scalars committed as dedicated 1-element branches on the C1
  tape (after standard per-input branches, before the root branch)
- `Input<F>` carries `extra_leaf_scalars: Vec<F>`; `proof_size()` accounts
  for extra branches
- `Fcmp::verify` and `FcmpPlusPlus::verify` accept extra scalars
- All tests use `ShekylCurves` with `EXTRA_LEAF_SCALARS = 1`; no
  backward-compatibility code for the 3-scalar Monero leaf format

**Completed**: The `shekyl-fcmp` crate (`rust/shekyl-fcmp/src/proof.rs`)
now contains real `prove()` and `verify()` implementations that call
through the full FCMP++ stack:
- `prove()` constructs `RerandomizedOutput`, `SpendAuthAndLinkability`,
  `OutputBlinds`, `Path`/`Branches`, `BranchBlind`s, and calls `Fcmp::prove()`
  to produce a complete FCMP++ proof with pseudo-outs.
- `verify()` deserializes via `FcmpPlusPlus::read()`, initializes batch
  verifiers for Ed25519/Selene/Helios, and finalizes all three.
- The FFI boundary (`shekyl-ffi`) passes `signable_tx_hash` for transaction
  binding and returns `ShekylFcmpProveResult` with proof + pseudo-outs.

### Upstream Security Fixes Status

19 commits on upstream `main` are not yet merged into `fcmp++`. The three
security-critical commits have been audited against the Shekyl fork:

| Commit | Issue | Status |
|--------|-------|--------|
| `b6d3e44` | Base58 overflow fix, identity/torsion point rejection | **Base58 fixed** (`checked_add` + non-canonical rejection). Identity/torsion checks already present in fork. |
| `a941dff` | Varint length fix for zero | **Not applicable** — fork uses different formula that correctly returns 1 for zero. |
| `c8be5d3` | Gate debug `Extra::write` assertions | **Not applicable** — fork's `Extra::write` was refactored without debug assertions. |

**Base58 defense-in-depth note:** Shekyl core has fully migrated to Bech32m.
All C++ Base58 code (`base58.{h,cpp}`, unit tests, fuzz targets, config
prefixes) has been deleted. Address encoding uses `shekyl-address` via FFI;
wallet proofs use `shekyl-encoding` via FFI. The monero-oxide fork's wallet
still uses base58 via `shekyl-base58` (defense-in-depth fixes applied).
Migration of the fork's address crate is deferred — the fork's deep
Monero-style address type assumptions (Legacy, Subaddress, Integrated,
Featured) make the migration disproportionately expensive relative to the
fork's disposable nature.

**Cargo hardening:** Both the monero-oxide fork and the Shekyl Rust workspace
(`rust/Cargo.toml`) now enforce `overflow-checks = true` across all profiles
(dev, release, test, bench) and `panic = "abort"` for dev and release.

### RELEASE-BLOCKER Items (monero-oxide)

7 items tagged `RELEASE-BLOCKER(shekyl)` in the fork must be resolved before
audit signoff:

| Item | File | Impact |
|------|------|--------|
| FCMP\_PARAMS safe API | `fcmp/fcmp++/src/lib.rs` | API quality |
| Generated constant visibility | `fcmp/fcmp++/build.rs` | Encapsulation |
| DKG offset introspection | `fcmp/fcmp++/src/sal/legacy_multisig.rs` | Upstream coupling |
| On-curve constraint for `c` | `crypto/fcmps/src/gadgets/mod.rs` | Correctness |
| Bulk block fetch | `rpc/src/lib.rs` | Sync performance |
| Bulk height-based fetch | `rpc/src/lib.rs` | Sync performance |
| Decoy validation | `rpc/src/lib.rs` | Consensus safety |

The 3 RPC items only matter if Shekyl adopts `monero-rpc`/`monero-wallet` for
wallet functionality. The on-curve constraint and DKG coupling are the items
most likely to affect proof correctness.

### Upstream Sync Workflow

Use the required workflow in `docs/SHEKYL_OXIDE_VENDORING.md`:

1. Upstream fix lands
2. Cherry-pick/merge into `Shekyl-Foundation/monero-oxide`
3. Test fork in isolation
4. Sync subtree into `rust/shekyl-oxide/`
5. Run full `shekyl-core` test/build gates
6. Commit with upstream reference

---

## Related Documents

- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` — full PQC specification
- `docs/PQC_MULTISIG.md` — multisig scheme (`scheme_id = 2`)
- `docs/AUDIT_SCOPE.md` — 4-scalar leaf circuit security audit scope
- `tests/stressnet/README.md` — stressnet operational guide (pre-audit gate)
- `src/shekyl/shekyl_ffi.h` — FFI declarations
- `src/fcmp/rctSigs.h` — `genRctFcmpPlusPlus` declaration
- `rust/shekyl-fcmp/` — Rust FCMP++ proof implementation
- `rust/shekyl-crypto-pq/` — PQC primitives, KEM, address encoding
