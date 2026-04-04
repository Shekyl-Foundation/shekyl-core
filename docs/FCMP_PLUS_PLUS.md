# FCMP++ Full-Chain Membership Proofs — Specification

> **Last updated:** 2026-04-04
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

The tree is **append-only**: outputs enter the tree when they become
spendable (after the unlock period), and spent outputs remain in the tree
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

### `tx_extra`: ML-KEM ciphertext tag (`0x06`)

Outputs carry hybrid KEM material for per-output PQC key derivation. The field
`tx_extra_pqc_kem_ciphertext` is tagged `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
(`0x06` in `tx_extra.h`). The payload is a single `blob` whose length is
**N × 1088** bytes: **N** concatenated ML-KEM-768 ciphertexts (FIPS 203),
one per transaction output in **vout order** (same order as outputs are
listed in the prefix). Implementation may strip an X25519-specific header
from the FFI-produced buffer before appending the 1088-byte ML-KEM component.

### Coinbase KEM self-encapsulation

Coinbase transactions do not carry `pqc_auths` (no real inputs to sign).
Coinbase outputs still need a distinct per-output `H(pqc_pk)` in the curve
tree. When `hard_fork_version >= HF_VERSION_FCMP_PLUS_PLUS_PQC` and the miner
address includes a PQC encapsulation key, `construct_miner_tx` performs the same
hybrid KEM encapsulation **to the miner’s own address** for each coinbase
output as a transfer would: one 1088-byte ML-KEM ciphertext per output in the
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

Each `pqc_auths[i]` signs a payload that commits to the full transaction
state:

```text
signed_payload_i = cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(RctSigningBody)
    || serialize(PqcAuthHeader_i)
)
```

### Coverage Analysis

| Field | Covered via | Binding |
|-------|-----------|---------|
| `referenceBlock` | `RctSigningBody` (in `rctSigBase`) | Anchors the tree snapshot |
| All key images | `TransactionPrefixV3` (in `vin`) | Prevents key image substitution |
| `fcmp_pp_proof` | `prunable_hash` → `tx_hash` → miner commitment | Proof immutability |
| `H(pqc_pk)` values | `PqcAuthHeader_i` (contains `hybrid_public_key`) | PQC key binding |

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
- `FCMP_REFERENCE_BLOCK_MIN_AGE = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60)

> **Design rationale (MIN_AGE = 60):** Outputs enter the curve tree at creation
> time (not maturity), which maximises the anonymity set.  Maturity is enforced
> implicitly: since the reference block is at least 60 blocks behind the tip,
> every output in the referenced tree state has at least 60 confirmations,
> satisfying both the coinbase unlock window (60) and regular spendable age (10).
> `static_assert`s in `cryptonote_config.h` guard this invariant.

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
the existing `ver_rct_non_semantics_simple_cached` infrastructure.

---

## 8. FFI Boundary (Rust ↔ C++)

All FCMP++ cryptographic operations are implemented in Rust and called
from C++ through the `shekyl-ffi` crate.

### Crate Architecture

```text
rust/
├── shekyl-fcmp/            # FCMP++ proof ops, curve tree, leaf hashing
├── shekyl-crypto-pq/       # PQC signing, KEM, address encoding, derivation
├── shekyl-ffi/             # C ABI exports (libshekyl_ffi.a)
└── Cargo.toml              # Workspace root
```

### Key FFI Functions

| C function | Rust source | Purpose |
|-----------|-------------|---------|
| `shekyl_fcmp_prove()` | `shekyl-ffi/src/lib.rs` | Generate FCMP++ proof |
| `shekyl_fcmp_verify()` | `shekyl-ffi/src/lib.rs` | Verify FCMP++ proof |
| `shekyl_fcmp_proof_len()` | `shekyl-ffi/src/lib.rs` | Estimate proof byte length |
| `shekyl_fcmp_pqc_leaf_hash()` | `shekyl-ffi/src/lib.rs` | Hash ML-DSA-65 pubkey for leaf |
| `shekyl_fcmp_derive_pqc_keypair()` | `shekyl-ffi/src/lib.rs` | Derive per-output PQC keypair |
| `shekyl_fcmp_outputs_to_leaves()` | `shekyl-ffi/src/lib.rs` | Convert outputs to 4-scalar leaves |
| `shekyl_pqc_verify()` | `shekyl-ffi/src/lib.rs` | Verify hybrid PQC signature |
| `shekyl_kem_encapsulate()` | `shekyl-ffi/src/lib.rs` | Hybrid KEM encapsulation |
| `shekyl_kem_decapsulate()` | `shekyl-ffi/src/lib.rs` | Hybrid KEM decapsulation |
| `shekyl_address_encode()` | `shekyl-ffi/src/lib.rs` | Bech32m address encoding |
| `shekyl_address_decode()` | `shekyl-ffi/src/lib.rs` | Bech32m address decoding |

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

### Output Metadata Table

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `output_metadata` | `global_output_index` (u64) | `output_pruning_metadata_t` (packed struct) | Wallet scanning after tx pruning |

The `output_pruning_metadata_t` struct stores per-output scan data:
output public key, Pedersen commitment, unlock_time, block height, and a
pruned flag. This allows wallets to scan for owned outputs even after the
full transaction data has been pruned.

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
void prune_tx_data(uint64_t below_height);
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

The ML-KEM-768 ciphertexts are stored in `tx_extra` as
`tx_extra_pqc_kem_ciphertext`: tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (`0x06`),
field `blob` = concatenation of **N** raw 1088-byte ML-KEM-768 ciphertexts
(N = number of outputs), in vout order.

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

### Implementation

Encoding and decoding are in `rust/shekyl-crypto-pq/src/address.rs`,
exposed via `shekyl_address_encode()` and `shekyl_address_decode()`.

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

`prune_tx_data(below_height)` removes full transaction blobs for blocks
older than `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`, retaining only the
`output_pruning_metadata_t` entries needed for wallet scanning. A
`last_pruned_tx_data_height` watermark in the LMDB properties table
ensures already-processed blocks are skipped on subsequent runs.

The `--prune-blockchain` CLI flag triggers both Monero's existing
stripe-based pruning and the output-metadata pruning.

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

**Deferred curve-tree insertion:** Staked outputs only enter the curve tree
after `block_height >= lock_until`. Until then, they are invisible to
the anonymity set. This requires a `pending_staked_leaves` DB table
(not yet implemented) to track deferred insertions.

**Claim validation:** `txin_stake_claim` inputs are validated against
the staked output's `lock_until`, watermark, and computed reward. The
`lock_until > current_height` check ensures outputs are only claimable
after their lock period expires.

---

## 16. Failure Modes

| Check | Failure | Error |
|-------|---------|-------|
| referenceBlock unknown | Block hash not in DB | `tvc.m_verifivation_failed` |
| referenceBlock too old | `ref_height < tip - MAX_AGE` | `tvc.m_verifivation_failed` |
| referenceBlock too recent | `ref_height > tip - MIN_AGE` | `tvc.m_verifivation_failed` |
| tree depth mismatch | `curve_trees_tree_depth` wrong | `tvc.m_verifivation_failed` |
| key_offsets non-empty | Ring members present in FCMP++ tx | `tvc.m_verifivation_failed` |
| key image not y-normalized | Sign bit set on key image | `tvc.m_verifivation_failed` |
| FCMP++ proof invalid | `shekyl_fcmp_verify` returns false | `tvc.m_verifivation_failed` |
| `pqc_auths` count mismatch | `pqc_auths.size() != vin.size()` | `tvc.m_verifivation_failed` |
| PQC signature invalid | `shekyl_pqc_verify` returns false | `tvc.m_verifivation_failed` |
| Key image double-spend | Key image already in DB | `tvc.m_double_spend` |

---

## 17. Constants

| Constant | Value | Location |
|----------|-------|----------|
| `FCMP_REFERENCE_BLOCK_MAX_AGE` | 100 | `cryptonote_config.h` |
| `FCMP_REFERENCE_BLOCK_MIN_AGE` | 60 (= `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`) | `cryptonote_config.h` |
| `FCMP_MAX_INPUTS_PER_TX` | 8 | `cryptonote_config.h` |
| `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` | 10,000 | `cryptonote_config.h` |
| `RCTTypeFcmpPlusPlusPqc` | 7 | `rctTypes.h` |
| `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` | 0x06 | `tx_extra.h` |
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
| Verification caching | **Done** | `blockchain_db.h`, `tx_pool.cpp`, `blockchain.cpp` |
| `genRctFcmpPlusPlus` (wallet-side proof) | **Done** | `rctSigs.cpp` |
| Wallet tree-path precomputation | **Done** | `wallet2.cpp` |
| PQC key rederivation from stored secret | **Done** | `wallet2.cpp` |
| Restore-from-seed PQC rederivation | **Done** | `wallet2.cpp` |
| `prune_tx_data` skeleton | **Skeleton** | `db_lmdb.cpp` |
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
| Deferred staked-output insertion | **TODO** | `pending_staked_leaves` DB table |
| Per-input `pqc_auths` field | **Done** | `cryptonote_basic.h` |
| Per-input PQC signature verification | **Done** | `tx_pqc_verify.cpp` |
| `tx_extra` KEM blob tag `0x06` (N × 1088 bytes) | **Done** | `tx_extra.h`, `cryptonote_format_utils.cpp` |
| Coinbase KEM self-encapsulation | **Done** | `cryptonote_tx_utils.cpp` (`construct_miner_tx`) |
| Wallet transfer flow FCMP++ integration | **Done** | `wallet2.cpp` |
| Fee estimation for FCMP++ proof size | **Done** | `wallet2.cpp` |

---

## Related Documents

- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` — full PQC specification
- `docs/PQC_MULTISIG.md` — multisig scheme (`scheme_id = 2`)
- `src/shekyl/shekyl_ffi.h` — FFI declarations
- `src/ringct/rctSigs.h` — `genRctFcmpPlusPlus` declaration
- `rust/shekyl-fcmp/` — Rust FCMP++ proof implementation
- `rust/shekyl-crypto-pq/` — PQC primitives, KEM, address encoding
