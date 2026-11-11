# FCMP++ Full-Chain Membership Proofs — Specification

> **Last updated:** 2026-11-11 (the C++/FFI sections are cut; §8 maps each part to the Rust module that holds it)
>
> **Parent document:** `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

## Purpose

This document is the comprehensive technical reference for Shekyl's FCMP++
(Full-Chain Membership Proofs) implementation. It covers the cryptographic
structure, consensus rules, database schema, wallet integration, and
performance characteristics.

FCMP++ replaces ring signatures entirely. The membership **proof** is
zero-knowledge over the entire UTXO set: nothing in the proof itself reveals
which leaf is proven. Each input still reveals its
`pqc_auths[i].hybrid_public_key` in cleartext. Since `PL-D3` that key is
bound to the spent leaf by an in-circuit opening of the leaf's Pedersen
commitment `CM = k·G_k + r·J` (`k = H_ℓ(hybrid_pk)`); the published
`tx_extra` `0x07` value is `CM ‖ record`, not a public function of the key,
so hashing the revealed key no longer names the spent output (`PL-D1`
closed, [`FCMP_SPEND_LINKABILITY.md`](design/FCMP_SPEND_LINKABILITY.md)).
Amounts and destinations are unaffected.

This is the consensus-critical reference for implementors working on FCMP++.
Everything it describes is Rust; §8 maps each part to its crate and module.

---

## 1. Curve Tree Structure

The FCMP++ proof ranges over the entire UTXO set, represented as a **curve
tree** — a Merkle-like hash tree built over an elliptic curve cycle. That
range is the spend's anonymity set since `PL-D3` (2026-09-14): nothing
published per output is a function of the key a spend reveals (see the
preamble).

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

The tree is **append-only**: outputs enter the tree via **deferred insertion**
— they drain into the tree only once their type-specific maturity height is
reached. The set that drains at a height is a function of the chain below it,
computed by `shekyl-chain-rules/src/drain.rs`, not read from a pending table;
drain order, not global output index, assigns tree positions (§15).
Tree position is **not** the same as global output index; explicit
bidirectional mapping tables (`output_to_leaf`, `leaf_to_output`) track
the relationship. Spent outputs remain in the tree permanently — removing
them would reveal which output was spent, breaking the anonymity guarantee.

### 4-Scalar Leaf Format

Each UTXO occupies one leaf in the tree. A leaf is a 4-scalar tuple
(128 bytes):

```text
Leaf = { O.x, I.x, C.x, CM.x }
```

| Scalar | Source | Meaning |
|--------|--------|---------|
| `O.x` | x-coordinate of output public key | Identifies the output |
| `I.x` | x-coordinate of key image | Prevents double-spending |
| `C.x` | x-coordinate of Pedersen commitment | Binds the hidden amount |
| `CM.x` | x-coordinate of the PQC leaf commitment `CM = k·G_k + r·J`, `k = H_ℓ(hybrid_pk)` | Binds the hybrid (Ed25519 ‖ ML-DSA-65) public key without publishing a function of it (`PL-D3`) |

The 4th scalar (`CM.x`) is Shekyl-specific. `CM` is a Pedersen commitment
to the per-output PQC key scalar `k = H_ℓ(hybrid_pk)` under a per-output
blind `r`; the commitment binds the post-quantum public key to the leaf
while hiding it (`docs/design/FCMP_SPEND_LINKABILITY.md` §6.2, `PL-D3`,
ratified 2026-09-14). Upstream Monero's FCMP++ uses a 3-scalar leaf; Shekyl
extends this to 4 scalars.

**x-only representation:** All three point scalars (`O.x`, `I.x`, `C.x`)
are the x-coordinates only — y-coordinates are not stored in the tree or
included in the flat leaf array. The circuit recovers y from x via the
curve equation inside its `on_curve` gadget. This means a single output's
leaf data is exactly 4 field elements (128 bytes), not 6 or 8.

The 4th scalar's derivation, implemented once in
`rust/shekyl-crypto-pq/src/derivation.rs` (the single source;
`shekyl_fcmp::leaf::PqcKeyScalar` / `PqcLeafScalar` wrap it):

- `k = H_ℓ(hybrid_pk)`: a 64-byte cSHAKE256 read of the canonical hybrid
  public key under customization `shekyl/pqc-leaf-key-v1`, reduced modulo
  the Ed25519 group order (`pqc_key_scalar`; the verifier's typed form is `shekyl_fcmp::PqcKeyScalar`).
- `r`: HKDF-Expand of the output's `combined_ss` under
  `shekyl-pqc-leaf-blind ‖ idx_le64 ‖ ctr`, reduced mod ℓ; the guard counter
  `ctr` (0 in all but a ~2⁻²⁵² fraction of outputs) is re-derived at scan and
  never carried on the wire (exceptional-value guard: `r = 0`, an identity
  operand, or `k·G_k = ±r·J` are refused and the next counter tried).
- `CM = k·G_k + r·J` over the NUMS generators `PQC_LEAF_COMMITMENT_G_K` /
  `PQC_LEAF_COMMITMENT_J` (`shekyl-curve-generators`); the leaf holds its
  Wei25519 x-coordinate. The verifier never sees `k` from the leaf — it
  derives `K = k·G_k` from the key the spend reveals, and the circuit proves
  `K + r·J = CM` for the spent leaf (`circuit.rs` `first_layer`).
- Beside `CM`, the output's `0x07` entry carries the post-quantum record
  `cSHAKE256("shekyl/pqc-leaf-record-v1", hybrid_pk ‖ r_h)` with
  `r_h = HKDF-Expand(combined_ss, "shekyl-pqc-leaf-record-blind" ‖ idx_le64)`
  (`PL-D3a`): checked by nothing live, Keccak-chained into the block, and
  what a transparent claim (`PL-D5`, reserved) would open.

---

## 2. Dual-Layer Security Model

FCMP++ spend authorization has two layers; both must hold for a spend to be
valid. They are **not independent in security**: the link between them —
that the signing key is the one committed to the spent leaf — is enforced
inside Layer 1, whose soundness rests on the discrete-logarithm assumption.
Layer 2 is post-quantum unforgeable under the key it presents. The
composition is post-quantum only where Layer 1's binding survives, which a
full EC discrete-log break does not leave standing (`PL-D2`, [`FCMP_SPEND_LINKABILITY.md`](design/FCMP_SPEND_LINKABILITY.md) §4).

### Layer 1: FCMP++ Membership Proof (In-Circuit PQC Commitment Opening)

The FCMP++ proof is a zero-knowledge argument that the prover knows openings
to leaves in the curve tree whose 4th scalars are commitments `CM` that open,
under a blind `r` the prover holds, to the key points `K = k·G_k` supplied as
public inputs. The proof does not reveal which leaves are spent — the entire
UTXO set serves as the anonymity set — and, because `CM` is hiding, the
public input `K` is not a value any leaf or `0x07` entry publishes.

The per-input key scalars `k = H_ℓ(hybrid_pk)` are passed to
`shekyl_fcmp::proof::verify` as its `pqc_keys` (`PqcKeyScalar`); the verifier
derives `K` from each and the proof succeeds only if the prover committed to
leaves whose commitments open to exactly those points. This binding is
DLOG-sound (Generalized Bulletproofs): see `FCMP_SPEND_LINKABILITY.md` §4
(`PL-D2`) for what the in-circuit binding does and does not guarantee against
a quantum adversary.

### Layer 2: Per-Input PQC Signature (Authorization)

Each input carries a `PqcAuthentication` structure containing a hybrid
Ed25519 + ML-DSA-65 signature over a canonical payload. The signature proves
that the signer possesses the ML-DSA-65 secret key corresponding to the
`pqc_pk` whose key point the spent leaf's commitment was opened to in-circuit.

### Security Guarantee

Together, the two layers guarantee:

- **Layer 1** proves: "the spent output exists in the tree and its leaf
  commitment opens to the key point of `pqc_pk`" (anonymous, zero-knowledge).
- **Layer 2** proves: "the signer knows the secret key for `pqc_pk`"
  (non-interactive; unforgeable under the presented key against a quantum
  adversary — the binding of that key to the leaf is Layer 1's, `PL-D2`).

An attacker who breaks only EC discrete log cannot forge the ML-DSA-65
signature. An attacker who breaks only ML-DSA cannot forge the FCMP++ curve
tree membership proof (which is classical). The hybrid construction requires
both to be compromised simultaneously.

---

## 3. Proof Format

### FCMP++ Membership Proof

The proof blob (`fcmp_pp_proof` in `CtSigPrunable`) is an opaque byte
array produced by the Rust prover (`shekyl_fcmp::proof::prove`), reached in
production through `shekyl-tx-builder`'s signing. It encodes:

- Generalized Schnorr Protocol (GSP) transcripts for each input
- Curve tree path commitments across Helios/Selene layers
- Key image linkability proofs
- Pseudo-output balance commitments

The proof verifier (`shekyl_fcmp::proof::verify`) checks:

| Property | What is verified |
|----------|-----------------|
| Membership | Referenced leaves exist in the curve tree at `tree_root` |
| Key images | Match the key images in the transaction inputs |
| Pseudo outputs | Match the Pedersen commitments (balance proof) |
| PQC binding | Each spent leaf's commitment `CM` opens to `K = H_ℓ(pqc_pk)·G_k` under the prover's blind (`PL-D3`) |

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

### CTTypeFcmpPlusPlusPqc (type = 1)

Shekyl's only non-coinbase transaction type: `CT_TYPE_FCMP` (`Ct::Fcmp`) in `rust/shekyl-wire/src/transaction.rs`.

```text
TransactionV3 {
  prefix: TransactionPrefixV3
  ct_signatures: CtSig {
    type: CTTypeFcmpPlusPlusPqc   // = 1
    txnFee: u64
    ecdhInfo: [EcdhTuple]
    outPk: [key]
    referenceBlock: hash            // block hash anchoring curve tree snapshot
    pseudoOuts: [key]               // in CtSigPrunable
    bp_plus: [BulletproofPlus]      // range proofs (unchanged)
    curve_trees_tree_depth: u8      // tree depth at referenceBlock
    fcmp_pp_proof: bytes            // opaque FCMP++ proof blob
  }
  pqc_auths: [PqcAuthentication]    // one per input; hybrid Ed25519 + ML-DSA-65
}
```

**Only two CT type values exist:** `CT_TYPE_NULL = 0` (coinbase only) and
`CT_TYPE_FCMP = 1` (all non-coinbase spends), in `shekyl-wire`. Legacy Monero types (`RCTTypeFull` through
`RCTTypeBulletproofPlus`) are not defined; associated structs (`mgSig`,
`clsag`, `rangeSig`, non-plus `Bulletproof`, `RCTConfig`, etc.) and ring /
CLSAG signing and verification code have been removed from the codebase.

The `CtSigBase` struct has no `mixRing` member. `CtSigPrunable` holds only
`bulletproofs_plus`, `pseudoOuts`, `curve_trees_tree_depth`, and
`fcmp_pp_proof`. The `serialize_ctsig_prunable` API has no `mixin`
parameter.

### `tx_extra`: Hybrid KEM ciphertext tag (`0x06`)

Outputs carry hybrid KEM material for per-output PQC key derivation. The field
`TxExtraField::PqcKemCiphertext` is tagged `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
(`0x06`, `rust/shekyl-wire/src/tx_extra.rs` — the one `tx_extra` codec since
`TX_EXTRA_RUST_CUTOVER.md`, 2026-09-23). The payload is a single `blob` whose length is
**N × 1120** bytes: **N** concatenated hybrid ciphertexts, one per transaction
output in **vout order**. Each 1120-byte entry is
`x25519_ephemeral_pk[32] || ml_kem_768_ct[1088]` — the X25519 ephemeral
public key followed by the ML-KEM-768 ciphertext (FIPS 203). Both components
are required for correct hybrid KEM decapsulation.

### `tx_extra`: PQC leaf entry tag (`0x07`)

Each output's `0x07` entry is 64 bytes: the leaf commitment point `CM`
(compressed Ed25519, 32 bytes) followed by the post-quantum record (32
bytes) — `CM ‖ record`, computed by the sender from the output's
`combined_ss` and canonical hybrid public key (`derive_pqc_leaf`;
`PL-D3` / `PL-D3a`). The entries are stored in the field
`TxExtraField::PqcLeafEntries`, tagged `TX_EXTRA_TAG_PQC_LEAF_ENTRIES` (`0x07`
in `tx_extra.rs`). The payload is a single `blob` of **N × 64** bytes:
**N** concatenated entries, one per transaction output in **vout order**.

The drain (`shekyl-chain-rules/src/drain.rs`) takes each entry's commitment
point and the shared leaf constructor (`shekyl_fcmp::tree::construct_leaf`)
extracts its x-coordinate as the 4th leaf scalar. The field is **consensus-mandatory**
(CEN-I19, ruled 2026-09-05; content rule added by `PL-D3`, 2026-09-14):
admission rejects any transaction with outputs that does not carry exactly
one `0x07` of exactly `N × 64` bytes whose every entry begins with a
canonical, prime-order, non-identity point (and exactly one `0x06` of
`N × 1120`), at relay, at connect and at DB add (`shekyl_tx_extra_shape_of`
over `check_tx_extra_shape`, which is CEN-I19 + `check_pqc_leaf_entries`
plus the coinbase grammar `CEN-I20` on a coinbase); the collector
aborts rather than substituting a placeholder — on a v3-from-genesis chain
there are no pre-feature outputs. (Until 2026-09-06 an absent or short field
was zero-filled into the leaf: a leaf bound to nothing, unspendable, and a
leaf set a faithful port would not have stored.) The record half is opaque
to consensus. This field is emitted by `construct_miner_tx` (coinbase) and
by every wallet output path (transfer, drain, bond, emission claim).

**Recipient verification.** A non-honest entry (any `CM ‖ record` other
than the recipient's own derivation) yields an output the recipient can see
but never open. The wallet verifies both halves at scan: `shekyl-scanner`
re-derives `(CM, record)` from `combined_ss` and the output index and
compares the 64 bytes with the published entry (constant-time). A mismatch,
or a missing entry, is classified **received-but-unspendable** on the
persisted row (`TransferDetails::unspendable`): the output is retained in the
ledger with the sender's transaction named, excluded from coin selection and
from `unlocked`, totalled separately (`get_balance.unspendable`) and shown
as the wallet-RPC state `UNSPENDABLE` with an `unspendable_reason`
(`FCMP_SPEND_LINKABILITY.md` §6.2, rule 82). The signer keeps a second
check as defence in depth — the derived `CM.x` against the chain's leaf
before proving (`TxBuilderError::PqcLeafMismatch`) — so a stale ledger can
never reach a proof failure. Consensus verifies neither half: only the
recipient can. The output's creator can recognise its spend (the sender
residual, `FCMP_SPEND_LINKABILITY.md` §13).

### Coinbase KEM self-encapsulation

Coinbase transactions do not carry `pqc_auths` (no real inputs to sign).
Coinbase outputs still need a distinct per-output leaf commitment in the curve
tree. When the miner address includes a PQC encapsulation key,
`construct_miner_tx` performs the same
hybrid KEM encapsulation **to the miner’s own address** for each coinbase
output as a transfer would: one 1120-byte hybrid ciphertext per output in the
`0x06` blob, standard HKDF per-output derivation, shared secret wiped after
use. This prevents all coinbase outputs to the same miner from sharing an
identical leaf-commitment pattern (which would link rewards). Spending a matured
coinbase then follows the normal recipient path (decapsulate from `tx_extra`,
rederive per-output keys, sign with `pqc_auths` on the spend transaction).

### Transaction Hash Computation

The txid is built in `shekyl_wire::transaction::txid` (`GENESIS_TX_WIRE_FORMAT.md`
§11): a coinbase mixes `H(prefix) · H(base) · null`; an FCMP++ spend mixes
`H(prefix) · H(base) · H(pqc_auths) · H(prunable) · len`, where `len` is the
archival length (prunable region plus `pqc_auths`). Coinbase transactions
omit PQC authorization fields; non-coinbase FCMP++ transactions must have
`pqc_auths.len() == vin.len()`.

The `prunable_hash` covers `fcmp_pp_proof`, `curve_trees_tree_depth`,
`pseudoOuts`, and `BulletproofPlus` range proofs.

---

## 5. Block Header Commitment

Each block header contains a `curve_tree_root` field (`crypto::hash`,
32 bytes) that commits to the state of the curve tree **at the block's own
height** — after its parent connected and before the block's own drain: the
state the block was built on, which the template reads at fill time, the
node's per-height record stores under the block's height, the wallet client
names as `drained_through = N − 1`, and the CT-2 KAT pins at height 61. The
connect check compares the field against that state **at admission, before
the block is added**; a mismatch rejects the block outright, never
connect-then-pop.

> **Ruled 2026-09-05 (fix authorized by Rick; census §7 #18).** This section
> previously said "after processing all transactions in the block", a state
> neither the template nor the client ever named, and the connect check
> compared the field against the root read *after* the add — so the two
> witnesses disagreed at every block where a leaf matures and every real
> nettype would have halted at height 60 (the S1 of §7 #17). The check now
> runs before the add against the tip root, on every nettype — the
> FAKECHAIN skip around it was retired in the same PR once the test
> generator computed real roots through the Rust curve-tree client.

### Serialization

The field is always serialized (genesis-native, no version gating) in both
the binary archive and Boost serialization. Initialized to `null_hash` at
genesis.

### Block Template Creation

`Blockchain::create_block_template` snapshots the current DB curve tree
root into the header before mining begins.

### Block Validation

CEN-B5 (`shekyl-chain-rules/src/rules/header.rs`) holds the header's
`curve_tree_root` to the node's own tree state at the block's height. A
mismatch rejects the block.

### RPC Exposure

Every block-header reply carries `curve_tree_root` as a hex string. The wire
type is `shekyl_rpc_types::BlockHeader` (`rust/shekyl-rpc-types/src/chain.rs`),
shared by `get_block_header_by_height`, `get_block_header_by_hash`,
`get_block_headers_range`, `get_last_block_header` and `get_block`.

### `get_curve_tree_path` — REJECTED (removed 2026-09-18, RPC 3.34)

`get_curve_tree_path` — **REJECTED** (spend-revealing; `PHASE_2A_SEND_PATH.md`
§3.0.1; `SOK-10` Q7 → A). The name is kept here so it is not re-minted
(rule 23): a per-output membership-path query tells the daemon, before
broadcast, exactly which output is being spent — the one boundary FCMP++
closed, with no ring to hide behind. The removed implementation was also
wrong on every chain carrying a transaction: it paired the leaf at tree
position `p` with the `(O, C)` of global output index `p`, and the two
orders diverge in the first block with a transaction (coinbase `+60` vs
transaction output `+10` maturity — see "tree position is **not** the same
as global output index" above).

**Where membership paths come from:** the wallet assembles them locally
from its block-derived leaf stream
(`shekyl_curve_tree::CurveTreeClient::assemble_path`), resolving its own
output by global index through the drain order and checking the
reconstructed root against the reference block's `curve_tree_root`. The
daemon serves no per-output path. A future light-wallet consumer needs a
**bulk, non-revealing leaf-range** service (`PHASE_2A_SEND_PATH.md` §3.0.2,
`CURVE_TREE_CLIENT.md` §"leaf range") — a design round in that consumer's
plan, not a restoration of this method. Record:
`docs/completed/SOK_10_PATH_POSITION_RESOLUTION.md`.

### `get_curve_tree_info` JSON-RPC

Returns the current curve tree state summary.

**Request:** `{}`

**Response:** `{ "root": hex, "depth": uint8, "leaf_count": uint64, "height": uint64 }`

### `get_curve_tree_checkpoint` JSON-RPC

Retrieves the curve tree after the block at a specific height (for
fast-sync). The chain store records the tree at every height, so any height
through the tip answers.

**Request:** `{ "block_height": uint64 }`

**Response:** `{ "root": hex, "depth": uint8, "leaf_count": uint64, "block_height": uint64 }`

Returns an error if no checkpoint exists at the requested height.

---

## 6. Per-Input Signed Payload Layout

Implementation entry point: `shekyl_wire::PqcSigningPreimage`
(`rust/shekyl-wire/src/transaction/signing_preimage.rs`) — the one
derivation, held to this layout by the captured KAT
`pqc_signing_preimage_v1.json`. The validator reaches it as CEN-I17
(`shekyl-chain-rules/src/rules/proofs.rs`), the submit path through
`shekyl-daemon-rpc/src/submit/verifier.rs`, and the wallet through
`shekyl_tx_builder::phase1_payload_hashes`.

Each `pqc_auths[i]` signs a payload that commits to the full transaction
state:

```text
signed_payload_i = cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(CtSigningBody)
    || H(serialize(CtSigPrunable))
    || serialize(PqcAuthHeader_i)
    || H(pqc_pk_0) || H(pqc_pk_1) || ... || H(pqc_pk_{N-1})
)
```

`H(serialize(CtSigPrunable))` is `cn_fast_hash` of the serialized prunable
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
| `referenceBlock` | `CtSigningBody` (in `CtSigBase`) | Anchors the tree snapshot |
| All key images | `TransactionPrefixV3` (in `vin`) | Prevents key image substitution |
| `fcmp_pp_proof` | `H(CtSigPrunable)` in signed payload | Direct proof binding |
| `pseudoOuts` | `H(CtSigPrunable)` in signed payload | Pseudo-output binding |
| `curve_trees_tree_depth` | `H(CtSigPrunable)` in signed payload | Tree depth binding |
| `BulletproofPlus` | `H(CtSigPrunable)` in signed payload | Range proof binding |
| `pqc_auths[i].hybrid_public_key` (the bytes `k` is derived from) | `PqcAuthHeader_i` + all-inputs hash tail | Full PQC key binding |

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
`CT_TYPE_FCMP` transactions in `shekyl-chain-rules` (`rules/tx_inputs.rs`,
`rules/tx_against.rs`, `rules/proofs.rs`).
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

Constants from `config/consensus_constants.json`
(`fcmp_reference_block_max_age`, `fcmp_reference_block_min_age`), read by
`shekyl-chain-rules/src/rules/tx_against.rs`:
- `FCMP_REFERENCE_BLOCK_MAX_AGE = 100` (~3.3 hours at 2-minute blocks)
- `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` (reorg safety margin)

> **Design rationale (MIN_AGE = 5):** Maturity is enforced by universal
> deferred tree insertion: outputs only enter the curve tree after their
> type-specific maturity period (coinbase: 60 blocks; every other output: 10
> blocks — the claim-era "staked" arm was retired with the confidential-staking
> cutover and never existed in code, CEN-L12).  MIN_AGE therefore only needs to
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

**What the anchor is (ruled 2026-09-04, CEN-I12).** The anchor is the
curve-tree state **at chain height `ref_height`**: the tree as it stands
after `referenceBlock`'s *parent* connects and before `referenceBlock`'s own
drain — a property of chain state, not of any one place that state is
written down. Every existing keying names that one state: the reference
block's header `curve_tree_root` was filled from it at template time, the
per-height record stores it under key `ref_height` (written by the parent's
connect under post-add keying; read through the store's `root_at`,
`shekyl-chain-store`), the wallet client names it `drained_through =
ref_height − 1` (`shekyl-curve-tree/src/client.rs:908`), and the CT-2 KAT
pins it at height 61. Two witnesses of it therefore exist — the header
field (the block's *attestation*) and the node's own per-height record —
and CEN-B5 is the consensus check that binds them (§5): at admission,
before the block's own drain, the header must equal the tip root. Until
2026-09-05 that binding held on no nettype — skipped on FAKECHAIN and,
everywhere else, comparing the header against the root *after* the drain
(census §7 #17, S1, fixed in §7 #18) — so the two witnesses agreed only
because the template filled the header honestly. Today it holds on every
nettype. One more reason
the verifier reads its **own computed record**, never the header; a rewrite
does the same in whatever form its store keeps that record. The prover holds no
store and reads the header ([`CURVE_TREE_CLIENT.md`](design/CURVE_TREE_CLIENT.md) §3.3); today its only
protection is its own leaf recompute against that header (`verify_root`
refuses to build against a root it cannot reproduce), and B5 is the
consensus-side binding of that header on every real nettype. The two reads
name one value on every network, and B5 binds them on every one, so nothing
makes the choice observable.

*Reconciled 2026-09-04:* this paragraph previously narrated a header read
the code stopped performing on 2026-04-13; the archaeology and the ruling
are in [`CONSENSUS_RULE_CENSUS.md`](design/CONSENSUS_RULE_CENSUS.md) §7 #16.

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
pqc_keys    = [ PqcKeyScalar::from_pqc_auth(scheme_id_i, hybrid_public_key_i)  # k = H_l(...)
                for i in 0..num_inputs ]
tree_root   = (from Step 2a)
tree_depth  = rv.p.curve_trees_tree_depth

result = shekyl_fcmp::proof::verify(
    proof, key_images, pseudo_outs, pqc_keys,
    tree_root, tree_depth, signable_tx_hash
)
```

### Step 5: PQC Commitment Opening (inside step 4)

There is no separate equality check: the verifier derives `K_i = k_i·G_k`
from each revealed key and the circuit proves, for the leaf each input
spends, `K_i + r_i·J = CM_i` (`PL-D3`). A key whose point the leaf does not
open to fails step 4 itself.

(The pre-`PL-D3` spec kept a separate verifier-side leaf-value equality here
as defence in depth; since `PL-D3`, 2026-09-14, no such check exists.)

### Step 6: Per-Input PQC Signature Verification

```text
6a. pqc_auths[i].auth_version == 1
6b. pqc_auths[i].scheme_id in {1, 2}   (single-signer or multisig)
6c. pqc_auths[i].flags == 0
6d. Compute signed_payload_i
6e. verify_pqc_auth(scheme_id, hybrid_public_key, hybrid_signature,
                    signed_payload_i, network) succeeds
```

`verify_pqc_auth` is `shekyl_crypto_pq::signature::verify_pqc_auth`; the
validator's step is `judge_signatures` in `shekyl-chain-rules/src/rules/proofs.rs`.

### Step 7: Bulletproof+ Range Proof Verification

Standard BulletproofPlus verification for output range proofs
(`shekyl-bulletproofs`), batched by the validator's range-proof rule
(`shekyl-chain-rules/src/rules/range_proof.rs`); the pseudo-output sum check
is `shekyl-ct-balance`.

---

## 8. Rust Implementation Map

Every FCMP++ component is Rust, and there is no FFI. Where each part lives:

| Concern | Crate (module) |
|---|---|
| Transaction wire format, `tx_extra` tags (`0x06`, `0x07`, `0x0D`), signing preimage, txid | `shekyl-wire` (`transaction.rs`, `tx_extra/`, `transaction/signing_preimage.rs`, `transaction/txid.rs`) |
| Prove, verify, the SAL, leaf scalars, tree hashing | `shekyl-fcmp` (`proof.rs`, `leaf.rs`, `tree.rs`), over `shekyl-fcmp-proofs` and the vendored `shekyl-oxide/crypto/fcmps` |
| Multisig SAL (FROST) | `shekyl-fcmp` (`frost_sal.rs`) |
| Output construction and scan, KEM, derivation, leaf commitment, hybrid signatures | `shekyl-crypto-pq` (`output.rs`, `kem.rs`, `derivation.rs`, `leaf_commitment.rs`, `signature.rs`) |
| Consensus: reference block, header root (CEN-B5), proofs, signatures, range proofs, the drain | `shekyl-chain-rules` (`rules/tx_against.rs`, `rules/header.rs`, `rules/proofs.rs`, `rules/range_proof.rs`, `drain.rs`) |
| Submit-path verification | `shekyl-daemon-rpc` (`submit/verifier.rs`) |
| Daemon store: curve-tree tables, per-height roots, transaction tables | `shekyl-chain-store` (`schema.rs`; pinned by `schemas/tables.snap`) |
| Wallet curve-tree replica and path assembly | `shekyl-curve-tree` (`client.rs`, `assemble.rs`, `reference.rs`) |
| Wallet signing | `shekyl-tx-builder`, driven by `shekyl-engine-core` |
| Addresses and proof blobs (Bech32m) | `shekyl-address`, `shekyl-encoding` |

### Invariants

1. **A path carries every branch layer up to the root.** `tree_depth`
   counts the leaf layer, so a path holds one branch layer for each layer
   above it: `c1_layers.len() + c2_layers.len() + 1 == tree_depth`.
   `shekyl-curve-tree/src/assemble.rs` refuses a path with fewer or more.
2. **A layer hash is a point; its parent takes it as a scalar.** Each layer
   stores points on its own curve (Selene, Helios alternating). A branch
   witness converts them to scalars on the parent curve
   (`selene_point_to_helios_scalar` / `helios_point_to_selene_scalar` in
   `shekyl-fcmp/src/tree.rs`).
3. **FCMP++ key images are not y-normalized.** The key image `I = x·Hp(O)`
   is used as-is. Clearing the sign bit of byte 31 (Monero's
   `key_image_y_normalize`) breaks the Ed25519 batch verification, because
   the prover computes `I` algebraically while the verifier would receive
   the modified value.
4. **PQC signing has two phases.** The signing preimage
   (`PqcSigningPreimage`) binds every input's `hybrid_public_key` into every
   input's message, so every key is placed in `tx.pqc_auths[i]` before any
   input is signed (`shekyl_tx_builder::phase1_payload_hashes`).

---

## 9. Database Schema

The daemon's store is `shekyl-chain-store` (redb). Its tables are declared
in `rust/shekyl-chain-store/src/schema.rs` and pinned by
`schemas/tables.snap` (rule 42: a persisted change bumps the schema
version). The curve tree lives in `curve_tree_leaves`, `curve_tree_layers`,
`curve_tree_meta`, `curve_tree_roots` (the root at every height, §12) and
`curve_tree_leaf_counts`, with `output_to_leaf` / `leaf_to_output` mapping
tree position to global output index. Transactions are split across
`txs_pruned`, `txs_pqc_auths` and `txs_prunable`, with the digests
`txs_prunable_hash` and `txs_pqc_auth_hash` kept on every node as txid
operands.

**Invariant (PQC restore).** No discard may delete or truncate the retained
transaction prefix in a way that removes `tx_extra` while leaving outputs
discoverable, or the ML-KEM ciphertexts (`0x06`) that wallet restore and PQC
key re-derivation read would be lost. S-PRUNE
(`docs/design/DRS_E1_SPRUNE.md`) inherits this as a constraint on its
predicate.

---

## 10. Per-Output PQC Key Derivation

Every output has a unique PQC keypair derived deterministically from the
combined KEM shared secret, enabling wallet restore from seed.

### Hybrid KEM (Unclamped Montgomery DH + ML-KEM-768)

The sender performs a hybrid key encapsulation to derive a per-output
shared secret. The classical component uses unclamped Montgomery DH over
Curve25519 — **not** RFC 7748 X25519. The recipient's X25519 public key is
not transmitted in the address; it is derived from the Ed25519 view public
key via the canonical Edwards→Montgomery birational map.

For the full specification of the X25519 derivation, unclamped DH
semantics, and low-order point rejection rules, see
`POST_QUANTUM_CRYPTOGRAPHY.md` §X25519 Binding to View Key and
§DH Semantics.

```text
1. Montgomery DH:  ss_classical = ephemeral_scalar * recipient_x25519_pk
                   (unclamped; recipient_x25519_pk = EdwardsToMontgomery(view_pub))
2. ML-KEM-768:     ss_pq, ciphertext = ML-KEM-768.Encaps(recipient_ml_kem_pk)
3. Combined:       shared_secret = HKDF-SHA-512(
                       salt = "shekyl-kem-v1",
                       ikm  = ss_classical || ss_pq,
                       info = ""
                   )
```

Recipients MUST reject low-order Montgomery points on `kem_ct_x25519`
before performing DH (see `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics).

The hybrid KEM ciphertexts are stored in `tx_extra` as
`tx_extra_pqc_kem_ciphertext`: tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (`0x06`),
field `blob` = concatenation of **N** 1120-byte hybrid ciphertexts
(`x25519_ephemeral_pk[32] || ml_kem_768_ct[1088]`, N = number of outputs),
in vout order.

### Per-Output Keypair Derivation

From the combined shared secret, each output derives its own PQC keypair
using the unified `OutputSecrets` HKDF stream (salt B =
`shekyl-output-derive-v1`):

```text
ml_dsa_seed = OutputSecrets.ml_dsa_seed   // HKDF info: "shekyl-pqc-output" || output_index_le64
ml_dsa_keypair = ML-DSA-65.KeyGen(seed = ml_dsa_seed)
```

This is implemented in `rust/shekyl-crypto-pq/src/output.rs` as
`construct_output` and `scan_output_recover`. The block template and the
genesis builder call `construct_output` for coinbase outputs; the wallet
scans with `scan_output_recover`. Signing derives the per-output keypair
inside `shekyl-crypto-pq` from `combined_ss`, signs and wipes
(`sign_pqc_auth_for_output`); the leaf entry (`leaf_commitment.rs`,
`derive_pqc_leaf`) is derived the same way and returns no secret.


### Wallet Restore from Seed

Key derivation is implemented in `rust/shekyl-crypto-pq/src/account.rs`
(the single source of truth; see the crate docstring for the full
diagram, and [`NETWORK_IDENTITY.md`](design/NETWORK_IDENTITY.md) NI-R7 and
NI-R10 for the rulings). It is pinned by the `ADDRESS_DERIVATION_V3`
vector suite and its independent oracle. In outline:

```text
seed                = 32 random bytes, on every network: the wallet's
                      one secret, shown to the user as BIP-39's 24 words
                      (the words spell the bytes; no PBKDF2 step, no
                      passphrase)

master_seed_64      = HKDF-SHA-512(salt="shekyl-seed-normalize-v1",
                                   ikm=seed, L=64)

name_id             = cSHAKE256(S="shekyl/network-name-v1",
                                X=tag)[..16]
                      (tag = the network's name, "shekyl/<network>")
salt                = name_id || "shekyl-master-derive-v3"
spend_wide          = HKDF-SHA-512(salt, ikm=master_seed_64,
                                   info="shekyl-ed25519-spend", L=64)
view_wide           = HKDF-SHA-512(salt, ikm=master_seed_64,
                                   info="shekyl-ed25519-view",  L=64)
d_z                 = HKDF-SHA-512(salt, ikm=master_seed_64,
                                   info="shekyl-ml-kem-768",    L=64)

spend_sk, view_sk   = Scalar::from_bytes_mod_order_wide(...)   (unclamped)
ml_kem_768 (ek,dk)  = keygen(SeededRng::from_seed(
                        SHA3-256("shekyl-mlkem-chacha-seed" || d_z)))
                      (those bytes are what ChaCha20Rng::from_seed produces)
```

All key material, classical and PQC, is therefore a pure function of
the seed and the network's name. The wallet file stores the 32-byte
seed (`docs/WALLET_FILE_FORMAT_V1.md` §2.2); every open rederives the
full key set from it and checks the recomputed classical address
against the file's expected-address bytes.

On restore, the wallet re-scans the chain for owned outputs. Per-output
PQC shared secrets are recomputed during the scan by decapsulating with
the account-level ML-KEM decapsulation key; nothing per-output needs to
be present in the wallet file for restore to succeed.

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
funds (the PQC segments carry the ML-KEM-768 encapsulation key; the X25519
public key is derived from the view key in the classical segment — see
`POST_QUANTUM_CRYPTOGRAPHY.md` §X25519 Binding to View Key).

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

`shekyl-crypto-pq` re-exports `shekyl-address` as its `address` module.
Wallet proofs, message signatures and signer keys are `shekyl-encoding`
blobs with purpose-specific HRPs. There is no Base58 code path.

---

## 12. Checkpoint and Pruning Strategy

### Curve Tree Checkpoints

The Rust chain store keeps the tree's root and leaf count at every height
(`curve_tree_roots`, `curve_tree_leaf_counts`; `shekyl-chain-store`
`schema.rs`), and `get_curve_tree_checkpoint` answers from them for any
height through the tip. There is no separate interval checkpoint table: it
would be a second source for rows that already exist (CTW-Q3).

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

Under archival pruning
(`docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md`) **every** daemon discards the
same good — the prunable region + `pqc_auths` — **shard-granularly** at
`[b_k, b_{k+1})` at the epoch boundary after the shard's freeze epoch
(`current_epoch ≥ close_epoch(k) + 2`; `PDM-Q2`, re-ruled 2026-09-22), never
a transaction at a time and never at an operator-chosen depth. The prunable **hash** and `txs_pqc_auth_hash` stay on every node as
the txid's operands; the bodies are served from the bonded archivers'
wallet-side stores and the Foundation floor. That discard is **S-PRUNE**,
Rust, on the redb store (`docs/design/DRS_E1_SPRUNE.md`), and its frontier is
chain-derivable (the largest `k` the predicate admits) rather than a stored
watermark.

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

A transaction's stateless judgement — its form, signatures, proofs against
the reference claim, and range proof — is a function of its bytes, the rule
set, the network and the claim the chain made for its reference. The
validator returns it as a `StatelessPass` (`shekyl-chain-rules/src/validate.rs`,
`judge_lone_stateless`), and the pool keeps it beside each held transaction
(`shekyl-mempool/src/door.rs`). While the transaction's rule set and claim
hold, the pass is the answer again: the pool re-judges only the view-bound
half (`tx_against` and the policy) as the chain moves, and nothing is
verified twice (CEN-M8).

---

## 15. Staking and FCMP++

**Genesis disposition (2026-06 — transfer-shaped admission).** The leading genesis
staking form ([`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md) §2.4)
does **not** ship Decision **3C** below. Admission principal lives on the **main tree**
as ordinary FCMP++ transfers (principal ↔ HKDF-derived **`P`** sub-wallet); only
**bond** (gate 4) and **reward emission** are consensus-special. Cleartext
`txout_to_staked_key` and the separate staking subtree are **deletion targets** for
genesis — the subtree was **docs-only**, never implemented in production code.

**Historical — Decision 3C (confidential-claim path; not genesis):**

Staked outputs (`txout_to_staked_key`) were designed to live in a **separate staking
subtree** with a **160-byte / 5-scalar** leaf (Decision 3C —
[`V3_STAKER_ARCHIVAL.md`](V3_STAKER_ARCHIVAL.md) §2, §6.4.3). The **main tree**
(all non-staked outputs) keeps the **128-byte / 4-scalar** leaf, unchanged.

```text
Staking-subtree leaf (160 B):
  [  0: 32]  O.x
  [ 32: 64]  I.x
  [ 64: 96]  C.x       // C_stake = z·G + amount·H   (plain Pedersen — no τ·H_t)
  [ 96:128]  h_pqc      = shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)
  [128:160]  h_bind     = H("stake-bind" ‖ tier ‖ creation_height)   // consensus-set at inclusion
```

> **Never built (census `d-5`, 2026-09-14).** No 5-scalar staking leaf, no
> `h_bind`, and no stake-claim leaf cross-check exist in the tree; staking
> is bond-record state (`ARCHIVAL_*`), and the main tree's 4th scalar is
> `CM.x` (`PL-D3`), not a key hash. This passage is kept as the record of a
> Round-2 design that was superseded before implementation.

**Tier + creation** are bound by `h_bind` (5th scalar): consensus stamps exact
`creation_height` at inclusion (the staker does not know mining height at build time), and
the claim proves subtree membership + `h_bind` equality against the **revealed**
`(tier, creation)`. The accrual window is then **pure arithmetic**
(`creation < S ≤ creation + tier_lock`) — no historical-root checkpointing.

**Implementation notes (Round 2):**

- `SCALARS_PER_LEAF` generalizes from a const to a **per-tree parameter** (`=5` for the
  staking subtree, `=4` for the main tree); the 5th-position Selene generator is a **NUMS
  consensus constant** under the cbindgen consensus-constant guard, with a KAT.
- The leaf-layer Selene MSM grows from `4·W` to `5·W` terms **for the staking subtree only**
  (~+25% on that hash); main-tree hashing and all Helios/Selene layers above the leaf are
  untouched. Off the wallet-scan/decap path (no block-loading impact).
- The **locked witness header** (now `[O][I][C][CM][r][x][y][z][a]`, 288 B) is **untouched** — `h_bind` is
  a public membership input recomputed by the verifier, **not** a witness field.
- Stake-creation and unstake are **cross-tree transitions** (main↔subtree); `pop_block`
  rewinds both atomically. Leaves are append-only, so claim-after-unstake works.

**Legacy note:** cleartext-claim code compared `H(pqc_pk)` on all output types; confidential
claims require the staking-subtree `h_bind` binding above. No compatibility shim for
pre-genesis implementations.

**Universal deferred curve-tree insertion:** Every output drains into the
curve tree only once it matures, and maturity is a function of height and
origin alone: a coinbase output matures `mined_money_unlock_window` (60)
blocks after its block, every other output `tx_spendable_age` (10) blocks
after (`RuleSet::GENESIS`, `shekyl-chain-rules/src/rule_set.rs`). The set that drains when the
block at `h` connects is therefore a function of the chain below `h` —
block `h − 60`'s coinbase outputs, then block `h − 10`'s listed outputs, in
that order — computed by `shekyl-chain-rules/src/drain.rs` from the store's
view, never read from a pending table. Drain order is not output order, so
`output_to_leaf` / `leaf_to_output` (`shekyl-chain-store`) map between tree
position and global output index.

Because `FCMP_REFERENCE_BLOCK_MIN_AGE` (5) is now a reorg safety margin
only (not a maturity enforcement mechanism), the tree is guaranteed to
contain only matured outputs.

**Lock-tier claim validation (`txin_stake_claim`) is retired.** Genesis
staking does not use lock-tier claims. Archival reward emission is specified
in [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) (membership-only
backing + work payload; dedup on the bond record). FCMP++ membership proofs
for ordinary spends are unchanged.

**PQC ownership binding** for **regular** spends: the circuit proves `leaf[96:128] = (K + r·J).x` with `K = PqcKeyScalar::from_pqc_public_key(pqc_pk)·G_k` (`PL-D3`); no verifier-side equality on the leaf value exists.

Lock-tier staked-output / `txin_stake_claim` PQC checks, claim-reward fingerprinting
rules, the claim sub-path of input checking, claim-transaction construction, batch pool
balance, and stake-claim input sorting are **retired** with the claim-era model.
Do not reintroduce them. Archival emission is a different vin
([`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md)).

---

## 16. Failure Modes

Each failure is a typed refusal from `shekyl-chain-rules`; the transaction
or the block that carries it is rejected.

| Check | Failure |
|-------|---------|
| referenceBlock unknown | Block hash not on the chain |
| referenceBlock too old | `ref_height < tip - MAX_AGE` |
| referenceBlock too recent | `ref_height > tip - MIN_AGE` |
| tree depth out of range | `curve_trees_tree_depth` 0 or > current |
| key_offsets non-empty | Ring members present in FCMP++ tx |
| key image not y-normalized | Sign bit set on key image |
| FCMP++ proof invalid | `shekyl_fcmp::proof::verify` does not accept |
| `pqc_auths` count mismatch | `pqc_auths.len() != vin.len()` |
| PQC signature invalid | `verify_pqc_auth` refuses |
| Key image double-spend | Key image already spent on the chain |

---

## 17. Constants

| Constant | Value | Location |
|----------|-------|----------|
| `fcmp_reference_block_max_age` | 100 | `config/consensus_constants.json` (`REFERENCE_BLOCK_MAX_AGE`, `shekyl-chain-rules/src/rules/tx_against.rs`) |
| `fcmp_reference_block_min_age` | 5 (reorg safety margin) | `config/consensus_constants.json` |
| `MAX_FCMP_INPUTS` | 8 | `shekyl-wire/src/transaction.rs` |
| `CT_TYPE_FCMP` | 1 | `shekyl-wire/src/transaction.rs` |
| `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` | 0x06 | `shekyl-wire/src/tx_extra/mod.rs` |
| `TX_EXTRA_TAG_PQC_LEAF_ENTRIES` | 0x07 | `shekyl-wire/src/tx_extra/mod.rs` |
| `ML_KEM_768_CT_BYTES` | 1088 | `shekyl-wire/src/tx_extra/mod.rs` |
| `X25519_CT_BYTES` | 32 | `shekyl-wire/src/tx_extra/mod.rs` |
| `HYBRID_KEM_CT_BYTES` | 1120 (32 + 1088) | `shekyl-wire/src/tx_extra/mod.rs` |
| `PQC_LEAF_ENTRY_LEN` | 64 (`CM ‖ record` per output, `PL-D3`) | `shekyl-wire/src/tx_extra/mod.rs` |
| `COINBASE_NONCE_BYTES` | 8 (coinbase `0x02`, fixed; `TXE-Q6′`, `CEN-I20`) | `shekyl-wire/src/tx_extra/coinbase.rs` |

---

## 18. Implementation Status

Every component in this document is built in Rust; §8 says where each one
lives. Identifier-level status (rulings, census rows, open items) is
`docs/design/IMPLEMENTATION_INDEX.md`, and residue is `docs/FOLLOWUPS.md`.

---

## 19. Testing & Fuzzing

### Fuzz Targets

Ten `cargo-fuzz` targets exercise the critical parsing, crypto, multisig, and staking boundaries:

| Target | Crate | What it tests |
|--------|-------|---------------|
| `fuzz_fcmp_proof_deserialize` | `shekyl-fcmp` | Malformed, truncated, and oversized proof blobs |
| `fuzz_curve_tree_leaf_hash` | `shekyl-fcmp` | Arbitrary 4×32-byte leaf inputs, key-scalar canonicality, commitment-point admission vs. leaf-scalar definedness |
| `fuzz_block_header_tree_root` | `shekyl-fcmp` | Mismatched `curve_tree_root` between prove and verify |
| `fuzz_bech32m_address_decode` | `shekyl-crypto-pq` | Random strings through Bech32m decoder, wrong HRPs, bad checksums |
| `fuzz_kem_decapsulate` | `shekyl-crypto-pq` | Corrupted ML-KEM ciphertexts, wrong-length keys and ciphertexts |
| `fuzz_multisig_verify` | `shekyl-crypto-pq` | Multisig verify path with malformed key blobs, signatures, and payloads |
| `fuzz_multisig_key_blob` | `shekyl-crypto-pq` | Randomized multisig key-blob decode and bounds checks |
| `fuzz_multisig_sig_blob` | `shekyl-crypto-pq` | Randomized multisig signature-blob decode and validation |
| `fuzz_claim_reward` | `shekyl-staking` | Random accrual records; reward overflow, monotonicity, and bound invariants |
| `fuzz_tx_deserialize_fcmp_type7` | `shekyl-fcmp` | Transaction-structured FCMP++ deserialization: pseudoOuts, proof blobs, PQC leaf entries, corrupted types |

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
consistency between `pqc_key_scalar` and
`PqcKeyScalar::from_pqc_public_key`.

```bash
cd rust && cargo test --workspace
```

### Staking Tests

Lock-tier `txin_stake_claim` / `txout_to_staked_key` tests were
**claim-era** and are not a genesis gate. Archival emission and bond-post
tests live with the `REWARD_EMISSION_*` / `ARCHIVAL_*` designs and their
crates.

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

The FCMP++ Rust crypto stack descends from the
[Shekyl Foundation monero-oxide fork](https://github.com/Shekyl-Foundation/monero-oxide)
(`fcmp++` branch). After the un-vendor (slice 2, `SHEKYL_OXIDE_UNVENDOR.md`), the
proof/generator/support crates are **first-party** `shekyl-*` crates (relocated out
of the vendored tree, no longer upstream-tracked); only the research crypto remains
vendored under `rust/shekyl-oxide/crypto/`. `rust/shekyl-fcmp/Cargo.toml` consumes
them by path:

- `shekyl-fcmp-proofs` (first-party — the FCMP++ SAL/membership proofs; was `shekyl-fcmp-plus-plus`)
- `shekyl-curve-generators` (first-party; was `shekyl-generators`)
- `helioselene` (vendored crypto)
- `ec-divisors` (vendored crypto)

### Current Pin

The vendored snapshot source of truth is:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`

This metadata records the upstream repo/branch/commit used for the current
vendored crate copy.

### Circuit Integration Status

The `full-chain-membership-proofs` circuit in the monero-oxide fork has been
modified to support Shekyl's 4-scalar leaf format. The `FcmpCurves` trait now
includes `const EXTRA_LEAF_SCALARS: usize = 1`, and `Curves` in the
`shekyl-fcmp-proofs` wrapper sets this to `1`. `FcmpPlusPlus::verify` takes
each input's key point `K` (`InputVerification::pqc_key_point`); the
circuit's `first_layer` claims the spent leaf's commitment `CM`, proves the
discrete log of `r·J`, and constrains `K + r·J = CM` before appending `CM.x`
to the membership tuple (`PL-D3`).

**x-only leaf optimization:** During implementation, we discovered that the
upstream circuit's internal (x,y) coordinate representation for O, I, C was
unnecessary for the flat leaf array and membership proof. The `on_curve` and
blinding proof gadgets still operate on full (x,y) points internally, but
the leaf flattening (`flatten_leaves`) and `tuple_member_of_list` membership
gadget now use **x-only coordinates**:

```text
Upstream (original):  [O.x, O.y, I.x, I.y, C.x, C.y]   — 6 scalars per output
Shekyl (implemented): [O.x, I.x, C.x, CM.x]             — 4 scalars per output
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
- `prove()` takes the transaction's `signable_tx_hash` for binding and
  returns the proof with its pseudo-outs (`ProveResult`).

### Upstream Security Fixes Status

19 commits on upstream `main` are not yet merged into `fcmp++`. The three
security-critical commits have been audited against the Shekyl fork:

| Commit | Issue | Status |
|--------|-------|--------|
| `b6d3e44` | Base58 overflow fix, identity/torsion point rejection | **Base58 fixed** (`checked_add` + non-canonical rejection). Identity/torsion checks already present in fork. |
| `a941dff` | Varint length fix for zero | **Not applicable** — fork uses different formula that correctly returns 1 for zero. |
| `c8be5d3` | Gate debug `Extra::write` assertions | **Not applicable** — fork's `Extra::write` was refactored without debug assertions. |

**Base58 defense-in-depth note:** Shekyl core has fully migrated to Bech32m.
Shekyl has no Base58 code: addresses are `shekyl-address`, wallet proofs
`shekyl-encoding`. The monero-oxide fork's wallet
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
| DKG offset introspection | Removed (`legacy_multisig.rs` deleted) | Resolved — legacy multisig removed; modern SAL in `sal/multisig.rs` |
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

## 20. Two-Component Output Keys (O = xG + yT)

### Problem

FCMP++ SAL (Spend-Authorization and Linkability) proves knowledge of `(x, y)`
such that `O = xG + yT`. The `OpenedInputTuple::open` function enforces:

```
x*G + (y + r_o)*T == O~    =>    x*G + y*T == O
```

Legacy Monero-style outputs use single-component keys `O = xG` (equivalently
`O = xG + 0*T`), so the SAL `y` for these outputs is zero. Previously, the
wallet incorrectly passed the Pedersen commitment mask `z` as `y`, causing
`open()` to check `x*G + z*T == O` which fails for all non-zero `z`.

### Design

Every output public key is now:

```
O = Hs(derivation || i) * G + B + Hs_y(derivation || i) * T
```

Where:
- `Hs(derivation || i)` is the existing x-derivation scalar (unchanged)
- `Hs_y(derivation || i)` is a domain-separated y-derivation scalar using
  the `"shekyl_y"` salt prefix
- `B` is the recipient's spend public key
- The full spend key is `x = Hs(derivation || i) + b`
- The SAL secret is `y = Hs_y(derivation || i)`

### Domain Separation and y-Derivation Migration

**Canonical (PR-construct and beyond):** All per-output secrets (`ho`, `y`,
`z`, `k_amount`, `view_tag_combined`, `amount_tag`, `ml_dsa_seed`) are derived
from the unified HKDF-SHA-512 stream using the combined KEM shared secret
(`X25519_ss || ML-KEM_ss`). Each uses a distinct HKDF info string:

| Secret | HKDF Salt | HKDF Info |
|--------|-----------|-----------|
| `ho` (x-derivation) | `shekyl-output-derive-v1` | `shekyl-output-x \|\| output_index_le64` |
| `y` (T-component) | `shekyl-output-derive-v1` | `shekyl-output-y \|\| output_index_le64` |
| `z` (commitment mask) | `shekyl-output-derive-v1` | `shekyl-output-mask \|\| output_index_le64` |
| `k_amount` | `shekyl-output-derive-v1` | `shekyl-output-amount-key \|\| output_index_le64` |
| `view_tag_combined` | `shekyl-output-derive-v1` | `shekyl-output-view-tag \|\| output_index_le64` |
| `amount_tag` | `shekyl-output-derive-v1` | `shekyl-output-amount-tag \|\| output_index_le64` |
| `ml_dsa_seed` | `shekyl-output-derive-v1` | `shekyl-pqc-output \|\| output_index_le64` |

For `ho`, `y`, `z`: 64 bytes are expanded and reduced mod Ed25519 scalar
order `l` (wide reduce). For `k_amount`, `ml_dsa_seed`: 32 bytes expanded.
For `view_tag_combined`, `amount_tag`: first byte of expanded output.

Test vectors: `docs/test_vectors/PQC_OUTPUT_SECRETS.json`
Reference implementation: `tools/reference/derive_output_secrets.py`

**X25519-only view tag (fast scan):** A separate view tag is derived from
the X25519 shared secret alone (no ML-KEM decapsulation needed), enabling
fast pre-filtering during wallet sync:

| Secret | HKDF Salt | HKDF Info |
|--------|-----------|-----------|
| `view_tag_x25519` | `shekyl-view-tag-x25519-v1` | `shekyl-view-tag \|\| output_index_le64` |

The scanner checks `view_tag_x25519` first (cheap: one X25519 + one HKDF).
On match, it performs full ML-KEM decap and verifies `view_tag_combined` as
a cross-check (DoS hardening).

All construction and scanning paths use the HKDF derivation above
(`construct_output`, `scan_output_recover` in `shekyl-crypto-pq`).

### Commitment Mask Independence

The Pedersen commitment `C = z*G + amount*H` uses a mask `z` that has
**nothing to do with `y`**. In the proof pipeline:

- `y` is passed to `OpenedInputTuple::open` (SAL verification of O)
- `z` is used to compute `r_c = a - z` for pseudo-out rerandomization
- `a` is the desired pseudo-out blinding factor

### Encrypted Amounts Wire Format

Per-output encrypted amounts use `enc_amounts` (9 bytes each) instead of
the legacy `ecdhInfo` (`ecdhTuple`):

```
[8 bytes: amount XOR ecdhHash(k_amount)] [1 byte: amount_tag]
```

- `ecdhHash(k)` is `cn_fast_hash("amount" || k)`, truncated to 8 bytes
- `amount_tag` is derived from HKDF `OutputSecrets.amount_tag` (1 byte)
- `ecdhTuple`, `ecdhEncode`, and `ecdhDecode` have been removed from the codebase
- Production signing (`shekyl-tx-builder`) takes the 9-byte `enc_amount`
  values `construct_output` produced

### Encrypted Labels Wire Format (5-T, FA-11)

Per-output logical labels use `enc_labels` in `CtSigBase` (9 bytes each),
serialized immediately after `enc_amounts` and before `outPk`:

```
[8 bytes: label_plaintext XOR k_label[..8]] [1 byte: label_tag]
```

- Launch default **plaintext** is the sentinel block `0xFF…` (`SENTINEL_PLAINTEXT`);
  on-wire `enc_label` is `plaintext XOR k_label[..8]` per output — **never**
  a fixed `0xFF` wire constant (that would fingerprint all non-merchant pays).
- `label_tag` is the first byte of HKDF-Expand(`shekyl-output-label-tag` ‖ index);
  verified at scan like `amount_tag` (integrity / fast-reject only — **not** a
  cleartext sentinel-vs-tag discriminator).
- Included in `serialize_ctsig_base` (transaction binding / prehash). **Not** part of the FCMP++ leaf witness.
- Label ciphertext has **no** Pedersen commitment backstop (unlike amounts). Prehash binding is the sole relay-tamper defense; AEAD is redundant once bound. CI: `fcmp.enc_label_binds_ctsig_base_prehash`.
- ~~`genRctFcmpPlusPlus` rejects all-zero `enc_labels` outside fake/test
  device mode~~ — **superseded 2026-08-23 by a type; the guard itself was
  deleted 2026-08-22 with its host.** Kept as a record because the invariant
  outlived both.

  Deleting the guard lost no coverage: `genRctFcmpPlusPlus` had no caller, so
  the check was unreachable and enforced nothing. The invariant it *stated* was
  real, though not for the obvious reason — an all-zero *plaintext* is
  harmless, since `0x00…00 XOR k_label[..8]` is uniform and §5.7.10 holds for
  it exactly as for the sentinel. What the guard was aimed at is a path that
  writes the field **without encrypting it at all**
  (`fill_construct_tx_rct_stub`, since deleted, value-initialised `enc_labels`
  and never called the label encryption), which put a literal `00×9` on the
  wire, identical
  across every output, with `label_tag` zero where a derived tag is uniform.

  The Rust signing path *used to* carry the same shape: `enc_label` was a plain
  `[u8; 9]` on `OutputInfo`, so an unencrypted value was representable there
  too. It is not any longer. `EncryptedOutputField`
  (`shekyl-crypto-pq/src/encrypted_output_field.rs`) has no public byte
  constructor — in-process construction is `OutputData::enc_label_wire()` /
  `enc_amount_wire()` (the value `construct_output` assembled at encryption),
  so an unencrypted field is **unrepresentable**, not merely rejected. Deliberately not implemented as "reject zeros": that treats one
  symptom, admits any other unencrypted constant, and can fire on a legitimate
  ciphertext that happens to be zero.

- KAT: `PQC_OUTPUT_SECRETS.json` includes `enc_label_sentinel` / `enc_label_sentinel_9` wire octets.
- `construct_output` / wallet signing supply pre-computed 9-byte values parallel to `enc_amount`.
- **Indistinguishability invariant (normative home: `SUBADDRESS_UNDER_PQC.md`
  §5.7.10).** `enc_label` octets are computationally indistinguishable from
  uniform to any non-recipient, *independent of plaintext*; the real-label and
  sentinel wire distributions are identical. Real-label population is therefore
  **ungated** (the R2-F8 `cooperative_payment_requests` wallet flag was retired
  2026-06-15) — it withholds nothing from an observer that the sentinel does
  not. The mandatory-uniform-wire pin is unchanged. Enforced by the
  `real_label_indistinguishable_from_sentinel` statistical KAT.

### Prover Inputs

Each input's prover witness is `shekyl_fcmp::ProveInput`
(`rust/shekyl-fcmp/src/proof.rs`), beside its leaf chunk and branch layers:

| Field | Purpose |
|-------|---------|
| O | Output public key (curve tree leaf) |
| I | Key image generator Hp(O) |
| C | Pedersen commitment (curve tree leaf) |
| CM | PQC leaf commitment point `k·G_k + r·J` (compressed Ed25519) |
| r | The commitment's blind — the opening leg's witness |
| x | SAL spend secret key (`ho + b_spend`) |
| y | SAL output-key secret (HKDF-derived) |
| z | Pedersen commitment mask (HKDF-derived) |
| a | Pseudo-out blinding factor |

### Security Properties

- **Spend-auth vs discovery**: A view-key holder can compute `y` (derived
  from the shared secret), so `y` alone does not provide spend/view
  separation. Full separation requires a Carrot-style address scheme
  (V4 consideration). The y-component binds the key image to a
  recipient-controlled blinder, which is the SAL design requirement.
- **FROST SAL multisig**: An Option E′ output's T-component is
  `y_group + y_kem`: `y_group` is the FROST group secret, shared M-of-N;
  `y_kem` is the per-output tweak every member derives from the shared
  secret. The signers' keys are offset by `y_kem` and the rerandomization
  before signing (`shekyl_fcmp::frost_sal`; `PQC_MULTISIG.md` §15.4a).
- **Coinbase commitment mask**: `zeroCommit(amount) = G + amount*H`, so the
  mask scalar is 1 (`ct::identity()`), not 0.

---

## 21. Wallet Proof Structure

Shekyl wallet proofs (transaction proofs and reserve proofs) are a
genesis-native design. There is no prior version, no migration path, and
no backward-compatibility shims. The design draws on Monero's proof
protocols as prior art but differs structurally due to the hybrid KEM
construction. This section explains the design rationale so auditors
familiar with Monero's DLEQ-based proofs understand why Shekyl's proofs
use a different construction and why the difference is not a regression.

### Why Monero's DLEQ does not apply

In Monero, the sender proves they constructed a transaction by
demonstrating knowledge of the discrete log behind both `tx_pubkey` (the
on-chain Diffie-Hellman ephemeral key) and the shared secret derivation
base. A single DLEQ proof does double duty: it proves sender identity
*and* binds the proof to a message. Shekyl replaces Diffie-Hellman with
hybrid KEM (X25519 + ML-KEM-768), so there is no discrete-log
relationship between the transaction key and the shared secret. The DLEQ
construction is inapplicable, not merely unnecessary.

### Shekyl's decomposition

Shekyl decomposes sender authentication and proof integrity into two
independent mechanisms:

- **KEM recomputation** handles "the prover really is the sender." The
  sender reveals `tx_key_secret` (a per-transaction ephemeral value, not
  a long-term key). The verifier re-runs deterministic KEM encapsulation
  with that key and checks that the resulting X25519 ephemeral public key
  and ML-KEM-768 ciphertext match the on-chain values. A match proves
  the prover produced the transaction's KEM material.

- **Ed25519 Schnorr signature** handles "the proof contents are not
  tampered." The signature is bound to
  `H(domain_separator || txid || address || message || per_output_data)`,
  making the proof a sealed unit. Anyone holding the revealed
  `tx_key_secret` can produce a *different* proof for a different
  message, but they cannot take an existing proof and modify a field
  without invalidating the signature. The signature protects the proof
  from the verifier (or any third party who later obtains the key), not
  from the world.

Each proof type uses a distinct domain separator in the Schnorr hash to
prevent cross-type replay:

| Proof Type | Domain Separator |
|---|---|
| Outbound TX | `shekyl-outbound-tx-proof-v1` |
| Inbound TX | `shekyl-inbound-tx-proof-v1` |
| Reserve | `shekyl-reserve-proof-v1` |

### Reserve proofs and the DLEQ requirement

TX proofs assert "outputs were sent to / received by an address with
certain amounts." Reserve proofs assert "outputs are owned and
**unspent**." The unspent claim requires proving that the key image
included in the proof was correctly derived: `key_image = (ho + b) ·
Hp(O)`. Without this proof, a malicious prover can substitute a random
32-byte value as the key image; the verifier checks the spent pool, finds
no match, and incorrectly concludes the output is unspent. This is a
reserve-proof forgery — the class of attack that breaks exchange
proof-of-solvency.

Reserve proofs therefore carry a standard two-base Schnorr DLEQ (64 bytes
per output: challenge `c` + response `s`) proving
`DL_G(P) == DL_{Hp(O)}(I)` where `P = O - y·T` and `I = key_image`. TX
proofs do not need a DLEQ because they make no claim about spent status.

The DLEQ challenge hash includes the bases, points, and a domain
separator to prevent cross-protocol confusion:

```text
c = H("shekyl-reserve-proof-dleq-v1" || G || Hp(O) || R1 || R2 || P || I || msg)
```

`G` is a constant but is included for completeness. `Hp(O)` varies per
output and its inclusion is mandatory to prevent base-substitution
attacks across different outputs.

### Wire Format

| Proof Type | Header | Per-Output | Total |
|---|---|---|---|
| Outbound TX | 101 B (version[1] + tx_key_secret[32] + Schnorr[64] + count[4]) | 128 B (ho, y, z, k_amount) | `101 + 128*N` |
| Inbound TX | 69 B (version[1] + Schnorr[64] + count[4]) | 128 B (ho, y, z, k_amount) | `69 + 128*N` |
| Reserve | 69 B (version[1] + Schnorr[64] + count[4]) | 192 B (ho, y, k_amount, key_image, DLEQ) | `69 + 192*N` |

The `output_count` field is 4 bytes (little-endian u32), supporting up to
2³² − 1 outputs per proof. TX proofs will typically have single-digit
outputs. Reserve proofs from large wallets (exchanges doing
proof-of-solvency) may contain thousands of entries; the 4-byte count
avoids an artificial 65,535 cap that would require proof splitting under
pressure.

### Proof version assertion

The `version` byte is 1 for all current proof types. The verifier
**must** check `version == CURRENT_PROOF_VERSION` as the very first
operation, before any cryptographic work. On mismatch, the verifier
returns an immediate error with a human-readable message. There is no
version negotiation, no graceful degradation, and no fallback. A version
mismatch is a developer error, not a user-recoverable condition.

### TX proofs carry `z`; reserve proofs do not

TX proofs include the Pedersen commitment mask `z` (32 bytes per output)
to enable direct commitment verification `C = z·G + amount·H`. This is
defense-in-depth: 32 bytes per output on a proof with single-digit
outputs is negligible, and the explicit check catches any mismatch
between the decrypted amount and the on-chain commitment.

Reserve proofs omit `z` to save 32 bytes per output (192 vs 224 per
entry). This asymmetry is justified because reserve proofs can have
hundreds or thousands of entries, and the saving is material. The
soundness argument for omitting `z` follows.

**HKDF binding argument (why omitting `z` from reserve proofs is
sound):** The per-output secrets `ho`, `y`, `z`, and `k_amount` are all
derived from the same HKDF-SHA-512 stream keyed by `combined_ss` with
per-label domain separation (labels pinned in
`docs/test_vectors/PQC_OUTPUT_SECRETS.json`). The verifier checks
`O == ho·G + B + y·T` against the on-chain output key `O`. If this
check passes, the `ho` and `y` in the proof are the correct HKDF
outputs for this specific `combined_ss` and output index. Because
`k_amount` is derived from the same HKDF stream with a different label,
providing a *wrong* `k_amount` requires providing a different
`combined_ss`, which forces a different `ho` and `y`, which fails the
algebraic `O` check. The prover **cannot** decouple `k_amount` from
`(ho, y)` without breaking HKDF.

The decrypted amount is then `amount = enc_amount XOR k_amount[..8]`.
Since `k_amount` is forced correct by the HKDF binding, and `enc_amount`
is read from the blockchain (see below), the decrypted amount is the
genuine amount committed to in `C`. The on-chain Bulletproofs+ consensus
check independently guarantees `C` commits to a value in `[0, 2⁶⁴)`.

**Critical invariant: `enc_amount` must be fetched from the blockchain.**
The reserve proof does **not** carry `enc_amount` as a field. The
verifier reads `enc_amount` from the on-chain transaction, indexed by
the output reference in the proof. If the proof carried `enc_amount`, a
malicious prover could provide a manipulated `enc_amount` alongside a
manipulated `k_amount` such that the XOR produces any desired amount —
the HKDF binding argument would not protect against this because the
verifier's XOR input would be attacker-controlled. Implementations must
assert that `enc_amount` comes from chain lookup, not from the proof.

---

## Related Documents

- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` — full PQC specification
- `docs/PQC_MULTISIG.md` — multisig scheme (`scheme_id = 2`)
- `docs/AUDIT_SCOPE.md` — 4-scalar leaf circuit security audit scope
- `tests/stressnet/README.md` — stressnet operational guide (pre-audit gate)
- `rust/shekyl-fcmp/` — Rust FCMP++ proof implementation
- `rust/shekyl-crypto-pq/` — PQC primitives, KEM, address encoding
