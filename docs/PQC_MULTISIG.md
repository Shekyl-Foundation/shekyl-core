# PQC Multisig V3.1: Equal-Participants Multisig with Per-Output Forward Privacy

> **Status:** DRAFT for implementation
> **Supersedes:** `PQC_MULTISIG.md`, the standalone V3.1 governance and receiving drafts
> **Companion:** `PQC_MULTISIG_V3_1_ANALYSIS.md` (size analysis, attack catalog, design rationale)
> **Consensus impact:** None. Wallet-layer protocol on existing V3 consensus rules.

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Design Principles](#2-design-principles)
3. [Threat Model](#3-threat-model)
4. [Roles](#4-roles)
5. [Group Setup](#5-group-setup)
6. [Address Format](#6-address-format)
7. [Receiving Outputs](#7-receiving-outputs)
8. [Wallet Scanning](#8-wallet-scanning)
9. [Spend Intent](#9-spend-intent)
10. [Canonical Construction](#10-canonical-construction)
11. [Spending: Prover and Signing](#11-spending-prover-and-signing)
12. [Messages and Transport](#12-messages-and-transport)
13. [State Machine and Counter Recovery](#13-state-machine-and-counter-recovery)
14. [Security Properties](#14-security-properties)
15. [Forward Compatibility](#15-forward-compatibility)
16. [Implementation Plan](#16-implementation-plan)

---

## 1. Purpose and Scope

Shekyl V3.1 multisig replaces the original coordinator-based design with an
**equal-participants** model that:

- Eliminates the central coordinator role as a power center
- Achieves deterministic transaction construction
- Provides per-output forward privacy on the receive side (Option C model)
- Composes cleanly with the existing `scheme_id = 2` consensus rules

This document is the single source of truth. It supersedes the original
`PQC_MULTISIG.md` and the two split drafts (`PQC_MULTISIG_V3_1.md` and
`PQC_MULTISIG_V3_1_RECEIVING.md`) that were merged here.

**No consensus changes are made by V3.1.** All bindings, checks, and
authorizations rely on rules and code paths already present in V3.

---

## 2. Design Principles

1. **Symmetric authority.** The four authorities historically conflated
   in "coordinator" — proposal, construction, signing, assembly — are split.
   Only the FCMP++ proving role retains a designated holder per output, and
   that role rotates deterministically across the group.
2. **Deterministic construction.** Given a spend intent and a committed
   chain snapshot, every participant produces byte-identical transaction
   bytes. There is no interface latitude.
3. **Per-output forward privacy.** Each output to a multisig group derives
   N fresh ephemeral hybrid keypairs. Two spends from the same group are
   cryptographically indistinguishable from spends by two different groups
   of the same cardinality.
4. **No consensus changes.** Every binding is achievable within existing
   V3 rules. The worst-case failure of a wallet-layer bug is a failed
   broadcast, never a chain split.
5. **Get it right.** Where deferring a feature lets us avoid shipping
   speculative cryptography, we defer. FROST SAL (V4), key rotation
   (V3.2+), and chain-anchored group registries (V3.3+) are all explicitly
   out of V3.1 scope, with reserved namespace for clean future addition.
6. **Honest-signer protocol invariants.** Where consensus cannot enforce
   a property without a hard fork, the property is enforced at the wallet
   layer by honest signers. Specs that assume "every honest signer
   verifies X before signing" are explicit and documented.

---

## 3. Threat Model

### 3.1 In scope

| Adversary | Capabilities | Defended by |
|---|---|---|
| Malicious sender | Constructs outputs to grief recipients | §7.5 wallet-side filtering |
| Malicious group member (single) | Tries to spend alone, redirect funds, or DoS | M-of-N threshold; §11.4 honest-signer prover verification; veto |
| Malicious prover | Tries to construct invalid or substitute proof | §11.3 signer-side proof verification before signing |
| Malicious assembler | Tries to broadcast tampered tx | §10.5 tx-hash commitments in signature shares |
| Network observer | Tries to identify groups, link spends | §6 file-based addresses; §7 per-output ephemeral keys; §12 encrypted transport |
| Malicious relay operator | Drops, reorders, injects messages | §12.4 mandatory multi-relay; §13.3 heartbeat protocol |
| Network partition | Causes state divergence | §13.4 CounterProof recovery |

### 3.2 Out of scope

| Threat | Reason |
|---|---|
| M-of-N collusion | Defeats any multisig by definition |
| Compromise of group's enduring KEM private keys | Catastrophic by design; mitigated by V3.2 key rotation |
| Quantum break of both ML-KEM and X25519 simultaneously | The hybrid scheme's whole point |
| Permanent loss of a participant's keys | 1/N of group's outputs become unrecoverable; documented limitation |
| FCMP++ prover liveness on permanent participant loss | 1/N of outputs locked; V4 FROST SAL fixes |
| Selective disclosure by M signers to outside auditor | Inherent to any threshold scheme |
| Sustained griefing-attack scanning cost | Bounded; see §3.3 |

### 3.3 Accepted but bounded threats

**Griefing via malformed multisig output.** A malicious sender can construct
outputs that *appear* to target a multisig group (correct `tx_extra`
fields, correct `group_id` claim) but whose KEM ciphertexts do not
correspond to the group's real KEM public keys. The recipient's wallet
attempts decap, fails, and discards the output. The attacker pays the fee;
the recipient gets nothing.

This attack is **bounded by attacker fee cost.** Sustained griefing
requires sustained fee expenditure. At Shekyl's expected fee rates,
sustained attack against a single group requires non-trivial economic
commitment by the attacker.

**Mitigation:** §7.5 wallet-side filtering ensures these outputs never
appear in user-facing balance or transaction history. Residual cost is
scanner CPU. A consensus-layer fix would require a chain-anchored group
registry (V3.3+ candidate); accepted as residual risk for V3.1.

### 3.4 Attacks mitigated by previous work but worth naming

| Attack | Mitigation |
|---|---|
| Scheme downgrade (output committed scheme_id=2, spent as scheme_id=1) | §7.4 indirect binding via leaf hash + `pqc_auth` size check; §7.4 wired `expected_scheme_id` and `expected_group_id` for defense in depth |
| Key substitution within a group | Existing `verify_multisig` Check 8 (key uniqueness) |
| Signer index manipulation | Existing `verify_multisig` Checks 6 and 7 (range, ascending) |
| Blob truncation/padding | Strict size checks in `tx_pqc_verify.cpp` |
| Replay across groups | `group_id` binding in canonical signing payload (existing) |
| Replay within group | `intent_id` + `tx_counter` + `expires_at` + `reference_block_hash` |

---

## 4. Roles

| Role | Authority | Who | Adversarial bound |
|---|---|---|---|
| Proposer | Publishes signed spend intent | Any group member | Signers veto by refusing to sign |
| Prover | Constructs FCMP++ membership proof for a specific output | Deterministically rotated; see §11.1 | Cannot modify tx; proof binds to signers' computed payload |
| Signer | Produces hybrid signature over canonical payload | Any M of the N members | Cannot individually authorize; needs M−1 collaborators |
| Assembler | Collects M signatures, broadcasts | Any group member with M sigs | Can only broadcast what signers produced |

The prover role is the only structural asymmetry remaining in V3.1, and
even it is per-output rather than per-group. V4 FROST SAL eliminates the
prover role entirely by threshold-sharing the classical key.

---

## 5. Group Setup

### 5.1 Group parameters

A group is defined by:

- `n_total`: total signers, `1 ≤ n_total ≤ 7` (consensus cap)
- `m_required`: threshold, `1 ≤ m_required ≤ n_total`
- `group_version`: `0x01` for V3.1 (reserved for future rotation)
- N hybrid signing keypairs (Ed25519 + ML-DSA-65), one per participant
- N hybrid KEM keypairs (X25519 + ML-KEM-768), one per participant

### 5.2 Distributed Key Generation (mandatory)

V3.1 groups MUST be created via Distributed Key Generation for the
**group shared transport secret**. Simple-mode shared-secret distribution
(where the founding proposer generates and distributes the secret) is
explicitly **NOT permitted in production**. Wallets MAY include simple-mode
as a testing fixture, but production deployments MUST use DKG.

The DKG ceremony uses the existing `dkg-pedpop` infrastructure already
present in `shekyl-wallet-core/src/multisig/dkg.rs`. The DKG output is
the 32-byte `group_shared_secret` from which per-message encryption keys
are derived (see §12.3).

DKG is performed once at group creation. The shared secret persists for
the lifetime of the group's transport layer. (Note: this secret is
distinct from any cryptographic spend key. Its only purpose is encrypting
multisig coordination messages on relays/transport.)

### 5.3 group_id derivation

The 32-byte `group_id` binds the group's identity:

```
group_id = cn_fast_hash(
    group_version ||
    scheme_id (= 2) ||
    n_total ||
    m_required ||
    concat(sorted(hybrid_signing_pubkeys))
)
```

The signing pubkeys (not KEM pubkeys) define group identity. This allows
KEM-only rotation (compromised KEM keys) without changing authorization
identity, in a future V3.2 enhancement.

### 5.4 Address derivation

The group's address is derived from all N hybrid pubkeys (signing and KEM)
plus the group's parameters; see §6.

### 5.5 Setup ceremony (informative summary)

Concrete steps for participants forming a new group:

1. Each participant generates fresh hybrid signing and KEM keypairs.
2. Participants exchange signing public keys and KEM public keys via
   authenticated out-of-band channels (cryptographic verification: each
   participant signs a setup attestation with their hybrid signing key
   over the canonical encoding of all participants' public keys).
3. Each participant independently computes `group_id` and verifies all
   others derived the same value.
4. Participants jointly run the DKG ceremony for `group_shared_secret`.
5. Each participant constructs the full multisig address locally; all
   should produce byte-identical addresses.
6. Address is exported as a file (too large for QR/clipboard at most N
   values).
7. Participants store group state: their own keypairs, the N pubkeys of
   others, group_id, group_version, threshold parameters, DKG-derived
   shared secret, and an initial `tx_counter = 0`.

---

## 6. Address Format

### 6.1 Bech32m encoding with new HRP

Multisig addresses use a new Bech32m human-readable prefix:

```
single-sig:     shekyl1:<version 0x01><classical>/<pqc>
single-sig tn:  shekyltest1:<...>
multisig:       shekyl1m:<version 0x01><group_metadata>
multisig tn:    shekyltest1m:<...>
```

The visible `m` suffix prevents wallet confusion: a multisig address
cannot be parsed as single-sig and vice versa. Wallets MUST type-check
the HRP at parse time.

**Reserved for future:** `shekyl1n...` (rotated-key multisig, V3.2+).
Do not issue.

### 6.2 Multisig address payload

```
MultisigAddressPayload {
    version:             u8   (= 0x01)
    group_version:       u8   (= 0x01)
    network_byte:        u8
    n_total:             u8   (1..=7)
    m_required:          u8   (1..=n_total)

    hybrid_kem_pubkeys:  [HybridKemPubkey; n_total]
    // Each: X25519 (32 B) + ML-KEM-768 (1184 B) = 1216 B
    // Canonically ordered by participant_index (0..n_total)

    hybrid_sign_pubkeys: [HybridSignPubkey; n_total]
    // Each: Ed25519 (32 B) + ML-DSA-65 (1952 B) = 1984 B
    // Canonically ordered by participant_index (0..n_total)

    checksum:            [u8; 4]   // Bech32m
}
```

Total payload: `9 + N × 3200` bytes.

| N | Payload bytes | Bech32m chars |
|---|---|---|
| 2 | 6,409 | ~10,260 |
| 3 | 9,609 | ~15,380 |
| 5 | 16,009 | ~25,620 |
| 7 | 22,409 | ~35,860 |

### 6.3 Address handling and the size problem

A 35 KB address is unusable in QR codes, clipboard, email, or most UIs.
Wallets MUST handle multisig addresses via:

**Primary (canonical):** export to file, transfer via authenticated
channel, import from file at recipient end.

**Optional convenience:** display a 32-byte fingerprint (hex-encoded) of
the canonical address payload:

```
address_fingerprint = cn_fast_hash(canonical(MultisigAddressPayload))
```

The fingerprint is short enough for human verification but cryptographically
binding. Wallets MUST display this fingerprint during send confirmation
(see §7.6) so users can verify they are sending to the intended group via
out-of-band fingerprint comparison.

### 6.4 Mandatory fingerprint UI requirement

When constructing a transaction with a multisig recipient, the sender's
wallet MUST:

1. Compute and display the recipient address fingerprint
2. Require explicit user confirmation that the displayed fingerprint
   matches what the recipient communicated out-of-band
3. Refuse to construct the transaction if confirmation is not given

This protects against:

- Address file substitution (attacker swaps the recipient's exported file
  for one with attacker-controlled keys)
- Truncation or partial-paste corruption
- Social engineering ("send to my new address" with a substituted file)

The fingerprint comparison places a small but real burden on users. This
is intentional. The alternative — silently sending to whatever address
the wallet parses — is unacceptable for high-value multisig usage.

### 6.5 Future: chain-anchored group registry

A V3.3+ candidate enhancement would add a `CreateGroup` transaction type
that commits a group's pubkeys on-chain at a short identifier. Addresses
would reference the on-chain group by short hash (~100 B address). This is
explicitly out of V3.1 scope and would be a consensus change.

---

## 7. Receiving Outputs

### 7.1 Per-output KEM fan-out (Option C)

For each multisig-recipient output, the sender performs N separate KEM
encapsulations, producing N independent ephemeral hybrid signing keypairs.

```python
def construct_multisig_output(
    sender_tx_secret_key:  secret_key,
    recipient_address:     MultisigAddress,
    amount:                u64,
    output_index:          u64,
    kem_seed:              [u8; 32],   # see §7.2
):
    kem_ciphertexts    = []   # N × HybridKemCiphertext
    ephemeral_sign_pks = []   # N × HybridSignPubkey
    view_tag_hints     = []   # N × u8

    for i in range(recipient_address.n_total):
        # Per-participant deterministic KEM randomness
        kem_randomness_i = HKDF_Expand(
            kem_seed,
            b"shekyl-v31-multisig-kem" || u64_le(output_index) || u8(i),
            64
        )

        # Encap to participant i's KEM pubkey
        ct_i, ss_i = HybridKEM.encap_deterministic(
            recipient_address.hybrid_kem_pubkeys[i],
            kem_randomness_i
        )
        kem_ciphertexts.append(ct_i)

        # Derive participant i's per-output ephemeral signing keypair
        secrets_i = derive_output_secrets(ss_i, output_index)
        ephemeral_pk_i = derive_hybrid_sign_pubkey(secrets_i)
        ephemeral_sign_pks.append(ephemeral_pk_i)

        # 1-byte hint for fast scanner identification
        view_tag_hints.append(
            HKDF_Expand(ss_i, b"shekyl-v31-view-tag", 1)[0]
        )

    # Canonical leaf container
    leaf_container = MultisigKeyContainer {
        n_total:    recipient_address.n_total,
        m_required: recipient_address.m_required,
        keys:       ephemeral_sign_pks,
    }

    # 4th leaf scalar (consensus re-derives this on spend)
    h_pqc = multisig_pqc_leaf_hash(leaf_container)

    # Output public key uses prover's per-output classical material
    # (see §11.1 for prover assignment)
    prover_idx = rotating_prover_index(
        recipient_address.group_id,
        output_index,
        reference_block_hash
    )
    prover_secrets = derive_output_secrets(
        shared_secrets[prover_idx], output_index
    )
    output_pubkey = prover_secrets.classical_pk
    commitment    = Commit(amount, prover_secrets.commitment_mask)

    return OutputConstruction {
        output_pubkey,
        commitment,
        kem_ciphertexts,
        view_tag_hints,
        h_pqc,
        leaf_container,
    }
```

### 7.2 Deterministic KEM seed

The `kem_seed` derives from the transaction's secret key:

```
kem_seed = HKDF_Expand(
    tx_secret_key,
    b"shekyl-v31-kem-seed" || u64_le(output_index),
    32
)
```

`tx_secret_key` MUST be freshly generated per transaction. Wallets MUST
assert this and refuse to construct a transaction if `tx_secret_key`
is reused.

### 7.3 tx_extra additions

Per multisig-recipient output:

```
TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT  (0x06)  N × 1120 B
TX_EXTRA_TAG_PQC_LEAF_HASHES     (0x07)  32 B
TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS  (0x09)  N × 1 B  (NEW in V3.1)
```

`TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS` (0x09) MUST be absent for single-sig
outputs. Wallets MUST reject any single-sig-shaped output that contains
this tag, to prevent ambiguous classification.

**Reserved tags (do not use in V3.1):**
- `0x08`: `TX_EXTRA_TAG_MULTISIG_MIGRATION` — future group-to-group migration

### 7.4 Spend-time consensus binding

The spend-time binding works through the existing FCMP++ leaf hash check
combined with the `pqc_auth` size check, both already in V3 consensus.

When the multisig-owned output is spent:

1. The spender presents `pqc_auths[i].hybrid_public_key` containing the
   canonical `MultisigKeyContainer` (the same N ephemeral pubkeys).
2. `blockchain.cpp:3720` computes `shekyl_fcmp_pqc_leaf_hash(blob)`.
3. The FCMP++ proof confirms this leaf is in the curve tree.
4. Any blob other than the canonical container fails leaf hash matching,
   and the proof rejects.

The size check at `tx_pqc_verify.cpp:206-211` independently rejects
attempts to spend with `scheme_id=1` against a multisig-shaped blob
(blob size ≠ HYBRID_SINGLE_KEY_LEN of 1996 bytes).

**Defense-in-depth wiring fixes** (no consensus rule change, but explicit
enforcement of rules already implicitly guaranteed):

- `blockchain.cpp:3768` SHOULD pass `expected_scheme_id` derived from
  the output's `tx_extra_pqc_ownership` to `verify_transaction_pqc_auth`
- `rust/shekyl-ffi/src/lib.rs:343` SHOULD pass `expected_group_id` to
  `verify_multisig` when `scheme_id == 2`

These plug latent wiring gaps that the existing code's comments
explicitly call out as "consensus must supply this." Both fixes increase
robustness without changing what consensus accepts.

### 7.5 Wallet-side filtering of malformed outputs

Outputs that look multisig-shaped but cannot be decapped by the claimed
recipient group are griefing artifacts (see §3.3). Wallets MUST:

1. Attempt KEM decap on every output where the participant's KEM
   ciphertext slot is present
2. If decap fails, mark the output as garbage in wallet state and never
   surface it in balance, history, or any user-visible interface
3. Periodically purge garbage entries to prevent state bloat
4. Optionally log griefing-attack indicators if a sustained pattern is
   detected (without false-positive risk for normal failed decaps)

This bounds the attack to scanner CPU cost, with no user impact.

### 7.6 Wallet send-side requirements

When sending to a multisig recipient, the sender's wallet MUST:

1. Display the address fingerprint (§6.3) and require user confirmation
2. Verify that the parsed address has a valid Bech32m checksum
3. Verify that all N hybrid pubkey blobs deserialize correctly
4. Reject addresses with `n_total > 7` or `m_required > n_total`
5. Compute and surface the per-output size cost (so users understand
   why a multisig-recipient transaction is larger than a single-sig)

---

## 8. Wallet Scanning

### 8.1 View tag hint check

Each participant's wallet processes outputs as follows:

```python
def check_output_for_me(output, my_participant_index, my_kem_secret):
    hints = parse_tx_extra_tag(output.tx_extra, 0x09)
    if hints is None:
        return None  # not multisig-shaped

    if my_participant_index >= len(hints):
        return None  # group cardinality mismatch

    # Decap only my slot
    my_ct = parse_kem_ciphertext_slot(output, my_participant_index)
    ss = HybridKEM.decap(my_kem_secret, my_ct)
    if ss is None:
        return None  # decap failure (could be grief or unrelated tx)

    # Fast hint check
    expected_hint = HKDF_Expand(ss, b"shekyl-v31-view-tag", 1)[0]
    if expected_hint != hints[my_participant_index]:
        return None  # not for us; mark as garbage if decap-shaped

    # Full verification (slower path)
    secrets = derive_output_secrets(ss, output_index)
    if not verify_output_ownership(output, secrets):
        return None  # malformed; mark as garbage

    return MatchedOutput { secrets, ... }
```

### 8.2 Cost

Per output: 1 KEM decap + 1 HKDF for hint comparison. False positive rate
~1/256 (1-byte hint), each false positive triggering a full output
ownership check that ultimately rejects.

Per-participant scanning cost is **not multiplied by N**. Each participant
processes only their own ciphertext slot.

### 8.3 Garbage tracking

Outputs that fail decap or hint check are tracked separately from real
balance state. Garbage entries are purged periodically (e.g., every 10,000
blocks) to bound state growth.

---

## 9. Spend Intent

### 9.1 Schema

```
SpendIntent {
    // Versioning
    version:          u8 (= 1)
    intent_id:        [u8; 32]   // random per intent

    // Group binding
    group_id:         [u8; 32]

    // Proposer
    proposer_index:   u8
    proposer_sig:     HybridSignature   // over all other fields

    // Temporal binding
    created_at:       u64
    expires_at:       u64
    tx_counter:       u64
    reference_block_height: u64
    reference_block_hash:   [u8; 32]

    // Content
    recipients: [
        { address: Bech32mAddress, amount: u64 }
    ]   // sorted
    fee:              u64
    input_global_indices: [u64]   // sorted ascending

    // Determinism anchor
    kem_randomness_seed: [u8; 32]   // 32 fresh random bytes

    // Optional: chain state fingerprint binding
    chain_state_fingerprint: [u8; 32]   // see §9.3
}
```

### 9.2 Invariants (verified before any signer signs)

1. `version == 1`
2. `group_id` matches the verifier's group
3. `proposer_index < n_total`
4. `proposer_sig` verifies against `hybrid_signing_pubkeys[proposer_index]`
5. `created_at ≤ now ≤ expires_at`
6. `expires_at - created_at ≤ 86400` (24-hour validity max)
7. `tx_counter` equals the group's currently-expected counter
8. `reference_block_height ≥ FCMP_REFERENCE_BLOCK_MIN_AGE` blocks behind
   tip and `≤ FCMP_REFERENCE_BLOCK_MAX_AGE`
9. `reference_block_hash` matches the chain's block at
   `reference_block_height` per the verifier's local view
10. All `input_global_indices` are owned by the group, unspent, and
    eligible at the reference height
11. Recipients are sorted; no duplicate (address, amount) tuples
12. `sum(recipient.amount) + fee == sum(input.amount)` per local view
13. `kem_randomness_seed` is unique within the group's history of
    `seen_intents` (replay/linkability prevention)
14. `chain_state_fingerprint` matches the verifier's local fingerprint
    (see §9.3); mismatch → resync, do not sign

### 9.3 Chain state fingerprint

Members must agree on chain state to safely sign. Each intent commits to:

```
chain_state_fingerprint = cn_fast_hash(
    reference_block_hash ||
    sorted_concat(input_global_indices) ||
    sorted_concat(input_eligible_heights) ||
    sorted_concat(input_amounts)
)
```

This fingerprint is computed by the proposer. Each verifier independently
recomputes from their local view. Mismatch indicates either chain state
divergence or attempted manipulation. Either way: do not sign; trigger
sync.

### 9.4 Intent hash

```
intent_hash = cn_fast_hash(canonical_serialize(SpendIntent))
```

`intent_hash` is the durable identifier. All subsequent messages reference
it.

---

## 10. Canonical Construction

### 10.1 Algorithm

Given verified `SpendIntent`, every member runs:

1. **Pre-flight verification** (§9.2 invariants). On any failure, publish
   `Veto`; do not proceed.
2. **Output derivation** (§7.1). For each recipient (and the change
   output, if any), derive output public key, KEM ciphertext(s), leaf hash.
3. **Transaction prefix construction.** Inputs reference key images
   computed from each input's prover-assigned `y` (§11.1); outputs are
   derived per step 2; `tx_extra` includes KEM ciphertexts, leaf hashes,
   view tag hints.
4. **RCT base.** Type = `RCTTypeFcmpPlusPlusPqc (=7)`; ecdh info,
   commitment masks, pseudo outputs all deterministic from intent.
5. **Compute `signing_payload`** (§10.4).

### 10.2 Bulletproof+ range proofs

**Important change from earlier drafts:** Bulletproof+ range proofs use
**fresh randomness produced by the prover**, not deterministic blinding
from the intent. This was changed during V3.1 design after cryptographic
review concerns about deterministic BP+ blinding.

Concrete protocol:

1. The prover (§11.1) constructs the BP+ proof with fresh randomness
2. The prover publishes it as part of the `ProverOutput` message (§12.2)
3. Each signer independently verifies the BP+ proof against the canonical
   output commitments before signing
4. The signer signs only after BP+ verification succeeds

This costs one verification round per signer (~10ms per verification) but
eliminates novel cryptographic claims about deterministic BP+ blinding.
The prover already has discretion over FCMP++ proof construction; BP+
joins it.

### 10.3 Change output handling

When the group sends to itself (a change output):

- The change recipient is the group's own multisig address
- The Option C construction (§7.1) applies identically
- N KEM encapsulations to the group's own KEM pubkeys
- N fresh per-output ephemeral keys derived
- Leaf hash committed
- Result: change output is byte-identically constructible by every
  participant from the intent + group address

**There is no single-sig change escape hatch.** Change outputs are full
multisig-bound outputs requiring `scheme_id=2` authorization to spend,
identical to any other multisig output.

### 10.4 Canonical signing payload

```
signing_payload = cn_fast_hash(
    serialize(TransactionPrefixV3) ||
    serialize(RctSigBase) ||
    cn_fast_hash(serialize(RctSigPrunable_skeleton)) ||
    serialize(PqcAuthHeader) ||
    H(hybrid_pubkeys[0]) || ... || H(hybrid_pubkeys[n_total-1])
)
```

Where `RctSigPrunable_skeleton` excludes the FCMP++ proof and BP+ proof
(both come from the prover asynchronously). Their hashes are included
separately in the signature share commitment (§12.2.1).

### 10.5 Tiebreaker for conflicting intents

When two proposers publish conflicting intents at the same `tx_counter`:

```
winner = intent that the prover (per §11.1) acknowledges first via
         signed ProverReceipt message (§12.2)
```

The prover acts as a deterministic tiebreaker by emitting a
`ProverReceipt` for the first valid intent they receive. The receipt is
a hybrid-signed message:

```
ProverReceipt {
    prover_index:    u8
    intent_hash:     [u8; 32]
    received_at:     u64
    sig:             HybridSignature   // over all above
}
```

Members observing two conflicting intents accept the one with the
prover's earlier-timestamped, signed receipt. Members who already signed
the losing intent publish a `Veto` to reset state.

**Why not hash-based tiebreaking:** hash comparison can be ground by an
attacker varying `intent_id`, `created_at`, `kem_randomness_seed`. The
prover-receipt mechanism cannot be ground because the prover holds private
state (their own per-output classical key) that determines who they ack
first based on observation order, not intent content.

---

## 11. Spending: Prover and Signing

### 11.1 Rotating prover assignment

For each output being spent, the prover is determined deterministically:

```
prover_index(output) = first_byte(
    cn_fast_hash(
        group_id ||
        output_block_height ||
        output_position_in_block ||
        reference_block_hash
    )
) mod n_total
```

This uses on-chain-observable data (the output's block height and position
within that block) plus the group_id and reference_block_hash from the
intent. Every group member computes the same prover_index for the same
output.

### 11.2 Prover responsibilities per output

The prover for an input:

1. Computes the FCMP++ proof using their per-output ephemeral classical
   key `y_prover_i`
2. Generates fresh-randomness Bulletproof+ range proofs for the
   transaction's outputs (§10.2)
3. Publishes a `ProverOutput` message (§12.2) containing both proofs

The prover holds **only** the per-output classical key for outputs they
were assigned. Compromise of one prover's host exposes their per-output
keys for those outputs only — not the group's spending power generally.

### 11.3 Signer verification of prover assignment (CRITICAL INVARIANT)

Honest signers MUST verify that the FCMP++ proof was constructed by the
**correct** assigned prover before producing a signature. This is the
honest-signer enforcement of prover-uniqueness.

Concretely, before signing:

```python
def verify_prover_assignment(input, prover_output, intent):
    expected_prover = rotating_prover_index(
        intent.group_id,
        input.output_block_height,
        input.output_position_in_block,
        intent.reference_block_hash
    )
    if prover_output.prover_index != expected_prover:
        raise ProverAssignmentMismatch
    
    # Verify the proof's key image is derivable from the expected
    # prover's per-output classical key
    expected_key_image = compute_expected_key_image(
        input, expected_prover, group.kem_shared_secrets
    )
    if input.key_image != expected_key_image:
        raise KeyImageProverMismatch
    
    return True
```

**Why this matters:** consensus does not enforce prover assignment. If
honest signers don't verify it, a malicious member could construct a
valid FCMP++ proof for an output they're *not* assigned to spend (using
their own per-output `y_i`), produce a different valid key image, and —
with M-of-N collusion — successfully drain that output. With honest-signer
verification, this attack requires M signers to all skip the check. In
the M-of-N collusion case, security is already lost; in the
honest-majority case, security holds.

This invariant is the V3.1 substitute for consensus-level prover-uniqueness
enforcement (which would require a hard fork).

### 11.4 Signing protocol (non-interactive scheme_id=2)

Each signer in the M-of-N selected subset:

1. Receives intent + ProverOutput (with FCMP++ proof + BP+ proof)
2. Independently reconstructs the canonical transaction (§10)
3. Verifies the FCMP++ proof against signing_payload
4. Verifies the BP+ range proofs
5. Verifies prover assignment (§11.3)
6. Computes the final tx_hash (including the prover's proofs)
7. Produces hybrid (Ed25519 + ML-DSA-65) signature over signing_payload
8. Publishes `SignatureShare` (§12.2) including the tx_hash commitment

### 11.5 Assembly

Any member with M valid SignatureShare messages:

1. Verifies all M tx_hash commitments agree (mismatch → publish Veto,
   abort; this catches prover equivocation, see §12.2.4)
2. Constructs `pqc_auth` blob with scheme_id=2 layout
3. Submits transaction to daemon

Multiple members may attempt assembly simultaneously. Network picks
whichever broadcast succeeds first.

### 11.6 The 1/N permanent loss limitation

A participant who permanently loses their keys cannot serve as prover for
the outputs they were assigned. Approximately 1/N of group outputs become
permanently unspendable.

For N=3: 33% loss risk per missing key.
For N=5: 20%.
For N=7: 14%.

This is documented as an accepted V3.1 limitation. Users MUST be informed
during group setup. V4 FROST SAL eliminates this entirely by making
proving a threshold operation; V3.2 may add a key escrow protocol as a
mitigation.

---

## 12. Messages and Transport

### 12.1 Common envelope

```
MultisigEnvelope {
    version:        u8 (= 1)
    group_id:       [u8; 32]
    message_type:   u8                  // ENCRYPTED in payload (see §12.5)
    intent_hash:    [u8; 32]
    sender_index:   u8
    sender_sig:     HybridSignature     // over above + payload
    payload:        EncryptedBlob
}
```

The envelope's `message_type` is encrypted along with the payload (§12.5)
to prevent role-pattern leakage to relay observers. Cleartext envelope
fields are limited to: `version`, `group_id`, `sender_index`, `intent_hash`,
`sender_sig`, encrypted payload.

### 12.2 Message types (encrypted)

- `0x01` — `SpendIntent` (proposer publishes)
- `0x02` — `ProverOutput` (FCMP++ proof + BP+ proofs)
- `0x03` — `SignatureShare` (signer's hybrid signature + tx_hash commitment)
- `0x04` — `Veto` (refusal to participate or abort signal)
- `0x05` — `ProverReceipt` (prover's tiebreaker acknowledgment)
- `0x06` — `Heartbeat` (liveness + censorship detection, §13.3)
- `0x07` — `CounterProof` (state recovery, §13.4)
- `0x08` — `GroupStateSummary` (periodic synchronization)

#### 12.2.1 SignatureShare structure

```
SignatureShare {
    signer_index:               u8
    hybrid_sig:                 HybridSignature
    tx_hash_commitment:         [u8; 32]
    fcmp_proof_commitment:      [u8; 32]
    bp_plus_proof_commitment:   [u8; 32]
}
```

The three commitments let the assembler detect prover equivocation
(see §12.2.4).

#### 12.2.4 Prover equivocation detection

If a malicious prover sends different `ProverOutput` messages to different
signer subsets, the resulting `SignatureShare` messages will have
disagreeing `fcmp_proof_commitment` or `bp_plus_proof_commitment` values.

Detection rule: if any two signature shares for the same intent have
disagreeing commitments, the prover has equivocated. Members publish:

```
EquivocationProof {
    prover_index:    u8
    intent_hash:     [u8; 32]
    proof_a:         (ProverOutput message including prover_sig)
    proof_b:         (different ProverOutput message including prover_sig)
}
```

The two prover_sig values together prove the prover signed two different
outputs for the same intent — undeniable equivocation. The prover is
marked untrusted by all members. Recovery options: rotate prover for
remaining outputs (deterministic rotation already gives some natural
rotation), or in extreme cases, group rebuild (V3.2+ protocol).

### 12.3 Encryption

Per-message symmetric key derivation:

```
message_key = HKDF_Expand(
    group_shared_secret,
    intent_hash || u8(message_type) || u8(sender_index),
    32
)
```

The `group_shared_secret` is the DKG-derived 32-byte value from §5.2.
**Production deployments MUST use DKG** (no member knows the full secret
alone).

AEAD: ChaCha20-Poly1305 with 96-bit nonce derived as
`HKDF_Expand(group_shared_secret, b"nonce" || u8(sender_index) || u64(message_counter), 12)`.

### 12.4 Multi-relay mandatory

Members MUST publish each message to **at least 3 independent relays**
operated by disjoint operators. The list of subscribed relays is part of
group state, established at setup time.

Members read from all subscribed relays. The first valid copy of any
message wins; later duplicates are deduplicated by `(intent_hash,
message_type, sender_index)`.

### 12.5 Cleartext envelope minimization

The encrypted `message_type` prevents passive observers from inferring
roles (only-prover-sends-0x02, only-signers-send-0x03). Observers see
encrypted blobs at varying sizes addressed to a stable `group_id`. This
is significant timing/role obfuscation but not perfect — for stronger
privacy, see traffic padding in V3.2 future work.

### 12.6 Transport bindings

**Nostr relay binding:** Each message posted as a Nostr kind-30000
replaceable event with `d` tag including `group_id` and unique message
identifier. Nostr signature is for relay acceptance only; cryptographic
authority is the envelope's `sender_sig`.

**Direct P2P binding:** Members connect via mTLS with hybrid certificates
when network topology permits. Direct messages still subject to all
envelope/encryption requirements.

**File binding:** Air-gap-compatible. Files written with naming convention
`shekyl-multisig-<group_id_hex>-<intent_hash>-<message_type>-<sender_index>.bin`.
Note: file naming reveals message_type in cleartext on the filesystem —
acceptable for air-gap workflows but should be flagged in user-facing
docs as a metadata leak risk if files are stored on shared media.

---

## 13. State Machine and Counter Recovery

### 13.1 Per-intent state

Each member tracks per-intent state:

```
PROPOSED       → intent received, not yet verified
VERIFIED       → §9.2 invariants pass
PROVER_READY   → ProverOutput received and verified
SIGNED         → this member produced and published SignatureShare
ASSEMBLED      → M signatures observed
BROADCAST      → tx confirmed in mempool / on-chain
REJECTED       → veto threshold reached or chain-rejected
TIMED_OUT      → expires_at reached without BROADCAST
```

### 13.2 tx_counter advancement

`tx_counter` advances ONLY upon observed chain state, not local optimism.
Specifically: tx_counter increments to k+1 when a member observes the
broadcast tx confirmed in their local chain at height ≥ N confirmations
(default N=3; configurable per group).

### 13.3 Heartbeat protocol

Members publish a `Heartbeat` message every `HEARTBEAT_INTERVAL`
(default: 5 minutes) to all subscribed relays:

```
Heartbeat {
    sender_index:       u8
    timestamp:          u64
    last_seen_intent:   [u8; 32]   // most recent intent_hash this member observed
    sig:                HybridSignature
}
```

Members compare received heartbeats to detect:

- Missing heartbeats from a specific member (offline or censored)
- Disagreement on `last_seen_intent` (relay censorship)
- Time skew

If a member observes heartbeats from M-1 others but is missing one
expected member's heartbeat, they should retry across all subscribed
relays before assuming the member is offline.

If members observe disagreement on `last_seen_intent` across heartbeats,
this indicates relay censorship targeting some subset of members. Action:
escalate to user, attempt cross-relay recovery, do not advance state
optimistically.

### 13.4 CounterProof recovery

When a member is at stale tx_counter (others have advanced beyond them),
recovery uses cryptographic chain proof:

```
CounterProof {
    sender_index:      u8
    advancing_to:      u64                  // new tx_counter value
    tx_hash:           [u8; 32]             // tx that advanced the counter
    block_height:      u64
    block_hash:        [u8; 32]
    tx_position:       u16
    sender_sig:        HybridSignature
}
```

A stale member receiving a `CounterProof`:

1. Verifies `block_hash` matches their local chain at `block_height`
   (waits for sync if necessary)
2. Verifies `tx_hash` appears in that block at `tx_position`
3. Verifies the tx was indeed a multisig spend by their group (via
   `pqc_auths.scheme_id == 2` and `multisig_pqc_leaf_hash` matching one
   of their tracked outputs)
4. If all checks pass, advances local `tx_counter` to `advancing_to`

This is a verifiable forward jump. No trust required: stale members
cryptographically confirm the counter advancement against on-chain
reality. The mechanism resolves the partition-driven desync attack
identified in adversarial review.

If a member receives a `CounterProof` for a block they don't yet have,
they wait for chain sync. They do NOT veto or treat conflicting intents
as adversarial — they're temporarily behind, and the proof tells them
exactly how to catch up.

### 13.5 Disagreement resolution

**Conflicting intents same counter** → §10.5 prover-receipt tiebreaker

**Proposer disappears mid-flight** → expires_at; group transitions to
TIMED_OUT and discards

**Prover disappears** → for that output, intent times out; rotating prover
means subsequent intents involving different outputs may proceed normally;
1/N permanent-loss applies per §11.6

**Chain reorg of reference_block** → all in-flight intents referencing the
orphaned block transition to TIMED_OUT; require re-proposal with new
reference_block

**Equivocation by prover** → §12.2.4 detection and untrust

### 13.6 Per-proposer rate limiting

To prevent intent-spam DoS:

- Each proposer_index may have at most 1 active intent at a time per
  group (active = state in {PROPOSED, VERIFIED, PROVER_READY, SIGNED})
- New proposals from same proposer are rejected with rate-limit veto
  until prior intent reaches BROADCAST, REJECTED, or TIMED_OUT

This bounds verification work to N concurrent intents maximum (one per
member).

---

## 14. Security Properties

### 14.1 Authorization

| Property | Mechanism |
|---|---|
| No unilateral spend | scheme_id=2 consensus requires M PQC signatures |
| No unilateral redirect | Deterministic construction; signers reconstruct and verify |
| No prover override | §11.3 honest-signer prover assignment verification |

### 14.2 Privacy

| Property | Mechanism |
|---|---|
| Per-output forward privacy | Option C N-fold KEM fan-out; per-output ephemeral keys |
| Spend-to-spend unlinkability | Different ephemeral N-key blobs per spend |
| Group identity privacy from passive observer | group_id not on-chain; encrypted transport |
| Role-pattern privacy from relay observers | Encrypted message_type in envelope |

### 14.3 Liveness

| Property | Status |
|---|---|
| Any M honest signers can advance | Yes (assuming the assigned prover is among them) |
| Proposer disappearance recovery | Yes (timeout + re-propose) |
| Signer disappearance recovery | Yes if M others remain |
| Prover disappearance per-output | Limited; 1/N outputs lock per missing prover (V4 fixes) |
| Network partition recovery | Yes via CounterProof |
| Relay censorship resistance | Multi-relay + heartbeat detection |

### 14.4 Integrity

| Property | Mechanism |
|---|---|
| Tx hash integrity through assembly | tx_hash_commitment in SignatureShare |
| Prover proof integrity | fcmp_proof_commitment + bp_plus_proof_commitment in SignatureShare |
| Prover non-equivocation | Equivocation produces undeniable proof (§12.2.4) |
| Counter integrity | CounterProof recovery (§13.4); advances on observed chain state |
| Replay resistance | intent_id, kem_randomness_seed freshness, expires_at, reference_block_hash, tx_counter |

---

## 15. Forward Compatibility

### 15.1 Reserved namespace

| Reserved Item | Purpose |
|---|---|
| `group_version` field, value `0x01` | Future rotated groups use higher values |
| HRP `shekyl1n...` | Rotated-key multisig (V3.2+) |
| `TX_EXTRA_TAG_MULTISIG_MIGRATION (0x08)` | Group-to-group migration (V3.2+) |

### 15.2 V3.2 candidate features

- **Group key rotation:** Migration tx that consumes current group's
  outputs and re-emits to a new group_version with rotated keys
- **Granular KEM-only rotation:** Replace KEM keys without changing
  signing keys (or vice versa)
- **Key escrow protocol:** Optional escrow of prover-required material
  to mitigate 1/N permanent loss

### 15.3 V3.3 candidate features

- **Chain-anchored group registry:** New tx type committing groups
  on-chain at short identifiers; reduces address size from ~35 KB to
  ~100 bytes; opt-in (groups preferring privacy keep addresses off-chain)
- **Traffic padding for transport privacy:** Dummy messages, batched
  delivery to obscure timing

### 15.4 V4 path

- **FROST SAL with Carrot-style address typing:** Threshold-shared
  classical key eliminates the prover role entirely; no per-output
  prover assignment; no 1/N permanent loss
- Receiving model (Option C) carries forward unchanged
- Governance protocol (this document's §9-13) carries forward unchanged
- Only the prover layer changes

### 15.5 Migration to V4

The V3.1→V4 migration is designed to be smooth: existing V3.1 groups can
opt to upgrade by performing FROST DKG over their existing signing keys,
producing distributed `y_threshold` material. Existing outputs to the
group can be spent under V4 rules without re-creating the group. Group
identity (group_id) remains stable; only the proving mechanism changes.

---

## 16. Implementation Plan

### 16.1 New Rust modules

```
shekyl-wallet-core/src/multisig/v31/
├── intent.rs              — SpendIntent type, canonical serialization
├── construction.rs        — canonical_construct() deterministic function
├── prover.rs              — ProverOutput; rotating prover assignment
├── signing.rs             — non-interactive scheme_id=2 signing
├── messages.rs            — envelope + message types
├── encryption.rs          — group_shared_secret + AEAD
├── transport/
│   ├── mod.rs
│   ├── nostr.rs           — Nostr binding
│   ├── p2p.rs             — direct P2P binding
│   └── file.rs            — air-gap file binding
├── state.rs               — per-intent state machine
├── heartbeat.rs           — liveness protocol
├── counter_proof.rs       — recovery mechanism
└── tx_counter.rs          — counter advancement on observed chain state

shekyl-crypto-pq/src/multisig_receiving.rs
├── construct_multisig_output_for_sender
├── scan_multisig_output_for_participant
└── rotating_prover_index
```

### 16.2 New tx_extra tag

`src/cryptonote_basic/tx_extra.h`:
- Add `TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS = 0x09`
- Reserve `TX_EXTRA_TAG_MULTISIG_MIGRATION = 0x08`

### 16.3 Defense-in-depth wiring fixes

`src/cryptonote_core/blockchain.cpp:3768`:
- Wire `expected_scheme_id` from output's `tx_extra_pqc_ownership`

`rust/shekyl-ffi/src/lib.rs:343`:
- Pass `expected_group_id` to `verify_multisig` for scheme_id=2

These are not strictly required for correctness (existing leaf hash + size
check provide indirect binding) but plug latent wiring gaps.

### 16.4 Modified C++

- `src/cryptonote_core/cryptonote_tx_utils.cpp`: add multisig-aware output
  construction path (new function; does not modify single-sig path)
- `src/wallet/wallet2.cpp`: add multisig output scanning and garbage filtering

### 16.5 New address parsing

- `rust/shekyl-encoding/src/lib.rs`: add `shekyl1m` HRP parsing
- `rust/shekyl-address/`: add `MultisigAddress` type

### 16.6 GUI wallet changes

- Multisig page: file-based address import/export
- Multisig page: mandatory fingerprint verification dialog
- Multisig page: per-intent state display, veto, equivocation indicators
- Settings: relay configuration (minimum 3 mandatory)
- Settings: heartbeat interval
- DKG ceremony UI for group setup

### 16.7 Feature flag

`shekyl-wallet-rpc` crate: add `multisig-v3.1` feature, replacing the
dormant `multisig` feature. The pre-existing FROST SAL scaffolding moves
to a separate `frost-sal-v4` feature, kept for V4 work.

### 16.8 Test matrix

**Functional:**
- 2-of-3, 3-of-5, 5-of-7 happy paths (receive + spend)
- Single-sig sender → multisig receiver
- Multisig sender → multisig receiver (chained groups)
- Change outputs (group sending to itself)
- Staked outputs received and claimed by multisig groups

**Adversarial:**
- Malicious proposer (bad recipients, bad fee, bad reference block)
- Malicious prover (wrong payload, malformed proof, equivocation)
- Malicious signer (no sig, wrong payload, duplicate sig)
- Malicious assembler (tampered tx, dropped signatures)
- Network partition + CounterProof recovery
- Relay censorship (drop, reorder, inject, split-brain)
- Conflicting simultaneous intents (prover-receipt tiebreaking)
- Tiebreaker grinding attempts (prove non-grindability)
- Wrong-prover key image attempt (honest-signer detection)
- Prover equivocation (detection + EquivocationProof)
- Sustained griefing attack (wallet filtering, no balance corruption)

**Determinism:**
- Same intent + chain state → byte-identical tx across 10⁶ iterations
- Cross-platform determinism (x86_64 Linux, macOS, Windows)

**Performance:**
- Scanner cost at 10k+ tx/block with 5%/10%/25% multisig adoption
- Prover proof construction time benchmark
- Multi-relay overhead measurement

### 16.9 Fuzz targets

- `fuzz_spend_intent_deserialize`
- `fuzz_construction_determinism`
- `fuzz_envelope_parser`
- `fuzz_multisig_address_parse`
- `fuzz_view_tag_hint_check`
- `fuzz_rotating_prover_assignment` (uniformity statistics)
- `fuzz_counter_proof_verifier`
- `fuzz_equivocation_proof_verifier`

### 16.10 Rollout sequencing

1. **Phase 1 (4-6 weeks):** Receiving model + sender-side construction
   in `shekyl-crypto-pq`. Address format and parsing. tx_extra tag
   addition. Wallet-side filtering. Defense-in-depth wiring fixes.
2. **Phase 2 (4-6 weeks):** Governance protocol (intent, construction,
   signing, assembly). State machine. CounterProof. Heartbeat. Multi-relay
   transport. DKG mandatory enforcement.
3. **Phase 3 (2-3 weeks):** GUI integration. Fingerprint verification UI.
   Group setup ceremony UI. State visualization.
4. **Phase 4 (2-4 weeks):** Test matrix execution. Fuzz harness setup.
   Cross-platform determinism validation.
5. **Phase 5 (2 weeks):** Adversarial review by external reviewers.
6. **Phase 6 (TBD):** Cryptographer review of view-tag-hint information
   theory; rotating prover assignment uniformity; KEM-derivation chain.

Total estimate: **14-23 weeks** of focused engineering work, plus review.

---

## Appendix A: Mapping from Original Spec

This document supersedes:

- `PQC_MULTISIG.md` (original; coordinator-based)
- `PQC_MULTISIG_V3_1.md` (governance draft)
- `PQC_MULTISIG_V3_1_RECEIVING.md` (Option C receiving draft)

All material from the three predecessor documents is consolidated here.
The two predecessor V3.1 drafts can be deleted from the repo once this
document is merged. The original `PQC_MULTISIG.md` should be updated to
a single-paragraph deprecation pointer.

For attack analysis, size analysis, and design rationale, see the
companion document `PQC_MULTISIG_V3_1_ANALYSIS.md`.
