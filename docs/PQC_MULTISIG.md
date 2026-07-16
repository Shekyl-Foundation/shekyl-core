# PQC Multisig V3.1: Equal-Participants Multisig with Per-Output Forward Privacy

> **Status:** DRAFT v1.1 — incorporates three rounds of adversarial wargame feedback and the resolved prover-verification mechanism
> **Supersedes:** `PQC_MULTISIG.md` (original), the standalone V3.1 governance and receiving drafts, and v1.0 of this consolidated spec
> **Companion:** `PQC_MULTISIG_V3_1_ANALYSIS.md` (size analysis, attack catalog, cryptographer review targets, design rationale)
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
8. [Wallet Scanning and Receive-Time Validation](#8-wallet-scanning-and-receive-time-validation)
9. [Spend Intent](#9-spend-intent)
10. [Canonical Construction](#10-canonical-construction)
11. [Spending: Prover and Signing](#11-spending-prover-and-signing)
12. [Messages and Transport](#12-messages-and-transport)
13. [State Machine and Counter Recovery](#13-state-machine-and-counter-recovery)
14. [Security Properties](#14-security-properties)
15. [Forward Compatibility](#15-forward-compatibility)
16. [Implementation Plan](#16-implementation-plan)
17. [Appendix A: Canonical Test Vectors](#17-appendix-a-canonical-test-vectors)
18. [Appendix B: Mapping from Original Spec](#18-appendix-b-mapping-from-original-spec)

---

## 1. Purpose and Scope

Shekyl V3.1 multisig replaces the original coordinator-based design with an
**equal-participants** model that:

- Eliminates the central coordinator role as a power center
- Achieves deterministic transaction construction
- Provides per-output forward privacy on the receive side (Option C model)
- Composes cleanly with the existing `scheme_id = 2` consensus rules

This document is the single source of truth. It supersedes the original
`PQC_MULTISIG.md` and the two split drafts that were merged into v1.0, as
well as v1.0 itself.

**No consensus changes are made by V3.1.** All bindings, checks, and
authorizations rely on rules and code paths already present in V3.

---

## 2. Design Principles

1. **Equal participants under Option E′.** Proposal, construction,
   signing, and assembly are shared. There is **no mandatory prover**.
   (Rotating-prover / Option D scaffold is **deleted** — see §4 / §11.)
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
5. **Get it right — defer speculative crypto, ship E′.** **In V3.1
   scope:** Option E′ threshold FROST SAL on `y` (`spend_auth_version =
   0x02`; §15.4a). **Out of V3.1 scope:** the deleted Option D
   mandatory-prover / 1/N-*loss* scaffold; the full *key* rotation
   protocol (V3.2); chain-anchored group registries (V3.3+); composite /
   lattice-only *auth* size (§15.4b, waits on lattice-threshold maturity
   beyond IR 8214C). Authorization is already PQ (M × ML-DSA); do not
   read "deferral" as "multisig is classical," and do not read §15.4a
   FROST-on-`y` as "out of scope."
6. **Honest-signer protocol invariants.** Where consensus cannot enforce
   a property without a hard fork, the property is enforced at the wallet
   layer by honest signers. These invariants are enumerated in §2.7 and
   each one is made mechanically unbypassable in supported client stacks.
7. **Forward-compatible primitives.** Cryptographic primitives that might
   change in future versions (spend-auth keys, auth schemes) are
   abstracted behind a `version` byte so future schemes slot in without
   protocol rewrites.

### 2.7 Honest-Signer Invariants (Authoritative List)

Several security properties in V3.1 cannot be enforced at the consensus
layer without a hard fork. These properties are instead enforced at the
wallet layer by honest signers. This section is the authoritative list
of such invariants; the signing path in supported wallets MUST enforce
each one before producing a signature.

| # | Invariant | Enforced in | §reference |
|---|---|---|---|
| I1 | Spend intent passes all invariant checks in §9.2 | Pre-signing verification | §9.2 |
| I2 | Chain state fingerprint matches signer's local view | Pre-signing verification | §9.3 |
| I3 | FCMP++ proof binds to signer's independently-computed signing payload | Pre-signing verification | §11.3 |
| I4 | BP+ range proofs verify against signer's independently-computed commitments | Pre-signing verification | §10.2 |
| I5 | Output public key O matches the assigned prover's spend-auth pubkey | Pre-signing verification | §11.3 |
| I6 | tx_hash commitment agrees across all M SignatureShares before assembly | Pre-assembly verification | §11.5 |
| I7 | Receive-time: every tracked output's O matches `spend_auth_pubkeys[rotating_prover_index(...)]` | Receive-time validation | §8.3 |

**Implementation requirements:**

- Each invariant MUST be checked in the core signing path. It MUST NOT
  be possible to produce a valid SignatureShare without the corresponding
  check having executed and returned success.
- On any invariant violation, the wallet MUST:
  1. Abort the signing operation
  2. Publish a signed `InvariantViolation` message (type `0x09`; see §12.2.6)
  3. Move the intent to `REJECTED` state
- Wallets MUST NOT expose `--unsafe-skip-verification` flags or
  equivalents. Tests that bypass invariants MUST be gated behind
  compile-time feature flags that are excluded from release builds.
- Interop test suite (see §16.8) MUST include cases where a malicious
  client attempts each invariant violation; all conforming clients MUST
  reject identically.

This list is closed. New invariants require a spec update and reviewer
sign-off before addition.

---

## 3. Threat Model

### 3.1 In scope

| Adversary | Capabilities | Defended by |
|---|---|---|
| Malicious sender | Constructs outputs to grief recipients | §7.6 wallet-side filtering; §8.3 receive-time validation |
| Malicious group member (single) | Tries to spend alone, redirect funds, or DoS | M-of-N threshold; §2.7 I5 honest-signer prover verification; veto |
| Malicious prover | Tries to construct invalid or substitute proof | §2.7 I3, I4 signer-side proof verification before signing |
| Malicious assembler | Tries to broadcast tampered tx | §2.7 I6 tx-hash commitments |
| Network observer | Tries to identify groups, link spends | §6 file-based addresses; §7 per-output ephemeral keys; §12 encrypted transport |
| Malicious relay operator | Drops, reorders, injects messages | §12.4 mandatory multi-relay with operator uniqueness; §13.3 heartbeat protocol |
| Network partition | Causes state divergence | §13.4 CounterProof recovery |
| Scanner resource exhaustion | Burns scanner CPU via griefing outputs | §7.6 per-sender griefing scores + hard caps |

### 3.2 Out of scope

| Threat | Reason |
|---|---|
| M-of-N collusion | Defeats any multisig by definition |
| Compromise of group's enduring KEM private keys | Catastrophic by design; mitigated by V3.2 full rotation |
| Quantum break of both ML-KEM and X25519 simultaneously | The hybrid scheme's whole point |
| Permanent loss of a participant's keys | 1/N of group's outputs become unrecoverable; documented limitation; V3.1 requires setup-time acknowledgment per §5.4 |
| FCMP++ prover liveness on permanent participant loss | 1/N of outputs locked; V4 FROST SAL fixes |
| Selective disclosure by M signers to outside auditor | Inherent to any threshold scheme |

### 3.3 Accepted but bounded threats

**Griefing via malformed multisig output.** A malicious sender can construct
outputs that *appear* to target a multisig group (correct `tx_extra`
fields, correct group-id claim) but whose KEM ciphertexts or spend-auth
pubkey bindings do not correspond to the group's real keys. The
recipient's wallet attempts decap and receive-time validation, rejects,
and the output is discarded. The attacker pays the fee; the recipient
gets nothing.

This attack is **bounded by attacker fee cost**. §7.6 specifies scanner-
side resource limits (per-sender griefing scores, hard caps, 7-day
cooldowns) to bound the scanner CPU cost of sustained griefing. A
consensus-layer fix would require a chain-anchored group registry
(V3.3+ candidate); accepted as residual risk for V3.1.

### 3.4 Attacks mitigated by previous work

| Attack | Mitigation |
|---|---|
| Scheme downgrade (output committed scheme_id=2, spent as scheme_id=1) | §7.5 indirect binding via leaf hash + `pqc_auth` size check; wired `expected_scheme_id` and `expected_group_id` for defense in depth |
| Key substitution within a group | Existing `verify_multisig` Check 8 (key uniqueness) |
| Signer index manipulation | Existing `verify_multisig` Checks 6 and 7 (range, ascending) |
| Blob truncation/padding | Strict size checks in `tx_pqc_verify.cpp` |
| Replay across groups | `group_id` binding in canonical signing payload |
| Replay within group | `intent_id` + `tx_counter` + `expires_at` + `reference_block_hash` + `kem_randomness_seed` freshness |

---

## 4. Roles

> **Product path (Option E′):** roles are **Proposer / Signer /
> Assembler** only. There is **no mandatory Prover**. Sections that
> still name a rotating Prover (and I7 / ProverReceipt / grinding)
> describe the **deleted Option D scaffold** — retained for archaeology
> until those sections are rewritten; they are **not** operational
> guidance for E′.

| Role | Authority | Who | Adversarial bound |
|---|---|---|---|
| Proposer | Publishes signed spend intent | Any group member | Signers veto by refusing to sign |
| Signer | Produces hybrid signature over canonical payload; FROST share on `y` | Any M of the N members | Cannot individually authorize; needs M−1 collaborators |
| Assembler | Collects M signatures, broadcasts | Any group member with M sigs | Can only broadcast what signers produced |
| ~~Prover~~ | ~~FCMP++ proof for a specific output~~ | **Option D only — deleted** | — |

Under E′, FCMP++ proving is not a privileged single-member role: the
group constructs proofs under the shared spend path without a
1/N permanent-loss assignment. V4 lattice work does not reintroduce
that role.

---

## 5. Group Setup

### 5.1 Group parameters

A group is defined by:

- `n_total`: total signers, `1 ≤ n_total ≤ MAX_MULTISIG_PARTICIPANTS`
- `m_required`: threshold, `1 ≤ m_required ≤ n_total`
- `group_version`: `0x01` for V3.1 (reserved for future rotation)
- `spend_auth_version`: **`0x02` for Option E′** (product path —
  threshold FROST SAL on `y`; dealer-mode). **`0x01` is never issued**
  (mandatory-prover Option D scaffold is deleted, not shipped). A later
  mutually-distrusting DKG ceremony mode, if any, gets its own version
  byte — do not overload `0x01`.
- N hybrid signing keypairs (Ed25519 + ML-DSA-65), one per participant
- N hybrid KEM keypairs (X25519 + ML-KEM-768), one per participant

**`MAX_MULTISIG_PARTICIPANTS` (MSW-G) = 5** (decided 2026-07-15
overhaul; withdraws same-day provisional 8).

**Enforcement status (pre-genesis).** This is the **ratified target**,
not the live constant. Until **MSW-1** lands, production code still
compiles the constant as **seven**
(`rust/shekyl-crypto-pq/src/multisig.rs`,
`src/cryptonote_config.h`). Do not read this section as "the node
already rejects n>5." MSW-1 is the atomic cutover of the constant +
bound KATs; this PR is design/docs only.

**Derivation:** MAX = **2f+1 at f=2** — classical majority-threshold
BFT for the *largest group we intend to serve*. Consumer: largest
group served. **Not** a resource bound, reward-zone fill, or
power-of-two bias fix. The operator chooses m-of-n ≤ MAX; MAX is the
largest n tooling ships. Rule-21 reopen: only if a named consumer
requires n>5 *and* zone/address usability are dispositioned. See
`V3_1_MULTISIG_RUST_ENGINE.md` §0.3.

### 5.2 Distributed Key Generation — **not the ship default**

**Product path (Option E′, §15.4a / design §0.5):** the owner is the
trusted dealer. Generate `b` and `y_group`, Shamir-split `y_group`,
write participant files. **No DKG.** TRaccoon-class papers assume the
same trusted KeyGen.

**Mutually-distrusting parties** (buyer/seller/arbitrator) MAY get a
DKG ceremony behind a **later** `spend_auth_version` / ceremony mode —
not `0x02`, and not compiled into the dealer-mode default.

When that mode exists:

- Production wallet builds MUST NOT compile a path that distributes
  the *threshold spend secret* without the ceremony that mode requires.
- A transport-only shared secret (message AEAD), if any, is distinct
  from `y_group` and must not be confused with spend authorization.

*(Older prose requiring DKG for every V3.1 group applied to mandatory-
prover Option D and is withdrawn for the E′ product path.)*

### 5.3 group_id derivation

The 32-byte `group_id` binds the group's identity. The code hashes the
**leaf** `MultisigKeyContainer` (ephemeral hybrid keys + spend-auth pubkeys)
for its key material — not address key fields — while sourcing the three
version axes from the group's address payload
(`multisig_group_id_from_address`, MSW-4; the bare `multisig_group_id`
convenience form fabricates them from constants and is tests/fuzz-only):

```
group_id = cn_fast_hash(
    DOMAIN_SEP_V31 ||
    group_version ||
    scheme_id (= 2) ||
    spend_auth_version ||
    n_total ||
    m_required ||
    concat(container.keys) ||
    concat(container.spend_auth_pubkeys)   # layout per multisig.rs
)
```

> **Honesty pin:** older prose claimed address `hybrid_signing_pubkeys`
> define group identity. That field is vestigial (**MSW-8**) and was
> never a `group_id` input in code. E′ will rebind `group_id` to
> `(spend_auth_version, B, Y_group, KEMs, m, n)` (exact preimage in
> the E′ address freeze) — Track A MSW-4/5 keep the version bytes real.

`spend_auth_version` is included so that a future ceremony/mode produces
a new `group_id`, preventing silent reinterpretation across stacks.

### 5.4 1/N permanent-loss acknowledgment — **withdrawn for E′**

Mandatory-prover Option D required a 1/N loss acknowledgment (assigned
prover holds per-output `y`). **Option E′ deletes the mandatory prover**
— threshold FROST on `y_group` means any M honest devices can spend.
The §5.4 acknowledgment UI is **not** part of the E′ product path.

*(If a future mutual-distrust mode reintroduces a single-holder
liveness dependency, restore an acknowledgment under that mode's
version byte — do not revive it for `0x02`.)*

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
6. Each participant completes the 1/N risk acknowledgment (§5.4).
7. Address is exported as a file (too large for QR/clipboard at most N
   values).
8. Participants store group state: their own keypairs, the N pubkeys of
   others, group_id, group_version, spend_auth_version, threshold
   parameters, DKG-derived shared secret, acknowledgments, and an
   initial `tx_counter = 0`.

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

The visible `m` suffix prevents wallet confusion. Wallets MUST
type-check the HRP at parse time.

**Reserved:** `shekyl1n...` (rotated-key multisig, V3.2+). Do not issue.

### 6.2 Multisig address payload

```
MultisigAddressPayload {
    version:             u8   (= 0x01)
    group_version:       u8   (= 0x01)
    spend_auth_version:  u8   (= 0x02 for Option E′; 0x01 never issued)
    network_byte:        u8
    n_total:             u8   (1..=MAX_MULTISIG_PARTICIPANTS)
    m_required:          u8   (1..=n_total)

    hybrid_kem_pubkeys:  [HybridKemPubkey; n_total]
    // Each: X25519 (32 B) + ML-KEM-768 (1184 B) = 1216 B
    // Canonically ordered by participant_index (0..n_total)

    // Option E′ additionally carries group B and Y_group (layout TBD
    // in E′ address freeze). Not shown in the D-era struct below.

    // No stored checksum: integrity is the fingerprint (§6.3). A Bech32m
    // string encoding (§6.1) appends the HRP + checksum at encode time; the
    // checksum is derived from the data, never a payload field.
}
```

> **MSW-8 (2026-07-15):** `hybrid_sign_pubkeys: [HybridSignPubkey; n_total]`
> is **deleted**. Vestigial Solution C fossil — constructed and parsed,
> never consumed (`multisig_receiving.rs` derives leaf hybrid sign keys
> from KEM shared secrets). `PER_PARTICIPANT_LEN` collapses 3200 → 1216.
> Free pre-genesis. Applies to D and E′ identically.

Canonical payload after MSW-8: `6 + N × 1216` bytes
(`HEADER_LEN + N × PER_PARTICIPANT_LEN`, plus E′ `B`/`Y` when those fields
land). This is the fingerprint preimage and the file contents; the Bech32m
string form (§6.1) adds the HRP + checksum on top, which are not stored here.

| N | After MSW-8 (bech32m chars, approx) |
|---|---|
| 2 | ~3,900 ← QR-able |
| 3 | ~5,850 |
| 5 | ~9,740 |

### 6.3 Address handling, fingerprint UX, and provenance

Wallets MUST handle multisig addresses via file export and import:
canonical payload written to a file, transferred via authenticated
channel, imported at recipient end.

**Fingerprint display:** wallets MUST display a 32-byte fingerprint during
send confirmation:

```
address_fingerprint = cn_fast_hash(canonical(MultisigAddressPayload))
```

The fingerprint MUST be displayed in **three parallel representations**:

1. **Hex format** (64 characters, grouped as 4-char blocks for reading)
2. **Grouped-word checksum phrase** (derived from the fingerprint via a
   fixed wordlist; 10-word phrase, stable, deterministic, for human
   verbal verification)
3. **Structured metadata badge:** `(m)-of-(n), spend_auth v(X), group v(Y)`

**Provenance tracking:** wallets MUST persist address provenance in
local state:

```
AddressProvenance {
    address_fingerprint:    [u8; 32]
    first_imported_at:      u64
    imported_from_source:   string  (file path, URL, QR, etc.)
    user_assigned_label:    string
    last_used_at:           u64
    prior_fingerprints:     [[u8; 32]]  // history of changed fingerprints for same label
}
```

**Dual confirmation on changes:** when a user initiates a payment to a
label that previously resolved to a different fingerprint, the wallet
MUST require dual confirmation:

1. Display the new fingerprint prominently alongside the old
2. Display the user-assigned label and warn that the underlying address
   has changed
3. Require a second confirmation step (e.g., typing "CONFIRM CHANGED")

This protects against address file substitution attacks where an attacker
swaps a victim's address file between payments.

### 6.4 Mandatory fingerprint verification UI

For every multisig send, the sender's wallet MUST:

1. Compute and display the recipient address fingerprint (all three
   representations from §6.3)
2. Require explicit user confirmation that the displayed fingerprint
   matches what the recipient communicated out-of-band
3. Refuse to construct the transaction if confirmation is not given

This is the primary defense against social-engineering attacks on
multisig addresses.

### 6.5 Future: chain-anchored group registry

A V3.3+ candidate enhancement would add a `CreateGroup` transaction type
that commits a group's pubkeys on-chain at a short identifier. Addresses
would reference the on-chain group by short hash (~100 B address). This is
explicitly out of V3.1 scope and would be a consensus change.

---

## 7. Receiving Outputs

### 7.1 Per-output KEM fan-out with published spend-auth pubkeys (Option C + Solution C)

For each multisig-recipient output, the sender performs N separate KEM
encapsulations, producing N independent ephemeral hybrid signing keypairs
**and** N independent ephemeral classical spend-auth keypairs. The spend-
auth pubkeys are published explicitly in `tx_extra` to enable public
prover-assignment verification.

```python
def construct_multisig_output(
    sender_tx_secret_key:  secret_key,
    recipient_address:     MultisigAddress,
    amount:                u64,
    output_index_in_tx:    u64,
    reference_block_hash:  [u8; 32],
    kem_seed:              [u8; 32],   # see §7.3
):
    kem_ciphertexts    = []    # N × HybridKemCiphertext
    ephemeral_sign_pks = []    # N × HybridSignPubkey
    spend_auth_pubkeys = []    # N × 32 bytes (classical Y_i = y_i * G)
    view_tag_hints     = []    # N × u8
    ss_by_index        = {}    # cache for commitment mask derivation

    for i in range(recipient_address.n_total):
        # Per-participant deterministic KEM randomness
        kem_randomness_i = HKDF_Expand(
            kem_seed,
            b"shekyl-v31-multisig-kem" || u64_le(output_index_in_tx) || u8(i),
            64
        )

        # Encap to participant i's KEM pubkey
        ct_i, ss_i = HybridKEM.encap_deterministic(
            recipient_address.hybrid_kem_pubkeys[i],
            kem_randomness_i
        )
        kem_ciphertexts.append(ct_i)
        ss_by_index[i] = ss_i

        # Derive per-output ephemeral material with DOMAIN SEPARATION
        # See §7.2 for KDF label definitions
        hybrid_sign_kdf = HKDF_Expand(
            ss_i, b"shekyl-v31-hybrid-sign", 64
        )
        hybrid_sign_pk_i = derive_hybrid_sign_pubkey(hybrid_sign_kdf)
        ephemeral_sign_pks.append(hybrid_sign_pk_i)

        classical_spend_kdf = HKDF_Expand(
            ss_i, b"shekyl-v31-classical-spend", 64
        )
        y_i = derive_classical_scalar(classical_spend_kdf)
        Y_i = y_i * G   # 32-byte compressed Ed25519 point
        spend_auth_pubkeys.append(Y_i)

        # View tag hint (1 byte) for fast scanner identification
        view_tag_hints.append(
            HKDF_Expand(ss_i, b"shekyl-v31-view-tag", 1)[0]
        )

    # Determine assigned prover using SENDER-COMPUTABLE rule (§11.1)
    tx_secret_key_hash = cn_fast_hash(sender_tx_secret_key)
    assigned_prover = rotating_prover_index(
        recipient_address.group_id,
        output_index_in_tx,
        tx_secret_key_hash,
        reference_block_hash,
        recipient_address.n_total
    )

    # Output public key binds to the assigned prover's spend-auth pubkey
    O = spend_auth_pubkeys[assigned_prover]

    # Commitment uses the assigned prover's commitment mask
    commitment_mask = derive_commitment_mask(
        ss_by_index[assigned_prover], output_index_in_tx
    )
    commitment = Commit(amount, commitment_mask)

    # Canonical leaf container includes all three components
    leaf_container = MultisigKeyContainer {
        version:              0x01,
        n_total:              recipient_address.n_total,
        m_required:           recipient_address.m_required,
        keys:                 ephemeral_sign_pks,  # HybridPublicKey per participant
        spend_auth_pubkeys:   spend_auth_pubkeys,
    }

    # 4th leaf scalar covers the full container
    h_pqc = multisig_pqc_leaf_hash(leaf_container)

    return OutputConstruction {
        output_pubkey:     O,
        commitment,
        kem_ciphertexts,
        view_tag_hints,
        spend_auth_pubkeys,    # published separately in tx_extra
        h_pqc,
        leaf_container,
        assigned_prover_index: assigned_prover,
    }
```

### 7.2 KDF domain separation (CRITICAL)

Per-output material derives from each participant's KEM shared secret
`ss_i` via three strictly domain-separated HKDF expansions:

| Purpose | Label | Output length |
|---|---|---|
| Hybrid signing keypair | `"shekyl-v31-hybrid-sign"` | 64 B |
| Classical spend-auth keypair | `"shekyl-v31-classical-spend"` | 64 B |
| View tag hint | `"shekyl-v31-view-tag"` | 1 B |

**Future spend-auth versions use distinct labels**, preventing
cross-version key reuse:

| spend_auth_version | KDF label |
|---|---|
| **0x02 (Option E′ / 15.4a)** | `"shekyl-v31-classical-spend"` — classical threshold SAL on `y` (Ed25519 in the FCMP++ circuit). **Not** lattice auth. |
| 0x01 | **Never issued** (was Option D mandatory-prover scaffold) |
| Future 15.4b auth evolution | Distinct label — do not overload `0x02` |

Domain separation is a HARD requirement. Any implementation that uses
identical material for two purposes is non-conforming.

### 7.3 Deterministic KEM seed

The `kem_seed` derives from the transaction's secret key:

```
kem_seed = HKDF_Expand(
    tx_secret_key,
    b"shekyl-v31-kem-seed" || u64_le(output_index_in_tx),
    32
)
```

`tx_secret_key` MUST be freshly generated per transaction. Wallets MUST
assert freshness and refuse to construct a transaction if `tx_secret_key`
is reused.

### 7.4 tx_extra additions

Per multisig-recipient output, the tx_extra includes:

| Tag | Name | Payload |
|---|---|---|
| 0x06 | `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` | N × 1120 B |
| 0x07 | `TX_EXTRA_TAG_PQC_LEAF_HASHES` | 32 B (hash of full container) |
| 0x09 | `TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS` | N × 1 B |
| **0x0A** | `TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS` | **1 + N × 32 B** (version byte + N Y_i) |

Tag `0x0A` is new in V3.1 and is REQUIRED on every multisig-recipient
output. Its first byte is the `spend_auth_version` (**`0x02` for
Option E′**; `0x01` never issued); subsequent bytes are the N
spend-auth pubkeys in canonical participant order (E′ layout pinned
in design §0.5 — `B` + `Y_group` + N×KEM once MSW-8 lands).

`TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS` (0x09) MUST be absent for single-sig
outputs. Wallets MUST reject any single-sig-shaped output that contains
this tag.

**Reserved tags (do not use in V3.1):**

| Tag | Reserved for |
|---|---|
| 0x08 | `TX_EXTRA_TAG_MULTISIG_MIGRATION` (V3.2 group rotation / migration tx) |

### 7.5 Spend-time consensus binding

The spend-time binding works through the existing FCMP++ leaf hash check
combined with the `pqc_auth` size check, both already in V3 consensus.
With the Solution C receiving model in place, the binding chain is:

1. Output committed at receive time with `O = spend_auth_pubkeys[assigned]`
2. Leaf scalar `h_pqc = H(MultisigKeyContainer)` binds the full container
   including spend_auth_pubkeys
3. At spend time, the spender presents `pqc_auths[i].hybrid_public_key`
   containing the canonical `MultisigKeyContainer` (byte-identical to the
   one committed)
4. `blockchain.cpp:3720` computes `shekyl_fcmp_pqc_leaf_hash(blob)` and
   the FCMP++ proof confirms this leaf is in the curve tree
5. The FCMP++ proof verifies the key image derives from `O`
6. Honest signers (pre-signing, §2.7 I5) verify
   `O == spend_auth_pubkeys[rotating_prover_index(...)]` — confirming
   the proof was constructed by the assigned prover

Any blob other than the canonical container fails leaf hash matching;
the proof rejects. Size check at `tx_pqc_verify.cpp:206-211` rejects
scheme_id=1 against multisig-shaped blobs.

**Defense-in-depth wiring fixes** (no consensus rule change, but explicit
enforcement of rules already implicitly guaranteed):

- `blockchain.cpp:3768` SHOULD pass `expected_scheme_id` derived from
  the output's `tx_extra_pqc_ownership` to `verify_transaction_pqc_auth`
- `rust/shekyl-ffi/src/lib.rs:343` SHOULD pass `expected_group_id` to
  `verify_multisig` when `scheme_id == 2`

### 7.6 Wallet-side filtering and griefing resource limits

Outputs that pass structural tag parsing but fail KEM decap, view-tag
hint check, or receive-time validation (§8.3) are griefing artifacts.
Wallets MUST:

1. Attempt KEM decap on candidate outputs
2. On decap failure or validation failure, mark the output as garbage
   and never surface it in balance, history, or any user-visible view
3. Apply **per-sender griefing scores**:
   - Maintain a rolling 24-hour window of failed-validation counts per
     sender (keyed by tx author hash, not output)
   - After 10 failures from the same sender in 24h, temporarily mark
     that sender's outputs as low-priority (deprioritized scan) for
     7 days with a user-visible banner "possible griefing detected"
   - After 100 failures in 24h, skip that sender's outputs entirely
     for 7 days
4. Apply **hard caps on garbage state**:
   - Maximum 10,000 garbage entries retained per wallet at any time
   - When cap reached, drop oldest entries first
5. Optionally expose griefing-attack indicators via daemon RPC
   (`get_griefing_stats`) for network-wide monitoring
6. Periodically purge garbage entries (default every 10,000 blocks;
   configurable)

This bounds attack to scanner CPU cost, with no user-visible impact and
no unbounded state growth.

### 7.7 Wallet send-side requirements

When sending to a multisig recipient, the sender's wallet MUST:

1. Display the address fingerprint (§6.3) and require user confirmation
2. Verify that the parsed address has a valid Bech32m checksum
3. Verify that all N hybrid pubkey blobs deserialize correctly
4. Reject addresses with `n_total > MAX_MULTISIG_PARTICIPANTS` or
   `m_required > n_total` (cap = 5 per §5.1 / MSW-G)
5. Reject addresses with unknown `spend_auth_version` (wallets only
   construct outputs for versions they fully implement)
6. Compute and surface the per-output size cost
7. *(Option D only — withdrawn for E′.)* Determine
   `assigned_prover_index` via the sender-computable rule
8. *(Option D only — withdrawn for E′.)* Set
   `O = spend_auth_pubkeys[assigned_prover_index]`. Under **Option E′**
   (§15.4a), construct `O = ho·G + B + y_out·T` with
   `y_out = y_group + y_kem`; any wallet bug here would produce
   unspendable outputs

---

## 8. Wallet Scanning and Receive-Time Validation

### 8.1 Scan-time filtering

Each participant's wallet processes each candidate output:

```python
def scan_output(output, my_participant_index, my_kem_secret):
    # Fast tag check
    hints = parse_tx_extra_tag(output.tx_extra, 0x09)
    if hints is None:
        return None  # not multisig-shaped

    spend_auth_tag = parse_tx_extra_tag(output.tx_extra, 0x0A)
    if spend_auth_tag is None:
        return None  # malformed multisig output

    spend_auth_version = spend_auth_tag[0]
    if spend_auth_version not in KNOWN_VERSIONS:
        return None  # unknown scheme — do not scan (forward-compat)

    if my_participant_index >= len(hints):
        return None  # cardinality mismatch

    # KEM decap my slot
    my_ct = parse_kem_ciphertext_slot(output, my_participant_index)
    ss = HybridKEM.decap(my_kem_secret, my_ct)
    if ss is None:
        register_griefing_failure(output.sender_id)
        return None  # decap failed

    # Fast hint check
    expected_hint = HKDF_Expand(ss, b"shekyl-v31-view-tag", 1)[0]
    if expected_hint != hints[my_participant_index]:
        register_griefing_failure(output.sender_id)
        return None  # hint mismatch

    # Full receive-time validation (§8.3)
    if not validate_multisig_output_at_receive(
        output, my_participant_index, ss, spend_auth_tag
    ):
        register_griefing_failure(output.sender_id)
        return None  # structural validation failed

    # All checks pass; output is ours
    return MatchedOutput { ss, ... }
```

### 8.2 Unknown spend_auth_version handling (forward compatibility)

When a wallet encounters an output with `spend_auth_version` it does not
understand:

- It MUST NOT attempt decap
- It MUST NOT track the output in any form
- It MUST NOT emit an error
- It MUST silently skip the output

This preserves forward compatibility: a V3.1 wallet encountering a V4
output ignores it cleanly. The output remains scannable by upgraded
wallets that understand the newer version.

### 8.3 Receive-time validation (CRITICAL)

Every scanned-and-apparently-ours output MUST be validated for correct
prover-assignment binding before being added to the wallet's balance.
This is honest-signer invariant **I7** from §2.7.

```python
def validate_multisig_output_at_receive(
    output, my_participant_index, ss_mine, spend_auth_tag
):
    # Derive my own spend-auth pubkey
    classical_kdf = HKDF_Expand(ss_mine, b"shekyl-v31-classical-spend", 64)
    y_mine = derive_classical_scalar(classical_kdf)
    Y_mine_computed = y_mine * G

    # Parse the published N spend-auth pubkeys
    n_total = (len(spend_auth_tag) - 1) // 32
    spend_auth_pubkeys = [
        spend_auth_tag[1 + i*32 : 1 + (i+1)*32]
        for i in range(n_total)
    ]

    # Check 1: my own published Y matches my derivation
    if spend_auth_pubkeys[my_participant_index] != Y_mine_computed:
        return False  # sender used wrong material for my slot

    # Check 2: output pubkey O matches the assigned prover's published Y
    tx_secret_key_hash = extract_from_output(output)  # via tx_public_key + cn_fast_hash; see §11.1
    assigned_prover = rotating_prover_index(
        group.group_id,
        output.index_in_tx,
        tx_secret_key_hash,
        output.reference_block_hash,
        n_total
    )

    Y_assigned = spend_auth_pubkeys[assigned_prover]
    if output.output_pubkey != Y_assigned:
        return False  # O doesn't bind to assigned prover

    # Validation passes: output is structurally correct for future spend
    return True
```

**Rationale:** this check catches three distinct failure modes at
receive time, before funds enter user-visible balance:

1. **Malicious sender grief (time-bomb outputs):** sender publishes an
   output that decaps successfully but binds `O` to the wrong participant.
   At spend time, honest signers would detect and refuse to sign (I5),
   leaving funds locked. Receive-time validation rejects before acceptance.
2. **Sender implementation bugs:** a buggy wallet produces outputs with
   incorrect Y_prover assignment. Same outcome as malicious; detected here.
3. **Spec violations during transition periods:** older wallet mis-implements
   the new derivation. Detected.

Outputs failing receive-time validation are treated as griefing artifacts
per §7.6.

### 8.4 Persistence requirements

For each validated multisig output, the wallet MUST persist:

```
PersistedMultisigOutput {
    output_id:             [u8; 32]  # local identifier
    global_output_index:   u64
    my_participant_index:  u8
    my_shared_secret:      [u8; 32]  # ss_mine from decap
    spend_auth_version:    u8
    spend_auth_pubkeys:    [[u8; 32]; n_total]  # ALL N pubkeys from tx_extra
    output_pubkey:         [u8; 32]  # O
    commitment:            [u8; 32]
    amount:                u64
    reference_block_hash:  [u8; 32]
    output_index_in_tx:    u64
    tx_secret_key_hash:    [u8; 32]  # extracted at scan time
    assigned_prover_index: u8  # computed once at scan time, cached
    received_at_height:    u64
    eligible_height:       u64
}
```

**Persistence of all N spend-auth pubkeys** is required so that
prover-assignment verification works at spend time without re-reading
the transaction from chain (which may be pruned on participant's node).

**Seed restore:** When a wallet is restored from seed, it rescans the
chain. For each matched output, it reconstructs `PersistedMultisigOutput`
deterministically from chain data plus the restored seed (which gives
the KEM secret for decap). All fields are reproducible.

### 8.5 Cost

Per output (fast path): 1 KEM decap + 1 HKDF hint check + 1 structural
validation. Each participant processes only their own ciphertext slot.
Per-participant scanning cost is not multiplied by N.

False-positive rate from view-tag hint: ~1/256. Each false positive
triggers full validation (which fails) and griefing-score increment.

---

## 9. Spend Intent

### 9.1 Schema

```
SpendIntent {
    // Versioning
    version:                  u8 (= 1)
    intent_id:                [u8; 32]   // random per intent

    // Group binding
    group_id:                 [u8; 32]

    // Proposer
    proposer_index:           u8
    proposer_sig:             HybridSignature   // over all other fields

    // Temporal binding
    created_at:               u64
    expires_at:               u64
    tx_counter:               u64
    reference_block_height:   u64
    reference_block_hash:     [u8; 32]

    // Content
    recipients: [
        { address: Bech32mAddress, amount: u64 }
    ]   // sorted
    fee:                      u64
    input_global_indices:     [u64]   // sorted ascending

    // Determinism anchor
    kem_randomness_seed:      [u8; 32]   // 32 fresh random bytes

    // Chain state fingerprint
    chain_state_fingerprint:  [u8; 32]   // see §9.3
}
```

### 9.2 Invariants (verified before any signer signs; honest-signer invariant I1)

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
    eligible at the reference height, with each input's
    `assigned_prover_index` locally known
11. Recipients are sorted; no duplicate (address, amount) tuples
12. `sum(recipient.amount) + fee == sum(input.amount)` per local view
13. `kem_randomness_seed` is unique within the group's history of
    `seen_intents` (replay/linkability prevention)
14. `chain_state_fingerprint` matches the verifier's local fingerprint
    (see §9.3); mismatch → do not sign; trigger sync

### 9.3 Chain state fingerprint (honest-signer invariant I2)

Members must agree on chain state before signing. Each intent commits to:

```
chain_state_fingerprint = cn_fast_hash(
    reference_block_hash ||
    sorted_concat(input_global_indices) ||
    sorted_concat(input_eligible_heights) ||
    sorted_concat(input_amounts) ||
    sorted_concat(input_assigned_prover_indices)
)
```

The proposer computes this. Each verifier independently recomputes from
their local view. Mismatch indicates state divergence or manipulation:
do not sign; trigger sync.

Including `input_assigned_prover_indices` ensures all members agree on
which prover is responsible for each input — any disagreement on this is
itself a state divergence that must be resolved before signing.

### 9.4 Intent hash

```
intent_hash = cn_fast_hash(canonical_serialize(SpendIntent))
```

`intent_hash` is the durable identifier. All subsequent messages
reference it.

---

## 10. Canonical Construction

### 10.1 Algorithm

Given verified `SpendIntent`, every member runs:

1. **Pre-flight verification** (§9.2 invariants). On any failure, publish
   `Veto`; do not proceed.
2. **Output derivation** (§7.1). For each recipient (including change
   output, if any), derive output public key, KEM ciphertexts, leaf hash,
   spend-auth pubkeys, and set `O` to the assigned prover's pubkey.
3. **Transaction prefix construction.** Inputs reference key images
   computed from each input's prover-assigned `y` (§11.1); outputs are
   derived per step 2; `tx_extra` includes KEM ciphertexts, leaf hashes,
   view tag hints, spend-auth pubkeys.
4. **CT base.** Type = `CTTypeFcmpPlusPlusPqc (= 1)`; ecdh info,
   commitment masks, pseudo outputs all deterministic from intent.
5. **Compute `signing_payload`** (§10.4).

### 10.2 Bulletproof+ range proofs (deterministic from intent)

Bulletproof+ range proofs use **fresh-looking randomness deterministically
derived from the intent**. This lets every participant independently
reconstruct byte-identical BP+ bytes while keeping the randomness
unpredictable to an external observer.

```
bp_plus_randomness = HKDF_Expand(
    intent.kem_randomness_seed,
    b"shekyl-v31-bp-plus-randomness" || u64_le(output_index_in_tx),
    64
)
```

**Properties:**

- Per-output unique (indexed by output)
- Per-intent unique (tied to fresh `kem_randomness_seed`)
- Reproducible by all group members (deterministic from intent data they
  all hold)
- Unpredictable to external observers (derived from a group-only secret
  chain seed)

**Signer verification (honest-signer invariant I4):** Each signer
independently constructs the BP+ proof from this derivation and verifies
that the bytes match what the prover published. If they differ: prover
equivocated or produced incorrect proof; publish Veto and abort.

This approach was chosen over "prover produces fresh randomness, signers
verify" because it preserves full deterministic construction (every
participant produces byte-identical tx bytes). The cryptographic
question ("is HKDF-derived BP+ randomness sound?") is isolated to one
well-defined concern that cryptographer review explicitly covers
(see `PQC_MULTISIG_V3_1_ANALYSIS.md` §7 review target).

### 10.3 Change output handling

When the group sends to itself (a change output):

- The change recipient is the group's own multisig address
- The Option C + Solution C construction (§7.1) applies identically
- N KEM encapsulations to the group's own KEM pubkeys
- N fresh per-output ephemeral signing keypairs derived
- N fresh per-output ephemeral classical spend-auth keypairs derived
- All N spend-auth pubkeys published in `tx_extra` tag 0x0A
- `O` set to the change output's assigned prover (could be a different
  participant than any input's assigned prover)
- Leaf hash committed

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

Where `RctSigPrunable_skeleton` excludes the FCMP++ proof (comes from
the prover asynchronously). Its hash is included separately in the
signature share commitment (§12.2.1).

### 10.5 Tiebreaker for conflicting intents

When two proposers publish conflicting intents at the same `tx_counter`:

```
winner = intent for which the prover (per §11.1) emits a signed
         ProverReceipt first, where ProverReceipt is published only
         after full invariant verification
```

**ProverReceipt mechanics** (strengthened from v1.0 in response to R3):

```
ProverReceipt {
    prover_index:        u8
    intent_hash:         [u8; 32]
    received_at:         u64
    local_counter:       u64   // monotonic, prover-local, increments per receipt
    sig:                 HybridSignature
}
```

Requirements:

- Prover emits `ProverReceipt` **only after completing full §9.2
  invariant verification** on the intent. A malformed or invariant-failing
  intent never earns a receipt.
- Prover MUST publish the receipt to **all subscribed relays
  simultaneously** (multi-relay mandatory per §12.4)
- `local_counter` is prover-local, monotonic, increments once per receipt.
  Two receipts from the same prover with non-monotonic counters is
  equivocation (§12.2.4)
- Signers observing conflicting intents wait **conflict window**
  (default: 30 seconds) after the first intent before acting, to allow
  the prover's receipt to propagate across relays
- Signers accept the intent for which the ProverReceipt shows the
  lowest `local_counter` (earliest-observed by prover)
- Members who already signed the losing intent publish a `Veto` to reset

**Why the monotonic counter matters:** an attacker controlling network
delivery to the prover can attempt to equivocate (claim "received A first"
to some signers, "received B first" to others). The monotonic
`local_counter` in the receipt makes equivocation detectable: two
receipts with the same counter or out-of-order counters = equivocation
= prover marked untrusted via EquivocationProof (§12.2.4).

**Why not hash-based tiebreaking:** grindable by attacker varying
intent content fields. Prover-receipt shifts the tiebreaker to prover's
observation order, which requires network-level asymmetry to exploit
rather than content grinding.

---

## 11. Spending: Prover and Signing

### 11.1 Rotating prover assignment (sender-computable)

> **Product path (Option E′):** this entire subsection is **deleted
> machinery** — E′ has no mandatory prover (§15.4a / design §0.5).
> Retained as historical specification of the Option D scaffold.
>
> **Naming:** "rotating *prover* assignment" ≠ §15.2 V3.2 "full
> *key* rotation protocol." E′ deletes the former; the latter survives.

For each output being spent, the prover is determined deterministically
from data the **sender knew at construction time**:

```
rotating_prover_index(group_id, output_index_in_tx, tx_secret_key_hash,
                      reference_block_hash, n_total) -> u8

prover_index = first_byte(
    cn_fast_hash(
        group_id ||
        u64_le(output_index_in_tx) ||
        tx_secret_key_hash ||
        reference_block_hash
    )
) mod n_total
```

Where:
- `group_id`: from recipient address (sender knows)
- `output_index_in_tx`: position of this output within its transaction
  (sender knows; not consensus-assigned)
- `tx_secret_key_hash = cn_fast_hash(sender_tx_secret_key)`: sender
  knows; derivable from tx_public_key only by the sender
- `reference_block_hash`: from the spend intent or output's associated
  tx data (sender knows at construction)
- `n_total`: from recipient address

**Properties:**

- **Sender-computable**: every input is known to the sender before
  broadcasting
- **Deterministic**: every group member, given the same output, computes
  the same `prover_index`
- **Unpredictable to observers**: `tx_secret_key_hash` is not derivable
  from on-chain data alone (tx_public_key is related but the hash adds
  a layer; a motivated observer can attempt to correlate but cannot
  pre-compute)
- **Roughly uniform**: cryptographic hash mod N is uniform over any
  reasonable input distribution

**Rotation protects against accident and load, not a hostile sender.**
"Grinding resistance" in the authorization sense is **unreachable by
construction**: the assignment is sender-computable, so a sender who
wants a chosen prover can iterate `tx_secret_key` / `tx_secret_key_hash`
until they get it. Reframe: rotation spreads prover duty so one
participant does not accidentally own every proof; it does **not** stop
a motivated sender from biasing assignments.

**Lead figure (availability griefing, not authorization):** ~`n_total`
expected tries to force one output onto a chosen prover; ~`k · n_total`
to land `k` preferred assignments across `k` independent targets
(separate 1-output txs). That is cheap (~hashes, fee-bounded) — an
**availability** surface (MS-4/MS-5), not a steal path (auth remains
M × ML-DSA). Do **not** lead with scare-`N^k`: forcing *all* `k`
outputs in *one* tx onto the same prover under one shared
`tx_secret_key_hash` is still ~`(1/n)^k` per trial, but that is not
the everyday attack — k separate txs cost ~`k·N`. Cryptographer
formalization of the joint tail remains optional
(`PQC_MULTISIG_V3_1_ANALYSIS.md` §7); it is not a Phase 6 ship gate.

**Recipient-side verification** at receive time confirms the sender's
computed assignment matches the one the group independently derives.
Mismatch rejects the output.

### 11.2 Prover responsibilities per output

The prover for an input:

1. Computes the FCMP++ proof using their per-output classical spend-auth
   secret `y_prover_i` (derived via the `"shekyl-v31-classical-spend"`
   KDF label from their shared secret)
2. Publishes a `ProverOutput` message (§12.2) containing the proof

The prover holds ONLY the per-output classical spend-auth keys for
outputs they were assigned. Compromise of one prover's host exposes
their per-output keys for those outputs only.

### 11.3 Signer verification of prover assignment (honest-signer invariant I5)

Before producing a signature, honest signers MUST verify:

```python
def verify_prover_assignment_and_proof(intent, input, prover_output):
    # Step 1: Recompute assigned prover from persisted output metadata
    persisted = get_persisted_output(input.output_id)
    assigned_prover = persisted.assigned_prover_index  # cached at receive

    # Step 2: Read Y_assigned from persisted state
    Y_assigned = persisted.spend_auth_pubkeys[assigned_prover]

    # Step 3: Verify output public key matches assigned prover
    if persisted.output_pubkey != Y_assigned:
        # Should never happen if receive-time validation passed
        raise PersistedStateInconsistent

    # Step 4: Verify the FCMP++ proof binds to the assigned pubkey
    if not fcmp_verify(
        prover_output.fcmp_proof,
        input.key_image,
        persisted.output_pubkey,   # proof must bind to Y_assigned
        intent.reference_block_hash
    ):
        return False

    # Step 5: Verify BP+ proofs against independently-computed bytes (I4)
    if not verify_bp_plus_deterministic(intent, output_commitments,
                                         prover_output.bp_plus):
        return False

    # Step 6: Verify the key image is consistent with Y_assigned
    # (FCMP++ verify already does this internally, but explicit check
    # guards against future implementation drift)
    if not key_image_binds_to_pubkey(input.key_image, Y_assigned):
        return False

    return True
```

**This check uses only publicly-verifiable data.** No participant needs
to know another participant's shared secret. `spend_auth_pubkeys` is
persisted locally at receive time and is the full N-pubkey list.

**Enforcement level (§2.7):** this check is unbypassable in supported
wallets. It runs in the core signing path; any return-false or
exception-raise causes:
1. Signing aborted
2. `InvariantViolation` message published (type 0x09)
3. Intent moved to REJECTED state

### 11.4 Signing protocol (non-interactive scheme_id=2)

Each signer in the M-of-N selected subset:

1. Receives intent + ProverOutput
2. Independently reconstructs the canonical transaction (§10)
3. Verifies the FCMP++ proof against signing_payload (I3)
4. Verifies BP+ proofs match deterministic derivation (I4)
5. Verifies prover assignment (I5, §11.3)
6. Computes the final tx_hash (including the prover's proof)
7. Produces hybrid (Ed25519 + ML-DSA-65) signature over signing_payload
8. Publishes `SignatureShare` (§12.2.1) including the tx_hash and
   proof commitments

### 11.5 Assembly (honest-signer invariant I6)

Any member with M valid SignatureShare messages:

1. Verifies all M tx_hash commitments agree
2. Verifies all M FCMP++ proof commitments agree
3. Verifies all M BP+ proof commitments agree
4. Any disagreement → publish EquivocationProof (§12.2.4) and abort
5. Otherwise, constructs `pqc_auth` blob with scheme_id=2 layout,
   attaches to transaction, submits to daemon

Multiple members may attempt assembly simultaneously. Network picks
whichever broadcast succeeds first.

### 11.6 The 1/N permanent loss limitation

A participant who permanently loses their keys cannot serve as prover
for the outputs they were assigned. Approximately 1/N of group outputs
become permanently unspendable.

| N | Loss per missing key |
|---|---|
| 3 | ~33% |
| 5 | ~20% |
| 7 | ~14% |

This is an accepted V3.1 limitation. Users MUST complete §5.4
acknowledgment at group setup. Wallets MUST surface, on the multisig
dashboard, the estimated percentage of value held by each participant's
prover responsibility.

V4 FROST SAL eliminates this entirely. V3.2 may add a key escrow
protocol as mitigation.

### 11.7 Rate limiting (by signing pubkey, not index)

To prevent intent-spam DoS:

- Each proposer's **hybrid signing public key** (not proposer_index) may
  have at most 1 active intent per group at a time (active = state in
  {PROPOSED, VERIFIED, PROVER_READY, SIGNED})
- Rate limit is group-wide configurable at setup (default: 1 active
  intent per signing pubkey; maximum 1 new proposal per 5 minutes per
  signing pubkey)
- Keying off signing pubkey prevents a malicious member with multiple
  proposer_index slots from multi-indexing their way around the limit
- New proposals from the same signing pubkey violating the limit are
  rejected with rate-limit veto

This bounds verification work to ≤ N concurrent intents.

---

## 12. Messages and Transport

### 12.1 Common envelope

```
MultisigEnvelope {
    version:        u8 (= 1)
    group_id:       [u8; 32]
    message_type:   u8                  // ENCRYPTED in payload
    intent_hash:    [u8; 32]
    sender_index:   u8
    sender_sig:     HybridSignature     // over all above + payload
    payload:        EncryptedBlob
}
```

The envelope's `message_type` is encrypted in the payload (§12.3) to
prevent role-pattern leakage. Cleartext envelope fields: `version`,
`group_id`, `sender_index`, `intent_hash`, `sender_sig`, encrypted
payload.

### 12.2 Message types (encrypted)

| Type | Name | Purpose |
|---|---|---|
| 0x01 | SpendIntent | Proposer publishes |
| 0x02 | ProverOutput | FCMP++ proof (BP+ is now in main tx per §10.2) |
| 0x03 | SignatureShare | Signer's hybrid signature + commitments |
| 0x04 | Veto | Refusal or abort |
| 0x05 | ProverReceipt | Prover's tiebreaker acknowledgment |
| 0x06 | Heartbeat | Liveness + censorship detection |
| 0x07 | CounterProof | State recovery |
| 0x08 | GroupStateSummary | Periodic synchronization |
| **0x09** | **InvariantViolation** | **Signed notice that an honest-signer invariant failed** |
| 0x0A | RotationIntent (RESERVED) | V3.2 full rotation protocol; reserved in V3.1 |
| 0x0B | EquivocationProof | Prover equivocation evidence |

#### 12.2.1 SignatureShare structure

```
SignatureShare {
    signer_index:              u8
    hybrid_sig:                HybridSignature
    tx_hash_commitment:        [u8; 32]
    fcmp_proof_commitment:     [u8; 32]
    bp_plus_proof_commitment:  [u8; 32]
}
```

#### 12.2.4 Prover equivocation detection

If a malicious prover sends different `ProverOutput` messages to
different signer subsets, signature shares will disagree on
`fcmp_proof_commitment`. Members publish:

```
EquivocationProof {
    prover_index:    u8
    intent_hash:     [u8; 32]
    proof_a:         ProverOutput  // including prover_sig
    proof_b:         ProverOutput  // different, including prover_sig
}
```

Also detected: two `ProverReceipt` messages from the same prover for the
same intent with non-monotonic or duplicate `local_counter` values.

#### 12.2.6 InvariantViolation structure

```
InvariantViolation {
    reporter_index:      u8
    intent_hash:         [u8; 32]
    invariant_id:        u8         // which of I1-I7 from §2.7 was violated
    evidence:            bytes      // intent or proof bytes demonstrating the violation
    reporter_sig:        HybridSignature
}
```

Publishing an InvariantViolation is how honest signers signal that they
refused to sign a specific intent. Other members treat a published
InvariantViolation as a strong signal to also refuse, and to investigate
whether their own state disagrees.

### 12.3 Encryption

Per-message symmetric key derivation:

```
message_key = HKDF_Expand(
    group_shared_secret,
    intent_hash || u8(message_type) || u8(sender_index),
    32
)
```

`group_shared_secret` is the DKG-derived 32-byte value from §5.2.

AEAD: ChaCha20-Poly1305 with 96-bit nonce:
```
nonce = HKDF_Expand(
    group_shared_secret,
    b"nonce" || u8(sender_index) || u64_le(message_counter),
    12
)
```

### 12.4 Multi-relay with operator uniqueness (mandatory)

Members MUST publish each message to **at least 3 independent relays
operated by disjoint operators**. The relay list is part of group state.

**Operator uniqueness enforcement:**

1. Wallets MUST consume a signed **relay directory** (updated via GitHub
   releases or published on-chain as a special metadata transaction).
   The directory maps relay URLs to operator identifiers.
2. At group setup, each participant MUST select relays from at least
   3 distinct operators per the directory.
3. Each `Heartbeat` message (§13.3) includes the sender's **observed relay
   operator IDs** — the operator IDs corresponding to relays where that
   member has actually received messages in the last interval.
4. Members compare observed operator IDs from heartbeats; if all
   heartbeats come from relays operated by the same entity (or a small
   subset), they flag this as potential centralization and warn users.

This closes the attack where a single operator running three relays
under different names could satisfy "3 relays" without providing actual
censorship resistance.

### 12.5 Cleartext envelope minimization

The encrypted `message_type` prevents passive observers from inferring
roles (only-prover-sends-0x02, only-signers-send-0x03). Observers see
encrypted blobs at varying sizes addressed to a stable `group_id`.

Future V3.2 traffic padding + batched delivery can strengthen this; not
in V3.1 scope.

### 12.6 Transport bindings

**Nostr relay binding:** Each message posted as Nostr kind-30000
replaceable event; `d` tag includes `group_id` hash + unique message
identifier. Nostr signature is for relay acceptance only.

**Direct P2P binding:** Members connect via mTLS with hybrid
certificates when topology permits. Messages still subject to envelope
/encryption requirements.

**File binding (air-gap) with opaque naming:**

Rather than the previous draft's metadata-leaking filename convention,
file transport now uses:

- **Random opaque filenames** (e.g., `shekyl-ms-<random64hex>.bin`)
- **Encrypted manifest** inside the file metadata (not in filename)
  that contains the `group_id`, `intent_hash`, `message_type`,
  `sender_index` for wallet ingestion
- **Display-only filenames** in the UI (e.g.,
  "Intent 0x1a2b... message from member 3") derived from the encrypted
  manifest once decrypted; never written to disk

This preserves air-gap compatibility while preventing filesystem metadata
leakage when files end up on shared media, USB drives, cloud backups,
or forensic images.

---

## 13. State Machine and Counter Recovery

### 13.1 Per-intent state

```
PROPOSED       → intent received, not yet verified
VERIFIED       → §9.2 invariants pass
PROVER_READY   → ProverOutput received; FCMP++ and BP+ verification pass
SIGNED         → this member produced and published SignatureShare
ASSEMBLED      → M signatures observed
BROADCAST      → tx confirmed in mempool / on-chain
REJECTED       → veto/invariant-violation threshold reached or chain-rejected
TIMED_OUT      → expires_at reached without BROADCAST
```

### 13.2 tx_counter advancement

`tx_counter` advances ONLY upon observed chain state, not local optimism.
Specifically: tx_counter increments to k+1 when a member observes the
broadcast tx confirmed in their local chain at height ≥ N confirmations
(default N=3; configurable).

### 13.3 Heartbeat protocol

Members publish `Heartbeat` every `HEARTBEAT_INTERVAL` (default 5 min)
to all subscribed relays:

```
Heartbeat {
    sender_index:             u8
    timestamp:                u64
    last_seen_intent:         [u8; 32]
    observed_relay_ops:       [RelayOperatorId]   // which operators this member sees
    local_tx_counter:         u64
    sig:                      HybridSignature
}
```

Members compare heartbeats to detect:

- Missing heartbeats from a specific member (offline or censored)
- Disagreement on `last_seen_intent` (relay censorship)
- Collapse of observed relay operator diversity (censorship + operator
  collusion)
- tx_counter divergence
- Time skew

Action on anomaly: retry across all subscribed relays, escalate to user,
do not advance state optimistically.

### 13.4 CounterProof recovery (strengthened formalization)

When a member is at stale `tx_counter`, recovery uses cryptographic
chain proof with **explicit advancement-lineage verification**:

```
CounterProof {
    sender_index:           u8
    advancing_to:           u64
    tx_hash:                [u8; 32]
    block_height:           u64
    block_hash:             [u8; 32]
    tx_position:            u16
    consumed_inputs:        [[u8; 32]]   // key images of consumed inputs
    resulting_outputs:      [[u8; 32]]   // output pubkeys produced by the tx
    intent_hash:            [u8; 32]     // the intent this tx broadcast
    sender_sig:             HybridSignature
}
```

**Verification rules (strengthened from v1.0):**

A stale member receiving a `CounterProof` MUST verify, in order:

1. `block_hash` matches their local chain at `block_height`
   (if local chain lacks this block, wait for sync; do not reject)
2. `tx_hash` appears at `tx_position` in that block
3. `tx.pqc_auths[i].scheme_id == 2` for all inputs (multisig spend)
4. `multisig_pqc_leaf_hash(tx.pqc_auths[i].hybrid_public_key)` matches
   the leaf hash of an output tracked in local state with matching
   `group_id`
5. The `consumed_inputs` listed in CounterProof match the tx's actual
   input key images exactly (no loose matching)
6. All `consumed_inputs` are in local state as tracked unspent outputs
   owned by the group
7. `intent_hash` references an intent the member has seen (or, if
   unseen, a note is logged: member was absent during proposal)
8. `sender_sig` verifies

**Advancement rule:** only after all checks pass, the member:

1. Marks all `consumed_inputs` as spent in local state
2. Adds all `resulting_outputs` to scanning (if they belong to the group)
3. Advances `tx_counter` to `advancing_to`

**If any check fails:**
- If the failure is "I don't have the block yet": wait for sync; do not
  reject; do not advance
- If the failure is "I don't recognize these inputs as my tracked outputs":
  trigger full wallet rescan from reference height; do not advance based
  on this CounterProof
- If the failure is structural (scheme_id wrong, leaf hash doesn't
  match): CounterProof is invalid; do not advance; publish Veto

This formalization prevents:
- Attackers forging CounterProofs for arbitrary on-chain transactions
  (must reference the group's actual tracked inputs)
- Loose matching leading to false advancement (exact input/output match
  required)
- Advancement without state consistency (rescan forced if local state
  is out of sync)

### 13.5 Disagreement resolution

**Conflicting intents same counter** → §10.5 ProverReceipt with
monotonic counter

**Proposer disappears** → `expires_at` → TIMED_OUT

**Prover disappears for an output** → intent times out; rotating prover
means different outputs have different provers; 1/N permanent-loss per
missing key

**Chain reorg of reference_block** → intents referencing orphaned blocks
transition to TIMED_OUT; re-propose with new reference

**Prover equivocation** → §12.2.4 detection and EquivocationProof

**Honest-signer invariant violation** → §2.7 InvariantViolation
published; intent REJECTED

---

## 14. Security Properties

### 14.1 Authorization

| Property | Mechanism |
|---|---|
| No unilateral spend | scheme_id=2 consensus requires M PQC signatures |
| No unilateral redirect | Deterministic construction; signers reconstruct and verify |
| No wrong-prover spend | §11.3 honest-signer prover assignment verification (I5) |
| No sender griefing via malformed assignment | §8.3 receive-time validation (I7) |
| No invariant bypass | §2.7 mechanical enforcement in signing path |

### 14.2 Privacy

| Property | Mechanism |
|---|---|
| Per-output forward privacy | Option C N-fold KEM fan-out + per-output ephemeral keys |
| Spend-to-spend unlinkability (within scheme-2) | Different ephemeral N-key blobs per spend — **but see stream attribution below** |
| Group identity privacy from passive observer | group_id not on-chain; encrypted transport |
| Role-pattern privacy from relay observers | Encrypted message_type in envelope |
| Filesystem metadata privacy | Opaque filenames + encrypted manifest (§12.6) |

**Stream attribution (honest statement, 2026-07-15).** Do **not** write
"accepted given negligible multisig volume" — that is circular: the
anonymity set stays small *because* volume is negligible. The load-
bearing privacy fact for `scheme_id = 2` spends:

- Every scheme-2 spend is **provably one entity's** (the M-of-N group
  that authorized it). One linkage event (exchange deposit/withdrawal,
  KYC'd counterparty, etc.) **retroactively deanonymizes the whole
  history** of that stream.
- The scheme-2 FCMP set is the multisig outputs **by construction** —
  harmless at low N; it is not a separate "multisig set" to grow into.
- Change-output leak lands on **senders** (who choose to pay a
  multisig address), not on the group as a special consensus class.

Operator docs and UX must treat multisig as a **labeled custody
stream**, not as "same privacy as solo at small volume."

### 14.3 Liveness

| Property | Status |
|---|---|
| Any M honest signers can advance | Yes (assuming assigned prover is among them) |
| Proposer disappearance recovery | Yes (timeout + re-propose) |
| Signer disappearance recovery | Yes if M others remain |
| Prover disappearance per-output | Limited; 1/N outputs lock per missing prover (V4 fixes) |
| Network partition recovery | Yes via formalized CounterProof |
| Relay censorship resistance | Multi-relay + operator uniqueness + heartbeat |
| Scanner resource bounds | Hard caps + per-sender griefing scores (§7.6) |

### 14.4 Integrity

| Property | Mechanism |
|---|---|
| Tx hash integrity through assembly | tx_hash_commitment in SignatureShare (I6) |
| Prover proof integrity | fcmp_proof_commitment + bp_plus_proof_commitment |
| Prover non-equivocation | EquivocationProof detection (§12.2.4) |
| Counter integrity | Formalized CounterProof advancement lineage (§13.4) |
| Replay resistance | intent_id, kem_randomness_seed freshness, expires_at, reference_block_hash, tx_counter |
| Invariant enforcement | §2.7 mechanical, unbypassable in signing path |

---

## 15. Forward Compatibility

### 15.1 Reserved namespace

| Item | Purpose |
|---|---|
| `group_version = 0x01` | V3.1; higher values for future rotated groups |
| `spend_auth_version = 0x02` | **Option E′** (15.4a threshold classical SAL on `y`). **`0x01` never issued.** Higher values only for a later mutually-distrusting / lattice-auth path — do not overload `0x02`. |
| HRP `shekyl1n...` | Rotated-key multisig (V3.2+) |
| `TX_EXTRA_TAG_MULTISIG_MIGRATION (0x08)` | V3.2 migration transactions |
| Message type `0x0A` (RotationIntent) | V3.2 full rotation protocol |

**Honesty pin (2026-07-14 — P0-k / R1-F-11).** These rows are
*intent*, not substrate. Today:

1. **`group_version` is fused with `MULTISIG_CONTAINER_VERSION`.**
   `multisig_group_id` passes the compile-time constant as
   `group_version`, not `container.version`. Wire-encoding version and
   protocol-semantics version are different jobs sharing one byte.
   When a v2 container exists under the current code, group_id would
   silently hash v1's group_version. **MSW-4** unfuses: parse accepts
   a known-version set; `group_id` reads `container.version`.
2. **`spend_auth_version` is not a container wire field.** It is a
   hardcoded `SPEND_AUTH_VERSION_ED25519` argument into the group_id
   preimage (and appears as the first byte of the `tx_extra`
   spend-auth tag at receive time — wallet layer). Address/`group_id`
   binding may be the right carrier (§15.5); it is currently so **by
   accident**, not named decision. **MSW-5** pins the disposition.
3. **Reserved-namespace KATs are incomplete.** Existing
   `group_id_v31_includes_version_fields` covers `scheme_id` and
   `spend_auth_version` via `with_versions`; it does **not** vary
   `group_version`. A reserved byte never set to a second value is
   indistinguishable from a constant.

V3.2 / V4 / 2030+ migration paths run through these bytes. They are
genesis-frozen the same way `PQC_MAX_*_BLOB` is — the `multisig`
feature gate does not protect them. Track A owns the fix.

V3.1 provides the necessary hooks **once MSW-4/5 land**:
- Separated container vs group version (or one byte with both jobs
  *named* and `group_id` reading the wire)
- Named spend_auth_version carrier
- Exercised reserved-namespace KATs
- Reserved message type 0x0A / `tx_extra` tag 0x08 (unchanged)

### 15.2 V3.2 full rotation protocol (hooks reserved, protocol deferred)

> **Naming collision (2026-07-15).** This section is **participant / group
> *key* rotation** (new KEM keys, new `group_id`, migration txs). It is
> **unrelated** to §11.1 "rotating *prover* assignment," which Option E′
> deletes. Do not read "rotation deleted" (E′ / mandatory prover) as
> striking this V3.2 key-rotation work.

V3.1 reserves the message type and namespace for rotation but does NOT
implement the rotation protocol itself. The rotation protocol will be
specified and shipped in V3.2 as a focused release.

**Rationale for deferral:** rotation is a complex protocol with multiple
rotation modes (individual, group, spend-auth upgrade), migration
transaction semantics, race conditions during the rotation window, and
privacy considerations on migration txs. **These flaws will surface only
through actual use.** The V3.2 timeline is explicitly chosen so that
design flaws surface when real users depend on the feature, not in a
rushed pre-launch implementation. This is not a scope-protection
argument; it is a design-maturity argument.

V3.1 provides the necessary hooks **once MSW-4/5 land** (see §15.1
honesty pin). V3.2 will add:
- Full `RotationIntent` protocol
- Individual participant key rotation
- Full group rotation (new group_id)
- Migration transactions consuming old outputs, producing new

~~Key escrow protocol as 1/N loss mitigation~~ — **struck for E′**
(2026-07-15). There is no mandatory-prover 1/N loss to mitigate under
`spend_auth_version = 0x02`. If a future mutual-distrust mode
reintroduces single-holder liveness, escrow belongs under *that*
version byte — not inherited silently into V3.2 from Option D.

### 15.3 Address size / group registry (re-priced 2026-07-15)

**MSW-8** deletes vestigial address `hybrid_sign_pubkeys`
(`PER_PARTICIPANT_LEN` 3200 → 1216). After that cut:

| N | bech32m chars (approx) | note |
|---|---|---|
| 2 | ~3,900 | QR-able under alphanumeric cap ~4,296 |
| 3 | ~5,850 | file-friendly |
| 5 | ~9,740 | still a file; not 25k |

**Chain-anchored group registry** (§6.5) is an **optimization**, not a
V3.1 critical-path prerequisite. The fossil made 15k–36k chars look
unusable; that weight was the unread field. Traffic-padding /
heartbeat privacy work remains a separate V3.3-candidate.

Does not reopen `MAX_MULTISIG_PARTICIPANTS` (MSW-G=5).

### 15.4 V4 path — two items, two blockers (split 2026-07-14; posture pin same day)

Earlier prose bundled "FROST SAL + pure-PQC spend-auth" behind a single
NIST-lattice gate. That was wrong twice: it parked 15.4a behind NIST,
and the phrase "pure-PQC spend-auth" is ambiguous (pin below).

#### Posture first — multisig is already PQ for authorization

Scheme_id=2 verify check 10 is `M × Ed25519 + M × ML-DSA`
(`shekyl-crypto-pq` multisig). The key container is hybrid by
construction (`SINGLE_KEY_CANONICAL_LEN = 1996`). Forging an M-of-N
spend requires breaking ML-DSA-65 M times. **Threshold authorization
is quantum-resistant today.**

Classical exposure lives in the **FCMP++ layer**, not in multisig:

- SAL / membership: Ed25519 (`SPEND_AUTH_VERSION_ED25519 = 0x01`;
  `SpendAuthAndLinkability` in `shekyl-fcmp`, compiled unconditionally).
- Leaf `{O.x, I.x, C.x, H(pqc_pk)}` for every output on the chain.
- **Solo has the identical posture** — classical membership/SAL +
  hybrid PQC auth bound through `h_pqc`. Multisig adds **zero**
  classical exposure; it carries M hybrid signatures instead of one.

**Quantum degradation of the SAL is graceful for funds, not for
privacy.** An adversary who breaks Ed25519 learns each assigned
prover's `y` and can produce the SAL themselves — the mandatory-prover
dependency evaporates — and **M × ML-DSA still authorizes the spend**.
Classical SAL is a **liveness** dependency (1/N permanent-*loss*), not
a compromise path. Curve break against FCMP++ membership is
**privacy retroactive** (HNDL on the anonymity set); that concern is
real, **not multisig-specific**, and multisig neither helps nor hurts
it.

**Consequence for Track B:** grinding, rotation bias, hostage fraction,
veto / heartbeat / griefing are **availability engineering** (MS-4 /
MS-5 / R-F), not cryptography. They do not belong in the Phase 6
cryptographer queue. Funds are freezable under those attacks, not
stealable via them. Shipping multisig now is an **economics** question
(~2.4× per-tx size vs solo for 5-of-5; ≪ five solos — `V3_ROLLOUT.md`)
— whether threshold custody is worth that cost — not a crypto-maturity
question.

#### Phrase pin — what "pure-PQC spend-auth" is *not*

| Reading | Meaning | Status |
| --- | --- | --- |
| **(a) Lattice-only *auth signing*** | Drop the Ed25519 half of the hybrid `scheme_id=2` key/sig container; M-of-N or composite becomes lattice-only at the *authorization* layer | Achievable in principle; size/FIPS story; **not** what `spend_auth_version` gates |
| **(b) Lattice *SAL*** | Replace Ed25519 `O` / `y` with a lattice key verified inside FCMP++ | **Impossible** while FCMP++ is the membership proof (Helios/Selene circuit verifies a curve equation) |

`spend_auth_version` gates the **SAL key scheme** published in
`tx_extra` (`spend_auth_pubkeys`), not the hybrid auth container.
**`spend_auth_version = 0x02` means 15.4a** (threshold classical SAL /
FROST group-shaped `y` under a two-component address) — still Ed25519
points in the circuit. It does **not** mean (b). Reading (a) is a
separate auth-layer evolution (scheme id / blob layout), tracked
under 15.4b's size motivation when lattice threshold maturity allows
a composite or lattice-only auth path.

#### 15.4a — FROST SAL / Option E′ (threshold `y`; no mandatory prover)

**Product shape (2026-07-15):** **Option E′** — see
`V3_1_MULTISIG_RUST_ENGINE.md` §0.5. Two-component
`O = ho·G + B + y·T` (`output.rs:286-304`) splits trust axes:

- **`b` / `B`:** group-plaintext view+link key → local key images /
  balance without co-signer ceremony.
- **`y`:** FROST M-of-N group secret with per-output tweak
  `y_out = y_group + y_kem` (E′, not fixed-`y` E).
- **Ship:** dealer-mode (owner = trusted KeyGen), MAX=5,
  `spend_auth_version = 0x02`, **`0x01` never issued**.
- **Deletes:** mandatory prover, rotation/grinding, heartbeat,
  counter_proof, I7 receive-time prover check, griefing scores.

**Fixes:** 1/N permanent-**loss** lock and the availability surface that
existed only because a single assigned prover held `y`. Does **not**
change quantum authorization strength (already M × ML-DSA). Does **not**
shrink auth blobs (15.4b).

**Blocked on (internal — now open):** Apr 9 `y=0` / two-component-address
gate is dead — `derive_output_secrets` asserts `y ≠ 0`
(`rust/shekyl-crypto-pq/src/derivation.rs`; formula
`O = ho·G + B + y·T` in `output.rs`). Remaining work: threshold-
share `y_group`, wire `0x02`, nonce-discipline types, E′ address layout
(`B` + `Y_group` + N×KEM). **Not blocked on NIST.**

**Watch (15.4b size only):** dPN25 (T≤8, ~2.7 KB), TALUS/ML-DSA-threshold.
Do **not** lead with TRaccoon (wrong N, coordinator, no DKG).

**Coexistence:** E′ is the issued V3.1 path. A later stack (lattice
auth, mutual-distrust DKG mode) lands **beside** it under a new
version/HRP — §15.5 + MSW-4/5 discriminability. See design doc §0.4 /
§0.5.

#### 15.4b — Composite / lattice-only *auth* (size, not SAL)

**Fixes:** M-of-N hybrid signature-list **blob size**, F-1 bound
pressure, full-reward-zone tension with large N, N-cap size lens.
Does **not** fix the mandatory prover (that is 15.4a). Does **not**
add PQ authorization (already present).

**Blocked on (external):** lattice *threshold* maturity. NIST IR 8214C
(final 2026-01-20) is a **reference-material collection**, not a
standardization — packages → analysis → MPTC characterization report
(~2027) that "may include recommendations for future processes."
Actual standardization is that later process (2030+ plausible). The
deferral **hardened**.

**Watch list (not V3.0/V3.1 adoption):**

| Line | Regime / note | Fit for Shekyl N≤8 |
| --- | --- | --- |
| Threshold Raccoon (del Pino et al., eprint 2024/184) | ~13 KiB sigs, ~40 KiB/user, T≤1024; trusted KeyGen; coordinator combine; not FIPS | Wrong regime; imports F-3; not FIPS 204 |
| dPN25 (del Pino–Niot) | Compact T≤8, ~2.7 KiB Dilithium-family; **not** FIPS 204 | Exact N; best size win on paper |
| Tanuki (MPTS 2026 preview) | 2-round + preprocessing; Raccoon-compatible | Watch |
| **TALUS** (MPTS 2026) | Threshold **ML-DSA**, 1-round online | **Primary watch** — thresholds shipped `fips204` |

All of the above threshold the **auth layer** only. None are a lattice
SAL. None touch 15.4a.

**Genesis / MSW-G:** MAX=5 is 2f+1 at f=2 (largest group served), not
a zone fill. A future composite auth (15.4b) may reopen the size lens
for larger N; genesis freezes on today's signature-list economics with
that explicit 15.4b expiry.

### 15.5 No implicit upgrades

Outputs created under one `spend_auth_version` MUST NOT be reinterpreted
under another. Upgrading requires explicit migration transaction. This
prevents silent misreinterpretation and preserves auditability across
scheme transitions.

**Implication for Stage 4 / V4:** this rule forbids in-place evolution of
V3.1 durable fields into V4 shapes. V4 is a **coexisting rewrite**
(§15.4). Do not design V3.1 persistence for "Stage 4 will evolve this
type" — design it so the version discriminator routes to the correct
stack forever.

---

## 16. Implementation Plan

### 16.1 New Rust modules

```
shekyl-engine-core/src/multisig/v31/
├── intent.rs              — SpendIntent type, canonical serialization
├── construction.rs        — canonical_construct() deterministic function
├── prover.rs              — ProverOutput; rotating prover assignment
├── signing.rs             — non-interactive scheme_id=2 signing
├── messages.rs            — envelope + message types
├── encryption.rs          — group_shared_secret + AEAD
├── invariants.rs          — §2.7 honest-signer invariant checks
├── transport/
│   ├── mod.rs
│   ├── nostr.rs
│   ├── p2p.rs
│   ├── file.rs            — opaque filenames + encrypted manifest
│   └── relay_directory.rs — operator uniqueness enforcement
├── state.rs               — per-intent state machine
├── heartbeat.rs
├── counter_proof.rs
└── tx_counter.rs

shekyl-crypto-pq/src/multisig_receiving.rs
├── construct_multisig_output_for_sender
├── scan_multisig_output_for_participant
├── validate_multisig_output_at_receive  — §8.3
├── derive_spend_auth_pubkey               — versioned §7.2
└── rotating_prover_index                  — sender-computable §11.1
```

### 16.2 New tx_extra tags

`src/cryptonote_basic/tx_extra.h`:
- `TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS = 0x09`
- `TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS = 0x0A`
- Reserved: `TX_EXTRA_TAG_MULTISIG_MIGRATION = 0x08`

### 16.3 Defense-in-depth wiring fixes

> **MSW-6 (landed).** The tx-wide `expected_scheme_id` DiD that forced
> **tx-wide** scheme agreement is **withdrawn** (option a — dropped
> outright, not exempted). Its *stated* purpose (a cross-input
> scheme-downgrade defense) was vacuous: `expected_scheme` was derived
> from `pqc_auths[0]` itself (self-referential), and per-output scheme
> binding is the leaf hash `h_pqc = H(hybrid_public_key)`, not this
> check. Its *actual* effect was to foreclose a
> solo(1)/multisig(2) **cross-model linkage** — under FCMP++ separate
> txs are unlinkable, so co-spending is the only proof of common control
> across key models. That belongs in the wallet, not consensus, on two
> grounds: **(1) no externality** — the two co-spent outputs are one-time
> keys and the FCMP++ proof ranges over the whole tree, so no other
> party's anonymity set shrinks (contrast a small ring, which poisons
> others' decoys — the reason ring size *is* consensus); it is pure
> self-harm; **(2)** Shekyl already permits exactly this opt-in class — a
> `scheme_id=2` spend provably marks the spender, shipped as a disclosed
> opt-in cost — so refusing an opt-in cross-model link while permitting
> the multisig mark would be incoherent. It is therefore a **wallet
> coin-selection invariant**, which must land as a **blocking E′ / MS-5
> ship gate** (a coin-selection rule that never crosses key models, with a
> test, + the disclosure line — see the FOLLOWUPS residue), not a consensus
> mechanism. (**Not TM-1**: that disposition rests on the linkage being
> *impossible to mechanize* — shared-operator personas are unlinkable by
> construction — which does not transfer to a case where the mechanism
> existed and worked.) Each input is still validated per-input (scheme ∈ `{1,2}`,
> blob length, signature). Cross-scheme confusion remains prevented by
> length disjointness (MSW-2); archival core never sees funding
> `pqc_auths`.

- ~~`src/cryptonote_core/blockchain.cpp` tx-wide `expected_scheme_id`~~
  → **MSW-6 landed** — dropped in both C++ verify batteries
  (`tx_pqc_verify.{h,cpp}` + `blockchain.cpp`) and the Rust submit
  verifier (`verifier.rs`). KAT: `fcmp.cpp::msw6_mixed_scheme_transaction_verifies`.
- `rust/shekyl-ffi` / group_id DiD for scheme_id=2: **MS-8 retired**
  (leaf already binds the blob; no-op)

### 16.4 Modified C++ — **RETIRED**

> **Retired 2026-07-15 (Phase 0).** Do not implement wallet2 /
> `cryptonote_tx_utils` multisig paths. Wallet-side multisig logic
> lands in Rust behind the `multisig` Cargo feature
> ([`V3_1_MULTISIG_RUST_ENGINE.md`](design/V3_1_MULTISIG_RUST_ENGINE.md),
> **MS-2**). Allowed C++ surface: LMDB / chain-DB persistence of
> consensus-visible bytes; existing `scheme_id ∈ {1,2}` verify into
> Rust FFI; **MSW-6** tx-layer scheme rule. Historical bullets deleted
> rather than kept as "superseded" temptation.

### 16.5 New address parsing

- `rust/shekyl-encoding/src/lib.rs`: `shekyl1m` HRP
- `rust/shekyl-address/`: `MultisigAddress` type with
  `spend_auth_version` handling

### 16.6 GUI wallet changes

- Multisig page: file import/export for addresses
- Multisig page: mandatory fingerprint verification dialog (3 representations)
- Multisig page: 1/N loss acknowledgment gate at group setup
- Multisig page: prover-responsibility distribution view
- Multisig page: address provenance tracking UI with change warnings
- Settings: relay configuration (minimum 3 with operator diversity check)
- DKG ceremony UI for group setup
- Invariant violation alerts surfaced to user

### 16.7 Feature flag structure

**Status: planned sketch — these flags are not in any `Cargo.toml`
today.** Do not copy-paste the block below into a crate; it names the
intended gate axes for Track B / Option E′. Live today: `multisig`
scaffolding feature on engine-core / engine-rpc / ffi (F-6 CI lane).
`frost-sal-v4` and `unsafe-testing-only` land when E′ / simple-mode
fixtures are implemented (after Option A orchestration DELETE).

```
# PLANNED (not present in workspace Cargo.toml as of 2026-07-15)
[features]
default = []
multisig = []                       # scaffolding / CI compile (F-6) — PARTIAL: exists
frost-sal-v4 = []                   # Option E′ product path (15.4a) — NOT YET
unsafe-testing-only = []            # simple-mode fixtures, dev only — NOT YET
# Mutual exclusion: cargo enforces at compile time (when landed)
```

CI verifies release builds do not contain simple-mode symbols.
**F-6:** CI must build `check/clippy/test` with `--features multisig`.

**`frost-sal-v4` is E′'s planned gate** (was specified, never built —
now the first real coexistence boundary for `spend_auth_version =
0x02`). Build it after deleting the Option A `MultisigGroup` wrapper;
**keep** `shekyl-fcmp::{frost_sal, frost_dkg}` primitives. Do **not**
park the rejected fixed `pqc_public_key` fossil behind this flag —
**delete** `multisig/{dkg,group,signing}.rs` orchestration (R1-F-3)
and re-home clean SAL-only types under the E′ stack.

### 16.8 Test matrix

**Functional:**
- 2-of-3, 3-of-5, 5-of-5 happy paths (receive + spend)
- Single-sig → multisig, multisig → multisig
- Change outputs (group → self)
- Staked outputs

**Adversarial (per-invariant):**
- Malicious proposer attacks each of §9.2 invariants (I1)
- Chain state fingerprint manipulation (I2)
- Malicious prover: wrong payload, malformed proof (I3)
- Malicious prover: incorrect BP+ randomness (I4)
- Wrong-prover key image attack (I5)
- tx_hash commitment disagreement in signing (I6)
- Receive-time validation failures: wrong Y_assigned, wrong my_Y (I7)

**Adversarial (other):**
- Network partition + CounterProof recovery (including malformed proofs)
- Relay censorship; operator collusion detection
- Conflicting simultaneous intents (ProverReceipt tiebreaking)
- Rotation rule grinding attempts
- Prover equivocation (detection + EquivocationProof)
- Sustained griefing: per-sender score effectiveness, state bounds
- Address fingerprint change: dual confirmation triggers
- Rate limit bypass via multi-indexing (by signing key)
- Unknown spend_auth_version silent skip
- Simple-mode absence in release builds

**Interop:**
- Malicious client produces invariant-violating SignatureShare;
  all conforming clients reject identically
- Cross-platform determinism: same intent → same bytes on Linux, macOS,
  Windows, x86_64, ARM64

**Performance:**
- Scanner cost at 10k+ tx/block with 5%, 10%, 25% multisig adoption
- Griefing score lookup performance
- Prover proof construction time
- Multi-relay overhead

### 16.9 Fuzz targets

```
fuzz_spend_intent_deserialize
fuzz_construction_determinism
fuzz_envelope_parser
fuzz_multisig_address_parse
fuzz_view_tag_hint_check
fuzz_rotating_prover_assignment      (uniformity + grindability)
fuzz_counter_proof_verifier          (strengthened rules)
fuzz_equivocation_proof_verifier
fuzz_invariant_violation_parser
fuzz_spend_auth_pubkey_derivation
fuzz_receive_time_validation
```

### 16.10 Rollout sequencing

| Phase | Duration | Content |
|---|---|---|
| 1 | 4-6 wk | Receiving model (Option C + Solution C), spend-auth derivation, tx_extra tag 0x0A, address format, wallet-side filtering with griefing scores, defense-in-depth wiring |
| 2 | 4-6 wk | Governance protocol, invariants (§2.7), state machine, CounterProof, heartbeat with operator IDs, multi-relay + directory, DKG mandatory enforcement, InvariantViolation message type |
| 3 | 3-4 wk | GUI: fingerprint (3-representation) verification, 1/N acknowledgment gate, prover distribution view, address provenance tracking, relay diversity check, DKG ceremony UI |
| 4 | 3-4 wk | Test matrix, fuzz harness, cross-platform determinism, interop tests across conforming clients |
| 5 | 2-3 wk | External adversarial review (reviewer round 4) |
| 6 | TBD | Cryptographer review of specific targets (see ANALYSIS §7) |

**Total estimate:** 16-23 weeks engineering + cryptographer review.

---

## 17. Appendix A: Canonical Test Vectors

*Normative.* Implementations MUST produce byte-identical output to these
vectors for the input conditions specified. Any implementation that
cannot is non-conforming.

Test vectors are maintained in a separate file `test_vectors/v3.1/`
alongside the implementation. This appendix enumerates required vectors
with their structure; actual bytes will be generated at implementation
time from the reference Rust implementation and cross-verified by at
least two independent implementations before being locked.

### A.1 Required vectors

1. **Group setup vector**
   - Input: fixed 5 hybrid signing keypairs, fixed 5 hybrid KEM keypairs,
     fixed parameters (n=5, m=3, group_version=1, spend_auth_version=1)
   - Output: canonical serialized address, computed group_id, fingerprint
     (hex + word-phrase + structured metadata)

2. **Receive-output vector**
   - Input: fixed recipient address (from A.1), fixed tx_secret_key,
     fixed output_index_in_tx, fixed reference_block_hash, fixed amount
   - Output: full construct_multisig_output result — kem_ciphertexts,
     spend_auth_pubkeys, view_tag_hints, leaf_container bytes,
     output_pubkey O, assigned_prover_index, h_pqc

3. **Spend-intent vector**
   - Input: fixed group state (from A.1), fixed input list, fixed
     recipient list, fixed parameters
   - Output: canonical serialized SpendIntent, intent_hash,
     chain_state_fingerprint

4. **Full-construction vector**
   - Input: fixed spend intent (from A.3), fixed chain reference data
   - Output: canonical transaction bytes (prefix + rct_base +
     rct_prunable_skeleton + pqc_auth_header), signing_payload hash,
     deterministic BP+ bytes

5. **CounterProof vector**
   - Input: fixed consumed inputs, fixed resulting outputs, fixed
     block data
   - Output: canonical CounterProof bytes, verification pass/fail cases
     (including malformed attempts)

6. **Prover-assignment vector**
   - Input: grid of (group_id, output_index_in_tx, tx_secret_key_hash,
     reference_block_hash, n_total)
   - Output: expected prover_index for each combination (uniformity
     verification)

### A.2 Generation and verification protocol

1. Vectors generated by the reference Rust implementation
2. Each vector cross-verified by a second independent implementation
   (e.g., C++ via FFI)
3. Vectors locked in the repository; changes require a spec version bump
4. Client certification: any implementation claiming V3.1 conformance
   MUST pass all vectors in this appendix

---

## 18. Appendix B: Mapping from Original Spec

This document supersedes:

- `PQC_MULTISIG.md` (original; coordinator-based)
- `PQC_MULTISIG_V3_1.md` (governance draft)
- `PQC_MULTISIG_V3_1_RECEIVING.md` (Option C receiving draft)
- `PQC_MULTISIG.md` v1.0 (consolidated draft; superseded by v1.1)

All material from predecessors is consolidated here. Predecessor
documents can be deleted from the repo once this document is merged.
The original `PQC_MULTISIG.md` should be updated to a single-paragraph
deprecation pointer.

For attack analysis, size analysis, and design rationale, see the
companion document `PQC_MULTISIG_V3_1_ANALYSIS.md`.
