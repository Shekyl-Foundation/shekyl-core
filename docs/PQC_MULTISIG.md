# PQC Multisig V3.1: Equal-Participants Multisig with Per-Output Forward Privacy

> **Status:** DRAFT v1.1 — Option E′. Built: the receive path (§7–§8), the intent (§9), the ceremony files (§12) and the signing ceremony (§11, §13). Not built: the multisig builder and the wallet (§16.10)
> **Supersedes:** `PQC_MULTISIG.md` (original), the standalone V3.1 governance and receiving drafts, and v1.0 of this consolidated spec
> **Companion:** `PQC_MULTISIG_V3_1_ANALYSIS.md` (size analysis, attack catalog, cryptographer review targets, design rationale)
> **Consensus impact:** the scheme-2 key blob and its check (CEN-I16, CEN-I18), the leaf key scalar of a scheme-2 spend (CEN-I15), and the `0x0D` clause of CEN-I19 (§7.4–§7.5).

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
11. [Spending: the Signing Ceremony](#11-spending-the-signing-ceremony)
12. [Messages and Transport](#12-messages-and-transport)
13. [Ceremony State and Recovery](#13-ceremony-state-and-recovery)
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
2. **Deterministic construction.** Given a spend intent and a committed
   chain snapshot, every participant builds the same unsigned
   transaction, and signs only the transaction it built itself (§11.2).
   There is no interface latitude.
3. **Per-output forward privacy.** Each output to a multisig group derives
   N fresh ephemeral hybrid keypairs. Two spends from the same group are
   cryptographically indistinguishable from spends by two different groups
   of the same cardinality.
4. **No consensus changes.** Every binding is achievable within existing
   V3 rules. The worst-case failure of a wallet-layer bug is a failed
   broadcast, never a chain split.
5. **Get it right — defer speculative crypto, ship E′.** **In V3.1
   scope:** Option E′ threshold FROST SAL on `y` (`spend_auth_version =
   0x02`; §15.4a). **Out of V3.1 scope:** the full *key* rotation
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
| I3 | The FCMP++ proof, SALs included, verifies against the signer's own transaction | Before the hybrid signature | §11.2 |
| I4 | The range proof verifies against the output commitments of the signer's own transaction | Before the hybrid signature | §11.2 |
| I5 | **RETIRED** (slice 3 PR-C): matched an output key to an assigned prover; E′ has no prover | — | — |
| I6 | **RETIRED** (slice 3 PR-C): compared tx-hash commitments across shares; each signer builds the transaction it signs (§11.2), and the proposer verifies every hybrid signature and runs `verify_multisig` before release | — | — |

**Implementation requirements:**

- Each invariant is the constructor of a type the signing step takes
  (§11.3): no share and no hybrid signature can be produced without the
  check having run and passed.
- On any invariant violation, the wallet refuses, shows its human which
  check failed, and holds nothing. It sends nothing to the group: the
  refusal is the member's, and its human tells the others.
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
| Malicious sender | Constructs outputs to grief recipients | §8.2 multisig check: the output is received but unspendable and named (§7.6); a sender can always burn an output |
| Malicious group member (single) | Tries to spend alone, redirect funds, or DoS | M-of-N threshold; every file is signed by its sender (§12.1); each signer builds what it signs (§11.2); refusal |
| Malicious proposer | Shows signers a transaction or proofs other than the intent's, or different preprocess sets | Each signer builds the transaction from the intent and verifies the proofs against it (I3, I4); different preprocess sets complete no SAL and use each nonce once (§11.4) |
| Malicious cosigner | Sends a bad share, or a per-output key that is not its own | A bad share is named at aggregation; a key is checked against its committed hash on receipt (§11.2) |
| Network observer | Tries to identify groups, link spends | §6 file-based addresses; §7 per-output ephemeral keys; §12 encrypted transport |
| Whoever carries a ceremony file | Reads, drops, reorders, or injects files | §12.1 files are sealed and signed by their sender; §12.5 nothing but the format version is in the clear; a dropped file stalls the session until it is sent again, and the session ends with its reference block (§9.6) |
| Network partition | Causes state divergence | §9.3 chain state fingerprint: a member whose view differs does not sign until it has synced |
| Scanner resource exhaustion | Burns scanner CPU via griefing outputs | §7.6 per-sender griefing scores + hard caps |

### 3.2 Out of scope

| Threat | Reason |
|---|---|
| M-of-N collusion | Defeats any multisig by definition |
| Compromise of group's enduring KEM private keys | Catastrophic by design; mitigated by V3.2 full rotation |
| Quantum break of both ML-KEM and X25519 simultaneously | The hybrid scheme's whole point |
| Loss of more than `n − m` members | The group can no longer reach `m`; inherent to any threshold |
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
| Scheme downgrade (output committed scheme_id=2, spent as scheme_id=1) | §7.5 indirect binding via the leaf commitment opening (`PL-D3`) + `pqc_auth` size check; `expected_scheme_id` for defense in depth (the `expected_group_id` leg is deleted — §5.3) |
| Key substitution within a group | Existing `verify_multisig` Check 8 (key uniqueness) |
| Signer index manipulation | `verify_multisig`: indices in range, ascending, and exactly the key blob's bitmap (§7.5) |
| Key substitution by a signer | `verify_multisig`: each revealed key must hash to the committed `h_i` at its index (§7.5) |
| Blob truncation/padding | Exact-length parses in `MultisigKeyBlob` / `MultisigSigContainer`; CEN-I16's floor and ceiling |
| Replay across groups | **address-fingerprint** binding in the canonical signing intent (I1; §5.3 — replaces the retired `group_id`) |
| Replay within group | The reference block's age (§9.6), the held nonce bound to one intent hash, consensus key images; one live intent per input (§9.2 item 6) |

---

## 4. Roles

The roles for one spend come from its intent (R-5); any member can hold
any of them.

| Role | Does | Who | Adversarial bound |
|---|---|---|---|
| Proposer | Proposes the intent; collects the shares; proves; assembles and releases | The member that writes the `Proposal` | Cannot complete a SAL or a hybrid signature alone; every signer builds and checks what it signs |
| Responder | Approves and signs round 1 in one visit; holds no nonce | `responder_index` | One of the `m`; its share is checked at aggregation |
| Holder | Every other signer; holds a nonce between the rounds | The intent's other signers (none when `m = 2`) | One of the `m`; its share is named at aggregation |

There is no prover role: the proposer proves the FCMP++ membership and
the range, and every signer verifies both against the transaction it
builds itself (§11).

---

## 5. Group Setup

### 5.1 Group parameters

A group is defined by:

- `n_total`: total signers, `2 ≤ n_total ≤ MAX_MULTISIG_PARTICIPANTS`
- `m_required`: threshold, `2 ≤ m_required ≤ n_total`
  (`MIN_MULTISIG_THRESHOLD`, R-11). With `m = 1` the FROST polynomial is a
  constant: every member holds the whole of `y_group`, the PQ leg is 1-of-N
  and the ceremony has no responder — a shared key under a multisig label.
  The address, the dealer split, the on-chain container (CEN-I16/I18) and
  the spend intent each refuse it.
- `group_version`: `0x01` for V3.1 (reserved for future rotation)
- `spend_auth_version`: **`0x02` for Option E′** (product path —
  threshold FROST SAL on `y`; dealer-mode). **`0x01` is never issued.** A later
  mutually-distrusting DKG ceremony mode, if any, gets its own version
  byte — do not overload `0x01`.
- N hybrid signing keypairs (Ed25519 + ML-DSA-65), one per participant
- N hybrid KEM keypairs (X25519 + ML-KEM-768), one per participant

**`MAX_MULTISIG_PARTICIPANTS` (MSW-G) = 5** (decided 2026-07-15
overhaul; withdraws same-day provisional 8).

**Enforced.** `MAX_MULTISIG_PARTICIPANTS = 5` in
`rust/shekyl-crypto-pq/src/multisig.rs`, mirrored in `shekyl-address`
and `shekyl-wire` under compile-time pins. The address, the key
container, the `0x0D` entry and the dealer split each refuse `n > 5`.

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
write participant files (§6.6). **No DKG.** TRaccoon-class papers assume
the same trusted KeyGen. The split is
`shekyl_fcmp::frost_sal::dealer_split`: Shamir over the Ed25519 scalar
field at `x = 1..=n`, verification shares `share_i·T`, `y_group` gone
once the shares exist.

**Mutually-distrusting parties** (buyer/seller/arbitrator) MAY get a
DKG ceremony behind a **later** `spend_auth_version` / ceremony mode —
not `0x02`, and not compiled into the dealer-mode default.

When that mode exists:

- Production wallet builds MUST NOT compile a path that distributes
  the *threshold spend secret* without the ceremony that mode requires.
- A transport-only shared secret (message AEAD), if any, is distinct
  from `y_group` and must not be confused with spend authorization.

### 5.3 Group identity — **the address fingerprint** (`group_id` retired)

The group's identity is the **address fingerprint** (§6.3):
`frame("shekyl/multisig-address-v3", name_id, [canonical(MultisigAddressPayload)])`,
where `name_id` is the network's name binding: a group is derived from
keys and addresses, which exist before any genesis, so it binds the name, not
the genesis-derived id (`NETWORK_IDENTITY.md` NI-R15). It is per-group, computable by every participant from the address alone, and
covers the group's whole public state (`B_group`, `Y_group`, the N KEM pubkeys,
both version axes, `m`/`n`). Four independent implementers exchange the address
file and compare the 67-char fingerprint string: same bytes → same fingerprint,
or the address is wrong.

The former `multisig_group_id` — Keccak-256 over the leaf
`MultisigKeyContainer` — is **deleted**. It had **no consumer** under E′; it
hashed the container's *per-output* KEM-derived keys, so it produced a different
value for every output while being named for the group; and its one long-term
caller (`wallet2::create_pqc_multisig_group`) threw on every input. Deleted with
it: `verify_multisig`'s check 9 + the `expected_group_id` parameter, the FFI
`shekyl_pqc_multisig_group_id` / `shekyl_pqc_verify_with_group_id`, and
`DOMAIN_SEP_V31`. Verify is now a **9-check** pipeline (FFI error code 9 retired,
10/11 unchanged). Version-axis binding survives *in the fingerprint*: the
canonical payload includes `spend_auth_version`, so a version change still yields
a distinct identity.

### 5.4 Setup ceremony (informative summary)

Concrete steps for participants forming a new group:

1. Each participant generates fresh hybrid signing and KEM keypairs.
2. Participants exchange signing public keys and KEM public keys via
   authenticated out-of-band channels (cryptographic verification: each
   participant signs a setup attestation with their hybrid signing key
   over the canonical encoding of all participants' public keys).
3. Each participant independently computes the **address fingerprint**
   (§5.3 / §6.3) and verifies all others derived the same 67-char string.
4. The owner deals the threshold spend secret and writes each member's
   file (§5.2, §6.6).
5. Each participant constructs the full multisig address locally; all
   should produce byte-identical addresses.
6. Address is exported as a file (too large for QR/clipboard at most N
   values).
7. Each participant keeps its member file (§6.6).

---

## 6. Address Format

### 6.1 Bech32m encoding with new HRP

Multisig addresses use a new Bech32m human-readable prefix:

```
single-sig:     shekyl1<classical+tag>/<pqc_a>/<pqc_b>   (full string; POST_QUANTUM_CRYPTOGRAPHY.md §Address Format)
single-sig tn:  tshekyl1<...>/<...>/<...>                (classical HRP `tshekyl`; PQC `tskpq`/`tskpq2`)
multisig:       shekyl1m1<fingerprint 32B>               (names the fingerprint, not the payload; §6.2)
multisig tn:    shekyltest1m1<fingerprint 32B>
```

The single-sig address is a three-segment full string (each segment under
Bech32m's 1023-char bound; the classical segment carries the `ek_bind_tag`).
The multisig payload is far past that bound and is **file-based** — so the
`shekyl1m` HRP encodes the fixed 32-byte **fingerprint** (67 chars, §6.2/§6.3),
never the group payload. The visible `m` suffix prevents wallet confusion.
Wallets MUST type-check the HRP at parse time.

**Reserved:** `shekyl1n...` (rotated-key multisig, V3.2+). Do not issue.

### 6.2 Multisig address payload

```
MultisigAddressPayload {
    version:             u8   (= 0x02)
    group_version:       u8   (= 0x01)
    spend_auth_version:  u8   (= 0x02, Option E′)
    network_byte:        u8
    n_total:             u8   (2..=MAX_MULTISIG_PARTICIPANTS = 5)
    m_required:          u8   (2..=n_total)

    b_group:             [u8; 32]   // B = b·G. Every member holds b.
    y_group:             [u8; 32]   // Y = y·T. y is FROST-shared, M-of-N.

    group_kem_pubkey:    HybridKemPubkey
    // X25519 (32 B) + ML-KEM-768 (1184 B) = 1216 B. Every member holds the
    // secret. A payer's one 0x06 ciphertext per output is to this key.

    hybrid_kem_pubkeys:  [HybridKemPubkey; n_total]
    // Each member's own key, member order (participant index 0..n_total).
    // The per-member 0x0D ciphertexts are to these keys.
}
```

The wire order is the field order. A payer needs `B` and `Y` to build
`O = ho·G + B + (y_group + y_kem)·T`, and both kinds of KEM key to build the
output's `0x06` and `0x0D` fields (§7.1). The points are opaque compressed
Edwards points in the address; the output constructor checks that each is a
prime-order, non-identity point. There is no stored checksum: integrity is
the fingerprint (§6.3). A `version` other than `0x02` is refused.

The X25519 half of every KEM key is one canonical Montgomery u-coordinate:
the integer is strictly less than `2^255 − 19`, so bit 255 is clear.
X25519 ignores that bit and reduces modulo the prime, and the address
compares keys as bytes. A second encoding of the group key would be a
different byte string and the same point, and the group secret would open
that member's slot. `new`, `from_canonical_bytes` and the output
constructor refuse it, and they refuse a key that repeats another.

Canonical payload: `70 + (N + 1) × 1216` bytes
(`HEADER_LEN(6) + 2 × GROUP_POINT_LEN(32) + (1 + N) × 1216`). This is the
fingerprint preimage and the file contents.

**The full address is file-based, not a Bech32m string.** At these sizes it
is far past Bech32m's ~1023-character checksum-validity limit, so the
Bech32m string form (§6.1) encodes the **fingerprint** (32 B → 67 chars),
the short identifier participants compare.

| N | Canonical bytes |
|---|---|
| 2 | 3,718 B |
| 3 | 4,934 B |
| 5 | 7,366 B |

### 6.3 Address handling, fingerprint UX, and provenance

Wallets MUST handle multisig addresses via file export and import:
canonical payload written to a file, transferred via authenticated
channel, imported at recipient end.

**Fingerprint display:** wallets MUST display a 32-byte fingerprint during
send confirmation:

```
address_fingerprint = frame("shekyl/multisig-address-v3", name_id,
                            [canonical(MultisigAddressPayload)])
name_id = cSHAKE256(S = "shekyl/network-name-v1", X = "shekyl/<network>")[..16]
```

`frame` is the signing envelope (`NETWORK_IDENTITY.md` §2.4.2): cSHAKE256
under the domain, over the 16-byte binding then each field behind its u64
little-endian length.

Vectors: `docs/test_vectors/MULTISIG_FINGERPRINT_V3.json`, rebuilt by
`scripts/kat/multisig_fingerprint_oracle.py`.

The address is on **no consensus path** (no C++ mirror, no FFI, no leaf), so
nothing requires byte-identity with the daemon — the only reason the
consensus-parity Keccak-256 primitive (Rust `shekyl_crypto_hash::keccak256`,
C++ `cn_fast_hash`) exists. The address instead has multiple independent
implementers, for whom "Keccak-256" is ambiguous (original `0x01` vs SHA3 `0x06`
padding fail silently); cSHAKE256 has one meaning and its customization string
makes domain separation structural. This fingerprint is also the group's
**identity** — it retires `multisig_group_id` (which has no consumer under E′ and
hashes a per-output container under a per-group name; the code removal is the
cross-language follow-up slice). With `B`/`Y` in the payload it covers the group's
whole public state.

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

### 6.6 The member file

The dealer gives each member one file (`shekyl-multisig::member_file`,
layout version 2). It holds everything that member needs to receive and to
sign:

| Field | Size | What it is |
|---|---|---|
| magic, version | 4 + 1 B | `"SKMF"`, `2` |
| address payload | `u32_le` length + §6.2 payload | the group's public state and identity |
| `member_index` | 1 B | `0..n` |
| `b` | 32 B | the group-plaintext spend scalar |
| `y_share` | 32 B | this member's share of `y_group` |
| verification shares | `n × 32` B | every member's, member order |
| group KEM secret | 2432 B | X25519 (32) ‖ ML-KEM-768 decapsulation key (2400) |
| member KEM secret | 2432 B | this member's own, same layout |
| transport secret | 32 B | keys the ceremony files (§12) |
| envelope secret | 64 B | this member's long-term envelope key: Ed25519 seed ‖ ML-DSA-65 seed (R-6) |
| envelope public keys | `n × 1996` B | every member's, member order |

`y_share` is the Shamir share at FROST participant `member_index + 1`.
`shekyl_fcmp::frost_sal::threshold_keys` loads it, with the verification
shares and the address's `Y_group`, into the member's
`ThresholdKeys<Ed25519T>`, and refuses a file whose shares would not sign:
a non-canonical share, a verification share that is not a prime-order
point, a share that is not its own verification share's discrete log,
shares that do not open `Y_group`, and a share off the group's
polynomial. Each refusal is its own `FrostKeyError` variant.

The **transport secret** is
`shekyl_crypto_pq::derivation::derive_group_transport_secret`: HKDF-SHA-512
with salt `salt_for(network)` (the network's `name_id`, then
`shekyl-master-derive-v3`), input keying material the dealer's 32-byte group
seed, and info `shekyl/multisig-transport-v1`. The dealer derives it once
and writes the same value into every member file. The file stores the bytes;
it does not derive them.

The **envelope keys** are minted by the dealer, one keypair per member from
fresh randomness (`shekyl_crypto_pq::multisig_envelope::mint_multisig_envelope_keypair`).
They derive from no spend secret and sign nothing but ceremony files: a
member signs every file it sends with its secret, and every other member
checks it under the public key at the sender's index (§12.1). The file
refuses a list of the wrong length, a malformed key, two equal keys (a
file could not then say which of them sent it), and an envelope secret
that is not behind the member's own slot. A version-1 file, which had no
envelope keys, is refused.

This is the plaintext serialization. Keeping the file encrypted at rest is
the wallet's job, as for every other key file. Every secret is wiped on
drop, and the type's `Debug` prints none of them.

---

## 7. Receiving Outputs

### 7.1 Output construction

A multisig output is a solo output to the group, plus one entry per member.
The constructor is `shekyl-crypto-pq::multisig_output::construct_multisig_output`.

```python
def construct_multisig_output(tx_key_secret, address, amount, output_index, network_id):
    assert output_index <= 255            # the 0x0D entry names it in one byte

    # The solo part: the solo output core, to the group.
    spend_key = address.b_group + address.y_group           # checked prime-order, non-identity
    ct_group, ss_group = encapsulate(tx_key_secret, address.group_kem_pubkey, output_index)
    ho, y_kem, z, k_amount, k_label = derive_output_secrets(ss_group, output_index)
    O = ho·G + spend_key + y_kem·T       # = ho·G + B + (y_group + y_kem)·T
    C = z·G + amount·H
    enc_amount, enc_label = encrypt(k_amount, amount), encrypt(k_label, SENTINEL)

    # The per-member part.
    cts, hashes = [], []
    for i in range(address.n_total):
        ct_i, ss_i = encapsulate(tx_key_secret, address.hybrid_kem_pubkeys[i], output_index)
        pk_i = member_keypair(ss_i).public                   # §7.2
        hashes.append(frame32("shekyl/multisig-key-hash-v1", network_id, [pk_i]))
        cts.append(ct_i)
        # ss_i and the keypair are wiped here.

    committed = 0x02 ‖ n ‖ m ‖ hashes[0] ‖ … ‖ hashes[n-1]  # 3 + 32·n bytes

    # The leaf commits to the committed form, blinded from the group secret.
    (CM, record) = pqc_leaf_commitment(ss_group, output_index, committed)

    # The hashes travel encrypted under the group secret.
    key = derive_multisig_key_hashes_key(ss_group, output_index)
    enc_hashes = ChaCha20Poly1305(key).encrypt(nonce = 0^12,
                                               msg = hashes[0] ‖ … ‖ hashes[n-1],
                                               aad = u8(output_index) ‖ u8(n))

    return O, C, enc_amount, enc_label, ct_group,     # the solo fields; ct_group is the 0x06 entry
           (CM, record),                              # the 0x07 entry
           (output_index, n, cts, enc_hashes)         # the 0x0D entry
```

The solo constructor's per-output PQC key is never made for a multisig
output. Every member holds the group secret and could derive it, so a leaf
over it would let any one member satisfy the PQ leg alone.

**Why the hashes are encrypted.** A spend reveals the committed form
(§7.5). In the clear at receive time, the hashes would match it and link
the spend to its output.

**Why the hash key needs no nonce.** The key is derived per output from a
fresh KEM secret and the output index, and encrypts one plaintext.

### 7.2 Derivations

| Value | From | Label or domain |
|---|---|---|
| `ho`, `y_kem`, `z`, `k_amount`, `k_label`, leaf blinds | the group secret `ss_group` | the solo `shekyl-output-*` labels, unchanged |
| hash AEAD key | `ss_group` | `shekyl-output-multisig-key-hashes` (same PRK as the solo labels) |
| member `i`'s per-output signing keypair | member `i`'s secret `ss_i` | `HKDF-SHA-512(ikm = ss_i).expand("shekyl-v31-hybrid-sign", 64)`: bytes `0..32` seed Ed25519, `32..64` seed ML-DSA-65 |
| `h_i` | `pk_i` | `frame(shekyl/multisig-key-hash-v1, network_id, [pk_i])`, 32 B |

`h_i` binds the chain's network id because consensus compares it at every
spend (§7.5). Every label is registered in `CRYPTO_DOMAIN_REGISTRY.tsv`.

### 7.3 Deterministic encapsulation

Every encapsulation in a multisig output, the group's and each member's,
uses the solo deterministic encapsulation. Its per-recipient seed is
`derive_kem_seed(tx_key_secret, recipient_x25519, recipient_ml_kem, output_index)`,
which binds the recipient's two public keys. So two recipients of one
output never share encapsulation randomness: one member decapsulating its
own ciphertext learns nothing about another member's.

`tx_secret_key` MUST be freshly generated per transaction.

### 7.4 tx_extra

Per transaction:

| Tag | Name | Payload |
|---|---|---|
| 0x06 | `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` | exactly one field, `1120 × n_outputs` B: a multisig output's entry is its group ciphertext, the same shape as a solo output's |
| 0x07 | `TX_EXTRA_TAG_PQC_LEAF_ENTRIES` | exactly one field, `64 × n_outputs` B: a multisig output's entry is `CM ‖ record` over the committed form |
| **0x0D** | `TX_EXTRA_TAG_PQC_MULTISIG` | at most one field: one entry per multisig output, strictly ascending by output index |

A `0x0D` entry is

```
out_idx(1) ‖ n(1) ‖ ct_1 … ct_n (1120 B each) ‖ enc(h_1 … h_n) (32·n B) ‖ tag (16 B)
```

`2 + 1152·n + 16` bytes. It carries `n` so the field parses without the
address. CEN-I19's multisig clause (`check_pqc_multisig_shape`) refuses a
second `0x0D` field, an empty one, entries out of order or repeated, and an
entry naming an output the transaction does not have. The parser refuses
`n` outside `1..=5` and a short or long entry. A coinbase's closed grammar
does not admit `0x0D`, so a coinbase cannot pay a group.

**Cost per multisig output**, across the three fields:
`1120 + 64 + 2 + 1152·n + 16` bytes, about **4.7 KB at n = 3** and **7.0 KB at
n = 5**. The `n` per-member ciphertexts are what keep the PQ leg M-of-N; a
key every member could derive would make it 1-of-N. Under the 24,576-byte
relay cap on `extra` (CEN-M4), one transaction carries at most **five**
multisig outputs to a 3-member group, or **three** to a 5-member group,
beside a change output.

**Privacy.** A `0x0D` field says that a transaction pays a multisig group,
and each entry gives the group's size. That is inherent to Option E′. The
entries carry nothing linkable to the group across transactions: the
ciphertexts are fresh per output and the hashes are encrypted.

**Retired and reserved tags** (never reused; each parses as unknown):

| Tag | Disposition |
|---|---|
| 0x05 | Retired. A per-output `(scheme_id, group_id)` entry with no producer and no reader. |
| 0x08 | RESERVED for the group-rotation / migration transaction; producer undesigned (rule 23). |
| 0x09 | Retired. Per-member view-tag hints, never produced; `0x0D` replaced it. |
| 0x0A | Retired. Per-member spend-auth pubkeys, never produced; `0x0D` replaced it. |

### 7.5 Spend-time consensus binding

The key blob a multisig spend reveals in `pqc_auths[i].hybrid_public_key`
(scheme 2) is

```
committed form (0x02 ‖ n ‖ m ‖ h_1 … h_n) ‖ signer_bitmap(1) ‖ pk_{i_1} ‖ … ‖ pk_{i_m}
```

`3 + 32·n + 1 + 1996·m` bytes; the bitmap has exactly `m` bits set, none at
or above `n`, and the keys follow in ascending member order. The signature
blob is `sig_count ‖ m × HybridSignature ‖ m × index`, its indices exactly
the bitmap's set bits.

1. The leaf's 4th scalar is `CM.x` with `CM = k·G_k + r·J`,
   `k = H_ℓ(committed form)` (`PL-D3`).
2. Both consensus verifiers derive `k` from **the committed form only**
   (`pqc_leaf_key_bytes`, `PqcKeyScalar::from_pqc_auth`), and the FCMP++
   proof opens the spent leaf to `K = k·G_k`. A blob whose committed form is
   not the output's does not open.
3. `verify_multisig` (CEN-I18) parses both blobs, checks `m` signatures and
   that their indices are the bitmap's, checks each revealed `pk_i` against
   `h_i` under this network's id, refuses duplicate keys, then verifies each
   signature under `shekyl/pqc-auth-tx-multisig-v1`.

So `m` signers spend without the other `n − m`: they reveal only their own
keys, and every member can read every `h_j` from the `0x0D` entry. A
non-signer's key never reaches the chain. CEN-I16's structural floor for a
scheme-2 key blob is `MULTISIG_KEY_BLOB_MIN = 4060` bytes (a 2-of-2
revealing both keys; R-11 refuses a smaller group).

### 7.6 Outputs a group cannot spend

A sender can always make an output unspendable. Under E′ that shows up as
an output the group owns (its view pair matches and the amount opens) whose
`0x0D` entry is missing or wrong, or whose leaf does not commit to the
entry's hashes. The scanner keeps such an output, names its transaction,
and marks it received-but-unspendable, naming the check that failed
(`UnspendableReason::MultisigEntryAbsent` when the `0x0D` entry is
missing, and one variant per refusal of `open_multisig_entry`; §8.2).
It is never offered to coin selection.

### 7.7 Wallet send-side requirements

When sending to a multisig recipient, the sender's wallet MUST:

1. Display the address fingerprint (§6.3) and require user confirmation
2. Refuse an address whose version is not `0x02`, whose `spend_auth_version`
   it does not implement, whose `n_total > MAX_MULTISIG_PARTICIPANTS` or
   `m_required > n_total`, or whose points or KEM keys do not parse
3. Build the output with `construct_multisig_output` (§7.1) and write its
   `0x06`, `0x07` and `0x0D` parts into the transaction's single fields
4. Surface the per-output size (§7.4)

---

## 8. Wallet Scanning and Receive-Time Validation

### 8.1 Scanning as the group

Every member scans with the **solo scanner**, as the group: its view pair is
the group KEM secret with spend point `B_group + Y_group`, and its spend
secret is `b`. An output paid to the group is found exactly as a solo
wallet finds its own: the `0x06` ciphertext decapsulates, the view tag
matches, `recover_recipient_spend_pubkey` returns `B_group + Y_group`, the
amount opens, and the key image is `compute_output_key_image` with `b`. So
balance and spent-detection are local: no member needs another to see what
the group holds.

### 8.2 The multisig check

For each output the group's view pair matches, the member then runs
`open_multisig_entry` in place of the solo leaf comparison
(`shekyl-scanner`, `MultisigMemberScan`):

1. Find the `0x0D` entry for the output's index. A missing entry is
   `UnspendableReason::MultisigEntryAbsent`.
2. Check its `n` is the group's (`MultisigGroupSize`). Decrypt the hashes
   under the output's group secret (AEAD-authenticated, with `out_idx ‖ n`
   as associated data; `MultisigHashesUndecryptable`).
3. Refuse a repeated decrypted hash (`MultisigDuplicateKeyHash`). Every
   member sees the whole list, and `verify_multisig` would refuse the same
   bytes as duplicate keys.
4. Decapsulate `ct_i` with the member's own KEM secret
   (`MultisigMemberDecap`), derive `pk_i`, and check `h_i` against it
   (`MultisigMemberKeyHash`). A sender lying about *this* member is caught
   here.
5. Rebuild the committed form from the `n` hashes and the group's `m`, and
   check that the published `0x07` entry is its leaf commitment
   (`MultisigLeafMismatch`). A sender lying about *any other* member, while
   leaving the leaf over the honest list, is caught here. A sender who
   keeps every `ss_i`, replaces another member's hash, and recomputes the
   leaf is not caught by this member: that member does not hold the other
   member's KEM secret. The cosigners refuse that committed form before
   they sign (§11.2).

A missing `0x07` entry stays `PqcLeafEntryAbsent`. The solo leaf comparison
never runs for a group output: its leaf never commits to the solo
per-output key.

### 8.3 Versions

A wallet refuses an address whose version is not `0x02` (§6.2). A spend's
key blob with a container version other than `0x02` is refused by
consensus (`PqcVerifyError::ContainerVersion`); `0x01` was never issued.

### 8.4 Persistence

A group output is persisted as a solo output is. Nothing multisig-specific
is stored at receive time: at spend time each signer re-derives its `pk_i`
by decapsulating `ct_i` again, and the committed form is rebuilt from the
transaction's `0x0D` entry, as the solo spend path re-derives its secrets
from chain data. Restoring a member from its member file and rescanning
reproduces everything.

### 8.5 Cost

An output that is not the group's costs exactly a solo scan. An output that
is costs one more decapsulation, one ML-DSA-65 key generation, one AEAD
open and one leaf commitment.

---

## 9. Spend Intent

### 9.1 Schema

```
SpendIntent {
    version:                  u8 (= 2)
    intent_id:                [u8; 32]   // random per intent

    // Group binding — the address fingerprint (§5.3)
    address_fingerprint:      [u8; 32]

    // Who signs (R-5)
    proposer_index:           u8
    signers:                  [u8]       // exactly m, strictly ascending, the proposer among them
    responder_index:          u8         // one of signers, not the proposer

    // Display and chain binding
    created_at:               u64        // unix seconds; display only (R-13)
    reference_block_height:   u64
    reference_block_hash:     [u8; 32]

    // Content
    recipients: [
        { address: bytes, amount: u64 }
    ]   // sorted
    fee:                      u64
    input_global_indices:     [u64]

    // Determinism anchor (R-7, §9.5)
    kem_randomness_seed:      [u8; 32]   // 32 fresh random bytes

    // Chain state fingerprint
    chain_state_fingerprint:  [u8; 32]   // see §9.3
}
```

The byte layout is `SHEKYL_MULTISIG_WIRE_FORMAT.md` §2.2. The intent has
no signature field: a `Proposal` file carries it, and that file's sender
signature, under the proposer's envelope key (§12.1), is the proposal's.
Its `sender_index` must equal `proposer_index`.

### 9.2 Invariants (verified before any signer signs; honest-signer invariant I1)

1. `version == 2`
2. `address_fingerprint` matches the verifier's group (§5.3)
3. `2 ≤ m ≤ n` (R-11); `proposer_index < n_total`
4. `signers` holds exactly `m` indices, strictly ascending, each `< n`,
   the proposer among them; `responder_index` is a signer and not the
   proposer
5. The `Proposal` file that carried the intent verified under
   `envelope_public_keys[proposer_index]` (§12.1)
6. None of `input_global_indices` is spent by another of this member's
   live ceremonies: a member commits to at most one live intent per
   input, and refuses to commit to any other (the ceremony's
   `LiveCeremonies`, §11.2)
7. A spend anchored at `reference_block_height` can still be listed: its
   age measured from the connecting height is in
   `[FCMP_REFERENCE_BLOCK_MIN_AGE, FCMP_REFERENCE_BLOCK_MAX_AGE]` (CEN-I11;
   `shekyl_curve_tree::reference`). This is the intent's only deadline
   (R-13, §9.6)
8. `reference_block_hash` matches the chain's block at
   `reference_block_height` per the verifier's local view
9. All `input_global_indices` are owned by the group, unspent, and in the
   tree at the reference height; `1 ≤ count ≤ MAX_INPUTS`
10. Recipients are sorted; no duplicate (address, amount) tuples; at most
    `MAX_RECIPIENTS`
11. `sum(recipient.amount) + fee == sum(input.amount)` per local view
12. `kem_randomness_seed` is unique within the group's history of
    `seen_intents` (replay/linkability prevention)
13. `chain_state_fingerprint` matches the verifier's local fingerprint
    (see §9.3); mismatch → do not sign; trigger sync

No invariant reads a clock.

**Replay.** There is no group counter. Three things stop an intent, or a
signature over it, being used twice: the reference block's age ends every
intent (§9.6); a member's held FROST nonce is bound to one intent hash and
consumed once; and consensus refuses a second spend of a key image. Item 6
keeps a member from committing to two live intents that spend one input.

### 9.3 Chain state fingerprint (honest-signer invariant I2)

Members must agree on chain state before signing. Each intent commits to:

```
chain_state_fingerprint = keccak256(
    reference_block_hash ||
    sorted_concat(input_global_indices) ||
    sorted_concat(input_eligible_heights) ||
    sorted_concat(input_amounts)
)
```

Where `keccak256` — here and in every live hash definition below — is
**original-padding Keccak-256** (`0x01` padding, NOT FIPS-202 SHA3-256's
`0x06`), implemented as `shekyl_crypto_hash::keccak256`.

The proposer computes this. Each verifier independently recomputes from
their local view. Mismatch indicates state divergence or manipulation:
do not sign; trigger sync.

### 9.4 Intent hash

```
intent_hash = keccak256(canonical_serialize(SpendIntent))
```

`intent_hash` is the durable identifier. Every ceremony file carries it,
and because the signer set and the responder are in the canonical bytes,
every file binds them.

### 9.5 The intent is the only trusted input (R-7)

A signer trusts the intent and nothing else. It rebuilds every signing
input from the intent itself — the outputs, their commitments, the
pseudo-outs, each input's rerandomization, the transaction prefix and
base — and a file that disagrees with its rebuild is refused. Nothing a
member sends after the `Proposal` can change what a signer signs.

`kem_randomness_seed` is the root of every value the transaction needs
that solo would draw at random. One HKDF label per derived value; this
table is what the ceremony and the builder both read:

| Value | Label | Indexed by |
|---|---|---|
| The transaction key: it seeds every output's KEM encapsulation, and so every output key and every output commitment mask, under the solo labels (`shekyl-output-kem-v1`, `shekyl-output-mask`, …) | `shekyl/multisig-intent-tx-key-v1` | — |
| Each input's pseudo-out blind `a_j`, but the last, which balances the commitments as solo does | `shekyl/multisig-intent-pseudo-out-blind-v1` | input position |
| Each input's rerandomization (`RerandomizedOutput`'s blinds) | `shekyl/multisig-intent-rerandomize-v1` | input position |

The three labels are RESERVED: no code derives under them yet. The
derivation lands with the multisig builder (slice 4a), and each label is
registered in `CRYPTO_DOMAIN_REGISTRY.tsv` with the code that uses it.

### 9.6 The session clock (R-13)

The intent expires when its reference block does: the last block that can
list the spend is `reference_block_height + FCMP_REFERENCE_BLOCK_MAX_AGE`,
measured as consensus measures it (§9.2 item 7). A wallet anchors a new
spend `REF_ANCHOR_AGE` blocks below the tip, so a signing session has
`PROOF_VALIDITY_HORIZON` blocks — about three hours at the target block
time. There is no wall-clock expiry: devices in one session do not agree
to the second, and a device kept in a safe may have a wrong clock.

An offline signer has no chain view and cannot check the deadline. That
is acceptable: signing a stale intent produces a transaction no block can
list, not a loss.

---

## 10. Canonical Construction

### 10.1 Algorithm

Given verified `SpendIntent`, every member runs:

1. **Pre-flight verification** (§9.2 invariants). On any failure,
   refuse (§2.7); do not proceed.
2. **Output derivation** (§7.1). For each recipient (including change
   output, if any), derive the output key, the KEM ciphertexts and the
   leaf commitment.
3. **Transaction prefix construction.** Inputs reference each input's
   key image, which every member computes alone (§15.4a); outputs are
   derived per step 2; `tx_extra` carries each multisig output's `0x0D`
   entry (§7.4).
4. **CT base.** Type = `CTTypeFcmpPlusPlusPqc (= 1)`; ecdh info,
   commitment masks, pseudo outputs all deterministic from intent.
5. **Compute `signing_payload`** (§10.4).

### 10.2 Bulletproof+ range proofs

The proposer proves the outputs' range (§11.1, step 7). Each signer
verifies the proof against the output commitments its own construction
yields (I4, §11.2) before it signs; the proof's randomness is the
proposer's, and no other member needs to reproduce it.

### 10.3 Change output handling

When the group sends to itself (a change output):

- The change recipient is the group's own multisig address
- The Option C + Solution C construction (§7.1) applies identically
- N KEM encapsulations to the group's own KEM pubkeys
- N fresh per-output member keys derived (§7.2)
- Leaf commitment over the output's committed form (§7.5)

**There is no single-sig change escape hatch.** Change outputs are full
multisig-bound outputs requiring `scheme_id=2` authorization to spend,
identical to any other multisig output.

### 10.4 Canonical signing payload

Each input's hybrid signatures sign `signed_hash(i)` (CEN-I17,
`design/FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1): the transaction's prefix and
base (`tx_signable`), the hash of its prunable part (the FCMP++ proof,
the range proof and the pseudo-outs), that input's PQC header, and the
hash of every input's key blob. The hybrid signatures therefore come
last, over the finished proofs (§11).

---

## 11. Spending: the Signing Ceremony

A spend is one FROST signature per input over the group's `y` (the SAL,
inside the FCMP++ proof) and `m` hybrid `scheme_id = 2` signatures per
input. The hybrid signatures come last: each signs `signed_hash(i)`
(§10.4), which covers the finished proofs. The ceremony is
`shekyl-multisig`'s `ceremony` module. It consumes bytes and returns
bytes, and never reads a clock, a disk or a network.

### 11.1 Roles and files

The roles for one intent come from the intent (R-5): the proposer **A**
(`proposer_index`), the responder **B** (`responder_index`), and the
holders **H**, every other signer (none when `m = 2`).

| Step | File (type) | From → to | Body | Nonce |
|---|---|---|---|---|
| 1 | `Proposal` 0x0C | A → each H (`m ≥ 3`); A → B (`m = 2`) | the intent; per input, A's preprocess and per-output public key | A holds |
| 2 | `Commitment` 0x0D | H → A | per input, H's preprocess and per-output public key | H holds |
| 3 | `SigningSet` 0x0E | A → B (`m ≥ 3`) | the `Proposal` file and every `Commitment` file, sealed as received | |
| 4 | `ResponderShare` 0x0F | B → A | per input, B's preprocess, share and per-output public key | B preprocesses and signs in one call |
| 5 | `SigningSet` 0x0E | A → each H | the `Proposal`, every `Commitment` and B's `ResponderShare`, sealed as received | |
| 6 | `SignatureShare` 0x03 | H → A | per input, H's share | H consumes |
| 7 | — | A | A's shares; one SAL per input; the FCMP++ proof, SALs inside; the range proof | A consumes |
| 8 | `FinalTx` 0x10 | A → B and each H | the `Proposal` file; per input, every signer's per-output public key; the FCMP++ proof; the range proof | |
| 9 | `HybridSig` 0x11 | B, H → A | per input, the hybrid signature | |
| 10 | — | A | A's hybrid signatures; every signature verified; `verify_multisig` on every input; release | |

`m = 2` is files 1, 4, 8 and 9. Each holder adds four files and two
visits; the responder's count is the same at any `m`. Every per-input
list is in the intent's input order and has the intent's input count.
The body layouts are `SHEKYL_MULTISIG_WIRE_FORMAT.md` §3.1.

**Why every signer's keys travel in round 1.** `signed_hash(i)` covers
the hash of every input's key blob (CEN-I17), and a scheme-2 key blob
carries the `m` signers' per-output keys (§7.5). A member's per-output
key derives from its own KEM secret, so no signer can compute what it
signs until every signer's keys are known. Each signer sends its keys
with its preprocess, and the receiver checks each against `h_i` at that
signer's index in the input's committed form. The keys are on chain at
spend anyway.

**Why files are forwarded sealed.** The responder sees the whole
preprocess set and the intent in one visit. A forwards the original
sealed files, and B opens each under its own sender's envelope signature
(§12.1), so no preprocess rests on A's word.

**Why `FinalTx` carries the `Proposal` and the keys.** The responder's
second visit is a check its wallet does, not a second decision. A member
that kept nothing since round 1 (restarted, restored, or another device)
rebuilds its context from the `Proposal` and checks the keys against its
own ledger's committed forms: the second round is stateless.

### 11.2 What each member checks

- **Opening any file.** `import` runs the envelope checks (§12.1),
  parses the body exactly, and yields the body with its sender. A step
  takes only the body type it expects, from the role that sends it. A
  file of another intent is refused by its intent hash, and a file a
  step already took is a duplicate: this is what replaced the message
  counter (R-12).
- **On `Proposal`** (H, and B when `m = 2`): the intent validates
  against the member's own ledger (I1, I2); the member is a signer; the
  sender is the proposer; none of the intent's inputs is in another of
  the member's live ceremonies (§9.2 item 6); the caller supplies the
  member's context, built from the intent (§11.5). A refusal is shown to
  the member's human here, and nothing is held.
- **On a forwarded file in a `SigningSet`**: opened as above, under its
  own sender, for the same intent. A set holds exactly one file per
  signer other than the member it is for, and each key in it matches its
  `h_i`.
- **Before any share** (B at step 4, H at 6, A at 7): the preprocess set
  is exactly the intent's signers but this member, each from a file its
  sender signed, and a held nonce rebuilds the preprocess its member
  sent.
- **On `FinalTx`** (B, H): the member builds the transaction itself:
  the prefix and base from its context, `pqc_auths` with `scheme_id = 2`
  and each input's key blob from its own ledger's committed form and the
  `m` checked keys, and the prunable part from the two proofs. The
  membership proof, SALs included, verifies against the member's own
  rerandomized inputs, `tx_signable` and reference root (I3); the range
  proof verifies against the output commitments of the member's own base
  (I4). The SALs bind `tx_signable` and each input's rerandomized tuple,
  not the range proof or the tree depth: the member verifies the one and
  sets the other, and its hybrid signature then covers the whole
  prunable part. Only that transaction is signed.
- **On `HybridSig`** (A): each signature verifies under that signer's
  key from round 1 over `signed_hash(i)`; then `verify_multisig` runs on
  every input before the transaction is released.

### 11.3 The guards are types

Each check of §11.2 runs once, in the only constructor of a type, and
the step that needs the check takes that type. The code that signs
cannot be reached with an unchecked value.

| Rule | Type that holds it |
|---|---|
| A file is from the member it names | `Authenticated<B>` per body type, made only by `import` |
| The intent is valid for this member | `ValidatedIntent`, made only by I1 and I2 against the member's ledger; `SigningContext` takes it |
| A per-output key matches its committed hash | `CommittedMemberKey`; a key blob is assembled only from checked keys |
| The preprocess set is exactly the other signers | `PreprocessSet`; signing takes one, never a map |
| A held nonce is used once, after the durable persist | `HeldNonce` (not `Clone`, wiped on drop) is moved out of the store; `ConsumedNonce` exists only after `NonceCounterSink` returns `Ok`; signing consumes it |
| A held nonce is used only with the parameters it was made for | `HeldSession` owns its parameters and keys; `resume(self)` uses them, and no function pairs a seed with parameters given separately |
| The responder never holds a nonce | `Responder::respond` takes no nonce store; it preprocesses and signs inside one call |
| A file is refused out of phase | per-role typestates (`Proposer<Collecting>`, `<SharesPending>`, `<AwaitingSignatures>`; `Holder<Committed>`), each with only its legal transitions |
| Every byte a hybrid signature covers was built or verified by the signer | `VerifiedMembershipProof`, `VerifiedRangeProof`; `SignableTransaction`, made only by assembling the member's context, the two verified proofs and the checked keys, is all the member signer signs |

`compile_fail` doctests pin the transitions that must not exist
(`ceremony::nonce`, `ceremony::roles`, `ceremony::proofs`).

What types cannot do: a disk restored from a backup can hand a consumed
`HeldNonce` back. The store's contract covers it: held nonces are
excluded from backups, a restore cancels every open ceremony, and `take`
deletes durably before it returns (the wallet's store, slice 4a).

### 11.4 Nonces

- **The proposer and holders hold.** Round 1's state for one input is a
  `HeldSession`: the cached preprocess together with the
  `SalSigningParams` and keys it was made under. A member's sessions for
  one intent are one `HeldNonce`, put into the `HeldNonceStore` the
  caller injects (the wallet keeps it in the same protected container as
  the member's `y_group` share), keyed by intent hash. The ceremony keeps
  no copy.
- **Used once.** To sign, the ceremony takes the nonce out of the store,
  then durably records its use (`NonceCounterSink`, the member's
  monotonic nonce counter), and only then holds a `ConsumedNonce`. One
  persist covers every input of the intent. If the persist fails, the
  nonce is dropped and the ceremony is forfeit: a new intent is needed.
- **Bound to its parameters.** `from_cache` cannot fail and ignores its
  parameters: the nonces are a hash of the 32-byte seed and the member's
  share, and every SAL commitment is on `T`, so `modular_frost` gives no
  protection of its own. A held session therefore owns its parameters
  and resumes only with them. Every signer builds the same parameters
  independently, from the input's rerandomization seed and pseudo-out
  blind (§9.5), and a preprocess rebuilt from a held session is checked
  against the one its member sent.
- **The responder never holds.** It preprocesses and signs in one call,
  and the machine is dropped.
- **Equivocation buys nothing.** If A shows different preprocess sets to
  different signers, the binding factors differ, the shares do not
  aggregate, and each held nonce has been used once. A bad share is
  named by its signer when A aggregates; blame is advisory.

### 11.5 What a member brings

- **`SigningContext`**, built by the caller from the validated intent
  and the member's own ledger: the network id; per input the spent
  output (`O`, `C`, `x`, `y_kem`, `z`), its pseudo-out blind and
  rerandomization seed (§9.5), its key image, its committed form and the
  member's own `0x0D` ciphertexts; the unsigned spend (prefix, fee,
  reference block, base), from which `tx_signable` is derived; the
  reference root and tree depth; and the member file, from which the
  member's threshold keys load. Its constructor checks that the member
  signs the intent, that the inputs are the intent's and the prefix
  spends them in order, that the fee is the intent's, that each
  committed form is for this group, and that the member's keys open
  every input.
- **`ProposerInputs`**, A only: each output's amount and mask (for the
  range proof) and each input's leaf chunk and branch (for the
  membership proof).
- **`HeldNonceStore`**, **`NonceCounterSink`** and **`LiveCeremonies`**:
  the durable writes the ceremony needs but does not own.

The unsigned spend's derivation from the intent, and the size of a
scheme-2 fee, are the multisig builder's (slice 4a).

### 11.6 Rate limiting (by signing pubkey, not index)

To prevent intent-spam DoS:

- Each proposer's **hybrid signing public key** (not proposer_index) may
  have at most 1 live intent per group at a time (§13.1)
- Rate limit is group-wide configurable at setup (default: 1 live
  intent per signing pubkey; maximum 1 new proposal per 5 minutes per
  signing pubkey)
- Keying off signing pubkey prevents a malicious member with multiple
  proposer_index slots from multi-indexing their way around the limit
- New proposals from the same signing pubkey violating the limit are
  refused

This bounds verification work to ≤ N concurrent intents.

---

## 12. Messages and Transport

### 12.1 The ceremony file

Members exchange **files** (R-9). One file is one message from one member:

```
file      = format_version(1) ‖ nonce(24) ‖ XChaCha20-Poly1305(ciphertext) ‖ tag(16)
plaintext = address_fingerprint(32) ‖ intent_hash(32) ‖ sender_index(1) ‖ message_type(1)
            ‖ u32_le(body_len) ‖ body ‖ u32_le(sig_len) ‖ sender_sig
```

Only the format version is in the clear (R-10). The sender signs every
plaintext field but the signature with its envelope key (§6.6), framed
with the network id under `shekyl/multisig-envelope-v1` and signed under
`shekyl/multisig-envelope-scheme-v1` (R-6). A member who holds the
transport secret can write a file that opens for the group, but not one
that verifies as another member's.

A wallet imports a file by **trial decryption**: it tries each of its
groups' keys, and a file that opens under none is not for it. A file that
opens is checked in order — exact parse, the fingerprint is that group's,
the sender index names a member, the signature verifies under that
member's envelope key, the message type is live — and its body reaches
nothing before every check has passed. The byte layout, the bounds and
the check order are `SHEKYL_MULTISIG_WIRE_FORMAT.md` §1.

### 12.2 Message types (encrypted)

| Type | Name | Purpose |
|---|---|---|
| 0x03 | SignatureShare | Per input, a holder's FROST share |
| 0x0C | Proposal | The intent; per input, the proposer's preprocess and per-output key |
| 0x0D | Commitment | Per input, a holder's preprocess and per-output key |
| 0x0E | SigningSet | Other members' files, forwarded sealed as received |
| 0x0F | ResponderShare | Per input, the responder's preprocess, share and per-output key |
| 0x10 | FinalTx | The `Proposal` file; per input, every signer's per-output key; the FCMP++ proof; the range proof |
| 0x11 | HybridSig | Per input, the signer's hybrid signature |

`0x01`, `0x02`, `0x04`–`0x0B` are REJECTED and never reused
(`SHEKYL_MULTISIG_WIRE_FORMAT.md` §3). A member that refuses an intent
sends nothing (§2.7). Each body's layout is
`SHEKYL_MULTISIG_WIRE_FORMAT.md` §3.1, and its step is §11.1.

### 12.3 Encryption

```
key  = HKDF-SHA-512(ikm = transport_secret, info = "shekyl/multisig-blob-key-v1", 32)
aad  = format_version
file = format_version ‖ nonce(24, random) ‖ XChaCha20-Poly1305(key, nonce, aad, plaintext) ‖ tag(16)
```

`transport_secret` is the group transport secret every member file holds
(§6.6). One key per group. The nonce is drawn at random for every file: a
nonce derived from persisted state would repeat after a wallet is
restored from a backup, and a repeated nonce under this AEAD leaks the
XOR of two plaintexts and the Poly1305 key. Replays and ordering are the
ceremony's phase checks (§11.2), not a counter (R-12).

### 12.4 Transport: files only (R-9)

The wallet moves no bytes. A member writes a ceremony file and passes it
to the others by whatever means the group uses — email, a messenger, a
USB stick, a shared folder. There are no relays, no relay directory and
no heartbeat; a group agrees a time, passes files, and a device kept in
a safe comes out once per session (`MULTISIG_OPERATIONS.md`).

An online mailbox is **DEFERRED** (rule 23): `docs/FOLLOWUPS.md`
"Multisig: an online mailbox for ceremony files". It reopens only if
file-based sessions are shown to be what stops groups from spending, and
then starts from an outbound-only mailbox over Tor with a per-intent
drop-box address.

### 12.5 What a file reveals

Nothing is in the clear but the format version. A file shows its size and
that it is a Shekyl multisig file; which group, which intent, which
member and which step are inside the ciphertext, so files carried or
found by others are not linkable to a group or to each other.

### 12.6 File naming

Files use **random opaque filenames** (`shekyl-ms-<random64hex>.bin`,
from a CSPRNG), never metadata. A wallet shows a display name derived
from the opened file (e.g., "Proposal 0x1a2b… from member 3") and never
writes it to disk. This keeps files that end up on shared media, cloud
backups or forensic images from leaking anything through their names.

---

## 13. Ceremony State and Recovery

### 13.1 Per-intent state

A member's intent is **live** from the moment it proposes or commits to
it until the transaction is released or the reference block ages out
(§9.6). While it is live the member holds:

- its reservation of the intent's inputs (`LiveCeremonies`, §9.2 item 6);
- as proposer or holder, between the rounds, its `HeldNonce` (§11.4).

Every member keeps its monotonic nonce counter, and a responder's
wallet keeps the hashes of the intents it approved (no secret), so its
second visit is a check, not a decision. Nothing else is durable: the ceremony's own state is its typestates (§11.3), rebuilt
after a restart from the member's context, its store and the files it
received:

- the proposer is rebuilt from its own `Proposal` file
  (`Proposer::resume`) and replays the files it received;
- a holder is rebuilt as committed (`Holder::committed`) and signs from
  its held nonce;
- the second round is stateless (`Cosigner`).

A held nonce is used once: a holder that crashes after signing finds no
nonce to sign from again.

### 13.2 Disagreement resolution

**Conflicting intents spending one input** → a member commits to at most
one of them (§9.2 item 6); the other times out

**Proposer disappears** → the reference block ages out (§9.6); the
intent times out

**Chain reorg of reference_block** → intents referencing orphaned blocks
time out; re-propose with a new reference

**A member refuses** → it shows its human which check failed (§2.7) and
sends nothing; the human tells the group

**A bad share** → A's aggregation names the signer that sent it (§11.4)

---

## 14. Security Properties

### 14.1 Authorization

| Property | Mechanism |
|---|---|
| No unilateral spend | scheme_id=2 consensus requires M PQC signatures |
| No unilateral redirect | Deterministic construction; signers reconstruct and verify |
| No signature over bytes the signer did not build or verify | §11.3 `SignableTransaction` |
| No silent acceptance of a malformed group output | §8.2 multisig check (received but unspendable, named) |
| No invariant bypass | §11.3: each check is the constructor of a type the signing step takes |

### 14.2 Privacy

| Property | Mechanism |
|---|---|
| Per-output forward privacy | Option C N-fold KEM fan-out + per-output ephemeral keys |
| Spend-to-spend unlinkability (within scheme-2) | Different ephemeral N-key blobs per spend — **but see stream attribution below** |
| Group identity privacy from passive observer | The address fingerprint is not on chain; a file shows only its version (§12.5) |
| Group size | **Not private.** Each `0x0D` entry gives the receiving group's `n` (§7.4); inherent to Option E′ |
| Role-pattern privacy from whoever carries a file | Nothing but the format version is in the clear (§12.5) |
| Filesystem metadata privacy | Opaque filenames; the header is inside the ciphertext (§12.6) |

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
| Any M honest signers can advance | Yes |
| Proposer disappearance recovery | Yes (timeout + re-propose) |
| Signer disappearance recovery | Yes if M others remain |
| Network partition recovery | Yes: a member syncs, and the chain state fingerprint (§9.3) agrees again |
| A carrier withholding files | Members send by another means; files are the only transport (§12.4) |
| Scanner resource bounds | Hard caps + per-sender griefing scores (§7.6) |

### 14.4 Integrity

| Property | Mechanism |
|---|---|
| Transaction integrity through assembly | Each signer builds the transaction it signs (§11.2); the proposer verifies every hybrid signature and runs `verify_multisig` before release |
| Proof integrity | Each signer verifies the membership and range proofs against its own transaction (I3, I4) |
| Proposer equivocation | Different preprocess sets complete no SAL; each nonce is used once (§11.4) |
| Replay resistance | The reference block's age, the held nonce bound to one intent hash, consensus key images; kem_randomness_seed freshness |
| Invariant enforcement | §11.3: the guards are types |

---

## 15. Forward Compatibility

### 15.1 Reserved namespace

| Item | Purpose |
|---|---|
| `group_version = 0x01` | V3.1; higher values for future rotated groups |
| `spend_auth_version = 0x02` | **Option E′** (15.4a threshold classical SAL on `y`). **`0x01` never issued.** Higher values only for a later mutually-distrusting / lattice-auth path — do not overload `0x02`. |
| HRP `shekyl1n...` | Rotated-key multisig (V3.2+) |
| `TX_EXTRA_TAG_MULTISIG_MIGRATION (0x08)` | migration transactions — reserved slot in §7.4's table, no code symbol until designed |
| Message type `0x0A` (RotationIntent) | V3.2 full rotation protocol |

> **Superseded by group_id deletion (2026-07-18, MS-5 PR-B).** Items 1–3
> below analyze how `multisig_group_id` bound the version bytes into its
> preimage. `multisig_group_id` is now **deleted** (§5.3): group identity
> is the **address fingerprint** — `cSHAKE256(canonical(MultisigAddressPayload),
> …)` — whose canonical payload carries `group_version` and
> `spend_auth_version` as real wire fields. The version-binding *goal* of
> MSW-4/5 is met by the fingerprint's preimage, not by a `group_id` hash;
> the `group_id`-preimage mechanics below are historical.

**Honesty pin (2026-07-14 — P0-k / R1-F-11; historical — see the
supersession note above).** *When written*, these rows were *intent*, not
substrate. The `multisig_group_id` mechanics described below are now deleted
(§5.3); items 1–3 are retained only as the reasoning record for MSW-4/5:

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

> **Naming.** This section is **participant / group *key* rotation** (new
> KEM keys, a new address fingerprint, migration txs). E′ rotates no role
> among the members.

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
- Full group rotation (a new address fingerprint)
- Migration transactions consuming old outputs, producing new

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

Scheme_id=2 verify check 9 (the final, crypto check — see §5.3; returns
`CryptoVerifyFailed` = FFI code 10) is `M × Ed25519 + M × ML-DSA`
(`shekyl-crypto-pq` multisig). The key container is hybrid by
construction (`SINGLE_KEY_CANONICAL_LEN = 1996`). Forging an M-of-N
spend requires breaking ML-DSA-65 M times. **Threshold authorization
is quantum-resistant today.**

Classical exposure lives in the **FCMP++ layer**, not in multisig:

- SAL / membership: Ed25519 (`SPEND_AUTH_VERSION_ED25519 = 0x02`; `0x01`
  never issued; `SpendAuthAndLinkability` in `shekyl-fcmp`, compiled
  unconditionally).
- Leaf `{O.x, I.x, C.x, CM.x}` for every output on the chain.
- **Solo has the identical posture** — classical membership/SAL +
  hybrid PQC auth bound through the leaf commitment opening. Multisig adds **zero**
  classical exposure; it carries M hybrid signatures instead of one.

**Quantum degradation of the SAL is graceful for funds, not for
privacy.** An adversary who breaks Ed25519 learns the group's `y` and
can produce the SAL itself, and **M × ML-DSA still authorizes the
spend**. Classical SAL is not a compromise path. Curve break against FCMP++ membership is
**privacy retroactive** (HNDL on the anonymity set); that concern is
real, **not multisig-specific**, and multisig neither helps nor hurts
it.

**Consequence for Track B:** an attack on the ceremony that does not
break ML-DSA can freeze funds, not steal them. Shipping multisig now is an **economics** question
(~2.4× per-tx size vs solo for 5-of-5; ≪ five solos — `V3_ROLLOUT.md`)
— whether threshold custody is worth that cost — not a crypto-maturity
question.

#### Phrase pin — what "pure-PQC spend-auth" is *not*

| Reading | Meaning | Status |
| --- | --- | --- |
| **(a) Lattice-only *auth signing*** | Drop the Ed25519 half of the hybrid `scheme_id=2` key/sig container; M-of-N or composite becomes lattice-only at the *authorization* layer | Achievable in principle; size/FIPS story; **not** what `spend_auth_version` gates |
| **(b) Lattice *SAL*** | Replace Ed25519 `O` / `y` with a lattice key verified inside FCMP++ | **Impossible** while FCMP++ is the membership proof (Helios/Selene circuit verifies a curve equation) |

`spend_auth_version` gates the **SAL key scheme** (it is the container's
version byte and the address's `spend_auth_version`), not the hybrid
signature scheme inside the container.
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

**Built:** the two-component output (`derive_output_secrets` asserts
`y ≠ 0`), the E′ address (`B` + `Y_group` + `(N+1)`×KEM), the `0x0D`
receive path, the dealer split of `y_group`, and the SAL leg as a FROST
signature through `modular_frost`'s machines (`shekyl_fcmp::frost_sal`;
keys offset by `y_kem − o_blind`, refused when they do not open the
rerandomized output), and the signing ceremony (§11): a 2-of-3 and a
3-of-5 group each spend two of their outputs, verified from the wire
(`rust/shekyl-multisig/tests/ceremony.rs`). **Remaining:** the multisig
builder (the unsigned spend from the intent, §9.5) and the wallet.
**Not blocked on NIST.**

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

### 16.1 Rust modules — **E′ / MS-5 (the `shekyl-multisig` crate)**

The multisig ceremony lives in its own crate `shekyl-multisig` (MS-1(a)); its
dependency list *is* the "no transport" ban: the wallet writes and reads
ceremony files that members pass by any means (R-9, §12.4).

```
rust/shekyl-multisig/src/
├── lib.rs                 — crate root + re-exports
├── ceremony/              — the signing ceremony (§11)
│   ├── mod.rs             — Role, CeremonyError
│   ├── context.rs         — SigningContext, InputContext, UnsignedSpend,
│   │                        ProposerInputs (§11.5)
│   ├── files.rs           — the bodies, Authenticated<B>, import (§11.1,
│   │                        wire format §3.1)
│   ├── nonce.rs           — HeldNonce, HeldNonceStore, NonceCounterSink,
│   │                        ConsumedNonce, LiveCeremonies (§11.4)
│   ├── proofs.rs          — CommittedMemberKey, the verified proofs,
│   │                        SignableTransaction (§11.3)
│   └── roles.rs           — Proposer, Holder, Responder, Cosigner
├── intent.rs              — SpendIntent v2, canonical serialization (§9)
├── envelope.rs            — the ceremony file: seal as a member, trial-decrypt
│                            import, the plaintext codec (§12.1)
├── messages.rs            — the message-type discriminants (§12.2)
├── invariants.rs          — ValidatedIntent: I1 and I2 (§2.7)
├── group_descriptor.rs    — public group identity (no share, no KEM secret)
└── build.rs               — the CT type from config JSON

rust/shekyl-engine-core/src/engine/signer.rs
└── MultisigSignerV2        — EngineSignerKind marker (spend_auth 0x02);
                              SigningCeremony = shekyl_multisig::Role

rust/shekyl-multisig/src/member_file.rs
└── MemberFile — §6.6 (stores the transport and envelope secrets; derives neither)

rust/shekyl-crypto-pq/src/derivation.rs
└── derive_group_transport_secret — §6.6

rust/shekyl-crypto-pq/src/multisig_blob.rs
└── seal_blob / open_blob / check_blob_version — §12.3

rust/shekyl-crypto-pq/src/multisig_envelope.rs
├── mint_multisig_envelope_keypair             — §6.6
└── envelope_message / sign_ / verify_multisig_envelope — §12.1

rust/shekyl-crypto-pq/src/multisig.rs
├── MultisigCommittedForm, MultisigKeyBlob     — §7.5
├── multisig_key_hash (shekyl/multisig-key-hash-v1)
└── verify_multisig                            — CEN-I18

rust/shekyl-crypto-pq/src/multisig_output.rs
├── construct_multisig_output                  — §7.1
├── derive_multisig_member_keypair             — §7.2
├── multisig_member_public_key                 — a member's per-output key (§11.1)
└── open_multisig_entry                        — §8.2

rust/shekyl-fcmp/src/frost_sal.rs
├── dealer_split, threshold_keys               — §5.2
├── SalSigningParams::new                      — each signer's own params (§11.4)
├── hold, HeldSession                          — a held nonce that owns its params (§11.4)
└── preprocess / share byte codecs             — 64 and 32 bytes (wire format §3.1)

rust/shekyl-scanner/src/multisig_scan.rs
└── MultisigMemberScan — §8.2

rust/shekyl-scanner/src/scan.rs
└── Scanner::new_multisig_member — §8.1–§8.2
```

### 16.2 New tx_extra tags

`rust/shekyl-wire/src/tx_extra/mod.rs` (not in the coinbase grammar `CEN-I20`):
- `TX_EXTRA_TAG_PQC_MULTISIG = 0x0D`, `MultisigEntry`, CEN-I19's
  `check_pqc_multisig_shape` (§7.4)
- Retired, never reused: `0x09`, `0x0A`. Reserved (spec table only, no code
  symbol): `0x08`

### 16.3 Defense-in-depth wiring fixes

> **MSW-6 (landed).** The tx-wide `expected_scheme_id` DiD that forced
> **tx-wide** scheme agreement is **withdrawn** (option a — dropped
> outright, not exempted). Its *stated* purpose (a cross-input
> scheme-downgrade defense) was vacuous: `expected_scheme` was derived
> from `pqc_auths[0]` itself (self-referential), and per-output scheme
> binding is the leaf commitment opening (`PL-D3`; formerly the leaf hash
> `h_pqc = H(hybrid_public_key)`), not this
> check. Its *actual* effect was to foreclose a
> solo(1)/multisig(2) **cross-model linkage** — co-spending proves common
> control across key models (the 2026-09-11 reading added "the only proof,
> since separate FCMP++ txs are unlinkable"; that premise was false under
> `PL-D1` and holds again since `PL-D3`, 2026-09-14). That belongs in the wallet, not consensus. **Re-based
> 2026-09-14 (`PL-D1`, [`FCMP_SPEND_LINKABILITY.md`](design/FCMP_SPEND_LINKABILITY.md)):**
> the first of the two grounds recorded here — *"no externality: the FCMP++
> proof ranges over the whole tree, so no other party's anonymity set
> shrinks"* — was struck while every FCMP++ spend identified its input by
> the public 4th leaf scalar (`PL-D1`); `PL-D3` (2026-09-14) restored it.
> In the interval the conclusion stood on the remaining ground alone: **(2)** Shekyl already permits exactly this opt-in class — a
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
  → **MSW-6 landed**: no tx-wide scheme agreement in either verifier
  (the CEN-I18 validator and the submit verifier, `verifier.rs`).
- group_id DiD for scheme_id=2: **MS-8 retired** (the leaf already binds the
  committed form; no-op)

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
- Multisig page: address provenance tracking UI with change warnings
- A member's refusal, shown with the check that failed (§2.7)

### 16.7 Feature flag structure

**Status: planned sketch — these flags are not in any `Cargo.toml`
today.** Do not copy-paste the block below into a crate; it names the
intended gate axes for Track B / Option E′. Live today: the `multisig`
feature on engine-core, `shekyl-fcmp` and `shekyl-fcmp-proofs` (F-6 CI
lane, `.github/workflows/multisig-feature.yml`).
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
0x02`). The Option A `MultisigGroup` wrapper is deleted; the SAL layer it
gates is `shekyl_fcmp::frost_sal`, and the Option A orchestration
(`multisig/{dkg,group,signing}.rs`, R1-F-3) is deleted. Do **not** park
the rejected fixed `pqc_public_key` fossil behind this flag.

### 16.8 Test matrix

**Functional:**
- 2-of-3, 3-of-5, 5-of-5 happy paths (receive + spend)
- Single-sig → multisig, multisig → multisig
- Change outputs (group → self)
- Staked outputs

**Adversarial (per-invariant):**
- Malicious proposer attacks each of §9.2 invariants (I1)
- Chain state fingerprint manipulation (I2)
- A membership proof not over the signer's own transaction, or edited (I3)
- A range proof edited, or not over the signer's own outputs (I4)

**Adversarial (ceremony, §11; `rust/shekyl-multisig/tests/adversaries.rs`):**
- A `Proposal` from a member that is not the proposer, or written as the
  proposer by another member (refused at the envelope signature)
- A forged `Commitment` inside a `SigningSet` (named by its sender)
- A `SigningSet` without every other signer
- Different preprocess sets for different signers (no SAL; each nonce used once)
- A `FinalTx` whose proofs are not over the signer's own transaction, or
  with a key that is not the signer's (refused before any hybrid signature)
- A bad share (named by its signer)
- A per-output key that does not match its hash (refused in round 1)
- A replayed file, and a file of another intent
- A holder signing twice from one held nonce (impossible)
- A second intent on a live input (refused)
- Every member restarting between files (the spend completes)

**Adversarial (receive, §8.2):**
- A sender lies about one member's key hash: that member sees `MemberKeyHash`, every other member `LeafMismatch`
- Damaged or missing `0x0D` entry, damaged leaf, wrong `out_idx`, wrong group size
- A member decapsulating another member's ciphertext cannot pass that member's hash

**Adversarial (other):**
- Two live intents spending one input: a member commits to one of them
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
- Proposer proof construction time

### 16.9 Fuzz targets

```
fuzz_construction_determinism
fuzz_envelope_v2_decode              (the ceremony file's plaintext; landed)
fuzz_multisig_blob_roundtrip         (the file seal; landed)
fuzz_intent_validation               (landed)
fuzz_body_proposal_decode            (each ceremony body, exact; landed;
fuzz_body_commitment_decode           the intent's canonical bytes ride
fuzz_body_signing_set_decode          the Proposal's)
fuzz_body_responder_share_decode
fuzz_body_signature_share_decode
fuzz_body_final_tx_decode
fuzz_body_hybrid_sig_decode
fuzz_multisig_address_parse
fuzz_receive_time_validation
```

### 16.10 Rollout sequencing

| Phase | Duration | Content |
|---|---|---|
| 1 | 4-6 wk | Receiving model (§7–§8), the `0x0D` entry, address format, defense-in-depth wiring |
| 2 | 4-6 wk | The intent (§9), the ceremony files (§12), the signing ceremony (§11, §13), the multisig builder (§9.5, §10) |
| 3 | 3-4 wk | GUI: fingerprint (3-representation) verification, address provenance tracking, refusals |
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
     fixed parameters (n=5, m=3, group_version=1, spend_auth_version=2)
   - Output: canonical serialized address, address fingerprint
     (hex + word-phrase + structured metadata)

2. **Receive-output vector**
   - Input: fixed recipient address (from A.1), fixed tx_secret_key,
     fixed output_index_in_tx, fixed reference_block_hash, fixed amount
   - Output: full construct_multisig_output result — the 0x06 ciphertext,
     the output key O, the commitment, the 0x07 entry (CM ‖ record over the
     committed form), and the 0x0D entry (member ciphertexts, encrypted key
     hashes)

3. **Spend-intent vector**
   - Input: fixed group state (from A.1), fixed input list, fixed
     recipient list, fixed parameters
   - Output: canonical serialized SpendIntent, intent_hash,
     chain_state_fingerprint. The intent half is pinned:
     `docs/test_vectors/MULTISIG_INTENT_V2.json`, checked by
     `scripts/kat/multisig_intent_oracle.py`

4. **Full-construction vector**
   - Input: fixed spend intent (from A.3), fixed chain reference data
   - Output: the unsigned transaction (prefix and base) and its
     `tx_signable`

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
