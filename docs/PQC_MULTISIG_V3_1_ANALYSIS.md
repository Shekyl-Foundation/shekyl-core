# PQC Multisig V3.1: Analysis and Design Rationale

> **Status:** Living document; updated with new findings as design evolves
> **Companion to:** `PQC_MULTISIG.md` (the V3.1 specification)

This document captures the analysis, wargame history, size measurements,
attack catalog, and rationale behind the V3.1 design decisions. The
specification document references this for "why" answers; this document
references the spec for "what" answers.

---

## Table of Contents

1. [Design History](#1-design-history)
2. [Size Analysis](#2-size-analysis)
3. [Receiving Model Selection: C vs D](#3-receiving-model-selection-c-vs-d)
4. [Attack Catalog](#4-attack-catalog)
5. [Wargame Round Summaries](#5-wargame-round-summaries)
6. [Open Questions and Future Reviews](#6-open-questions-and-future-reviews)
7. [Cryptographer Review Targets](#7-cryptographer-review-targets)

---

## 1. Design History

### 1.1 Why V3.1 exists

The original `PQC_MULTISIG.md` design relied on a single coordinator who
held authority over transaction construction, signing orchestration, and
assembly. This created two structural problems the project lead explicitly
disliked:

1. **Uneven participant power.** The coordinator had outsized control:
   could decide what gets signed, when, and could potentially construct
   transactions other participants would only review (not co-author).
2. **Off-chain transactional construction.** Construction happened in a
   single coordinator's process, with limited audit trail and no
   structural protection against coordinator misbehavior.

V3.1 was scoped to address both, while preserving on-chain transaction
indistinguishability (no separate on-chain class for multisig) and avoiding
consensus changes.

### 1.2 Major architectural decisions

| Decision | Rationale |
|---|---|
| Equal-participants protocol | Eliminates coordinator power center |
| Deterministic construction | Removes coordinator latitude over content |
| Option C receiving (per-output ephemeral keys) | Spend-to-spend unlinkability for groups |
| Rotating prover (per-output) | Distributes liveness risk across group; bounds 1/N loss |
| No consensus changes | "Get it right, not get it now"; hard forks signal failure to plan |
| Honest-signer enforcement of prover uniqueness | Avoids consensus change while preserving safety in honest-majority case |
| Mandatory DKG for transport secret | Removes founding-proposer privileged-observer attack |
| Multi-relay + heartbeat | Censorship-resistant transport |
| Fresh-randomness BP+ (changed from deterministic) | Removes novel cryptographic claim |
| Prover-receipt tiebreaker | Ungrindable conflict resolution |

### 1.3 Decisions deferred to V4

| Decision | Reason |
|---|---|
| FROST SAL (threshold classical key) | Awaiting NIST lattice threshold standardization (12-24 months) |
| Carrot-style address typing | Coupled to FROST SAL |
| Hardware wallet support | V3 hardware wallet support deferred separately |

### 1.4 Decisions deferred to V3.2 / V3.3

| Decision | Reason |
|---|---|
| Group key rotation protocol | Important but additive; can ship after V3.1 |
| Granular KEM-only rotation | Fine-grained version of the above |
| Key escrow for prover material | Mitigates 1/N loss; complex social/UX design needed |
| Chain-anchored group registry | Would solve address-size UX problem; consensus change |
| Traffic padding for transport | Marginal additional privacy; complex |

---

## 2. Size Analysis

### 2.1 Confirmed constants

| Constant | Value | Source |
|---|---|---|
| `X25519_CT_BYTES` | 32 | `tx_extra.h` |
| `ML_KEM_768_CT_BYTES` | 1,088 | `tx_extra.h` |
| `HYBRID_KEM_CT_BYTES` | 1,120 | `tx_extra.h` |
| `PQC_LEAF_HASH_BYTES` | 32 | `tx_extra.h` |
| `HYBRID_SINGLE_KEY_LEN` | 1,996 | `tx_pqc_verify.cpp` |
| `HYBRID_SINGLE_SIG_LEN` | 3,385 | `cryptonote_config.h` |
| `MAX_MULTISIG_PARTICIPANTS` | 7 | `cryptonote_config.h` |
| `FCMP_MAX_INPUTS_PER_TX` | 8 | `cryptonote_config.h` |
| FCMP++ proof per input | ~3,500 (estimate) | docs |

### 2.2 Per-output cost

| N | Single-sig | Option D | Option C | C−D delta |
|---|---|---|---|---|
| 2 | 1,152 B | 1,152 B | 2,272 B | +1.1 KB |
| 3 | 1,152 B | 1,152 B | 3,392 B | +2.2 KB |
| 5 | 1,152 B | 1,152 B | 5,632 B | +4.4 KB |
| 7 | 1,152 B | 1,152 B | 7,872 B | +6.6 KB |

Linear formula: Option C uplift per output = `(N - 1) × 1,120 B`.

### 2.3 Per-input cost (scheme_id=2 authorization, same for C and D)

| Configuration | Per-input pqc_auth | vs single |
|---|---|---|
| Single-sig | 5,385 B | baseline |
| 2-of-3 | 12,767 B | +137% |
| 3-of-5 | 20,145 B | +274% |
| 5-of-7 | 30,909 B | +474% |
| 7-of-7 | 37,679 B | +599% |

This cost is incurred regardless of receiving model and dwarfs the
Option C vs D delta.

### 2.4 Whole-transaction examples

| Scenario | Single-sig | Option D | Option C | C/D delta |
|---|---|---|---|---|
| User → 2-of-3 (2-in, 2-out, 1 multisig output) | 20.9 KB | 20.9 KB | 23.1 KB | +10.5% |
| 2-of-3 spends (2-in, 2-out, change to group) | 20.9 KB | 35.3 KB | 37.5 KB | +6.2% |
| 3-of-5 spends (4-in, 2-out, change to group) | 38.4 KB | 96.0 KB | 100.4 KB | +4.6% |
| 5-of-7 spends (4-in, 2-out, change to group) | 38.4 KB | 138.1 KB | 144.6 KB | +4.8% |

### 2.5 Address size

| N | Payload bytes | Bech32m chars |
|---|---|---|
| 2 | 6,409 | ~10,260 |
| 3 | 9,609 | ~15,380 |
| 5 | 16,009 | ~25,620 |
| 7 | 22,409 | ~35,860 |

Multisig addresses are not QR-shareable and not paste-friendly. File-based
exchange + 32-byte fingerprint verification is the canonical UX. A future
chain-anchored group registry (V3.3+) would reduce these to ~100 bytes.

### 2.6 Storage impact

KEM ciphertexts in `tx_extra` are NOT prunable. Option C's per-output
uplift is permanent chain growth.

`pqc_auths` blob (the per-input scheme_id=2 cost) IS prunable (separate
LMDB table `m_txs_pqc_auths`). Pruned nodes lose this; archival nodes
retain.

For permanent storage planning: each multisig-received output adds
`(N-1) × 1,120 B = up to 6.6 KB` to permanent chain bytes. At N=4
average and 1000 outputs/year per active multisig group, that's ~3.4 MB
per group per year of permanent storage.

### 2.7 Chain-wide impact (adoption-weighted)

Assuming average multisig tx adds ~3.4 KB over single-sig:

| Adoption | Avg per-tx overhead | Chain growth |
|---|---|---|
| 0.1% | +3 B | +0.02% |
| 1% | +34 B | +0.16% |
| 5% | +168 B | +0.79% |
| 10% | +336 B | +1.57% |
| 25% | +840 B | +3.93% |

Realistic expected adoption: 1-5%. Chain-wide impact <1%.

### 2.8 Fee impact

For a user *receiving* to a multisig group (the only case where Option C
vs D affects them directly):

| N | Tx weight increase | Fee increase |
|---|---|---|
| 3 | +10.5% | +10.5% |
| 5 | +21.0% | +21.0% |
| 7 | +31.4% | +31.4% |

For a multisig group *spending*: +4-7% over Option D. Almost noise
relative to the scheme_id=2 authorization cost.

---

## 3. Receiving Model Selection: C vs D

### 3.1 The four candidates

We considered four receiving models:

- **A:** N-recipient KEM (single ciphertext decappable by any of N)
- **B:** Shared KEM decap via DKG
- **C:** N parallel KEM ciphertexts
- **D:** Enduring group key in leaf

### 3.2 Why A and B are out

**A (N-recipient KEM):** ML-KEM-768 has no NIST-standardized
multi-recipient variant. Adoption would require speculative cryptography
incompatible with Shekyl's "minimum NIST primitives" posture.

**B (DKG-shared decap):** All N members would derive the same shared
secret, hence the same per-output ephemeral keypair. Per-participant
authorization becomes meaningless; M-of-N collapses to "any one member
can sign with the shared ephemeral key." Defeats the purpose.

### 3.3 C vs D: the core tradeoff

| Property | Option C | Option D |
|---|---|---|
| Per-output forward privacy | Yes | No |
| Spend-to-spend unlinkability for group | Yes | No |
| On-chain group fingerprint | None | Same N-key blob every spend |
| Per-output size cost | (N-1) × 1,120 B | 0 |
| Treasury operational privacy | Strong | Weak (full activity correlation) |

### 3.4 The decisive argument for C

Under Option D, every spend from the same group reveals the same enduring
N-key blob in the on-chain `pqc_auths.hybrid_public_key` field. Two spends
from the same group are trivially linkable by any observer who saw both
transactions before pruning. Over the lifetime of the group, on-chain
activity forms one fully-correlated cluster.

For treasury usage (the primary multisig use case), this is unacceptable.
A 3-of-5 corporate treasury under D effectively publishes its complete
transaction graph to any observer watching the chain.

Under Option C, each spend uses different per-output ephemeral hybrid
keys. Two spends from the same group are indistinguishable from spends
by two different groups of the same cardinality. Treasury operations are
private to the same standard as single-sig spends.

### 3.5 The cost analysis that confirmed C

The 4-10% per-transaction size uplift for Option C vs D is small
compared to the existing scheme_id=2 authorization cost (which causes a
2-4× uplift over single-sig). Saving 5% on tx weight by sacrificing
spend-to-spend unlinkability would be misaligned with Shekyl's
privacy-first posture.

Decision: **Option C.**

---

## 4. Attack Catalog

This catalog tracks every attack identified across wargames, with current
mitigation status. Attacks are organized by category.

### 4.1 Authorization attacks

#### 4.1.1 Scheme downgrade (PQC_MULTISIG.md original Attack 1)

**Attack:** Spend a multisig-committed output with scheme_id=1, using one
of the N individual hybrid keys.

**Status:** Mitigated indirectly (leaf hash + size check) and explicitly
(§7.4 wired `expected_scheme_id` defense-in-depth).

#### 4.1.2 Group substitution

**Attack:** Spend with a different group's N-key blob.

**Status:** Mitigated by leaf hash binding (different blob → different
hash → proof rejects).

#### 4.1.3 Signer index manipulation

**Attack:** Manipulate signer_indices to map two sigs to same key, or
out-of-range index, or unsorted.

**Status:** Mitigated by existing `verify_multisig` Checks 6 and 7.

#### 4.1.4 Blob truncation/padding

**Attack:** Send malformed pqc_auth blob with wrong size.

**Status:** Mitigated by strict size checks in `tx_pqc_verify.cpp`.

### 4.2 Construction attacks

#### 4.2.1 Coordinator content tampering (original design's main flaw)

**Attack:** Coordinator constructs a tx that doesn't match what they
showed signers.

**Status:** Eliminated by design. Construction is deterministic from
intent; signers reconstruct independently and verify byte-for-byte.

#### 4.2.2 Prover proof substitution

**Attack:** Prover constructs a proof binding to a different payload.

**Status:** Mitigated by signers verifying proof binds to their
independently-computed payload before signing.

#### 4.2.3 Prover equivocation

**Attack:** Prover sends different ProverOutputs to different signer
subsets.

**Status:** Detection added (§12.2.4); produces undeniable
EquivocationProof; prover marked untrusted.

#### 4.2.4 Wrong-prover key image (rotating prover specific)

**Attack:** A non-assigned prover constructs a valid FCMP++ proof using
their own per-output `y_i`, producing a different valid key image.

**Status:** Mitigated by §11.3 honest-signer prover assignment
verification. Honest-majority assumption: if M signers honestly verify
prover assignment, the attack fails. M-of-N collusion case is out of
scope.

### 4.3 Receiving attacks

#### 4.3.1 Change address single-sig escape (RESOLVED)

**Attack (original):** Earlier draft derived `change_spend_key` from
`group_id` via HKDF; any group member could derive and spend
unilaterally.

**Status:** RESOLVED. §10.3 specifies that change outputs use the
identical Option C construction as any other multisig output. There is
no single-sig change derivation in the spec.

#### 4.3.2 Griefing via malformed multisig output

**Attack:** Sender constructs an output that looks multisig-shaped
(claims a group_id, has KEM ciphertext array) but whose ciphertexts
don't decap with the group's keys. The output is unspendable. Attacker
pays fees; recipient gets nothing.

**Status:** Accepted as bounded threat. §3.3 documents; §7.5 mandates
wallet-side filtering so users never see griefing artifacts. Cost-bounded
by attacker fee expenditure. Consensus-layer fix would require chain-
anchored group registry (V3.3+ candidate).

#### 4.3.3 View tag hint distinguishability

**Attack:** Observer infers an output is multisig-shaped from the presence
of `TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS` and the size of the KEM ciphertext
array.

**Status:** Acknowledged minor leak. Multisig vs single-sig is
distinguishable on-chain. Cardinality (N) is also leakable from KEM
array size. Specific group identity is NOT leaked (per Option C). This
is a residual privacy property gap; unfixable without consensus changes
to make all outputs structurally identical.

### 4.4 Transport attacks

#### 4.4.1 Selective relay censorship

**Attack:** Malicious relay drops messages from specific senders to
prevent group from reaching M signatures, without triggering veto
threshold (since vetoes also dropped).

**Status:** Mitigated by §12.4 mandatory multi-relay (3+ disjoint
operators) and §13.3 heartbeat protocol. A single malicious relay
cannot censor; would require collusion across all subscribed relays.

#### 4.4.2 Role-pattern leakage from message types

**Attack:** Observer infers prover/signer roles from message_type field
in unencrypted envelope.

**Status:** Mitigated by §12.5 encrypted message_type. Cleartext envelope
is minimized.

#### 4.4.3 Group identification from group_id

**Attack:** Stable group_id in cleartext envelope lets observers build
longitudinal dossier on group activity patterns.

**Status:** Acknowledged. Mitigation via group_id rotation is a V3.2+
feature. For V3.1, users are advised that relay traffic patterns are
correlatable per group.

#### 4.4.4 Filename leakage in file transport

**Attack:** Filenames include group_id, intent_hash, message_type, sender
in cleartext; if files are stored on shared media (cloud, removable),
metadata leaks.

**Status:** Acknowledged and documented. Air-gap workflows acceptable;
shared-storage workflows flagged as risk in user-facing docs.

### 4.5 State machine / counter attacks

#### 4.5.1 Counter desync via delayed broadcast (RESOLVED)

**Attack (original):** Malicious assembler delays broadcast; group
state diverges between members who saw broadcast and those who didn't.

**Status:** RESOLVED. §13.4 CounterProof mechanism allows stale members
to verify forward jumps cryptographically against on-chain reality.
Counter advances only on observed chain state.

#### 4.5.2 Conflicting same-counter intents (RESOLVED)

**Attack (original):** Two proposers race to publish at same counter;
hash-based tiebreaking is grindable.

**Status:** RESOLVED. §10.5 prover-receipt tiebreaker. Prover signs
acknowledgment of first valid intent received; not grindable from intent
content alone.

#### 4.5.3 Veto griefing

**Attack:** Single member in 2-of-3 vetoes every intent.

**Status:** Inherent to threshold systems; documented as accepted. The
malicious member could simply refuse to sign anyway; explicit veto only
makes the attack visible. Mitigation: group composition discipline; users
should not form groups where one member can practically veto everything.

#### 4.5.4 Intent spam DoS

**Attack:** Spam high rate of intents to exhaust honest verifier work.

**Status:** Mitigated by §13.6 per-proposer rate limit (1 active intent
per proposer at a time).

### 4.6 Replay attacks

#### 4.6.1 Literal replay

**Attack:** Resubmit identical intent.

**Status:** Mitigated by intent_id, expires_at, tx_counter binding.

#### 4.6.2 Semantic replay (kem_randomness_seed reuse)

**Attack:** Reuse `kem_randomness_seed` across retries to create linkable
output artifacts.

**Status:** Mitigated by §9.2 invariant 13 — kem_randomness_seed must be
unique within group's seen_intents history.

### 4.7 Address/social engineering attacks

#### 4.7.1 Address file substitution

**Attack:** Attacker substitutes recipient's exported address file with
attacker-controlled-keys address.

**Status:** Mitigated by §6.4 mandatory fingerprint verification UI.
Attack requires also intercepting fingerprint exchange channel.

#### 4.7.2 Truncation/encoding corruption

**Attack:** Partial paste of long address corrupts encoding.

**Status:** Bech32m checksum + mandatory fingerprint check both detect.

#### 4.7.3 Short ID poisoning

**Attack:** If short content addresses are introduced, attacker generates
fake address that hashes to victim's short ID.

**Status:** Not relevant in V3.1 (full file-based exchange is canonical).
Becomes relevant in V3.3+ if chain-anchored registry is added; design
must use full content-address hash, not truncated.

### 4.8 Out-of-scope attacks (documented for completeness)

| Attack | Reason out of scope |
|---|---|
| M-of-N collusion | Defeats any multisig by definition |
| Permanent loss of participant keys | 1/N stuck; documented limitation |
| Compromise of group's KEM private keys | Catastrophic; V3.2 rotation mitigates |
| Quantum break of both ML-KEM and X25519 | Hybrid scheme's whole point |
| Long-term selective disclosure by M | Inherent to threshold |
| Sustained griefing scanning cost | Bounded by fee cost; accepted |

---

## 5. Wargame Round Summaries

### 5.1 Round 1 (initial V3.1 governance draft)

Two reviewers independently identified four ship-blockers and one
out-of-scope concern:

| Finding | Both reviewers? | Resolution |
|---|---|---|
| Change address single-sig escape | Both | RESOLVED §10.3 |
| Simple-mode shared secret | Both | RESOLVED §5.2 mandatory DKG |
| Counter desync recovery undefined | Both | RESOLVED §13.4 CounterProof |
| Hash-based tiebreaker grindable | One (R2) | RESOLVED §10.5 prover receipt |
| Deterministic BP+ novel claim | One (R1) | RESOLVED §10.2 fresh randomness |
| Relay censorship | Both | RESOLVED §12.4 multi-relay + §13.3 heartbeat |
| Veto griefing | Both | Documented; inherent |

### 5.2 Round 2 (after consolidation, governance + receiving combined)

Review of consolidated spec is pending. Expected to focus on:

- Composition correctness of governance and receiving layers
- Honest-signer prover-assignment-verification soundness
- CounterProof verification logic
- Multi-relay coordination edge cases
- Fingerprint-verification UI threat model

---

## 6. Open Questions and Future Reviews

### 6.1 Open implementation questions

1. **Output sequence numbering for prover rotation.** §11.1 uses block
   height + tx position. Alternative: per-group off-chain monotonic
   counter. Block-height-based is more robust to network partitions but
   couples to chain state. Confirm choice during implementation.

2. **Heartbeat cadence.** Default 5 minutes is a guess. Bench against
   real network conditions. Consider adaptive cadence (more frequent
   during active intents, less between).

3. **Garbage-purge cadence.** Default 10,000 blocks is a guess.
   Calibrate against typical griefing rates if any are observed in
   stressnet.

4. **Multi-relay quorum.** Spec says 3 disjoint operators minimum. Should
   wallets enforce this as hard requirement, or allow user override with
   warning? Recommend hard requirement for production groups.

### 6.2 Open cryptographic questions (cryptographer review needed)

1. **View-tag hint information theory.** Does the 1-byte hint, derived as
   `HKDF_Expand(ss, "shekyl-v31-view-tag", 1)[0]`, leak any information
   about the shared secret beyond what's already public (the KEM
   ciphertext)? Expected answer: no, because HKDF is one-way. Need
   formal analysis.

2. **Rotating prover assignment uniformity.** Does
   `H(group_id || height || pos || ref_block) mod N` produce uniformly
   distributed prover indices over realistic input distributions?
   Expected answer: yes (cryptographic hash output distribution).
   Statistical test on 10⁶ samples should confirm.

3. **Per-output KEM derivation chain soundness.** The chain `KEM.encap →
   shared_secret → derive_output_secrets → ephemeral_signing_keypair`
   produces per-participant ephemeral keys. Need analysis confirming:
   (a) keys derived from independent shared_secrets are
   cryptographically independent; (b) deterministic derivation does not
   compromise signing key confidentiality given the public hybrid pubkey.

4. **CounterProof cryptographic correctness.** The verifier accepts a
   forward jump based on (block_hash, tx_hash, position). Need to confirm
   this is not exploitable for spoofing — e.g., can an attacker construct
   a valid-looking CounterProof for a tx that wasn't actually theirs?

### 6.3 Cross-platform determinism questions

The deterministic construction guarantee depends on byte-identical
serialization across platforms. Specific concerns:

- Endianness of all integer fields (must be explicit little-endian)
- HKDF output equivalence across implementations
- Hybrid signature canonical encoding
- Floating-point usage anywhere (must be zero — Bulletproof+ uses
  field arithmetic, but verify implementation has no f64 paths)

---

## 7. Cryptographer Review Targets

When the spec goes to external cryptographic review, the highest-priority
items for analysis are:

### 7.1 Critical (must be cleared before launch)

1. **§7.1 Option C derivation chain:** per-output ephemeral keys derived
   from per-participant KEM shared secrets. Confirm independence,
   confirm deterministic derivation does not weaken signing keys.
2. **§11.3 honest-signer prover assignment invariant:** confirm this is
   sufficient to prevent wrong-prover key image attacks in honest-majority
   case.
3. **§10.2 fresh-randomness BP+ with signer verification:** confirm the
   protocol's prover-produces / signers-verify split is sound.
4. **§13.4 CounterProof:** confirm the cryptographic chain proof is not
   exploitable for spoofing.

### 7.2 Important (should be cleared before launch)

1. **§8.1 view-tag hint:** confirm 1-byte hint does not leak key material.
2. **§11.1 rotating prover assignment:** statistical uniformity analysis.
3. **§12.3 message encryption:** confirm AEAD construction and key
   derivation are sound.

### 7.3 Useful (can be cleared post-launch)

1. **§9.3 chain state fingerprint:** confirm fingerprint contents are
   sufficient to detect divergence without false positives.
2. **§5.3 group_id derivation:** confirm collision resistance.
3. **Address fingerprint:** confirm 32-byte cn_fast_hash is sufficient
   for the threat model.

---

## 8. Implementation Risk Register

Items that could derail implementation and need attention:

| Risk | Impact | Mitigation |
|---|---|---|
| Cross-platform determinism bugs | Network split | Explicit byte ordering spec; comprehensive determinism fuzz harness |
| Multi-relay coordination edge cases | Liveness failures | Heartbeat + CounterProof recovery as backstop |
| Honest-signer verification implementation gap | Authorization break | Make prover verification a documented hard invariant; integration tests cover the attack |
| Address UX friction blocking adoption | Feature disuse | File-based exchange + clear UI guidance + future chain-anchored registry |
| 1/N permanent loss in real groups | User funds lost | Documentation; future V3.2 escrow protocol; FROST SAL in V4 |
| Performance at scale (high multisig adoption) | Scanner cost | Benchmark early; possible daemon-side pre-filter RPC |
