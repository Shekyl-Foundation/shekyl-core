# Wallet Message Signing (A2 / rewrite-plan 2c residue) — Design Round

**Status: ROUND 0 OPEN (2026-08-08); PASS 1 FOLDED (2026-08-08).** Poses
SM-DQ-1…SM-DQ-8. Nothing here is ratified; the signature format freezes
the moment it ships (a signature issued on day one must verify forever),
so every fork below resolves before implementation starts. Pass 1
superseded the round-0 SM-DQ-1 lead (see the pass record, §6) and
escalated the address-version half to the genesis lane (SM-DQ-7).

**Scope.** The last unwired 2c method pair:
`Engine::sign_message(msg)` / `Engine::verify_message(msg, sig, address)`
([`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md) Phase 2 target list),
projected as the RESERVED `sign_message` / `verify_message` RPC methods
(error band `-29800..-29899`, [`wallet_rpc.yaml`](../api/wallet_rpc.yaml))
and the stubbed CLI `sign` / `verify` commands. The rewrite plan parked
this pair with the annotation "own hybrid-key design decision"
([`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §rewrite row 2c);
this round is that decision.

**What the feature is for.** A transferable attestation binding a message
to a Shekyl address: "the holder of this address's keys signed these
bytes." Lineage use cases: proving address ownership to a counterparty
(exchange, pool, dispute), signing a statement from a treasury address.
It is user-facing surface (rules 80/81 apply to its errors and its size).

---

## §1 Grounded inventory (verified at source, 2026-08-08, dev 2ea0710a1)

1. **Address v1 carries no post-quantum *signature* anchor.** The
   classical segment is `version || spend_pk || view_pk || ek_bind_tag`
   (Ed25519 keys); the two PQC segments carry an **ML-KEM-768
   encapsulation key** (1184 B) — an *encryption* key, bound to the
   classical segment by `ek_bind_tag = cSHAKE256("shekyl/ek-bind-v1",
   ml_kem_ek)[..16]` (`shekyl-address/src/address.rs`). There is no
   ML-DSA verification key, and no commitment to one, anywhere in the
   address.
2. **The wallet holds no wallet-level ML-DSA identity.** The secret
   inventory is `spend_sk`, `view_sk`, `ml_kem_dk`
   (`shekyl-engine-file/src/secrets_transitional.rs`). ML-DSA keys exist
   only per-output, derived from `combined_ss` at spend time
   (`shekyl-crypto-pq/src/derivation.rs`).
3. **The machinery to mint one deterministically exists.**
   `derivation.rs::keygen_from_seed` derives a domain-separated
   ML-DSA-65 keypair from a seed and index; a wallet-level identity
   under a fresh domain string is mnemonic-recoverable by construction.
4. **Hybrid signature primitives exist with versioned canonical
   encodings.** `HybridEd25519MlDsa` sign/verify, `HYBRID_KEY_VERSION` /
   `HYBRID_SIG_VERSION` / scheme-id bytes, length-checked
   `from_canonical_bytes` (`shekyl-crypto-pq/src/signature.rs`).
5. **Sizes.** Ed25519 signature 64 B. ML-DSA-65 signature 3309 B,
   verification key 1952 B. A hybrid signature carrying its vk is
   ~5.3 KB raw, ~7.2 KB base64 — three orders of magnitude larger than
   the 64 B classical form users paste today.

## §2 The structural fact the round turns on

A **transferable** signature is verified against the address alone, so it
is at most as strong as the address's signature anchors — and address v1
anchors only Ed25519 (§1.1). No signature format choice can make a
transferable proof quantum-resistant against address v1: a quantum
forger who breaks the spend key can issue fresh signatures of any format
we define, because the address cannot distinguish our PQ key from theirs.

The inverse also holds and is easy to miss: the ML-KEM ek **is** a
PQ-secure anchor for an **interactive** proof (verifier encapsulates to
the address, wallet proves decapsulation). Interactivity, not signature
composition, is where address-v1 PQ ownership proof actually lives.

**Pass-1 amendment — the asymmetry that dissolves the impasse.** The
address must carry the *full* 1184-byte ML-KEM ek because a sender
encapsulates *to* the key — you cannot encapsulate to a digest. A
signature verification key has no such constraint: the verifier needs
it only at verification time, and the signature blob can carry it —
provided the address **commits** to it. So the PQ signing anchor costs
the address 32 bytes of binding, not a key. The mechanism is already
in-tree and proven: `ek_bind_tag = cSHAKE256("shekyl/ek-bind-v1",
ml_kem_ek)[..16]` binds the classical segment to the PQC segments
(`shekyl-address/src/address.rs:180-187`, verified). A signing-key
commitment is a second instance of that pattern — with one deliberate
difference ratified below (SM-DQ-7: 32 bytes, not 16).

And critically: **we are pre-genesis. The address format is not yet
frozen.** Round 0 analyzed the fork against an unchangeable address v1;
that framing was too narrow. The real question is what the
genesis-frozen address commits to — which is SM-DQ-7, and it is not
A2's decision to make alone.

Every fork below is downstream of these facts.

## §3 Design questions

### SM-DQ-1 — Signature composition (the anchor question)

- **(a) Classical-only.** Ed25519 over the domain-separated preimage,
  64 B, wallet2-parity shape. Honest about §2, minimal size. But it
  mints a *new, frozen, pure-classical attestation surface* on a chain
  whose first mission commitment is hybrid PQC from genesis — and every
  signature issued before a future upgrade is classical forever.
- **(b) Hybrid, vk-certified — LEAD.** The signature carries a
  seed-derived wallet-level ML-DSA-65 vk (§1.3); the Ed25519 half signs
  `preimage || ml_dsa_vk` (the address-anchored key certifies the PQ
  key); the ML-DSA half signs the same preimage. Properties, stated
  without overselling:
  - Against a classical adversary: strictly ≥ (a) — both halves must
    verify.
  - Against a future quantum adversary: *fresh* forgeries remain
    possible (§2, inherent to address v1) — but signatures issued
    **before** the break retain PQ non-repudiation for any verifier who
    archived them (their embedded vk stays unforgeable), and the format
    survives an address-v2 PQ anchor without redefinition: v2 turns the
    embedded vk from Ed25519-certified into address-committed.
  - Cost: ~7.2 KB armored strings (§1.5) — a paste-into-a-form UX, not
    a read-over-the-phone one.
- **(c) Defer the pair to address v2.** No new frozen format until the
  address can anchor it. Rejects A2 rather than deciding it; blocks a
  parity item on an unscheduled, genesis-adjacent format change.

~~The lead is (b)~~ — **SUPERSEDED by pass 1 (2026-08-08), on the
record.** Round 0's (b) certified the PQ vk with the Ed25519 key
*because* it took address v1 as unchangeable; pre-genesis it is not
(§2 pass-1 amendment), and Ed25519-certification is the weaker binding
(a quantum forger of the spend key re-certifies its own vk). The
superseding lead is the **agile commitment** (SM-DQ-7): the address
commits to `cSHAKE256(DST, alg_id ‖ pk)`, the signature blob carries
`alg_id ‖ pk ‖ σ_pq ‖ σ_ed25519`, and the *algorithm* becomes a
second, decoupled decision (SM-DQ-8). BIP-360's history is the
precedent, verified against the current changelog (bips/bip-0360,
fetched 2026-08-08): v0.3.0 (2024-10) replaced XMSS with
CRYSTALS-Dilithium; v0.6.0 (2025-01) removed SLH-DSA on performance
grounds; v0.8.0 (2025-07) cut the supported set from three to two; and
the proposal's current form commits to a **32-byte Merkle root** with
post-quantum signatures explicitly deferred to a separate proposal.
Three algorithm churns in a year *inside an address proposal*, resolved
by freezing a commitment structure and moving the algorithm debate out
— that is the transferable lesson. The timing sharpens it: NIST's
additional-signatures onramp advanced nine candidates to round 3 on
2026-05-14 (verified: csrc.nist.gov/projects/pqc-dig-sig), a phase
expected to run ~2 years, motivated exactly by diversifying away from
structured lattices and shrinking signatures. Freezing `ml_dsa_pk`
into the genesis address bets a permanent artifact on a 2024 answer to
a question that reopens in 2028; committing to `alg_id ‖ pk` costs the
same 32 bytes and turns a future scheme into a new `alg_id` instead of
an address-version bump.

**Combiner (pass 1, binding for whatever algorithm wins): nested, not
parallel.** Plain concatenation is *separable* — a lenient or
downgrade-tolerant verifier can be shown the classical half alone —
and third-party verifiers will exist for this surface, so strong
non-separability is the property that matters. Verified at source:
Bindel–Hale (ePrint 2023/423) enumerates exactly this property space
(proof composability, weak/strong separability, backwards
compatibility, hybrid generality, simultaneous verification) and notes
few of the goals are achieved by parallel signing or concatenation;
the nested form is `σ₁ ← Sign₁(label ‖ m)`, `σ₂ ← Sign₂(label ‖ m ‖
σ₁)`. There is now a machine-checked EUF-CMA proof for hybrid
Fiat–Shamir (ePrint 2026/1086, EasyCrypt) with two symmetric bounds —
security holds if *either* component is EUF-CMA — and ML-DSA is
Fiat–Shamir, so the composition we would build sits close to formal
support. The round-0 §4 "AND-not-OR" test obligation upgrades
accordingly: non-separability must be *structural* (nested), not a
verifier-discipline promise.

### SM-DQ-2 — Interactive KEM ownership proof (separate surface)

§2's inverse: `ml_kem_ek` supports a PQ-secure *interactive*
challenge-response today. That is a different API contract
(challenge/response, non-transferable), a different consumer (live
counterparty vs. archived attestation), and none of wallet2's parity
surface. Disposition to ratify: **rejected-now, rule 21** — reopen when
a consumer surface needs live PQ ownership proof (e.g. an exchange
integration spec) or when address v2 lands and the comparison changes.
Not a blocker for SM-DQ-1; recorded so the round shows it was seen.

### SM-DQ-3 — Preimage and domain separation

Proposed preimage (rule 30 — no naked hashes, no cross-surface reuse):

```
preimage = H(domain || version || network_id || mode ||
             classical_segment || H(message))
```

- `domain`: a fresh string in the house style (`"shekyl/msg-sign-v1"`);
  collision-checked against the derivation/binding domains in §1.
  **Pass-1 amendment:** the label does double duty — it is also the
  hybrid *binding label* of the nested combiner (the constant-prefix
  construction Google's hardware-key work adopted from Bindel et al.,
  ePrint 2022/1225): it encodes the `alg_id` so an adversary cannot
  derive partial signatures for messages outside this surface. One
  registered label satisfies both the rule-30 domain-separation
  requirement and the combiner's binding requirement. Register it
  once, in the crypto crate, next to the §1 domain inventory.
- `mode`: 1 byte — `0x01` spend-tier (this round's only mode);
  view-tier and future modes append, never renumber.
- Address binding: the **full classical segment** (version + spend +
  view + ek_bind_tag) so a signature cannot be transplanted between
  addresses sharing a spend key, and the ek binding rides the preimage.
  Fork to settle: full canonical address string instead? (Network
  segregation is already explicit via `network_id`; the segment is the
  byte-stable form.)
- `H(message)` not raw message: fixed-size preimage, no
  length-extension shape, streaming-friendly for large messages. House
  hash per rule 30 alignment (Blake2b-512 is the derivation-side
  precedent, cSHAKE256 the binding-side; pick one and pin it).

### SM-DQ-4 — The wallet-level ML-DSA identity

New domain-separated derivation from the wallet seed (fresh domain
string, reserved index) via §1.3's `keygen_from_seed`. Pins to ratify:
mnemonic-recoverable (no new backup material); never reused by any
other surface (per-output keys stay per-output; multisig identities
stay theirs); derived on demand and zeroized (rules 35/36) rather than
persisted — the wallet file schema does not change.

### SM-DQ-5 — Wire format

Versioned, armored, append-only:
`ShekylMsgSigV1` + base64(canonical bytes), canonical bytes being a
length-checked layout in the §1.4 house style (version, scheme,
mode, vk, ed25519 sig, ml_dsa sig). Reject-don't-truncate on decode,
explicit DoS ceiling (the decoder sees attacker-supplied strings via
`verify_message`). The multi-KB size is stated in user-facing docs, not
hidden.

**Pass-1 verification finding — the Bech32m precedent does not
transfer at this size.** The WI-RPC-3 proof strings are Bech32m
(`shekyltxproof` / `shekylreserveproof`,
`shekyl-engine-core/src/engine/proofs.rs`), and Bech32m framing was
proposed for the signature blob on that precedent. But BIP-350's
checksum guarantees hold only to 1023 characters, and our own address
code *enforces* that bound (`address.rs` compile-time assert splits the
ML-KEM ek across two PQC segments to stay under it). A 5.3–7.9 KB
signature blob is ~8.5–12.7k Bech32m characters — far past the bound
the codebase itself treats as hard. Fork to settle here: (a)
multi-segment Bech32m in the address's own split style, (b) base64
with an explicit outer checksum, or (c) single Bech32m accepting
degraded checksum properties — (c) contradicts the in-tree discipline
and should be rejected with that reason recorded.

### SM-DQ-6 — API / RPC / CLI contract

- `Engine::sign_message` needs the open wallet (secrets). But
  **verification needs no secrets**: `verify_message` should be a pure
  function (crypto crate), callable by the RPC *without an open wallet*
  and by the CLI offline. Contract question to ratify: does RPC
  `verify_message` require an open wallet session (tenant model) or is
  it a session-less method? Lead: session-less — refusing to verify
  because no wallet is open is a rule-82 lie about a public operation.
- Errors in the reserved `-29800..-29899` band: malformed signature
  string vs. well-formed-but-not-verifying are different codes (the
  `get_transfer_by_id` precedent: formatting problems are `-32602`-class,
  semantic failure is its own honest code).
- Idempotent, deterministic signatures? ML-DSA-65 signing is
  randomized by default ("hedged"); deterministic mode exists. Fork:
  hedged (side-channel margin, fips204 default) vs. deterministic
  (reproducible outputs). Lead: hedged — reproducibility of the
  *signature bytes* is not a contract anyone needs, and hedging is the
  conservative side-channel posture.

### SM-DQ-7 — The commitment shape, and who owns the address decision (pass 1)

Proposed for ratification, algorithm-independent:

- Address v2 adds a 32-byte
  `sig_bind_tag = cSHAKE256("shekyl/sig-bind-v1", alg_id ‖ pk)[..32]`.
- The signature blob carries `alg_id ‖ pk ‖ σ_pq ‖ σ_ed25519`; the
  verifier recomputes the tag from the carried `alg_id ‖ pk` and
  matches it against the address. A future scheme is a new `alg_id`,
  not an address version bump.
- **32 bytes, deliberately not the ek_bind_tag's 16.** The 16-byte tag
  does a *detection* job — catching spliced or corrupted segments,
  where the attacker must additionally produce a usable address. The
  signing-key commitment does a *binding security* job: anyone who
  finds any `alg_id ‖ pk` preimage of the tag can sign as the address
  holder. 16 bytes is 128-bit classical / ~64-bit Grover preimage
  resistance against a grindable target — not a margin. The precedent's
  *mechanism* transfers; its *length* must not, and this paragraph is
  the recorded reason.
- **Escalation: A2 surfaced the address-version decision; it does not
  own it.** A v2 address format touches the GUI, URI handling, the
  address book, multisig address exchange, and every future exchange
  integration — and it is genesis-frozen wire —
  the class ranked first by proximity to the genesis format freeze.
  The commitment *shape* above is
  what this round sends to the genesis lane for ratification; SM-DQ-8
  (algorithm) deliberately does not travel with it. Until the genesis
  lane rules, no implementation PR freezes anything.

### SM-DQ-8 — The algorithm, chosen second (pass 1)

Constructions priced (sizes from the pinned `fips204` crate where it
exists; SLH-DSA figures are FIPS 205 nominal pending a crate pin —
`fips205` is **not** in the workspace, so choosing (B) opens a rule-17
dependency round):

| | Address cost | Signature blob | Assumption | Status |
|---|---|---|---|---|
| (A) ML-DSA-65 + Ed25519, key committed | +32 B tag | pk 1952 + σ 3309 + 64 ≈ 5.3 KB | module lattice + EC | FIPS 204 final; `fips204 0.4.6` pinned, sizes verified |
| (B) SLH-DSA-128s + Ed25519 | +32 B tag (pk itself is 32 B) | σ ≈ 7856 + 64 ≈ 7.9 KB | hash functions only | FIPS 205 final; no crate pinned |
| (C) Agile commitment, algorithm deferred | +32 B tag | scheme-dependent | — | the SM-DQ-7 shape; composes with (A) or (B) |

Two pulls, both real and both satisfied by (C)'s shape:

- **Consistency pulls toward ML-DSA.** ML-DSA-65 is already
  load-bearing on-chain — per-input hybrid auth over
  `prefix ‖ ct_base ‖ H(prunable)` with keys from
  `OutputSecrets.ml_dsa_seed`
  (`shekyl-wire/src/transaction.rs`, verified) — so (A) is a second
  use of an audited path, not a first.
- **Diversification pulls toward SLH-DSA, and message signing is the
  surface where its costs don't bite.** The transaction path chose
  ML-DSA under per-block verification pressure; message signing is
  low-frequency, off-chain, human-initiated, and consumes no block
  space. SLH-DSA rests on hash assumptions alone — immune to the
  lattice-cryptanalysis risk that motivated NIST's diversification
  onramp — at the cost of a 7.9 KB signature and slow signing. It
  would be a mistake to inherit ML-DSA here *merely because* the tx
  path uses it; that reasoning does not transfer.

No lead is declared for SM-DQ-8 in this pass: the point of SM-DQ-7's
shape is that this decision can stay open without blocking anything,
and the honest price of (B) includes a dependency round.

## §4 Pre-committed test obligations (whatever SM-DQ-1 resolves to)

- Pinned KATs for preimage construction and full sign/verify vectors
  (rule 30: fixed seed → fixed vk → pinned signature bytes under
  deterministic test mode, plus verify-side vectors that must never
  rot).
- Tamper battery: every field of the armored format flipped
  independently → reject (version, scheme, mode, vk, each half,
  network, address binding, message).
- Cross-half battery: classical-valid/PQ-invalid and the inverse both
  reject (the hybrid contract is AND, never OR — §1.4's tx precedent).
- Decode DoS: oversized strings, truncations, non-base64 — bounded cost
  refusals.
- Round-trip through RPC + CLI including the no-open-wallet verify path
  (SM-DQ-6).

## §5 Proposed PR decomposition

- **PR-SM-1** — crypto + engine: preimage/domain, wallet-level identity
  derivation, sign/verify functions, armored codec, KATs + batteries.
- **PR-SM-2** — projection: RPC methods (band allocation), CLI
  un-stubbing (parity-matrix rows), OpenAPI, user-facing docs
  (including the size statement), FOLLOWUPS/INDEX closure of the 2c
  residue.

Small enough to merge if PR-SM-1 lands clean; split pre-committed only
if review load argues for it.

**Pass-1 scope revision.** This is no longer a one-day spec: SM-DQ-7's
commitment shape is a genesis-frozen wire decision owned by the genesis
lane, and PR-SM-1 cannot start until it is ratified there. The
sequencing is the good news — the shape freezes now while SM-DQ-8
stays open as long as wanted. Revised order: (0) genesis lane ratifies
the SM-DQ-7 shape (and the address-v2 carrier), (1) PR-SM-1
crypto+engine against the ratified shape with the algorithm behind
`alg_id`, (2) PR-SM-2 projection.

## §6 Pass record

**PASS 1 (2026-08-08).** Review pass folded with source verification:

- The §2 impasse dissolved by the commit-not-carry asymmetry (full ek
  forced into the address because encapsulation targets the key; a
  signature vk needs only a 32-byte commitment). Verified in-tree
  precedent: `ek_bind_tag` (`address.rs:180-187`).
- Round-0 SM-DQ-1 lead (b) hybrid-vk-certified **superseded on the
  record** by the agile commitment (SM-DQ-7) + decoupled algorithm
  (SM-DQ-8); pre-genesis, the address format is not yet frozen and the
  round-0 framing against an immutable v1 was too narrow.
- BIP-360 history verified against the current changelog — the
  round-0 fold initially carried secondhand specifics (SQIsign at
  v0.6.0; "all PQ stripped" at v0.8.0) that the fetch corrected
  (XMSS→Dilithium v0.3.0; SLH-DSA removed v0.6.0; three→two v0.8.0;
  current form = 32-byte Merkle-root commitment, PQ signatures
  deferred to a separate proposal). The transferable lesson is
  unchanged and the record carries the verified telling.
- Nested combiner + registered dual-duty label adopted into SM-DQ-1/3;
  literature anchors verified at abstract level: Bindel–Hale ePrint
  2023/423 (property taxonomy; parallel/concatenation achieves few of
  the goals), ePrint 2026/1086 (machine-checked EUF-CMA, hybrid
  Fiat–Shamir, symmetric either-component bounds), NIST onramp round 3
  announced 2026-05-14. Foundational: ePrint 2017/460; the 2022/1225
  label construction.
- New verification findings this pass: `fips205` not in workspace
  (rule-17 round if SLH-DSA chosen); Bech32m framing precedent does
  not transfer past 1023 chars (SM-DQ-5 re-posed with the in-tree
  assert as the reason); EK_BIND_TAG_LEN=16 must not transfer
  (detection vs binding — SM-DQ-7).
- Escalation recorded: the address-v2 / commitment-shape decision goes
  to the genesis lane; A2 implements against its ruling.

