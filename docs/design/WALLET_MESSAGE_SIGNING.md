# Wallet Message Signing (A2 / rewrite-plan 2c residue) — Design Round

**Status: ROUND 0 OPEN (2026-08-08); PASSES 1–2 FOLDED (2026-08-08).** Poses
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
  future modes append, never renumber. *(A view-tier mode was named
  here through pass 2 and deleted at SM-R-3 ratification — see the
  ruling: naming it implied a plan that does not exist.)*
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

### SM-DQ-4 — The wallet-level PQ signing identity

New domain-separated derivation from the wallet seed (fresh domain
string, reserved index) via §1.3's `keygen_from_seed`. Pins to ratify:
mnemonic-recoverable (no new backup material); never reused by any
other surface (per-output keys stay per-output; multisig identities
stay theirs); derived on demand and zeroized (rules 35/36) rather than
persisted — the wallet file schema does not change.

**Pass-2 amendment — derivability holds for either SM-DQ-8 algorithm,
and statelessness is load-bearing, not a footnote.**

- *Derivability.* SLH-DSA keygen is fully deterministic from seed
  material: FIPS 205 separates randomized `slh_keygen` from pure
  `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` (Algorithm 18), and
  the `fips205` crate **exports** that shape as
  `KeyGen::keygen_with_seeds(sk_seed, sk_prf, pk_seed)` (verified in
  crate source, `traits.rs`). The wallet branch is one more HKDF arm:
  `master seed ──HKDF("shekyl/slh-dsa-seed-v1")──▶ 3n bytes ──▶
  keygen_with_seeds`. This is *purer* than the in-tree ML-DSA
  precedent, which routes a seed through a ChaCha20 RNG shim into
  `try_keygen_with_rng` (`derivation.rs:40-52`, verified) — the SLH
  path has no sampling loop and no RNG indirection in the caller.
- *Statelessness.* SLH-DSA carries no signing state. The stateful
  hash-based schemes (XMSS/LMS, SP 800-208) are **excluded by
  construction, recorded here**: their security requires never reusing
  a one-time key index, and that state lives outside the seed — a
  wallet restored from its mnemonic cannot know which indices were
  consumed, so restore-from-seed becomes a key-disclosure event on the
  next signature. Shekyl just ratified seed-phrase custody as the
  entire cold-storage story (A4 decision); any signing scheme whose
  safety does not survive seed-restore contradicts it. SLH-DSA
  restores completely from the seed, which is exactly the property the
  rest of the wallet already guarantees.

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
- **Pass-2 amendment — the pk-inline variant, and the tension it
  creates.** At category parity SLH-DSA-192s's public key is **48
  bytes** — small enough to go in the address *literally*, as a fourth
  field. That eliminates the commitment machinery entirely: no
  key-carried-in-signature, no tag-strength question, no `alg_id`
  registry to get right — verification takes the address at face
  value. But it must be priced against pass 1's own BIP-360 lesson:
  an inline pk **freezes the algorithm** into the genesis address,
  which is exactly what the commitment shape exists to avoid — a
  future scheme becomes an address-version bump instead of a new
  `alg_id`. Two counterweights, on the record: (i) the address
  already freezes algorithms literally (Ed25519 keys, an ML-KEM-768
  ek) — algorithm-freezing per se is not novel for this format; (ii)
  SLH-DSA is the conservative *endpoint* of the diversification
  argument — the scheme one flees TO under lattice cryptanalysis, not
  FROM — so the agility being given up is agility we are least likely
  to need. Neither counterweight is decisive; the fork is now
  explicitly coupled to SM-DQ-8: **(A) requires the commitment shape;
  (B) makes it optional.**
- **Escalation: A2 surfaced the address-version decision; it does not
  own it.** A v2 address format touches the GUI, URI handling, the
  address book, multisig address exchange, and every future exchange
  integration — and it is genesis-frozen wire —
  the class ranked first by proximity to the genesis format freeze.
  The commitment *shape* above is
  what this round sends to the genesis lane for ratification; SM-DQ-8
  (algorithm) deliberately does not travel with it. Until the genesis
  lane rules, no implementation PR freezes anything. **Pass-2 note:**
  if SM-DQ-8 lands on (B) pk-inline, the genesis-lane item simplifies
  from "ratify a commitment scheme" to "ratify a fourth address field"
  — a smaller thing to get wrong permanently — but it remains an
  address-format decision and the escalation stands either way. The
  Pi 4 measurement (SM-DQ-8's prerequisite) should therefore land
  before the genesis-lane item is drafted, so the lane rules on the
  real fork, not both hypotheticals. **Measurement landed 2026-08-08
  (SM-DQ-8 table); genesis-lane item DRAFTED 2026-08-08** —
  `FOLLOWUPS.md` §V3.0 "GENESIS ADDRESS FORMAT: PQ signing anchor
  decision", carried on the pre-launch format-freeze row in
  `RELEASE_CHECKLIST.md`.

### SM-DQ-8 — The algorithm, chosen second (pass 1)

Constructions priced. **Pass-2 category correction:** the stack is NIST
category 3 throughout (ML-KEM-768, ML-DSA-65), so the SLH comparison at
matched security is **SLH-DSA-192s**, not the 128s the pass-1 table
carried. All non-Ed25519 sizes below are read from crate constants and
confirmed by execution (scratch bench, 2026-08-08 — see the measured
row):

| | Address cost | Signature blob | Assumption | Status |
|---|---|---|---|---|
| (A) ML-DSA-65 + Ed25519, key committed | +32 B tag | pk 1952 + σ 3309 + 64 ≈ 5.3 KB | module lattice + EC | FIPS 204 final; `fips204 0.4.6` pinned, sizes verified |
| (B) SLH-DSA-192s + Ed25519, pk inline | +48 B (the pk itself) | σ 16224 + 64 ≈ 16.3 KB | hash functions only | FIPS 205 final; `fips205` NOT pinned (resolves 0.4.1) |
| (C) Agile commitment, algorithm deferred | +32 B tag | scheme-dependent | — | the SM-DQ-7 shape; composes with (A); (B) can bypass it (see SM-DQ-7 pass-2 amendment) |

**Measured — including on the Pi 4 provisioning floor (prerequisite
DISCHARGED 2026-08-08).** Same binary both hosts (release, hedged
signing; averages over 3 sign / 3 keygen / 20 verify iterations; Pi =
Raspberry Pi 4 Model B Rev 1.4, aarch64, the rule-76 floor):

| | keygen | sign | verify | sig bytes |
|---|---|---|---|---|
| SLH-192s — Pi 4 | 415 ms | **3.83 s** | 3.4 ms | 16,224 |
| SLH-192f — Pi 4 | 6.5 ms | **171 ms** | 9.4 ms | 35,664 |
| ML-DSA-65 — Pi 4 | 0.69 ms | 1.77 ms | 0.45 ms | 3,309 |
| SLH-192s — x86 i9 | 47 ms | 517 ms | 0.47 ms | 16,224 |
| SLH-192f — x86 i9 | 0.73 ms | 21.9 ms | 1.2 ms | 35,664 |
| ML-DSA-65 — x86 i9 | 0.18 ms | 0.40 ms | 0.11 ms | 3,309 |

What the floor numbers say, without deciding for the round:

- **192s on the floor is ~4.3 s per signing session** (derive-on-demand
  keygen 415 ms + sign 3.83 s) — human-noticeable, plausibly
  acceptable for a low-frequency, deliberate operation, and honest to
  disclose in the UX rather than hide.
- **192f inverts the trade decisively on latency**: 171 ms sign +
  6.5 ms keygen is imperceptible even on the floor — at the cost of a
  **35.7 KB** signature (2.2× the s-variant, ~6.7× construction (A)).
  The x86→Pi scaling factor measured ~7.4×, not the 10–20× a
  projection would have guessed — which is why rule 76 forbids
  guessing.
- Verification is trivial everywhere (≤ 9.4 ms worst case), so the
  verifier side constrains nothing.

SM-DQ-8's decision inputs are now complete: (A) 5.3 KB / sub-ms,
(B-s) 16.3 KB / ~4 s-on-floor, (B-f) 35.7 KB / ~0.2 s-on-floor, all
under the same hash-only-vs-lattice assumption split and the same
dependency terms.

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
  onramp — at the cost of a 16 KB signature and measurably slow
  signing (~0.5 s x86, Pi 4 pending). It would be a mistake to inherit
  ML-DSA here *merely because* the tx path uses it; that reasoning
  does not transfer.

**Dependency (pass 2, audited at source).** Choosing (B) adds
`fips205` — a rule-17 decision, and the audit already has its first
finding: the crate's deterministic-keygen path
(`KeyGen::keygen_with_seeds`) is implemented over the **same
`DummyRng` pattern that forced the `fips203` exact-pin**
(`fill_bytes = unimplemented!()`; seeds served via `try_fill_bytes`,
loud panic on over-draw or length mismatch — verified in
`fips205-0.4.1/src/traits.rs`). Same maintainer (integritychain) as
the pinned `fips203`/`fips204`. If adopted: exact-pin with the same
comment rationale, and the KAT battery pins `keygen_with_seeds`
end-to-end so an upstream RNG-path refactor cannot move underneath us.

No lead is declared for SM-DQ-8 in this pass: what blocks ruling is
the Pi 4 measurement, and the honest price of (B) includes the
dependency round above.

## §4 Pre-committed test obligations (whatever SM-DQ-1 resolves to)

- Pinned KATs for preimage construction and full sign/verify vectors
  (rule 30: fixed seed → fixed vk → pinned signature bytes under
  deterministic test mode, plus verify-side vectors that must never
  rot). **Including the R3-a `ctx` pin:** a vector that fails if any
  non-empty FIPS 204/205 context string is supplied on either half.
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

**PASS 2 (2026-08-08).** Review pass folded with source verification
and a measurement:

- Category correction (reviewer's own): the pass-1 table quoted
  SLH-DSA-**128s**; the stack is category 3 throughout, so the honest
  comparison is **192s** — pk 48 B, σ 16224 B, both read from crate
  constants and confirmed by execution.
- Derivability verified *stronger than claimed*: the reviewer expected
  `slh_keygen_internal` purity from the spec; the `fips205` crate
  **exports** the 3n-seed shape (`KeyGen::keygen_with_seeds`), so the
  wallet branch is one HKDF arm plus a library call — purer than the
  in-tree ML-DSA seeded-RNG shim (`derivation.rs:40-52`).
- Statelessness folded as load-bearing: XMSS/LMS (SP 800-208) excluded
  by construction — restore-from-seed cannot recover one-time-key
  state, so a stateful scheme makes mnemonic restore a key-disclosure
  event, contradicting the ratified seed-custody cold-storage story.
- Measured on the dev box (i9, release): SLH-192s sign ≈ 519 ms /
  verify ≈ 0.45 ms vs ML-DSA-65 sign ≈ 0.27 ms / verify ≈ 0.11 ms.
  **Pi 4 floor measurement is the named prerequisite** before SM-DQ-8
  rules (rule 76: no deciding on scaled projections).
- Dependency audit opened early: `fips205`'s deterministic keygen uses
  the same `DummyRng` pattern that forced the `fips203` exact-pin
  (verified in `fips205-0.4.1/src/traits.rs`); adoption terms recorded
  in SM-DQ-8.
- SM-DQ-7 gains the pk-inline variant and its recorded tension with
  the pass-1 BIP-360 lesson; the SM-DQ-7/SM-DQ-8 coupling is now
  explicit ((A) requires the commitment shape, (B) makes it optional),
  and the genesis-lane item waits for the Pi measurement so the lane
  rules on the real fork.

**PASS 2 ADDENDUM (2026-08-08) — the Pi 4 floor measurement, run and
folded.** Cross-compiled the scratch bench (aarch64, same binary both
hosts) and ran it on the floor hardware (Pi 4 Model B Rev 1.4):
SLH-192s sign **3.83 s** / keygen 415 ms; SLH-192f sign **171 ms** /
sig 35,664 B; ML-DSA-65 sign 1.77 ms. Measured x86→Pi scaling ≈ 7.4×
(a projection would have guessed 10–20× — rule 76 vindicated in both
directions). The named prerequisite is DISCHARGED; SM-DQ-8's decision
inputs are complete and the genesis-lane item is draftable.

## §7 Proposed rulings — PENDING RATIFICATION (drafted 2026-08-08)

Drafted for ratification in one pass; each carries its rule-21 clause
where it rejects something. SM-DQ-1's combiner (nested, dual-duty
label) and SM-DQ-7's escalation are already binding-shaped above and
are not re-proposed here.

**SM-R-2 (rules SM-DQ-2) — interactive KEM ownership proof: REJECT
now. RATIFIED 2026-08-08, with two amendments folded.** Reopen when a
named consumer surface requires **liveness / non-transferability** —
the criterion is the freshness requirement itself, not any particular
consumer class (exchange integration specs, proof-of-reserves
attestations, custody audits, and challenge-response login are
illustrations, not the boundary). **Conditionality amendment (the
ratification's substantive change):** this rejection is recorded as
**conditional on the genesis lane not ruling fork (iii)**. Under
fork (iii) — no PQ signing anchor, address frozen without one —
Shekyl would have no PQ ownership proof of any kind, permanently, and
no later round could fix it; that is not a reopening trigger for
R-2, it is a **precondition on fork (iii) itself**: (iii) is
admissible only if the interactive proof is simultaneously committed
to. The cost is priced where the decision is made — the genesis-lane
item's fork (iii) carries it — rather than referenced forward from a
document the lane may not read.

**SM-R-3 (rules SM-DQ-3) — preimage, domain, and nesting order.
RATIFIED 2026-08-08, with three findings folded and the nesting
rationale strengthened.**
- Hash: **cSHAKE256 throughout** — this is a binding job, and the
  binding-side house precedent is cSHAKE (`ek_bind`, and the tag in
  the SM-DQ-7 shape); the derivation-side Blake2b precedent does not
  apply. *(Ratified as drafted.)*
- `preimage = cSHAKE256("shekyl/msg-sign-v1", sig_format_version ‖
  network_id ‖ mode ‖ len(classical_segment) ‖ classical_segment ‖
  cSHAKE256("shekyl/msg-hash-v1", message))`, where:
  - **`sig_format_version`, renamed from `version` (R3-b):** the
    classical segment already *contains* the address version
    (`SPEND_OFFSET = VERSION_LEN`, `address.rs`), so the draft had two
    fields both spelled "version" — the outer one is the
    message-signing format version and now says so.
  - **`len(classical_segment)` length prefix (R3-b, second half):**
    with fork (ii) the segment is variable-length across address
    versions (v1 vs v2 with an inline SLH key). Concatenation would
    stay unambiguous anyway — the in-segment address version
    determines the length, and the message-hash tail is fixed-width —
    but both of those are load-bearing-by-accident properties.
    A two-byte LE length prefix makes the framing unambiguous by
    construction instead of by coincidence.
  - `classical_segment` is the **full bound form as ruled by the
    genesis lane** (the byte layout is exactly what SM-DQ-7 freezes;
    this is why PR-SM-1 blocks on that ruling); `mode = 0x01`
    spend-tier, future modes append, never renumber.
- **R3-c — the view-tier forward reference is DELETED, not
  softened.** The mode byte's append-only discipline is kept — that
  is cheap, real forward compatibility. But naming view-tier implied
  a plan, and there isn't one: under the ratified design the address
  commits to one master-seed-derived key and a view-only wallet has
  no master seed, so view-tier is structurally unbuildable without an
  address-format change — reserving a name for that *inside the
  freeze window* is worse than not reserving it, and it wore the
  shape of a deferral with no rule-21 criteria, which this project
  forbids. If a view-tier consumer ever materializes, the honest form
  is a second signing key committed in the address — decided while
  v2's layout is open, or never.
- **R3-a — the FIPS 204/205 `ctx` parameter is PINNED EMPTY
  (`ctx = ""`), by ruling, not by convention.** All domain separation
  lives inside the preimage's cSHAKE customization strings; the
  signing interfaces' context parameter must therefore be the empty
  string on both halves. "Should be empty" is not enough — an
  implementation passing the domain string as `ctx` would produce
  signatures that fail against one passing `""`, silently forking the
  format. A KAT pins it: the vector must fail if any non-empty
  context is supplied (same discipline as the label-tag KATs).
- Nesting order: **PQ inner, Ed25519 outer** —
  `σ_pq = PQ.Sign(preimage)`, `σ_ed = Ed25519.Sign(preimage ‖ σ_pq)`.
  **Rationale strengthened at ratification — the complete argument,
  not the half the draft gave:** unforgeability is order-independent
  (a forger needs both halves over the new preimage either way; the
  either-component property matches ePrint 2026/1086 in both orders).
  **Separability is where order matters, and it is asymmetric: the
  inner component remains a standalone-verifiable artifact; the outer
  does not.** With PQ inner, stripping to one signature leaves
  σ_pq — degrading to hash-based security, the *strong* half — and an
  Ed25519-only lazy verifier **cannot verify at all**, because σ_ed
  does not check out over the preimage alone: the lazy path is forced
  through the PQ dependency. With Ed inner, the lazy path silently
  yields a *working classical-only verifier* — passes every
  happy-path test, provides no post-quantum protection, the worst
  outcome available. **We chose the order whose degenerate
  implementation fails to verify over the one whose degenerate
  implementation verifies insecurely.** This paragraph exists to
  foreclose flipping the order later for convenience.
- Both domain strings register in the crypto crate's domain inventory
  beside `shekyl/ek-bind-v1`, collision-checked by test. *(Ratified
  as drafted.)*

**SM-R-4 (rules SM-DQ-4) — the signing identity. RATIFIED
2026-08-08, with the algorithm-generic framing dropped and two pins
added.**

- **The literal domain, not the template.** The draft's
  `"shekyl/msg-sign-seed-<alg>-v1"` was written before SM-R-8
  ratified; the scheme has won, and a parameterized domain is a
  template, not a domain — rule 30's inventory collision-checks
  literals. Pinned: **`"shekyl/msg-sign-seed-slh-dsa-192s-v1"`**. The
  ML-DSA arm (the seeded-ChaCha20 shim) is dropped rather than kept as
  a live branch nothing reaches; if ML-DSA ever returns it is a new
  domain string and a new address version anyway, since the address
  commits to the key.
- **R4-a — the split is 72 bytes, written as a literal because the
  reflex is wrong.** SLH-DSA-192s has `n = 24` (not the 32 a
  category-3 reflex suggests), so the derivation is one HKDF expand of
  **72 bytes, sliced in order into `SK.seed ‖ SK.prf ‖ PK.seed` at 24
  bytes each** — a single expand sliced into thirds, ruled explicitly
  because three separate expands with distinct info strings would
  produce different (equally valid-looking) keys and only one layout
  can be the spec. A wrong split silently produces a
  valid-but-different keypair; the pin is a KAT from a fixed master
  seed to a fixed public key.
- **R4-b — derive-on-demand's costs, stated rather than discovered.**
  (1) Keygen runs on every signing call (the top-layer XMSS tree
  build, unamortized by design). The measurement already covers this:
  the Pi 4 bench timed keygen (415 ms) and sign (3.83 s) as separate
  phases, and the ruling's "~4.3 s per signing session" figure is
  their composition — sign-only is 3.83 s, and the HKDF derive adds
  microseconds. The UX argument rests on the composed figure and
  said so. (2) Zeroization of an SLH key is not scalar-shaped:
  `SK.seed`/`SK.prf` are the secrets, `PK.seed`/`PK.root` public.
  **Verified at the crate (2026-08-08): `fips205-0.4.1` derives
  `Zeroize + ZeroizeOnDrop` on `PrivateKey` and its inner types**
  (`src/types.rs`, `zeroize_derive` feature), so the key type wipes
  on drop; whether intermediate WOTS+ state inside keygen/sign is
  wiped is a crate-internals property the caller cannot control —
  carried as a named item of the rule-17 dependency audit, to be
  answered before PR-SM-1, not assumed.
- Ratified as drafted: mnemonic-recoverable with no new backup
  material (the A4 seed-custody story holds for this surface); never
  reused by any other surface (per-output and multisig identities
  stay theirs — the property that makes the domain inventory
  meaningful); **no wallet-file schema change**.

**SM-R-5 (rules SM-DQ-5) — armoring.** Single-line
`shekylmsgsig1.<base64url(canonical bytes)>`; canonical bytes are the
length-checked house layout (version ‖ scheme ‖ mode ‖ [alg_id ‖ pk —
present iff the genesis lane rules fork (i)] ‖ σ_pq ‖ σ_ed) with a
**4-byte cSHAKE256 checksum trailer** — not for security (verification
is the integrity check) but for rule-82 error honesty: decode
distinguishes "this paste is corrupted" from "this signature is not
from that address". Hard decode ceiling 64 KB (covers B-f's 35.7 KB
with margin; attacker-supplied input via `verify_message`).
**Multi-segment Bech32m REJECTED** with the reason recorded: BIP-350
checksum guarantees end at 1023 chars, our address code enforces that
bound, and a 16–36 KB blob would need ~26–56 segments — an interface
nobody can paste correctly. Reopen only if a transport emerges that
requires Bech32m framing end-to-end.

**SM-R-6 (rules SM-DQ-6) — API contract.** `verify_message` is
**session-less** (pure function in the crypto crate; RPC method
callable with no wallet open; CLI `verify` works offline) — refusing a
public operation for lack of a wallet session is a rule-82 lie.
`sign_message` requires the open wallet. Errors: malformed signature
string / bad address = `-32602` (shape-first, the `get_transfer_by_id`
precedent); well-formed signature that does not verify = its own
honest code in the `-29800` band, with the checksum separating
corruption from mismatch in the error detail. Signing is **hedged**
(fips204/205 default; side-channel margin; signature-byte
reproducibility is not a contract anyone needs).

**SM-R-8 (rules SM-DQ-8) — the algorithm: LEAD = (B-s)
SLH-DSA-192s, pk-inline.** The reasoning, stated for ratification
rather than assumed:

- *Assumption diversity is the mission-hierarchy argument.* The chain
  is already triple-exposed to structured lattices (ML-KEM-768
  addresses, ML-DSA-65 tx auth, ML-DSA-65 archival identities). The
  one new frozen surface where we can buy hash-only conservatism —
  the assumption class NIST's own diversification onramp exists to
  hedge toward — is this one, and it costs no block space.
- *The measured floor costs are acceptable for this surface.* ~4.3 s
  per signing session on a Pi 4 for a deliberate, low-frequency,
  human-initiated operation, disclosed in the UX; verification —
  the side third parties run — is 3.4 ms. If UX testing before the
  freeze finds 4 s intolerable, **192f is the pre-priced fallback**
  (171 ms floor signing at 35.7 KB): flipping s→f before freeze is a
  parameter-set change, not a redesign.
- *16.3 KB vs 5.3 KB does not change the interface class.* Both are
  paste-a-blob, neither is read-over-the-phone; size stopped being
  the discriminator when the classical-only option died in pass 1.
- *pk-inline (fork ii) deletes permanent machinery.* No `alg_id`
  registry to govern forever, no tag-strength argument, no
  key-in-blob — the smallest possible genesis-frozen surface, which
  is the right direction for a format that must outlast the team.
- *The dependency terms are pre-audited.* `fips205` exact-pin with
  the fips203 DummyRng rationale; KATs pin `keygen_with_seeds`
  end-to-end (§SM-DQ-8 pass-2 audit note).

Rule-21 clause if ratified: reopen the algorithm (as a new address
version, accepted cost of fork (ii)) only on cryptanalytic weakening
of SHA-2/SHAKE at the SLH-DSA security argument level, or a NIST
onramp standard offering ≥4× signature-size reduction at equal
assumption conservatism — not on lattice-scheme improvements, which
this choice deliberately declines to track.

**Ratification order.** SM-R-2..6 are independent of the genesis
lane. SM-R-8 and the genesis lane's fork are coupled: ratifying
SM-R-8 (B-s) selects fork (ii); rejecting it in favor of (A) selects
fork (i) and re-poses SM-R-5's `alg_id ‖ pk` blob fields as
mandatory.

