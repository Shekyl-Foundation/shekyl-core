# `FcmpMembershipOnly` — spend authority + tree membership, no key image

**Status:** implemented 2026-06-12 (`feat/fcmp-membership-only`). Consumes the
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §7.2 verify-API pin
(2026-06-12) and closes the §12 "line-441 gap" (the missing sibling API at the
composition layer of the FCMP++ crate, symbol anchor `FcmpPlusPlus`).

**First consumer:** the emission vin
([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §5.3, §7.1 step 6). The
FFI entry point, C++ call site, vin deserializer, and emission KAT vectors are
deferred to that PR — see §9 (Carries).

All code citations in this document pin **symbol names**; line numbers are
never load-bearing.

---

## 1. Statement

The prover demonstrates, for each input `i` in an ordered set, that:

1. **Spend authority:** the prover knows `(x, y~)` opening the rerandomized
   output key `O~ᵢ = x·G + y~·T`; and
2. **Tree membership:** the input tuple `(O~ᵢ, I~ᵢ, Rᵢ, C~ᵢ)` is a
   rerandomization of a leaf on the FCMP++ curve tree under the supplied
   `TreeRoot`, with the leaf's `H(pqc_pk)` extra scalar bound in-circuit;

**without** producing the key image `L = x·I`. No linking tag of any kind is
published; nothing is consumed from or checked against the spent set.

Per §7.2, the statement is **spend authority + membership only**. The "bond
posture" conjunct in §7.2's prose (`bonded_total_atomic == bond_floor(holdings)`)
is **not** part of this proof — see §8.1.

## 2. Construction

### 2.1 Option B — minimal subtraction

`FcmpPlusPlus` composes two legs per input (symbol: `FcmpPlusPlus::verify`):

- **SAL** (`SpendAuthAndLinkability::verify`, Ed25519 batch): four batched
  verification statements — BP+, the `O~` GSP (`R_O` leg), the `P'` GSP, and
  the `L` GSP.
- **`Fcmp`** tree membership (`Fcmp::verify`, Selene/Helios batches): never
  touches the key image.

Inside SAL, the `R_O` leg alone is a self-contained Schnorr proof of knowledge
of the `(x, y~)` opening of `O~` over `(G, T)` — that alone is spend
authority. The BP+, `P'`, and `L` legs exist solely to bind the key image
`L = x·I` to the same `x`. The subtraction is therefore precise:

- **Kept:** the `R_O` leg (`R_O` point + `s_alpha`, `s_y` responses,
  96 bytes/input) and the entire `Fcmp` leg unchanged, including the
  `H(pqc_pk)` extra-leaf-scalar binding.
- **Dropped:** `L` and the BP+/`P'`/`L` legs (`P, A, B, R_P, R_L` and
  `s_beta, s_delta, s_z, s_r_p`).

**Option A rejected** (keep BP+/`P'`, drop only `L`/`R_L`): dead proof
machinery — statements about `x·r_i` that serve nothing without `L` — is
unused audit surface per rule 15, at 4× the leg size.

Soundness of the isolated sub-proof is **not** inherited from the Cypher-Stack
review of the full composition; the composition was reviewed as a whole. The
reduction that re-establishes it stands alone in §5.

### 2.2 Sibling type, not mode flag

§7.2 floated "per-input mode flag or sibling type." `FcmpMembershipOnly` is a
**sibling type** because that makes cross-type rejection a compile-time
property of the type system rather than a runtime flag a code path can forget
to check or an attacker can flip. Corollary: the type guarantee evaporates at
the byte/FFI seam — which is exactly why the transcript DST (§4), not the
type, is the load-bearing guard there, and why the cross-type test targets the
deserialization boundary (§9, FFI-seam carry).

## 3. Wire format

```text
MembershipSpendAuth (96 bytes):
  R_O      32 B   compressed Ed25519 point
  s_alpha  32 B   scalar
  s_y      32 B   scalar

FcmpMembershipOnly (per input: 192 B, plus the Fcmp leg):
  for each input i:
    O~ᵢ    32 B   ┐
    I~ᵢ    32 B   │ Input::write_partial (C~ travels as the pseudo-out,
    Rᵢ     32 B   ┘ exactly as in FcmpPlusPlus::write)
    MembershipSpendAuthᵢ  96 B
  Fcmp     Fcmp::proof_size(inputs, layers) bytes (unchanged)
```

`FcmpMembershipOnly::proof_size(inputs, layers) =
inputs × 192 + Fcmp::proof_size(inputs, layers)` — versus
`inputs × 480 + Fcmp::proof_size(...)` for `FcmpPlusPlus` (whose SAL leg is
384 B/input and whose input encoding is identical).

`read` mirrors `FcmpPlusPlus::read`: pseudo-outs and layer count are supplied
by the caller; the input count is the pseudo-out count.

## 4. Transcripts and domain separation

### 4.1 Fixed-width 64-byte type tags

Both SAL-family challenge transcripts open with a **64-byte zero-padded
ASCII type tag** as the first field, via one shared helper
(symbol: `sal_dst`, `sal/mod.rs`):

| Path | Label | Label length |
|---|---|---|
| Full SAL | `Shekyl FCMP++ SAL full v1` | 25 B |
| Membership-only | `Shekyl FCMP++ SAL membership-only v1` | 36 B |

The field is 64 bytes — not 32 — because the membership-only label is 36 bytes
(the full label fits in 32; the asymmetry is the trap an implementer
validating only against the full tag would miss). 64 is the natural Blake2b512
output width, leaves headroom for future tags, and costs nothing: the tag is
preimage-only, never on the wire. Labels are compile-time-asserted to fit and
to be distinct. Hash-the-label (`Blake2b512(label)[..32]`) was rejected: it
trades hexdump auditability of the human-readable tag for a length non-issue
the 64-byte field already settles.

### 4.2 Challenge preimage inventories (verified baseline)

Injective domain separation here rests on **length-regularity**: every field
in both preimages is fixed-width, so the leading 64-byte tag occupies an
invariant position and cross-type preimage collision requires a Blake2b
collision across differing first blocks. This is a **security invariant with
a verified baseline**, not an observation. The inventories, enumerated
field-by-field at source (2026-06-12):

**Full SAL** (`SpendAuthAndLinkability::challenge`):

| # | Field | Width |
|---|---|---|
| 0 | type tag (`Shekyl FCMP++ SAL full v1`, padded) | 64 B |
| 1 | `signable_tx_hash` | 32 B |
| 2–6 | `O~, I~, C~, R, L` (`Input::transcript`, binds `L`) | 5 × 32 B |
| 7–12 | `P, A, B, R_O, R_P, R_L` | 6 × 32 B |

Total 448 B. The commitment set is **not variable-count** — it is the six
named commitments structurally fixed by the `SpendAuthAndLinkability` type.

**Membership-only** (`MembershipSpendAuth::challenge`):

| # | Field | Width |
|---|---|---|
| 0 | type tag (`Shekyl FCMP++ SAL membership-only v1`, padded) | 64 B |
| 1 | `signable_tx_hash` | 32 B |
| 2 | input index, `u32` little-endian | 4 B |
| 3–6 | `O~, I~, C~, R` (no `L`) | 4 × 32 B |
| 7 | `R_O` | 32 B |

Total 260 B. The input index is bound so that a `MembershipSpendAuth`
transplanted across input slots fails verification even when two slots carry
identical input tuples (§8.2).

### 4.3 Framing discipline (forbidden pattern)

Any future **variable-length** field entering either transcript MUST be
length-prefixed (TupleHash-style framing, Blake2b instantiation). Bare
concatenation of variable-length fields is the forbidden pattern: it would
silently void the length-regularity invariant that §4.2's tables establish
as the verified baseline. A reviewer finding a variable-length unprefixed
field in either preimage has found a security regression, not a style issue.

### 4.4 Transcript-mechanism audit (2026-06-12, verified at source)

- The SAL challenge is a raw `Blake2b512` (bare `update()` calls into
  `Scalar::from_hash`); the GBP transcripts
  (`generalized-bulletproofs::transcript`) and the `Fcmp` context digest are
  also Blake2b. The proof stack is **uniformly Blake2b**.
- `flexible-transcript` is declared by the fcmp++ crate but is **optional,
  multisig-feature-only** (`sal/multisig.rs`, FROST signing) — off the
  consensus verify path — and its enabled `recommended` backend is
  `DigestTranscript<Blake2b512>`, not Merlin/STROBE (the Merlin backend is
  behind a `merlin` feature nothing enables). `generalized-bulletproofs`
  declares it unused (MSRV pinning).
- **CShake256 customization-string routing rejected:** correct in the
  abstract (SP 800-185 `S` is length-encoded by construction; TupleHash256 is
  the FIPS injective-framing answer), but it would introduce `sha3` into the
  consensus-critical crate and a second hash family into the consensus path
  for one 64-byte challenge. Reopening criterion: the fcmp++ crate adopts a
  transcript abstraction, or gains `sha3` for independent reasons — then fold
  the type tags into native customization-string/labeled separation.
- **Merlin rejected:** STROBE is not a NIST-standardized construction;
  adopting it would inject a non-FIPS primitive into a consensus-critical
  transcript for properties (injective framing, nonce synthesis) replicated
  here within the Blake2b stack. No Merlin/STROBE exists in any current build
  path, so the rejection preserves the status quo.

## 5. Security argument

### 5.1 Soundness reduction

**(a0) — G-preserving rerandomization (keystone premise).** The membership
leg admits `O~` only as a `T`-confined displacement of a tree leaf's `O`.
Prover-side, `RerandomizedOutput::new` computes `O~ = O + r_o·T`
(`sal/mod.rs`). Verifier-side — the side soundness rests on — the `Fcmp`
first-layer gadget (`Circuit::first_layer`,
`crypto/fcmps/src/circuit.rs`) opens `O~ → O` via a `PointWithDlog`
discrete-log gadget instantiated over the **`T` generator table alone**
(`FcmpParams::T_table`, wired in `Fcmp::membership`), constraining
`O~ = o_blind·T + O` where `O` is the in-tree leaf variable. No
`G`-component displacement is expressible in the constraint system. Writing
the leaf as `O = x_leaf·G + y_leaf·T`, every `O~` the membership leg accepts
therefore has `G`-component exactly `x_leaf` — the `G`-coefficient is **not
prover-chooseable**. This forecloses the transplant attack: presenting `O~`
to the `Fcmp` leg as a rerandomization of `O_victim` while opening it in
`R_O` with a self-chosen `(x', y')` requires either a non-`T` displacement
(inexpressible in the circuit) or a second distinct `(G, T)` opening of the
same point (premise (a): breaks binding).

**(a)** `dlog_G(T)` unknown — `T = hash_to_point(keccak256("Monero Generator
T"))` (`shekyl_generators::T`), NUMS by construction — implies the `(x, y')`
opening of `O~` over `(G, T)` is computationally binding: two distinct
openings yield `dlog_G(T)`. A verifying `R_O` proof therefore implies
knowledge of the *specific* `x` fixed by (a0) (extractor via standard Schnorr
rewinding on the two-generator relation).

**(b)** The `R_O` leg's `O~` and the `Fcmp` leg's `O~` are bound to be
identical — the same `Input` tuple is transcripted into the membership-only
challenge (§4.2) and consumed by `Fcmp::verify` as the public input — so the
extracted `x` is the `G`-component of a **real tree leaf**, per (a0).

**(c)** On-chain `O` bakes in the recipient spend key
(`FCMP_PLUS_PLUS.md`: `O = Hs·G + B + Hs_y·T`, so `x = Hs + b`): knowledge of
`x` requires knowledge of the recipient's spend scalar `b` — ownership.

### 5.2 Zero-knowledge transfer

The kept responses are syntactically and distributionally identical to their
full-SAL counterparts: `s_alpha = α + e·x`, `s_y = r_y + e·y~` with fresh
uniform per-proof nonces `α, r_y` (synthesized per §6, which preserves the
uniform marginal distribution under a working RNG). The standard simulator
for the two-generator Schnorr relation applies unchanged; the subtraction
removes statements without altering the distribution of what remains.

### 5.3 Replay binding

The challenge binds `signable_tx_hash` (same contract as the full path: the
hash must bind the transaction prefix and pseudo-outs), so a
`MembershipSpendAuth` cannot be replayed under a different transaction, and
binds the input index, so it cannot be transplanted across slots (§8.2).

### 5.4 Batch verification

Verified at source (2026-06-12): SAL's `verify` issues one
`BatchVerifier::queue` call per verification statement, and
`multiexp::BatchVerifier::queue` draws a fresh random scalar weight per call
(first statement unit-weighted, standard and sound) — weighting is
**per-equation independent** by construction. `MembershipSpendAuth::verify`
follows the same per-equation discipline (one `queue` call for its single
`R_O` equation). Mixed batches — membership-only backing (§7.1 step 6) and
full key-image proofs (§7.1 step 7) sharing the same three verifiers — are
covered by tests in both polarities rather than assumed.

### 5.5 External-review reopening criterion

§5.1's reduction is necessary but **not sufficient** for genesis: §7.2 names
the type-confusion surface load-bearing. **Named criterion: external
cryptographic review of this section before genesis freeze.** Until that
review lands, this proof type is implemented-but-not-genesis-final.

### 5.6 Adversarial pressure-test record (post-draft obligation)

Attacks considered against the drafted reduction:

1. **Transplant via crafted rerandomization** — present `O~` as a
   rerandomization of `O_victim`, open with own `(x', y')`. Foreclosed by
   (a0) + (a): the circuit pins the displacement to `⟨T⟩`; a second opening
   breaks `(G, T)` binding.
2. **Cross-leg mismatch** — hand the `R_O` leg a different `O~` than the
   `Fcmp` leg. Foreclosed by (b): one `Input` value feeds both transcripts;
   there is no second `O~` slot in the wire format (§3).
3. **Type confusion at the byte seam** — feed membership-only bytes to the
   full verifier or vice versa. Foreclosed structurally by the 64-byte DSTs
   (§4.1–4.2); covered by the deserialization-seam test; the FFI-seam variant
   is a named carry to the emission vin PR.
4. **Batch slack borrowing** — invalid membership-only proof co-batched with
   a valid full proof. Foreclosed by per-equation independent weights (§5.4);
   covered by mixed-batch tests in both polarities.
5. **Challenge-collision across types** — craft preimages of equal bytes
   under both tags. Foreclosed by length-regularity (§4.2) + fixed-width
   distinct leading tags: equal preimages would need a Blake2b collision.

## 6. Privacy: non-linkability and nonce synthesis

§7.3 (E-4): repeated membership proofs of the same leaf publish no key image
and are not linkable by the proof statement alone. That property rests
entirely on the rerandomization scalars (`r_o, r_i, r_r_i, r_c`) and Schnorr
nonces (`α, r_y`) being **fresh and nonzero per proof**. If `r_o` is zero or
reused, the proof still verifies — a distribution bug, not a correctness
bug — while `O~` directly links repeated backing proofs of the same leaf,
for the one input type already publicly tagged as archival activity.

Three layers of defense (prevention, runtime guard, deterministic tests):

1. **Nonce synthesis (prevention).** The membership-only prove path derives
   all six scalars RFC-6979-style instead of raw RNG draws
   (symbol: `synthesize_scalar`, `membership_only.rs`):
   `Blake2b512(64-byte per-scalar domain tag ‖ x ‖ context ‖ fresh RNG
   output) → Scalar::from_hash`, where `x` is the secret spend scalar and
   the context is the leaf tuple `(O, I, C)` plus a caller-supplied
   length-prefixed context string (the emission caller passes the reference
   root) for rerandomization scalars, and the tx hash + input index + input
   tuple for `α, r_y`. A degraded RNG then cannot produce zero or
   cross-context-reused nonces; the worst case collapses to
   deterministic-but-distinct-per-context — the RFC 6979 guarantee.
   **Residual (documented honestly):** under a *totally* dead RNG, two
   rerandomizations of the same leaf with the same caller context are
   identical; freshness across proofs of the same leaf in that failure mode
   is carried by the caller context varying (distinct reference roots).
   The full SAL path keeps its existing raw draws: its linkability story is
   structural (`L` is published) and touching it is out of scope.
2. **Construction guard (backstop).** `membership_only_rerandomize` returns
   a loud error — not a `debug_assert` — if any rerandomized component
   equals its base (`O~ == O`, `I~ == I`, `C~ == C`) or `R` is the identity.
   Catches the measure-zero synthesis outputs and any future regression that
   bypasses synthesis. Lives in the membership-only path, not shared
   `RerandomizedOutput` code.
3. **Deterministic tests.** Freshness: prove the same leaf twice through the
   production seam; assert pairwise inequality of all four tuple components
   across proofs and per-proof distance from base. Each assertion fails with
   probability ≤ ~2⁻²⁵² under a correct implementation — point-inequality
   checks, not flaky statistics. RNG-seam: a `ZeroRng` must still yield
   nonzero, per-context-distinct scalars, and the guard must fire on a
   forced degenerate construction.

## 7. Quantum posture (cross-PR gate)

The `R_O` leg is curve25519 — **classically secure only**. A quantum
adversary recovering `x` from on-chain `O` can forge a membership-only proof
for an output they do not own and claim it as backing for their pseudonym
`P`. The defense is two-part:

1. **In this PR:** the `H(pqc_pk)` leaf binding stays in-circuit — the
   `Fcmp` leg's extra leaf scalars (`fcmps::Input::with_extra_scalars`),
   identical to the full path.
2. **At the vin layer (deferred but gated):** ML-DSA authentication against
   the leaf-committed `pqc_pk`
   ([`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §10.1 sizes two
   ML-DSA-65 auths into the emission wire).

This PR in isolation has **no quantum spend-authority guarantee**. Per the
absence-of-claim-is-claim-of-absence rule, the gate is written as a blocker:
**the emission vin PR is not mergeable without ML-DSA verification binding
the `H(pqc_pk)` committed by the membership-only proof.** (Also recorded in
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §12.)

**Quantum-forgery wargame (post-draft obligation, input to the vin PR).**
Adversary: CRQC-equipped, targeting emission backing. Path: recover `x` from
any on-chain `O` (Shor against curve25519) → construct a valid
`FcmpMembershipOnly` proof over the victim leaf (the proof requires only
`(x, y~)` and public tree data; `y~` is recoverable the same way) → present
it as backing for the adversary's `P`. Where the defense interposes: the vin
carries the prover's `pqc_pk` and an ML-DSA-65 signature over the vin
context; verify recomputes `H(pqc_pk)` and demands it equal the leaf-committed
extra scalar that the `Fcmp` leg proved in-circuit. The adversary cannot
produce an ML-DSA signature under the victim's `pqc_pk` (ML-DSA is
quantum-resistant), and cannot substitute their own `pqc_pk` (its hash would
not match the leaf commitment proven in-circuit). Conclusion: the vin-layer
check is **load-bearing for the entire quantum spend-authority property**;
its absence reduces backing ownership to classical security. This is why the
gate in §12 is phrased as a merge blocker, not a checklist item.

## 8. Scope notes

### 8.1 Bond posture is discharged elsewhere (F-3)

§7.2's prose says the membership proof "attests spend authority **and bond
posture**." An auditor reading that literally would expect the circuit to
bind `bonded_total_atomic`. It does not and must not: `bonded_total_atomic`
is consensus-state, not a circuit witness. The posture conjunct
(`bonded_total_atomic == bond_floor(holdings)`) is discharged by the §7.1
**step-2 bond-posture check** against the bond record, independent of the
step-6 membership check this proof implements. The proof is spend authority +
membership only.

### 8.2 E-class type contract

- **Empty inputs reject.** `FcmpMembershipOnly::verify` returns an error on
  zero inputs — never a vacuous accept. The rejection lives **at this type**,
  not deferred to the vin's posture checks.
- **Index binding.** Each per-input challenge binds the input's index
  (`u32` LE, §4.2), so a `MembershipSpendAuth` swapped across slots fails
  even if two slots carry identical input tuples.
- **Duplicate tuples are not rejected by the proof.** With no key image
  there is nothing in the proof to dedup on. Listing the same output twice
  yields two valid per-input proofs of the same statement. If the emission
  vin requires input distinctness, it enforces it at the vin layer — named
  carry to that PR.

## 9. Carries (deferred, named)

| Item | Where it lands | Gate / reversion |
|---|---|---|
| ML-DSA backing auth (quantum spend authority) | emission vin PR | **Hard merge blocker** — §7 |
| FFI entry point, `shekyl-fcmp` wrapper, C++ call site, vin deserializer, emission KATs | emission vin PR | §12 checklist |
| FFI-seam variant of the deser cross-type test | emission vin PR | the byte boundary it guards is built there |
| Vin-layer input-distinctness rule (if required) | emission vin PR | §8.2 |
| Multisig-`P` backing proofs | not built | Reopen iff a production multisig archiver emerges; re-evaluate via a design round against `sal/multisig.rs` |
| CShake-S / native transcript domain separation | not built | Reopen iff fcmp++ adopts a transcript abstraction or gains `sha3` independently — §4.4 |

## 10. Sizing

Measured at implementation (1 input, 1 layer, test
`membership_only_proof_size`): `FcmpMembershipOnly` per-input overhead is
**192 B** versus 480 B for `FcmpPlusPlus` (the 96-byte `MembershipSpendAuth`
replaces the 384-byte SAL); the `Fcmp` leg is byte-identical. Total proof
size is therefore **strictly smaller** than the 1-input `FcmpPlusPlus`
estimate that [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §10.1
carried as the sizing caveat — the 3× reversion trigger is not approached
(measured ratio < 1×). The §10.1 caveat is closed by the doc sweep
accompanying this PR; the test asserts the 3× bound permanently.

## 11. Timeframe note (rule 05)

Serves **now** (the emission vin path). Quantum posture: classical
spend-auth here + leaf-committed `pqc_pk` verified at the vin layer (§7
gate) — the hybrid pattern the genesis stack uses everywhere. The **V4
lattice-only transition** replaces the entire FCMP++ stack including this
type — same posture as `FcmpPlusPlus` itself, no new debt. No mining-era
sensitivity.
