# `CA-1` and `CA-2` together: Round 0 for `HelioseleneField`'s representation

**Status:** DRAFT, Round 0 posed to Rick (opened 2026-11-28, shekyl-core
#1574). Nothing here is ruled. No vendored consensus-critical arithmetic
changes in this round. A port, if ruled, is its own PR in the Shekyl
monero-oxide fork, followed by shekyl-core's pin and the paired GUI wallet
PR.

This round answers to the [crypto audit register](CRYPTO_AUDIT.md): `CA-1`
(§1) and `CA-2` (§2). The before-measurement it depends on is registered in
[`ca2-round0-baseline-registration.md`](../formal/checkct/results/2026-11-28/ca2-round0-baseline-registration.md),
with [amendment 1](../formal/checkct/results/2026-11-28/ca2-round0-baseline-amendment-1.md).

## 1. The problem

- **`CA-2` is open.** Inlined `HelioseleneField` square and mul take
  operand-dependent time on two x86_64 hosts, and the same operations
  behind a call boundary do not. The core's cycle count, not the clock,
  carries it, and DOITM does not govern it. It closes only on the code
  side: a representation measured flat on the direct path (§2, "Reopen /
  close").
- **`CA-1` is ignored by ruling, and its fix is undesigned.**
  crypto-bigint 0.5.5 is flagged by RUSTSEC-2026-0387. Rick wants a real
  fix, upstream as well, not a standing waiver.
- **One change may serve both.** serai's `prime-field` declares a field
  in Montgomery form over crypto-bigint 0.7. `Field25519`, already
  Montgomery (`dalek-ff-group`'s `Residue`), is flat on every `CA-2` row.

The question for Rick is which representation of `HelioseleneField`, if
any, to build, and what `CA-1` still needs beyond it.

## 2. What the source says (B1)

### 2.1 The current field

Paths are in shekyl-core's vendored tree,
`rust/shekyl-oxide/crypto/helioselene/`, a mirror of the Shekyl
monero-oxide fork at `c753b3475f`.

- `HelioseleneField(pub(crate) U256)`, in **canonical** form
  (`rust/shekyl-oxide/crypto/helioselene/src/field/mod.rs:22`). The modulus is
  p = 2^255 − `0x08cab7e2e6960ce8067af49720ee20ad`
  (`rust/shekyl-oxide/crypto/helioselene/src/field/mod.rs:25`, `rust/shekyl-oxide/crypto/helioselene/src/field/verified/mod.rs:26`).
- Mul and square: crypto-bigint's `U256::mul_wide` and `square_wide`,
  then `red512`, a Crandall reduction (`rust/shekyl-oxide/crypto/helioselene/src/field/verified/red.rs:30`).
- Also in `src/field/verified/`:
  - inversion: Bernstein–Yang binary GCD, Algorithm 1 of eprint 2020/972
    (`rust/shekyl-oxide/crypto/helioselene/src/field/verified/invert.rs:23`);
  - pow: a constant-time 4-bit window (`rust/shekyl-oxide/crypto/helioselene/src/field/verified/pow.rs:4`);
  - sqrt: a^((p+1)/4), normalised to the even root (`rust/shekyl-oxide/crypto/helioselene/src/field/verified/sqrt.rs:9`).
- **The Veridise assessment** (monero-oxide `audits/helioselene/`; the
  crate's README) formally verified a Dafny translation of the functions
  in `src/field/verified/`, as of upstream commit `27b1c7f291`. It covers
  functional correctness, not timing, and the translation, not the Rust
  as written. One flaw it found was fixed in `00bafcf08e`.
- **crypto-bigint:** the manifest asks for `"0.5"` (`rust/shekyl-oxide/crypto/helioselene/Cargo.toml:28`), and
  every lock resolves **0.5.5**. The field uses only limb plumbing from
  it: `mul_wide`/`square_wide`, `sbb`/`adc`/`mac`, `ct_eq`, and
  `const_rem` in a `const` constructor.
- **Upstream** monero-oxide `fcmp++` at `63e7e7d215` (2026-11-26) still
  asks for crypto-bigint 0.5.5 and `dalek-ff-group` 0.5.
- The fork's pin `c753b3475f` (synced 2026-11-23) predates upstream's
  eight commits of 2026-11-26. They touch `ec-divisors` (`46135ae638`
  says "some arithmetic bugs have also been correct[ed]"), helioselene's
  divisor plumbing in `point.rs` and its MSRV, zeroization, and the
  FCMP++ SAL. They do not touch the field.

### 2.2 The candidate base: `prime-field`

On serai `next` at `f483295da9` (2026-11-28):
- `crypto/prime-field` 0.1.0, edition 2024, MSRV 1.87, **unreleased**.
- It depends on crypto-bigint `0.7.9` and ctutils `0.4`
  (its `Cargo.toml`, lines 28 and 29); a fresh resolve takes crypto-bigint 0.7.11 and
  ctutils 0.4.8.
- `odd_prime_field_with_specific_repr!` declares an `ff::PrimeField`
  whose value is `crypto_bigint::modular::ConstMontyForm` (its `src/lib.rs`, lines 137
  and 192).
- Arithmetic, inversion (`ConstMontyForm::invert`) and sqrt (a pow,
  normalised to the even root, its `src/lib.rs`, lines 431 to 473) are all
  crypto-bigint's.
- `dalek-ff-group` on `next` (version string `0.5.0`, the same as the
  crates.io release, with different code) declares its `FieldElement`
  through it (`crypto/dalek-ff-group/src/lib.rs`, line 274).
- serai's own workspace patches `ciphersuite` with a `0.4.99` shim
  (`patches/ciphersuite`) so that its graph takes that `dalek-ff-group`.
- **Its lock still holds crypto-bigint 0.5.5**, through `elliptic-curve`
  0.13.8 and `monero-ed25519` 0.1.0.

**Its API is narrower than what Shekyl calls.** The `next` `FieldElement`
has none of `from_u256`, `wide_reduce` or a field-exponent `pow`, only the
`ff` traits and a `const` `from_bytes`. helioselene, `ec-divisors` and
`shekyl-curve-generators` call `Field25519::from_u256` (with a 0.5
`U256`) and `Field25519::wide_reduce` today.

### 2.3 `CA-1`'s real scope: every crypto-bigint 0.5 consumer

The lock and the compiled graph differ, and `cargo audit` reads the lock.
Read from `rust/Cargo.lock` and `cargo tree` at `8b5f8e2674`:

| Consumer | Version | In the lock | Compiled in the workspace | In the shipped binaries |
| --- | --- | --- | --- | --- |
| `dalek-ff-group` (`Field25519`) | 0.5.0, crates.io | yes | yes | **yes** |
| `helioselene` (vendored) | path | yes | yes | **yes** |
| `ec-divisors` (vendored) | path | yes | yes | **yes** |
| `shekyl-curve-generators` (first-party) | path | yes | yes | **yes** |
| `dalek-ff-group` | 0.4.6, crates.io | yes | only through `shekyl-wss-q1b-bench`'s `ciphersuite/ed25519` | no |
| `elliptic-curve` | 0.13.8 | yes | no | no |
| `minimal-ed448` | 0.4.2 | yes | no | no |

"Shipped binaries" means `shekyld`, `shekyl-cli`, `shekyl-wallet-rpc` and
`shekyl-rpc-tunnel`, each read with `cargo tree -p`.

Every other lock carries the same crypto-bigint 0.5.5:
- ten of the eleven fuzz workspaces (`shekyl-noise`'s has none);
- `docs/formal/checkct/dynamic`;
- the GUI wallet's `src-tauri`.

`CRYPTO_AUDIT.md` §1 lists `elliptic-curve` and `minimal-ed448` among the
consumers "via `ciphersuite`". They are in the lock, but no workspace
build compiles them.

**Porting `HelioseleneField` alone does not close `CA-1`.**
- `Field25519`, the consumer that carries `CA-1`'s secrets (§1, "Where
  secrets meet it"), stays `dalek-ff-group` 0.5.0 on crypto-bigint 0.5.5.
- So do `ec-divisors`' constants and Edwards x-recovery, and
  `shekyl-curve-generators`' hash-to-point.
- helioselene itself would keep crypto-bigint 0.5 for the `Field25519`
  constants in its curve macro.
- What `CA-1` needs beyond a helioselene port is §6.

### 2.4 The DRS lane's multiexp finding

#1497 (merged 2026-11-22) moved the prover's multiexp to 0.5.2, which
selects table entries in constant time. DRS-X has nothing running or
scheduled (2026-11-28). It owes one floor timing of #1538's spend
self-verify, unscheduled. That timing will be taken on whatever binary
this round produces, and DRS-X claims a Pi only after telling this lane.
Its floor baseline for one proof is shekyl-dev
`infrastructure/captures/fcmp-prover-multiexp/2026-11-21-pi4-floor/`.

## 3. The before-measurement (B2)

The registration runs `CA-2`'s direct `HelioseleneField` rows, with
their nulls and controls, at 1,000,000 per class. In the same session it
runs RT-P4's validity rows, which are `CA-4`'s observation. The host is
the Tiger Lake laptop, under CA-3's quiet gate.

**The workstation is not used.** It has a reported failing core: 17
corrected bank-0 machine checks in 2.6 days of the current boot, all on
one physical core's two threads. It also carries shared editing load.

**The codegen gate stopped the first attempt before anything was
timed.** The MSVC binary calls the wide multiply out of line. So does
every `CA-2` record, so amendment 1 restates the criterion as "red512
inlined, no wrapper", and the binary meets it.

*Results: pending.*

## 4. Candidate shapes

Each shape is put as a question. "Closes `CA-2`" is a prediction until
the shape's direct rows are measured flat on the B2 host. Every
prediction below is untested.

### (a) Port `HelioseleneField` onto `prime-field`

- **Closes:** `CA-2` predicted, since the representation becomes
  Montgomery and the reduction becomes crypto-bigint 0.7's
  `montgomery_reduction`. `CA-1` for `HelioseleneField` only (§2.3).
- **Replaces audited code:** all of `src/field/verified/`: `red512`,
  invert, pow and sqrt. Equivalent assurance would come from:
  - crypto-bigint's own record. NCC Group's 2023 review (two commits on
    the 0.5/0.6 line, no significant findings); 0.7's README says the
    code has diverged significantly since. Upstream's checkct fixes for
    RUSTSEC-2026-0387 landed in 0.7.6.
  - this tree's BINSEC harness run on the new field.
  - bit-identical results against the current field (§5).
- **Upstream route:**
  - `prime-field` is unreleased, so a pin is a git rev of serai `next`.
  - monero-oxide upstream would take helioselene onto it only alongside
    `dalek-ff-group`'s move. Upstream is still on 0.5 and has not said
    when.
- **Fork maintenance:** a diverged `src/field/` in the fork. Every resync
  from upstream is then a hand merge of that directory, the content
  manifest is regenerated, and the change is re-vetted against the Q6
  freeze (`GENESIS_TX_WIRE_FORMAT.md` §6). The proof bytes must stay
  pinned (`a_seeded_proof_is_pinned_byte_for_byte`).
- **Prototype:** shekyl-dev `tools/ca-round0-field/helioselene-a`.

### (b) A Montgomery representation inside the existing type, hand-written over crypto-bigint 0.5

- **Closes:** `CA-2` predicted. `CA-1` not at all: the field stays on
  crypto-bigint 0.5.
- **Replaces audited code:** `red512` in mul and square, with new
  arithmetic that nobody has verified.
- **Not prototyped.** On the reading, (d) is the same representation
  with generated code that carries proofs, and it leaves crypto-bigint
  out of the field. Is there a reason to prefer (b) that this reading
  misses?

### (c) Blinded operands

- **The shape:** each secret operand is held as x·λ for a per-proof
  random λ, unblinded with one extra multiplication by λ⁻¹ per product.
- **Closes:** `CA-2` only if the dependence is on operand values that
  the blinding randomises. Values that repeat within a proof would still
  repeat under the same λ. `CA-1` not at all.
- **Cost:** at least one more field multiplication per multiplication,
  and a per-proof secret threaded through the prover's generic code.
- **Not prototyped,** for that cost and that reach.

### (d) Found while reading: a Montgomery representation inside the existing type, with fiat-crypto's arithmetic

- **The shape:** Fiat Cryptography v0.1.6 generates word-by-word
  Montgomery arithmetic for this prime. It is proved correct in Coq,
  branch-free by construction, and `const fn`, with no crypto-bigint. It
  covers mul, square, add, sub, negation, the conversions, byte encoding
  and a `divstep` for Bernstein–Yang inversion. Its `solinas-reduction`
  generator fails for this prime.
- **The type:** `HelioseleneField([u64; 4])` holds x·2^256 mod p, fully
  reduced.
- **Kept from the verified code:** `red512` (now only on wide input:
  hashing and random draws), pow and sqrt, unchanged. They are chains of
  the field's own operations.
- **Replaced:**
  - mul, square, add, sub and neg, by fiat;
  - inversion, by fiat's `divstep`, driven as RustCrypto's
    `impl_field_invert!` drives it.
- **Closes:** `CA-2` predicted (same representation argument as (a)).
  `CA-1` for the field's arithmetic. crypto-bigint 0.5 stays for the
  wide reduction's input type and the curve macro's constants, as in
  (a).
- **Assurance:** fiat-crypto's proofs for the generated functions, which
  cover a Coq model of the code it emits (the same caveat as Veridise's
  Dafny translation). Plus BINSEC on the new field, and bit-identical
  results against the current field.
- **Upstream route:** none needed. The generated file is pinned by its
  generator command and version and lives in the crate. monero-oxide
  upstream could take it as a field implementation, independent of
  serai.
- **Fork maintenance:** as for (a), but with no new dependency to pin.
- **Prototype:** shekyl-dev `tools/ca-round0-field/helioselene-d`.

## 5. Equivalence, measured

*Pending.*

## 6. `CA-1` beyond `HelioseleneField`

*Pending.*

## 7. The acceptance bar for a port

1. Field results bit-identical to the current implementation. That means
   every operation, including sqrt's root choice, invert's `None` for
   zero, `from_repr`'s refusals and `Field::random`'s stream use. Checked
   exhaustively over structured families (every single-bit and
   all-ones-below-bit value, pairwise, every single-bit wide input,
   non-canonical encodings at and above p and above 2^255), plus a
   million random tuples, plus KATs.
2. The FCMP++ vectors and proofs unchanged:
   `a_seeded_proof_is_pinned_byte_for_byte` (digest `dcb32df4…`),
   `kat_fcmp_proof_size_depth1_row`, and the full `shekyl-fcmp`,
   `shekyl-fcmp-proofs`, curve-tree and generator suites.
3. The direct rows flat after the port, with the same filter and lines as
   the baseline, on the B2 host and on a second x86_64 host.
4. The floor device still flat.
5. BINSEC clean on the new field's entrypoints.

## 8. The wallet's threat-model note for releases before the fix

*Pending.*

## 9. Questions for Rick

*Pending the measurements.*
