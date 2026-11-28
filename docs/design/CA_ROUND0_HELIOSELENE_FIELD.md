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

shekyl-dev `tools/ca-round0-field/equiv` (commit `b4cefe4`) evaluates
every observable of the current field against (a) and (d) and compares
the encodings:
- the 17 field observables: add, sub, neg, mul, square, double, invert,
  sqrt, `sqrt_ratio`, `pow`, `is_zero`/`is_odd`, the bit
  decomposition, `wide_reduce`, `from_uniform_bytes`, `from_repr` on
  arbitrary bytes, and both equalities;
- the `PrimeField` constants;
- `Field::random` from identical seeded streams;
- both curves: generators, a scalar multiple each, and the decompression
  and doubling of arbitrary 32-byte encodings.

The current field is the fork at `c753b3475f`, the vendored pin. The
run was on a build VM, release profile, rustc 1.94.0:

| Family | Inputs | Result |
| --- | --- | --- |
| Structured, exhaustive within the family | 514 operands pairwise (264,196 pairs: 0, 1, p−1, p−2, every 2^k and every 2^k − 1 below 2^255), every single-bit 512-bit wide input plus all-zero and all-one (514), 130 encodings at and above p and above 2^255 | 0 mismatches |
| Random | 1,000,000 tuples, seed 20261128 | 0 mismatches |
| `Field::random` | 10,000 seeded streams | 0 mismatches |
| Curves | 10,000 scalars and encodings | 0 mismatches |
| **All** | **21,572,292 comparisons** | **0 mismatches** |

**The prototypes in core** (`overlay.sh`, on the same build VM, against
core `8b5f8e2674`). Each variant was laid over the vendored helioselene.
`cur` is the vendored crate itself:
- the suites: `cargo test --release` of `shekyl-fcmp`,
  `shekyl-fcmp-proofs`, `shekyl-curve-tree`, `shekyl-curve-generators`
  and `shekyl-crypto-pq`;
- the KATs: `shekyl-engine-core`'s `tx_weight_kat`, which signs whole
  transactions.

| Variant | Suites | `tx_weight_kat` | `a_seeded_proof_is_pinned_byte_for_byte` | Crate's own tests |
| --- | --- | --- | --- | --- |
| `cur` | 747 passed, 0 failed, 13 ignored | 3 passed, 1 ignored (the timing test) | ok | — |
| (a) | 747 passed, 0 failed, 13 ignored | 3 passed, 1 ignored | ok | 10 of 10 |
| (d) | 747 passed, 0 failed, 13 ignored | 3 passed, 1 ignored | ok | 12 of 12 |

The pinned KAT hashes a seeded depth-1 proof and its pseudo-outs (digest
`dcb32df4…`). So a proof built on (a) or (d) is byte-for-byte the proof
built on the current field. The captures are in shekyl-dev
`infrastructure/captures/ca-round0-prototypes/2026-11-28/`.

Not yet covered here:
- the prototypes on aarch64, which the floor run will build;
- BINSEC on (a) and (d), which is acceptance item 5 and is run for the
  shape Rick rules.

**What the one-proof timing will measure.** Upstream monero-oxide's
commits of 2026-11-26 delete the Barycentric divisor calculator that the
current pin's prover uses for every blind (`3383652`), and make the
`Poly` path the prover's (`46135ae638`). DRS-X is putting that resync to
Rick (shekyl-dev `claude/OXIDE_UPSTREAM_2026-11-26_ASSESSMENT.md`). If
the resync is ruled first, the one-proof timings are taken on the
resynced pin. Each prototype's `point.rs` is then rebased onto the new
`DivisorCurve` impl first. The field's mul and square figures do not
depend on it.

## 6. `CA-1` beyond `HelioseleneField`

`cargo audit` reads the lock, so `CA-1`'s ignore can be dropped only when
no crates.io crate on crypto-bigint 0.5 remains in any lock. From §2.3,
that needs every one of these:

1. **`dalek-ff-group` 0.5.0 (`Field25519`), the consumer that carries
   `CA-1`'s secrets.**
   - Nothing released replaces it. The code that does is serai `next`'s
     `dalek-ff-group`, on `prime-field`, unreleased.
   - Taking it now means `[patch.crates-io]` to a serai git revision for
     `dalek-ff-group`, with `ciphersuite` going to serai's `0.4.99` shim
     (`patches/ciphersuite`), as serai's own workspace does.
   - It also means migrating every call to the API it drops:
     - helioselene's `Field25519::from_u256` constants and
       `Field25519::wide_reduce`;
     - `ec-divisors`' `from_u256` constants and its `DynResidue`
       `const` evaluations;
     - `shekyl-curve-generators`' `from_u256(U256::from_le_bytes(hash))`
       in hash-to-point. Its replacement must reduce a 256-bit value
       mod p exactly as today. `from_bytes` refuses non-canonical input,
       so the replacement is `FromUniformBytes<64>` over the 32 bytes
       zero-extended.
   - `Field25519` is a consensus field: the daemon verifies FCMP++ proofs
     over it. The swap must therefore be bit-identical, checked as §5
     checks `HelioseleneField`, and it is a consensus-boundary change in
     its own PR (`107-consensus-atomic-cutovers`,
     `126-sub-pr-design-discipline`).
2. **`ciphersuite` 0.4.2 from crates.io.** It lists `dalek-ff-group`
   0.4.6, `elliptic-curve` 0.13.8 and `minimal-ed448` 0.4.2 as optional
   dependencies, so all three stay in the lock while it does. That is
   true even though only `shekyl-wss-q1b-bench` (`ciphersuite/ed25519`)
   compiles one of them. They leave with item 1's shim, or with a
   `ciphersuite` release on crypto-bigint 0.7.
3. **`ec-divisors` and `shekyl-curve-generators`** move with item 1.
   Their crypto-bigint uses are `const` constructors and public-input
   reductions, not secret arithmetic.
4. **helioselene after (a) or (d).**
   - It keeps crypto-bigint 0.5 for the curve macro's `const` constants,
     and in (d) for `red512`'s input type.
   - Both go when item 1 lands. The constants become byte constants,
     and in (d) `red512` takes limbs.
5. **The other locks** follow core:
   - the ten fuzz workspaces;
   - `docs/formal/checkct/dynamic`, which keeps 0.5.5 on purpose as an
     instrument of the old code;
   - the GUI wallet's `src-tauri`, in its paired PR.

So `CA-1` closes in two steps, whichever field shape is chosen:
- **The field port.** It removes crypto-bigint 0.5 from
  `HelioseleneField`'s arithmetic.
- **The `Field25519` and `ciphersuite` move.** It removes it from the
  lock. That move waits on serai: a release, or Rick's ruling to pin
  `next` by revision.

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

`CA-2`'s close criterion asks for a note in the wallet's threat model for
the releases that predate the fix. Proposed text, as a new row of
[`THREAT_MODEL_WALLET.md`](../THREAT_MODEL_WALLET.md)'s adversary-surface
index:

> **T8 — a timing observer on the proving machine (`CA-2`).** On x86_64,
> releases up to and including *[the last release before the fix]* build
> FCMP++ proofs with `HelioseleneField` multiplication and squaring whose
> cycle count depends on the operands' values. It was measured on Intel
> Tiger Lake cores and one other x86_64 host, and not on the Pi 4's
> Cortex-A72.
>
> A process or virtual machine sharing the proving machine's CPU, with a
> fine-grained clock, could learn a few bits per operation about the
> values in the blinded membership path. Over the thousands of operations
> in one proof, that could link the spend to the output it spends.
>
> It is not reachable over the network, and verification on the daemon
> uses only public data. Until the fix ships, build transactions on a
> machine whose CPU you do not share with software you do not trust.
> Fixed in *[release]*.

The note lands with the fix's release, or now, since alpha releases
already predate it. That timing is Rick's call (§9).

## 9. Questions for Rick

The measurements still owed before these can be answered on numbers:
- the laptop baseline (§3);
- each surviving shape's direct rows on that host;
- the field and one-proof costs on the floor device and x86_64.

They are posed now so the reading can be argued while the measurements
run.

1. **Which representation for `HelioseleneField`?**
   - The problem: `CA-2` closes only on the code side, and both
     prototypes are bit-identical to the current field down to the
     proof bytes. They differ in what audited code they replace and in
     what they add to the dependency graph.
   - (a) puts the field on an unreleased serai crate and crypto-bigint
     0.7, whose last audit predates 0.7's divergence.
   - (d) puts it on fiat-crypto's generated code, proved correct in Coq,
     with no new dependency.
   - (b) is the same representation as (d), hand-written, and is not
     prototyped.
   - (c) blinding costs at least one extra multiplication per
     multiplication, and its reach is unclear.
   - Option: none of them, until the baseline and the direct rows say
     whether a representation change is flat at all.
   - Which, if any, should go to a fork PR once the measurements are in?
2. **What closes `CA-1` beyond the field?** `Field25519` and
   `ciphersuite` keep crypto-bigint 0.5 in every lock until one of:
   - serai releases `dalek-ff-group` and `ciphersuite` on 0.7;
   - Shekyl pins serai `next` by revision, with the API migration of §6.
     That is a consensus-boundary PR of its own.
   - A third route: `Field25519` on fiat-crypto as well. This one is not
     examined here.
   - Is the ignore kept until a serai release, or is the pin built?
3. **Upstream.** monero-oxide's Contributing.md rule 1 bars contributions
   written with an LLM agent, so what can go upstream is a notice with
   links, as in October.
   - Should the notice on monero-oxide#210 offer (d)'s shape (fiat-crypto
     Montgomery for this prime) as a finding, once it is measured?
4. **The threat-model note (§8).** It lands with the fix's release by
   `CA-2`'s criterion. Alpha releases already predate the fix. Does it
   land now?
5. **The order against the resync.** DRS-X proposes resyncing the fork
   to upstream's 2026-11-26 commits. That changes the prover's divisor
   path, which the one-proof timing measures, and the curve code a port
   touches.
   - Does the resync go first?
   - Does a field port wait for it, or go into the same fork round?

**The shipped prover has the direct path's shape on Linux x86_64.** §2's
threat frame takes the harness's direct path as the closer analogue of the
prover. A release `shekyl-cli` was disassembled: `cargo build --release`
at `8b5f8e2674`, `x86_64-unknown-linux-gnu`, rustc 1.94.0.
- It has no standalone `HelioseleneField` mul or square symbol.
- `red512`'s constant is inlined into 53 functions of the prover,
  verifier and curve code: `ArithmeticCircuitStatement::prove`,
  `Divisor::merge`, `SelenePoint` add and double, `LinComb` arithmetic
  and the divisor gadgets.
- The wide multiply in them is an out-of-line call, as in every `CA-2`
  record.

The scan is in shekyl-dev
`infrastructure/captures/ca-round0-prototypes/2026-11-28/`. The Windows
and aarch64 release binaries are not scanned yet. The harness's MSVC
build has the same direct-loop shape (amendment 1).
