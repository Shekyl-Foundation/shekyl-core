# V3.1 Multisig — Rust engine integration design

**Status.** **Round 1 OPEN** (remaining: F-6 clippy-green / F-3 delete
debt + F-7 SoloSigner framing). F-6 CI **lane landed** (this follow-on PR).
Doc-only branch `docs/v31-multisig-rust-engine-plan`. Protocol crypto:
[`PQC_MULTISIG.md`](../PQC_MULTISIG.md) (DRAFT v1.1).

---

## Corrected picture (2026-07-14) — read this first

### The design is done, and it's good

Every load-bearing question was answered in April, with provenance.
Nothing in that list needs revisiting. Session findings were about
**tree/gate/docs**, not redesign.

| Decided | When | Provenance |
| --- | --- | --- |
| **Option C** — per-output PQC keys (X25519+ML-KEM-768) | 2026-04-04 | Fixed key in `pqc_auth` collapses anonymity set to 1 |
| **Option D** — C + N classical spend-auth in `tx_extra` | 2026-04-15 | A/B rejected on forward privacy |
| Equal participants, coordinator-less, deterministic construction | 2026-04-15 | Governance |
| **C.alpha-rotating** — prover per output (named 1/N loss) | 2026-04-15 | *"that is simply a limitation at this time"* — both rotating and fixed were defensible |
| **Solution C** — independent per-participant spend-auth, publicly verifiable | v1.1 Round 3 | Fixed non-implementable §11.3 |
| **scheme_id = 2** — M-of-N hybrid (Ed25519 + ML-DSA-65) | earlier | PQ authorization **today** |
| V3.2 rotation deferred; hooks reserved | §15.2 | Design-maturity, not scope protection |
| V4 deferred — FROST-SAL + lattice threshold | §15.4 | NIST Threshold Call ≠ standardize; ~2027 → 2030+ |
| Staking as product driver | 2026-04-15 | Economics of ~3× size vs threshold custody |

The two "competing models" raised in review resolve **into** this table:
rotating-vs-fixed **prover** closed Apr 15; per-output-vs-group **key**
closed Apr 4. The FROST lineage is a **pre-Option-C fossil** (DELETE),
not a fork.

### Where the tree actually is — three buckets

**1. Frozen at genesis (feature gate does not protect these) — Track A**

| Surface | State |
| --- | --- |
| Tx-wide `scheme_id` agreement | Blocks scheme-2 funding + scheme-1 bond vin. → **MSW-6** (staking unblock) |
| `PQC_MAX_*_BLOB` | DoS fossil; exactness belongs in parse. → **MSW-1** (MAX=5; single-source `SINGLE_KEY_CANONICAL_LEN`) |
| `MULTISIG_KEY_HEADER_LEN = 2` | Header is 3. → **MSW-1** |
| Version bytes | Address payload correct; `group_id` hashes constants. → **MSW-4/5** |
| `MAX_MULTISIG_PARTICIPANTS` | **MSW-G = 5** (2f+1 at f=2; withdraws same-day 8). → **MSW-1** |
| Leaf / scheme separation | Length primary; untested. → **MSW-2** |
| `bond_spend_pk` | Stays 1996 — **MSW-7 retracted** (pseudonym uniformity) |
| Address `hybrid_sign_pubkeys` | Vestigial (zero consumers). → **MSW-8** |

**2. Behind the gate — designed, scaffolded, uncompiled — Track B**

FROST Option A fossil (**DELETE**) · `frost-sal-v4` specified never built ·
**no CI `--features multisig`** · `MultisigGroup` hygiene · `MAX_INPUTS=128`
vs consensus 8 · fee model no multisig arm · prover grinding (availability)
· `MultisigSigner<N,K>` absent · `EngineSignerKind` phantom marker · no
scanner path.

**3. Docs that mislead (Phase 0)**

`V3_ROLLOUT` Option A prose + size table + staking note — Phase 0 ·
§5 MSW-G=5 derivation · §11.1 grinding · §15.4a/b · §16.4/16.7 ·
privacy stream-attribution · `bond_wire` uniformity comment · Pin #4
reversion for MSW-6.

### The gap isn't the design

The design was never built; the parts that leaked past the gate leaked
into **consensus**. Today it reads "mostly implemented, needs wiring."
It is **"fully designed, scaffolded, uncompiled — with a consensus bug
in the one layer the gate never covered."**

What should be true today and isn't:

1. Scheme-2 funding may share a tx with a scheme-1 bond vin (**MSW-6**).
2. Blob bounds are a DoS ceiling; exactness is in the parse (**MSW-1**).
3. Version bytes plumb from address payload into `group_id` (**MSW-4/5**).
4. CI compiles `--features multisig` (**F-6**).
5. Operator docs match Option D + whole-tx weights (Phase 0).
6. FROST Option A lineage gone (DELETE disposition; impl pending).
7. MAX=5 with written §5 derivation (MSW-G).

### Process — differential rigor

Maximal process on Track B (~4y then legacy) with Track A historically
out of scope was the **inversion**. Genesis-frozen earns unlimited
rigor; gated replaceable subsystem earns a bounded, well-sealed design.
**Track A is the urgent half.** Track B keeps rounds + halt — not the
priority queue.

### Reviewer scorecard (what held / what didn't)

| Held | Retracted |
| --- | --- |
| F-1 (fossil bounds) | Leaf preimage must change |
| MS-8 redundant with leaf | "Deferral has no recorded justification" (§15.4 existed) |
| Track A/B split (better justification from coexistence) | "Mandatory prover is permanent" (§15.5 versions it) |
| | "Per-output vs group key is a Phase 6 cryptographer question" (answered Apr 4; `pqc_auth` is plaintext) |

Twice absence was claimed without searching. Search first.

---

**Process.** Cites
[`STAGE_1_PER_PR_TEMPLATE.md`](STAGE_1_PER_PR_TEMPLATE.md) and
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
**Halt condition (Track B only):** no Track B implementation until
design closure + pre-flight + explicit go-ahead. **Track A** is **not**
held by that halt — still needs **explicit go-ahead** (`feat/msw-*`).

**Trigger fired.**
[`V3_ENGINE_TRAIT_BOUNDARIES.md`](../V3_ENGINE_TRAIT_BOUNDARIES.md)
§10.3.1 (2026-07-14).

**Identifier families (rule 94).**

| Family | Owns |
| --- | --- |
| **MS-1…MS-N** | Track B engine-integration Round 1 questions |
| **MSW-1…MSW-N** | Track A V3.0 pre-genesis multisig **wire** work: bound-family reconcile + disjointness + misattribution + **version-byte hooks** (MSW-4/5) so 2030+ migration paths stay open; **not** a leaf-preimage change |
| **R1-F-N** | Round 1 adversarial findings (doc-scoped; this file) |

Prefix `MS` / `MSW` uniqueness: registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2.

**Pin discipline (R1-F-10 — accepted).** Verification pins are
**`dev`-at-time-of-recording**, not "this branch tip." Design-branch
HEAD diverges immediately. Re-pin at Round 0 / Track A pre-flight.
§2.3 rows name the pin they were verified against.

| What | Pin |
| --- | --- |
| Design branch opened | `dev` = `13bd508c7` (2026-07-14) |
| Round 1 adversarial verification (reviewer) | `dev` = `b23cdaff0` (2026-07-14; +9 archival commits, no multisig surface move) |
| Local re-check of R1-F-1 arithmetic + F-2-retraction prefix layout | this design-branch tree |
| F-2 retraction / blast-radius / size Q&A | reviewer pin `b23cdaff0` (2026-07-14) |
| Corrected picture / F-3 DELETE / coexistence | this design-branch tree (2026-07-14/15) |

---

## §0 Structural disposition — Track A / Track B split

Accepted from Round 1 adversarial review (2026-07-14), **revised**
same day after F-2 retraction + blast-radius / size Q&A.

### Track A — V3.0 pre-genesis wire (**revised 2026-07-15 overhaul**)

Always-compiled tx / deserialize / verify surfaces. Ship whether or not
`multisig` flips. **Archival core is untouched** (confirmed at source:
`verify_*_bond_post(vin, record_state)` never sees funding inputs /
`pqc_auths` / `scheme_id`; `emission_verify.rs:20` — FCMP fee balance
is C++ tx layer, not that module; Rust submit verifier has no archival
arm). Architecture already separates: **P hot/disposable**,
`bond_spend_pk` cold/once (JoinMarket vin only, §9.11), **multisig holds
funds before and after**.

**MSW-7 retracted.** `bond_spend_pk` stays exactly
`SINGLE_KEY_CANONICAL_LEN` (1996). Pseudonym uniformity — all P's look
the same; a bond commits exactly one hybrid key so no bond is
distinguishable by controller structure. Anonymity constraint, not a
bounds check. Rule-21 reopen: only if P-set uniformity is abandoned.
Amend `bond_wire.rs:24-28` accordingly (PR #229 truncation note stays
true and incidental).

#### Wire work

| ID | Work |
| --- | --- |
| **MSW-6** ✅ **LANDED** | **Relax tx-wide `scheme_id` agreement** — the staking unblock. `expected_scheme = tx.pqc_auths[0].scheme_id` forced every input to match, so scheme-2 funding could not share a tx with a scheme-1 bond vin. **Change (option a — drop the agreement):** each input is still validated per-input (scheme ∈ `{1,2}`, blob length, signature); only the cross-input agreement is removed, in lockstep across both batteries — `tx_pqc_verify.{h,cpp}` + `blockchain.cpp` (C++) and `verifier.rs` (Rust twin). **Why (corrected — *not* "guards nothing", a §11.8 error):** the *stated* purpose (a cross-input scheme-downgrade defense) was vacuous — self-referential, and per-output scheme binding is the leaf hash `h_pqc = H(hybrid_public_key)` (`blockchain.cpp:3769`), not this check. Its *actual* effect was to make a tx that spends a solo (scheme 1) and a multisig (scheme 2) output together unrepresentable — a **cross-model linkage** (co-spending is the only proof of common control under FCMP++). That has **no externality** (one-time keys, FCMP++ proof over the whole tree — no other set shrinks, unlike a small ring poisoning decoys) and mirrors Shekyl's own opt-in `scheme_id=2` self-marking cost, so it is a *wallet coin-selection invariant* — which must land as a **blocking E′/MS-5 ship gate** (never cross key models, with a test, + disclosure), not a consensus mechanism. (**Not TM-1**, whose disposition rests on impossibility — it does not transfer to this case where the mechanism existed and worked.) **Proof:** `fcmp.cpp::msw6_mixed_scheme_transaction_verifies` — a solo(1)+multisig(2) tx verifies, with a tamper control pinning the per-input signature binding. **Independent of `--features multisig`.** Own validation surface. |
| **MSW-1** ✅ **LANDED** | **Bound family (narrowed).** Copy `bond_wire.rs:11` pattern: `use shekyl_crypto_pq::multisig::SINGLE_KEY_CANONICAL_LEN`. Kill duplicate `1996` literals in `shekyl-wire::transaction` / `cryptonote_config.h`; delete `tx_pqc_verify.cpp:49` shadow. Split jobs: `PQC_MAX_*_BLOB` = **generous DoS ceiling** (round number, documented headroom; bump needs consensus rationale); correctness = `MultisigKeyContainer::from_canonical_bytes` exact-length parse. Cross-seam KAT `n ∈ 1..=MAX` through both deserializers (absence produced F-1). Sized for **MAX=5**. — **Landed:** `HybridPublicKey/Signature::CANONICAL_LEN` is the one canonical length; `SINGLE_KEY/SIG_CANONICAL_LEN` alias it; ceilings decoupled (16384 key / 32768 sig — the sig ceiling is **not** 16384, which would make a max-threshold spend unserializable) with compile-time `const _` ladder asserts; fossil `2 + N·LEN` deleted from `cryptonote_config.h`, `tx_pqc_verify.cpp`, `shekyl-wire`. **Bound-family sweep:** `multisig_receiving.rs:177` + `shekyl-address` ×3 also hardcoded `> 7` — deduped to `MAX_MULTISIG_PARTICIPANTS`, and the crypto-pq↔address caps are **pinned equal at compile time** (`const _` in `multisig.rs`; crypto-pq already depends on address). **F-1 catcher:** `shekyl_pqc_canonical_lens()` FFI + `fcmp.cpp::msw1_pqc_constants_match_rust` prove C++ config == Rust across the FFI (31/31 fcmp green); Rust cross-seam `msw1_container_lengths_and_roundtrip_over_all_n`. |
| **MSW-2** ✅ **LANDED** | Disjointness KAT — **length primary**, byte[2] secondary. Leaf left alone. — **Landed:** `multisig::tests::msw2_length_primary_disjointness` — `1996 ∉` container lengths, `expected_blob_len` strictly increasing (injective) so distinct `n` never collide, a length-relabelled blob is rejected on the length cross-check (not the bounds check), and `byte[2] = m_required ≥ 1` ⊥ reserved-zero as the secondary separator. |
| **MSW-3** ✅ **LANDED** (via MSW-6) | `"output committed="` misattributions; MS-8 retirement record. — **Landed:** the misattributed `"output committed="` string was already removed by **MSW-6** (#314); no such literal remains. **MS-8 retirement recorded** here: `group_id` verify is a no-op check → folded into MSW-2's disjointness reasoning; MS-8 stays RETIRED. |
| **MSW-4** ✅ **LANDED** | `multisig_group_id` reads versions from `MultisigAddressPayload` (already has `version`/`group_version`/`spend_auth_version`) — plumbing gap, not container change. — **Landed:** `multisig_group_id_from_address(container, &MultisigAddressPayload)` sources `group_version` + `spend_auth_version` from the payload (crypto-pq→address dep); the bare `multisig_group_id` wrapper is now documented tests/fuzz-only (fabricates the axes from constants). KAT `msw4_group_id_reads_versions_from_address_payload`: the version bytes are load-bearing (spend_auth `0x01` vs `0x02` ⇒ distinct group_id), and a payload/container shape mismatch is `ParameterBounds`, never silently hashed. **FFI/engine rewiring to call `_from_address` is Track B (MS-*).** |
| **MSW-5** ✅ **LANDED** | Disposition **(A)** — address/`group_id` intentional carrier; already built on the payload. KAT reserved `0x02`. — **Landed:** `multisig_address::tests::reserved_spend_auth_version_is_carried` — a reserved `spend_auth_version = 0x02` round-trips unchanged (never normalized or rejected), so forward-compatible readers (§8.2) can dispatch on it. |
| **MSW-8** ✅ **LANDED** | **Delete `MultisigAddressPayload.hybrid_sign_pubkeys`.** Vestigial — constructed/validated/serialized/parsed, **never consumed** (`multisig_receiving.rs:163` populates leaf keys from KEM; address field unread). Solution C fossil. Free pre-genesis. Applies to D and E′ identically. ~2.6× address shrink is **this**, not E′. — **Landed:** field + its error variants (`SignPubkeyCount`/`SignPubkeyLength`) + serialize/parse loops removed; `PER_PARTICIPANT_LEN` collapses to KEM-only (1216), address payload `10 + N·1216`. Zero external readers verified. `PQC_MULTISIG.md` §6.2 is authoritative. **Test-vector regen** (`PQC_TEST_VECTOR_002_MULTISIG.json`) landed as its own concern. |
| **MSW-G** ✅ **BUILT (MSW-1)** | **DECIDED MAX=5** (2026-07-15 overhaul; withdraws same-day MAX=8). See §0.3. |

#### Explicitly not changing

- `bond_spend_pk` length / shape (MSW-7 retracted)
- Bond record schema
- P (hot key) shape
- Emission vin
- Archival retention core / FFI verify signatures
- No "multisig archival coupling" inside bond semantics — MSW-6 is a
  **tx-layer** scheme rule only

### Track B — engine (MS-1…MS-7, gated) → **pivots to Option E′**

Round 1 still needs **F-6 CI** + **F-7** for any gated work. F-3
DELETE of Option A fossil stands (keep `frost_sal` / `frost_dkg`
primitives; drop `MultisigGroup.pqc_public_key`).

**Product path is Option E′** (§0.5) — dealer-mode, MAX=5,
`spend_auth_version = 0x02`, **`0x01` never issued**. Mandatory-prover
Option D machinery is deleted, not shipped. Spec after Track A + F-6;
implementation still needs explicit go-ahead.

### Hard scope pins (amended 2026-07-15)

1. **This branch is documentation-only** until the user issues an
   explicit implementation go-ahead. No production *logic*, no wire
   layout changes, no consensus constants mutated in code.
   **Reversion (named, 2026-07-15):** comment-only amendments in
   production source are permitted when they record a semantic this
   PR is pinning (e.g. `bond_wire.rs` HYBRID_PUBKEY_CANONICAL_BYTES
   — pseudonym-uniformity rationale for MSW-7 retract). No executable
   change; diff must be comments/docs inside the source file only.
   Reopen criterion for broader code: explicit go-ahead for Track A
   (`feat/msw-*`) or Track B. *(Pin #1 was violated silently by the
   `bond_wire` comment riding in `3b70404` before this reversion —
   same failure mode the pin exists to catch.)*
2. **Feature gate protects wallet orchestration only** — not
   `PQC_MAX_*_BLOB`, not the tx-wide scheme rule (MSW-6).
3. **Rust owns new wallet multisig logic.** Don't thicken `wallet2`
   PQC group surface.
4. **Archival bond *semantics* out of scope** for Track A/B wallet
   work. **Reversion (named):** MSW-6 *is* the permitted archival
   *tx-layer* coupling — relax scheme_id agreement so scheme-2 funding
   may accompany a scheme-1 bond vin. It does **not** reopen archival
   core, `bond_spend_pk`, or record shape. Prior Pin #4 absolute
   "no archival contact" is withdrawn for that one rule only.
5. **Track A** on `feat/msw-*` after explicit go-ahead. Sequencing
   below. **MSW-G = 5** must be cold before MSW-1 mutates bounds
   (see P-3: 8→5 withdrawal inside this PR would have frozen wrong
   `expected_blob_len` if it had been code).
6. **V4 rewrite-and-coexist** (§0.4). Discriminability > evolvability.

### Sequencing (implementation order when go-ahead lands)

1. **Phase 0 docs** — stop the misdirection (ROLLOUT fossils, §5
   MSW-G derivation, §11.1 grinding reframes, §15.4a/b, §16.4/16.7,
   privacy stream-attribution, `bond_wire` comment, Pin #4 reversion).
   Doc-only; no feature gate.
2. **MSW-6** — own validation surface; staking unblock; independent of
   `multisig` feature.
3. **MSW-1/2/3/4/5/8 at MAX=5** — one surface; cross-seam KAT is the
   gate; MSW-8 deletes address `hybrid_sign_pubkeys` fossil.
4. **F-6** CI `--features multisig` — Round 1 closure + Track B trust.
5. **Option E′ spec + `frost-sal-v4` gate** — product path (§0.5);
   deletes mandatory-prover Option D scaffold.

---

## §0.3 MSW-G — **DECIDED: MAX = 5** (2026-07-15 overhaul)

**Decision.** `MAX_MULTISIG_PARTICIPANTS = 5`.

**Code vs docs.** Decision is normative for Track A. Live constants
remain `= 7` until **MSW-1** (this PR does not cut over the constant —
pre-genesis cutover is its own surface). Normative protocol prose that
states `= 5` must carry the same "decided / not yet enforced" label
(`PQC_MULTISIG.md` §5).

**Derivation (write into `PQC_MULTISIG.md` §5).** MAX = **2f+1 at f=2**
— classical majority-threshold BFT for the *largest group we intend to
serve*, not a resource/zone/bias bound. Consumer: largest group served.
**Not** "fill the reward zone" and **not** "power-of-two for modulo bias."

**Withdraws same-day MAX=8.** The 8 pick optimized an irreducible
3-fault-vs-zone conflict under "security > performance → N≥7" and then
picked 8 because the zone lens was binary once crossed. That framing
treated the *cap* as the BFT parameter. Correct framing: the operator
chooses m-of-n ≤ MAX; MAX is the largest n we ship tooling for. **5**
serves 3-of-5 (f=2) cleanly, stays inside today's de-facto fossil
behavior for worst-case size, and matches Option E's intended product
surface. Rule-21 reopen of MAX: only if a named consumer requires
n>5 *and* zone/address usability are dispositioned.

### Lenses that do not pick MAX

| Lens | Disposition |
| --- | --- |
| **Bias** | Wide-reduce separately; not a consensus-constant driver. |
| **Hostage fraction** | **Retracted** — `E[frozen]=p`, independent of n. |
| **Reward zone** | Informs worst-case fee UX; does not set MAX under the 2f+1 derivation. |
| **Address bech32m** | After **MSW-8**, payload is `10 + N×1216` (KEM only). N=2 ≈ QR-able. Does not set MAX. §15.3 registry **re-priced** — optimization, not prerequisite. |

---

### Lattice threshold / §15.4 — out of Track A; posture pin

**Hybrid posture (pin 2026-07-14).** Scheme_id=2 is already
post-quantum for authorization (M × ML-DSA). Solo and multisig share
classical FCMP++ membership/SAL + hybrid auth via `h_pqc`. Multisig
adds **no** classical exposure. Classical SAL is a **liveness**
dependency (1/N *loss*), not a compromise path. Curve HNDL on
membership privacy is real and **not multisig-specific**. Under
Option D, grinding / rotation / griefing were **availability
engineering** (MS-4/5). **Under E′** those surfaces largely die with
the mandatory prover; remaining availability work is FROST nonce
discipline (MS-5 restated) — not the Phase 6 cryptographer queue
beyond the small `y_out` tweak claim. Shipping now ≈ economics
(~2.4× tx size for 5-of-5 threshold custody), not crypto-maturity.

**§15.4 phrase pin:** "pure-PQC spend-auth" ≠ lattice SAL (impossible
under FCMP++). `spend_auth_version = 0x02` = **15.4a** threshold
classical SAL. **15.4b** = composite / lattice-only *auth* size win.
Full text: `PQC_MULTISIG.md` §15.4.

**NIST / TRacoon:** IR 8214C is reference-only (deferral hardened).
TRacoon wrong N regime + trusted KeyGen + not FIPS. Watch TALUS /
dPN25 for 15.4b size. Do **not** couple to F-1 / MSW-G.

---

## §0.5 Option E′ — intended use of two-component `O` (2026-07-15)

**Status.** Design pin for the **product** multisig path. Spec detail
and implementation await Track A + F-6 + explicit go-ahead. Replaces
"Option E later" with a named shape. **Take E′, not plain E.**

### The one-line change

Solo binds both components to the wallet: `b` long-term, `y` per-output
KEM-derived; recipient holds both.

**Option E′ splits them across trust axes** — the intended use of
`O = ho·G + B + y·T` (`shekyl-crypto-pq` `output.rs:286-304`):

| component | in solo | in Option E′ | enables |
| --- | --- | --- | --- |
| **`b` → `B = b·G`** | wallet spend secret | **group-plaintext.** Every participant holds it. | `ho`, `x = ho+b`, key image `I = x·Hp(O)` → **local scan, local balance, local spent-detection** |
| **`y` → `Y = y·T`** | per-output, KEM-derived | **FROST M-of-N group secret** (with per-output tweak below) | **spending.** Nothing else. |
| `ho`, `z`, amount keys | per-output KEM | per-output, N-fold fan-out of one secret `s` | `O` stays one-time |
| per-output PQC key | KEM-derived | per-participant from **their own** `ss_i` | M hybrid sigs, `scheme_id=2`, no group fingerprint |

`compute_output_key_image(&combined_ss, idx, &spend_secret, &hp_of_output)`
— **`y` is not an argument.** That is the whole thing. Apr 9 named the
`y = 0` complaint: *"an attacker who learns `x` can spend it without
needing any T-side secret."* With `y ≠ 0`, **`x` is discovery and `y`
is authorization.** E′ thresholds exactly the component that was
already the spend-auth.

`b` becomes a group **view+link key**. Compromise one participant →
they watch, they can't spend. A security model users already have a
name for.

### E vs E′ — take E′

| | `y` per output | output algebra vs solo |
| --- | --- | --- |
| **E** | fixed `y_group` for all group outputs | `O₁−O₂ = (ho₁−ho₂)·G` (no T term) |
| **E′** | `y_out = y_group + y_kem` (`y_kem` per-output, public to group) | same *shape* as solo: G and T terms both move |

FROST signs under `Y_group`; `y_kem·T` is added in the clear — standard
key tweak (Taproot-shaped). E does not *obviously* leak (differences
are still just points without the DL), but **E′ costs one scalar
addition** and keeps every future analysis's "per-output `y`"
assumption. Under "don't be structurally special," take the free one.

**E′ is the lean.** The tweak soundness claim is standard but still a
crypto claim → **Phase 6**, as a small well-formed question, not
"review our protocol."

### Why it's usable — two unlocks

1. **No `export_multisig_info`.** Monero's killer was split spend keys
   forcing a file round-trip with every co-signer *before you can see
   your balance*. Here nobody needs a ceremony to know what they have.
   **Absent by construction, not fixed.**
2. **No DKG for the ship product.** One owner, three devices ⇒ **the
   owner is the trusted dealer.** Generate `b`, generate `y_group`,
   Shamir-split `y_group` locally, write three files. One button.
   TRaccoon's paper concedes the same trusted-KeyGen assumption. DKG
   exists for mutually-distrusting parties (buyer/seller/arbitrator) —
   **reserve it** behind a later `spend_auth_version` / ceremony mode;
   **do not ship it** as the default.

Net UX: **SLIP-39-shaped setup, local balance, and one ceremony at the
only moment a ceremony belongs — spending.**

### What it deletes (mandatory prover is the root)

| dies | ~lines (tree today) |
| --- | --- |
| `v31/prover.rs` — assignment, receipts, vetoes, equivocation | 231 |
| `v31/heartbeat.rs` — prover-availability | 274 |
| `v31/counter_proof.rs` — prover equivocation | 297 |
| `rotating_prover_index` + `% n` bias + grinding finding | — |
| `validate_multisig_output_at_receive` (I7) | — |
| griefing scores, R-F storage question | — |
| much of `v31/invariants.rs` | ~491 |

**Survives:** `messages.rs`, `encryption.rs`, `group_descriptor.rs`
(transport), `intent.rs`, `state.rs` (still agree on what to spend).

**Adds:** `frost_sal.rs` (852, in-tree; `y≠0` gate open) + **nonce
discipline** (F-9: make reuse unrepresentable by type, not by review).

### What it does *not* buy

- **Not smaller on the wire.** M hybrid sigs still ride; the leaf
  commits `H(pqc_pk)` and consensus verifies it. Same auth bytes as
  Option D. Size win = composite lattice sig (dPN25 / 15.4b, 2030+).
- **Does not fix the anonymity partition.** `scheme_id=2` and N-fold
  fan-out remain visible. Same cost at N=3 as at N=5. Honest price;
  April priced it circularly ("negligible volume").
- **Address size is not an E′ win.** The ~2.6× shrink
  (`PER_PARTICIPANT_LEN` 3200 → 1216) is **MSW-8** — deleting the
  vestigial address `hybrid_sign_pubkeys`. D gets it too. E′ address
  adds `B` + `Y_group` on top of N×1216; still smaller than today's
  fossil, still a file at N=5. §15.3 registry re-priced (below).
- **Nonce discipline is the new footgun.** F-9 already found `sign_own`
  with no state guard.

### Status in-tree

| | |
| --- | --- |
| **Open** | `output.rs:304` two-component landed, `y ≠ 0` — Apr 9 blocker dead. `frost_sal.rs` + `frost_dkg` exist (852 + 423). |
| **Wrong** | They sit under `MultisigGroup` with **Option A** `pqc_public_key` (fixed per group). **DELETE** that wrapper; **keep** the FROST primitives. |
| **Missing** | `frost-sal-v4 = []` was specified in §16.7 and never built — that is **E′'s feature gate**, and building it is the first real coexistence boundary (discriminability for 0x02). |
| **Version** | `spend_auth_version = 0x02` for E′; **`0x01` never issued.** §15.5 + MSW-4/5 make that real instead of aspirational. |
| **Address** | After MSW-8: KEM-only per participant. E′ layout: `B` + `Y_group` + N×1216 + `spend_auth_version=0x02`. |

### MSW-8 — address `hybrid_sign_pubkeys` is vestigial (CLOSED)

**Confirmed at source.** `multisig_receiving.rs:163`: *"hybrid_sign_pubkeys:
populated by this function using per-participant KEM derivation."*
`:186-214` encaps to each address `kem_pubkey`, derives spend-auth /
view-tag / hybrid sign seed from `ss` — **never reads address sign
keys.** In `multisig_address.rs` the field is declare / construct /
validate / serialize / parse — **and nowhere else in the tree.**

`multisig_group_id` hashes `MultisigKeyContainer` keys (the leaf
ephemeral hybrid keys), not the address field. §5.3 prose that
"signing pubkeys in the address define group identity" is itself
fossil — code never did that from the address.

**Disposition:** **MSW-8** — delete `MultisigAddressPayload.hybrid_sign_pubkeys`
(+ `HYBRID_SIGN_PUBKEY_LEN` / `PER_PARTICIPANT_LEN` collapse to 1216).
Free pre-genesis; hard fork after first issuance. Same for D and E′.

| N | today (fossil) | after MSW-8 |
| --- | --- | --- |
| 2 | ~10,300 chars | **~3,900** ← QR-able (alphanumeric cap ~4,296) |
| 3 | ~15,400 | **~5,850** |
| 5 | ~25,700 | **~9,740** |

**§15.3 re-price:** chain-anchored group registry was carrying the
fossil's weight. At ~5,850 for 2-of-3 it is an optimization; at 15,400
it looked like a prerequisite. **Registry may leave the critical path.**
P0-m demoted accordingly.

**Defect class (named):** fifth constant/field this session whose
semantics lived only in imagined consumers — `PQC_MAX_*_BLOB`,
`MAX_MULTISIG_PARTICIPANTS`, `bond_spend_pk` length rationale,
fused `group_version`, and now a field with **zero** consumers.
Not five bugs — one class: **shape-from-prose without a read site.**

### Relation to Track A / 15.4a

E′ *is* 15.4a in product form (threshold classical SAL on `y`), shipped
as the only issued `spend_auth_version` rather than a later migration
from mandatory-prover 0x01. Track A (MSW-1…6, **MSW-8**, MSW-G) still
lands first — wire bounds, scheme rule, version plumbing, address
fossil — because E′ still uses `scheme_id=2` containers and
genesis-frozen bytes.

---

## §0.4 Coexistence pin — V4 rewrites beside V3.1; it does not replace it

**Source.** §15.5: no implicit upgrades; migration is an explicit tx.
**Product path (E′, §0.5):** only `spend_auth_version = 0x02` is issued;
`0x01` never lands on-chain. A later stack (lattice auth, mutual-distrust
DKG mode, …) lands **beside** E′ under a new version/HRP — you do **not**
`rm -rf` the E′ stack. Both stay live forever, discriminated by
**version byte and address HRP**.

*(Historical §15.4 prose about "0x01 outputs remain spendable" assumed
a mandatory-prover V3.1 that E′ replaces before issue. If any 0x01
test/fixture outputs exist, they stay spendable under §15.5; they are
not a product surface.)*

### What V3.1 owes V4 is discriminability, not evolvability

Plan §1 three-timeframes asked: *must not bake classical-only
assumptions into durable ledger fields or trait method signatures that
Stage 4 cannot evolve.* Under rewrite-and-coexist, **you never evolve
those fields.** V4 writes its own. What V3.1 owes V4 is a
**discriminator that works**. §15.5 already forbids the flexibility §1
asked for.

That sharpens R1-F-11 / MSW-4/5 / MS-7:

- Do **not** make `PersistedMultisigOutput.spend_auth_pubkey` an
  evolvable enum "for Stage 4."
- Do make it a **versioned record whose discriminator is real** —
  exactly the three bytes that are today one fused byte, one hardcoded
  constant, and an incomplete KAT. Under a rewrite those bytes are
  *the entire interface* between V3.1 and V4.

### Differential rigor (process inversion named)

| | Design life | On the rewrite |
| --- | --- | --- |
| **Track A** — blob bounds, version bytes, N cap, leaf/scheme separation | **Permanent** | Outlives V4; V4 inherits every one |
| **Track B** — MS-1…MS-7 trait/engine/transport | **~4 years, then legacy** | Dies as active design; survives as maintenance |

"Get it right, not get it now" is **differential**. Genesis-frozen
surfaces earn unlimited rigor (Track A). A subsystem with a known
replacement date earns a **bounded, well-sealed** design (Track B),
not an architecturally-integral-forever one. Current process load
(three rounds, pre-flight, R-*/CL-*, P0-*) on Track B with Track A
historically out of scope was the **inversion**; this pin corrects it.

### MS-1 under coexistence

`Engine<S: EngineSignerKind>` must hold **solo + two multisig stacks**
simultaneously forever. `signer.rs:12` names `MultisigSigner<N, K>`
and never defines `K` — threshold? Or **scheme / spend_auth version**
(the coexistence axis)? Round-2 load-bearing: MS-1 is not picking a
shape for V3.1 alone; it is picking the shape that holds two multisig
implementations at once.

| Candidate | Under coexist |
| --- | --- |
| **MS-1(b)** extend PendingTx/Refresh/Key methods | Threads *two* schemes through five traits — **rejected** under §15.5 rewrite |
| **MS-1(a)/(c)** standalone / cuttable seam | Can stand a second stack beside the first — **preferred**; both "permanent" and "temporary-then-coexisting" argue for a cuttable seam. Only "temporary and gradually evolved" favored (b), and §15.5 forbids that |

### F-3 — Option A fossil, not a competing V3.1 model (**DELETE**)

**Wrong axis corrected (2026-07-14).** The fork under
`multisig/{dkg,group,signing}.rs` is **not** the Apr 15
fixed-prover vs rotating-prover fork (both were Option C/D —
per-output KEM + per-participant spend-auth; you chose rotating with
eyes open on 1/N permanent-loss — §15.4). It is also **not** a V4
seed to quarantine.

It is **Option A** (fixed group-aggregate PQC pubkey), rejected
**2026-04-04**: a fixed `hybrid_public_key` in plaintext `pqc_auth`
is a ~1996-byte fingerprint that collapses FCMP++ anonymity. Option
**D** (N parallel KEM + N classical spend-auth in `tx_extra`) won.
`MultisigGroup { group_id, serialized_keys, pqc_public_key }` is that
rejected model — one PQC pubkey per group for life — surviving only
because nothing compiles it. v31's per-output `MultisigKeyContainer`
is the shipping design.

**Do not move it behind `frost-sal-v4`.** The artifact fuses two axes:

| Field | Axis | V4 want? |
| --- | --- | --- |
| `serialized_keys` (FROST threshold) | **SAL** | Yes — legitimately fixed-per-group for real FROST-SAL |
| `pqc_public_key` (fixed group) | **PQC auth** | **No** — Option A, rejected |

A real V4 FROST-SAL keeps the first and must never have the second.
Keeping this blob costs four years of F-3 confusion to buy a seed
you'd throw away.

**Disposition: DELETE** `multisig/{dkg,group,signing}.rs` (+
`MultisigGroup` / tests) under Track B go-ahead (or a tiny cleanup
PR). F-4 / F-5 / F-9 evaporate with it. `frost-sal-v4` (§16.7) remains
worth building as the first **coexistence** boundary when there is a
*clean* SAL-only scaffold — not around this fossil.

**Prose fossil:** `V3_ROLLOUT.md` still documents coordinator-held
single classical key — Option A as shipping design. **P0-h** (landed
partially this commit).

**Retraction:** claiming "per-output vs fixed-group privacy is a
Phase 6 cryptographer question" was wrong — answered in-repo since
Apr 4 (`pqc_auth` plaintext fingerprint). Search before pointing at
external review.

---

## §0.1 Round 1 adversarial findings (R1-F-N)

Reviewer verification pin: `dev` = `b23cdaff0`. Local arithmetic /
path confirmation on this branch. Disposition column is **this
design's acceptance**, not implementation.

| ID | Sev | Finding (one line) | Disposition |
| --- | --- | --- | --- |
| **R1-F-1** | CRITICAL | Fossil `PQC_MAX_*_BLOB`; N=7 unserializable. | **Accepted → MSW-1 + MSW-G=5** (DoS ceiling + exact-length parse; MAX=5 after overhaul). |
| **R1-F-2** | CRITICAL → **retracted as leaf change** | Original: change leaf preimage / treat length as sole separator. **Retraction:** leaf shared scheme-1+2; change not free. Cross-scheme already impossible: **length primary** (`1996 ∉` scheme-2 lengths); **byte[2] secondary** (`reserved==0` ⊥ `m_required≥1`). MS-8 redundant. Dual `DOMAIN_PQC_LEAF` = hygiene debt. | **Leaf change REJECTED.** **MSW-2 = both separators (length primary).** **MS-8 RETIRED.** Misattribution → MSW-3. |
| **R1-F-3** | HIGH | `multisig/{dkg,group,signing}.rs` = **Option A** fixed-group PQC key fossil vs v31 Option D. Not the Apr 15 rotating-vs-fixed *prover* fork. | **DELETE** (not `frost-sal-v4` quarantine). Fuses SAL keys (V4-want) with `pqc_public_key` (Option A, rejected 2026-04-04). Unblocks MS-1 lineage. F-4/F-5/F-9 evaporate on delete. |
| **R1-F-4** | HIGH | Two `group_id` defs: deterministic `multisig_group_id` vs caller-supplied `dkg.rs` context. | **Accepted → evaporates with F-3 DELETE** (DKG caller-supplied id dies with the file). Canonical = `multisig_group_id` / v31. |
| **R1-F-5** | HIGH | `MultisigGroup` Serialize hex of secrets; un-zeroized `Vec` reassign; not a `WalletLedger` extension — falsifies "confirm R6". | **Accepted → evaporates with F-3 DELETE.** R6 re-open against **v31** persist shape only (MS-7). |
| **R1-F-6** | HIGH | No CI job builds `--features multisig`. Gate armed, no positive compile trigger. | **Landed (this PR).** `ci/multisig-feature`: check/clippy/test + P0-n. First enable may clippy-fail on `frost_sal` — discovery, not greenwash. Round 1 closure still needs clippy-green / F-3 DELETE. |
| **R1-F-7** | MEDIUM | §3.1 "associated items only on multisig kind" is a compile error; `EngineSignerKind` has zero associated items; marker is aspiration. | **Accepted.** Correct framing: first associated item = trait-surface amend touching `SoloSigner` (`SigningCeremony = Infallible`). |
| **R1-F-8** | MEDIUM | Second verify site + five independent bound defs; folds into MSW-1 lockstep + MSW-3 misattribution. | **Accepted → MSW-1/MSW-3.** |
| **R1-F-9** | MEDIUM | FROST `sign_own` nonce-reuse; unauthenticated `participant` claims. | **Accepted → evaporates with F-3 DELETE.** |
| **R1-F-10** | LOW | Pin discipline: `dev`-at-recording ≠ branch tip. | **Accepted.** Banner + this table. |
| **R1-F-11** | HIGH | Version hooks: `multisig_group_id` hashes constants; address payload already has three separate §15.1 axes. | **Accepted → MSW-4 (plumbing) + MSW-5(A).** group_id must take versions from address payload. |

### Wargame table (accepted)

| # | Adversary | Armed at source? |
| --- | --- | --- |
| A1 | N=7 output lands; spend never serializes | **No** — R1-F-1 |
| A2 | Present scheme-2 blob against scheme-1 leaf (or reverse) | **Armed by construction** — **length primary** (`1996 ∉` scheme-2 lengths); byte[2] secondary. Guard both with MSW-2 KAT. |
| A3 | Spender lies about `group_id` | **Vacuous** — already in leaf; MS-8 retired |
| A4 | Mix scheme 1/2 across inputs | **MSW-6 relaxed (landed).** Stated purpose of the tx-wide agreement was vacuous (self-referential; per-output binding is the leaf hash `h_pqc = H(blob)`). Actual effect: forecloses a solo/multisig cross-model linkage → a wallet coin-selection invariant (**no externality** + the opt-in `scheme_id=2` precedent; **not** TM-1), which must land as a **blocking E′/MS-5 ship gate**, **not** consensus. Length disjointness (MSW-2) still prevents cross-scheme confusion. |
| A5 | Malicious DKG steers `group_id` | **No** — R1-F-4 |
| A6 | Replay `sign_own` / nonce reuse | **No** — R1-F-9 |
| A7 | Forge FROST `participant` index | **No** on FROST lineage |
| A8 | Flip ships never-compiled code | **Wrong-direction gate** — R1-F-6 |

**A2 + MSW-1:** raising bounds does **not** remove length disjointness
(1996 ∉ {2031…14199}); MSW-2 KAT remains belt-and-suspenders after
MSW-1. No leaf change.

---

## §0.2 Independent code audit of the findings (maintainer/agent)

Reviewed against this tree (same formulas as pin `b23cdaff0` for
multisig surfaces). Disposition: **confirm / sharpen / push back**.

### R1-F-1 — **CONFIRMED**

- `expected_blob_len(7) = 14199`; `PQC_MAX_PUBLIC_KEY_BLOB = 13974`
  (`cryptonote_config.h:290`, `shekyl-wire` twin). Sig twin:
  `23703 > 23697`. Arithmetic matches the review.
- Reject site is deserialize (`cryptonote_basic.h:458`), before verify.
- **"Correction, not growth"** holds: container layout already encodes
  14199; the ceiling was written for a pre-version/`spend_auth`
  formula.
- Local shadow `MULTISIG_MAX_KEY_BLOB = 2 + 7*1996` in
  `tx_pqc_verify.cpp:50-52` is the **same fossil**, and is wrong in
  *two* ways (header claimed as `n‖m` only — omits `version`; max
  omits `n·32` spend-auth). A naive "fix" of `3 + 7*1996 = 13975`
  would **still** reject N=7. MSW-1 must single-source
  `expected_blob_len` / the sig twin, not invent a third formula.
- Fund-loss shape holds: creating a payment *to* a multisig address
  does not put the key container in the creator's `pqc_auths`; the
  spend does. Output can land; spend fails to parse.

### R1-F-2 / leaf change — **RETRACTION HOLDS; byte[2] oversold**

- **Leaf change not needed / not free:** confirmed. `PqcLeafScalar`
  hashes raw `pqc_pk` bytes for scheme 1 and 2; retargeting the
  preimage is a cross-cutting ABI/vector/emission Auth-B change.
- **Dual-parse of one byte string as both `HybridPublicKey` and
  `MultisigKeyContainer` is already impossible by length alone:**
  solo is exactly 1996; scheme-2 lengths are `3+n·2028`
  (`2031…14199`). No integer `n` yields 1996. Both parsers require
  exact length (`cursor == len` / `expected_blob_len`).
- **Byte[2] `reserved==0` ⊥ `m_required≥1`:** real as a *header-level*
  check when a solo key blob is fed to `MultisigKeyContainer::from_canonical_bytes`
  (`bytes[2]==0` → `m_required==0` reject at `multisig.rs:120`). It is
  **secondary** to length for the actual parsers. Calling it "the"
  separator overstates; MSW-2 is still worth pinning as a rule-21
  invariant (reserved must not gain meaning; container version bumps
  must re-prove non-collision), not as the sole A2 defense.
- **A2 (lie about `scheme_id`):** with leaf-bound bytes, scheme-1
  verify requires `len==1996`; scheme-2 requires a container parse.
  Cross-scheme auth fails at length/parse without a leaf change.
  Blockchain comment that scheme binding "relies on the leaf hash"
  (`blockchain.cpp:4251-4253`) is imprecise — the leaf binds **bytes**;
  scheme is enforced by how those bytes parse under `scheme_id`.

### MS-8 retirement — **CONFIRMED**

`verify_multisig` check 9 recomputes `multisig_group_id(container)`
from the same blob the leaf already commits. Optional
`expected_group_id` cannot add binding the leaf lacks. Redundancy
argument does **not** depend on changing the leaf.

### Reward-zone / `MAX=7` — **MATH CONFIRMED; rhetoric trim**

- Per-input 7-of-7 `PqcAuth` ≈ **37911** bytes (header + varints + <!-- doc-literal-gate-allow: historical MAX=7-era reward-zone analysis -->
  14199 + 23703). `8 * 37911 = 303288 > 300000`
  (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`). Correct.
- Prefer: "a single legal maxed multisig spend **exceeds the
  penalty-free zone by itself**" over "unprofitable to mine" (penalty
  ≠ necessarily unprofitable once fees are counted).
- Corner case (8-in × 7-of-7), but still a fair **MSW-G** genesis <!-- doc-literal-gate-allow: historical MAX=7-era reward-zone analysis -->
  question.

### Fee model / `MAX_INPUTS` — **CONFIRMED (Track B)**

- `pqc_auth_weight()` hardcodes solo lengths
  (`tx_fee_model.rs:151-158`).
- `v31/intent.rs MAX_INPUTS = 128` vs `shekyl_fcmp::MAX_INPUTS = 8` /
  `FCMP_MAX_INPUTS_PER_TX`. Note: `cryptonote_config.h:200-207`
  comments about intent.rs/`build.rs` sync refer to **reference-block
  age** constants, **not** this 128 — so 128 is real drift, not a
  synced authority.

### `wallet2` PQC multisig surface — **CONFIRMED**

`create_pqc_multisig_group` / `m_pqc_multisig_*` at
`wallet2.cpp:9828-9852` uses `shekyl_pqc_multisig_group_id` (correct
derivation). MS-2 "don't thicken" stands; §2.3 must not claim C++ has
no multisig surface.

### R1-F-6 CI + F-7 — F-6 **lane landed**; F-7 still open; F-3…F-5/F-9 dispositioned DELETE

F-3 Option A fossil DELETE is closed as design disposition (impl
pending). F-6 CI lane: `ci/multisig-feature` — check / clippy / test
+ P0-n (toolchain 1.94.0; no job-level RUSTFLAGS). First enable may
fail clippy on `frost_sal` (discovery). Remaining Round 1 blockers
for **closure**: clippy-green (via F-3 DELETE) + SoloSigner
associated-item framing (F-7).

Still Round 1 closure blockers for Track B; this audit focused on the
Track A / F-2 / size claims that decide whether Track A is a constant
fix.

**Net:** proceed with **revised Track A** as documented in §0. Record
MSW-2 as invariant+KAT with the sharpened "length primary, prefix
secondary" wording. Do not reopen leaf preimage.

---

## §1 Mission posture

Per [`00-mission.mdc`](../../.cursor/rules/00-mission.mdc):

| Priority | How this design touches it |
| --- | --- |
| **1 — Security** | **Track A first:** lying ceilings (F-1); disjointness (MSW-2); **version discriminators (MSW-4/5)** — the V3.1↔V4 interface under §0.4. Track B: threshold authority, wipe-on-drop, honest-signer invariants — **bounded** design life. |
| **2 — Privacy** | Track B receive path (Option C / FA-6b). Spend must not weaken FCMP++ vs solo. |
| **3 — System longevity** | §0.4 coexistence: V3.1 permanent beside V4. Discriminability > evolvability. Feature-gated Track B (v31 only). `frost-sal-v4` for a *future clean* SAL scaffold — not the Option A fossil. |

**Three timeframes (corrected under §0.4).** Now: Track A bounds +
disjointness + **real version bytes** before genesis; MSW-G. V3.1:
Track B behind `multisig` — sealed, replaceable. V4: **new stack
beside** V3.1 (`multisig/v4/`); not an in-place evolution of durable
fields. Lattice container must re-prove MSW-2; discriminators must
already work.

---

## §2 Scope

### §2.1 In scope

**Track A (this doc owns the finding → MSW map; implementation is a
separate go-ahead):** MSW-1…MSW-5, MSW-G.

**Track B:** MS-1…MS-7 (MS-8 retired); map protocol onto engines;
Rust-owns-logic; feature-gate discipline; Phase 0 doc amends after
rounds close.

### §2.2 Out of scope / deferred

| Item | Carrier |
| --- | --- |
| Protocol crypto redesign | `PQC_MULTISIG.md` — **design is closed** (April table); do not reopen in engine rounds |
| Cryptographer / external wargame (protocol Phases 5–6) | FOLLOWUPS; **crypto** surfaces only. Grinding / rotation / griefing = **availability** (lead cost ~`k·n`, not scare-`n^k`) |
| Headless co-signer / HW wallet / GUI | FOLLOWUPS / sibling repos |
| Archival | Separate |
| Enabling `multisig` in release packages | Named flip PR |
| Wiring `shekyl_pqc_verify_with_group_id` as the primary fix | **Retired** (MS-8 redundancy); do not schedule as ship-gate |
| Changing `DOMAIN_PQC_LEAF ‖ …` preimage | **Rejected** (F-2 retraction); not free, not needed |
| Lattice SAL / "PQ the FCMP++ layer via multisig" | **Rejected as framing** — same classical membership/SAL as solo |
| Option A FROST fossil keep/quarantine | **Rejected** — DELETE (R1-F-3) |

### §2.3 Substrate table (corrected)

**Opening pin:** `13bd508c7`. **Adversarial re-verify pin:**
`b23cdaff0` (rows below that the review touched). Multisig surfaces
unchanged across the 9-commit archival drift.

| Surface | State | Pin |
| --- | --- | --- |
| Cargo `multisig` on engine-core / rpc / ffi | `default = []` | both |
| Production wallet-rpc / cli | do not enable `multisig` | both |
| Envelope `CAPABILITY_RESERVED_MULTISIG` | refused | both |
| `EngineSignerKind` / `SoloSigner` | marker only; **zero associated items**; `MultisigSigner` type **absent** | both |
| **`multisig/{dkg,group,signing}.rs`** | **Option A FROST fossil** — **DELETE** (R1-F-3 disposition) | **closed as delete** |
| `multisig/v31/` | equal-participants scaffold; no `construction.rs` / `transport/` | both |
| `shekyl-crypto-pq::multisig` | **always compiled**; V3.1 container `expected_blob_len = 3+n·2028` | both |
| `PQC_MAX_PUBLIC_KEY_BLOB` | `2+7·1996 = 13974` — **N=7 canonical 14199 fails** | **R1-F-1 → MSW-1** |
| `PQC_MAX_SIGNATURE_BLOB` | `2+7·3385 = 23697` — **M=7 canonical 23703 fails** | **R1-F-1 → MSW-1** |
| `MULTISIG_KEY_HEADER_LEN` | still `2` in `tx_pqc_verify.cpp` + `submit/verifier.rs` | **R1-F-1 → MSW-1** |
| Leaf preimage | `DOMAIN ‖ pqc_pk` — **leave alone** (F-2 retraction) | shared scheme 1+2 |
| Scheme blob prefix | byte[2]: `reserved==0` ⊥ `m_required≥1` | **MSW-2 invariant** |
| `DOMAIN_PQC_LEAF` | dual def fcmp + crypto-pq; hygiene debt, not Track A blocking | note |
| Daemon `tx_pqc_verify.cpp` | `scheme_id=2`; misattribution `"output committed="` | **MSW-3** |
| **`shekyl-daemon-rpc/.../verifier.rs`** | second verify site; header shadow | **MSW-1 lockstep** |
| **`wallet2.cpp:9828-9852`** | **existing** `create_pqc_multisig_group` / `m_pqc_multisig_*` / correct `shekyl_pqc_multisig_group_id` | **MS-2:** don't thicken; third group_id consumer (vs F-4 DKG) |
| `MultisigGroup` (engine) | Serialize hex secrets; claims "wallet file encrypted" | **R1-F-5** |
| `tx_fee_model::pqc_auth_weight` | scheme-1 lengths only | **Track B R-B** |
| `v31/intent.rs MAX_INPUTS` | 128 vs consensus `FCMP_MAX_INPUTS_PER_TX=8` | **Track B R-C** |
| `MULTISIG_CONTAINER_VERSION` / `multisig_group_id` | **Fused:** constant passed as `group_version`, not `container.version`; `spend_auth_version` hardcoded | **R1-F-11 → MSW-4/5** |
| CI `--features multisig` | **`ci/multisig-feature`** | **R1-F-6 lane; clippy debt open** |
| Protocol §16.4 | superseded note (Rust-owns-logic) | design branch |

---

## §3 Pre-flight discipline (citation-paying)

### §3.1 Engine identification (corrected per R1-F-7)

- §10.3.1 still open for MS-1.
- **Honest framing:** adding the first associated item to
  `EngineSignerKind` is a **trait-surface amendment that touches
  `SoloSigner`** (e.g. `type SigningCeremony = Infallible`), not a
  silent feature flip. Module docs describing "eventual" associated
  types are aspiration, not substrate (`signer.rs:60-64`, `:65`).
- `#[cfg(feature = "multisig")]` on inherent/`Engine` methods remains
  valid for bodies that must not exist in V3.0 builds.

### §3.2–§3.4

Unchanged in applicability (principles 4–8; lenses bounded; no
Monero `wallet2` inheritance). **Add:** fossil-sweep obligation for
Option A FROST lineage DELETE (R1-F-3) — same shape as superseded
docs left standing beside replacements.

### §3.5 Branch posture

- Design docs: this branch.
- **Track A impl:** `feat/msw-*` off current `dev` after go-ahead
  (not blocked on Track B rounds).
- **Track B impl:** `feat/ms-*` after Round 1–3 + pre-flight +
  go-ahead.

### §3.6 Conformance lenses

Deferred to Round 2 after MS-1 **and** F-3 lineage fate.

---

## §4 Phase 0 candidates (Track B doc amends — after Round 1 close)

| ID | Target | Intent |
| --- | --- | --- |
| **P0-a** | `PQC_MULTISIG.md` §16 | Align feature name; list modules; keep §16.4 superseded |
| **P0-b** | `V3_ENGINE_TRAIT_BOUNDARIES.md` | MS-1 + SoloSigner associated-item amend (§8.2) |
| **P0-c** | `WALLET_REWRITE_PLAN.md` | Feature-flip checklist → this doc |
| **P0-d** | Persistence / ledger | **Re-open R6** against post-F-3/F-5 group shape |
| **P0-e** | INDEX | MS / MSW status rows |
| **P0-f** | FA-6b FOLLOWUPS | V3.1 engine ship gate |
| **P0-g** | FOLLOWUPS "wire group_id into consensus" | **Close as superseded by MSW-2 / MS-8 retirement** |
| **P0-h** | `V3_ROLLOUT.md` | **Partial land 2026-07-14:** delete Option A "coordinator-held" + "recommended for staking" drift. Still owed: replace fossil ~7× auth-overhead table with whole-tx weights (post-MSW-1 sizes). |
| **P0-i** | `MAX_MULTISIG_PARTICIPANTS` | **Landed 2026-07-15: MAX=5** (§0.3; withdraws same-day provisional 8). |
| **P0-j** | `PQC_MULTISIG.md` §15.4 + `VERSIONING.md` | **Landed 2026-07-14:** split 15.4a/15.4b; posture pin |
| **P0-k** | `PQC_MULTISIG.md` §15.1 honesty | Address payload already correct; group_id plumbing = MSW-4 |
| **P0-l** | R1-F-3 DELETE | **Disposition landed:** delete Option A FROST fossil; not `frost-sal-v4` quarantine. Impl = Track B / cleanup. |
| **P0-m** | Address bech32m / §15.3 registry | **Re-priced 2026-07-15:** MSW-8 deletes vestigial address sign keys (~2.6×). N=2 QR-able. Registry demoted from critical-path prerequisite to optimization. |
| **P0-n** | Doc prose KAT / grep-gate | **Landed (this PR):** `scripts/ci/check_multisig_doc_literals.sh` + `ci/multisig-doc-literals` job (split out of `ci/multisig-feature` so docs-only changes skip the F-6 cargo lane). Fossil sweeps were on the docs carrier (#308). This carrier + INDEX + FOLLOWUPS **are scanned**; their few genuinely-historical lines (decision-log rows, reward-zone `MAX=7` analysis) opt out per-line with an inline `doc-literal-gate-allow` marker rather than excluding the whole file. |

---

## §5 Load-bearing questions (Track B)

Criteria unchanged. Status reflects adversarial review.

### MS-1 — Trait identity — **OPEN (F-3 lineage CLOSED → v31 only; lean §0.4)**

**Lean MS-1(a)/(c)** — cuttable seam for solo + **future** second
multisig stack (V4 coexist). **MS-1(b) rejected.** Lineage question
**closed**: only v31 Option D ships under `multisig`; Option A FROST
fossil **DELETE** (R1-F-3). Round-2 still names `K` on
`MultisigSigner<N, K>` (threshold vs spend_auth / scheme version for
the *future* coexist axis — not "which fossil").

Still needs R1-F-7 SoloSigner associated-item amend. F-6 CI remains
Round 1 closure prerequisite.

**Reopen.** Only if coexistence premise withdrawn (§15.5 amended).

### MS-2 — C++ / Rust boundary — **OPEN (lean holds; substrate corrected)**

New wallet multisig logic: Rust-only. C++: LMDB + verify FFI.
**Do not claim C++ has no multisig surface** — `wallet2.cpp:9828-9852`
already has group create / `m_pqc_multisig_*` using the **correct**
`shekyl_pqc_multisig_group_id` (contrast F-4 DKG caller-supplied id).
MS-2 forbids thickening that surface; migration/deletion is rewrite /
Phase 5. Track A bound fixes are consensus ceiling corrections, not
wallet logic.

### MS-3 — Feature gate — **OPEN (lean amended)**

Keep Cargo feature name `multisig`. Flip checklist **amended**:

1. Rounds + pre-flight (Track B).
2. Receive + spend + regtest gate.
3. FA-6b disposed.
4. Capability un-reserve in flip PR only.
5. **Positive CI:** `cargo check/clippy/test -p shekyl-engine-core
   -p shekyl-engine-rpc -p shekyl-ffi --features multisig` green in
   CI (**R1-F-6** — Round 1 closure prerequisite, not Round 3).
6. **Negative CI:** default/release builds do not enable `multisig`;
   no simple-mode symbols.
7. **F-3:** Option A fossil **deleted** before flip (not shipped, not
   quarantined behind `frost-sal-v4`).

### MS-4 — Receive path — **OPEN — restated under E′ (2026-07-15)**

**Prior lean (Option D):** Refresh/scanner arm; I7 receive-time prover
check (`O == spend_auth_pubkeys[assigned]`); FA-6b gate.

**Under E′ the question changed.** There is no assigned prover and no
I7 prover binding. Receive path must:

1. N-fold KEM decap + view-tag filter (unchanged from C/D).
2. Reconstruct / verify `O = ho·G + B + y_out·T` with
   `y_out = y_group + y_kem` (group knows `B`, `Y_group`; `y_kem` from
   own `ss_i` / published material as specified).
3. Local key-image / balance via plaintext `b` — **no**
   `export_multisig_info` round-trip.
4. Drop griefing-score / I7 machinery tied to rotating prover.

Placement lean MS-4(a) (Refresh/scanner arm) still holds; the
*validation contents* do not. Round 1 cannot close on the old I7 lean.

### MS-5 — Spend path — **OPEN — restated under E′ (2026-07-15)**

**Prior lean (Option D):** `intent → canonical construction → prover →
signature shares → assembly`. Gaps: no v31 `construction.rs`; F-7
`EngineSignerKind` ceremony associated type.

**Under E′ the question changed.** Spend path is a **two-round FROST
ceremony over `y_group`** (with public `y_kem` tweak), plus M hybrid
`scheme_id=2` sigs from per-participant KEM-derived keys — **not** a
prover handoff.

1. Agree intent / construction (survives: `intent.rs`, `state.rs`).
2. FROST SAL on `y_group` with **nonce discipline unrepresentable by
   type** (F-9 footgun; `frost_sal.rs` kept, Option A wrapper deleted).
3. Assemble `scheme_id=2` auth blob (unchanged wire size vs D).
4. No `rotating_prover_index`, heartbeat, counter_proof, veto.

Lean MS-5(a)/(c) for trait placement still applies; **"unblocked on
lineage" is not "prover path ready."** Restate before Round 1 close.

**DoD gate (inherited from MSW-6, non-negotiable).** MSW-6 dropped the
*consensus* rule that forbade co-spending a solo (scheme-1) and a multisig
(scheme-2) output; that guardrail's replacement lives **here**, and MS-5 is
**not done** until it lands. Required: (1) `shekyl-tx-builder` coin selection
**never crosses key models**, with a test that fails if it does; (2) the
one-line cross-model disclosure ships (`MULTISIG_OPERATIONS.md` +
`USER_GUIDE.md`: "a tx spending both solo and multisig outputs proves common
control; the wallet will not construct one"). This is justified by no-externality
+ the opt-in `scheme_id=2` precedent (see §16.3), **not** TM-1 — but a working
consensus mechanism was removed on the promise that this lands, so leaving it a
soft follow-up would be the armed-gate / no-trigger shape one layer up.

### MS-6 — Transport — **OPEN (lean holds)**

Pure wire in `v31`; I/O via adapter. File-first.

### MS-7 — Persistence — **OPEN — lean WITHDRAWN (R1-F-5); Round-2 amend §0.4**

Do **not** "confirm R6" against the protocol table alone.
**Re-open R6** against `MultisigGroup`'s actual Serialize-hex secret
shape (and whatever F-3 replaces it with). Secret hygiene
(`35`/`36`) is a closure prerequisite for any group-persist path.

**Round-2 amend (R1-F-11 / §0.4).** Plan §1 asked for *evolvability*;
§15.5 forbids it. V4 writes new fields; V3.1 owes a **discriminator
that works**, not an evolvable enum. `PersistedMultisigOutput` must
be a **versioned record** keyed by a real `spend_auth_version` /
container version (MSW-4/5). Pinning bare `[u8; 32]` / 
`SPEND_AUTH_PUBKEY_LEN = 32` "compressed Ed25519" without a working
discriminator freezes the V3.1↔V4 interface as a lie.

**Reopen triggers.** Existing PR 6 §5.4.1 triggers, plus: any durable
secret field that is not `Zeroizing`/`ZeroizeOnDrop` end-to-end; any
durable field whose layout assumes a single classical key size
**without a version discriminant that group_id / address actually
read**.

### MS-8 — Daemon `group_id` verify — **RETIRED (redundancy; F-2 retraction compatible)**

**Rejection.** Wiring `shekyl_pqc_verify_with_group_id` buys a no-op:
`group_id = f(key_blob)` and the leaf already binds the blob. No
sound daemon-side `expected_group_id` from the creating output.
**This conclusion does not depend on changing the leaf preimage.**

**Replacement (Track A / MSW-2–3).** Pin prefix-disjointness; fix
`"output committed="` misattributions; do not change leaf hash.

**Re-evaluation shape.** Only if a future scheme breaks MSW-2 reopen
criteria *and* leaf binding is shown insufficient — new design round,
not a quiet reopen of MS-8.

---

## §6 Round 1 disposition status

| ID | Status | Notes |
| --- | --- | --- |
| MS-1 | **OPEN** | Lean **(a)/(c)**; **(b) rejected**; name `K`; F-3 lineage **CLOSED** (v31 only) |
| MS-2 | **OPEN** | Lean holds |
| MS-3 | **OPEN** | Amended: positive CI (F-6); F-3 = delete fossil before flip |
| MS-4 | **OPEN — restated E′** | No I7 / prover; local KI via `b`; KEM fan-out + `O` verify |
| MS-5 | **OPEN — restated E′** | FROST-on-`y` + nonce types; not prover handoff; F-7 still |
| MS-6 | **OPEN** | Lean holds |
| MS-7 | **OPEN** | R6 vs **v31** persist only; versioned discriminator (R1-F-11) |
| MS-8 | **RETIRED** | redundancy; leaf change not required |

**Round 1 still cannot close until:**

- [x] **R1-F-6:** CI lane `ci/multisig-feature` —
      `check`/`clippy`/`test` for engine-core + engine-rpc + ffi with
      `--features multisig` (+ P0-n doc gate). **Lane exists (this PR);**
      first enable may clippy-fail on `frost_sal` (F-3 DELETE) — Round 1
      closure still needs that debt cleared, not `-D warnings` weakened.
- [x] **R1-F-3:** Disposition **DELETE** Option A fossil (impl pending).
- [x] **R1-F-4:** Evaporates with F-3 DELETE; canonical = v31 `multisig_group_id`.
- [x] **R1-F-5 / MS-7:** `MultisigGroup` dies with F-3; R6 against v31 + discriminator.
- [ ] **R1-F-7:** §3.1 / SoloSigner associated-item framing accepted
      into Phase 0 plan.
- [ ] **D-10:** MS-4 / MS-5 restated under E′ (above) — maintainer
      sign-off that Round 1 leans are no longer Option D prover-shaped.
- [ ] Maintainer sign-off on revised Track A (constant fix) + MS-8
      retirement + F-2 leaf-leave-alone + F-3 DELETE.
- [ ] Lens-1 re-test after MS-1; R-residuals pointed at Round 2.

**Round 2 residuals (updated).**

- R-A…R-F as before (engine surface, construction, regtest, FA-6b,
  capability). Griefing-storage (R-F) largely evaporates with E′
  (no I7 / prover griefing scores) — reconfirm in Round 2.
- R-B **extends:** multisig arm in `pqc_auth_weight` / fee model
  (scheme-1-only today).
- R-C **extends:** pin `SpendIntent::MAX_INPUTS` to
  `FCMP_MAX_INPUTS_PER_TX` (128 → 8); refuse unserializable intents.
- R-G: MSW-2 KAT remains green after MSW-1 bound raise; flip must not
  assume length-only separation.
- R-H: F-3 DELETE PR (`dkg`/`group`/`signing` + tests); not quarantine.
- R-I: F-5 zeroize + ledger migration for group secrets.
- R-J / **MSW-G:** **CLOSED = 5** (§0.3; withdraws same-day 8).
- R-K **(new):** E′ FROST nonce-discipline types; Phase 6 tweak claim
  (`y_out = y_group + y_kem`).

---

## §7 Implementation gates

### §7.1 Track A (MSW-*) — priority 1 (revised)

1. Explicit user go-ahead for Track A implementation.
2. Short-lived `feat/msw-*` off current `dev`.
3. **MSW-6 first** (own surface) — relax tx-wide scheme_id; archival
   core untouched.
4. Then one surface: **MSW-G=5** → MSW-1 (DoS ceiling +
   `SINGLE_KEY_CANONICAL_LEN` single-source + cross-seam KAT
   `n∈1..=5` + delete shadows) + MSW-2/3 + MSW-4/5 (group_id ←
   address-payload versions) + **MSW-8** (delete address
   `hybrid_sign_pubkeys`).
5. **Do not** change leaf preimage / FFI leaf hash ABI / emission
   Auth-B / test-vector corpus / `bond_spend_pk` length as part of
   Track A.
6. **Do not** adopt lattice-threshold / TRacoon here.
7. **MSW-G decided (=5).** Awaiting **explicit Track A implementation
   go-ahead** (this doc does not authorize code). F-6/F-7 remain
   Round 1 / Track B and do **not** block Track A or MSW-6.

### §7.2 Track B (MS-*) — rule-26 halt

1. Satisfy §6 Round 1 closure prerequisites (including F-6 CI).
2. Round 2 → Round 3 → pre-flight (Round 0 / R0-D#).
3. Explicit go-ahead; then `feat/ms-*`.

This design branch remains **documentation only**.

---

## §8 Appendix — Grep pins (adversarial set)

```text
# F-1 fossil bounds
src/cryptonote_config.h:290  PQC_MAX_PUBLIC_KEY_BLOB = 2 + 7*1996
src/cryptonote_config.h:293  PQC_MAX_SIGNATURE_BLOB = 2 + 7*3385
rust/shekyl-wire/src/transaction.rs:167-170  same formulas
rust/shekyl-crypto-pq/src/multisig.rs:85-87  expected_blob_len = 3+n*2028
rust/shekyl-crypto-pq/src/multisig.rs:198-201  sig = 1+M*3385+M

# F-2 leaf / domain
rust/shekyl-fcmp/src/leaf.rs:29-33
rust/shekyl-fcmp/src/lib.rs:36 DOMAIN_PQC_LEAF
rust/shekyl-crypto-pq/src/derivation.rs:27 DOMAIN_PQC_LEAF (duplicate)

# F-3 lineage
rust/shekyl-engine-core/src/multisig/mod.rs  "FROST" + v31/
rust/shekyl-engine-core/src/multisig/signing.rs  coordinator ceremony

# F-8 second verifier
rust/shekyl-daemon-rpc/src/submit/verifier.rs:322-386
src/cryptonote_core/tx_pqc_verify.cpp  MULTISIG_KEY_HEADER_LEN = 2
```

---

## §9 Document history

| Date | Event |
| --- | --- |
| 2026-07-14 | Round 1 opened; MS-1…MS-8 posed |
| 2026-07-14 | Adversarial review recorded (R1-F-1…F-11); Track A/B split; MS-8 retired; Round 1 closure blocked on F-3…F-7 + F-6 CI; MSW family registered |
| 2026-07-14 | **F-2 retraction:** leaf preimage left alone; Track A revised to constant-family fix + prefix-disjointness KAT + misattribution; size/fee/`MAX_INPUTS` → Track B; `wallet2` group surface acknowledged; **MSW-G** on whether `MAX=7` survives reward-zone |
| 2026-07-14 | **§0.2 independent audit:** F-1 confirmed; F-2 leaf-leave-alone; length primary / byte[2] secondary; reward-zone rhetoric trim |
| 2026-07-14 | **§0.3 MSW-G:** MAX=7 has no derivation; F-1 fix *is* the 6/7/8 choice; fossil bound ≡ zone both imply effective 6; V3_ROLLOUT table fossil + coordinator/staking drift → P0-h; TRacoon = V4 research candidate not Track A |
| 2026-07-14 | **§15.4 split (P0-j):** FROST SAL (15.4a, internal two-component/`y` blocker) ≠ pure-PQC auth (15.4b, NIST IR 8214C reference call → later process). TRacoon wrong N regime + no DKG + not FIPS; watch dPN25/TALUS for size. Size lens for MSW-G has 15.4b expiry; genesis still freezes on today's list economics. |
| 2026-07-14 | **§15.4 posture pin:** scheme_id=2 already PQ auth (M×ML-DSA); solo≡multisig classical FCMP++/SAL; SAL = liveness not compromise; grinding/griefing → availability not Phase 6 crypto; `spend_auth_version=0x02` = 15.4a classical threshold SAL ≠ lattice SAL (impossible under FCMP++); 15.4b = auth size only. Ship decision = economics (~3×), not crypto-maturity. |
| 2026-07-14 | **R1-F-11 / MSW-4+5:** version hooks fake at genesis — fuse container/group version; spend_auth_version constant not wire; under-tested reserved namespace. Same shape as F-1. MS-7 Round-2: R6 must not bake `[u8;32]` classical-only durable field (plan §1). |
| 2026-07-14 | **§0.4 coexistence pin:** V4 = rewrite beside V3.1 (§15.4–15.5), not evolve-in-place. Discriminability > evolvability; version bytes = entire V3.1↔V4 interface. Track A permanent / Track B ~4y then legacy — process inversion named. MS-1(a)/(c) win, (b) rejected. |
| 2026-07-14 | **R1-F-3 → DELETE:** Option A fixed-group PQC fossil (not Apr 15 rotating-vs-fixed prover; that closed with named 1/N loss). Not a V4 seed — fuses SAL keys with rejected `pqc_public_key`. `frost-sal-v4` later for clean SAL only. V3_ROLLOUT Option A prose fixed (P0-h partial). Retract "Phase 6 cryptographer" claim on per-output privacy. |
| 2026-07-15 | **Corrected picture banner:** design done (April table); gap = unbuilt + consensus leak past gate. Track A urgent / Track B bounded. Scorecard. §11.1 grinding lead → ~`k·n` availability, not scare-`n^k`. |
| 2026-07-15 | **MSW-G = 8.** Security (3-fault) > zone; 7 incoherent. Bias + hostage lenses drop (hostage E[frozen]=p independent of n — retracted). Address bech32m ~36k chars = usability fossil (P0-m), not MSW-G. MSW-5(A): address payload already has three version axes; MSW-4 = group_id plumbing to that payload. R1-F-2 row: length primary. |
| 2026-07-15 | **Overhaul:** MSW-6 (relax tx-wide scheme_id — staking unblock; archival core untouched). MSW-G **5** (2f+1 at f=2; withdraws 8). MSW-1 narrowed to SINGLE_KEY_CANONICAL_LEN single-source + DoS ceiling. MSW-7 retracted (`bond_spend_pk` 1996 = pseudonym uniformity). Pin #4 named reversion for MSW-6 only. Sequencing: Phase 0 docs → MSW-6 → MSW-1…5 → F-6 → Option E′. |
| 2026-07-15 | **§0.5 Option E′** (lean). Two-component `O` splits trust: `b` group-plaintext (view+link / local KI); `y` FROST M-of-N with `y_out = y_group + y_kem` tweak. Dealer-mode, no DKG, no `export_multisig_info`. Deletes mandatory-prover Option D scaffold. `spend_auth_version=0x02`; `0x01` never issued. `frost-sal-v4` = E′ gate. |
| 2026-07-15 | **MSW-8:** delete vestigial `MultisigAddressPayload.hybrid_sign_pubkeys` (Solution C fossil; zero consumers). ~2.6× address shrink is MSW-8, not E′. §15.3 registry re-priced off critical path. Defect class named: shape-from-prose without a read site (fifth instance this session). |
| 2026-07-15 | **Phase 0 sweep D-1…D-6:** normative `n_total > 7` → MAX (D-1); ROLLOUT vs-N-solos math + cap fossils + `5385→5389` + date (D-2…D-5); ANALYSIS historical banner + E′ row + §6/§15.2 escrow struck + rotation naming collision (D-6). **P0-n** doc grep-gate. <!-- doc-literal-gate-allow: decision-log row recording the n_total > 7 → MAX fix (D-1) --> |
| 2026-07-15 | **PR process:** Pin #1 named reversion — comment-only source amendments OK when recording a semantic this PR pins (`bond_wire` MSW-7 uniformity). VERSIONING.md aligned to E′ (15.4a blocker open; `0x02` = product path). §10.3.1 status refreshed (MS-8 retired, E′, MSW-*). P-3: MSW-G cold before MSW-1 code. |
| 2026-07-15 | **Copilot on #308:** label MAX=5 as decided/unenforced until MSW-1 (reject cutting the constant in a docs PR); drop superseded MSW-G=8 CHANGELOG bullet; F-10→F-11 consistency; §16.7 flags = planned sketch not live Cargo. |
| 2026-07-15 | **P0-n + F-6 CI:** draft lane + fossil sweeps prepared; **CI files split out** to a follow-on PR so this docs carrier lands alone. Operator/protocol fossils swept here (`USER_GUIDE` / `MULTISIG_OPERATIONS` / `POST_QUANTUM` / `DESIGN_CONCEPTS` / `ANONYMITY` / `LEVIN` / `RELEASE_CHECKLIST`). |
