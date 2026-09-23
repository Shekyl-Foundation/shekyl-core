# PL — FCMP++ spend linkability through the public 4th leaf scalar

**Status:** OPEN — round 1 **RATIFIED by Rick, 2026-09-14** (§12); the
implementation, built under §10 on its own worktree from `dev`, **lands in
this document's PR** under rule 07 (§12.1; the clause "no implementation in this document's PR" that stood here was true of the doc-only PR #744 and was superseded 2026-09-14 by #745, which carries both). `PL-D1` (the linkability defect) is verified at source,
not refuted, and **closed by `PL-D3` in this PR** (§12.1). `PL-D2` (the in-circuit PQ binding is only as sound as the
discrete-log proof enforcing it) is raised here; **ruled 2026-09-14** — the
four documents that claimed otherwise are corrected at source (§4.5), on
Rick's instruction that this is security information, not marketing.
`PL-D3` (§6.2) is the fix, per Rick's in-channel direction of 2026-09-14
("go with Pedersen now, then re-design a proper hash mechanism, not patch it
in the middle of everything else"): a **Pedersen commitment** to the key in
the leaf's 4th scalar, opened in-circuit by the discrete-log gadget the first
layer already runs; the hash mechanism is the named successor round `PL-D4`
(§6.5). Rick ratified the written form on 2026-09-14 (§12) and the
implementation landed with it under rule 07 (§10, §12.1). The document
corrections `PL-D1` requires are applied at source (§11). The wire, the
leaf format and the circuit change exactly as §6.2 specifies.
**Grounded at** `dev` = `42333d34f` (2026-09-13), fresh worktree
`~/shekyl/wt-pl-linkability`. Every `file:line` below was read at that tree
on 2026-09-13; citations into the documents this branch itself corrects
(§11) are given at the branch's post-edit state so they resolve here. The agent brief that opened this round was grounded at
`37accf6f9`; where an anchor moved between the two pins it is listed in §2.4.
**Identifier family:** `PL-` (PQC-leaf linkability), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit that
lands this document (rule 94). `PL-D*` are dispositions of this round; `PL-R*`
are review-round findings. `PL-D` and `PL-R` parse as distinct prefixes and
were clear of the 77 registered families at the anchor
(`check_index_prefix_uniqueness.py`, exit 0). The finding was first filed as
`F5` in `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §1.5 on `docs/so-d8-proposal`
(branch-only, commit `02244f6616`); `F-N` is doc-scoped, so the round mints
its own family and `F5` stays as the historical name.
**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
is invoked — the fix crosses the circuit, the FFI (`shekyl_fcmp_verify`,
`shekyl_construct_curve_tree_leaf`, `shekyl_fcmp_pqc_leaf_hash` — renamed `shekyl_fcmp_pqc_key_scalar` by the fix), the wire
(`tx_extra` `0x07`), and the genesis-frozen leaf format.
[`07-consensus-atomic-cutovers`](../../.cursor/rules/07-consensus-atomic-cutovers.mdc)
is named for the implementation PR (§10); this round is the design-first
half. Every rejection in §7–§8 takes
[`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc)'s
three-part shape.
**Decision authority:** Rick. §12 separates what this round ruled from what
needs his ruling. **No push has been authorised**; this branch is local.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
security and quantum resilience are the first precondition; privacy is the
product, second. `PL-D2` is a priority-1 question and `PL-D1` a priority-2
defect; this document orders them by the mission, not by the opening brief
(whose §0 wrote "privacy > security" — the inversion is noted so nobody
inherits it). Both are pre-genesis: nothing has leaked, nothing migrates.

---

## 0. The defect in one paragraph (`PL-D1`) — CLOSED by `PL-D3` in this PR, 2026-09-14; described below as found at the 2026-09-13 pin

Every FCMP++ spend reveals the spent output's hybrid PQC public key in
cleartext (`tx.pqc_auths[i].hybrid_public_key`). That key's hash was published
per output, in vout order, in `tx_extra` tag `0x07` when the output was
created, and copied by every node into the output's curve-tree leaf as its
4th scalar. Consensus hashes the revealed key with the same function and hands
the result to the FCMP++ verifier as a **public input**; the circuit
constrains the leaf's 4th scalar equal to it and puts it **unblinded** into
the membership tuple beside the three blinded scalars. An observer hashes the
revealed key, looks the hash up in the published `0x07` index, and has the
spent output — one hash, one map lookup, `O(1)`, for every input of every
transaction. The membership proof is not broken; it is bypassed, because the
value that identifies the leaf is supplied to it in public.

What leaks: the spend graph, walkable backward from any transaction to the
coinbase that funded it. What does not leak: amounts (CT) and destinations
(stealth addresses). Pre-genesis; nothing has leaked; the fix (§6) is a
change to what the published per-output value *is*, not to the proof.

---

## 1. This is not a bug in the proof

The circuit does exactly what it documents (`circuit.rs:153–167`); proofs
verify; KATs match; soundness holds under its assumption. Against a classical
adversary the key cannot be substituted. **Nothing fails.** The defect is in
the composition: the value that provides the PQ binding is also, by
construction, a published per-output identifier, and it is declared public
to the proof. The binding needed a commitment that binds; it also needed one
that **hides**, and it does not have one. (§4 adds that the binding it does
have is only as sound as the proof enforcing it — `PL-D2`.)

---

## 2. Verification of the evidence chain

Every row was read at source at `42333d34f`. No row is accepted on the
brief's authority.

### 2.1 The chain

| # | Fact | Confirmed at |
|---|---|---|
| 1 | The leaf is 4 Selene scalars, 128 bytes | `rust/shekyl-curve-tree/src/segment.rs` (`LEAF_BYTES = SCALARS_PER_LEAF * 32`, `assert!(LEAF_BYTES == 128)`); `rust/shekyl-fcmp/src/tree.rs:506–524` (`construct_leaf`: `leaf[96..128] = h_pqc`) |
| 2 | At creation the creator publishes `h_pqc = H(hybrid_pk)` per output, vout order, in `tx_extra` `0x07` | Coinbase: `src/cryptonote_core/cryptonote_tx_utils.cpp:198–199` (field), `:237` (`append(od.h_pqc)`), `:253–261` (serialised into `tx.extra`). C++ non-coinbase path: `:499–500`, `:547`, `:567`. **The live wallet producer is Rust** (`rust/shekyl-wire/src/tx_extra.rs`, `rust/shekyl-engine-core/src/engine/sign_bridge.rs`, `drain_assembly.rs`, genesis: `rust/shekyl-genesis-tool/src/builder.rs`) — same derivation, same bytes (§9 census) |
| 3 | Each published `h_pqc` is copied into that output's leaf at DB add, as opaque bytes | `src/blockchain_db/blockchain_db.cpp:528–548` (`extract_leaf_hashes`: shape-checked, then the blob is returned verbatim), `:550–557` (`collect_outputs`: `h_pqc = blob + i*32`), `:608–611` (`shekyl_construct_curve_tree_leaf(output_key, commitment, h_pqc, leaf)`); `rust/shekyl-ffi/src/legacy_curve_tree.rs:526–563` → `shekyl_fcmp::tree::construct_leaf`. **No node can recompute it** — nodes never hold the output's `pqc_pk` |
| 4 | `h_pqc` is per-output unique | `rust/shekyl-crypto-pq/src/derivation.rs:230–265` (`derive_output_secrets(combined_ss, output_index)`: `ml_dsa_seed` and `ed25519_pqc_seed` are `HKDF-Expand` under labels salted with `idx_le64`, `:198–199`); `:66–81` (`hash_pqc_public_key`: Blake2b-512 under `DOMAIN_PQC_LEAF`, `wide_reduce` into the leaf field); `:87–113` (`derive_pqc_leaf_hash`); `rust/shekyl-crypto-pq/src/output.rs:1412–1434` (`compute_hybrid_h_pqc`, the creation/scan-side value at `:394`, `:751`, `:965`) |
| 5 | At spend the input carries `hybrid_public_key` in cleartext | `src/cryptonote_core/tx_pqc_verify.cpp:128–129` (serialised into the signed header), `:193–232` (checked, then passed to `shekyl_pqc_verify` as supplied); wallet fills it from `sign_pqc_auth_for_output`: `rust/shekyl-tx-builder/src/sign.rs:260–275`, `rust/shekyl-crypto-pq/src/output.rs:1019–1049`; Rust verifier: `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1131–1140` |
| 6 | Consensus hashes it with the leaf-hash function and passes the result to the verifier | `src/cryptonote_core/blockchain.cpp:3775–3789` (bond-post arm), `:4084–4098` (emission fee-input arm), `:4208–4218` (general FCMP++ arm) — each `shekyl_fcmp_pqc_leaf_hash(hpk) → pqc_hashes_flat → shekyl_fcmp_verify(...)`; `rust/shekyl-ffi/src/legacy_fcmp.rs:39–53` (`shekyl_fcmp_pqc_leaf_hash` = `hash_pqc_public_key`); Rust twin `verifier.rs:1021–1024` (`PqcLeafScalar::from_pqc_public_key(&auth.hybrid_public_key)`) |
| 7 | The verifier takes those hashes as public inputs, by name | `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:102–111` (`Input.extra_leaf_scalars`, doc: *"Public values for extra leaf scalars (e.g. `[H(pqc_pk)]` for Shekyl)"*), `:442–443` (handed to the first layer), `:784`; `rust/shekyl-fcmp/src/proof.rs:412` (`output_extra_scalars: vec![output_h_pqc]`), `:993` (`verify(.., pqc_pk_hashes, ..)`), `:1118` (`verify_membership_only`) |
| 8 | The circuit constrains the 4th leaf variable equal to the public value and puts it unblinded into the membership tuple | `rust/shekyl-oxide/crypto/fcmps/src/circuit.rs:153–163` (`constrain_equal_to_zero(var − public_val)`), `:165–168` (`member = [O.x, I.x, C.x] ++ extra_leaf_vars`) — contrast the blinded legs `:131–150` (`o_blind`, `i_blind_*`, `c_blind` through `discrete_log` + `incomplete_add_pub`) |

### 2.2 Refutation attempts — all closed

The most valuable output of this round would have been a step that breaks
the hash-and-lookup chain. Each candidate was checked at source:

- **A different key at spend than at creation?** No. Creation
  (`output.rs:1412–1434`) and spend (`output.rs:1019–1049`) both call
  `derive_output_secrets(combined_ss, output_index)`, build the same
  `HybridPublicKey { ed25519, ml_dsa }` from the same two seeds, and encode it
  with the same `to_canonical_bytes`. Deterministic; no per-spend salt.
- **A different hash or domain separator at spend?** No. One function,
  `hash_pqc_public_key` (`derivation.rs:66`), serves creation, the C++
  verifier's FFI (`legacy_fcmp.rs:52`) and the Rust verifier
  (`rust/shekyl-fcmp/src/leaf.rs:34`). One domain string, no nettype or era
  switch (`71-network-uniformity` holds here, unhelpfully).
- **Any re-randomisation of the 4th scalar?** No. `circuit.rs:165–168`
  pushes `extra_leaf_vars` into the tuple with no blind; the three blinded
  legs at `:131–150` are the contrast.
- **Structural closure.** `circuit.rs:159–162` constrains the leaf variable
  **equal** to the public value. A spend whose revealed key did *not* hash to
  the leaf's published scalar would fail verification. **A valid spend is
  therefore linkable by construction**; the two checks above are redundant
  with the proof's own correctness.
- **Multisig (`PQC_SCHEME_MULTISIG`)?** Same. The leaf hash is over the
  canonical `MultisigKeyContainer` and the spend must present it byte-identical
  (`docs/PQC_MULTISIG.md:653–670`; `tx_pqc_verify.cpp:208–219` accepts the
  blob and hashes it on the same path).
- **Membership-only (emission backing)?** Same. `verify_membership_only`
  takes `pqc_pk_hashes` (`proof.rs:1118`); the emission vin reveals
  `backing_pubkey` and verify recomputes `hash_pqc_public_key` of it
  (`rust/shekyl-archival-retention/src/emission_wire.rs:118–122`). This arm
  already knew it was identifying its backing (§3).
- **Coinbase and genesis outputs?** Same producer path (`:237`; genesis
  builder writes `0x07`, §9).

**Result: `PL-D1` is not refuted.** The chain holds at every link, on both
verifier implementations, for every spend arm.

### 2.3 What is known by every node

The lookup table is not derived data; every node already holds it. The
`0x07` blob is parsed at admission (`check_tx_extra_shape`) and the
leaf bytes `[96..128]` are stored per output in the curve-tree store
(`LEAVES_TABLE`, `segment.rs` `LEAF_BYTES`). `tx_extra` is part of the non-prunable
transaction prefix, so a pruned node holds the `0x07` table too. No
special-purpose indexer is needed.

### 2.4 Divergences from the opening brief (pin `37accf6f9` → `42333d34f`)

- `blockchain.cpp:4348–4356` → the three arms now at `:3775–3789`,
  `:4084–4098`, `:4208–4218` (same code, moved by PR #737/#738/#739).
- `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` is **not on `dev`**; it exists only
  on `docs/so-d8-proposal` (`02244f6616`). Its `F5` and its `FOLLOWUPS.md`
  line are branch-only; this document is the `dev` record.
- The brief's row 2 names `cryptonote_tx_utils.cpp` as *the* producer. It is
  the coinbase producer (and a C++ non-coinbase path); the live wallet writes
  `0x07` from Rust. Same bytes; the row is corrected above.

---

## 3. The near-misses — the mechanism was seen and scoped one level too small

1. **`REWARD_EMISSION_LEG.md` §7.3 (2026-07-01).** Found the mechanism,
   described it correctly (*"leaf extra-scalars are publicly enumerable, so
   this reveal deterministically identifies the backing output"*), then
   bounded it to one output on an invariant the same mechanism refutes:
   *"the creating tx's inputs are FCMP++-hidden, so the identification does
   not trace back to the principal"* and *"the forward change-heuristic dies
   under FCMP++"*. Both false when written: every input of the creating tx
   reveals its own `pqc_pk`. The paragraph's own tripwire (*"letting output
   identification reach a tx's inputs reopens this finding"*) has fired —
   not by a later change but because its premise was never true. **Struck at
   source in this branch**, with the tripwire recorded as fired.
2. **The MSW-6 rationale**, in three places that share one sentence:
   `src/cryptonote_core/blockchain.cpp:4276–4290`,
   `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1077–1086`,
   `docs/PQC_MULTISIG.md:2026–2040` (and its landed row
   `docs/design/V3_1_MULTISIG_RUST_ENGINE.md:172`): *"the FCMP++ proof ranges
   over the whole tree, so no other party's anonymity set shrinks"* and *"under
   FCMP++ separate txs are unlinkable"*. The **conclusion** (drop the tx-wide
   `scheme_id` agreement; it is a wallet coin-selection invariant, not
   consensus) survives on its other ground — the opt-in `scheme_id=2`
   precedent — but the "no other set shrinks" ground is void while `PL-D1` is
   open: there is no set to shrink. Re-ruled by Rick (§12 item 5):
   re-based on the `scheme_id=2` precedent alone, applied with dated notes
   at `verifier.rs`, `PQC_MULTISIG.md` and the `V3_1_MULTISIG_RUST_ENGINE.md`
   row. The `blockchain.cpp` comment is off the ledger by that ruling (the
   code is going away) and is rewritten in this PR regardless — the historical exception is explicit, not silent.
3. **`docs/DESIGN_CONCEPTS.md` §14 Mechanism A (2026-07-17).** *"An FCMP++
   spend never reveals which output it consumes, so N is unobservable ...
   Do not build this."* The observable exists today. Corrected at source;
   the disposition's ground is gone and it is listed for re-ruling (§8).
4. **The gate-6 firewall arc** — `ARCHIVAL_FIREWALL_GATE6.md:316–330`
   (`GF-4b`), `REWARD_EMISSION_VIN_PLAN.md:1045–1052`,
   `emission_wire.rs:118–132`, `ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md:172,
   189, 1292, 1331, 1364`, `PRINCIPAL_STAKE_LIFECYCLE.md:173`,
   `STAKER_ARCHIVAL_SIM.md:3533`, `rust/shekyl-standoff/src/lib.rs:55`,
   `rust/shekyl-standoff/src/conformance.rs:213`,
   `rust/shekyl-engine-state/src/pscan_state.rs:124`,
   `rust/shekyl-engine-core/src/engine/drain_select.rs:18`,
   `rust/shekyl-staking-sim/src/standoff.rs:63`,
   `ARCHIVAL_BOND_2C_GF7_HOOKS.md:180`,
   `ARCHIVAL_BOND_WI4_MEASUREMENT.md:3445, 3721, 3888, 3922` — all rest on
   "funding is FCMP++-hidden". **The principal↔P firewall's stated on-chain
   premise is refuted.** Out of this round's fix scope (brief §7); in its
   report scope. Each is a rule-26 A5 forward-action in §8, and the whole
   arc is flagged for Rick in §12.
5. **An agent-side note** (`tm1-self-inflicted-wallet-disclosure`, the
   session memory that justified MSW-6) carries the same "FCMP++ proof over
   the whole tree — no other set shrinks" sentence. Corrected in the memory
   store, not in the tree.

The pattern across all five: each is **true of the proof and false of the
transaction**, which is why they read as correct. Rule 16's corollary in its
purest form — the claim is true of the design's intent and false of the
design.

---

## 4. `PL-D2` — the in-circuit PQ binding is only as sound as the proof enforcing it (**RULED 2026-09-14; corrections applied**)

Raised by this round as a separate finding. It does **not** drive the fix in
§6; it decides what the successor round (§6.5) and any later post-quantum
strengthening have to deliver. Not part of the brief. Corrections applied
at source in this branch (§4.5).

### 4.1 The claim under review

Quoted as the documents read before §4.5 was applied; line numbers are at
that pre-correction state and are records-was.

`docs/POST_QUANTUM_CRYPTOGRAPHY.md:301–305`: *"The membership proof is
classical ... but the overall scheme achieves quantum resistance through the
`H(pqc_pk)` leaf binding: even if an attacker could break the EC discrete log
problem, they cannot forge a valid per-input `pqc_auths[i]` signature without
the ML-DSA-65 secret key bound to the leaf."* Repeated at `:1141–1144`
(*"Quantum-resistant binding ... even if EC discrete log is broken, the
ML-DSA-65 authorization prevents unauthorized spending"*), `:745–746`,
`docs/MERKLE_TREE.md:237` (*"still can't steal funds"*), and
`docs/FCMP_PLUS_PLUS.md` §2 ("Dual-Layer Security Model").
`docs/completed/FCMP_MEMBERSHIP_ONLY.md:361–374` runs the wargame explicitly:
the CRQC adversary *"cannot substitute their own `pqc_pk` (its hash would not
match the leaf commitment proven in-circuit)"*.

### 4.2 Why it does not hold against the adversary it names

The binding is the equality constraint at `circuit.rs:159–162`, enforced by a
Generalized-Bulletproofs arithmetic-circuit argument over Helios/Selene.
Bulletproofs-family arguments have **computational** witness-extended
emulation under the **discrete-logarithm relation assumption** on the
Pedersen vector-commitment generators (Bünz, Bootle, Boneh, Poelstra, Wuille,
Maxwell, *Bulletproofs*, IEEE S&P 2018, §4; Generalized Bulletproofs, Eagen &
Parker, is the same argument with vector commitments over the curve cycle).
A prover who can compute discrete logarithms among the generators can open a
commitment to more than one vector and prove any statement. The Pedersen
hashes that form the tree layers are collision-resistant under the same
assumption. **The vendored crates state no soundness assumption at all**
(zero hits for "soundness"/"discrete log" in
`rust/shekyl-oxide/crypto/generalized-bulletproofs/src/lib.rs` and
`crypto/fcmps/src/lib.rs` at the pin; the Cypher Stack review referenced at
`docs/MONERO_OXIDE_VENDOR_STATUS.md:232–238` is the external statement) —
a documentation gap recorded in §12, since a consensus-critical crate that
does not name its assumption cannot be held to it.

An adversary who "could break the EC discrete log problem" breaks it on
Ed25519, Helios and Selene alike (all three are ~2^126-security prime-order
curves; Shor's algorithm is curve-agnostic). Such an adversary:

1. recovers `x` (and `y`) from any on-chain `O`, so produces the victim's key
   image and a *valid* SAL proof — the step §7 of `FCMP_MEMBERSHIP_ONLY.md`
   already grants;
2. **forges** the membership argument for any public inputs it likes —
   including `extra_leaf_scalars = [H(pk_adv)]` for its own freshly generated
   ML-DSA key — because the argument's soundness is exactly the assumption it
   broke;
3. signs with `pk_adv`; `verify_transaction_pqc_auth` passes (the signature is
   genuine under the key presented, `tx_pqc_verify.cpp:230–241`);
4. spends the victim's output. It can also open the CT amount commitments
   (Pedersen, same assumption), which is the larger problem: under the PQ
   contract's own "classical assumptions fail" regime
   (`POST_QUANTUM_CRYPTOGRAPHY.md:72–75`) the chain's amount binding is gone
   before spend authorization is even tested. That is context for Rick, not
   a widening of this round.

### 4.3 What the in-circuit check buys, per era

| Adversary | Can produce `KI_V`, SAL? | Can forge the membership + 4th-scalar argument? | What the in-circuit binding adds |
|---|---|---|---|
| Classical (no DLOG break) | No | No | **Nothing** — SAL already refuses; the PQ layer is never the deciding check |
| CRQC (all EC DLOG broken) | Yes | **Yes** | **Nothing** — forgeable with the rest of the proof |
| Ed25519-specific break sparing Helios/Selene | Yes (valid SAL) | No | **Holds** — the only regime in which the 4th scalar decides anything. Note it requires the 2005 curve to fall while the 2024 curves survive |

Privacy is the other direction: the proof is perfectly zero-knowledge, so a
future CRQC does **not** retroactively de-anonymise past spends (no
harvest-now-decrypt-later exposure) — except that `PL-D1` makes every spend
public today, which is why the two findings are one composition.

### 4.4 What is PQ-binding today, and where it lives

The one object in the design that **is** post-quantum binding is the `0x07`
field itself: a Blake2b hash of the key, serialised into `tx_extra`, hashed
by Keccak into the txid, the block's tx-hash root, and the PoW chain. That
commitment is outside the circuit and outside the Pedersen tree; a CRQC
cannot open it to a second key. It is not used by any live check — consensus
uses the *leaf copy* through the circuit — but it is what would let an owner
prove, transparently, at a V4 transition, that a given output's ML-DSA key
was committed at creation (§7, `PL-D5`). Every fix candidate in §6 must
preserve that object's binding; a candidate that replaces `0x07` with a
DLOG-based encoding alone loses it — which is why `PL-D3` carries the
`PL-D3a` amendment (§6.2) rather than a bare point.

### 4.5 Corrections applied (Rick, 2026-09-14: "security information, not marketing; be precise")

Applied at source in this branch, each stating exactly what holds under
which assumption: `docs/POST_QUANTUM_CRYPTOGRAPHY.md` Security Goals (the
second "remain secure" clause's v3 status), the curve-tower paragraph, the
ownership-binding bullet, and the privacy-boundary bullet;
`docs/MERKLE_TREE.md` §"Our 4th scalar" closing paragraph;
`docs/FCMP_PLUS_PLUS.md` §2 preamble and Security Guarantee;
`docs/completed/FCMP_MEMBERSHIP_ONLY.md` §7 wargame (closed record: in-line
refutation marker). The common statement: *"The membership
argument and the leaf's `H(pqc_pk)` equality are enforced by a discrete-log
argument. Against an adversary who breaks EC discrete log they are forgeable;
the ML-DSA layer then authorises whichever key the forger presents. The
post-quantum property the design retains is the `0x07` commitment's binding
(Keccak-chained into the block), which supports a transparent claim at the
V4 transition, not a hidden-output spend. The in-circuit binding is
load-bearing only against a curve-specific break of Ed25519 that spares
Helios/Selene."*

---

## 5. Requirements for any fix

From the brief's §6.1, refined by the census:

- **R1 — bind at creation, and keep the post-quantum record.** The chain
  commits to the output's ML-DSA key when the output is created; the spend
  cannot open the *leaf* commitment to a different key under the assumption
  the proof rests on; and the Keccak-chained `0x07` record stays binding
  beyond that assumption (§4.4 — mission rule 1 rejects a change that
  weakens the PQ posture for a privacy gain). `PL-D3`'s leaf commitment is
  Pedersen (discrete-log binding, the proof's own assumption); the
  post-quantum record is kept by the `PL-D3a` amendment (§6.2): a hash half
  beside the point in `0x07`, checked by nothing live, exactly as today's
  hash is. A hash commitment *in the leaf* is `PL-D4`.
- **R2 — hide, at every surface.** The published per-output commitment must
  not be linkable to the key revealed at spend by anyone without the owner's
  secret. `Commit(k, r)` with `r` derived from `combined_ss` satisfies it;
  any deterministic public function of the key does not (that is the whole
  of `PL-D1`, and of the §7.4 retraction). "Every surface" is the census
  §6 (d)-9 list: the `0x07` field, the leaf, the RPC `chunk_outputs`, served
  shards, the wallet's leaf-meta copy — all of which may carry the
  *commitment* — and the verifier's `MDEBUG` line at
  `src/cryptonote_core/blockchain.cpp:4225`, which prints the recomputed
  value per input and must print nothing that opens it.
- **R3 — keep the in-circuit binding.** The circuit continues to bind the
  revealed key to the spent leaf; the fix changes the *statement* (an
  opening instead of an equality), not whether it is made. Its soundness is
  the proof system's, as today (`PL-D2`, §4); removing it is a downgrade
  this round does not propose (§7.7).
- **R4 — transparent opening.** The owner can open the creation commitment
  to the revealed key outside the circuit (reveal `k`, `r`), so the `0x07`
  record supports a claim if one is ever needed (§7.5).
- **R5 — genesis-frozen surface.** Leaf content, `0x07` semantics and the
  verifier's public-input shape are consensus bytes; the change is a rule-07
  cutover with the census as its criterion-3 enumeration (§10).
- **R6 — no new primitive in this cut.** The fix uses only mechanisms the
  circuit and the wallet already run (Wei25519 point arithmetic, the
  `discrete_log` gadget, NUMS generators, HKDF, cSHAKE256). Anything else is
  `PL-D4`.

The creation path is free: nobody verifies the `0x07` value at creation
(row 3 — nodes cannot). The creator publishes 64 bytes per output instead
of 32 (§6.2, `PL-D3a`), nodes copy the point half into the leaf, the tree
builds the same. **The whole verification cost lands at spend.**

---

## 6. The fix

### 6.1 Baseline, measured (2026-09-13)

`rust/shekyl-wire/tests/fcmp_spend_e2e.rs` (`fcmp_spend_real_tree_verifies_against_consensus`),
one input over a real depth-3 tree built by the production client, signed by
the production `sign_transaction`, verified by `shekyl_fcmp::proof::verify`;
`--release`, three runs, throwaway `Instant` timers around the two calls
(patch not committed). Machine: 16-thread i9-11950H @ 2.6 GHz — a developer
box, **not** the rule-76 floor; the numbers order candidates, they do not
set budgets.

| Quantity | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| sign + prove (1 input, depth 3) | 499 ms | 497 ms | 504 ms |
| verify (1 input, depth 3) | 23 ms | 22 ms | 23 ms |
| `fcmp_proof` bytes | 4 768 | 4 768 | 4 768 |

The first layer of the circuit runs **five** `discrete_log` gadgets per
input (`o_blind`, `i_blind_u`, `i_blind_v`, `i_blind_blind`, `c_blind`,
`circuit.rs:131–150`) over **four claimed points** in the proof tape
(`fcmps/src/lib.rs:305–312`: `inputs × (WORDS_PER_DIVISOR + 4 × WORDS_PER_CLAIMED_POINT)`,
one claimed point = 4 words, packed with `COMMITMENT_WORD_LEN = 128` words
per vector commitment over the padded C1 rows — the 4 288 B FCMP part of
the 4 768 B measured blob; the other 480 B is the SAL leg); the 4th-scalar equality at
`:159–162` is one linear constraint and costs nothing measurable today. Gate
counts are not exposed by the GBP API at the pin; the pre-flight (`26` B9)
instruments them before any budget becomes a gate.

### 6.2 `PL-D3` — the fix: a Pedersen commitment to the key in the leaf, opened in-circuit

**Creation.** Next to the ML-DSA seed, the sender derives a blind
`r = HKDF-Expand(prk, "shekyl-pqc-leaf-blind" ‖ idx_le64, 64) mod ℓ` from the
same `combined_ss` (`derivation.rs:230–265`; new label registered in
`CRYPTO_DOMAIN_REGISTRY.tsv` by hand — the gate does not detect omissions,
census §3), and the key scalar `k = H_ℓ(hybrid_pk)`: a 64-byte cSHAKE256
read of the canonical hybrid key under the customization
`shekyl/pqc-leaf-key-v1`, wide-reduced into the **Ed25519 scalar field**
(`hash_pqc_public_key`, `derivation.rs:66–81`, rewritten; the forwarders
`PqcLeafScalar::from_pqc_public_key` and the FFI `shekyl_fcmp_pqc_leaf_hash`
are unchanged). **Why cSHAKE256 and not the prefixed Blake2b of today
(Rick, 2026-09-14, "Tier B"):** cSHAKE carries the domain in its
construction, and the registry treats it as an always-domain mechanism —
a new call site that is not registered breaks the count-pin
(`domain_registry_gate.sh` tripwire 2; `PRODUCTION_PINS` in
`rust/shekyl-crypto-pq/tests/domain_registry.rs`) — whereas a Blake2b
prefix is a convention the gate cannot see. The existing
`DOMAIN_PQC_LEAF` row (`CRYPTO_DOMAIN_REGISTRY.tsv:182`, mechanism 4)
retires and two mechanism-1 rows replace it (this one and the record's,
below); the mechanism-1 pin rises by two and the mechanism-4 pin falls by
one. `shekyl-crypto-hash` already exports `cshake256_64` (the 64-byte read used for signature digests); it is reused, not added.
The multisig container takes the same function (`k = H_ℓ(container)`,
`multisig_pqc_leaf_hash`). Documents that name Blake2b for the leaf hash
follow in the implementing PR: `FCMP_PLUS_PLUS.md` §1, the CBOM row in
`CRYPTOGRAPHIC_INVENTORY.md`, the label registry in
`POST_QUANTUM_CRYPTOGRAPHY.md`, and the comment at `verifier.rs:1007`,
whose rationale becomes "same Keccak family as the cross-input binding,
distinct customization" (the C++ comment at `tx_pqc_verify.cpp:137–143` and
the C++ header strings go with the code they annotate and are not on this
ledger). The published `0x07` value becomes the compressed Ed25519 point

    CM = k·G_k + r·G_r

with `G_k`, `G_r` two new NUMS generators (hash-to-point of fixed domain
strings, the way `T`, `U`, `V` are made; registered with their strings).
`construct_leaf` (`tree.rs:506–524`) decompresses `CM` and converts it to
its Wei25519 `x` as the 4th scalar, as it does for `O` and `C`. The
recipient re-derives `r` at scan the way it re-derives the key
(`output.rs:1412–1434` gains the blind). Nothing at creation verifies the
*opening*, today or after.

**Point validity is an admission rule, not a DB-add check (Rick, review
2026-09-14).** `O` and `C` are gated at admission on both paths
(`cryptonote_core.cpp:800` → `check_outs_valid`; `blockchain.cpp:1458` for
the coinbase; `:3262` for the masks), which is what makes the DB-add throws
unreachable by construction (CEN-L11). If `CM`'s validity lived only in
`construct_leaf`, a transaction whose `0x07` bytes pass the length-only
shape rule but are not a canonical prime-order point would be
relay-admitted, mined, and then rejected at connect — `blockchain.cpp:6061–6066`
catches the throw, `reject_block_internal`, `return_txs_to_pool` — and every
block that includes it dies after its PoW: mempool poisoning. So the `0x07`
shape rule (`check_pqc_field_shape`, `shekyl-wire` `tx_extra.rs:478–512`;
its C++ adapter `check_tx_extra_shape` (over the codec's own parse since 2026-09-23),
`cryptonote_format_utils.cpp:978–995`) is extended from length to
**content**: per output, decompress, canonical encoding, prime order,
non-identity — on the relay path (`cryptonote_core.cpp:818–829`,
`check_tx_semantic`, no `kept_by_block` exemption) and the connect path
(`blockchain.cpp:1448–1453`, `prevalidate_miner_transaction`, and the
block-tx semantic check). `construct_leaf`'s failure then stays
unreachable. This is a **new consensus rule**: the implementing PR registers
it as a `CEN-I` row in `CONSENSUS_RULE_CENSUS.md` at birth and adds the S0
census row; it is also a rule the Rust twin (`transaction.rs:1829–1836` →
`check_pqc_field_shape_of`) enforces identically.

**`PL-D3a` — keep the post-quantum record (kept: Rick, 2026-09-14).**
§4.4 names the Keccak-chained `0x07` hash as the one object in the design
that is binding beyond discrete log, and mission rule 1 forbids trading it
for a privacy gain. A bare Pedersen point in `0x07` would give it up: a
quantum adversary opens `CM` to any key. The record is kept beside the
point, at no circuit cost and no new primitive:

    0x07 per output  =  CM (32 B)  ‖  cSHAKE256("shekyl/pqc-leaf-record-v1", pk ‖ r_h) (32 B)

with `pk` the **canonical hybrid key bytes** (`HybridPublicKey::to_canonical_bytes`),
not `k` — the record exists to survive into a lattice-only world, so it
must not depend on an Ed25519-scalar-field reduction that V4 retires;
committing to the key bytes directly lets `PL-D5` open it at V4 without
Ed25519 arithmetic even to define what was committed (Rick, review
2026-09-14) — and `r_h` a second blind derived under its own HKDF label
(`"shekyl-pqc-leaf-record-blind"`; HKDF is mechanism 2, so this label —
like `r`'s — stays a registry review duty, the one part of the path the
count-pin does not cover). The hash half is **not** in the
leaf (the leaf holds `CM.x` only, as before) and is checked by nothing live
— exactly the status of today's `0x07` hash — but it is Keccak-chained into
the txid and the block, so a quantum adversary cannot open it to a second
key, and it is what `PL-D5`'s transparent claim (§7.5) opens: reveal `pk`
and `r_h`, recompute the record, compare. What it buys is bounded and stated: nothing against
theft in the live path (`PL-D2`), nothing for privacy, and nothing `PL-D4`
does not supersede; it protects the migration path for every output created
before `PL-D4` lands — and with `PL-D4` ruled to V4 (§6.5) that is **every
v3 output**, which is why it is worth 32 bytes. Cost: 32 B more per
output on the wire (shape rule `64·n`; `tx-weight`'s
`extra_leaf_hashes_field_weight`, `lib.rs:213–220`, counts 64), one more
HKDF-Expand and one cSHAKE256 at creation and scan, nothing at spend,
nothing in the circuit; one registry row and the count-pin bump above.
**Fee consequence, stated where it is paid:** every output's predicted
weight rises by 32 B for the v3 era (`tx-weight`'s
`extra_leaf_hashes_field_weight` counts `64·n`), and fees follow weight.

**Scan-time verification, and the failure mode (spec; Rick, review
2026-09-14).** Consensus never verifies the opening — but the **wallet
must**, and today it does not: the scan path derives `h_pqc`
(`output.rs:394`, `:751`, `:965`) and never compares it with the published
`0x07` value; the only comparison anywhere is the emission backing gate
(`stake_engine/claim.rs:271`, `emission_verify.rs:670`). So a sender can
publish a well-formed value that does not open to the recipient's
`(k, r)`: the output scans, counts as balance, and fails at sign time when
`signing_assembly.rs:156–165` takes the leaf's 4th scalar from the assembled
chunk and the wallet's `r` does not open it — a silent-unspendable griefing
vector that exists today with `h_pqc` and carries over unchanged. The spec
therefore requires scan to verify **both halves** of the published value
against the recipient's own derivation: decompress the published point and
check `CM == k·G_k + r·G_r`, and recompute `cSHAKE256(pk ‖ r_h)` and check
it equals the record. On mismatch the output is classified
**received-but-unspendable**: excluded from spendable balance, retained in
the ledger, and surfaced to the user with the sender's transaction named
(rule 82 — a failure mode is design scope, not a log line). This is the
record's one live check, and it lives in the wallet, not consensus. The
pre-existing gap is census finding d-14 (§9).

**Exceptional-value guard (spec; Rick, review 2026-09-14).** The existing
legs reject the incomplete-addition exceptional cases by point-inequality
assertion (`membership_only.rs:391`, ~2⁻²⁵² each); the derivation crate
asserts its zero scalars (`derivation.rs:245–252`). The new leg has the same
shape and one case of its own: `r = 0` makes `CM = k·G_k`, a deterministic
function of the key — `PL-D1` again, for that one output. The derivation
therefore **rejects and re-derives** rather than asserting: if `r = 0`, or if
`K`, `−r·G_r` or `CM` is the identity, or `K` and `−r·G_r` are equal or
opposite (the `incomplete_add_pub` exceptional inputs), the blind is
re-derived with a one-byte counter appended to the HKDF info
(`"shekyl-pqc-leaf-blind" ‖ idx_le64 ‖ ctr`), starting at `ctr = 0` and
incrementing; the recipient reproduces the same walk at scan. Stated so the
guard is a rule, not a later "we assumed"; the probability is negligible
and the check is one comparison.

**Spend.** The key is revealed as today for the ML-DSA check
(`tx_pqc_verify.cpp:230–241`); consensus computes `k` as today
(`blockchain.cpp:3783`, `:4092`, `:4212`; `verifier.rs:1021–1024`) and then
the public point `K = k·G_k`. The verifier's public input becomes `K`
instead of a scalar. **`K` is not a wire field.** `Input`'s wire form is
`O~, I~, R, C~` (`lib.rs:102–146`); `extra_leaf_scalars` was never on the
wire — it is verifier-computed from the revealed key and enters only the
transcript and the first-layer public values (`lib.rs:350–362`, `:442–443`)
— and `K` takes exactly that place, so there is never a second copy of a
derived value for the wire to disagree with.
In the circuit the blind `r` is a witness and the first-layer constraint at
`circuit.rs:159–162` becomes the shape of the `c_blind` leg at `:148–150`:

    CM   = on_curve(leaf4_x)                          // witness point, x from the leaf
    Rneg = discrete_log(−r, G_r table)                // witness dlog over a new generator table
    incomplete_add_pub(K, Rneg, CM)                   // K = CM + (−r)·G_r  ⇔  CM = k·G_k + r·G_r

`CM.x` still enters the membership tuple (`:165–168`), so the leaf is still
proven to be in the tree with *that* commitment.

**Why it fixes `PL-D1`.** `k` (and `K`) appears once, at spend, and is
published nowhere at creation; `CM` is published at creation and is a
perfectly hiding commitment, so matching `K` to any `CM` requires `r`. The
observer's lookup table has nothing to look up — **for everyone except the
output's creator**, who holds `combined_ss` and therefore derives `pk`, `r`
and `r_h` exactly as the recipient does, and can recognise the spend of the
output it created. That residual is structural to sender-derived per-output
keys and is recorded in §13 with its reopener; it is not this round's.

**What it keeps.** Every binding the design has today, under the assumption
the design already rests on: the circuit binds the revealed key to the
spent leaf, and opening `CM` to a second key requires the discrete log
between `G_k` and `G_r` — the same assumption under which the membership
argument is sound (§4). R2–R6 hold; R1 holds under that assumption for the
leaf and beyond it for the record under `PL-D3a`. **Sign ambiguity,
recorded so it is not rediscovered:** the leaf holds `CM.x`, shared by
`±CM`, so the holder of `(k, r)` can also open to `(−k, −r)`. Harmless — a
substitute key would need `H_ℓ(pk') = −k`, a preimage — and identical to the
ambiguity `O.x` and `C.x` already carry.

**Cost.** One more claimed point on the four the first layer already
carries, in the exact shape of an existing leg — so the cost is known by
analogy today and confirmed by measurement at pre-flight. **Numeric
correction, 2026-09-14 (rule 26 B6):** the first ratified draft priced the
proof-size delta as "+128 B per input" by reading one claimed point's four
words as bytes on the wire; the words are packed into vector commitments,
and the crate's own formula gives the figures below.

| Quantity | Figure | Basis |
|---|---|---|
| Proof size | **+128 B per proof for one input at depths 3–6; 0 to −2 752 B for 2–16 inputs** — measured on real proofs at pre-flight (census companion §8). The leg replaces the per-input extra-scalar branch commitment with one claimed point packed into the existing C1 words, so multi-input proofs shrink. Two earlier figures in this row ("+128 B per input", then "+256 B per proof") were formula readings that kept the extra branch; superseded | real `proof.len()` against the crate's `proof_size` at every (inputs, layers) the suite proves, 2026-09-14 |
| First-layer rows | **+14 rows** per input (97 → 111, `Circuit::muls()`); the one-input C1 IPA now pads to 512 at 7 layers instead of 8 | measured 2026-09-14 (census §8) |
| Prove | 8-layer crate bench: +3 % to +24 % (601 → 737 ms one input; 2 079 → 2 588 ms four inputs), most of it the padding crossing at 8 layers | measured, noisy box; floor device owed |
| Verify | +6 ms per proof (25 → 31 ms, n = 100); batches of 10 and 100 within noise | measured |
| Creation / scan | one fixed-base double-scalar multiplication + one HKDF-Expand per output | wallet-side, negligible |
| `0x07` width | **64 B per output** under `PL-D3a` (32 B compressed point ‖ 32 B record); the point alone would be 32 B | shape rule `64·n` |
| New primitive | **none** — Wei25519 arithmetic, the divisor `discrete_log` gadget, NUMS generators, HKDF and `cshake256` (`shekyl-crypto-hash`) all exist | R6 |

**Blast radius beyond the circuit** (census S0–S3): the `0x07` semantics
(point, not scalar) and the shape rule's doc; `construct_leaf` and both
leaf FFI constructors (decompress + validate the 4th input like `O`, `C`);
the three verifier arms and the Rust twin (compute `K`, pass a point); the
prover path (`ProveInput` carries `r`; sibling leaves carry `CM.x` as now);
`Input`/`InputVerification` (point instead of scalar; `PqcCommitmentMismatch`
finally means what it says); the derivation crate (second reduction target,
two blind labels, two generators with pinned strings and vectors);
`shekyl-crypto-hash`'s existing `cshake256_64` gains a consensus-path caller
(S0); **the
`G_r` generator table joins the `discrete_log_challenge` generator set at
`circuit.rs:124–125` (`[T, U, V, G]` becomes five) and `FcmpParams`
(`params.rs:26–29`, `:57–59`) — an S0 row of its own, because the challenge
derivation and every transcript change with it**; the `0x07` shape rule
becomes a content rule (above) and, under `PL-D3a`, a `64·n` rule; every S1
class-a/b vector regenerates (§9); the vendored-crypto manifest updates as a
sanctioned event; the curve-tree store `SCHEMA_VERSION` and LMDB `VERSION`
bumps are manual duties (the rule-42 snapshot gate is silent, census §5);
the `MDEBUG` print at `blockchain.cpp:4225` is dropped or prints only `CM`;
the census (d)-2 `hp_of_O`/`h_pqc` aliasing on the legacy sign bridge is
fixed in the same PR or it routes the wrong value.

### 6.3 Alternatives priced against it

| | `PL-D3` Pedersen commitment (the fix) | Hash commitment, opened in-circuit (`PL-D4`, successor round) | Drop the in-circuit check, hiding `0x07` only (§7.7) |
|---|---|---|---|
| Published `0x07` | compressed point `k·G_k + r·G_r` ‖ record `cSHAKE256(pk ‖ r_h)` (`PL-D3a`), 64 B | `H2(k ‖ r)` field element | `H2(k ‖ r)` |
| Circuit change | one more `discrete_log` + `on_curve` + `incomplete_add_pub` leg (the `c_blind` shape) | one arithmetisation-friendly hash gadget (Poseidon2 or sibling) replaces the equality | remove the constraint and the public input |
| In-circuit cost | +1 claimed point on 4; +256 B per proof at depths 3–4 (formula, §6.2) | ≈ 250 multiplication gates by estimate; +0–64 B | negative |
| Commitment binding | discrete log — the proof's own assumption | collision resistance — survives a discrete-log break | collision resistance |
| Hiding | perfect | yes | yes |
| New primitive | **none** | **yes**: a hash over the leaf field with generated parameters, vectors, a Rust implementation every producer shares, and its own cryptanalysis posture | no |
| Fits the current code | yes — an existing gadget, an existing validation path for points | no — a new consensus primitive patched into the first layer mid-stream | — |
| Disposition | **the fix now** (Rick, 2026-09-14) | **successor round** — designed properly, not patched in (§6.5, §7.6) | rejected on record |

### 6.4 Prior ruling superseded (rule 21)

`docs/design/V3_1_MULTISIG_RUST_ENGINE.md:612–614` (`R1-F-2` retraction) and
`:800–802` rejected changing the `DOMAIN_PQC_LEAF ‖ …` leaf preimage as *"not
free, not needed"* — for the purpose that round had, scheme separation,
which length already provides. `PL-D1` is the need that ruling did not have,
and §6.2 prices the "not free". The rejection's own reopening shape (a new
need, substrate-anchored) is met; this round supersedes it for this purpose
and leaves the scheme-separation conclusion untouched. The multisig
container (`multisig_pqc_leaf_hash`, census (d)-13) takes the same
commitment with `k = H_ℓ(container)`; whether `r` derives per scheme is a
pre-flight item.

### 6.5 `PL-D4` — the successor round: a proper hash commitment mechanism

Named here, not designed here. What it owes:

- **The commitment.** `H2(k ‖ r)` in the leaf with an in-circuit opening,
  where `H2` is an arithmetisation-friendly hash over the leaf field chosen
  on measured gates *and* published cryptanalysis (Poseidon2 has the most
  analysis; Rescue-Prime and Anemoi are the siblings to price), with
  parameters generated by the reference procedure for that prime, pinned
  vectors, a domain-registry row, and one Rust implementation shared by the
  sender, scan, the genesis tool and the circuit gadget (rules 17, 30).
- **What it buys over `PL-D3`.** A creation record that is binding beyond
  discrete log: a quantum adversary cannot open `H2(k ‖ r)` to a second
  key, so the `0x07` record becomes a genuinely post-quantum commitment to
  which key each output was created for — the object a post-quantum-sound
  membership leg (the `PL-D2` strengthening: a hash-based zero-knowledge
  proof over a hash tree of these commitments, carrying the key-image
  relation) would prove over. `PL-D3`'s Pedersen record cannot serve that
  leg; `PL-D4` re-commits.
- **Target — RULED (Rick, 2026-09-14): post-genesis, at the V4
  transition.** V4 is the lattice-only cutover, itself gated on primitives
  that do not yet exist in approved form — lattice-based threshold
  signatures, or mature isogeny-based signatures (PRISM) — so the hash
  commitment is designed *together with* the post-quantum-sound membership
  leg it exists to serve, as one leaf-format cutover under rule 07, not as
  a standalone re-commitment of every v3 leaf. Carried in `FOLLOWUPS.md`
  under `Target: V4`. Consequence for `PL-D3a`: the window it covers is the
  **entire v3 era**, which is why the record beside the point is kept
  (§6.2).

---

## 7. Alternatives rejected on record (rule 21 shape)

### 7.1 Do not reveal the key at spend — verify ML-DSA in-circuit

**Rejection.** ML-DSA-65 verification is NTT-heavy lattice arithmetic over a
23-bit modulus (`q = 8380417`) with `k=6, ℓ=5` polynomial vectors of degree
256; SNARK encodings of Dilithium verification in the literature run to
**order 10^6–10^7 constraints** (estimate; no source pinned this round —
pre-flight pins one if this is ever reopened) against a first layer that
today runs five discrete-log legs. It also removes the revealed key the
transparent opening (R4) needs, and it would still be enforced by the same
proof system, so it buys nothing against the adversary `PL-D2` names.
**Reopening criteria.** A post-quantum-sound proof leg (§6.5) in which the
signature check is cheaper than the reveal. **Re-evaluation shape.** That
leg's design round.

### 7.2 Non-per-output PQC keys (per wallet / per account)

**Rejection.** The reveal then identifies the wallet instead of the output:
every spend by one owner links to every other. Strictly worse than `PL-D1`.
**Reopening criteria.** None substrate-anchored; recorded so it is not
re-proposed. **Re-evaluation shape.** Not applicable.

### 7.3 Move PQ authorisation off the leaf — bind to the key image

**Rejection.** The key image is a discrete-log object (`I = Hp(O)`,
`KI = x·I`); a binding through it is no stronger than the binding through
the leaf, and the key image is already a public per-spend identifier so
nothing is gained on privacy. A wallet-level commitment reduces to §7.2.
**Reopening criteria.** A post-quantum linking tag (a deterministic,
unlinkable function of the per-output ML-DSA key with a post-quantum-sound
proof of derivation) — the §6.5 leg's natural companion. **Re-evaluation
shape.** The §6.5 round.

### 7.4 Blind the 4th scalar in-circuit (the brief's §6.2 retraction, recorded)

**Rejection.** Making the scalar a private witness changes nothing an
observer cannot recompute: the leak is the key's reveal against a
*published* deterministic function of it, not the circuit's declaration.
**`PL-D3` is not this**: it changes the published value to a hiding
commitment; the retracted idea kept it as `H(pk)`. The discriminator is
whether `0x07` still equals a function of `pk` alone. **Reopening
criteria.** None. **Re-evaluation shape.** Not applicable.

### 7.5 `PL-D5` — the transparent claim (named, not designed)

The thing R4 keeps possible: a claim that reveals the output, `pk` and
`r_h`; consensus recomputes `cSHAKE256("shekyl/pqc-leaf-record-v1", pk ‖ r_h)`
and checks it against the record half of the `0x07` value in the
Keccak-chained block, verifies the ML-DSA signature under `pk`, and marks
the output spent transparently. That check is post-quantum binding under
`PL-D3` + `PL-D3a` — it opens the **hash record**, which is why the record
exists; the Pedersen half is not consulted (it could be opened with `r` as
well, but that proves nothing a discrete-log adversary could not also
prove). Under `PL-D4` the leaf's own hash commitment serves the same role.
**Disposition:** RESERVED (rule 23) — named so
every candidate is checked against R4, **no code symbol, no wire tag**.
**Reopening criteria.** The V4 transition design, or a ruling that a bridge
is wanted before the §6.5 leg lands. **Re-evaluation shape.** That round.

### 7.6 Hash commitment in this cut

**Rejection — for this cut, not on the merits.** A hash commitment is the
stronger record (§6.3) and is the successor round's subject. Building it
*now* means adopting a new consensus primitive — a hash over the leaf field
with generated parameters, a shared Rust implementation, vectors, a
registry row and a cryptanalysis posture — in the middle of a fix whose
every other part is an existing mechanism; that is patching, not
designing, and it multiplies the review surface of a genesis-frozen change.
**Reopening criteria.** The V4 transition round opens (`PL-D4` is ruled to
it, §6.5) with a chosen hash, pinned parameters and measured gates.
**Re-evaluation shape.** The V4 design round, in which the hash commitment
and the post-quantum-sound membership leg are one cutover.

### 7.7 Drop the in-circuit check; publish a hiding commitment only

**Rejection.** Cheapest of all and privacy-complete, but it removes the
binding between the revealed key and the spent leaf in the live spend path.
Whatever that binding's soundness against a quantum adversary (`PL-D2`), it
holds against every classical adversary and is the load-bearing half of the
hybrid posture the mission ships from genesis; removing it is a security
downgrade, which is a conscious ruling, not a side effect of a privacy fix.
**Reopening criteria.** A ruling on `PL-D2` that retires in-circuit binding
in favour of the §6.5 leg, with that leg landed. **Re-evaluation shape.**
That round's closure.

---

## 8. Forward-actions (rule 26 A5) — every consumer of the refuted invariant

Each carries `file:line` at `42333d34f`; each is absorb-later by a named
carrier, never "a follow-up". **Carriers (Rick, review 2026-09-14):** rows
A5-1…A5-7 are a firewall re-ruling, not a leaf fix — their carrier is the
**gate-6 owner** (`ARCHIVAL_FIREWALL_GATE6.md`'s round), opened once
`PL-D3` lands and the premise is restored; rows A5-8…A5-12 are carried by
**this round's closure** (the ratifying edit of §12).

| # | Site | What it says | Disposition |
|---|---|---|---|
| A5-1 | `docs/design/ARCHIVAL_FIREWALL_GATE6.md:316–330` (`GF-4b`) | rung 2 "backward lineage is FCMP++-hidden"; rung 3 "the only rung whose reveal newly identifies the funding tx" | Re-rule: every rung identifies its funding chain today; the ladder orders rungs by a distinction that does not exist until `PL-D1` is fixed |
| A5-2 | `docs/design/ARCHIVAL_FIREWALL_GATE6.md:1599, 1629, 2294, 2990, 3224, 3246` | "FCMP++-hidden funding" as a load-bearing premise | Re-rule with A5-1 |
| A5-3 | `docs/design/REWARD_EMISSION_VIN_PLAN.md:1045–1052` | "RESOLVED (freeze) … does not trace to the funder" | Mark the resolution's ground struck; the freeze decision stands or falls with §6's ruling |
| A5-4 | `rust/shekyl-archival-retention/src/emission_wire.rs:118–132` | doc comment citing the §7.3 invariant | Rewrite the comment from the corrected §7.3 |
| A5-5 | `docs/completed/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md:172, 189, 1292, 1331, 1364` | closed record | In-line refutation markers (rule 95), same shape as `FCMP_MEMBERSHIP_ONLY.md:376` |
| A5-6 | `docs/design/PRINCIPAL_STAKE_LIFECYCLE.md:173`, `docs/design/STAKER_ARCHIVAL_SIM.md:3533`, `docs/design/ARCHIVAL_BOND_2C_GF7_HOOKS.md:180`, `docs/design/ARCHIVAL_BOND_WI4_MEASUREMENT.md:3445, 3721, 3888, 3922` | "FCMP++-hidden" premises in live design docs | Correct at source once §6 is ruled (the fix restores the premise; the docs then state it as restored, not as always-true) |
| A5-7 | `rust/shekyl-standoff/src/lib.rs:55`, `rust/shekyl-standoff/src/conformance.rs:213`, `rust/shekyl-engine-state/src/pscan_state.rs:124`, `rust/shekyl-engine-core/src/engine/drain_select.rs:18`, `rust/shekyl-staking-sim/src/standoff.rs:63` | crate/module docs stating consensus cannot classify funding because it is FCMP++-hidden | Rewrite from the ruled design |
| A5-8 | `src/cryptonote_core/blockchain.cpp:4276–4290`, `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1077–1086`, `docs/PQC_MULTISIG.md:2026–2040`, `docs/design/V3_1_MULTISIG_RUST_ENGINE.md:172` | MSW-6 "no other set shrinks" ground | **RULED (Rick, 2026-09-14, §12 item 5):** re-based on the `scheme_id=2` precedent alone; applied with dated notes at `verifier.rs`, `PQC_MULTISIG.md` and the `V3_1_MULTISIG_RUST_ENGINE.md` row. The `blockchain.cpp` comment is off the ledger by the same ruling (the code is going away) and is rewritten in this PR regardless |
| A5-9 | `docs/DESIGN_CONCEPTS.md` §14 Mechanism A | "do not build this" on a refuted premise | Premise corrected at source in this branch; the disposition is re-ruled with §6 |
| A5-10 | `docs/CHANGELOG.md:5969` and other ledger lines | historical wording | Ledger; not edited (rule 95) |
| A5-11 | `docs/POST_QUANTUM_CRYPTOGRAPHY.md` (Security Goals, curve tower, ownership binding, privacy boundary); `docs/MERKLE_TREE.md` §"Our 4th scalar"; `docs/FCMP_PLUS_PLUS.md` §2; `docs/completed/FCMP_MEMBERSHIP_ONLY.md` §7 wargame | `PL-D2` claims | **Applied** in this branch (§4.5), ruled 2026-09-14 |
| A5-12 | `rust/shekyl-oxide/crypto/generalized-bulletproofs`, `crypto/fcmps` crate docs | no stated soundness assumption | Add the assumption to the crate-level doc (rule 30: state what the primitive rests on) — a one-paragraph PR, independent of the fix |

---

## 9. Blast-radius census

Every site that reads, writes, computes, serialises, stores, verifies,
documents or tests the 4th leaf scalar, the leaf format, or `tx_extra` `0x07`,
severity-ordered; the enumeration a rule-07 criterion-3 PR pastes at
`Base commit: 42333d34f`. Counted as **function-level sites** (one row per
function or passage, not per grep hit).

The full census is the companion record
[`FCMP_SPEND_LINKABILITY_CENSUS.md`](FCMP_SPEND_LINKABILITY_CENSUS.md)
(158 rows, 256 distinct file references, produced by a subagent sweep and
spot-checked at source: the genesis golden KAT constants, the `R1-F-2`
retraction row, the emission leaf gate, the stale fuzz target, the
vendored-crypto manifest line, the `MDEBUG` print). Counted from its tables:

| Band | Rows (function-level sites) | Distinct files |
|---|---|---|
| S0 consensus / wire (circuit, prove/verify, `0x07` codec and shape rule, verifier arms, DB leaf store, replica, RPC path, genesis, creation) | 74 | 62 |
| S1 KATs / frozen vectors / gates | 19 | 28 |
| S2 wallet / engine (create, scan, spend, stake, drain, tx-weight, serve) | 22 | 44 |
| S3 FFI signatures / headers / ABI pins | 7 | 5 |
| S4 documentation | 22 | 52 |
| S5 tests / benches / fuzz | 14 | 76 |

**Frozen vectors `PL-D3` regenerates (census S1, class a/b):**
`docs/test_vectors/PQC_LEAF_HASH_KAT.json`, `PQC_LEAF_HASH_RAW_PK_KAT.json`,
`PQC_SCAN_OUTPUT_KAT.json` (the Selene-field `k` pins are replaced by
Ed25519-scalar `k` pins plus `CM` vectors);
`rust/shekyl-curve-tree/tests/fixtures/ct2_tier_a.json` and `ct2_tier_b.json`
(639 blocks of real `0x07` blobs and consensus roots; regenerated from a
daemon running the new leaf); `rust/shekyl-genesis-tool/tests/golden_kat.rs:28–34`
(genesis blob sha256, tx hash, block id — the genesis freeze artifact);
`rust/shekyl-archival-retention/tests/fixtures/{emission_connect,gate2_serve_credit,serve_credit_equivalence}_kat_v1.json`
and their C++ consumers; `rust/shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json`.
Layout-only vectors (`WITNESS_HEADER.json`, `TX_EXTRA_PQC_ROUND_TRIP.json`,
`EMISSION_AUTH_MSG_V1`) survive a content-only change.

**Gates that fire:** the vendored-crypto manifest (circuit files), the
workspace test run (every class-a/b KAT), the C++ unit tests on the
archival fixtures, the docs citation gates. **Gates that do not fire and
must be done by hand:** the rule-42 snapshot (silent), the domain registry
(silent on a *new* domain), the fuzz inventory (file presence only).

**Census findings outside the asked scope, with dispositions:**

| # | Finding (census §6) | Disposition |
|---|---|---|
| d-1 | `fuzz_curve_tree_leaf_hash.rs:33` calls `construct_leaf` with two arguments; the fuzz crate is built nowhere in CI, so it has been uncompilable undetected; `FCMP_PLUS_PLUS.md:1372,1388` advertise it as live | Fix in the implementation PR (it must exercise the new opening anyway); the fuzz-crate build gap is its own FOLLOWUPS line |
| d-2 | `legacy_tx.rs:306` routes `hp_of_O` into `h_pqc`; every caller passes the same hex for both | Fix in the implementation PR — with `cm ≠ H(pk)` the aliasing silently breaks |
| d-3 | The wallet replica keeps the zero-`h_pqc` fallback the daemon retired (CEN-I19): `recon.rs:26–76`, `client.rs:759`, `curve_tree_decode.rs:43–47`; docs `CT2_DRAIN_ORDER.md:161–163`, `CURVE_TREE_CLIENT.md:410` state it as the contract | Rick: fold into this round's PR or its own; unreachable on an admitted chain but a stated contract that is false |
| d-4 | "32 zero bytes if unavailable" doc strings on `construct_leaf`, `shekyl_construct_curve_tree_leaf`, `shekyl_ffi.h:1389` | Fix with d-3 |
| d-5 | `FCMP_PLUS_PLUS.md:1172–1174, 1196–1198, 1110–1135` describe a stake-claim leaf cross-check and a 5-scalar staking leaf that do not exist | Doc correction; can ride the §11 PR |
| d-6 | `FCMP_PLUS_PLUS.md:73, 530–531, 548–550, 1111, 1822` and `GENESIS_TX_WIRE_FORMAT.md:773, 1028` say the preimage is the ML-DSA key alone; code hashes the full canonical hybrid key | Doc correction; can ride the §11 PR |
| d-7 | Stale FFI locations in `FCMP_PLUS_PLUS.md:599–601`, `CT2_DRAIN_ORDER.md:193`; `verifier.rs:1009` cites moved `blockchain.cpp` lines | Doc/comment correction; can ride the §11 PR |
| d-8 | Four independent `LEAF_BYTES = 128` declarations besides the derived one | Unchanged by `PL-D3` (width stays); recorded |
| d-9 | Enumeration surfaces of the value today, incl. the `MDEBUG` print | Absorbed into R2 |
| d-10 | `R1-F-2` prior ruling | Superseded, §6.4 |
| d-11 | Test comments (`local_keys_tests.rs:113–125`, `synthetic_tree.rs:18–27`, `tx_weight_kat.rs:68`) document "any consistent `h_pqc` verifies because it is a public input" | Become false under `PL-D3`; rewritten in the implementation PR |
| d-12 | `PqcCommitmentMismatch` already named as if the scalar were a commitment; count-mismatch and non-canonical share it on the full path | Name becomes right; the shared variant is split in the implementation PR |
| d-13 | Multisig container hashed under the same DST | §6.4 |
| d-14 | **The scan path never verifies the published `0x07` value** (`output.rs:394, 751, 965` derive `h_pqc`; no comparison; the only `!=` is the emission backing gate at `claim.rs:271` / `emission_verify.rs:670`), so a mismatching value scans as balance and fails at `signing_assembly.rs:156–165` — a silent-unspendable griefing vector that predates this round | Absorbed into the §6.2 scan-time verification spec; the received-but-unspendable failure mode is part of the implementing PR (rule 82) |


---

## 10. The implementation PR, when ratified (rule 07 framing — not this round) — EXECUTED 2026-09-14, record in §12.1

- **Criterion 1** met: leaf content and the verifier's public-input shape
  are byte-identical-reproduction rules. **Criterion 2** follows. **Criterion 3**: §9 at `Base commit`.
  **Criterion 4**: reviewer map = §9's S0 rows (consensus-affecting), S2/S3
  (mechanical rewires), S1 (regenerated vectors), S4/S5 (docs/tests).
- **Rule 42**: `0x07`'s semantics change is a persisted-wire change. The
  snapshot gate is **silent** for it (nothing under `shekyl-engine-state`
  carries the value — census §5), so the version-constant bumps are manual
  duties named in the PR: the curve-tree store's `SCHEMA_VERSION`
  (`redb_backend.rs:75`), LMDB `VERSION` (`db_lmdb.cpp:149`) if the format
  changes, and the vendored-crypto manifest for the circuit files.
- **The first thing the implementing agent writes is the fix-falsifier**
  (Rick, review 2026-09-14): hash the revealed key of every spend in a
  synthetic chain, search every leaf and every `0x07` value, expect zero
  matches — red on today's tree, green only when the commitment hides.
- **Rule 26 pre-flight** before the first production commit: instrument GBP
  gate counts; measure the chosen candidate on the rule-76 floor device;
  re-derive every census S1 vector from the ruled derivation; re-run this
  document's §2 chain against the new composition and show the lookup
  **fails** (the fix-falsifier is separate from the defect-falsifier: a test
  that hashes the revealed key and searches every leaf and every `0x07`
  value must find **no** match), and that a wrong `r` or wrong `k` fails
  verification (the binding-falsifier: `test_wrong_h_pqc_fails` at
  `fcmps/src/tests.rs:757–789` becomes `test_wrong_opening_fails`).
- Reversibility: pre-genesis, so "revert" = regenerate genesis and vectors;
  no migration.

---

## 11. Document corrections applied in this branch (`PL-D1` at source)

Struck and restated, not softened, per the brief's §9. Ruled 2026-09-14:
they land in the same PR as this document (one design PR, since all other
work is paused for this fix); they are true regardless of the candidate
chosen, and a reader who trusts the current text is being told the product
has a property it lacks.

- `docs/FCMP_PLUS_PLUS.md` preamble, §1 opening, §2 Layer 1, §2 Security
  Guarantee — the proof's zero-knowledge is kept; the transaction-level
  anonymity claim is struck.
- `docs/MERKLE_TREE.md` §"Our 4th scalar" — *"again, without revealing which
  leaf"* struck; the sentence now says the public input is what reveals it;
  the closing "still can't steal funds" paragraph restated under `PL-D2`
  (§4.5).
- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` Security Goals, §"FCMP++ and PQC
  ownership binding", §"v3 Privacy Boundary" — six `PL-D1` passages, plus
  the four `PL-D2` passages (§4.5).
- `docs/design/REWARD_EMISSION_LEG.md` §7.3 — the 2026-07-01 invariant
  struck with a dated record; tripwire recorded as fired; the GF-4b rung-2
  clause annotated as re-ruled by this round.
- `docs/completed/FCMP_MEMBERSHIP_ONLY.md` §7 cross-ref — closed record,
  in-line dated refutation marker (rule 95), no rewrite.
- `docs/USER_GUIDE.md` glossary — operator-facing; states the defect in plain
  words and that amounts/recipients stay hidden (rules 81, 82).
- `docs/design/PHASE_2A_SEND_PATH.md` §"no per-output path query" — the
  boundary rule is necessary, not sufficient, while `PL-D1` is open.
- `docs/DESIGN_CONCEPTS.md` §14 — Mechanism A's premise and the anonymity-set
  sentence.
- Source comments, own commit: `rust/shekyl-fcmp/src/leaf.rs:6–13`,
  `rust/shekyl-curve-tree/src/lib.rs:8–13`,
  `rust/shekyl-fcmp-proofs/README.md:5–9`, `tests/unit_tests/fcmp.cpp:311–314`.
- Swept, nothing found: `docs/design/FCMP_SPEND_SIGNING_PREIMAGE.md` (no
  anonymity claim; it documents the preimage only).

---

## 12. Findings — what this round ruled and what needs Rick

**Ratified by Rick, 2026-09-14:** §6.2 as written, including the two
2026-09-14 reviews' additions.

**Ruled by this round (agent), grounded at `42333d34f`:**

1. `PL-D1` is confirmed at every link on both verifier implementations and
   every spend arm; no refutation exists (§2). Priority-2 defect, pre-genesis.
2. The §11 corrections are applied at source; they are true under every
   candidate and can land ahead of the design ruling.
3. `PL-` is the family; `F5` is the historical name.
4. §7.1–§7.7 are rejected on record with reopening criteria; `R1-F-2` is
   superseded for this purpose (§6.4).
5. `PL-D5` is RESERVED, no symbol (§7.5).
6. The measured baseline (§6.1) and the estimate/measurement split (§6.2).

**Rulings (Rick, 2026-09-14) — each item names what was open and how it was
settled; nothing here is still pending except where an item says so:**

1. **`PL-D3` in its written form — RATIFIED (Rick, 2026-09-14):** the
   Pedersen commitment opened in-circuit (§6.2). Rick gave the direction
   in-channel ("go with Pedersen now"); the derivation details
   (Ed25519-scalar `k`, the blind label, two NUMS generators, compressed
   point in `0x07`) are this document's rendering of it, ratified as
   written. His
   review of 2026-09-14 moved point validity to an admission rule on both
   paths (applied, §6.2) — that rule is a new consensus rule and is ratified
   with the fix. His second review the same day added, all applied in §6.2:
   the record commits to the canonical key bytes, not `k`; scan verifies
   both halves and mismatches are received-but-unspendable; the `r = 0` /
   exceptional-input guard is reject-and-re-derive under a counter; the
   `0x07` width is 64 B everywhere the document states it.
1a. **`PL-D3a` — RULED, kept (Rick, 2026-09-14):** the post-quantum `0x07`
   record rides beside the point (`CM ‖ record`, 64 B per output). **Tier B
   RULED (same day):** both the key hash `k` and the record move onto
   cSHAKE256 under registered customizations so the domain is mechanical;
   the C++ side's comments and header strings are not on the ledger
   because that code is going away. The written form in §6.2 is confirmed
   by the ratification in item 1.
2. **`PL-D4`'s target — RULED (Rick, 2026-09-14): V4**, post-genesis,
   designed with the lattice-only transition, which itself waits on
   lattice threshold signatures or mature isogeny signatures (PRISM).
   FOLLOWUPS carries it under `Target: V4`.
3. **`PL-D2` — RULED (Rick, 2026-09-14):** the "even if EC discrete log is
   broken" claims are corrected at source as §4.5 records; the
   post-quantum-sound leg is designed with `PL-D4` at V4.
4. **The archival firewall premise — RULED:** the gate-6 owner re-rules
   A5-1…A5-7 **after** the implementation PR lands, when the premise is
   actually restored.
5. **MSW-6's rationale — RULED, applied:** re-based on the `scheme_id=2`
   precedent alone, with a dated note at `verifier.rs`, `PQC_MULTISIG.md`
   and the `V3_1_MULTISIG_RUST_ENGINE.md` row (the C++ comment is off the
   ledger).
6. **A5-12 — RULED:** the soundness-assumption paragraph goes into the
   implementation PR, which already updates the vendored-crypto manifest.
7. **Census d-3/d-4 — RULED:** folded into the implementation PR (same
   call sites, same validation surface).
8. **Landing order — RULED:** one design PR carrying this document, the
   census, the index and FOLLOWUPS lines, and every §11 correction.
9. **The emission backing arm's wire — RULED:** the vin's `pqc_pk_hash`
   field is removed (its only consumer becomes the in-proof opening);
   `backing_pubkey` stays; the implementing PR cites the emission wire
   freeze when it changes the field.
10. **Where the implementation is done — RULED:** a clean worktree from
    current `dev`, not stacked on this branch; pre-flight (§10) before any
    production commit.
11. **The `docs/so-d8-proposal` reconciliation** — whichever lands second
    reconciles to one FOLLOWUPS line and a cross-reference.

---

### 12.1 Implementation record (2026-09-14)

Landed on `feat/pl-d3-pedersen-leaf-commitment` (a clean worktree from
`dev` at `a6160a4bd`, ruling 10), rule-07 framing per §10:

- **Fix-falsifier first** (`rust/shekyl-wire/tests/pl_d1_fix_falsifier.rs`,
  commit `cf063a744`): red on the pre-`PL-D3` tree with exactly one match
  on each surface at the spent index; green after the fix with zero matches
  on both. Binding-falsifier `test_wrong_opening_fails` (vendored circuit
  crate) rejects a wrong `K`.
- **Rule 26 pre-flight** measured before the first production commit
  (census companion §8) and the cost table in §6.3 corrected to the
  measured figures.
- Everything §6.2 specifies is implemented: `k` and the record on cSHAKE256
  under registered customizations (Tier B), the HKDF blinds with the
  exceptional-value guard, the two NUMS generators pinned, the 64-byte
  `0x07` entry with the point-admission rule at relay and connect (Rust rule
  + C++ adapter passing the payload), `K` derived by every verifier and
  never on the wire, the circuit's opening leg, scan-time verification of
  both halves of the published entry against the recipient's own derivation
  (`shekyl-scanner` compares `CM ‖ record` with `derive_pqc_leaf`'s entry; a
  mismatch or a missing entry is classified received-but-unspendable on the
  persisted row — `TransferDetails::unspendable`, `LEDGER_BLOCK_VERSION 11`
  — retained in the ledger, excluded from coin selection and `unlocked`,
  surfaced as the wallet-RPC state `UNSPENDABLE` with `unspendable_reason`
  and the sender's `tx_hash`, and totalled in `get_balance.unspendable`;
  the persona funding extractor skips such an output rather than counting
  it as bond funding, warning loudly but anonymously — the log line names
  no slot, transaction, or index, because any sender can mint the trigger
  and log sinks travel beyond the custody boundary; the ledger row and
  RPC carry the specifics (the D-A1 / rule-82 reconciliation, pinned by
  `unspendable_warn_is_loud_but_names_no_persona_or_tx`) —
  `pscan/scan_step.rs`; census `d-14`, rule 82; this reconciliation and
  the sign-input JSON key rename (`h_pqc` → `cm_x` at both producers, no
  serde alias) ratified by Rick, 2026-09-14) with the signer-side refusal kept as defence in
  depth (`TxBuilderError::PqcLeafMismatch`, FFI −32), the emission vin without
  `pqc_pk_hash` (ruling 9), census `d-3`/`d-4` (no zero fallback anywhere),
  `d-1` (fuzz targets rebuilt and compiling), `d-2` (`hp_of_O` left the
  signing JSON contract with the aliasing), `d-11` (test comments
  rewritten), `d-12` (`PqcKeyPointInvalid` /
  `PqcKeyCountMismatch` split), A5-12 (the discrete-log soundness
  assumption stated in both vendored crate docs).
- Every §9 S1 vector regenerated under the decision-log citation; LMDB
  `VERSION 14` and the wallet curve-tree store `SCHEMA_VERSION 5`.
- Open by design: A5-1…A5-7 (gate-6 owner, ruling 4, now that the premise
  is restored), `PL-D4` (`Target: V4`), the fuzz-crate CI gap (FOLLOWUPS).

## 13. What this round did not find (denominator, rule 26)

Examined and clean: `docs/design/FCMP_SPEND_SIGNING_PREIMAGE.md` (no
anonymity claim); the signing preimage itself (`tx_pqc_verify.cpp:58–152`) —
the Keccak binding of all inputs' key hashes is a substitution defence and
adds no *new* linkage beyond `PL-D1`; the KEM ciphertext field `0x06` (per
output, but keyed to the recipient's address, not revealed at spend — not a
linkage channel); persona identity keys (`hybrid_bond_id` — public by design,
no leaf, never spent, out of scope by brief §7 and verified so at
`verifier.rs:331`); shard holdings (public by design).

**Found and left open — the sender residual.** The party that created an
output holds `combined_ss` for it and therefore derives its `pk`, `r` and
`r_h` exactly as the recipient does. `PL-D3` hides the spend from every
observer **except the output's creator**, who can recognise it (and, for a
change output, that is the spender's own wallet, which is harmless; for a
payment it is the payer). This is structural to sender-derived per-output
keys, not to the commitment, and it is not this round's to fix.
**Reopener:** a post-quantum signature scheme with recipient-side key
derivation (the recipient contributes entropy the sender never sees), or a
recipient-contributed key-custody round; either is a `PL-D4`-class round
of its own. **Not examined:** the wallet-side scan/store of the leaf value
for *timing* side channels (which output a wallet re-derives when) — named
for the next round's scope, not claimed clean.
