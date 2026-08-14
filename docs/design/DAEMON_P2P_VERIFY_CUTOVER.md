# Daemon P2P / block-connect verify cutover

**Status:** ROUND 1 — drafted 2026-08-14. Thesis accepted from source
review at `c84af21` (PR #460 merge) and re-verified against `origin/dev`
`7a2d2a7a9` (PR #465 merge): the verify-path files are a 0-line diff.
Findings F-1–F-9 recorded. Sequence DPV-1…DPV-8 + DPV-H is the work
order. **No implementation commits until Round 1 closes.** DPV-3 and
DPV-4 are subsequent design rounds that accrete in this document;
DPV-5–DPV-8 do not start until those rounds close. DPV-1, DPV-2, and
DPV-H may open after Round-1 closure without waiting for DPV-3/DPV-4.

**Process rule:**
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
(FFI-boundary-moving, consensus-adjacent: the P2P and block-connect
paths share admission logic with the RPC submit battery; routing half
the kinds onto a new battery is a consensus fork). Cited explicitly, as
that rule requires.

**Spec-first per**
[`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc):
this document freezes the cutover contract — what runs, what stays
C++, how the embargo skip crosses the shim, how the two batteries
become one — **before** any implementation PR lands.

**Timeframes (rule 05):** *now* — RPC submit is already a closed
in-process Rust path; P2P still orchestrates the same crates through
fine `shekyl_*` FFI. *Mining-era end* — the battery is
fee-market-neutral and carries no reward-era assumptions. *V4
lattice-only* — `DaemonTxVerifier` dispatches on kind and proof
system; a lattice membership successor replaces the FCMP++ arm, it
does not reopen the dispatch seam.

**Identifier family:** `DPV-*` (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth, rule
94). Findings F-1…F-9 are this document's review findings (the
doc-scoped `F-N` family). They are not `F-W*` and not
`DAEMON_SUBMIT_VERDICT.md`'s F1–F41.

**Audit pin:** `origin/dev` `7a2d2a7a9`. Line citations below are
against that commit. Re-verify at pre-flight (rule 26 B6).

**Parent deferral this document reopens:**
[`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §9.4 KEEP-P2P
(`tx_verification_context` and the P2P `add_tx` path including
`ver_non_input_consensus` + `check_tx_inputs` — "unchanged"). That
KEEP is the starting disposition, not a refusal-forever.

---

## 0. Problem statement (verified at source)

RPC transaction submit is a closed in-process Rust path:
`shekyl-wire` parse (byte-canonical) + `DaemonTxVerifier` calling
`shekyl-fcmp`, `shekyl-ct-balance`, `shekyl-bulletproofs`,
`shekyl-crypto-pq`, `shekyl-archival-retention` with **no FFI hop**
(`rust/shekyl-daemon-rpc/src/submit/verifier.rs`). C++ on that path
is fact-gather (`SubmitStateShim`, `facts.rs:6-13`) plus pool insert
and relay.

P2P and block-connect still parse with epee
(`cryptonote_core.cpp:747`) and then orchestrate the same crates via
fine `shekyl_*` FFI inside `Blockchain::check_tx_inputs`
(`blockchain.cpp:3530`, 77 `shekyl_` lines in the file). The two
paths are two batteries of the same proofs. Every serialization-shape
change has to be applied twice; the PQC payload assembly already is
(`FOLLOWUPS.md` "Daemon PQC phase-1 payload assembly duplicates
`shekyl_wire::Transaction::pqc_signing_payload_hashes`").

This is not a store rewrite and not a p2p-stack rewrite. It is the
opportunistic boundary-advancement
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
names: new consensus logic belongs in a `shekyl_*` entry point, C++
stays a marshaling shim. The RPC submit cutover already built the
entry point. P2P has not been pointed at it.

**The fix at one sentence:** P2P / block-connect transaction
verification runs `DaemonTxVerifier` over `SubmitStateShim` facts;
C++ remains fact-gather, pool insert, and relay; dual-parse plus
txid-equality stays because C++ still needs the object for
insert/relay.

---

## 1. Thesis (Round 1, accepted)

| Claim | Disposition |
| --- | --- |
| P2P / block-connect is the right next daemon Rust-forward cut | **Accepted.** Highest FFI density that is not a planned migration (DRS, LV-3). |
| C++ stays fact-gather (`SubmitStateShim`), pool insert, relay | **Accepted.** The shim is the named reversion boundary (rule 21). |
| Rule 07 does not apply to the dispatch swap | **Accepted.** Step DPV-8 is a behavior-preserving refactor; criterion 1 excludes that class. See §6. |
| Header PoW + difficulty coarse FFI is the cleaner first dual-parser proof | **Accepted as DPV-H (parallel).** No embargo coupling. Not a substitute for DPV-1…DPV-8. |

---

## 2. Explicitly not this cut

These are named so a later round cannot absorb them as "while we're
here" (`15-deletion-and-debt.mdc`).

| Track | Why not |
| --- | --- |
| **DRS-E\*** (`DAEMON_REDB_STORE.md`) | Store swap. Own design rounds, own PR. This cut does not touch `m_db`. |
| **LV-2 / LV-3** (Levin payload codec + connection-path) | Framing emit is now live (#465); `BucketReader` and portable_storage are not. LV-2 still gates LV-3. FOLLOWUPS "Levin p2p migration" is the deferral record. |
| **Curve-tree grow** | Intentional math/storage split. The verifier consumes a root; it does not grow the tree. |
| **Rust relay reactor** | RP-3 already made `levin_notify.cpp` a transport shim over `shekyl-relay`. A reactor is a different PR. |
| **Wallet FFI / `wallet2`** | Phase 5 deletes `wallet2`. Two of three `get_transaction_signed_payload` production callers die with it; DPV-1 does not wait for that deletion and does not perform it. |
| **`shekyl-consensus` pluggable proofs** | Rule 70: no speculative consensus scaffolding. Kind-dispatch in `DaemonTxVerifier` is enough. |
| **Relaxing submit Phase A to admit coinbase** | F-3 / DPV-6. Two rule-19 surfaces. |
| **Deleting `PER_BLOCK_CHECKPOINT` because the `.dat` files are empty** | F-5 / DPV-2. `DAEMON_RELAY_PRIVACY.md` §74.2 names the wrap as the inherited IBD skip; shipping hashes is an unmade decision. |

---

## 3. Substrate inventory (rule 26 A2)

Read at pin `7a2d2a7a9`. A table without citations is a claim that no
audit happened.

### 3.1 The two batteries

| Surface | Site | Notes |
| --- | --- | --- |
| RPC submit engine | `rust/shekyl-daemon-rpc/src/submit/{phase_a,verifier,facts,verify}.rs` | Closed Rust path. Check order in `verifier.rs:19-23` already mirrors C++: NIC battery first (O6, N8), then `check_tx_inputs` (K12, K13). |
| `SubmitStateShim` | `facts.rs:264` | Named reversion boundary. Facts are plain data; the engine decides. |
| `SubmitFacts` | `facts.rs:146-222` | Identity, KI conflicts, reference (height/root/depth), fee floor, weight limit, chain count, bond/emission probes. **No cache-hit / `fcmp_verified` field.** |
| P2P parse | `cryptonote_core.cpp:729` `handle_incoming_tx` (singular); parse at `:747` | `handle_incoming_txs` does not exist (F-8). A second parse site at `:1154` is the batch blob path. |
| Pool NIC | `tx_pool.cpp:187` | `ver_non_input_consensus(tx, tvc, version)` unless `nic_verified_hf_version` matches. |
| Block-connect NIC | `blockchain.cpp:2340`, `:5845` | Batched `pool_supplement` overload. |
| `ver_non_input_consensus` | `tx_verification_utils.cpp:49` templated body; `:259` single-tx; `:265` `pool_supplement` | Header contract `:100` Rule 7 is `ver_mixed_rct_semantics` (batch CT + BP+). |
| `check_tx_inputs` | `blockchain.cpp:3530` | `skip_fcmp_verify` parameter. Dead `hf_version` local at `:3540`. |
| Embargo skip | `blockchain.cpp:6018-6039` | `can_skip_fcmp = found_tx_in_pool && is_rct_fcmp_pp_pqc`. Comment is load-bearing: hop includes verification; only pool admission pays it. |
| Skip consumption | `blockchain.cpp:3888`, `:4198`, `:4321` | Three `skip_fcmp_verify` tests inside the three FCMP arms. |
| `kept_by_block` early-return | `blockchain.cpp:3336-3343` | Compiled in (`CMakeLists.txt:470-473`). Fires only if `m_blocks_hash_check` is populated **and** `kept_by_block`. |
| Checkpoint blobs | `src/blocks/{checkpoints,stagenet_blocks,testnet_blocks}.dat` | **0 bytes** at pin. `m_blocks_hash_check` stays empty; neither skip fires today. |
| PQC payload twin | `tx_pqc_verify.cpp:62` vs `shekyl-wire/src/transaction.rs` `pqc_signing_payload_hashes` | Production callers: `tx_pqc_verify.cpp:223`, `wallet2.cpp:9046`, `wallet2_ffi.cpp:3880`. Test: `tests/unit_tests/fcmp.cpp:716`. |
| `BlockHeader` | `shekyl-wire/src/block.rs:52` | Exists. DPV-H consumes it. |
| `origin_zone` packing | `blockchain_db.h:215-253` | Bit-packed next to `fcmp_verified`. Shifting bits makes `fcmp_verified` read 1 where 0 was written. Q12-U3 (#461) rolls the origination zone in `daemon_submit_ffi` relay — **not a verify fact**. |

### 3.2 The triplication inside `check_tx_inputs` (F-7)

The same orchestration
`block_exists → get_curve_tree_root_at_height → get_curve_tree_depth →
fcmp_pqc_leaf_hash loop → fcmp_verify` appears three times:

| Arm | Lines |
| --- | --- |
| Bond / serve-credit | `blockchain.cpp:3833-3891` |
| Emission | `:3982-4128` |
| Regular spend | `:4228-4329` |

The 77-count in the file is the density argument's *symptom*. The
collapse case is this triplication. `DaemonTxVerifier` already has
kind-dispatch; pointing P2P at it deletes the three copies rather
than adding a fourth.

### 3.3 Named rule-21 reopens already in the engine

| Refusal | Site | Reopening criterion (already written) |
| --- | --- | --- |
| Serve-credit dies at the Phase-C fee floor (SP-T4a) | `verifier.rs:48-54`, `:141-150` | SP-T4a fee-floor resolution lands; extend `SubmitFacts` with SC-row archival facts; implement SC1–SC8. |
| Non-JoinMarket bond-posts `Malformed` | `verifier.rs:55-65`, `:246-254` | Wallet construction leg for a non-JM kind, **or** §8.7.1 grows rows; extend `SubmitFacts` with that kind's fact set and Phase-D re-check. |

DPV-5 is those reopens, not a new flag on `parse_submission`.

### 3.4 Coinbase is a gate inversion (F-3)

Phase A refuses coinbase three times: `phase_a.rs:199-201`
(`tx.is_coinbase()`), `:232-238` (`Input::Gen` in a non-coinbase
submission), `:256-265` (Null ct on a non-coinbase submission). C++
inverts the last at `blockchain.cpp:3716-3717` (`CTTypeNull` is not
allowed for *non-coinbase*). "No coinbase may be submitted" and
"this coinbase must validate" are independent validation surfaces
(rule 19). Relaxing Phase A lets a block-path test mask a
submit-path hole.

---

## 4. Findings (Round 1 source review)

Severity-ordered. F-1 and F-2 are load-bearing omissions from the
first draft of this cut. F-5 and F-9 were amended after the
`c84af21`→`7a2d2a7a9` delta (sequence unchanged).

| ID | Sev | Claim | Pin |
| --- | --- | --- | --- |
| **F-1** | Critical | Plan omitted the embargo skip. `hop` (`DAEMON_RELAY_PRIVACY.md` §71) is receive-to-forward **including verification**, paid only on **pool admission**. `SubmitFacts` has no cache-hit field. Seeding is C++ pool state (`txd.fcmp_verified`, `m_input_cache`, O(1) ref-window re-derivation at `tx_pool.cpp:1691-1725`). A dispatch swap that drops the skip invalidates the 190 s embargo at `F′ = 3250 ms`. A swap that silently keeps a C++ cache adjudicating whether the Rust battery runs hides a privacy parameter inside a throughput flag. | `blockchain.cpp:6018-6039`; `facts.rs:146-222` |
| **F-2** | Critical | `check_tx_inputs` is half the P2P battery. `ver_non_input_consensus` is the other: blob size, version, weight, `check_tx_semantic`, `check_tx_outputs`, archival taxonomy, and Rule 7 `ver_mixed_rct_semantics` → `verRctSemanticsSimple` (CT balance + BP+ = `DaemonTxVerifier` N8). Called from the pool and from both block-connect sites via batched `pool_supplement`. §9.4 names both. Swapping only `check_tx_inputs` leaves two batteries agreeing forever — the dual-impl DPV-1 exists to kill. The batch shape is the IBD/BP+ reason this might stay C++ permanently; that is a decision, not a default. | `tx_verification_utils.cpp:49`, `:212-256`; `tx_pool.cpp:187`; `blockchain.cpp:2340`, `:5845`; §9.4 |
| **F-3** | High | Coinbase is a gate inversion, not a missing arm. See §3.4. | `phase_a.rs:199-265`; `blockchain.cpp:3716-3717` |
| **F-4** | High | DPV-1 is not small and not a deletion. FOLLOWUPS already names a consensus-verification migration with its own design round and byte-parity KATs before the C++ copy is deleted. The FFI entry is the cut; C++ becomes a marshaling shim; deletion follows independently (two of three production callers die with Phase 5). | FOLLOWUPS "Daemon PQC phase-1 payload assembly"; callers in §3.1 |
| **F-5** | Medium | Dead `hf_version` at `blockchain.cpp:3540`: delete. `PER_BLOCK_CHECKPOINT` skip is compiled in; `.dat` files are 0-byte so it cannot fire **today**. Do **not** bundle deleting the `fast_check` wrap (`:5771` / `:6018`) into the rule-15 sweep — §74.2 names it the inherited IBD skip and shipping hashes as an unmade decision. | `blockchain.cpp:3336-3343`, `:3540`, `:6018`; `CMakeLists.txt:470`; `src/blocks/*.dat`; `DAEMON_RELAY_PRIVACY.md` §74.2 |
| **F-6** | Medium | "One parser for consensus" is not reachable. `handle_incoming_tx` parses at `:747` before downstream. Realistic outcome: dual-parse + txid-equality gate, same as submit §3.4. | `cryptonote_core.cpp:747` |
| **F-7** | Medium | Collapse case is triplication, not the 77-count. See §3.2. | `blockchain.cpp:3833-3891`, `:3982-4128`, `:4228-4329` |
| **F-8** | Low | `handle_incoming_txs` does not exist. Singular `handle_incoming_tx`. Doc drift inherited from §9.4. | `cryptonote_core.h:129` / `.cpp:729` |
| **F-9** | Low | Levin: LV-1 + compression (2026-08-06) + white-noise emit (#465, 2026-08-13) live. `BucketReader` and plain builders still inert. LV-2 (portable_storage) not started; LV-3 still gates on it. Still not this cut. | `IMPLEMENTATION_INDEX.md` LV row UPDATE 2026-08-13; `shekyl-levin/src/lib.rs` wiring status 2026-08-13 |

### 4.1 `c84af21` → `7a2d2a7a9` delta (sequence unchanged)

| PR | What landed | Plan impact |
| --- | --- | --- |
| #461 Q12-U3 | Anonymity zone chosen once at origination, in `daemon_submit_ffi` relay | Not a verify fact. DPV-3 must not shift `origin_zone` bits next to `fcmp_verified` (`blockchain_db.h:215-217`; `Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`). A missed pool nudge / `on_relay_tx` is a named FOLLOWUPS "second chooser" — relay inheritance, not dispatch. |
| #462 Q12-D9 | Floor-is-a-self-condition | No hop / embargo / skip coupling. |
| #464 SH-2b | Wallet serving-host lifecycle | Out of scope. |
| #465 Levin emit | White-noise / fragment emit now Rust | F-9 status only. |

Verify-path files (`blockchain.cpp`, `check_tx_inputs`,
`ver_non_input_consensus`, `DaemonTxVerifier`, `tx_pqc_verify`) are
byte-identical across the range.

---

## 5. Sequence

Work-item tokens are `DPV-N`. Do not write a bare `3` whose scheme
the reader must infer (rule 94).

### DPV-1 — PQC payload FFI entry + byte-parity KATs

**Blocking:** nothing. Parallel with DPV-H.

**Why this order.** FOLLOWUPS already names this a
consensus-verification migration. Three production consumers plus
`tests/unit_tests/fcmp.cpp`. The FFI entry is the cut; the C++ copy
becomes a marshaling shim; deletion follows independently.

**Explicitly not.** Not a ride-along deletion. Not "small." The KAT
PR retargets `fcmp.cpp` at the FFI entry.

**Gate.** Byte-parity KATs between C++ assembly and the Rust entry
point **before** the C++ copy is deleted (FOLLOWUPS, unchanged).

### DPV-2 — Rule-15 sweep on the P2P verify path

**Blocking:** separate commit, bisect-clean, before any fact-schema
work.

**Why this order.** `hf_version` at `blockchain.cpp:3540` is unused
in the remaining body of `check_tx_inputs`; the Rust engine has zero
hardfork awareness — do not add it to `SubmitFacts`. Split the rest:
the `:3336-3343` `kept_by_block` early-return is the same family as
the `:6018` `fast_check` wrap. `.dat` files are 0-byte so neither
fires today, but §74.2 treats the wrap as the inherited IBD skip.

**This commit deletes** the dead `hf_version` local.

**This commit does not delete** the checkpoint fast path. That is a
shipping-decision PR against §74.2, recorded as a named non-goal
(§2), not as P2P-verify debris.

**Explicitly not.** Not plumbing `hf_version` into `SubmitFacts`.
Not silently deleting `PER_BLOCK_CHECKPOINT` because the `.dat`
files are empty.

### DPV-3 — Embargo-fact design round

**Blocking:** blocks DPV-5–DPV-8. **This is a design round, not a
code commit.** It accretes in this document as Round 2.

**The question.** How does `fcmp_verified` (and the rest of the
pool-admission cache: `m_input_cache`, O(1) ref-window
re-derivation) cross `SubmitStateShim` without moving the cache into
the engine and without leaving a C++ boolean that decides whether
the Rust battery runs?

**Rule-21 reopen that would skip the round.** Unnecessary if §72.1
is re-derived and the block path is measured to pay full
verification without moving the 190 s embargo. That is a
measurement, not a preference. Re-evaluation shape: a Round-2
section in this document naming the measured hop, the new embargo,
and the `DAEMON_RELAY_PRIVACY.md` amendment that records it.

**Constraints the round cannot violate.**

1. Hop remains receive-to-forward including verification unless
   §72.1 is explicitly re-derived.
2. The cache stays C++ pool state until a named later store
   migration (DRS is not this cut).
3. A cache-hit field on `SubmitFacts`, if one is added, is a *fact
   the engine interprets*, not a *flag that skips the engine*.
4. `origin_zone` is bit-packed next to `fcmp_verified`. A layout
   change that shifts those bits is a consensus-adjacent persistence
   bug (`blockchain_db.h:215-217`). Q12-U3's origination roll is a
   **relay** fact; it is not added to `SubmitFacts`.
5. Not a throughput footnote.

### DPV-4 — `ver_non_input_consensus` disposition

**Blocking:** answer before, not during, the shadow phase. **This is
a design round (Round 3), not a default.**

**The question.** Fold NIC into `DaemonTxVerifier`, or does the
batched `pool_supplement` overload stay C++ permanently for IBD/BP+
batching?

**Why it cannot wait.** `verifier.rs:19-23` already claims to mirror
NIC then `check_tx_inputs`. The overlapping crypto is Rule 7 /
N8 (CT balance + BP+). Swapping only `check_tx_inputs` leaves two
batteries. DPV-1 exists to kill dual-impls; leaving NIC as a second
battery reintroduces the class of bug DPV-1 closes.

**Candidates (not yet dispositioned).**

| Option | Shape | Cost |
| --- | --- | --- |
| Fold | `DaemonTxVerifier` grows the NIC checks it does not already run (blob size, version, weight, semantic, outputs, archival taxonomy). Batch BP+ becomes a verifier entry that takes a slice. | One battery. IBD batching has to be re-expressed in Rust. |
| Keep C++ for batch | Single-tx NIC folds; `pool_supplement` stays C++ as the IBD batch. Shadow-parity covers both overloads. | Two batteries on the batch path only. Dual-impl residue on N8 for IBD. |

Round 3 picks one, with a reversion clause.

**Explicitly not.** Not "`DaemonTxVerifier` already covers this." It
does not. N8 overlap is not the whole NIC contract
(`tx_verification_utils.h:100`).

### DPV-5 — Serve-credit + non-JoinMarket arms on `DaemonTxVerifier`

**Blocking:** existing rule-21 criteria in `verifier.rs:51` and
`:64-65`. DPV-3/DPV-4 closed.

**Why this order.** P2P must accept both kinds. These are the named
reopens; they land as arms, not as Phase-A relaxations.

**Explicitly not.** Not a flag on `parse_submission`.

### DPV-6 — Coinbase as a distinct entry point

**Blocking:** independent of submit Phase A (rule 19). DPV-3/DPV-4
closed.

**Why this order.** See F-3 / §3.4. A block-connect coinbase
verifier is a new function with its own facts (height, miner
outputs, Null ct). It does not share `parse_submission`.

**Explicitly not.** Not a missing arm of `DaemonTxVerifier`. Not a
`SubmitTxKind::Coinbase` on the RPC engine.

### DPV-7 — Shadow-parity on the P2P path

**Blocking:** gated on DPV-3–DPV-6 having dispositions. C++ verdict
stays authoritative.

**Named pre-flight (rule 26 halt).** DPV-7 names a pre-flight pass
between design closure of DPV-3–DPV-6 and the first shadow
implementation commit. The pass re-reads the cited substrate at the
then-`dev` tip and records R0-D# findings in this document. **No
shadow implementation commit lands while that pass is
undischarged.**

**Shape.** Run `DaemonTxVerifier` alongside `check_tx_inputs` (and
alongside NIC, per the DPV-4 disposition). Log and count
divergences. Both flag states produce identical consensus output —
a criterion-2 **non-consensus routing flag**, legal under rule 06
and splittable. Converts F-1/F-2/F-3 from design arguments into
measurements.

**The named block count** that gates DPV-8 is a DPV-7 pre-flight
output (rule 26 B9: do not write the number from intuition). Record
it in this document when measured.

**Explicitly not.** Not the cutover. Not "Rust authoritative behind
a flag."

### DPV-8 — Dispatch swap

**Blocking:** zero divergences over the named block count from
DPV-7.

**Why this order.** One-line change against a divergence count you
can point at. C++ remains fact-gather (`SubmitStateShim`), pool
insert, and relay. Dual-parse plus txid-equality stays —
`handle_incoming_tx` still parses at `cryptonote_core.cpp:747`
because C++ still needs the object for insert/relay. Same shape
submit already runs (`DAEMON_SUBMIT_VERDICT.md` §3.4).

**Rule 07.** Does not apply (criterion 1: behavior-preserving
internal refactor). See §6.

**Explicitly not.** Not "one parser for consensus" (F-6). Not
`handle_incoming_txs` (F-8).

### DPV-H — Header PoW + difficulty coarse FFI (parallel)

**Blocking:** none of DPV-1–DPV-8. Cleaner first dual-parser proof:
no embargo coupling.

**Why parallel.** RandomX v2 and LWMA-1 already live in Rust;
`shekyl-wire` already has `BlockHeader` (`block.rs:52`). C++
gathers seedhash and the difficulty window. A
`shekyl_block_header_check(header_blob, seedhash, window)` is the
dual-parser pattern without F-1. Better *first proof of the
pattern* than P2P verify, which carries the embargo.

**Explicitly not.** Not a substitute for DPV-1…DPV-8. Not coupled
to hop.

---

## 6. Why shadow-parity, not a dispatch flag

**Rule 07 does not apply.** DPV-8 is an internal refactor that
preserves consensus behavior. `07-consensus-atomic-cutovers.mdc`
criterion 1 excludes that class. Splitting guidance stays rule 06
(5-day / 10-commit).

**A single dispatch swap cannot split under rule 06.** Routing half
the transaction kinds to a new battery is a consensus fork: two
honest nodes, one on each side of a split PR, reach different
conclusions about the same block.

**The legal split.** Shadow-run `DaemonTxVerifier` alongside
`check_tx_inputs`. C++ verdict authoritative. Divergences logged
and counted. Both flag states produce identical consensus output —
a criterion-2 non-consensus routing flag, splittable. The swap is
then one line against a named block-count of zero divergences.

---

## 7. Open design rounds (after Round 1 closes)

Round 1 freezes the thesis, the findings, the sequence, and the
non-goals. It does **not** freeze the embargo-fact shape or the NIC
disposition. Those are:

| Round | Token | Closes | Implementation gated |
| --- | --- | --- | --- |
| 1 (this draft) | — | Thesis, F-1–F-9, sequence, non-goals, rule 06/07 | DPV-1, DPV-2, DPV-H after closure |
| 2 | DPV-3 | How `fcmp_verified` crosses the shim, or §72.1 re-derived | DPV-5–DPV-8 |
| 3 | DPV-4 | Fold NIC vs keep-C++-for-batch | DPV-5–DPV-8 |
| DPV-7 pre-flight | — | Substrate re-check + named block count (B6/B9) | DPV-7 implementation |
| Late (A3) | — | Threat-model addenda against 3–6 attacker objectives | Before DPV-8 |

Round 2 and Round 3 may run concurrently. They accrete in this
document; they are not new files.

### 7.1 Round-1 closure criteria

Round 1 closes when a reviewer confirms, against the audit pin (or
a named newer `dev` tip with a 0-line verify-path delta recorded
here):

1. The thesis in §1 is the work this track will do.
2. The non-goals in §2 are the work this track will not do.
3. F-1–F-9 are accepted as stated, including the F-5 split and the
   F-9 Levin status.
4. DPV-1…DPV-8 + DPV-H is the work order.
5. Rule 07 is not invoked.
6. `DPV-*` is registered in the index.

Closure is a status-block edit in this document (decision-anchored,
rule 94), not an implementation commit.

---

## 8. Threat-model sketch (Round 1)

Full A3 (3–6 named attacker objectives, absorb / discipline /
forward-action) is a late round, before DPV-8. Round 1 records the
wargame that made F-1–F-4 load-bearing, so a later round cannot
treat them as folklore.

| Adversary | Vector | Defense today | Armed if DPV-8 lands without this sequence? |
| --- | --- | --- | --- |
| Embargo-narrowing observer | Block-path verify time enters hop, shrinking the fluff-timing gap | `can_skip_fcmp` (`:6035`) | Yes — no fact carries the skip (F-1) |
| Verdict-divergence splitter | Crafts a tx the two remaining batteries classify differently | Single C++ battery | Yes — F-2 leaves two |
| Coinbase-shaped submitter | Probes a relaxed Phase-A gate over RPC | `phase_a.rs:199` hard reject | Yes, if the gate is relaxed rather than bypassed (F-3) |
| Preimage-drift attacker | Exploits C++/Rust PQC payload divergence | End-to-end spend tests only | Already latent; DPV-1 closes it if KATs land first (F-4) |

---

## 9. Test obligations

1. **DPV-1.** Byte-parity KATs: C++ `get_transaction_signed_payload`
   vs the new `shekyl_*` entry vs
   `shekyl_wire::Transaction::pqc_signing_payload_hashes`, for every
   production kind the function currently hashes (regular spend,
   bond-post, emission; serve-credit has no PQC auths). `fcmp.cpp`
   retargeted at the FFI entry in the same PR.
2. **DPV-2.** The dead-local deletion compiles; `check_tx_inputs`
   body does not mention `hf_version`. Negative control: a grep CI
   line, or a comment at the deletion site pointing at this
   document, so a later edit cannot reintroduce it as "the C++ still
   has a version."
3. **DPV-7.** Divergence counter. Every disagreement is a logged
   `(txid, cpp_tvc_flags, rust_verdict)` row. The named block count
   is a pre-flight output. Shadow must cover pool admission **and**
   block-connect, including the `can_skip_fcmp` true and false
   cases, or F-1 is unmeasured.
4. **DPV-8.** The swap PR's reviewer-map is the shadow counter at
   zero over that count, plus a grep that `check_tx_inputs`'s
   `shekyl_fcmp_verify` call sites are gone (or are shims).
5. **DPV-H.** Header-blob KAT against RandomX v2 + LWMA-1 on a
   pinned header; C++ gather of seedhash and window is in the test
   fixture so the FFI is the only moving part.
6. **DPV-6.** Coinbase vectors do not enter `parse_submission`. A
   test that a coinbase blob submitted over RPC is still
   `Malformed` / Phase-A reject after DPV-6 lands.

---

## 10. Related documents

| Doc | Relationship |
| --- | --- |
| [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) | Parent. §9.4 KEEP-P2P is the deferral this track reopens. §3.4 dual-parse + txid-equality is the parse shape DPV-8 keeps. |
| [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) | §71 hop definition; §72.1 embargo derivation; §74.2 IBD checkpoint skip. DPV-3 is not allowed to silently invalidate these. |
| [`Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`](Q12_FORWARD_DELAY_AND_ZONE_FIELD.md) | `origin_zone` packing next to `fcmp_verified`. DPV-3 constraint 4. |
| [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) | Not this cut. "P2P and levin remain C++ at genesis" remains true of the *stack*; this track moves *verification* only. |
| [`../FOLLOWUPS.md`](../FOLLOWUPS.md) | PQC payload dual-impl (DPV-1 carrier); Levin LV-2/LV-3 deferral; Q12-U3 second chooser (not dispatch). |
| [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) | `DPV-*` registry row. |

---

## 11. Round-1 decision record

Empty until Round 1 closes. Subsequent rounds append.

| ID | Decision | Status |
| --- | --- | --- |
| R1-D1 | Thesis: P2P/block-connect verify → `DaemonTxVerifier`; C++ fact-gather | Drafted, awaiting closure |
| R1-D2 | Rule 07 does not apply; shadow-parity is the rule-06 split | Drafted |
| R1-D3 | DPV-H parallel; not a substitute | Drafted |
| R1-D4 | F-5 splits: delete dead `hf_version`; do not delete `PER_BLOCK_CHECKPOINT` in this track | Drafted |
| R1-D5 | F-3: coinbase is a distinct entry point, not a Phase-A relaxation | Drafted |
| R1-D6 | DPV-3 and DPV-4 are design rounds that gate DPV-5–DPV-8 | Drafted |
