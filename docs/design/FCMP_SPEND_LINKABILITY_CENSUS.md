# PL — blast-radius census of the curve-tree leaf's 4th scalar (`h_pqc`)

**Status:** RECORD — the rule-07 criterion-3 enumeration for the `PL-` round
([`FCMP_SPEND_LINKABILITY.md`](FCMP_SPEND_LINKABILITY.md) §9), produced
2026-09-13 at `dev` = `42333d34f`. Every `file:line` is a *records-was* claim
at that sha: read at source, not inferred from a grep line. An implementation
PR re-runs the sweep against its own `Base commit` and pastes the delta; this
file is not re-anchored in place. Companion to the round document, in the
rule-26 sibling-audit-trail shape.
**Identifier family:** `PL-` (registered in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2).
**Owner:** the `PL-` round; findings in §6 are dispositioned in the round
document's §9, not here.

---


Grounded at `shekyl-core` `dev` @ `42333d34f` (2026-09-13). Read-only; every
`file:line` below was read at that sha, not inferred from a grep line.

## 0. What the 4th scalar is today (verified at source)

- **Derivation.** `h_pqc = wide_reduce_Selene(Blake2b-512("shekyl-pqc-leaf" ‖ pk))`
  where `pk` is the **full canonical `HybridPublicKey`** (`version ‖ scheme=1 ‖
  reserved ‖ ed_len ‖ ed25519[32] ‖ ml_dsa[1952]`, `rust/shekyl-crypto-pq/src/signature.rs:139-162`), not the
  ML-DSA key alone — `rust/shekyl-crypto-pq/src/derivation.rs:66-79`
  (`hash_pqc_public_key`, SSOT); `derive_pqc_leaf_hash` (`:87-113`) derives the
  per-output keypair from `combined_ss` + index and calls it.
- **Creation.** Sender computes it in `construct_output*` (`rust/shekyl-crypto-pq/src/output.rs:394`,
  `compute_hybrid_h_pqc` `:1412-1434`) and publishes it in cleartext in tx_extra tag
  `0x07`, one 32-byte entry per vout (`shekyl-wire tx_extra.rs:44,65,118,232-233,370`).
- **Storage.** Daemon slices the 0x07 blob per output (`src/blockchain_db/blockchain_db.cpp:528-557`)
  and packs it verbatim as bytes `[96..128)` of the 128-byte leaf
  (`shekyl-fcmp tree.rs:506-523`, `rust/shekyl-fcmp/src/leaf.rs:57-82`), which is Pedersen-hashed into
  the Selene leaf layer with 4 scalars/output (`rust/shekyl-fcmp/src/tree.rs:44`, `src/blockchain_db/lmdb/db_lmdb.cpp:9006`).
- **Spend.** Spender reveals `hybrid_public_key` in cleartext in
  `tx.pqc_auths[i]`; consensus recomputes `h_pqc` from it
  (`src/cryptonote_core/blockchain.cpp:4211-4212` via `shekyl_fcmp_pqc_leaf_hash`;
  `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1021-1024` via `PqcLeafScalar::from_pqc_public_key`) and passes it
  to the verifier as a **public input**; the circuit constrains the leaf's 4th
  variable equal to that public constant
  (`rust/shekyl-oxide/crypto/fcmps/src/circuit.rs:153-163`) and then includes it in the
  membership tuple (`:165-168`). The verifier therefore learns, per input, the exact
  `h_pqc` value that was published in some earlier transaction's 0x07 field.
- **Also on the wire in cleartext:** the archival emission vin carries
  `backing.pqc_pk_hash` (`rust/shekyl-archival-retention/src/emission_wire.rs:154,543,617`); the daemon RPC
  `get_curve_tree_path` returned every chunk leaf's `h_pqc` (`fcmp/src/rpc_path.rs:94`,
  `rpc/core_rpc_server.cpp:1560` at `8494f2a27` — **surface removed 2026-09-18, `SOK-10` Q7 → A**; records-was); served archival shards are raw 128-byte leaves
  (`rust/shekyl-curve-tree/src/store/redb_backend.rs:411-420`, `p-serve provider.rs:111-116`).

Column 4 of the table marks each site's role: **PUBLIC-INPUT** (the value crosses
into the verifier as a public scalar), **WITNESS** (prover-side leaf-chunk data),
**WIRE** (serialized on chain/RPC), **STORE** (persisted), **DERIVE** (computes it),
**LAYOUT** (only knows "4 scalars / 128 bytes"), **PROSE** (documents it).

Unit for all counts: a *site* = one function/struct/const/doc-passage group that
reads, writes, computes, serializes, stores, verifies or documents the 4th scalar;
N grep hits inside one function are one site.

---

## 1. Severity-ordered table

### S0 — consensus / wire

| Sev | Layer | file:line | What it does with the 4th scalar | What a leaf-content change breaks |
|---|---|---|---|---|
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/circuit.rs:41-49` | `FcmpCurves::EXTRA_LEAF_SCALARS = 1`, `leaf_tuple_width() = 3 + extras` — declares that exactly one extra scalar exists per leaf. LAYOUT | Any change in scalar *count* (e.g. `(Commit, …)` split into 2 scalars) changes this constant and every proof size; content-only change (still 1 scalar) does not touch it. Pinned by `rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256:29` — editing fires `vendored-crypto-content.yml`. |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/circuit.rs:119-120, 153-168` (`Circuit::first_layer`) | Takes `extra_leaf_vars` (witness) and `extra_leaf_public_values` (public); for each pair emits `constrain_equal_to_zero(var − public)`, then appends the var to the membership tuple `[O.x, I.x, C.x, extra…]`. **PUBLIC-INPUT — this is the constraint that makes `h_pqc` public.** | If the 4th scalar becomes `Commit(h_pqc, r)` and the *commitment* stays the public value, this constraint is unchanged (verifier supplies `Commit`). If the round instead wants the opening proven in-circuit (verifier supplies nothing / a different statement), this gadget is replaced and the whole `fcmps` pin forks. Manifest-gated (`:29`). |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:104-111, 132-144` (`Input.extra_leaf_scalars`, `Input::with_extra_scalars`) | The verifier-side input tuple carries `extra_leaf_scalars: Vec<F>` — the public values. PUBLIC-INPUT | Type of the public value changes with the design; every caller of `with_extra_scalars` (fcmp-proofs `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:326,465`) changes. Manifest `:32`. |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:278-304` (`Fcmp::proof_size`) | Adds `inputs × EXTRA_LEAF_SCALARS` one-element C1 branches to the proof size. LAYOUT | Count change → proof size, and every consumer of `proof_size` (`shekyl-fcmp tree.rs:558`, tx-weight). |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:380-443` (`Fcmp::input` — `:442-443` passes `opening.extra_leaf_vars` / `input.extra_leaf_scalars` to `first_layer`); `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:582-599, 686-689, 782-784` (`Fcmp::prove`: flattens leaves as `[O.x, I.x, C.x, extra…]`, reserves extra blinds, assigns `fcmp_input.extra_leaf_scalars = input.output_extra_scalars`); `rust/shekyl-oxide/crypto/fcmps/src/lib.rs:853-974` (`Fcmp::verify`: `:905-912` builds `input_extra_leaf_vars` from the C1 tape, `:936-965` feeds `first_layer`) | Prove/verify plumbing of the extra scalar as witness + public value. WITNESS / PUBLIC-INPUT | Same as `first_layer`. Manifest `:32`. |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/prover/mod.rs:16-31` (`Path.output_extra_scalars`, `Path.leaves_extra_scalars`), `:91-100` (`InputProofData.output_extra_scalars`), `:131-210` (`Branches::new` — carries/compares extras across paths), `:300-386` (`transcript_branches` — `flatten_leaves` interleaves `[O.x,I.x,C.x,extra]`, allocates `extra_leaf_vars`) | Prover-side path carries the spent output's extra scalar and every chunk sibling's extra scalar. WITNESS | The prover must hold whatever the leaf now contains (e.g. `Commit` for every sibling, not `h_pqc`); if openings `r` are needed for the spent output only, `Path` gains a field. Manifest `:35`. |
| S0 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/tree.rs:11, 40` (`hash_grow`/`hash_trim`, generic over scalar slices) | Leaf-layer Pedersen hash; content-agnostic, count-sensitive via caller. LAYOUT | Unchanged for a 32-byte content swap. Manifest `:38`. |
| S0 | fcmp wrapper | `rust/shekyl-fcmp-proofs/src/lib.rs:71-79` (`impl FcmpCurves for Curves`, `EXTRA_LEAF_SCALARS = 1` at `:78`) | Fixes the extra-scalar count for the production curve set. LAYOUT | Count change. |
| S0 | fcmp wrapper | `rust/shekyl-fcmp-proofs/src/lib.rs:191-205` (`InputVerification { key_image, pqc_pk_hash: Selene::F }`) | Verifier-side per-input bundle carrying the public 4th scalar. PUBLIC-INPUT | Field type/semantics change; name `pqc_pk_hash` becomes wrong. |
| S0 | fcmp wrapper | `rust/shekyl-fcmp-proofs/src/lib.rs:301-333` (`FcmpPlusPlus::verify` — `:326-332` `with_extra_scalars(vec![ctx.pqc_pk_hash])`) | Passes each input's public `h_pqc` into the circuit. PUBLIC-INPUT | Public value semantics. |
| S0 | fcmp wrapper | `rust/shekyl-fcmp-proofs/src/lib.rs:438-472` (`FcmpMembershipOnly::verify(pqc_pk_hashes)` — `:452-453` count check, `:465-471` `with_extra_scalars(vec![h_pqc])`) | Membership-only path (archival emission backing) takes the public `h_pqc` per input. PUBLIC-INPUT | Same. |
| S0 | leaf format | `rust/shekyl-fcmp/src/leaf.rs:16-18` (`PqcLeafScalar([u8;32])`) | The newtype for the 4th scalar. LAYOUT | Name/semantics; every `PqcLeafScalar(...)` constructor (≈40 sites listed in S2/S5) follows. |
| S0 | leaf format | `rust/shekyl-fcmp/src/leaf.rs:29-33` (`PqcLeafScalar::from_pqc_public_key`) | Forwards to `hash_pqc_public_key`. DERIVE | Becomes wrong/insufficient if the leaf holds a commitment (needs `r`). Used by consensus at `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1023`. |
| S0 | leaf format | `rust/shekyl-fcmp/src/leaf.rs:36-50` (`ShekylLeaf { o_x, i_x, c_x, h_pqc }`), `:54` (`SIZE = 128`), `:57-64` (`to_bytes` puts `h_pqc` at `[96..128]`), `:67-82` (`from_bytes`) | Canonical 128-byte leaf layout, 4th scalar at byte offset 96. LAYOUT/STORE | Offset/width fixed; content change is transparent here unless width changes. |
| S0 | leaf format | `rust/shekyl-fcmp/src/tree.rs:43-44` (`SCALARS_PER_LEAF = 4`), `:53` (`LEAF_CHUNK_SCALARS`) | Leaf width constants consumed by daemon/wallet/archival. LAYOUT | Count change only. |
| S0 | leaf format | `rust/shekyl-fcmp/src/tree.rs:490-523` (`construct_leaf(output_key, commitment, h_pqc) -> Option<[u8;128]>`; `:522` copies `h_pqc` verbatim to `[96..128]`; doc `:504-505` still says "pass `&[0u8;32]` for outputs that have no PQC key commitment") | The ONE leaf constructor shared by daemon (via FFI) and wallet. STORE | Signature/doc; any change to what the 4th field *is* lands here first. Doc is stale (zero no longer admissible, CEN-I19). |
| S0 | leaf format | `rust/shekyl-fcmp/src/tree.rs:548-556` (`leaves_to_bytes`) | Serializes `ShekylLeaf`s for LMDB. STORE | Transparent for 32-byte content. |
| S0 | leaf format — **SURFACE REMOVED 2026-09-18** (`SOK-10` Q7 → A) | records-was at `8494f2a27`: `fcmp/src/rpc_path.rs:24-25` (`LEAF_BYTES = 128`), `:53-56` (layout doc), `:72-94` (`append_layer0` — `:94` copied `leaf[96..128]` into `chunk_outputs` served over RPC); the module is deleted | RPC path serving handed the wallet every sibling leaf's 4th scalar in cleartext. WIRE (RPC) — **no longer exists** | None going forward: a leaf-format change no longer propagates through this surface. Historical: it served the scalar as-is and could not have served openings. |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:161-193` (`ProveInput.h_pqc: PqcLeafScalar` `:168-169`; `leaf_chunk_h_pqc: Vec<[u8;32]>` `:192-193`) | Prover input carries own + sibling 4th scalars. WITNESS | Field semantics; prover needs whatever the leaf holds. |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:224-414` (`prove_with_rng`: `:349-355` deserializes each `leaf_chunk_h_pqc[j]` as Selene scalar into `chunk_extra`, `:358-361` own `h_pqc`, `:412-414` `output_extra_scalars`/`leaves_extra_scalars`) | Builds the FCMP `Path` extras. WITNESS | Same. |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:513-684` (`prove_membership_only`: `:628-640`, `:682-684`) | Same for membership-only proofs. WITNESS | Same. |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:757-906` (`prove_with_sal`: `:845-857`, `:904-906`), `:969-972` (`ProveInputLeafChunk { output_h_pqc, leaf_h_pqc }`) | FROST/multisig prove path extras. WITNESS | Same. |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:989-1060` (`verify(proof, key_images, pseudo_outs, pqc_pk_hashes: &[PqcLeafScalar], …)`: `:1019-1020` count → `PqcCommitmentMismatch`, `:1045-1049` non-canonical scalar → `PqcCommitmentMismatch(i)`, `:1053-1058` → `InputVerification`) | Consensus verify entry: takes the public 4th scalars. PUBLIC-INPUT | Parameter semantics; error name `PqcCommitmentMismatch` (discriminant 3 in the C ABI, `src/shekyl/shekyl_ffi.h:490`) documented as a mismatch of "commitment". |
| S0 | prove/verify | `rust/shekyl-fcmp/src/proof.rs:1115-1162` (`verify_membership_only(proof, pseudo_outs, pqc_pk_hashes, …)`: `:1138-1141`, `:1158-1162`) | Same for membership-only. PUBLIC-INPUT | Same. |
| S0 | derive | `rust/shekyl-crypto-pq/src/derivation.rs:26-32` (`DOMAIN_PQC_LEAF = b"shekyl-pqc-leaf"`) | Blake2b DST for the leaf hash (registry row `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:182`). DERIVE | Rename/removal trips `domain_registry_gate.sh` row-presence; a *new* commitment domain in mech 4 will NOT trip it (honest scope, `scripts/ci/domain_registry_gate.sh:100-107`) — must be added to the TSV + `rust/shekyl-crypto-pq/tests/domain_registry.rs::PRODUCTION_PINS` by hand. |
| S0 | derive | `rust/shekyl-crypto-pq/src/derivation.rs:58-79` (`hash_pqc_public_key`) | SSOT for `H(pk)`. DERIVE | Becomes one half of a commitment or is replaced. |
| S0 | derive | `rust/shekyl-crypto-pq/src/derivation.rs:82-113` (`derive_pqc_leaf_hash(combined_ss, idx)`) | Recipient-side re-derivation from KEM secret. DERIVE | If `r` is needed, must be derived here too (HKDF label — see §3). |
| S0 | wire (Rust) | `rust/shekyl-wire/src/tx_extra.rs:44` (`TX_EXTRA_TAG_PQC_LEAF_HASHES = 0x07`), `:65` (`PQC_LEAF_HASH_BYTES = 32`), `:118` (`TxExtraField::PqcLeafHashes(Vec<u8>)`), `:232-233` (parse), `:305` (canonical-sort arm), `:370` (`write_field`) | 0x07 field codec. WIRE | Width per output if the published value changes size; name. |
| S0 | wire (Rust) | `rust/shekyl-wire/src/tx_extra.rs:401-417` (`pqc_leaf_hashes_per_output`) | Splits the blob into `[u8;32]` per output. WIRE | Width. |
| S0 | wire (Rust) | `rust/shekyl-wire/src/tx_extra.rs:478-512` (`check_pqc_field_shape` — rule: exactly one 0x07 of `32·n` when `n>0`, none when `n==0`; doc `:490-494` "0x07 is the fourth scalar of every leaf"), `:514-540` (`check_one`), `:555-563` (`check_pqc_field_shape_of`) | **The consensus shape rule for 0x07 (CEN-I19), one home.** WIRE | Stride constant; rule text. |
| S0 | wire (Rust) | `rust/shekyl-wire/src/transaction.rs:1829-1836` (`validate_context_free_pruned` → `check_pqc_field_shape_of`) | Rust port applies the shape rule at validation. WIRE | Follows the rule. |
| S0 | wire (C++) | `src/cryptonote_basic/tx_extra.h:48` (`#define TX_EXTRA_TAG_PQC_LEAF_HASHES 0x07`), `:168` (`PQC_LEAF_HASH_BYTES = 32`), `:170-172` (`struct tx_extra_pqc_leaf_hashes { std::string blob; }`), `:223` (variant), `:232` (`VARIANT_TAG`) | C++ 0x07 codec. WIRE | Width/name. |
| S0 | wire (C++) | `src/cryptonote_basic/cryptonote_format_utils.cpp:558` (canonical field order `pick<tx_extra_pqc_leaf_hashes>`), `:978-995` (`check_tx_extra_pqc_field_shape` — collects 0x06/0x07 lengths, verdict from `shekyl_tx_extra_pqc_field_shape`) | Adapter over the daemon's own parser to the one Rust rule. WIRE | Follows the rule. |
| S0 | wire (FFI) | `rust/shekyl-ffi/src/tx_extra_ffi.rs:54-107` (`code()` + `shekyl_tx_extra_pqc_field_shape` calling `check_pqc_field_shape` at `:107`) | FFI twin of the shape rule. WIRE | Follows the rule. |
| S0 | consensus gate | `src/cryptonote_core/cryptonote_core.cpp:818-829` (`core::check_tx_semantic`, shape rule on relay + block, no `kept_by_block` exemption) | Admission of 0x07 shape. WIRE | Follows the rule. |
| S0 | consensus gate | `src/cryptonote_core/blockchain.cpp:1448-1453` (`Blockchain::prevalidate_miner_transaction`, coinbase shape rule) | Coinbase 0x07 shape. WIRE | Follows the rule. |
| S0 | consensus verify | `src/cryptonote_core/blockchain.cpp:3773-3801` (`Blockchain::check_tx_inputs`, archival bond-post arm: `pqc_hashes_flat[j] = shekyl_fcmp_pqc_leaf_hash(tx.pqc_auths[i].hybrid_public_key)` `:3782-3783`, passed to `shekyl_fcmp_verify` `:3801`) | **Recomputes the public 4th scalar from the revealed pubkey.** PUBLIC-INPUT | Whole arm changes: verifier can no longer derive the leaf value from the pubkey alone; needs whatever the design makes public. |
| S0 | consensus verify | `src/cryptonote_core/blockchain.cpp:4082-4109` (same, archival emission fee-input arm `:4091-4092`, `:4109`) | Same. PUBLIC-INPUT | Same. |
| S0 | consensus verify | `src/cryptonote_core/blockchain.cpp:4208-4243` (same, general FCMP++ arm `:4211-4212`; debug log `:4225` prints `pqc_hash` per input; `:4243` into `shekyl_fcmp_verify`) | Same, plus the value is logged in cleartext at MDEBUG. PUBLIC-INPUT | Same; the log line leaks the value if it is meant to be hiding. |
| S0 | consensus verify | `src/cryptonote_core/blockchain.cpp:4272-4278` (comment: MSW-6 withdrawal rationale — "per-output scheme binding is the leaf hash `h_pqc = H(hybrid_public_key)`") | Reasons about the binding. PROSE | Rationale text. |
| S0 | consensus verify | `src/cryptonote_core/tx_pqc_verify.cpp:137-143` (comment: cross-input Keccak binding is intentionally distinct from `shekyl_fcmp_pqc_leaf_hash` / "in-circuit 4th leaf scalar") | Reasons about the 4th scalar. PROSE | Comment. |
| S0 | consensus verify (Rust port) | `rust/shekyl-daemon-rpc/src/submit/verifier.rs:999-1030` (`verify_fcmp`: `:1006-1009` comment "same `H_blake2b(dst ‖ hybrid_public_key)` Selene scalar the C++ caller computes"; `:1021-1024` `PqcLeafScalar::from_pqc_public_key(&auth.hybrid_public_key)`; `:1025-1028` K12 count check) | Rust twin of the C++ recompute. PUBLIC-INPUT | Same as C++ arms. |
| S0 | consensus verify (Rust port) | `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1078-1082` (doc on `verify_pqc_auths`: "per-output binding is the leaf hash `h_pqc = H(hybrid_public_key)`") | Reasons. PROSE | Comment. |
| S0 | consensus FFI | `rust/shekyl-ffi/src/legacy_fcmp.rs:32-53` (`shekyl_fcmp_pqc_leaf_hash` → `hash_pqc_public_key`) | C ABI recompute used by all three `blockchain.cpp` arms. DERIVE | Semantics. |
| S0 | consensus FFI | `rust/shekyl-ffi/src/legacy_fcmp.rs:55-80` (`shekyl_derive_pqc_leaf_hash`) | C ABI recipient-side derivation. DERIVE | Semantics. |
| S0 | consensus FFI | `rust/shekyl-ffi/src/legacy_fcmp.rs:356-454` (`shekyl_fcmp_verify`: `pqc_pk_hashes_ptr` `:374-375`, sliced `:407`, wrapped `:450-452` into `PqcLeafScalar`) | C ABI verify: the public scalars cross the boundary as raw 32-byte arrays. PUBLIC-INPUT | Parameter semantics; header doc `src/shekyl/shekyl_ffi.h:490` ("3 = PqcCommitmentMismatch"). |
| S0 | consensus FFI | `rust/shekyl-ffi/src/legacy_fcmp.rs:476-566` (`shekyl_fcmp_membership_only_verify`: `:493-504`, `:525`, `:559-566`) | Same for membership-only. PUBLIC-INPUT | Same. |
| S0 | consensus FFI | `rust/shekyl-ffi/src/legacy_fcmp.rs:588-615` (`shekyl_fcmp_outputs_to_leaves` — 128-byte tuples `{O.x,I.x,C.x,pqc_pk_hash}` → `ShekylLeaf::from_bytes`) | Leaf re-validation helper. LAYOUT | Transparent. |
| S0 | archival consensus | `rust/shekyl-archival-retention/src/emission_wire.rs:148-157` (`MembershipOnlyBacking { pseudo_out, pqc_pk_hash: [u8;32], backing_pubkey: Vec<u8> }`; doc `:117-122`), `:526-545` (`write` — `:543` writes `pqc_pk_hash`), `:568-642` (`read_payload` — `:617`) | **The emission vin carries the backing leaf's 4th scalar AND the pubkey in cleartext on chain.** WIRE | Field semantics/width; if the leaf value is hiding, the vin must carry `Commit` (and prove opening) rather than `H(pk)`; the `backing_pubkey` reveal itself remains a linkage channel unless the design changes it. |
| S0 | archival consensus | `rust/shekyl-archival-retention/src/emission_verify.rs:657-684` (`emission_vin_verify_backing`: `:670-672` leaf gate `hash_pqc_public_key(backing_pubkey) != pqc_pk_hash → BackingLeafMismatch`, `:680-684` `verify_membership_only(.., &[PqcLeafScalar(backing.pqc_pk_hash)], ..)`), `:184-186` (error variant doc) | Auth-B leaf gate + membership-only verify. PUBLIC-INPUT | Gate must become "opening verifies"; membership-only public value changes. |
| S0 | archival consensus | `rust/shekyl-archival-retention/src/emission_verify.rs:720-730` (`emission_vin_verify_auth`: `:727-730` leaf gate first, order pinned) | Same gate, second site (order-pinned). PUBLIC-INPUT | Same. |
| S0 | archival consensus | `rust/shekyl-ffi/src/archival_ffi/serve_credit.rs:112-153` (`shekyl_archival_verify_serve_credit_vin`: `:150-152` `scalar_count % SCALARS_PER_LEAF`) | Serve-credit verifier consumes a raw leaf-layer chunk (`leaf_layer_scalars`, `src/shekyl/shekyl_ffi.h:1625-1627`) read from the daemon's own LMDB (`src/cryptonote_core/blockchain.cpp:5078-5089`). LAYOUT/STORE | Count only. |
| S0 | archival consensus | `rust/shekyl-archival-retention/src/path.rs:54-58` (`CHALLENGED_LEAF_LEN = SCALARS_PER_LEAF*32`, asserted `== 128`), `:76-78` (`leaf_node_from_layer_scalars`), `:103-125` (`challenged_leaf_bytes`) | Path/opening arithmetic over 4-scalar leaves (deletion-bound per RF-D8 retraction, but live at this sha). LAYOUT | Count only. |
| S0 | DB store (C++) | `src/blockchain_db/blockchain_db.cpp:511-546` (`BlockchainDB::add_block` → `extract_leaf_hashes` lambda: shape rule `:530`, parse `:538`, `find_tx_extra_field_by_type` `:541`, abort instead of zero-fill; history comment `:522-527`) | Pulls the 0x07 blob for leaf construction; fail-closed. STORE/WIRE | Follows the rule; comment history. |
| S0 | DB store (C++) | `src/blockchain_db/blockchain_db.cpp:550-557` (`collect_outputs` lambda: `h_pqc = blob + i*PQC_LEAF_HASH_BYTES` `:557`), `:600-611` (`shekyl_construct_curve_tree_leaf(output_key, commitment, h_pqc, leaf)` `:608-610`, throws on false) | Builds the stored 128-byte leaf from the published value. STORE | The 4th input becomes whatever is published. |
| S0 | DB store (C++) | `src/blockchain_db/blockchain_db.cpp:1713-1724` (`get_curve_tree_leaf_chunk` portable fallback, `kLeafSize` stride) | Reads leaves back. STORE | Width only. |
| S0 | DB store (C++) | `src/blockchain_db/blockchain_db.h:2474-2480` (`add_pending_tree_leaf` "128 bytes"), `:2501-2507` (`drain_pending_tree_leaves`), `:2534-2540` (`add_pending_tree_drain_entry`), `:2622-2633` (`grow_curve_tree` — "Each leaf is 128 bytes: {O.x[32], I.x[32], C.x[32], H(pqc_pk)[32]}"), `:2693-2709` (`get_curve_tree_leaf_chunk`) | Interface docs pin the 4-scalar leaf and name the 4th as `H(pqc_pk)`. PROSE/LAYOUT | `:2625` names the content; must be reworded. |
| S0 | DB store (C++) | `src/blockchain_db/shekyl_types.h:144` (`kLeafSize = 128 // 4 Selene scalars × 32B`), `:289-300` (`DrainValue` holds the 128-byte leaf) | Leaf width constant shared by DB + `src/cryptonote_core/blockchain.cpp:5078-5082`. LAYOUT | Width only. |
| S0 | DB store (C++) | `src/blockchain_db/lmdb/db_lmdb.cpp:149` (`#define VERSION 13`), `:8629-8638, 8679-8686, 8755` (`kLeafSize` reads/writes), `:9006-9009` (`CT_SCALARS_PER_LEAF = 4`, `CT_LEAF_SIZE`), `:9028-9030` (`ct_leaf_scalars_per_chunk`), `:9033+` (`grow_curve_tree`, `:9111`, `:9133`), `:9246+` (`trim_curve_tree`, `:9360-9362`); `src/blockchain_db/lmdb/db_lmdb.h:982` (`m_curve_tree_leaves // global_output_index -> 128 bytes leaf data`) | LMDB leaf table and layer growth over 4 scalars/leaf. STORE/LAYOUT | Width/count; a content change invalidates every stored leaf + layer hash + checkpoint (pre-genesis: DB reset, no migration; `VERSION` bump only if format changes). |
| S0 | DB store (Rust daemon port) | `rust/shekyl-chain-store/src/schema.rs:215-217` (`CURVE_TREE_LEAVES: TableDefinition<u64, &[u8]>`) | redb daemon leaf table (opaque bytes). STORE | Transparent unless width changes. |
| S0 | wallet-side replica (consensus-equal by KAT) | `rust/shekyl-curve-tree/src/types.rs:44-46` (`OutputIdentity.h_pqc`, "zero-fallback applied"), `:62-66` (why `AssembleInput` omits it), `:149-153, 169-173` (`LeafEntry.leaf` 128-byte), `:197-200` (`ChunkLeaf.h_pqc`) | Wallet replica of the leaf set. STORE | Field semantics; doc at `:44-46` names the fallback. |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/recon.rs:23-28` (`PQC_LEAF_HASH_BYTES`, `ZERO_PQC` "mirrors the C++ zero_pqc fallback"), `:39-69` (`extract_leaf_hashes` — empty on absent / `%32≠0`), `:71-76` (`per_output_h_pqc` zero-fallback), `:98-117` (`try_build_leaf` → `construct_leaf(&out.output_key, &commitment, &out.h_pqc)`), `:207-213` (`assemble_leaf_stream` 4 scalars/leaf) | Post-parse 0x07 validation + leaf construction for the wallet's root oracle. STORE/WIRE | Stride; **note the zero-fallback is retained here although C++ retired it (CEN-I19) — see §6 (d)-3.** |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/client.rs:14-28` (module doc), `:66-69`, `:81-92` (`TxLeafInputs.leaf_hash_blob: Option<&[u8]>`), `:717-761` (`ingest_block` — `:752` `extract_leaf_hashes`, `:759` `per_output_h_pqc`) | Resolves each output's 4th scalar from the raw 0x07 blob at ingest. WIRE→STORE | Same. |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/segment.rs` (`LEAF_BYTES = SCALARS_PER_LEAF*32`, `const _: () = assert!(LEAF_BYTES == 128)`), `:88-95` (`leaf_bytes_to_scalars`) | Segment geometry. LAYOUT | Width. |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/served_frame.rs:18-22, 36-40, 53-58, 97-107, 204-208, 220-223, 293-297` (`ServedFrameHeader` — `segment_bytes = leaf_count × LEAF_BYTES`, padding bound) | Served-shard frame is a raw leaf array. WIRE (P2P) | Width. |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/store/redb_backend.rs:22` (`LEAVES_TABLE: TableDefinition<TreePosition, &[u8;128]>`), `:30-34` (pending rows = leaf ‖ 192-byte meta), `:75` (`SCHEMA_VERSION = 4`), `:364-366, 411-420` (serving reads by `LEAF_BYTES`), `:2057-2061` (`leaf_bytes_are_canonical` — each of 4 scalars must be canonical Selene), `:2171-2184` (`encode_leaf_meta` — `h_pqc` at `buf[81..113]`), `:2192-2221` (`decode_stored_leaf_meta` `:2206-2207`) | Wallet store persists the leaf **and** a second copy of `h_pqc` in leaf-meta. STORE | Meta layout `[81..113)` and `SCHEMA_VERSION` (this store is NOT under the rule-42 `schema-snapshot.yml`, which watches `shekyl-engine-state/**` only — a bump here is a manual duty). |
| S0 | wallet-side replica | `rust/shekyl-curve-tree/src/assemble.rs:72-155` (`assemble_path` — `:153` `h_pqc: e.identity.h_pqc` into `ChunkLeaf`) | Path assembly reads the 4th scalar back from the drained leaf identity. WITNESS | Semantics. |
| S0 | replica FFI | `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs:74-82` (`ShekylCurveTreeReplicaTx { has_leaf_hash_blob, leaf_hash_blob, leaf_hash_blob_len, … }`), `:94-101` (`const _` ABI offset pins), `:200-240` (marshals to `TxLeafInputs`), `:359-365` (test) | C++→Rust replica feed of the raw 0x07 payload (used by `tests/core_tests/chaingen.cpp:323-382`). WIRE/S3 | Struct name/doc; ABI pins hold unless a field is added. |
| S0 | leaf FFI | `rust/shekyl-ffi/src/legacy_curve_tree.rs:321-328` (`shekyl_curve_tree_scalars_per_leaf` = 4), `:512-560` (`shekyl_construct_curve_tree_leaf(output_key, commitment, h_pqc_ptr, leaf_out)` — doc `:514` "or 32 zero bytes if unavailable", `:556` → `construct_leaf`) | C ABI leaf constructor used by `src/blockchain_db/blockchain_db.cpp:608`. STORE | Doc stale (zero not admissible); parameter semantics. |
| S0 | RPC path — **SURFACE REMOVED 2026-09-18** (`SOK-10` Q7 → A; spend-revealing, `PHASE_2A` §3.0.1) | records-was at `8494f2a27`: `ffi/src/curve_tree_path_ffi.rs:13-35` (`CallbackStore::leaf`), `:84-90` (`shekyl_assemble_curve_tree_path`); `cryptonote_core/curve_tree_path.cpp:50` (`read_leaf`), `:91-119` (`assemble_curve_tree_path` → `chunk_outputs`); `cryptonote_core/curve_tree_path.h:20-27` (layout doc); `rpc/core_rpc_server.cpp:1470-1561` (`on_get_curve_tree_path`); `rpc/core_rpc_server_commands_defs.h:1389-1390` (`chunk_outputs_blob`) — all deleted | Daemon served every chunk sibling's 4th scalar to wallets over RPC. WIRE (RPC) — **no longer exists** | None going forward: provers take the 4th scalar from their own drained leaf identity (`assemble.rs`, the row above), never from a daemon. Historical: doc strings named the content; openings were never served. |
| S0 | genesis | `rust/shekyl-genesis-tool/src/builder.rs:56-128` (`build_genesis_tx`: `:110` `leaf_blob.extend_from_slice(&od.h_pqc)`, `:122` length assert, `:124-128` `TxExtraField::PqcLeafHashes(leaf_blob)`) | Genesis coinbase publishes real `h_pqc` per recipient in 0x07. WIRE/DERIVE | Genesis tx bytes, tx hash, block id all change → `golden_kat.rs` pins (S1). |
| S0 | creation (C++) | `src/cryptonote_core/cryptonote_tx_utils.cpp:126` (`construct_miner_tx`: `:198-199` reserve `n×PQC_LEAF_HASH_BYTES`, `:237` `leaf_hash_field.blob.append(od.h_pqc, 32)`, `:256-258` serialize) | Coinbase creation publishes `od.h_pqc` from `shekyl_construct_output`. WIRE | Published value/width. |
| S0 | creation (C++) | `src/cryptonote_core/cryptonote_tx_utils.cpp:301` (`construct_tx_with_tx_key`: `:499-500`, `:547`, `:567-569`) | Non-coinbase creation (test/legacy C++ path). WIRE | Same. |

### S1 — KATs / frozen vectors / snapshots / golden files

Classification: **(a)** pins the *derivation* of `h_pqc`; **(b)** pins a *root / proof
/ hash computed over real `h_pqc` values*; **(c)** layout-only with dummy 4th scalar.
A `Commit(h_pqc, r)` change breaks every (a) and (b) unconditionally; (c) only if
width/count changes.

| Sev | Class | file (what it pins) | Consumer test(s) | What breaks |
|---|---|---|---|---|
| S1 | (a) | `docs/test_vectors/PQC_LEAF_HASH_KAT.json` — 8 vectors `(combined_ss, output_index) → h_pqc` (lines 5,10,15,20,25,30,35,40) | `rust/shekyl-crypto-pq/src/derivation.rs:525-549` `pqc_leaf_hash_known_answer_vectors` | Every `h_pqc` value. |
| S1 | (a) | `docs/test_vectors/PQC_LEAF_HASH_RAW_PK_KAT.json` — 4 raw-pk pins (empty / 1-byte / ML-DSA-65-length / all-0xff; lines 6,10,14,18) | `rust/shekyl-crypto-pq/src/derivation.rs:574-602` `pqc_leaf_hash_raw_pk_known_answer_vectors` (asserts BOTH `hash_pqc_public_key` and `PqcLeafScalar::from_pqc_public_key`) | Every value. |
| S1 | (a) | `docs/test_vectors/PQC_SCAN_OUTPUT_KAT.json:22,43` — `h_pqc` of two constructed outputs | `rust/shekyl-crypto-pq/tests/scan_output_kat.rs:62,154` (+ regen writer `:292-296`) | Both `h_pqc` fields. |
| S1 | (a)+(b) | `rust/shekyl-archival-retention/tests/fixtures/emission_connect_kat_v1.json` — wire blob whose `backing.pqc_pk_hash = hash_pqc_public_key([0x22; 1996])` (built at `rust/shekyl-archival-retention/tests/emission_connect_kat.rs:56-57,77-81`) | `emission_connect_kat.rs`; C++ via `tests/unit_tests/CMakeLists.txt:233,235` `EMISSION_CONNECT_KAT_FIXTURE_PATH` | Blob bytes + extract outputs. |
| S1 | (b) | `rust/shekyl-curve-tree/tests/fixtures/ct2_tier_a.json` — 639 blocks × {`miner_tx.pqc_leaf_hashes` (raw 0x07 blob of real `h_pqc`), `curve_tree_root` (C++ consensus header root)}; provenance `:1-9` (`fixture_bytes_commit e0526f17…`, `audited_daemon_commit 5bfef7c0…`) | `rust/shekyl-curve-tree/tests/recon_kat.rs:73-85, 258-279`, `rust/shekyl-curve-tree/tests/assemble_kat.rs:86-116`, `rust/shekyl-curve-tree/tests/store_kat.rs:62-75,108-113`; `rust/shekyl-archival-retention/tests/assembled_path_crosscheck.rs:16,54-58`, `rust/shekyl-archival-retention/tests/gate2_serve_credit_kat.rs:32,406-432`; `rust/shekyl-engine-core/src/engine/curve_tree_decode.rs:252-284` (test), `rust/shekyl-engine-core/src/engine/refresh/start_refresh_integration_tests.rs:1352-1379` | Every root; the fixture must be regenerated from a daemon running the new leaf (`rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py:195-262`, `rust/shekyl-curve-tree/tests/fixtures/README.md:17-19`). |
| S1 | (b) | `rust/shekyl-curve-tree/tests/fixtures/ct2_tier_b.json` — same shape incl. non-coinbase txs with spends (`pqc_leaf_hashes` per tx + `curve_tree_root`) | `rust/shekyl-curve-tree/tests/recon_tier_b.rs:78-93`; generator `rust/shekyl-engine-core/src/engine/regtest_e2e.rs:1483-1487` (`generate_ct2_tier_b_fixture`, `--ignored`), emitter `:3949-3960` | Every root. |
| S1 | (b) | `rust/shekyl-genesis-tool/tests/golden_kat.rs:28-34` — `KAT_TX_SECRET_HEX`, `KAT_TX_PUB_HEX` (unaffected), `KAT_BLOB_LEN = 6263`, `KAT_BLOB_SHA256_HEX`, `KAT_TX_HASH_HEX`, `KAT_BLOCK_ID_HEX` (all over the genesis tx whose 0x07 carries real `h_pqc`) | `rust/shekyl-genesis-tool/tests/golden_kat.rs:59-82` `golden_kat`; `:109-131` `extra_is_canonical_fixed_point` (asserts field 2 is 0x07 of `n×32`) | Blob length only if width changes; sha256 / tx hash / block id change for any content change. Genesis freeze artifact. |
| S1 | (b) | `rust/shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json` — `leaf_bytes_hex` ×3, `segment_subroot_rk_hex` ×3 (from the ct2 tier-a tree) | `rust/shekyl-archival-retention/tests/gate2_serve_credit_kat.rs` (`:464-467` `construct_leaf(.., &cl.h_pqc)`, `:945-949`); C++ `tests/unit_tests/archival_serve_credit_integration.cpp:392-396` (`leaf_scalars_hex`, CMake `:209,219,228`) | All leaf/subroot bytes. |
| S1 | (b) | `rust/shekyl-archival-retention/tests/fixtures/serve_credit_equivalence_kat_v1.json` (`leaf_scalars_hex`) | C++ `tests/unit_tests/archival_serve_credit_equivalence.cpp:553-557` (CMake `:229`); Rust standing KAT | Leaf bytes. |
| S1 | (b) | `rust/shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json` (blobs are the gate-2 integration section's) and `gate4_lifecycle_kat_v1.json` (reads gate-2's integration section) | shekyl-wire parity test; C++ CMake `:210,217,231` | Follow gate-2. |
| S1 | (c) | `docs/test_vectors/WITNESS_HEADER.json:2,8,20,31,42,53` — 256-byte witness header layout `[O][I][C][h_pqc:32@96][x][y][z][a]` with dummy `h_pqc` | `rust/shekyl-ffi/src/legacy_tests.rs:598-738` (`:639`, `:671-675` `blob[96..128]`, `:703-707`, `:734-737`) | Offset/width only. |
| S1 | (c) | `docs/test_vectors/TX_EXTRA_PQC_ROUND_TRIP.json:6,10,14-53` — 0x07 tag/32-byte stride round-trip | `tests/unit_tests/test_tx_utils.cpp:362-434, 437-488` | Stride only. |
| S1 | (c) | `docs/test_vectors/EMISSION_AUTH_MSG_V1/vectors.json:20` — `pqc_pk_hash = 0x33×32` inside the signed auth message | `rust/shekyl-archival-retention/tests/kat_emission_auth_msg.rs:104-108` | Only if the vin field width/semantics change. |
| S1 | (c) | Dummy-filler 0x07 builders: `rust/shekyl-daemon-rpc/tests/submit_fixtures/mod.rs:480-484`, `rust/shekyl-wire/tests/common/mod.rs:23-27`, `rust/shekyl-engine-core/src/engine/test_support.rs:982-986`, `tests/unit_tests/pqc_spend_fixture.h:65-93,161-164` (all `0x7b`/`'\x7b'` × `32·n`) | shape-rule tests | Stride only. |
| S1 | gate | `rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256:29,32,35,37,38` (sha256 of `fcmps/src/{circuit,lib,prover/mod,tests,tree}.rs`) via `scripts/ci/check_vendored_crypto_manifest.sh` / `.github/workflows/vendored-crypto-content.yml:48` | — | Any circuit edit must `--update` the manifest (a sanctioned fork re-sync event). |
| S1 | gate | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:182` (`4 shekyl-pqc-leaf derivation.rs DOMAIN_PQC_LEAF`) via `scripts/ci/domain_registry_gate.sh` (`.github/workflows/grep-gates.yml:133`) + `rust/shekyl-crypto-pq/tests/domain_registry.rs` (`PRODUCTION_PINS` count) | — | Rename/move of the DST trips row-presence; a new mech-2/4 domain must be registered by hand (gate is explicitly incomplete for HKDF/Blake2b, `scripts/ci/domain_registry_gate.sh:100-107`). |
| S1 | gate (does NOT fire) | `.github/workflows/schema-snapshot.yml` / `rust/shekyl-engine-state/schemas/*.snap` — grep for `h_pqc\|pqc\|leaf` over the schemas is empty; `h_pqc` is not persisted in the wallet ledger (`git grep h_pqc -- rust/shekyl-engine-state rust/shekyl-engine-file` = ∅) | — | Rule-42 snapshot gate is silent for this change. The curve-tree redb store (`SCHEMA_VERSION = 4`) and LMDB (`VERSION 13`) are outside that workflow. |
| S1 | gate (does NOT fire) | `scripts/ci/check_golden_revision_bump.py:71-73` — subject is `rust/shekyl-shard-visual/tests/goldens/*.png` + `RENDER_REVISION` | — | Unrelated to leaves (false positive of the "golden" search). |

### S2 — wallet / engine

| Sev | Layer | file:line | What it does | What breaks |
|---|---|---|---|---|
| S2 | create | `rust/shekyl-crypto-pq/src/output.rs:8-18` (module doc `h_pqc = PqcLeafHash(pqc_kp.pk)`), `:79-117` (`OutputData.h_pqc` `:115-117`), `:274-407` (`construct_output_with_label_plaintext`: `:393-394` keygen + `compute_hybrid_h_pqc`, `:405`), `:1410-1434` (`compute_hybrid_h_pqc` — full hybrid pk → `hash_pqc_public_key`) | Sender computes the published value. DERIVE | Must produce the new value (and hold/transport `r` if any). |
| S2 | scan | `rust/shekyl-crypto-pq/src/output.rs:198-223` (`ScannedOutput.h_pqc`), `:641-765` (`scan_output_with_ml_kem_dk` `:750-751,763` recomputes), `:793-806` (`RecoveredOutput.h_pqc`), `:867-982` (`scan_output_recover_with_ml_kem_dk` `:964-965,980`), `:775-789` (ZeroizeOnDrop rationale — `h_pqc` "privacy-linkable artifact, a wallet fingerprint") | Recipient re-derives `h_pqc` at scan; treats it as linkable. DERIVE | Same; the zeroize rationale at `:786-788` already states the linkage concern. |
| S2 | create/scan FFI | `rust/shekyl-ffi/src/legacy_tx.rs:394-452` (`shekyl_construct_output` `:414,450`), `:466-538` (`shekyl_construct_output_labeled` `:487,536`), `:631-729` (`shekyl_scan_output` `:653,699,727`), `:745-848` (`shekyl_scan_output_recover` `:768,813,846`), `:939-1054` (`shekyl_scan_and_recover` `:967,1014,1053`); `rust/shekyl-ffi/src/legacy_types.rs:54-57` (`ShekylOutputData.h_pqc`), `:71-74` (scan result `.h_pqc`) | C ABI create/scan expose `h_pqc[32]`. DERIVE | Out-param semantics/width. |
| S2 | spend (FFI legacy) | `rust/shekyl-ffi/src/legacy_tx.rs:163-185` (`FcmpSignInput { hp_of_O, …, h_pqc, leaf_chunk }`), `:208-312` (`shekyl_sign_fcmp_transaction` — **`:306` `h_pqc: inp.hp_of_O`**), `:364-378` (`shekyl_fcmp_build_witness_header` `:376` `buf[96..128] = inp.h_pqc`); `rust/shekyl-ffi/src/legacy_types.rs:8-11` (header layout doc), `:34-37` (`ProveInputFields.h_pqc`) | JSON→`SpendInput` bridge + witness header. WITNESS | Field semantics; the `hp_of_O`/`h_pqc` naming defect (§6 (d)-2). |
| S2 | spend (FFI legacy) | `rust/shekyl-ffi/src/legacy_fcmp.rs:196-211` (witness byte-layout doc), `:227-275` (`parse_prove_witness` `:242,251,259,267,273`), `:293-316` (`parse_leaf_chunks` — 128-byte entries, `[96..128]` → `h_pqc`) | Witness parser for C++ callers. WITNESS | Layout/semantics. |
| S2 | spend (FROST) | `rust/shekyl-ffi/src/legacy_frost.rs:286-292` (`ProveInputLeafChunk { output_h_pqc, leaf_h_pqc }`) | Multisig prove path extras. WITNESS | Same. |
| S2 | spend (engine) | `rust/shekyl-engine-core/src/engine/sign_bridge.rs:65-77` (`BuiltOutput.h_pqc` — doc "an output whose tx omits the field ingests with a zero `h_pqc` leaf and is unspendable"), `:79-113` (`build_output` `:112`), `:208-224` (`spend_input_from_context` `:222`), `:232-362` (`sign_tx` — `:350-361` builds the 0x07 blob and `push_pqc_leaf_hashes`) | Transfer path: publishes `h_pqc` per vout and feeds the spend input. WIRE/WITNESS | Published value; comments at `:70-75, 351-358` describe the zero-leaf failure mode. |
| S2 | spend (engine) | `rust/shekyl-engine-core/src/engine/signing_assembly.rs:139-183` (`input_context_from_transfer` — `:156-167` looks up own `h_pqc` in the assembled leaf chunk by `(O, C)`), `:192-199` (`leaf_entry_from_chunk`) | Reads the 4th scalar back from the tree rather than deriving it. WITNESS | If the leaf holds `Commit`, the prover must also recover `r` from its own derivation (not from the chunk). |
| S2 | spend (engine) | `rust/shekyl-engine-core/src/engine/traits/key.rs:341-363` (`TxInputSigningContext.h_pqc`), `:376-388` (Debug redacts it), `:426-430` (doc: public components ride outside the secret bundle) | Actor message shape. WITNESS | Field. |
| S2 | spend (engine) | `rust/shekyl-engine-core/src/engine/drain_assembly.rs:385-395` (step 3: `leaf_hash_blob` from `BuiltOutput.h_pqc`, `push_pqc_leaf_hashes`) | Drain tx publishes 0x07. WIRE | Published value. |
| S2 | stake (engine) | `rust/shekyl-engine-core/src/engine/stake_engine/helpers.rs:48-54` (`ConstructedVouts.leaf_hash_blob`), `:60-91` (`construct_vouts_to_base` `:72,89`), `:110-120` (`DerivedSpendParts.h_pqc` "read back from its own leaf chunk — not persisted on the record"), `:126-161` (`derive_spend_parts` `:138-143` lookup by `output_key`), `:167-183` (`into_spend_input` `:181`) | Bond/claim vout construction + spend-part derivation. WIRE/WITNESS | Same as transfer. |
| S2 | stake (engine) | `rust/shekyl-engine-core/src/engine/stake_engine/claim.rs:120+` (`handle`: `:223-226` 0x07 push; `:260-276` **pre-flight leaf gate** `hash_pqc_public_key(&backing_pubkey) != backing_h_pqc`; `:312-316` `MembershipOnlyBacking { pqc_pk_hash: backing_h_pqc, backing_pubkey }`; `:323-327` Auth-B rationale) | Emission claim builder mirrors the consensus leaf gate and puts the leaf value + pubkey on the vin. WIRE/PUBLIC-INPUT | Gate and vin fields. |
| S2 | stake (engine) | `rust/shekyl-engine-core/src/engine/stake_engine/bond_post_assemble.rs:104-131` (`assemble_signed_bond_post` `:128-129`) | Bond-post publishes 0x07. WIRE | Published value. |
| S2 | stake (engine) | `rust/shekyl-engine-core/src/engine/bond_orchestrator.rs:505+` (`assemble_bond_post` `:650-652` `LeafEntry.h_pqc`), `rust/shekyl-engine-core/src/engine/drain_orchestrator.rs:748+` (`orchestrate_drain` `:907-909`), `rust/shekyl-engine-core/src/engine/emission_claim.rs:838-856` (`claims_vin` weight placeholder `pqc_pk_hash: [0;32]`) | Path→`LeafEntry` conversions; weight estimation. WITNESS | Field. |
| S2 | scan (wire parse) | `rust/shekyl-scanner/src/extra.rs:43-44` (tag re-export), `:54-67` (`ExtraField::PqcLeafHashes`), `:74-84` (`to_wire`), `:88-110` (`try_from_wire` — doc `:92-94`: failing the whole extra "would make curve-tree decode fall back to zero `h_pqc`"), `:202-207` (`pqc_leaf_hashes()` first-match), `:266-279` (`push_pqc_leaf_hashes` — doc `:269-276` unspendable-without-field) | The wallet's only tx_extra parser for 0x07. WIRE | Field; docs. |
| S2 | scan (engine) | `rust/shekyl-engine-core/src/scan.rs:81-100` (`OwnedTxLeaves.leaf_hash_blob`), `rust/shekyl-engine-core/src/engine/curve_tree_decode.rs:26-47` (module doc — `:43-47` "malformed/absent extra … resolves to the zero `h_pqc` fallback"), `:103-147` (`decode_tx` `:113-122`), `rust/shekyl-engine-core/src/engine/curve_tree_actor.rs:338-352` (`handle` IngestBlock → `TxLeafInputs`) | Block→leaf-input decode feeding the replica. WIRE | Field; docs assert the retired fallback. |
| S2 | tx-builder | `rust/shekyl-tx-builder/src/types.rs:155-168` (`LeafEntry.h_pqc` serde hex), `:181-212` (`SpendInput.h_pqc` `:199-201`, `leaf_chunk` doc `:209-211`), `rust/shekyl-tx-builder/src/sign.rs:357-392` (`prove_input_from_spend` `:363` sibling `h_pqc`s, `:384` `PqcLeafScalar(input.h_pqc)`, `:390`) | Typed spend input → `ProveInput`. WITNESS | Field semantics. |
| S2 | tx-weight | `rust/shekyl-tx-weight/src/lib.rs:213-220` (`extra_leaf_hashes_field_weight`), `:260-272` (`predict_weight`), `:415-449` (test uses real serializer) ; `rust/shekyl-tx-weight/tests/weight_gate.rs:107-110` | Weight model counts `n_out × 32` for 0x07. LAYOUT | Only if the published width changes (weight gate then reddens). |
| S2 | archival serve | `rust/shekyl-p-serve/src/provider.rs:30-33, 110-116, 156-160` (`flat_header` requires multiple of `LEAF_BYTES`); `rust/shekyl-sp-t3-spike/src/fixture.rs:9-14, 41-48, 65-71` (`LEAF_BYTES = 128`, `SHARD_BYTES`), `rust/shekyl-sp-t3-spike/bins/extract_shard.rs:17-37, 146-155` (rebuilds leaves via `construct_leaf(&o, &c, &h)` from RPC `chunk_outputs`) | Shard serving / fixture extraction over raw leaves. LAYOUT/WIRE | Width; the spike's local `LEAF_BYTES = 128` is a third copy. |
| S2 | multisig | `rust/shekyl-crypto-pq/src/multisig.rs:318-324` (comment: former check 9 recomputed group id from the same blob "the curve-tree leaf `h_pqc = H(blob)` already binds"), `:400-408` (`multisig_pqc_leaf_hash(container)` = `H(container bytes)`); `rust/shekyl-multisig/src/ceremony.rs:24-28` (doc: leaf binds SAL to key); `rust/shekyl-crypto-hash/src/lib.rs:7-11` (doc lists `multisig_pqc_leaf_hash` as a byte-identical-with-C++ hash) | Multisig container hashed to the same 4th scalar. DERIVE | Must follow the new derivation for scheme-2 keys. |
| S2 | CLI (false positive) | `rust/shekyl-cli/src/rpc_client.rs:157-162`, `rust/shekyl-cli/src/validate.rs:8-18` ("128 bytes") | Unrelated buffer sizes. — | Nothing. See §7. |

### S3 — FFI signatures / headers / ABI pins

| Sev | file:line | What | What breaks |
|---|---|---|---|
| S3 | `src/shekyl/shekyl_ffi.h:442-446` (`shekyl_fcmp_pqc_leaf_hash` "Compute H(pqc_pk) leaf scalar"), `:448-454` (`shekyl_derive_pqc_leaf_hash` "h_pqc = H(hybrid_public_key)"), `:456+` (`shekyl_derive_pqc_public_key`) | Hand-maintained C header (no cbindgen for these; only the relay surface is cbindgen-gated by `scripts/ci/cbindgen-relay-signatures.toml` / `check_relay_ffi_signatures.sh`) | Doc strings + any signature change must be hand-mirrored. |
| S3 | `src/shekyl/shekyl_ffi.h:487-507` (`shekyl_fcmp_verify` — `pqc_pk_hashes_ptr`, `pqc_hash_count`; error `3 = PqcCommitmentMismatch` at `:490`), `:512-531` (`shekyl_fcmp_membership_only_verify` `:518,527-528`), `:533-536` (`shekyl_fcmp_outputs_to_leaves` "4-scalar leaves") | Verify ABI takes the public scalars as `count×32` bytes | Parameter semantics; error taxonomy names "commitment". |
| S3 | `src/shekyl/shekyl_ffi.h:641` (`ShekylOutputData.h_pqc[32]`), `:706-708, 733-735, 774-776` (`h_pqc_out` on the three scan exports) | Create/scan ABI | Width/name. |
| S3 | `src/shekyl/shekyl_ffi.h:1228` (`shekyl_curve_tree_scalars_per_leaf(); // 4`), `:1251-1281` (`ShekylCurveTreeReplicaOutput`/`ReplicaTx` with `has_leaf_hash_blob`/`leaf_hash_blob`/`leaf_hash_blob_len` + `static_assert` offsets `:1279-1281`), `:1315-1344` (`shekyl_tx_extra_pqc_field_shape` doc "exactly one 0x07 leaf-hash field of 32·n bytes"), `:1386-1396` (`shekyl_construct_curve_tree_leaf` — `:1389` "or 32 zero bytes if unavailable", `:1390` "{O.x, I.x, C.x, H(pqc_pk)}"), `:1398-1417` (`shekyl_ct_read_leaf_fn(.., uint8_t leaf_out[128])`, `shekyl_assemble_curve_tree_path`), `:1441-1444` (`FcmpSignInput` JSON doc listing `hp_of_O` and `h_pqc`), `:1620-1627` (`shekyl_archival_verify_ctx.leaf_layer_scalars_ptr/len` — flattened Selene leaf-layer scalars), `:2856-2857` (`SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF = 13` "backing pubkey does not hash to the committed leaf") | Leaf/replica/path/archival ABI + docs | Doc strings assert `H(pqc_pk)` and the zero placeholder; ABI offset pins hold unless fields change; error text. |
| S3 | `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs:94-101` (`const _` offset pins mirrored by `src/shekyl/shekyl_ffi.h:1279-1281`) | ABI pin pair | Only if the struct gains a field (e.g. per-output openings). |
| S3 | `rust/shekyl-ffi/src/legacy_types.rs:8-11, 34-37, 54-57, 71-74` | Witness header / output / scan structs | Width/name. |

### S4 — documentation (asserts-is unless marked record)

| Sev | file:line(s) | What it says about the 4th scalar |
|---|---|---|
| S4 | `docs/FCMP_PLUS_PLUS.md:61-91` (leaf = 4 scalars/128 B; `H(pqc_pk)` = `shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)` at `:73`; Blake2b/`shekyl-pqc-leaf` SSOT `:86-90`), `:101-108` (public inputs `pqc_pk_hashes_ptr`), `:121-123`, `:152-154`, `:217-221` (0x07 field), `:239-248` (coinbase per-output `H(pqc_pk)` "prevents linking rewards"), `:341-343`, `:412-414`, `:529-550` (verify pseudocode `extract_ml_dsa_pk` → leaf hash; `:548-550` asserts equality), `:598-601` (FFI table — says `shekyl-ffi/src/lib.rs`), `:703-705` (LMDB `curve_tree_leaves` 128 B `{…,H(pqc_pk)}`), `:820-831` (derive-leaf-hash FFI; testnet reset note — record), `:1110-1135` (staking-subtree proposal: 5-scalar leaf, `h_pqc = shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)`, `SCALARS_PER_LEAF` per-tree), `:1146-1154` (pending table 128-byte values), `:1172-1174` ("PQC ownership cross-check for regular spends: `leaf[96:128] == shekyl_fcmp_pqc_leaf_hash(pqc_pk)`"), `:1196-1198` (stake-claim PQC mismatch row), `:1211-1218` (constants table), `:1253-1297` (status table rows), `:1371-1389` (fuzz targets), `:1407-1410`, `:1551-1588` (circuit extension description), `:1565-1567` (scalar layout), `:1813-1823` (witness header; `h_pqc` = "H(ml_dsa_pk)") | Primary spec. Several passages are stale at this sha (§6 (d)-5/6/7). |
| S4 | `docs/MERKLE_TREE.md:26-31, 55-57, 105-107, 174-176, 232-236, 254-261, 270-272, 282-284` | Explainer: 4th scalar is `H(pqc_pk)`, "verifier provides the expected `H(pqc_pk)` as a public input" (`:235`). |
| S4 | `docs/POST_QUANTUM_CRYPTOGRAPHY.md:148-152, 291-302, 351-362, 723-742, 1134-1136, 1206-1214, 1286-1288` | Leaf tuple, "commit `H(pqc_pk)` as the 4th scalar" (`:361`), security argument (`:723-742`). |
| S4 | `docs/PQC_MULTISIG.md:570-580, 629-634, 657-664, 1602-1604, 1849-1853, 2015-2028, 2223-2225` | Multisig container hashed to the leaf; `:631` says 0x07 is "32 B (hash of full container)" (per-tx it is `32·N`). |
| S4 | `docs/AUDIT_SCOPE.md:16-20, 31-33, 39-42, 45-55, 207-209, 233-235, 275-277` | Audit scope: "circuit correctly constrains 4th leaf scalar = `H(pqc_pk)`", "no information leakage about `pqc_pk` beyond the hash value" (`:55`). |
| S4 | `docs/CRYPTOGRAPHIC_INVENTORY.md:40-42, 277-279, 287-289` | CBOM: `DOMAIN_PQC_LEAF` mech-4; leaf gate description; "hashes the full canonical `HybridPublicKey`". |
| S4 | `docs/LMDB_SCHEMA.md:869-871, 957-959` | `curve_tree_leaves` / `pending_tree_leaves` value = 128 bytes, 4×32 scalars. (Coverage-gated by `check_lmdb_schema_coverage.py` — table presence, not value content.) |
| S4 | `docs/MID_REWIRE_HARDENING.md:166-168` | Precomputed path entries carry PQC-key hashes. |
| S4 | `docs/design/CT2_DRAIN_ORDER.md:52-54, 102-104, 120-122, 139-152` (table: coinbase `h_pqc` derivation `:150`; where the tree reads it `:151` — records CEN-I19 retirement of the fallback), `:155-174` (§3.1 "`h_pqc` is on-chain, not recomputable" — `:161-163` still states the zero-fallback contract), `:192-202, 218-220, 335-340, 444-446, 494-507, 589-594, 599-651` | The replication spec for the wallet's leaf builder. |
| S4 | `docs/design/CURVE_TREE_CLIENT.md:94-96, 109-116, 163-165, 174-176, 258-260, 330-332, 352-354, 397-421` (`:402-410` "`h_pqc` is an additional public input … zero-fallback"), `:471-473, 1181-1188, 1314-1330, 1415-1450` | Client design + inlined test code. |
| S4 | `docs/design/PHASE_2A_SEND_PATH.md:211-214, 220-222, 230-232, 262-264, 459-461, 644-650, 793-795, 872-874, 1095-1097, 1720-1722, 1836-1838` | Send-path design: `SpendInput.h_pqc`, C3 precondition recompute. |
| S4 | `docs/design/GENESIS_TX_WIRE_FORMAT.md:772-774` (0x07 = `varint(len) · h_pqc[32] × n_outputs`, `h_pqc = Blake2b(pqc_pk)`, CEN-I19), `:1023-1028` | Genesis wire spec. |
| S4 | `docs/design/CONSENSUS_RULE_CENSUS.md:450-454` (CEN-I15: per-input leaf hashes are "the in-circuit 4th leaf scalar"; CEN-I17), `:532-534` (CEN-L11), `:937-969` (CEN-I19 narrative: zero-`h_pqc` leaf spendable only by a Blake2b preimage of zero) | Consensus rule register (load-bearing). |
| S4 | `docs/design/CONSENSUS_STORE_RECONCILIATION.md:404-406` (CEN-L10/L11/L12 review rows), `:565-567` (CEN-I19 re-review) | Reconciliation register. |
| S4 | `docs/design/REWARD_EMISSION_LEG.md:434-438, 807-809` (**"Leaf extra-scalars are publicly enumerable, so this reveal deterministically…"** — the doc already names the enumerability), `:1016-1018`; `docs/design/REWARD_EMISSION_VIN_PLAN.md:147-151, 217-225, 288-290, 582-584, 667-669, 755-757, 1006-1008` | Emission vin: recompute-`H(pqc_pk)`-and-equate (C-1). |
| S4 | `docs/design/ARCHIVAL_FIREWALL_GATE6.md:561-563, 782-784, 901-911, 965-968, 3697-3699`; `docs/design/ARCHIVAL_CHALLENGE_MECHANISM.md:940-942`; `docs/design/ARCHIVAL_DRAIN_SEND_FD2.md:585-587`; `docs/design/ARCHIVAL_PASS_RECORD_CARRIER.md:227-229`; `docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md:239-241, 562-564, 1441-1456, 1490-1492, 2064-2066, 2089-2091` (`h_pqc` from 0x07 is KEEP-D replay input; `curve_tree_leaves` 128 B is CACHE); `docs/design/ARCHIVAL_RESPONSE_FORMAT.md:1231-1233, 1256-1258, 1285-1287, 1316-1318, 1343-1345, 1365-1371, 1394-1396, 1412-1414`; `docs/design/ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md:91-93, 118-120, 178-180, 189-191`; `docs/design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md:404-406`; `docs/design/ARCHIVAL_SHARD_FETCH.md:150-152, 521-523`; `docs/design/ARCHIVAL_SHARD_SELECTION_LIST.md:33-35`; `docs/design/ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:535-537`; `docs/design/ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md:109-111` | Archival designs: leaf width, `LEAF_BYTES`, leaf gate order, replayability of `h_pqc`. |
| S4 | `docs/design/DAEMON_RELAY_PRIVACY.md:12243-12245, 12341-12343, 12353-12356` | Relay: "the PQ commitment is a hash bound into the proof, not a signature checked beside it". |
| S4 | `docs/design/SIGNATURE_ALIGNMENT.md:487-489, 504-507, 532-534, 581-583`; `docs/design/V3_1_MULTISIG_RUST_ENGINE.md:171-173, 287-289, 401-403, 612-614` (R1-F-2: "Leaf change REJECTED … not free"), `:630-632, 668-670, 800-802, 824-826, 1019-1023, 1203-1205` | SA-3a SSOT history; **prior ruling that a leaf-preimage change was rejected (F-2 retraction)** — a new round must cite/supersede it. |
| S4 | `docs/design/SUBADDRESS_UNDER_PQC.md:1355-1357`; `docs/design/FA-6_VIEW_TAG_ML_KEM.md:158-160` (classifies `h_pqc` as "Public"); `docs/design/SP_T3_SKELETON_MEASUREMENT.md:348-354`; `docs/design/WALLET_REWRITE_PLAN.md:428-430, 498-500`; `docs/design/IMPLEMENTATION_INDEX.md:116-118, 142-144` (RF-D4 `LEAF_BYTES`; SA-3a/3b rows) | Cross-references. |
| S4 (record) | `docs/completed/CONSENSUS_RULE_CENSUS_2.md:336-339, 354-356`; `docs/completed/CONSENSUS_RULE_CENSUS_3.md:339-341, 419-421`; `docs/completed/CT1_ROUND1_CLOSEOUT.md:17-19`; `docs/completed/CT2_ROUND1_CLOSEOUT.md:40-42, 59-62, 88-96`; `docs/completed/CT3_SYNC.md:328-330`; `docs/completed/CT4_ROUND1_CLOSEOUT.md:23-25, 52-54`; `docs/completed/CT5C_ASSEMBLER_CUTOVER.md:34-36, 49-51, 66-68, 79-81, 471-474`; `docs/completed/CT5_ENGINE_WIRING.md:24-26, 203-205, 307-309, 361-363, 409-411, 802-808, 1204-1211, 1253-1264, 1315-1333, 1457-1459, 1572-1574, 1690-1697, 1756-1758`; `docs/completed/FCMP_MEMBERSHIP_ONLY.md:25-27, 53-55, 345-348, 356-358, 366-368`; `docs/completed/SHEKYL_OXIDE_UNVENDOR.md:95-97, 106-108` (fcmps "PRISTINE (not forked)" — the extra-leaf machinery is *in the pin*); `docs/completed/STAGE_1_PR_3_M3C_PREFLIGHT.md:256-258`; `docs/completed/STAGE_1_PR_3_MIGRATION_PLAN.md:440-442`; `docs/completed/STAGE_2_KEY_ENGINE_ACTOR.md:826-828`; `docs/audit_trail/RESOLVED_260419.md:486-488`; `docs/CHANGELOG.md` (62 hits; dated records — e.g. `:636-638` CEN-I19, `:3687-3699` RAW_PK KAT relocation, `:5084-5092` transfer-path 0x07 gap, `:26948-26950` testnet reset, `:26997-27000` KAT birth, `:27639-27641` wide-reduce fix, `:28195-28229` tag birth) | Completed/records — not asserts-is; no edit owed, but they document the lineage the round must not contradict. |
| S4 | `.cursor/rules/*` | **No rule mentions `h_pqc`, `0x07`, the 4th scalar, or `H(pqc_pk)`** (`git grep` over `.cursor` = ∅). |

### S5 — tests / benches / fuzz that exercise the 4th scalar

| Sev | Class | file:line | Note |
|---|---|---|---|
| S5 | circuit | `rust/shekyl-oxide/crypto/fcmps/src/tests.rs:87-98` (`random_h_pqc`, `flatten_output_scalars` = `[O.x,I.x,C.x,h_pqc]`), `:101-212` (`random_path` extras), `:220-302, 393-398`, `:591-597` (`input_with_h_pqc`), `:602-616, 630-651, 690-707`, **`:757-789` `test_wrong_h_pqc_fails`** (negative: wrong public value must not verify), `:793-852` benches | Random 4th scalar; manifest-pinned (`:37`). |
| S5 | fcmp-proofs | `rust/shekyl-fcmp-proofs/src/tests/mod.rs:46-154`; `rust/shekyl-fcmp-proofs/src/tests/membership_only.rs:58-74, 84-133, 225-229, 254-258, 277-281, 336-342, 377-381, 530-620, 687-691, 709-713, 738-742, 782-786` | Random `h_pqc` through `InputVerification`/`pqc_pk_hashes`. |
| S5 | shekyl-fcmp | `rust/shekyl-fcmp/src/leaf.rs:98-198` (10 unit tests: determinism, canonical field element, 128-byte layout, `[96..128]` round-trip), `rust/shekyl-fcmp/src/tree.rs:611-634, 707-728, 794-834, 851-853`, `rust/shekyl-fcmp/src/proof.rs:1298-2163` (prove/verify round-trips with random `h_pqc`, count/depth negatives `:1351-1371, 1857-1877`), `rust/shekyl-fcmp/tests/curve_tree_freeze.rs:65-69, 139-193, 241-245, 653-657, 753-983` (4-scalar leaf streams) | Layout + prove/verify. |
| S5 | fuzz | `rust/shekyl-fcmp/fuzz/fuzz_targets/fuzz_curve_tree_leaf_hash.rs:11-41` (**`:33` calls `construct_leaf(&output_key, &commitment)` with 2 args — stale, see §6 (d)-1**), `rust/shekyl-fcmp/fuzz/fuzz_targets/fuzz_block_header_tree_root.rs:30-38, 50-54`, `rust/shekyl-fcmp/fuzz/fuzz_targets/fuzz_fcmp_proof_deserialize.rs:22-26, 59-63`, `rust/shekyl-fcmp/fuzz/fuzz_targets/fuzz_tx_deserialize_fcmp_type7.rs:11-16, 52-65`; `rust/shekyl-fcmp/fuzz/Cargo.toml:21-25`; inventory gate `.github/workflows/rust-audit-test.yml:186-208` (file-presence only) | |
| S5 | crypto-pq | `rust/shekyl-crypto-pq/src/derivation.rs:356-380, 406-456, 478-510` (cross-entry-point agreement), `:525-549, 574-602` (KATs); `rust/shekyl-crypto-pq/src/output.rs:1469-1503, 1831-1836, 1898-1973` (`h_pqc_matches_hybrid_pk_hash` — asserts NOT ml-dsa-only, matches `derive_pqc_leaf_hash`), `:2015-2019`; `rust/shekyl-crypto-pq/src/multisig.rs:958-978`; `rust/shekyl-crypto-pq/tests/scan_output_kat.rs:62,154,292-296`; `rust/shekyl-crypto-pq/tests/trybuild/enc_fields_cannot_be_literal_constructed.rs:27-31`; `rust/shekyl-crypto-pq/benches/pqc_rederivation.rs:15-69` | Derivation invariants. |
| S5 | wire | `rust/shekyl-wire/src/tx_extra.rs:570-691` (`pqc_field_shape` tests incl. `rick_s_vectors_are_refused`), `rust/shekyl-wire/tests/tx_extra_roundtrip.rs:12-16, 47-54, 74-78, 195-200`, `rust/shekyl-wire/tests/validation.rs:560-603` (duplicate / wrong-length 0x07 refusals), `rust/shekyl-wire/tests/common/mod.rs:6-27`, `rust/shekyl-wire/tests/fcmp_spend_e2e.rs:79-83, 247-298, 345-359, 448-490` (real tree, real `h_pqc`, `proof::verify` with `PqcLeafScalar(spent.h_pqc)`) | |
| S5 | curve-tree | `rust/shekyl-curve-tree/src/recon.rs:243-292, 325-329, 378-416` (zero-fallback + `[96..128]` verbatim tests), `rust/shekyl-curve-tree/src/client.rs:1084-1108, 1343-1403, 1465-1506` (`ingest_resolves_h_pqc_from_blob`), `rust/shekyl-curve-tree/src/store/ops.rs:153-170`, `rust/shekyl-curve-tree/src/store/redb_backend.rs:2308-2312, 2893-2919, 3135-3146, 3602-3606, 3696-3700`, `tests/{assemble_kat,recon_kat,recon_tier_b,store_kat,upper_layers_kat}.rs` (S1 consumers; `rust/shekyl-curve-tree/tests/recon_tier_b.rs:225-232` `#[ignore]`+`todo!`) | |
| S5 | ffi | `rust/shekyl-ffi/src/legacy_tests.rs:269-276, 598-738`; `rust/shekyl-ffi/tests/leaf_gate_agreement.rs:7-25, 88-111, 163-165` (`construct_leaf(.., &[0u8;32])` — gate/leaf agreement, content-agnostic); `rust/shekyl-ffi/tests/signing_round_trip.rs:11-15, 110-114, 152-156, 180-184, 218-270, 276-290, 335-373, 517-521` (full C-ABI create→scan→leaf→prove→verify with real `h_pqc`; `:366` passes `h_pqc` as `hp_of_O`); `rust/shekyl-ffi/tests/block_connect_pins.rs:108-112`; `rust/shekyl-ffi/benches/relay_admission_fixture.rs:27-28, 64-67, 141-158, 181-183, 272-292, 307-327, 353-357`, `rust/shekyl-ffi/benches/relay_admission_verify.rs:24-28`, `rust/shekyl-ffi/benches/block_connect_fixture.rs:218-222`; `rust/shekyl-ffi/src/archival_ffi/tests.rs:1646-1650, 1761-1772`; `rust/shekyl-ffi/src/curve_tree_replica_ffi.rs:359-365` | |
| S5 | engine-core | `rust/shekyl-engine-core/src/engine/local_keys_tests.rs:112-139` (`make_synthetic_h_pqc_bytes` — doc `:118-121` "the FCMP++ verifier accepts any consistent `h_pqc` because the proof binds `pqc_pk_hashes` as a public input"), `:706-729, 760-763, 867-880, 909-913, 994-1029, 1123-1140, 1215-1219, 1278-1305, 1407-1424`; `rust/shekyl-engine-core/src/engine/synthetic_tree.rs:16-27, 29-105`; `rust/shekyl-engine-core/src/engine/tx_weight_kat.rs:9-13, 66-87`; `rust/shekyl-engine-core/src/engine/transfer/transfer_pending_tx_tests.rs:448-515, 2292-2299, 2342-2346, 2416-2436, 2495-2552`; `rust/shekyl-engine-core/src/engine/proofs_tests.rs:446-450`; `rust/shekyl-engine-core/src/engine/pscan/scan_step_tests.rs:72-78`; `rust/shekyl-engine-core/src/engine/refresh/start_refresh_integration_tests.rs:1324-1379`; `rust/shekyl-engine-core/src/engine/regtest_e2e.rs:1472-1476, 1483-1487, 3949-3960`; `rust/shekyl-engine-core/src/engine/claim_orchestrator.rs:537-603` (test); `rust/shekyl-engine-core/src/engine/stake_engine/test_fixtures.rs:52-89` (REAL `h_pqc` load-bearing for the leaf gate); `rust/shekyl-engine-core/src/engine/stake_engine/serve_set_source_tests.rs:152-156`; `rust/shekyl-engine-core/src/engine/test_support.rs:980-986`; `rust/shekyl-engine-core/src/engine/curve_tree_decode.rs:209-217, 252-284, 343-346` | |
| S5 | daemon-rpc | `rust/shekyl-daemon-rpc/tests/submit_verifier.rs:282-327, 377-391` (real tree; decoys share the spent `h_pqc`), `rust/shekyl-daemon-rpc/tests/submit_fixtures/mod.rs:211-215, 478-484` | |
| S5 | archival | `rust/shekyl-archival-retention/tests/assembled_path_crosscheck.rs:12-16, 54-58, 107-123, 163-167, 198-202`; `rust/shekyl-archival-retention/tests/emission_connect_kat.rs:26-30, 55-59, 77-81`; `rust/shekyl-archival-retention/tests/emission_verify_kat.rs:29-33, 167-171, 585-589, 648-652, 695-699` (leaf-gate negatives); `rust/shekyl-archival-retention/tests/gate2_serve_credit_kat.rs:28-32, 406-432, 464-468, 514-518, 945-949`; `rust/shekyl-archival-retention/tests/kat_emission_auth_msg.rs:104-108`; `rust/shekyl-archival-retention/src/emission_wire.rs:823-827` (test) | |
| S5 | p-serve / p-host / tx-builder | `rust/shekyl-p-serve/src/serve_tests.rs:10-14, 37-46, 59-68, 80-84, 378-383, 436-440`, `rust/shekyl-p-serve/tests/store_axis.rs:18-22, 40-44, 117-122`; `rust/shekyl-p-host/tests/composition.rs:23-26, 55-59, 466-470, 664-668, 1064-1068`; `rust/shekyl-tx-builder/src/tests.rs:22-26, 35-39, 362-366` | Layout / dummy `[3u8;32]`. |
| S5 | C++ | `tests/unit_tests/fcmp.cpp:432-476` (`multisig_pqc_leaf_hash_via_ffi`), `:519-531` (`per_output_pqc_leaf_hash_derivation_consistency`); `tests/unit_tests/json_serialization.cpp:99-103, 133-137, 148-152, 199-203, 279-283, 314-328, 416-420` (end-to-end; `:316` `hp_of_O` = `h_pqc`); `tests/unit_tests/tx_extra_pqc_field_shape.cpp:9-13, 59-70, 155-179, 222-226, 244-292` (13 wired tests incl. `db_collector_refuses_a_short_leaf_hash_field_instead_of_zero_filling`); `tests/unit_tests/test_tx_utils.cpp:362-488`; `tests/unit_tests/mining_parity.cpp:312-315`; `tests/unit_tests/deferred_insertion.cpp:44-74, 89-306, 417-421` and `tests/unit_tests/pending_tree_fuzz.cpp:45-235` (local `LEAF_BYTES = 128`, synthetic leaves); `tests/unit_tests/pqc_spend_fixture.h:64-93, 161-164`; `tests/unit_tests/pruned_tx_hash_parity.cpp:189-192`; `tests/unit_tests/archival_substrate_lmdb.cpp:2912-2916`; `archival_serve_credit_{equivalence,integration}.cpp:553-557 / 392-396`; `tests/unit_tests/tx_prunable_region_sole_occupant.cpp:325-329`; `tests/core_tests/chaingen.cpp:323-382` (replica feed), `:753-771, 881-899` (scan), `:1522-1576, 1659-1676` (constructs 0x07 from `od.h_pqc`) | |

---

## 2. Count summary

**Unit.** One table row = one *site group*: a function / struct / const / KAT
fixture / doc that reads, writes, computes, serializes, stores, verifies or
documents the 4th scalar. A row's file cell may list several `file:line` ranges
when they are one construct split across files (e.g. the RPC path-serving chain,
or one C++ function with three hit ranges), so **rows ≠ raw hits and rows ≤ sites**.
The figures below are **counted from the table above** (rows per band; distinct
files named in each band's file column), not estimated.

| Band | Rows (site groups) | Distinct files named in the file column |
|---|---|---|
| S0 consensus/wire | 74 | 62 |
| S1 KATs / pins / gates | 19 (3 class-a fixtures, 6 class-b, 4 class-c, 2 firing gates, 2 non-firing gates, 2 fixture-generator/consumer rows) | 28 |
| S2 wallet/engine | 22 | 44 |
| S3 FFI/ABI headers | 7 | 5 |
| S4 docs | 22 (21 asserts-is/record doc rows + 1 `.cursor/rules` null row) | 52 |
| S5 tests/benches/fuzz | 14 | 76 |
| **Total** | **158 rows** | **256 distinct file references** (a file can appear in more than one band) |

Raw sweep for calibration: 2,745 grep hits in 220 tracked files (symbol families
from the brief plus the aliases discovered while reading; `rust/target` and
non-fcmps `shekyl-oxide` excluded); 820 of those hits are the two
`ct2_tier_*.json` fixtures. Files reached only by follow-up probes (manifest,
CMakeLists, workflows, fixtures) are in the table but not in the 220.

---

## 3. Domain separators / HKDF labels on the PQC-key → leaf path

| String | Mechanism | Definition | Registry row |
|---|---|---|---|
| `shekyl-pqc-leaf` | Blake2b-512 DST (mech 4) | `rust/shekyl-crypto-pq/src/derivation.rs:32` `DOMAIN_PQC_LEAF`; used `:71` | `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:182` |
| `shekyl-kem-v1` | HKDF-SHA-512 salt (combine X25519‖ML-KEM → `combined_ss`) | `rust/shekyl-crypto-pq/src/kem.rs:47` `KEM_DOMAIN_SALT`; `combine_shared_secrets` `:275-279` | `:129` |
| `shekyl-output-derive-v1` | HKDF salt (Instance 1, `derive_output_secrets`) | `rust/shekyl-crypto-pq/src/derivation.rs:157` `HKDF_SALT_OUTPUT_DERIVE`; `:231` | `:133` |
| `shekyl-pqc-output` ‖ `idx_le64` | HKDF info → `ml_dsa_seed` (32 B) | `rust/shekyl-crypto-pq/src/derivation.rs:178` `LABEL_OUTPUT_PQC`; formula `:198` | `:151` |
| `shekyl-pqc-ed25519` ‖ `idx_le64` | HKDF info → `ed25519_pqc_seed` (32 B) | `rust/shekyl-crypto-pq/src/derivation.rs:179` `LABEL_OUTPUT_PQC_ED25519`; formula `:199` | `:152` |
| `shekyl-output-kem-v1` | HKDF salt (Instance 3, deterministic KEM seed from tx_key — sender side) | `rust/shekyl-crypto-pq/src/derivation.rs:166` `SALT_KEM_DERIVE_V1` | `:135` |
| `shekyl-view-tag-prefilter-v1` / `shekyl-view-tag-prefilter` | HKDF salt/info (Instance 2; sibling of the same `combined_ss`, not on the leaf path) | `rust/shekyl-crypto-pq/src/derivation.rs:160,180` | — |
| `shekyl-master-derive-v1` / `shekyl-ml-kem-768` | HKDF salt/info for the account-level ML-KEM key (upstream of `combined_ss`) | `kem.rs` (`HKDF_SALT_MASTER_DERIVE`), `account.rs` (`KEM_INFO`) | `:131, 139, 142` |
| `version(1) ‖ scheme_id=1 ‖ reserved(2) ‖ ed_len(4)` header | Canonical `HybridPublicKey` encoding that is the hash preimage (not a DST, but part of what `h_pqc` commits to) | `rust/shekyl-crypto-pq/src/signature.rs:139-162` (`HYBRID_SCHEME_ID_ED25519_ML_DSA_65 = 1` at `:66`) | — |
| `shekyl/pqc-auth-tx-v1`, `shekyl/pqc-auth-tx-multisig-v1` | cSHAKE scheme domains for the *signature* over the tx (adjacent, not in the leaf hash) | `rust/shekyl-crypto-pq/src/signature.rs:77, 90` | `:114, 115` |
| `shekyl/archival-emission-backing-scheme-v1` | Auth-B signature domain under the backing pubkey whose hash is the leaf value | `rust/shekyl-crypto-pq/src/signature.rs:94` | (mech 1 row) |

Any new label for an opening `r` (e.g. `shekyl-pqc-leaf-blind`) must be added as
a mech-2 (HKDF) row keyed `salt|info`, and any new Blake2b/cSHAKE commitment DST as
its own row — the CI gate will not detect the omission (`scripts/ci/domain_registry_gate.sh:100-107`),
only `rust/shekyl-crypto-pq/tests/domain_registry.rs::PRODUCTION_PINS` distinctness once the row exists.

---

## 4. Test-vector JSON under `docs/test_vectors/` that contain `h_pqc` / leaf values

| File | Contains | Class |
|---|---|---|
| `docs/test_vectors/PQC_LEAF_HASH_KAT.json` | 8 × `h_pqc` (derived from `combined_ss`, `output_index`) | (a) |
| `docs/test_vectors/PQC_LEAF_HASH_RAW_PK_KAT.json` | 4 × `(pqc_pk, h_pqc)` raw-pk pins | (a) |
| `docs/test_vectors/PQC_SCAN_OUTPUT_KAT.json` | 2 × `h_pqc` inside full constructed-output vectors | (a) |
| `docs/test_vectors/WITNESS_HEADER.json` | `h_pqc` at offset 96 (dummy values) | (c) |
| `docs/test_vectors/TX_EXTRA_PQC_ROUND_TRIP.json` | 0x07 tag, `PQC_LEAF_HASH_BYTES = 32`, pattern payloads | (c) |
| `docs/test_vectors/EMISSION_AUTH_MSG_V1/vectors.json:20` | `pqc_pk_hash` (dummy 0x33) inside the auth-message preimage | (c) |
| `docs/test_vectors/PQC_OUTPUT_SECRETS.json:5` | mentions `shekyl-kem-v1` in prose only (no `h_pqc` values) | — |

Not under `docs/test_vectors/` but equally frozen: `ct2_tier_{a,b}.json`,
`golden_kat.rs` constants, and the four archival `*_kat_v1.json` fixtures (S1 table).

---

## 5. CI gates that would fire on a leaf-content change

| Gate | Fires? | Why |
|---|---|---|
| `vendored-crypto-content.yml` → `check_vendored_crypto_manifest.sh` | **Yes** if `fcmps/src/{circuit,lib,prover/mod,tests,tree}.rs` change (`rust/shekyl-oxide/CRYPTO_CONTENT_MANIFEST.sha256:29-38`) | must `--update` as a sanctioned event |
| `.github/workflows/grep-gates.yml:133` → `domain_registry_gate.sh` | **Yes** on rename/move of `DOMAIN_PQC_LEAF` / `shekyl-pqc-leaf`; **No** on a new unregistered domain | honest scope |
| `.github/workflows/rust-audit-test.yml:403` `cargo test --workspace` | **Yes** — every (a)/(b) KAT reddens | |
| C++ `unit_tests` (`tx_extra_pqc_field_shape`, `archival_serve_credit_*`, `json_serialization`, `fcmp`) | **Yes** for (b) archival fixtures and any width change | CMake fixture paths `tests/unit_tests/CMakeLists.txt:209-235` |
| `schema-snapshot.yml` (rule 42) | **No** — nothing under `shekyl-engine-state/schemas` carries `h_pqc` | curve-tree redb `SCHEMA_VERSION = 4` and LMDB `VERSION 13` are manual duties |
| `check_golden_revision_bump.py` | **No** — shard-visual PNGs only | false positive of the "golden" search |
| `.github/workflows/rust-audit-test.yml:186-208` fuzz inventory | **No** — checks file presence only; does not compile the fuzz crate | see (d)-1 |
| `docs-gates.yml` (`check_doc_code_citations.py` etc.) | **Yes** for any doc citation whose `file:line` moves | the ~180 S4 passages |

---

## 6. (d) Findings outside the asked scope

1. **Dead/stale fuzz target.** `rust/shekyl-fcmp/fuzz/fuzz_targets/fuzz_curve_tree_leaf_hash.rs:33`
   calls `construct_leaf(&output_key, &commitment)` with two arguments; the function
   has taken three since the `h_pqc_ptr` parameter was added (`rust/shekyl-fcmp/src/tree.rs:506-510`;
   CHANGELOG `:28287-28289`). The fuzz crate is not built anywhere in CI — the only
   gate is the file-presence "smoke gate" (`.github/workflows/rust-audit-test.yml:186-208`) — so the
   target has been uncompilable without detection. `docs/FCMP_PLUS_PLUS.md:1372,1388`
   still advertises it as a live harness.
2. **Misnamed JSON field on the legacy sign bridge.** `rust/shekyl-ffi/src/legacy_tx.rs:306`
   fills `SpendInput.h_pqc` from `inp.hp_of_O` (declared `:170-171`), while the
   struct's own `h_pqc` field (`:179-180`) is parsed and never read
   (`#[allow(dead_code)]` on the struct at `:162`). Every caller compensates by passing the same hex for both
   (`tests/unit_tests/json_serialization.cpp:316,321`;
   `rust/shekyl-ffi/tests/signing_round_trip.rs:366,371`;
   `src/shekyl/shekyl_ffi.h:1441-1444` documents both). Any change to what the 4th scalar
   carries must fix the name or it will silently route the wrong value.
3. **Wallet replica retains the zero-fallback the daemon retired.**
   `rust/shekyl-curve-tree/src/recon.rs:26-28` (`ZERO_PQC`, comment "Mirrors the C++
   `zero_pqc` fallback"), `:71-76` (`per_output_h_pqc`), `:54-69`
   (`extract_leaf_hashes` returns empty on `%32≠0`), `rust/shekyl-curve-tree/src/client.rs:759`,
   `rust/shekyl-engine-core/src/engine/curve_tree_decode.rs:43-47,113-116` still zero-fill, while C++
   (`src/blockchain_db/blockchain_db.cpp:522-546`, CEN-I19, 2026-09-06) now aborts. Unreachable on an
   admitted chain, but the "faithful port" comments and `docs/design/CT2_DRAIN_ORDER.md:161-163`
   / `docs/design/CURVE_TREE_CLIENT.md:410` still state the fallback as the contract; `docs/FOLLOWUPS.md`
   has no entry for it (grep `zero.?fallback|per_output_h_pqc|0x07` = ∅). The
   Tier-B adversarial parity oracle is `#[ignore]`+`todo!`
   (`rust/shekyl-curve-tree/tests/recon_tier_b.rs:225-232`).
4. **Stale "zero placeholder" contracts.** `rust/shekyl-fcmp/src/tree.rs:504-505` ("Pass `&[0u8;32]` for
   outputs that have no PQC key commitment"), `rust/shekyl-ffi/src/legacy_curve_tree.rs:514`,
   `src/shekyl/shekyl_ffi.h:1389` ("or 32 zero bytes if unavailable"), and
   `rust/shekyl-ffi/tests/leaf_gate_agreement.rs:90,106,165` (uses `&[0u8;32]` as the 4th input) predate
   CEN-I19; a zero 4th scalar is no longer an admissible leaf on any path.
5. **`docs/FCMP_PLUS_PLUS.md` describes a stake-claim leaf cross-check that no longer
   exists.** `:1172-1174` ("`leaf[96:128] == shekyl_fcmp_pqc_leaf_hash(pqc_pk)`"),
   `:1196-1198`, `:1253-1255` (its birth is a dated record at
   `docs/CHANGELOG.md:28226-28229`) — `git grep stake_claim -- src` is empty; the
   cross-check lived in the retired claim-era code. Also `:1110-1135`
   proposes a 5-scalar staking-subtree leaf with per-tree `SCALARS_PER_LEAF` — no
   code exists for it.
6. **Doc says ML-DSA-only preimage; code hashes the full hybrid key.**
   `docs/FCMP_PLUS_PLUS.md:73` (`shekyl_fcmp_pqc_leaf_hash(ml_dsa_pk)`), `:530-531,548-550`
   (`extract_ml_dsa_pk`), `:1111`, `:1822` ("H(ml_dsa_pk)"); `docs/design/GENESIS_TX_WIRE_FORMAT.md:773,1028`
   (`Blake2b(pqc_pk)`). Code: `rust/shekyl-crypto-pq/src/output.rs:1410-1434` and the test
   `h_pqc_matches_hybrid_pk_hash` (`:1913-1934`) assert the preimage is the canonical
   `HybridPublicKey` (Ed25519 ‖ ML-DSA), `docs/CRYPTOGRAPHIC_INVENTORY.md:287-289` says so
   correctly.
7. **Doc FFI locations stale.** `docs/FCMP_PLUS_PLUS.md:599-601` places
   `shekyl_fcmp_pqc_leaf_hash` / `shekyl_derive_pqc_leaf_hash` in `shekyl-ffi/src/lib.rs`;
   they are in `rust/shekyl-ffi/src/legacy_fcmp.rs:39,63`. `docs/design/CT2_DRAIN_ORDER.md:193` cites
   lines 2972 and 3002 of `shekyl-ffi`'s crate root (`src/lib.rs`) for `shekyl_construct_curve_tree_leaf`; that
   file is 187 lines at this sha, so the cite cannot resolve — the symbol is at
   `rust/shekyl-ffi/src/legacy_curve_tree.rs:526`. `docs/PQC_MULTISIG.md:631` states 0x07 is "32 B (hash of
   full container)" (it is `32·N` per tx). `rust/shekyl-daemon-rpc/src/submit/verifier.rs:1009` cites
   `src/cryptonote_core/blockchain.cpp:3810-3820`; the arms are at `:3782-3783`, `:4091-4092`, `:4211-4212`.
8. **Three independent `LEAF_BYTES = 128` declarations outside the derived one.**
   ~~`rpc_path.rs:25`~~ (deleted 2026-09-18, `SOK-10` Q7 → A), `rust/shekyl-sp-t3-spike/src/fixture.rs:68`
   (bare `128`), `tests/unit_tests/{deferred_insertion,pending_tree_fuzz}.cpp:46-47`
   (bare `128`), C++ `kLeafSize = 128` (`src/blockchain_db/shekyl_types.h:144`) vs the derived
   `rust/shekyl-curve-tree/src/segment.rs` `LEAF_BYTES` (`SCALARS_PER_LEAF * 32`, asserted `== 128`) and
   `rust/shekyl-archival-retention/src/path.rs:57`. A width change would have to touch all of them;
   `docs/design/ARCHIVAL_RESPONSE_FORMAT.md:1365-1371` claims `LEAF_BYTES` has one home.
9. **Where `h_pqc` is publicly enumerable today (the linkage surfaces a hiding
   commitment would have to close).** (i) tx_extra 0x07 at creation — every node;
   (ii) `tx.pqc_auths[i].hybrid_public_key` at spend — every node, and the
   recomputed hash is logged at `src/cryptonote_core/blockchain.cpp:4225`; (iii) the emission vin's
   `backing.pqc_pk_hash` + `backing_pubkey` (`rust/shekyl-archival-retention/src/emission_wire.rs:154-157`) — every
   node, per epoch; (iv) `get_curve_tree_path` `chunk_outputs` (`fcmp/src/rpc_path.rs:94`,
   `rpc/core_rpc_server.cpp:1560` at `8494f2a27`) — RPC clients — **surface removed 2026-09-18 (`SOK-10` Q7 → A); this leg no longer exists**; (v) served archival shards
   (`rust/shekyl-curve-tree/src/store/redb_backend.rs:411-420`, `served_frame.rs`) — P2P; (vi) the wallet's own
   leaf-meta table stores a second copy (`rust/shekyl-curve-tree/src/store/redb_backend.rs:2183`).
   `docs/design/REWARD_EMISSION_LEG.md:807-809` already states "leaf extra-scalars are publicly
   enumerable, so this reveal deterministically…" and `rust/shekyl-crypto-pq/src/output.rs:786-788` classifies
   `h_pqc` as "a wallet fingerprint". `docs/design/FA-6_VIEW_TAG_ML_KEM.md:159` classifies it as
   simply "Public / no clustering".
10. **A prior ruling rejected changing the leaf preimage.** `docs/design/V3_1_MULTISIG_RUST_ENGINE.md:612-614`
    (R1-F-2 retraction: "Leaf change REJECTED … not free, not needed") and `:800-802`.
    The new round must cite and supersede this under rule 21, or it reads as a
    contradiction of a recorded disposition.
11. **The public-input property is documented as a *feature* in tests.**
    `rust/shekyl-engine-core/src/engine/local_keys_tests.rs:113-125, 706-712` explain that any consistent synthetic
    `h_pqc` verifies "because the proof binds `pqc_pk_hashes` as a public input rather
    than re-deriving it from a real PQC public key in-circuit". These comments (and
    `rust/shekyl-engine-core/src/engine/synthetic_tree.rs:18-27`, `rust/shekyl-engine-core/src/engine/tx_weight_kat.rs:68`) become false if the design moves
    the opening in-circuit.
12. **`PqcCommitmentMismatch`** (`rust/shekyl-fcmp/src/proof.rs:1020,1048,1141,1161`; C ABI code 3 in
    `src/shekyl/shekyl_ffi.h:490,518`, `rust/shekyl-ffi/src/legacy_fcmp.rs:358,478`) is already named as if the 4th
    scalar were a commitment; the *count* mismatch and the *non-canonical scalar*
    case share this variant on the full path (`:1019-1020` vs `:1045-1049`), while
    the membership-only path splits them (`InputCountMismatch` `:1138-1141`).
13. **`multisig_pqc_leaf_hash`** (`rust/shekyl-crypto-pq/src/multisig.rs:406-408`) hashes the multisig
    container bytes with the same DST; scheme-2 outputs therefore have a different
    preimage *shape* under one domain (length-separated per MSW-2). A commitment
    design must decide whether `r` derivation is per-scheme.

---

## 7. Matched, excluded, why

| Hit | Why excluded |
|---|---|
| `rust/shekyl-pow-randomx/src/vm.rs:487-492, 1365-1369` ("128 bytes") | RandomX program entropy buffer. |
| `rust/shekyl-economics-sim/src/proxy.rs:9-13, 68-72` | Prose cost model of the serve-challenge opening ("one 128-byte leaf", `SCALARS_PER_LEAF · SELENE_CHUNK_WIDTH`); numeric only, no code dependency. Would need a re-read only if width changes. |
| `rust/shekyl-cli/src/rpc_client.rs:157-162`, `rust/shekyl-cli/src/validate.rs:8-18` | serde_json buffer / hex length limits. |
| `rust/shekyl-proofs/src/reserve_proof.rs:277-281`, `fuzz_verify_tx_proof_{inbound,outbound}.rs:20-24` | `[96..128]` slices of unrelated 192-byte records. |
| `rust/shekyl-crypto-pq/fuzz/fuzz_targets/fuzz_derive_output_key.rs:21-25` | `[96..104]` slice of fuzz input. |
| `rust/shekyl-archival-retention/src/attestation_wire.rs:233-237` | `input[96..104]` of the attestation nonce preimage. |
| `derivation.rs` `k_label` / `label_tag` / `LABEL_*` hits | HKDF labels for other output secrets (listed in §3 only where on the KEM→PQC path). |
| `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv:22, 98-99` (`archival-serve-challenge-leaf`) | "leaf" here is the challenged leaf *index* customization, not the 4th scalar. |
| `rust/shekyl-chain-store/src/accumulator/set.rs`, `digest_v0.rs` ("XOR leaf") | Accumulator leaves, unrelated. |
| `docs/design/ARCHIVAL_RESPONSE_FORMAT.md`, `ARCHIVAL_SHARD_FETCH.md` `LEAF_BYTES` passages | Kept in S4 as width-only. |
| `scripts/ci/check_golden_revision_bump.py` | Shard-visual PNG oracle (§5). |
| `.github/workflows/rust-audit-test.yml:190` | Fuzz-inventory presence list (§6 (d)-1). |
| `src/shekyl/shekyl_ffi.h:67, 340, 390, 580, 863-910, 2962-3061, 3771, 3982` | `u128` difficulty, SLH-DSA "fourth classical field", 128-byte `proof_secrets` (ho‖y‖z‖k_amount) — unrelated 128s. |

---

## 8. Pre-flight measurements — `PL-D3` opening leg (2026-09-14)

Rule 26 B9: measured, not estimated. Vendored crate `full-chain-membership-proofs`
with the opening leg implemented (uncommitted at measurement time, branch
`feat/pl-d3-pedersen-leaf-commitment` off `dev` a6160a4bd), same box as the
§6.1 baseline of the round document (16-thread i9-11950H, `--release`, other
builds running concurrently — treat the timings as ordering evidence, not
budgets; the rule-76 floor device is still owed).

**Circuit rows (`Circuit::muls()` at the first layer, one input).** 97 before,
**111** after: the opening leg costs **14 rows** (one `discrete_log` gadget over
the new `J` table, one `on_curve`, one `incomplete_add_pub`); the per-input
constant `C1_LEAVES_ROWS_PER_INPUT` is set to 111. With `C1_TARGET_ROWS = 256`
the one-input IPA keeps its padding through 6 layers (215 rows) and crosses to
512 at 7 layers (267 rows); the old circuit crossed at 8 (253 → 8 layers = 305).

**Proof bytes (FCMP part; the SAL leg adds 480 B per input on top).** The
crate's own `proof_size` equals the real `proof.len() + 64` at every (inputs,
layers) the suite proves (`debug_assert_eq` exercised in the debug profile;
release runs printed both). Before → after:

| inputs, layers | before | after | Δ |
|---|---|---|---|
| 1, 3 | 4 288 | 4 416 | **+128** |
| 1, 4 | 4 928 | 5 056 | +128 |
| 1, 5 | 5 312 | 5 440 | +128 |
| 1, 6 | 5 952 | 6 080 | +128 |
| 1, 7 | (5 312 pad-256) | 5 504 (pad-512) | padding regime crosses |
| 1, 8 | 6 976 | 6 144 | −832 |
| 2, 3 | 5 248 | 5 248 | 0 |
| 2, 4 | 6 528 | 6 528 | 0 |
| 4, 3 | 7 104 | 6 848 | −256 |
| 8, 3 | 8 768 | 8 000 | −768 |
| 16, 3 | 11 968 | 10 176 | −1 792 |
| 16, 8 | 22 848 | 20 096 | −2 752 |

Why the multi-input proofs shrink: the leg **replaces** the per-input
one-element "extra leaf scalar" branch (a whole vector commitment plus its `t`
terms) with one claimed point packed into the existing C1 words. The round
document's first figure ("+128 B per input") was right for one input at depth
3 for the wrong reason, and its correction ("+256 B per proof") was wrong
because the replica kept the extra branch; this table supersedes both.

**Prove / verify (crate benches, 8 layers, sequential, n = 10 / n = 100).**

| | before | after |
|---|---|---|
| prove, 1 input | 601 ms | 737 ms |
| prove, 2 inputs | 1 157 ms | 1 400 ms |
| prove, 3 inputs | 1 786 ms | 1 841 ms |
| prove, 4 inputs | 2 079 ms | 2 588 ms |
| verify, 1 proof (n=100) | 25 ms | 31 ms |
| verify, batch of 10 | 100 ms | 105 ms |
| verify, batch of 100 | 849 ms | 833 ms |

At 8 layers the one-input C1 IPA crosses from 256 to 512 rows, which is most of
the one-input prove delta; at ≤6 layers the padding is unchanged and the delta
is one leg's work. Verify moves by a few milliseconds per proof; batch
verification is within noise.

**Correctness.** All eight crate tests pass in release (single input at 1–9
layers, 2–4 inputs at 1–4 layers, the malleated-proof suite, the size table,
both benches, and the new `test_wrong_opening_fails`, which rejects a
verifier-supplied `K` the leaf's commitment does not open to). `cargo fmt`
clean.

**Ledger corrections.** `shekyl-crypto-hash` already exports `cshake256_64`; no
new hash entry point is needed (round doc §6.2 said one would be added). The
two NUMS generators are `PQC_LEAF_COMMITMENT_G_K` and `PQC_LEAF_COMMITMENT_J`
in `shekyl-curve-generators`, pinned in the frozen-points KAT.
