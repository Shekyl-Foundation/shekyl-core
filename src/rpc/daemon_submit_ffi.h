// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// C FFI: the three transaction-submit state shims consumed by the Rust
// admission engine (rust/shekyl-daemon-rpc/src/submit/), per
// docs/design/DAEMON_SUBMIT_VERDICT.md §4. Zero verdict logic lives here:
// the shims fetch facts and execute the attested insert tail; Rust decides.
//
// Compatibility domain (§4.5): shekyl_submit_facts_ffi is SAME-BUILD ABI —
// the Rust and C++ sides ship in one artifact, so the layout is free to
// change between builds and carries no versioning. The layout is pinned by
// compile-time asserts on both sides (static_assert in daemon_submit_ffi.cpp,
// const asserts in shekyl-daemon-rpc's ffi.rs) against the documented
// offsets below, plus the bidirectional runtime round-trip test
// (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp).

#pragma once

#include <stdint.h>
#include <stddef.h>

// The archival gather row PODs (shekyl_archival_epoch_close_bond / _shard /
// _credit_pair) reused by the emission fact marshal below.
#include "shekyl/shekyl_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct core_rpc_handle core_rpc_handle;

// Per-key-image conflict descriptor values (§4.1: none | own_txid | other).
enum {
    SHEKYL_SUBMIT_KI_FREE = 0,
    SHEKYL_SUBMIT_KI_OWN_TX = 1,
    SHEKYL_SUBMIT_KI_OTHER = 2,
};

// Return codes shared by the snapshot and commit shims. The commit outcomes
// mirror rust CommitOutcome (§4.2); the snapshot uses OK / INTERNAL_FAULT
// only.
enum {
    SHEKYL_SUBMIT_OK = 0,               // snapshot filled / commit committed
    SHEKYL_SUBMIT_RACED = 1,            // a re-checked premise moved; fresh facts filled
    SHEKYL_SUBMIT_PRUNED_ON_INSERT = 2, // insert tail's prune() evicted the tx (F23)
    SHEKYL_SUBMIT_INTERNAL_FAULT = -1,  // §3.4 loud-failure arm; never a verdict
};

// POD fact snapshot (§4.1) — also the shape of Phase-D fresh facts when the
// commit races. Byte layout (size 104, align 8), asserted on both sides:
//
//   offset  0: in_pool               (u8; txid pool-resident at `all` category — §3.1 F40)
//   offset  1: in_chain              (u8; txid in main chain)
//   offset  2: ref_block_found       (u8; reference hash known ⇒ fields below valid)
//   offset  3: tree_depth            (u8; current curve-tree depth, LMDB convention)
//   offset  4: in_pool_broadcast     (u8; txid pool-resident at `legacy`/broadcast category —
//                                      the foreign-disclosable presence; differs from in_pool
//                                      only for a Dandelion++-embargoed tx, §3.1 identity pin)
//   offset  5: bond_record_probed    (u8; the §8.7.1 BP3 archival-bond-record probe ran —
//                                      snapshot: caller passed a bond p_canonical_id;
//                                      commit: the reparsed blob carries a bond-post vin)
//   offset  6: bond_record_exists    (u8; valid iff bond_record_probed — a bond record
//                                      exists for the probed p_canonical_id)
//   offset  7: emission_probed       (u8; the §8.7.2 E6 claim-slot probe ran — snapshot:
//                                      caller passed the emission (p_id, epochs); commit:
//                                      the reparsed blob carries an emission vin)
//   offset  8: emission_claim_conflict (u8; valid iff emission_probed — the claimant bond
//                                      record is gone OR a claimed epoch overlaps the
//                                      record's claimed set; Rust classifies)
//   offset  9: reserved[7]           (zeroed)
//   offset 16: ref_height            (u64; reference block main-chain height)
//   offset 24: root[32]              (curve-tree root at ref_height)
//   offset 56: fee_per_byte          (u64; check_fee's derived floor param)
//   offset 64: fee_quantization_mask (u64; ≥ 1)
//   offset 72: weight_limit          (u64; get_transaction_weight_limit)
//   offset 80: chain_height          (u64; block count, m_db->height())
//   offset 88: in_chain_height       (u64; valid iff in_chain — the F40 confirming-block
//                                      height, read under the same lock scope as the
//                                      membership fact so the pair cannot be racy)
//   offset 96: bond_record_bonded_total (u64; valid iff bond_record_probed AND the probe
//                                      kind was _UNBOND -- the debit arm's Phase-D
//                                      predicate, because an exit preserves the row)
//
// Key-image conflicts travel beside the struct as a plain uint8_t array
// (one SHEKYL_SUBMIT_KI_* entry per submitted key image, submission order).
typedef struct shekyl_submit_facts_ffi {
    uint8_t in_pool;
    uint8_t in_chain;
    uint8_t ref_block_found;
    uint8_t tree_depth;
    uint8_t in_pool_broadcast;
    uint8_t bond_record_probed;
    uint8_t bond_record_exists;
    uint8_t emission_probed;
    uint8_t emission_claim_conflict;
    uint8_t reserved[7];
    uint64_t ref_height;
    uint8_t root[32];
    uint64_t fee_per_byte;
    uint64_t fee_quantization_mask;
    uint64_t weight_limit;
    uint64_t chain_height;
    uint64_t in_chain_height;
    // The probed record's bonded total, valid iff bond_record_probed AND the
    // probe kind was _UNBOND. Appended (offset 96) so no existing offset
    // moves.
    //
    // WHY PRESENCE IS NOT ENOUGH: apply_archival_unbond does a WHOLE-RECORD
    // write, so an exited persona keeps its row with bonded_total_atomic == 0
    // and get_archival_bond_hybrid_pubkey still reports it present. A
    // competing Unbond connecting during Phase C therefore leaves
    // bond_record_exists == 1, and a re-check keyed on presence can never
    // observe the exit. The balance is what moves; the row does not.
    //
    // 0 is not ambiguous here: paired with bond_record_exists it distinguishes
    // "no row" from "row with nothing bonded", and the second IS the exited
    // state a debit must be refused against.
    uint64_t bond_record_bonded_total;
} shekyl_submit_facts_ffi;

// ── §8.7.2 emission fact marshal (rows E6 + E7) ─────────────────────────────
//
// The emission-arm facts are variable-size (per-claimed-epoch gather rows), so
// they travel beside the fixed POD as a C++-owned handle: the snapshot fills it
// under the same lock scope as every other fact, Rust copies the view into
// owned data during the call, then frees the handle. Row PODs are the
// shekyl_ffi.h gather shapes the block path already marshals
// (ArchivalEmissionEpochSnapshot::to_ffi_*), so the two marshals share one
// definition per row.

// E6: the claimant bond record's verify operands.
typedef struct shekyl_submit_emission_bond_ffi {
    uint64_t join_settlement_epoch;
    uint8_t holdings_kind;
    const uint64_t* shard_ids;
    size_t shard_ids_len;
    const uint64_t* claimed_epochs;
    size_t claimed_epochs_len;
} shekyl_submit_emission_bond_ffi;

// E7: one frozen as-of-E gather snapshot (ArchivalEmissionEpochSnapshot's
// submit-side view; has_budget_row rides along so an unclosed epoch is a
// marshaled fact, not a shim fault).
typedef struct shekyl_submit_emission_snapshot_ffi {
    uint8_t has_budget_row;
    uint64_t settlement_epoch;
    uint64_t close_block_height;
    uint64_t sigma_work_milli;
    uint64_t budget_atomic;
    // SIZE_MAX = claimant has no serve-credit row in E.
    size_t claimant_bond_idx;
    const struct shekyl_archival_epoch_close_bond* bonds;
    size_t bonds_len;
    const struct shekyl_archival_epoch_close_shard* shards;
    size_t shards_len;
    const struct shekyl_archival_credit_pair* credit_pairs;
    size_t credit_pairs_len;
} shekyl_submit_emission_snapshot_ffi;

typedef struct shekyl_submit_emission_facts_ffi {
    uint8_t bond_present;
    shekyl_submit_emission_bond_ffi bond; // valid iff bond_present
    const shekyl_submit_emission_snapshot_ffi* snapshots;
    size_t snapshots_len;
} shekyl_submit_emission_facts_ffi;

// Opaque owner of every buffer the view above points into.
typedef struct shekyl_submit_emission_facts_handle shekyl_submit_emission_facts_handle;

// The handle's view (never NULL for a live handle; pointers valid until free).
const shekyl_submit_emission_facts_ffi* shekyl_submit_emission_facts_view(
    const shekyl_submit_emission_facts_handle* h);

void shekyl_submit_emission_facts_free(shekyl_submit_emission_facts_handle* h);

// ── §8.7.1.1 Unbond fact marshal (rows UB2/UB3/UB4/UB6/UB7) ─────────────────
//
// Which archival-bond question the probe asks. The two bond-post arms ask
// OPPOSITE questions of the same table: JoinMarket wants the record ABSENT
// (row BP3, one bit) and Unbond wants it PRESENT with its contents as verify
// operands. One id plus a discriminant, mirroring the Rust `BondProbe` enum,
// so the two sides cannot disagree about which probe ran.
#define SHEKYL_SUBMIT_BOND_PROBE_JOIN   0
#define SHEKYL_SUBMIT_BOND_PROBE_UNBOND 1

// The debited record's verify operands. Variable-size (the committed
// bond_spend_pk and the per-shard last-served slice), so like the emission
// bundle it travels beside the fixed POD as a C++-owned handle.
typedef struct shekyl_submit_unbond_record_ffi {
    uint64_t bonded_total_atomic;
    size_t   bad_interval_count;
    // The record's COMMITTED debit authorizer, exactly as stored (may be
    // empty -> the record authorizes no debit; the Rust pin fails closed).
    const uint8_t* bond_spend_pk;
    size_t   bond_spend_pk_len;
    uint8_t  holdings_kind;
    // WHICH accessor produced per_shard_last_served
    // (SHEKYL_ARCHIVAL_LAST_SERVED_SCAN_HELD_SHARDS / _ALL_SHARDS). Echoed
    // rather than re-derived Rust-side because the wrong gather fails
    // PERMISSIVELY: a complete-tree record stores no shard list, so the
    // held-shards accessor returns an empty slice, which folds to "never
    // served", which makes the release cooldown elapse for a record that has
    // been serving. Rust pins this byte against the record's holdings kind.
    uint8_t  last_served_scan;
    // 1 = the gather REFUSED to run the scan because the debit-auth pin
    // failed, so per_shard_last_served is empty-because-unread rather than
    // empty-because-never-served. Rust must refuse rather than fold: an
    // unread slice folds to "never served", which is the PERMISSIVE cooldown
    // answer.
    uint8_t  last_served_scan_skipped;
    const uint64_t* per_shard_last_served;
    size_t   per_shard_last_served_len;
} shekyl_submit_unbond_record_ffi;

typedef struct shekyl_submit_unbond_facts_ffi {
    uint8_t record_present;
    shekyl_submit_unbond_record_ffi record; // valid iff record_present
    // The slash scheduler's watermark AS STORED. u64::MAX ("nothing settled
    // yet") is NOT normalised here -- Rust owns that normalisation, in one
    // place, exactly as the block path's FFI wrapper does.
    uint64_t last_settled_slash_epoch;
} shekyl_submit_unbond_facts_ffi;

// Opaque owner of every buffer the view above points into.
typedef struct shekyl_submit_unbond_facts_handle shekyl_submit_unbond_facts_handle;

// The handle's view (never NULL for a live handle; pointers valid until free).
const shekyl_submit_unbond_facts_ffi* shekyl_submit_unbond_facts_view(
    const shekyl_submit_unbond_facts_handle* h);

void shekyl_submit_unbond_facts_free(shekyl_submit_unbond_facts_handle* h);

// Shim 1 (§4.1): Phase-B POD fact snapshot under one short pool→blockchain
// lock scope (§4.4 order), reads only.
//
// txid / reference_block: 32 bytes each. key_images: n_key_images × 32
// bytes, flat, submission order. out_ki_conflicts: n_key_images entries.
// bond_p_canonical_id: 32 bytes or NULL — non-NULL for a bond-post
// submission of ANY kind, keying the record probe
// (get_archival_bond_hybrid_pubkey) into bond_record_probed/exists. That
// pair is kind-AGNOSTIC on purpose: it is the record's PRESENCE, which BOTH
// arms consume during verification (§8.7.1 BP3 wants it absent, §8.7.1.1 UB2
// wants it present), and the commit shim re-gathers only this POD -- never
// the bundle below.
//
// At Phase D, however, only the CREDIT arm races on presence. An exit
// preserves the row (see bond_record_bonded_total), so the debit arm's race
// predicate is the balance; presence there only separates "no row" from "row
// with nothing bonded". bond_probe_kind selects what is gathered ON TOP: _UNBOND
// additionally marshals the record's CONTENTS into *out_unbond (a handle the
// caller must free; NULL when no unbond probe ran), which only the debit
// arm's Phase-C battery needs. _JOIN gathers nothing extra.
//
// Presence therefore arrives twice for an _UNBOND probe -- as the POD bit and
// as bundle->record_present -- from two DB reads under one lock scope. They
// cannot legitimately disagree, and the Rust shim refuses the pair if they
// do rather than verifying an Unbond against half a record.
//
// An _UNBOND probe also requires bond_auth_pubkey (the bond slot's
// pqc_auths key, from the same blob as the probe id). It gates the EXPENSIVE
// half of the gather: the per-shard last-served scan is two LMDB seeks per
// served shard, run while the pool and blockchain locks are held. The block
// path already performs the cheap key pin before its cursor scans; this
// mirrors that ordering.
//
// An _UNBOND probe also carries bond_debit, the vin's fixed debit term. UB9
// requires it to equal the record's whole balance, so a mismatch cannot verify
// whatever the scan returns -- the gather skips the scan on that ground, which
// is what stops a broadcast-then-invalidated Unbond being replayed for the
// scan forever (it is neither in-pool nor in-chain, so the identity skip never
// fires for it). See the invariant on fill_unbond_facts_locked.
//
// It does NOT keep an unauthenticated caller out on its own -- both compared
// keys are public. Possession is proved earlier, by the Rust engine's UB0
// pre-gate, and the two checks compose. The argument lives in ONE place,
// DAEMON_SUBMIT_VERDICT.md §8.7.1.1's "Why UB0 exists" note; do not restate it
// here (an earlier revision of this comment asserted the pin stopped "an
// unsigned, unfunded transaction", which was false and outlived its own
// retraction in daemon_submit_ffi.cpp).
//
// It is a WORK gate, not a verdict. The same shared pin runs again Rust-side
// and issues the actual refusal, so a divergence here can only cause less
// work, never a different answer.
//
// An _UNBOND probe REQUIRES a non-NULL out_unbond -- INTERNAL_FAULT
// otherwise. The debit battery cannot run on the presence bit alone
// (UB3/UB5/UB7/UB9 all read the record's contents), so a dropped bundle is
// an incoherent call, not a cheaper probe. This is deliberately NOT the
// emission rule below, where a NULL out_emission is legitimate: there the
// POD's claim-conflict bit is a complete answer on its own. Do not flatten
// the two into one convention.
//
// emission_p_canonical_id (32 bytes) + emission_epochs (n_emission_epochs
// u64s): non-NULL for an emission submission, keying the §8.7.2 E6 claim-slot
// probe (emission_probed/emission_claim_conflict) and, when out_emission is
// non-NULL, the E6/E7 fact-bundle marshal (*out_emission set to a handle the
// caller must free; NULL on absent probe).
// Returns SHEKYL_SUBMIT_OK or SHEKYL_SUBMIT_INTERNAL_FAULT (DB exception /
// bad arguments; never a verdict).
int shekyl_submit_snapshot_facts(core_rpc_handle* h,
    const uint8_t* txid,
    const uint8_t* key_images, size_t n_key_images,
    const uint8_t* reference_block,
    const uint8_t* bond_p_canonical_id,
    uint8_t bond_probe_kind,
    const uint8_t* bond_auth_pubkey, size_t bond_auth_pubkey_len,
    uint64_t bond_debit,
    const uint8_t* emission_p_canonical_id,
    const uint64_t* emission_epochs, size_t n_emission_epochs,
    shekyl_submit_emission_facts_handle** out_emission,
    shekyl_submit_unbond_facts_handle** out_unbond,
    shekyl_submit_facts_ffi* out_facts,
    uint8_t* out_ki_conflicts);

// Shim 2 (§4.2): Phase-D check-and-commit under one short pool→blockchain
// lock scope. Recomputes the C++ txid over the blob and release-checks it
// against the engine txid (§3.4; mismatch = INTERNAL_FAULT, never a
// verdict); re-checks every mutable premise (identity, key images,
// hash-anchored reference + age window, root == certificate root, the
// check_fee re-gate against fresh params — F34, and the §8.7.1 BP3
// bond-record re-probe when the reparsed blob carries a bond-post vin —
// a record appearing during Phase C is a claim-slot race); on clean,
// executes the attested insert tail (tx_memory_pool::insert_attested_tx)
// and the post-prune membership check (F23).
//
// cert_* carry the VerificationCertificate facts (§3.3). On RACED, the
// fresh facts (same collection as shim 1, same lock scope) are written to
// out_fresh_facts / out_fresh_ki_conflicts (n_key_images entries) and Rust
// classifies, most-terminal-first (§3.1). The blob-derived key-image count
// must equal n_key_images (INTERNAL_FAULT otherwise).
int shekyl_submit_commit_tx(core_rpc_handle* h,
    const uint8_t* blob, size_t blob_len,
    const uint8_t* txid,
    uint64_t tx_weight, uint64_t fee,
    const uint8_t* cert_ref_block, uint64_t cert_ref_height,
    const uint8_t* cert_root,
    shekyl_submit_facts_ffi* out_fresh_facts,
    uint8_t* out_fresh_ki_conflicts, size_t n_key_images);

// Shim 3 (§4.3): post-commit relay nudge — fetch the pool-resident blob by
// txid and enqueue it through the existing
// relay_transactions(relay_method::local) dispatch, the same entry point
// the deleted legacy on_send_raw_tx handler used (§9.3), so Dandelion++
// embargo arming is inherited, not
// re-implemented (§5.2 item 2). This is also the Q12-D5a origination roll:
// the zone argument is `invalid` (fail-closed onto anonymity) or `public_`
// (clearnet by design), never a silent fallback. Fire and forget: the
// nudge is latency; the embargo + periodic loop are the guarantee. Returns
// SHEKYL_SUBMIT_OK / SHEKYL_SUBMIT_INTERNAL_FAULT (callers may ignore; a
// miss means the tx raced away post-commit and the periodic loop owns
// whatever remains — that fallback does not re-roll).
int shekyl_submit_relay_tx(core_rpc_handle* h, const uint8_t* txid);

// ── §4.5 round-trip test hooks (no production callers) ─────────────────────
//
// Layout probes for the bidirectional FFI struct tests: per-FIELD writes and
// reads, so a field-offset disagreement fails even where a memcpy echo would
// pass. `fill` writes seed-derived values into every field through the C++
// view of the layout; `check` reads every field through the C++ view and
// returns 0 iff each matches the same derivation. The Rust twin does the
// mirror-image derivation through its view.
void shekyl_submit_facts_test_fill(shekyl_submit_facts_ffi* out, uint64_t seed);
int shekyl_submit_facts_test_check(const shekyl_submit_facts_ffi* facts, uint64_t seed);

#ifdef __cplusplus
} // extern "C"

// ── C++-side implementations over the core objects ──────────────────────────
//
// The extern "C" wrappers above only resolve pool/blockchain/protocol from
// the handle and delegate here. Exposed so the latch-based commit
// integration test (§10 item 2) can drive the real shim logic against a
// unit-test pool/blockchain fixture without constructing a core_rpc_server.

namespace cryptonote { class tx_memory_pool; class Blockchain; struct i_cryptonote_protocol; }

namespace daemon_submit {

int snapshot_facts(cryptonote::tx_memory_pool& pool, cryptonote::Blockchain& bc,
    const uint8_t* txid,
    const uint8_t* key_images, size_t n_key_images,
    const uint8_t* reference_block,
    const uint8_t* bond_p_canonical_id,
    uint8_t bond_probe_kind,
    const uint8_t* bond_auth_pubkey, size_t bond_auth_pubkey_len,
    uint64_t bond_debit,
    const uint8_t* emission_p_canonical_id,
    const uint64_t* emission_epochs, size_t n_emission_epochs,
    shekyl_submit_emission_facts_handle** out_emission,
    shekyl_submit_unbond_facts_handle** out_unbond,
    shekyl_submit_facts_ffi* out_facts,
    uint8_t* out_ki_conflicts) noexcept;

int commit_tx(cryptonote::tx_memory_pool& pool, cryptonote::Blockchain& bc,
    const uint8_t* blob, size_t blob_len,
    const uint8_t* txid,
    uint64_t tx_weight, uint64_t fee,
    const uint8_t* cert_ref_block, uint64_t cert_ref_height,
    const uint8_t* cert_root,
    shekyl_submit_facts_ffi* out_fresh_facts,
    uint8_t* out_fresh_ki_conflicts, size_t n_key_images) noexcept;

int relay_tx(cryptonote::tx_memory_pool& pool,
    cryptonote::i_cryptonote_protocol& protocol,
    const uint8_t* txid) noexcept;

} // namespace daemon_submit

#endif // __cplusplus
